// NVMe block device driver
// Reference: NVM Express Base Specification 2.0
//
// Features:
// - Controller initialization and admin queue
// - I/O queue pair with IRQ-driven completion
// - NVMe read (opcode 0x02) and write (opcode 0x01) commands
// - WaitQueue-based synchronous I/O
// - Namespace identification

#![allow(dead_code)]

use crate::{
    hardware::pci_client::{self as pci, Bar, ProbeCriteria},
    memory::{allocate_zeroed_frame, paging, phys_to_virt},
    sync::waitqueue::WaitQueue,
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};
use spin::Mutex;

const NVME_PAGE_SIZE: usize = 4096;
const IO_QUEUE_SIZE: usize = 64;
const MAX_IO_COMMANDS: usize = IO_QUEUE_SIZE;

const ADMIN_CQE_ERROR: u16 = (0x1 << 14) | (0x1 << 10);

#[repr(transparent)]
struct VolatileCell<T> {
    value: T,
}

impl<T> VolatileCell<T> {
    fn read(&self) -> T
    where
        T: Copy,
    {
        unsafe { ptr::read_volatile(&self.value) }
    }
    fn write(&self, val: T) {
        unsafe { ptr::write_volatile(core::ptr::addr_of!(self.value) as *mut T, val) }
    }
}

unsafe impl<T: Send> Send for VolatileCell<T> {}
unsafe impl<T: Sync> Sync for VolatileCell<T> {}

#[repr(C)]
struct Capability {
    value: VolatileCell<u64>,
}

impl Capability {
    fn max_queue_entries(&self) -> u16 {
        (self.value.read() & 0xFFFF) as u16
    }
    fn doorbell_stride(&self) -> u64 {
        (self.value.read() >> 32) & 0xF
    }
}

#[repr(transparent)]
struct Version {
    value: VolatileCell<u32>,
}

#[repr(C)]
struct ControllerConfig {
    value: VolatileCell<u32>,
}

impl ControllerConfig {
    fn clear_io_fields(&self) {
        let mut val = self.value.read();
        val &= !(((0xF) << 16) | ((0xF) << 20) | ((0x7) << 4));
        self.value.write(val);
    }
    fn set_iosqes(&self, size: u32) {
        let mut val = self.value.read();
        val |= (size & 0xF) << 16;
        self.value.write(val);
    }
    fn set_iocqes(&self, size: u32) {
        let mut val = self.value.read();
        val |= (size & 0xF) << 20;
        self.value.write(val);
    }
    fn set_css(&self, css: u32) {
        let mut val = self.value.read();
        val |= (css & 0x7) << 4;
        self.value.write(val);
    }
    fn set_enable(&self, enable: bool) {
        let mut val = self.value.read();
        if enable {
            val |= 1;
        } else {
            val &= !1;
        }
        self.value.write(val);
    }
    fn is_enabled(&self) -> bool {
        (self.value.read() & 1) != 0
    }
}

#[repr(transparent)]
struct ControllerStatus {
    value: VolatileCell<u32>,
}

impl ControllerStatus {
    fn is_ready(&self) -> bool {
        (self.value.read() & 1) != 0
    }
    fn is_fatal(&self) -> bool {
        (self.value.read() >> 1) & 1 != 0
    }
}

#[repr(C)]
struct Registers {
    capability: Capability,
    version: Version,
    _intms: VolatileCell<u32>,
    _intmc: VolatileCell<u32>,
    cc: ControllerConfig,
    _reserved1: VolatileCell<u32>,
    csts: ControllerStatus,
    _reserved2: VolatileCell<u32>,
    aqa: VolatileCell<u32>,
    asq: VolatileCell<u64>,
    acq: VolatileCell<u64>,
}

#[derive(Debug, Clone, Copy)]
enum NvmeError {
    ControllerFatal,
    Timeout,
    InvalidNamespace,
    IoError,
}

#[derive(Debug, Clone)]
pub struct NvmeNamespace {
    pub nsid: u32,
    pub size: u64,
    pub block_size: u32,
}

struct IoQueuePair {
    submission: IoQueue<Submission>,
    completion: IoQueue<Completion>,
    command_id: u16,
    size: usize,
}

struct IoQueue<T: QueueType> {
    doorbell: *const VolatileCell<u32>,
    entries: *mut T::EntryType,
    size: usize,
    index: usize,
    phase: bool,
    phys_addr: u64,
}

unsafe impl<T: QueueType> Send for IoQueue<T> {}
unsafe impl<T: QueueType> Sync for IoQueue<T> {}

impl<T: QueueType> IoQueue<T> {
    fn new(registers_base: usize, size: usize, queue_id: u16, dstrd: usize) -> Self {
        let doorbell_offset =
            0x1000 + ((((queue_id as usize) * 2) + T::DOORBELL_OFFSET) * (4 << dstrd));
        let doorbell =
            unsafe { &*((registers_base + doorbell_offset) as *const VolatileCell<u32>) };

        let frame = allocate_zeroed_frame().expect("NVMe: failed to allocate I/O queue frame");
        let phys_addr = frame.start_address.as_u64();
        paging::ensure_identity_map_range(phys_addr, NVME_PAGE_SIZE as u64);
        let virt_addr = phys_to_virt(phys_addr);

        unsafe {
            ptr::write_bytes(
                virt_addr as *mut u8,
                0,
                size * core::mem::size_of::<T::EntryType>(),
            );
        }

        Self {
            doorbell,
            entries: virt_addr as *mut T::EntryType,
            size,
            index: 0,
            phase: true,
            phys_addr,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NvmeCompletionResult {
    pub command_id: u16,
    pub status: u16,
}

pub struct NvmeController {
    registers: usize,
    admin_queue: Mutex<QueuePair>,
    io_queue: Mutex<IoQueuePair>,
    namespaces: Vec<NvmeNamespace>,
    pub name: String,
    irq_line: u8,
    io_done: Box<[AtomicBool]>,
    io_wq: WaitQueue,
}

unsafe impl Send for NvmeController {}
unsafe impl Sync for NvmeController {}

impl NvmeController {
    unsafe fn new(registers: usize, name: String) -> Result<Self, NvmeError> {
        let regs = &*(registers as *const Registers);
        let dstrd = regs.capability.doorbell_stride() as usize;
        let max_entries = regs.capability.max_queue_entries();
        let queue_size = core::cmp::min(max_entries as usize, 1024);

        let admin_queue = QueuePair::new(registers, queue_size, dstrd);

        let io_sub = IoQueue::new(registers, IO_QUEUE_SIZE, 1, dstrd);
        let io_comp = IoQueue::new(registers, IO_QUEUE_SIZE, 1, dstrd);
        let io_queue = IoQueuePair {
            submission: io_sub,
            completion: io_comp,
            command_id: 0,
            size: IO_QUEUE_SIZE,
        };

        let io_done: Box<[AtomicBool]> = (0..MAX_IO_COMMANDS).map(|_| AtomicBool::new(false)).collect();

        let mut controller = Self {
            registers,
            admin_queue: Mutex::new(admin_queue),
            io_queue: Mutex::new(io_queue),
            namespaces: Vec::new(),
            name,
            irq_line: 0,
            io_done,
            io_wq: WaitQueue::new(),
        };

        controller.init_admin_queue()?;
        controller.create_io_queues()?;
        controller.identify_namespaces()?;
        Ok(controller)
    }

    fn submit_admin_command(&self, command: Command) -> Result<CompletionEntry, NvmeError> {
        let mut admin = self.admin_queue.lock();
        admin.submit_command(command).ok_or(NvmeError::IoError)
    }

    fn init_admin_queue(&mut self) -> Result<(), NvmeError> {
        let regs = unsafe { &*(self.registers as *const Registers) };
        let (admin_sq_phys, admin_cq_phys, queue_size) = {
            let q = self.admin_queue.lock();
            (q.submission_phys(), q.completion_phys(), q.size)
        };

        if queue_size == 0 {
            return Err(NvmeError::IoError);
        }
        let qsz = ((queue_size as u32).saturating_sub(1)) & 0x0FFF;

        if regs.cc.is_enabled() {
            regs.cc.set_enable(false);
            let mut disable_timeout = 1_000_000u32;
            while regs.csts.is_ready() {
                core::hint::spin_loop();
                disable_timeout = disable_timeout.saturating_sub(1);
                if disable_timeout == 0 {
                    return Err(NvmeError::Timeout);
                }
            }
        }

        regs.aqa.write(qsz | (qsz << 16));
        regs.asq.write(admin_sq_phys);
        regs.acq.write(admin_cq_phys);

        regs.cc.clear_io_fields();
        regs.cc.set_css(0);
        regs.cc.set_iosqes(6);
        regs.cc.set_iocqes(6);
        regs.cc.set_enable(true);

        let mut timeout = 1_000_000;
        while !regs.csts.is_ready() {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                return Err(NvmeError::Timeout);
            }
        }

        if regs.csts.is_fatal() {
            return Err(NvmeError::ControllerFatal);
        }

        log::info!(
            "NVMe: Controller v{}.{}.{} ready",
            regs.version.value.read() >> 16,
            (regs.version.value.read() >> 8) & 0xFF,
            regs.version.value.read() & 0xFF
        );
        Ok(())
    }

    fn create_io_queues(&mut self) -> Result<(), NvmeError> {
        let (io_sq_phys, io_cq_phys, queue_size) = {
            let q = self.io_queue.lock();
            (q.submission.phys_addr, q.completion.phys_addr, q.size)
        };

        let qsz = ((queue_size as u32).saturating_sub(1)) & 0xFFF;

        let set_feature_cmd = Command {
            opcode: 0x09,
            cdw10: 0x07,
            cdw11: 0x0100_0000,
            ..Default::default()
        };
        self.submit_admin_command(set_feature_cmd).ok();

        let cq_cmd = Command {
            opcode: 0x05,
            cdw10: qsz | (0 << 16),
            prp1: io_cq_phys,
            ..Default::default()
        };
        match self.submit_admin_command(cq_cmd) {
            Ok(c) => {
                if c.status_code() != 0 {
                    log::warn!("NVMe: Create I/O CQ failed: status={}", c.status_code());
                }
            }
            Err(e) => {
                log::warn!("NVMe: Create I/O CQ error: {:?}", e);
                return Err(e);
            }
        }

        let sq_cmd = Command {
            opcode: 0x01,
            cdw10: qsz | (1 << 16),
            cdw11: 0x0000_0001,
            prp1: io_sq_phys,
            ..Default::default()
        };
        match self.submit_admin_command(sq_cmd) {
            Ok(c) => {
                if c.status_code() != 0 {
                    log::warn!("NVMe: Create I/O SQ failed: status={}", c.status_code());
                }
            }
            Err(e) => {
                log::warn!("NVMe: Create I/O SQ error: {:?}", e);
                return Err(e);
            }
        }

        log::info!("NVMe: I/O queues created (size={})", queue_size);
        Ok(())
    }

    fn identify(&self, cns: u8, nsid: u32) -> Result<*mut u8, NvmeError> {
        let frame = allocate_zeroed_frame().ok_or(NvmeError::IoError)?;
        let phys = frame.start_address.as_u64();
        paging::ensure_identity_map_range(phys, NVME_PAGE_SIZE as u64);
        let virt = phys_to_virt(phys) as *mut u8;
        unsafe {
            ptr::write_bytes(virt, 0, NVME_PAGE_SIZE);
        }

        let cmd = Command {
            opcode: 0x06,
            nsid,
            prp1: phys,
            cdw10: cns as u32,
            ..Default::default()
        };

        let completion = self.submit_admin_command(cmd)?;
        if completion.status_code() != 0 {
            return Err(NvmeError::IoError);
        }
        Ok(virt)
    }

    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        let ctrl_data = self.identify(0x01, 0)?;
        let nn = unsafe { ptr::read(ctrl_data.add(520) as *const u32) };
        if nn == 0 {
            return Err(NvmeError::InvalidNamespace);
        }

        for nsid in 1..=nn {
            if let Ok(ns_data) = self.identify(0x00, nsid) {
                unsafe {
                    let nsze = ptr::read(ns_data.add(16) as *const u64);
                    let flbas = ptr::read(ns_data.add(26) as *const u8) as usize;
                    let lbaf_index = flbas & 0xF;
                    let lbaf_offset = 128 + lbaf_index * 16;
                    let lbaf_data = ptr::read(ns_data.add(lbaf_offset) as *const u16);
                    let block_size = (1 << lbaf_data) as u32;

                    self.namespaces.push(NvmeNamespace {
                        nsid,
                        size: nsze,
                        block_size,
                    });
                    log::info!(
                        "NVMe: Namespace {} - {} blocks @ {} bytes",
                        nsid,
                        nsze,
                        block_size
                    );
                }
            }
        }
        Ok(())
    }

    fn submit_io_command(&self, command: &mut Command) -> Result<u16, NvmeError> {
        let mut io = self.io_queue.lock();
        let cmd_id = io.command_id;
        command.command_id = cmd_id;
        io.command_id = io.command_id.wrapping_add(1);

        let slot = cmd_id as usize % io.size;
        unsafe {
            ptr::write(io.submission.entries.add(slot), *command);
            (*io.submission.doorbell).write(((slot + 1) % io.size) as u32);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        Ok(cmd_id)
    }

    pub fn read_blocks(
        &self,
        nsid: u32,
        lba: u64,
        block_count: u32,
        buf_phys: u64,
    ) -> Result<(), NvmeError> {
        let cmd_id = {
            let mut cmd = Command {
                opcode: 0x02,
                nsid,
                prp1: buf_phys,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: (block_count - 1),
                ..Default::default()
            };
            self.submit_io_command(&mut cmd)?
        };

        let idx = cmd_id as usize % MAX_IO_COMMANDS;
        self.io_done[idx].store(false, Ordering::SeqCst);

        self.io_wq.wait_until(|| {
            if self.io_done[idx].load(Ordering::Acquire) {
                Some(())
            } else {
                None
            }
        });

        Ok(())
    }

    pub fn write_blocks(
        &self,
        nsid: u32,
        lba: u64,
        block_count: u32,
        buf_phys: u64,
    ) -> Result<(), NvmeError> {
        let cmd_id = {
            let mut cmd = Command {
                opcode: 0x01,
                nsid,
                prp1: buf_phys,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: (block_count - 1),
                ..Default::default()
            };
            self.submit_io_command(&mut cmd)?
        };

        let idx = cmd_id as usize % MAX_IO_COMMANDS;
        self.io_done[idx].store(false, Ordering::SeqCst);

        self.io_wq.wait_until(|| {
            if self.io_done[idx].load(Ordering::Acquire) {
                Some(())
            } else {
                None
            }
        });

        Ok(())
    }

    pub fn handle_interrupt(&self) {
        let mut io = self.io_queue.lock();

        loop {
            let entry = unsafe { &*io.completion.entries.add(io.completion.index) };
            let status = entry.status;
            if ((status & 0x1) != 0) == io.completion.phase {
                let cmd_id = entry.command_id;
                let sc = (entry.status >> 1) & 0xFF;
                let dnr = (entry.status >> 14) & 1;

                io.completion.index = (io.completion.index + 1) % io.completion.size;
                if io.completion.index == 0 {
                    io.completion.phase = !io.completion.phase;
                }
                unsafe {
                    (*io.completion.doorbell).write(io.completion.index as u32);
                }

                let idx = cmd_id as usize % MAX_IO_COMMANDS;
                if sc != 0 && dnr == 0 {
                    log::warn!("NVMe: I/O error cmd_id={} sc={}", cmd_id, sc);
                }
                self.io_done[idx].store(true, Ordering::Release);
                self.io_wq.wake_all();
            } else {
                break;
            }
        }
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    pub fn get_namespace(&self, index: usize) -> Option<&NvmeNamespace> {
        self.namespaces.get(index)
    }

    pub fn set_irq_line(&mut self, irq: u8) {
        self.irq_line = irq;
    }

    pub fn irq_line(&self) -> u8 {
        self.irq_line
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Command {
    opcode: u8,
    flags: u8,
    command_id: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CompletionEntry {
    dw0: u32,
    dw1: u32,
    sq_head: u16,
    sq_id: u16,
    command_id: u16,
    status: u16,
}

impl CompletionEntry {
    fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }
}

struct QueuePair {
    #[allow(dead_code)]
    id: u16,
    size: usize,
    command_id: u16,
    submission: Queue<Submission>,
    completion: Queue<Completion>,
}

struct Submission;
struct Completion;

trait QueueType {
    type EntryType;
    const DOORBELL_OFFSET: usize;
}

impl QueueType for Submission {
    type EntryType = Command;
    const DOORBELL_OFFSET: usize = 0;
}

impl QueueType for Completion {
    type EntryType = CompletionEntry;
    const DOORBELL_OFFSET: usize = 1;
}

struct Queue<T: QueueType> {
    doorbell: *const VolatileCell<u32>,
    entries: *mut T::EntryType,
    size: usize,
    index: usize,
    phase: bool,
    phys_addr: u64,
}

impl<T: QueueType> Queue<T> {
    fn new(registers_base: usize, size: usize, queue_id: u16, dstrd: usize) -> Self {
        let doorbell_offset =
            0x1000 + ((((queue_id as usize) * 2) + T::DOORBELL_OFFSET) * (4 << dstrd));
        let doorbell =
            unsafe { &*((registers_base + doorbell_offset) as *const VolatileCell<u32>) };

        let frame = allocate_zeroed_frame().expect("NVMe: failed to allocate queue frame");
        let phys_addr = frame.start_address.as_u64();
        paging::ensure_identity_map_range(phys_addr, NVME_PAGE_SIZE as u64);
        let virt_addr = phys_to_virt(phys_addr);

        unsafe {
            ptr::write_bytes(
                virt_addr as *mut u8,
                0,
                size * core::mem::size_of::<T::EntryType>(),
            );
        }

        Self {
            doorbell,
            entries: virt_addr as *mut T::EntryType,
            size,
            index: 0,
            phase: true,
            phys_addr,
        }
    }

    fn phys_addr(&self) -> u64 {
        self.phys_addr
    }
}

impl Queue<Completion> {
    fn poll_completion(&mut self) -> Option<CompletionEntry> {
        unsafe {
            let entry = &*self.entries.add(self.index);
            let status = entry.status;
            if ((status & 0x1) != 0) == self.phase {
                let completion = ptr::read(entry);
                self.index = (self.index + 1) % self.size;
                if self.index == 0 {
                    self.phase = !self.phase;
                }
                (*self.doorbell).write(self.index as u32);
                Some(completion)
            } else {
                None
            }
        }
    }
}

impl Queue<Submission> {
    fn submit_command(&mut self, command: Command, idx: usize) {
        unsafe {
            ptr::write(self.entries.add(idx), command);
            (*self.doorbell).write(((idx + 1) % self.size) as u32);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl QueuePair {
    fn new(registers_base: usize, size: usize, dstrd: usize) -> Self {
        static NEXT_ID: AtomicU8 = AtomicU8::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst) as u16;
        Self {
            id,
            size,
            command_id: 0,
            submission: Queue::new(registers_base, size, id, dstrd),
            completion: Queue::new(registers_base, size, id, dstrd),
        }
    }

    fn submission_phys(&self) -> u64 {
        self.submission.phys_addr()
    }
    fn completion_phys(&self) -> u64 {
        self.completion.phys_addr()
    }

    fn submit_command(&mut self, command: Command) -> Option<CompletionEntry> {
        let slot = self.command_id as usize % self.size;
        let mut cmd = command;
        unsafe {
            ptr::write(&mut cmd.command_id as *mut u16, self.command_id);
        }
        self.command_id = self.command_id.wrapping_add(1);
        self.submission.submit_command(cmd, slot);
        let mut timeout = 5_000_000u32;
        loop {
            if let Some(c) = self.completion.poll_completion() {
                return Some(c);
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                log::error!("NVMe: admin command timeout");
                return None;
            }
            core::hint::spin_loop();
        }
    }
}

static NVME_CONTROLLERS: Mutex<Vec<Arc<Mutex<NvmeController>>>> = Mutex::new(Vec::new());
static NVME_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static NVME_IRQ_LINE: AtomicU8 = AtomicU8::new(0);

pub fn init() {
    log::info!("[NVMe] Scanning for NVMe controllers...");

    let candidates = pci::probe_all(ProbeCriteria {
        vendor_id: None,
        device_id: None,
        class_code: Some(pci::class::MASS_STORAGE),
        subclass: Some(pci::storage_subclass::NVM),
        prog_if: None,
    });

    for (i, pci_dev) in candidates.into_iter().enumerate() {
        log::info!(
            "NVMe: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        let irq = pci_dev.interrupt_line;
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64 { addr, .. }) => addr,
            _ => {
                log::warn!("NVMe: Invalid BAR0");
                continue;
            }
        };

        paging::ensure_identity_map_range(bar, 0x10000);
        let registers = phys_to_virt(bar) as usize;
        let name = format!("nvme{}", i);

        match unsafe { NvmeController::new(registers, name.clone()) } {
            Ok(mut controller) => {
                controller.set_irq_line(irq);
                NVME_IRQ_LINE.store(irq, Ordering::Relaxed);
                log::info!("NVMe: {} initialized, IRQ={}", name, irq);
                NVME_CONTROLLERS.lock().push(Arc::new(Mutex::new(controller)));
                crate::arch::x86_64::idt::register_nvme_irq(irq);
            }
            Err(e) => {
                log::warn!("NVMe: Failed to initialize controller: {:?}", e);
            }
        }
    }

    NVME_INITIALIZED.store(true, Ordering::SeqCst);
    log::info!(
        "[NVMe] Found {} controller(s)",
        NVME_CONTROLLERS.lock().len()
    );
}

pub fn get_first_controller() -> Option<Arc<Mutex<NvmeController>>> {
    NVME_CONTROLLERS.lock().first().cloned()
}

pub fn is_available() -> bool {
    NVME_INITIALIZED.load(Ordering::Relaxed) && !NVME_CONTROLLERS.lock().is_empty()
}

pub fn handle_interrupt() {
    if let Some(ctrl) = get_first_controller() {
        let controller = ctrl.lock();
        controller.handle_interrupt();
    }
}

pub fn list_controllers() -> Vec<String> {
    NVME_CONTROLLERS
        .lock()
        .iter()
        .map(|c| c.lock().name.clone())
        .collect()
}
