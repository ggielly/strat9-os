// NVMe block device driver
// Reference: NVM Express Base Specification 2.0

use crate::{
    arch::x86_64::pci::{self, Bar, ProbeCriteria},
    memory::{allocate_dma_frame, phys_to_virt},
};
use alloc::string::String;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Mutex;

const NVME_PAGE_SIZE: usize = 4096;

#[repr(transparent)]
struct VolatileCell<T> {
    value: T,
}

impl<T> VolatileCell<T> {
    fn read(&self) -> T where T: Copy {
        unsafe { ptr::read_volatile(&self.value) }
    }
    fn write(&self, val: T) {
        unsafe { ptr::write_volatile(&mut self.value, val) }
    }
}

unsafe impl<T: Send> Send for VolatileCell<T> {}
unsafe impl<T: Sync> Sync for VolatileCell<T> {}

#[repr(C)]
struct Capability { value: VolatileCell<u64> }

impl Capability {
    fn max_queue_entries(&self) -> u16 { (self.value.read() & 0xFFFF) as u16 }
    fn doorbell_stride(&self) -> u64 { (self.value.read() >> 32) & 0xF }
}

#[repr(transparent)]
struct Version { value: VolatileCell<u32> }

#[repr(C)]
struct ControllerConfig { value: VolatileCell<u32> }

impl ControllerConfig {
    fn set_iosqes(&mut self, size: u32) {
        let mut val = self.value.read();
        val |= (size & 0xF) << 16;
        self.value.write(val);
    }
    fn set_iocqes(&mut self, size: u32) {
        let mut val = self.value.read();
        val |= (size & 0xF) << 20;
        self.value.write(val);
    }
    fn set_css(&mut self, css: u32) {
        let mut val = self.value.read();
        val |= (css & 0x7) << 4;
        self.value.write(val);
    }
    fn set_enable(&mut self, enable: bool) {
        let mut val = self.value.read();
        if enable { val |= 1; } else { val &= !1; }
        self.value.write(val);
    }
    fn is_enabled(&self) -> bool { (self.value.read() & 1) != 0 }
}

#[repr(transparent)]
struct ControllerStatus { value: VolatileCell<u32> }

impl ControllerStatus {
    fn is_ready(&self) -> bool { (self.value.read() & 1) != 0 }
    fn is_fatal(&self) -> bool { (self.value.read() >> 1) & 1 != 0 }
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
enum NvmeError { ControllerFatal, Timeout, InvalidNamespace, IoError }

#[derive(Debug, Clone)]
pub struct NvmeNamespace {
    pub nsid: u32,
    pub size: u64,
    pub block_size: u32,
}

pub struct NvmeController {
    registers: usize,
    admin_queue: Mutex<QueuePair>,
    namespaces: Vec<NvmeNamespace>,
    pub name: String,
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
        let mut controller = Self {
            registers,
            admin_queue: Mutex::new(admin_queue),
            namespaces: Vec::new(),
            name,
        };

        controller.init_admin_queue()?;
        controller.identify_namespaces()?;
        Ok(controller)
    }

    fn submit_admin_command(&self, command: Command) -> Result<CompletionEntry, NvmeError> {
        let mut admin = self.admin_queue.lock();
        admin.submit_command(command).ok_or(NvmeError::IoError)
    }

    fn init_admin_queue(&mut self) -> Result<(), NvmeError> {
        let regs = unsafe { &*(self.registers as *const Registers) };
        let admin_sq_phys = self.admin_queue.lock().submission_phys();
        let admin_cq_phys = self.admin_queue.lock().completion_phys();

        regs.aqa.write((1023 & 0xFFF) | ((1023 & 0xFFF) << 16));
        regs.asq.write(admin_sq_phys);
        regs.acq.write(admin_cq_phys);

        let mut cc = regs.cc;
        cc.set_css(0);
        cc.set_iosqes(6);
        cc.set_iocqes(6);
        cc.set_enable(true);

        let mut timeout = 1_000_000;
        while !regs.csts.is_ready() {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 { return Err(NvmeError::Timeout); }
        }

        if regs.csts.is_fatal() { return Err(NvmeError::ControllerFatal); }

        log::info!(
            "NVMe: Controller v{}.{}.{} ready",
            regs.version.value.read() >> 16,
            (regs.version.value.read() >> 8) & 0xFF,
            regs.version.value.read() & 0xFF
        );
        Ok(())
    }

    fn identify(&self, cns: u8, nsid: u32) -> Result<*mut u8, NvmeError> {
        let frame = allocate_dma_frame().ok_or(NvmeError::IoError)?;
        let phys = frame.start_address();
        let virt = phys_to_virt(phys) as *mut u8;
        unsafe { ptr::write_bytes(virt, 0, NVME_PAGE_SIZE); }

        let cmd = Command {
            opcode: 0x06,
            nsid,
            prp1: phys,
            cns,
            ..Default::default()
        };

        let completion = self.submit_admin_command(cmd)?;
        if completion.status_code() != 0 { return Err(NvmeError::IoError); }
        Ok(virt)
    }

    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        let ctrl_data = self.identify(0x01, 0)?;
        let nn = unsafe { ptr::read(ctrl_data.add(520) as *const u32) };
        if nn == 0 { return Err(NvmeError::InvalidNamespace); }

        for nsid in 1..=nn {
            if let Ok(ns_data) = self.identify(0x00, nsid) {
                unsafe {
                    let nsze = ptr::read(ns_data.add(16) as *const u64);
                    let flbas = ptr::read(ns_data.add(26) as *const u8) as usize;
                    let lbaf_index = flbas & 0xF;
                    let lbaf_offset = 128 + lbaf_index * 16;
                    let lbaf_data = ptr::read(ns_data.add(lbaf_offset) as *const u16);
                    let block_size = (1 << lbaf_data) as u32;

                    self.namespaces.push(NvmeNamespace { nsid, size: nsze, block_size });
                    log::info!("NVMe: Namespace {} - {} blocks @ {} bytes", nsid, nsze, block_size);
                }
            }
        }
        Ok(())
    }

    pub fn namespace_count(&self) -> usize { self.namespaces.len() }
    pub fn get_namespace(&self, index: usize) -> Option<&NvmeNamespace> { self.namespaces.get(index) }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Command {
    opcode: u8, flags: u8, command_id: u16, nsid: u32,
    cdw2: u32, cdw3: u32, prp1: u64, prp2: u64,
    cdw10: u32, cdw11: u32, cdw12: u32, cdw13: u32, cdw14: u32, cdw15: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CompletionEntry {
    dw0: u32, dw1: u32, sq_head: u16, sq_id: u16,
    command_id: u16, status: u16,
}

impl CompletionEntry {
    fn status_code(&self) -> u8 { ((self.status >> 1) & 0xFF) as u8 }
}

struct QueuePair {
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
    phase: bool,
    phys_addr: u64,
}

impl<T: QueueType> Queue<T> {
    fn new(registers_base: usize, size: usize, queue_id: u16, dstrd: usize) -> Self {
        let doorbell_offset = 0x1000 + ((((queue_id as usize) * 2) + T::DOORBELL_OFFSET) * (4 << dstrd));
        let doorbell = unsafe { &*((registers_base + doorbell_offset) as *const VolatileCell<u32>) };

        let frame = allocate_dma_frame().expect("NVMe: failed to allocate queue frame");
        let phys_addr = frame.start_address();
        let virt_addr = phys_to_virt(phys_addr);

        unsafe { ptr::write_bytes(virt_addr as *mut u8, 0, size * core::mem::size_of::<T::EntryType>()); }

        Self { doorbell, entries: virt_addr as *mut T::EntryType, size, phase: true, phys_addr }
    }

    fn phys_addr(&self) -> u64 { self.phys_addr }
}

impl Queue<Completion> {
    fn poll_completion(&mut self) -> Option<CompletionEntry> {
        unsafe {
            let entry = &*self.entries.add(self.index);
            let status = entry.status;
            if ((status & 0x1) != 0) == self.phase {
                let completion = ptr::read(entry);
                if (completion.status >> 9) & 0x7 != 0 || (completion.status >> 1) & 0xFF != 0 {
                    log::error!("NVMe: completion error");
                    return None;
                }
                self.index = (self.index + 1) % self.size;
                if self.index == 0 { self.phase = !self.phase; }
                (*self.doorbell).write(self.index as u32);
                Some(completion)
            } else { None }
        }
    }
}

impl Queue<Submission> {
    fn submit_command(&mut self, command: Command, idx: usize) {
        unsafe { ptr::write(self.entries.add(idx), command); }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        (*self.doorbell).write(((idx + 1) % self.size) as u32);
    }
}

impl QueuePair {
    fn new(registers_base: usize, size: usize, dstrd: usize) -> Self {
        static NEXT_ID: AtomicU8 = AtomicU8::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst) as u16;
        Self {
            id, size, command_id: 0,
            submission: Queue::new(registers_base, size, id, dstrd),
            completion: Queue::new(registers_base, size, id, dstrd),
        }
    }

    fn submission_phys(&self) -> u64 { self.submission.phys_addr() }
    fn completion_phys(&self) -> u64 { self.completion.phys_addr() }

    fn submit_command(&mut self, command: Command) -> Option<CompletionEntry> {
        let slot = self.command_id as usize % self.size;
        let mut cmd = command;
        unsafe { ptr::write(&mut cmd.command_id as *mut u16, self.command_id); }
        self.command_id = self.command_id.wrapping_add(1);
        self.submission.submit_command(cmd, slot);
        loop {
            if let Some(c) = self.completion.poll_completion() { return Some(c); }
            core::hint::spin_loop();
        }
    }
}

static NVME_CONTROLLERS: Mutex<Vec<Arc<NvmeController>>> = Mutex::new(Vec::new());

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
        log::info!("NVMe: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address, pci_dev.vendor_id, pci_dev.device_id);

        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        let bar = match pci_dev.read_bar(0) {
            Some(Bar::Memory64(addr)) => addr,
            _ => { log::warn!("NVMe: Invalid BAR0"); continue; }
        };

        let registers = phys_to_virt(bar) as usize;
        let name = format!("nvme{}", i);

        match unsafe { NvmeController::new(registers, name) } {
            Ok(controller) => {
                NVME_CONTROLLERS.lock().push(Arc::new(controller));
            }
            Err(e) => { log::warn!("NVMe: Failed to initialize controller: {:?}", e); }
        }
    }

    log::info!("[NVMe] Found {} controller(s)", NVME_CONTROLLERS.lock().len());
}

pub fn get_first_controller() -> Option<Arc<NvmeController>> {
    NVME_CONTROLLERS.lock().first().cloned()
}

pub fn list_controllers() -> Vec<String> {
    NVME_CONTROLLERS.lock().iter().map(|c| c.name.clone()).collect()
}
