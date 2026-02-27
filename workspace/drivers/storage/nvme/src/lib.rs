// NVMe block device driver
// Reference: NVM Express Base Specification 2.0

#![no_std]

extern crate alloc;

mod command;
mod queue;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Mutex;

use command::*;
use queue::QueuePair;

const NVME_PAGE_SIZE: usize = 4096;

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
        unsafe { ptr::write_volatile(&mut self.value, val) }
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
    intms: VolatileCell<u32>,
    intmc: VolatileCell<u32>,
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
        let cap = &regs.capability;

        let dstrd = cap.doorbell_stride() as usize;
        let max_entries = cap.max_queue_entries();
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
        admin
            .submit_command(command)
            .ok_or(NvmeError::IoError)
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

    fn identify(&self, cns: IdentifyCns, nsid: u32) -> Result<*mut u8, NvmeError> {
        let frame = crate::memory::allocate_dma_frame()
            .ok_or(NvmeError::IoError)?;

        let phys = frame.start_address() as u64;
        let virt = crate::memory::phys_to_virt(phys) as *mut u8;

        unsafe {
            ptr::write_bytes(virt, 0, NVME_PAGE_SIZE);
        }

        let cmd = Command {
            identify: IdentifyCommand {
                opcode: AdminOpcode::Identify as u8,
                nsid,
                data_ptr: DataPointer { prp1: phys, prp2: 0 },
                cns: cns as u8,
                ..Default::default()
            },
        };

        let completion = self.submit_admin_command(cmd)?;

        if completion.status_code() != 0 {
            return Err(NvmeError::IoError);
        }

        Ok(virt)
    }

    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        let ctrl_data = self.identify(IdentifyCns::Controller, 0)?;

        let nn = unsafe { ptr::read(ctrl_data.add(520) as *const u32) };

        if nn == 0 {
            return Err(NvmeError::InvalidNamespace);
        }

        for nsid in 1..=nn {
            if let Ok(ns_data) = self.identify(IdentifyCns::Namespace, nsid) {
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

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    pub fn get_namespace(&self, index: usize) -> Option<&NvmeNamespace> {
        self.namespaces.get(index)
    }

    pub fn read(&self, nsid: u32, lba: u64, buffer: &mut [u8]) -> Result<(), NvmeError> {
        if buffer.is_empty() {
            return Ok(());
        }

        let frame = crate::memory::allocate_dma_frame()
            .ok_or(NvmeError::IoError)?;

        let phys = frame.start_address() as u64;
        let virt = crate::memory::phys_to_virt(phys) as *mut u8;

        let blocks = (buffer.len() / 512) as u32;

        let cmd = Command {
            nvm: NvmCommand {
                opcode: CommandOpcode::Read as u8,
                nsid,
                prp1: phys,
                cdw10: (lba & 0xFFFFFFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFFFFFF) as u32,
                cdw12: (blocks - 1) as u32,
                ..Default::default()
            },
        };

        let mut admin = self.admin_queue.lock();
        let completion = admin.submit_command(cmd).ok_or(NvmeError::IoError)?;

        if completion.status_code() != 0 {
            return Err(NvmeError::IoError);
        }

        unsafe {
            ptr::copy_nonoverlapping(virt, buffer.as_mut_ptr(), buffer.len());
        }

        Ok(())
    }

    pub fn write(&self, nsid: u32, lba: u64, buffer: &[u8]) -> Result<(), NvmeError> {
        if buffer.is_empty() {
            return Ok(());
        }

        let frame = crate::memory::allocate_dma_frame()
            .ok_or(NvmeError::IoError)?;

        let phys = frame.start_address() as u64;
        let virt = crate::memory::phys_to_virt(phys) as *mut u8;

        unsafe {
            ptr::copy_nonoverlapping(buffer.as_ptr(), virt, buffer.len());
        }

        let blocks = (buffer.len() / 512) as u32;

        let cmd = Command {
            nvm: NvmCommand {
                opcode: CommandOpcode::Write as u8,
                nsid,
                prp1: phys,
                cdw10: (lba & 0xFFFFFFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFFFFFF) as u32,
                cdw12: (blocks - 1) as u32,
                ..Default::default()
            },
        };

        let mut admin = self.admin_queue.lock();
        let completion = admin.submit_command(cmd).ok_or(NvmeError::IoError)?;

        if completion.status_code() != 0 {
            return Err(NvmeError::IoError);
        }

        Ok(())
    }
}

static NVME_CONTROLLERS: Mutex<Vec<Arc<NvmeController>>> = Mutex::new(Vec::new());

pub fn init() {
    log::info!("[NVMe] Scanning for NVMe controllers...");

    let candidates = crate::arch::x86_64::pci::probe_all(crate::arch::x86_64::pci::ProbeCriteria {
        vendor_id: None,
        device_id: None,
        class_code: Some(crate::arch::x86_64::pci::class::MASS_STORAGE),
        subclass: Some(crate::arch::x86_64::pci::storage_subclass::NVM),
        prog_if: None,
    });

    for (i, pci_dev) in candidates.into_iter().enumerate() {
        log::info!(
            "NVMe: Found controller at {:?} (VEN:{:04x} DEV:{:04x})",
            pci_dev.address,
            pci_dev.vendor_id,
            pci_dev.device_id
        );

        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        let bar = match pci_dev.read_bar(0) {
            Some(crate::arch::x86_64::pci::Bar::Memory64(addr)) => addr,
            _ => {
                log::warn!("NVMe: Invalid BAR0");
                continue;
            }
        };

        let registers = crate::memory::phys_to_virt(bar as usize);

        let name = format!("nvme{}", i);
        match unsafe { NvmeController::new(registers, name) } {
            Ok(controller) => {
                NVME_CONTROLLERS.lock().push(Arc::new(controller));
            }
            Err(e) => {
                log::warn!("NVMe: Failed to initialize controller: {:?}", e);
            }
        }
    }

    let controllers = NVME_CONTROLLERS.lock();
    log::info!("[NVMe] Found {} controller(s)", controllers.len());
}

pub fn get_controller(index: usize) -> Option<Arc<NvmeController>> {
    NVME_CONTROLLERS.lock().get(index).cloned()
}

pub fn get_first_controller() -> Option<Arc<NvmeController>> {
    NVME_CONTROLLERS.lock().first().cloned()
}

pub fn list_controllers() -> Vec<String> {
    NVME_CONTROLLERS
        .lock()
        .iter()
        .map(|c| c.name.clone())
        .collect()
}
