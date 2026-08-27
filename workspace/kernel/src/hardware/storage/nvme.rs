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
const MAX_PRP_ENTRIES: usize = NVME_PAGE_SIZE / 8; // 512 entries per PRP list page

const ADMIN_CQE_ERROR: u16 = (0x1 << 14) | (0x1 << 10);

// =========================================================================
// TSC-based timeout helpers
// =========================================================================

/// Read the TSC (Time Stamp Counter).
#[inline]
fn rdtsc() -> u64 {
    unsafe { crate::arch::rdtsc() }
}

/// Convert TSC ticks to approximate milliseconds (assumes ~3GHz TSC).
/// For exact calibration, use the kernel's TSC frequency if available.
fn tsc_to_ms(ticks: u64) -> u64 {
    // Rough: 3GHz TSC → 3_000_000 ticks per ms
    ticks / 3_000_000
}

/// Get a TSC deadline for `ms` milliseconds from now.
fn tsc_deadline_ms(ms: u32) -> u64 {
    rdtsc().wrapping_add((ms as u64) * 3_000_000)
}

/// Check if a TSC deadline has expired.
fn tsc_expired(deadline: u64) -> bool {
    rdtsc() >= deadline
}

/// Read a 64-bit register from the NVMe controller.
unsafe fn regs_read64(base: usize, offset: u64) -> u64 {
    let low = core::ptr::read_volatile((base + offset as usize) as *const u32) as u64;
    let high = core::ptr::read_volatile((base + offset as usize + 4) as *const u32) as u64;
    low | (high << 32)
}

/// Build PRP (Physical Region Page) list for a physically contiguous buffer.
///
/// Returns (prp1, prp2):
/// - If the buffer fits in a single page: prp1 = buf_phys, prp2 = 0
/// - If the buffer spans multiple pages: prp1 = buf_phys, prp2 = PRP list phys addr
///
/// The caller must ensure `buf_phys` is page-aligned and the buffer is physically
/// contiguous for multi-page transfers.
unsafe fn build_prp_list(buf_phys: u64, byte_count: usize) -> (u64, u64) {
    let first_page_remaining = NVME_PAGE_SIZE - (buf_phys as usize % NVME_PAGE_SIZE);
    if byte_count <= first_page_remaining {
        return (buf_phys, 0);
    }

    // Allocate a PRP list page
    let prp_frame = allocate_zeroed_frame().expect("NVMe: failed to allocate PRP list");
    let prp_phys = prp_frame.start_address.as_u64();
    paging::ensure_identity_map_range(prp_phys, NVME_PAGE_SIZE as u64);
    let prp_virt = phys_to_virt(prp_phys) as *mut u64;

    // First page covers buf_phys..end_of_first_page
    let mut remaining = byte_count - first_page_remaining;
    let mut next_phys = (buf_phys & !0xFFF) + NVME_PAGE_SIZE as u64;
    let mut idx = 0;

    while remaining > 0 && idx < MAX_PRP_ENTRIES {
        core::ptr::write_volatile(prp_virt.add(idx), next_phys);
        idx += 1;
        next_phys += NVME_PAGE_SIZE as u64;
        remaining = remaining.saturating_sub(NVME_PAGE_SIZE);
    }

    (buf_phys, prp_phys)
}

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
    asq_low: VolatileCell<u32>,
    asq_high: VolatileCell<u32>,
    acq_low: VolatileCell<u32>,
    acq_high: VolatileCell<u32>,
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

/// LBA Format descriptor (4 bytes each, starting at byte 128 of Identify Namespace).
#[repr(C)]
#[derive(Copy, Clone)]
struct LbaFormat {
    _metadata_size: u16,
    lbads: u8,
    _relative_perf: u8,
}

/// Identify Namespace data (first 384 bytes needed).
/// Layout per NVMe spec: bytes 0-73 are explicit fields, 74-127 reserved, 128-383 LBAF[0..64].
#[repr(C)]
#[derive(Copy, Clone)]
struct IdentifyNamespaceData {
    nsze: u64,
    _ncap: u64,
    _nuse: u64,
    _nsfeat: u8,
    _nlbaf: u8,
    flbas: u8,
    _mc: u8,
    _dpc: u8,
    _dps: u8,
    _nmic: u8,
    _rescap: u8,
    _fpi: u8,
    _dlfeat: u8,
    _nawun: u16,
    _nawupf: u16,
    _nacwu: u16,
    _nabsn: u16,
    _nabo: u16,
    _nabspf: u16,
    _noiob: u16,
    _nvmcap: [u64; 2],
    _npwg: u16,
    _npwa: u16,
    _npdg: u16,
    _npda: u16,
    _nows: u16,
    _reserved: [u8; 54], // bytes 74-127
    /// LBA Format Support : 64 entries × 4 bytes at offset 128
    lbaf: [LbaFormat; 64],
}

/// Identify Controller data (partial : fields we need).
#[repr(C)]
#[derive(Copy, Clone)]
struct IdentifyControllerData {
    _vid: u16,
    _ssvid: u16,
    _sn: [u8; 20],
    _mn: [u8; 40],
    _fr: [u8; 8],
    _rab: u8,
    _ieee: [u8; 3],
    _cmic: u8,
    mdts: u8,
    _cntlid: u16,
    _ver: u32,
    _rtd3r: u32,
    _rtd3e: u32,
    _oaes: u32,
    _ctratt: u32,
    _reserved0: [u8; 100],
    _oacs: u16,
    _acl: u8,
    _aerl: u8,
    _frmw: u8,
    _lpa: u8,
    _elpe: u8,
    _npss: u8,
    _avscc: u8,
    _apsta: u8,
    _wctemp: u16,
    _cctemp: u16,
    _reserved1: [u8; 242],
    sqes: u8,
    cqes: u8,
    _maxcmd: u16,
    nn: u32,
    _oncs: u16,
    _fuses: u16,
    _fna: u8,
    _vwc: u8,
    _awun: u16,
    _awupf: u16,
    _icsvscc: u8,
    _nwpc: u8,
    _acwu: u16,
    _cdfs: u16,
    _sgls: u32,
    _reserved2: [u8; 228],
    _subnqn: [u8; 256],
    _reserved3: [u8; 1024],
    _psd: [[u8; 32]; 32],
    _vs: [u8; 1024],
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

        let io_done: Box<[AtomicBool]> = (0..MAX_IO_COMMANDS)
            .map(|_| AtomicBool::new(false))
            .collect();

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

        log::info!("NVMe init: queue_size={} qsz={}", queue_size, qsz);
        log::info!(
            "NVMe init: ASQ phys={:#x} ACQ phys={:#x}",
            admin_sq_phys,
            admin_cq_phys
        );

        // Step 1: Disable controller if it's already enabled
        let cc_val = regs.cc.value.read();
        let csts_val = regs.csts.value.read();
        log::info!("NVMe init: CC={:#010x} CSTS={:#010x}", cc_val, csts_val);

        if cc_val & 1 != 0 {
            log::info!("NVMe init: controller enabled, disabling...");

            // Some AMD NVMe controllers (e.g. on Lenovo X13) hang if we send
            // SHN (shutdown notification) before clearing CC.EN.  The safe
            // approach for re-initialisation is to skip SHN and just write
            // CC.EN=0 directly.  This matches Linux's nvme_disable_ctrl().
            regs.cc.set_enable(false);
            log::info!("NVMe init: wrote CC.EN=0 (no SHN), waiting for CSTS.RDY...");

            // Wait for CSTS.RDY (bit 0) to clear : up to 5.5 s per NVMe spec.
            // Use a generous timeout; some AMD controllers are slow to respond.
            let deadline = tsc_deadline_ms(5500);
            let mut log_count = 0u32;
            loop {
                let csts = regs.csts.value.read();
                if csts & 1 == 0 {
                    log::info!("NVMe init: controller disabled, CSTS={:#x}", csts);
                    break;
                }
                if tsc_expired(deadline) {
                    log::warn!("NVMe init: RDY timeout, CSTS={:#x} : forcing CC=0", csts);

                    // Last resort: write CC=0x00000000
                    regs.cc.value.write(0x0000_0000);
                    log::info!("NVMe init: wrote CC=0x00000000 (full reset)");
                    let force_deadline = tsc_deadline_ms(3000);
                    while !tsc_expired(force_deadline) {
                        let c = regs.csts.value.read();
                        if c & 1 == 0 {
                            log::info!("NVMe init: forced disable OK, CSTS={:#x}", c);
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    break;
                }
                core::hint::spin_loop();
                log_count += 1;
                if log_count % 2_000_000 == 0 {
                    log::info!(
                        "NVMe init: still waiting... CSTS={:#x}",
                        regs.csts.value.read()
                    );
                }
            }
        } else {
            log::info!("NVMe init: controller already disabled");
        }

        // Small delay after disable ; some AMD controllers need this before
        // admin queue registers become writable.
        let settle = tsc_deadline_ms(2);
        while !tsc_expired(settle) {
            core::hint::spin_loop();
        }

        // Step 2: Verify CSTS
        let csts = regs.csts.value.read();
        log::info!("NVMe init: CSTS={:#x}", csts);
        if csts & 2 != 0 {
            log::error!("NVMe init: CSTS.CFS (fatal) set!");
            return Err(NvmeError::ControllerFatal);
        }

        // Step 3: Write admin queue registers (32-bit writes, like Redox/MaestroOS)
        log::info!("NVMe init: writing AQA={:#x}...", qsz | (qsz << 16));
        regs.aqa.write(qsz | (qsz << 16));
        log::info!("NVMe init: writing ASQ={:#x}...", admin_sq_phys);
        regs.asq_low.write(admin_sq_phys as u32);
        regs.asq_high.write((admin_sq_phys >> 32) as u32);
        log::info!("NVMe init: writing ACQ={:#x}...", admin_cq_phys);
        regs.acq_low.write(admin_cq_phys as u32);
        regs.acq_high.write((admin_cq_phys >> 32) as u32);

        // Step 4: Configure CC
        log::info!("NVMe init: configuring CC...");
        regs.cc.clear_io_fields();
        regs.cc.set_css(0); // NVM Command Set
        regs.cc.set_iosqes(6); // 2^6 = 64 byte submission queue entries
        regs.cc.set_iocqes(6); // 2^6 = 64 byte completion queue entries
        log::info!("NVMe init: CC={:#010x} (configured)", regs.cc.value.read());

        // Step 5: Enable controller
        log::info!("NVMe init: enabling controller...");
        regs.cc.set_enable(true);
        log::info!("NVMe init: CC={:#010x} (EN=1)", regs.cc.value.read());

        // Step 6: Wait for CSTS.RDY (up to 5.5s per NVMe spec)
        let deadline = tsc_deadline_ms(5500);
        let mut log_interval = 0u32;
        loop {
            let csts = regs.csts.value.read();
            if csts & 1 != 0 {
                log::info!("NVMe init: controller ready, CSTS={:#x}", csts);
                break;
            }
            if tsc_expired(deadline) {
                log::error!("NVMe init: enable timeout! CSTS={:#x}", csts);
                return Err(NvmeError::Timeout);
            }
            core::hint::spin_loop();
            log_interval += 1;
            if log_interval % 500_000 == 0 {
                log::info!("NVMe init: waiting for ready... CSTS={:#x}", csts);
            }
        }

        let csts = regs.csts.value.read();
        log::info!("NVMe init: final CSTS={:#x}", csts);

        if csts & 2 != 0 {
            log::error!("NVMe init: controller fatal error!");
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

        log::info!(
            "NVMe I/O queues: size={} qsz={} SQ={:#x} CQ={:#x}",
            queue_size,
            qsz,
            io_sq_phys,
            io_cq_phys
        );

        log::info!("NVMe I/O: sending Set Features (IRQ coalescing)...");
        let set_feature_cmd = Command {
            opcode: 0x09,
            cdw10: 0x07,
            cdw11: 0x0100_0000,
            ..Default::default()
        };
        self.submit_admin_command(set_feature_cmd).ok();

        log::info!("NVMe I/O: creating I/O CQ...");
        // NVMe spec CDW10: bits 15:0=QID, bits 31:16=QSIZE(0-based)
        // NVMe spec CDW11: bit 0=PCIE, bit 1=IEN, bits 31:16=IV
        let cq_cmd = Command {
            opcode: 0x05,
            cdw10: qsz << 16,   // QID=0 in bits 15:0, QSIZE in bits 31:16
            cdw11: 0x0000_0003, // PCIE=1, IEN=1
            prp1: io_cq_phys,
            ..Default::default()
        };
        match self.submit_admin_command(cq_cmd) {
            Ok(c) => {
                if c.status_code() != 0 {
                    log::warn!("NVMe: Create I/O CQ failed: status={}", c.status_code());
                } else {
                    log::info!("NVMe I/O: CQ created OK");
                }
            }
            Err(e) => {
                log::warn!("NVMe: Create I/O CQ error: {:?}", e);
                return Err(e);
            }
        }

        log::info!("NVMe I/O: creating I/O SQ...");
        // NVMe spec CDW10: bits 15:0=QID, bits 31:16=QSIZE(0-based)
        // NVMe spec CDW11: bit 0=PCIE, bits 31:16=CQID
        let sq_cmd = Command {
            opcode: 0x01,
            cdw10: (qsz << 16) | 1, // QID=1 in bits 15:0, QSIZE in bits 31:16
            cdw11: (1 << 16) | 0x0000_0001, // CQID=1 in bits 31:16, PCIE=1
            prp1: io_sq_phys,
            ..Default::default()
        };
        match self.submit_admin_command(sq_cmd) {
            Ok(c) => {
                if c.status_code() != 0 {
                    log::warn!("NVMe: Create I/O SQ failed: status={}", c.status_code());
                } else {
                    log::info!("NVMe I/O: SQ created OK");
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

    fn identify(&self, cns: u8, nsid: u32) -> Result<Vec<u8>, NvmeError> {
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

        // Copy data to owned Vec before the DMA frame is freed.
        let mut data = Vec::with_capacity(NVME_PAGE_SIZE);
        unsafe {
            for i in 0..NVME_PAGE_SIZE {
                data.push(ptr::read_volatile(virt.add(i)));
            }
        }
        // frame dropped here → physical memory freed
        Ok(data)
    }

    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        // Step 1: Identify Controller : get NN, MDTS, SQES, CQES, and info
        let ctrl_data = self.identify(0x01, 0)?;
        let ctrl = unsafe { core::ptr::read(ctrl_data.as_ptr() as *const IdentifyControllerData) };
        let nn = ctrl.nn;
        let mdts = ctrl.mdts;

        // Validate SQES/CQES (like MaestroOS)
        let min_sqes = ctrl.sqes & 0xF;
        let max_sqes = (ctrl.sqes >> 4) & 0xF;
        let min_cqes = ctrl.cqes & 0xF;
        let max_cqes = (ctrl.cqes >> 4) & 0xF;
        let our_sqes = 6u8; // 2^6 = 64 bytes
        let our_cqes = 4u8; // 2^4 = 16 bytes

        if our_sqes < min_sqes || our_sqes > max_sqes {
            log::warn!(
                "NVMe: SQES {} not in range [{}..{}] : controller may reject commands",
                our_sqes,
                min_sqes,
                max_sqes
            );
        }
        if our_cqes < min_cqes || our_cqes > max_cqes {
            log::warn!(
                "NVMe: CQES {} not in range [{}..{}] : controller may reject completions",
                our_cqes,
                min_cqes,
                max_cqes
            );
        }

        // Validate page size against CAP (like MaestroOS)
        let cap = unsafe { regs_read64(self.registers, 0x00) };
        let mpsmin = ((cap >> 48) & 0xF) as u32 + 12; // log2 of min page size
        let mpsmax = ((cap >> 52) & 0xF) as u32 + 12; // log2 of max page size
        let our_mps = 12u32; // 4096 bytes
        if our_mps < mpsmin || our_mps > mpsmax {
            log::warn!(
                "NVMe: Page size {} not in range [{}..{}] bytes",
                1 << our_mps,
                1 << mpsmin,
                1 << mpsmax
            );
        }

        log::info!(
            "NVMe: Controller NN={} MDTS={} SQES={:#x} CQES={:#x} MPS=[{}..{}]",
            nn,
            mdts,
            ctrl.sqes,
            ctrl.cqes,
            1 << mpsmin,
            1 << mpsmax
        );

        if nn == 0 {
            return Err(NvmeError::InvalidNamespace);
        }

        // Step 2: Identify Active Namespace ID List (CNS=2)
        let ns_list = self.identify(0x02, 0)?;
        let ns_list_words = unsafe {
            core::slice::from_raw_parts(ns_list.as_ptr() as *const u32, ns_list.len() / 4)
        };
        let mut active_nsids: Vec<u32> = Vec::new();
        for &word in ns_list_words.iter() {
            if word == 0 {
                break;
            }
            active_nsids.push(word);
        }
        log::info!("NVMe: {} active namespace(s)", active_nsids.len());

        // Step 3: Identify each active namespace
        for nsid in &active_nsids {
            if let Ok(ns_data) = self.identify(0x00, *nsid) {
                let ns =
                    unsafe { core::ptr::read(ns_data.as_ptr() as *const IdentifyNamespaceData) };

                let flbas = ns.flbas as usize;
                let lbaf_idx = flbas & 0xF;
                let lbads = ns.lbaf[lbaf_idx].lbads;
                let block_size = 1u32 << lbads;

                self.namespaces.push(NvmeNamespace {
                    nsid: *nsid,
                    size: ns.nsze,
                    block_size,
                });
                log::info!(
                    "NVMe: NSID {} - {} blocks @ {} bytes (LBADS={}, FLBAS={:#x})",
                    nsid,
                    ns.nsze,
                    block_size,
                    lbads,
                    flbas
                );
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

        let idx = cmd_id as usize % MAX_IO_COMMANDS;
        self.io_done[idx].store(false, Ordering::SeqCst);

        unsafe {
            ptr::write(io.submission.entries.add(slot), *command);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            (*io.submission.doorbell).write(((slot + 1) % io.size) as u32);
        }

        Ok(cmd_id)
    }

    pub fn read_blocks(
        &self,
        nsid: u32,
        lba: u64,
        block_count: u32,
        buf_phys: u64,
    ) -> Result<(), NvmeError> {
        let byte_count = block_count as usize * 512;
        let (prp1, prp2) = unsafe { build_prp_list(buf_phys, byte_count) };

        let cmd_id = {
            let mut cmd = Command {
                opcode: 0x02,
                nsid,
                prp1,
                prp2,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: (block_count - 1),
                ..Default::default()
            };
            self.submit_io_command(&mut cmd)?
        };

        let idx = cmd_id as usize % MAX_IO_COMMANDS;

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
        let byte_count = block_count as usize * 512;
        let (prp1, prp2) = unsafe { build_prp_list(buf_phys, byte_count) };

        let cmd_id = {
            let mut cmd = Command {
                opcode: 0x01,
                nsid,
                prp1,
                prp2,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: (block_count - 1),
                ..Default::default()
            };
            self.submit_io_command(&mut cmd)?
        };

        let idx = cmd_id as usize % MAX_IO_COMMANDS;

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
        let deadline = tsc_deadline_ms(5500); // NVMe spec: up to 5.5s for admin commands
        loop {
            if let Some(c) = self.completion.poll_completion() {
                return Some(c);
            }
            if tsc_expired(deadline) {
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
                NVME_CONTROLLERS
                    .lock()
                    .push(Arc::new(Mutex::new(controller)));
                crate::arch::idt::register_nvme_irq(irq);
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
