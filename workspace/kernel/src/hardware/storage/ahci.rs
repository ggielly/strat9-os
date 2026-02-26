//! AHCI (Advanced Host Controller Interface) driver — AHCI spec 1.3.1
//!
//! PCI: class=0x01 (Mass Storage), subclass=0x06 (SATA), prog_if=0x01
//! MMIO base: BAR5 (ABAR)
//!
//! Per-port memory layout (packed into one 4 KB page):
//!   [0x000..0x3FF]  Command List   (1024 B, 32 × 32-byte headers)
//!   [0x400..0x4FF]  FIS receive    (256 B)
//!   [0x500..0x5FF]  Command table  (128 B header + 1 × 16-byte PRDT)

use crate::{
    arch::x86_64::pci::{self, ProbeCriteria},
    memory::{buddy::get_allocator, phys_to_virt, FrameAllocator, PhysFrame},
    sync::SpinLock,
};
use alloc::{boxed::Box, vec::Vec};
use core::ptr;

pub use super::virtio_block::{BlockDevice, BlockError, SECTOR_SIZE};

// ─── HBA generic registers (at ABAR) ─────────────────────────────────────────
const HBA_GHC: u64 = 0x04;
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0C;

const GHC_AE: u32 = 1 << 31; // AHCI Enable
const GHC_HR: u32 = 1 << 0; // HBA Reset

// ─── Port register offsets (relative to port base = ABAR + 0x100 + n*0x80) ──
const PORT_CLB: u64 = 0x00;
const PORT_CLBU: u64 = 0x04;
const PORT_FB: u64 = 0x08;
const PORT_FBU: u64 = 0x0C;
const PORT_IS: u64 = 0x10;
const PORT_CMD: u64 = 0x18;
const PORT_TFD: u64 = 0x20;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
const PORT_SERR: u64 = 0x30;
const PORT_CI: u64 = 0x38;

const CMD_ST: u32 = 1 << 0; // Start
const CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const CMD_FR: u32 = 1 << 14; // FIS Receive Running
const CMD_CR: u32 = 1 << 15; // Command List Running

const TFD_BSY: u32 = 1 << 7;
const TFD_DRQ: u32 = 1 << 3;

const SSTS_DET_COMM: u32 = 3;
const SSTS_DET_MASK: u32 = 0xF;

const SIG_SATA: u32 = 0x0000_0101;

// ─── Per-port memory layout offsets ──────────────────────────────────────────
const CLB_OFF: u64 = 0x000; // Command List (1024 B)
const FB_OFF: u64 = 0x400; // FIS buffer   (256 B)
const CTAB_OFF: u64 = 0x500; // Command Table (128 B header + 16 B PRDT)

// Command header field byte offsets within a 32-byte slot
const CMDH_FLAGS: usize = 0; // u16: cfl[4:0] | a | w | p | r | b | c
const CMDH_PRDTL: usize = 2; // u16
const CMDH_CTBA: usize = 8; // u32
const CMDH_CTBAU: usize = 12; // u32

// Command table FIS and PRDT offsets
const CTAB_CFIS: usize = 0x00; // H2D FIS (64 B allocated)
const CTAB_PRDT: usize = 0x80; // PRDT entries

// H2D FIS field offsets (FIS type 0x27, Register Host-to-Device)
const FIS_TYPE: usize = 0;
const FIS_FLAGS: usize = 1; // PM port [3:0] | C [7]
const FIS_CMD: usize = 2;
const FIS_LBA0: usize = 4;
const FIS_LBA1: usize = 5;
const FIS_LBA2: usize = 6;
const FIS_DEVICE: usize = 7;
const FIS_LBA3: usize = 8;
const FIS_LBA4: usize = 9;
const FIS_LBA5: usize = 10;
const FIS_CNT_LO: usize = 12;
const FIS_CNT_HI: usize = 13;

const FIS_TYPE_H2D: u8 = 0x27;
const FIS_C_BIT: u8 = 0x80; // command (not control)
const FIS_LBA_MODE: u8 = 1 << 6;

// ATA commands (48-bit LBA)
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;

// PxIS bit 30 = Task File Error Status
const PxIS_TFES: u32 = 1 << 30;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AhciError {
    #[error("no AHCI controller on PCI bus")]
    NoController,
    #[error("invalid BAR5 (ABAR)")]
    BadAbar,
    #[error("physical memory allocation failed")]
    Alloc,
    #[error("port BSY/DRQ set")]
    Busy,
    #[error("command timed out")]
    Timeout,
    #[error("device reported task-file error")]
    DeviceError,
    #[error("invalid sector number")]
    InvalidSector,
    #[error("buffer too small (need ≥ SECTOR_SIZE bytes)")]
    BufferTooSmall,
    #[error("no usable SATA port found")]
    NoPort,
}

// ─── Internal port handle ─────────────────────────────────────────────────────

struct AhciPort {
    port_num: u8,
    port_virt: u64, // virtual address of port registers
    mem_phys: u64,  // physical base of the per-port CLB/FB/CTAB frame
    mem_virt: u64,  // HHDM virtual address of that frame
    sector_count: u64,
}

// ─── Controller ──────────────────────────────────────────────────────────────

pub struct AhciController {
    abar_virt: u64,
    ports: Vec<AhciPort>,
}

// SAFETY: AhciController is only accessed behind SpinLock<Option<...>>
unsafe impl Send for AhciController {}
unsafe impl Sync for AhciController {}

// ─── MMIO helpers ─────────────────────────────────────────────────────────────

#[inline]
unsafe fn rd32(base: u64, off: u64) -> u32 {
    ptr::read_volatile((base + off) as *const u32)
}

#[inline]
unsafe fn wr32(base: u64, off: u64, val: u32) {
    ptr::write_volatile((base + off) as *mut u32, val);
}

// ─── Port start/stop ──────────────────────────────────────────────────────────

fn port_stop(pvirt: u64) {
    // SAFETY: pvirt is a valid MMIO virtual address for this port's registers
    unsafe {
        let mut cmd = rd32(pvirt, PORT_CMD);
        cmd &= !(CMD_ST | CMD_FRE);
        wr32(pvirt, PORT_CMD, cmd);
        // Spec mandates waiting ≤ 500 ms for FR and CR to clear
        for _ in 0..500_000u32 {
            if rd32(pvirt, PORT_CMD) & (CMD_FR | CMD_CR) == 0 {
                return;
            }
            core::hint::spin_loop();
        }
        log::warn!("AHCI: port stop timed out (port registers @ {:#x})", pvirt);
    }
}

fn port_start(pvirt: u64) {
    // SAFETY: pvirt is a valid MMIO virtual address
    unsafe {
        // Ensure Command List Running is clear before asserting ST
        while rd32(pvirt, PORT_CMD) & CMD_CR != 0 {
            core::hint::spin_loop();
        }
        let mut cmd = rd32(pvirt, PORT_CMD);
        cmd |= CMD_FRE | CMD_ST;
        wr32(pvirt, PORT_CMD, cmd);
    }
}

/// Rebase port: assign our CLB/FB buffers then start the port.
fn port_rebase(pvirt: u64, phys: u64) {
    port_stop(pvirt);
    // SAFETY: pvirt valid MMIO; phys is our allocated frame
    unsafe {
        let clb = phys + CLB_OFF;
        let fb = phys + FB_OFF;
        wr32(pvirt, PORT_CLB, (clb & 0xFFFF_FFFF) as u32);
        wr32(pvirt, PORT_CLBU, (clb >> 32) as u32);
        wr32(pvirt, PORT_FB, (fb & 0xFFFF_FFFF) as u32);
        wr32(pvirt, PORT_FBU, (fb >> 32) as u32);
        // Clear any stale interrupt/error status
        wr32(pvirt, PORT_IS, 0xFFFF_FFFF);
        wr32(pvirt, PORT_SERR, 0xFFFF_FFFF);
    }
    port_start(pvirt);
}

// ─── Bounce-buffer management ─────────────────────────────────────────────────

struct Bounce {
    frame: PhysFrame,
    order: u8,
    phys: u64,
    virt: u64,
}

impl Bounce {
    fn alloc(bytes: usize) -> Result<Self, AhciError> {
        let pages = (bytes + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let mut lock = get_allocator().lock();
        let frame = lock
            .as_mut()
            .ok_or(AhciError::Alloc)?
            .alloc(order)
            .map_err(|_| AhciError::Alloc)?;
        let phys = frame.start_address.as_u64();
        Ok(Self {
            frame,
            order,
            phys,
            virt: phys_to_virt(phys),
        })
    }

    fn free(self) {
        let mut lock = get_allocator().lock();
        if let Some(a) = lock.as_mut() {
            a.free(self.frame, self.order);
        }
    }
}

// ─── Command submission (polled, single slot 0) ───────────────────────────────

fn submit_cmd(
    port: &AhciPort,
    lba: u64,
    count: u16,
    buf: &mut [u8],
    write: bool,
    ata_cmd: u8,
) -> Result<(), AhciError> {
    let nbytes = (count as usize) * SECTOR_SIZE;
    if buf.len() < nbytes {
        return Err(AhciError::BufferTooSmall);
    }

    // SAFETY: MMIO read to check device readiness
    let tfd = unsafe { rd32(port.port_virt, PORT_TFD) };
    if tfd & (TFD_BSY | TFD_DRQ) != 0 {
        return Err(AhciError::Busy);
    }

    let bounce = Bounce::alloc(nbytes)?;

    if write {
        // SAFETY: bounce.virt is a valid HHDM address ≥ nbytes; buf.len() ≥ nbytes
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), bounce.virt as *mut u8, nbytes);
        }
    }

    let ctab_phys = port.mem_phys + CTAB_OFF;
    let cmdh_virt = port.mem_virt + CLB_OFF; // slot 0 = first 32 bytes of CLB
    let ctab_virt = port.mem_virt + CTAB_OFF;

    // SAFETY: cmdh_virt and ctab_virt point to our allocated frame (physically valid)
    unsafe {
        // --- Command header (slot 0, 32 bytes) ---
        let h = cmdh_virt as *mut u8;
        ptr::write_bytes(h, 0, 32);

        // CFL = 5 (H2D FIS = 20 B = 5 DWORDs); W bit set for writes
        let flags: u16 = 5u16 | (if write { 1 << 6 } else { 0 });
        ptr::write_unaligned(h.add(CMDH_FLAGS) as *mut u16, flags.to_le());
        ptr::write_unaligned(h.add(CMDH_PRDTL) as *mut u16, 1u16.to_le()); // 1 PRDT entry
        ptr::write_unaligned(
            h.add(CMDH_CTBA) as *mut u32,
            (ctab_phys & 0xFFFF_FFFF) as u32,
        );
        ptr::write_unaligned(h.add(CMDH_CTBAU) as *mut u32, (ctab_phys >> 32) as u32);

        // --- Command table ---
        let t = ctab_virt as *mut u8;
        ptr::write_bytes(t, 0, CTAB_PRDT + 16);

        // H2D Register FIS (20 bytes at CFIS offset)
        let f = t.add(CTAB_CFIS);
        *f.add(FIS_TYPE) = FIS_TYPE_H2D;
        *f.add(FIS_FLAGS) = FIS_C_BIT;
        *f.add(FIS_CMD) = ata_cmd;
        *f.add(FIS_LBA0) = (lba & 0xFF) as u8;
        *f.add(FIS_LBA1) = ((lba >> 8) & 0xFF) as u8;
        *f.add(FIS_LBA2) = ((lba >> 16) & 0xFF) as u8;
        *f.add(FIS_DEVICE) = FIS_LBA_MODE; // LBA addressing, device 0
        *f.add(FIS_LBA3) = ((lba >> 24) & 0xFF) as u8;
        *f.add(FIS_LBA4) = ((lba >> 32) & 0xFF) as u8;
        *f.add(FIS_LBA5) = ((lba >> 40) & 0xFF) as u8;
        *f.add(FIS_CNT_LO) = (count & 0xFF) as u8;
        *f.add(FIS_CNT_HI) = (count >> 8) as u8;

        // PRDT entry 0 (16 bytes)
        let p = t.add(CTAB_PRDT);
        // DBA: physical address of DMA bounce buffer
        ptr::write_unaligned(p.add(0) as *mut u32, (bounce.phys & 0xFFFF_FFFF) as u32);
        ptr::write_unaligned(p.add(4) as *mut u32, (bounce.phys >> 32) as u32);
        ptr::write_unaligned(p.add(8) as *mut u32, 0u32);
        // DBC: byte_count - 1; bit 31 = interrupt on completion
        let dbc = ((nbytes as u32).saturating_sub(1)) | (1 << 31);
        ptr::write_unaligned(p.add(12) as *mut u32, dbc);
    }

    // Issue command in slot 0
    // SAFETY: MMIO write to PxCI
    unsafe { wr32(port.port_virt, PORT_CI, 1) };

    // Busy-poll until slot 0 clears or an error fires (≤ ~5 s at ~1 M spins)
    let mut tries = 5_000_000u32;
    loop {
        // SAFETY: MMIO reads
        let ci = unsafe { rd32(port.port_virt, PORT_CI) };
        let is = unsafe { rd32(port.port_virt, PORT_IS) };

        if is & PxIS_TFES != 0 {
            // SAFETY: MMIO writes to clear error status
            unsafe {
                wr32(port.port_virt, PORT_IS, 0xFFFF_FFFF);
                wr32(port.port_virt, PORT_SERR, 0xFFFF_FFFF);
            }
            bounce.free();
            return Err(AhciError::DeviceError);
        }

        if ci & 1 == 0 {
            break; // slot 0 completed
        }

        tries = tries.saturating_sub(1);
        if tries == 0 {
            bounce.free();
            return Err(AhciError::Timeout);
        }
        core::hint::spin_loop();
    }

    // SAFETY: MMIO write to clear port interrupt status
    unsafe { wr32(port.port_virt, PORT_IS, 0xFFFF_FFFF) };

    if !write {
        // SAFETY: bounce.virt valid, nbytes ≤ allocated
        unsafe {
            ptr::copy_nonoverlapping(bounce.virt as *const u8, buf.as_mut_ptr(), nbytes);
        }
    }

    bounce.free();
    Ok(())
}

// ─── BlockDevice impl for AhciController ─────────────────────────────────────

impl AhciController {
    /// Probe and initialise an AHCI controller from the PCI bus.
    ///
    /// # Safety
    /// Must be called once during single-threaded kernel init (MMIO mapping).
    pub unsafe fn init() -> Result<Self, AhciError> {
        // AHCI: class=0x01, subclass=0x06 (SATA), prog_if=0x01 (AHCI 1.0)
        let pci_dev = pci::probe_first(ProbeCriteria {
            class_code: Some(pci::class::MASS_STORAGE),
            subclass: Some(pci::storage_subclass::SATA),
            prog_if: Some(pci::sata_progif::AHCI),
            ..ProbeCriteria::any()
        })
        .ok_or(AhciError::NoController)?;

        log::info!("AHCI: found controller at {:?}", pci_dev.address);

        // Enable bus-mastering and memory-space access (required for DMA)
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        // BAR5 = ABAR (AHCI Base Memory Register)
        let abar_phys = pci_dev.read_bar_raw(5).ok_or(AhciError::BadAbar)?;
        if abar_phys == 0 {
            return Err(AhciError::BadAbar);
        }

        // Map the entire HBA register space (0x100 + 32 ports * 0x80 = 0x1100 bytes)
        crate::memory::paging::ensure_identity_map_range(abar_phys, 0x1200);
        let abar_virt = phys_to_virt(abar_phys);

        // SAFETY: abar_virt is now a mapped MMIO virtual address
        // Enable AHCI mode
        let ghc = rd32(abar_virt, HBA_GHC);
        if ghc & GHC_AE == 0 {
            wr32(abar_virt, HBA_GHC, ghc | GHC_AE);
        }

        log::debug!(
            "AHCI: ABAR phys={:#x} virt={:#x}  GHC={:#010x}",
            abar_phys,
            abar_virt,
            rd32(abar_virt, HBA_GHC)
        );

        let pi = rd32(abar_virt, HBA_PI); // bitmask of implemented ports
        log::debug!("AHCI: ports implemented mask = {:#010x}", pi);

        let mut ports: Vec<AhciPort> = Vec::new();

        for port_num in 0..32u8 {
            if pi & (1 << port_num) == 0 {
                continue;
            }

            let pvirt = abar_virt + 0x100 + (port_num as u64) * 0x80;

            // Check DET: only accept DET=3 (device present + communication)
            let ssts = rd32(pvirt, PORT_SSTS);
            let det = ssts & SSTS_DET_MASK;
            if det != SSTS_DET_COMM {
                log::debug!("AHCI: port {} DET={} — no device, skipping", port_num, det);
                continue;
            }

            // Only handle plain SATA (signature 0x00000101)
            let sig = rd32(pvirt, PORT_SIG);
            if sig != SIG_SATA {
                log::debug!(
                    "AHCI: port {} sig={:#010x} — not plain SATA, skipping",
                    port_num,
                    sig
                );
                continue;
            }

            // Allocate one 4 KB frame for CLB + FIS + CTAB
            let mut lock = get_allocator().lock();
            let frame = lock
                .as_mut()
                .ok_or(AhciError::Alloc)?
                .alloc_frame()
                .map_err(|_| AhciError::Alloc)?;
            drop(lock);

            let mem_phys = frame.start_address.as_u64();
            let mem_virt = phys_to_virt(mem_phys);

            // Zero the frame so HBA sees clean structures
            // SAFETY: mem_virt is valid HHDM-mapped physical memory, 4096 bytes
            ptr::write_bytes(mem_virt as *mut u8, 0, 4096);

            port_rebase(pvirt, mem_phys);

            // Identify device to read sector count
            let mut port = AhciPort {
                port_num,
                port_virt: pvirt,
                mem_phys,
                mem_virt,
                sector_count: 0,
            };

            let mut id_buf = [0u8; SECTOR_SIZE];
            match submit_cmd(&port, 0, 1, &mut id_buf, false, ATA_IDENTIFY) {
                Ok(()) => {
                    // Words 100-103 (bytes 200-207): 48-bit LBA native max address
                    let w0 = u16::from_le_bytes([id_buf[200], id_buf[201]]) as u64;
                    let w1 = u16::from_le_bytes([id_buf[202], id_buf[203]]) as u64;
                    let w2 = u16::from_le_bytes([id_buf[204], id_buf[205]]) as u64;
                    let w3 = u16::from_le_bytes([id_buf[206], id_buf[207]]) as u64;
                    port.sector_count = w0 | (w1 << 16) | (w2 << 32) | (w3 << 48);
                    log::info!(
                        "AHCI: port {} SATA — {} sectors ({} MiB)",
                        port_num,
                        port.sector_count,
                        (port.sector_count * SECTOR_SIZE as u64) / (1024 * 1024)
                    );
                }
                Err(e) => {
                    log::warn!("AHCI: port {} IDENTIFY failed: {}", port_num, e);
                }
            }

            ports.push(port);
        }

        if ports.is_empty() {
            return Err(AhciError::NoPort);
        }

        Ok(AhciController { abar_virt, ports })
    }

    /// Return sector count of the first port.
    pub fn sector_count(&self) -> u64 {
        self.ports.first().map(|p| p.sector_count).unwrap_or(0)
    }

    fn first_port(&self) -> Option<&AhciPort> {
        self.ports.first()
    }
}

impl BlockDevice for AhciController {
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let port = self.first_port().ok_or(BlockError::NotReady)?;
        if sector >= port.sector_count {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        submit_cmd(port, sector, 1, buf, false, ATA_READ_DMA_EXT).map_err(|_| BlockError::IoError)
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        let port = self.first_port().ok_or(BlockError::NotReady)?;
        if sector >= port.sector_count {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        // submit_cmd needs &mut [u8]; copy to a mutable staging buffer
        let mut tmp = [0u8; SECTOR_SIZE];
        tmp.copy_from_slice(&buf[..SECTOR_SIZE]);
        submit_cmd(port, sector, 1, &mut tmp, true, ATA_WRITE_DMA_EXT)
            .map_err(|_| BlockError::IoError)
    }

    fn sector_count(&self) -> u64 {
        self.sector_count()
    }
}

// ─── Global singleton + public API ───────────────────────────────────────────

static AHCI: SpinLock<Option<Box<AhciController>>> = SpinLock::new(None);

/// Scan the PCI bus for an AHCI controller and initialise it.
///
/// Called once during kernel boot from `hardware::init()`.
pub fn init() {
    log::info!("AHCI: scanning PCI bus...");

    match unsafe { AhciController::init() } {
        Ok(ctrl) => {
            *AHCI.lock() = Some(Box::new(ctrl));
            log::info!("AHCI: controller ready");
        }
        Err(AhciError::NoController) => {
            log::info!("AHCI: no controller found (not a SATA system?)");
        }
        Err(e) => {
            log::error!("AHCI: init failed: {}", e);
        }
    }
}

/// Return a reference to the first usable AHCI controller, if any.
pub fn get_device() -> Option<&'static AhciController> {
    // SAFETY: the global Option is only ever set during init and never cleared
    unsafe {
        let lock = AHCI.lock();
        lock.as_ref().map(|b| {
            let ptr = b.as_ref() as *const AhciController;
            &*ptr
        })
    }
}
