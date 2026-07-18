//! AHCI (Advanced Host Controller Interface) driver : AHCI spec 1.3.1
//!
//! PCI: class=0x01 (Mass Storage), subclass=0x06 (SATA), prog_if=0x01
//! MMIO base: BAR5 (ABAR)
//!
//! Per-port memory layout (packed into one 4 KB page):
//!   [0x000..0x3FF]  Command List   (1024 B, 32 × 32-byte headers)
//!   [0x400..0x4FF]  FIS receive    (256 B)
//!   [0x500..0x5FF]  Command table  (128 B header + 1 × 16-byte PRDT)
//!
//! ## IRQ-driven completion (DRV-02 v2)
//!
//! When a task context exists (`current_task_id()` is `Some`), commands are
//! completed via interrupt + `WaitQueue::wait_until()` so the issuing task
//! blocks without busy-spinning.  During early boot (no task yet) the legacy
//! polling path is used as a fallback.
//!
//! Per-port statics (indexed by `port_num 0..32`) are used so the IRQ handler
//! can signal completion without acquiring any slow lock:
//!   - `PORT_VIRT[n]`       : MMIO virtual address of port n registers
//!   - `PORT_SLOT0_DONE[n]` : set by IRQ handler when slot-0 completes
//!   - `PORT_SLOT0_ERROR[n]`: set by IRQ handler when a task-file error fires
//!   - `PORT_WQ[n]`         : WaitQueue; issuing task blocks here

use crate::{
    dma::DmaBuffer,
    hardware::pci_client::{self as pci, ProbeCriteria},
    memory,
    memory::{phys_to_virt, UserSliceRead, UserSliceWrite},
    sync::{SpinLock, WaitQueue},
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering},
};

pub use super::virtio_block::{BlockDevice, BlockError, SECTOR_SIZE};

// ========== HBA generic registers (at ABAR) ======================================================
const HBA_GHC: u64 = 0x04;
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0C;

const GHC_AE: u32 = 1 << 31; // AHCI Enable
const GHC_IE: u32 = 1 << 1; // Global Interrupt Enable
const GHC_HR: u32 = 1 << 0; // HBA Reset

// ========== Port register offsets (relative to port base = ABAR + 0x100 + n*0x80)
const PORT_CLB: u64 = 0x00;
const PORT_CLBU: u64 = 0x04;
const PORT_FB: u64 = 0x08;
const PORT_FBU: u64 = 0x0C;
const PORT_IS: u64 = 0x10;
const PORT_IE: u64 = 0x14; // PxIE : port interrupt enable
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

// PxIE bits
const PXIE_DHRE: u32 = 1 << 0; // D2H Register FIS Received Enable (normal DMA completion)
const PXIE_TFEE: u32 = 1 << 30; // Task File Error Enable

// ========== Per-port memory layout offsets ========================================================
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

const EFAULT: i32 = -14;

// PxIS bit 30 = Task File Error Status
const PXIS_TFES: u32 = 1 << 30;

// ========== Error type ==============================

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
    #[error("invalid userspace buffer")]
    InvalidUserBuffer,
    #[error("no usable SATA port found")]
    NoPort,
}

// ========== Internal port handle ======================================================================

struct AhciPort {
    port_num: u8,
    port_virt: u64, // virtual address of port registers
    mem_phys: u64,  // physical base of the per-port CLB/FB/CTAB frame
    mem_virt: u64,  // HHDM virtual address of that frame
    sector_count: u64,
}

// ========== Controller ==============================

pub struct AhciController {
    #[allow(dead_code)]
    abar_virt: u64,
    ports: Vec<AhciPort>,
}

// SAFETY: AhciController is only accessed behind SpinLock<Option<...>>
unsafe impl Send for AhciController {}
unsafe impl Sync for AhciController {}

// ========== Per-port IRQ completion state ===========================================================
// These statics are accessed from the IRQ handler without locks.
// Indexed by port_num (0..32).

/// AHCI ABAR virtual address : written once during init, read by IRQ handler.
static AHCI_ABAR_VIRT: AtomicU64 = AtomicU64::new(0);

/// PCI interrupt line used by this controller.
pub static AHCI_IRQ_LINE: AtomicU8 = AtomicU8::new(0xFF);

/// Per-port MMIO virtual addresses : written once during init.
static PORT_VIRT: [AtomicU64; 32] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 32]
};

/// Per-port slot-0 completion flags : set by IRQ handler, cleared by consumer.
static PORT_SLOT0_DONE: [AtomicBool; 32] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; 32]
};

/// Per-port slot-0 error flags : set by IRQ handler on task-file error.
static PORT_SLOT0_ERROR: [AtomicBool; 32] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; 32]
};

/// Per-port wait queues : tasks block here while waiting for IRQ completion.
static PORT_WQ: [WaitQueue; 32] = {
    const INIT: WaitQueue = WaitQueue::new();
    [INIT; 32]
};

// ========== Per-port async operation metadata  ====================================================================
//
// These statics bridge AHCI IRQ completions to the async I/O ring
// subsystem.  Before issuing a command in async mode, the submit path
// stores the ring_id / user_data / buffer address in the per-port
// arrays below.  When the IRQ fires, `handle_interrupt()` reads them
// back, pushes a CQE into the ring, and drops the DMA buffer.
//
// Only slot 0 is used (one in-flight op per port).

/// Ring id to push the completion CQE into (0 = no async pending).
static PORT_ASYNC_RING_ID: [AtomicU64; 32] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 32]
};

/// User-data token echoed in the completion CQE.
static PORT_ASYNC_USER_DATA: [AtomicU64; 32] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 32]
};

/// User virtual address where read data must be copied (0 = write op).
static PORT_ASYNC_BUF_VADDR: [AtomicU64; 32] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 32]
};

/// Number of bytes transferred.
static PORT_ASYNC_LEN: [AtomicU32; 32] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; 32]
};

/// Whether the in-flight async command is a write operation.
static PORT_ASYNC_IS_WRITE: [AtomicBool; 32] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; 32]
};

/// Raw pointer to a leaked `Box<DmaBuffer>` held until IRQ completion.
/// 0 means no buffer.  Freed inside `handle_interrupt()` via
/// `Box::from_raw()`.
static PORT_ASYNC_DMA_PTR: [AtomicU64; 32] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 32]
};

/// Whether an async operation is in-flight on this port's slot 0.
static PORT_ASYNC_ACTIVE: [AtomicBool; 32] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; 32]
};

struct PendingAsyncReadCompletion {
    ring_id: u64,
    user_data: u64,
    user_buf_vaddr: u64,
    dma_buf: DmaBuffer,
    len: usize,
    result: i32,
}

static PENDING_ASYNC_READ_COMPLETIONS: SpinLock<Vec<PendingAsyncReadCompletion>> =
    SpinLock::new(Vec::new());

// ========== MMIO helpers ==============================

/// Performs the rd32 operation.
#[inline]
unsafe fn rd32(base: u64, off: u64) -> u32 {
    ptr::read_volatile((base + off) as *const u32)
}

/// Performs the wr32 operation.
#[inline]
unsafe fn wr32(base: u64, off: u64, val: u32) {
    ptr::write_volatile((base + off) as *mut u32, val);
}

// ========== Port start/stop ====================

/// Performs the port stop operation.
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

/// Performs the port start operation.
fn port_start(pvirt: u64) {
    // SAFETY: pvirt is a valid MMIO virtual address
    unsafe {
        // Ensure Command List Running is clear before asserting ST
        let mut timeout = 500_000u32;
        while rd32(pvirt, PORT_CMD) & CMD_CR != 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                log::warn!("AHCI: port start wait for CR clear timed out");
                break;
            }
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

/// Enable interrupts for a port (DHRE = DMA completion, TFEE = errors).
fn port_enable_irq(pvirt: u64) {
    // SAFETY: pvirt is a valid MMIO port register address
    unsafe {
        wr32(pvirt, PORT_IE, PXIE_DHRE | PXIE_TFEE);
    }
}

// ========== DMA buffer management ======================================================================
//
// Replaced the old `Bounce` hand-rolled struct with the kernel-wide
// `DmaBuffer` abstraction
// DmaBuffer pins frames, preventing the buddy allocator from recycling
// them while a transfer is in flight, and automatically unpins on Drop.

// ========== Command submission ==========
//
// Two completion strategies:
//   1. Task context (current_task_id() is Some): IRQ + WaitQueue : the issuing
//      task is blocked by the scheduler until the IRQ fires and wakes it.
//   2. Boot context (no task yet): legacy busy-poll with timeout.

/// Performs the submit cmd operation.
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

    let dma_buf = DmaBuffer::alloc(nbytes).map_err(|_| AhciError::Alloc)?;

    if write {
        // SAFETY: dma_buf virtual addr is valid for nbytes; buf.len() >= nbytes
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), dma_buf.virt_addr() as *mut u8, nbytes);
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
        // DBA: physical address of DMA buffer
        let dma_phys = dma_buf.dma_addr().as_u64();
        ptr::write_unaligned(p.add(0) as *mut u32, (dma_phys & 0xFFFF_FFFF) as u32);
        ptr::write_unaligned(p.add(4) as *mut u32, (dma_phys >> 32) as u32);
        ptr::write_unaligned(p.add(8) as *mut u32, 0u32);
        // DBC: byte_count - 1; bit 31 = interrupt on completion
        let dbc = ((nbytes as u32).saturating_sub(1)) | (1 << 31);
        ptr::write_unaligned(p.add(12) as *mut u32, dbc);
    }

    let idx = port.port_num as usize;

    // Clear any stale completion state before issuing the command
    PORT_SLOT0_DONE[idx].store(false, Ordering::Release);
    PORT_SLOT0_ERROR[idx].store(false, Ordering::Release);

    // Issue command in slot 0
    // SAFETY: MMIO write to PxCI
    unsafe { wr32(port.port_virt, PORT_CI, 1) };

    // Completion strategy ================================================
    if crate::process::current_task_id().is_some() {
        // Task context: block until the IRQ handler signals DONE.
        // WaitQueue::wait_until() atomically checks the condition under the
        // waiters SpinLock (which disables IRQs via CLI), so the completion
        // interrupt cannot be lost between the check and the block.
        PORT_WQ[idx].wait_until(|| {
            if PORT_SLOT0_DONE[idx].load(Ordering::Acquire) {
                // Consume the flag atomically before returning
                PORT_SLOT0_DONE[idx].store(false, Ordering::Release);
                Some(())
            } else {
                None
            }
        });

        // Check whether the IRQ reported an error
        if PORT_SLOT0_ERROR[idx].load(Ordering::Acquire) {
            return Err(AhciError::DeviceError);
        }
    } else {
        // Boot context (no task): fall back to busy-poll with ≈5 s timeout.
        let mut tries = 5_000_000u32;
        loop {
            // SAFETY: MMIO reads
            let ci = unsafe { rd32(port.port_virt, PORT_CI) };
            let is = unsafe { rd32(port.port_virt, PORT_IS) };

            if is & PXIS_TFES != 0 {
                // SAFETY: MMIO writes to clear error status
                unsafe {
                    wr32(port.port_virt, PORT_IS, 0xFFFF_FFFF);
                    wr32(port.port_virt, PORT_SERR, 0xFFFF_FFFF);
                }
                return Err(AhciError::DeviceError);
            }

            if ci & 1 == 0 {
                break; // slot 0 completed
            }

            tries = tries.saturating_sub(1);
            if tries == 0 {
                return Err(AhciError::Timeout);
            }
            core::hint::spin_loop();
        }

        // SAFETY: MMIO write to clear port interrupt status
        unsafe { wr32(port.port_virt, PORT_IS, 0xFFFF_FFFF) };
    }

    if !write {
        // SAFETY: dma_buf virtual addr valid, nbytes ≤ allocated
        unsafe {
            ptr::copy_nonoverlapping(dma_buf.virt_addr() as *const u8, buf.as_mut_ptr(), nbytes);
        }
    }
    Ok(())
}

// ========== Async command submission =======================================
//
// Non-blocking variant of `submit_cmd`.  Stores per-port async metadata
// before issuing the command, so the IRQ handler can push a CQE directly
// into the caller's async ring without any further kernel involvement.

/// Submit a command asynchronously ; returns immediately without blocking.
///
/// The caller **must** have already set `PORT_ASYNC_ACTIVE[idx]` to `true`
/// and stored the ring / user-data / buffer info in the per-port statics.
///
/// On success the operation is in-flight; the IRQ handler will deliver the
/// CQE.  On failure (device busy, allocation error) the metadata is cleared
/// and the caller must push an error CQE itself.
fn submit_async_cmd(
    port: &AhciPort,
    lba: u64,
    count: u16,
    write: bool,
    ata_cmd: u8,
    dma_buf: DmaBuffer,
) -> Result<(), AhciError> {
    let nbytes = (count as usize) * SECTOR_SIZE;
    let idx = port.port_num as usize;

    // SAFETY: MMIO read to check device readiness
    let tfd = unsafe { rd32(port.port_virt, PORT_TFD) };
    if tfd & (TFD_BSY | TFD_DRQ) != 0 {
        return Err(AhciError::Busy);
    }

    // For writes: copy user data into the DMA buffer before issuing
    if write {
        let user_vaddr = PORT_ASYNC_BUF_VADDR[idx].load(Ordering::Acquire);
        if user_vaddr != 0 {
            // SAFETY: user buffer vaddr was validated at dispatch time,
            // nbytes ≤ allocated DMA buffer capacity.
            unsafe {
                ptr::copy_nonoverlapping(
                    user_vaddr as *const u8,
                    dma_buf.virt_addr() as *mut u8,
                    nbytes,
                );
            }
        }
    }

    let ctab_phys = port.mem_phys + CTAB_OFF;
    let cmdh_virt = port.mem_virt + CLB_OFF;
    let ctab_virt = port.mem_virt + CTAB_OFF;

    // SAFETY: all addresses point into our pre-allocated per-port frame.
    unsafe {
        // --- Command header (slot 0, 32 bytes) ---
        let h = cmdh_virt as *mut u8;
        ptr::write_bytes(h, 0, 32);

        let flags: u16 = 5u16 | (if write { 1 << 6 } else { 0 });
        ptr::write_unaligned(h.add(CMDH_FLAGS) as *mut u16, flags.to_le());
        ptr::write_unaligned(h.add(CMDH_PRDTL) as *mut u16, 1u16.to_le());
        ptr::write_unaligned(
            h.add(CMDH_CTBA) as *mut u32,
            (ctab_phys & 0xFFFF_FFFF) as u32,
        );
        ptr::write_unaligned(h.add(CMDH_CTBAU) as *mut u32, (ctab_phys >> 32) as u32);

        // --- Command table ---
        let t = ctab_virt as *mut u8;
        ptr::write_bytes(t, 0, CTAB_PRDT + 16);

        // H2D Register FIS
        let f = t.add(CTAB_CFIS);
        *f.add(FIS_TYPE) = FIS_TYPE_H2D;
        *f.add(FIS_FLAGS) = FIS_C_BIT;
        *f.add(FIS_CMD) = ata_cmd;
        *f.add(FIS_LBA0) = (lba & 0xFF) as u8;
        *f.add(FIS_LBA1) = ((lba >> 8) & 0xFF) as u8;
        *f.add(FIS_LBA2) = ((lba >> 16) & 0xFF) as u8;
        *f.add(FIS_DEVICE) = FIS_LBA_MODE;
        *f.add(FIS_LBA3) = ((lba >> 24) & 0xFF) as u8;
        *f.add(FIS_LBA4) = ((lba >> 32) & 0xFF) as u8;
        *f.add(FIS_LBA5) = ((lba >> 40) & 0xFF) as u8;
        *f.add(FIS_CNT_LO) = (count & 0xFF) as u8;
        *f.add(FIS_CNT_HI) = (count >> 8) as u8;

        // PRDT entry 0 (16 bytes)
        let p = t.add(CTAB_PRDT);
        let dma_phys = dma_buf.dma_addr().as_u64();
        ptr::write_unaligned(p.add(0) as *mut u32, (dma_phys & 0xFFFF_FFFF) as u32);
        ptr::write_unaligned(p.add(4) as *mut u32, (dma_phys >> 32) as u32);
        ptr::write_unaligned(p.add(8) as *mut u32, 0u32);
        let dbc = ((nbytes as u32).saturating_sub(1)) | (1 << 31);
        ptr::write_unaligned(p.add(12) as *mut u32, dbc);
    }

    // Leak the DmaBuffer so it stays alive until the IRQ consumes it.
    let dma_ptr = Box::into_raw(Box::new(dma_buf));
    PORT_ASYNC_DMA_PTR[idx].store(dma_ptr as u64, Ordering::Release);

    // Clear stale flags and issue the command
    PORT_SLOT0_DONE[idx].store(false, Ordering::Release);
    PORT_SLOT0_ERROR[idx].store(false, Ordering::Release);

    // SAFETY: MMIO write to PxCI issues slot 0
    unsafe { wr32(port.port_virt, PORT_CI, 1) };

    Ok(())
}

/// Public entry point called from `async_io::dispatch`.
///
/// Validates the port index, looks up the AHCI device, allocates a DMA
/// buffer, stores async metadata, and issues the command.
///
/// On success the caller should increment the ring's in-flight counter.
/// On failure an error CQE is returned so dispatch can push it immediately.
#[allow(dead_code)]
pub(crate) fn submit_async_storage_op(
    port_idx: u8,
    lba: u64,
    byte_count: u32,
    user_buf_vaddr: u64,
    write: bool,
    ring_id: u64,
    user_data: u64,
) -> Result<(), AhciError> {
    let controller = get_device().ok_or(AhciError::NoController)?;
    let port = controller.port_by_num(port_idx).ok_or(AhciError::NoPort)?;

    if lba >= port.sector_count {
        return Err(AhciError::InvalidSector);
    }

    let count = ((byte_count as usize + SECTOR_SIZE - 1) / SECTOR_SIZE) as u16;
    if count == 0 {
        return Err(AhciError::BufferTooSmall);
    }
    let nbytes = (count as usize) * SECTOR_SIZE;

    if write {
        UserSliceRead::new(user_buf_vaddr, nbytes).map_err(|_| AhciError::InvalidUserBuffer)?;
    } else {
        UserSliceWrite::new(user_buf_vaddr, nbytes).map_err(|_| AhciError::InvalidUserBuffer)?;
    }

    let dma_buf = DmaBuffer::alloc(nbytes).map_err(|_| AhciError::Alloc)?;

    let idx = port.port_num as usize;
    let ata_cmd = if write {
        ATA_WRITE_DMA_EXT
    } else {
        ATA_READ_DMA_EXT
    };

    // Store async metadata *before* issuing the command.
    PORT_ASYNC_RING_ID[idx].store(ring_id, Ordering::Release);
    PORT_ASYNC_USER_DATA[idx].store(user_data, Ordering::Release);
    PORT_ASYNC_BUF_VADDR[idx].store(user_buf_vaddr, Ordering::Release);
    PORT_ASYNC_LEN[idx].store(nbytes as u32, Ordering::Release);
    PORT_ASYNC_IS_WRITE[idx].store(write, Ordering::Release);
    PORT_ASYNC_ACTIVE[idx].store(true, Ordering::Release);

    match submit_async_cmd(port, lba, count, write, ata_cmd, dma_buf) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Roll back async metadata on submission failure.
            PORT_ASYNC_ACTIVE[idx].store(false, Ordering::Release);
            PORT_ASYNC_RING_ID[idx].store(0, Ordering::Release);
            PORT_ASYNC_USER_DATA[idx].store(0, Ordering::Release);
            PORT_ASYNC_BUF_VADDR[idx].store(0, Ordering::Release);
            PORT_ASYNC_LEN[idx].store(0, Ordering::Release);
            PORT_ASYNC_IS_WRITE[idx].store(false, Ordering::Release);
            PORT_ASYNC_DMA_PTR[idx].store(0, Ordering::Release);
            Err(e)
        }
    }
}

pub(crate) fn flush_deferred_async_read_completions(ring_id: u64) -> u32 {
    let Some(task) = crate::process::current_task_clone() else {
        return 0;
    };
    let Some(ring) = crate::async_io::ring::find_ring(ring_id) else {
        return discard_deferred_async_read_completions(ring_id);
    };
    if ring.owner_pid != task.pid {
        return 0;
    }
    // If the ring was destroyed, discard all deferred reads for it rather
    // than trying to push completions into a dead ring.
    if ring.destroyed.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return discard_deferred_async_read_completions(ring_id);
    }

    let pending = {
        let mut guard = PENDING_ASYNC_READ_COMPLETIONS.lock();
        // Extract only entries for this ring_id; leave others in place
        // (avoids the allocate + deallocate overhead of take + put-back).
        let mut pending = Vec::new();
        let mut i = 0;
        while i < guard.len() {
            if guard[i].ring_id == ring_id {
                // swap_remove is O(1); completion ordering across rings
                // is not guaranteed to userspace.
                pending.push(guard.swap_remove(i));
            } else {
                i += 1;
            }
        }
        pending
    };

    let mut flushed = 0;

    for mut completion in pending {
        // All entries in `pending` belong to `ring_id` (extracted by retain above).

        if completion.result >= 0 {
            completion.result = match UserSliceWrite::new(completion.user_buf_vaddr, completion.len)
            {
                Ok(user_buf) => {
                    /*
                    Original code before assembly TEST
                                  let src = unsafe {
                                            core::slice::from_raw_parts(
                                                completion.dma_buf.virt_addr() as *const u8,
                                                completion.len,
                                            )
                                        };
                                        user_buf.copy_from(src);

                    */

                    let src = completion.dma_buf.virt_addr() as *const u8;
                    let dst = user_buf.as_ptr() as *mut u8;
                    let n = completion.len;

                    if n >= 128 {
                        // Fast path for sector-aligned copies : `rep movsb`
                        // uses a single front-end uop and leverages ERMSB/FSRM hardware on modern x86-64 (Ivy Bridge+ /
                        // Ice Lake+), outperforming a scalar loop for buffers >= 128 bytes.
                        unsafe {
                            core::arch::asm!(
                                "rep movsb",
                                inout("rcx") n => _,
                                inout("rsi") src => _,
                                inout("rdi") dst => _,
                                options(nostack),
                            );
                        }
                    } else {
                        user_buf
                            .copy_from(unsafe { core::slice::from_raw_parts(src, completion.len) });
                    }
                    completion.len as i32
                }
                Err(_) => EFAULT,
            };
        }

        if crate::async_io::complete::push_completion_for_ring(
            &ring,
            completion.user_data,
            completion.result,
            0,
        ) {
            flushed += 1;
        } else {
            // Ring was destroyed between our check and the push : drop silently.
        }
    }

    flushed
}

pub(crate) fn discard_deferred_async_read_completions(ring_id: u64) -> u32 {
    let mut guard = PENDING_ASYNC_READ_COMPLETIONS.lock();
    let before = guard.len();
    guard.retain(|completion| completion.ring_id != ring_id);
    (before - guard.len()) as u32
}

// ========== IRQ handler ==============================

/// Called from the IDT AHCI IRQ handler.
///
/// Reads `HBA_IS` to find which ports raised an interrupt, reads and clears
/// `PxIS` per port, then signals the per-port `WaitQueue` so that any task
/// blocked in `submit_cmd` can resume.
///
/// # Safety of concurrent access
/// All per-port statics (`PORT_SLOT0_DONE`, `PORT_SLOT0_ERROR`, `PORT_WQ`) are
/// accessed via atomics or briefly-held SpinLocks (which disable IRQs).  The
/// IRQ handler itself is not re-entrant (x86 APIC level-triggered delivery
/// ensures this for the same vector).
pub fn handle_interrupt() {
    let abar = AHCI_ABAR_VIRT.load(Ordering::Relaxed);
    if abar == 0 {
        return; // controller not yet initialised
    }

    // SAFETY: abar is the MMIO-mapped AHCI base set during init
    let global_is = unsafe { rd32(abar, HBA_IS) };
    if global_is == 0 {
        return; // spurious
    }

    for port_num in 0..32u8 {
        if global_is & (1 << port_num) == 0 {
            continue;
        }

        let pvirt = PORT_VIRT[port_num as usize].load(Ordering::Relaxed);
        if pvirt == 0 {
            continue; // port not in use
        }

        // SAFETY: pvirt is the valid MMIO address for this port, set during init
        let pxis = unsafe { rd32(pvirt, PORT_IS) };

        // Determine outcome and record in the error flag
        if pxis & PXIS_TFES != 0 {
            PORT_SLOT0_ERROR[port_num as usize].store(true, Ordering::Release);
            // SAFETY: MMIO writes to clear error state
            unsafe {
                wr32(pvirt, PORT_IS, pxis);
                wr32(pvirt, PORT_SERR, 0xFFFF_FFFF);
            }
        } else {
            PORT_SLOT0_ERROR[port_num as usize].store(false, Ordering::Release);
            // SAFETY: W1C : write back PxIS to clear all set bits
            unsafe { wr32(pvirt, PORT_IS, pxis) };
        }

        // Clear this port's bit in global IS (W1C)
        // SAFETY: MMIO write to HBA_IS
        unsafe { wr32(abar, HBA_IS, 1 << port_num) };

        // Signal command completion (always, for sync waiters)
        PORT_SLOT0_DONE[port_num as usize].store(true, Ordering::Release);

        // Async path : if an async operation was in-flight on this port,
        // push a CQE into the registered ring and drop the DMA buffer.
        let idx = port_num as usize;
        if PORT_ASYNC_ACTIVE[idx].load(Ordering::Acquire) {
            let ring_id = PORT_ASYNC_RING_ID[idx].load(Ordering::Acquire);
            let user_data = PORT_ASYNC_USER_DATA[idx].load(Ordering::Acquire);
            let buf_vaddr = PORT_ASYNC_BUF_VADDR[idx].load(Ordering::Acquire);
            let nbytes = PORT_ASYNC_LEN[idx].load(Ordering::Acquire) as usize;
            let is_write = PORT_ASYNC_IS_WRITE[idx].load(Ordering::Acquire);
            let dma_ptr_val = PORT_ASYNC_DMA_PTR[idx].load(Ordering::Acquire);

            // Clear the active flag : this port is now idle.
            PORT_ASYNC_ACTIVE[idx].store(false, Ordering::Release);
            PORT_ASYNC_RING_ID[idx].store(0, Ordering::Release);
            PORT_ASYNC_USER_DATA[idx].store(0, Ordering::Release);
            PORT_ASYNC_BUF_VADDR[idx].store(0, Ordering::Release);
            PORT_ASYNC_LEN[idx].store(0, Ordering::Release);
            PORT_ASYNC_IS_WRITE[idx].store(false, Ordering::Release);
            PORT_ASYNC_DMA_PTR[idx].store(0, Ordering::Release);

            if dma_ptr_val != 0 {
                // Take ownership of the leaked DmaBuffer back.
                let dma_buf = unsafe { *Box::from_raw(dma_ptr_val as *mut DmaBuffer) };

                let result = if PORT_SLOT0_ERROR[idx].load(Ordering::Acquire) {
                    -5i32 // EIO
                } else {
                    nbytes as i32
                };

                if is_write || result < 0 {
                    crate::async_io::complete::push_completion(ring_id, user_data, result, 0);
                } else {
                    PENDING_ASYNC_READ_COMPLETIONS
                        .lock()
                        .push(PendingAsyncReadCompletion {
                            ring_id,
                            user_data,
                            user_buf_vaddr: buf_vaddr,
                            dma_buf,
                            len: nbytes,
                            result,
                        });

                    if let Some(ring) = crate::async_io::ring::find_ring(ring_id) {
                        ring.wq.wake_all();
                    }
                }
            }
        } else {
            PORT_WQ[idx].wake_one();
        }
    }
}

// ========== BlockDevice impl for AhciController ========================================================================================================================

impl AhciController {
    fn port_by_num(&self, port_num: u8) -> Option<&AhciPort> {
        self.ports.iter().find(|port| port.port_num == port_num)
    }

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

        // Read PCI interrupt line before we need it later
        let irq_line = pci_dev.read_config_u8(pci::config::INTERRUPT_LINE);

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

        // Perform HBA reset sequence (HR), then re-enable AHCI.
        let mut ghc_after = rd32(abar_virt, HBA_GHC) | GHC_AE;
        wr32(abar_virt, HBA_GHC, ghc_after | GHC_HR);
        let mut reset_timeout = 1_000_000u32;
        while rd32(abar_virt, HBA_GHC) & GHC_HR != 0 {
            reset_timeout = reset_timeout.saturating_sub(1);
            if reset_timeout == 0 {
                log::warn!("AHCI: HBA reset timed out, continuing with current state");
                break;
            }
            core::hint::spin_loop();
        }
        ghc_after = rd32(abar_virt, HBA_GHC) | GHC_AE;
        wr32(abar_virt, HBA_GHC, ghc_after);
        // Clear global pending interrupts before per-port setup.
        wr32(abar_virt, HBA_IS, 0xFFFF_FFFF);

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
                log::debug!("AHCI: port {} DET={} : no device, skipping", port_num, det);
                continue;
            }

            // Only handle plain SATA (signature 0x00000101)
            let sig = rd32(pvirt, PORT_SIG);
            if sig != SIG_SATA {
                log::debug!(
                    "AHCI: port {} sig={:#010x} : not plain SATA, skipping",
                    port_num,
                    sig
                );
                continue;
            }

            // Allocate one 4 KB frame for CLB + FIS + CTAB
            let frame = crate::sync::with_irqs_disabled(|token| memory::allocate_frame(token))
                .map_err(|_| AhciError::Alloc)?;

            let mem_phys = frame.start_address.as_u64();
            let mem_virt = phys_to_virt(mem_phys);

            // Zero the frame so HBA sees clean structures
            // SAFETY: mem_virt is valid HHDM-mapped physical memory, 4096 bytes
            ptr::write_bytes(mem_virt as *mut u8, 0, 4096);

            port_rebase(pvirt, mem_phys);

            // Enable per-port interrupts (DHRE + TFEE)
            port_enable_irq(pvirt);

            // Register this port's MMIO address in the per-port static table
            // so the IRQ handler can access it without holding the controller lock.
            PORT_VIRT[port_num as usize].store(pvirt, Ordering::Relaxed);

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
                        "AHCI: port {} SATA : {} sectors ({} MiB)",
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

        // Store the ABAR virtual address and IRQ line in statics so the
        // interrupt handler can reach them without going through the controller lock.
        AHCI_ABAR_VIRT.store(abar_virt, Ordering::Relaxed);
        AHCI_IRQ_LINE.store(irq_line, Ordering::Relaxed);

        // Enable global HBA interrupts (GHC.IE)
        // SAFETY: MMIO write : all port interrupts already enabled above
        let ghc = rd32(abar_virt, HBA_GHC);
        wr32(abar_virt, HBA_GHC, ghc | GHC_IE);

        log::info!("AHCI: global interrupts enabled (IRQ line {})", irq_line);

        Ok(AhciController { abar_virt, ports })
    }

    /// Return sector count of the first port.
    pub fn sector_count(&self) -> u64 {
        self.ports.first().map(|p| p.sector_count).unwrap_or(0)
    }

    /// Return the logical port number of the first usable port.
    pub fn first_port_num(&self) -> Option<u8> {
        self.ports.first().map(|port| port.port_num)
    }

    /// Performs the first port operation.
    fn first_port(&self) -> Option<&AhciPort> {
        self.ports.first()
    }
}

#[cfg(test)]
mod tests {
    use super::{AhciController, AhciPort};
    use alloc::vec;

    fn fake_port(port_num: u8) -> AhciPort {
        AhciPort {
            port_num,
            port_virt: 0,
            mem_phys: 0,
            mem_virt: 0,
            sector_count: 1024,
        }
    }

    #[test]
    fn selects_requested_port_number() {
        let controller = AhciController {
            abar_virt: 0,
            ports: vec![fake_port(2), fake_port(5), fake_port(7)],
        };

        assert_eq!(controller.port_by_num(5).map(|port| port.port_num), Some(5));
        assert_eq!(controller.port_by_num(1).map(|port| port.port_num), None);
        assert_eq!(controller.first_port_num(), Some(2));
    }
}

impl BlockDevice for AhciController {
    /// Reads sector.
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

    /// Writes sector.
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        let port = self.first_port().ok_or(BlockError::NotReady)?;
        if sector >= port.sector_count {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        // submit_cmd copies the data into a DMA buffer before issuing the
        // command, so the const-to-mut cast is safe (the buffer is never
        // written from the CPU side during a write request).
        let buf_mut = buf.as_ptr() as *mut u8;
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf_mut, buf.len()) };
        submit_cmd(port, sector, 1, buf_slice, true, ATA_WRITE_DMA_EXT)
            .map_err(|_| BlockError::IoError)
    }

    /// Read multiple sectors in a single ATA command.
    ///
    /// AHCI `submit_cmd` already accepts a `count: u16` parameter;
    /// this override uses it directly instead of looping per sector.
    fn read_sectors(&self, sector: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let port = self.first_port().ok_or(BlockError::NotReady)?;
        let nbytes = (count as usize) * SECTOR_SIZE;
        if sector.saturating_add(count as u64) > port.sector_count {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < nbytes {
            return Err(BlockError::BufferTooSmall);
        }
        submit_cmd(port, sector, count, buf, false, ATA_READ_DMA_EXT)
            .map_err(|_| BlockError::IoError)
    }

    /// Write multiple sectors in a single ATA command.
    fn write_sectors(&self, sector: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let port = self.first_port().ok_or(BlockError::NotReady)?;
        let nbytes = (count as usize) * SECTOR_SIZE;
        if sector.saturating_add(count as u64) > port.sector_count {
            return Err(BlockError::InvalidSector);
        }
        if buf.len() < nbytes {
            return Err(BlockError::BufferTooSmall);
        }
        // submit_cmd copies the data into a DMA buffer before issuing the
        // command, so the const-to-mut cast is safe.
        let buf_mut = buf.as_ptr() as *mut u8;
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf_mut, buf.len()) };
        submit_cmd(port, sector, count, buf_slice, true, ATA_WRITE_DMA_EXT)
            .map_err(|_| BlockError::IoError)
    }

    /// Performs the sector count operation.
    fn sector_count(&self) -> u64 {
        self.sector_count()
    }
}

// ========== Global singleton + public API ============================================================================================================================================

/// Leaked-Box pointer to the AHCI controller (valid for 'static).
static AHCI_PTR: core::sync::atomic::AtomicPtr<AhciController> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Scan the PCI bus for an AHCI controller and initialise it.
///
/// Called once during kernel boot from `hardware::init()`.
pub fn init() {
    log::info!("AHCI: scanning PCI bus...");

    match unsafe { AhciController::init() } {
        Ok(ctrl) => {
            let leaked: &'static mut AhciController = Box::leak(Box::new(ctrl));
            AHCI_PTR.store(leaked as *mut AhciController, Ordering::Release);
            log::info!("AHCI: controller ready");

            // Register IRQ handler in the IDT now that the controller is live.
            let irq = AHCI_IRQ_LINE.load(Ordering::Relaxed);
            crate::arch::x86_64::idt::register_ahci_irq(irq);
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
    let ptr = AHCI_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: ptr was obtained from Box::leak, valid for 'static.
        Some(unsafe { &*ptr })
    }
}
