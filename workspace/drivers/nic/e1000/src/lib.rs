#![no_std]

use core::ptr;
use intel_ethernet::{ctrl, eerd, int_bits, rctl, regs, tctl, LegacyRxDesc, LegacyTxDesc};
use net_core::NetError;
use nic_buffers::{DmaAllocator, DmaRegion};
use nic_queues::{RxDescriptor, RxRing, TxRing};

pub const NUM_RX: usize = 128; // Optimisé pour plus de throughput
pub const NUM_TX: usize = 128; // Optimisé pour plus de throughput
pub const RX_BUF_SIZE: usize = 4096; // Buffer size optimisé (MTU + overhead)

/// Poll `CTRL.RST` until hardware clears it (reset complete). Bounded to avoid hangs.
const RESET_MAX_POLLS: u32 = 200_000;
/// Max polls per EEPROM read (EERD.DONE). Much smaller than blind 1M spins.
const EEPROM_MAX_POLLS: u32 = 50_000;

pub const E1000_DEVICE_IDS: &[u16] = &[0x100E, 0x100F, 0x10D3, 0x153A, 0x1539];
pub const INTEL_VENDOR: u16 = 0x8086;

/// E1000 NIC structure with DMA-safe rings
pub struct E1000Nic {
    mmio: u64,
    rx: RxRing<LegacyRxDesc>,
    rx_bufs: [DmaRegion; NUM_RX],
    tx: TxRing<LegacyTxDesc>,
    tx_bufs: [Option<DmaRegion>; NUM_TX],
    mac: [u8; 6],
    link_up: bool,
}

// SAFETY: E1000Nic owns its MMIO region and DMA buffers. It is safe to send
// across threads as long as only one thread accesses the hardware at a time.
unsafe impl Send for E1000Nic {}

// MMIO helpers
/// # Safety
///
/// The caller must ensure that `base + reg` is a valid mapped MMIO region.
#[inline]
unsafe fn rd(base: u64, reg: usize) -> u32 {
    ptr::read_volatile((base + reg as u64) as *const u32)
}
/// # Safety
///
/// The caller must ensure that `base + reg` is a valid mapped MMIO region.
#[inline]
unsafe fn wr(base: u64, reg: usize, val: u32) {
    ptr::write_volatile((base + reg as u64) as *mut u32, val)
}

impl E1000Nic {
    /// Initialise the E1000 hardware.
    ///
    /// `mmio_base` is the virtual address of the mapped BAR0 region.
    /// The caller must ensure the MMIO region (>=128 KiB) is identity-mapped.
    pub fn init(mmio_base: u64, alloc: &dyn DmaAllocator) -> Result<Self, NetError> {
        // SAFETY: We have exclusive access to the MMIO region during initialization.
        // All DMA allocations are fresh and properly zeroed.
        unsafe {
            // Reset: set CTRL.RST; hardware clears RST when reset completes (SDM).
            let c = rd(mmio_base, regs::CTRL);
            log::trace!("e1000: assert CTRL.RST (ctrl={:#x})", c);
            wr(mmio_base, regs::CTRL, c | ctrl::RST);
            let mut reset_done = false;
            for poll in 0..RESET_MAX_POLLS {
                let ctrl = rd(mmio_base, regs::CTRL);
                if ctrl & ctrl::RST == 0 {
                    log::trace!(
                        "e1000: reset complete after {} polls (ctrl={:#x})",
                        poll + 1,
                        ctrl
                    );
                    reset_done = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !reset_done {
                log::warn!(
                    "e1000: reset timeout after {} CTRL polls (RST never cleared)",
                    RESET_MAX_POLLS
                );
                return Err(NetError::NotReady);
            }

            // Disable interrupts during setup
            wr(mmio_base, regs::IMC, 0xFFFF_FFFF);
            let _ = rd(mmio_base, regs::ICR);

            log::trace!("e1000: read MAC");
            let mac = Self::read_mac(mmio_base)?;
            log::trace!(
                "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            // RX ring
            let rx_ring_region = alloc
                .alloc_dma(NUM_RX * core::mem::size_of::<LegacyRxDesc>())
                .map_err(|_| NetError::NotReady)?;
            ptr::write_bytes(rx_ring_region.virt, 0, rx_ring_region.size);
            let rx_descs = rx_ring_region.virt as *mut LegacyRxDesc;

            let mut rx_bufs = [DmaRegion::ZERO; NUM_RX];
            for rx_buf in rx_bufs.iter_mut().take(NUM_RX) {
                let buf = alloc
                    .alloc_dma(RX_BUF_SIZE)
                    .map_err(|_| NetError::NotReady)?;
                ptr::write_bytes(buf.virt, 0, RX_BUF_SIZE);
                *rx_buf = buf;
            }

            wr(mmio_base, regs::RDBAL, rx_ring_region.phys as u32);
            wr(mmio_base, regs::RDBAH, (rx_ring_region.phys >> 32) as u32);
            wr(mmio_base, regs::RDLEN, rx_ring_region.size as u32);
            wr(mmio_base, regs::RDH, 0);
            wr(mmio_base, regs::RDT, (NUM_RX - 1) as u32);

            // Set buffer addresses in descriptors
            for (i, buf) in rx_bufs.iter().enumerate().take(NUM_RX) {
                (*rx_descs.add(i)).addr = buf.phys;
            }

            // TX ring
            let tx_ring_region = alloc
                .alloc_dma(NUM_TX * core::mem::size_of::<LegacyTxDesc>())
                .map_err(|_| NetError::NotReady)?;
            ptr::write_bytes(tx_ring_region.virt, 0, tx_ring_region.size);
            let tx_descs = tx_ring_region.virt as *mut LegacyTxDesc;

            wr(mmio_base, regs::TDBAL, tx_ring_region.phys as u32);
            wr(mmio_base, regs::TDBAH, (tx_ring_region.phys >> 32) as u32);
            wr(mmio_base, regs::TDLEN, tx_ring_region.size as u32);
            wr(mmio_base, regs::TDH, 0);
            wr(mmio_base, regs::TDT, 0);

            // Enable TX
            wr(
                mmio_base,
                regs::TCTL,
                tctl::EN | tctl::PSP | (0x10 << tctl::CT_SHIFT) | (0x40 << tctl::COLD_SHIFT),
            );

            // Enable RX with 2048 buffer size (default, works with all MTUs)
            wr(
                mmio_base,
                regs::RCTL,
                rctl::EN | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC,
            );

            // Link up + interrupts
            let c = rd(mmio_base, regs::CTRL);
            wr(mmio_base, regs::CTRL, c | ctrl::SLU);
            wr(
                mmio_base,
                regs::IMS,
                int_bits::RXT0 | int_bits::LSC | int_bits::RXDMT0 | int_bits::RXO | int_bits::TXDW,
            );
            let status = rd(mmio_base, regs::STATUS);
            let link_up = (status & 0x02) != 0;

            Ok(Self {
                mmio: mmio_base,
                rx: RxRing::new(rx_descs, NUM_RX),
                rx_bufs,
                tx: TxRing::new(tx_descs, NUM_TX),
                tx_bufs: [None; NUM_TX],
                mac,
                link_up,
            })
        }
    }

    /// Performs the mac address operation.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// Performs the link up operation.
    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// Check and update link status
    pub fn check_link(&mut self) -> bool {
        // SAFETY: MMIO read is safe as long as the device is mapped.
        unsafe {
            let status = rd(self.mmio, regs::STATUS);
            self.link_up = (status & 0x02) != 0;
        }
        self.link_up
    }

    /// Performs the receive operation.
    pub fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        // Check link status first
        if !self.check_link() {
            return Err(NetError::LinkDown);
        }

        let (idx, pkt_len) = self.rx.poll().ok_or(NetError::NoPacket)?;
        let len = pkt_len as usize;
        if buf.len() < len {
            return Err(NetError::BufferTooSmall);
        }

        // SAFETY: The DMA buffer is valid and we have exclusive access during receive.
        unsafe {
            ptr::copy_nonoverlapping(self.rx_bufs[idx].virt, buf.as_mut_ptr(), len);
        }

        // Recycle RX buffer
        self.rx.desc_mut(idx).clear_status();
        self.rx
            .desc_mut(idx)
            .set_buffer_addr(self.rx_bufs[idx].phys);
        let new_tail = self.rx.advance();
        // SAFETY: Writing to RDT is safe as the device is initialized.
        unsafe {
            wr(self.mmio, regs::RDT, new_tail as u32);
        }

        Ok(len)
    }

    /// Performs the transmit operation.
    pub fn transmit(&mut self, buf: &[u8], alloc: &dyn DmaAllocator) -> Result<(), NetError> {
        // Check link status first
        if !self.check_link() {
            return Err(NetError::LinkDown);
        }

        if buf.len() > net_core::MTU {
            return Err(NetError::BufferTooSmall);
        }

        let idx = self.tx.tail();

        // Check if previous TX at this slot is complete (non-blocking)
        if self.tx.desc(idx).cmd != 0 && !self.tx.is_done(idx) {
            return Err(NetError::TxQueueFull);
        }

        // Free previous buffer if present
        if let Some(old) = self.tx_bufs[idx].take() {
            // SAFETY: We own this DMA region and are freeing it after use.
            unsafe {
                alloc.free_dma(old);
            }
        }

        // Allocate new DMA buffer
        let region = alloc.alloc_dma(buf.len()).map_err(|_| NetError::NotReady)?;
        // SAFETY: The DMA region is valid and we have exclusive access.
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), region.virt, buf.len());
        }

        self.tx_bufs[idx] = Some(region);
        let _submitted = self.tx.submit(region.phys, buf.len() as u16);
        // SAFETY: Writing to TDT is safe as the device is initialized.
        unsafe {
            wr(self.mmio, regs::TDT, self.tx.tail() as u32);
        }

        // Non-blocking: return immediately, caller can poll is_transmit_complete()
        // For small packets, we can optionally wait (commented out for performance)
        /*
        while !self.tx.is_done(submitted) {
            core::hint::spin_loop();
        }
        */

        Ok(())
    }

    /// Check if last transmission is complete (non-blocking)
    pub fn is_transmit_complete(&self) -> bool {
        let idx = self.tx.tail();
        self.tx.is_done(idx)
    }

    /// Wait for transmission to complete (blocking)
    pub fn wait_for_transmit(&self) {
        while !self.is_transmit_complete() {
            core::hint::spin_loop();
        }
    }

    /// Handles interrupt.
    pub fn handle_interrupt(&self) {
        // Read and clear interrupt causes
        // SAFETY: MMIO access is safe during interrupt handling.
        let icr = unsafe { rd(self.mmio, regs::ICR) };

        // Handle specific interrupt causes
        if (icr & int_bits::LSC) != 0 {
            // Link Status Change - update cached state
            // SAFETY: MMIO read is safe.
            let _status = unsafe { rd(self.mmio, regs::STATUS) };
        }

        if (icr & (int_bits::RXT0 | int_bits::RXDMT0 | int_bits::RXO)) != 0 {
            // RX interrupts - packet received, will be handled by poll
        }

        if (icr & int_bits::TXDW) != 0 {
            // TX descriptor written back - buffers can be freed
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that `base` is a valid mapped MMIO region.
    unsafe fn read_mac(base: u64) -> Result<[u8; 6], NetError> {
        // Try RAL/RAH registers first
        let ral = rd(base, regs::RAL0);
        let rah = rd(base, regs::RAH0);
        log::trace!("e1000: RAL0={:#x} RAH0={:#x}", ral, rah);

        // Check if MAC address is valid (not all zeros)
        if ral != 0 || rah != 0 {
            return Ok([
                (ral) as u8,
                (ral >> 8) as u8,
                (ral >> 16) as u8,
                (ral >> 24) as u8,
                (rah) as u8,
                (rah >> 8) as u8,
            ]);
        }

        // Fallback to EEPROM read
        log::trace!("e1000: RAL/RAH empty — reading MAC words from EEPROM");
        let mut mac = [0u8; 6];
        for i in 0u32..3 {
            let w = Self::eeprom_read(base, i as u8)?;
            mac[(i * 2) as usize] = w as u8;
            mac[(i * 2 + 1) as usize] = (w >> 8) as u8;
        }
        if mac == [0; 6] || mac == [0xFF; 6] {
            return Err(NetError::NotReady);
        }
        Ok(mac)
    }

    /// # Safety
    ///
    /// The caller must ensure that `base` is a valid mapped MMIO region.
    unsafe fn eeprom_read(base: u64, addr: u8) -> Result<u16, NetError> {
        log::trace!("e1000: EEPROM read addr={}", addr);
        wr(
            base,
            regs::EERD,
            eerd::START | ((addr as u32) << eerd::ADDR_SHIFT),
        );
        for poll in 0..EEPROM_MAX_POLLS {
            let v = rd(base, regs::EERD);
            if v & eerd::DONE != 0 {
                let data = ((v >> eerd::DATA_SHIFT) & 0xFFFF) as u16;
                log::trace!(
                    "e1000: EEPROM addr={} ok after {} polls data={:#x}",
                    addr,
                    poll + 1,
                    data
                );
                return Ok(data);
            }
            core::hint::spin_loop();
        }
        log::warn!(
            "e1000: EEPROM addr={} timeout after {} EERD polls",
            addr,
            EEPROM_MAX_POLLS
        );
        Err(NetError::NotReady)
    }
}
