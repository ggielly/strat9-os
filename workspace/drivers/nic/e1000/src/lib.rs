#![no_std]

use core::ptr;
use intel_ethernet::{
    ctrl, eerd, int_bits, rctl, regs, rx_errors, rx_status, tctl, tx_status, LegacyRxDesc,
    LegacyTxDesc,
};
use net_core::NetError;
use nic_buffers::{DmaAllocator, DmaRegion};
use nic_queues::{RxDescriptor, RxRing, TxDescriptor, TxRing};

pub const NUM_RX: usize = 128;
pub const NUM_TX: usize = 128;
pub const RX_BUF_SIZE: usize = 4096;

const RESET_MAX_POLLS: u32 = 200_000;
const EEPROM_MAX_POLLS: u32 = 50_000;

/// Watchdog timeout in successful TX completions. If no TX completes
/// within this many transmit attempts the link is considered stalled.
const WATCHDOG_TX_THRESHOLD: u64 = 10_000;

pub const E1000_DEVICE_IDS: &[u16] = &[0x100E, 0x100F, 0x10D3, 0x153A, 0x1539];
pub const INTEL_VENDOR: u16 = 0x8086;

/// Hardware statistics maintained by the driver.
pub struct E1000Stats {
    pub rx_ok: u64,
    pub rx_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_length_errors: u64,
    pub tx_ok: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
    pub tx_late_collision: u64,
    pub tx_underrun: u64,
    pub watchdog_resets: u64,
}

impl E1000Stats {
    const fn new() -> Self {
        Self {
            rx_ok: 0,
            rx_errors: 0,
            rx_crc_errors: 0,
            rx_length_errors: 0,
            tx_ok: 0,
            tx_errors: 0,
            tx_dropped: 0,
            tx_late_collision: 0,
            tx_underrun: 0,
            watchdog_resets: 0,
        }
    }
}

pub struct E1000Nic {
    mmio: u64,
    rx: RxRing<LegacyRxDesc>,
    rx_bufs: [DmaRegion; NUM_RX],
    rx_ring_phys: u64,
    tx: TxRing<LegacyTxDesc>,
    tx_bufs: [DmaRegion; NUM_TX],
    tx_ring_phys: u64,
    mac: [u8; 6],
    link_up: bool,
    stats: E1000Stats,
    tx_since_last_reclaim: u64,
    /// Last known TDH value for watchdog stall detection.
    last_tdh: usize,
}

// SAFETY: E1000Nic owns its MMIO region and DMA buffers. It is safe to send
// across threads as long as only one thread accesses the hardware at a time.
unsafe impl Send for E1000Nic {}

#[inline]
unsafe fn rd(base: u64, reg: usize) -> u32 {
    ptr::read_volatile((base + reg as u64) as *const u32)
}

#[inline]
unsafe fn wr(base: u64, reg: usize, val: u32) {
    ptr::write_volatile((base + reg as u64) as *mut u32, val)
}

impl E1000Nic {
    pub fn init(mmio_base: u64, alloc: &dyn DmaAllocator) -> Result<Self, NetError> {
        unsafe {
            // --- Reset ---
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

            // --- MAC address ---
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

            // --- VLAN Ether Type (cosmetic : the 802.1Q network stack does not
            //     process VLAN tags, so this only makes the hardware parse the
            //     tag field without any functional effect.)
            // TODO here ! ---
            wr(mmio_base, regs::VET, 0x8100);
            // Zero-out VLAN filter table (accept no VLANs; functional once the
            // stack gains 802.1Q support).
            for i in 0..128u32 {
                wr(mmio_base, regs::VFTA + (i as usize) * 4, 0);
            }

            // --- RX ring ---
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

            for (i, buf) in rx_bufs.iter().enumerate().take(NUM_RX) {
                (*rx_descs.add(i)).addr = buf.phys;
            }

            // --- TX ring ---
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

            // Pre-allocate TX buffer pool (avoid per-packet DMA alloc).
            let mut tx_bufs = [DmaRegion::ZERO; NUM_TX];
            for tx_buf in tx_bufs.iter_mut().take(NUM_TX) {
                let buf = alloc
                    .alloc_dma(net_core::MTU)
                    .map_err(|_| NetError::NotReady)?;
                ptr::write_bytes(buf.virt, 0, net_core::MTU);
                *tx_buf = buf;
            }

            // Enable TX
            wr(
                mmio_base,
                regs::TCTL,
                tctl::EN | tctl::PSP | (0x10 << tctl::CT_SHIFT) | (0x40 << tctl::COLD_SHIFT),
            );

            // --- RX control: BSIZE_4096 (BSIZE=00 | BSEX=1) ---
            // RX_BUF_SIZE is 4096; the hardware must match.
            wr(
                mmio_base,
                regs::RCTL,
                rctl::EN | rctl::BAM | rctl::BSIZE_4096 | rctl::SECRC,
            );

            // --- Link up + interrupts ---
            let c = rd(mmio_base, regs::CTRL);
            wr(mmio_base, regs::CTRL, c | ctrl::SLU);

            // --- Interrupt coalescing ---
            // ITR    = 1950 =>  approx. 2000 irq/s max (1950 × 256 ns ≈ 500 µs between IRQs).
            // RDTR   = 0 => fire interrupt after first packet (baseline)
            // RADV   = 128 => absolute timer: force an interrupt after 128 µs even
            //                if no new packets arrive (keeps latency bounded).
            // TIDV   = 0 => transmit: fire on first descriptor writeback
            // TADV   = 64 => absolute timer: flush TX interrupts after 64 µs.
            //
            // ITR uses 256 ns units on 8254x; on e1000e/I210 the same register
            // uses 1024 ns units — the value still provides adequate coalescing.
            //
            // 488 × 256 ns ≈ 125 µs => approx 8 000 irq/s max.  Low enough to keep the
            // CPU from being swamped under heavy load, high enough for interactive
            // responsiveness (sub-ms ping).
            wr(mmio_base, regs::ITR, 488);
            wr(mmio_base, regs::RDTR, 0);
            wr(mmio_base, regs::RADV, 128);
            wr(mmio_base, regs::TIDV, 0);
            wr(mmio_base, regs::TADV, 64);

            wr(
                mmio_base,
                regs::IMS,
                int_bits::RXT0
                    | int_bits::LSC
                    | int_bits::RXDMT0
                    | int_bits::RXO
                    | int_bits::TXDW
                    | int_bits::TXQE,
            );
            let status = rd(mmio_base, regs::STATUS);
            let link_up = (status & 0x02) != 0;

            Ok(Self {
                mmio: mmio_base,
                rx: RxRing::new(rx_descs, NUM_RX),
                rx_bufs,
                rx_ring_phys: rx_ring_region.phys,
                tx: TxRing::new(tx_descs, NUM_TX),
                tx_bufs,
                tx_ring_phys: tx_ring_region.phys,
                mac,
                link_up,
                stats: E1000Stats::new(),
                tx_since_last_reclaim: 0,
                last_tdh: 0,
            })
        }
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        self.link_up
    }

    pub fn check_link(&mut self) -> bool {
        unsafe {
            let status = rd(self.mmio, regs::STATUS);
            self.link_up = (status & 0x02) != 0;
        }
        self.link_up
    }

    pub fn stats(&self) -> &E1000Stats {
        &self.stats
    }

    /// Recycle an RX descriptor: clear status, restore buffer address, bump tail.
    fn recycle_rx_desc(&mut self, idx: usize) {
        self.rx.desc_mut(idx).clear_status();
        self.rx
            .desc_mut(idx)
            .set_buffer_addr(self.rx_bufs[idx].phys);
        let new_tail = self.rx.advance();
        unsafe {
            wr(self.mmio, regs::RDT, new_tail as u32);
        }
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        if !self.check_link() {
            return Err(NetError::LinkDown);
        }

        let (idx, pkt_len) = self.rx.poll().ok_or(NetError::NoPacket)?;

        // --- RX error checking ---
        let err = self.rx.desc(idx).errors;
        let st = self.rx.desc(idx).status;

        if (err & rx_errors::CE) != 0 {
            log::warn!("e1000: RX CRC error on descriptor {}", idx);
            self.recycle_rx_desc(idx);
            self.stats.rx_crc_errors += 1;
            self.stats.rx_errors += 1;
            return Err(NetError::NoPacket);
        }
        if (err & rx_errors::SE) != 0 {
            log::warn!("e1000: RX symbol error on descriptor {}", idx);
            self.recycle_rx_desc(idx);
            self.stats.rx_errors += 1;
            return Err(NetError::NoPacket);
        }
        if (err & rx_errors::TCPE) != 0 {
            log::trace!("e1000: RX TCP/UDP checksum error on descriptor {}", idx);
        }
        if (err & rx_errors::IPE) != 0 {
            log::trace!("e1000: RX IP checksum error on descriptor {}", idx);
        }
        if (st & rx_status::EOP) == 0 {
            log::warn!(
                "e1000: RX descriptor {} missing EOP — fragment dropped",
                idx
            );
            self.recycle_rx_desc(idx);
            self.stats.rx_length_errors += 1;
            self.stats.rx_errors += 1;
            return Err(NetError::NoPacket);
        }

        let len = pkt_len as usize;
        if buf.len() < len {
            self.recycle_rx_desc(idx);
            return Err(NetError::BufferTooSmall);
        }

        unsafe {
            ptr::copy_nonoverlapping(self.rx_bufs[idx].virt, buf.as_mut_ptr(), len);
        }

        self.recycle_rx_desc(idx);
        self.stats.rx_ok += 1;
        Ok(len)
    }

    pub fn transmit(&mut self, buf: &[u8]) -> Result<(), NetError> {
        if !self.check_link() {
            return Err(NetError::LinkDown);
        }

        if buf.len() > net_core::MTU {
            return Err(NetError::BufferTooSmall);
        }

        let idx = self.tx.tail();

        // Reclaim completed TX buffers before checking fullness.
        self.reclaim_completed_tx_buffers();

        // Check if slot is still busy after reclaim.
        if self.tx.desc(idx).cmd != 0 && !self.tx.is_done(idx) {
            self.stats.tx_dropped += 1;
            return Err(NetError::TxQueueFull);
        }

        // Copy into the pre-allocated TX buffer pool slot.
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), self.tx_bufs[idx].virt, buf.len());
        }

        let _submitted = self.tx.submit(self.tx_bufs[idx].phys, buf.len() as u16);
        unsafe {
            wr(self.mmio, regs::TDT, self.tx.tail() as u32);
        }

        self.tx_since_last_reclaim += 1;
        self.stats.tx_ok += 1;
        Ok(())
    }

    /// Reclaim TX descriptors that the hardware has completed (DD bit set).
    /// No per-packet DMA free is needed because the buffer pool is
    /// pre-allocated; we only reset the descriptor for reuse.
    fn reclaim_completed_tx_buffers(&mut self) {
        // Scan all slots that might be in-flight.
        let head = unsafe { rd(self.mmio, regs::TDH) } as usize % NUM_TX;
        let tail = self.tx.tail();

        let mut idx = head;
        while idx != tail {
            if self.tx.is_done(idx) {
                let st = self.tx.desc(idx).status;
                if (st & tx_status::LC) != 0 {
                    log::warn!("e1000: TX late collision at descriptor {}", idx);
                    self.stats.tx_late_collision += 1;
                    self.stats.tx_errors += 1;
                }
                if (st & tx_status::TU) != 0 {
                    log::warn!("e1000: TX underrun at descriptor {}", idx);
                    self.stats.tx_underrun += 1;
                    self.stats.tx_errors += 1;
                }
                // Reset the descriptor for reuse.
                self.tx.desc_mut(idx).clear();
            }
            idx = (idx + 1) % NUM_TX;
        }
        self.tx_since_last_reclaim = 0;
    }

    /// Non-blocking: check if the last submitted TX has completed.
    pub fn is_transmit_complete(&self) -> bool {
        let idx = self.tx.tail();
        self.tx.is_done(idx)
    }

    /// Blocking spin until the last TX completes.
    pub fn wait_for_transmit(&self) {
        while !self.is_transmit_complete() {
            core::hint::spin_loop();
        }
    }

    pub fn tx_is_done(&self, idx: usize) -> bool {
        self.tx.is_done(idx % NUM_TX)
    }

    /// Process a hardware interrupt.  Returns the raw ICR value so the
    /// kernel adapter can decide what to do (e.g. wake a receive task).
    pub fn handle_interrupt(&mut self) -> u32 {
        let icr = unsafe { rd(self.mmio, regs::ICR) };

        if (icr & int_bits::LSC) != 0 {
            let status = unsafe { rd(self.mmio, regs::STATUS) };
            let was_up = self.link_up;
            self.link_up = (status & 0x02) != 0;
            if was_up != self.link_up {
                log::info!("e1000: link {}", if self.link_up { "up" } else { "down" });
            }
        }

        if (icr & (int_bits::RXT0 | int_bits::RXDMT0 | int_bits::RXO)) != 0 {
            log::trace!("e1000: RX interrupt (icr={:#x})", icr);
        }

        if (icr & int_bits::TXDW) != 0 {
            self.reclaim_completed_tx_buffers();
            log::trace!("e1000: TX descriptor writeback");
        }

        if (icr & int_bits::TXQE) != 0 {
            log::trace!("e1000: TX queue empty");
        }

        if (icr & int_bits::RXO) != 0 {
            log::warn!("e1000: RX overflow — descriptor ring full");
        }

        icr
    }

    /// Watchdog check: called periodically (e.g. from timer IRQ) to detect
    /// and recover from a stalled link.  Returns `true` if a reset was
    /// performed.
    ///
    /// Stall detection logic:
    ///   - If `tx_since_last_reclaim` exceeds `WATCHDOG_TX_THRESHOLD` the
    ///     software has been submitting without any reclaim happening.
    ///   - If TDH (hardware head) == `last_tdh` → the hardware has not
    ///     advanced → stall → reset.
    ///   - If TDH advanced → update `last_tdh` and reset counter (progress).
    ///   - If TDH == tail (ring empty) → normal idle → reset counter.
    pub fn watchdog_tick(&mut self, alloc: &dyn DmaAllocator) -> bool {
        if self.tx_since_last_reclaim < WATCHDOG_TX_THRESHOLD {
            return false;
        }

        let tdh = unsafe { rd(self.mmio, regs::TDH) } as usize;
        let tail = self.tx.tail();

        if tdh != tail {
            // Descriptors are in-flight — check if head has moved.
            if tdh == self.last_tdh {
                log::warn!(
                    "e1000: watchdog — TX stalled (TDH={} TDT={} last_tdh={}), resetting",
                    tdh,
                    tail,
                    self.last_tdh
                );
                self.reinit_hardware(alloc);
                self.stats.watchdog_resets += 1;
                return true;
            }
            // Head advanced: record new position, reset counter.
            self.last_tdh = tdh;
            self.tx_since_last_reclaim = 0;
        } else {
            // Ring empty — normal idle.
            self.tx_since_last_reclaim = 0;
        }
        false
    }

    /// Re-initialise hardware without tearing down the DMA rings.  Used by
    /// the watchdog to recover from a stuck state.
    fn reinit_hardware(&mut self, _alloc: &dyn DmaAllocator) {
        unsafe {
            // Mask all interrupts while we re-init.
            wr(self.mmio, regs::IMC, 0xFFFF_FFFF);
            let _ = rd(self.mmio, regs::ICR);

            // Soft-reset the controller.
            let c = rd(self.mmio, regs::CTRL);
            wr(self.mmio, regs::CTRL, c | ctrl::RST);
            for _ in 0..RESET_MAX_POLLS {
                if rd(self.mmio, regs::CTRL) & ctrl::RST == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // Re-point the rings using the stored physical addresses.
            wr(self.mmio, regs::RDBAL, self.rx_ring_phys as u32);
            wr(self.mmio, regs::RDBAH, (self.rx_ring_phys >> 32) as u32);
            wr(
                self.mmio,
                regs::RDLEN,
                (NUM_RX * core::mem::size_of::<LegacyRxDesc>()) as u32,
            );
            wr(self.mmio, regs::RDH, 0);
            wr(self.mmio, regs::RDT, (NUM_RX - 1) as u32);

            wr(self.mmio, regs::TDBAL, self.tx_ring_phys as u32);
            wr(self.mmio, regs::TDBAH, (self.tx_ring_phys >> 32) as u32);
            wr(
                self.mmio,
                regs::TDLEN,
                (NUM_TX * core::mem::size_of::<LegacyTxDesc>()) as u32,
            );
            wr(self.mmio, regs::TDH, 0);
            wr(self.mmio, regs::TDT, 0);

            // Re-enable interrupts.
            wr(
                self.mmio,
                regs::IMS,
                int_bits::RXT0
                    | int_bits::LSC
                    | int_bits::RXDMT0
                    | int_bits::RXO
                    | int_bits::TXDW
                    | int_bits::TXQE,
            );

            // Force link up.
            let c = rd(self.mmio, regs::CTRL);
            wr(self.mmio, regs::CTRL, c | ctrl::SLU);

            // Reconfigure RX: BSIZE_4096.
            wr(
                self.mmio,
                regs::RCTL,
                rctl::EN | rctl::BAM | rctl::BSIZE_4096 | rctl::SECRC,
            );

            // Reconfigure TX.
            wr(
                self.mmio,
                regs::TCTL,
                tctl::EN | tctl::PSP | (0x10 << tctl::CT_SHIFT) | (0x40 << tctl::COLD_SHIFT),
            );

            // Reconfigure interrupt coalescing.
            wr(self.mmio, regs::ITR, 488);
            wr(self.mmio, regs::RDTR, 0);
            wr(self.mmio, regs::RADV, 128);
            wr(self.mmio, regs::TIDV, 0);
            wr(self.mmio, regs::TADV, 64);
        }

        self.tx_since_last_reclaim = 0;
        self.last_tdh = 0;
        self.check_link();
    }

    unsafe fn read_mac(base: u64) -> Result<[u8; 6], NetError> {
        let ral = rd(base, regs::RAL0);
        let rah = rd(base, regs::RAH0);
        log::trace!("e1000: RAL0={:#x} RAH0={:#x}", ral, rah);

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

        log::trace!("e1000: RAL/RAH empty : reading MAC words from EEPROM");
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
