#![no_std]

use core::ptr;
use intel_ethernet::{ctrl, eerd, int_bits, rctl, regs, tctl, LegacyRxDesc, LegacyTxDesc};
use net_core::NetError;
use nic_buffers::{DmaAllocator, DmaRegion};
use nic_queues::{RxDescriptor, RxRing, TxRing};

pub const NUM_RX: usize = 64;
pub const NUM_TX: usize = 64;
pub const RX_BUF_SIZE: usize = 2048;

pub const E1000_DEVICE_IDS: &[u16] = &[0x100E, 0x100F, 0x10D3, 0x153A, 0x1539];
pub const INTEL_VENDOR: u16 = 0x8086;

pub struct E1000Nic {
    mmio: u64,
    rx: RxRing<LegacyRxDesc>,
    rx_bufs: [DmaRegion; NUM_RX],
    tx: TxRing<LegacyTxDesc>,
    tx_bufs: [Option<DmaRegion>; NUM_TX],
    mac: [u8; 6],
}

unsafe impl Send for E1000Nic {}

// MMIO helpers
#[inline]
unsafe fn rd(base: u64, reg: usize) -> u32 {
    ptr::read_volatile((base + reg as u64) as *const u32)
}
#[inline]
unsafe fn wr(base: u64, reg: usize, val: u32) {
    ptr::write_volatile((base + reg as u64) as *mut u32, val);
}

impl E1000Nic {
    /// Initialise the E1000 hardware.
    ///
    /// `mmio_base` is the virtual address of the mapped BAR0 region.
    /// The caller must ensure the MMIO region (>=128 KiB) is identity-mapped.
    pub fn init(mmio_base: u64, alloc: &dyn DmaAllocator) -> Result<Self, NetError> {
        unsafe {
            // Reset
            let c = rd(mmio_base, regs::CTRL);
            wr(mmio_base, regs::CTRL, c | ctrl::RST);
            for _ in 0..10_000_000u64 {
                core::hint::spin_loop();
            }

            // Disable interrupts during setup
            wr(mmio_base, regs::IMC, 0xFFFF_FFFF);
            let _ = rd(mmio_base, regs::ICR);

            let mac = Self::read_mac(mmio_base);

            // RX ring
            let rx_ring_region = alloc
                .alloc_dma(NUM_RX * core::mem::size_of::<LegacyRxDesc>())
                .map_err(|_| NetError::NotReady)?;
            ptr::write_bytes(rx_ring_region.virt, 0, rx_ring_region.size);
            let rx_descs = rx_ring_region.virt as *mut LegacyRxDesc;

            let mut rx_bufs = [DmaRegion::ZERO; NUM_RX];
            for i in 0..NUM_RX {
                let buf = alloc
                    .alloc_dma(RX_BUF_SIZE)
                    .map_err(|_| NetError::NotReady)?;
                ptr::write_bytes(buf.virt, 0, RX_BUF_SIZE);
                (*rx_descs.add(i)).addr = buf.phys;
                rx_bufs[i] = buf;
            }

            wr(mmio_base, regs::RDBAL, rx_ring_region.phys as u32);
            wr(mmio_base, regs::RDBAH, (rx_ring_region.phys >> 32) as u32);
            wr(mmio_base, regs::RDLEN, rx_ring_region.size as u32);
            wr(mmio_base, regs::RDH, 0);
            wr(mmio_base, regs::RDT, (NUM_RX - 1) as u32);

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

            // Enable RX
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
                int_bits::RXT0 | int_bits::LSC | int_bits::RXDMT0 | int_bits::RXO,
            );

            Ok(Self {
                mmio: mmio_base,
                rx: RxRing::new(rx_descs, NUM_RX),
                rx_bufs,
                tx: TxRing::new(tx_descs, NUM_TX),
                tx_bufs: [None; NUM_TX],
                mac,
            })
        }
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        unsafe { rd(self.mmio, regs::STATUS) & 0x02 != 0 }
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let (idx, pkt_len) = self.rx.poll().ok_or(NetError::NoPacket)?;
        let len = pkt_len as usize;
        if buf.len() < len {
            return Err(NetError::BufferTooSmall);
        }

        unsafe {
            ptr::copy_nonoverlapping(self.rx_bufs[idx].virt, buf.as_mut_ptr(), len);
        }

        self.rx.desc_mut(idx).clear_status();
        self.rx
            .desc_mut(idx)
            .set_buffer_addr(self.rx_bufs[idx].phys);
        let new_tail = self.rx.advance();
        unsafe {
            wr(self.mmio, regs::RDT, new_tail as u32);
        }

        Ok(len)
    }

    pub fn transmit(&mut self, buf: &[u8], alloc: &dyn DmaAllocator) -> Result<(), NetError> {
        if buf.len() > net_core::MTU {
            return Err(NetError::BufferTooSmall);
        }

        let idx = self.tx.tail();
        // Wait for previous TX at this slot
        if self.tx.desc(idx).cmd != 0 && !self.tx.is_done(idx) {
            return Err(NetError::TxQueueFull);
        }

        // Free previous buffer
        if let Some(old) = self.tx_bufs[idx].take() {
            unsafe {
                alloc.free_dma(old);
            }
        }

        let region = alloc.alloc_dma(buf.len()).map_err(|_| NetError::NotReady)?;
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), region.virt, buf.len());
        }

        self.tx_bufs[idx] = Some(region);
        let submitted = self.tx.submit(region.phys, buf.len() as u16);
        unsafe {
            wr(self.mmio, regs::TDT, self.tx.tail() as u32);
        }

        // Spin-wait for completion
        while !self.tx.is_done(submitted) {
            core::hint::spin_loop();
        }

        Ok(())
    }

    pub fn handle_interrupt(&self) {
        let _icr = unsafe { rd(self.mmio, regs::ICR) };
    }

    unsafe fn read_mac(base: u64) -> [u8; 6] {
        let ral = rd(base, regs::RAL0);
        let rah = rd(base, regs::RAH0);
        if ral != 0 || (rah & 0xFFFF) != 0 {
            return [
                (ral) as u8,
                (ral >> 8) as u8,
                (ral >> 16) as u8,
                (ral >> 24) as u8,
                (rah) as u8,
                (rah >> 8) as u8,
            ];
        }
        // EEPROM fallback
        let mut mac = [0u8; 6];
        for i in 0u32..3 {
            let w = Self::eeprom_read(base, i as u8);
            mac[(i * 2) as usize] = w as u8;
            mac[(i * 2 + 1) as usize] = (w >> 8) as u8;
        }
        mac
    }

    unsafe fn eeprom_read(base: u64, addr: u8) -> u16 {
        wr(
            base,
            regs::EERD,
            eerd::START | ((addr as u32) << eerd::ADDR_SHIFT),
        );
        loop {
            let v = rd(base, regs::EERD);
            if v & eerd::DONE != 0 {
                return ((v >> eerd::DATA_SHIFT) & 0xFFFF) as u16;
            }
            core::hint::spin_loop();
        }
    }
}
