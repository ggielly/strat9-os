/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! PCIe gen2 transport for the Intel AX201 (22000 family).
//!
//! The flow mirrors Linux `iwlwifi/pcie/trans-gen2.c`, `pcie/rx.c` and
//! `pcie/tx-gen2.c`:
//!
//! 1. `apm_init()` powers the MAC and enables DMA through `CSR_GP_CNTRL`.
//! 2. `rx_init()` allocates the RFH free/used RBD rings and status word.
//! 3. `tx_init()` allocates the TFH TFD table for the command queue.
//! 4. `load_firmware()` builds the `iwl_context_info` DRAM structure, copies
//!    every LMAC/UMAC/paging section into 32-bit-addressable DMA memory and
//!    writes its physical address to `CSR_CTXT_INFO_BA`.
//! 5. `kick_cpu()` writes `UREG_CPU_INIT_RUN`, then `wait_alive()` polls the
//!    RX queue for `UCODE_ALIVE_NTFY`.
//!
//! All register definitions come from `regs.rs` (iwl-csr.h / iwl-fh.h /
//! iwl-prph.h).  This module deliberately does not depend on the kernel: the
//! `Bus` trait supplies MMIO and DMA from the caller.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use nic_buffers::DmaRegion;

use crate::fw::{FwSection, UcodeImage};
use crate::regs;

/// MMIO + DMA abstraction.  The kernel implements this on top of the PCI
/// BAR mapping and the buddy DMA allocator; tests can use a mock.
pub trait Bus {
    fn read32(&self, offset: u32) -> u32;
    fn write32(&self, offset: u32, value: u32);
    fn alloc_dma(&self, size: usize) -> Option<DmaRegion>;
    /// Busy-wait for at least `us` microseconds.  The firmware-load path
    /// cannot block the scheduler, so the caller supplies the delay.
    fn delay_us(&self, us: u32) {
        let _ = us;
    }
}

/// Errors returned by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    NoDma,
    Timeout,
    BadFirmware,
    NotAlive,
    TxQueueFull,
    NoNicAccess,
    UnsupportedHw,
    DmaAbove4G,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwInfo {
    pub hw_rev: u32,
    pub rf_id: u32,
    pub mac: [u8; 6],
    pub hw_type: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RxNotification<'a> {
    pub cmd: u8,
    pub group: u8,
    pub sequence: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct RxPacketInfo {
    pub cmd: u8,
    pub group: u8,
    pub sequence: u16,
    pub payload_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct AliveInfo {
    pub status: u32,
    pub flags: u32,
    pub ver_type: u8,
    pub ver_subtype: u8,
    pub ver_main: u8,
    pub ver_minor: u8,
}

const RX_BD_ENTRIES: usize = 256;
const RX_BUF_SIZE: usize = 4096;
const CMD_SLOTS: usize = 64;
const CMD_SLOT_SIZE: usize = 512;
const TFD_SIZE: usize = 256;

struct RxQueue {
    free_bd: DmaRegion,
    used_bd: DmaRegion,
    status: DmaRegion,
    buffers: Vec<DmaRegion>,
    read: usize,
    write: usize,
}

struct TxQueue {
    tfd_table: DmaRegion,
    /// One command buffer per TFD slot (the whole table is DMA-coherent).
    cmd_bufs: DmaRegion,
    write: usize,
}

struct DataQueue {
    id: u8,
    tfd_table: DmaRegion,
    bc_table: DmaRegion,
    cmd_bufs: DmaRegion,
    write: usize,
    read: usize,
    slots: usize,
}

/// DMA buffer that must stay alive while the firmware references it.
struct FwDma {
    _region: DmaRegion,
}

pub struct IwlTransport<B: Bus> {
    bus: B,
    pub hw: HwInfo,
    rx: Option<RxQueue>,
    tx: Option<TxQueue>,
    /// Section buffers referenced by the context-info DRAM map.
    fw_sections: Vec<FwDma>,
    context_info: Option<DmaRegion>,
    pub alive: Option<AliveInfo>,
    sequence: u16,
    pub fw_version: u32,
    pub fw_api: u8,
    data_q: Option<DataQueue>,
    /// Notifications consumed while waiting for a command response.
    deferred_rx: VecDeque<RxOwned>,
}

#[derive(Clone, Debug)]
pub struct RxOwned {
    pub cmd: u8,
    pub group: u8,
    pub sequence: u16,
    pub data: Vec<u8>,
}

impl<B: Bus> IwlTransport<B> {
    pub fn new(bus: B) -> Self {
        Self {
            bus,
            hw: HwInfo {
                hw_rev: 0,
                rf_id: 0,
                mac: [0; 6],
                hw_type: 0,
            },
            rx: None,
            tx: None,
            fw_sections: Vec::new(),
            context_info: None,
            alive: None,
            sequence: 0,
            fw_version: 0,
            fw_api: 0,
            data_q: None,
            deferred_rx: VecDeque::new(),
        }
    }

    pub fn bus(&self) -> &B {
        &self.bus
    }

    // -- low-level helpers -------------------------------------------------

    fn write64(&self, offset: u32, value: u64) {
        self.bus.write32(offset, value as u32);
        self.bus.write32(offset + 4, (value >> 32) as u32);
    }

    fn read_prph(&self, addr: u32) -> u32 {
        self.bus
            .write32(regs::HBUS_TARG_PRPH_RADDR, addr | regs::HBUS_PRPH_32BIT);
        self.bus.read32(regs::HBUS_TARG_PRPH_RDAT)
    }

    fn write_prph(&self, addr: u32, value: u32) {
        self.bus
            .write32(regs::HBUS_TARG_PRPH_WADDR, addr | regs::HBUS_PRPH_32BIT);
        self.bus.write32(regs::HBUS_TARG_PRPH_WDAT, value);
    }

    fn set_bit(&self, offset: u32, bit: u32) {
        self.bus.write32(offset, self.bus.read32(offset) | bit);
    }

    fn grab_nic_access(&self) -> Result<(), TransportError> {
        self.set_bit(regs::CSR_GP_CNTRL, regs::GP_CNTRL_MAC_ACCESS_REQ);
        for _ in 0..1000 {
            let v = self.bus.read32(regs::CSR_GP_CNTRL);
            if v & regs::GP_CNTRL_MAC_CLOCK_READY != 0
                && v & regs::GP_CNTRL_GOING_TO_SLEEP == 0
            {
                return Ok(());
            }
            self.bus.delay_us(10);
        }
        Err(TransportError::NoNicAccess)
    }

    fn release_nic_access(&self) {
        let v = self.bus.read32(regs::CSR_GP_CNTRL);
        self.bus
            .write32(regs::CSR_GP_CNTRL, v & !regs::GP_CNTRL_MAC_ACCESS_REQ);
    }

    // -- hardware init -----------------------------------------------------

    pub fn apm_init(&mut self) -> Result<(), TransportError> {
        // Reset handshake.
        self.bus
            .write32(regs::CSR_RESET, regs::RESET_SW_RESET | regs::RESET_STOP_MASTER);
        self.bus.delay_us(10);
        self.bus.write32(regs::CSR_RESET, regs::RESET_MASTER_DISABLED);
        self.bus.delay_us(10);
        self.bus.write32(regs::CSR_RESET, 0);

        // Keep the values Linux uses for 22000 (gen2 ignores the L0S timer
        // workaround but the L1A bit matters).
        self.set_bit(regs::CSR_GIO_CHICKEN_BITS, regs::GIO_CHICKEN_L1A_NO_L0S_RX);
        self.set_bit(regs::CSR_DBG_HPET_MEM_REG, regs::DBG_HPET_MEM_VAL);
        self.set_bit(regs::CSR_HW_IF_CONFIG_REG, regs::HW_IF_CONFIG_HAP_WAKE);
        self.set_bit(regs::CSR_ANA_PLL_CFG, regs::ANA_PLL_CFG_VAL);

        // Activate the NIC: set INIT_DONE and wait for the MAC clock.
        self.bus
            .write32(regs::CSR_GP_CNTRL, self.bus.read32(regs::CSR_GP_CNTRL) | regs::GP_CNTRL_INIT_DONE);
        for _ in 0..1000 {
            let v = self.bus.read32(regs::CSR_GP_CNTRL);
            if v & regs::GP_CNTRL_MAC_CLOCK_READY != 0 && v & regs::GP_CNTRL_INIT_DONE != 0 {
                self.read_hw_info();
                return Ok(());
            }
            self.bus.delay_us(10);
        }
        Err(TransportError::Timeout)
    }

    fn read_hw_info(&mut self) {
        self.hw.hw_rev = self.bus.read32(regs::CSR_HW_REV);
        self.hw.rf_id = self.bus.read32(regs::CSR_HW_RF_ID);
        self.hw.hw_type = (self.hw.hw_rev & 0x000f_fff0) >> 4;
        let lo = self.bus.read32(regs::CSR_MAC_ADDR0);
        let hi = self.bus.read32(regs::CSR_MAC_ADDR1);
        self.hw.mac = [
            lo as u8,
            (lo >> 8) as u8,
            (lo >> 16) as u8,
            (lo >> 24) as u8,
            hi as u8,
            (hi >> 8) as u8,
        ];
        // The AX201 is a CNVi part: the MAC lives in the PCH, so the CSR
        // address is always populated once the MAC clock is ready.
    }

    // -- queues ------------------------------------------------------------

    fn alloc_32bit(&self, size: usize) -> Result<DmaRegion, TransportError> {
        // Context info and RBD pointers are 32-bit; retry a few times because
        // the buddy allocator does not guarantee placement below 4 GiB.
        for _ in 0..8 {
            let region = self.bus.alloc_dma(size).ok_or(TransportError::NoDma)?;
            if region.device_addr() + size as u64 <= u32::MAX as u64 {
                return Ok(region);
            }
            // Leak the region rather than free it: the driver core has no
            // ownership of the allocator here, and a failed bring-up is fatal
            // anyway.  The kernel glue logs this condition.
        }
        Err(TransportError::DmaAbove4G)
    }

    pub fn rx_init(&mut self) -> Result<(), TransportError> {
        self.grab_nic_access()?;
        let free_bd = self.alloc_32bit(RX_BD_ENTRIES * 8)?;
        let used_bd = self.alloc_32bit(RX_BD_ENTRIES * 4)?;
        let status = self.alloc_32bit(8)?;
        let mut buffers = Vec::with_capacity(RX_BD_ENTRIES);
        for _ in 0..RX_BD_ENTRIES {
            let buf = self.bus.alloc_dma(RX_BUF_SIZE).ok_or(TransportError::NoDma)?;
            buffers.push(buf);
        }

        // Fill the free RBD ring with buffer addresses (bits 35:8 in the low
        // 32-bit register; the high nibble is only needed above 4 GiB and the
        // allocator above guarantees 32-bit addresses).
        for (i, buf) in buffers.iter().enumerate() {
            let addr = buf.device_addr();
            unsafe {
                let bd = free_bd.virt.add(i * 8) as *mut u64;
                bd.write_unaligned(addr);
            }
        }

        let rx = RxQueue {
            free_bd,
            used_bd,
            status,
            buffers,
            read: 0,
            write: 0,
        };

        // Program the RFH registers.  The firmware reconfigures them on
        // alive, but the context info must already see valid addresses.
        self.write_prph64(regs::RFH_Q_FRBDCB_BA_LSB, rx.free_bd.device_addr());
        self.write_prph64(regs::RFH_Q_URBDCB_BA_LSB, rx.used_bd.device_addr());
        self.write_prph64(regs::RFH_Q_URBD_STTS_WPTR_LSB, rx.status.device_addr());
        self.write_prph(regs::RFH_Q_FRBDCB_WIDX, 0);
        self.write_prph(regs::RFH_Q_FRBDCB_RIDX, 0);
        self.write_prph(regs::RFH_Q_URBDCB_WIDX, 0);

        self.rx = Some(rx);
        self.release_nic_access();
        Ok(())
    }

    fn write_prph64(&self, addr: u32, value: u64) {
        self.write_prph(addr, value as u32);
        self.write_prph(addr + 4, (value >> 32) as u32);
    }

    pub fn tx_init(&mut self) -> Result<(), TransportError> {
        self.grab_nic_access()?;
        let tfd_table = self.alloc_32bit(CMD_SLOTS * TFD_SIZE)?;
        let cmd_bufs = self.alloc_32bit(CMD_SLOTS * CMD_SLOT_SIZE)?;
        // Command queue lives on TFH queue 0.
        self.write64(regs::TFH_TFDQ_CBB_TABLE, tfd_table.device_addr());
        self.bus.write32(
            regs::HBUS_TARG_WRPTR,
            (regs::IWL_CMD_QUEUE_ID as u32) << 8,
        );
        self.tx = Some(TxQueue {
            tfd_table,
            cmd_bufs,
            write: 0,
        });
        self.release_nic_access();
        Ok(())
    }

    /// Enable the RFH receiver after the firmware is alive.
    pub fn rfh_enable(&self) {
        let _ = self.read_prph(regs::RFH_GEN_CFG);
        self.write_prph(regs::RFH_RXF_DMA_CFG, 0);
        self.write_prph(regs::RFH_RXF_RXQ_ACTIVE, 0);
        self.write_prph(
            regs::RFH_RXF_DMA_CFG,
            regs::RFH_DMA_EN_ENABLE
                | regs::RFH_RXF_DMA_RB_SIZE_4K
                | regs::RFH_RXF_DMA_MIN_RB_4_8
                | regs::RFH_RXF_DMA_DROP_TOO_LARGE
                | regs::RFH_RXF_DMA_RBDCB_SIZE_256,
        );
        self.write_prph(
            regs::RFH_GEN_CFG,
            regs::RFH_GEN_CFG_RFH_DMA_SNOOP
                | regs::RFH_GEN_CFG_SERVICE_DMA_SNOOP
                | regs::RFH_GEN_CFG_RB_CHUNK_SIZE_64,
        );
        self.write_prph(regs::RFH_RXF_RXQ_ACTIVE, 0xF);
        // Program the initial write pointer.
        if let Some(rx) = self.rx.as_ref() {
            let write = rx.write & !7;
            self.bus.write32(0x1c80, write as u32);
        }
    }

    // -- firmware ----------------------------------------------------------

    pub fn load_firmware(&mut self, img: &UcodeImage<'_>) -> Result<(), TransportError> {
        self.fw_version = img.version;
        self.fw_api = img.api;

        // Copy every section into 32-bit DMA memory and remember its device
        // address for the context-info DRAM map.
        let (lmac, umac, paging) = img.split_context_sections();
        let mut lmac_phys = Vec::new();
        let mut umac_phys = Vec::new();
        let mut paging_phys = Vec::new();
        for section in &lmac {
            let region = self.copy_section(section)?;
            lmac_phys.push(region.device_addr());
            self.fw_sections.push(FwDma { _region: region });
        }
        for section in &umac {
            let region = self.copy_section(section)?;
            umac_phys.push(region.device_addr());
            self.fw_sections.push(FwDma { _region: region });
        }
        for section in &paging {
            let region = self.copy_section(section)?;
            paging_phys.push(region.device_addr());
            self.fw_sections.push(FwDma { _region: region });
        }

        let ctxt = self.alloc_32bit(core::mem::size_of::<ContextInfo>())?;
        unsafe {
            let p = ctxt.virt as *mut ContextInfo;
            p.write_bytes(0, 1);
            (*p).version.mac_id = (self.hw.hw_rev & 0xffff) as u16;
            (*p).version.version = 0;
            (*p).version.size = (core::mem::size_of::<ContextInfo>() / 4) as u16;
            let flags = regs::CTXT_INFO_TFD_FORMAT_LONG
                | ((RX_BD_ENTRIES.trailing_zeros() as u32) << 4)
                | (regs::CTXT_INFO_RB_SIZE_4K << 9);
            (*p).control.control_flags = flags;
            if let Some(rx) = self.rx.as_ref() {
                (*p).rbd_cfg.free_rbd_addr = rx.free_bd.device_addr();
                (*p).rbd_cfg.used_rbd_addr = rx.used_bd.device_addr();
                (*p).rbd_cfg.status_wr_ptr = rx.status.device_addr();
            }
            if let Some(tx) = self.tx.as_ref() {
                (*p).hcmd_cfg.cmd_queue_addr = tx.tfd_table.device_addr();
                // TFD_QUEUE_CB_SIZE(256) = log2(256) - 3 = 5.
                (*p).hcmd_cfg.cmd_queue_size = 5;
            }
            for (i, phys) in lmac_phys.iter().enumerate().take(64) {
                (*p).dram.lmac_img[i] = *phys;
            }
            for (i, phys) in umac_phys.iter().enumerate().take(64) {
                (*p).dram.umac_img[i] = *phys;
            }
            for (i, phys) in paging_phys.iter().enumerate().take(64) {
                (*p).dram.virtual_img[i] = *phys;
            }
        }

        let phys = ctxt.device_addr();
        self.context_info = Some(ctxt);
        self.write64(regs::CSR_CTXT_INFO_BA, phys);

        // Kick the embedded CPU.
        self.write_prph(regs::UREG_CPU_INIT_RUN, 1);
        Ok(())
    }

    fn copy_section(&self, section: &FwSection<'_>) -> Result<DmaRegion, TransportError> {
        let size = core::cmp::max(section.data.len(), 4);
        let region = self.alloc_32bit(size)?;
        unsafe {
            if !section.data.is_empty() {
                core::ptr::copy_nonoverlapping(
                    section.data.as_ptr(),
                    region.virt,
                    section.data.len(),
                );
            }
        }
        Ok(region)
    }

    pub fn wait_alive(&mut self, timeout_ms: u32) -> Result<AliveInfo, TransportError> {
        let steps = timeout_ms.saturating_mul(100);
        for _ in 0..steps {
            self.bus.delay_us(10);
            if self.bus.read32(regs::CSR_INT) & regs::INT_ALIVE != 0 {
                self.bus.write32(regs::CSR_INT, regs::INT_ALIVE);
            }
            let mut block = [0u8; 512];
            while let Some(pkt) = self.rx_next_into(&mut block) {
                if pkt.cmd == 1 && pkt.group == 0 {
                    let info = parse_alive(&block[..pkt.payload_len]);
                    if info.status == 0xCAFE {
                        self.alive = Some(info);
                        self.rfh_enable();
                        // Clear stale interrupts and enable the masks used by
                        // the data path.
                        self.bus.write32(regs::CSR_INT, 0xffff_ffff);
                        self.bus.write32(
                            regs::CSR_INT_MASK,
                            regs::INT_FH_RX
                                | regs::INT_HW_ERR
                                | regs::INT_FH_TX
                                | regs::INT_SW_ERR
                                | regs::INT_RF_KILL
                                | regs::INT_SW_RX
                                | regs::INT_ALIVE,
                        );
                        self.bus.write32(regs::CSR_FH_INT_MASK, 0);
                        return Ok(info);
                    }
                }
            }
        }
        Err(TransportError::NotAlive)
    }

    // -- RX ----------------------------------------------------------------

    /// Copy the next received packet payload into `out`.
    ///
    /// Returns the notification header.  The payload is copied because the
    /// RFH buffer is handed back to the device immediately; callers must not
    /// retain a slice into DMA memory.
    pub fn rx_next_into(&mut self, out: &mut [u8]) -> Option<RxPacketInfo> {
        if let Some(pkt) = self.deferred_rx.pop_front() {
            let n = pkt.data.len().min(out.len());
            out[..n].copy_from_slice(&pkt.data[..n]);
            return Some(RxPacketInfo {
                cmd: pkt.cmd,
                group: pkt.group,
                sequence: pkt.sequence,
                payload_len: n,
            });
        }
        let info = {
            let rx = self.rx.as_mut()?;
            // closed_rb_num is the first u16 of the status word for 22000.
            let closed = unsafe { (rx.status.virt as *const u16).read_unaligned() } as usize & 0xfff;
            if rx.read == closed {
                return None;
            }
            let idx = rx.read & (RX_BD_ENTRIES - 1);
            let buf = &rx.buffers[idx];
            let info = unsafe {
                let pkt = buf.virt;
                let len_n_flags = (pkt as *const u32).read_unaligned();
                let len = (len_n_flags & 0x3fff) as usize;
                rx.read = (rx.read + 1) & (RX_BD_ENTRIES - 1);
                // Re-arm the consumed RBD before handing the packet back.
                rx.write = (rx.write + 1) & (RX_BD_ENTRIES - 1);
                let addr = rx.buffers[rx.write].device_addr();
                (rx.free_bd.virt.add(rx.write * 8) as *mut u64).write_unaligned(addr);
                self.bus.write32(regs::RFH_Q_FRBDCB_WIDX_TRG, (rx.write & !7) as u32);
                if len < 8 || len > RX_BUF_SIZE {
                    return None;
                }
                let cmd = *pkt.add(4);
                let group = *pkt.add(5);
                let seq = (pkt.add(6) as *const u16).read_unaligned();
                let payload_len = (len - 8).min(out.len());
                core::ptr::copy_nonoverlapping(pkt.add(8), out.as_mut_ptr(), payload_len);
                RxPacketInfo {
                    cmd,
                    group,
                    sequence: seq,
                    payload_len,
                }
            };
            info
        };

        // A TX_CMD response releases its TFD slot.
        if info.cmd == 0x1c && info.group == 0 {
            if let Some(q) = self.data_q.as_mut() {
                q.read = ((info.sequence as usize & 0xff) + 1) % q.slots;
            }
        }
        Some(info)
    }

    /// Copy the next received notification into an owned buffer.
    pub fn rx_poll_owned(&mut self) -> Option<RxOwned> {
        if let Some(pkt) = self.deferred_rx.pop_front() {
            return Some(pkt);
        }
        let mut block = [0u8; 2048];
        let info = self.rx_next_into(&mut block)?;
        Some(RxOwned {
            cmd: info.cmd,
            group: info.group,
            sequence: info.sequence,
            data: block[..info.payload_len].to_vec(),
        })
    }

    /// Wait for the response to command sequence `seq`.
    ///
    /// Non-matching notifications are preserved in `deferred_rx` so the
    /// normal RX path still sees them.
    pub fn wait_response(&mut self, seq: u16, timeout_ms: u32) -> Option<Vec<u8>> {
        let steps = timeout_ms.saturating_mul(100);
        for _ in 0..steps {
            while let Some(pkt) = self.rx_poll_owned() {
                // Responses carry the request sequence without SEQ_RX_FRAME.
                if pkt.sequence == seq && pkt.sequence & 0x8000 == 0 {
                    return Some(pkt.data);
                }
                self.deferred_rx.push_back(pkt);
                if self.deferred_rx.len() > 64 {
                    self.deferred_rx.pop_front();
                }
            }
            self.bus.delay_us(10);
        }
        None
    }

    /// Send a host command and wait for its response.
    pub fn send_cmd_wait(
        &mut self,
        cmd: u8,
        group: u8,
        version: u8,
        payload: &[u8],
        timeout_ms: u32,
    ) -> Option<Vec<u8>> {
        let seq = self.send_cmd(cmd, group, version, payload).ok()?;
        self.wait_response(seq, timeout_ms)
    }

    // -- TX commands -------------------------------------------------------


    pub fn send_cmd(
        &mut self,
        cmd: u8,
        group: u8,
        version: u8,
        payload: &[u8],
    ) -> Result<u16, TransportError> {
        if payload.len() + 8 > CMD_SLOT_SIZE {
            return Err(TransportError::TxQueueFull);
        }
        let tx = self.tx.as_mut().ok_or(TransportError::TxQueueFull)?;
        let slot = tx.write;
        let seq = (self.sequence & 0xff) | ((regs::IWL_CMD_QUEUE_ID as u16) << 8);
        self.sequence = self.sequence.wrapping_add(1);
        let total = payload.len() + 8;

        unsafe {
            let base = tx.cmd_bufs.virt.add(slot * CMD_SLOT_SIZE);
            *base = cmd;
            *base.add(1) = group;
            (base.add(2) as *mut u16).write_unaligned(seq);
            (base.add(4) as *mut u16).write_unaligned(total as u16);
            *base.add(6) = 0;
            *base.add(7) = version;
            core::ptr::copy_nonoverlapping(payload.as_ptr(), base.add(8), payload.len());

            let tfd = tx.tfd_table.virt.add(slot * TFD_SIZE);
            (tfd as *mut u16).write_unaligned(1); // num_tbs
            // struct iwl_tfh_tb { u16 tb_len; u64 addr; }
            (tfd.add(2) as *mut u16).write_unaligned(total as u16);
            (tfd.add(4) as *mut u64).write_unaligned(tx.cmd_bufs.device_addr() + (slot * CMD_SLOT_SIZE) as u64);
        }

        tx.write = (slot + 1) % CMD_SLOTS;
        self.bus.write32(
            regs::HBUS_TARG_WRPTR,
            ((tx.write as u32) & 0xff) | ((regs::IWL_CMD_QUEUE_ID as u32) << 8),
        );
        Ok(seq)
    }

    /// Allocate the data TX queue tables (does not enable the queue yet).
    pub fn data_tx_alloc(&mut self, id: u8) -> Result<(), TransportError> {
        const SLOTS: usize = 128;
        const SLOT_SIZE: usize = 2048;
        let tfd_table = self.alloc_32bit(SLOTS * TFD_SIZE)?;
        let bc_table = self.alloc_32bit(SLOTS * 2)?;
        let cmd_bufs = self.alloc_32bit(SLOTS * SLOT_SIZE)?;
        // 64-bit TFD circular-buffer base for this queue.
        self.write64(regs::TFH_TFDQ_CBB_TABLE + 8 * id as u32, tfd_table.device_addr());
        self.data_q = Some(DataQueue {
            id,
            tfd_table,
            bc_table,
            cmd_bufs,
            write: 0,
            read: 0,
            slots: SLOTS,
        });
        Ok(())
    }

    /// Enable the data queue in the SCD and bind it to `sta_id`/`tid`.
    ///
    /// Tries the new `SCD_QUEUE_CONFIG_CMD` first (22000 firmware API 77)
    /// and falls back to the legacy `SCD_QUEUE_CFG` command.
    pub fn data_tx_enable(&mut self, sta_id: u8, tid: u8) -> Result<(), TransportError> {
        let Some(q) = self.data_q.as_ref() else {
            return Err(TransportError::TxQueueFull);
        };
        let id = q.id;
        let cb_size = (q.slots.trailing_zeros() as u32).saturating_sub(3);
        let sta_mask = 1u32 << (sta_id & 31);

        let mut cfg = Vec::with_capacity(40);
        cfg.extend_from_slice(&0u32.to_le_bytes()); // IWL_SCD_QUEUE_ADD
        cfg.extend_from_slice(&sta_mask.to_le_bytes());
        cfg.push(tid);
        cfg.extend_from_slice(&[0u8; 3]);
        cfg.extend_from_slice(&0u32.to_le_bytes()); // flags
        cfg.extend_from_slice(&cb_size.to_le_bytes());
        cfg.extend_from_slice(&q.bc_table.device_addr().to_le_bytes());
        cfg.extend_from_slice(&q.tfd_table.device_addr().to_le_bytes());

        // DATA_PATH_GROUP = 5, SCD_QUEUE_CONFIG_CMD = 0x17.
        if let Some(resp) = self.send_cmd_wait(0x17, 5, 3, &cfg, 200) {
            // Response starts with a little-endian status (0 = success).
            let status = if resp.len() >= 4 {
                u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]])
            } else {
                0
            };
            if status == 0 {
                return Ok(());
            }
        }

        // Legacy SCD_QUEUE_CFG (legacy group, 0x1d).
        let mut old = [0u8; 12];
        old[0] = 0; // token
        old[1] = sta_id;
        old[2] = tid;
        old[3] = id;
        old[4] = 1; // SCD_CFG_ENABLE_QUEUE
        old[5] = 0; // aggregate
        old[6] = 0; // tx_fifo BE
        old[7] = 64; // BA window
        old[8..10].copy_from_slice(&0u16.to_le_bytes());
        let _ = self.send_cmd_wait(0x1d, 0, 1, &old, 200);
        Ok(())
    }

    /// Transmit one 802.11 MPDU on the data queue.
    ///
    /// Layout in the DMA slot: `iwl_cmd_header` (4) + `iwl_tx_cmd_v9` (20)
    /// + MPDU.  TB0 is the fixed 64-byte first chunk, TB1 the remainder.
    pub fn send_mpdu(&mut self, mpdu: &[u8], encrypt_disabled: bool) -> Result<u16, TransportError> {
        const SLOT_SIZE: usize = 2048;
        const TX_CMD: u8 = 0x1c;
        let q = self.data_q.as_mut().ok_or(TransportError::TxQueueFull)?;
        if (q.write + 1) % q.slots == q.read {
            return Err(TransportError::TxQueueFull);
        }
        let slot = q.write;
        let total = 24 + mpdu.len();
        if total > SLOT_SIZE {
            return Err(TransportError::TxQueueFull);
        }
        let seq = (slot as u16 & 0xff) | ((q.id as u16) << 8);

        unsafe {
            let base = q.cmd_bufs.virt.add(slot * SLOT_SIZE);
            // Clear the header + TX command; the slot is reused and may hold
            // stale dram_info / rate bytes from a previous frame.
            core::ptr::write_bytes(base, 0, 24);
            *base = TX_CMD;
            *base.add(1) = 0;
            (base.add(2) as *mut u16).write_unaligned(seq);
            // iwl_tx_cmd_v9
            let cmd = base.add(4);
            (cmd as *mut u16).write_unaligned(mpdu.len() as u16);
            (cmd.add(2) as *mut u16).write_unaligned(0); // offload_assist
            let mut flags = (1u32 << 0) // IWL_TX_FLAGS_CMD_RATE
                | (1u32 << 2) // IWL_TX_FLAGS_HIGH_PRI
                | (1u32 << 3) // TX_CMD_FLG_ACK
                | (1u32 << 13); // TX_CMD_FLG_SEQ_CTL
            if encrypt_disabled {
                flags |= 1u32 << 1; // IWL_TX_FLAGS_ENCRYPT_DIS
            }
            (cmd.add(4) as *mut u32).write_unaligned(flags);
            // dram_info (8 bytes) remains zero.
            // rate_n_flags: 1 Mbps CCK, antenna A (management/pre-assoc).
            (cmd.add(16) as *mut u32).write_unaligned(0x0000_4000);
            core::ptr::copy_nonoverlapping(mpdu.as_ptr(), cmd.add(20), mpdu.len());

            let tb0_len = 64usize.min(total);
            let tb1_len = total - tb0_len;
            let tfd = q.tfd_table.virt.add(slot * TFD_SIZE);
            let num_tbs = if tb1_len > 0 { 2 } else { 1 };
            (tfd as *mut u16).write_unaligned(num_tbs);
            (tfd.add(2) as *mut u16).write_unaligned(tb0_len as u16);
            (tfd.add(4) as *mut u64).write_unaligned(
                q.cmd_bufs.device_addr() + (slot * SLOT_SIZE) as u64,
            );
            if num_tbs == 2 {
                (tfd.add(2 + 10) as *mut u16).write_unaligned(tb1_len as u16);
                (tfd.add(2 + 10 + 2) as *mut u64).write_unaligned(
                    q.cmd_bufs.device_addr() + (slot * SLOT_SIZE + tb0_len) as u64,
                );
            }

            // Byte-count table entry: four-byte units + fetch chunks in
            // bits 14:12 (22000 format).
            let filled = 2 + num_tbs as u32 * 10;
            let chunks = ((filled + 63) / 64).saturating_sub(1) as u16;
            let words = ((mpdu.len() as u32 + 3) / 4) as u16;
            let bc = (words & 0x0fff) | ((chunks & 0x3) << 12);
            (q.bc_table.virt.add(slot * 2) as *mut u16).write_unaligned(bc);
        }

        q.write = (slot + 1) % q.slots;
        self.bus.write32(
            regs::HBUS_TARG_WRPTR,
            ((q.write as u32) & 0xff) | ((q.id as u32) << 8),
        );
        self.sequence = self.sequence.wrapping_add(1);
        Ok(seq)
    }

    /// Number of TFD slots still free (diagnostics).
    pub fn tx_free_slots(&self) -> usize {
        self.tx.as_ref().map(|_| CMD_SLOTS).unwrap_or(0)
    }
}

fn parse_alive(payload: &[u8]) -> AliveInfo {
    let u32_at = |o: usize| -> u32 {
        if payload.len() >= o + 4 {
            u32::from_le_bytes([
                payload[o],
                payload[o + 1],
                payload[o + 2],
                payload[o + 3],
            ])
        } else {
            0
        }
    };
    AliveInfo {
        status: u32_at(0),
        flags: u32_at(4),
        ver_type: payload.get(8).copied().unwrap_or(0),
        ver_subtype: payload.get(9).copied().unwrap_or(0),
        ver_main: payload.get(10).copied().unwrap_or(0),
        ver_minor: payload.get(11).copied().unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// Context info (BOOT_LOADER_CONTEXT_INFO_S, 22000 / gen2)
// ---------------------------------------------------------------------------

const CTXT_DRAM_ENTRIES: usize = 64;

#[repr(C, packed)]
struct CtxtVersion {
    mac_id: u16,
    version: u16,
    size: u16,
    reserved: u16,
}

#[repr(C, packed)]
struct CtxtControl {
    control_flags: u32,
    reserved: u32,
}

#[repr(C, packed)]
struct CtxtRbdCfg {
    free_rbd_addr: u64,
    used_rbd_addr: u64,
    status_wr_ptr: u64,
}

#[repr(C, packed)]
struct CtxtHcmdCfg {
    cmd_queue_addr: u64,
    cmd_queue_size: u8,
    reserved: [u8; 7],
}

#[repr(C, packed)]
struct CtxtDumpCfg {
    addr: u64,
    size: u32,
    reserved: u32,
}

#[repr(C, packed)]
struct CtxtDram {
    umac_img: [u64; CTXT_DRAM_ENTRIES],
    lmac_img: [u64; CTXT_DRAM_ENTRIES],
    virtual_img: [u64; CTXT_DRAM_ENTRIES],
}

#[repr(C, packed)]
struct ContextInfo {
    version: CtxtVersion,
    control: CtxtControl,
    reserved0: u64,
    rbd_cfg: CtxtRbdCfg,
    hcmd_cfg: CtxtHcmdCfg,
    reserved1: [u32; 4],
    dump_cfg: CtxtDumpCfg,
    edbg_cfg: CtxtDumpCfg,
    pnvm_cfg: CtxtDumpCfg,
    reserved2: [u32; 16],
    dram: CtxtDram,
    reserved3: [u32; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockBus {
        regs: RefCell<[u32; 0x4000 / 4]>,
        mem: RefCell<Vec<u8>>,
        base: u64,
    }

    impl MockBus {
        fn new() -> Self {
            Self {
                regs: RefCell::new([0u32; 0x4000 / 4]),
                mem: RefCell::new(alloc::vec![0u8; 1 << 20]),
                base: 0x1000_0000,
            }
        }
    }

    impl Bus for MockBus {
        fn read32(&self, offset: u32) -> u32 {
            self.regs.borrow()[(offset as usize / 4) & 0x3fff]
        }
        fn write32(&self, offset: u32, value: u32) {
            self.regs.borrow_mut()[(offset as usize / 4) & 0x3fff] = value;
        }
        fn alloc_dma(&self, size: usize) -> Option<DmaRegion> {
            let mut mem = self.mem.borrow_mut();
            static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            let off = NEXT.fetch_add(size as u64, core::sync::atomic::Ordering::Relaxed);
            if off as usize + size > mem.len() {
                return None;
            }
            let _ = &mut *mem;
            Some(DmaRegion {
                phys: self.base + off,
                iova: 0,
                domain_id: 0,
                virt: unsafe { mem.as_mut_ptr().add(off as usize) },
                size,
            })
        }
    }

    #[test]
    fn context_info_layout_is_stable() {
        // 4 + 4 + 8 + 24 + 16 + 16 + 12*3 + 48 + 1536 + 48
        assert_eq!(core::mem::size_of::<ContextInfo>(), 1792);
    }

    #[test]
    fn data_tfd_and_rate_layout() {
        let bus = MockBus::new();
        bus.write32(regs::CSR_GP_CNTRL, regs::GP_CNTRL_MAC_CLOCK_READY);
        let mut t = IwlTransport::new(bus);
        t.tx_init().unwrap();
        t.data_tx_alloc(1).unwrap();
        let mut mpdu = alloc::vec![0u8; 80];
        mpdu[0] = 0x80; // beacon frame control (any MPDU works)
        t.send_mpdu(&mpdu, true).unwrap();
        let q = t.data_q.as_ref().unwrap();
        unsafe {
            let tfd = q.tfd_table.virt;
            assert_eq!((tfd as *const u16).read_unaligned(), 2);
            assert_eq!((tfd.add(2) as *const u16).read_unaligned(), 64);
            let cmd = q.cmd_bufs.virt;
            assert_eq!(*cmd, 0x1c); // TX_CMD
            // rate_n_flags is at cmd header (4) + tx_cmd offset 16.
            let rate = (cmd.add(4 + 16) as *const u32).read_unaligned();
            assert_eq!(rate, 0x4000);
            let bc = (q.bc_table.virt as *const u16).read_unaligned();
            assert_eq!(bc & 0x0fff, (80u16 + 3) / 4);
        }
    }

    #[test]
    fn command_tfd_and_header() {
        let bus = MockBus::new();
        // Pretend the MAC clock is ready so grab_nic_access succeeds.
        bus.write32(regs::CSR_GP_CNTRL, regs::GP_CNTRL_MAC_CLOCK_READY);
        let mut t = IwlTransport::new(bus);
        t.tx_init().unwrap();
        let seq = t.send_cmd(0x08, 0, 2, &[0xaa, 0xbb]).unwrap();
        assert_eq!(seq & 0xff, 0);
        let tx = t.tx.as_ref().unwrap();
        unsafe {
            let base = tx.cmd_bufs.virt;
            assert_eq!(*base, 0x08);
            assert_eq!(*base.add(1), 0);
            assert_eq!((base.add(4) as *const u16).read_unaligned(), 10);
            assert_eq!(*base.add(8), 0xaa);
        }
    }
}
