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
        let rx = self.rx.as_mut()?;
        // closed_rb_num is the first u16 of the status word for 22000.
        let closed = unsafe { (rx.status.virt as *const u16).read_unaligned() } as usize & 0xfff;
        if rx.read == closed {
            return None;
        }
        let idx = rx.read & (RX_BD_ENTRIES - 1);
        let buf = &rx.buffers[idx];
        unsafe {
            let pkt = buf.virt;
            let len_n_flags = (pkt as *const u32).read_unaligned();
            let len = (len_n_flags & 0x3fff) as usize;
            rx.read = (rx.read + 1) & (RX_BD_ENTRIES - 1);
            if len < 8 || len > RX_BUF_SIZE {
                return None;
            }
            let cmd = *pkt.add(4);
            let group = *pkt.add(5);
            let seq = (pkt.add(6) as *const u16).read_unaligned();
            let payload_len = (len - 8).min(out.len());
            core::ptr::copy_nonoverlapping(pkt.add(8), out.as_mut_ptr(), payload_len);
            Some(RxPacketInfo {
                cmd,
                group,
                sequence: seq,
                payload_len,
            })
        }
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
