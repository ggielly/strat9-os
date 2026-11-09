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

//! Register definitions for the Intel AX201 (QuZ, 22000 family, CNVi).
//!
//! Values are taken from `iwl-csr.h`, `iwl-fh.h`, `iwl-prph.h` and the
//! `iwl_qu_mac_cfg` / `iwl_22000_base` configuration in the Linux iwlwifi
//! driver (GPL-2.0 OR BSD-3-Clause).  Only the registers the AX201 bring-up
//! and the station data path need are defined.

// ---------------------------------------------------------------------------
// PCI identity
// ---------------------------------------------------------------------------

pub const INTEL_VENDOR: u16 = 0x8086;

/// Intel Wi-Fi 6 AX201 (CNVi, "QuZ") device IDs.
///
/// `02f0`/`06f0` are the standard low-latency Qu variants, `34f0`/`3df0`/
/// `4df0` the medium-latency SKUs and `43f0`/`a0f0` the long-latency ones.
/// They all share `iwl_qu_mac_cfg` apart from the latency policy.
pub const AX201_DEVICE_IDS: &[u16] = &[0x02f0, 0x06f0, 0x34f0, 0x3df0, 0x4df0, 0x43f0, 0xa0f0];

pub const QUZ_HW_REV_TYPE: u32 = 0x0000_0351;

/// Firmware API level required by the AX201 (`IWL_22000_UCODE_API_MAX`).
pub const AX201_UCODE_API: u32 = 77;

/// Default firmware name inside `/initfs`.
pub const AX201_FIRMWARE: &str = "iwlwifi-QuZ-a0-hr-b0-77.ucode";

// ---------------------------------------------------------------------------
// CSR (control and status registers) - direct PCI MMIO
// ---------------------------------------------------------------------------

pub const CSR_HW_IF_CONFIG_REG: u32 = 0x000;
pub const CSR_INT_COALESCING: u32 = 0x004;
pub const CSR_INT: u32 = 0x008;
pub const CSR_INT_MASK: u32 = 0x00c;
pub const CSR_FH_INT_STATUS: u32 = 0x010;
pub const CSR_FH_INT_MASK: u32 = 0x014;
pub const CSR_GPIO_IN: u32 = 0x018;
pub const CSR_RESET: u32 = 0x020;
pub const CSR_GP_CNTRL: u32 = 0x024;
pub const CSR_HW_REV: u32 = 0x028;
pub const CSR_HW_RF_ID: u32 = 0x09c;
pub const CSR_EEPROM_REG: u32 = 0x02c;
pub const CSR_EEPROM_GP: u32 = 0x030;
pub const CSR_OTP_GP_REG: u32 = 0x034;
pub const CSR_GIO_REG: u32 = 0x03c;
pub const CSR_GP_UCODE_REG: u32 = 0x048;
pub const CSR_GP_DRIVER_REG: u32 = 0x050;
pub const CSR_UCODE_DRV_GP1: u32 = 0x054;
pub const CSR_UCODE_DRV_GP1_SET: u32 = 0x058;
pub const CSR_UCODE_DRV_GP1_CLR: u32 = 0x05c;
pub const CSR_UCODE_DRV_GP2: u32 = 0x060;
pub const CSR_LED_REG: u32 = 0x094;
pub const CSR_DRAM_INT_TBL_REG: u32 = 0x0a0;
pub const CSR_MAC_SHADOW_REG_CTRL: u32 = 0x0a8;
pub const CSR_GIO_CHICKEN_BITS: u32 = 0x100;
pub const CSR_ANA_PLL_CFG: u32 = 0x20c;
pub const CSR_HW_REV_WA_REG: u32 = 0x22c;
pub const CSR_DBG_HPET_MEM_REG: u32 = 0x240;
pub const CSR_DBG_LINK_PWR_MGMT_REG: u32 = 0x250;

/// Context-info base address (64-bit write) used by the 22000 self-load
/// flow.
pub const CSR_CTXT_INFO_BA: u32 = 0x40;
pub const CTXT_INFO_TFD_FORMAT_LONG: u32 = 0x0100;
pub const CTXT_INFO_RB_SIZE_4K: u32 = 0x4;

/// MAC address registers for 22000 (`mac_addr_from_csr = 0x380`).
pub const CSR_MAC_ADDR0: u32 = 0x380;
pub const CSR_MAC_ADDR1: u32 = 0x384;

// GP_CNTRL bits.
pub const GP_CNTRL_MAC_CLOCK_READY: u32 = 0x0000_0001;
pub const GP_CNTRL_INIT_DONE: u32 = 0x0000_0004;
pub const GP_CNTRL_MAC_ACCESS_REQ: u32 = 0x0000_0008;
pub const GP_CNTRL_GOING_TO_SLEEP: u32 = 0x0000_0010;
pub const GP_CNTRL_XTAL_ON: u32 = 0x0000_0400;
pub const GP_CNTRL_HW_RF_KILL_SW: u32 = 0x0800_0000;

// RESET bits.
pub const RESET_NEVO: u32 = 0x0000_0001;
pub const RESET_FORCE_NMI: u32 = 0x0000_0002;
pub const RESET_SW_RESET: u32 = 0x0000_0080;
pub const RESET_MASTER_DISABLED: u32 = 0x0000_0100;
pub const RESET_STOP_MASTER: u32 = 0x0000_0200;
pub const RESET_LINK_PWR_MGMT_DISABLED: u32 = 0x8000_0000;

// HW_IF_CONFIG bits.
pub const HW_IF_CONFIG_HAP_WAKE: u32 = 0x0008_0000;
pub const HW_IF_CONFIG_WAKE_ME: u32 = 0x0800_0000;
pub const HW_IF_CONFIG_WAKE_ME_PCIE_OWNER_EN: u32 = 0x1000_0000;
pub const HW_IF_CONFIG_PERSISTENCE: u32 = 0x4000_0000;

// Interrupt bits.
pub const INT_FH_RX: u32 = 1 << 31;
pub const INT_HW_ERR: u32 = 1 << 29;
pub const INT_RX_PERIODIC: u32 = 1 << 28;
pub const INT_FH_TX: u32 = 1 << 27;
pub const INT_SCD: u32 = 1 << 26;
pub const INT_SW_ERR: u32 = 1 << 25;
pub const INT_RF_KILL: u32 = 1 << 7;
pub const INT_CT_KILL: u32 = 1 << 6;
pub const INT_SW_RX: u32 = 1 << 3;
pub const INT_RESET_DONE: u32 = 1 << 2;
pub const INT_WAKEUP: u32 = 1;
pub const INT_ALIVE: u32 = 1;

pub const FH_INT_RX_MASK: u32 = (1 << 30) | (1 << 17) | (1 << 16);
pub const FH_INT_TX_MASK: u32 = (1 << 1) | 1;

// UCODE GP1 bits.
pub const UCODE_GP1_MAC_SLEEP: u32 = 0x1;
pub const UCODE_SW_BIT_RFKILL: u32 = 0x2;
pub const UCODE_GP1_CMD_BLOCKED: u32 = 0x4;

// GIO chicken bits.
pub const GIO_CHICKEN_L1A_NO_L0S_RX: u32 = 0x0080_0000;
pub const GIO_CHICKEN_DIS_L0S_EXIT_TIMER: u32 = 0x2000_0000;
pub const DBG_HPET_MEM_VAL: u32 = 0xffff_0000;
pub const ANA_PLL_CFG_VAL: u32 = 0x0088_0300;

// ---------------------------------------------------------------------------
// HBUS (indirect peripheral register window)
// ---------------------------------------------------------------------------

pub const HBUS_TARG_MEM_RADDR: u32 = 0x40c;
pub const HBUS_TARG_MEM_WADDR: u32 = 0x410;
pub const HBUS_TARG_MEM_WDAT: u32 = 0x418;
pub const HBUS_TARG_MEM_RDAT: u32 = 0x41c;
pub const HBUS_TARG_PRPH_WADDR: u32 = 0x444;
pub const HBUS_TARG_PRPH_RADDR: u32 = 0x448;
pub const HBUS_TARG_PRPH_WDAT: u32 = 0x44c;
pub const HBUS_TARG_PRPH_RDAT: u32 = 0x450;
pub const HBUS_TARG_WRPTR: u32 = 0x460;

/// HBUS peripheral access width selector: bits 24-25 encode size-1.
pub const HBUS_PRPH_ADDR_MASK: u32 = 0x0000_ffff;
pub const HBUS_PRPH_32BIT: u32 = 3 << 24;

// ---------------------------------------------------------------------------
// PRPH registers (accessed through HBUS)
// ---------------------------------------------------------------------------

pub const UREG_CPU_INIT_RUN: u32 = 0x00a0_5c44;
pub const UREG_NIC_SET_NMI_DRIVER: u32 = 0x00a0_5c10;
pub const WFPM_GP2: u32 = 0x00a0_30b4;
pub const LMPM_CHICK: u32 = 0x00a0_1ff8;
pub const LMPM_CHICK_EXTENDED_ADDR_SPACE: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Flow handler: gen2 TX/RX (from iwl-fh.h)
// ---------------------------------------------------------------------------

/// Gen2 keeps the RFH/TFH register blocks in the 0xA06xxx-0xA08xxx window.
pub const RFH_GEN_CFG: u32 = 0xa0_9800;
pub const RFH_GEN_CFG_SERVICE_DMA_SNOOP: u32 = 1 << 0;
pub const RFH_GEN_CFG_RFH_DMA_SNOOP: u32 = 1 << 1;
pub const RFH_GEN_CFG_RB_CHUNK_SIZE_64: u32 = 0;
pub const RFH_GEN_CFG_RB_CHUNK_SIZE_128: u32 = 1 << 4;
pub const RFH_GEN_CFG_DEFAULT_RXQ_NUM: u32 = 0x0f00;

pub const RFH_RXF_DMA_CFG: u32 = 0xa0_9820;
pub const RFH_RXF_DMA_RB_SIZE_4K: u32 = 0x4 << 16;
pub const RFH_RXF_DMA_RBDCB_SIZE_256: u32 = 0x8 << 20;
pub const RFH_RXF_DMA_MIN_RB_4_8: u32 = 3 << 24;
pub const RFH_RXF_DMA_DROP_TOO_LARGE: u32 = 1 << 26;
pub const RFH_DMA_EN_ENABLE: u32 = 1 << 31;
pub const RFH_RXF_RXQ_ACTIVE: u32 = 0xa0_980c;

pub const RFH_Q0_FRBDCB_BA_LSB: u32 = 0xa0_8000;
pub const RFH_Q_FRBDCB_BA_LSB: u32 = RFH_Q0_FRBDCB_BA_LSB;
pub const RFH_Q0_FRBDCB_WIDX: u32 = 0xa0_8080;
pub const RFH_Q_FRBDCB_WIDX: u32 = RFH_Q0_FRBDCB_WIDX;
pub const RFH_Q0_FRBDCB_RIDX: u32 = 0xa0_80c0;
pub const RFH_Q_FRBDCB_RIDX: u32 = RFH_Q0_FRBDCB_RIDX;
pub const RFH_Q0_URBDCB_BA_LSB: u32 = 0xa0_8100;
pub const RFH_Q_URBDCB_BA_LSB: u32 = RFH_Q0_URBDCB_BA_LSB;
pub const RFH_Q0_URBDCB_WIDX: u32 = 0xa0_8180;
pub const RFH_Q_URBDCB_WIDX: u32 = RFH_Q0_URBDCB_WIDX;
pub const RFH_Q0_FRBDCB_WIDX_TRG: u32 = 0x1c80;
pub const RFH_Q_FRBDCB_WIDX_TRG: u32 = RFH_Q0_FRBDCB_WIDX_TRG;
pub const RFH_Q0_URBD_STTS_WPTR_LSB: u32 = 0xa0_8200;
pub const RFH_Q_URBD_STTS_WPTR_LSB: u32 = RFH_Q0_URBD_STTS_WPTR_LSB;

/// TFH TFD circular-buffer table (64-bit entries), 22000 and later.
pub const TFH_TFDQ_CBB_TABLE: u32 = 0x1c00;
pub const TFH_TRANSFER_MODE: u32 = 0x1f40;
pub const TFH_SRV_DMA_CHNL0_CTRL: u32 = 0x1f60;
pub const TFH_SRV_DMA_CHNL0_SRAM_ADDR: u32 = 0x1f64;
pub const TFH_SRV_DMA_CHNL0_DRAM_ADDR: u32 = 0x1f68;
pub const TFH_SRV_DMA_CHNL0_BC: u32 = 0x1f70;

/// RX queue geometry.
pub const RX_QUEUE_SIZE: usize = 256;
pub const RX_QUEUE_MASK: usize = RX_QUEUE_SIZE - 1;
pub const RX_BUFFER_SIZE: usize = 4096;
pub const RX_QUEUE_CB_SIZE: u32 = 8; // log2(256)

/// Command queue.
pub const IWL_CMD_QUEUE_ID: u8 = 0;
pub const IWL_CMD_QUEUE_SIZE: usize = 256;
pub const TFD_QUEUE_SIZE_MAX: usize = 256;
pub const NUM_TBS: usize = 25;

/// Keep-warm buffer.
pub const KW_SIZE: usize = 0x1000;

// ---------------------------------------------------------------------------
// Firmware TLV
// ---------------------------------------------------------------------------

/// `struct iwl_tlv_ucode_header` magic (`IWL_UCODE_TLV_MAGIC`).
pub const IWL_UCODE_TLV_MAGIC: u32 = 0x0000_000a;

pub const IWL_UCODE_TLV_SEC_RT: u32 = 19;
pub const IWL_UCODE_TLV_SEC_INIT: u32 = 20;
pub const IWL_UCODE_TLV_SEC_WOWLAN: u32 = 21;
pub const IWL_UCODE_TLV_SEC_RT_USNIFFER: u32 = 22;
pub const IWL_UCODE_TLV_PAGING: u32 = 32;

/// Section destinations inside device SRAM/DRAM.
pub const IWL_FW_MEM_EXTENDED_START: u32 = 0x0000_0000;
pub const IWL_FW_MEM_EXTENDED_END: u32 = 0xffff_ffff;
/// Separator between LMAC and UMAC images.
pub const CPU1_CPU2_SEPARATOR_SECTION: u32 = 0xffff_cccc;
/// Separator before the paging image.
pub const PAGING_SEPARATOR_SECTION: u32 = 0xaaaa_bbbb;

/// TLV carrying the number of CPUs in the image (dual-CPU images use 2).
pub const IWL_UCODE_TLV_NUM_OF_CPU: u32 = 27;
