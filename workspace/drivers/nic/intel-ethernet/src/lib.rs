#![no_std]

use nic_queues::{RxDescriptor, TxDescriptor};

// ---------------------------------------------------------------------------
// Legacy RX descriptor (Intel 8254x SDM §3.2.3)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LegacyRxDesc {
    pub addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

const RX_DD: u8 = 1 << 0;

impl RxDescriptor for LegacyRxDesc {
    fn set_buffer_addr(&mut self, phys: u64) {
        self.addr = phys;
    }
    fn is_done(&self) -> bool {
        self.status & RX_DD != 0
    }
    fn packet_length(&self) -> u16 {
        self.length
    }
    fn clear_status(&mut self) {
        self.status = 0;
        self.length = 0;
        self.errors = 0;
    }
}

// ---------------------------------------------------------------------------
// Legacy TX descriptor (Intel 8254x SDM §3.3.3)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LegacyTxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

const TX_DD: u8 = 1 << 0;
const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;

impl TxDescriptor for LegacyTxDesc {
    fn set_buffer(&mut self, phys: u64, len: u16) {
        self.addr = phys;
        self.length = len;
    }
    fn set_eop_ifcs_rs(&mut self) {
        self.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
    }
    fn is_done(&self) -> bool {
        self.status & TX_DD != 0
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
}

// ---------------------------------------------------------------------------
// E1000 register offsets (shared by E1000 / E1000e / I210 families)
// ---------------------------------------------------------------------------

pub mod regs {
    pub const CTRL: usize = 0x0000;
    pub const STATUS: usize = 0x0008;
    pub const EERD: usize = 0x0014;
    pub const ICR: usize = 0x00C0;
    /// Interrupt Throttling Rate (SDM §13.4.19).
    /// Value in 256 ns units; 0 = no throttling,  approx. 1950 = 2000 irq/s (conservative).
    pub const ITR: usize = 0x00C4;
    pub const ICS: usize = 0x00C8;
    pub const IMS: usize = 0x00D0;
    pub const IMC: usize = 0x00D8;
    pub const RCTL: usize = 0x0100;
    pub const TCTL: usize = 0x0400;
    pub const RDBAL: usize = 0x2800;
    pub const RDBAH: usize = 0x2804;
    pub const RDLEN: usize = 0x2808;
    pub const RDH: usize = 0x2810;
    pub const RDT: usize = 0x2818;
    pub const RDTR: usize = 0x2820;
    pub const RADV: usize = 0x282C;
    pub const TDBAL: usize = 0x3800;
    pub const TDBAH: usize = 0x3804;
    pub const TDLEN: usize = 0x3808;
    pub const TDH: usize = 0x3810;
    pub const TDT: usize = 0x3818;
    pub const TIDV: usize = 0x3820;
    pub const TADV: usize = 0x382C;
    pub const RAL0: usize = 0x5400;
    pub const RAH0: usize = 0x5404;
    pub const VET: usize = 0x0008;
    pub const VFTA: usize = 0x5200;
}

pub mod ctrl {
    pub const SLU: u32 = 1 << 6;
    pub const RST: u32 = 1 << 26;
}

pub mod rctl {
    pub const EN: u32 = 1 << 1;
    pub const SBP: u32 = 1 << 2;
    pub const UPE: u32 = 1 << 3;
    pub const MPE: u32 = 1 << 4;
    pub const BAM: u32 = 1 << 15;
    pub const BSIZE_2048: u32 = 0;
    /// BSEX=1, BSIZE=10 => 4096 bytes (Intel SDM §3.2.6)
    pub const BSIZE_4096: u32 = (1 << 25) | (1 << 17);
    pub const BSIZE_8192: u32 = (1 << 25) | (1 << 16);
    pub const SECRC: u32 = 1 << 26;
}

pub mod tctl {
    pub const EN: u32 = 1 << 1;
    pub const PSP: u32 = 1 << 3;
    pub const CT_SHIFT: u32 = 4;
    pub const COLD_SHIFT: u32 = 12;
}

pub mod int_bits {
    pub const TXDW: u32 = 1 << 0;
    pub const TXQE: u32 = 1 << 1;
    pub const LSC: u32 = 1 << 2;
    pub const RXDMT0: u32 = 1 << 4;
    pub const RXO: u32 = 1 << 6;
    pub const RXT0: u32 = 1 << 7;
    pub const MDAC: u32 = 1 << 9;
    pub const RXCFG: u32 = 1 << 10;
    pub const GPI0: u32 = 1 << 11;
    pub const GPI1: u32 = 1 << 12;
}

pub mod eerd {
    pub const START: u32 = 1 << 0;
    pub const DONE: u32 = 1 << 4;
    pub const ADDR_SHIFT: u32 = 8;
    pub const DATA_SHIFT: u32 = 16;
}

/// RX descriptor status bits (SDM §3.2.3).
pub mod rx_status {
    pub const DD: u8 = 1 << 0;
    pub const EOP: u8 = 1 << 1;
    pub const IXSM: u8 = 1 << 3;
    pub const UDP: u8 = 1 << 4;
    pub const TCP: u8 = 1 << 5;
    pub const IPCS: u8 = 1 << 6;
    pub const PIF: u8 = 1 << 7;
}

/// RX descriptor error bits (SDM §3.2.3).
pub mod rx_errors {
    pub const CE: u8 = 1 << 0;
    pub const SE: u8 = 1 << 1;
    pub const SEQ: u8 = 1 << 3;
    pub const CPRS: u8 = 1 << 4;
    pub const TCPE: u8 = 1 << 5;
    pub const IPE: u8 = 1 << 6;
}

/// TX descriptor status bits (SDM §3.3.3).
pub mod tx_status {
    pub const DD: u8 = 1 << 0;
    pub const EC: u8 = 1 << 1;
    pub const LC: u8 = 1 << 2;
    pub const TU: u8 = 1 << 3;
}
