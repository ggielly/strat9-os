use crate::{BusChild, BusDriver, BusError, PowerState};
use alloc::{string::String, vec::Vec};

const MAX_MODULES: usize = 6;

const COMPATIBLE: &[&str] = &["cznic,moxtet"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoxtetModuleId {
    Sfp,
    Pci,
    Topaz,
    Peridot,
    Usb3,
    PcieBridge,
    Unknown(u8),
}

impl MoxtetModuleId {
    /// Builds this from raw.
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            0x01 => MoxtetModuleId::Sfp,
            0x02 => MoxtetModuleId::Pci,
            0x03 => MoxtetModuleId::Topaz,
            0x04 => MoxtetModuleId::Peridot,
            0x05 => MoxtetModuleId::Usb3,
            0x06 => MoxtetModuleId::PcieBridge,
            other => MoxtetModuleId::Unknown(other),
        }
    }

    /// Performs the name operation.
    pub fn name(&self) -> &'static str {
        match self {
            MoxtetModuleId::Sfp => "sfp",
            MoxtetModuleId::Pci => "pci",
            MoxtetModuleId::Topaz => "topaz",
            MoxtetModuleId::Peridot => "peridot",
            MoxtetModuleId::Usb3 => "usb3",
            MoxtetModuleId::PcieBridge => "pcie-bridge",
            MoxtetModuleId::Unknown(_) => "unknown",
        }
    }
}

/// A module discovered on the moxtet SPI shift chain.
pub struct MoxtetModule {
    pub id: MoxtetModuleId,
    /// Zero-based position of this module on the chain. This is the value
    /// used to address the module through `BusDriver::read_reg`/
    /// `write_reg` — see [`Moxtet`] for the addressing scheme.
    pub index: u8,
}

/// CZ.NIC Turris Omnia moxtet bus driver.
///
/// # Register-space semantics (`/bus/moxtet/reg/<idx>`)
///
/// The moxtet bus has **no MMIO register file**: it is a software-defined
/// FPGA bus where modules are enumerated at discovery time over SPI and
/// addressed by their position on the shift chain. Consequently, the
/// `offset` argument of [`BusDriver::read_reg`]/[`BusDriver::write_reg`]
/// (and therefore the `/bus/moxtet/reg/<idx>` scheme paths) is a
/// **zero-based module index**, *not* a byte/hex MMIO offset:
///
/// - `reg/0` reads/writes the TX/RX buffer slot of module 0,
/// - offsets `>= module_count` are rejected with [`BusError::DeviceNotFound`].
///
/// This deviates from MMIO-mapped buses where `reg/<hex>` is a hardware
/// offset; it is kept for compatibility with the [`BusDriver`] trait API.
pub struct Moxtet {
    modules: Vec<MoxtetModule>,
    module_count: usize,
    tx_buf: [u8; MAX_MODULES + 1],
    rx_buf: [u8; MAX_MODULES + 1],
    irq_mask: [bool; MAX_MODULES],
    power_state: PowerState,
}

impl Moxtet {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            module_count: 0,
            tx_buf: [0; MAX_MODULES + 1],
            rx_buf: [0; MAX_MODULES + 1],
            irq_mask: [false; MAX_MODULES],
            power_state: PowerState::Off,
        }
    }

    /// Performs the discover topology operation.
    pub fn discover_topology(&mut self, spi_data: &[u8]) {
        self.modules.clear();
        self.module_count = 0;

        for (i, &byte) in spi_data.iter().enumerate().skip(1) {
            if i > MAX_MODULES {
                break;
            }
            let id = MoxtetModuleId::from_raw(byte);
            self.modules.push(MoxtetModule {
                id,
                index: (i - 1) as u8,
            });
            self.module_count = i;
        }
    }

    /// Performs the module read operation.
    pub fn module_read(&self, index: usize) -> Result<u8, BusError> {
        if index >= self.module_count {
            return Err(BusError::DeviceNotFound);
        }
        Ok(self.rx_buf[index + 1])
    }

    /// Performs the module write operation.
    pub fn module_write(&mut self, index: usize, value: u8) -> Result<(), BusError> {
        if index >= self.module_count {
            return Err(BusError::DeviceNotFound);
        }
        self.tx_buf[index + 1] = value;
        Ok(())
    }

    /// Sets irq mask.
    pub fn set_irq_mask(&mut self, index: usize, masked: bool) {
        if index < MAX_MODULES {
            self.irq_mask[index] = masked;
        }
    }
}

impl BusDriver for Moxtet {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "moxtet"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Requires explicit SPI backend configuration; no auto-detect.
    fn probe(&self) -> bool {
        false
    }

    /// Performs the init operation.
    fn init(&mut self, _base: usize) -> Result<(), BusError> {
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads the RX buffer slot of the module at `offset`.
    ///
    /// `offset` is a **module index** (0-based position on the shift
    /// chain), not an MMIO byte offset — see the [`Moxtet`] type docs.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        self.module_read(offset).map(|v| v as u32)
    }

    /// Writes the TX buffer slot of the module at `offset`.
    ///
    /// `offset` is a **module index** (0-based position on the shift
    /// chain), not an MMIO byte offset — see the [`Moxtet`] type docs.
    /// Only the low 8 bits of `value` are significant: each module slot
    /// is one byte wide in the SPI frame.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        self.module_write(offset, value as u8)
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.modules
            .iter()
            .map(|m| BusChild {
                name: String::from(m.id.name()),
                base_addr: m.index as u64,
                size: 1,
            })
            .collect()
    }

    /// Handles irq.
    fn handle_irq(&mut self) -> bool {
        for i in 0..self.module_count {
            if self.irq_mask[i] {
                continue;
            }
            let status = self.rx_buf[i + 1];
            if status & 0xF0 != 0 {
                return true;
            }
        }
        false
    }
}
