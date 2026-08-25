use crate::{BusChild, BusDriver, BusError, PowerState, mmio::MmioRegion};
use alloc::{string::String, vec::Vec};

const COMPATIBLE: &[&str] = &["allwinner,sun50i-a64-de2"];

/// Configuration of the Allwinner SRAM controller (SRAMC) region that the
/// Display Engine 2 must own to operate.
///
/// The exact register layout differs across sunxi SoC generations; platform
/// code (board support / DeviceTree) supplies it explicitly — mirroring the
/// `sunxi_sram_claim()` DT-driven flow in Linux (`drivers/soc/sunxi/sunxi_sram.c`).
#[derive(Debug, Clone, Copy)]
pub struct SramConfig {
    /// Physical base address of the SRAM controller register block
    /// (A64: `0x01C0_0000`).
    pub ctrl_base: usize,
    /// Offset of the control register owning the DE2 SRAM region.
    pub ctrl_offset: usize,
    /// Mask of the ownership field inside the control register.
    pub owner_mask: u32,
    /// Value within the field selecting the display engine as owner.
    pub de2_owner: u32,
}

impl SramConfig {
    /// Applies `de2_owner` into the masked field of `current`.
    fn apply_field(current: u32, cfg: &Self) -> u32 {
        let shift = cfg.owner_mask.trailing_zeros();
        (current & !cfg.owner_mask) | ((cfg.de2_owner << shift) & cfg.owner_mask)
    }
}

pub struct Sun50iDe2 {
    regs: MmioRegion,
    power_state: PowerState,
    sram_claimed: bool,
    sram_config: Option<SramConfig>,
    children: Vec<BusChild>,
}

impl Sun50iDe2 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            power_state: PowerState::Off,
            sram_claimed: false,
            sram_config: None,
            children: Vec::new(),
        }
    }

    /// Supplies the SRAM-controller configuration required by
    /// [`Self::claim_sram`] before [`BusDriver::init`] can succeed.
    pub fn set_sram_config(&mut self, cfg: SramConfig) {
        self.sram_config = Some(cfg);
    }

    /// Claims DE2 ownership of its SRAM region: read-modify-write of the
    /// SRAM controller control register to route the region away from the
    /// CPU/debug default owner, followed by a read-back verification.
    ///
    /// Fails with [`BusError::InitFailed`] when no configuration was
    /// supplied, and with [`BusError::BusFault`] when the read-back does
    /// not confirm the new ownership (controller absent or wedged).
    pub fn claim_sram(&mut self) -> Result<(), BusError> {
        let cfg = match &self.sram_config {
            Some(cfg) => *cfg,
            None => return Err(BusError::InitFailed),
        };

        // SAFETY: platform code guarantees `ctrl_base + ctrl_offset` maps
        // the SRAM controller control register when a config is supplied.
        let addr = (cfg.ctrl_base + cfg.ctrl_offset) as *mut u32;
        let current = unsafe { core::ptr::read_volatile(addr) };
        let updated = SramConfig::apply_field(current, &cfg);
        unsafe { core::ptr::write_volatile(addr, updated) };

        // Verify the controller accepted the ownership switch.
        let readback = unsafe { core::ptr::read_volatile(addr) };
        if readback != updated {
            return Err(BusError::BusFault);
        }

        self.sram_claimed = true;
        Ok(())
    }

    /// Releases DE2 SRAM ownership, restoring the default (CPU) owner.
    /// A missing configuration or failed write leaves the flag cleared so
    /// a later `shutdown`/`claim` cycle starts from a known state.
    pub fn release_sram(&mut self) {
        if let Some(cfg) = self.sram_config {
            // SAFETY: same mapping as in `claim_sram`.
            let addr = (cfg.ctrl_base + cfg.ctrl_offset) as *mut u32;
            let current = unsafe { core::ptr::read_volatile(addr) };
            let restored = current & !cfg.owner_mask;
            unsafe { core::ptr::write_volatile(addr, restored) };
        }
        self.sram_claimed = false;
    }

    /// Returns true while this instance owns the DE2 SRAM region.
    pub fn sram_claimed(&self) -> bool {
        self.sram_claimed
    }

    /// Performs the add child operation.
    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for Sun50iDe2 {
    /// Performs the name operation.
    fn name(&self) -> &str {
        "sun50i-de2"
    }

    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        COMPATIBLE
    }

    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x1000);
        self.claim_sram()?;
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError> {
        self.release_sram();
        self.power_state = PowerState::Off;
        Ok(())
    }

    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        Ok(self.regs.read32(offset))
    }

    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() {
            return Err(BusError::InitFailed);
        }
        self.regs.write32(offset, value);
        Ok(())
    }

    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
