use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const DA8XX_MSTPRI0_OFFSET: usize = 0x0;
const DA8XX_MSTPRI1_OFFSET: usize = 0x4;
const DA8XX_MSTPRI2_OFFSET: usize = 0x8;

const COMPATIBLE: &[&str] = &["ti,da850-mstpri"];

#[derive(Clone, Copy)]
pub struct MasterPriDescr {
    pub reg: usize,
    pub shift: u32,
    pub mask: u32,
}

pub const MSTPRI_ARM_I: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI0_OFFSET, shift: 0, mask: 0x0000_000F };
pub const MSTPRI_ARM_D: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI0_OFFSET, shift: 4, mask: 0x0000_00F0 };
pub const MSTPRI_UPP: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI0_OFFSET, shift: 16, mask: 0x000F_0000 };
pub const MSTPRI_SATA: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI0_OFFSET, shift: 20, mask: 0x00F0_0000 };
pub const MSTPRI_PRU0: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 0, mask: 0x0000_000F };
pub const MSTPRI_PRU1: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 4, mask: 0x0000_00F0 };
pub const MSTPRI_EDMA30TC0: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 8, mask: 0x0000_0F00 };
pub const MSTPRI_EDMA30TC1: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 12, mask: 0x0000_F000 };
pub const MSTPRI_EDMA31TC0: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 16, mask: 0x000F_0000 };
pub const MSTPRI_VPIF_DMA0: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 24, mask: 0x0F00_0000 };
pub const MSTPRI_VPIF_DMA1: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI1_OFFSET, shift: 28, mask: 0xF000_0000 };
pub const MSTPRI_EMAC: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI2_OFFSET, shift: 0, mask: 0x0000_000F };
pub const MSTPRI_USB0: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI2_OFFSET, shift: 8, mask: 0x0000_0F00 };
pub const MSTPRI_USB1: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI2_OFFSET, shift: 12, mask: 0x0000_F000 };
pub const MSTPRI_UHPI: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI2_OFFSET, shift: 20, mask: 0x00F0_0000 };
pub const MSTPRI_LCDC: MasterPriDescr = MasterPriDescr { reg: DA8XX_MSTPRI2_OFFSET, shift: 28, mask: 0xF000_0000 };

pub struct MasterPriority {
    pub master: MasterPriDescr,
    pub priority: u32,
}

pub struct Da8xxMstpri {
    regs: MmioRegion,
    priorities: Vec<MasterPriority>,
    power_state: PowerState,
}

impl Da8xxMstpri {
    pub fn new() -> Self {
        Self {
            regs: MmioRegion::new(),
            priorities: Vec::new(),
            power_state: PowerState::Off,
        }
    }

    pub fn add_priority(&mut self, master: MasterPriDescr, priority: u32) {
        self.priorities.push(MasterPriority { master, priority });
    }

    fn apply_priorities(&self) {
        for p in &self.priorities {
            let val = self.regs.read32(p.master.reg);
            let new_val = (val & !p.master.mask) | ((p.priority << p.master.shift) & p.master.mask);
            self.regs.write32(p.master.reg, new_val);
        }
    }
}

impl BusDriver for Da8xxMstpri {
    fn name(&self) -> &str { "da8xx-mstpri" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x10);
        self.apply_priorities();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn read_reg(&self, offset: usize) -> Result<u32, BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        Ok(self.regs.read32(offset))
    }

    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError> {
        if !self.regs.is_valid() { return Err(BusError::InitFailed); }
        self.regs.write32(offset, value);
        Ok(())
    }
}
