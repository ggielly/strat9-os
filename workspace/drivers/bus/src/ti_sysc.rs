use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const SYSC_IDLE_SMART: u32 = 2;
const SYSC_IDLE_NO: u32 = 1;
const SYSC_IDLE_FORCE: u32 = 0;

const MAX_MODULE_SOFTRESET_WAIT: u32 = 10000;

const COMPATIBLE: &[&str] = &[
    "ti,sysc-omap2",
    "ti,sysc-omap4",
    "ti,sysc-omap4-timer",
    "ti,sysc-omap4-simple",
    "ti,sysc-omap2-timer",
    "ti,sysc-omap3430-sr",
    "ti,sysc-omap3630-sr",
    "ti,sysc-omap4-sr",
    "ti,sysc-omap3-sham",
    "ti,sysc-omap-aes",
    "ti,sysc-mcasp",
    "ti,sysc-dra7-mcasp",
    "ti,sysc-usb-host-fs",
    "ti,sysc-dra7-mcan",
    "ti,sysc-pruss",
];

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct SyscQuirks: u32 {
        const QUIRK_16BIT = 1 << 0;
        const QUIRK_RESET_STATUS = 1 << 1;
        const QUIRK_SWSUP_SIDLE = 1 << 2;
        const QUIRK_SWSUP_MSTANDBY = 1 << 3;
        const QUIRK_SWSUP_SIDLE_ACT = 1 << 4;
        const QUIRK_NO_IDLE = 1 << 5;
        const QUIRK_NO_RESET_ON_INIT = 1 << 6;
        const QUIRK_EXT_OPT_CLK = 1 << 7;
        const QUIRK_REINIT_ON_CTX_LOST = 1 << 8;
    }
}

pub struct SyscRegbits {
    pub midle_shift: u32,
    pub sidle_shift: u32,
    pub clkact_shift: u32,
    pub srst_shift: u32,
    pub autoidle_shift: u32,
    pub emufree_shift: u32,
}

pub const REGBITS_OMAP2: SyscRegbits = SyscRegbits {
    midle_shift: 12,
    sidle_shift: 3,
    clkact_shift: 8,
    srst_shift: 1,
    autoidle_shift: 0,
    emufree_shift: 5,
};

pub const REGBITS_OMAP4: SyscRegbits = SyscRegbits {
    midle_shift: 4,
    sidle_shift: 2,
    clkact_shift: 0,
    srst_shift: 0,
    autoidle_shift: 0,
    emufree_shift: 1,
};

pub struct TiSysc {
    regs: MmioRegion,
    rev_offset: Option<usize>,
    sysc_offset: Option<usize>,
    syss_offset: Option<usize>,
    regbits: &'static SyscRegbits,
    quirks: SyscQuirks,
    revision: u32,
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl TiSysc {
    pub fn new(regbits: &'static SyscRegbits) -> Self {
        Self {
            regs: MmioRegion::new(),
            rev_offset: Some(0),
            sysc_offset: None,
            syss_offset: None,
            regbits,
            quirks: SyscQuirks::empty(),
            revision: 0,
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    pub fn set_offsets(&mut self, rev: Option<usize>, sysc: Option<usize>, syss: Option<usize>) {
        self.rev_offset = rev;
        self.sysc_offset = sysc;
        self.syss_offset = syss;
    }

    pub fn set_quirks(&mut self, quirks: SyscQuirks) {
        self.quirks = quirks;
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }

    fn read_sysc(&self) -> u32 {
        match self.sysc_offset {
            Some(off) => {
                if self.quirks.contains(SyscQuirks::QUIRK_16BIT) {
                    self.regs.read16(off) as u32
                } else {
                    self.regs.read32(off)
                }
            }
            None => 0,
        }
    }

    fn write_sysc(&self, val: u32) {
        if let Some(off) = self.sysc_offset {
            if self.quirks.contains(SyscQuirks::QUIRK_16BIT) {
                self.regs.write16(off, val as u16);
            } else {
                self.regs.write32(off, val);
            }
        }
    }

    pub fn read_revision(&self) -> u32 {
        match self.rev_offset {
            Some(off) => self.regs.read32(off),
            None => 0,
        }
    }

    pub fn enable_module(&self) {
        let mut val = self.read_sysc();
        let sidle_mask = 0x3 << self.regbits.sidle_shift;
        val &= !sidle_mask;
        val |= SYSC_IDLE_SMART << self.regbits.sidle_shift;

        if self.regbits.midle_shift > 0 {
            let midle_mask = 0x3 << self.regbits.midle_shift;
            val &= !midle_mask;
            val |= SYSC_IDLE_SMART << self.regbits.midle_shift;
        }

        if self.regbits.autoidle_shift > 0 || self.regbits.clkact_shift > 0 {
            val |= 1 << self.regbits.autoidle_shift;
        }

        self.write_sysc(val);
    }

    pub fn disable_module(&self) {
        let mut val = self.read_sysc();
        let sidle_mask = 0x3 << self.regbits.sidle_shift;
        val &= !sidle_mask;
        val |= SYSC_IDLE_FORCE << self.regbits.sidle_shift;

        if self.regbits.midle_shift > 0 {
            let midle_mask = 0x3 << self.regbits.midle_shift;
            val &= !midle_mask;
            val |= SYSC_IDLE_FORCE << self.regbits.midle_shift;
        }

        self.write_sysc(val);
    }

    pub fn softreset(&self) -> Result<(), BusError> {
        if self.quirks.contains(SyscQuirks::QUIRK_NO_RESET_ON_INIT) {
            return Ok(());
        }

        if self.sysc_offset.is_none() {
            return Err(BusError::NotSupported);
        }

        let mut val = self.read_sysc();
        val |= 1 << self.regbits.srst_shift;
        self.write_sysc(val);

        for _ in 0..MAX_MODULE_SOFTRESET_WAIT {
            let current = self.read_sysc();
            if (current & (1 << self.regbits.srst_shift)) == 0 {
                return Ok(());
            }
        }

        if let Some(syss) = self.syss_offset {
            for _ in 0..MAX_MODULE_SOFTRESET_WAIT {
                let status = self.regs.read32(syss);
                if (status & 1) != 0 {
                    return Ok(());
                }
            }
        }

        Err(BusError::Timeout)
    }
}

impl BusDriver for TiSysc {
    fn name(&self) -> &str { "ti-sysc" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        self.regs.init(base, 0x100);
        self.revision = self.read_revision();

        if !self.quirks.contains(SyscQuirks::QUIRK_NO_RESET_ON_INIT) {
            self.softreset()?;
        }

        self.enable_module();
        self.power_state = PowerState::On;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BusError> {
        self.disable_module();
        self.power_state = PowerState::Off;
        Ok(())
    }

    fn suspend(&mut self) -> Result<(), BusError> {
        self.disable_module();
        self.power_state = PowerState::Suspended;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), BusError> {
        if self.quirks.contains(SyscQuirks::QUIRK_REINIT_ON_CTX_LOST) {
            self.softreset()?;
        }
        self.enable_module();
        self.power_state = PowerState::On;
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

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
