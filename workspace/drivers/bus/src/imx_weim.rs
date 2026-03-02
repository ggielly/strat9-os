use alloc::{string::String, vec::Vec};
use crate::{BusChild, BusDriver, BusError, PowerState};
use crate::mmio::MmioRegion;

const MAX_CS_REGS_COUNT: usize = 6;
const MAX_CS_COUNT: usize = 6;

const COMPATIBLE: &[&str] = &[
    "fsl,imx1-weim",
    "fsl,imx27-weim",
    "fsl,imx50-weim",
    "fsl,imx51-weim",
    "fsl,imx6q-weim",
];

#[derive(Clone, Copy)]
pub struct WeimDevtype {
    pub cs_count: usize,
    pub cs_regs_count: usize,
    pub cs_stride: usize,
    pub wcr_offset: usize,
    pub wcr_bcm: u32,
    pub wcr_cont_bclk: u32,
}

pub const IMX1_WEIM: WeimDevtype = WeimDevtype {
    cs_count: 6, cs_regs_count: 2, cs_stride: 0x08,
    wcr_offset: 0, wcr_bcm: 0, wcr_cont_bclk: 0,
};

pub const IMX27_WEIM: WeimDevtype = WeimDevtype {
    cs_count: 6, cs_regs_count: 3, cs_stride: 0x10,
    wcr_offset: 0, wcr_bcm: 0, wcr_cont_bclk: 0,
};

pub const IMX50_WEIM: WeimDevtype = WeimDevtype {
    cs_count: 4, cs_regs_count: 6, cs_stride: 0x18,
    wcr_offset: 0x90, wcr_bcm: 1 << 0, wcr_cont_bclk: 1 << 3,
};

pub const IMX51_WEIM: WeimDevtype = WeimDevtype {
    cs_count: 6, cs_regs_count: 6, cs_stride: 0x18,
    wcr_offset: 0, wcr_bcm: 0, wcr_cont_bclk: 0,
};

pub struct CsTiming {
    pub is_applied: bool,
    pub regs: [u32; MAX_CS_REGS_COUNT],
}

impl CsTiming {
    pub const fn new() -> Self {
        Self {
            is_applied: false,
            regs: [0; MAX_CS_REGS_COUNT],
        }
    }
}

pub struct ImxWeim {
    regs: MmioRegion,
    devtype: WeimDevtype,
    timings: [CsTiming; MAX_CS_COUNT],
    power_state: PowerState,
    children: Vec<BusChild>,
}

impl ImxWeim {
    pub fn new(devtype: WeimDevtype) -> Self {
        Self {
            regs: MmioRegion::new(),
            devtype,
            timings: [const { CsTiming::new() }; MAX_CS_COUNT],
            power_state: PowerState::Off,
            children: Vec::new(),
        }
    }

    pub fn set_cs_timing(&mut self, cs: usize, regs: &[u32]) {
        if cs >= self.devtype.cs_count || regs.len() > self.devtype.cs_regs_count {
            return;
        }
        for (i, &val) in regs.iter().enumerate() {
            self.timings[cs].regs[i] = val;
        }
        self.timings[cs].is_applied = true;
    }

    pub fn apply_timings(&self) {
        for cs in 0..self.devtype.cs_count {
            if !self.timings[cs].is_applied {
                continue;
            }
            let base = cs * self.devtype.cs_stride;
            for i in 0..self.devtype.cs_regs_count {
                self.regs.write32(base + i * 4, self.timings[cs].regs[i]);
            }
        }
    }

    pub fn set_burst_clock(&self, enable: bool) {
        if self.devtype.wcr_offset == 0 { return; }
        let mut wcr = self.regs.read32(self.devtype.wcr_offset);
        if enable {
            wcr |= self.devtype.wcr_bcm;
        } else {
            wcr &= !self.devtype.wcr_bcm;
        }
        self.regs.write32(self.devtype.wcr_offset, wcr);
    }

    pub fn add_child(&mut self, child: BusChild) {
        self.children.push(child);
    }
}

impl BusDriver for ImxWeim {
    fn name(&self) -> &str { "imx-weim" }

    fn compatible(&self) -> &[&str] { COMPATIBLE }

    fn init(&mut self, base: usize) -> Result<(), BusError> {
        let size = self.devtype.cs_count * self.devtype.cs_stride + 0x100;
        self.regs.init(base, size);
        self.apply_timings();
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

    fn children(&self) -> Vec<BusChild> {
        self.children.clone()
    }
}
