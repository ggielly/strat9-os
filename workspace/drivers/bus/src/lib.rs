#![no_std]
#![feature(alloc_error_handler)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

extern crate alloc;

pub mod mmio;
pub mod probe;
pub mod registry; // The list of bus drivers is here
pub mod scheme;

pub mod arm_cci;
pub mod arm_integrator_lm;
pub mod brcmstb_gisb;
pub mod bt1_apb;
pub mod bt1_axi;
pub mod da8xx_mstpri;
pub mod hisi_lpc;
pub mod imx_aipstz;
pub mod imx_weim;
pub mod intel_ixp4xx_eb;
pub mod mips_cdmm;
pub mod moxtet;
pub mod mvebu_mbus;
pub mod omap_l3_noc;
pub mod omap_l3_smx;
pub mod omap_ocp2scp;
pub mod qcom_ebi2;
pub mod qcom_ssc_block_bus;
pub mod simple_pm_bus;
pub mod stm32_etzpc;
pub mod stm32_firewall;
pub mod stm32_rifsc;
pub mod sun50i_de2;
pub mod sunxi_rsb;
pub mod tegra_aconnect;
pub mod tegra_gmi;
pub mod ti_pwmss;
pub mod ti_sysc;
pub mod ts_nbus;
pub mod uniphier_system_bus;
pub mod vexpress_config;

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusError {
    InitFailed,
    Timeout,
    InvalidAddress,
    PermissionDenied,
    NotSupported,
    IoError,
    InvalidArgument,
    DeviceNotFound,
    BusFault,
    SlaveError,
    ProtocolError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    On,
    Suspended,
    Off,
}

#[derive(Debug, Clone)]
pub struct BusChild {
    pub name: String,
    pub base_addr: u64,
    pub size: u64,
}

pub trait BusDriver: Send + Sync {
    /// Performs the name operation.
    fn name(&self) -> &str;
    /// Performs the compatible operation.
    fn compatible(&self) -> &[&str] {
        &[]
    }
    /// Returns the optional [`FirewallController`] capability, if any.
    ///
    /// Drivers managing hardware isolation (STM32 ETZPC/RIFSC) override
    /// this to return `Some(self)`, which makes the scheme server publish
    /// the `/bus/<driver>/firewall/...` paths. The default returns `None`:
    /// no firewall capability.
    fn as_firewall(&self) -> Option<&dyn stm32_firewall::FirewallController> {
        None
    }
    /// Returns `true` if the driver believes the hardware is present.
    ///
    /// The default returns `true` (assume present : let `init()` decide).
    /// Override to `false` for software-backed buses (GPIO, SPI, …) that
    /// cannot auto-detect their hardware without platform configuration.
    fn probe(&self) -> bool {
        true
    }
    /// Performs the init operation.
    fn init(&mut self, base: usize) -> Result<(), BusError>;
    /// Performs the shutdown operation.
    fn shutdown(&mut self) -> Result<(), BusError>;
    /// Performs the suspend operation.
    fn suspend(&mut self) -> Result<(), BusError> {
        Ok(())
    }
    /// Performs the resume operation.
    fn resume(&mut self) -> Result<(), BusError> {
        Ok(())
    }
    /// Reads reg.
    fn read_reg(&self, offset: usize) -> Result<u32, BusError>;
    /// Writes reg.
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError>;
    /// Performs the error count operation.
    fn error_count(&self) -> u64 {
        0
    }
    /// Performs the children operation.
    fn children(&self) -> Vec<BusChild> {
        Vec::new()
    }
    /// Handles irq.
    fn handle_irq(&mut self) -> bool {
        false
    }
}
