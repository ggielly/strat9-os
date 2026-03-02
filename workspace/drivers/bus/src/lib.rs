#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

pub mod mmio;
pub mod scheme;

pub mod simple_pm_bus;
pub mod bt1_axi;
pub mod bt1_apb;
pub mod vexpress_config;
pub mod tegra_aconnect;
pub mod tegra_gmi;
pub mod arm_cci;
pub mod arm_integrator_lm;
pub mod omap_ocp2scp;
pub mod omap_l3_noc;
pub mod omap_l3_smx;
pub mod ti_pwmss;
pub mod ti_sysc;
pub mod imx_weim;
pub mod imx_aipstz;
pub mod da8xx_mstpri;
pub mod ts_nbus;
pub mod sunxi_rsb;
pub mod sun50i_de2;
pub mod mvebu_mbus;
pub mod moxtet;
pub mod stm32_rifsc;
pub mod stm32_etzpc;
pub mod stm32_firewall;
pub mod qcom_ebi2;
pub mod qcom_ssc_block_bus;
pub mod hisi_lpc;
pub mod intel_ixp4xx_eb;
pub mod brcmstb_gisb;
pub mod mips_cdmm;
pub mod uniphier_system_bus;

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
    fn name(&self) -> &str;
    fn compatible(&self) -> &[&str];
    fn init(&mut self, base: usize) -> Result<(), BusError>;
    fn shutdown(&mut self) -> Result<(), BusError>;
    fn suspend(&mut self) -> Result<(), BusError> { Ok(()) }
    fn resume(&mut self) -> Result<(), BusError> { Ok(()) }
    fn read_reg(&self, offset: usize) -> Result<u32, BusError>;
    fn write_reg(&mut self, offset: usize, value: u32) -> Result<(), BusError>;
    fn error_count(&self) -> u64 { 0 }
    fn children(&self) -> Vec<BusChild> { Vec::new() }
    fn handle_irq(&mut self) -> bool { false }
}
