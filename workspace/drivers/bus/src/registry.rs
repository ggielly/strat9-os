//! Bus driver registry : discovers and instantiates all known bus drivers.
//!
//! Each driver implements the `BusDriver` trait and declares one or more
//! DeviceTree-compatible strings.  The registry attempts to initialise every
//! driver; those that succeed are made available through the `/bus/` VFS
//! scheme under their own name (e.g. `/bus/simple-pm-bus/status`).
//!
//! On systems that lack DeviceTree (e.g. x86) only generic drivers such as
//! `SimplePmBus` are expected to succeed.  On ARM / embedded platforms the
//! SoC-specific drivers will match their corresponding hardware blocks.
use alloc::{boxed::Box, string::String, vec::Vec};
use strat9_syscall::call;

use crate::{
    BusDriver,
    arm_cci::ArmCci,
    arm_integrator_lm::ArmIntegratorLm,
    brcmstb_gisb::{BCM7038_OFFSETS, BrcmstbGisb},
    bt1_apb::Bt1Apb,
    bt1_axi::Bt1Axi,
    da8xx_mstpri::Da8xxMstpri,
    hisi_lpc::HisiLpc,
    imx_aipstz::{IMX8MP_DEFAULT_CFG, ImxAipstz},
    imx_weim::{IMX1_WEIM, ImxWeim},
    intel_ixp4xx_eb::IntelIxp4xxEb,
    mips_cdmm::MipsCdmm,
    moxtet::Moxtet,
    mvebu_mbus::MvebuMbus,
    omap_l3_noc::OmapL3Noc,
    omap_l3_smx::OmapL3Smx,
    omap_ocp2scp::OmapOcp2Scp,
    qcom_ebi2::QcomEbi2,
    qcom_ssc_block_bus::QcomSscBlockBus,
    simple_pm_bus::SimplePmBus,
    stm32_etzpc::Stm32Etzpc,
    stm32_rifsc::Stm32Rifsc,
    sun50i_de2::Sun50iDe2,
    sunxi_rsb::SunxiRsb,
    tegra_aconnect::TegraAconnect,
    tegra_gmi::TegraGmi,
    ti_pwmss::TiPwmss,
    ti_sysc::{REGBITS_OMAP4, TiSysc},
    ts_nbus::TsNbus,
    uniphier_system_bus::UniphierSystemBus,
    vexpress_config::VexpressConfig,
};

/// Try to probe and init a driver; log and return `(name, driver)` on success.
fn try_init<D: BusDriver + 'static>(
    name: &str,
    mut driver: D,
) -> Option<(String, Box<dyn BusDriver>)> {
    if !driver.probe() {
        let msg = alloc::format!("[bus] {}: probe failed (no hardware detected)\n", name);
        let _ = call::debug_log(msg.as_bytes());
        return None;
    }
    match driver.init(0) {
        Ok(()) => {
            let msg = alloc::format!("[bus] {}: init OK\n", name);
            let _ = call::debug_log(msg.as_bytes());
            Some((String::from(name), Box::new(driver)))
        }
        Err(e) => {
            let msg = alloc::format!("[bus] {}: init skipped ({:?})\n", name, e);
            let _ = call::debug_log(msg.as_bytes());
            None
        }
    }
}

/// Initialise all known bus drivers and return the ones that succeeded.
///
/// Call this once at startup, then pass the result to `BusSchemeServer::new()`.
pub fn init_all() -> Vec<(String, Box<dyn BusDriver>)> {
    let mut entries = Vec::new();

    // ===  Generic / fallback =================================================
    entries.extend(try_init("simple-pm-bus", SimplePmBus::new()));
    entries.extend(try_init("vexpress-config", VexpressConfig::new()));

    // ===  ARM / CoreLink =================================================
    entries.extend(try_init("arm-cci", ArmCci::new()));
    entries.extend(try_init("arm-integrator-lm", ArmIntegratorLm::new()));

    // ===  Broadcom STB ===================================================
    entries.extend(try_init("brcmstb-gisb", BrcmstbGisb::new(BCM7038_OFFSETS)));

    // ===  Baikal-T1 ======================================================
    entries.extend(try_init("bt1-apb", Bt1Apb::new()));
    entries.extend(try_init("bt1-axi", Bt1Axi::new()));

    // ===  Texas Instruments ==============================================
    entries.extend(try_init("da8xx-mstpri", Da8xxMstpri::new()));
    entries.extend(try_init("omap-l3-noc", OmapL3Noc::new()));
    entries.extend(try_init("omap-l3-smx", OmapL3Smx::new()));
    entries.extend(try_init("omap-ocp2scp", OmapOcp2Scp::new()));
    entries.extend(try_init("ti-pwmss", TiPwmss::new()));
    entries.extend(try_init("ti-sysc", TiSysc::new(&REGBITS_OMAP4)));

    // ===  HiSilicon ======================================================
    entries.extend(try_init("hisi-lpc", HisiLpc::new()));

    // ===  NXP i.MX =======================================================
    entries.extend(try_init("imx-aipstz", ImxAipstz::new(IMX8MP_DEFAULT_CFG)));
    entries.extend(try_init("imx-weim", ImxWeim::new(IMX1_WEIM)));

    // ===  Intel IXP4xx ===================================================
    entries.extend(try_init("intel-ixp4xx-eb", IntelIxp4xxEb::new()));

    // ===  MIPS ===========================================================

    entries.extend(try_init("mips-cdmm", MipsCdmm::new()));

    // ===  CZ.NIC Turris / Moxtet ========================================
    entries.extend(try_init("moxtet", Moxtet::new()));

    // ===  Marvell MVEBU ================================================
    entries.extend(try_init("mvebu-mbus", MvebuMbus::new(20, true)));

    // ===  Qualcomm =======================================================
    entries.extend(try_init("qcom-ebi2", QcomEbi2::new()));
    entries.extend(try_init("qcom-ssc-block-bus", QcomSscBlockBus::new()));

    // ===  STM32 ==========================================================
    entries.extend(try_init("stm32-etzpc", Stm32Etzpc::new()));
    entries.extend(try_init("stm32-rifsc", Stm32Rifsc::new()));

    // ===  Allwinner ======================================================
    entries.extend(try_init("sun50i-de2", Sun50iDe2::new()));
    entries.extend(try_init("sunxi-rsb", SunxiRsb::new()));

    // ===  NVIDIA Tegra ===================================================
    entries.extend(try_init("tegra-aconnect", TegraAconnect::new()));
    entries.extend(try_init("tegra-gmi", TegraGmi::new()));

    // ===  Technologic Systems ===========================================
    entries.extend(try_init("ts-nbus", TsNbus::new()));

    // ===  Socionext UniPhier ============================================
    entries.extend(try_init("uniphier-system-bus", UniphierSystemBus::new()));

    entries
}
