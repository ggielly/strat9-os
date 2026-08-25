//! Regression tests for the `qcom_ssc_block_bus` MMIO mapping requirements.
//!
//! Issue #58: only the halt registers were ever mapped; `bus_init()` /
//! `bus_deinit()` unconditionally accessed the unmapped config regions,
//! tripping `MmioRegion` assertions (kernel panic). They also swallowed
//! their own poll timeouts.

use strat9_bus_drivers::{BusDriver, BusError, qcom_ssc_block_bus::QcomSscBlockBus};

/// RAM-backed stand-in for one 16-byte register block.
#[repr(C, align(4))]
struct FakeRegs([u32; 4]);

impl FakeRegs {
    fn new() -> &'static mut Self {
        Box::leak(Box::new(Self([0; 4])))
    }

    fn base(&mut self) -> usize {
        self.0.as_mut_ptr() as usize
    }
}

/// Offsets used by the driver inside each block.
const REG0: usize = 0;
const AXI_IDLE: usize = 2; // 0x8

const CLAMP_EN_OVRD: u32 = 1 << 4;
const CLAMP_EN_OVRD_VAL: u32 = 1 << 5;
const CONFIG1_CFG: u32 = 1 << 31;

#[test]
fn init_without_config_mapping_fails_cleanly() {
    let mut bus = QcomSscBlockBus::new();
    let halt = FakeRegs::new();
    bus.init_halt_regs(halt.base());

    // config0/config1 never mapped: must fail with InitFailed, NOT panic
    // in MmioRegion::checked_addr.
    assert_eq!(bus.init(halt.base()), Err(BusError::InitFailed));
}

#[test]
fn bus_init_applies_clamp_sequence_and_waits_for_idle() {
    let halt = FakeRegs::new();
    let cfg0 = FakeRegs::new();
    let cfg1 = FakeRegs::new();

    let mut bus = QcomSscBlockBus::new();
    bus.init_halt_regs(halt.base());
    bus.init_config_regs(cfg0.base(), cfg1.base());

    // AXI already idle at offset 0x8.
    halt.0[AXI_IDLE] = 1;
    // Pre-set bits that bus_init is expected to clear.
    cfg0.0[REG0] = CLAMP_EN_OVRD_VAL;
    cfg1.0[REG0] = CONFIG1_CFG;

    assert_eq!(bus.init(halt.base()), Ok(()));

    assert_eq!(cfg0.0[REG0] & CLAMP_EN_OVRD_VAL, 0, "override val cleared");
    assert_ne!(cfg0.0[REG0] & CLAMP_EN_OVRD, 0, "override en set");
    assert_eq!(cfg1.0[REG0] & CONFIG1_CFG, 0, "config1 cfg cleared");
    assert_eq!(halt.0[0], 0, "halt request de-asserted");
}

#[test]
fn bus_init_times_out_when_axi_never_goes_idle() {
    let halt = FakeRegs::new();
    let cfg0 = FakeRegs::new();
    let cfg1 = FakeRegs::new();

    let mut bus = QcomSscBlockBus::new();
    bus.init_halt_regs(halt.base());
    bus.init_config_regs(cfg0.base(), cfg1.base());

    // Idle register stays 0 for the whole poll window.
    assert_eq!(bus.init(halt.base()), Err(BusError::Timeout));
}

#[test]
fn bus_deinit_sets_haltreq_and_safety_clamps() {
    let halt = FakeRegs::new();
    let cfg0 = FakeRegs::new();
    let cfg1 = FakeRegs::new();

    let mut bus = QcomSscBlockBus::new();
    bus.init_halt_regs(halt.base());
    bus.init_config_regs(cfg0.base(), cfg1.base());

    // Halt handshake completes immediately.
    halt.0[AXI_IDLE] = 1;
    halt.0[1] = 1; // AXI_HALTACK at 0x4
    assert_eq!(bus.shutdown(), Ok(()));

    assert_eq!(halt.0[0], 1, "halt request asserted");
    assert_ne!(cfg0.0[REG0] & CLAMP_EN_OVRD_VAL, 0, "clamp override set");
    assert_ne!(cfg1.0[REG0] & CONFIG1_CFG, 0, "config1 cfg restored");
}

#[test]
fn bus_deinit_reports_timeout_but_still_clamps() {
    let halt = FakeRegs::new();
    let cfg0 = FakeRegs::new();
    let cfg1 = FakeRegs::new();

    let mut bus = QcomSscBlockBus::new();
    bus.init_halt_regs(halt.base());
    bus.init_config_regs(cfg0.base(), cfg1.base());

    halt.0[AXI_IDLE] = 1;
    bus.init(halt.base()).unwrap();

    // HALTACK stays low: shutdown must report Timeout yet apply clamps
    // (safety first).
    assert_eq!(bus.shutdown(), Err(BusError::Timeout));
    assert_ne!(cfg0.0[REG0] & CLAMP_EN_OVRD_VAL, 0);
}
