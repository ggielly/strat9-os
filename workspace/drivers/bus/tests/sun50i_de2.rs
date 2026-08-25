//! Regression tests for the `sun50i_de2` SRAM ownership management.
//!
//! Issue #57: `claim_sram()`/`release_sram()` were log-only stubs that just
//! flipped an internal flag. These tests drive the real MMIO sequence
//! against a RAM-backed fake SRAM controller.

use strat9_bus_drivers::{
    BusDriver, BusError,
    sun50i_de2::{SramConfig, Sun50iDe2},
};

/// Fake SRAM controller register block (RAM-backed): control register for
/// the DE2 region sits at +0x004.
#[repr(C)]
struct FakeSramc {
    _pad: u32,
    reg: u32,
}

const OWNER_MASK: u32 = 0b111 << 12;
const DE2_OWNER: u32 = 0b101;

fn config(base: usize) -> SramConfig {
    SramConfig {
        ctrl_base: base,
        ctrl_offset: 0x4,
        owner_mask: OWNER_MASK,
        de2_owner: DE2_OWNER,
    }
}

fn new_fake_sramc() -> &'static mut FakeSramc {
    Box::leak(Box::new(FakeSramc { _pad: 0, reg: 0 }))
}

#[test]
fn claim_requires_platform_configuration() {
    let mut de2 = Sun50iDe2::new();
    assert_eq!(de2.claim_sram(), Err(BusError::InitFailed));
    assert!(!de2.sram_claimed());
}

#[test]
fn claim_sets_ownership_field_via_mmio() {
    let sramc = new_fake_sramc();
    let mut de2 = Sun50iDe2::new();
    de2.set_sram_config(config(sramc as *mut FakeSramc as usize));

    de2.claim_sram().expect("claim with valid config");

    // Field replaced by DE2 owner; neighbouring bits preserved.
    let expected = (sramc.reg & !OWNER_MASK) | ((DE2_OWNER << 12) & OWNER_MASK);
    assert_eq!(sramc.reg, expected);
    assert!(de2.sram_claimed());
}

// NOTE: the read-back verification branch (`BusFault` when a real
// controller ignores writes) cannot be exercised from userspace tests:
// plain RAM always accepts stores. It is exercised by QEMU-level
// anti-regression runs against real hardware emulation instead.

#[test]
fn release_restores_default_owner() {
    let sramc = new_fake_sramc();
    let mut de2 = Sun50iDe2::new();
    de2.set_sram_config(config(sramc as *mut FakeSramc as usize));

    de2.claim_sram().unwrap();
    assert_ne!(sramc.reg & OWNER_MASK, 0);

    de2.release_sram();
    assert_eq!(sramc.reg & OWNER_MASK, 0, "ownership field must be cleared");
    assert!(!de2.sram_claimed());
}

#[test]
fn release_without_config_is_safe() {
    let mut de2 = Sun50iDe2::new();
    de2.release_sram(); // must not panic nor touch hardware
    assert!(!de2.sram_claimed());
}

#[test]
fn init_fails_without_sram_configuration() {
    let mut de2 = Sun50iDe2::new();
    // init(0) is what the registry attempts before any platform wiring.
    assert_eq!(
        de2.init(0),
        Err(BusError::InitFailed),
        "DE2 without routed SRAM must not come up"
    );
}
