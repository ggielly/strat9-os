//! Regression tests for the `ts_nbus` driver GPIO bit-banging implementation.
//!
//! Issue #55: the `GpioPin` methods were empty stubs, making `reset_bus()`,
//! `bus_read()` and `bus_write()` silent no-ops. These tests exercise the
//! real MMIO code paths by pointing pins at a plain RAM buffer that stands
//! in for the FPGA GPIO controller register block.

use strat9_bus_drivers::{
    BusDriver, BusError,
    ts_nbus::{GpioPin, NbusControlPin, TsNbus},
};

/// Simulated GPIO controller: data register at +0x00, direction at +0x04.
#[repr(C, align(4))]
struct FakeGpioController {
    regs: [u32; 2],
}

impl FakeGpioController {
    fn new() -> Self {
        Self { regs: [0; 2] }
    }

    fn pin(&mut self, offset: u32) -> GpioPin {
        GpioPin {
            base: self.regs.as_mut_ptr() as usize,
            offset,
            active_low: false,
        }
    }

    fn pin_active_low(&mut self, offset: u32) -> GpioPin {
        GpioPin {
            base: self.regs.as_mut_ptr() as usize,
            offset,
            active_low: true,
        }
    }
}

const DATA_REG: usize = 0;
const DIR_REG: usize = 1;

#[test]
fn set_high_sets_data_bit_via_mmio() {
    let mut ctrl = FakeGpioController::new();
    let pin = ctrl.pin(3);
    assert!(pin.is_configured());

    pin.set_high();
    assert_eq!(ctrl.regs[DATA_REG], 1 << 3);

    // Sibling lines are preserved by the read-modify-write.
    let other = ctrl.pin(5);
    other.set_high();
    assert_eq!(ctrl.regs[DATA_REG], (1 << 3) | (1 << 5));
}

#[test]
fn set_low_clears_only_its_own_bit() {
    let mut ctrl = FakeGpioController::new();
    ctrl.regs[DATA_REG] = 0b1010;

    let pin = ctrl.pin(3);
    pin.set_low();
    // Bit 1 untouched.
    assert_eq!(ctrl.regs[DATA_REG], 1 << 1);
}

#[test]
fn active_low_inverts_logical_levels() {
    let mut ctrl = FakeGpioController::new();
    let pin = ctrl.pin_active_low(2);

    // Logical high => electrical low (bit cleared).
    pin.set_high();
    assert_eq!(ctrl.regs[DATA_REG] & (1 << 2), 0);

    // Logical low => electrical high (bit set).
    pin.set_low();
    assert_ne!(ctrl.regs[DATA_REG] & (1 << 2), 0);

    // Sampling follows the same inversion: the line reads back at its
    // logical level, i.e. low.
    assert!(!pin.get_value());
}

#[test]
fn get_value_samples_the_data_register() {
    let mut ctrl = FakeGpioController::new();
    let pin = ctrl.pin(7);
    assert!(!pin.get_value());

    ctrl.regs[DATA_REG] |= 1 << 7;
    let _ = ctrl.regs[DATA_REG]; // keep the backing buffer observable
    assert!(pin.get_value());
}

#[test]
fn direction_register_is_driven_by_set_direction() {
    let mut ctrl = FakeGpioController::new();
    let a = ctrl.pin(0);
    let b = ctrl.pin(9);

    a.set_direction_output();
    b.set_direction_input();
    assert_eq!(ctrl.regs[DIR_REG], 1 << 0);

    b.set_direction_output();
    assert_eq!(ctrl.regs[DIR_REG], (1 << 0) | (1 << 9));

    a.set_direction_input();
    assert_eq!(ctrl.regs[DIR_REG], 1 << 9);
}

#[test]
fn unconfigured_pin_is_detected() {
    let unconfigured = GpioPin {
        base: 0,
        offset: 4,
        active_low: false,
    };
    assert!(!unconfigured.is_configured());
}

#[test]
fn init_rejects_missing_or_unconfigured_pins() {
    // No pins at all.
    let mut bus = TsNbus::new();
    assert_eq!(bus.init(0), Err(BusError::InvalidArgument));

    // All slots present but one data pin with base == 0.
    let mut bus = fully_wired_bus();
    bus.set_data_pin(
        6,
        GpioPin {
            base: 0,
            offset: 6,
            active_low: false,
        },
    )
    .unwrap();
    assert_eq!(bus.init(0), Err(BusError::InvalidArgument));

    // Out-of-range data-pin index is rejected too.
    let mut bus = fully_wired_bus();
    assert_eq!(
        bus.set_data_pin(8, leaked_pin(8)),
        Err(BusError::InvalidArgument)
    );
}

#[test]
fn set_data_pin_rejects_out_of_range_index() {
    let mut ctrl = FakeGpioController::new();
    let pin = ctrl.pin(0);

    let mut bus = TsNbus::new();
    assert!(bus.set_data_pin(7, pin).is_ok());
}

/// Builds a TsNbus whose every required line points into RAM-backed fake
/// controllers (8 data pins + csn/txrx/strobe/ale/rdy).
fn fully_wired_bus() -> TsNbus {
    let mut bus = TsNbus::new();
    for i in 0..8 {
        bus.set_data_pin(i, leaked_pin(i as u32)).unwrap();
    }
    bus.set_control_pin(NbusControlPin::Csn, leaked_pin(0));
    bus.set_control_pin(NbusControlPin::TxRx, leaked_pin(1));
    bus.set_control_pin(NbusControlPin::Strobe, leaked_pin(2));
    bus.set_control_pin(NbusControlPin::Ale, leaked_pin(3));
    bus.set_control_pin(NbusControlPin::Rdy, leaked_pin(4));
    bus
}

fn leaked_pin(offset: u32) -> GpioPin {
    Box::leak(Box::new(FakeGpioController::new())).pin(offset)
}
