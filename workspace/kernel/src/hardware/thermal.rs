//! ACPI thermal management : temperature reading and fan control.
//!
//! On Lenovo ThinkPads (X13, T14, etc.), the Embedded Controller (EC)
//! exposes temperature sensors and fan control registers at known offsets.
//! This driver reads the CPU temperature and controls the fan via the EC.
//!
//! ## ThinkPad EC register map (verified for X13 Gen 1/2)
//!
//! | Register | Description                     |
//! |----------|---------------------------------|
//! | 0x78     | CPU temperature (°C, unsigned)  |
//! | 0x79     | GPU temperature (°C, unsigned)  |
//! | 0x7A     | Battery temperature (°C)        |
//! | 0x93     | Fan control: bit 0 = enable,    |
//! |          |   bits 1–7 = speed level (0=max)|
//! | 0x94     | Fan speed (RPM, 16-bit LE)      |
//! | 0x84     | EC query: thermal event         |

#![allow(dead_code)]

use crate::hardware::ec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};
use spin::Mutex;

/// EC register: CPU temperature in degrees Celsius.
const EC_REG_TEMP_CPU: u8 = 0x78;

/// EC register: GPU temperature in degrees Celsius.
const EC_REG_TEMP_GPU: u8 = 0x79;

/// EC register: battery temperature in degrees Celsius.
const EC_REG_TEMP_BAT: u8 = 0x7A;

/// EC register: fan control byte.
/// - Bit 0: fan enabled
/// - Bits 1–7: speed level (0 = max speed, 127 = minimum speed)
const EC_REG_FAN_CTRL: u8 = 0x93;

/// EC register: fan speed in RPM (16-bit little-endian).
const EC_REG_FAN_SPEED: u8 = 0x94;

/// Fan speed levels for the ThinkPad manual fan control.
/// Level 0 = maximum speed, 7 = off. The EC uses an inverted scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FanSpeed {
    /// Maximum speed (loudest, best cooling).
    Max = 0,
    /// High speed.
    High = 2,
    /// Medium speed.
    Medium = 4,
    /// Low speed (quiet).
    Low = 6,
    /// Off.
    Off = 7,
}

/// Thermal state snapshot, read atomically from EC registers.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThermalState {
    pub cpu_temp_c: u8,
    pub gpu_temp_c: u8,
    pub bat_temp_c: u8,
    pub fan_rpm: u16,
    pub fan_enabled: bool,
    pub fan_level: u8,
}

/// Latest thermal snapshot (updated by periodic polling).
static THERMAL_STATE: Mutex<ThermalState> = Mutex::new(ThermalState {
    cpu_temp_c: 0,
    gpu_temp_c: 0,
    bat_temp_c: 0,
    fan_rpm: 0,
    fan_enabled: false,
    fan_level: 0,
});

/// Whether thermal management is initialized.
static THERMAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Last read CPU temperature (for quick non-locking access).
static LAST_CPU_TEMP: AtomicU8 = AtomicU8::new(0);

/// Last read fan RPM (for quick non-locking access).
static LAST_FAN_RPM: AtomicU16 = AtomicU16::new(0);

/// Temperature thresholds for fan control (in °C).
const FAN_ON_THRESHOLD: u8 = 55;
const FAN_MAX_THRESHOLD: u8 = 85;
const FAN_OFF_THRESHOLD: u8 = 45;

/// Whether automatic fan control is enabled.
static AUTO_FAN_CONTROL: AtomicBool = AtomicBool::new(true);

/// Initialize the thermal subsystem.
pub fn init() {
    if !ec::is_available() {
        log::warn!("[Thermal] EC not available, thermal management disabled");
        return;
    }

    let state = read_thermal_state();
    if state.cpu_temp_c > 0 && state.cpu_temp_c < 130 {
        THERMAL_INITIALIZED.store(true, Ordering::Release);
        LAST_CPU_TEMP.store(state.cpu_temp_c, Ordering::Relaxed);
        LAST_FAN_RPM.store(state.fan_rpm, Ordering::Relaxed);

        log::info!(
            "[Thermal] CPU={}°C GPU={}°C BAT={}°C Fan={}RPM (enabled={})",
            state.cpu_temp_c,
            state.gpu_temp_c,
            state.bat_temp_c,
            state.fan_rpm,
            state.fan_enabled,
        );
    } else {
        log::warn!(
            "[Thermal] Failed to read temperature (got {}°C), EC may not be ThinkPad-compatible",
            state.cpu_temp_c
        );
    }
}

/// Read the current thermal state from EC registers.
pub fn read_thermal_state() -> ThermalState {
    let cpu_temp = ec::read(EC_REG_TEMP_CPU).unwrap_or(0);
    let gpu_temp = ec::read(EC_REG_TEMP_GPU).unwrap_or(0);
    let bat_temp = ec::read(EC_REG_TEMP_BAT).unwrap_or(0);

    let fan_lo = ec::read(EC_REG_FAN_SPEED).unwrap_or(0);
    let fan_hi = ec::read(EC_REG_FAN_SPEED.wrapping_add(1)).unwrap_or(0);
    let fan_rpm = u16::from_le_bytes([fan_lo, fan_hi]);

    let fan_ctrl = ec::read(EC_REG_FAN_CTRL).unwrap_or(0x87);
    let fan_enabled = (fan_ctrl & 1) == 0;
    let fan_level = (fan_ctrl >> 1) & 0x7F;

    ThermalState {
        cpu_temp_c: cpu_temp,
        gpu_temp_c: gpu_temp,
        bat_temp_c: bat_temp,
        fan_rpm,
        fan_enabled,
        fan_level,
    }
}

/// Update the cached thermal state. Call periodically (e.g., from timer tick).
pub fn poll() {
    if !THERMAL_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let state = read_thermal_state();
    LAST_CPU_TEMP.store(state.cpu_temp_c, Ordering::Relaxed);
    LAST_FAN_RPM.store(state.fan_rpm, Ordering::Relaxed);

    let mut current = THERMAL_STATE.lock();
    *current = state;

    if AUTO_FAN_CONTROL.load(Ordering::Relaxed) {
        drop(current);
        auto_fan_control(state.cpu_temp_c);
    }
}

/// Get the last known CPU temperature (lock-free).
pub fn cpu_temperature() -> u8 {
    LAST_CPU_TEMP.load(Ordering::Relaxed)
}

/// Get the last known fan RPM (lock-free).
pub fn fan_rpm() -> u16 {
    LAST_FAN_RPM.load(Ordering::Relaxed)
}

/// Enable automatic fan control based on CPU temperature.
pub fn set_auto_fan_control(enabled: bool) {
    AUTO_FAN_CONTROL.store(enabled, Ordering::Relaxed);
}

/// Set the fan to a specific speed level.
///
/// `level` maps to the ThinkPad EC fan control register:
/// - 0 = maximum speed
/// - 7 = off
/// - Intermediate values scale between max and off
pub fn set_fan_speed(speed: FanSpeed) {
    let ctrl: u8 = ((speed as u8) << 1) | 0; // bit 0 = 0 means manual mode
    ec::write(EC_REG_FAN_CTRL, ctrl);
}

/// Enable or disable the fan entirely.
pub fn set_fan_enabled(enabled: bool) {
    let current = ec::read(EC_REG_FAN_CTRL).unwrap_or(0x87);
    let new_val = if enabled {
        current & !1 // bit 0 = 0: fan enabled (active-low on some models)
    } else {
        current | 1 // bit 0 = 1: fan disabled
    };
    ec::write(EC_REG_FAN_CTRL, new_val);
}

/// Automatic fan control logic based on CPU temperature.
fn auto_fan_control(cpu_temp: u8) {
    if cpu_temp >= FAN_MAX_THRESHOLD {
        set_fan_speed(FanSpeed::Max);
    } else if cpu_temp >= FAN_ON_THRESHOLD {
        set_fan_speed(FanSpeed::High);
    } else if cpu_temp <= FAN_OFF_THRESHOLD {
        set_fan_speed(FanSpeed::Off);
    }
    // Between FAN_OFF_THRESHOLD and FAN_ON_THRESHOLD: maintain current fan state
}

/// Dump thermal status to serial console.
pub fn dump_status() {
    let state = read_thermal_state();
    log::info!(
        "[Thermal] CPU={}°C GPU={}°C BAT={}°C Fan={}RPM level={} auto={}",
        state.cpu_temp_c,
        state.gpu_temp_c,
        state.bat_temp_c,
        state.fan_rpm,
        state.fan_level,
        AUTO_FAN_CONTROL.load(Ordering::Relaxed),
    );
}
