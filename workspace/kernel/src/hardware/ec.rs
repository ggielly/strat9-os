//! Embedded Controller (EC) driver for x86.
//!
//! Provides direct access to the ACPI Embedded Controller via I/O ports
//! 0x62 (data) and 0x66 (command/status). Used for temperature reading,
//! fan control, and battery management on laptops (ThinkPad X13, etc.).
//!
//! Reference: ACPI Embedded Controller Interface Specification 1.0a

#![allow(dead_code)]

use crate::arch::x86_64::io::{inb, outb};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// EC data port (read/write data bytes).
const EC_DATA_PORT: u16 = 0x62;

/// EC command/status port (write commands, read status).
const EC_SC_PORT: u16 = 0x66;

/// EC status register bits.
const EC_STATUS_OBF: u8 = 1 << 0; // Output Buffer Full — data available to read
const EC_STATUS_IBF: u8 = 1 << 1; // Input Buffer Full — controller busy, don't write
const EC_STATUS_SCI: u8 = 1 << 5; // SCI event pending

/// EC commands.
const EC_CMD_READ: u8 = 0x80; // Read EC register
const EC_CMD_WRITE: u8 = 0x81; // Write EC register
const EC_CMD_QUERY: u8 = 0x84; // Query event

/// Maximum number of retries when waiting for EC to become ready.
const EC_TIMEOUT: u32 = 100_000;

/// Whether the EC was detected and initialized successfully.
static EC_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Serialize all EC access to prevent interleaved command/data sequences.
static EC_LOCK: Mutex<()> = Mutex::new(());

/// Wait for the EC input buffer to be empty (ready to accept a write).
///
/// Returns `true` if the IBF cleared, `false` on timeout.
fn ec_wait_ibf() -> bool {
    for _ in 0..EC_TIMEOUT {
        unsafe {
            if inb(EC_SC_PORT) & EC_STATUS_IBF == 0 {
                return true;
            }
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait for the EC output buffer to become full (data available to read).
///
/// Returns `Some(byte)` if data is ready, `None` on timeout.
fn ec_wait_obf() -> Option<u8> {
    for _ in 0..EC_TIMEOUT {
        unsafe {
            let status = inb(EC_SC_PORT);
            if status & EC_STATUS_OBF != 0 {
                return Some(inb(EC_DATA_PORT));
            }
        }
        core::hint::spin_loop();
    }
    None
}

/// Read a single byte from an EC register.
///
/// # Safety
/// The caller must ensure no concurrent EC access occurs without holding `EC_LOCK`.
unsafe fn ec_read_byte(reg: u8) -> Option<u8> {
    if !ec_wait_ibf() {
        return None;
    }
    outb(EC_SC_PORT, EC_CMD_READ);
    if !ec_wait_ibf() {
        return None;
    }
    outb(EC_DATA_PORT, reg);
    ec_wait_obf()
}

/// Write a single byte to an EC register.
///
/// # Safety
/// The caller must ensure no concurrent EC access occurs without holding `EC_LOCK`.
unsafe fn ec_write_byte(reg: u8, val: u8) -> bool {
    if !ec_wait_ibf() {
        return false;
    }
    outb(EC_SC_PORT, EC_CMD_WRITE);
    if !ec_wait_ibf() {
        return false;
    }
    outb(EC_DATA_PORT, reg);
    if !ec_wait_ibf() {
        return false;
    }
    outb(EC_DATA_PORT, val);
    true
}

/// Query the EC for a pending event. Returns the event byte (Query ID).
///
/// # Safety
/// The caller must ensure no concurrent EC access occurs without holding `EC_LOCK`.
unsafe fn ec_query() -> Option<u8> {
    if !ec_wait_ibf() {
        return None;
    }
    outb(EC_SC_PORT, EC_CMD_QUERY);
    ec_wait_obf()
}

// =========================================================================
// Public API
// =========================================================================

/// Detect and initialize the Embedded Controller.
///
/// Probes port 0x66 to verify the EC is present. On most x86 laptops the EC
/// is always present; this mainly serves to confirm the I/O ports are wired.
pub fn init() {
    // Try reading EC status to see if the port responds.
    // A non-zero/0xFF response indicates a live EC.
    let _lock = EC_LOCK.lock();
    unsafe {
        let status = inb(EC_SC_PORT);
        if status != 0xFF {
            EC_AVAILABLE.store(true, Ordering::Release);
            log::info!("[EC] Embedded Controller detected (status=0x{:02x})", status);
        } else {
            log::warn!("[EC] No Embedded Controller found (status=0xFF)");
        }
    }
}

/// Returns whether the EC was detected.
pub fn is_available() -> bool {
    EC_AVAILABLE.load(Ordering::Acquire)
}

/// Read a byte from an EC register.
pub fn read(reg: u8) -> Option<u8> {
    let _lock = EC_LOCK.lock();
    if !EC_AVAILABLE.load(Ordering::Acquire) {
        return None;
    }
    unsafe { ec_read_byte(reg) }
}

/// Write a byte to an EC register.
pub fn write(reg: u8, val: u8) -> bool {
    let _lock = EC_LOCK.lock();
    if !EC_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }
    unsafe { ec_write_byte(reg, val) }
}

/// Query a pending EC event (SCI). Returns the query byte.
pub fn query_event() -> Option<u8> {
    let _lock = EC_LOCK.lock();
    if !EC_AVAILABLE.load(Ordering::Acquire) {
        return None;
    }
    unsafe { ec_query() }
}

/// Check if there is a pending SCI event in the EC.
pub fn has_sci_event() -> bool {
    if !EC_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }
    unsafe { inb(EC_SC_PORT) & EC_STATUS_SCI != 0 }
}
