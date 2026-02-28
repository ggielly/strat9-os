// RTC (Real Time Clock) Driver
// Reference: MC146818A RTC chip
//
// Features:
// - Current time reading (BCD and binary modes)
// - CMOS RAM access
// - Update interrupt handling
// - Alarm support

#![allow(dead_code)]

use crate::arch::x86_64::io::{inb, outb};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// CMOS ports
const CMOS_ADDR_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

// CMOS registers
const CMOS_REG_SECOND: u8 = 0x00;
const CMOS_REG_MINUTE: u8 = 0x02;
const CMOS_REG_HOUR: u8 = 0x04;
const CMOS_REG_WEEKDAY: u8 = 0x06;
const CMOS_REG_DAY: u8 = 0x07;
const CMOS_REG_MONTH: u8 = 0x08;
const CMOS_REG_YEAR: u8 = 0x09;
const CMOS_REG_STATUS_A: u8 = 0x0A;
const CMOS_REG_STATUS_B: u8 = 0x0B;
const CMOS_REG_STATUS_C: u8 = 0x0C;

// Status register A bits
const STATUS_A_UIP: u8 = 0x80; // Update In Progress

// Status register B bits
const STATUS_B_PIE: u8 = 0x40; // Periodic interrupt enable
const STATUS_B_UIE: u8 = 0x10; // Update interrupt enable
const STATUS_B_DM: u8 = 0x04; // Data mode (1=binary, 0=BCD)
const STATUS_B_24H: u8 = 0x02; // 24-hour mode

// Status register C bits (read-only, clears interrupts)
// RTC frequency options (Hz)
const RTC_FREQ_1024: u8 = 6;  // 1024 Hz
const RTC_FREQ_256: u8 = 8;   // 256 Hz
const RTC_FREQ_64: u8 = 10;   // 64 Hz
const RTC_FREQ_16: u8 = 12;   // 16 Hz
const RTC_FREQ_4: u8 = 14;    // 4 Hz
const RTC_FREQ_1: u8 = 15;    // 1 Hz

/// RTC date/time structure
#[derive(Clone, Copy, Debug)]
pub struct RtcDateTime {
    pub second: u8,
    pub minute: u8,
    pub hour: u8,
    pub weekday: u8,  // 0=Sunday, 6=Saturday
    pub day: u8,
    pub month: u8,
    pub year: u16,
    pub century: u16,
}

impl RtcDateTime {
    pub fn new() -> Self {
        Self {
            second: 0,
            minute: 0,
            hour: 0,
            weekday: 0,
            day: 0,
            month: 0,
            year: 2000,
            century: 20,
        }
    }
    
    /// Convert to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
    pub fn to_timestamp(&self) -> u64 {
        let mut year = self.year as i64;
        let mut month = self.month as i64;
        let day = self.day as i64;
        let hour = self.hour as i64;
        let minute = self.minute as i64;
        let second = self.second as i64;
        
        // Adjust for months starting from March
        if month <= 2 {
            year -= 1;
            month += 12;
        }
        
        // Calculate days since epoch (Howard Hinnant algorithm)
        let days = 365 * year + year / 4 - year / 100 + year / 400
            + (153 * (month - 3) + 2) / 5 + day - 1 - 719468;
        
        // Convert to seconds
        ((days * 86400 + hour * 3600 + minute * 60 + second) as u64)
    }
    
    /// Format as ISO 8601 string (simplified)
    pub fn to_string(&self) -> [u8; 19] {
        let mut buf = [0u8; 19];
        let year = self.year;
        
        // YYYY-MM-DDTHH:MM:SS
        buf[0] = b'0' + ((year / 1000) % 10) as u8;
        buf[1] = b'0' + ((year / 100) % 10) as u8;
        buf[2] = b'0' + ((year / 10) % 10) as u8;
        buf[3] = b'0' + (year % 10) as u8;
        buf[4] = b'-';
        buf[5] = b'0' + (self.month / 10);
        buf[6] = b'0' + (self.month % 10);
        buf[7] = b'-';
        buf[8] = b'0' + (self.day / 10);
        buf[9] = b'0' + (self.day % 10);
        buf[10] = b'T';
        buf[11] = b'0' + (self.hour / 10);
        buf[12] = b'0' + (self.hour % 10);
        buf[13] = b':';
        buf[14] = b'0' + (self.minute / 10);
        buf[15] = b'0' + (self.minute % 10);
        buf[16] = b':';
        buf[17] = b'0' + (self.second / 10);
        buf[18] = b'0' + (self.second % 10);
        
        buf
    }
}

/// RTC driver state
pub struct RtcDriver {
    cmos_century_reg: u8,
    use_binary: bool,
    last_update_tick: AtomicU64,
}

unsafe impl Send for RtcDriver {}
unsafe impl Sync for RtcDriver {}

static RTC_DRIVER: Mutex<Option<RtcDriver>> = Mutex::new(None);
static RTC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static RTC_LAST_TICK: AtomicU64 = AtomicU64::new(0);

/// Read CMOS register
fn cmos_read(reg: u8) -> u8 {
    unsafe {
        outb(CMOS_ADDR_PORT, reg | 0x80); // NMI disable
        inb(CMOS_DATA_PORT)
    }
}

/// Write CMOS register
fn cmos_write(reg: u8, value: u8) {
    unsafe {
        outb(CMOS_ADDR_PORT, reg | 0x80); // NMI disable
        outb(CMOS_DATA_PORT, value);
    }
}

/// Convert BCD to binary
fn bcd_to_binary(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd / 16) * 10)
}

/// Check if RTC update is in progress
fn is_update_in_progress() -> bool {
    cmos_read(CMOS_REG_STATUS_A) & STATUS_A_UIP != 0
}

/// Read time from RTC registers
fn read_rtc_time() -> RtcDateTime {
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct RawRtc {
        second: u8,
        minute: u8,
        hour: u8,
        weekday: u8,
        day: u8,
        month: u8,
        year: u8,
        century: u8,
        status_b: u8,
    }

    fn read_raw_once(century_reg: u8) -> RawRtc {
        RawRtc {
            second: cmos_read(CMOS_REG_SECOND),
            minute: cmos_read(CMOS_REG_MINUTE),
            hour: cmos_read(CMOS_REG_HOUR),
            weekday: cmos_read(CMOS_REG_WEEKDAY),
            day: cmos_read(CMOS_REG_DAY),
            month: cmos_read(CMOS_REG_MONTH),
            year: cmos_read(CMOS_REG_YEAR),
            century: if century_reg != 0 { cmos_read(century_reg) } else { 0 },
            status_b: cmos_read(CMOS_REG_STATUS_B),
        }
    }

    let (century_reg, default_binary) = {
        let driver = RTC_DRIVER.lock();
        if let Some(ref drv) = *driver {
            (drv.cmos_century_reg, drv.use_binary)
        } else {
            (0, false)
        }
    };

    let mut raw = loop {
        while is_update_in_progress() {
            core::hint::spin_loop();
        }
        let a = read_raw_once(century_reg);
        while is_update_in_progress() {
            core::hint::spin_loop();
        }
        let b = read_raw_once(century_reg);
        if a == b {
            break b;
        }
    };

    let use_binary = if raw.status_b == 0 { default_binary } else { (raw.status_b & STATUS_B_DM) != 0 };
    let pm_bit = raw.hour & 0x80;
    if !use_binary {
        raw.second = bcd_to_binary(raw.second);
        raw.minute = bcd_to_binary(raw.minute);
        raw.hour = bcd_to_binary(raw.hour & 0x7F);
        raw.weekday = bcd_to_binary(raw.weekday);
        raw.day = bcd_to_binary(raw.day);
        raw.month = bcd_to_binary(raw.month);
        raw.year = bcd_to_binary(raw.year);
        if raw.century != 0 {
            raw.century = bcd_to_binary(raw.century);
        }
    }

    let is_24h = (raw.status_b & STATUS_B_24H) != 0;
    if !is_24h {
        let pm = pm_bit != 0;
        raw.hour &= 0x7F;
        if pm {
            if raw.hour != 12 {
                raw.hour = raw.hour.saturating_add(12);
            }
        } else if raw.hour == 12 {
            raw.hour = 0;
        }
    }

    let full_year = if raw.century != 0 {
        (raw.century as u16) * 100 + raw.year as u16
    } else if raw.year >= 70 {
        1900 + raw.year as u16
    } else {
        2000 + raw.year as u16
    };

    RtcDateTime {
        second: raw.second,
        minute: raw.minute,
        hour: raw.hour,
        weekday: raw.weekday.saturating_sub(1),
        day: raw.day,
        month: raw.month,
        year: full_year,
        century: (full_year / 100) as u16,
    }
}

/// Initialize RTC
pub fn init() -> Result<(), &'static str> {
    log::info!("[RTC] Initializing RTC...");
    
    // Read status B to check mode
    let status_b = cmos_read(CMOS_REG_STATUS_B);
    let use_binary = (status_b & STATUS_B_DM) != 0;
    
    // Detect century register (ACPI FADT would tell us, but we try common values)
    let cmos_century_reg = 0x32; // Common value
    
    // Verify century register works (convert from BCD if needed)
    let century_raw = cmos_read(cmos_century_reg);
    let century_val = if use_binary { century_raw } else { bcd_to_binary(century_raw) };
    let cmos_century_reg = if century_val >= 19 && century_val <= 21 {
        cmos_century_reg
    } else {
        0
    };
    
    let driver = RtcDriver {
        cmos_century_reg,
        use_binary,
        last_update_tick: AtomicU64::new(0),
    };
    
    *RTC_DRIVER.lock() = Some(driver);
    
    // Enable update interrupt (IRQ8)
    // This would be done in IDT setup
    // For now, just enable the interrupt in RTC
    let mut status_b = cmos_read(CMOS_REG_STATUS_B);
    status_b |= STATUS_B_UIE;
    cmos_write(CMOS_REG_STATUS_B, status_b);
    
    // Clear any pending interrupts
    let _ = cmos_read(CMOS_REG_STATUS_C);
    
    RTC_INITIALIZED.store(true, Ordering::SeqCst);
    
    let time = RtcDriver::get_time();
    log::info!(
        "[RTC] Initialized: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.year, time.month, time.day,
        time.hour, time.minute, time.second
    );
    
    Ok(())
}

impl RtcDriver {
    /// Get current time from RTC
    pub fn get_time() -> RtcDateTime {
        read_rtc_time()
    }
    
    /// Get Unix timestamp
    pub fn get_timestamp() -> u64 {
        Self::get_time().to_timestamp()
    }
    
    /// Get last update tick
    pub fn last_update_tick() -> u64 {
        RTC_LAST_TICK.load(Ordering::Relaxed)
    }
}

/// RTC interrupt handler (IRQ8)
pub fn rtc_interrupt_handler() {
    // Read status C to clear interrupt
    let _status_c = cmos_read(CMOS_REG_STATUS_C);
    
    // Update tick counter
    RTC_LAST_TICK.fetch_add(1, Ordering::Relaxed);
    
    // Notify driver
    let driver = RTC_DRIVER.lock();
    if let Some(ref drv) = *driver {
        drv.last_update_tick.fetch_add(1, Ordering::Relaxed);
    }
}

/// Check if RTC is available
pub fn is_available() -> bool {
    RTC_INITIALIZED.load(Ordering::Relaxed)
}

/// Get current date/time
pub fn get_datetime() -> RtcDateTime {
    RtcDriver::get_time()
}

/// Get Unix timestamp
pub fn get_timestamp() -> u64 {
    RtcDriver::get_timestamp()
}

/// Set periodic interrupt frequency
pub fn set_periodic_frequency(freq_hz: u16) {
    // Rate is encoded as: rate = 32768 / (2^(rate-1))
    // Valid rates: 6-15 (1024 Hz to 1 Hz)
    let rate = match freq_hz {
        1024 => RTC_FREQ_1024,
        256 => RTC_FREQ_256,
        64 => RTC_FREQ_64,
        16 => RTC_FREQ_16,
        4 => RTC_FREQ_4,
        1 => RTC_FREQ_1,
        _ => {
            log::warn!(
                "[RTC] Unsupported periodic frequency {} Hz, falling back to 1 Hz",
                freq_hz
            );
            RTC_FREQ_1
        }
    };
    
    let mut status_a = cmos_read(CMOS_REG_STATUS_A);
    status_a = (status_a & 0xF0) | (rate & 0x0F);
    cmos_write(CMOS_REG_STATUS_A, status_a);
}

/// Enable/disable periodic interrupt
pub fn set_periodic_interrupt(enable: bool) {
    let mut status_b = cmos_read(CMOS_REG_STATUS_B);
    if enable {
        status_b |= STATUS_B_PIE;
    } else {
        status_b &= !STATUS_B_PIE;
    }
    cmos_write(CMOS_REG_STATUS_B, status_b);
}

/// Get seconds since boot (approximate, based on RTC updates)
pub fn uptime_secs() -> u64 {
    RTC_LAST_TICK.load(Ordering::Relaxed)
}
