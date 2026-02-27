// HPET (High Precision Event Timer) Driver
// Reference: HPET spec 1.0a
//
// Uses the kernel's ACPI subsystem (already initialized) to locate the HPET
// table, then maps and configures the HPET MMIO registers.

#![allow(dead_code)]

use crate::memory::{self, phys_to_virt};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

const HPET_GENERAL_CAP_ID: usize = 0x000;
const HPET_GENERAL_CONFIG: usize = 0x010;
const HPET_MAIN_COUNTER: usize = 0x0F0;

const HPET_CAP_NUM_TIMERS_MASK: u64 = 0x0000_0000_0000_1F00;
const HPET_CAP_COUNTER_SIZE: u64 = 1 << 13;
const HPET_CAP_COUNTER_CLK_PERIOD_SHIFT: u32 = 32;

const HPET_CONFIG_ENABLE: u64 = 0x0000_0000_0000_0001;

const GAS_ADDR_SPACE_MEMORY: u8 = 0;

/// HPET MMIO register page size (minimum 1 KiB, map one full page).
const HPET_MMIO_MAP_SIZE: u64 = 0x1000;

pub struct HpetInfo {
    base_addr: u64,
    mmio_base: usize,
    num_timers: u8,
    tick_period_fs: u32,
    tick_period_ns: u32,
    is_64bit: bool,
}

unsafe impl Send for HpetInfo {}
unsafe impl Sync for HpetInfo {}

static HPET_INFO: Mutex<Option<HpetInfo>> = Mutex::new(None);
static HPET_INITIALIZED: AtomicBool = AtomicBool::new(false);

unsafe fn hpet_read(mmio_base: usize, offset: usize) -> u64 {
    core::ptr::read_volatile((mmio_base + offset) as *const u64)
}

unsafe fn hpet_write(mmio_base: usize, offset: usize, value: u64) {
    core::ptr::write_volatile((mmio_base + offset) as *mut u64, value);
}

/// Initialize HPET using the already-discovered ACPI table.
pub fn init() -> Result<(), &'static str> {
    log::info!("[HPET] Searching for HPET...");

    let hpet_acpi = crate::acpi::hpet::HpetAcpiTable::get()
        .ok_or("HPET ACPI table not found")?;

    // Read packed fields safely.
    let gas = hpet_acpi.gen_addr_struct;
    let base_addr = gas.phys_addr;
    let address_space = gas.address_space;
    let comparator_desc = hpet_acpi.comparator_descriptor;
    let min_tick = hpet_acpi.min_periodic_clock_tick;

    log::info!(
        "[HPET] Found HPET: base=0x{:x}, comparators={}, min_tick={}",
        base_addr,
        (comparator_desc >> 3) & 0x1F,
        min_tick,
    );

    if address_space != GAS_ADDR_SPACE_MEMORY {
        return Err("HPET: address space is not memory-mapped");
    }
    if base_addr == 0 || (base_addr & 0x7) != 0 {
        return Err("HPET: base address invalid or misaligned");
    }

    // Map the HPET MMIO page(s) into the HHDM before any register access.
    memory::paging::ensure_identity_map_range(base_addr, HPET_MMIO_MAP_SIZE);

    let mmio_base = phys_to_virt(base_addr) as usize;

    unsafe {
        let cap_id = hpet_read(mmio_base, HPET_GENERAL_CAP_ID);
        let num_timers = ((cap_id & HPET_CAP_NUM_TIMERS_MASK) >> 8) as u8 + 1;
        let is_64bit = (cap_id & HPET_CAP_COUNTER_SIZE) != 0;
        let tick_period_fs = (cap_id >> HPET_CAP_COUNTER_CLK_PERIOD_SHIFT) as u32;
        if tick_period_fs == 0 {
            return Err("HPET counter period is zero");
        }
        if tick_period_fs > 1_000_000_000 {
            return Err("HPET counter period out of range");
        }
        let tick_period_ns = core::cmp::max(1, tick_period_fs / 1_000_000);

        let info = HpetInfo {
            base_addr,
            mmio_base,
            num_timers,
            tick_period_fs,
            tick_period_ns,
            is_64bit,
        };

        *HPET_INFO.lock() = Some(info);

        let mut config = hpet_read(mmio_base, HPET_GENERAL_CONFIG);
        config |= HPET_CONFIG_ENABLE;
        hpet_write(mmio_base, HPET_GENERAL_CONFIG, config);

        HPET_INITIALIZED.store(true, Ordering::SeqCst);

        log::info!(
            "[HPET] Initialized: {} timers, {}-bit, {} ns/tick",
            num_timers,
            if is_64bit { 64 } else { 32 },
            tick_period_ns,
        );
    }

    Ok(())
}

/// Read main counter value
pub fn read_counter() -> u64 {
    let info = HPET_INFO.lock();
    match *info {
        Some(ref hpet) => unsafe { hpet_read(hpet.mmio_base, HPET_MAIN_COUNTER) },
        None => 0,
    }
}

/// Get tick period in nanoseconds
pub fn tick_period_ns() -> u32 {
    let info = HPET_INFO.lock();
    match *info {
        Some(ref hpet) => hpet.tick_period_ns,
        None => 0,
    }
}

/// Get HPET frequency in Hz
pub fn frequency_hz() -> u64 {
    let info = HPET_INFO.lock();
    match *info {
        Some(ref hpet) if hpet.tick_period_fs > 0 => 1_000_000_000_000_000u64 / hpet.tick_period_fs as u64,
        _ => 0,
    }
}

/// Check if HPET is initialized
pub fn is_available() -> bool {
    HPET_INITIALIZED.load(Ordering::Relaxed)
}

/// Get number of timers
pub fn num_timers() -> u8 {
    let info = HPET_INFO.lock();
    match *info {
        Some(ref hpet) => hpet.num_timers,
        None => 0,
    }
}

/// High-precision delay in microseconds
pub fn delay_us(us: u64) {
    if !is_available() {
        // Fallback to busy wait
        for _ in 0..(us * 100) {
            core::hint::spin_loop();
        }
        return;
    }
    
    let period_ns = tick_period_ns() as u64;
    if period_ns == 0 {
        return;
    }
    let start = read_counter();
    let ticks_needed = if us == 0 {
        0
    } else {
        core::cmp::max(1, (us.saturating_mul(1000)) / period_ns)
    };
    while read_counter().wrapping_sub(start) < ticks_needed {
        core::hint::spin_loop();
    }
}

/// High-precision delay in milliseconds
pub fn delay_ms(ms: u64) {
    delay_us(ms * 1000);
}

/// Get elapsed time since boot in milliseconds
pub fn uptime_ms() -> u64 {
    if !is_available() {
        return 0;
    }
    
    let counter = read_counter() as u128;
    let period_ns = tick_period_ns() as u128;
    ((counter.saturating_mul(period_ns)) / 1_000_000) as u64
}

/// Get elapsed time since boot in seconds
pub fn uptime_secs() -> u64 {
    uptime_ms() / 1000
}
