/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

use core::sync::atomic::{AtomicU64, Ordering};

use super::sbi;

pub const TIMER_HZ: u64 = 100;
pub const NS_PER_TICK: u64 = 1_000_000_000 / TIMER_HZ;

static USE_SSTC: AtomicU64 = AtomicU64::new(0);
static FREQUENCY: AtomicU64 = AtomicU64::new(0);
static INTERVAL: AtomicU64 = AtomicU64::new(0);
static NEXT_DEADLINE: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);

fn program_deadline(deadline: u64) {
    if USE_SSTC.load(Ordering::Acquire) != 0 {
        unsafe {
            core::arch::asm!("csrw stimecmp, {0}", in(reg) deadline, options(nostack));
        }
    } else {
        let _ = sbi::set_timer(deadline);
    }
}

pub fn init(frequency: u64, sstc: bool) -> Result<u64, &'static str> {
    if frequency == 0 {
        return Err("SBI time frequency is zero");
    }
    let interval = frequency / TIMER_HZ;
    if interval == 0 {
        return Err("SBI timer interval is zero");
    }
    let now = super::rdtsc();
    let deadline = now.saturating_add(interval);
    USE_SSTC.store(u64::from(sstc), Ordering::Release);
    program_deadline(deadline);
    FREQUENCY.store(frequency, Ordering::Release);
    INTERVAL.store(interval, Ordering::Release);
    NEXT_DEADLINE.store(deadline, Ordering::Release);
    TICKS.store(0, Ordering::Release);
    unsafe {
        core::arch::asm!("csrs sie, {0}", in(reg) 1usize << 5, options(nostack));
    }
    super::sti();
    Ok(frequency)
}

pub fn handle_interrupt() {
    let interval = INTERVAL.load(Ordering::Acquire);
    if interval == 0 {
        return;
    }
    let next = NEXT_DEADLINE
        .load(Ordering::Acquire)
        .saturating_add(interval);
    NEXT_DEADLINE.store(next, Ordering::Release);
    program_deadline(next);
    crate::process::scheduler::timer_tick();
    TICKS.fetch_add(1, Ordering::AcqRel);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Acquire)
}

pub fn is_apic_timer_active() -> bool {
    false
}

pub fn apic_ticks_per_10ms() -> u32 {
    0
}

pub fn start_apic_timer_cached() {
    let _ = init(
        FREQUENCY.load(Ordering::Acquire),
        USE_SSTC.load(Ordering::Acquire) != 0,
    );
}
