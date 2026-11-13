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

//! Console rendering mode selection.
//!
//! The framebuffer console has two very different cost profiles:
//!
//! * `Full` : the complete graphical console: decorative boot art, status
//!   bar, scrollback scrollbar, mouse/text cursors, dirty-rect double
//!   buffering. This is what interactive use (`top`, panels, TUI) expects.
//! * `Lite` : a deliberately boring, DOS-like text console: no decoration,
//!   no status bar, no cursor sprites, no scrollbar, no graphical UI. Every
//!   line of text still reaches the screen, but the only pixels written are
//!   glyph cells, and scrolling is a single bulk row move.
//! * `Serial` : no framebuffer touches at all: `/dev/display` stays absent
//!   and everything is logged to COM1. On a laptop this makes boot as fast
//!   as the hardware allows, and debugging happens over a USB-serial adapter
//!   (or QEMU `-serial file:`).
//!
//! Selection is a boot parameter so a machine can be switched without
//! recompiling: `console.mode=lite` (see `/boot/strat9.cfg` on the ESP).
//! Without an explicit value we pick `Lite` on bare metal and `Full` under a
//! hypervisor, where the graphical console is known to be cheap and is also
//! what the test suite screenshots.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use strat9_abi::boot::KernelArgs;

/// Framebuffer console rendering mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ConsoleMode {
    /// Full graphical console (decorations, status bar, TUI).
    Full = 1,
    /// Minimal text-only console: glyph cells and bulk scrolling.
    Lite = 2,
    /// No framebuffer output at all; serial only.
    Serial = 3,
}

/// 0 means "not selected yet".
static CONSOLE_MODE: AtomicU8 = AtomicU8::new(0);

/// Frame budget in scheduler ticks (0 = not configured).
static PRESENT_INTERVAL_TICKS: AtomicU32 = AtomicU32::new(0);

/// Timer tick rate, matching `PRESENT_MIN_TICKS` in the framebuffer layer.
const TIMER_HZ: u32 = 100;

/// Default console refresh rate.
///
/// `TIMER_HZ / 50 = 2 ticks`, so a present is due every 2 scheduler ticks.
/// Anything above 50 FPS needs a faster timer: 60+ would compute an interval
/// of 1 tick and run at the 100 Hz timer rate instead.
const DEFAULT_FPS: u32 = 50;

impl ConsoleMode {
    /// Stable name for logs and `/proc`-style reporting.
    pub const fn as_str(self) -> &'static str {
        match self {
            ConsoleMode::Full => "full",
            ConsoleMode::Lite => "lite",
            ConsoleMode::Serial => "serial",
        }
    }

    /// Parse a boot parameter value.
    ///
    /// Accepts the canonical names plus a few synonyms so a typo in a config
    /// file degrades to "unknown, keep the default" instead of a bare screen.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "full" | "gfx" | "graphical" | "rich" => Some(ConsoleMode::Full),
            "lite" | "light" | "text" | "simple" | "basic" | "dos" => Some(ConsoleMode::Lite),
            "serial" | "none" | "off" | "headless" => Some(ConsoleMode::Serial),
            _ => None,
        }
    }
}

/// `CPUID.01H:ECX[31]` : a hypervisor is present.
fn hypervisor_present() -> bool {
    let (_, _, ecx, _) = crate::arch::x86_64::cpuid(1, 0);
    ecx & (1 << 31) != 0
}

/// Pick and publish the console mode from the boot environment.
///
/// Idempotent: a second call returns the value selected by the first one, so
/// later code can call it freely without depending on init ordering.
pub fn select(args: &KernelArgs) -> ConsoleMode {
    let current = CONSOLE_MODE.load(Ordering::Acquire);
    if current != 0 {
        return decode(current);
    }

    let requested = args
        .env_get("console.mode")
        .or_else(|| args.env_get("vga.mode"))
        .and_then(ConsoleMode::parse);

    let mode = requested.unwrap_or({
        if hypervisor_present() {
            ConsoleMode::Full
        } else {
            ConsoleMode::Lite
        }
    });

    // Optional refresh cap: `console.fps=5` makes a slow panel usable by
    // trading latency for far fewer full-screen copies.
    let fps = args
        .env_get("console.fps")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|fps| (1..=60).contains(fps))
        .unwrap_or(DEFAULT_FPS);
    let interval = (TIMER_HZ / fps).max(1);
    PRESENT_INTERVAL_TICKS.store(interval, Ordering::Release);

    CONSOLE_MODE.store(mode as u8, Ordering::Release);
    mode
}

/// Minimum number of scheduler ticks between two console presents.
pub fn present_min_ticks() -> u64 {
    let configured = PRESENT_INTERVAL_TICKS.load(Ordering::Relaxed);
    if configured == 0 {
        // Not selected yet: use the compile-time default cadence.
        (TIMER_HZ / DEFAULT_FPS) as u64
    } else {
        configured as u64
    }
}

/// Currently selected console mode.
///
/// Before [`select`] runs, reports the compile-time default (`Full`) so that
/// early callers never observe an invalid state.
pub fn current() -> ConsoleMode {
    decode(CONSOLE_MODE.load(Ordering::Acquire))
}

fn decode(raw: u8) -> ConsoleMode {
    match raw {
        2 => ConsoleMode::Lite,
        3 => ConsoleMode::Serial,
        _ => ConsoleMode::Full,
    }
}

/// True when the lightweight text console is active.
#[inline]
pub fn is_lite() -> bool {
    current() == ConsoleMode::Lite
}

/// True when the framebuffer must not be touched at all.
#[inline]
pub fn is_serial() -> bool {
    current() == ConsoleMode::Serial
}
