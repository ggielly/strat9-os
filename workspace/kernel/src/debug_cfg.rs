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

//! Centralised debug configuration.
//!
//! All global toggles and knobs that control debug output, diagnostic
//! behaviour, or temporary workarounds live here.  When a debug feature
//! is no longer needed, simply flip the default to `false` : no other
//! code changes required.

use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Quiet mode : disable ALL debug output (serial, VGA, overlay)
// ---------------------------------------------------------------------------

/// Master switch to disable all debug output. When `true`, no serial,
/// VGA, overlay, or status line output is produced. The kernel still
/// runs, but produces zero diagnostic output. Intended for production
/// builds and real hardware bring-up where debug output would slow boot.
pub static QUIET_MODE: AtomicBool = AtomicBool::new(false);

/// Returns `true` if quiet mode is active (all debug output disabled).
pub fn is_quiet() -> bool {
    QUIET_MODE.load(Ordering::Relaxed)
}

/// Enable or disable quiet mode at runtime.
pub fn set_quiet(enabled: bool) {
    QUIET_MODE.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Hot-path QEMU debugcon (port 0xe9) tracing
// ---------------------------------------------------------------------------

/// Master switch for the QEMU debugcon (port 0xe9) markers: `e9_mark!`,
/// `e9_print!` and `e9_println!`.  Each byte is a port-I/O VM exit (1-2 us
/// under KVM), and some markers sit in hot paths (CR3 switch, preemption,
/// entropy, buddy/frame alloc).  Keep `false` unless chasing an early-boot
/// hang with `-debugcon stdio`; the macros then compile to nothing.
pub const E9_TRACE: bool = false;

/// Trace every `TSS.rsp0` update (`[tss-set] ...`), i.e. once per context
/// switch.  Each byte is a port-I/O VM exit, so leaving this on makes
/// single-CPU guests (and everything running in them, e.g. telnetd) crawl.
pub const E9_TRACE_TSS: bool = false;

/// Emit one byte on port 0xe9 for every acquire/release of the spinlocks
/// registered with `debug_set_trace_lock_addr` (buddy, slab...).  These locks
/// are taken thousands of times per second.  Only useful when chasing a lock
/// race with the QEMU debugcon open.
pub const E9_TRACE_LOCKS: bool = false;

// ---------------------------------------------------------------------------
// VGA live debug output
// ---------------------------------------------------------------------------

/// When `true`, every `log::info!` / `log::warn!` / etc. is drawn directly to
/// the VGA framebuffer in real time (pixel by pixel, no buffering).
pub static VGA_DEBUG_LIVE: AtomicBool = AtomicBool::new(true);

pub fn is_vga_debug_live() -> bool {
    !is_quiet() && VGA_DEBUG_LIVE.load(Ordering::Relaxed)
}

pub fn set_vga_debug_live(enabled: bool) {
    VGA_DEBUG_LIVE.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// VGA circular buffer (vgabuf) : async display via status line task
// ---------------------------------------------------------------------------

/// When `true`, log lines are written into the lock-free circular buffer
/// for async display by the status line task.
pub static VGA_DEBUG_BUFFER: AtomicBool = AtomicBool::new(true);

pub fn is_vga_debug_buffer() -> bool {
    !is_quiet() && VGA_DEBUG_BUFFER.load(Ordering::Relaxed)
}

pub fn set_vga_debug_buffer(enabled: bool) {
    VGA_DEBUG_BUFFER.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Serial output
// ---------------------------------------------------------------------------

/// Master switch to enable/disable serial port output. When `false`,
/// `serial_print!` / `serial_println!` become no-ops and `init_serial()`
/// is skipped. The serial module is still compiled but produces no output.
pub const SERIAL_ENABLED: bool = true;

// ---------------------------------------------------------------------------
// SMP
// ---------------------------------------------------------------------------

/// Bring up the application processors.
///
/// Enabled: the TLB shootdown IPI acknowledgement path is now verified (APs run
/// the vector-0xF0 handler on QEMU with `-smp 2`), and the initiator waits for
/// each online target instead of panicking on a fixed 10 ms deadline, so a
/// target inside a long IRQ-off section no longer aborts the boot.
///
/// Note for bare-metal bring-up (Lenovo X13): a CPU that never acknowledges a
/// shootdown now blocks the initiator rather than panicking; flip this back to
/// `false` if hardware AP/IPI delivery turns out to be broken.
pub const SMP_ENABLED: bool = true;

/// Run the storage drivers (VirtIO-blk, AHCI, NVMe) during the hardware stage.
///
/// Disabled temporarily: on the Lenovo X13 the storage probe resets the machine
/// (triple fault, no panic output) right after the VirtIO scan, before USB is
/// initialised. The BT test only needs initfs/ramfs, so storage can stay off
/// until the AHCI/NVMe probe is fixed.
pub const STORAGE_ENABLED: bool = false;

/// Bluetooth (btusb HCI transport, xHCI event routing, BT summary) at boot.
///
/// Disabled: the BT probe/routing path breaks boot. Re-enable once fixed.
pub const BT_ENABLED: bool = false;

/// Pause a few seconds after the USB/BT summary so the early xHCI lines can be
/// photographed on real hardware (no serial console on the X13).
pub const USB_BOOT_PAUSE: bool = false;

/// Blocking PC-speaker boot beeps (`beep_phase`, `beep_startup`).
///
/// Each phase beep busy-waits ~100 ms on the PIT and the startup jingle ~700 ms,
/// i.e. ~2.3 s of a ~3.5 s kernel boot.  They are the only progress indicator on
/// machines without a serial console (Lenovo X13), so they stay enabled on bare
/// metal.  They are always skipped under a hypervisor (QEMU/KVM has no speaker
/// by default) regardless of this flag.  Set to `false` to silence them on
/// hardware too.  `beep_panic` is unaffected.
pub const BOOT_BEEPS: bool = true;

// ---------------------------------------------------------------------------
// Future debug flags : TODO
// ---------------------------------------------------------------------------
