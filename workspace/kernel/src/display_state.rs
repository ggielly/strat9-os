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

//! Display ownership state.
//!
//! The framebuffer has exactly one writer at a time:
//!
//! ```text
//!   Boot        : kernel owns the framebuffer (boot console, logs)
//!   StrateOwned : a userspace display server owns it (via /dev/display)
//! ```
//!
//! The console scheme consults [`kernel_fb_allowed`] before writing to the
//! framebuffer, so kernel logs do not race the display server once it has
//! taken over. Serial output is never gated.
//!
//! Ownership is reference-counted: one acquisition per writable
//! `/dev/display/<id>.<screen>` handle. The display server keeps its handle
//! open for its whole lifetime; a crash closes it and gives the framebuffer
//! back to the kernel.
//!
//! Panic output deliberately stays serial-only (see `boot::panic`), so a
//! panicking kernel never steals the framebuffer back from the display
//! server. That invariant is unchanged by this module.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Number of writable display handles currently held by userspace.
static STRATE_OWNERS: AtomicUsize = AtomicUsize::new(0);

/// PID that took the framebuffer on the 0 -> 1 ownership transition (0 = none).
static OWNER_PID: AtomicU32 = AtomicU32::new(0);

/// Mark the framebuffer as owned by a userspace display server.
///
/// Called by the display scheme when a writable screen handle is opened. The
/// first owner records its PID so damage/clear writes can be attributed.
pub fn acquire_strate(pid: u32) {
    if STRATE_OWNERS.fetch_add(1, Ordering::SeqCst) == 0 {
        OWNER_PID.store(pid, Ordering::SeqCst);
    }
}

/// Release one userspace display ownership reference.
///
/// Called by the display scheme when a writable screen handle is closed.
/// The last release hands the framebuffer back to the kernel (boot console).
pub fn release_strate() {
    let mut current = STRATE_OWNERS.load(Ordering::SeqCst);
    while current != 0 {
        match STRATE_OWNERS.compare_exchange_weak(
            current,
            current - 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                if current == 1 {
                    OWNER_PID.store(0, Ordering::SeqCst);
                }
                return;
            }
            Err(observed) => current = observed,
        }
    }
}

/// PID of the current framebuffer owner, or 0 when the kernel owns it.
pub fn strate_owner_pid() -> u32 {
    OWNER_PID.load(Ordering::SeqCst)
}

/// Returns true while at least one userspace display owner exists.
pub fn strate_owned() -> bool {
    STRATE_OWNERS.load(Ordering::SeqCst) != 0
}

/// Returns true if the kernel may draw on the framebuffer.
///
/// False as soon as a display server owns the screen; the kernel keeps
/// logging to serial only.
pub fn kernel_fb_allowed() -> bool {
    !strate_owned()
}

/// Human-readable owner name, for `/dev/display/info`.
pub fn owner_name() -> &'static str {
    if strate_owned() {
        "strate"
    } else {
        "kernel"
    }
}
