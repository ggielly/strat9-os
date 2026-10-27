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

use core::sync::atomic::{AtomicUsize, Ordering};

/// Number of writable display handles currently held by userspace.
static STRATE_OWNERS: AtomicUsize = AtomicUsize::new(0);

/// Mark the framebuffer as owned by a userspace display server.
///
/// Called by the display scheme when a writable screen handle is opened.
pub fn acquire_strate() {
    STRATE_OWNERS.fetch_add(1, Ordering::SeqCst);
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
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
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
