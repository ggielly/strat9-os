//! Keyboard Layout Configuration
//!
//! Allows selection between different keyboard layouts (US QWERTY, French AZERTY, etc.)

use core::sync::atomic::{AtomicBool, Ordering};

// Flag to determine which keyboard layout to use
// true = French AZERTY, false = US QWERTY
static USE_FRENCH_LAYOUT: AtomicBool = AtomicBool::new(true);

/// Set the keyboard layout to French AZERTY
pub fn set_french_layout() {
    USE_FRENCH_LAYOUT.store(true, Ordering::SeqCst);
}

/// Set the keyboard layout to US QWERTY
pub fn set_us_layout() {
    USE_FRENCH_LAYOUT.store(false, Ordering::SeqCst);
}

/// Get the current keyboard layout setting
pub fn is_french_layout() -> bool {
    USE_FRENCH_LAYOUT.load(Ordering::SeqCst)
}

/// Handle a keyboard scancode based on the current layout
pub fn handle_scancode() -> Option<u8> {
    if is_french_layout() {
        crate::arch::x86_64::keyboard::handle_scancode()
    } else {
        crate::arch::x86_64::keyboard_us::handle_scancode()
    }
}
