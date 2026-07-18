//! Kernel boot configuration application.
//!
//! Parses `kernel.toml` (loaded by Limine as an internal module) and applies
//! settings to the appropriate subsystems. Called once during early boot, after
//! the buddy allocator is initialized (needed for heap allocation in the TOML
//! parser) and before VGA init (so quiet_mode can suppress early debug output).

/// Apply all kernel.toml configuration to their respective subsystems.
///
/// Call this once after `buddy::init_buddy_allocator()` and before VGA init.
pub fn apply_kernel_config() {
    let Some((base, size)) = crate::boot::limine::kernel_toml_module() else {
        crate::serial_println!("[config] No kernel.toml module found, using defaults");
        return;
    };

    if base == 0 || size == 0 {
        crate::serial_println!("[config] kernel.toml module is empty, using defaults");
        return;
    }

    // SAFETY: The module memory is valid for the duration of the kernel's lifetime.
    // It was provided by Limine and is mapped in the higher half.
    let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };

    let config = match crate::boot::toml::parse_toml(data) {
        Ok(c) => c,
        Err(e) => {
            crate::serial_println!("[config] Failed to parse kernel.toml: {}", e);
            return;
        }
    };

    crate::serial_println!("[config] Applying kernel.toml configuration");

    // ── [quiet] section ────────────────────────────────────────────────
    if let Some(quiet) = config.get_bool("quiet", "quiet_mode") {
        crate::debug_cfg::set_quiet(quiet);
        if quiet {
            crate::serial_println!("[config] quiet_mode = true (all debug output suppressed)");
        }
    }

    // ── [buddy] section ────────────────────────────────────────────────
    if let Some(threshold) = config.get_int("buddy", "compaction_threshold") {
        let t = threshold.clamp(0, 100) as usize;
        crate::memory::buddy::set_compaction_threshold(t);
        crate::serial_println!(
            "[config] buddy.compaction_threshold = {} (from kernel.toml)",
            t
        );
    }
}
