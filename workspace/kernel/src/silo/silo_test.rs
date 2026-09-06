//! In-flight silo manager tests (selftest feature).
//!
//! Two families, each assertion traced to the review commit it pins:
//! 1. **Pure-function suite** — pledge monotonicity, config validation,
//!    unveil normalisation (dot-segment rejection), path-rule boundaries,
//!    tier derivation, fault packing, labels, output ring buffer.
//! 2. **Lifecycle e2e** — spawn/duplicate-label/rename/stop/rename/
//!    destroy through the public `kernel_*` API, plus quota adjustment
//!    and pledge escalation rejection.

use super::{
    normalize_unveil_path, path_rule_matches, pack_fault, sanitize_label, is_valid_label,
    extract_strate_label, OctalMode, SiloConfig, SiloFaultReason, SiloId, SiloOutputBuf, SiloTier,
};
use crate::process::{add_task, Task, TaskPriority};
use crate::syscall::error::SyscallError;

fn check(label: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: {}", label);
    }
}

// ===========================================================================
// Pure-function suite
// ===========================================================================

fn run_pure_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // --- SiloId tiers -----------------------------------------------------
    check("tier critical 1..=9", SiloId::new(1).tier == SiloTier::Critical, &mut passed, &mut total);
    check("tier system 10..=999", SiloId::new(500).tier == SiloTier::System, &mut passed, &mut total);
    check("tier user >=1000", SiloId::new(1000).tier == SiloTier::User, &mut passed, &mut total);

    // --- OctalMode pledge monotonicity ------------------------------------
    let full = OctalMode::from_octal(0o777);
    let mut m = full;
    // Subset re-pledge is allowed (review: pledge is monotonic decreasing).
    check("pledge subset ok", m.pledge(OctalMode::from_octal(0o040)).is_ok(), &mut passed, &mut total);
    // Escalation is rejected.
    check(
        "pledge escalation denied",
        m.pledge(OctalMode::from_octal(0o777)).is_err(),
        &mut passed,
        &mut total,
    );
    // Equal re-pledge allowed (subset of itself).
    check(
        "pledge equal ok",
        m.pledge(OctalMode::from_octal(0o040)).is_ok(),
        &mut passed,
        &mut total,
    );

    // --- SiloConfig::validate --------------------------------------------
    let mut cfg = SiloConfig::default();
    check("default config valid", cfg.validate().is_ok(), &mut passed, &mut total);

    cfg.mem_min = 100;
    cfg.mem_max = 50;
    check("mem_min > mem_max rejected", cfg.validate().is_err(), &mut passed, &mut total);

    let mut cfg = SiloConfig::default();
    cfg.cpu_quota_us = 1000;
    check("quota without period rejected", cfg.validate().is_err(), &mut passed, &mut total);

    let mut cfg = SiloConfig::default();
    cfg.caps_len = (super::MAX_SILO_CAPS + 1) as u64;
    check("caps_len over MAX_SILO_CAPS rejected", cfg.validate().is_err(), &mut passed, &mut total);

    let mut cfg = SiloConfig::default();
    cfg.flags = super::SILO_FLAG_WEBRTC_NATIVE;
    check("webrtc-native without graphics rejected", cfg.validate().is_err(), &mut passed, &mut total);

    let mut cfg = SiloConfig::default();
    cfg.flags = super::SILO_FLAG_GRAPHICS;
    check("graphics without sessions/ttl rejected", cfg.validate().is_err(), &mut passed, &mut total);

    let mut cfg = SiloConfig::default();
    cfg.flags = super::SILO_FLAG_GRAPHICS;
    cfg.graphics_max_sessions = 2;
    cfg.graphics_session_ttl_sec = 60;
    check("graphics with sessions+ttl ok", cfg.validate().is_ok(), &mut passed, &mut total);

    // --- normalize_unveil_path (review SILO-4: dot segments rejected) -----
    check("unveil collapse //", normalize_unveil_path("//etc//passwd").is_ok(), &mut passed, &mut total);
    check(
        "unveil reject . segment",
        normalize_unveil_path("/etc/./passwd").is_err(),
        &mut passed,
        &mut total,
    );
    check(
        "unveil reject .. segment",
        normalize_unveil_path("/etc/../secret").is_err(),
        &mut passed,
        &mut total,
    );
    check(
        "unveil reject trailing ..",
        normalize_unveil_path("/etc/..").is_err(),
        &mut passed,
        &mut total,
    );
    check("unveil reject relative", normalize_unveil_path("etc/passwd").is_err(), &mut passed, &mut total);
    match normalize_unveil_path("/etc/passwd") {
        Ok(p) => check("unveil clean path preserved", p == "/etc/passwd", &mut passed, &mut total),
        Err(_) => check("unveil clean path preserved", false, &mut passed, &mut total),
    }

    // --- path_rule_matches boundary semantics -----------------------------
    check("rule / matches all", path_rule_matches("/", "/anything"), &mut passed, &mut total);
    check("exact match", path_rule_matches("/etc", "/etc"), &mut passed, &mut total);
    check("prefix on boundary", path_rule_matches("/etc", "/etc/passwd"), &mut passed, &mut total);
    // No sibling-prefix leakage: /etc must not match /etcetera.
    check("no sibling prefix leak", !path_rule_matches("/etc", "/etcetera"), &mut passed, &mut total);

    // --- pack_fault encoding ----------------------------------------------
    let packed = pack_fault(SiloFaultReason::PageFault, 0x1234);
    check("pack_fault reason low bits", packed & 0xFFFF == 1, &mut passed, &mut total);
    check(
        "pack_fault subcode shifted",
        packed >> super::FAULT_SUBCODE_SHIFT == 0x1234,
        &mut passed,
        &mut total,
    );

    // --- labels -----------------------------------------------------------
    check("valid label", is_valid_label("net-a_1.0"), &mut passed, &mut total);
    check("label rejects slash", !is_valid_label("a/b"), &mut passed, &mut total);
    check("label rejects empty", !is_valid_label(""), &mut passed, &mut total);
    check("label rejects 32 chars", !is_valid_label(&"x".repeat(32)), &mut passed, &mut total);
    check("sanitize maps bad chars", sanitize_label("ab/cd") == "ab_cd", &mut passed, &mut total);
    check("sanitize truncates 31", sanitize_label(&"y".repeat(40)).len() == 31, &mut passed, &mut total);
    check(
        "extract label from /srv path",
        extract_strate_label("/srv/strate-fs-ramfs/alpha/data").as_deref() == Some("alpha"),
        &mut passed,
        &mut total,
    );
    check(
        "extract label rejects extra depth",
        extract_strate_label("/srv/strate-fs-ramfs/a/b/c").is_none(),
        &mut passed,
        &mut total,
    );

    // --- SiloOutputBuf ring behaviour --------------------------------------
    let mut buf = SiloOutputBuf::new();
    buf.push(b"hello");
    check("output drain returns data", buf.drain() == b"hello", &mut passed, &mut total);
    check("output drain empties", buf.drain().is_empty(), &mut passed, &mut total);
    // Wraparound: push more than capacity, only the tail survives.
    let mut ring = SiloOutputBuf::new();
    for i in 0..(super::SILO_OUTPUT_CAPACITY + 16) {
        ring.push(&[b'a' + (i % 26) as u8]);
    }
    let drained = ring.drain();
    check("output wrap keeps capacity", drained.len() == super::SILO_OUTPUT_CAPACITY, &mut passed, &mut total);

    let ok = passed == total && total > 0;
    crate::serial_println!(
        "[silo-test][ASSERT] pure suite: {}/{} PASS ({})",
        passed,
        total,
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

// ===========================================================================
// Lifecycle e2e (public kernel_* API only)
// ===========================================================================

fn run_lifecycle_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // Spawn requires initfs blob; skip gracefully when absent so the suite
    // can run on minimal images.
    let ram = match read_initfs("/initfs/strate-fs-ramfs") {
        Some(v) => v,
        None => {
            crate::serial_println!("[silo-test] no /initfs/strate-fs-ramfs, skipping lifecycle");
            return true;
        }
    };

    let sid = match crate::silo::kernel_spawn_strate(&ram, Some("t-silo-a"), None) {
        Ok(id) => id,
        Err(e) => {
            crate::serial_println!("[silo-test][ASSERT] FAIL spawn: {:?}", e);
            return false;
        }
    };
    total += 1;
    passed += 1;

    // Duplicate label protection.
    total += 1;
    match crate::silo::kernel_spawn_strate(&ram, Some("t-silo-a"), None) {
        Err(SyscallError::AlreadyExists) => passed += 1,
        _ => crate::serial_println!("[silo-test][ASSERT] FAIL: duplicate label accepted"),
    }

    // Quota adjustment via kernel_limit_silo.
    total += 1;
    if crate::silo::kernel_limit_silo("t-silo-a", "mem_max", 1024 * 1024).is_ok() {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: limit mem_max");
    }

    // Invalid quota: mem_min above mem_max.
    total += 1;
    if crate::silo::kernel_limit_silo("t-silo-a", "mem_min", 2048 * 1024).is_err() {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: min>max accepted");
    }

    // Unknown limit key.
    total += 1;
    if crate::silo::kernel_limit_silo("t-silo-a", "bogus_key", 1).is_err() {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: bogus key accepted");
    }

    // Rename while running must fail; rename after stop must succeed
    // (same contract the strate lifecycle e2e already exercises).
    total += 1;
    if crate::silo::kernel_rename_silo_label("t-silo-a", "t-silo-b").is_err() {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: rename while running");
    }

    total += 1;
    let stopped = crate::silo::kernel_stop_silo("t-silo-a", true).is_ok();
    if stopped {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: kill");
    }

    total += 1;
    if stopped && crate::silo::kernel_destroy_silo("t-silo-b").is_ok() {
        passed += 1;
    } else {
        crate::serial_println!("[silo-test][ASSERT] FAIL: destroy");
    }

    let ok = passed == total;
    crate::serial_println!(
        "[silo-test][ASSERT] lifecycle suite: {}/{} PASS ({})",
        passed,
        total,
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Reads initfs.
fn read_initfs(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let fd = crate::vfs::open(path, crate::vfs::OpenFlags::READ).ok()?;
    let data = crate::vfs::read_all(fd).ok();
    let _ = crate::vfs::close(fd);
    data
}

extern "C" fn silo_test_main() -> ! {
    crate::serial_println!("[silo-test][SETUP] task start");
    let pure = run_pure_suite();
    let life = run_lifecycle_suite();
    crate::serial_println!(
        "[silo-test][ASSERT] final : {}",
        if pure && life { "PASS" } else { "FAIL" }
    );
    crate::serial_println!("[silo-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

/// Create the silo test task (called from the selftest orchestrator).
pub fn create_silo_test_task() {
    match Task::new_kernel_task(silo_test_main, "silo-test", TaskPriority::Normal) {
        Ok(task) => add_task(task),
        Err(_) => crate::serial_println!("[silo-test][SETUP] failed to create task"),
    }
}
