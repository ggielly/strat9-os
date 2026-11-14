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

//! Host unit tests for the pure configuration crate.

use super::*;

fn planned<'a>(plan: &'a BootPlan, name: &str) -> Option<&'a PlannedSilo> {
    plan.silos.iter().find(|s| s.name == name)
}

fn plan_of(toml: &str) -> BootPlan {
    let parsed = parse_config(toml);
    build_plan(parsed.silos, parsed.diagnostics)
}

const MULTI_STRATE: &str = r#"
[[silos]]
name = "svc"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "a"
binary = "/initfs/a"
type = "elf"
[[silos.strates]]
name = "b"
binary = "/initfs/b"
type = "elf"
"#;

#[test]
fn multi_strate_silo_is_preserved() {
    let plan = plan_of(MULTI_STRATE);
    let silo = planned(&plan, "svc").expect("svc planned");
    assert_eq!(silo.strates.len(), 2);
    assert_eq!(silo.strates[0].name, "a");
    assert_eq!(silo.strates[1].name, "b");
    assert_eq!(silo.strates[1].kind, PlannedKind::Elf);
}

#[test]
fn inline_comment_ignores_hash_inside_quotes() {
    let toml = r#"
[[silos]]
name = "svc#one" # trailing comment
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "a"
binary = "/initfs/a#frag" # comment
type = "elf"
"#;
    let parsed = parse_config(toml);
    let silo = &parsed.silos[0];
    assert_eq!(silo.name, "svc#one");
    assert_eq!(silo.strates[0].binary, "/initfs/a#frag");
}

#[test]
fn duplicate_fixed_sid_skips_second_silo() {
    let toml = r#"
[[silos]]
name = "one"
family = "NET"
mode = "076"
sid = 500
[[silos]]
name = "two"
family = "NET"
mode = "076"
sid = 500
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "one").is_some());
    assert!(planned(&plan, "two").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("is already used")));
}

#[test]
fn invalid_mode_skips_silo() {
    let toml = r#"
[[silos]]
name = "bad"
family = "NET"
mode = "999"
sid = 42
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "bad").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("invalid mode")));
}

#[test]
fn admin_outside_sys_skips_silo() {
    let toml = r#"
[[silos]]
name = "sneaky"
family = "NET"
mode = "076"
sid = 42
admin = true
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "sneaky").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("admin requested for non-SYS")));
}

#[test]
fn unknown_family_skips_silo() {
    let toml = r#"
[[silos]]
name = "weird"
family = "FOO"
mode = "000"
sid = 42
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "weird").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("Invalid family 'FOO'")));
}

#[test]
fn mode_exceeding_ceiling_skips_silo() {
    let toml = r#"
[[silos]]
name = "greedy"
family = "USR"
mode = "777"
sid = 42
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "greedy").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("exceeds family ceiling")));
}

#[test]
fn overlay_adds_missing_and_skips_existing() {
    let base = r#"
[[silos]]
name = "alpha"
family = "NET"
mode = "076"
sid = 42
"#;
    let overlay = r#"
[[silos]]
name = "alpha"
family = "NET"
mode = "076"
sid = 42
[[silos]]
name = "beta"
family = "WASM"
mode = "006"
sid = 42
"#;
    let mut silos = parse_config(base).silos;
    let added = merge_overlay(&mut silos, parse_config(overlay).silos);
    assert_eq!(added, 1);
    assert_eq!(silos.iter().filter(|s| s.name == "alpha").count(), 1);
    assert_eq!(silos.iter().filter(|s| s.name == "beta").count(), 1);
}

#[test]
fn bus_is_moved_first() {
    let toml = r#"
[[silos]]
name = "first"
family = "NET"
mode = "076"
sid = 42
[[silos]]
name = "bus"
family = "DRV"
mode = "076"
sid = 42
[[silos.strates]]
name = "strate-bus"
binary = "/initfs/strate-bus"
type = "elf"
[[silos]]
name = "last"
family = "NET"
mode = "076"
sid = 42
"#;
    let plan = plan_of(toml);
    assert_eq!(plan.silos[0].name, "bus");
    // Relative order of the remaining silos is preserved.
    let names: Vec<&str> = plan.silos.iter().map(|s| s.name.as_str()).collect();
    let first = names.iter().position(|n| *n == "first").unwrap();
    let last = names.iter().position(|n| *n == "last").unwrap();
    assert!(first < last);
}

#[test]
fn mandatory_silo_fallbacks_are_added() {
    let toml = r#"
[[silos]]
name = "only"
family = "NET"
mode = "076"
sid = 42
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "bus").is_some());
    assert!(planned(&plan, "network").is_some());
    assert!(planned(&plan, "dhcp-client").is_some());
    // Fallbacks use the same definitions as the shipped image.
    let bus = planned(&plan, "bus").unwrap();
    assert_eq!(bus.strates[0].name, "strate-bus");
    assert_eq!(bus.strates[0].binary, "/initfs/strate-bus");
}

#[test]
fn wasm_app_target_resolves_to_runtime_label() {
    let toml = r#"
[[silos]]
name = "wasm"
family = "WASM"
mode = "006"
sid = 42
[[silos.strates]]
name = "strate-wasm"
binary = "/initfs/strate-wasm"
type = "wasm-runtime"
target_strate = "default"
[[silos.strates]]
name = "hello-world"
binary = "/initfs/bin/hello.wasm"
type = "wasm-app"
target_strate = "strate-wasm"
"#;
    let plan = plan_of(toml);
    let silo = planned(&plan, "wasm").expect("wasm planned");
    let app = silo
        .strates
        .iter()
        .find(|s| s.name == "hello-world")
        .expect("hello planned");
    assert_eq!(
        app.kind,
        PlannedKind::WasmApp {
            service_label: String::from("default")
        }
    );
}

#[test]
fn unknown_strate_type_is_ignored_not_fatal() {
    let toml = r#"
[[silos]]
name = "svc"
family = "NET"
mode = "076"
sid = 42
[[silos.strates]]
name = "a"
binary = "/initfs/a"
type = "elf"
[[silos.strates]]
name = "mystery"
binary = "/initfs/m"
type = "quantum"
"#;
    let plan = plan_of(toml);
    let silo = planned(&plan, "svc").expect("svc planned");
    assert_eq!(silo.strates.len(), 1);
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown type 'quantum'")));
}

#[test]
fn invalid_sid_is_reported_and_skipped() {
    let toml = r#"
[[silos]]
name = "bad-sid"
family = "NET"
mode = "076"
sid = "not-a-number"
"#;
    let plan = plan_of(toml);
    assert!(planned(&plan, "bad-sid").is_none());
    assert!(plan
        .diagnostics
        .iter()
        .any(|d| d.message.contains("invalid sid 'not-a-number'")));
}

#[test]
fn auto_sid_skips_fixed_and_used() {
    let toml = r#"
[[silos]]
name = "auto-a"
family = "NET"
mode = "076"
sid = 42
[[silos]]
name = "pinned"
family = "NET"
mode = "076"
sid = 100
[[silos]]
name = "auto-b"
family = "NET"
mode = "076"
sid = 42
"#;
    let plan = plan_of(toml);
    // 100 is pinned, so automatic allocation must skip it.
    assert_eq!(planned(&plan, "pinned").unwrap().sid, 100);
    let auto_a = planned(&plan, "auto-a").unwrap().sid;
    let auto_b = planned(&plan, "auto-b").unwrap().sid;
    assert_ne!(auto_a, 100);
    assert_ne!(auto_b, 100);
    assert_ne!(auto_a, auto_b);
}

// ---------------------------------------------------------------------------
// Restart policy model / parser
// ---------------------------------------------------------------------------

#[test]
fn restart_keys_default_when_absent() {
    let plan = plan_of(MULTI_STRATE);
    let silo = planned(&plan, "svc").expect("svc planned");
    assert_eq!(silo.restart, RestartPolicy::Always);
    assert!(!silo.critical);
    assert_eq!(silo.max_restarts, 3);
    let strate = &silo.strates[0];
    assert_eq!(strate.restart, RestartPolicy::Always);
    assert!(!strate.critical);
    assert_eq!(strate.max_restarts, 3);
}

#[test]
fn restart_keys_propagate_to_plan_and_strates() {
    let toml = r#"
[[silos]]
name = "svc"
family = "NET"
mode = "076"
sid = 42
restart = "on-failure"
critical = true
max_restarts = 5
[[silos.strates]]
name = "a"
binary = "/initfs/a"
type = "elf"
"#;
    let plan = plan_of(toml);
    let silo = planned(&plan, "svc").expect("svc planned");
    assert_eq!(silo.restart, RestartPolicy::OnFailure);
    assert!(silo.critical);
    assert_eq!(silo.max_restarts, 5);
    let strate = &silo.strates[0];
    assert_eq!(strate.restart, RestartPolicy::OnFailure);
    assert!(strate.critical);
    assert_eq!(strate.max_restarts, 5);
}

#[test]
fn unknown_restart_policy_falls_back_with_diagnostic() {
    let toml = r#"
[[silos]]
name = "svc"
family = "NET"
mode = "076"
sid = 42
restart = "sometimes"
"#;
    let parsed = parse_config(toml);
    assert_eq!(parsed.silos[0].restart, RestartPolicy::Always);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown restart policy 'sometimes'")));
}

// ---------------------------------------------------------------------------
// Exit classification / policy / backoff / budget
// ---------------------------------------------------------------------------

#[test]
fn classify_linux_wait_status() {
    assert_eq!(classify(0), ExitKind::Normal(0));
    // exit(3) => code in bits 8..15.
    assert_eq!(classify(3 << 8), ExitKind::Normal(3));
    // killed by SIGKILL (9) => signal in low bits.
    assert_eq!(classify(9), ExitKind::Signal(9));
    // stopped by SIGSTOP (19) => 0x7f low byte, stop signal in bits 8..15.
    assert_eq!(classify(19 << 8 | 0x7f), ExitKind::Stopped(19));
    // continued.
    assert_eq!(classify(0xffff), ExitKind::Continued);
    assert!(!classify(0xffff).is_exit());
}

#[test]
fn policy_restart_decisions() {
    use RestartPolicy::{Always, Never, OnFailure};

    assert!(Always.should_restart(ExitKind::Normal(0)));
    assert!(Always.should_restart(ExitKind::Signal(9)));

    assert!(!OnFailure.should_restart(ExitKind::Normal(0)));
    assert!(OnFailure.should_restart(ExitKind::Normal(1)));
    assert!(OnFailure.should_restart(ExitKind::Signal(11)));

    assert!(!Never.should_restart(ExitKind::Normal(1)));
    assert!(!Never.should_restart(ExitKind::Signal(9)));

    // Not terminations: never restart.
    assert!(!Always.should_restart(ExitKind::Stopped(19)));
    assert!(!Always.should_restart(ExitKind::Continued));
}

#[test]
fn restart_policy_names_roundtrip() {
    for (name, policy) in [
        ("always", RestartPolicy::Always),
        ("on-failure", RestartPolicy::OnFailure),
        ("never", RestartPolicy::Never),
    ] {
        assert_eq!(RestartPolicy::from_name(name), Some(policy));
        assert_eq!(policy.as_str(), name);
    }
    assert_eq!(RestartPolicy::from_name("bogus"), None);
}

#[test]
fn backoff_doubles_and_caps_then_resets() {
    let mut b = Backoff::new();
    assert_eq!(b.delay_ms(), 100);
    assert_eq!(b.next(), 100);
    assert_eq!(b.next(), 200);
    assert_eq!(b.next(), 400);
    assert_eq!(b.next(), 800);
    // Run past the cap.
    for _ in 0..40 {
        b.next();
    }
    assert_eq!(b.delay_ms(), 30_000);
    assert_eq!(b.next(), 30_000);
    b.reset();
    assert_eq!(b.next(), 100);
}

#[test]
fn budget_exhausts_within_window() {
    let budget = RestartBudget::new(); // 3 / 60s / 60s
    let now = 120_000;
    assert!(!budget.is_exhausted(now, &[]));
    assert!(!budget.is_exhausted(now, &[60_001, 90_000]));
    assert!(budget.is_exhausted(now, &[60_001, 90_000, 100_000]));
    // Timestamps older than the window are ignored.
    assert_eq!(budget.window_count(now, &[0, 10_000]), 0);
}

#[test]
fn budget_window_is_rolling() {
    let budget = RestartBudget::with_max(2);
    let restarts = [1_000u64, 2_000];
    assert!(budget.is_exhausted(3_000, &restarts));
    // Once the first restart falls out of the 60 s window, capacity returns.
    assert!(!budget.is_exhausted(61_001, &restarts));
}

#[test]
fn budget_resets_after_stable_run() {
    let budget = RestartBudget::new();
    let spawned_at = 10_000;
    // Only 5 s of uptime: not stable, history counts.
    assert!(!budget.is_stable(15_000, spawned_at));
    assert!(budget.is_stable(70_000, spawned_at));
}
