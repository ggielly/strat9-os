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

//! Child supervision: blocking reap loop with OTP-style restart policies.
//!
//! All policy math (classification, backoff, intensity window) lives in the
//! host-tested `init-config::policy` module. This file only records timestamps
//! and applies the decision at the kernel boundary.
//!
//! Backoff sleeps inline before a restart. The supervisor reaps one child at a
//! time, and a child that exits during the sleep simply stays a zombie until
//! the next `waitpid`, so delaying the whole loop is the simplest correct
//! approach: no per-child timers and no restart queue.

use alloc::{string::String, vec::Vec};

use init_config::{Backoff, ExitKind, RestartBudget, RestartPolicy, classify};
use strat9_syscall::{CLOCK_MONOTONIC, call, data::TimeSpec};

use crate::{fmt::log_u32, log};

/// Number of strates the supervisor can watch.
///
/// The shipped configuration already declares a dozen strates and the wasm
/// test overlay adds more; the table is therefore sized for `silo.toml` plus a
/// comfortable margin instead of silently dropping strates over the old 16.
pub const CAPACITY: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrateHealth {
    Ready,
    Failed,
}

/// One child process under supervision.
pub struct SupervisedChild {
    pub(crate) name: String,
    pub(crate) pid: u64,
    /// SID of the owning silo, reused as reserved SID set on reload.
    pub(crate) sid: u32,
    /// Name of the silo this strate belongs to, used by `reload` and shutdown.
    pub(crate) silo: String,
    /// Silo handle, kept so a crashed strate can be restarted in place.
    silo_handle: usize,
    /// Module handle of this strate.
    ///
    /// A silo only stores one `module_id`, and every `silo_attach_module`
    /// overwrites it: without this handle a restart in a silo that hosts
    /// several strates would start the last attached binary instead of the
    /// one that crashed.
    module_handle: usize,
    /// True when the owning silo was configured with `admin = true`.
    ///
    /// `/srv/init` uses this to approximate authorization for mutating
    /// commands; a real capability check needs a kernel pid→silo query.
    pub(crate) admin: bool,
    pub(crate) health: StrateHealth,
    pub(crate) restart_count: u32,
    /// Last observed exit status, reported by the `status` command.
    pub(crate) last_exit: Option<ExitKind>,
    /// When the current instance was started, used for the stability reset.
    spawned_at_ms: u64,
    /// Timestamps (ms) of the restarts recorded in the current window.
    restart_times: Vec<u64>,
    backoff: Backoff,
    restart: RestartPolicy,
    critical: bool,
    budget: RestartBudget,
}

impl SupervisedChild {
    fn new(
        name: &str,
        pid: u64,
        sid: u32,
        silo_handle: usize,
        module_handle: usize,
        silo: &str,
        admin: bool,
        restart: RestartPolicy,
        critical: bool,
        max_restarts: u8,
    ) -> Self {
        Self {
            name: String::from(name),
            pid,
            sid,
            silo: String::from(silo),
            silo_handle,
            module_handle,
            admin,
            health: StrateHealth::Ready,
            restart_count: 0,
            last_exit: None,
            spawned_at_ms: now_ms(),
            restart_times: Vec::new(),
            backoff: Backoff::new(),
            restart,
            critical,
            budget: RestartBudget::with_max(max_restarts),
        }
    }
}

/// Adds a launched strate to the supervision set.
///
/// The set is a pre-allocated `Vec`; a full set logs and drops the child
/// instead of growing the heap at runtime.
pub fn register(
    children: &mut Vec<SupervisedChild>,
    name: &str,
    pid: usize,
    sid: u32,
    silo_handle: usize,
    module_handle: usize,
    silo: &str,
    admin: bool,
    restart: RestartPolicy,
    critical: bool,
    max_restarts: u8,
) {
    if children.len() < CAPACITY {
        children.push(SupervisedChild::new(
            name,
            pid as u64,
            sid,
            silo_handle,
            module_handle,
            silo,
            admin,
            restart,
            critical,
            max_restarts,
        ));
    } else {
        log("[init] WARN: supervision table full, strate '");
        log(name);
        log("' pid=");
        log_u32(pid as u32);
        log(" not supervised\n");
    }
}

/// Monotonic time in milliseconds (`0` if the clock is unavailable).
fn now_ms() -> u64 {
    let mut ts = TimeSpec::zero();
    if call::clock_gettime(CLOCK_MONOTONIC, &mut ts).is_ok() {
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec.max(0) as u64) / 1_000_000)
    } else {
        0
    }
}

/// Sleeps for `ms` milliseconds.
pub(crate) fn sleep_ms(ms: u32) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) as i64) * 1_000_000,
    };
    let mut rem = TimeSpec::zero();
    let _ = call::nanosleep(&req, &mut rem);
}

/// Logs how a child terminated.
fn log_exit_kind(kind: ExitKind) {
    match kind {
        ExitKind::Normal(code) => {
            log("exited(code=");
            log_u32(code as u32);
            log(")");
        }
        ExitKind::Signal(signal) => {
            log("killed(signal=");
            log_u32(signal);
            log(")");
        }
        ExitKind::Stopped(_) | ExitKind::Continued => {}
    }
}

/// Applies the child's policy after it terminated.
fn handle_exit(children: &mut [SupervisedChild], pid: u64, status: i32) {
    let kind = classify(status);
    let Some(child) = children.iter_mut().find(|c| c.pid == pid) else {
        // PID 1 invariant: every orphan is reparented here and must be reaped
        // even when it is not a strate we launched.
        log("[init] Supervisor: unknown child pid=");
        log_u32(pid as u32);
        log(" exited status=");
        log_u32(status as u32);
        log("\n");
        return;
    };

    // A stop/continue status is not a termination: keep watching.
    if !kind.is_exit() {
        log("[init] Supervisor: '");
        log(&child.name);
        log("' changed state (not an exit), ignored\n");
        return;
    }

    child.last_exit = Some(kind);

    log("[init] Supervisor: strate '");
    log(&child.name);
    log("' ");
    log_exit_kind(kind);
    log(", restarts=");
    log_u32(child.restart_count);
    log("\n");

    if !child.restart.should_restart(kind) {
        child.health = StrateHealth::Failed;
        log("[init] Supervisor: '");
        log(&child.name);
        log("' policy '");
        log(child.restart.as_str());
        log("', staying down\n");
        return;
    }

    let now = now_ms();
    // A run at least `stable_ms` long resets both the intensity history and
    // the backoff: the crash is treated as a fresh failure, not a crash loop.
    if child.budget.is_stable(now, child.spawned_at_ms) {
        child.restart_times.clear();
        child.backoff.reset();
    }

    if child.budget.is_exhausted(now, &child.restart_times) {
        child.health = StrateHealth::Failed;
        log("[init] Supervisor: '");
        log(&child.name);
        log("' exceeded restart budget\n");
        if child.critical {
            // No userspace reboot wrapper exists yet: log loudly and keep
            // supervising the remaining strates instead of exiting (declared
            // limitation of this step).
            log("[init] CRITICAL: '");
            log(&child.name);
            log("' exhausted its restart budget\n");
        }
        return;
    }

    child.restart_times.push(now);
    child.restart_count = child.restart_count.saturating_add(1);
    let delay = child.backoff.next();
    log("[init] Supervisor: restarting '");
    log(&child.name);
    log("' in ");
    log_u32(delay);
    log("ms (attempt ");
    log_u32(child.restart_count);
    log(")\n");
    sleep_ms(delay);

    // Hot-restart in place: re-attach *this* strate's module (a silo keeps a
    // single `module_id` slot, so the last attach wins) and start it under
    // its own instance name. The replacement strate re-binds its namespace
    // path; the mount takeover in `ipc_bind_port` makes that atomic.
    match relaunch(child) {
        Ok(new_pid) => {
            child.pid = new_pid as u64;
            child.health = StrateHealth::Ready;
            child.spawned_at_ms = now_ms();
            log("[init] Supervisor: restarted '");
            log(&child.name);
            log("' pid=");
            log_u32(new_pid as u32);
            log("\n");
        }
        Err(e) => {
            child.health = StrateHealth::Failed;
            log("[init] Supervisor: restart failed: ");
            log(e);
            log("\n");
        }
    }
}

/// Re-attaches a child's own module and starts it under its instance name.
fn relaunch(child: &mut SupervisedChild) -> Result<usize, &'static str> {
    call::silo_attach_module(child.silo_handle, child.module_handle).map_err(|e| e.name())?;
    call::silo_start_named(child.silo_handle, &child.name).map_err(|e| e.name())
}

/// Starts a supervised child that is currently down.
pub fn start_child(children: &mut [SupervisedChild], name: &str) -> Result<usize, &'static str> {
    let Some(child) = children.iter_mut().find(|c| c.name == name) else {
        return Err("no such strate");
    };
    if child.pid != 0 {
        return Err("already running");
    }
    match relaunch(child) {
        Ok(pid) => {
            child.pid = pid as u64;
            child.health = StrateHealth::Ready;
            child.spawned_at_ms = now_ms();
            Ok(pid)
        }
        Err(e) => {
            child.health = StrateHealth::Failed;
            Err(e)
        }
    }
}

/// Stops one child: `silo_stop`, a 500 ms grace window, then `silo_kill`.
fn stop_silo_child(child: &mut SupervisedChild) {
    if child.pid != 0 {
        let _ = call::silo_stop(child.silo_handle);
        sleep_ms(500);
        let _ = call::silo_kill(child.silo_handle);
    }
    // Zeroing the pid keeps the restart policy from reviving an operator stop
    // and makes the `wasm app failed`/`run` reaper ignore the pending zombie
    // instead of restarting it.
    child.pid = 0;
    child.health = StrateHealth::Failed;
}

/// Stops the child named `name`, if supervised.
pub fn stop_child(children: &mut [SupervisedChild], name: &str) -> Result<(), &'static str> {
    let Some(child) = children.iter_mut().find(|c| c.name == name) else {
        return Err("no such strate");
    };
    stop_silo_child(child);
    Ok(())
}

/// Stops every child belonging to `silo_name`.
pub fn stop_silo(children: &mut [SupervisedChild], silo_name: &str) {
    for child in children.iter_mut().filter(|c| c.silo == silo_name) {
        stop_silo_child(child);
    }
}

/// Stops every child, following the plan order in reverse.
pub fn shutdown_all(children: &mut [SupervisedChild], order: &[String]) {
    for silo in order.iter().rev() {
        stop_silo(children, silo);
    }
}

/// Supervisor loop multiplexing reaping and `/srv/init` requests.
///
/// The control port is drained first so an operator can act between reaps,
/// then `waitpid` polls non-blocking, then the loop sleeps 5 ms when idle.
pub fn run(
    mut children: Vec<SupervisedChild>,
    control_port: usize,
    mut plan_order: Vec<String>,
) -> ! {
    log("[init] Supervisor: entering watch loop\n");
    loop {
        if control_port != 0 {
            let mut msg = strat9_syscall::data::IpcMessage::new(0);
            while call::ipc_try_recv(control_port, &mut msg).is_ok() {
                crate::control::handle(&mut children, &mut plan_order, &msg);
                msg = strat9_syscall::data::IpcMessage::new(0);
            }
        }

        let mut wstatus: i32 = 0;
        match call::waitpid(-1, Some(&mut wstatus), call::WNOHANG) {
            Ok(pid) if pid > 0 => handle_exit(&mut children, pid as u64, wstatus),
            _ => sleep_ms(5),
        }
    }
}
