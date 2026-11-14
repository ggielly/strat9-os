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

//! Restart policy, wait-status classification and exponential backoff.
//!
//! Everything here is pure (no kernel ABI, no allocation beyond borrowed
//! slices) so the supervisor's decisions can be unit tested on the host. The
//! execution boundary (`strate-init/src/supervisor.rs`) only supplies the
//! observed timestamps and status words.

/// OTP-style restart policy attached to a silo/strate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    /// Restart on any termination.
    #[default]
    Always,
    /// Restart only on a signal or a non-zero exit code.
    OnFailure,
    /// Never restart; the strate stays down after it exits.
    Never,
}

impl RestartPolicy {
    /// Parses the `restart` configuration value.
    pub fn from_name(s: &str) -> Option<RestartPolicy> {
        match s {
            "always" => Some(RestartPolicy::Always),
            "on-failure" | "on_failure" => Some(RestartPolicy::OnFailure),
            "never" => Some(RestartPolicy::Never),
            _ => None,
        }
    }

    /// The canonical configuration name.
    pub fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::Never => "never",
        }
    }

    /// True when a child that terminated as `kind` should be restarted.
    ///
    /// A stopped/continued status is not a termination, so no policy restarts
    /// on it.
    pub fn should_restart(self, kind: ExitKind) -> bool {
        match kind {
            ExitKind::Normal(code) => match self {
                RestartPolicy::Always => true,
                RestartPolicy::OnFailure => code != 0,
                RestartPolicy::Never => false,
            },
            ExitKind::Signal(_) => !matches!(self, RestartPolicy::Never),
            ExitKind::Stopped(_) | ExitKind::Continued => false,
        }
    }
}

/// Classification of a Linux-shaped wait status.
///
/// The kernel reports the "same layout as Linux waitpid": low 7 bits are the
/// terminating signal (`0` when the process exited normally), bits 8..15 are
/// the exit code or stop signal, `0x7f` in the low byte means stopped and the
/// full low word `0xffff` means continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitKind {
    /// Normal exit with this code.
    Normal(u8),
    /// Killed by this signal number.
    Signal(u32),
    /// Stopped by this signal number (job control, not an exit).
    Stopped(u32),
    /// Resumed after a stop (not an exit).
    Continued,
}

impl ExitKind {
    /// True when this status describes a termination (normal exit or signal).
    pub fn is_exit(self) -> bool {
        matches!(self, ExitKind::Normal(_) | ExitKind::Signal(_))
    }

    /// True for a clean `exit(0)`.
    pub fn is_success(self) -> bool {
        matches!(self, ExitKind::Normal(0))
    }
}

/// Classifies a raw wait status into an [`ExitKind`].
pub fn classify(status: i32) -> ExitKind {
    let status = status as u32;
    if status & 0xffff == 0xffff {
        return ExitKind::Continued;
    }
    match status & 0x7f {
        0 => ExitKind::Normal(((status >> 8) & 0xff) as u8),
        0x7f => ExitKind::Stopped((status >> 8) & 0xff),
        signal => ExitKind::Signal(signal),
    }
}

/// Exponential restart backoff: `base` ms, doubled per attempt, capped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    pub base_ms: u32,
    pub cap_ms: u32,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    /// 100 ms base, 30 s cap.
    pub const fn new() -> Self {
        Self {
            base_ms: 100,
            cap_ms: 30_000,
            attempt: 0,
        }
    }

    /// Delay for the current attempt without consuming it.
    pub fn delay_ms(&self) -> u32 {
        let shift = self.attempt.min(31);
        self.base_ms.saturating_mul(1u32 << shift).min(self.cap_ms)
    }

    /// Returns the delay for this attempt and advances to the next one.
    pub fn next(&mut self) -> u32 {
        let delay = self.delay_ms();
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    /// Resets the backoff after a stable run.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// OTP-style restart intensity budget.
///
/// At most `max_restarts` restarts are admitted within `window_ms`. A run that
/// lasted at least `stable_ms` resets the recorded history, so a strate that
/// crashes, recovers and later crashes again is not penalised for the old
/// crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartBudget {
    pub max_restarts: u8,
    pub window_ms: u64,
    pub stable_ms: u64,
}

impl Default for RestartBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartBudget {
    /// 3 restarts / 60 s window / 60 s stability.
    pub const fn new() -> Self {
        Self {
            max_restarts: 3,
            window_ms: 60_000,
            stable_ms: 60_000,
        }
    }

    /// Default window and stability, with a per-strate restart cap.
    pub const fn with_max(max_restarts: u8) -> Self {
        Self {
            max_restarts,
            window_ms: 60_000,
            stable_ms: 60_000,
        }
    }

    /// Number of recorded restarts inside the window ending at `now_ms`.
    pub fn window_count(&self, now_ms: u64, restart_times: &[u64]) -> usize {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        restart_times.iter().filter(|&&t| t >= cutoff).count()
    }

    /// True when no further restart fits in the current window.
    pub fn is_exhausted(&self, now_ms: u64, restart_times: &[u64]) -> bool {
        self.window_count(now_ms, restart_times) >= self.max_restarts as usize
    }

    /// True when the current instance ran long enough to reset the budget.
    pub fn is_stable(&self, now_ms: u64, spawned_at_ms: u64) -> bool {
        now_ms.saturating_sub(spawned_at_ms) >= self.stable_ms
    }
}
