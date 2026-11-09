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

//! Fake IRQ gating for host tests (replaces kernel/src/sync/irq.rs).
//!
//! Mirrors the real token API surface used by guardian/spinlock:
//! `verify()`, `new_unchecked()` (module-restricted), `with_irqs_disabled()`.

/// Dummy stand-in for the kernel's IRQ-disabled token.
#[derive(Debug, Clone, Copy)]
pub struct IrqDisabledToken;

impl IrqDisabledToken {
    /// Real semantics: returns Some iff IRQs are known-disabled on this CPU.
    /// On the single-threaded host they trivially are.
    #[inline]
    pub fn verify() -> Option<Self> {
        Some(IrqDisabledToken)
    }

    /// Module-restricted constructor, same visibility rules as the kernel.
    #[inline]
    pub(super) unsafe fn new_unchecked() -> Self {
        IrqDisabledToken
    }

    /// Host-test constructor: proves nothing on the host (no IRQs), kept
    /// separate from `new_unchecked` to preserve the real API shape.
    #[inline]
    pub fn for_test() -> Self {
        IrqDisabledToken
    }
}

/// Runs `f` with a dummy token : semantically "interrupts disabled" because
/// each host test is single-threaded.
#[inline]
pub fn with_irqs_disabled<R>(f: impl FnOnce(&IrqDisabledToken) -> R) -> R {
    f(&IrqDisabledToken)
}

/// Test-only global token accessor for integration probes.
pub fn irq_probe_token() -> IrqDisabledToken {
    IrqDisabledToken
}
