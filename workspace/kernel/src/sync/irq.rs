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

use crate::arch;

/// Typed proof that IRQs are masked on the current CPU.
///
/// The memory allocator consumes this token to prevent, at compile time,
/// calls from contexts where an interrupt could re-enter the same lock
/// and cause a deadlock.
///
/// Intentionally non-`Copy` and non-`Clone`: the token must not escape
/// the IRQ-off context in which it was created.
///
/// # Creation paths
///
/// | Path | Visibility | Use case |
/// |------|-----------|----------|
/// | `verify()` | `pub` | Check RFLAGS; returns `Some` if IRQs already disabled |
/// | `with_irqs_disabled()` | `pub` | Safe wrapper: disables IRQs, runs closure, restores |
/// | `IrqDisabled::enter()` | `pub(super)` | Guardian: called by SpinLock on acquire |
/// | `token_from_trusted_context()` | `pub(crate)` | Trait impls (e.g. `X86FrameAllocator`) that can't accept a token parameter |
/// | `new_unchecked()` | `pub(super)` | Internal to `sync` module only; never call directly |
#[derive(Debug)]
pub struct IrqDisabledToken(());

impl IrqDisabledToken {
    /// Check the current interrupt state and return proof if IRQs are already disabled.
    #[inline]
    pub fn verify() -> Option<Self> {
        if arch::interrupts_enabled() {
            None
        } else {
            Some(Self(()))
        }
    }

    /// Build the proof without re-checking `RFLAGS`.
    ///
    /// **Restricted to `pub(super)`**: only visible within the `sync` module.
    /// External code must use `verify()`, `with_irqs_disabled()`, or
    /// `token_from_trusted_context()` instead.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that IRQs are indeed disabled on the current
    /// CPU for the entire logical validity of the token.
    #[inline]
    pub(super) unsafe fn new_unchecked() -> Self {
        Self(())
    }

    /// Create a token when the caller guarantees that IRQs are already disabled.
    ///
    /// **Purpose:** Implementing external traits (e.g. `X86FrameAllocator`)
    /// whose signature cannot accept a token parameter.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that IRQs are disabled on the current CPU.
    /// This is a `pub(crate)` escape hatch : prefer `verify()` or
    /// `with_irqs_disabled()` for all other use cases.
    #[inline]
    pub(crate) unsafe fn token_from_trusted_context() -> Self {
        Self::new_unchecked()
    }
}

/// Execute a closure with IRQs disabled, providing an `IrqDisabledToken` as proof.
///
/// Saves and disables IRQs before calling `f`, then restores the previous flag state.
#[inline]
pub fn with_irqs_disabled<R>(f: impl FnOnce(&IrqDisabledToken) -> R) -> R {
    let saved = crate::arch::save_flags_and_cli();
    // SAFETY: save_flags_and_cli() has just disabled interrupts on this CPU;
    // the token is dropped before restore_flags() re-enables them.
    let token = unsafe { IrqDisabledToken::new_unchecked() };
    let result = f(&token);
    crate::arch::restore_flags(saved);
    result
}
