//! Lock guardian trait — determines the guard behaviour of [`SpinLock`].
//!
//! Two built-in implementations are provided:
//!
//! * [`IrqDisabled`]   – saves RFLAGS and clears IF before acquiring the lock.
//!   Use this for data shared across CPUs (heap, VFS, IPC queues, …).
//!   This corresponds to the classic Linux `spin_lock_irqsave`.
//!
//! * [`PreemptDisabled`] – increments the per-CPU preemption depth without
//!   touching IF. Use this for **per-CPU** data that is never accessed from
//!   interrupt handlers (scheduler run-queues, per-CPU frame caches, …).
//!
//! The trait is sealed so that only these two implementations exist inside
//! the kernel crate, preventing accidental misuse.

use super::{IrqDisabledToken, PreemptGuard};

// ─── Sealed trait ─────────────────────────────────────────────────────────────

mod private {
    pub trait Sealed {}
}

/// Determines how interrupts / preemption are handled while a [`SpinLock`] is
/// held.
///
/// [`SpinLock`]: super::SpinLock
pub trait Guardian: private::Sealed {
    /// Token type that proves the CPU is in the right protection mode.
    type Token;

    /// Enter the protected mode and return the token.
    fn enter() -> GuardianState<Self::Token>;
    /// Exit the protected mode, restoring the previous CPU state.
    fn exit(state: GuardianState<Self::Token>);
}

/// Opaque state returned by [`Guardian::enter`] and consumed by
/// [`Guardian::exit`].
pub struct GuardianState<Token> {
    pub(crate) token: Token,
    pub(crate) saved_flags: u64,
    pub(crate) restore_flags: bool,
}

// ─── IrqDisabled ─────────────────────────────────────────────────────────────

/// Guardian that saves RFLAGS and disables IRQs before the lock is acquired.
///
/// Equivalent to Linux `spin_lock_irqsave`. Use this for data that may be
/// accessed from interrupt handlers or from multiple CPUs.
pub struct IrqDisabled;

impl private::Sealed for IrqDisabled {}

impl Guardian for IrqDisabled {
    type Token = IrqDisabledToken;

    #[inline]
    fn enter() -> GuardianState<Self::Token> {
        let saved = crate::arch::x86_64::save_flags_and_cli();
        // SAFETY: save_flags_and_cli() just cleared IF on this CPU.
        let token = unsafe { IrqDisabledToken::new_unchecked() };
        GuardianState {
            token,
            saved_flags: saved,
            restore_flags: true,
        }
    }

    #[inline]
    fn exit(state: GuardianState<Self::Token>) {
        if state.restore_flags {
            crate::arch::x86_64::restore_flags(state.saved_flags);
        }
    }
}

// ─── PreemptDisabled ─────────────────────────────────────────────────────────

/// Guardian that only disables preemption, leaving IRQs untouched.
///
/// Use this for **per-CPU** data that is never accessed from interrupt handlers.
/// Cheaper than [`IrqDisabled`] because it avoids a RFLAGS read/write.
pub struct PreemptDisabled;

impl private::Sealed for PreemptDisabled {}

impl Guardian for PreemptDisabled {
    type Token = PreemptGuard;

    #[inline]
    fn enter() -> GuardianState<Self::Token> {
        GuardianState {
            token: PreemptGuard::new(),
            saved_flags: 0,
            restore_flags: false,
        }
    }

    #[inline]
    fn exit(_state: GuardianState<Self::Token>) {
        // PreemptGuard::drop() re-enables preemption automatically.
    }
}
