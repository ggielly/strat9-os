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

/// Runs `f` with a dummy token — semantically "interrupts disabled" because
/// each host test is single-threaded.
#[inline]
pub fn with_irqs_disabled<R>(f: impl FnOnce(&IrqDisabledToken) -> R) -> R {
    f(&IrqDisabledToken)
}

/// Test-only global token accessor for integration probes.
pub fn irq_probe_token() -> IrqDisabledToken {
    IrqDisabledToken
}
