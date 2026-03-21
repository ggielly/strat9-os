use crate::arch::x86_64;

/// Preuve typée que les IRQ sont masquées sur le CPU courant.
///
/// L'allocateur mémoire consomme ce token pour empêcher à la compilation les
/// appels depuis des contextes où une interruption pourrait ré-entrer sur le
/// même verrou et provoquer un deadlock.
///
/// Intentionnellement non-`Copy` et non-`Clone` : le token ne doit pas pouvoir
/// s'échapper du contexte IRQ-off dans lequel il a été créé.
#[derive(Debug)]
pub struct IrqDisabledToken(());

impl IrqDisabledToken {
    /// Vérifie l'état courant des interruptions et retourne la preuve si elles
    /// sont déjà désactivées.
    #[inline]
    pub fn verify() -> Option<Self> {
        if x86_64::interrupts_enabled() {
            None
        } else {
            Some(Self(()))
        }
    }

    /// Builds the proof without re-checking `RFLAGS`.
    /// Reserved for internal producers of the `sync` module (guardian, with_irqs_disabled).
    ///
    /// # Safety
    /// The caller must guarantee that IRQs are indeed disabled on the current CPU for the entire
    /// logical validity of the token.

    #[inline]
    pub(super) unsafe fn new_unchecked() -> Self {
        Self(())
    }

    /// Create a token when the caller guarantees that IRQs are already disabled.
    /// Only to be used for implementing external traits (e.g. `X86FrameAllocator`)
    /// whose signature cannot accept a token parameter. The caller MUST guarantee
    /// that interrupts are disabled on the current CPU.
    ///
    /// # Safety
    /// The caller must guarantee that IRQs are disabled on the current CPU.
    ///
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
    let saved = crate::arch::x86_64::save_flags_and_cli();
    // SAFETY: save_flags_and_cli() has just disabled interrupts on this CPU;
    // the token is dropped before restore_flags() re-enables them.
    let token = unsafe { IrqDisabledToken::new_unchecked() };
    let result = f(&token);
    crate::arch::x86_64::restore_flags(saved);
    result
}
