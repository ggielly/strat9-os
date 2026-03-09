use crate::arch::x86_64;

/// Preuve typée que les IRQ sont masquées sur le CPU courant.
///
/// L'allocateur mémoire consomme ce token pour empêcher à la compilation les
/// appels depuis des contextes où une interruption pourrait ré-entrer sur le
/// même verrou et provoquer un deadlock.
#[derive(Clone, Copy, Debug)]
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

    /// Construit la preuve sans relire `RFLAGS`.
    ///
    /// # Safety
    ///
    /// L'appelant doit garantir que les interruptions sont bien désactivées sur
    /// le CPU courant pendant toute la durée de validité logique du token.
    #[inline]
    pub(crate) unsafe fn new_unchecked() -> Self {
        Self(())
    }
}