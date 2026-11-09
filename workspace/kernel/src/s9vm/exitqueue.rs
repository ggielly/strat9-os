//! s9vm — file d'événements de sortie bornée.
//!
//! Chaque monde possède une file d'événements (taille fixe) que la couche
//! d'exécution remplit et que la politique consomme via
//! `SYS_VMM_EXIT_HANDLER`. La file est **bornée** : un producteur ne peut pas
//! faire croître la mémoire du noyau, et un consommateur lent provoque un
//! refus explicite (`Full`) plutôt qu'une perte silencieuse.
//!
//! Module pur (testable sur l'hôte) : il ne dépend que de l'ABI.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use strat9_abi::vmm::VmmExitEvent;

/// Capacité par défaut d'une file d'exits.
pub const DEFAULT_CAPACITY: usize = 64;

/// Erreurs de la file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// File pleine.
    Full,
    /// File vide.
    Empty,
}

/// File bornée d'événements de sortie.
#[derive(Debug)]
pub struct ExitQueue {
    entries: VecDeque<VmmExitEvent>,
    capacity: usize,
    dropped: u64,
}

impl ExitQueue {
    /// Crée une file de capacité donnée (au moins 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    /// Capacité.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Nombre d'événements en attente.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Vrai si la file est vide.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Nombre d'événements refusés depuis la création (diagnostic).
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Ajoute un événement. Retourne `Full` si la file est pleine ; aucune
    /// donnée n'est écrasée silencieusement.
    pub fn push(&mut self, event: VmmExitEvent) -> Result<(), QueueError> {
        if self.entries.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return Err(QueueError::Full);
        }
        self.entries.push_back(event);
        Ok(())
    }

    /// Retire le plus ancien événement.
    pub fn pop(&mut self) -> Result<VmmExitEvent, QueueError> {
        self.entries.pop_front().ok_or(QueueError::Empty)
    }

    /// Vide la file et retourne les événements retirés.
    pub fn drain(&mut self) -> Vec<VmmExitEvent> {
        self.entries.drain(..).collect()
    }

    /// Vide la file.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for ExitQueue {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}
