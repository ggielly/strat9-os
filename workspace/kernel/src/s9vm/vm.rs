//! s9vm — registre des mondes virtuels.
//!
//! Cette couche est volontairement minimale : elle tient le registre des
//! mondes créés (identifiant opaque, nom, silo propriétaire, état) et sert
//! d'ossature à l'ABI `SYS_VMM_*`. Les vCPU, la mémoire invitée et les
//! périphériques viendront s'y greffer sans changer l'ABI.
//!
//! Aucune politique n'est décidée ici : les contrôles d'accès sont faits par
//! la couche syscall (capabilities), pas par le registre.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinLock;

/// Nombre maximal de mondes simultanés (borne de sécurité).
pub const MAX_WORLDS: usize = 64;
/// Longueur maximale d'un nom.
pub const NAME_MAX: usize = 32;
/// Nombre maximal de vCPU par monde (borne de sécurité, avant quotas).
pub const MAX_VCPUS_PER_WORLD: usize = 32;

/// Enregistrement d'un monde.
#[derive(Debug, Clone, Copy)]
pub struct WorldRecord {
    /// Identifiant opaque (jamais 0).
    pub id: u64,
    /// Nom (UTF-8 tronqué, complété par des zéros).
    pub name: [u8; NAME_MAX],
    /// Longueur utile du nom.
    pub name_len: u8,
    /// Silo propriétaire (0 = monde noyau).
    pub silo_id: u32,
    /// État (constantes `strat9_abi::vmm::state`).
    pub state: u32,
    /// Nombre de vCPU enregistrés.
    pub vcpu_count: u32,
    /// Pages invitées mappées.
    pub mapped_pages: u64,
}

impl WorldRecord {
    fn new(id: u64, name: &[u8], silo_id: u32) -> Self {
        let mut stored = [0u8; NAME_MAX];
        let length = name.len().min(NAME_MAX);
        stored[..length].copy_from_slice(&name[..length]);
        Self {
            id,
            name: stored,
            name_len: length as u8,
            silo_id,
            state: strat9_abi::vmm::state::CREATED,
            vcpu_count: 0,
            mapped_pages: 0,
        }
    }

    /// Nom sous forme de tranche d'octets utiles.
    pub fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Registre global des mondes.
static WORLDS: SpinLock<BTreeMap<u64, WorldRecord>> = SpinLock::new(BTreeMap::new());
/// Prochain identifiant (1 = premier monde ; 0 est réservé au résumé global).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Crée un monde. Retourne `None` si le registre est plein ou si le nom est
/// vide.
pub fn create(name: &[u8], silo_id: u32) -> Option<WorldRecord> {
    if name.is_empty() || name.len() > NAME_MAX {
        return None;
    }
    let mut worlds = WORLDS.lock();
    if worlds.len() >= MAX_WORLDS {
        return None;
    }
    // Boucle bornée : les identifiants ne sont jamais réutilisés.
    let mut id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    while id == 0 || worlds.contains_key(&id) {
        id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    }
    let record = WorldRecord::new(id, name, silo_id);
    worlds.insert(id, record);
    Some(record)
}

/// Détruit un monde. Retourne l'enregistrement supprimé, s'il existait.
pub fn destroy(id: u64) -> Option<WorldRecord> {
    WORLDS.lock().remove(&id)
}

/// Retourne un enregistrement.
pub fn get(id: u64) -> Option<WorldRecord> {
    WORLDS.lock().get(&id).copied()
}

/// Liste les mondes (ordre des identifiants).
pub fn list() -> Vec<WorldRecord> {
    WORLDS.lock().values().copied().collect()
}

/// Nombre de mondes.
pub fn count() -> usize {
    WORLDS.lock().len()
}

/// Met à jour l'état d'un monde. Retourne `false` si le monde est inconnu.
pub fn set_state(id: u64, state: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(record) => {
            record.state = state;
            true
        }
        None => false,
    }
}

/// Met à jour le nombre de vCPU d'un monde.
pub fn set_vcpu_count(id: u64, count: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(record) => {
            record.vcpu_count = count;
            true
        }
        None => false,
    }
}

/// Libère toutes les entrées (utilisé par les tests et l'arrêt du noyau).
pub fn clear() {
    WORLDS.lock().clear();
}
