//! s9vm — registre des mondes virtuels et mémoire invitée.
//!
//! Cette couche tient le registre des mondes (identifiant opaque, nom, silo
//! propriétaire, état) et possède, pour chaque monde, sa mémoire invitée :
//! frames épinglées, carte GPA (`GuestMap`) et tables de traduction de second
//! niveau (`SecondLevelMemory`).
//!
//! Invariants :
//! - une frame invitée est **épinglée** tant que le monde vit (jamais swappée,
//!   jamais libérée) ;
//! - l'ordre de destruction libère d'abord les tables de traduction, puis les
//!   frames invitées ;
//! - aucune allocation de frame n'est faite en tenant le verrou du registre :
//!   la mémoire est sortie du registre, manipulée, puis remise en place.
//!
//! Aucune politique n'est décidée ici : les contrôles d'accès sont faits par
//! la couche syscall (capabilities).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::s9vm::caps::HwCaps;
use crate::s9vm::memmap::{perms_from_abi, GuestMap, MapError};
use crate::s9vm::mmu::Perms as MmuPerms;
use crate::s9vm::mmu::PAGE_SIZE;
use crate::s9vm::vcpu::{SecondLevelMemory, VcpuError};
use crate::sync::SpinLock;

/// Nombre maximal de mondes simultanés (borne de sécurité).
pub const MAX_WORLDS: usize = 64;
/// Longueur maximale d'un nom.
pub const NAME_MAX: usize = 32;
/// Nombre maximal de vCPU par monde (borne de sécurité, avant quotas).
pub const MAX_VCPUS_PER_WORLD: usize = 32;
/// Quota de pages invitées par défaut (1 Gio).
pub const DEFAULT_QUOTA_PAGES: u64 = 262_144;

/// Enregistrement public d'un monde.
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

/// Erreurs de la couche mémoire invitée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// Monde inconnu.
    Unknown,
    /// Réservation invalide (alignement, chevauchement, quota).
    Map(MapError),
    /// Plus de frames disponibles.
    OutOfMemory,
    /// Erreur de traduction de second niveau.
    Translation(VcpuError),
}

impl From<MapError> for VmError {
    fn from(value: MapError) -> Self {
        Self::Map(value)
    }
}

impl From<VcpuError> for VmError {
    fn from(value: VcpuError) -> Self {
        Self::Translation(value)
    }
}

/// Alloue une frame de RAM invitée (zéro, non movable, épinglée).
fn alloc_guest_frame() -> Option<PhysFrame> {
    crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
            .ok()
    })
}

/// Libère une liste de frames invitées.
fn free_guest_frames(frames: Vec<PhysFrame>) {
    if frames.is_empty() {
        return;
    }
    crate::sync::with_irqs_disabled(|token| {
        for frame in frames {
            crate::memory::free_frame(token, frame);
        }
    });
}

/// Mémoire invitée d'un monde.
pub struct WorldMemory {
    second_level: SecondLevelMemory,
    map: GuestMap,
    frames: Vec<PhysFrame>,
}

impl WorldMemory {
    /// Crée une mémoire invitée vide.
    pub fn new(quota_pages: u64) -> Result<Self, VmError> {
        Ok(Self {
            second_level: SecondLevelMemory::new()?,
            map: GuestMap::new(quota_pages),
            frames: Vec::new(),
        })
    }

    /// Pages réservées.
    pub fn pages(&self) -> u64 {
        self.map.pages()
    }

    /// Mappe une plage GPA en RAM invitée (frames allouées et épinglées).
    ///
    /// `memtype` doit valoir `0` (write-back par défaut) ; les autres types ne
    /// sont pas encore supportés et sont refusés par l'appelant.
    ///
    /// En cas d'échec, tous les mappings et toutes les frames alloués pendant
    /// l'appel sont annulés : la mémoire du monde reste cohérente.
    pub fn map(
        &mut self,
        _caps: &HwCaps,
        gpa: u64,
        len: u64,
        perms_bits: u32,
        memtype: u8,
    ) -> Result<u64, VmError> {
        // 1. Valide la plage et réserve le quota avant toute allocation.
        self.map.reserve(gpa, len, perms_bits, memtype)?;
        let decoded = perms_from_abi(perms_bits);
        let perms = MmuPerms {
            read: decoded.read,
            write: decoded.write,
            execute: decoded.execute,
        };
        let pages = len / PAGE_SIZE;
        let mut allocated: Vec<PhysFrame> = Vec::with_capacity(pages as usize);
        let mut mapped: u64 = 0;
        for index in 0..pages {
            let Some(frame) = alloc_guest_frame() else {
                // Plus de mémoire : annule ce qui a déjà été fait.
                self.rollback(gpa, mapped, allocated);
                self.map.remove(gpa);
                return Err(VmError::OutOfMemory);
            };
            let hpa = frame.start_address.as_u64();
            if let Err(error) = self.second_level.map_4k(gpa + index * PAGE_SIZE, hpa, perms) {
                allocated.push(frame);
                self.rollback(gpa, mapped, allocated);
                self.map.remove(gpa);
                return Err(VmError::Translation(error));
            }
            allocated.push(frame);
            mapped += 1;
        }
        self.frames.extend(allocated);
        Ok(pages)
    }

    /// Annule `mapped` pages à partir de `gpa` et libère les frames.
    fn rollback(&mut self, gpa: u64, mapped: u64, frames: Vec<PhysFrame>) {
        for index in 0..mapped {
            let _ = self.second_level.unmap_4k(gpa + index * PAGE_SIZE);
        }
        free_guest_frames(frames);
    }

    /// Traduit une GPA (diagnostic).
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        self.second_level.translate(gpa)
    }

    /// Libère les tables de traduction puis les frames invitées.
    pub fn destroy(mut self) {
        let frames = core::mem::take(&mut self.frames);
        self.map.clear();
        self.second_level.destroy();
        free_guest_frames(frames);
    }
}

/// Monde enregistré : enregistrement public + mémoire invitée paresseuse +
/// vCPU logiques.
struct World {
    record: WorldRecord,
    memory: Option<WorldMemory>,
    vcpus: Vec<VcpuSlot>,
}

/// vCPU logique : identifiant opaque, APIC id et bloc de registres ABI.
///
/// Le contexte matériel (bloc de contrôle, pile hôte, état invité) est créé au
/// moment de l'exécution, pas à la création logique : un monde peut être
/// configuré (mémoire, vCPU, registres) avant que le matériel ne soit activé.
#[derive(Debug, Clone, Copy)]
pub struct VcpuSlot {
    /// Identifiant opaque du vCPU.
    pub id: u64,
    /// Identifiant APIC invité.
    pub apic_id: u32,
    /// Bloc de registres ABI.
    pub regs: strat9_abi::vmm::VmmRegs,
}

/// Registre global des mondes.
static WORLDS: SpinLock<BTreeMap<u64, World>> = SpinLock::new(BTreeMap::new());
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
    let mut id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    while id == 0 || worlds.contains_key(&id) {
        id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    }
    let record = WorldRecord::new(id, name, silo_id);
    worlds.insert(
        id,
        World {
            record,
            memory: None,
            vcpus: Vec::new(),
        },
    );
    Some(record)
}

/// Détruit un monde et libère sa mémoire invitée.
pub fn destroy(id: u64) -> Option<WorldRecord> {
    let world = {
        let mut worlds = WORLDS.lock();
        worlds.remove(&id)?
    };
    if let Some(memory) = world.memory {
        memory.destroy();
    }
    Some(world.record)
}

/// Retourne un enregistrement.
pub fn get(id: u64) -> Option<WorldRecord> {
    WORLDS.lock().get(&id).map(|world| world.record)
}

/// Liste les mondes (ordre des identifiants).
pub fn list() -> Vec<WorldRecord> {
    WORLDS
        .lock()
        .values()
        .map(|world| world.record)
        .collect()
}

/// Nombre de mondes.
pub fn count() -> usize {
    WORLDS.lock().len()
}

/// Met à jour l'état d'un monde. Retourne `false` si le monde est inconnu.
pub fn set_state(id: u64, state: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            world.record.state = state;
            true
        }
        None => false,
    }
}

/// Met à jour le nombre de vCPU d'un monde.
pub fn set_vcpu_count(id: u64, count: u32) -> bool {
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            world.record.vcpu_count = count;
            true
        }
        None => false,
    }
}

/// Mappe de la mémoire invitée dans un monde.
///
/// La mémoire est sortie du registre pendant l'allocation (jamais d'allocation
/// de frames sous le verrou), puis remise en place. Si le monde a été détruit
/// entre-temps, la mémoire est immédiatement libérée.
pub fn map_memory(
    id: u64,
    caps: &HwCaps,
    gpa: u64,
    len: u64,
    perms_bits: u32,
    memtype: u8,
) -> Result<u64, VmError> {
    // Le registre est verrouillé le moins longtemps possible : on récupère la
    // mémoire existante (ou on note son absence), puis on relâche le verrou
    // avant toute allocation de frame.
    enum Slot {
        Existing(WorldMemory),
        Empty,
    }
    let slot = {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&id).ok_or(VmError::Unknown)?;
        match world.memory.take() {
            Some(memory) => Slot::Existing(memory),
            None => Slot::Empty,
        }
    };
    let mut memory = match slot {
        Slot::Existing(memory) => memory,
        Slot::Empty => WorldMemory::new(DEFAULT_QUOTA_PAGES)?,
    };
    let result = memory.map(caps, gpa, len, perms_bits, memtype);
    let mut worlds = WORLDS.lock();
    match worlds.get_mut(&id) {
        Some(world) => {
            if result.is_ok() {
                world.record.mapped_pages = memory.pages();
            }
            world.memory = Some(memory);
            result
        }
        None => {
            drop(worlds);
            memory.destroy();
            Err(VmError::Unknown)
        }
    }
}

/// Erreurs de la couche vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRegistryError {
    /// Monde inconnu.
    WorldUnknown,
    /// vCPU inconnu.
    Unknown,
    /// Limite de vCPU atteinte pour ce monde.
    Limit,
    /// Version d'ABI incompatible.
    BadAbiVersion,
}

/// Prochain identifiant de vCPU (global, jamais 0).
static NEXT_VCPU: AtomicU64 = AtomicU64::new(1);

/// Crée un vCPU logique dans un monde.
pub fn create_vcpu(world_id: u64, apic_id: u32) -> Result<u64, VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VcpuRegistryError::WorldUnknown)?;
    if world.vcpus.len() >= MAX_VCPUS_PER_WORLD {
        return Err(VcpuRegistryError::Limit);
    }
    let id = NEXT_VCPU.fetch_add(1, Ordering::AcqRel);
    let regs = strat9_abi::vmm::VmmRegs {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..Default::default()
    };
    world.vcpus.push(VcpuSlot { id, apic_id, regs });
    world.record.vcpu_count = world.vcpus.len() as u32;
    Ok(id)
}

/// Détruit un vCPU logique. Retourne `false` s'il est inconnu.
pub fn destroy_vcpu(vcpu_id: u64) -> bool {
    let mut worlds = WORLDS.lock();
    for world in worlds.values_mut() {
        if let Some(index) = world.vcpus.iter().position(|slot| slot.id == vcpu_id) {
            world.vcpus.remove(index);
            world.record.vcpu_count = world.vcpus.len() as u32;
            return true;
        }
    }
    false
}

/// Retrouve le monde propriétaire d'un vCPU.
fn vcpu_world_mut(worlds: &mut BTreeMap<u64, World>, vcpu_id: u64) -> Option<&mut World> {
    worlds
        .values_mut()
        .find(|world| world.vcpus.iter().any(|slot| slot.id == vcpu_id))
}

/// Écrit le bloc de registres d'un vCPU.
pub fn set_vcpu_regs(vcpu_id: u64, regs: &strat9_abi::vmm::VmmRegs) -> Result<(), VcpuRegistryError> {
    if regs.abi_version != strat9_abi::vmm::VMM_ABI_VERSION {
        return Err(VcpuRegistryError::BadAbiVersion);
    }
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.regs = *regs;
    Ok(())
}

/// Lit le bloc de registres d'un vCPU.
pub fn get_vcpu_regs(vcpu_id: u64) -> Option<strat9_abi::vmm::VmmRegs> {
    let worlds = WORLDS.lock();
    for world in worlds.values() {
        if let Some(slot) = world.vcpus.iter().find(|slot| slot.id == vcpu_id) {
            return Some(slot.regs);
        }
    }
    None
}

/// Nombre de vCPU logiques d'un monde.
pub fn vcpu_count(world_id: u64) -> Option<u32> {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.vcpus.len() as u32)
}

/// Détail de diagnostic pour un monde : pages mappées et traduction d'une GPA.
pub fn debug_translate(id: u64, gpa: u64) -> Option<u64> {
    let memory_ref = {
        let worlds = WORLDS.lock();
        let world = worlds.get(&id)?;
        // On ne peut pas rendre une référence au-delà du verrou : on recopie
        // la traduction avant de le relâcher.
        world
            .memory
            .as_ref()
            .and_then(|memory| memory.translate(gpa))
    };
    memory_ref
}

/// Libère toutes les entrées (tests et arrêt du noyau).
pub fn clear() {
    let worlds: BTreeMap<u64, World> = {
        let mut guard = WORLDS.lock();
        core::mem::take(&mut *guard)
    };
    for (_, world) in worlds {
        if let Some(memory) = world.memory {
            memory.destroy();
        }
    }
}
