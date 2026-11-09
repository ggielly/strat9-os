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
use crate::s9vm::exit::ExitClass;
use crate::s9vm::exitqueue::ExitQueue;
use crate::s9vm::guest::{FixedBits, GuestState};
use crate::s9vm::memmap::{perms_from_abi, GuestMap, MapError};
use crate::s9vm::mmu::Perms as MmuPerms;
use crate::s9vm::mmu::PAGE_SIZE;
use crate::s9vm::vcpu::{ExitInfo, SecondLevelMemory, Vcpu, VcpuError};
use crate::sync::SpinLock;
use strat9_abi::vmm::{exit_kind, VmmExitEvent, VmmRegs};

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

    /// Valeur du pointeur de traduction (EPTP) pour le bloc de contrôle.
    pub fn second_level_pointer(&self, caps: &HwCaps) -> u64 {
        self.second_level.pointer(caps)
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
    exits: ExitQueue,
}

/// vCPU logique : identifiant opaque, APIC id et bloc de registres ABI.
///
/// Le contexte matériel (bloc de contrôle, pile hôte, état invité) est créé au
/// moment de l'exécution, pas à la création logique : un monde peut être
/// configuré (mémoire, vCPU, registres) avant que le matériel ne soit activé.
pub struct VcpuSlot {
    /// Identifiant opaque du vCPU.
    pub id: u64,
    /// Identifiant APIC invité.
    pub apic_id: u32,
    /// Bloc de registres ABI.
    pub regs: VmmRegs,
    /// Contexte matériel (créé au premier `RUN`).
    hardware: Option<Vcpu>,
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
            exits: ExitQueue::default(),
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

/// Erreurs d'exécution d'un vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    /// vCPU inconnu.
    UnknownVcpu,
    /// Le monde n'a pas de mémoire invitée mappée.
    NoMemory,
    /// L'état invité fourni est invalide (voir `guest::GuestError`).
    InvalidGuestState,
    /// Le matériel n'est pas activé sur ce CPU.
    HardwareNotReady,
    /// Erreur matérielle pendant l'exécution.
    Hardware(VcpuError),
    /// La limite d'exits consécutifs résumés est atteinte (boucle pathologique).
    ExitStorm,
}

impl From<VcpuError> for RunError {
    fn from(value: VcpuError) -> Self {
        Self::Hardware(value)
    }
}

/// Nombre maximal d'exits « résumables » traités en interne avant de rendre
/// la main à la politique (protection contre une tempête d'interruptions).
const MAX_RESUMED_EXITS: u32 = 64;

/// Vrai si une sortie peut être reprise immédiatement par le noyau.
const fn is_resumable(class: ExitClass) -> bool {
    matches!(
        class,
        ExitClass::ExternalInterrupt
            | ExitClass::InterruptWindow
            | ExitClass::Apic
            | ExitClass::PreemptionTimer
    )
}

fn regs_from_guest(guest: &GuestState, base: &VmmRegs) -> VmmRegs {
    VmmRegs {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        flags: base.flags,
        rax: guest.rax,
        rbx: guest.rbx,
        rcx: guest.rcx,
        rdx: guest.rdx,
        rsi: guest.rsi,
        rdi: guest.rdi,
        rbp: guest.rbp,
        rsp: guest.rsp,
        r8: guest.r8,
        r9: guest.r9,
        r10: guest.r10,
        r11: guest.r11,
        r12: guest.r12,
        r13: guest.r13,
        r14: guest.r14,
        r15: guest.r15,
        rip: guest.rip,
        rflags: guest.rflags,
        cr0: guest.cr0,
        cr3: guest.cr3,
        cr4: guest.cr4,
        efer: guest.efer,
    }
}

fn event_from_exit(exit: &ExitInfo, vcpu_id: u64) -> VmmExitEvent {
    let class = exit.class();
    let mut event = VmmExitEvent {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        vcpu_id,
        gpa: exit.guest_physical_address,
        flags: 0,
        ..VmmExitEvent::default()
    };
    match class {
        ExitClass::IoPort => {
            let qualification = exit.qualification;
            event.kind = exit_kind::IO_PORT;
            event.port = ((qualification >> 16) & 0xFFFF) as u32;
            event.size = ((qualification & 0x7) + 1) as u32;
            // Bit 3 : 0 = OUT, 1 = IN.
            event.flags = ((qualification >> 3) & 1) as u32;
        }
        ExitClass::Halt => {
            event.kind = exit_kind::HALT;
        }
        ExitClass::EptViolation => {
            event.kind = exit_kind::TRANSLATION;
            // Bits 2:0 de la qualification EPT : lecture/écriture/exécution.
            event.flags = (exit.qualification & 0x7) as u32;
        }
        ExitClass::ExceptionOrNmi => {
            event.kind = exit_kind::EXCEPTION;
            event.flags = exit.interrupt_info;
        }
        _ => {
            event.kind = exit_kind::OTHER;
            event.flags = exit.raw_reason;
        }
    }
    event
}

/// Exécute un vCPU jusqu'à la prochaine sortie « de politique » et empile
/// l'événement correspondant dans la file du monde.
///
/// Les sorties purement hostiles au débit (interruption externe, fenêtre
/// d'interruption, APIC, timer de préemption) sont reprises immédiatement par
/// le noyau ; toutes les autres sont remontées à la politique.
pub fn run_vcpu(vcpu_id: u64, caps: &HwCaps) -> Result<(), RunError> {
    if crate::s9vm::active_cpu_count() == 0 {
        return Err(RunError::HardwareNotReady);
    }
    // 1. Retire le contexte matériel et les registres du registre, sans tenir
    //    le verrou pendant l'exécution.
    let (world_id, mut hardware, mut regs, pointer) = {
        let mut worlds = WORLDS.lock();
        let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(RunError::UnknownVcpu)?;
        let slot = world
            .vcpus
            .iter_mut()
            .find(|slot| slot.id == vcpu_id)
            .ok_or(RunError::UnknownVcpu)?;
        let memory = world.memory.as_ref().ok_or(RunError::NoMemory)?;
        let pointer = memory.second_level_pointer(caps);
        let hardware = slot.hardware.take();
        (world.record.id, hardware, slot.regs, pointer)
    };
    let mut hardware = match hardware {
        Some(hardware) => hardware,
        None => Vcpu::new(caps, pointer)?,
    };

    // 2. Construit et valide l'état invité.
    let mut guest = GuestState::from_abi_regs(&regs);
    let fixed = FixedBits::new(
        caps.cr0_fixed0,
        caps.cr0_fixed1,
        caps.cr4_fixed0,
        caps.cr4_fixed1,
    );
    guest
        .validate(&fixed, caps.unrestricted_guest)
        .map_err(|_| RunError::InvalidGuestState)?;

    // 3. Charge le bloc de contrôle, configure et exécute.
    // SAFETY: VT-x est actif sur ce CPU (vérifié ci-dessus) ; le bloc de
    // contrôle et la pile hôte appartiennent à ce vCPU, qui n'est pas en
    // cours d'exécution (contexte retiré du registre).
    let mut result = Ok(());
    unsafe {
        let _ = hardware.clear();
        if let Err(error) = hardware.load() {
            result = Err(RunError::Hardware(error));
        } else if let Err(error) = hardware.configure_host() {
            result = Err(RunError::Hardware(error));
        } else if let Err(error) = hardware.configure(caps, &guest) {
            result = Err(RunError::Hardware(error));
        } else {
            let mut resumed = 0u32;
            loop {
                match hardware.run() {
                    Ok(exit) => {
                        if is_resumable(exit.class()) && resumed < MAX_RESUMED_EXITS {
                            resumed += 1;
                            continue;
                        }
                        if is_resumable(exit.class()) {
                            result = Err(RunError::ExitStorm);
                        } else {
                            let event = event_from_exit(&exit, vcpu_id);
                            let _ = push_exit(world_id, event);
                        }
                        break;
                    }
                    Err(error) => {
                        result = Err(RunError::Hardware(error));
                        break;
                    }
                }
            }
        }
    }

    // 4. Recharge les registres depuis l'état invité post-exécution et remet
    //    le contexte matériel dans le registre si le monde existe toujours.
    regs = regs_from_guest(hardware.guest(), &regs);
    let mut worlds = WORLDS.lock();
    if let Some(world) = worlds.get_mut(&world_id) {
        if let Some(slot) = world.vcpus.iter_mut().find(|slot| slot.id == vcpu_id) {
            slot.regs = regs;
            slot.hardware = Some(hardware);
        }
    }
    result
}

/// Empile un événement dans la file d'un monde.
pub fn push_exit(world_id: u64, event: VmmExitEvent) -> Result<(), ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    world.exits.push(event).map_err(|_| ())
}

/// Dépile le prochain événement d'un monde.
pub fn pop_exit(world_id: u64) -> Result<VmmExitEvent, ()> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(())?;
    world.exits.pop().map_err(|_| ())
}

/// Nombre d'événements en attente pour un monde.
pub fn exit_count(world_id: u64) -> Option<usize> {
    WORLDS.lock().get(&world_id).map(|world| world.exits.len())
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
    world.vcpus.push(VcpuSlot { id, apic_id, regs, hardware: None });
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
