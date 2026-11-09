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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::process::{kthread, scheduler::ticks, sleep_current_task_ticks, TaskId};
use crate::s9vm::apic::LocalApic;
use crate::s9vm::caps::HwCaps;
use crate::s9vm::exit::ExitClass;
use crate::s9vm::exitqueue::ExitQueue;
use crate::s9vm::guest::{FixedBits, GuestState};
use crate::s9vm::memmap::{perms_from_abi, GuestMap, MapError};
use crate::s9vm::mmu::Perms as MmuPerms;
use crate::s9vm::mmu::PAGE_SIZE;
use crate::s9vm::vcpu::{ExitInfo, SecondLevelMemory, Vcpu, VcpuError};
use crate::sync::{SpinLock, WaitQueue};
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
    /// Destruction en cours : toute nouvelle opération est refusée et les
    /// tâches vCPU sont arrêtées avant de libérer la mémoire.
    closing: bool,
    /// Monde en pause : les `RUN` sont refusés (`Paused`) jusqu'à reprise.
    paused: bool,
}

/// vCPU logique : identifiant opaque, APIC id et bloc de registres ABI.
///
/// Le contexte matériel (bloc de contrôle, pile hôte, état invité) est créé au
/// moment de l'exécution, pas à la création logique : un monde peut être
/// configuré (mémoire, vCPU, registres) avant que le matériel ne soit activé.
///
/// Modèle ADR-4 : chaque vCPU est piloté par une **tâche noyau** dédiée
/// ([`VcpuSlot::task`]). La tâche attend une demande de `RUN`, exécute
/// l'invité jusqu'à la prochaine sortie de politique, empile l'événement puis
/// se remet en attente. Le noyau garantit ainsi qu'un invité ne s'exécute
/// jamais sur la pile de l'appelant syscall.
pub struct VcpuSlot {
    /// Identifiant opaque du vCPU.
    pub id: u64,
    /// Identifiant APIC invité.
    pub apic_id: u32,
    /// Bloc de registres ABI.
    pub regs: VmmRegs,
    /// Contexte matériel (créé au premier `RUN`).
    hardware: Option<Vcpu>,
    /// APIC local invité (état architectural, page MMIO et MSR x2APIC).
    apic: LocalApic,
    /// Interruption externe en attente d'injection au prochain `RUN`.
    pending_irq: Option<u8>,
    /// NMI en attente d'injection au prochain `RUN`.
    pending_nmi: bool,
    /// Tâche noyau qui pilote ce vCPU (créée avec le vCPU).
    task: Option<TaskId>,
    /// Un `RUN` a été demandé et n'a pas encore été pris en compte.
    run_requested: bool,
    /// Un `RUN` est en vol : un seul appelant à la fois.
    run_in_flight: bool,
    /// Le dernier `RUN` demandé est terminé.
    run_done: bool,
    /// Résultat du dernier `RUN` (valide quand `run_done`).
    run_result: Option<Result<(), RunError>>,
    /// Arrêt demandé (destruction du vCPU ou du monde).
    shutdown: bool,
    /// La tâche noyau a terminé et ses ressources matérielles sont déchargées.
    exited: bool,
    /// Réveil de la tâche vCPU sur demande de `RUN` (ou d'arrêt).
    run_wait: Arc<WaitQueue>,
    /// Réveil des appelants bloqués sur la fin d'un `RUN` ou sur un arrêt.
    done_wait: Arc<WaitQueue>,
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
            closing: false,
            paused: false,
        },
    );
    Some(record)
}

/// Détruit un monde et libère sa mémoire invitée.
///
/// Les tâches vCPU sont arrêtées et attendues **avant** de libérer la mémoire :
/// une tâche encore en vol pourrait sinon déréférencer les tables de second
/// niveau du monde. Un second appel concurrent pendant la fermeture retourne
/// `None`.
pub fn destroy(id: u64) -> Option<WorldRecord> {
    // 1. Marque le monde fermé et réveille toutes les tâches vCPU.
    let mut to_join: Vec<u64> = Vec::new();
    let mut wakers: Vec<Arc<WaitQueue>> = Vec::new();
    {
        let mut worlds = WORLDS.lock();
        let world = worlds.get_mut(&id)?;
        if world.closing {
            return None;
        }
        world.closing = true;
        for slot in world.vcpus.iter_mut() {
            slot.shutdown = true;
            wakers.push(Arc::clone(&slot.run_wait));
            wakers.push(Arc::clone(&slot.done_wait));
            if slot.task.is_some() {
                to_join.push(slot.id);
            }
        }
    }
    for waiter in wakers {
        waiter.wake_all();
    }
    // 2. Attend la sortie des tâches vCPU, sans tenir le verrou.
    for vcpu in to_join {
        wait_vcpu_exited(vcpu);
    }
    // 3. Retire le monde et libère la mémoire invitée.
    let world = {
        let mut worlds = WORLDS.lock();
        worlds.remove(&id)?
    };
    if let Some(memory) = world.memory {
        memory.destroy();
    }
    Some(world.record)
}

/// Retrouve un monde et l'index d'un vCPU dans ce monde.
fn locate_slot(
    worlds: &mut BTreeMap<u64, World>,
    vcpu_id: u64,
) -> Option<(&mut World, usize)> {
    for world in worlds.values_mut() {
        if let Some(index) = world.vcpus.iter().position(|slot| slot.id == vcpu_id) {
            return Some((world, index));
        }
    }
    None
}

/// Attend que la tâche noyau d'un vCPU ait terminé (ou que le vCPU ait
/// disparu du registre).
fn wait_vcpu_exited(vcpu_id: u64) {
    loop {
        let waiters = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &world.vcpus[index];
            if slot.exited || slot.task.is_none() {
                return;
            }
            Arc::clone(&slot.done_wait)
        };
        waiters.wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) if !world.vcpus[index].exited => None,
                _ => Some(()),
            }
        });
    }
}

/// Retire un vCPU du registre sans attendre de tâche.
fn remove_vcpu(vcpu_id: u64) -> bool {
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

/// Crée l'entrée de registre d'un vCPU.
fn new_vcpu_slot(id: u64, apic_id: u32) -> VcpuSlot {
    let regs = strat9_abi::vmm::VmmRegs {
        abi_version: strat9_abi::vmm::VMM_ABI_VERSION,
        ..Default::default()
    };
    VcpuSlot {
        id,
        apic_id,
        regs,
        hardware: None,
        apic: LocalApic::new(apic_id),
        pending_irq: None,
        pending_nmi: false,
        task: None,
        run_requested: false,
        run_in_flight: false,
        run_done: false,
        run_result: None,
        shutdown: false,
        exited: false,
        run_wait: Arc::new(WaitQueue::new()),
        done_wait: Arc::new(WaitQueue::new()),
    }
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

/// Journalise un instantané du moteur (diagnostic noyau).
pub fn debug_dump() {
    let worlds = list();
    log::info!(
        "[s9vm] debug: {} monde(s), {} CPU actif(s)",
        worlds.len(),
        crate::s9vm::active_cpu_count()
    );
    for world in worlds {
        let name = core::str::from_utf8(world.name_slice()).unwrap_or("<non-utf8>");
        log::info!(
            "[s9vm] debug: world {} name={} silo={} state={} vcpus={} pages={}",
            world.id,
            name,
            world.silo_id,
            world.state,
            world.vcpu_count,
            world.mapped_pages
        );
        let mut worlds = WORLDS.lock();
        if let Some(entry) = worlds.get(&world.id) {
            for slot in &entry.vcpus {
                log::info!(
                    "[s9vm] debug:   vcpu {} apic={} tpr={} irr={} isr={} irq={:?} nmi={} task={:?}",
                    slot.id,
                    slot.apic.apic_id(),
                    slot.apic.tpr(),
                    slot.apic.has_pending(),
                    slot.apic.in_service(),
                    slot.pending_irq,
                    slot.pending_nmi,
                    slot.task
                );
            }
        }
    }
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
    /// La tâche noyau du vCPU n'a pas pu être créée.
    Thread,
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
    /// Un `RUN` est déjà en vol pour ce vCPU.
    Busy,
    /// Le monde est en pause.
    Paused,
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
        ExitClass::ExternalInterrupt | ExitClass::InterruptWindow | ExitClass::Apic
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
        ExitClass::PreemptionTimer => {
            event.kind = exit_kind::PREEMPTION_TIMER;
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
    let (world_id, mut hardware, mut regs, pointer, pending_irq, pending_nmi) = {
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
        let pending_irq = slot.pending_irq.take();
        let pending_nmi = core::mem::replace(&mut slot.pending_nmi, false);
        (world.record.id, hardware, slot.regs, pointer, pending_irq, pending_nmi)
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
        } else if pending_nmi {
            // Le NMI est prioritaire sur une interruption externe en attente.
            if let Err(error) = hardware.inject_nmi() {
                result = Err(RunError::Hardware(error));
            }
        } else if let Some(vector) = pending_irq {
            // Injection différée : le champ « VM-entry interruption
            // information » est écrit juste avant l'entrée ; le processeur le
            // consomme et le remet à zéro lors de la livraison.
            if let Err(error) = hardware.inject_interrupt(vector) {
                result = Err(RunError::Hardware(error));
            }
        }
        if result.is_ok() {
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

/// Crée un vCPU logique dans un monde et la tâche noyau qui le pilote.
pub fn create_vcpu(world_id: u64, apic_id: u32) -> Result<u64, VcpuRegistryError> {
    // 1. Enregistre le vCPU sans tenir le verrou pendant la création de tâche.
    let id = {
        let mut worlds = WORLDS.lock();
        let world = worlds
            .get_mut(&world_id)
            .ok_or(VcpuRegistryError::WorldUnknown)?;
        if world.closing {
            return Err(VcpuRegistryError::WorldUnknown);
        }
        if world.vcpus.len() >= MAX_VCPUS_PER_WORLD {
            return Err(VcpuRegistryError::Limit);
        }
        let id = NEXT_VCPU.fetch_add(1, Ordering::AcqRel);
        world.vcpus.push(new_vcpu_slot(id, apic_id));
        world.record.vcpu_count = world.vcpus.len() as u32;
        id
    };
    // 2. Crée la tâche noyau du vCPU (modèle ADR-4).
    let task = match kthread::spawn("s9vm-vcpu", move || vcpu_task_main(world_id, id)) {
        Ok(task) => task,
        Err(_) => {
            let _ = remove_vcpu(id);
            return Err(VcpuRegistryError::Thread);
        }
    };
    // 3. Publie l'identifiant de tâche si le vCPU existe encore.
    {
        let mut worlds = WORLDS.lock();
        if let Some((world, index)) = locate_slot(&mut worlds, id) {
            world.vcpus[index].task = Some(task);
        }
    }
    Ok(id)
}

/// Détruit un vCPU logique. Retourne `false` s'il est inconnu.
///
/// La tâche noyau est arrêtée et attendue avant que l'entrée ne soit retirée :
/// le contexte matériel (bloc de contrôle, pile hôte, EPT) n'est jamais libéré
/// pendant une entrée invitée.
pub fn destroy_vcpu(vcpu_id: u64) -> bool {
    let (run_wait, done_wait, has_task) = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return false;
        };
        let slot = &mut world.vcpus[index];
        if slot.shutdown {
            return false;
        }
        slot.shutdown = true;
        (
            Arc::clone(&slot.run_wait),
            Arc::clone(&slot.done_wait),
            slot.task.is_some(),
        )
    };
    run_wait.wake_all();
    done_wait.wake_all();
    if has_task {
        wait_vcpu_exited(vcpu_id);
    }
    remove_vcpu(vcpu_id)
}

/// Corps de la tâche noyau d'un vCPU : attend les demandes de `RUN`, exécute
/// l'invité jusqu'à la prochaine sortie de politique, publie l'événement puis
/// se remet en attente.
fn vcpu_task_main(world_id: u64, vcpu_id: u64) {
    let _ = world_id;
    loop {
        // Réveils : demande de RUN ou arrêt.
        let run_wait = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &world.vcpus[index];
            if slot.shutdown {
                break;
            }
            Arc::clone(&slot.run_wait)
        };
        let run = run_wait.wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) => {
                    let slot = &mut world.vcpus[index];
                    if slot.shutdown {
                        Some(false)
                    } else if slot.run_requested {
                        slot.run_requested = false;
                        Some(true)
                    } else {
                        None
                    }
                }
                None => Some(false),
            }
        });
        if !run {
            break;
        }

        let result = execute_one_run(vcpu_id);

        let done_wait = {
            let mut worlds = WORLDS.lock();
            let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
                return;
            };
            let slot = &mut world.vcpus[index];
            slot.run_done = true;
            slot.run_in_flight = false;
            slot.run_result = Some(result);
            Arc::clone(&slot.done_wait)
        };
        done_wait.wake_all();
    }
    cleanup_vcpu(vcpu_id);
}

/// Exécute un `RUN` (une entrée invitée au maximum) dans la tâche vCPU.
fn execute_one_run(vcpu_id: u64) -> Result<(), RunError> {
    if crate::s9vm::active_cpu_count() == 0 {
        return Err(RunError::HardwareNotReady);
    }
    let caps = crate::s9vm::detect().ok_or(RunError::HardwareNotReady)?;
    // Les interruptions hôte restent coupées pendant l'entrée invitée : le
    // temps invité est borné par la sortie suivante (P0). La préemption VMX
    // (timer) viendra avec le modèle de préemption complet.
    crate::sync::with_irqs_disabled(|_| run_vcpu(vcpu_id, &caps))
}

/// Décharge le contexte matériel et signale la sortie de la tâche vCPU.
fn cleanup_vcpu(vcpu_id: u64) {
    let hardware = {
        let mut worlds = WORLDS.lock();
        match locate_slot(&mut worlds, vcpu_id) {
            Some((world, index)) => world.vcpus[index].hardware.take(),
            None => None,
        }
    };
    if let Some(mut hardware) = hardware {
        if crate::s9vm::active_cpu_count() > 0 {
            // SAFETY: plus aucun invité ne s'exécute sur ce vCPU.
            unsafe {
                let _ = hardware.clear();
            }
        }
    }
    let done_wait = {
        let mut worlds = WORLDS.lock();
        match locate_slot(&mut worlds, vcpu_id) {
            Some((world, index)) => {
                let slot = &mut world.vcpus[index];
                slot.exited = true;
                Arc::clone(&slot.done_wait)
            }
            None => return,
        }
    };
    done_wait.wake_all();
}

/// Demande l'exécution d'un vCPU et **bloque** l'appelant jusqu'à la fin de ce
/// `RUN` (une sortie de politique au maximum).
///
/// Un seul `RUN` peut être en vol par vCPU ; un second appel concurrent reçoit
/// [`RunError::Busy`].
pub fn request_run(vcpu_id: u64) -> Result<(), RunError> {
    let (run_wait, done_wait) = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return Err(RunError::UnknownVcpu);
        };
        if world.closing {
            return Err(RunError::UnknownVcpu);
        }
        if world.paused {
            return Err(RunError::Paused);
        }
        let slot = &mut world.vcpus[index];
        if slot.shutdown || slot.task.is_none() {
            return Err(RunError::UnknownVcpu);
        }
        if slot.run_in_flight || slot.run_requested {
            return Err(RunError::Busy);
        }
        slot.run_in_flight = true;
        slot.run_requested = true;
        slot.run_done = false;
        slot.run_result = None;
        (Arc::clone(&slot.run_wait), Arc::clone(&slot.done_wait))
    };
    run_wait.wake_one();
    done_wait
        .wait_until(|| {
            let mut worlds = WORLDS.lock();
            match locate_slot(&mut worlds, vcpu_id) {
                Some((world, index)) => {
                    let slot = &mut world.vcpus[index];
                    if slot.run_done {
                        Some(slot.run_result.take())
                    } else {
                        None
                    }
                }
                None => Some(Some(Err(RunError::UnknownVcpu))),
            }
        })
        .unwrap_or(Err(RunError::UnknownVcpu))
}

/// Attend qu'au moins un événement de sortie soit disponible dans le monde du
/// vCPU, ou que le délai expire.
///
/// `timeout_ns = 0` teste immédiatement (pas d'attente). Retourne `true` si un
/// événement est en attente, `false` en cas d'expiration.
pub fn wait_exit(vcpu_id: u64, timeout_ns: u64) -> Result<bool, VcpuRegistryError> {
    let world_id = {
        let mut worlds = WORLDS.lock();
        let Some((world, index)) = locate_slot(&mut worlds, vcpu_id) else {
            return Err(VcpuRegistryError::Unknown);
        };
        if world.closing || world.vcpus[index].shutdown {
            return Err(VcpuRegistryError::Unknown);
        }
        world.record.id
    };
    if exit_count(world_id).unwrap_or(0) > 0 {
        return Ok(true);
    }
    if timeout_ns == 0 {
        return Ok(false);
    }
    let budget_ticks = (timeout_ns / crate::arch::timer::NS_PER_TICK).max(1);
    let deadline = ticks().saturating_add(budget_ticks);
    loop {
        if exit_count(world_id).unwrap_or(0) > 0 {
            return Ok(true);
        }
        if ticks() >= deadline {
            return Ok(false);
        }
        sleep_current_task_ticks(1);
    }
}

/// Programme l'injection d'une interruption externe dans un vCPU.
///
/// L'injection est différée : le vecteur est mémorisé et écrit dans le champ
/// « VM-entry interruption information » au prochain `run_vcpu`. Retourne
/// `Unknown` si le vCPU n'existe pas.
pub fn inject_irq(vcpu_id: u64, vector: u8) -> Result<(), VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.pending_irq = Some(vector);
    slot.apic.inject(vector);
    Ok(())
}

/// Programme l'injection d'un NMI dans un vCPU (délivré au prochain `RUN`).
pub fn inject_nmi(vcpu_id: u64) -> Result<(), VcpuRegistryError> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id).ok_or(VcpuRegistryError::Unknown)?;
    let slot = world
        .vcpus
        .iter_mut()
        .find(|slot| slot.id == vcpu_id)
        .ok_or(VcpuRegistryError::Unknown)?;
    slot.pending_nmi = true;
    Ok(())
}

/// Met un monde en pause (`RUN` refusé jusqu'à reprise).
pub fn pause(world_id: u64) -> Result<(), VmError> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing {
        return Err(VmError::Unknown);
    }
    world.paused = true;
    world.record.state = strat9_abi::vmm::state::PAUSED;
    Ok(())
}

/// Reprend un monde en pause.
pub fn resume(world_id: u64) -> Result<(), VmError> {
    let mut worlds = WORLDS.lock();
    let world = worlds.get_mut(&world_id).ok_or(VmError::Unknown)?;
    if world.closing {
        return Err(VmError::Unknown);
    }
    world.paused = false;
    world.record.state = strat9_abi::vmm::state::RUNNING;
    Ok(())
}

/// Vrai si le monde est en pause.
pub fn is_paused(world_id: u64) -> bool {
    WORLDS
        .lock()
        .get(&world_id)
        .map(|world| world.paused)
        .unwrap_or(false)
}

/// Vecteur d'interruption en attente pour un vCPU, s'il existe.
pub fn pending_irq(vcpu_id: u64) -> Option<u8> {
    let mut worlds = WORLDS.lock();
    let world = vcpu_world_mut(&mut worlds, vcpu_id)?;
    world
        .vcpus
        .iter()
        .find(|slot| slot.id == vcpu_id)
        .and_then(|slot| slot.pending_irq)
}

/// Retrouve le monde propriétaire d'un vCPU (hors fermeture).
fn vcpu_world_mut(worlds: &mut BTreeMap<u64, World>, vcpu_id: u64) -> Option<&mut World> {
    worlds
        .values_mut()
        .find(|world| !world.closing && world.vcpus.iter().any(|slot| slot.id == vcpu_id))
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

