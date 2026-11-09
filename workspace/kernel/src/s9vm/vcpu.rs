//! s9vm — vCPU : état, configuration du bloc de contrôle, entrée/sortie.
//!
//! Un `Vcpu` est l'unité d'exécution invitée. Il possède :
//! - un bloc de contrôle matériel ([`ControlBlock`]) ;
//! - une pile hôte dédiée (utilisée par le trampoline pour revenir du guest) ;
//! - l'état invité ([`GuestState`]) et la zone d'échange [`EnterFrame`].
//!
//! La configuration est volontairement explicite (`configure_host`,
//! `configure_guest`, `configure_controls`) plutôt que répartie dans le
//! constructeur : chaque étape est vérifiable et les erreurs matérielles
//! (`VMfail`) sont attribuables à une étape.
//!
//! Aucune politique n'est décidée ici : le module ne sait pas ce qu'est un OS
//! invité, un périphérique ou une machine virtuelle complète.

use crate::memory::frame::{
    FrameAllocOptions, FramePurpose, PhysFrame,
};
use crate::s9vm::control::{field, ControlBlock, ControlError};
use crate::s9vm::exit::{ExitReason, ExitClass};
use crate::s9vm::guest::GuestState;
use crate::s9vm::launch::{
    s9vm_enter_guest, s9vm_guest_exit, EnterFrame, S9VM_ENTER_FRAME_SIZE,
};
use crate::s9vm::mmu::{self, Perms, SecondLevel, TableMemory};
use crate::s9vm::caps::HwCaps;

/// Bits de contrôle utiles à la configuration (SDM).
pub mod bits {
    /// Contrôle de sortie : l'hôte fonctionne en mode 64 bits (IA-32e).
    pub const EXIT_HOST_ADDR_SPACE_SIZE: u32 = 1 << 9;
    /// Contrôle de sortie : recharger IA32_EFER de l'hôte (requis en 64 bits).
    pub const EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
    /// Contrôle d'entrée : l'invité fonctionne en mode 64 bits (IA-32e).
    pub const ENTRY_IA32E_MODE: u32 = 1 << 9;
    /// Contrôle d'entrée : recharger IA32_EFER de l'invité (requis en 64 bits).
    pub const ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;
    /// Contrôle primaire : sortie sur `hlt`.
    pub const PRIMARY_HLT_EXITING: u32 = 1 << 7;
    /// Contrôle secondaire : activer l'EPT.
    pub const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
    /// Contrôle secondaire : invité non restreint.
    pub const SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
    /// Contrôle « pin » : timer de préemption (borne le temps invité).
    pub const PIN_PREEMPTION_TIMER: u32 = 1 << 6;
    /// Contrôle « pin » : sortie sur interruption externe.
    pub const PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
}

/// Erreurs du cycle de vie d'un vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuError {
    /// Allocation de frame impossible.
    OutOfMemory,
    /// Opération sur le bloc de contrôle.
    Control(ControlError),
    /// Échec d'entrée (`VMfail`) : code lu dans le champ d'instruction.
    VmFail(u32),
    /// L'invité est déjà lancé et la reprise n'est pas permise.
    AlreadyLaunched,
    /// L'EPT n'a pas pu être construite.
    Translation(mmu::MmuError),
    /// État de sortie illisible.
    BadExit,
}

impl From<ControlError> for VcpuError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}

impl From<mmu::MmuError> for VcpuError {
    fn from(value: mmu::MmuError) -> Self {
        Self::Translation(value)
    }
}

/// Informations d'une sortie invitée, copiées hors du bloc de contrôle.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExitInfo {
    /// Raison brute (bit 31 = échec d'entrée).
    pub raw_reason: u32,
    /// Raison décodée.
    pub reason: ExitReason,
    /// Qualification de sortie.
    pub qualification: u64,
    /// Adresse physique invitée au moment de la sortie.
    pub guest_physical_address: u64,
    /// Information d'interruption.
    pub interrupt_info: u32,
    /// Information de vectorisation (événement à réinjecter).
    pub vectoring_info: u32,
    /// Code d'erreur de vectorisation.
    pub vectoring_error: u32,
    /// Longueur de l'instruction fautive.
    pub instruction_length: u32,
    /// Information sur l'instruction.
    pub instruction_info: u32,
    /// Vrai si la sortie est un échec d'entrée.
    pub entry_failed: bool,
}

impl ExitInfo {
    /// Classe fonctionnelle de la sortie.
    pub fn class(&self) -> ExitClass {
        self.reason.class()
    }

    /// Vrai s'il existe un événement à réinjecter.
    pub fn has_vectoring_event(&self) -> bool {
        self.vectoring_info & (1 << 31) != 0
    }
}

/// Pile hôte dédiée au trampoline.
struct HostStack {
    frame: PhysFrame,
    top: u64,
}

impl HostStack {
    fn allocate() -> Result<Self, VcpuError> {
        // 16 Kio, ordre 2.
        let frame = crate::sync::with_irqs_disabled(|token| {
            crate::memory::buddy::alloc(token, 2)
        })
        .map_err(|_| VcpuError::OutOfMemory)?;
        let base = crate::memory::phys_to_virt(frame.start_address.as_u64());
        let top = (base + 16 * 1024) & !0xF;
        Ok(Self { frame, top })
    }

    fn top(&self) -> u64 {
        self.top
    }

    fn phys(&self) -> u64 {
        self.frame.start_address.as_u64()
    }
}

/// Fournisseur de tables qui accède à la mémoire physique via le HHDM et
/// garde la trace des tables allouées pour pouvoir les libérer.
pub struct HhdmTables {
    allocated: alloc::vec::Vec<u64>,
}

impl HhdmTables {
    /// Crée un fournisseur vide.
    pub fn new() -> Self {
        Self {
            allocated: alloc::vec::Vec::new(),
        }
    }

    /// Libère toutes les tables allouées (les entrées ne sont plus lues après
    /// cet appel).
    pub fn free_all(&mut self) {
        if self.allocated.is_empty() {
            return;
        }
        crate::sync::with_irqs_disabled(|token| {
            for table in self.allocated.drain(..) {
                let frame = crate::memory::frame::PhysFrame::containing_address(
                    crate::arch::xshim::PhysAddr::new(table),
                );
                crate::memory::free_frame(token, frame);
            }
        });
    }
}

impl Default for HhdmTables {
    fn default() -> Self {
        Self::new()
    }
}

impl TableMemory for HhdmTables {
    fn alloc_table(&mut self) -> Option<u64> {
        let result = crate::sync::with_irqs_disabled(|token| {
            FrameAllocOptions::new()
                .purpose(FramePurpose::PageTable)
                .allocate(token)
                .ok()
                .map(|frame| frame.start_address.as_u64())
        });
        if let Some(table) = result {
            self.allocated.push(table);
        }
        result
    }

    fn free_table(&mut self, table: u64) {
        // La libération est centralisée dans `free_all` : l'ordre de
        // libération des tables n'a pas d'importance pour l'allocateur, mais
        // éviter les doubles libérations est plus simple ainsi. On retire
        // l'entrée de la liste pour ne pas la libérer deux fois.
        if let Some(index) = self.allocated.iter().position(|entry| *entry == table) {
            self.allocated.swap_remove(index);
        }
    }

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        let base = crate::memory::phys_to_virt(table) as *const u64;
        // SAFETY: `table` provient de `alloc_table` (frame zéro, 4 Kio) et
        // `index < 512` : lecture dans les limites de la frame.
        unsafe { core::ptr::read_volatile(base.add(index)) }
    }

    fn write_entry(&mut self, table: u64, index: usize, value: u64) {
        let base = crate::memory::phys_to_virt(table) as *mut u64;
        // SAFETY: même invariant que `read_entry` ; la frame est exclusive.
        unsafe { core::ptr::write_volatile(base.add(index), value) }
    }
}

/// Ressources pré-allouées pour la traduction de second niveau.
pub struct SecondLevelMemory {
    pub tables: HhdmTables,
    pub root: SecondLevel,
}

impl SecondLevelMemory {
    /// Crée une traduction vide.
    pub fn new() -> Result<Self, VcpuError> {
        let mut tables = HhdmTables::new();
        let root = SecondLevel::new(&mut tables)?;
        Ok(Self { tables, root })
    }

    /// Libère toutes les tables de traduction.
    pub fn destroy(mut self) {
        self.tables.free_all();
    }

    /// Traduit une adresse physique invitée, si elle est mappée.
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        self.root.translate(&self.tables, gpa)
    }

    /// Retire un mapping de 4 Kio.
    pub fn unmap_4k(&mut self, gpa: u64) -> bool {
        self.root.unmap_4k(&mut self.tables, gpa)
    }

    /// Mappe une page de 4 Kio.
    pub fn map_4k(
        &mut self,
        gpa: u64,
        hpa: u64,
        perms: Perms,
    ) -> Result<(), VcpuError> {
        self.root
            .map_4k(&mut self.tables, gpa, hpa, mmu::PAGE_SIZE, perms)
            .map_err(VcpuError::Translation)
    }

    /// Mappe une zone de 2 Mio.
    pub fn map_2m(
        &mut self,
        gpa: u64,
        hpa: u64,
        perms: Perms,
    ) -> Result<(), VcpuError> {
        self.root
            .map_2m(&mut self.tables, gpa, hpa, mmu::entry::LARGE_2MB, perms)
            .map_err(VcpuError::Translation)
    }

    /// Valeur du pointeur de traduction, prête pour le bloc de contrôle.
    pub fn pointer(&self, caps: &HwCaps) -> u64 {
        mmu::encode_second_level_pointer(
            self.root.root_phys(),
            6,
            true,
            caps.ept_ad,
        )
    }
}

/// Un vCPU : ressources, état invité et bloc de contrôle.
pub struct Vcpu {
    control: ControlBlock,
    host_stack: HostStack,
    frame: EnterFrame,
    guest: GuestState,
    launched: bool,
    second_level_pointer: u64,
    exit: Option<ExitInfo>,
    /// Rechargement du timer de préemption (comptes) si le CPU le supporte.
    preemption_timer: Option<u32>,
}

impl Vcpu {
    /// Crée les ressources d'un vCPU (bloc de contrôle et pile hôte).
    pub fn new(caps: &HwCaps, second_level_pointer: u64) -> Result<Self, VcpuError> {
        let revision = caps.control_block_revision;
        let frame = crate::sync::with_irqs_disabled(|token| {
            FrameAllocOptions::new()
                .purpose(FramePurpose::PageTable)
                .allocate(token)
        })
        .map_err(|_| VcpuError::OutOfMemory)?;
        let phys = frame.start_address.as_u64();
        // La frame de bloc de contrôle doit exister avant la création du
        // descripteur ; on la « fuit » volontairement (propriété du vCPU).
        let control = unsafe { ControlBlock::new(phys, revision) };
        // SAFETY: la frame est exclusive, couverte par le HHDM et fait 4 Kio.
        unsafe {
            control.prepare_region(crate::memory::phys_to_virt(phys) as *mut u8);
        }
        let host_stack = HostStack::allocate()?;
        Ok(Self {
            control,
            host_stack,
            frame: EnterFrame::zeroed(),
            guest: GuestState::real_mode(0, 0),
            launched: false,
            second_level_pointer,
            exit: None,
            preemption_timer: None,
        })
    }

    /// Adresse physique du bloc de contrôle.
    pub fn control_phys(&self) -> u64 {
        self.control.phys()
    }

    /// Adresse physique de la pile hôte.
    pub fn host_stack_phys(&self) -> u64 {
        self.host_stack.phys()
    }

    /// Charge le bloc de contrôle sur le CPU courant.
    ///
    /// # Safety
    /// Le CPU doit être en mode racine VT-x et le bloc ne doit pas être
    /// chargé sur un autre CPU.
    pub unsafe fn load(&mut self) -> Result<(), VcpuError> {
        // SAFETY: contrat de l'appelant.
        unsafe { self.control.load()? };
        Ok(())
    }

    /// Photographie des champs invités du bloc de contrôle, pour diagnostiquer
    /// un échec d'entrée (« VM entry with invalid guest state »).
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé sur le CPU courant.
    pub unsafe fn guest_diagnostics(&self) -> alloc::string::String {
        use alloc::format;
        let natural = |f: u32| unsafe { self.control.read_natural(f).unwrap_or(u64::MAX) };
        let u16_field = |f: u32| unsafe { self.control.read_u16(f).unwrap_or(u16::MAX) };
        let u32_field = |f: u32| unsafe { self.control.read_u32(f).unwrap_or(u32::MAX) };
        unsafe {
            format!(
                "guest cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} pat={:#x} rsp={:#x} rip={:#x} \
                 rflags={:#x} dr7={:#x} act={:#x} intr={:#x} \
                 sel(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 ar(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 lim(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} ldtr={:#x} tr={:#x}) \
                 gdtr={:#x}/{:#x} idtr={:#x}/{:#x} link={:#x} dbgctl={:#x} smstate={:#x} \
                 exit(reason={:#x} qual={:#x} instrerr={:#x} len={:#x} info={:#x})",
                natural(field::GUEST_CR0),
                natural(field::GUEST_CR3),
                natural(field::GUEST_CR4),
                natural(field::GUEST_EFER),
                natural(field::GUEST_PAT),
                natural(field::GUEST_RSP),
                natural(field::GUEST_RIP),
                natural(field::GUEST_RFLAGS),
                natural(field::GUEST_DR7),
                u32_field(field::GUEST_ACTIVITY_STATE),
                u32_field(field::GUEST_INTERRUPTIBILITY_INFO),
                u16_field(field::GUEST_CS_SELECTOR),
                u16_field(field::GUEST_SS_SELECTOR),
                u16_field(field::GUEST_DS_SELECTOR),
                u16_field(field::GUEST_ES_SELECTOR),
                u16_field(field::GUEST_FS_SELECTOR),
                u16_field(field::GUEST_GS_SELECTOR),
                u16_field(field::GUEST_LDTR_SELECTOR),
                u16_field(field::GUEST_TR_SELECTOR),
                u32_field(field::GUEST_CS_ACCESS_RIGHTS),
                u32_field(field::GUEST_SS_ACCESS_RIGHTS),
                u32_field(field::GUEST_DS_ACCESS_RIGHTS),
                u32_field(field::GUEST_ES_ACCESS_RIGHTS),
                u32_field(field::GUEST_FS_ACCESS_RIGHTS),
                u32_field(field::GUEST_GS_ACCESS_RIGHTS),
                u32_field(field::GUEST_LDTR_ACCESS_RIGHTS),
                u32_field(field::GUEST_TR_ACCESS_RIGHTS),
                u32_field(field::GUEST_CS_LIMIT),
                u32_field(field::GUEST_SS_LIMIT),
                u32_field(field::GUEST_DS_LIMIT),
                u32_field(field::GUEST_ES_LIMIT),
                u32_field(field::GUEST_FS_LIMIT),
                u32_field(field::GUEST_GS_LIMIT),
                u32_field(field::GUEST_LDTR_LIMIT),
                u32_field(field::GUEST_TR_LIMIT),
                natural(field::GUEST_GDTR_BASE),
                u32_field(field::GUEST_GDTR_LIMIT),
                natural(field::GUEST_IDTR_BASE),
                u32_field(field::GUEST_IDTR_LIMIT),
                natural(field::GUEST_VMCS_LINK_POINTER),
                natural(field::GUEST_DEBUGCTL),
                u32_field(field::GUEST_SMSTATE),
                u32_field(field::EXIT_REASON),
                natural(field::EXIT_QUALIFICATION),
                u32_field(field::INSTRUCTION_ERROR),
                u32_field(field::EXIT_INSTRUCTION_LENGTH),
                u32_field(field::EXIT_INSTRUCTION_INFO),
            )
        }
    }
    /// Programme l'injection d'un NMI au prochain passage dans l'invité.
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé et l'invité inactif.
    pub unsafe fn inject_nmi(&self) -> Result<(), VcpuError> {
        unsafe {
            self.control
                .write_u32(field::ENTRY_INTERRUPT_INFO, crate::s9vm::exit::nmi_info())?;
        }
        Ok(())
    }

    /// Programme l'injection d'une interruption externe au prochain passage
    /// dans l'invité (champ « VM-entry interruption information »).
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé et l'invité inactif.
    pub unsafe fn inject_interrupt(&self, vector: u8) -> Result<(), VcpuError> {
        unsafe {
            self.control.write_u32(
                field::ENTRY_INTERRUPT_INFO,
                crate::s9vm::exit::external_interrupt_info(vector),
            )?;
        }
        Ok(())
    }
    /// Avance le pointeur d'instruction invité après l'émulation d'une
    /// instruction qui a provoqué une sortie (E/S, `rdtsc`, etc.).
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé et l'invité ne doit pas être actif.
    pub unsafe fn advance_rip(&mut self, bytes: u64) -> Result<(), VcpuError> {
        self.guest.rip = self.guest.rip.wrapping_add(bytes);
        unsafe {
            self.control
                .write_natural(field::GUEST_RIP, self.guest.rip)?;
        }
        Ok(())
    }
    /// Décharge le bloc de contrôle.
    ///
    /// # Safety
    /// Aucun invité ne doit être actif sur ce vCPU.
    pub unsafe fn clear(&mut self) -> Result<(), VcpuError> {
        // SAFETY: contrat de l'appelant.
        unsafe { self.control.clear()? };
        self.launched = false;
        Ok(())
    }

    /// Écrit l'état hôte (CPU courant) dans le bloc de contrôle.
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé.
    pub unsafe fn configure_host(&self) -> Result<(), VcpuError> {
        let cr0 = read_cr0();
        let cr3 = read_cr3();
        let cr4 = read_cr4();
        let efer = crate::arch::x86_64::rdmsr(0xC000_0080);
        let pat = crate::arch::x86_64::rdmsr(0x277);

        // SAFETY: bloc chargé ; les écritures respectent les largeurs.
        unsafe {
            self.control.write_natural(field::HOST_CR0, cr0)?;
            self.control.write_natural(field::HOST_CR3, cr3)?;
            self.control.write_natural(field::HOST_CR4, cr4)?;
            self.control.write_u64(field::HOST_EFER, efer)?;
            self.control.write_u64(field::HOST_PAT, pat)?;
            self.control
                .write_natural(field::HOST_RSP, self.host_stack.top())?;
            self.control.write_natural(
                field::HOST_RIP,
                s9vm_guest_exit as unsafe extern "C" fn() as usize as u64,
            )?;

            // Segments hôte : lus depuis les registres du CPU courant.
            let mut cs: u16;
            let mut ss: u16;
            let mut ds: u16;
            let mut es: u16;
            let mut fs: u16;
            let mut gs: u16;
            let mut tr: u16;
            core::arch::asm!("mov ax, cs", out("ax") cs, options(nomem, nostack));
            core::arch::asm!("mov ax, ss", out("ax") ss, options(nomem, nostack));
            core::arch::asm!("mov ax, ds", out("ax") ds, options(nomem, nostack));
            core::arch::asm!("mov ax, es", out("ax") es, options(nomem, nostack));
            core::arch::asm!("mov ax, fs", out("ax") fs, options(nomem, nostack));
            core::arch::asm!("mov ax, gs", out("ax") gs, options(nomem, nostack));
            core::arch::asm!("str ax", out("ax") tr, options(nomem, nostack));

            self.control.write_u16(field::HOST_CS_SELECTOR, cs)?;
            self.control.write_u16(field::HOST_SS_SELECTOR, ss)?;
            self.control.write_u16(field::HOST_DS_SELECTOR, ds)?;
            self.control.write_u16(field::HOST_ES_SELECTOR, es)?;
            self.control.write_u16(field::HOST_FS_SELECTOR, fs)?;
            self.control.write_u16(field::HOST_GS_SELECTOR, gs)?;
            self.control.write_u16(field::HOST_TR_SELECTOR, tr)?;
            self.control.write_natural(field::HOST_TR_BASE, tr_base(tr))?;

            // Tables système hôte.
            let (gdtr_base, _gdtr_limit) = read_gdtr();
            let (idtr_base, _idtr_limit) = read_idtr();
            self.control
                .write_natural(field::HOST_GDTR_BASE, gdtr_base)?;
            self.control
                .write_natural(field::HOST_IDTR_BASE, idtr_base)?;

            // Bases FS/GS hôte (GS porte les données par-CPU).
            let fs_base = crate::arch::x86_64::rdmsr(0xC000_0100);
            let gs_base = crate::arch::x86_64::rdmsr(0xC000_0101);
            self.control
                .write_natural(field::HOST_FS_BASE, fs_base)?;
            self.control
                .write_natural(field::HOST_GS_BASE, gs_base)?;
            self.control
                .write_u32(field::HOST_SYSENTER_CS, cs as u32)?;
            self.control.write_natural(
                field::HOST_SYSENTER_ESP,
                crate::arch::x86_64::rdmsr(0x175),
            )?;
            self.control.write_natural(
                field::HOST_SYSENTER_EIP,
                crate::arch::x86_64::rdmsr(0x176),
            )?;
        }
        Ok(())
    }

    /// Photographie des champs hôte du bloc de contrôle, pour diagnostiquer un
    /// échec d'entrée `VmFail(8)` (« invalid host-state field »).
    ///
    /// Affiche aussi les valeurs réellement portées par le CPU au moment de
    /// l'appel, ce qui permet de repérer un champ oublié ou mal encodé.
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé sur le CPU courant.
    pub unsafe fn host_diagnostics(&self) -> alloc::string::String {
        use alloc::format;
        let natural = |f: u32| unsafe { self.control.read_natural(f).unwrap_or(u64::MAX) };
        let u16_field = |f: u32| unsafe { self.control.read_u16(f).unwrap_or(u16::MAX) };
        let u32_field = |f: u32| unsafe { self.control.read_u32(f).unwrap_or(u32::MAX) };

        // Sélecteurs réellement chargés dans le CPU.
        let mut tr: u16 = 0;
        let mut cs: u16 = 0;
        let mut ss: u16 = 0;
        let mut ds: u16 = 0;
        let mut es: u16 = 0;
        let mut fs: u16 = 0;
        let mut gs: u16 = 0;
        unsafe {
            core::arch::asm!("str ax", out("ax") tr, options(nomem, nostack));
            core::arch::asm!("mov ax, cs", out("ax") cs, options(nomem, nostack));
            core::arch::asm!("mov ax, ss", out("ax") ss, options(nomem, nostack));
            core::arch::asm!("mov ax, ds", out("ax") ds, options(nomem, nostack));
            core::arch::asm!("mov ax, es", out("ax") es, options(nomem, nostack));
            core::arch::asm!("mov ax, fs", out("ax") fs, options(nomem, nostack));
            core::arch::asm!("mov ax, gs", out("ax") gs, options(nomem, nostack));
        }
        let (gdtr_base, gdtr_limit) = read_gdtr();
        let (idtr_base, idtr_limit) = read_idtr();
        let efer = unsafe { crate::arch::x86_64::rdmsr(0xC000_0080) };
        let pat = unsafe { crate::arch::x86_64::rdmsr(0x277) };
        let host_sysenter_cs = u32_field(field::HOST_SYSENTER_CS);
        unsafe {
            format!(
                "host cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} pat={:#x} rsp={:#x} rip={:#x} \
                 sel(cs={:#x} ss={:#x} ds={:#x} es={:#x} fs={:#x} gs={:#x} tr={:#x}) \
                 trbase={:#x} gdtr={:#x} idtr={:#x} fsb={:#x} gsb={:#x} \
                 sysenter(cs={:#x} esp={:#x} eip={:#x}) exitctl={:#x} entryctl={:#x} \
                 cpu(cr0={:#x} cr4={:#x} efer={:#x} pat={:#x} tr={:#x} \
                 gdtr={:#x}/lim={:#x} idtr={:#x}/lim={:#x})",
                natural(field::HOST_CR0),
                natural(field::HOST_CR3),
                natural(field::HOST_CR4),
                natural(field::HOST_EFER),
                natural(field::HOST_PAT),
                natural(field::HOST_RSP),
                natural(field::HOST_RIP),
                u16_field(field::HOST_CS_SELECTOR),
                u16_field(field::HOST_SS_SELECTOR),
                u16_field(field::HOST_DS_SELECTOR),
                u16_field(field::HOST_ES_SELECTOR),
                u16_field(field::HOST_FS_SELECTOR),
                u16_field(field::HOST_GS_SELECTOR),
                u16_field(field::HOST_TR_SELECTOR),
                natural(field::HOST_TR_BASE),
                natural(field::HOST_GDTR_BASE),
                natural(field::HOST_IDTR_BASE),
                natural(field::HOST_FS_BASE),
                natural(field::HOST_GS_BASE),
                host_sysenter_cs,
                natural(field::HOST_SYSENTER_ESP),
                natural(field::HOST_SYSENTER_EIP),
                u32_field(field::EXIT_CONTROLS),
                u32_field(field::ENTRY_CONTROLS),
                read_cr0(),
                read_cr4(),
                efer,
                pat,
                tr,
                gdtr_base,
                gdtr_limit,
                idtr_base,
                idtr_limit
            )
        }
    }
    /// Écrit l'état invité et les contrôles d'exécution.
    ///
    /// # Safety
    /// Le bloc de contrôle doit être chargé.
    pub unsafe fn configure(
        &mut self,
        caps: &HwCaps,
        guest: &GuestState,
    ) -> Result<(), VcpuError> {
        self.guest = *guest;
        self.preemption_timer = if caps.preemption_timer {
            // ~1 M de « ticks » du timer : borne le temps invité sans créer
            // une tempête de sorties.
            Some(1_000_000)
        } else {
            None
        };
        // SAFETY: bloc chargé ; les largeurs correspondent aux champs.
        unsafe {
            self.write_guest_state(guest)?;
            self.write_controls(caps)?;
            self.control
                .write_u64(field::GUEST_VMCS_LINK_POINTER, u64::MAX)?;
            self.control.write_u32(field::EXCEPTION_BITMAP, 0)?;
            self.control.write_u32(field::PAGE_FAULT_ERROR_CODE_MASK, 0)?;
            self.control.write_u32(field::PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
            self.control.write_u32(field::CR3_TARGET_COUNT, 0)?;
            self.control.write_u32(field::TPR_THRESHOLD, 0)?;
            self.control.write_u32(field::PLE_GAP, 0)?;
            self.control.write_u32(field::PLE_WINDOW, 0)?;
            self.control.write_u64(field::TSC_OFFSET, 0)?;
            self.control.write_u64(field::MSR_BITMAP, 0)?;
            self.control.write_u64(field::IO_BITMAP_A, 0)?;
            self.control.write_u64(field::IO_BITMAP_B, 0)?;
            self.control
                .write_u64(field::EPT_POINTER, self.second_level_pointer)?;
            self.control.write_u32(field::ENTRY_INTERRUPT_INFO, 0)?;
            self.control
                .write_u32(field::ENTRY_EXCEPTION_ERROR_CODE, 0)?;
            self.control.write_u32(field::ENTRY_INSTRUCTION_LENGTH, 0)?;
        }
        Ok(())
    }

    unsafe fn write_guest_state(&mut self, guest: &GuestState) -> Result<(), VcpuError> {
        // SAFETY: appelant garantit le bloc chargé.
        unsafe {
            // Registres généraux.
            self.frame = EnterFrame {
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
                ..EnterFrame::zeroed()
            };
            let _ = S9VM_ENTER_FRAME_SIZE;

            // Registres de contrôle et d'état.
            self.control.write_natural(field::GUEST_CR0, guest.cr0)?;
            self.control.write_natural(field::GUEST_CR3, guest.cr3)?;
            self.control.write_natural(field::GUEST_CR4, guest.cr4)?;
            self.control.write_u64(field::GUEST_EFER, guest.efer)?;
            self.control.write_u64(field::GUEST_PAT, guest.pat)?;
            self.control.write_natural(field::GUEST_RSP, guest.rsp)?;
            self.control.write_natural(field::GUEST_RIP, guest.rip)?;
            self.control.write_natural(field::GUEST_RFLAGS, guest.rflags)?;
            self.control.write_natural(field::GUEST_DR7, guest.dr7)?;
            self.control.write_u64(
                field::GUEST_PENDING_DEBUG_EXCEPTIONS,
                guest.pending_debug_exceptions,
            )?;
            self.control.write_u32(
                field::GUEST_INTERRUPTIBILITY_INFO,
                guest.interruptibility,
            )?;
            self.control
                .write_u32(field::GUEST_ACTIVITY_STATE, guest.activity_state)?;

            // Segments.
            self.write_segment(
                field::GUEST_ES_SELECTOR,
                field::GUEST_ES_BASE,
                field::GUEST_ES_LIMIT,
                field::GUEST_ES_ACCESS_RIGHTS,
                guest.es,
            )?;
            self.write_segment(
                field::GUEST_CS_SELECTOR,
                field::GUEST_CS_BASE,
                field::GUEST_CS_LIMIT,
                field::GUEST_CS_ACCESS_RIGHTS,
                guest.cs,
            )?;
            self.write_segment(
                field::GUEST_SS_SELECTOR,
                field::GUEST_SS_BASE,
                field::GUEST_SS_LIMIT,
                field::GUEST_SS_ACCESS_RIGHTS,
                guest.ss,
            )?;
            self.write_segment(
                field::GUEST_DS_SELECTOR,
                field::GUEST_DS_BASE,
                field::GUEST_DS_LIMIT,
                field::GUEST_DS_ACCESS_RIGHTS,
                guest.ds,
            )?;
            self.write_segment(
                field::GUEST_FS_SELECTOR,
                field::GUEST_FS_BASE,
                field::GUEST_FS_LIMIT,
                field::GUEST_FS_ACCESS_RIGHTS,
                guest.fs,
            )?;
            self.write_segment(
                field::GUEST_GS_SELECTOR,
                field::GUEST_GS_BASE,
                field::GUEST_GS_LIMIT,
                field::GUEST_GS_ACCESS_RIGHTS,
                guest.gs,
            )?;
            self.write_segment(
                field::GUEST_LDTR_SELECTOR,
                field::GUEST_LDTR_BASE,
                field::GUEST_LDTR_LIMIT,
                field::GUEST_LDTR_ACCESS_RIGHTS,
                guest.ldtr,
            )?;
            self.write_segment(
                field::GUEST_TR_SELECTOR,
                field::GUEST_TR_BASE,
                field::GUEST_TR_LIMIT,
                field::GUEST_TR_ACCESS_RIGHTS,
                guest.tr,
            )?;

            // Tables système et MSR invités.
            self.control
                .write_natural(field::GUEST_GDTR_BASE, guest.gdtr_base)?;
            self.control
                .write_u32(field::GUEST_GDTR_LIMIT, guest.gdtr_limit)?;
            self.control
                .write_natural(field::GUEST_IDTR_BASE, guest.idtr_base)?;
            self.control
                .write_u32(field::GUEST_IDTR_LIMIT, guest.idtr_limit)?;
            self.control
                .write_u32(field::GUEST_SYSENTER_CS, guest.sysenter_cs)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_ESP, guest.sysenter_esp)?;
            self.control
                .write_natural(field::GUEST_SYSENTER_EIP, guest.sysenter_eip)?;
        }
        Ok(())
    }

    unsafe fn write_segment(
        &self,
        selector_field: u32,
        base_field: u32,
        limit_field: u32,
        access_rights_field: u32,
        segment: crate::s9vm::guest::Segment,
    ) -> Result<(), VcpuError> {
        // SAFETY: appelant garantit le bloc chargé.
        unsafe {
            self.control.write_u16(selector_field, segment.selector)?;
            self.control.write_natural(base_field, segment.base)?;
            self.control.write_u32(limit_field, segment.limit)?;
            self.control.write_u32(access_rights_field, segment.access_rights)?;
        }
        Ok(())
    }

    unsafe fn write_controls(&self, caps: &HwCaps) -> Result<(), VcpuError> {
        let mut pin_requested = bits::PIN_EXTERNAL_INTERRUPT_EXITING;
        if caps.preemption_timer {
            pin_requested |= bits::PIN_PREEMPTION_TIMER;
        }
        let pin = caps.pin_allowed.apply(pin_requested);
        let primary = caps.primary_proc_allowed.apply(
            crate::s9vm::caps::control_bits::PROC_ACTIVATE_SECONDARY
                | bits::PRIMARY_HLT_EXITING,
        );
        let secondary = caps
            .secondary_proc_allowed
            .apply(bits::SECONDARY_ENABLE_EPT | bits::SECONDARY_UNRESTRICTED_GUEST);
        let exit = caps
            .exit_allowed
            .apply(bits::EXIT_HOST_ADDR_SPACE_SIZE | bits::EXIT_LOAD_IA32_EFER);
        let entry = caps
            .entry_allowed
            .apply(bits::ENTRY_IA32E_MODE | bits::ENTRY_LOAD_IA32_EFER);
        // SAFETY: bloc chargé ; largeurs 16 bits pour les contrôles.
        unsafe {
            self.control.write_u32(field::PIN_BASED_CONTROLS, pin)?;
            self.control
                .write_u32(field::PRIMARY_PROC_BASED_CONTROLS, primary)?;
            self.control
                .write_u32(field::SECONDARY_PROC_BASED_CONTROLS, secondary)?;
            self.control.write_u32(field::EXIT_CONTROLS, exit)?;
            self.control.write_u32(field::ENTRY_CONTROLS, entry)?;
        }
        Ok(())
    }

    /// Lance ou reprend l'invité. Bloquant jusqu'à la prochaine sortie.
    ///
    /// # Safety
    /// - VT-x doit être actif sur le CPU courant (le bloc est chargé) ;
    /// - les interruptions locales doivent être désactivées ;
    /// - `configure_host` et `configure` doivent avoir été appelés.
    pub unsafe fn run(&mut self) -> Result<ExitInfo, VcpuError> {
        self.frame.launched = u64::from(self.launched);
        if let Some(ticks) = self.preemption_timer {
            // Réarmé à chaque entrée : chaque tranche de temps invitée est
            // bornée, y compris après une reprise interne.
            unsafe {
                let _ = self
                    .control
                    .write_u32(field::VMX_PREEMPTION_TIMER, ticks);
            }
        }
        // SAFETY: contrat de l'appelant ; le trampoline restaure l'état hôte.
        let failed = unsafe {
            s9vm_enter_guest(
                &mut self.frame as *mut EnterFrame,
                self.host_stack.top(),
            )
        };
        if failed != 0 {
            // Le code d'erreur est dans le champ d'instruction du bloc.
            // SAFETY: bloc chargé.
            let code = unsafe {
                self.control
                    .read_u32(field::INSTRUCTION_ERROR)
                    .unwrap_or(u32::MAX)
            };
            return Err(VcpuError::VmFail(code));
        }
        self.launched = true;
        // SAFETY: bloc chargé ; lecture des champs de sortie.
        let exit = unsafe { self.read_exit()? };
        // Récupère l'état invité post-sortie conservé dans le bloc.
        // SAFETY: bloc chargé.
        unsafe {
            if let Ok(rip) = self.control.read_natural(field::GUEST_RIP) {
                self.guest.rip = rip;
            }
            if let Ok(rsp) = self.control.read_natural(field::GUEST_RSP) {
                self.guest.rsp = rsp;
            }
            if let Ok(rflags) = self.control.read_natural(field::GUEST_RFLAGS) {
                self.guest.rflags = rflags;
            }
            if let Ok(cr0) = self.control.read_natural(field::GUEST_CR0) {
                self.guest.cr0 = cr0;
            }
            if let Ok(cr3) = self.control.read_natural(field::GUEST_CR3) {
                self.guest.cr3 = cr3;
            }
            if let Ok(cr4) = self.control.read_natural(field::GUEST_CR4) {
                self.guest.cr4 = cr4;
            }
            if let Ok(efer) = self.control.read_u64(field::GUEST_EFER) {
                self.guest.efer = efer;
            }
        }
        self.update_guest_from_exit(&exit);
        self.exit = Some(exit);
        Ok(exit)
    }

    unsafe fn read_exit(&self) -> Result<ExitInfo, VcpuError> {
        // SAFETY: bloc chargé ; champs 32 bits.
        unsafe {
            let raw_reason = self.control.read_u32(field::EXIT_REASON)?;
            let reason = ExitReason::decode(raw_reason);
            let mut info = ExitInfo {
                raw_reason,
                reason,
                ..ExitInfo::default()
            };
            info.qualification = self
                .control
                .read_u64(field::EXIT_QUALIFICATION)
                .unwrap_or(0);
            info.guest_physical_address = self
                .control
                .read_u64(field::GUEST_PHYSICAL_ADDRESS)
                .unwrap_or(0);
            info.interrupt_info = self.control.read_u32(field::EXIT_INTERRUPT_INFO)?;
            info.vectoring_info = self.control.read_u32(field::IDT_VECTORING_INFO)?;
            info.vectoring_error = self
                .control
                .read_u32(field::IDT_VECTORING_ERROR_CODE)
                .unwrap_or(0);
            info.instruction_length = self
                .control
                .read_u32(field::EXIT_INSTRUCTION_LENGTH)
                .unwrap_or(0);
            info.instruction_info = self
                .control
                .read_u32(field::EXIT_INSTRUCTION_INFO)
                .unwrap_or(0);
            info.entry_failed = reason.entry_failed;
            Ok(info)
        }
    }

    fn update_guest_from_exit(&mut self, exit: &ExitInfo) {
        self.guest.rax = self.frame.rax;
        self.guest.rbx = self.frame.rbx;
        self.guest.rcx = self.frame.rcx;
        self.guest.rdx = self.frame.rdx;
        self.guest.rsi = self.frame.rsi;
        self.guest.rdi = self.frame.rdi;
        self.guest.rbp = self.frame.rbp;
        self.guest.r8 = self.frame.r8;
        self.guest.r9 = self.frame.r9;
        self.guest.r10 = self.frame.r10;
        self.guest.r11 = self.frame.r11;
        self.guest.r12 = self.frame.r12;
        self.guest.r13 = self.frame.r13;
        self.guest.r14 = self.frame.r14;
        self.guest.r15 = self.frame.r15;
        let _ = exit;
    }

    /// Dernière sortie observée.
    pub fn last_exit(&self) -> Option<ExitInfo> {
        self.exit
    }

    /// État invité courant (registres mis à jour après la dernière sortie).
    pub fn guest(&self) -> &GuestState {
        &self.guest
    }
}

// ---------------------------------------------------------------------------
// Accès CPU (lecture seule) utilisés pour construire l'état hôte.
// ---------------------------------------------------------------------------

fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: lecture d'un registre de contrôle.
    unsafe { core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: lecture d'un registre de contrôle.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: lecture d'un registre de contrôle.
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

/// Lit la base de la table des descripteurs globaux (`sgdt`).
fn read_gdtr() -> (u64, u16) {
    let mut descriptor = [0u8; 10];
    // SAFETY: `sgdt` écrit 10 octets dans un buffer local.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) descriptor.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let base = u64::from_le_bytes([
        descriptor[2],
        descriptor[3],
        descriptor[4],
        descriptor[5],
        descriptor[6],
        descriptor[7],
        descriptor[8],
        descriptor[9],
    ]);
    (base, limit)
}

/// Lit la base de la table des descripteurs d'interruption (`sidt`).
fn read_idtr() -> (u64, u16) {
    let mut descriptor = [0u8; 10];
    // SAFETY: `sidt` écrit 10 octets dans un buffer local.
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) descriptor.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let base = u64::from_le_bytes([
        descriptor[2],
        descriptor[3],
        descriptor[4],
        descriptor[5],
        descriptor[6],
        descriptor[7],
        descriptor[8],
        descriptor[9],
    ]);
    (base, limit)
}

/// Base d'un descripteur de TSS à partir de son sélecteur (GDT).
fn tr_base(selector: u16) -> u64 {
    if selector == 0 {
        return 0;
    }
    let index = (selector >> 3) as usize;
    let (gdt_base, _) = read_gdtr();
    let entry = (gdt_base as *const u8).wrapping_add(index * 8);
    // SAFETY: le sélecteur TR désigne une entrée valide de la GDT courante.
    unsafe {
        let low = core::ptr::read_volatile(entry as *const u64);
        let upper = core::ptr::read_volatile(entry.add(8) as *const u32);
        // TSS 64 bits : base éclatée en quatre morceaux (voir SDM).
        ControlBlock::decode_tss_base(low, upper)
    }
}





