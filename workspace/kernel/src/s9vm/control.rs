//! s9vm — bloc de contrôle du processeur (structure d'état invitée/hôte).
//!
//! Ce module fournit :
//! - l'encodage des champs (16, 32, 64 bits et « naturel ») selon la SDM ;
//! - les primitives assembleur `vmptrld`, `vmclear`, `vmptrst`, `vmread`,
//!   `vmwrite` (noms d'instructions Intel, sans lien avec un hyperviseur
//!   commercial) ;
//! - la fabrication de la valeur d'activation (`EPTP`) et le calcul des
//!   contrôles à partir des masques « allowed ».
//!
//! Le module ne dépend que de `core` : il est testable sur l'hôte (tests L2).
//! Les appels assembleur doivent être faits avec les interruptions locales
//! désactivées et un bloc de contrôle chargé sur le CPU courant.

use core::arch::asm;

/// Poids des champs selon les bits 14:13 de l'encodage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldWidth {
    Bits16,
    Bits64,
    Bits32,
    Natural,
}

impl FieldWidth {
    /// Décode la largeur d'un champ depuis son encodage.
    pub const fn of(field: u32) -> Self {
        match (field >> 13) & 0b11 {
            0 => Self::Bits16,
            1 => Self::Bits64,
            2 => Self::Bits32,
            _ => Self::Natural,
        }
    }
}

/// Encodages de champs utiles au socle s9vm. La largeur est déduite par
/// [`FieldWidth::of`] ; ces constantes sont vérifiées par les tests L2.
pub mod field {
    // --- Champs de contrôle 16 bits ---
    pub const VIRTUAL_PROCESSOR_ID: u32 = 0x0000;
    pub const POSTED_INTERRUPT_NOTIFICATION: u32 = 0x0002;
    pub const EPT_INDEX: u32 = 0x0004;

    // --- Sélecteurs invités 16 bits ---
    pub const GUEST_ES_SELECTOR: u32 = 0x0800;
    pub const GUEST_CS_SELECTOR: u32 = 0x0802;
    pub const GUEST_SS_SELECTOR: u32 = 0x0804;
    pub const GUEST_DS_SELECTOR: u32 = 0x0806;
    pub const GUEST_FS_SELECTOR: u32 = 0x0808;
    pub const GUEST_GS_SELECTOR: u32 = 0x080A;
    pub const GUEST_LDTR_SELECTOR: u32 = 0x080C;
    pub const GUEST_TR_SELECTOR: u32 = 0x080E;

    // --- Limites invitées 32 bits ---
    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;

    // --- Droits d'accès invités 32 bits ---
    pub const GUEST_ES_ACCESS_RIGHTS: u32 = 0x4814;
    pub const GUEST_CS_ACCESS_RIGHTS: u32 = 0x4816;
    pub const GUEST_SS_ACCESS_RIGHTS: u32 = 0x4818;
    pub const GUEST_DS_ACCESS_RIGHTS: u32 = 0x481A;
    pub const GUEST_FS_ACCESS_RIGHTS: u32 = 0x481C;
    pub const GUEST_GS_ACCESS_RIGHTS: u32 = 0x481E;
    pub const GUEST_LDTR_ACCESS_RIGHTS: u32 = 0x4820;
    pub const GUEST_TR_ACCESS_RIGHTS: u32 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u32 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x4826;
    pub const GUEST_SMSTATE: u32 = 0x4828;
    pub const GUEST_SYSENTER_CS: u32 = 0x482A;

    // --- Sélecteurs hôte 16 bits ---
    pub const HOST_ES_SELECTOR: u32 = 0x0C00;
    pub const HOST_CS_SELECTOR: u32 = 0x0C02;
    pub const HOST_SS_SELECTOR: u32 = 0x0C04;
    pub const HOST_DS_SELECTOR: u32 = 0x0C06;
    pub const HOST_FS_SELECTOR: u32 = 0x0C08;
    pub const HOST_GS_SELECTOR: u32 = 0x0C0A;
    pub const HOST_TR_SELECTOR: u32 = 0x0C0C;

    // --- Adresses de structures (64 bits) ---
    pub const IO_BITMAP_A: u32 = 0x2000;
    pub const IO_BITMAP_B: u32 = 0x2002;
    pub const MSR_BITMAP: u32 = 0x2004;
    pub const EXIT_MSR_STORE_ADDRESS: u32 = 0x2006;
    pub const EXIT_MSR_LOAD_ADDRESS: u32 = 0x2008;
    pub const ENTRY_MSR_LOAD_ADDRESS: u32 = 0x200A;
    pub const PML_ADDRESS: u32 = 0x200E;
    pub const TSC_OFFSET: u32 = 0x2010;
    pub const VIRTUAL_APIC_ADDRESS: u32 = 0x2012;
    pub const APIC_ACCESS_ADDRESS: u32 = 0x2014;
    pub const POSTED_INTERRUPT_DESCRIPTOR: u32 = 0x2016;
    pub const EPT_POINTER: u32 = 0x201A;
    pub const EPT_POINTER_LIST: u32 = 0x2024;
    pub const CONTROL_READ_BITMAP: u32 = 0x2026;
    pub const CONTROL_WRITE_BITMAP: u32 = 0x2028;
    pub const VIRTUAL_EXCEPTION_INFO: u32 = 0x202A;

    // --- Champs de contrôle 32 bits ---
    pub const PIN_BASED_CONTROLS: u32 = 0x4000;
    /// Valeur du timer de préemption VMX (32 bits).
    pub const VMX_PREEMPTION_TIMER: u32 = 0x482E;
    pub const PRIMARY_PROC_BASED_CONTROLS: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x4006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    pub const EXIT_CONTROLS: u32 = 0x400C;
    pub const EXIT_MSR_STORE_COUNT: u32 = 0x400E;
    pub const EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    pub const ENTRY_CONTROLS: u32 = 0x4012;
    pub const ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    pub const ENTRY_INTERRUPT_INFO: u32 = 0x4016;
    pub const ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x4018;
    pub const ENTRY_INSTRUCTION_LENGTH: u32 = 0x401A;
    pub const TPR_THRESHOLD: u32 = 0x401C;
    pub const SECONDARY_PROC_BASED_CONTROLS: u32 = 0x401E;
    pub const PLE_GAP: u32 = 0x4020;
    pub const PLE_WINDOW: u32 = 0x4022;

    // --- Informations de sortie (32 bits, lecture seule) ---
    pub const INSTRUCTION_ERROR: u32 = 0x4400;
    pub const EXIT_REASON: u32 = 0x4402;
    pub const EXIT_INTERRUPT_INFO: u32 = 0x4404;
    pub const EXIT_INTERRUPT_ERROR_CODE: u32 = 0x4406;
    pub const IDT_VECTORING_INFO: u32 = 0x4408;
    pub const IDT_VECTORING_ERROR_CODE: u32 = 0x440A;
    pub const EXIT_INSTRUCTION_LENGTH: u32 = 0x440C;
    pub const EXIT_INSTRUCTION_INFO: u32 = 0x440E;

    // --- État invité 64 bits ---
    pub const GUEST_VMCS_LINK_POINTER: u32 = 0x2800;
    pub const GUEST_DEBUGCTL: u32 = 0x2802;
    pub const GUEST_PAT: u32 = 0x2804;
    pub const GUEST_EFER: u32 = 0x2806;
    pub const GUEST_PERF_GLOBAL_CTRL: u32 = 0x2808;
    pub const GUEST_PDPTE0: u32 = 0x280A;
    pub const GUEST_PDPTE1: u32 = 0x280C;
    pub const GUEST_PDPTE2: u32 = 0x280E;
    pub const GUEST_PDPTE3: u32 = 0x2810;
    pub const GUEST_IA32_XSS: u32 = 0x2816;

    // --- État hôte 64 bits ---
    pub const HOST_PAT: u32 = 0x2C00;
    pub const HOST_EFER: u32 = 0x2C02;
    pub const HOST_PERF_GLOBAL_CTRL: u32 = 0x2C04;

    // --- État invité « naturel » (pleine largeur) ---
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_DR7: u32 = 0x681A;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;
    pub const GUEST_PENDING_DEBUG_EXCEPTIONS: u32 = 0x6822;
    pub const GUEST_SYSENTER_ESP: u32 = 0x6824;
    pub const GUEST_SYSENTER_EIP: u32 = 0x6826;

    // --- État hôte « naturel » ---
    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_FS_BASE: u32 = 0x6C06;
    pub const HOST_GS_BASE: u32 = 0x6C08;
    pub const HOST_TR_BASE: u32 = 0x6C0A;
    pub const HOST_GDTR_BASE: u32 = 0x6C0C;
    pub const HOST_IDTR_BASE: u32 = 0x6C0E;
    /// Sélecteur de code hôte pour `sysenter` (champ 32 bits, `0x4C00`).
    pub const HOST_SYSENTER_CS: u32 = 0x4C00;
    pub const HOST_SYSENTER_ESP: u32 = 0x6C10;
    pub const HOST_SYSENTER_EIP: u32 = 0x6C12;
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;

    // --- Divers ---
    pub const GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;
    pub const EXIT_QUALIFICATION: u32 = 0x6400;
}

/// Erreurs des primitives du bloc de contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// L'instruction a signalé un échec (CF = 1).
    Failed,
    /// Le bloc n'est pas chargé sur ce CPU.
    NotLoaded,
    /// La région est mal alignée ou trop petite.
    BadRegion,
    /// Le CPU n'est pas en mode racine VT-x (activation absente).
    NotEnabled,
}

/// Portée d'un bloc de contrôle : une région physique alignée sur 4 Kio.
#[derive(Debug)]
pub struct ControlBlock {
    /// Adresse physique de la région (4 Kio alignée).
    phys: u64,
    /// Identifiant de révision attendu dans les 4 premiers octets.
    revision: u32,
    /// Chargé sur le CPU courant (via `vmptrld`).
    loaded: bool,
}

impl ControlBlock {
    /// Crée un descripteur de bloc de contrôle.
    ///
    /// # Safety
    /// `phys` doit désigner une région de 4 Kio alignée, exclusivement
    /// réservée à ce bloc de contrôle, située dans de la RAM accessible par
    /// le CPU. Aucun accès n'est fait ici.
    pub const unsafe fn new(phys: u64, revision: u32) -> Self {
        Self {
            phys,
            revision,
            loaded: false,
        }
    }

    /// Adresse physique de la région.
    pub const fn phys(&self) -> u64 {
        self.phys
    }

    /// Révision encodée dans la région.
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// Vrai si le bloc est chargé sur le CPU courant.
    pub const fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Initialise les 4 premiers octets de la région avec l'identifiant de
    /// révision. `region_virt` est l'adresse virtuelle (HHDM) de la région.
    ///
    /// # Safety
    /// `region_virt` doit être une adresse valide, alignée, couvrant au moins
    /// 4 octets, et non utilisée par un autre objet.
    pub unsafe fn prepare_region(&self, region_virt: *mut u8) {
        // SAFETY: contract du paramètre ; écriture de 4 octets.
        unsafe {
            core::ptr::write_volatile(region_virt as *mut u32, self.revision);
        }
    }

    /// Décode la base d'un descripteur de TSS 64 bits (16 octets).
    ///
    /// En mode long, la base d'un TSS est éclatée en quatre morceaux :
    /// `base[15:0]` dans les octets 2-3, `base[23:16]` dans l'octet 4,
    /// `base[31:24]` dans l'octet 7 et `base[63:32]` dans les octets 8-11.
    ///
    /// Cette fonction est pure pour être testable sur l'hôte : un décalage
    /// erroné produit une adresse non canonique, que le processeur refuse au
    /// moment de l'entrée invitée (`VMfail(8)`, host-state invalide).
    pub const fn decode_tss_base(descriptor_low: u64, descriptor_upper: u32) -> u64 {
        let base_low = (descriptor_low >> 16) & 0xFFFF;
        let base_mid = (descriptor_low >> 32) & 0xFF;
        let base_high = (descriptor_low >> 56) & 0xFF;
        let base_upper = descriptor_upper as u64;
        base_low | (base_mid << 16) | (base_high << 24) | (base_upper << 32)
    }

    /// Charge le bloc de contrôle sur le CPU courant (`vmptrld`).
    ///
    /// # Safety
    /// - le CPU doit être en mode racine VT-x (activation préalable) ;
    /// - `self.phys` doit être une région initialisée et exclusivement
    ///   réservée ;
    /// - le bloc ne doit pas être chargé sur un autre CPU.
    pub unsafe fn load(&mut self) -> Result<(), ControlError> {
        let phys = self.phys;
        let fail: u8;
        // SAFETY: l'opérande mémoire est une adresse physique 4 Kio alignée
        // fournie par l'appelant. `vmptrld` lit 8 octets.
        unsafe {
            asm!(
                "vmptrld qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &phys,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        self.loaded = true;
        Ok(())
    }

    /// Décharge le bloc de contrôle (`vmclear`).
    ///
    /// # Safety
    /// Le bloc doit être celui chargé sur le CPU courant, ou ne pas être
    /// chargé du tout ; l'appelant garantit qu'aucun invité n'est actif.
    pub unsafe fn clear(&mut self) -> Result<(), ControlError> {
        let phys = self.phys;
        let fail: u8;
        // SAFETY: même contrat que `load`.
        unsafe {
            asm!(
                "vmclear qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &phys,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        self.loaded = false;
        Ok(())
    }

    /// Récupère l'adresse physique du bloc actuellement chargé (`vmptrst`).
    ///
    /// # Safety
    /// Le CPU doit être en mode racine VT-x.
    pub unsafe fn current_phys(&self) -> Result<u64, ControlError> {
        let mut phys: u64 = 0;
        let fail: u8;
        // SAFETY: `vmptrst` écrit 8 octets dans `phys`, variable locale.
        unsafe {
            asm!(
                "vmptrst qword ptr [{addr}]",
                "setc {fail}",
                addr = in(reg) &mut phys,
                fail = out(reg_byte) fail,
                options(nostack)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(phys)
    }

    /// Lit un champ 16 bits.
    ///
    /// # Safety
    /// - le bloc doit être chargé sur le CPU courant ;
    /// - `field` doit être un encodage 16 bits valide.
    pub unsafe fn read_u16(&self, field: u32) -> Result<u16, ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.read_raw(field).map(|v| v as u16) }
    }

    /// Lit un champ 32 bits.
    ///
    /// # Safety
    /// Voir [`Self::read_u16`] ; `field` doit être un encodage 32 bits.
    pub unsafe fn read_u32(&self, field: u32) -> Result<u32, ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.read_raw(field).map(|v| v as u32) }
    }

    /// Lit un champ 64 bits ou « naturel » (les deux sont lus sur 64 bits).
    ///
    /// # Safety
    /// Voir [`Self::read_u16`].
    pub unsafe fn read_u64(&self, field: u32) -> Result<u64, ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.read_raw(field) }
    }

    /// Lit un champ « naturel » (pointeur, RSP/RIP, CR0/CR3/CR4…).
    ///
    /// # Safety
    /// Voir [`Self::read_u16`].
    pub unsafe fn read_natural(&self, field: u32) -> Result<u64, ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.read_raw(field) }
    }

    /// Écrit un champ 16 bits.
    ///
    /// # Safety
    /// - le bloc doit être chargé sur le CPU courant ;
    /// - `field` doit être un encodage 16 bits valide ;
    /// - la valeur doit respecter les contraintes de l'architecture (sinon
    ///   `VMLAUNCH` échouera et le diagnostic sera difficile).
    pub unsafe fn write_u16(&self, field: u32, value: u16) -> Result<(), ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.write_raw(field, value as u64) }
    }

    /// Écrit un champ 32 bits.
    ///
    /// # Safety
    /// Voir [`Self::write_u16`].
    pub unsafe fn write_u32(&self, field: u32, value: u32) -> Result<(), ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.write_raw(field, value as u64) }
    }

    /// Écrit un champ 64 bits ou « naturel ».
    ///
    /// # Safety
    /// Voir [`Self::write_u16`].
    pub unsafe fn write_u64(&self, field: u32, value: u64) -> Result<(), ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.write_raw(field, value) }
    }

    /// Écrit un champ « naturel ».
    ///
    /// # Safety
    /// Voir [`Self::write_u16`].
    pub unsafe fn write_natural(&self, field: u32, value: u64) -> Result<(), ControlError> {
        // SAFETY: contrat de la méthode.
        unsafe { self.write_raw(field, value) }
    }

    unsafe fn read_raw(&self, field: u32) -> Result<u64, ControlError> {
        if !self.loaded {
            return Err(ControlError::NotLoaded);
        }
        let value: u64;
        let fail: u8;
        // SAFETY: le bloc est chargé (vérifié) et `field` vient de l'appelant.
        unsafe {
            asm!(
                "vmread {value}, {field}",
                "setc {fail}",
                value = out(reg) value,
                field = in(reg) field as u64,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(value)
    }

    unsafe fn write_raw(&self, field: u32, value: u64) -> Result<(), ControlError> {
        if !self.loaded {
            return Err(ControlError::NotLoaded);
        }
        let fail: u8;
        // SAFETY: le bloc est chargé (vérifié).
        unsafe {
            asm!(
                "vmwrite {field}, {value}",
                "setc {fail}",
                field = in(reg) field as u64,
                value = in(reg) value,
                fail = out(reg_byte) fail,
                options(nostack, preserves_flags)
            );
        }
        if fail != 0 {
            return Err(ControlError::Failed);
        }
        Ok(())
    }
}

/// Identifiant de révision du bloc de contrôle depuis `MSR_BASIC`.
pub const fn revision_from_basic(basic: u64) -> u32 {
    (basic & 0x7FFF_FFFF) as u32
}

/// Taille minimale de la région du bloc de contrôle (octets), depuis
/// `MSR_BASIC` bits 44:32.
pub const fn region_size_from_basic(basic: u64) -> u16 {
    ((basic >> 32) & 0x1FFF) as u16
}

/// Construit la valeur d'activation de la traduction de second niveau
/// (`EPTP`) : type mémoire, longueur de marche, A/D et adresse racine.
///
/// Format (SDM) : bits 2:0 = type mémoire (6 = WB), bits 5:3 = longueur de
/// marche moins 1 (3 pour 4 niveaux), bit 6 = A/D, bits 51:12 = adresse
/// physique de la racine (PML4).
pub const fn make_eptp(root_phys: u64, memory_type: u8, four_levels: bool, ad: bool) -> u64 {
    let mut value = (memory_type as u64) & 0x7;
    if four_levels {
        value |= 3 << 3;
    }
    if ad {
        value |= 1 << 6;
    }
    value | (root_phys & 0x000F_FFFF_FFFF_F000)
}

/// Invalide les traductions de second niveau pour un contexte donné
/// (`invept` type 1, contexte unique). Ne fait rien si le CPU n'a pas `invept`.
///
/// # Safety
/// Le CPU doit être en mode racine VT-x et la traduction de second niveau ne
/// doit plus être utilisée par un invité actif.
pub unsafe fn invalidate_second_level(eptp: u64) {
    let descriptor = [eptp, 0u64];
    // SAFETY: `invept` lit 16 octets en mémoire (descripteur local).
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            kind = in(reg) 1u64,
            descriptor = in(reg) &descriptor,
            options(nostack)
        );
    }
}

/// Invalide toutes les traductions de second niveau (`invept` type 2).
///
/// # Safety
/// Voir [`invalidate_second_level`].
pub unsafe fn invalidate_second_level_all() {
    let descriptor = [0u64, 0u64];
    // SAFETY: `invept` type 2 ignore le descripteur, mais l'opérande mémoire
    // doit être valide (16 octets lus).
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            kind = in(reg) 2u64,
            descriptor = in(reg) &descriptor,
            options(nostack)
        );
    }
}

