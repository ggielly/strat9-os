//! s9vm — état invité et validation avant entrée.
//!
//! Module **pur** : il décrit l'état d'un processeur invité (registres
//! généraux, registres de contrôle, segments, tables système) et vérifie les
//! invariants que le matériel exigera de toute façon, mais avec un diagnostic
//! exploitable côté noyau. Testable sur l'hôte (tests L2).
//!
//! Les règles proviennent de la SDM Intel (vol. 3C, chapitre « VM entry »
//! et « checking and loading guest state »). Aucune constante propre à un
//! hyperviseur particulier.

/// Bit `CR0.PE` (protection enable).
pub const CR0_PE: u64 = 1 << 0;
/// Bit `CR0.MP`.
pub const CR0_MP: u64 = 1 << 1;
/// Bit `CR0.EM`.
pub const CR0_EM: u64 = 1 << 2;
/// Bit `CR0.TS`.
pub const CR0_TS: u64 = 1 << 3;
/// Bit `CR0.NE`.
pub const CR0_NE: u64 = 1 << 5;
/// Bit `CR0.WP`.
pub const CR0_WP: u64 = 1 << 16;
/// Bit `CR0.PG` (paging enable).
pub const CR0_PG: u64 = 1 << 31;

/// Bit `CR4.PAE`.
pub const CR4_PAE: u64 = 1 << 5;
/// Bit `CR4.PGE`.
pub const CR4_PGE: u64 = 1 << 7;
/// Bit `CR4.OSFXSR`.
pub const CR4_OSFXSR: u64 = 1 << 9;
/// Bit `CR4.OSXMMEXCPT`.
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
/// Bit `CR4.OSXSAVE`.
pub const CR4_OSXSAVE: u64 = 1 << 18;
/// Bit `CR4.SMEP`.
pub const CR4_SMEP: u64 = 1 << 20;
/// Bit `CR4.SMAP`.
pub const CR4_SMAP: u64 = 1 << 21;

/// Bit `EFER.SCE`.
pub const EFER_SCE: u64 = 1 << 0;
/// Bit `EFER.LME` (long mode enable).
pub const EFER_LME: u64 = 1 << 8;
/// Bit `EFER.LMA` (long mode active — positionné par le CPU, pas par l'hôte).
pub const EFER_LMA: u64 = 1 << 10;
/// Bit `EFER.NXE`.
pub const EFER_NXE: u64 = 1 << 11;

/// Bit « segment inutilisable » des droits d'accès invités (VMCS : bit 16).
pub const AR_UNUSABLE: u32 = 1 << 16;
/// Bit « L » (mode long) des droits d'accès de `CS`.
pub const AR_LONG_MODE: u32 = 1 << 9;
/// Bit « D/B » des droits d'accès.
pub const AR_DEFAULT_BIG: u32 = 1 << 10;
/// Bit « présent ».
pub const AR_PRESENT: u32 = 0x80;
/// Bit « code ou données » (1 = code/données, 0 = système).
pub const AR_CODE_DATA: u32 = 0x10;

/// Droits d'accès d'un segment de données lu/écrit, noyau (DPL 0).
pub const fn data_access_rights(dpl: u8) -> u32 {
    0x2 | AR_CODE_DATA | AR_PRESENT | (((dpl as u32) & 3) << 5)
}

/// Droits d'accès d'un segment de code 64 bits exécutable/lisible.
pub const fn long_code_access_rights(dpl: u8) -> u32 {
    0xA | AR_CODE_DATA | AR_PRESENT | AR_LONG_MODE | (((dpl as u32) & 3) << 5)
}

/// Droits d'accès d'un segment de code 32 bits exécutable/lisible.
pub const fn protected_code_access_rights(dpl: u8) -> u32 {
    0xA | AR_CODE_DATA | AR_PRESENT | AR_DEFAULT_BIG | (((dpl as u32) & 3) << 5)
}

/// Droits d'accès « inutilisable » (segment non chargé).
pub const fn unusable_access_rights() -> u32 {
    AR_UNUSABLE
}

/// Descripteur de segment tel que stocké dans le bloc de contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Sélecteur (16 bits).
    pub selector: u16,
    /// Base (ignorée en mode long sauf FS/GS).
    pub base: u64,
    /// Limite.
    pub limit: u32,
    /// Droits d'accès au format du bloc de contrôle.
    pub access_rights: u32,
}

impl Segment {
    /// Segment inutilisable (tous champs à zéro).
    pub const fn unusable() -> Self {
        Self {
            selector: 0,
            base: 0,
            limit: 0,
            access_rights: AR_UNUSABLE,
        }
    }

    /// Vrai si le segment est marqué inutilisable.
    pub const fn is_unusable(&self) -> bool {
        self.access_rights & AR_UNUSABLE != 0
    }

    /// Vrai si le segment est un segment de code en mode long (L = 1).
    pub const fn is_long_code(&self) -> bool {
        self.access_rights & AR_CODE_DATA != 0 && self.access_rights & AR_LONG_MODE != 0
    }
}

/// État complet d'un processeur invité, prêt à être chargé dans le bloc de
/// contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestState {
    // Registres généraux (rsp est un champ séparé).
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    /// Pointeur d'instruction.
    pub rip: u64,
    /// Pointeur de pile.
    pub rsp: u64,
    /// Drapeaux.
    pub rflags: u64,

    /// Registres de contrôle.
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    /// `IA32_EFER`.
    pub efer: u64,
    /// `DR7`.
    pub dr7: u64,
    /// `IA32_PAT` (0 si non utilisé).
    pub pat: u64,

    /// Segments.
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ldtr: Segment,
    pub tr: Segment,

    /// Tables système.
    pub gdtr_base: u64,
    pub gdtr_limit: u32,
    pub idtr_base: u64,
    pub idtr_limit: u32,

    /// MSR SYSENTER.
    pub sysenter_cs: u32,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,

    /// Exceptions de débogage en attente.
    pub pending_debug_exceptions: u64,
    /// État d'interruptibilité (bits STI/MOV-SS/SMI/NMI).
    pub interruptibility: u32,
    /// État d'activité (0 = actif).
    pub activity_state: u32,
}

impl GuestState {
    /// État de base en mode réel 16 bits, pour un invité minimal.
    ///
    /// Aucune paging, aucun segment en mode protégé : destiné aux tests de
    /// fumée du moteur (l'invité exécute quelques instructions puis sort).
    pub const fn real_mode(entry: u64, stack_top: u64) -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: entry,
            rsp: stack_top,
            rflags: 0x2,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            dr7: 0x400,
            pat: 0x0007_0406_0007_0406,
            es: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            cs: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: protected_code_access_rights(0),
            },
            ss: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            ds: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: data_access_rights(0),
            },
            fs: Segment::unusable(),
            gs: Segment::unusable(),
            ldtr: Segment::unusable(),
            tr: Segment {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: 0x8B, // type 0xB (busy TSS 32 bits), présent
            },
            gdtr_base: 0,
            gdtr_limit: 0,
            idtr_base: 0,
            idtr_limit: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            pending_debug_exceptions: 0,
            interruptibility: 0,
            activity_state: 0,
        }
    }

    /// État de base en mode long 64 bits (paging activée, CS.L = 1).
    pub const fn long_mode_64(entry: u64, stack_top: u64, cr3: u64) -> Self {
        let mut state = Self::real_mode(entry, stack_top);
        state.cr0 = CR0_PE | CR0_MP | CR0_NE | CR0_PG | CR0_WP;
        state.cr3 = cr3;
        state.cr4 = CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        state.efer = EFER_SCE | EFER_LME | EFER_NXE;
        state.cs = Segment {
            selector: 0x8,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: long_code_access_rights(0),
        };
        state.ss = Segment {
            selector: 0x10,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: data_access_rights(0),
        };
        state.ds = state.ss;
        state.es = state.ss;
        state.fs = Segment::unusable();
        state.gs = Segment::unusable();
        state
    }

    /// Vrai si l'état demande le mode long 64 bits.
    pub const fn is_long_mode(&self) -> bool {
        (self.cr0 & CR0_PG) != 0 && (self.efer & EFER_LME) != 0
    }

    /// Vrai si l'état est en mode réel (PE = 0).
    pub const fn is_real_mode(&self) -> bool {
        (self.cr0 & CR0_PE) == 0
    }
}

/// Erreur de validation d'état invité, exploitable dans les logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestError {
    /// Un bit interdit de CR0 est positionné.
    Cr0FixedBit,
    /// Un bit obligatoire de CR0 est absent.
    Cr0RequiredBit,
    /// Un bit interdit de CR4 est positionné.
    Cr4FixedBit,
    /// Un bit obligatoire de CR4 est absent.
    Cr4RequiredBit,
    /// Mode long demandé sans paging (`CR0.PG` absent).
    LongModeWithoutPaging,
    /// Mode réel sans « unrestricted guest ».
    RealModeRestricted,
    /// En mode long, `CS.L` doit être à 1 et `CS.D` à 0.
    BadLongCodeSegment,
    /// En mode long, bases de CS/SS/DS/ES doivent être nulles.
    SegmentBaseNotZero,
    /// En mode long, limites de CS/SS/DS/ES doivent valoir 0xFFFF_FFFF.
    SegmentLimitNotFull,
    /// `RFLAGS` contient une combinaison réservée.
    BadRflags,
    /// État d'interruptibilité invalide.
    BadInterruptibility,
    /// État d'activité non actif.
    NotActive,
    /// Segment de pile invalide.
    BadStackSegment,
}

impl GuestState {
    /// Valide l'état avant une entrée invitée.
    ///
    /// `cr0_fixed0`/`cr0_fixed1` et `cr4_fixed0`/`cr4_fixed1` sont les MSR de
    /// masques fixes lus au boot. `unrestricted_guest` indique si le mode
    /// réel sans VM86 est disponible.
    pub fn validate(&self, caps: &FixedBits, unrestricted_guest: bool) -> Result<(), GuestError> {
        // CR0 : les bits fixes sont imposés par l'architecture.
        if self.cr0 & !caps.cr0_fixed1 != 0 {
            return Err(GuestError::Cr0FixedBit);
        }
        if self.cr0 & caps.cr0_fixed0 != caps.cr0_fixed0 {
            return Err(GuestError::Cr0RequiredBit);
        }
        if self.cr4 & !caps.cr4_fixed1 != 0 {
            return Err(GuestError::Cr4FixedBit);
        }
        if self.cr4 & caps.cr4_fixed0 != caps.cr4_fixed0 {
            return Err(GuestError::Cr4RequiredBit);
        }

        // Mode réel (PE = 0) : nécessite l'invité non restreint.
        if self.is_real_mode() && !unrestricted_guest {
            return Err(GuestError::RealModeRestricted);
        }

        // Mode long : EFER.LME demande la paging, et CS doit être en mode long.
        if self.efer & EFER_LME != 0 {
            if self.cr0 & CR0_PG == 0 {
                return Err(GuestError::LongModeWithoutPaging);
            }
            if !self.cs.is_long_code() || self.cs.access_rights & AR_DEFAULT_BIG != 0 {
                return Err(GuestError::BadLongCodeSegment);
            }
            for segment in [self.cs, self.ss, self.ds, self.es] {
                if segment.base != 0 {
                    return Err(GuestError::SegmentBaseNotZero);
                }
                if segment.limit != 0xFFFF_FFFF {
                    return Err(GuestError::SegmentLimitNotFull);
                }
            }
        }

        // RFLAGS : bit 1 obligatoire, bits réservés nuls.
        if self.rflags & 0x2 == 0 {
            return Err(GuestError::BadRflags);
        }
        const RFLAGS_RESERVED: u64 = (1 << 3) | (1 << 5) | (1 << 15) | (1 << 16) | (1 << 17);
        if self.rflags & RFLAGS_RESERVED != 0 {
            return Err(GuestError::BadRflags);
        }

        // Interruptibilité : seuls les bits 0-3 sont définis.
        if self.interruptibility & !0xF != 0 {
            return Err(GuestError::BadInterruptibility);
        }

        // Activité : seul l'état « actif » (0) est accepté pour l'entrée.
        if self.activity_state != 0 {
            return Err(GuestError::NotActive);
        }

        // Pile : SS doit être utilisable si RSP est utilisé.
        if self.ss.is_unusable() {
            return Err(GuestError::BadStackSegment);
        }

        Ok(())
    }
}

/// Masques fixes de CR0/CR4, extraits des MSR de capacité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedBits {
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

impl FixedBits {
    /// Construit depuis les masques bruts.
    pub const fn new(cr0_fixed0: u64, cr0_fixed1: u64, cr4_fixed0: u64, cr4_fixed1: u64) -> Self {
        Self {
            cr0_fixed0,
            cr0_fixed1,
            cr4_fixed0,
            cr4_fixed1,
        }
    }

    /// Masques permissifs (tests synthétiques, ou CPU dont les MSR valent
    /// `0`/`u64::MAX`).
    pub const fn permissive() -> Self {
        Self {
            cr0_fixed0: 0,
            cr0_fixed1: u64::MAX,
            cr4_fixed0: 0,
            cr4_fixed1: u64::MAX,
        }
    }
}
