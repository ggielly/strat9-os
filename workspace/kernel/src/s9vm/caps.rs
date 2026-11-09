//! s9vm — décodage des capacités matérielles de virtualisation (Intel VT-x).
//!
//! Ce module est **pur** : il ne lit aucun MSR lui-même, il reçoit une
//! photographie (`MsrSnapshot`) lue par la couche noyau (`s9vm::mod`). Il est
//! donc compilable et testable sur l'hôte (tests L2).
//!
//! Les constantes d'encodage proviennent de la documentation Intel (SDM
//! vol. 3C, chapitres « VMX ») : MSR `0x480`–`0x492`, `IA32_FEATURE_CONTROL`
//! (`0x3A`). Aucune valeur propre à un hyperviseur particulier n'est utilisée.

/// MSR `IA32_FEATURE_CONTROL` : verrouillage et autorisation d'activation.
pub const MSR_FEATURE_CONTROL: u32 = 0x3A;
/// `IA32_FEATURE_CONTROL` bit 0 : MSR verrouillé par le firmware.
pub const FEATURE_CONTROL_LOCKED: u64 = 1 << 0;
/// `IA32_FEATURE_CONTROL` bit 2 : activation autorisée hors SMX.
pub const FEATURE_CONTROL_ENABLE_OUTSIDE_SMX: u64 = 1 << 2;

/// MSR de capacités VT-x (plage `0x480`–`0x492`).
pub const MSR_BASIC: u32 = 0x480;
pub const MSR_PIN_BASED: u32 = 0x481;
pub const MSR_PRIMARY_PROC_BASED: u32 = 0x482;
pub const MSR_EXIT_CONTROLS: u32 = 0x483;
pub const MSR_ENTRY_CONTROLS: u32 = 0x484;
pub const MSR_MISC: u32 = 0x485;
pub const MSR_CR0_FIXED0: u32 = 0x486;
pub const MSR_CR0_FIXED1: u32 = 0x487;
pub const MSR_CR4_FIXED0: u32 = 0x488;
pub const MSR_CR4_FIXED1: u32 = 0x489;
pub const MSR_VMCS_ENUM: u32 = 0x48A;
pub const MSR_SECONDARY_PROC_BASED: u32 = 0x48B;
pub const MSR_EPT_VPID_CAP: u32 = 0x48C;
pub const MSR_TRUE_PIN_BASED: u32 = 0x48D;
pub const MSR_TRUE_PRIMARY_PROC_BASED: u32 = 0x48E;
pub const MSR_TRUE_EXIT_CONTROLS: u32 = 0x48F;
pub const MSR_TRUE_ENTRY_CONTROLS: u32 = 0x490;

/// Bits du MSR `MSR_EPT_VPID_CAP` utiles à s9vm.
pub mod ept_vpid_cap {
    /// Instruction `invept` disponible.
    pub const INVEPT: u64 = 1 << 0;
    /// Marche de tables EPT sur 4 niveaux (`PM4L`).
    pub const WALK_LENGTH_4: u64 = 1 << 6;
    /// Type mémoire *uncacheable* supporté pour les tables EPT.
    pub const MEMTYPE_UC: u64 = 1 << 8;
    /// Type mémoire *write-back* supporté pour les tables EPT.
    pub const MEMTYPE_WB: u64 = 1 << 14;
    /// Pages de 2 Mio supportées dans l'EPT.
    pub const PAGE_2MB: u64 = 1 << 16;
    /// Pages de 1 Gio supportées dans l'EPT.
    pub const PAGE_1GB: u64 = 1 << 17;
    /// Bits *accessed/dirty* (A/D) supportés dans l'EPT.
    pub const ACCESSED_DIRTY: u64 = 1 << 21;
    /// `invvpid` avec un contexte unique.
    pub const INVVPID_SINGLE_CONTEXT: u64 = 1 << 32;
    /// `invvpid` avec tous les contextes.
    pub const INVVPID_ALL_CONTEXT: u64 = 1 << 33;
    /// `invvpid` avec une adresse individuelle.
    pub const INVVPID_INDIVIDUAL_ADDRESS: u64 = 1 << 34;
    /// `invvpid` avec un contexte unique, en conservant les entrées globales.
    pub const INVVPID_SINGLE_CONTEXT_RETAIN_GLOBALS: u64 = 1 << 35;
}

/// Bits utiles du MSR `MSR_PIN_BASED`, `MSR_PRIMARY_PROC_BASED`,
/// `MSR_SECONDARY_PROC_BASED` et `MSR_MISC`.
pub mod control_bits {
    /// Contrôles « pin-based » : sortie sur interruption externe.
    pub const PIN_EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
    /// Contrôles « pin-based » : sortie sur NMI.
    pub const PIN_NMI_EXITING: u32 = 1 << 3;
    /// Contrôles « pin-based » : NMI virtuels.
    pub const PIN_VIRTUAL_NMIS: u32 = 1 << 5;
    /// Contrôles « pin-based » : timer de préemption (tranche invitée).
    pub const PIN_PREEMPTION_TIMER: u32 = 1 << 6;
    /// Contrôles « pin-based » : interruptions postées.
    pub const PIN_POSTED_INTERRUPTS: u32 = 1 << 7;

    /// Contrôles primaires : activer les contrôles secondaires.
    pub const PROC_ACTIVATE_SECONDARY: u32 = 1 << 31;
    /// Contrôles primaires : bitmap d'E/S.
    pub const PROC_USE_IO_BITMAPS: u32 = 1 << 25;
    /// Contrôles primaires : bitmap de MSR.
    pub const PROC_USE_MSR_BITMAPS: u32 = 1 << 28;
    /// Contrôles primaires : sortie sur `hlt`.
    pub const PROC_HLT_EXITING: u32 = 1 << 7;
    /// Contrôles primaires : sortie sur `rdtsc`.
    pub const PROC_RDTSC_EXITING: u32 = 1 << 12;
    /// Contrôles primaires : sortie sur `mov cr`.
    pub const PROC_CR3_LOAD_EXITING: u32 = 1 << 15;

    /// Contrôles secondaires : activer l'EPT.
    pub const PROC2_ENABLE_EPT: u32 = 1 << 1;
    /// Contrôles secondaires : mode x2APIC virtuEL.
    pub const PROC2_VIRTUALIZE_X2APIC: u32 = 1 << 4;
    /// Contrôles secondaires : activer VPID.
    pub const PROC2_ENABLE_VPID: u32 = 1 << 5;
    /// Contrôles secondaires : invité non restreint (real mode sans VM86).
    pub const PROC2_UNRESTRICTED_GUEST: u32 = 1 << 7;
    /// Contrôles secondaires : virtualisation du registre APIC.
    pub const PROC2_APIC_REGISTER_VIRT: u32 = 1 << 8;
    /// Contrôles secondaires : livraison virtuelle des interruptions.
    pub const PROC2_VIRTUAL_INTERRUPT_DELIVERY: u32 = 1 << 9;
    /// Contrôles secondaires : sortie sur boucle `pause` (PLE).
    pub const PROC2_PAUSE_LOOP_EXITING: u32 = 1 << 10;
    /// Contrôles secondaires : shadowing du bloc de contrôle (nested).
    pub const PROC2_CONTROL_SHADOWING: u32 = 1 << 14;
    /// Contrôles secondaires : `rdseed`.
    pub const PROC2_ENABLE_RDSEED: u32 = 1 << 16;
    /// Contrôles secondaires : *page modification logging*.
    pub const PROC2_ENABLE_PML: u32 = 1 << 17;
    /// Contrôles secondaires : XSAVES/XRSTORS.
    pub const PROC2_ENABLE_XSAVES: u32 = 1 << 20;
    /// Contrôles secondaires : `umwait`.
    pub const PROC2_ENABLE_UMWAIT: u32 = 1 << 21;
    /// Contrôles secondaires : `tpause`.
    pub const PROC2_ENABLE_TPAUSE: u32 = 1 << 22;
}

/// Photographie des MSR nécessaires à la détection. Toutes les valeurs sont
/// brutes (telles que lues), le décodage est fait par [`HwCaps::from_snapshot`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsrSnapshot {
    pub feature_control: u64,
    pub basic: u64,
    pub pin_based: u64,
    pub primary_proc_based: u64,
    pub exit_controls: u64,
    pub entry_controls: u64,
    pub misc: u64,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub secondary_proc_based: u64,
    pub ept_vpid_cap: u64,
    pub true_pin_based: Option<u64>,
    pub true_primary_proc_based: Option<u64>,
    pub true_exit_controls: Option<u64>,
    pub true_entry_controls: Option<u64>,
}

impl MsrSnapshot {
    /// Construit une photographie depuis un lecteur de MSR (le noyau fournit
    /// un lecteur `rdmsr`, les tests un lecteur synthétique).
    pub fn from_reader<R: Fn(u32) -> u64>(read: R) -> Self {
        let mut snapshot = Self {
            feature_control: read(MSR_FEATURE_CONTROL),
            basic: read(MSR_BASIC),
            pin_based: read(MSR_PIN_BASED),
            primary_proc_based: read(MSR_PRIMARY_PROC_BASED),
            exit_controls: read(MSR_EXIT_CONTROLS),
            entry_controls: read(MSR_ENTRY_CONTROLS),
            misc: read(MSR_MISC),
            cr0_fixed0: read(MSR_CR0_FIXED0),
            cr0_fixed1: read(MSR_CR0_FIXED1),
            cr4_fixed0: read(MSR_CR4_FIXED0),
            cr4_fixed1: read(MSR_CR4_FIXED1),
            secondary_proc_based: read(MSR_SECONDARY_PROC_BASED),
            ept_vpid_cap: read(MSR_EPT_VPID_CAP),
            true_pin_based: None,
            true_primary_proc_based: None,
            true_exit_controls: None,
            true_entry_controls: None,
        };
        // Les MSR « TRUE_* » n'existent que si le bit 55 de `MSR_BASIC` est
        // positionné (contrôles par défaut, SDM). Sur les CPU anciens, les MSR
        // de base font foi.
        if snapshot.basic & (1 << 55) != 0 {
            snapshot.true_pin_based = Some(read(MSR_TRUE_PIN_BASED));
            snapshot.true_primary_proc_based = Some(read(MSR_TRUE_PRIMARY_PROC_BASED));
            snapshot.true_exit_controls = Some(read(MSR_TRUE_EXIT_CONTROLS));
            snapshot.true_entry_controls = Some(read(MSR_TRUE_ENTRY_CONTROLS));
        }
        snapshot
    }
}

/// Jeu de capacités décodées, utilisé par le moteur `s9vm`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwCaps {
    /// Le firmware autorise l'activation (bit 2 de `IA32_FEATURE_CONTROL`).
    pub allowed: bool,
    /// MSR `IA32_FEATURE_CONTROL` verrouillé (s'il ne l'est pas, on peut
    /// l'écrire une fois pour autoriser l'activation).
    pub feature_control_locked: bool,
    /// Identifiant de révision du bloc de contrôle (bits 30:0 de `MSR_BASIC`).
    pub control_block_revision: u32,
    /// Taille de la région du bloc de contrôle en octets (bits 44:32).
    pub control_block_size: u16,
    /// Type mémoire recommandé pour la région (bits 53:50 ; 6 = WB).
    pub control_block_memory_type: u8,
    /// Les bits « TRUE_* » sont disponibles.
    pub has_true_controls: bool,
    /// EPT disponible (autorisé côté contrôles secondaires).
    pub ept: bool,
    /// EPT sur 4 niveaux de marche.
    pub ept_four_levels: bool,
    /// EPT 2 Mio.
    pub ept_2mb: bool,
    /// EPT 1 Gio.
    pub ept_1gb: bool,
    /// EPT en write-back.
    pub ept_wb: bool,
    /// EPT avec bits A/D.
    pub ept_ad: bool,
    /// `invept` disponible.
    pub invept: bool,
    /// VPID disponible.
    pub vpid: bool,
    /// Variantes d'`invvpid` disponibles.
    pub invvpid_single_context: bool,
    pub invvpid_all_context: bool,
    pub invvpid_individual_address: bool,
    /// Invité non restreint (16 bits sans VM86).
    pub unrestricted_guest: bool,
    /// APIC virtuelle (registre + livraison).
    pub apic_register_virt: bool,
    pub virtual_interrupt_delivery: bool,
    /// Interruptions postées.
    pub posted_interrupts: bool,
    /// Sortie sur boucle `pause` (PLE).
    pub pause_loop_exiting: bool,
    /// x2APIC virtualisé.
    pub virtualize_x2apic: bool,
    /// Timer de préemption.
    pub preemption_timer: bool,
    /// NMI virtuels.
    pub virtual_nmis: bool,
    /// `rdseed` autorisé dans l'invité.
    pub rdseed: bool,

    /// Valeurs « allowed » (32 bits bas / hauts) des MSR de contrôle, après
    /// sélection des MSR `TRUE_*` quand ils existent.
    pub pin_allowed: AllowedControls,
    pub primary_proc_allowed: AllowedControls,
    pub secondary_proc_allowed: AllowedControls,
    pub exit_allowed: AllowedControls,
    pub entry_allowed: AllowedControls,

    /// Masques fixes de CR0/CR4.
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

/// Valeur d'un MSR de contrôle : bits devant être à 1 (bas) et bits pouvant
/// être à 1 (hauts). Voir SDM « VMX capability MSRs ».
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllowedControls {
    /// Bits qui doivent être à 1 dans le champ.
    pub must_be_one: u32,
    /// Bits qui peuvent être à 1 dans le champ.
    pub may_be_one: u32,
}

impl AllowedControls {
    /// Décode une valeur 64 bits de MSR de contrôle.
    pub const fn from_msr(value: u64) -> Self {
        Self {
            must_be_one: value as u32,
            may_be_one: (value >> 32) as u32,
        }
    }

    /// Construit la valeur à écrire pour un contrôle souhaité : les bits
    /// obligatoires sont forcés, les bits interdits sont effacés.
    ///
    /// `value = (desired & may_be_one) | must_be_one`
    ///
    /// L'ordre relatif de `must_be_one` et `may_be_one` est sans importance :
    /// l'architecture garantit que tout bit obligatoire est aussi autorisé.
    pub const fn apply(self, desired: u32) -> u32 {
        (desired & self.may_be_one) | self.must_be_one
    }

    /// Vrai si tous les bits demandés sont autorisés (utile pour diagnostiquer
    /// une configuration demandée trop ambitieuse).
    pub const fn supports(self, desired: u32) -> bool {
        (desired & !self.may_be_one) == 0
    }
}

impl HwCaps {
    /// Décode une photographie de MSR. `cpuid_vmx` est le résultat de
    /// `CPUID.1:ECX[5]` ; il est passé séparément pour garder ce module pur.
    pub fn from_snapshot(snapshot: &MsrSnapshot, cpuid_vmx: bool) -> Self {
        let pin = snapshot
            .true_pin_based
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.pin_based));
        let primary = snapshot
            .true_primary_proc_based
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.primary_proc_based));
        let exit = snapshot
            .true_exit_controls
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.exit_controls));
        let entry = snapshot
            .true_entry_controls
            .map(AllowedControls::from_msr)
            .unwrap_or_else(|| AllowedControls::from_msr(snapshot.entry_controls));
        let secondary = AllowedControls::from_msr(snapshot.secondary_proc_based);
        let ept_vpid = snapshot.ept_vpid_cap;

        let _ = cpuid_vmx; // La présence CPUID est vérifiée par l'appelant.

        Self {
            allowed: snapshot.feature_control & FEATURE_CONTROL_ENABLE_OUTSIDE_SMX != 0
                && cpuid_vmx,
            feature_control_locked: snapshot.feature_control & FEATURE_CONTROL_LOCKED != 0,
            control_block_revision: (snapshot.basic & 0x7FFF_FFFF) as u32,
            control_block_size: ((snapshot.basic >> 32) & 0x1FFF) as u16,
            control_block_memory_type: ((snapshot.basic >> 50) & 0xF) as u8,
            has_true_controls: snapshot.true_pin_based.is_some(),
            ept: cpuid_vmx && secondary.supports(control_bits::PROC2_ENABLE_EPT),
            ept_four_levels: secondary.supports(control_bits::PROC2_ENABLE_EPT)
                && ept_vpid & ept_vpid_cap::WALK_LENGTH_4 != 0,
            ept_2mb: ept_vpid & ept_vpid_cap::PAGE_2MB != 0,
            ept_1gb: ept_vpid & ept_vpid_cap::PAGE_1GB != 0,
            ept_wb: ept_vpid & ept_vpid_cap::MEMTYPE_WB != 0,
            ept_ad: ept_vpid & ept_vpid_cap::ACCESSED_DIRTY != 0,
            invept: ept_vpid & ept_vpid_cap::INVEPT != 0,
            vpid: secondary.supports(control_bits::PROC2_ENABLE_VPID),
            invvpid_single_context: ept_vpid & ept_vpid_cap::INVVPID_SINGLE_CONTEXT != 0,
            invvpid_all_context: ept_vpid & ept_vpid_cap::INVVPID_ALL_CONTEXT != 0,
            invvpid_individual_address: ept_vpid
                & ept_vpid_cap::INVVPID_INDIVIDUAL_ADDRESS
                != 0,
            unrestricted_guest: secondary.supports(control_bits::PROC2_UNRESTRICTED_GUEST),
            apic_register_virt: secondary.supports(control_bits::PROC2_APIC_REGISTER_VIRT),
            virtual_interrupt_delivery: secondary
                .supports(control_bits::PROC2_VIRTUAL_INTERRUPT_DELIVERY),
            posted_interrupts: pin.supports(control_bits::PIN_POSTED_INTERRUPTS),
            pause_loop_exiting: secondary.supports(control_bits::PROC2_PAUSE_LOOP_EXITING),
            virtualize_x2apic: secondary.supports(control_bits::PROC2_VIRTUALIZE_X2APIC),
            preemption_timer: pin.supports(control_bits::PIN_PREEMPTION_TIMER),
            virtual_nmis: pin.supports(control_bits::PIN_VIRTUAL_NMIS),
            rdseed: secondary.supports(control_bits::PROC2_ENABLE_RDSEED),
            pin_allowed: pin,
            primary_proc_allowed: primary,
            secondary_proc_allowed: secondary,
            exit_allowed: exit,
            entry_allowed: entry,
            cr0_fixed0: snapshot.cr0_fixed0,
            cr0_fixed1: snapshot.cr0_fixed1,
            cr4_fixed0: snapshot.cr4_fixed0,
            cr4_fixed1: snapshot.cr4_fixed1,
        }
    }

    /// Vrai si la plateforme peut héberger le moteur s9vm avec EPT et VPID.
    pub const fn can_run(&self) -> bool {
        self.allowed && self.ept && self.ept_four_levels
    }

    /// Résumé lisible (une ligne) pour les logs de boot.
    pub fn summary(&self) -> alloc::string::String {
        use alloc::format;
        format!(
            "allowed={} rev={} cb={}B ept={} 2mb={} 1gb={} ad={} vpid={} ug={} apicv={} pi={} ple={} x2apic={} ptimer={} cr0fix={:#x}/{:#x} cr4fix={:#x}/{:#x}",
            self.allowed,
            self.control_block_revision,
            self.control_block_size,
            self.ept,
            self.ept_2mb,
            self.ept_1gb,
            self.ept_ad,
            self.vpid,
            self.unrestricted_guest,
            self.apic_register_virt && self.virtual_interrupt_delivery,
            self.posted_interrupts,
            self.pause_loop_exiting,
            self.virtualize_x2apic,
            self.preemption_timer,
            self.cr0_fixed0,
            self.cr0_fixed1,
            self.cr4_fixed0,
            self.cr4_fixed1
        )
    }
}

/// Erreurs de détection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsError {
    /// Le CPU n'expose pas VT-x (CPUID.1:ECX[5] = 0).
    NotSupported,
    /// Le firmware interdit l'activation et le MSR est verrouillé.
    LockedByFirmware,
    /// EPT absent ou non utilisable en 4 niveaux.
    EptUnavailable,
}

impl HwCaps {
    /// Vérifie les conditions d'activation et renvoie une erreur explicite.
    pub fn validate(&self) -> Result<(), CapsError> {
        if !self.allowed {
            return Err(if self.feature_control_locked {
                CapsError::LockedByFirmware
            } else {
                CapsError::NotSupported
            });
        }
        if !self.ept || !self.ept_four_levels {
            return Err(CapsError::EptUnavailable);
        }
        Ok(())
    }
}
