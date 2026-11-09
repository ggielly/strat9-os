//! s9vm — structures ABI du système de virtualisation.
//!
//! Toutes les structures sont `#[repr(C)]`, versionnées par
//! [`VMM_ABI_VERSION`] et de taille fixe. Les identifiants (`vmm_id`,
//! `vcpu_id`) sont des entiers opaques : jamais des pointeurs, jamais des
//! adresses.
//!
//! Invariants :
//! - un client vérifie `abi_version` avant toute utilisation ;
//! - le noyau refuse une taille ou une version inattendue ;
//! - toute évolution ajoute des champs **en fin** de structure et incrémente
//!   la version.

/// Version de l'ABI s9vm. Incrémenter à chaque évolution de structure.
pub const VMM_ABI_VERSION: u32 = 1;

/// Nombre maximal de registres exposés par [`VmmRegs`] (registres généraux).
pub const VMM_REG_COUNT: usize = 16;
/// Longueur maximale d'un nom de monde.
pub const VMM_NAME_MAX: usize = 32;

/// Bloc de registres partagé entre `SYS_VMM_SET_REGS` et `SYS_VMM_GET_REGS`.
///
/// Taille : 184 octets. L'ordre suit l'ordre usuel de sauvegarde
/// (`rax`, `rbx`, …) ; `rsp` et `rip` sont inclus.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmRegs {
    pub abi_version: u32,
    pub flags: u32,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

/// États d'un monde, exposés par [`VmmInfo::state`].
pub mod state {
    /// Monde créé, aucun vCPU en cours.
    pub const CREATED: u32 = 0;
    /// Monde en cours d'exécution.
    pub const RUNNING: u32 = 1;
    /// Monde en pause.
    pub const PAUSED: u32 = 2;
    /// Monde arrêté.
    pub const STOPPED: u32 = 3;
    /// Monde en erreur.
    pub const FAILED: u32 = 4;
}

/// Snapshot d'un monde.
///
/// Taille : 96 octets. `vmm_id == 0` est réservé au résumé global du moteur
/// (état, nombre de vCPU, compteurs).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmInfo {
    pub abi_version: u32,
    pub state: u32,
    pub vmm_id: u64,
    pub silo_id: u32,
    pub vcpu_count: u32,
    pub exit_total: u64,
    pub ept_violations: u64,
    pub mmio_emulations: u64,
    pub irq_injected: u64,
    pub mapped_pages: u64,
    pub name: [u8; VMM_NAME_MAX],
}

/// Nature d'un événement remonté au monde de politique.
pub mod exit_kind {
    /// Lecture MMIO à émuler.
    pub const MMIO_READ: u32 = 1;
    /// Écriture MMIO à émuler.
    pub const MMIO_WRITE: u32 = 2;
    /// Accès à un port d'E/S.
    pub const IO_PORT: u32 = 3;
    /// `hlt` invité.
    pub const HALT: u32 = 4;
    /// Violation de traduction de second niveau.
    pub const TRANSLATION: u32 = 5;
    /// Exception ou NMI.
    pub const EXCEPTION: u32 = 6;
    /// Autre sortie à traiter par la politique.
    pub const OTHER: u32 = 7;
}

/// Événement de sortie remonté au monde de politique.
///
/// Taille : 48 octets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmmExitEvent {
    pub abi_version: u32,
    /// Une des constantes de [`exit_kind`].
    pub kind: u32,
    pub vcpu_id: u64,
    /// Adresse physique invitée concernée (0 si sans objet).
    pub gpa: u64,
    /// Largeur de l'accès (1, 2, 4, 8) pour MMIO/PIO, 0 sinon.
    pub size: u32,
    pub flags: u32,
    /// Valeur lue ou à écrire pour MMIO/PIO.
    pub value: u64,
    /// Port d'E/S pour [`exit_kind::IO_PORT`].
    pub port: u32,
    pub reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn struct_sizes_are_stable() {
        assert_eq!(size_of::<VmmRegs>(), 184);
        assert_eq!(size_of::<VmmInfo>(), 96);
        assert_eq!(size_of::<VmmExitEvent>(), 48);
    }
}
