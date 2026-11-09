//! s9vm — système de virtualisation bare-metal de strat9-os.
//!
//! # Principe
//!
//! **Bedrock fournit le mécanisme** (activation VT-x par CPU, bloc de contrôle
//! matériel, traduction de second niveau, réception des sorties, injection
//! d'événements), **le silo de politique** (à venir) décidera du cycle de vie
//! des machines, du modèle de périphériques et du routage des interruptions.
//!
//! # Découpage
//!
//! | Module | Contenu | Testable hôte |
//! |---|---|---|
//! | [`caps`] | décodage des MSR de capacité VT-x | oui |
//! | [`control`] | encodage des champs, primitives du bloc de contrôle | oui (compile) |
//! | [`mmu`] | tables de traduction de second niveau | oui |
//! | [`exit`] | décodage et classification des sorties | oui |
//!
//! # Cycle d'initialisation
//!
//! 1. détection très tôt (CPUID + MSR), sans effet de bord ;
//! 2. activation par CPU quand l'allocateur de frames est prêt (composant
//!    `bootstrap`) : `CR4.VMXE`, région d'activation 4 Kio, activation ;
//! 3. les vCPU seront créés plus tard par la couche de politique.
//!
//! L'absence de VT-x n'est jamais fatale : le noyau démarre normalement et
//! journalise `virtualisation inactive`.

pub mod caps;
pub mod control;
pub mod exit;
pub mod guest;
pub mod launch;
pub mod memmap;
pub mod mmu;
pub mod selftest;
pub mod vcpu;
pub mod vm;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use caps::{CapsError, HwCaps, MsrSnapshot};

/// Interrupteur global de compilation/comportement.
///
/// À `false`, `init()` ne fait que journaliser : utile pour un noyau de
/// diagnostic ou une plateforme exotique. Le code reste compilé, ce qui évite
/// deux variantes de binaire.
pub const S9VM_ENABLED: bool = true;

/// Bit `CR4.VMXE` (activation de l'extension matérielle).
const CR4_VMXE: u64 = 1 << 13;

/// Nombre maximum de CPU suivis (aligné sur `percpu::MAX_CPUS`).
const MAX_CPUS: usize = crate::arch::x86_64::percpu::MAX_CPUS;

/// Régions d'activation par CPU (adresse physique, 0 = non activé).
static REGIONS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// CPU dont l'activation a réussi.
static ACTIVATED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// Nombre de CPU activés.
static ACTIVE_CPUS: AtomicU32 = AtomicU32::new(0);
/// Capacités détectées une fois pour toutes (0 = non détectées).
static CAPS_VALID: AtomicBool = AtomicBool::new(false);

/// Erreurs d'initialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// Pas de VT-x sur ce CPU.
    NotSupported,
    /// Le firmware a verrouillé l'interdiction d'activation.
    LockedByFirmware,
    /// EPT absent ou inutilisable.
    EptUnavailable,
    /// Impossible d'allouer la région d'activation.
    OutOfMemory,
    /// L'instruction d'activation a échoué.
    ActivationFailed,
}

impl From<CapsError> for InitError {
    fn from(value: CapsError) -> Self {
        match value {
            CapsError::NotSupported => Self::NotSupported,
            CapsError::LockedByFirmware => Self::LockedByFirmware,
            CapsError::EptUnavailable => Self::EptUnavailable,
        }
    }
}

/// Lit un MSR via la couche architecture.
#[inline]
fn read_msr(msr: u32) -> u64 {
    crate::arch::x86_64::rdmsr(msr)
}

/// Écrit un MSR via la couche architecture.
#[inline]
fn write_msr(msr: u32, value: u64) {
    crate::arch::x86_64::wrmsr(msr, value);
}

/// Lit `CR4`.
#[inline]
fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: lecture d'un registre de contrôle, sans effet de bord.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Écrit `CR4`.
#[inline]
unsafe fn write_cr4(value: u64) {
    // SAFETY: l'appelant garantit que les bits modifiés sont valides.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) value, options(nomem, nostack));
    }
}

/// Détecte les capacités matérielles. Ne modifie aucun état du CPU.
pub fn detect() -> Option<HwCaps> {
    let info = crate::arch::x86_64::cpuid::host();
    let cpuid_vmx = info
        .features
        .contains(crate::arch::x86_64::cpuid::CpuFeatures::VMX);
    if !cpuid_vmx {
        return None;
    }
    let snapshot = MsrSnapshot::from_reader(read_msr);
    Some(HwCaps::from_snapshot(&snapshot, true))
}

/// Tente d'activer VT-x sur le CPU courant.
///
/// Cette fonction est idempotente : un CPU déjà activé renvoie `Ok(())`.
/// Elle alloue une région d'activation (une frame 4 Kio) qui reste réservée
/// pour toute la vie du CPU.
pub fn activate_current_cpu() -> Result<(), InitError> {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    if cpu >= MAX_CPUS {
        return Err(InitError::NotSupported);
    }
    if ACTIVATED[cpu].load(Ordering::Acquire) {
        return Ok(());
    }

    let Some(mut caps) = detect() else {
        return Err(InitError::NotSupported);
    };

    // Autorise l'activation si le firmware ne l'a pas fait mais n'a pas
    // verrouillé le MSR. Si le MSR est verrouillé sans autorisation, il n'y a
    // rien à faire : c'est un réglage BIOS.
    if !caps.allowed {
        if caps.feature_control_locked {
            return Err(InitError::LockedByFirmware);
        }
        let feature_control = read_msr(caps::MSR_FEATURE_CONTROL);
        write_msr(
            caps::MSR_FEATURE_CONTROL,
            feature_control
                | caps::FEATURE_CONTROL_ENABLE_OUTSIDE_SMX
                | caps::FEATURE_CONTROL_LOCKED,
        );
        let Some(updated) = detect() else {
            return Err(InitError::NotSupported);
        };
        caps = updated;
        if !caps.allowed {
            return Err(InitError::LockedByFirmware);
        }
    }

    caps.validate()?;

    // Région d'activation : une frame zéro, 4 Kio alignée.
    let frame = crate::sync::with_irqs_disabled(|token| {
        crate::memory::frame::FrameAllocOptions::new()
            .purpose(crate::memory::frame::FramePurpose::PageTable)
            .allocate(token)
    })
    .map_err(|_| InitError::OutOfMemory)?;
    let phys = frame.start_address.as_u64();

    // L'identifiant de révision doit être écrit dans les 4 premiers octets.
    let virt = crate::memory::phys_to_virt(phys) as *mut u32;
    // SAFETY: la frame est exclusivement réservée, le HHDM la couvre, et
    // l'écriture porte sur ses 4 premiers octets.
    unsafe {
        core::ptr::write_volatile(virt, caps.control_block_revision);
    }

    // Active CR4.VMXE puis exécute l'activation matérielle.
    let cr4 = read_cr4();
    // SAFETY: le bit 13 est légal dès lors que CPUID l'annonce.
    unsafe {
        write_cr4(cr4 | CR4_VMXE);
    }
    // SAFETY: région initialisée, CPU annoncé compatible, interruptions
    // locales désactivées par l'appelant (composant de boot).
    let failed = unsafe { enable_virtualization(phys) };
    if failed {
        // SAFETY: restauration de l'état précédent.
        unsafe {
            write_cr4(cr4);
        }
        return Err(InitError::ActivationFailed);
    }

    REGIONS[cpu].store(phys, Ordering::Release);
    ACTIVATED[cpu].store(true, Ordering::Release);
    ACTIVE_CPUS.fetch_add(1, Ordering::AcqRel);
    log::info!(
        "[s9vm] activation matérielle OK (cpu {}, région {:#x})",
        cpu,
        phys
    );
    Ok(())
}

/// Exécute l'activation matérielle (`vmxon`) sur une région pré-initialisée.
///
/// # Safety
/// - le CPU doit annoncer VT-x et `CR4.VMXE` doit être positionné ;
/// - `region_phys` doit être une frame 4 Kio alignée, initialisée avec
///   l'identifiant de révision, exclusivement réservée ;
/// - les interruptions locales doivent être désactivées.
unsafe fn enable_virtualization(region_phys: u64) -> bool {
    let fail: u8;
    // SAFETY: contrat de la fonction.
    unsafe {
        core::arch::asm!(
            "vmxon qword ptr [{region}]",
            "setc {fail}",
            region = in(reg) &region_phys,
            fail = out(reg_byte) fail,
            options(nostack)
        );
    }
    fail != 0
}

/// Initialisation appelée par le composant de boot.
///
/// Ne panique jamais : toute indisponibilité est journalisée et le noyau
/// poursuit son démarrage.
pub fn init() {
    if !S9VM_ENABLED {
        log::info!("[s9vm] désactivé par configuration");
        return;
    }
    let Some(caps) = detect() else {
        log::info!("[s9vm] VT-x absent — virtualisation inactive");
        return;
    };
    CAPS_VALID.store(true, Ordering::Release);
    log::info!("[s9vm] capacités: {}", caps.summary());
    match caps.validate() {
        Ok(()) => {}
        Err(error) => {
            log::warn!(
                "[s9vm] plateforme non exploitable ({:?}) — virtualisation inactive",
                error
            );
            return;
        }
    }
    // L'activation consomme une frame : elle n'est tentée qu'au stage
    // `bootstrap`, après l'allocateur de frames.
    match activate_current_cpu() {
        Ok(()) => {
            log::info!(
                "[s9vm] prêt ({} CPU activé(s))",
                ACTIVE_CPUS.load(Ordering::Acquire)
            );
            selftest::maybe_run_from_boot_env(&caps);
        }
        Err(error) => log::warn!("[s9vm] activation impossible ({:?})", error),
    }
}

/// Nombre de CPU sur lesquels VT-x est actif.
pub fn active_cpu_count() -> u32 {
    ACTIVE_CPUS.load(Ordering::Acquire)
}

/// Vrai si les capacités ont été détectées au boot.
pub fn detected() -> bool {
    CAPS_VALID.load(Ordering::Acquire)
}

/// Adresse physique de la région d'activation d'un CPU, si activé.
pub fn activation_region(cpu: usize) -> Option<u64> {
    if cpu >= MAX_CPUS || !ACTIVATED[cpu].load(Ordering::Acquire) {
        return None;
    }
    Some(REGIONS[cpu].load(Ordering::Acquire))
}

/// Les constantes de pagination de memmap doivent rester alignées sur celles
/// du module de traduction.
const _: () = assert!(crate::s9vm::memmap::PAGE_SIZE == crate::s9vm::mmu::PAGE_SIZE);
const _: () = assert!(crate::s9vm::memmap::MAX_GPA == crate::s9vm::mmu::MAX_GPA);
