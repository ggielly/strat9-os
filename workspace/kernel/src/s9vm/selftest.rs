//! s9vm — test de fumée matériel du moteur.
//!
//! Objectif : exécuter un invité minimal (mode long 64 bits, EPT active, deux
//! pages mappées) qui écrit un octet sur un port d'E/S puis exécute `hlt`, et
//! vérifier que le chemin complet fonctionne :
//!
//! 1. construction des tables invitées et des tables de second niveau ;
//! 2. chargement du bloc de contrôle ;
//! 3. entrée invitée (`vmlaunch`), sortie sur I/O, reprise, sortie sur `hlt` ;
//! 4. arrêt propre.
//!
//! Le test n'est lancé que si le noyau est activé sur VT-x et si l'option de
//! boot `s9vm.selftest=1` est présente. Il ne panique jamais : un échec est
//! journalisé et le boot continue.

use crate::memory::frame::{FrameAllocOptions, FramePurpose, PhysFrame};
use crate::s9vm::caps::HwCaps;
use crate::s9vm::exit::{ExitClass, ExitReason};
use crate::s9vm::guest::GuestState;
use crate::s9vm::vcpu::{SecondLevelMemory, Vcpu, VcpuError};

/// Taille de la zone invitée du test : 6 pages (tables + code + pile).
const GUEST_PAGES: u64 = 6;
const GPA_PML4: u64 = 0x0000;
const GPA_PDPT: u64 = 0x1000;
const GPA_PD: u64 = 0x2000;
const GPA_CODE: u64 = 0x3000;
const GPA_STACK: u64 = 0x4000;
const GPA_PT: u64 = 0x5000;
const ENTRY_POINT: u64 = GPA_CODE;
const STACK_TOP: u64 = GPA_STACK + 0x800;

/// Octet écrit par l'invité sur le port de test (0xE9).
const TEST_BYTE: u8 = 0x41;
/// Port d'E/S utilisé par le test (port de debug standard des émulateurs).
const TEST_PORT: u16 = 0xE9;

/// Erreurs du test de fumée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelftestError {
    OutOfMemory,
    Mmu,
    Vcpu(VcpuError),
    BadExit(&'static str),
    VmFail(u32),
}

impl From<VcpuError> for SelftestError {
    fn from(value: VcpuError) -> Self {
        Self::Vcpu(value)
    }
}

/// Résultat détaillé, journalisé par l'appelant.
pub struct SelftestReport {
    pub io_exits: u32,
    pub halt_exits: u32,
    pub total_exits: u32,
    pub observed_byte: Option<u8>,
}

/// Alloue une frame zéro pour l'invité.
fn alloc_frame() -> Result<PhysFrame, SelftestError> {
    crate::sync::with_irqs_disabled(|token| {
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
    })
    .map_err(|_| SelftestError::OutOfMemory)
}

/// Écrit une valeur 64 bits dans une frame via le HHDM.
fn write_u64(frame: &PhysFrame, offset: usize, value: u64) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: la frame fait 4 Kio et `offset` est un décalage valide.
    unsafe {
        core::ptr::write_volatile(base.add(offset) as *mut u64, value);
    }
}

/// Écrit des octets dans une frame via le HHDM.
fn write_bytes(frame: &PhysFrame, bytes: &[u8]) {
    let base = crate::memory::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    // SAFETY: la frame fait 4 Kio et `bytes` tient dans une page.
    unsafe {
        for (index, byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(base.add(index), *byte);
        }
    }
}

/// Exécute le test de fumée. Retourne un rapport ou une erreur.
pub fn run(caps: &HwCaps) -> Result<SelftestReport, SelftestError> {
    if !caps.can_run() {
        return Err(SelftestError::BadExit("platform cannot run"));
    }

    // Pages invitées : PML4, PDPT, PD, code, pile, PT.
    let pml4 = alloc_frame()?;
    let pdpt = alloc_frame()?;
    let pd = alloc_frame()?;
    let code = alloc_frame()?;
    let stack = alloc_frame()?;
    let pt = alloc_frame()?;

    // Tables de pagination invitées : identité GVA = GPA sur 6 pages.
    write_u64(&pml4, 0, pdpt.start_address.as_u64() | 0x3);
    write_u64(&pdpt, 0, pd.start_address.as_u64() | 0x3);
    write_u64(&pd, 0, pt.start_address.as_u64() | 0x3);
    for page in 0..GUEST_PAGES {
        let gpa = page * crate::s9vm::mmu::PAGE_SIZE;
        write_u64(&pt, page as usize * 8, gpa | 0x3);
    }

    // Code invité : mov al, imm8 ; out 0xE9, al ; hlt.
    write_bytes(&code, &[0xB0, TEST_BYTE, 0xE6, TEST_PORT as u8, 0xF4]);

    // Traduction de second niveau : GPA → HPA pour les 6 pages.
    let mut second_level = SecondLevelMemory::new().map_err(|_| SelftestError::Mmu)?;
    let pages = [
        (GPA_PML4, &pml4),
        (GPA_PDPT, &pdpt),
        (GPA_PD, &pd),
        (GPA_CODE, &code),
        (GPA_STACK, &stack),
        (GPA_PT, &pt),
    ];
    for (gpa, frame) in pages {
        second_level
            .map_4k(
                gpa,
                frame.start_address.as_u64(),
                crate::s9vm::mmu::Perms::read_write_execute(),
            )
            .map_err(|_| SelftestError::Mmu)?;
    }
    let pointer = second_level.pointer(caps);

    let mut vcpu = Vcpu::new(caps, pointer)?;
    let guest = GuestState::long_mode_64(ENTRY_POINT, STACK_TOP, GPA_PML4);

    // Validation locale avant l'entrée : un état refusé ici produirait un
    // « VM entry with invalid guest state » difficile à diagnostiquer.
    let fixed = crate::s9vm::guest::FixedBits {
        cr0_fixed0: caps.cr0_fixed0,
        cr0_fixed1: caps.cr0_fixed1,
        cr4_fixed0: caps.cr4_fixed0,
        cr4_fixed1: caps.cr4_fixed1,
    };
    if let Err(error) = guest.validate(&fixed, caps.unrestricted_guest) {
        log::warn!("[s9vm] état invité refusé par validate(): {:?}", error);
    }

    // SAFETY: VT-x est actif sur ce CPU (vérifié par l'appelant), les
    // interruptions sont désactivées au stage bootstrap, et le bloc de
    // contrôle vient d'être créé pour ce vCPU.
    unsafe {
        vcpu.load()?;
        vcpu.configure_host()?;
        vcpu.configure(caps, &guest)?;
    }

    let mut report = SelftestReport {
        io_exits: 0,
        halt_exits: 0,
        total_exits: 0,
        observed_byte: None,
    };

    let mut outcome: Result<(), SelftestError> = Ok(());
    for _ in 0..16 {
        // SAFETY: contrat de `run` (bloc chargé, IRQ coupées).
        let exit = match unsafe { vcpu.run() } {
            Ok(exit) => exit,
            Err(error) => {
                // SAFETY: le bloc de contrôle est encore chargé ; diagnostic
                // utile pour les échecs `VmFail(8/9)`.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.host_diagnostics());
                }
                outcome = Err(SelftestError::from(error));
                break;
            }
        };
        report.total_exits += 1;
        let class = ExitReason::decode(exit.raw_reason).class();
        match class {
            ExitClass::IoPort => {
                report.io_exits += 1;
                // Qualification d'E/S : port dans les bits 16..31.
                let port = ((exit.qualification >> 16) & 0xFFFF) as u16;
                if port == TEST_PORT {
                    report.observed_byte = Some((vcpu.guest().rax & 0xFF) as u8);
                }
                // Pour une sortie sur instruction d'E/S, le processeur a déjà
                // positionné `GUEST_RIP` sur l'instruction suivante : ne pas
                // l'avancer à nouveau, sinon la reprise saute le `hlt`.
                log::info!(
                    "[s9vm] sortie E/S port={:#x} octet={:?} rip={:#x} len={}",
                    port,
                    report.observed_byte,
                    vcpu.guest().rip,
                    exit.instruction_length
                );
            }
            ExitClass::Halt => {
                report.halt_exits += 1;
                break;
            }
            ExitClass::ExternalInterrupt | ExitClass::InterruptWindow => {
                // Au boot, les interruptions hôte sont masquées : on reprend
                // simplement l'invité.
            }
            ExitClass::EntryFailure => {
                // SAFETY: le bloc de contrôle est encore chargé ; diagnostic
                // du champ invité refusé par le processeur.
                unsafe {
                    log::warn!("[s9vm] {}", vcpu.guest_diagnostics());
                }
                outcome = Err(SelftestError::BadExit("entry failure"));
                break;
            }
            _ => {
                outcome = Err(SelftestError::BadExit("unexpected exit"));
                break;
            }
        }
    }

    // SAFETY: le vCPU n'est plus actif ; on décharge son bloc de contrôle.
    unsafe {
        let _ = vcpu.clear();
    }

    match outcome {
        Ok(()) if report.io_exits >= 1 && report.halt_exits >= 1 => Ok(report),
        Ok(()) => Err(SelftestError::BadExit("guest did not reach hlt")),
        Err(error) => Err(error),
    }
}

/// Lance le test si l'option de boot `s9vm.selftest=1` est présente.
///
/// Ne fait rien si VT-x n'est pas actif. Ne panique jamais.
pub fn maybe_run_from_boot_env(caps: &HwCaps) {
    let enabled = crate::boot_args()
        .and_then(|args| args.env_get("s9vm.selftest"))
        .map(|value| value == "1" || value == "true")
        .unwrap_or(false);
    if !enabled {
        return;
    }
    log::info!("[s9vm] test de fumée matériel demandé");
    match run(caps) {
        Ok(report) => log::info!(
            "[s9vm] selftest PASS: exits={} io={} hlt={} byte={:?}",
            report.total_exits,
            report.io_exits,
            report.halt_exits,
            report.observed_byte
        ),
        Err(error) => log::warn!("[s9vm] selftest FAIL: {:?}", error),
    }
}
