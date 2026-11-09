//! s9vm — décodage des sorties matérielles (VM-exits).
//!
//! Module pur : il transforme la valeur brute `EXIT_REASON` (et les champs
//! d'information associés) en structures exploitables, sans accès matériel.
//! Testable sur l'hôte (tests L2).
//!
//! Les numéros de raison sont ceux de la documentation Intel (SDM vol. 3C,
//! appendix C).

/// Raison de sortie décodée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitReason {
    /// Numéro de raison sur 16 bits.
    pub reason: u16,
    /// Vrai si la sortie est en réalité un échec d'entrée invité (`VMLAUNCH`
    /// ou `VMRESUME` a échoué et on est revenu à l'hôte).
    pub entry_failed: bool,
}

impl Default for ExitReason {
    fn default() -> Self {
        Self {
            reason: 0,
            entry_failed: false,
        }
    }
}

impl ExitReason {
    /// Décode la valeur brute lue dans le champ de sortie.
    pub const fn decode(raw: u32) -> Self {
        Self {
            reason: (raw & 0xFFFF) as u16,
            entry_failed: (raw & 0x8000_0000) != 0,
        }
    }

    /// Valeur brute telle qu'attendue par les champs matériels.
    pub const fn raw(self) -> u32 {
        let mut raw = self.reason as u32;
        if self.entry_failed {
            raw |= 0x8000_0000;
        }
        raw
    }

    /// Classe fonctionnelle de la sortie, utilisée par le dispatcher.
    pub const fn class(self) -> ExitClass {
        if self.entry_failed {
            return ExitClass::EntryFailure;
        }
        match self.reason {
            EXCEPTION_OR_NMI => ExitClass::ExceptionOrNmi,
            EXTERNAL_INTERRUPT => ExitClass::ExternalInterrupt,
            TRIPLE_FAULT => ExitClass::TripleFault,
            PENDING_INTERRUPT => ExitClass::InterruptWindow,
            NMI_WINDOW => ExitClass::InterruptWindow,
            CPUID => ExitClass::Cpuid,
            HLT => ExitClass::Halt,
            PAUSE => ExitClass::Pause,
            IO_INSTRUCTION => ExitClass::IoPort,
            CONTROL_REGISTER => ExitClass::ControlRegister,
            DR_ACCESS => ExitClass::DebugRegister,
            MSR_READ | MSR_WRITE => ExitClass::Msr,
            INVALID_GUEST_STATE | MSR_LOAD_FAILURE => ExitClass::EntryFailure,
            MWAIT | MONITOR_TRAP_FLAG | MONITOR_INSTRUCTION => ExitClass::MonitorWait,
            TPR_BELOW_THRESHOLD | EOI_INDUCED => ExitClass::Apic,
            APIC_ACCESS | APIC_WRITE => ExitClass::Apic,
            EPT_VIOLATION => ExitClass::EptViolation,
            EPT_MISCONFIGURATION => ExitClass::EptMisconfiguration,
            PREEMPTION_TIMER => ExitClass::PreemptionTimer,
            VMCALL => ExitClass::Call,
            XSETBV | XSAVES | XRSTORS => ExitClass::ExtendedState,
            INVLPG => ExitClass::Tlb,
            RDTSC | RDTSCP | RDPMC => ExitClass::Timestamp,
            INVD | WBINVD => ExitClass::Cache,
            _ => ExitClass::Unknown,
        }
    }
}

/// Classes fonctionnelles de sortie ; le dispatcher de s9vm route sur cette
/// classification plutôt que sur le numéro brut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// Exception invité ou NMI.
    ExceptionOrNmi,
    /// Interruption externe (IRQ hôte à réinjecter).
    ExternalInterrupt,
    /// Triple faute : l'invité est mort, l'hôte survit.
    TripleFault,
    /// Fenêtre d'interruption ou de NMI à ouvrir.
    InterruptWindow,
    /// `cpuid` invité.
    Cpuid,
    /// `hlt` invité.
    Halt,
    /// `pause` invité (boucle d'attente).
    Pause,
    /// Accès à un port d'E/S.
    IoPort,
    /// Accès à un registre de contrôle.
    ControlRegister,
    /// Accès à un registre de débogage.
    DebugRegister,
    /// Lecture/écriture de MSR.
    Msr,
    /// `monitor`/`mwait` ou drapeau de surveillance.
    MonitorWait,
    /// Accès APIC (page, TPR, EOI).
    Apic,
    /// Violation de traduction de second niveau (GPA non mappée).
    EptViolation,
    /// Table de second niveau mal configurée (bug hôte).
    EptMisconfiguration,
    /// Tranche de temps invité expirée.
    PreemptionTimer,
    /// Appel de l'invité vers l'hôte.
    Call,
    /// État étendu (XSAVE/XCR0).
    ExtendedState,
    /// Invalidation TLB invité.
    Tlb,
    /// Compteur de temps.
    Timestamp,
    /// Instruction de cache.
    Cache,
    /// Échec d'entrée invité (état invité ou chargement MSR).
    EntryFailure,
    /// Non classée : à traiter par le chemin lent.
    Unknown,
}

/// Lit le vecteur et le type d'événement d'un champ d'information
/// d'interruption (`EXIT_INTERRUPT_INFO` / `IDT_VECTORING_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorEvent {
    /// Vecteur (0-255).
    pub vector: u8,
    /// Type d'événement (SDM : 0 = externe, 2 = NMI, 3 = exception
    /// matérielle, 4 = logicielle, 5 = privilégiée, 6 = exception
    /// logicielle).
    pub kind: u8,
    /// Vecteur délivré avec un code d'erreur.
    pub error_code_valid: bool,
    /// Vrai si l'événement est valide (bit 31 de l'information).
    pub valid: bool,
}

impl VectorEvent {
    /// Décode le champ d'information d'interruption.
    pub const fn decode(info: u32) -> Self {
        Self {
            vector: (info & 0xFF) as u8,
            kind: ((info >> 8) & 0x7) as u8,
            error_code_valid: (info & (1 << 11)) != 0,
            valid: (info & (1 << 31)) != 0,
        }
    }

    /// Vrai si l'événement est une exception (matérielle ou logicielle).
    pub const fn is_exception(self) -> bool {
        self.kind == 3 || self.kind == 6
    }

    /// Vrai si l'événement est un NMI.
    pub const fn is_nmi(self) -> bool {
        self.kind == 2
    }
}

// --- Raisons de sortie (SDM appendix C) ---
pub const EXCEPTION_OR_NMI: u16 = 0;
pub const EXTERNAL_INTERRUPT: u16 = 1;
pub const TRIPLE_FAULT: u16 = 2;
pub const INIT_SIGNAL: u16 = 3;
pub const SIPI: u16 = 4;
pub const SMI: u16 = 5;
pub const PENDING_INTERRUPT: u16 = 7;
pub const NMI_WINDOW: u16 = 8;
pub const TASK_SWITCH: u16 = 9;
pub const CPUID: u16 = 10;
pub const GETSEC: u16 = 11;
pub const HLT: u16 = 12;
pub const INVD: u16 = 13;
pub const INVLPG: u16 = 14;
pub const RDPMC: u16 = 15;
pub const RDTSC: u16 = 16;
pub const RSM: u16 = 17;
pub const VMCALL: u16 = 18;
pub const VMCLEAR: u16 = 19;
pub const VMLAUNCH: u16 = 20;
pub const VMPTRLD: u16 = 21;
pub const VMPTRST: u16 = 22;
pub const VMREAD: u16 = 23;
pub const VMWRITE: u16 = 24;
pub const VMXOFF: u16 = 25;
pub const VMXON: u16 = 26;
pub const CONTROL_REGISTER: u16 = 28;
pub const DR_ACCESS: u16 = 29;
pub const IO_INSTRUCTION: u16 = 30;
pub const MSR_READ: u16 = 31;
pub const MSR_WRITE: u16 = 32;
pub const INVALID_GUEST_STATE: u16 = 33;
pub const MSR_LOAD_FAILURE: u16 = 34;
pub const MWAIT: u16 = 36;
pub const MONITOR_TRAP_FLAG: u16 = 37;
pub const MONITOR_INSTRUCTION: u16 = 39;
pub const PAUSE: u16 = 40;
pub const MCE_DURING_ENTRY: u16 = 41;
pub const TPR_BELOW_THRESHOLD: u16 = 43;
pub const APIC_ACCESS: u16 = 44;
pub const EOI_INDUCED: u16 = 45;
pub const GDTR_IDTR_ACCESS: u16 = 46;
pub const LDTR_TR_ACCESS: u16 = 47;
pub const EPT_VIOLATION: u16 = 48;
pub const EPT_MISCONFIGURATION: u16 = 49;
pub const INVEPT: u16 = 50;
pub const RDTSCP: u16 = 51;
pub const PREEMPTION_TIMER: u16 = 52;
pub const INVVPID: u16 = 53;
pub const WBINVD: u16 = 54;
pub const XSETBV: u16 = 55;
pub const APIC_WRITE: u16 = 56;
pub const RDRAND: u16 = 57;
pub const INVPCID: u16 = 58;
pub const VMFUNC: u16 = 59;
pub const ENCLS: u16 = 60;
pub const RDSEED: u16 = 61;
pub const PML_FULL: u16 = 62;
pub const XSAVES: u16 = 63;
pub const XRSTORS: u16 = 64;

/// Nom lisible d'une raison de sortie (diagnostic).
pub const fn reason_name(reason: u16) -> &'static str {
    match reason {
        0 => "exception-or-nmi",
        1 => "external-interrupt",
        2 => "triple-fault",
        3 => "init",
        4 => "sipi",
        5 => "smi",
        7 => "interrupt-window",
        8 => "nmi-window",
        9 => "task-switch",
        10 => "cpuid",
        11 => "getsec",
        12 => "hlt",
        13 => "invd",
        14 => "invlpg",
        15 => "rdpmc",
        16 => "rdtsc",
        17 => "rsm",
        18 => "call",
        19 => "clear-control-block",
        20 => "launch",
        21 => "load-control-block",
        22 => "store-control-block",
        23 => "read-control-block",
        24 => "write-control-block",
        25 => "disable",
        26 => "enable",
        28 => "control-register",
        29 => "debug-register",
        30 => "io-instruction",
        31 => "msr-read",
        32 => "msr-write",
        33 => "invalid-guest-state",
        34 => "msr-load-failure",
        36 => "mwait",
        37 => "monitor-trap-flag",
        39 => "monitor",
        40 => "pause",
        41 => "machine-check-during-entry",
        43 => "tpr-below-threshold",
        44 => "apic-access",
        45 => "eoi",
        46 => "gdtr-idtr-access",
        47 => "ldtr-tr-access",
        48 => "second-level-violation",
        49 => "second-level-misconfiguration",
        50 => "invalidate-second-level",
        51 => "rdtscp",
        52 => "preemption-timer",
        53 => "invalidate-vpid",
        54 => "wbinvd",
        55 => "xsetbv",
        56 => "apic-write",
        57 => "rdrand",
        58 => "invpcid",
        59 => "vm-function",
        60 => "encls",
        61 => "rdseed",
        62 => "pml-full",
        63 => "xsaves",
        64 => "xrstors",
        _ => "unknown",
    }
}

/// Errno interne pour les sorties non gérées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Traiter puis rentrer dans l'invité.
    Resume,
    /// Réinjecter un événement puis rentrer.
    Inject,
    /// Transférer au chemin lent (silo de politique).
    Forward,
    /// Arrêter le vCPU.
    Stop,
}

/// Politique de routage par défaut du socle : ce que le noyau sait traiter
/// seul (sans policy ni IPC).
pub const fn default_action(class: ExitClass) -> ExitAction {
    match class {
        ExitClass::ExceptionOrNmi
        | ExitClass::ExternalInterrupt
        | ExitClass::InterruptWindow
        | ExitClass::Halt
        | ExitClass::Pause
        | ExitClass::Apic
        | ExitClass::PreemptionTimer
        | ExitClass::Tlb
        | ExitClass::Timestamp
        | ExitClass::Call => ExitAction::Resume,
        ExitClass::TripleFault | ExitClass::EntryFailure => ExitAction::Stop,
        ExitClass::Cpuid
        | ExitClass::Msr
        | ExitClass::IoPort
        | ExitClass::ControlRegister
        | ExitClass::DebugRegister
        | ExitClass::MonitorWait
        | ExitClass::ExtendedState
        | ExitClass::Cache
        | ExitClass::EptViolation
        | ExitClass::EptMisconfiguration
        | ExitClass::Unknown => ExitAction::Forward,
    }
}

/// Bit de validité du champ « VM-entry interruption information » (`0x4016`).
pub const ENTRY_INTERRUPT_VALID: u32 = 1 << 31;
/// Type « interruption externe » dans le champ d'entrée (bits 10:8 = 0).
pub const ENTRY_INTERRUPT_TYPE_EXTERNAL: u32 = 0;
/// Bit « délivrer un code d'erreur » du champ d'entrée.
pub const ENTRY_INTERRUPT_DELIVER_ERROR: u32 = 1 << 11;

/// Encode le champ « VM-entry interruption information » pour injecter une
/// interruption externe de vecteur `vector` à la prochaine entrée invitée.
///
/// Le vecteur doit tenir sur 8 bits ; l'appelant valide la plage. La fonction
/// est pure pour être testable sur l'hôte.
pub const fn external_interrupt_info(vector: u8) -> u32 {
    ENTRY_INTERRUPT_VALID | ENTRY_INTERRUPT_TYPE_EXTERNAL | (vector as u32)
}
