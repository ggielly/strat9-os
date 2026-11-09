//! s9vm — decoding of hardware exits (VM-exits).
//!
//! Pure module: it turns the raw `EXIT_REASON` value (and the associated
//! information fields) into usable structures, with no hardware access.
//! Host-testable (L2 tests).
//!
//! The reason numbers are those of the Intel documentation (SDM vol. 3C,
//! appendix C).

/// Decoded exit reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitReason {
    /// Reason number on 16 bits.
    pub reason: u16,
    /// True if the exit is actually a guest entry failure (`VMLAUNCH`
    /// or `VMRESUME` failed and control returned to the host).
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
    /// Decodes the raw value read from the exit field.
    pub const fn decode(raw: u32) -> Self {
        Self {
            reason: (raw & 0xFFFF) as u16,
            entry_failed: (raw & 0x8000_0000) != 0,
        }
    }

    /// Raw value as expected by the hardware fields.
    pub const fn raw(self) -> u32 {
        let mut raw = self.reason as u32;
        if self.entry_failed {
            raw |= 0x8000_0000;
        }
        raw
    }

    /// Functional class of the exit, used by the dispatcher.
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

/// Functional exit classes; the s9vm dispatcher routes on this
/// classification rather than on the raw number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// Guest exception or NMI.
    ExceptionOrNmi,
    /// External interrupt (host IRQ to reinject).
    ExternalInterrupt,
    /// Triple fault: the guest is dead, the host survives.
    TripleFault,
    /// Interrupt or NMI window to open.
    InterruptWindow,
    /// Guest `cpuid`.
    Cpuid,
    /// Guest `hlt`.
    Halt,
    /// Guest `pause` (wait loop).
    Pause,
    /// Access to an I/O port.
    IoPort,
    /// Access to a control register.
    ControlRegister,
    /// Access to a debug register.
    DebugRegister,
    /// MSR read/write.
    Msr,
    /// `monitor`/`mwait` or monitor trap flag.
    MonitorWait,
    /// APIC access (page, TPR, EOI).
    Apic,
    /// Second-level translation violation (unmapped GPA).
    EptViolation,
    /// Misconfigured second-level table (host bug).
    EptMisconfiguration,
    /// Guest time slice expired.
    PreemptionTimer,
    /// Call from the guest to the host.
    Call,
    /// Extended state (XSAVE/XCR0).
    ExtendedState,
    /// Guest TLB invalidation.
    Tlb,
    /// Time stamp counter.
    Timestamp,
    /// Cache instruction.
    Cache,
    /// Guest entry failure (guest state or MSR loading).
    EntryFailure,
    /// Unclassified: to be handled by the slow path.
    Unknown,
}

/// Reads the vector and event type from an interrupt information field
/// (`EXIT_INTERRUPT_INFO` / `IDT_VECTORING_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorEvent {
    /// Vector (0-255).
    pub vector: u8,
    /// Event type (SDM: 0 = external, 2 = NMI, 3 = hardware
    /// exception, 4 = software, 5 = privileged, 6 = software
    /// exception).
    pub kind: u8,
    /// Vector delivered with an error code.
    pub error_code_valid: bool,
    /// True if the event is valid (bit 31 of the information field).
    pub valid: bool,
}

impl VectorEvent {
    /// Decodes the interrupt information field.
    pub const fn decode(info: u32) -> Self {
        Self {
            vector: (info & 0xFF) as u8,
            kind: ((info >> 8) & 0x7) as u8,
            error_code_valid: (info & (1 << 11)) != 0,
            valid: (info & (1 << 31)) != 0,
        }
    }

    /// True if the event is an exception (hardware or software).
    pub const fn is_exception(self) -> bool {
        self.kind == 3 || self.kind == 6
    }

    /// True if the event is an NMI.
    pub const fn is_nmi(self) -> bool {
        self.kind == 2
    }
}

// --- Exit reasons (SDM appendix C) ---
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

/// Human-readable name of an exit reason (diagnostics).
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

/// Internal errno for unhandled exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Handle, then re-enter the guest.
    Resume,
    /// Reinject an event, then re-enter.
    Inject,
    /// Forward to the slow path (policy silo).
    Forward,
    /// Stop the vCPU.
    Stop,
}

/// Default routing policy of the base layer: what the kernel can handle
/// on its own (without policy or IPC).
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

/// Validity bit of the "VM-entry interruption information" field (`0x4016`).
pub const ENTRY_INTERRUPT_VALID: u32 = 1 << 31;
/// "External interrupt" type in the entry field (bits 10:8 = 0).
pub const ENTRY_INTERRUPT_TYPE_EXTERNAL: u32 = 0;
/// "Deliver an error code" bit of the entry field.
pub const ENTRY_INTERRUPT_DELIVER_ERROR: u32 = 1 << 11;

/// Encodes the "VM-entry interruption information" field to inject an
/// external interrupt of vector `vector` at the next guest entry.
///
/// The vector must fit in 8 bits; the caller validates the range. The
/// function is pure so that it can be tested on the host.
pub const fn external_interrupt_info(vector: u8) -> u32 {
    ENTRY_INTERRUPT_VALID | ENTRY_INTERRUPT_TYPE_EXTERNAL | (vector as u32)
}

/// "NMI" type in the entry field (bits 10:8 = 2).
pub const ENTRY_INTERRUPT_TYPE_NMI: u32 = 2 << 8;
/// Architectural vector of the NMI.
pub const NMI_VECTOR: u8 = 2;

/// Encodes the entry field to inject an NMI at the next entry.
pub const fn nmi_info() -> u32 {
    ENTRY_INTERRUPT_VALID | ENTRY_INTERRUPT_TYPE_NMI | (NMI_VECTOR as u32)
}
