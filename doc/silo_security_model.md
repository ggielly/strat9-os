# Strat9-OS: Silo Security & IPC Coloration Model

## 1. Overview

Strat9-OS implements a multi-layered security model designed for a microkernel architecture. It distinguishes between **Identity** (who you are), **Capability** (what resources you own), and **Privilege** (what actions you are trusted to perform).

This document details the hybrid approach combining **SID Hierarchy**, **Octal Privilege Modes**, **IPC Coloration**, **Capability Handles**, **Dynamic Pledge/Unveil**, **Family Profiles**, and **Audit Trail**.

### Container Model: Silos and Strates

A **Silo** is the security container — it owns a unique SID, an Octal Mode, a Family, and a CSpace of Capabilities. It is the unit of isolation, exactly like a FreeBSD Jail or an Erlang node.

A **Strate** is a lightweight process running *inside* a Silo. A Silo contains one or more Strates. The user decides which Strates compose a Silo — it is their responsibility.

```
Silo (security boundary)
├── SID, Mode, Family, CSpace  ← kernel-enforced
└── Strates (1..N executables)
      ├── strate-wasm-runtime   ← implicit mutual trust
      └── strate-wasm-jit       ← direct communication, no kernel hop
```

**Intra-silo communication** is direct (shared memory, message channels) — no kernel IPC, no coloration label, no capability check. Strates within the same Silo share the same SID and capabilities. This is a deliberate performance and usability choice, following the Erlang node model: *the node is the trust boundary, not the process*.

**Inter-silo communication** always goes through the kernel IPC path with full label stamping, capability validation, and audit.

> **v2.0 note:** A hardened intra-silo mode will be introduced in v2.0, routing Strate-to-Strate messages through the kernel for auditing and fine-grained isolation. v1.0 chose speed and simplicity.

---

### Design Inspirations

| Concept | Historical Inspiration |
| :--- | :--- |
| Silo/Strate Container Model | **Erlang** OTP nodes (1998), **FreeBSD Jails** (1999) |
| Capability Handles | **seL4** CSpace + **Capsicum** (FreeBSD 9.0, 2012) |
| IPC Labels | **Solaris Trusted Extensions** (2006) + **Biba Integrity Model** (1977) |
| Pledge / Unveil | **OpenBSD** `pledge(2)` (2015) / `unveil(2)` (2018) |
| Family Profiles | **FreeBSD Jails** (1999) + **Solaris Zones** (2004) + **MINIX 3** Reincarnation Server |
| Audit Trail | **Solaris BSM** (1992) / **FreeBSD auditd** |

---

## 2. Silo Identity (SID) Hierarchy

Silo IDs are assigned based on their role and trust level. This simplifies identification and allows the kernel to apply global policies based on ID ranges.

| SID Range | Tier | Trust Level | Description |
| :--- | :--- | :--- | :--- |
| **1 - 9** | **Critical** | Full Trust | Core kernel services, `strate-init`, and IPC Registry. |
| **10 - 999** | **System** | High Trust | System Strates (Drivers, FS, Net Stack, Wasm Runtime). |
| **1000+** | **User** | Untrusted | User applications, isolated Wasm silos, and temporary tasks. |

### Key Rules

*   **SID < 10:** Can send administrative commands to any other silo.
*   **SID 10-999:** Can perform hardware-related operations if permitted by Octal Mode.
*   **SID 1000+:** Strictly sandboxed; requires explicit capabilities for any interaction.

### Rust Representation

```rust
/// Silo identity tier, derived from the numeric SID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SiloTier {
    /// SID 1–9: Full trust, kernel-level services.
    Critical = 0,
    /// SID 10–999: System services (drivers, FS, net).
    System   = 1,
    /// SID 1000+: Untrusted user applications.
    User     = 2,
}

/// A Silo ID with its derived tier.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SiloId {
    pub sid: u32,
    pub tier: SiloTier,
}

impl SiloId {
    pub const fn new(sid: u32) -> Self {
        let tier = match sid {
            1..=9     => SiloTier::Critical,
            10..=999  => SiloTier::System,
            _         => SiloTier::User,
        };
        Self { sid, tier }
    }
}
```

---

## 3. The Octal Privilege Mode

Each silo is assigned a three-digit octal mode `[C][H][R]` that defines its behavioral profile.

### Digit 1: Control (C) — Silo Management

*   `4` (List): Permission to query the state of other silos (`strate ls`).
*   `2` (Stop): Permission to stop or kill other silos (`strate stop`).
*   `1` (Spawn): Permission to create new silos (`strate spawn`).
*   *Example: `7` (Orchestrator), `0` (Isolated Application).*

### Digit 2: Hardware (H) — Bedrock Access

*   `4` (Interrupt): Permission to register IRQ handlers.
*   `2` (I/O): Permission to access I/O ports or MMIO ranges.
*   `1` (DMA): Permission to perform direct physical memory access.
*   *Example: `6` (Standard Driver), `0` (Pure Software).*

### Digit 3: Registry (R) — Plan 9 Namespace (`/srv`)

*   `4` (Lookup): Permission to browse the service registry.
*   `2` (Bind): Permission to register a service port in `/srv`.
*   `1` (Proxy): Permission to act as an IPC interceptor/middleware.
*   *Example: `6` (Standard Service), `4` (Consumer Only).*

### Rust Representation

```rust
use bitflags::bitflags;

bitflags! {
    /// Control digit — Silo management permissions.
    #[repr(transparent)]
    pub struct ControlMode: u8 {
        const LIST  = 0b100; // 4 — query other silos
        const STOP  = 0b010; // 2 — stop/kill other silos
        const SPAWN = 0b001; // 1 — create new silos
    }
}

bitflags! {
    /// Hardware digit — Bedrock (Ring 0) access permissions.
    #[repr(transparent)]
    pub struct HardwareMode: u8 {
        const INTERRUPT = 0b100; // 4 — register IRQ handlers
        const IO        = 0b010; // 2 — I/O ports or MMIO
        const DMA       = 0b001; // 1 — direct physical memory access
    }
}

bitflags! {
    /// Registry digit — Plan 9 namespace (`/srv`) permissions.
    #[repr(transparent)]
    pub struct RegistryMode: u8 {
        const LOOKUP = 0b100; // 4 — browse service registry
        const BIND   = 0b010; // 2 — register a service port
        const PROXY  = 0b001; // 1 — IPC interceptor/middleware
    }
}

/// The complete three-digit octal mode `[C][H][R]`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct OctalMode {
    pub control:  ControlMode,
    pub hardware: HardwareMode,
    pub registry: RegistryMode,
}

impl OctalMode {
    /// Parse from a numeric octal value, e.g. `0o764`.
    pub const fn from_octal(val: u16) -> Self {
        Self {
            control:  ControlMode::from_bits_truncate(((val >> 6) & 0o7) as u8),
            hardware: HardwareMode::from_bits_truncate(((val >> 3) & 0o7) as u8),
            registry: RegistryMode::from_bits_truncate((val & 0o7) as u8),
        }
    }

    /// Returns `true` if `self` is a subset of `other` (for pledge checks).
    pub const fn is_subset_of(&self, other: &OctalMode) -> bool {
        self.control.bits()  & !other.control.bits()  == 0
        && self.hardware.bits() & !other.hardware.bits() == 0
        && self.registry.bits() & !other.registry.bits() == 0
    }
}
```

---

## 4. IPC Coloration (Structured Labels)

The kernel "stamps" every 64-byte IPC message with a structured **Label**, representing the sender's effective privilege level. This metadata is stored in the message header and is **immutable by userspace**.

### 4.1 Label Structure

Inspired by **Solaris Trusted Extensions** Multi-Level Security labels, the IPC color is extended from a simple 3-color tag into a structured 14-bit label:

```rust
/// IPC security label, stamped by the kernel on every message.
/// Packed into 32 bits for embedding in the 64-byte IPC header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IpcLabel {
    /// Trust tier: Critical(0), System(1), User(2).
    /// Derived from SID range. 2 bits.
    pub tier: SiloTier,
    /// Strate family tag. 4 bits.
    pub family: StrateFamily,
    /// Sub-compartment within the family (e.g. disk0, eth0, or a Wasm app ID).
    /// 26 bits. Allowing millions of dynamically isolated Wasm apps.
    pub compartment: u32,
}

/// Strate family tag — identifies the functional domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StrateFamily {
    SYS  = 0,  // Core system services
    DRV  = 1,  // Hardware drivers
    FS   = 2,  // Filesystem services
    NET  = 3,  // Network stack
    WASM = 4,  // Wasm runtime
    USR  = 5,  // User applications
}
```

### 4.2 Color Mapping (Backward Compatibility)

The label's `tier` field maps to the legacy color names:

| Color | Tier | Required SID | Description |
| :--- | :--- | :--- | :--- |
| <span style="color:red">**RED**</span> | Critical | < 10 | **Administrative.** Bypasses access control, but receiver still validates message format. |
| <span style="color:blue">**BLUE**</span> | System | 10 - 999 | **System.** Trusted for resource manipulation (Disk/Net). |
| <span style="color:green">**GREEN**</span> | User | 1000+ | **User.** Requires Capability validation by the receiver. |

> **Note (security hardening):** Even RED messages must have their format/content validated by the receiver. Trust means *bypass access control*, not *absence of validation*. A bug in `strate-init` should not be able to send a malformed RED message that crashes a receiver.

### 4.3 Label Assignment Mechanism

When `sys_ipc_send` is called, the kernel:
1.  Identifies the `sender_sid` and its `OctalMode`.
2.  Constructs the `IpcLabel` from the sender's SID tier, family, and compartment.
3.  Stamps the label into the message header (immutable).
4.  The receiver checks the label to apply its policy.

### 4.4 IPC Flow Rules (Biba Integrity Model Inspired)

Inspired by the **Biba Integrity Model** (*no read down, no write up* in terms of trust) adapted for message-passing integrity:

*   A **USER** silo cannot send directly to a **DRV** silo — it must go through an intermediary (VFS, Net stack). The higher-privilege system does not blindly trust or accept inputs from lower levels without a designated intermediary doing the validation.
*   The `allowed_ipc` field in Family Profiles (see Section 7) restricts which families can communicate.

```rust
impl IpcLabel {
    /// Check if a message from `sender` to `receiver` is allowed.
    /// Enforces family-level IPC isolation.
    pub fn is_flow_allowed(
        sender: &IpcLabel,
        receiver: &IpcLabel,
        sender_profile: &FamilyProfile,
    ) -> bool {
        // Critical tier can send to anyone
        if sender.tier == SiloTier::Critical {
            return true;
        }
        // Check family-level allowed IPC list
        sender_profile.allowed_ipc.contains(&receiver.family)
    }
}
```

---

## 5. Capability Handles (seL4 + Capsicum)

Inspired by **seL4** CSpace and **FreeBSD Capsicum** `cap_rights_limit()`.

The Octal Mode defines the *ceiling* (what a silo is allowed to hold). Capabilities are the *mechanism* (specific grants on specific objects). The kernel refuses to grant a capability that exceeds the silo's mode ceiling.

### 5.1 CapHandle Structure (Kernel internal)

Capabilities are stored entirely in kernel space to prevent tampering. Userspace processes only possess index numbers (similar to file descriptors) that reference slot entries in their CSpace.

```rust
/// A local index referencing a capability in a silo's CSpace.
/// Userspace uses this type; it never sees the raw capability.
pub type CapIndex = u32;

/// A kernel-managed capability handle, granting access to a specific object.
/// Stored in the kernel's memory space.
///
/// Inspired by:
/// - seL4: CSpace slots, badged endpoints, generation counters.
/// - Capsicum (FreeBSD): rights attenuation on file descriptors.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CapEntry {
    /// Target object identifier. For finer revocation granularity, this may point
    /// to an intermediary 'Shadow Object' or node in a derivation tree.
    pub object_id: u64,
    /// Bitmask of allowed operations on this object.
    pub rights: CapRights,
    /// Kernel-immutable tag identifying who granted this capability.
    /// Set by the kernel during `sys_cap_grant`. Cannot be forged.
    pub badge: u32,
    /// Tree node reference to trace the lineage of this capability for
    /// precise revocation of this capability and its children.
    pub derivation_node_id: u64,
}
```

### 5.2 Capability Rights

```rust
bitflags! {
    /// Rights bitmask for capability handles.
    #[repr(transparent)]
    pub struct CapRights: u16 {
        const READ   = 1 << 0;
        const WRITE  = 1 << 1;
        const EXEC   = 1 << 2;
        const GRANT  = 1 << 3;  // Can delegate this cap to another silo
        const REVOKE = 1 << 4;  // Can revoke caps derived from this one
        const SEEK   = 1 << 5;
        const MMAP   = 1 << 6;
        const IOCTL  = 1 << 7;
    }
}
```

### 5.3 Capability Operations

```rust
/// Kernel syscalls for capability management.
pub trait CapabilityManager {
    /// Grant a capability to a target silo.
    /// The granted rights must be a subset of the granter's rights (attenuation).
    /// The kernel stamps the `badge` with the granter's SID.
    /// Returns the local `CapIndex` for the capability in the target silo's CSpace.
    /// Returns an error if the target silo's OctalMode ceiling forbids holding this type.
    fn sys_cap_grant(
        &mut self,
        target_sid: u32,
        granter_cap_index: CapIndex,
        attenuated_rights: CapRights,
    ) -> Result<CapIndex, CapError>;

    /// Revoke a capability and all capabilities derived from it.
    /// The kernel walks the capability derivation tree and invalidates the target
    /// node and all its children.
    fn sys_cap_revoke(&mut self, cap_index: CapIndex) -> Result<(), CapError>;

    /// Read-only inspection of a capability's metadata. 
    /// Allows userspace to check rights without gaining access to the kernel structure.
    fn sys_cap_inspect(&self, cap_index: CapIndex) -> Result<CapEntry, CapError>;
}

#[derive(Debug)]
pub enum CapError {
    /// Target silo's OctalMode does not permit holding this capability type.
    ModeCeilingViolation,
    /// Requested rights exceed the granter's own rights (attenuation failure).
    RightsEscalation,
    /// Handle index is invalid or out of bounds.
    InvalidHandle,
}
```

### 5.4 Attenuation Example

```rust
// A filesystem silo (SID=100, mode=066) holds a full read/write cap on disk0 (index 5)
// The kernel's CSpace tracks: Read|Write|Grant, Badge=100

// The FS silo delegates a read-only view to a user backup tool (SID=1010).
// This is rights attenuation — the tool gets strictly fewer rights.
let backup_cap_index = cap_manager.sys_cap_grant(
    1010,
    5, // Index of the FS silo's disk0 capability
    CapRights::READ,  // attenuated: read only, no GRANT (cannot re-delegate)
)?;
// Returns a CapIndex (e.g. `3`) in the backup tool's CSpace.
// The kernel records that the FS silo was the granter in its derivation tree.
// The user tool cannot elevate this back to READ|WRITE.
```

### 5.5 Interaction with Octal Mode

The mode is the **ceiling**, capabilities are the **mechanism**:

| Silo Mode | Can Hold Caps For | Example |
| :--- | :--- | :--- |
| `x6x` | IRQ + I/O port objects | VirtIO-blk driver |
| `x0x` | No hardware caps at all | Pure software / Wasm silo |
| `xx6` | Registry endpoints | Filesystem, Net stack |
| `xx4` | Read-only registry lookups | User application |

The kernel **refuses** `sys_cap_grant` if the target's mode ceiling does not include the capability type.

---

## 6. Pledge & Unveil (OpenBSD-style)

Inspired by **OpenBSD** `pledge(2)` (2015) and `unveil(2)` (2018): a silo can **irrevocably reduce** its own privileges at runtime. This enables the *privilege separation* pattern — a silo starts with broad rights for initialization, then self-restricts.

### 6.1 Syscalls

```rust
/// Irrevocably reduce the silo's Octal Mode.
/// `new_mode` must be a strict subset of the current mode.
/// Once pledged, the silo can never regain the dropped bits.
///
/// Inspired by OpenBSD pledge(2).
pub fn sys_silo_pledge(new_mode: OctalMode) -> Result<(), PledgeError>;

/// Restrict the silo's visible Plan 9 namespace.
/// Only the declared paths remain accessible. Irrevocable.
/// Multiple calls further narrow the view (intersection semantics).
///
/// Inspired by OpenBSD unveil(2).
pub fn sys_silo_unveil(path: &str, rights: CapRights) -> Result<(), UnveilError>;

/// Enter full sandbox mode (Capsicum `cap_enter()` equivalent).
/// After this call, the silo can only use already-open capability handles.
/// No new registry lookups, no new grants. Irrevocable.
pub fn sys_silo_enter_sandbox() -> Result<(), SandboxError>;
```

### 6.2 Pledge Validation

```rust
impl OctalMode {
    /// Apply a pledge: reduce mode to `new_mode`.
    /// Returns error if `new_mode` is not a subset of the current mode.
    pub fn pledge(&mut self, new_mode: OctalMode) -> Result<(), PledgeError> {
        if !new_mode.is_subset_of(self) {
            return Err(PledgeError::Escalation);
        }
        *self = new_mode;
        Ok(())
    }
}

#[derive(Debug)]
pub enum PledgeError {
    /// Attempted to pledge to a mode that includes bits not in the current mode.
    Escalation,
}
```

### 6.3 Usage Example: ELF Loader

```rust
// The ELF loader (SID=5, mode=776) starts with broad privileges:
// Control: 7 (list + stop + spawn), Hardware: 7 (irq + io + dma), Registry: 6 (lookup + bind)
// It needs these to map pages, load binaries, and register the loaded silo.

fn loader_main() {
    // Phase 1: Load the binary with full privileges
    let binary = fs_read("/srv/fs/bin/hello");
    let pages = map_pages(binary);
    let new_silo = spawn_silo(pages);

    // Phase 2: Work is done — self-restrict like OpenBSD sshd does after fork
    sys_silo_pledge(OctalMode::from_octal(0o004)).unwrap();
    // Now the loader can only do registry lookups.
    // It cannot spawn, stop, or access hardware ever again.

    // Phase 3: Optionally enter full sandbox
    sys_silo_enter_sandbox().unwrap();
    // Now it cannot even do registry lookups — only use existing handles.
}
```

---

## 7. Strate Family Profiles (Jails/Zones)

Inspired by **FreeBSD Jails** (1999) and **Solaris Zones** (2004), families are no longer just descriptive labels — they are **profiles with policy enforcement**, applied in two distinct layers.

### Enforcement Architecture

Following **Liedtke's Principle** (L4, 1995) — *"a concept is only tolerated in the µ-kernel if moving it outside would prevent the required functionality"* — enforcement is split:

```
┌─────────────────────────────────────────────────────────────┐
│  Kernel (TCB) — Absolute invariants, mechanism only         │
│  • User-tier silo (SID ≥ 1000) + HardwareMode ≠ 0 → PANIC  │
│  • A silo cannot self-escalate via pledge                   │
│  • sys_cap_grant cannot exceed the granter's own rights     │
│  These rules cannot be overridden by anyone, including init │
├─────────────────────────────────────────────────────────────┤
│  strate-init — Family policy, configurable                  │
│  • Reads silo.toml + FAMILY_PROFILES at boot                │
│  • Refuses to spawn a DRV silo with mode=777                │
│  • Refuses to spawn a WASM silo with H≠0                   │
│  Boot fails hard if a silo violates its family profile.     │
│  New families (ENCLAVE, REALTIME…) need no kernel change.   │
└─────────────────────────────────────────────────────────────┘
```

> **`strate-init` is the sole policy judge for family constraints.**
> The kernel only enforces mechanical, tier-based invariants that require zero knowledge of family semantics.

### 7.1 Profile Structure

```rust
/// A family profile, used by `strate-init` to validate silo spawning at boot.
/// The kernel itself has no knowledge of these profiles — they are policy,
/// not mechanism. Adding a new family (e.g. ENCLAVE) requires no kernel change.
///
/// Inspired by:
/// - FreeBSD Jails: declarative sandbox templates.
/// - Solaris Zones: resource-limited containers.
/// - MINIX 3 Reincarnation Server: automatic restart of failed drivers.
#[derive(Debug)]
#[repr(C)]
pub struct FamilyProfile {
    pub family: StrateFamily,
    /// Minimum required mode (the silo must have at least these bits).
    pub min_mode: OctalMode,
    /// Maximum allowed mode (ceiling — silo cannot exceed these bits).
    pub max_mode: OctalMode,
    /// Which families this silo can send IPC messages to.
    pub allowed_ipc: &'static [StrateFamily],
    /// Memory limit for silos in this family.
    pub max_memory: usize,
    /// Scheduling priority.
    pub priority: Priority,
    /// Restart policy (MINIX 3-style reincarnation for critical services).
    pub restart_policy: RestartPolicy,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Priority {
    Critical = 0,  // Interrupt-level
    High     = 1,  // Drivers, core services
    Normal   = 2,  // Standard system services
    Low      = 3,  // User applications
}

/// Inspired by MINIX 3 Reincarnation Server.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum RestartPolicy {
    /// Never restart — user apps.
    Never   = 0,
    /// Restart on crash — critical drivers and FS.
    Always  = 1,
    /// Restart up to N times, then mark as failed.
    Limited { max_restarts: u8 } = 2,
}
```

### 7.2 Default Profiles

```rust
pub const FAMILY_PROFILES: &[FamilyProfile] = &[
    FamilyProfile {
        family: StrateFamily::DRV,
        min_mode: OctalMode::from_octal(0o060),  // Must have at least I/O+IRQ
        max_mode: OctalMode::from_octal(0o076),  // No Control (can't spawn other silos)
        allowed_ipc: &[StrateFamily::FS, StrateFamily::SYS],
        max_memory: 4 * 1024 * 1024,             // 4 MB
        priority: Priority::High,
        restart_policy: RestartPolicy::Always,    // MINIX 3-style reincarnation
    },
    FamilyProfile {
        family: StrateFamily::FS,
        min_mode: OctalMode::from_octal(0o006),  // Must have registry Lookup+Bind
        max_mode: OctalMode::from_octal(0o076),  // May have hardware access for raw disk
        allowed_ipc: &[StrateFamily::DRV, StrateFamily::NET, StrateFamily::SYS, StrateFamily::USR],
        max_memory: 8 * 1024 * 1024,             // 8 MB
        priority: Priority::Normal,
        restart_policy: RestartPolicy::Always,
    },
    FamilyProfile {
        family: StrateFamily::NET,
        min_mode: OctalMode::from_octal(0o006),
        max_mode: OctalMode::from_octal(0o076),
        allowed_ipc: &[StrateFamily::DRV, StrateFamily::FS, StrateFamily::SYS, StrateFamily::USR],
        max_memory: 8 * 1024 * 1024,
        priority: Priority::Normal,
        restart_policy: RestartPolicy::Always,
    },
    FamilyProfile {
        family: StrateFamily::WASM,
        min_mode: OctalMode::from_octal(0o004),  // Registry lookup minimum
        max_mode: OctalMode::from_octal(0o006),  // Software only — no hardware
        allowed_ipc: &[StrateFamily::FS, StrateFamily::NET, StrateFamily::SYS],
        max_memory: 16 * 1024 * 1024,            // 16 MB
        priority: Priority::Normal,
        restart_policy: RestartPolicy::Never,
    },
    FamilyProfile {
        family: StrateFamily::USR,
        min_mode: OctalMode::from_octal(0o000),
        max_mode: OctalMode::from_octal(0o004),  // Ceiling: registry lookup only
        allowed_ipc: &[StrateFamily::FS, StrateFamily::NET, StrateFamily::WASM],
        max_memory: 16 * 1024 * 1024,            // 16 MB
        priority: Priority::Low,
        restart_policy: RestartPolicy::Never,
    },
];
```

### 7.3 `strate-init` Policy Validation

This code runs in **`strate-init` userspace**, not in the kernel. It reads `silo.toml` and applies family profiles before calling `sys_silo_spawn`. A violation causes a boot panic — the system refuses to start in an inconsistent state, analogous to how Solaris's `zoneadmd` refuses to launch a misconfigured zone.

```rust
/// Run inside strate-init. Validates a silo's mode against its family
/// profile BEFORE calling sys_silo_spawn. A violation aborts the boot.
/// This is policy, not mechanism — extendable without touching the kernel.
pub fn init_validate_silo_policy(
    name: &str,
    mode: &OctalMode,
    profile: &FamilyProfile,
) -> Result<(), RegistrationError> {
    // Check minimum requirements
    if !profile.min_mode.is_subset_of(mode) {
        return Err(RegistrationError::BelowMinimumMode);
    }
    // Check maximum ceiling
    if !mode.is_subset_of(&profile.max_mode) {
        return Err(RegistrationError::ExceedsMaximumMode {
            silo: name,
            requested: *mode,
            ceiling: profile.max_mode,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum RegistrationError<'a> {
    /// Silo mode is below the minimum required by its family.
    BelowMinimumMode,
    /// Silo mode exceeds the maximum allowed by its family. Boot will panic.
    ExceedsMaximumMode {
        silo: &'a str,
        requested: OctalMode,
        ceiling: OctalMode,
    },
}
```

### 7.4 Kernel Absolute Invariants (TCB)

These checks live in the kernel and are enforced on **every `sys_silo_spawn` call**, regardless of who calls it — even `strate-init` (SID=1) cannot bypass them. They require only tier knowledge, no family semantics.

```rust
/// Kernel-side invariant checks, executed inside sys_silo_spawn.
/// These are MECHANISMS baked into the TCB. They cannot be configured
/// or overridden by any userspace silo, including strate-init.
///
/// Follows Liedtke's Principle: only what cannot be moved outside.
pub fn kernel_check_spawn_invariants(
    sid: &SiloId,
    mode: &OctalMode,
) -> Result<(), SpawnDenied> {
    // Invariant 1: User-tier silos can NEVER hold hardware access.
    // A Wasm app requesting I/O ports is always rejected, no exceptions.
    if sid.tier == SiloTier::User && !mode.hardware.is_empty() {
        return Err(SpawnDenied::UserTierHardwareAccess);
    }

    // Invariant 2: User-tier silos can NEVER have Control mode (spawn/stop/list).
    // Only System or Critical silos may manage other silos.
    if sid.tier == SiloTier::User && !mode.control.is_empty() {
        return Err(SpawnDenied::UserTierControlAccess);
    }

    Ok(())
}

#[derive(Debug)]
pub enum SpawnDenied {
    /// A silo with SID ≥ 1000 attempted to register hardware access bits.
    /// This is a hard kernel invariant. Not configurable.
    UserTierHardwareAccess,
    /// A silo with SID ≥ 1000 attempted to register control bits (spawn/stop).
    /// This is a hard kernel invariant. Not configurable.
    UserTierControlAccess,
}
```

---

## 8. Audit Trail (Solaris BSM)

Inspired by **Solaris Basic Security Module** (BSM, 1992), adopted by FreeBSD and macOS. Every security-relevant transition produces an immutable event in a kernel ring buffer.

### 8.1 Audit Event Structure

```rust
/// A security audit event, produced by the kernel for every
/// capability change, IPC denial, pledge, spawn, or kill.
///
/// Inspired by Solaris BSM / FreeBSD auditd.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AuditEvent {
    /// Monotonic kernel timestamp (ticks).
    pub timestamp: u64,
    /// SID of the silo that initiated the action.
    pub actor_sid: u32,
    /// The security action being recorded.
    pub action: AuditAction,
    /// SID of the target silo (0 if self-action).
    pub target_sid: u32,
    /// Whether the action succeeded or was denied.
    pub result: AuditResult,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AuditAction {
    CapGrant      = 0,
    CapRevoke     = 1,
    CapDenied     = 2,
    Pledge        = 3,
    Unveil        = 4,
    EnterSandbox  = 5,
    SiloSpawn     = 6,
    SiloStop      = 7,
    IpcDenied     = 8,
    IpcSend       = 9,
    ModeViolation = 10,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AuditResult {
    Success = 0,
    Denied  = 1,
    Error   = 2,
}
```

### 8.2 Audit Ring Buffer

```rust
/// Kernel-side ring buffer for audit events.
/// A dedicated silo (SID=3, `strate-audit`, mode=700) consumes events
/// and writes them to `/srv/audit`.
pub struct AuditRingBuffer {
    buffer: [AuditEvent; AUDIT_RING_SIZE],
    head: usize,
    tail: usize,
    /// Counter to track how many events were dropped if the buffer fills up.
    /// This prevents an attacker from flooding the buffer to hide their tracks,
    /// while avoiding a full denial of service for innocent silos.
    dropped_events: u64,
}

const AUDIT_RING_SIZE: usize = 4096;

impl AuditRingBuffer {
    pub const fn new() -> Self {
        Self {
            buffer: [AuditEvent::ZERO; AUDIT_RING_SIZE],
            head: 0,
            tail: 0,
            dropped_events: 0,
        }
    }

    /// Push an event into the ring buffer (called from kernel context).
    /// If the buffer is full, the event is dropped and the drop counter increments.
    pub fn push(&mut self, event: AuditEvent) {
        let next_head = self.head.wrapping_add(1) % AUDIT_RING_SIZE;
        if next_head == self.tail {
            // Buffer is full. Drop the event to preserve history and log the drop.
            // Alternatively, in high-security environments, the kernel could pause
            // the offending silo, but dropping prevents deadlocks.
            self.dropped_events = self.dropped_events.saturating_add(1);
            return;
        }
        self.buffer[self.head] = event;
        self.head = next_head;
    }

    /// Pop the next event for the audit consumer silo.
    /// Returns a tuple of (Option<AuditEvent>, dropped_count) so the consumer
    /// knows if it missed events due to an overflow.
    pub fn pop(&mut self) -> (Option<AuditEvent>, u64) {
        let drops = self.dropped_events;
        self.dropped_events = 0; // Reset after reporting to consumer

        if self.tail == self.head {
            return (None, drops);
        }
        let event = self.buffer[self.tail];
        self.tail = self.tail.wrapping_add(1) % AUDIT_RING_SIZE;
        (Some(event), drops)
    }
}
```

---

## 9. Configuration (`silo.toml`)

The `silo.toml` file defines silos and their strates. A silo declares its security boundary (SID, mode, family). Each `[[silos.strates]]` entry is an executable that runs inside that silo. Strates within the same silo share its SID, capabilities, and mode — they are implicitly trusted by each other.

`strate-init` validates family profiles at boot before calling `sys_silo_spawn`. A violation is a hard panic.

```toml
# ── Critical silos (SID < 10) ────────────────────────────────────────────────

[[silos]]
name = "silo-init"
sid = 1                 # Critical range — MUST be < 10
family = "SYS"
mode = 0o777            # Full control, full hardware, full registry

  [[silos.strates]]
  name = "strate-init"
  binary = "/initfs/strate-init"

[[silos]]
name = "silo-audit"
sid = 3                 # Critical range — MUST be < 10, IPC label RED
family = "SYS"
mode = 0o706            # Control: full + Registry: Lookup+Bind (for /srv/audit)
                        # NOTE: mode 0o700 would be wrong — R=0 prevents binding /srv/audit

  [[silos.strates]]
  name = "strate-audit"
  binary = "/initfs/strate-audit"

# ── System silos (SID 10–999) ─────────────────────────────────────────────────

[[silos]]
name = "silo-virtio-blk"
sid = 100               # System range
family = "DRV"
mode = 0o066            # No control, IRQ+I/O, Lookup+Bind
compartment = "disk0"
restart = "always"      # MINIX 3-style reincarnation

  [[silos.strates]]
  name = "strate-virtio-blk"
  binary = "/initfs/strate-virtio-blk"

[[silos]]
name = "silo-fs"
sid = 200               # System range
family = "FS"
mode = 0o006            # No control, no hardware, Lookup+Bind
restart = "always"

  [[silos.strates]]
  name = "strate-ext4"
  binary = "/initfs/strate-ext4"

[[silos]]
name = "silo-wasm"
sid = 20                # System range
family = "WASM"
mode = 0o006            # No control, no hardware, Lookup+Bind

  # Multiple strates inside the same silo — implicit trust, direct communication.
  # Strate-wasm-runtime and strate-wasm-jit share SID=20, mode=006, and capabilities.
  [[silos.strates]]
  name = "strate-wasm-runtime"
  binary = "/initfs/strate-wasm-runtime"

  [[silos.strates]]
  name = "strate-wasm-jit"
  binary = "/initfs/strate-wasm-jit"

# ── User silos (SID 1000+) ────────────────────────────────────────────────────

[[silos]]
name = "silo-hello"
sid = 1005              # User range
family = "USR"
mode = 0o004            # Registry: Lookup only
wasm_fuel = 1000000

  [[silos.strates]]
  name = "strate-hello"
  binary = "/initfs/hello.wasm"
```

---

## 10. Observability (`strate ls`)

The shell command provides a comprehensive view of silos and their strates.

```
$ strate ls
 SID  SILO           STRATES  STATE    MODE  FAMILY  CAPS  MEMORY   RESTARTS
   1  silo-init            1  Running  777   SYS       12   2.4 MB         0
   3  silo-audit           1  Running  706   SYS        2   0.8 MB         0
 100  silo-virtio-blk      1  Running  066   DRV        5   1.2 MB         1
 200  silo-fs              1  Running  006   FS         8   3.1 MB         0
  20  silo-wasm            2  Ready    006   WASM       3  16.0 MB         0
1005  silo-hello           1  Running  004   USR        1   1.2 MB         0
```

```
# Inspect the strates inside a silo
$ strate ls --strates 20
 SID  SILO       STRATE                 STATE    MEMORY
  20  silo-wasm  strate-wasm-runtime    Running   8.0 MB   # intra-silo: direct comm
  20  silo-wasm  strate-wasm-jit        Running   8.0 MB   # shared SID, mode, caps

$ strate caps 200
 HANDLE  OBJECT         RIGHTS       BADGE
      0  disk0          READ|WRITE     100    # granted by silo-virtio-blk
      1  /srv/fs        BIND           200    # self-registered
      2  /srv/audit     WRITE            3    # granted by silo-audit

$ strate audit --tail 5
 TIMESTAMP   ACTOR  ACTION       TARGET  RESULT
 10284521        1  SiloSpawn      1005  Success
 10284600     1005  IpcSend         200  Success
 10284610     1005  IpcSend         100  Denied     # USR->DRV blocked by family profile
 10284700      200  CapGrant       1005  Success
 10284710     1005  Pledge           —   Success    # mode 004 -> 000
```

---

## 11. Summary of Hybrid Security

| Layer | Mechanism | Inspiration | Enforcement |
| :--- | :--- | :--- | :--- |
| **Silo/Strate Container** | Silo = security boundary, Strates = lightweight processes inside (implicit trust) | **Erlang** nodes, **FreeBSD Jails** | User responsibility (v1.0) — Kernel in v2.0 hardened mode |
| **Identity (SID)** | Tier-based hierarchy | Classic UNIX UID ranges | Kernel — assigned at spawn |
| **Behavior (Mode)** | Three-digit octal `[C][H][R]` | UNIX `chmod` | Kernel — checked on every syscall |
| **Tier Invariants** | Absolute tier × mode rules (User cannot hold H or C) | **Liedtke's Principle** (L4) | Kernel — enforced on every `sys_silo_spawn` |
| **Family (Profile)** | Policy: min/max mode, IPC topology, memory | **FreeBSD Jails**, **Solaris Zones**, **MINIX 3** | `strate-init` — boot-time, hard panic on violation |
| **Capabilities** | Handle-based, attenuated, revocable | **seL4** CSpace, **Capsicum** | Kernel — CSpace per silo |
| **IPC Label** | Structured (tier + family + compartment) | **Solaris Trusted Extensions**, **Biba Integrity Model** | Kernel — stamped on inter-silo send only |
| **Pledge/Unveil** | Irrevocable self-restriction | **OpenBSD** pledge/unveil | Kernel — monotonic reduction |
| **Audit** | Ring buffer + consumer silo | **Solaris BSM**, **FreeBSD auditd** | Kernel — every inter-silo security event |
