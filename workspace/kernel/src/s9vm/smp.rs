/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! s9vm — guest SMP bring-up model.
//!
//! Pure module: it models the architectural side of multiprocessor bring-up
//! for the virtual machine: the local APIC interrupt command register (ICR),
//! the INIT / INIT de-assert / STARTUP IPI sequence and the per-vCPU state
//! machine a hypervisor must implement when it injects those IPIs.
//!
//! It **touches no hardware**: the kernel layer decodes guest accesses to the
//! local APIC ICR and forwards them to [`SmpController::send_ipi`], then calls
//! [`SmpController::advance`] with the current TSC value to collect the
//! delayed operations (INIT de-assert, STARTUP retries, startup completion)
//! that must be injected. The module allocates nothing: all result sets are
//! fixed-size buffers returned by value.
//!
//! The encodings come from the Intel documentation (SDM vol. 3A, chapter
//! "Advanced Programmable Interrupt Controller"): ICR delivery modes,
//! destination modes, shorthands and the MP 1.4 INIT-SIPI-SIPI sequence.
//!
//! ## State machine
//!
//! ```text
//! Offline ──INIT──▶ WaitForSipi ──STARTUP──▶ Starting ──startup delay──▶ Running
//!    ▲                   │                      │
//!    │                   │ INIT (re-arm)        │ retries exhausted
//!    │                   ▼                      ▼
//!    └────────────── WaitForSipi              Offline (startup failed)
//!
//! Running ──guest HLT──▶ Halted ──wake──▶ Running
//! ```
//!
//! * `Offline`: the vCPU has not been started (reset state).
//! * `WaitForSipi`: INIT was delivered; a STARTUP IPI is accepted.
//! * `Starting`: a STARTUP IPI was accepted; the fetch/startup delay runs.
//! * `Running`: the vCPU is executing.
//! * `Halted`: the guest executed `HLT`; not part of bring-up, kept so the
//!   integration can expose the guest halt state to the scheduler.
//!
//! A STARTUP IPI is accepted only in `WaitForSipi`; without a prior INIT it is
//! ignored and reported through [`SmpController::last_error`]. An INIT to the
//! BSP/self is undefined by the architecture and modelled as ignored.

/// Number of bytes covered by one STARTUP vector step (vector << 12).
pub const SIPI_VECTOR_STEP: u64 = 0x1000;
/// Highest legal STARTUP address (the vector must stay below 1 MiB).
pub const SIPI_MAX_ADDRESS: u64 = 0x000F_FFFF;
/// Modeled INIT de-assert delay, in microseconds (MP specification: 10 ms).
pub const MODELLED_INIT_DEASSERT_DELAY_US: u64 = 10_000;
/// Modeled delay between STARTUP IPI retries, in microseconds.
pub const MODELLED_SIPI_RETRY_DELAY_US: u64 = 200;
/// Modeled number of extra STARTUP IPIs sent before a startup failure.
pub const MODELLED_SIPI_MAX_RETRIES: u8 = 2;
/// Modeled fetch delay after a STARTUP IPI before the vCPU is `Running`, in
/// TSC ticks (the model cannot know the guest fetch time).
pub const MODELLED_STARTUP_DELAY_TICKS: u64 = 1;
/// INIT de-assert delay, in microseconds.
pub const INIT_DEASSERT_DELAY_US: u64 = MODELLED_INIT_DEASSERT_DELAY_US;
/// Delay between STARTUP IPI retries, in microseconds.
pub const SIPI_RETRY_DELAY_US: u64 = MODELLED_SIPI_RETRY_DELAY_US;
/// Number of STARTUP IPI retries before giving up.
pub const SIPI_MAX_RETRIES: u8 = MODELLED_SIPI_MAX_RETRIES;
/// Default fetch delay after a STARTUP IPI, in TSC ticks.
pub const STARTUP_DELAY_TICKS: u64 = MODELLED_STARTUP_DELAY_TICKS;
/// Local APIC identifier of the bootstrap processor.
pub const BSP_LAPIC_ID: u8 = 0;
/// Maximum number of modeled vCPUs.
pub const MAX_VCPUS: usize = 64;
/// Maximum number of IPI effects returned by one call.
pub const MAX_EFFECTS: usize = MAX_VCPUS;
/// Maximum number of delayed events returned by one `advance` call.
pub const MAX_EVENTS: usize = MAX_VCPUS * 3;
/// Nominal TSC frequency used by the tests (1 GHz: 1 tick per microsecond).
pub const DEFAULT_TSC_HZ: u64 = 1_000_000_000;

/// Converts microseconds to TSC ticks, saturating on overflow.
pub const fn us_to_ticks(tsc_hz: u64, us: u64) -> u64 {
    us.saturating_mul(tsc_hz) / 1_000_000
}

/// Address delivered by a STARTUP IPI vector (`vector << 12`).
pub const fn sipi_vector_address(vector: u8) -> u64 {
    (vector as u64) * SIPI_VECTOR_STEP
}

/// Returns `true` when `vector` delivers a legal STARTUP address.
pub const fn sipi_vector_valid(vector: u8) -> bool {
    sipi_vector_address(vector) <= SIPI_MAX_ADDRESS
}

/// Local APIC interrupt delivery mode (ICR bits 10:8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Fixed vector delivery.
    Fixed,
    /// Lowest-priority delivery.
    LowestPriority,
    /// System management interrupt.
    Smi,
    /// Reserved encoding (3).
    Reserved,
    /// Non-maskable interrupt.
    Nmi,
    /// INIT IPI.
    Init,
    /// STARTUP IPI.
    Startup,
    /// ExtINT (delivered through the legacy interrupt controller path).
    ExtInt,
}

impl DeliveryMode {
    /// Decodes ICR bits 10:8.
    pub const fn from_bits(bits: u32) -> Self {
        match bits & 0x7 {
            0 => Self::Fixed,
            1 => Self::LowestPriority,
            2 => Self::Smi,
            3 => Self::Reserved,
            4 => Self::Nmi,
            5 => Self::Init,
            6 => Self::Startup,
            _ => Self::ExtInt,
        }
    }
}

/// ICR destination mode (bit 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationMode {
    /// Physical APIC identifier.
    Physical,
    /// Logical destination (flat model in this implementation).
    Logical,
}

/// ICR trigger mode (bit 15) and level/assert bit (bit 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Edge-triggered delivery; the level bit is not meaningful.
    Edge,
    /// Level-triggered; [`Icr::level_assert`] gives the requested level.
    Level,
}

/// ICR destination shorthand (bits 19:18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shorthand {
    /// Destination field is used.
    None,
    /// The sending processor only.
    SelfOnly,
    /// Every processor, including the sender.
    AllIncludingSelf,
    /// Every processor except the sender.
    AllExcludingSelf,
}

impl Shorthand {
    /// Decodes ICR bits 19:18.
    pub const fn from_bits(bits: u32) -> Self {
        match bits & 0x3 {
            0 => Self::None,
            1 => Self::SelfOnly,
            2 => Self::AllIncludingSelf,
            _ => Self::AllExcludingSelf,
        }
    }
}

/// Typed decoding of the ICR delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiKind {
    /// Fixed vector.
    Fixed {
        /// Vector delivered (ICR bits 7:0).
        vector: u8,
    },
    /// Lowest-priority vector.
    LowestPriority {
        /// Vector delivered.
        vector: u8,
    },
    /// System management interrupt.
    Smi,
    /// Non-maskable interrupt.
    Nmi,
    /// INIT IPI; `level_assert` is ICR bit 14.
    Init {
        /// Requested level: `true` asserts INIT, `false` de-asserts it.
        level_assert: bool,
    },
    /// STARTUP IPI.
    Startup {
        /// Startup vector; the delivered address is
        /// [`sipi_vector_address`].
        vector: u8,
    },
    /// ExtINT.
    ExtInt,
}

/// Errors reported by the controller; never panics on guest input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpError {
    /// ICR delivery mode 3 is reserved.
    ReservedDeliveryMode,
    /// The source vCPU is not part of the controller.
    UnknownSource,
    /// The physical destination or logical mask selects no vCPU.
    DestinationUnavailable,
    /// A STARTUP IPI arrived on a vCPU that is not in `WaitForSipi`.
    SipiWithoutInit,
    /// INIT was directed at the sending vCPU (undefined by the architecture).
    InitToSelf,
    /// Logical cluster destinations are not modeled: only logical flat is.
    ClusterModeUnsupported,
}

/// Decoded interrupt command register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icr {
    /// ICR low double word.
    pub low: u32,
    /// ICR high double word.
    pub high: u32,
}

impl Icr {
    /// Wraps the two ICR halves.
    pub const fn new(low: u32, high: u32) -> Self {
        Self { low, high }
    }

    /// Destination field (ICR high bits 31:24, one 8-bit APIC identifier in
    /// the physical destination model).
    pub const fn destination_field(self) -> u8 {
        ((self.high >> 24) & 0xFF) as u8
    }

    /// Vector field (ICR low bits 7:0).
    pub const fn vector(self) -> u8 {
        (self.low & 0xFF) as u8
    }

    /// Delivery mode (ICR low bits 10:8).
    pub const fn delivery_mode(self) -> DeliveryMode {
        DeliveryMode::from_bits((self.low >> 8) & 0x7)
    }

    /// Destination mode (ICR low bit 11).
    pub const fn destination_mode(self) -> DestinationMode {
        if self.low & (1 << 11) != 0 {
            DestinationMode::Logical
        } else {
            DestinationMode::Physical
        }
    }

    /// Delivery status bit (ICR low bit 12); read-only in the hardware.
    pub const fn delivery_status_pending(self) -> bool {
        self.low & (1 << 12) != 0
    }

    /// Level/assert bit (ICR low bit 14).
    pub const fn level_assert(self) -> bool {
        self.low & (1 << 14) != 0
    }

    /// Trigger mode (ICR low bit 15).
    pub const fn trigger_mode(self) -> TriggerMode {
        if self.low & (1 << 15) != 0 {
            TriggerMode::Level
        } else {
            TriggerMode::Edge
        }
    }

    /// Destination shorthand (ICR low bits 19:18).
    pub const fn shorthand(self) -> Shorthand {
        Shorthand::from_bits((self.low >> 18) & 0x3)
    }

    /// Typed delivery decode; reserved encodings are rejected.
    pub const fn kind(self) -> Result<IpiKind, SmpError> {
        let vector = self.vector();
        match self.delivery_mode() {
            DeliveryMode::Fixed => Ok(IpiKind::Fixed { vector }),
            DeliveryMode::LowestPriority => Ok(IpiKind::LowestPriority { vector }),
            DeliveryMode::Smi => Ok(IpiKind::Smi),
            DeliveryMode::Nmi => Ok(IpiKind::Nmi),
            DeliveryMode::Init => Ok(IpiKind::Init {
                level_assert: self.level_assert(),
            }),
            DeliveryMode::Startup => Ok(IpiKind::Startup { vector }),
            DeliveryMode::ExtInt => Ok(IpiKind::ExtInt),
            DeliveryMode::Reserved => Err(SmpError::ReservedDeliveryMode),
        }
    }
}

/// One immediate IPI effect produced by [`SmpController::send_ipi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpiEffect {
    /// Target local APIC identifier.
    pub target: u8,
    /// Typed delivery.
    pub kind: IpiKind,
    /// TSC value at which the effect must be injected.
    pub deliver_at: u64,
}

/// Fixed-capacity list of [`IpiEffect`] values.
#[derive(Debug, Clone, Copy)]
pub struct Effects {
    items: [IpiEffect; MAX_EFFECTS],
    len: usize,
}

impl Effects {
    /// Creates an empty list.
    pub const fn new() -> Self {
        Self {
            items: [IpiEffect::EMPTY; MAX_EFFECTS],
            len: 0,
        }
    }

    /// Number of effects.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` when no effect was produced.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Effects as a slice.
    pub fn as_slice(&self) -> &[IpiEffect] {
        &self.items[..self.len]
    }

    /// Iterates over the effects.
    pub fn iter(&self) -> core::slice::Iter<'_, IpiEffect> {
        self.items[..self.len].iter()
    }

    /// Appends an effect, dropping it silently when the buffer is full.
    fn push(&mut self, effect: IpiEffect) {
        if self.len < MAX_EFFECTS {
            self.items[self.len] = effect;
            self.len += 1;
        }
    }
}

impl Default for Effects {
    fn default() -> Self {
        Self::new()
    }
}

impl IpiEffect {
    /// Empty placeholder used to build the fixed array.
    const EMPTY: Self = Self {
        target: 0,
        kind: IpiKind::Nmi,
        deliver_at: 0,
    };
}

/// Delayed event produced by [`SmpController::advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpEventKind {
    /// INIT level must be de-asserted on the target.
    InitDeassert,
    /// A STARTUP IPI must be retried (initial delivery plus retries).
    SipiRetry {
        /// Startup vector to redeliver.
        vector: u8,
        /// Retry attempt number, starting at 1.
        attempt: u8,
    },
    /// The startup fetch delay elapsed: the vCPU is now `Running`.
    StartupComplete,
    /// The retries were exhausted: the AP startup failed.
    StartupFailed,
}

/// One delayed bring-up event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmpEvent {
    /// Target local APIC identifier.
    pub target: u8,
    /// Event kind.
    pub kind: SmpEventKind,
    /// TSC value at which the event became due.
    pub at: u64,
}

/// Fixed-capacity list of [`SmpEvent`] values.
#[derive(Debug, Clone, Copy)]
pub struct Events {
    items: [SmpEvent; MAX_EVENTS],
    len: usize,
}

impl Events {
    /// Creates an empty list.
    pub const fn new() -> Self {
        Self {
            items: [SmpEvent::EMPTY; MAX_EVENTS],
            len: 0,
        }
    }

    /// Number of events.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` when no event is due.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Events as a slice.
    pub fn as_slice(&self) -> &[SmpEvent] {
        &self.items[..self.len]
    }

    /// Iterates over the events.
    pub fn iter(&self) -> core::slice::Iter<'_, SmpEvent> {
        self.items[..self.len].iter()
    }

    /// Appends an event, dropping it silently when the buffer is full.
    fn push(&mut self, event: SmpEvent) {
        if self.len < MAX_EVENTS {
            self.items[self.len] = event;
            self.len += 1;
        }
    }
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl SmpEvent {
    /// Empty placeholder used to build the fixed array.
    const EMPTY: Self = Self {
        target: 0,
        kind: SmpEventKind::InitDeassert,
        at: 0,
    };
}

/// Bring-up state of one modeled vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VCpuState {
    /// Not started (reset state).
    Offline,
    /// INIT delivered; a STARTUP IPI is accepted.
    WaitForSipi,
    /// STARTUP accepted; the fetch delay is running.
    Starting,
    /// Executing guest code.
    Running,
    /// Guest halted (`HLT`), outside the bring-up sequence.
    Halted,
}

/// Per-vCPU model state.
#[derive(Debug, Clone, Copy)]
struct VCpu {
    /// Local APIC identifier.
    lapic_id: u8,
    /// Bring-up state.
    state: VCpuState,
    /// TSC value of the pending INIT de-assert (0 when none).
    deassert_due: u64,
    /// TSC value of the pending startup completion (0 when none).
    startup_due: u64,
    /// TSC value of the pending STARTUP retry check (0 when none).
    retry_due: u64,
    /// Vector of the last accepted STARTUP IPI.
    sipi_vector: u8,
    /// Retries already sent.
    attempts: u8,
}

impl VCpu {
    /// Unpopulated slot.
    const fn empty() -> Self {
        Self {
            lapic_id: 0,
            state: VCpuState::Offline,
            deassert_due: 0,
            startup_due: 0,
            retry_due: 0,
            sipi_vector: 0,
            attempts: 0,
        }
    }

    /// Resets the transient scheduling state on INIT.
    fn arm_init(&mut self, deassert_at: u64) {
        self.state = VCpuState::WaitForSipi;
        self.deassert_due = deassert_at;
        self.startup_due = 0;
        self.retry_due = 0;
        self.sipi_vector = 0;
        self.attempts = 0;
    }

    /// Accepts a STARTUP IPI.
    fn arm_startup(&mut self, vector: u8, startup_at: u64, retry_at: u64) {
        self.state = VCpuState::Starting;
        self.sipi_vector = vector;
        self.startup_due = startup_at;
        self.retry_due = retry_at;
        self.attempts = 0;
    }
}

/// Logical destination model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalMode {
    /// Logical flat: the destination field is an 8-bit APIC identifier mask.
    Flat,
    /// Logical cluster mode is not modeled; logical IPIs are rejected.
    Cluster,
}

/// Fixed-capacity target list used internally.
#[derive(Debug, Clone, Copy)]
struct Targets {
    ids: [u8; MAX_VCPUS],
    len: usize,
}

impl Targets {
    const fn new() -> Self {
        Self {
            ids: [0; MAX_VCPUS],
            len: 0,
        }
    }

    fn push(&mut self, id: u8) {
        if self.len < MAX_VCPUS {
            self.ids[self.len] = id;
            self.len += 1;
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.ids[..self.len]
    }
}

/// Guest SMP bring-up controller.
pub struct SmpController {
    vcpus: [VCpu; MAX_VCPUS],
    ids: [u8; MAX_VCPUS],
    count: usize,
    tsc_hz: u64,
    startup_delay_ticks: u64,
    logical_mode: LogicalMode,
    last_error: Option<SmpError>,
}

impl SmpController {
    /// Creates a controller with only the BSP (`BSP_LAPIC_ID`, `Running`).
    pub fn new(tsc_hz: u64) -> Self {
        Self::with_lapic_ids(tsc_hz, &[BSP_LAPIC_ID])
    }

    /// Creates a controller from the local APIC identifiers found in the
    /// guest MADT (the BSP is the entry whose identifier is
    /// [`BSP_LAPIC_ID`]; otherwise the first entry is used as the BSP).
    pub fn with_lapic_ids(tsc_hz: u64, ids: &[u8]) -> Self {
        let mut controller = Self {
            vcpus: [VCpu::empty(); MAX_VCPUS],
            ids: [0; MAX_VCPUS],
            count: 0,
            tsc_hz,
            startup_delay_ticks: STARTUP_DELAY_TICKS,
            logical_mode: LogicalMode::Flat,
            last_error: None,
        };
        for &id in ids {
            let _ = controller.add_vcpu(id);
        }
        if controller.count != 0 && controller.state(BSP_LAPIC_ID) != Some(VCpuState::Running) {
            // Make the first entry the BSP when the MADT does not use 0.
            if let Some(first) = controller.ids.first().copied() {
                if let Some(index) = controller.index_of(first) {
                    controller.vcpus[index].state = VCpuState::Running;
                }
            }
        }
        controller
    }

    /// Local APIC identifier of the BSP in this controller.
    pub fn bsp_lapic_id(&self) -> u8 {
        if self.index_of(BSP_LAPIC_ID).is_some() {
            BSP_LAPIC_ID
        } else {
            self.ids.first().copied().unwrap_or(BSP_LAPIC_ID)
        }
    }

    /// Adds a vCPU in `Offline` state (the BSP may be added in `Running`).
    ///
    /// Returns `false` when the identifier is duplicated or the capacity is
    /// exhausted.
    pub fn add_vcpu(&mut self, lapic_id: u8) -> bool {
        if self.count >= MAX_VCPUS || self.index_of(lapic_id).is_some() {
            return false;
        }
        let index = self.count;
        self.ids[index] = lapic_id;
        self.vcpus[index] = VCpu::empty();
        self.vcpus[index].lapic_id = lapic_id;
        self.vcpus[index].state = if lapic_id == BSP_LAPIC_ID {
            VCpuState::Running
        } else {
            VCpuState::Offline
        };
        self.count += 1;
        true
    }

    /// Number of modeled vCPUs.
    pub const fn vcpu_count(&self) -> usize {
        self.count
    }

    /// Local APIC identifiers, in controller order (MADT order).
    pub fn lapic_ids(&self) -> &[u8] {
        &self.ids[..self.count]
    }

    /// TSC frequency used for the microsecond delays.
    pub const fn tsc_hz(&self) -> u64 {
        self.tsc_hz
    }

    /// Overrides the fetch delay applied after a STARTUP IPI (TSC ticks).
    pub fn set_startup_delay_ticks(&mut self, ticks: u64) {
        self.startup_delay_ticks = ticks;
    }

    /// Selects the logical destination model.
    pub fn set_logical_mode(&mut self, mode: LogicalMode) {
        self.logical_mode = mode;
    }

    /// Current logical destination model.
    pub const fn logical_mode(&self) -> LogicalMode {
        self.logical_mode
    }

    /// Error reported by the last [`Self::send_ipi`] or [`Self::bring_up_ap`].
    pub const fn last_error(&self) -> Option<SmpError> {
        self.last_error
    }

    /// State of a vCPU, by local APIC identifier.
    pub fn state(&self, lapic_id: u8) -> Option<VCpuState> {
        self.index_of(lapic_id).map(|index| self.vcpus[index].state)
    }

    /// State of a vCPU, by controller index.
    pub fn state_at(&self, index: usize) -> Option<VCpuState> {
        if index >= self.count {
            return None;
        }
        Some(self.vcpus[index].state)
    }

    /// `true` when the vCPU is `Running`.
    pub fn is_running(&self, lapic_id: u8) -> bool {
        self.state(lapic_id) == Some(VCpuState::Running)
    }

    /// Number of vCPUs in a given state.
    pub fn count_in_state(&self, state: VCpuState) -> usize {
        self.vcpus[..self.count]
            .iter()
            .filter(|vcpu| vcpu.state == state)
            .count()
    }

    /// Number of STARTUP retries already sent to a vCPU.
    pub fn retries(&self, lapic_id: u8) -> Option<u8> {
        self.index_of(lapic_id)
            .map(|index| self.vcpus[index].attempts)
    }

    /// STARTUP vector accepted for a vCPU (0 when none).
    pub fn sipi_vector(&self, lapic_id: u8) -> Option<u8> {
        self.index_of(lapic_id)
            .map(|index| self.vcpus[index].sipi_vector)
    }

    /// Checks the controller against the number of local APIC entries of the
    /// guest MADT, and that every identifier is present exactly once.
    pub fn validate_against_madt(&self, madt_count: usize) -> bool {
        if self.count == 0 || self.count != madt_count {
            return false;
        }
        for (index, id) in self.ids[..self.count].iter().enumerate() {
            if self.ids[..index].contains(id) {
                return false;
            }
        }
        true
    }

    /// Sets the guest `HLT` state (`Running` <-> `Halted`).
    ///
    /// Returns `false` for a vCPU that is not running or halted, or unknown.
    pub fn set_halted(&mut self, lapic_id: u8, halted: bool) -> bool {
        let Some(index) = self.index_of(lapic_id) else {
            return false;
        };
        let state = self.vcpus[index].state;
        if halted && state == VCpuState::Running {
            self.vcpus[index].state = VCpuState::Halted;
            true
        } else if !halted && state == VCpuState::Halted {
            self.vcpus[index].state = VCpuState::Running;
            true
        } else {
            false
        }
    }

    /// Converts microseconds to TSC ticks for this controller.
    pub fn ticks_for_us(&self, us: u64) -> u64 {
        us_to_ticks(self.tsc_hz, us)
    }

    /// Decodes and applies an ICR write, returning the IPIs to inject now.
    ///
    /// `source` is the local APIC identifier of the sending processor.
    /// `now` is the current TSC value; it is used for immediate deliveries and
    /// to schedule the delayed operations handled by [`Self::advance`].
    pub fn send_ipi(&mut self, source: u8, icr_low: u32, icr_high: u32, now: u64) -> Effects {
        self.last_error = None;
        let icr = Icr::new(icr_low, icr_high);
        let kind = match icr.kind() {
            Ok(kind) => kind,
            Err(error) => {
                self.last_error = Some(error);
                return Effects::new();
            }
        };

        let targets = match self.expand_targets(source, &icr) {
            Some(targets) => targets,
            None => return Effects::new(),
        };

        match kind {
            IpiKind::Init { level_assert } => {
                self.deliver_init(source, &targets, level_assert, now)
            }
            IpiKind::Startup { vector } => self.deliver_startup(&targets, vector, now),
            IpiKind::Fixed { vector } => {
                self.deliver_broadcast(&targets, IpiKind::Fixed { vector }, now)
            }
            IpiKind::Smi => self.deliver_broadcast(&targets, IpiKind::Smi, now),
            IpiKind::Nmi => self.deliver_broadcast(&targets, IpiKind::Nmi, now),
            IpiKind::ExtInt => self.deliver_broadcast(&targets, IpiKind::ExtInt, now),
            IpiKind::LowestPriority { vector } => {
                let mut effects = Effects::new();
                if let Some(target) = targets.as_slice().iter().copied().min() {
                    effects.push(IpiEffect {
                        target,
                        kind: IpiKind::LowestPriority { vector },
                        deliver_at: now,
                    });
                } else {
                    self.last_error = Some(SmpError::DestinationUnavailable);
                }
                effects
            }
        }
    }

    /// Returns the due delayed operations and updates the vCPU states.
    ///
    /// Processes, per vCPU: INIT de-assert, startup completion, then STARTUP
    /// retry/failure. `now` is the current TSC value.
    pub fn advance(&mut self, now: u64) -> Events {
        let mut events = Events::new();
        let retry_delay = self.ticks_for_us(SIPI_RETRY_DELAY_US);
        for index in 0..self.count {
            let vcpu = &mut self.vcpus[index];

            if vcpu.deassert_due != 0 && now >= vcpu.deassert_due {
                events.push(SmpEvent {
                    target: vcpu.lapic_id,
                    kind: SmpEventKind::InitDeassert,
                    at: vcpu.deassert_due,
                });
                vcpu.deassert_due = 0;
            }

            if vcpu.startup_due != 0 && now >= vcpu.startup_due {
                if vcpu.state == VCpuState::Starting {
                    vcpu.state = VCpuState::Running;
                    events.push(SmpEvent {
                        target: vcpu.lapic_id,
                        kind: SmpEventKind::StartupComplete,
                        at: vcpu.startup_due,
                    });
                }
                vcpu.startup_due = 0;
                vcpu.retry_due = 0;
            }

            if vcpu.retry_due != 0 && now >= vcpu.retry_due {
                if vcpu.state == VCpuState::Starting {
                    if vcpu.attempts < SIPI_MAX_RETRIES {
                        vcpu.attempts = vcpu.attempts.saturating_add(1);
                        events.push(SmpEvent {
                            target: vcpu.lapic_id,
                            kind: SmpEventKind::SipiRetry {
                                vector: vcpu.sipi_vector,
                                attempt: vcpu.attempts,
                            },
                            at: vcpu.retry_due,
                        });
                        let delay = retry_delay;
                        vcpu.retry_due = if delay == 0 {
                            0
                        } else {
                            vcpu.retry_due.saturating_add(delay)
                        };
                    } else {
                        events.push(SmpEvent {
                            target: vcpu.lapic_id,
                            kind: SmpEventKind::StartupFailed,
                            at: vcpu.retry_due,
                        });
                        vcpu.state = VCpuState::Offline;
                        vcpu.retry_due = 0;
                        vcpu.startup_due = 0;
                    }
                } else {
                    // The startup completed (or the state changed): the
                    // retry check is no longer relevant.
                    vcpu.retry_due = 0;
                }
            }
        }
        events
    }

    /// INIT-SIPI-SIPI helper: returns the INIT effects and the STARTUP effect.
    ///
    /// The INIT is delivered at `now`; its de-assert is scheduled
    /// [`INIT_DEASSERT_DELAY_US`] later, and the STARTUP IPI effect carries
    /// that de-assert time as its `deliver_at`. The automatic retry policy
    /// (2 retries, 200 us apart) is handled by [`Self::advance`], so the
    /// second SIPI of the sequence does not need a third effect.
    pub fn bring_up_ap(
        &mut self,
        ap_lapic_id: u8,
        sipi_vector: u8,
        now: u64,
    ) -> (Effects, Effects) {
        self.last_error = None;
        let source = self.bsp_lapic_id();
        let init_low: u32 = (5 << 8) | (1 << 14);
        let init_high = (ap_lapic_id as u32) << 24;
        let init_effects = self.send_ipi(source, init_low, init_high, now);

        let deassert_delay = self.ticks_for_us(INIT_DEASSERT_DELAY_US);
        let sipi_at = now.saturating_add(deassert_delay);
        let startup_low: u32 = (6 << 8) | sipi_vector as u32;
        let startup_high = (ap_lapic_id as u32) << 24;
        let sipi_effects = self.send_ipi(source, startup_low, startup_high, sipi_at);
        (init_effects, sipi_effects)
    }

    /// Delivers INIT to the selected targets.
    fn deliver_init(
        &mut self,
        source: u8,
        targets: &Targets,
        level_assert: bool,
        now: u64,
    ) -> Effects {
        let mut effects = Effects::new();
        let deassert_delay = self.ticks_for_us(INIT_DEASSERT_DELAY_US);
        let deassert_at = now.saturating_add(deassert_delay);
        for &target in targets.as_slice() {
            if target == source {
                // INIT to self is undefined by the architecture: ignored.
                if targets.len == 1 {
                    self.last_error = Some(SmpError::InitToSelf);
                }
                continue;
            }
            if level_assert {
                if let Some(index) = self.index_of(target) {
                    self.vcpus[index].arm_init(deassert_at);
                }
            }
            effects.push(IpiEffect {
                target,
                kind: IpiKind::Init { level_assert },
                deliver_at: now,
            });
        }
        effects
    }

    /// Delivers STARTUP to the targets that are waiting for it.
    fn deliver_startup(&mut self, targets: &Targets, vector: u8, now: u64) -> Effects {
        let mut effects = Effects::new();
        if !sipi_vector_valid(vector) {
            self.last_error = Some(SmpError::DestinationUnavailable);
            return effects;
        }
        let startup_delay = self.startup_delay_ticks;
        let startup_at = now.saturating_add(startup_delay);
        let retry_delay = self.ticks_for_us(SIPI_RETRY_DELAY_US);
        let retry_at = if retry_delay == 0 {
            0
        } else {
            now.saturating_add(retry_delay)
        };
        for &target in targets.as_slice() {
            let Some(index) = self.index_of(target) else {
                continue;
            };
            if self.vcpus[index].state != VCpuState::WaitForSipi {
                self.last_error = Some(SmpError::SipiWithoutInit);
                continue;
            }
            self.vcpus[index].arm_startup(vector, startup_at, retry_at);
            effects.push(IpiEffect {
                target,
                kind: IpiKind::Startup { vector },
                deliver_at: now,
            });
        }
        effects
    }

    /// Emits one effect per target for an already-decoded delivery.
    fn deliver_broadcast(&mut self, targets: &Targets, kind: IpiKind, now: u64) -> Effects {
        let mut effects = Effects::new();
        for &target in targets.as_slice() {
            effects.push(IpiEffect {
                target,
                kind,
                deliver_at: now,
            });
        }
        effects
    }

    /// Expands the ICR destination (destination field or shorthand).
    ///
    /// Returns `None` (and records [`SmpError`]) when the delivery cannot
    /// target any modeled vCPU.
    fn expand_targets(&mut self, source: u8, icr: &Icr) -> Option<Targets> {
        let mut targets = Targets::new();
        if self.index_of(source).is_none() {
            self.last_error = Some(SmpError::UnknownSource);
            return None;
        }
        match icr.shorthand() {
            Shorthand::SelfOnly => targets.push(source),
            Shorthand::AllIncludingSelf => {
                for &id in &self.ids[..self.count] {
                    targets.push(id);
                }
            }
            Shorthand::AllExcludingSelf => {
                for &id in &self.ids[..self.count] {
                    if id != source {
                        targets.push(id);
                    }
                }
            }
            Shorthand::None => match icr.destination_mode() {
                DestinationMode::Physical => {
                    let destination = icr.destination_field();
                    if self.index_of(destination).is_some() {
                        targets.push(destination);
                    } else {
                        self.last_error = Some(SmpError::DestinationUnavailable);
                        return None;
                    }
                }
                DestinationMode::Logical => match self.logical_mode {
                    LogicalMode::Flat => {
                        let mask = icr.destination_field();
                        for &id in &self.ids[..self.count] {
                            if id < 8 && mask & (1 << id) != 0 {
                                targets.push(id);
                            }
                        }
                        if targets.len == 0 {
                            self.last_error = Some(SmpError::DestinationUnavailable);
                            return None;
                        }
                    }
                    LogicalMode::Cluster => {
                        self.last_error = Some(SmpError::ClusterModeUnsupported);
                        return None;
                    }
                },
            },
        }
        if targets.len == 0 {
            self.last_error = Some(SmpError::DestinationUnavailable);
            None
        } else {
            Some(targets)
        }
    }

    /// Controller index of a local APIC identifier.
    fn index_of(&self, lapic_id: u8) -> Option<usize> {
        self.ids[..self.count].iter().position(|id| *id == lapic_id)
    }
}

impl Default for SmpController {
    fn default() -> Self {
        Self::new(DEFAULT_TSC_HZ)
    }
}
