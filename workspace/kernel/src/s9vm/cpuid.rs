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

//! s9vm : guest CPU description (CPUID model).
//!
//! The guest never executes the host `CPUID` instruction: the exit is
//! intercepted and replayed in the kernel from a [`CpuidPolicy`]. This module
//! is the **pure** model behind that replay: it performs no hardware access,
//! holds no global state and can therefore be compiled and exercised on the
//! host.
//!
//! # Model
//!
//! A [`CpuidPolicy`] describes one guest-visible processor:
//!
//! | Leaf | Contents |
//! |---|---|
//! | `0x0000_0000` | max basic leaf, 12-byte vendor string |
//! | `0x0000_0001` | family/model/stepping, topology count, feature masks |
//! | `0x0000_0004` | deterministic cache: zero (no cache hierarchy modelled) |
//! | `0x0000_0007` | structured extended features: zero |
//! | `0x0000_000B` | topology enumeration (SMT + core levels) |
//! | `0x0000_000D` | XSAVE state: zero (XSAVE is not advertised) |
//! | `0x0000_0015` | TSC/core-crystal ratio and crystal frequency |
//! | `0x0000_0016` | nominal base frequency, in MHz |
//! | `0x0000_001F` | extended topology enumeration (same topology) |
//! | `0x8000_0000` | max extended leaf |
//! | `0x8000_0001` | extended features (NX, long mode, `SYSCALL`, `RDTSCP`) |
//! | `0x8000_0002..=0x8000_0004` | 48-byte processor brand string |
//! | `0x8000_0007` | invariant TSC bit (always set: the TSC is never offset) |
//! | `0x8000_0008` | physical/virtual address sizes |
//!
//! Every other leaf : including the `0x4000_0000` hypervisor range : returns
//! zeros. A guest probing an unimplemented feature therefore sees it as absent
//! instead of reading stale or host-derived values.
//!
//! # Invariants
//!
//! - **No nested virtualization**: the VMX bit (`leaf 1`, `ECX[5]`) can never
//!   be set, not even through [`CpuidPolicy::set_feature`], and the SVM bit
//!   (`0x8000_0001`, `ECX[2]`) is never advertised. A guest must not believe
//!   it can run its own hypervisor on this CPU.
//! - **No hypervisor present bit**: `leaf 1`, `ECX[31]` stays clear; s9vm does
//!   not provide a hypervisor CPUID interface, so the `0x4000_0000` range is
//!   zeroed.
//! - **Deterministic and total**: [`CpuidPolicy::leaf`] is a pure function of
//!   its arguments and the policy. It never panics, never blocks and returns
//!   the same four words for the same inputs. The single documented exception
//!   is the host fallback of the TSC leaves (`0x15`, `0x16`): when the policy
//!   fields are zero, the host frequency cache of [`crate::s9vm::tsc`] is read
//!   (it is immutable after detection); once a caller publishes explicit
//!   leaves the replay is again a pure function of the policy.
//! - **Coherent feature set**: only bits that the implementation can actually
//!   honour are set by default. XSAVE/OSXSAVE, AVX and the `leaf 0x0000_0007`
//!   features are deliberately absent because their instructions and
//!   `XGETBV` are not modelled.
//!
//! # Limits
//!
//! The model is **per world**, not per vCPU: topology leaves report package
//! and APIC identifier 0. An SMP guest would need the APIC identifier of the
//! executing vCPU, which the current `leaf(leaf, subleaf)` signature does not
//! take; that is a future evolution of the ABI (per-vCPU policy or an explicit
//! APIC id parameter). Until then [`CpuidPolicy::cores`] and
//! [`CpuidPolicy::threads`] only shape the counts advertised by leaves
//! `0x0000_000B`, `0x0000_001F` and `0x8000_0008`.
//!
//! The TSC leaves assume an **invariant host TSC**: s9vm never offsets or
//! scales the time-stamp counter, so the guest TSC is the host TSC. On a host
//! without an invariant TSC the guest clock would drift with the P-state; the
//! invariant bit is nevertheless published because s9vm itself cannot violate
//! that property any further (it adds no offset and no scaling).

use super::tsc::TscFrequency;

// --- Identity --------------------------------------------------------------

/// Length in bytes of the CPUID vendor string (three 32-bit words).
pub const VENDOR_LEN: usize = 12;

/// Vendor string reported by `CPUID.0`. Exactly twelve bytes, never padded.
///
/// The value is a synthetic identifier: it does not name any real vendor, so
/// guest software cannot apply a real vendor's quirks to s9vm.
pub const VENDOR: [u8; VENDOR_LEN] = *b"S9VMSTRAT9OS";

/// Length in bytes of the processor brand string.
pub const BRAND_LEN: usize = 48;

/// Processor brand string reported by leaves `0x8000_0002..=0x8000_0004`.
///
/// The string is stored zero-padded to [`BRAND_LEN`] bytes. It is deliberately
/// simple: a guest that prints it sees an explicitly virtual processor instead
/// of a host identifier.
pub const BRAND: [u8; BRAND_LEN] = build_brand();

/// Base family reported in `CPUID.1:EAX`.
pub const BASE_FAMILY: u32 = 6;

/// Base model reported in `CPUID.1:EAX` (recent but synthetic; no
/// model-specific behaviour is implemented).
pub const BASE_MODEL: u32 = 0x8C;

/// Stepping reported in `CPUID.1:EAX`.
pub const BASE_STEPPING: u32 = 0x01;

/// Guest-physical address bits reported by `0x8000_0008:EAX[7:0]`.
pub const PHYSICAL_ADDRESS_BITS: u32 = 36;

/// Guest-virtual address bits reported by `0x8000_0008:EAX[15:8]`.
pub const VIRTUAL_ADDRESS_BITS: u32 = 48;

// --- Leaf numbers ----------------------------------------------------------

/// `CPUID.0`: max basic leaf and vendor string.
pub const LEAF_VENDOR: u32 = 0x0000_0000;
/// `CPUID.1`: version information and feature bits.
pub const LEAF_FEATURES: u32 = 0x0000_0001;
/// `CPUID.4`: deterministic cache parameters.
pub const LEAF_CACHE: u32 = 0x0000_0004;
/// `CPUID.7`: structured extended feature flags.
pub const LEAF_STRUCTURED_FEATURES: u32 = 0x0000_0007;
/// `CPUID.0xB`: topology enumeration.
pub const LEAF_TOPOLOGY: u32 = 0x0000_000B;
/// `CPUID.0xD`: XSAVE state components.
pub const LEAF_XSAVE: u32 = 0x0000_000D;
/// `CPUID.0x15`: TSC/core-crystal ratio and core-crystal frequency.
pub const LEAF_TSC_RATIO: u32 = 0x0000_0015;
/// `CPUID.0x16`: nominal processor base frequency.
pub const LEAF_BASE_FREQUENCY: u32 = 0x0000_0016;
/// `CPUID.0x1F`: extended topology enumeration.
pub const LEAF_TOPOLOGY_V2: u32 = 0x0000_001F;
/// `CPUID.0x8000_0000`: max extended leaf.
pub const LEAF_EXTENDED_MAX: u32 = 0x8000_0000;
/// `CPUID.0x8000_0001`: extended feature bits.
pub const LEAF_EXTENDED_FEATURES: u32 = 0x8000_0001;
/// `CPUID.0x8000_0007`: invariant TSC and advanced power management.
///
/// Only the invariant-TSC bit is published: s9vm adds no TSC offset and no
/// scaling, so the guest TSC is the host TSC.
pub const LEAF_EXTENDED_FREQUENCY: u32 = 0x8000_0007;
/// Bit 8 of `CPUID.0x8000_0007:EDX`: the TSC is invariant.
///
/// Kept in sync with [`crate::s9vm::tsc::INVARIANT_TSC_BIT`]; duplicated here
/// so the CPUID model stays readable without a cross-module constant.
pub const INVARIANT_TSC_BIT: u32 = 1 << 8;
/// First brand string leaf (`0x8000_0002`); the brand spans three leaves.
pub const LEAF_BRAND: u32 = 0x8000_0002;
/// `CPUID.0x8000_0008`: address size information.
pub const LEAF_EXTENDED_ADDRESS_SIZES: u32 = 0x8000_0008;

/// Highest basic leaf advertised by the default policy.
///
/// Leaf `0x0000_001F` is the last one that carries information; leaves between
/// the implementation-specific ranges simply return zeros.
pub const MAX_BASIC_LEAF: u32 = LEAF_TOPOLOGY_V2;

/// Highest extended leaf advertised by the default policy.
pub const MAX_EXTENDED_LEAF: u32 = LEAF_EXTENDED_ADDRESS_SIZES;

// --- Feature bits ----------------------------------------------------------

/// Bits of `CPUID.1:ECX` defined by this model.
pub mod leaf1_ecx {
    /// Streaming SIMD extensions 3.
    pub const SSE3: u32 = 1 << 0;
    /// Carry-less multiplication (`PCLMULQDQ`).
    pub const PCLMUL: u32 = 1 << 1;
    /// Supplemental SSE3.
    pub const SSSE3: u32 = 1 << 9;
    /// SSE4.1.
    pub const SSE4_1: u32 = 1 << 19;
    /// SSE4.2.
    pub const SSE4_2: u32 = 1 << 20;
    /// x2APIC (MSR-based local APIC interface).
    pub const X2APIC: u32 = 1 << 21;
    /// Population count instruction.
    pub const POPCNT: u32 = 1 << 23;
    /// TSC deadline timer.
    pub const TSC_DEADLINE: u32 = 1 << 24;
    /// VMX (nested virtualization). **Never advertised**: s9vm does not
    /// virtualize VMX itself.
    pub const VMX: u32 = 1 << 5;
}

/// Bits of `CPUID.1:EDX` defined by this model.
pub mod leaf1_edx {
    /// x87 floating-point unit.
    pub const FPU: u32 = 1 << 0;
    /// Time-stamp counter.
    pub const TSC: u32 = 1 << 4;
    /// Model-specific registers (`RDMSR`/`WRMSR`).
    pub const MSR: u32 = 1 << 5;
    /// Physical address extension.
    pub const PAE: u32 = 1 << 6;
    /// `CMPXCHG8B`.
    pub const CX8: u32 = 1 << 8;
    /// On-chip local APIC.
    pub const APIC: u32 = 1 << 9;
    /// `SYSENTER`/`SYSEXIT`.
    pub const SEP: u32 = 1 << 11;
    /// Conditional move instructions.
    pub const CMOV: u32 = 1 << 15;
    /// Page attribute table.
    pub const PAT: u32 = 1 << 16;
    /// `CLFLUSH`.
    pub const CLFSH: u32 = 1 << 19;
    /// MMX.
    pub const MMX: u32 = 1 << 23;
    /// `FXSAVE`/`FXRSTOR`.
    pub const FXSR: u32 = 1 << 24;
    /// SSE.
    pub const SSE: u32 = 1 << 25;
    /// SSE2.
    pub const SSE2: u32 = 1 << 26;
}

/// Bits of `CPUID.0x8000_0001:ECX` defined by this model.
pub mod extended1_ecx {
    /// `LAHF`/`SAHF` in 64-bit mode.
    pub const LAHF_LM: u32 = 1 << 0;
    /// Secure virtual machine (AMD). **Never advertised**: s9vm does not
    /// virtualize SVM.
    pub const SVM: u32 = 1 << 2;
}

/// Bits of `CPUID.0x8000_0001:EDX` defined by this model.
pub mod extended1_edx {
    /// `SYSCALL`/`SYSRET` in 64-bit mode.
    pub const SYSCALL: u32 = 1 << 11;
    /// No-execute page protection.
    pub const NX: u32 = 1 << 20;
    /// One-gigabyte pages (not modelled by the guest page tables).
    pub const PAGE_1GB: u32 = 1 << 26;
    /// `RDTSCP`.
    pub const RDTSCP: u32 = 1 << 27;
    /// Long mode (IA-32e).
    pub const LONG_MODE: u32 = 1 << 29;
}

/// Bits that this model can never advertise in `CPUID.1:ECX`.
pub const LEAF1_ECX_FORBIDDEN: u32 = leaf1_ecx::VMX;

/// Bits that this model can never advertise in `CPUID.0x8000_0001:ECX`.
pub const EXTENDED1_ECX_FORBIDDEN: u32 = extended1_ecx::SVM;

/// Default `CPUID.1:ECX`: early-boot SIMD bits plus x2APIC and TSC-deadline.
pub const DEFAULT_LEAF1_ECX: u32 = leaf1_ecx::SSE3
    | leaf1_ecx::PCLMUL
    | leaf1_ecx::SSSE3
    | leaf1_ecx::SSE4_1
    | leaf1_ecx::SSE4_2
    | leaf1_ecx::X2APIC
    | leaf1_ecx::POPCNT
    | leaf1_ecx::TSC_DEADLINE;

/// Default `CPUID.1:EDX`: the baseline a 64-bit guest needs to boot.
pub const DEFAULT_LEAF1_EDX: u32 = leaf1_edx::FPU
    | leaf1_edx::TSC
    | leaf1_edx::MSR
    | leaf1_edx::PAE
    | leaf1_edx::CX8
    | leaf1_edx::APIC
    | leaf1_edx::SEP
    | leaf1_edx::CMOV
    | leaf1_edx::PAT
    | leaf1_edx::CLFSH
    | leaf1_edx::MMX
    | leaf1_edx::FXSR
    | leaf1_edx::SSE
    | leaf1_edx::SSE2;

/// Default `CPUID.0x8000_0001:ECX`.
pub const DEFAULT_EXTENDED1_ECX: u32 = 0;

/// Default `CPUID.0x8000_0001:EDX`: the 64-bit execution environment.
pub const DEFAULT_EXTENDED1_EDX: u32 =
    extended1_edx::SYSCALL | extended1_edx::NX | extended1_edx::RDTSCP | extended1_edx::LONG_MODE;

/// Builds the zero-padded brand string.
const fn build_brand() -> [u8; BRAND_LEN] {
    let text = b"s9vm virtual CPU";
    let mut out = [0u8; BRAND_LEN];
    let mut index = 0;
    while index < text.len() && index < BRAND_LEN {
        out[index] = text[index];
        index += 1;
    }
    out
}

// --- Feature selector ------------------------------------------------------

/// One bit of a CPUID feature register, used by
/// [`CpuidPolicy::set_feature`] and [`CpuidPolicy::clear_feature`].
///
/// The payload is the bit number; numbers above 31 wrap (`bit % 32`), which
/// keeps the helpers total instead of panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Bit of `CPUID.1:ECX`.
    Leaf1Ecx(u8),
    /// Bit of `CPUID.1:EDX`.
    Leaf1Edx(u8),
    /// Bit of `CPUID.0x8000_0001:ECX`.
    Extended1Ecx(u8),
    /// Bit of `CPUID.0x8000_0001:EDX`.
    Extended1Edx(u8),
}

/// Guest-visible CPU description.
///
/// The policy is a small `Copy` value: the exit loop keeps one per world in
/// its [`crate::s9vm::machine::Machine`] and replays every `CPUID` exit against
/// it. [`CpuidPolicy::default`] is a safe, boot-capable 64-bit profile:
/// family 6, one core, one thread, no nested virtualization, no XSAVE.
///
/// The fields are public so the syscall layer can assemble a policy from the
/// ABI structure; the accessors and feature helpers enforce the invariants
/// documented at module level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidPolicy {
    /// Highest basic leaf, reported by `CPUID.0:EAX`.
    pub max_basic_leaf: u32,
    /// Highest extended leaf, reported by `CPUID.0x8000_0000:EAX`.
    pub max_extended_leaf: u32,
    /// Guest-visible family (`CPUID.1:EAX[11:8]`).
    pub family: u32,
    /// Guest-visible model, extended-model bits included.
    pub model: u32,
    /// Guest-visible stepping.
    pub stepping: u32,
    /// Number of physical cores per package (at least one).
    pub cores: u32,
    /// Number of hardware threads per core (at least one).
    pub threads: u32,
    /// Raw `CPUID.1:ECX` mask; forbidden bits are filtered when read.
    pub leaf1_ecx: u32,
    /// Raw `CPUID.1:EDX` mask.
    pub leaf1_edx: u32,
    /// Raw `CPUID.0x8000_0001:ECX` mask; forbidden bits are filtered when
    /// read.
    pub extended1_ecx: u32,
    /// Raw `CPUID.0x8000_0001:EDX` mask.
    pub extended1_edx: u32,
    /// `CPUID.0x15:EAX` : TSC/core-crystal ratio denominator.
    ///
    /// Zero publishes the host value from the [`crate::s9vm::tsc`] cache, or
    /// nothing when the host frequency is unknown.
    pub tsc_ratio_denominator: u32,
    /// `CPUID.0x15:EBX` : TSC/core-crystal ratio numerator.
    pub tsc_ratio_numerator: u32,
    /// `CPUID.0x15:ECX` : core-crystal frequency, in hertz.
    pub crystal_hz: u32,
    /// `CPUID.0x16:EAX` : nominal base frequency, in megahertz.
    pub base_mhz: u32,
}

impl CpuidPolicy {
    /// Builds the safe default profile.
    ///
    /// This is a `const fn` so a policy can back a `static` without runtime
    /// initialization.
    pub const fn new() -> Self {
        Self {
            max_basic_leaf: MAX_BASIC_LEAF,
            max_extended_leaf: MAX_EXTENDED_LEAF,
            family: BASE_FAMILY,
            model: BASE_MODEL,
            stepping: BASE_STEPPING,
            cores: 1,
            threads: 1,
            leaf1_ecx: DEFAULT_LEAF1_ECX,
            leaf1_edx: DEFAULT_LEAF1_EDX,
            extended1_ecx: DEFAULT_EXTENDED1_ECX,
            extended1_edx: DEFAULT_EXTENDED1_EDX,
            tsc_ratio_denominator: 0,
            tsc_ratio_numerator: 0,
            crystal_hz: 0,
            base_mhz: 0,
        }
    }

    /// Publishes `frequency` in CPUID leaves `0x15` and `0x16`.
    ///
    /// The four fields are filled from
    /// [`TscFrequency::cpuid_leaves`](crate::s9vm::tsc::TscFrequency::cpuid_leaves).
    /// A caller that leaves them at zero keeps the host-derived fallback, which
    /// is the right default for a world that should see the real host TSC.
    pub fn set_tsc_frequency(&mut self, frequency: TscFrequency) {
        let leaves = frequency.cpuid_leaves();
        self.tsc_ratio_denominator = leaves.ratio_denominator;
        self.tsc_ratio_numerator = leaves.ratio_numerator;
        self.crystal_hz = leaves.crystal_hz;
        self.base_mhz = leaves.base_mhz;
    }

    /// Number of logical processors per package, clamped to the 8-bit
    /// `CPUID.1:EBX[23:16]` field. Never zero: an empty policy still describes
    /// one processor.
    pub fn logical_processors(&self) -> u32 {
        self.cores
            .max(1)
            .saturating_mul(self.threads.max(1))
            .min(0xFF)
    }

    /// Effective `CPUID.1:ECX`, with the forbidden bits cleared.
    pub fn effective_leaf1_ecx(&self) -> u32 {
        self.leaf1_ecx & !LEAF1_ECX_FORBIDDEN
    }

    /// Effective `CPUID.0x8000_0001:ECX`, with the forbidden bits cleared.
    pub fn effective_extended1_ecx(&self) -> u32 {
        self.extended1_ecx & !EXTENDED1_ECX_FORBIDDEN
    }

    /// `CPUID.1:EAX`: stepping, model and family encoding.
    ///
    /// The extended model field is used when `model > 0x0F`; the extended
    /// family field is only used for families at or above `0x0F`, which the
    /// default never is. Bits outside the architectural fields are zero.
    pub fn signature(&self) -> u32 {
        // Families at or above 0x0F set the base field to 0x0F and carry the
        // remainder in the extended family field.
        let (base_family, extended_family) = if self.family >= 0x0F {
            (0x0Fu32, (self.family - 0x0F) & 0xFF)
        } else {
            (self.family & 0x0F, 0)
        };
        let base_model = self.model & 0x0F;
        let extended_model = (self.model >> 4) & 0x0F;
        (self.stepping & 0x0F)
            | (base_model << 4)
            | (base_family << 8)
            | (extended_model << 16)
            | (extended_family << 20)
    }

    /// Sets one feature bit.
    ///
    /// Forbidden bits ([`LEAF1_ECX_FORBIDDEN`], [`EXTENDED1_ECX_FORBIDDEN`])
    /// are silently ignored: a caller can never enable nested virtualization
    /// through this helper.
    pub fn set_feature(&mut self, feature: Feature) {
        let mask = feature_mask(feature.bit());
        match feature {
            Feature::Leaf1Ecx(_) => self.leaf1_ecx |= mask & !LEAF1_ECX_FORBIDDEN,
            Feature::Leaf1Edx(_) => self.leaf1_edx |= mask,
            Feature::Extended1Ecx(_) => self.extended1_ecx |= mask & !EXTENDED1_ECX_FORBIDDEN,
            Feature::Extended1Edx(_) => self.extended1_edx |= mask,
        }
    }

    /// Clears one feature bit.
    pub fn clear_feature(&mut self, feature: Feature) {
        let mask = feature_mask(feature.bit());
        match feature {
            Feature::Leaf1Ecx(_) => self.leaf1_ecx &= !mask,
            Feature::Leaf1Edx(_) => self.leaf1_edx &= !mask,
            Feature::Extended1Ecx(_) => self.extended1_ecx &= !mask,
            Feature::Extended1Edx(_) => self.extended1_edx &= !mask,
        }
    }

    /// Reports whether one feature bit is in effect, forbidden bits included.
    pub fn has_feature(&self, feature: Feature) -> bool {
        let mask = feature_mask(feature.bit());
        match feature {
            Feature::Leaf1Ecx(_) => self.effective_leaf1_ecx() & mask != 0,
            Feature::Leaf1Edx(_) => self.leaf1_edx & mask != 0,
            Feature::Extended1Ecx(_) => self.effective_extended1_ecx() & mask != 0,
            Feature::Extended1Edx(_) => self.extended1_edx & mask != 0,
        }
    }

    /// Replays one `CPUID` instruction: returns `[EAX, EBX, ECX, EDX]`.
    ///
    /// The function is total and deterministic. `leaf == 0` always answers
    /// with the advertised basic range; a basic leaf above
    /// [`CpuidPolicy::max_basic_leaf`] and an extended leaf above
    /// [`CpuidPolicy::max_extended_leaf`] return zeros, as does every leaf
    /// this model does not implement (notably the `0x4000_0000` hypervisor
    /// range, because the hypervisor-present bit is never set).
    pub fn leaf(&self, leaf: u32, subleaf: u32) -> [u32; 4] {
        // Leaf 0 is always available: it advertises the range itself.
        if leaf == LEAF_VENDOR {
            return self.vendor_leaf();
        }

        // Basic range. The split point is deliberately the architectural
        // boundary between basic and extended leaves, not the advertised max:
        // a leaf outside the advertised range must read as zero even if later
        // policy code happens to implement it.
        if leaf <= 0x0000_FFFF {
            if leaf > self.max_basic_leaf {
                return [0; 4];
            }
            return match leaf {
                LEAF_FEATURES => self.feature_leaf(),
                LEAF_CACHE => [0; 4],
                LEAF_STRUCTURED_FEATURES => [0; 4],
                LEAF_TOPOLOGY | LEAF_TOPOLOGY_V2 => self.topology_leaf(subleaf),
                LEAF_XSAVE => [0; 4],
                LEAF_TSC_RATIO => self.tsc_ratio_leaf(),
                LEAF_BASE_FREQUENCY => self.base_frequency_leaf(),
                _ => [0; 4],
            };
        }

        // Extended range, plus the 0x4000_0000..0x7FFF_FFFF hypervisor range
        // which is intentionally not implemented.
        if leaf == LEAF_EXTENDED_MAX {
            return [self.max_extended_leaf, 0, 0, 0];
        }
        if leaf < LEAF_EXTENDED_MAX || leaf > self.max_extended_leaf {
            return [0; 4];
        }
        match leaf {
            LEAF_EXTENDED_FEATURES => self.extended_features_leaf(),
            LEAF_EXTENDED_FREQUENCY => self.extended_frequency_leaf(),
            LEAF_BRAND..=0x8000_0004 => self.brand_leaf(leaf),
            LEAF_EXTENDED_ADDRESS_SIZES => self.address_sizes_leaf(),
            _ => [0; 4],
        }
    }

    /// `CPUID.0`: max basic leaf and vendor string.
    fn vendor_leaf(&self) -> [u32; 4] {
        let mut words = [0u32; 3];
        let mut index = 0;
        while index < 3 {
            let offset = index * 4;
            words[index] = u32::from_le_bytes([
                VENDOR[offset],
                VENDOR[offset + 1],
                VENDOR[offset + 2],
                VENDOR[offset + 3],
            ]);
            index += 1;
        }
        // Architectural order: EBX, EDX, ECX.
        [self.max_basic_leaf, words[0], words[2], words[1]]
    }

    /// `CPUID.1`: signature, topology count and feature masks.
    fn feature_leaf(&self) -> [u32; 4] {
        // Brand index 0, 64-byte cache line (8 dwords), logical processors per
        // package, initial APIC id 0.
        let ebx = (8 << 8) | ((self.logical_processors() & 0xFF) << 16);
        [
            self.signature(),
            ebx,
            self.effective_leaf1_ecx(),
            self.leaf1_edx,
        ]
    }

    /// `CPUID.0x8000_0001`: extended feature masks.
    fn extended_features_leaf(&self) -> [u32; 4] {
        // EAX and EBX are reserved in this leaf.
        [0, 0, self.effective_extended1_ecx(), self.extended1_edx]
    }

    /// `CPUID.0x15`: TSC/core-crystal ratio and crystal frequency.
    ///
    /// The policy fields win when they form a usable ratio (non-zero
    /// denominator, numerator and crystal). Otherwise the host frequency cache
    /// is consulted, so a guest sees the real host TSC frequency even when the
    /// policy was not explicitly tuned; when neither source is available the
    /// leaf reads as zero and the guest falls back to leaf `0x16` or to
    /// calibration.
    fn tsc_ratio_leaf(&self) -> [u32; 4] {
        if self.tsc_ratio_denominator != 0 && self.tsc_ratio_numerator != 0 && self.crystal_hz != 0
        {
            return [
                self.tsc_ratio_denominator,
                self.tsc_ratio_numerator,
                self.crystal_hz,
                0,
            ];
        }
        match super::tsc::get() {
            Some(frequency) => {
                let leaves = frequency.cpuid_leaves();
                [
                    leaves.ratio_denominator,
                    leaves.ratio_numerator,
                    leaves.crystal_hz,
                    0,
                ]
            }
            None => [0; 4],
        }
    }

    /// `CPUID.0x16`: nominal base frequency in `EAX` (megahertz).
    ///
    /// The policy field wins; otherwise the host frequency cache is truncated
    /// to megahertz. Zero means "not published".
    fn base_frequency_leaf(&self) -> [u32; 4] {
        if self.base_mhz != 0 {
            return [self.base_mhz, 0, 0, 0];
        }
        match super::tsc::get() {
            Some(frequency) => [frequency.cpuid_leaves().base_mhz, 0, 0, 0],
            None => [0; 4],
        }
    }

    /// `CPUID.0x8000_0007`: invariant TSC bit in `EDX`.
    ///
    /// Only bit 8 is set: the guest TSC is the host TSC, s9vm never offsets or
    /// scales it, so the invariant-TSC guarantee is published unconditionally.
    /// Advanced power-management bits are not advertised.
    fn extended_frequency_leaf(&self) -> [u32; 4] {
        [0, 0, 0, INVARIANT_TSC_BIT]
    }

    /// `CPUID.0x8000_0002..=0x8000_0004`: one quarter of the brand string.
    fn brand_leaf(&self, leaf: u32) -> [u32; 4] {
        let mut result = [0u32; 4];
        let base = (leaf - LEAF_BRAND) as usize * 16;
        let mut index = 0;
        while index < 4 {
            let offset = base + index * 4;
            result[index] = u32::from_le_bytes([
                BRAND[offset],
                BRAND[offset + 1],
                BRAND[offset + 2],
                BRAND[offset + 3],
            ]);
            index += 1;
        }
        result
    }

    /// `CPUID.0x8000_0008`: physical and virtual address sizes.
    fn address_sizes_leaf(&self) -> [u32; 4] {
        // EBX (number of cores - 1) is only defined by AMD; topology is
        // advertised through leaves 0x0B/0x1F instead.
        [PHYSICAL_ADDRESS_BITS | (VIRTUAL_ADDRESS_BITS << 8), 0, 0, 0]
    }

    /// Topology enumeration, shared by `CPUID.0x0B` and `CPUID.0x1F`.
    ///
    /// Both leaves use the same `ECX[15:8]` level-type encoding (1 = SMT,
    /// 2 = core) and terminate with an invalid type. `0x1F` additionally
    /// carries the x2APIC identifier in `EDX[31:16]`; with a single package
    /// identifier 0 both variants return the same words.
    fn topology_leaf(&self, subleaf: u32) -> [u32; 4] {
        match subleaf {
            // SMT level: `threads` logical processors sharing this core.
            0 => [0, self.threads.max(1), 1 << 8, 0],
            // Core level: `cores * threads` logical processors in the package.
            1 => [1, self.logical_processors(), 2 << 8, 0],
            // Invalid level type terminates the enumeration.
            _ => [0; 4],
        }
    }
}

impl Default for CpuidPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl Feature {
    /// Bit number carried by the selector.
    fn bit(self) -> u8 {
        match self {
            Feature::Leaf1Ecx(bit)
            | Feature::Leaf1Edx(bit)
            | Feature::Extended1Ecx(bit)
            | Feature::Extended1Edx(bit) => bit,
        }
    }
}

/// Builds a one-bit mask, wrapping the bit number instead of panicking.
fn feature_mask(bit: u8) -> u32 {
    1u32 << (bit & 31)
}
