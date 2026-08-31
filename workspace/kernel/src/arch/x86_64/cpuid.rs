//! CPU feature detection via CPUID instruction.
//!
//! Provides a `CpuInfo` struct populated at boot time with vendor, model,
//! feature flags, and XSAVE geometry. All subsequent queries go through
//! `host()` which returns the cached result.

use crate::sync::SpinLock;
use alloc::string::String;
use bitflags::bitflags;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};


bitflags! {
    /// Logical internal bitmap.
    ///
    /// Bit positions do NOT match raw CPUID register positions: flags coming
    /// from different leaves/sub-registers are reallocated into one `u64`
    /// space (SMEP/SMAP are deliberately relocated high to avoid collisions).
    /// Only compare through the named constants — never raw bit positions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuFeatures: u64 {
        //  Leaf 0x01 ECX
        const SSE3      = 1 << 0;
        const SSSE3     = 1 << 1;
        const FMA       = 1 << 2;
        const SSE4_1    = 1 << 3;
        const SSE4_2    = 1 << 4;
        const POPCNT    = 1 << 5;
        const AES_NI    = 1 << 6;
        const XSAVE     = 1 << 7;
        const OSXSAVE   = 1 << 8;
        const AVX       = 1 << 12;
        const F16C      = 1 << 9;
        const VMX       = 1 << 10;
        const X2APIC    = 1 << 11;
        //  Leaf 0x01 EDX
        const FPU       = 1 << 16;
        const TSC       = 1 << 17;
        const APIC      = 1 << 18;
        const SSE       = 1 << 19;
        const SSE2      = 1 << 20;
        const FXSR      = 1 << 21;
        //  Leaf 0x07 ECX
        const SMEP      = 1 << 57; // CPUID(7).EBX bit 7 (relocated to avoid collision)
        const SMAP      = 1 << 58; // CPUID(7).EBX bit 20 (relocated to avoid collision)
        //  Leaf 0x07 EBX
        const AVX2      = 1 << 32;
        const AVX512F   = 1 << 33;
        const AVX512BW  = 1 << 34;
        const AVX512VL  = 1 << 35;
        const SHA       = 1 << 36;
        //  Leaf 0x80000001 EDX
        const NX        = 1 << 48;
        const PAGES_1G  = 1 << 49;
        const RDTSCP    = 1 << 50;
        const LONG_MODE = 1 << 51;
        //  Leaf 0x80000001 ECX
        const SVM       = 1 << 56;
    }
}

/// XCR0 component bits.
pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_AVX: u64 = 1 << 2;
pub const XCR0_OPMASK: u64 = 1 << 5;
pub const XCR0_ZMM_HI256: u64 = 1 << 6;
pub const XCR0_HI16_ZMM: u64 = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

/// Cached CPU identification and feature information.
#[derive(Debug, Clone)]
pub struct CpuInfo {
    pub vendor: CpuVendor,
    /// Raw CPUID(0) vendor string (EBX:EDX:ECX, 12 bytes, not NUL-terminated).
    /// Preserves vendors classified as [`CpuVendor::Unknown`] by
    /// [`Self::vendor_string`].
    pub vendor_id: [u8; 12],
    pub features: CpuFeatures,
    /// Bitmap of extended state components the CPU supports
    /// (CPUID.(0D,0):EDX:EAX). Capability bitmap, not a maximum value.
    pub supported_xcr0: u64,
    /// XSAVE area size (bytes) for the components enabled in XCR0 at
    /// detect() time (CPUID.(0D,0):EBX). Depends on the OS-enabled state —
    /// use [`xsave_size_for_xcr0`] for arbitrary masks.
    pub xsave_size_current: usize,
    /// XSAVE area size (bytes) required if every supported component were
    /// enabled (CPUID.(0D,0):ECX). Upper bound for synthetic XCR0 masks.
    pub xsave_size_max: usize,
    pub family: u16,
    pub model: u8,
    pub stepping: u8,
    pub model_name: [u8; 48],
    model_name_len: usize,
}

impl CpuInfo {
    /// Return the model name as a `&str`.
    pub fn model_name_str(&self) -> &str {
        let bytes = &self.model_name[..self.model_name_len];
        core::str::from_utf8(bytes).unwrap_or("Unknown")
    }

    /// Return a vendor id string (e.g. "GenuineIntel").
    pub fn vendor_string(&self) -> &'static str {
        match self.vendor {
            CpuVendor::Intel => "GenuineIntel",
            CpuVendor::Amd => "AuthenticAMD",
            CpuVendor::Unknown => "Unknown",
        }
    }
}

static HOST_CPU: SpinLock<Option<CpuInfo>> = SpinLock::new(None);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Lock-free cache of the host's default XCR0 mask, written once during
/// `init()`.  Used by `normalized_xcr0()` in the context-switch hot path
/// to avoid acquiring the `HOST_CPU` spinlock with interrupts disabled.
pub(crate) static HOST_DEFAULT_XCR0_CACHE: AtomicU64 = AtomicU64::new(0);

/// Cached extended-state save profile, frozen once at `init()`.
///
/// Precomputed so context-switch / task-creation code never walks CPUID
/// leaf 0x0D sub-leaves at runtime (see `xsave_size_for_xcr0`, which is
/// correct but too slow for hot paths).
#[derive(Debug, Clone, Copy)]
pub struct XsaveProfile {
    /// XCR0 mask the kernel programs (x87|SSE|AVX|AVX-512 as available).
    pub xcr0_mask: u64,
    /// Save-area size in bytes for that mask, rounded UP to a 64-byte
    /// multiple so allocators can over-allocate safely.
    pub area_size: usize,
    /// Alignment required by the save instruction: XSAVE/XRSTOR fault (#GP)
    /// on non-64-byte operands; FXSAVE/FXRSTOR only require 16 bytes, but we
    /// standardize on 64 everywhere (over-alignment is harmless).
    pub align: usize,
}

static PROFILE_XCR0: AtomicU64 = AtomicU64::new(0);
static PROFILE_AREA_SIZE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(512);

/// Return the frozen XSAVE profile. Before `init()` (or without XSAVE),
/// returns the conservative FXSAVE baseline (mask=x87|SSE, 512 bytes).
pub fn boot_xsave_profile() -> XsaveProfile {
    let mask = PROFILE_XCR0.load(Ordering::Acquire);
    let size = PROFILE_AREA_SIZE.load(Ordering::Acquire);
    XsaveProfile {
        xcr0_mask: mask,
        area_size: size,
        align: 64,
    }
}

/// Detect and cache CPU information. Must be called once at BSP boot.
pub fn init() {
    crate::e9_mark!(b'X');
    let info = detect();
    crate::e9_mark!(b'Y');
    crate::serial_println!(
        "[CPUID] {} {} (family={} model={} stepping={})",
        info.vendor_string(),
        info.model_name_str(),
        info.family,
        info.model,
        info.stepping,
    );
    crate::serial_println!(
        "[CPUID] features={:?}, supported_xcr0={:#x}, xsave_cur={} xsave_max={}",
        info.features,
        info.supported_xcr0,
        info.xsave_size_current,
        info.xsave_size_max,
    );
    // Compute the default XCR0 *before* publishing `info`, so no reader can
    // observe INITIALIZED=true with a stale/zero XCR0 cache (the previous
    // order relied on the locked fallback to paper over the window).
    let default_xcr0 = default_xcr0_for(&info);
    // Freeze the boot-time save profile: area size for the kernel's chosen
    // mask, rounded up to the 64-byte instruction-alignment granularity.
    //
    // NOTE: compute the size from the *local* `info`, not via the global
    // cache (`xsave_size_for_xcr0`/`host_uses_xsave`). Those consult
    // `INITIALIZED`, which is only published below — so during `init()` they
    // always fall back to 512 bytes even when AVX/AVX-512 is present, leaving
    // the XSAVE area too small and corrupting state on the first AVX context
    // switch.
    let profile_size = xsave_size_for_info(&info, default_xcr0).div_ceil(64) * 64;
    PROFILE_XCR0.store(default_xcr0, Ordering::Release);
    PROFILE_AREA_SIZE.store(profile_size, Ordering::Release);

    crate::e9_mark!(b'J');
    *HOST_CPU.lock() = Some(info);
    crate::e9_mark!(b'K');
    HOST_DEFAULT_XCR0_CACHE.store(default_xcr0, Ordering::Release);
    INITIALIZED.store(true, Ordering::Release);
    crate::e9_mark!(b'i');
}

/// Return a clone of the cached host CPU info. Panics if `init()` not called.
pub fn host() -> CpuInfo {
    HOST_CPU
        .lock()
        .clone()
        .expect("cpuid::init() not called yet")
}

/// Whether XSAVE is supported by the host.
pub fn host_uses_xsave() -> bool {
    INITIALIZED.load(Ordering::Acquire)
        && HOST_CPU
            .lock()
            .as_ref()
            .map_or(false, |h| h.features.contains(CpuFeatures::XSAVE))
}

/// Detect CPU features by interrogating CPUID leaves.
fn detect() -> CpuInfo {
    let cpuid = super::cpuid;

    crate::e9_mark!(b'D');
    //  Vendor (leaf 0): keep the raw 12-byte id, then classify.
    let (max_leaf, ebx0, ecx0, edx0) = cpuid(0, 0);
    crate::e9_mark!(b'E');
    let mut vendor_id = [0u8; 12];
    vendor_id[0..4].copy_from_slice(&ebx0.to_le_bytes());
    vendor_id[4..8].copy_from_slice(&edx0.to_le_bytes());
    vendor_id[8..12].copy_from_slice(&ecx0.to_le_bytes());
    let vendor = match (ebx0, edx0, ecx0) {
        (0x756E_6547, 0x4965_6E69, 0x6C65_746E) => CpuVendor::Intel,
        (0x6874_7541, 0x6974_6E65, 0x444D_4163) => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    };

    let mut features = CpuFeatures::empty();

    //  Leaf 0x01: main feature bits
    crate::e9_mark!(b'1');
    let (eax1, _ebx1, ecx1, edx1) = if max_leaf >= 1 {
            cpuid(1, 0)
    } else {
        (0, 0, 0, 0)
    };
    crate::e9_mark!(b'2');
    crate::e9_mark!(b'd');
    crate::e9_mark!(b'f');
    crate::e9_mark!(b'e');

    let stepping = (eax1 & 0xF) as u8;
    let base_family = (eax1 >> 8) & 0xF;
    let base_model = (eax1 >> 4) & 0xF;
    let ext_model = (eax1 >> 16) & 0xF;
    let ext_family = (eax1 >> 20) & 0xFF;
    let mut family_full: u16 = base_family as u16;
    let mut model: u8 = base_model as u8;
    if base_family == 6 || base_family == 15 {
        model |= (ext_model << 4) as u8;
    }
    if base_family == 15 {
        family_full += ext_family as u16;
    }
    let family = family_full;

    if ecx1 & (1 << 0) != 0 {
        features |= CpuFeatures::SSE3;
    }
    if ecx1 & (1 << 9) != 0 {
        features |= CpuFeatures::SSSE3;
    }
    if ecx1 & (1 << 12) != 0 {
        features |= CpuFeatures::FMA;
    }
    if ecx1 & (1 << 19) != 0 {
        features |= CpuFeatures::SSE4_1;
    }
    if ecx1 & (1 << 20) != 0 {
        features |= CpuFeatures::SSE4_2;
    }
    if ecx1 & (1 << 23) != 0 {
        features |= CpuFeatures::POPCNT;
    }
    if ecx1 & (1 << 25) != 0 {
        features |= CpuFeatures::AES_NI;
    }
    if ecx1 & (1 << 26) != 0 {
        features |= CpuFeatures::XSAVE;
    }
    if ecx1 & (1 << 27) != 0 {
        features |= CpuFeatures::OSXSAVE;
    }
    if ecx1 & (1 << 28) != 0 {
        features |= CpuFeatures::AVX;
    }
    if ecx1 & (1 << 21) != 0 {
        features |= CpuFeatures::X2APIC;
    }
    if ecx1 & (1 << 29) != 0 {
        features |= CpuFeatures::F16C;
    }
    if ecx1 & (1 << 5) != 0 {
        features |= CpuFeatures::VMX;
    }

    if edx1 & (1 << 0) != 0 {
        features |= CpuFeatures::FPU;
    }
    if edx1 & (1 << 4) != 0 {
        features |= CpuFeatures::TSC;
    }
    if edx1 & (1 << 9) != 0 {
        features |= CpuFeatures::APIC;
    }
    if edx1 & (1 << 24) != 0 {
        features |= CpuFeatures::FXSR;
    }
    if edx1 & (1 << 25) != 0 {
        features |= CpuFeatures::SSE;
    }
    if edx1 & (1 << 26) != 0 {
        features |= CpuFeatures::SSE2;
    }

    //  Leaf 0x07: extended features
    crate::e9_mark!(b'3');
    if max_leaf >= 7 {
        let (_eax7, ebx7, _ecx7, _edx7) = cpuid(7, 0);
        crate::e9_mark!(b'5');
        if ebx7 & (1 << 5) != 0 {
            features |= CpuFeatures::AVX2;
        }
        if ebx7 & (1 << 16) != 0 {
            features |= CpuFeatures::AVX512F;
        }
        if ebx7 & (1 << 29) != 0 {
            features |= CpuFeatures::SHA;
        }
        if ebx7 & (1 << 30) != 0 {
            features |= CpuFeatures::AVX512BW;
        }
        if ebx7 & (1 << 31) != 0 {
            features |= CpuFeatures::AVX512VL;
        }
        // SMEP (EBX bit 7): Supervisor Mode Execution Prevention
        if ebx7 & (1 << 7) != 0 {
            features |= CpuFeatures::SMEP;
        }
        // SMAP (EBX bit 20): Supervisor Mode Access Prevention
        if ebx7 & (1 << 20) != 0 {
            features |= CpuFeatures::SMAP;
        }
    }

    //  Leaf 0x0D: XSAVE geometry
    //
    // CPUID.(0D,0):EDX:EAX = bitmap of components supported by the CPU
    // (XCR0 candidates). EBX = size of the save area for the components
    // currently enabled in XCR0 (OS-chosen, not a constant). ECX = size if
    // every supported component were enabled — the correct upper bound for
    // synthetic masks. Supervisor states (managed via IA32_XSS, not XCR0)
    // are filtered out so `supported_xcr0` stays a true XCR0 bitmap.
    crate::e9_mark!(b'F');
    let mut supported_xcr0 = XCR0_X87 | XCR0_SSE;
    let mut xsave_size_current = 512usize;
    let mut xsave_size_max = 512usize;
    crate::e9_mark!(b'G');
    if features.contains(CpuFeatures::XSAVE) && max_leaf >= 0x0D {
        crate::e9_mark!(b'H');
        let (eax_d, ebx_d, ecx_d, edx_d) = cpuid(0x0D, 0);
        crate::e9_mark!(b'I');
        let raw = ((edx_d as u64) << 32) | eax_d as u64;
        // Keep the full hardware-reported XCR0 bitmap.  The kernel
        // applies its own policy mask in default_xcr0_for() rather than
        // hiding capability bits from the rest of the codebase.
        supported_xcr0 = raw;
        xsave_size_current = ebx_d as usize;
        xsave_size_max = ecx_d as usize;
    }

    //  Leaf 0x80000001: extended features (AMD-V, NX, 1G pages)
    let (max_ext, _, _, _) = cpuid(0x8000_0000, 0);
    if max_ext >= 0x8000_0001 {
        let (_eax_e, _ebx_e, ecx_e, edx_e) = cpuid(0x8000_0001, 0);
        if edx_e & (1 << 20) != 0 {
            features |= CpuFeatures::NX;
        }
        if edx_e & (1 << 26) != 0 {
            features |= CpuFeatures::PAGES_1G;
        }
        if edx_e & (1 << 27) != 0 {
            features |= CpuFeatures::RDTSCP;
        }
        if edx_e & (1 << 29) != 0 {
            features |= CpuFeatures::LONG_MODE;
        }
        if ecx_e & (1 << 2) != 0 {
            features |= CpuFeatures::SVM;
        }
    }

    //  Leaves 0x80000002-0x80000004: brand string
    let mut model_name = [0u8; 48];
    let mut model_name_len = 0usize;
    if max_ext >= 0x8000_0004 {
        for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            let (a, b, c, d) = cpuid(leaf, 0);
            let offset = i * 16;
            model_name[offset..offset + 4].copy_from_slice(&a.to_le_bytes());
            model_name[offset + 4..offset + 8].copy_from_slice(&b.to_le_bytes());
            model_name[offset + 8..offset + 12].copy_from_slice(&c.to_le_bytes());
            model_name[offset + 12..offset + 16].copy_from_slice(&d.to_le_bytes());
        }
        model_name_len = model_name
            .iter()
            .rposition(|&b| b != 0 && b != b' ')
            .map_or(0, |p| p + 1);
    }

    CpuInfo {
        vendor,
        vendor_id,
        features,
        supported_xcr0,
        xsave_size_current,
        xsave_size_max,
        family,
        model,
        stepping,
        model_name,
        model_name_len,
    }
}

/// Pure helper: the XCR0 mask this kernel would enable for `info`
/// (x87 + SSE always, plus AVX / AVX-512 states when the CPU announces
/// them AND the hardware supports the required XCR0 bits).
/// Shared by `init()` (pre-lock computation) and `host()`.
fn default_xcr0_for(info: &CpuInfo) -> u64 {
    const SSE_BASE: u64 = XCR0_X87 | XCR0_SSE;
    const AVX_STATE: u64 = SSE_BASE | XCR0_AVX;
    const AVX512_STATE: u64 =
        AVX_STATE | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

    if !info.features.contains(CpuFeatures::XSAVE) {
        return SSE_BASE;
    }

    let available = info.supported_xcr0;
    let mut wanted = SSE_BASE;

    if info.features.contains(CpuFeatures::AVX)
        && (available & AVX_STATE) == AVX_STATE
    {
        wanted = AVX_STATE;
    }

    if info.features.contains(CpuFeatures::AVX512F)
        && (available & AVX512_STATE) == AVX512_STATE
    {
        wanted = AVX512_STATE;
    }

    wanted
}

impl CpuInfo {
    /// Whether AVX may actually be executed: the hardware announces it AND
    /// the kernel enabled the required states (CR4.OSXSAVE via XSAVE +
    /// XCR0 bits 0|1|2). Never gate code paths on `features.contains(AVX)`
    /// alone — that only reflects CPUID, not what the OS programmed.
    pub fn avx_usable(&self) -> bool {
        const REQUIRED: u64 = XCR0_X87 | XCR0_SSE | XCR0_AVX;
        self.features.contains(
            CpuFeatures::AVX
                | CpuFeatures::XSAVE
                | CpuFeatures::OSXSAVE,
        ) && (self.supported_xcr0 & REQUIRED) == REQUIRED
            && crate::arch::x86_64::cpuid_osxsave_enabled()
            && host_default_xcr0() & XCR0_AVX != 0
    }

    /// Whether AVX-512 may actually be executed: hardware support plus all
    /// required XCR0 states enabled (opmask, ZMM_Hi256, HI16_ZMM on top of
    /// x87/SSE/AVX). See `avx_usable`.
    pub fn avx512_usable(&self) -> bool {
        const REQUIRED: u64 =
            XCR0_X87 | XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;
        self.features.contains(
            CpuFeatures::AVX512F
                | CpuFeatures::AVX
                | CpuFeatures::XSAVE
                | CpuFeatures::OSXSAVE,
        ) && (self.supported_xcr0 & REQUIRED) == REQUIRED
            && crate::arch::x86_64::cpuid_osxsave_enabled()
            && host_default_xcr0() & REQUIRED == REQUIRED
    }
}

/// Compute the XCR0 mask for a given set of allowed features,
/// clamped to what the host actually supports.
///
/// NOTE: currently the host default mask is returned regardless of
/// `features` (the kernel enables x87+SSE+AVX(+512) as one global profile).
/// Kept as an API seam for per-feature XCR0 profiles.
pub fn xcr0_for_features(_features: CpuFeatures) -> u64 {
    let h = host();
    default_xcr0_for(&h)
}

/// Compute the XSAVE area size needed for a given XCR0 mask directly from a
/// `CpuInfo`, without consulting the global cache (`host_uses_xsave`/`host`).
/// This is what `init()` must use, because the cache is not yet published when
/// `init()` runs — otherwise AVX/AVX-512 would be given a 512-byte area.
fn xsave_size_for_info(info: &CpuInfo, xcr0: u64) -> usize {
    if !info.features.contains(CpuFeatures::XSAVE) {
        return 512;
    }
    // Clamp to what the CPU actually supports; ignore unknown bits.
    let xcr0 = xcr0 & info.supported_xcr0;
    if xcr0 == info.supported_xcr0 {
        // Fast path: requesting all components — use the ECX upper-bound.
        return info.xsave_size_max.max(576);
    }
    let mut size = 576usize; // legacy area (512) + xsave header (64)
    for comp in 2..64 {
        if xcr0 & (1u64 << comp) == 0 {
            continue;
        }
        let (eax, ebx, ecx, _edx) = super::cpuid(0x0D, comp);
        // ECX bit 0: component managed via XCR0 (0) or IA32_XSS (1).
        // Skip supervisor states — not saved by a user-space XCR0 mask.
        if ecx & 1 != 0 {
            continue;
        }
        let comp_size = eax as usize;
        let comp_offset = ebx as usize;
        if comp_size != 0 {
            size = size.max(comp_offset.saturating_add(comp_size));
        }
    }
    size.min(info.xsave_size_max).max(576)
}

/// Compute the XSAVE area size needed for a given XCR0 mask.
/// Falls back to 512 (FXSAVE) if XSAVE is not supported.
pub fn xsave_size_for_xcr0(xcr0: u64) -> usize {
    if !host_uses_xsave() {
        return 512;
    }
    let h = host();
    if xcr0 == h.supported_xcr0 {
        return h.xsave_size_max;
    }

    // Enumerate each enabled XCR0 component via CPUID leaf 0xD sub-leaves.
    // Sub-leaf n returns offset (EBX) and size (EAX) for component n.
    // The total save area is max(offset + size) across all enabled components.
    // NOTE: this walks CPUID per component — do not call from context-switch
    // or task-creation hot paths; precompute profiles instead.
    // The ceiling is xsave_size_max (CPUID.0D.0:ECX), valid for any mask;
    // EBX would only be valid for the XCR0 currently programmed.
    let mut size = 576usize; // legacy area (512) + xsave header (64)
    for comp in 2..64 {
        if xcr0 & (1u64 << comp) == 0 {
            continue;
        }
        let (eax, ebx, ecx, _edx) = super::cpuid(0x0D, comp);
        // ECX bit 0: component managed via XCR0 (0) or IA32_XSS (1).
        // Skip supervisor states — they are not saved by XSAVE/XRSTOR
        // with a user-space XCR0 mask.
        if ecx & 1 != 0 {
            continue;
        }
        let comp_size = eax as usize;
        let comp_offset = ebx as usize;
        if comp_size != 0 {
            size = size.max(comp_offset.saturating_add(comp_size));
        }
    }
    size.min(h.xsave_size_max).max(576)
}

/// Return the host's default XCR0 mask from the lock-free cache, falling back
/// to the locked query before `init()` is complete.
#[inline]
pub fn host_default_xcr0_fast() -> u64 {
    let cached = HOST_DEFAULT_XCR0_CACHE.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    host_default_xcr0()
}

/// Return the host's default XCR0 mask (all supported features).
/// Safe to call before `init()` : returns `XCR0_X87 | XCR0_SSE` if not yet initialized.
///
/// Try to read the TSC frequency from CPUID leaf 0x15 (Time Stamp Counter and
/// Core Crystal Clock Information).  Returns kHz, or None if not available.
///
/// This is the preferred method on Intel/AMD CPUs that support invariant TSC.
/// Linux uses this as its primary TSC calibration source.
pub fn tsc_frequency_khz() -> Option<u64> {
    let max_leaf = super::cpuid(0, 0).0;
    if max_leaf < 0x15 {
        //  TSC frequency from CPUID leaf 0x15
        return None;
    }
    let (eax, ebx, ecx, _edx) = super::cpuid(0x15, 0);
    let core_crystal_hz = ecx as u64;

    // If the core crystal clock is known, compute TSC frequency.
    if core_crystal_hz != 0 {
        let denom = eax as u64;
        let num = ebx as u64;
        if denom != 0 {
            // TSC freq = core_crystal_hz * num / denom / 1_000
            // Use checked arithmetic to avoid silent overflow.
            return core_crystal_hz
                .checked_mul(num)?
                .checked_div(denom)?
                .checked_div(1_000);
        }
    }
    None
}

pub fn host_default_xcr0() -> u64 {
    if INITIALIZED.load(Ordering::Acquire) {
        HOST_CPU
            .lock()
            .as_ref()
            .map_or(XCR0_X87 | XCR0_SSE, default_xcr0_for)
    } else {
        XCR0_X87 | XCR0_SSE
    }
}

/// Build a Linux-style `flags` string from CPU features.
pub fn features_to_flags_string(f: CpuFeatures) -> String {
    let mut flags = String::new();
    let table: &[(CpuFeatures, &str)] = &[
        (CpuFeatures::FPU, "fpu"),
        (CpuFeatures::TSC, "tsc"),
        (CpuFeatures::APIC, "apic"),
        (CpuFeatures::FXSR, "fxsr"),
        (CpuFeatures::SSE, "sse"),
        (CpuFeatures::SSE2, "sse2"),
        (CpuFeatures::SSE3, "sse3"),
        (CpuFeatures::SSSE3, "ssse3"),
        (CpuFeatures::SSE4_1, "sse4_1"),
        (CpuFeatures::SSE4_2, "sse4_2"),
        (CpuFeatures::POPCNT, "popcnt"),
        (CpuFeatures::AES_NI, "aes"),
        (CpuFeatures::XSAVE, "xsave"),
        (CpuFeatures::OSXSAVE, "osxsave"),
        (CpuFeatures::AVX, "avx"),
        (CpuFeatures::F16C, "f16c"),
        (CpuFeatures::FMA, "fma"),
        (CpuFeatures::AVX2, "avx2"),
        (CpuFeatures::AVX512F, "avx512f"),
        (CpuFeatures::AVX512BW, "avx512bw"),
        (CpuFeatures::AVX512VL, "avx512vl"),
        (CpuFeatures::SHA, "sha_ni"),
        (CpuFeatures::X2APIC, "x2apic"),
        (CpuFeatures::NX, "nx"),
        (CpuFeatures::PAGES_1G, "pdpe1gb"),
        (CpuFeatures::RDTSCP, "rdtscp"),
        (CpuFeatures::LONG_MODE, "lm"),
        (CpuFeatures::VMX, "vmx"),
        (CpuFeatures::SVM, "svm"),
        (CpuFeatures::SMEP, "smep"),
        (CpuFeatures::SMAP, "smap"),
    ];
    for &(feat, name) in table {
        if f.contains(feat) {
            if !flags.is_empty() {
                flags.push(' ');
            }
            flags.push_str(name);
        }
    }
    flags
}
