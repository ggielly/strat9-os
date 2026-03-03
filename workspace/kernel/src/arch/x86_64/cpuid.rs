//! CPU feature detection via CPUID instruction.
//!
//! Provides a `CpuInfo` struct populated at boot time with vendor, model,
//! feature flags, and XSAVE geometry. All subsequent queries go through
//! `host()` which returns the cached result.

use crate::sync::SpinLock;
use alloc::string::String;
use bitflags::bitflags;
use core::sync::atomic::{AtomicBool, Ordering};

bitflags! {
    /// CPU feature flags detected via CPUID.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuFeatures: u64 {
        // ── Leaf 0x01 ECX ──
        const SSE3      = 1 << 0;
        const SSSE3     = 1 << 1;
        const FMA       = 1 << 2;
        const SSE4_1    = 1 << 3;
        const SSE4_2    = 1 << 4;
        const POPCNT    = 1 << 5;
        const AES_NI    = 1 << 6;
        const XSAVE     = 1 << 7;
        const AVX       = 1 << 8;
        const F16C      = 1 << 9;
        const VMX       = 1 << 10;
        // ── Leaf 0x01 EDX ──
        const FPU       = 1 << 16;
        const TSC       = 1 << 17;
        const APIC      = 1 << 18;
        const SSE       = 1 << 19;
        const SSE2      = 1 << 20;
        const FXSR      = 1 << 21;
        // ── Leaf 0x07 EBX ──
        const AVX2      = 1 << 32;
        const AVX512F   = 1 << 33;
        const AVX512BW  = 1 << 34;
        const AVX512VL  = 1 << 35;
        const SHA       = 1 << 36;
        // ── Leaf 0x80000001 EDX ──
        const NX        = 1 << 48;
        const PAGES_1G  = 1 << 49;
        const RDTSCP    = 1 << 50;
        const LONG_MODE = 1 << 51;
        // ── Leaf 0x80000001 ECX ──
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
    pub features: CpuFeatures,
    pub max_xcr0: u64,
    pub xsave_size: usize,
    pub family: u8,
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

/// Detect and cache CPU information. Must be called once at BSP boot.
pub fn init() {
    let info = detect();
    log::info!(
        "[CPUID] {} {} (family={} model={} stepping={})",
        info.vendor_string(),
        info.model_name_str(),
        info.family,
        info.model,
        info.stepping,
    );
    log::info!(
        "[CPUID] features={:?}, max_xcr0={:#x}, xsave_size={}",
        info.features,
        info.max_xcr0,
        info.xsave_size,
    );
    *HOST_CPU.lock() = Some(info);
    INITIALIZED.store(true, Ordering::Release);
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

    // ── Vendor (leaf 0) ──
    let (max_leaf, ebx0, ecx0, edx0) = cpuid(0, 0);
    let vendor = match (ebx0, edx0, ecx0) {
        (0x756E_6547, 0x4965_6E69, 0x6C65_746E) => CpuVendor::Intel,
        (0x6874_7541, 0x6974_6E65, 0x444D_4163) => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    };

    let mut features = CpuFeatures::empty();

    // ── Leaf 0x01: main feature bits ──
    let (eax1, _ebx1, ecx1, edx1) = if max_leaf >= 1 {
        cpuid(1, 0)
    } else {
        (0, 0, 0, 0)
    };

    let stepping = (eax1 & 0xF) as u8;
    let mut family = ((eax1 >> 8) & 0xF) as u8;
    let mut model = ((eax1 >> 4) & 0xF) as u8;
    if family == 6 || family == 15 {
        model += ((eax1 >> 12) & 0xF0) as u8;
    }
    if family == 15 {
        family += ((eax1 >> 20) & 0xFF) as u8;
    }

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
    if ecx1 & (1 << 28) != 0 {
        features |= CpuFeatures::AVX;
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

    // ── Leaf 0x07: extended features ──
    if max_leaf >= 7 {
        let (_eax7, ebx7, _ecx7, _edx7) = cpuid(7, 0);
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
    }

    // ── Leaf 0x0D: XSAVE geometry ──
    let (mut max_xcr0, mut xsave_size) = (XCR0_X87 | XCR0_SSE, 512usize);
    if features.contains(CpuFeatures::XSAVE) && max_leaf >= 0x0D {
        let (eax_d, ebx_d, _ecx_d, edx_d) = cpuid(0x0D, 0);
        max_xcr0 = ((edx_d as u64) << 32) | eax_d as u64;
        xsave_size = ebx_d as usize;
    }

    // ── Leaf 0x80000001: extended features (AMD-V, NX, 1G pages) ──
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

    // ── Leaves 0x80000002-0x80000004: brand string ──
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
        features,
        max_xcr0,
        xsave_size,
        family,
        model,
        stepping,
        model_name,
        model_name_len,
    }
}

/// Compute the XCR0 mask for a given set of allowed features,
/// clamped to what the host actually supports.
pub fn xcr0_for_features(features: CpuFeatures) -> u64 {
    let mut xcr0 = XCR0_X87 | XCR0_SSE;
    if features.contains(CpuFeatures::AVX) {
        xcr0 |= XCR0_AVX;
    }
    if features.contains(CpuFeatures::AVX512F) {
        xcr0 |= XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;
    }
    let h = host();
    xcr0 & h.max_xcr0
}

/// Compute the XSAVE area size needed for a given XCR0 mask.
/// Falls back to 512 (FXSAVE) if XSAVE is not supported.
pub fn xsave_size_for_xcr0(xcr0: u64) -> usize {
    if !host_uses_xsave() {
        return 512;
    }
    // CPUID leaf 0x0D, sub-leaf 0: ECX gives the size for the *current* XCR0.
    // Since we may not want to switch XCR0 just to query, use a conservative
    // computation from the host's max xsave_size clamped down.
    let h = host();
    if xcr0 == h.max_xcr0 {
        return h.xsave_size;
    }
    // Minimal sizes per component
    let mut size = 576usize; // legacy area (512) + xsave header (64)
    if xcr0 & XCR0_AVX != 0 {
        size = size.max(832); // +256 for YMM
    }
    if xcr0 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM) != 0 {
        size = size.max(2688); // full AVX-512
    }
    size.min(h.xsave_size)
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
        (CpuFeatures::AVX, "avx"),
        (CpuFeatures::F16C, "f16c"),
        (CpuFeatures::FMA, "fma"),
        (CpuFeatures::AVX2, "avx2"),
        (CpuFeatures::AVX512F, "avx512f"),
        (CpuFeatures::AVX512BW, "avx512bw"),
        (CpuFeatures::AVX512VL, "avx512vl"),
        (CpuFeatures::SHA, "sha_ni"),
        (CpuFeatures::NX, "nx"),
        (CpuFeatures::PAGES_1G, "pdpe1gb"),
        (CpuFeatures::RDTSCP, "rdtscp"),
        (CpuFeatures::LONG_MODE, "lm"),
        (CpuFeatures::VMX, "vmx"),
        (CpuFeatures::SVM, "svm"),
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
