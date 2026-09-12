//! CPU prerequisites checked while firmware diagnostics are still available.

#[derive(Clone, Copy, Debug)]
pub struct CpuFeatures {
    pub standard_edx: u32,
    pub extended_edx: u32,
    pub physical_bits: u8,
}

impl CpuFeatures {
    pub fn validate(self) -> Result<(), &'static str> {
        // PSE, MSR, PAE, PAT, FXSR, SSE and SSE2. 1 GiB pages are not required.
        let standard =
            (1 << 3) | (1 << 5) | (1 << 6) | (1 << 16) | (1 << 24) | (1 << 25) | (1 << 26);
        if self.standard_edx & standard != standard {
            return Err("CPU lacks required paging, MSR, PAT or SSE features");
        }
        let extended = (1 << 20) | (1 << 29);
        if self.extended_edx & extended != extended {
            return Err("CPU requires long mode and NX support");
        }
        if !(32..=52).contains(&self.physical_bits) {
            return Err("unsupported CPU physical address width");
        }
        Ok(())
    }

    pub fn physical_limit(self) -> u64 {
        1u64 << self.physical_bits
    }
}

pub fn validate_paging_mode(cr0: u64, cr4: u64, efer: u64) -> Result<(), &'static str> {
    let protected_paging = (1 << 31) | 1;
    if cr0 & protected_paging != protected_paging || cr4 & (1 << 5) == 0 || efer & (1 << 10) == 0 {
        return Err("firmware did not enter 64-bit paged protected mode");
    }
    // Switching between four/five levels requires leaving paging mode. Active
    // CET would also require a shadow-stack handoff that this loader does not do.
    if cr4 & ((1 << 12) | (1 << 23)) != 0 {
        return Err("active LA57 or CET is unsupported by the kernel handoff");
    }
    Ok(())
}

pub fn detect() -> Result<CpuFeatures, &'static str> {
    unsafe {
        use core::arch::x86_64::__cpuid;
        if __cpuid(0).eax < 1 || __cpuid(0x8000_0000).eax < 0x8000_0001 {
            return Err("required CPU feature leaves are unavailable");
        }
        let physical_bits = if __cpuid(0x8000_0000).eax >= 0x8000_0008 {
            (__cpuid(0x8000_0008).eax & 0xFF) as u8
        } else {
            36 // Architectural fallback for a PAE processor without this leaf.
        };
        let features = CpuFeatures {
            standard_edx: __cpuid(1).edx,
            extended_edx: __cpuid(0x8000_0001).edx,
            physical_bits,
        };
        features.validate()?;
        let cr0: u64;
        let cr4: u64;
        let low: u32;
        let high: u32;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        core::arch::asm!("rdmsr", in("ecx") 0xC0000080u32, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
        validate_paging_mode(cr0, cr4, ((high as u64) << 32) | low as u64)?;
        Ok(features)
    }
}
