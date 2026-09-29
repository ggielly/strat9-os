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
        let pat_low: u32;
        let pat_high: u32;
        core::arch::asm!("rdmsr", in("ecx") 0x277u32, out("eax") pat_low, out("edx") pat_high,
            options(nomem, nostack, preserves_flags));
        validate_pat(((pat_high as u64) << 32) | pat_low as u64)?;
        Ok(features)
    }
}

/// Keep firmware PAT unchanged. These two selectors are also required on APs.
pub fn validate_pat(pat: u64) -> Result<(), &'static str> {
    if pat & 0xFF != 6 || (pat >> 24) & 0xFF != 0 {
        return Err("PAT requires entry 0 = WB and entry 3 = UC");
    }
    Ok(())
}

/// Read the timestamp counter.
pub fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack))
    };
    ((high as u64) << 32) | low as u64
}

const PIT_FREQUENCY: u64 = 1_193_182;
const PIT_CH2_PORT: u16 = 0x42;
const PIT_COMMAND_PORT: u16 = 0x43;
const PC_SPEAKER_PORT: u16 = 0x61;
/// Largest count the 16-bit counter accepts, giving the longest window and so
/// the smallest relative error. 65535 / 1_193_182 Hz is about 54.9 ms.
const PIT_WINDOW_COUNT: u64 = 0xFFFF;
/// Bounded so a machine without a working PIT cannot wedge the boot.
const PIT_MAX_POLLS: u32 = 10_000_000;

/// # Safety
/// `port` must be a byte-wide I/O port.
unsafe fn outb(port: u16, value: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

/// # Safety
/// `port` must be a byte-wide I/O port.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

/// Measure the TSC frequency against PIT channel 2, for CPUs that do not
/// report one. `-cpu qemu64` implements neither leaf 0x15 nor 0x16, so without
/// this the boot timings would carry no scale at all.
///
/// Channel 2 drives the PC speaker and no interrupt, so driving it briefly is
/// harmless; the gate bit and port 0x61 are restored either way.
fn calibrate_tsc_khz_pit() -> Option<u64> {
    let saved = unsafe { inb(PC_SPEAKER_PORT) };
    let armed = saved & 0xFC;
    // Gate low: in mode 0 the count must not start before the counter is armed,
    // otherwise the measurement window opens before we begin sampling.
    unsafe { outb(PC_SPEAKER_PORT, armed) };
    // Channel 2, lobyte/hibyte, mode 0 (one-shot), binary.
    unsafe {
        outb(PIT_COMMAND_PORT, 0xB0);
        outb(PIT_CH2_PORT, (PIT_WINDOW_COUNT & 0xFF) as u8);
        outb(PIT_CH2_PORT, ((PIT_WINDOW_COUNT >> 8) & 0xFF) as u8);
    }

    // Sample before releasing the gate. The release latency is then excluded
    // from the window, which understates the frequency rather than overstating
    // it -- a slow boot report instead of a falsely fast one.
    let start = rdtsc();
    unsafe { outb(PC_SPEAKER_PORT, armed | 0x01) };

    // Bit 5 is channel 2's output; in mode 0 it latches high at terminal count.
    let mut polls = 0;
    while unsafe { inb(PC_SPEAKER_PORT) } & 0x20 == 0 {
        polls += 1;
        if polls > PIT_MAX_POLLS {
            unsafe { outb(PC_SPEAKER_PORT, saved) };
            return None;
        }
    }
    let delta = rdtsc().wrapping_sub(start);
    unsafe { outb(PC_SPEAKER_PORT, saved) };

    if delta == 0 {
        return None;
    }
    let window = PIT_WINDOW_COUNT as u128 * 1_000;
    let khz = (delta as u128 * PIT_FREQUENCY as u128) / window;
    if khz == 0 {
        return None;
    }
    Some(khz as u64)
}

/// TSC frequency in kHz, or `None` when no trustworthy figure is available.
///
/// CPUID is preferred because it costs nothing, but it is absent on the
/// emulated CPU models this project boots (`-cpu qemu64` reports neither leaf
/// 0x15 nor 0x16), so a PIT measurement backs it up. Callers must treat `None`
/// as "unknown" rather than substituting a default, because a wrong scale turns
/// every duration report into fiction.
pub fn tsc_frequency_khz() -> Option<u64> {
    if let Some(khz) = tsc_frequency_khz_cpuid() {
        return Some(khz);
    }
    calibrate_tsc_khz_pit()
}

fn tsc_frequency_khz_cpuid() -> Option<u64> {
    use core::arch::x86_64::__cpuid;
    let max_leaf = __cpuid(0).eax;
    if max_leaf >= 0x15 {
        let leaf = __cpuid(0x15);
        if leaf.eax != 0 && leaf.ecx != 0 {
            if let Some(khz) = (leaf.ecx as u64)
                .checked_mul(leaf.ebx as u64)
                .and_then(|scaled| scaled.checked_div(leaf.eax as u64))
                .and_then(|hz| hz.checked_div(1_000))
            {
                if khz != 0 {
                    return Some(khz);
                }
            }
        }
    }
    if max_leaf >= 0x16 {
        let mhz = __cpuid(0x16).eax & 0xFFFF;
        if mhz != 0 {
            return Some(mhz as u64 * 1_000);
        }
    }
    None
}
