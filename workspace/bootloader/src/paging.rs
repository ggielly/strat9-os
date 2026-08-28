pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const NX: u64 = 1 << 63;
const PAT_4K: u64 = 1 << 7;
const PS_1G: u64 = 1 << 7;

/// Bitmask returned by detect_cpu_features().
const CPUID_NX: u32 = 1 << 0;
const CPUID_PAT: u32 = 1 << 1;
const CPUID_1G_PAGES: u32 = 1 << 2;

/// Bump allocator for page table frames
static mut NEXT_FRAME: u64 = 0;

unsafe fn alloc_frame() -> u64 {
    let addr = unsafe { NEXT_FRAME };
    unsafe {
        NEXT_FRAME = NEXT_FRAME
            .checked_add(PAGE_SIZE)
            .expect("page table frame allocator overflow");
    }
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize);
    }
    addr
}

/// Detect CPU features required for paging. Returns a bitmask of
/// supported features (CPUID_NX, CPUID_PAT, CPUID_1G_PAGES).
///
/// Must be called in 64-bit mode (or at least after entering protected
/// mode with CPUID available).
fn detect_cpu_features() -> u32 {
    let mut flags: u32 = 0;

    // Leaf 0x80000000: max extended leaf
    // NOTE: EBX is reserved by LLVM — save/restore manually.
    let max_ext: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x80000000",
            "cpuid",
            "mov {tmp:e}, ebx",
            "pop rbx",
            inout("eax") 0x80000000u32 => max_ext,
            tmp = out(reg) _,
            out("ecx") _,
            out("edx") _,
        );
    }

    if max_ext >= 0x8000_0001 {
        let edx: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x80000001",
                "cpuid",
                "pop rbx",
                out("eax") _,
                out("ecx") _,
                out("edx") edx,
            );
        }
        if edx & (1 << 20) != 0 {
            flags |= CPUID_NX;          // No-Execute bit
        }
        if edx & (1 << 26) != 0 {
            flags |= CPUID_1G_PAGES;    // Page1GB
        }
    }

    // Leaf 1: PAT (EDX bit 16)
    let edx1: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") _,
            out("edx") edx1,
        );
    }
    if edx1 & (1 << 16) != 0 {
        flags |= CPUID_PAT;
    }

    flags
}

/// Map a single 4 KiB page. Walks the 4-level page table, allocating
/// intermediate tables as needed.
unsafe fn map_4k(
    pml4: *mut u64,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), ()> {
    if (virt | phys) & (PAGE_SIZE - 1) != 0 {
        return Err(());
    }

    let pml4_i = ((virt >> 39) & 0x1ff) as usize;
    let pdpt_i = ((virt >> 30) & 0x1ff) as usize;
    let pd_i = ((virt >> 21) & 0x1ff) as usize;
    let pt_i = ((virt >> 12) & 0x1ff) as usize;

    let pdpt = if (*pml4.add(pml4_i) & PRESENT) != 0 {
        (*pml4.add(pml4_i) & 0x000f_ffff_ffff_f000) as *mut u64
    } else {
        let table = alloc_frame() as *mut u64;
        *pml4.add(pml4_i) = table as u64 | PRESENT | WRITABLE;
        table
    };

    let pd = if (*pdpt.add(pdpt_i) & PRESENT) != 0 {
        (*pdpt.add(pdpt_i) & 0x000f_ffff_ffff_f000) as *mut u64
    } else {
        let table = alloc_frame() as *mut u64;
        *pdpt.add(pdpt_i) = table as u64 | PRESENT | WRITABLE;
        table
    };

    let pt = if (*pd.add(pd_i) & PRESENT) != 0 {
        (*pd.add(pd_i) & 0x000f_ffff_ffff_f000) as *mut u64
    } else {
        let table = alloc_frame() as *mut u64;
        *pd.add(pd_i) = table as u64 | PRESENT | WRITABLE;
        table
    };

    *pt.add(pt_i) = phys | flags | PRESENT;
    Ok(())
}

/// Map a contiguous physical range to contiguous virtual addresses, 4 KiB pages.
unsafe fn map_range_4k(
    pml4: *mut u64,
    virt: u64,
    phys: u64,
    size: u64,
    flags: u64,
) -> Result<(), ()> {
    if size == 0 {
        return Ok(());
    }
    let pages = (size.checked_add(PAGE_SIZE - 1).ok_or(())?) / PAGE_SIZE;

    for page in 0..pages {
        let off = page.checked_mul(PAGE_SIZE).ok_or(())?;
        map_4k(
            pml4,
            virt.checked_add(off).ok_or(())?,
            phys.checked_add(off).ok_or(())?,
            flags,
        )?;
    }
    Ok(())
}

pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_phys_end: u64,
    kernel_size: u64,
    _framebuffer_phys: u64,
    _framebuffer_size: u64,
    _env_phys: u64,
    _env_size: u64,
) -> u64 {
    // Detect CPU features before building page tables.
    let cpu_features = detect_cpu_features();
    let has_nx = (cpu_features & CPUID_NX) != 0;
    let has_pat = (cpu_features & CPUID_PAT) != 0;
    let has_1g = (cpu_features & CPUID_1G_PAGES) != 0;

    // Start allocator after kernel + safety margin
    unsafe {
        NEXT_FRAME = kernel_phys_end
            .checked_add(0x40_0000)
            .expect("page table allocator base overflow")
            & !0xFFF;
    }

    let pml4 = alloc_frame() as *mut u64;

    // Identity map: 0..8 GiB.
    // If 1 GiB pages are supported, use them (1 PDPTE per GiB).
    // Otherwise, fall back to 2 MiB pages (512 PDTE per PDPTE).
    // Required during the boot transition; must be torn down by the kernel.
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(0) = pdp as u64 | PRESENT | WRITABLE;

        if has_1g {
            // 1 GiB huge pages: PDPTE PS bit (bit 7) = 1.
            for i in 0..8u64 {
                *pdp.add(i as usize) = (i * 0x4000_0000) | PRESENT | WRITABLE | PS_1G;
            }
        } else {
            // Fallback: 2 MiB pages. Each PDPTE points to a PD with
            // 512 entries of 2 MiB each (PS bit in PDE, bit 7).
            for i in 0..8u64 {
                let pd = alloc_frame() as *mut u64;
                *pdp.add(i as usize) = pd as u64 | PRESENT | WRITABLE;
                for j in 0..512u64 {
                    let phys = i * 0x4000_0000 + j * 0x20_0000;
                    *pd.add(j as usize) = phys | PRESENT | WRITABLE | (1 << 7); // PS = 2 MiB
                }
            }
        }
    }

    // Higher-half kernel: PML4[511] => PDP[510] => PD => PT (4KB pages)
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(511) = pdp as u64 | PRESENT | WRITABLE;

        let pd = alloc_frame() as *mut u64;
        *pdp.add(510) = pd as u64 | PRESENT | WRITABLE;

        let pages_needed = ((kernel_size.checked_add(PAGE_SIZE - 1).expect("kernel_size overflow")) / PAGE_SIZE) as usize;
        let mut phys = kernel_phys;

        for pt_idx in 0..(pages_needed.checked_add(511).expect("pt_idx overflow")) / 512 {
            let pt = alloc_frame() as *mut u64;

            for entry in 0..512usize {
                let page_num = pt_idx * 512 + entry;
                if page_num >= pages_needed {
                    break;
                }
                // Map kernel RWX during boot. The kernel will remap with proper
                // W^X (PF_X -> RX, PF_W -> RW|NX) after relocation.
                *pt.add(entry) = phys | PRESENT | WRITABLE;
                phys = phys.checked_add(PAGE_SIZE).expect("kernel phys overflow");
            }

            *pd.add(pt_idx) = pt as u64 | PRESENT | WRITABLE;
        }
    }

    // Framebuffer: 4 KiB pages, optionally NX + PAT (Write-Combining).
    // PAT bit for 4 KiB pages is bit 7 of the PTE.
    if _framebuffer_phys != 0 && _framebuffer_size > 0 {
        let mut fb_flags = WRITABLE;
        if has_nx {
            fb_flags |= NX;
        }
        if has_pat {
            fb_flags |= PAT_4K;
        }
        map_range_4k(
            pml4,
            FRAMEBUFFER_BASE,
            _framebuffer_phys,
            _framebuffer_size,
            fb_flags,
        )
        .expect("framebuffer mapping failed");
    }

    // Environment: read-only + NX (if supported).
    if _env_phys != 0 && _env_size > 0 {
        let mut env_flags = 0u64;
        if has_nx {
            env_flags |= NX;
        }
        map_range_4k(pml4, ENVIRONMENT_BASE, _env_phys, _env_size, env_flags)
            .expect("environment mapping failed");
    }

    pml4 as u64
}

pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    // Detect CPU features before programming MSRs.
    let cpu_features = detect_cpu_features();
    let has_nx = (cpu_features & CPUID_NX) != 0;
    let has_pat = (cpu_features & CPUID_PAT) != 0;

    if has_nx {
        unsafe {
            core::arch::asm!(
                // Enable IA32_EFER.NXE (bit 11) so NX page bits are enforced.
                "mov ecx, 0xC0000080",          // IA32_EFER
                "rdmsr",
                "or eax, 1 << 11",              // NXE
                "wrmsr",
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nostack)
            );
        }
    }

    if has_pat {
        unsafe {
            core::arch::asm!(
                // Program IA32_PAT entry 4 to Write-Combining (0x01).
                // Default PAT entry 4 = WB (0x06); change to WC (0x01).
                "mov ecx, 0x277",               // IA32_PAT
                "rdmsr",
                "and edx, 0xFFFFFFF0",          // clear entry 4 (bits 35:32)
                "or edx, 0x00000001",           // set entry 4 = WC
                "wrmsr",
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nostack)
            );
        }
    }

    unsafe {
        core::arch::asm!(
            "xor rbp, rbp",   // woot
            "mov cr3, {pml4}",
            "mov rsp, {stack}",
            "and rsp, -16",
            "mov rdi, {args}",
            "jmp {entry}",
            pml4 = in(reg) pml4_phys,
            stack = in(reg) stack_top,
            entry = in(reg) entry,
            args = in(reg) args,
            options(noreturn)
        );
    }
}
