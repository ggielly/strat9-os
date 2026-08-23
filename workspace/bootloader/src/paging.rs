use crate::elf::Segment;
use strat9_abi::boot::{MemoryKind, MemoryRegion};

pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const NO_EXECUTE: u64 = 1 << 63;
/// Page tables consume 4 KiB each. Upper bound on the number of table
/// frames we may need, used to validate the allocation window up front.
const MAX_TABLE_FRAMES: u64 = 64;

static mut NEXT_FRAME: u64 = 0;
static mut FRAME_LIMIT: u64 = 0;

/// Raw COM1 write usable after ExitBootServices (no UEFI services).
pub fn serial_write_str(msg: &str) {
    unsafe {
        let lsr: u16 = 0x3F8 + 5;
        let thr: u16 = 0x3F8;
        for &b in msg.as_bytes() {
            loop {
                let status: u8;
                core::arch::asm!("in al, dx", out("al") status, in("dx") lsr, options(nomem, nostack));
                if status & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("al") b, in("dx") thr, options(nomem, nostack));
        }
    }
}

/// Fatal error path usable after ExitBootServices: raw COM1 output then halt.
pub fn fatal(msg: &str) -> ! {
    serial_write_str(msg);
    serial_write_str("\r\n");
    unsafe {
        loop {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

/// Validate that [start, start+size) lies inside physical RAM covered by a
/// Free or Reclaim region of the final memory map. Used to guarantee the
/// page-table frames we allocate actually exist and will not be handed to
/// the kernel as free memory behind its back (the kernel reserves them by
/// walking CR3).
fn range_in_usable_ram(regions: &[MemoryRegion], region_count: usize, start: u64, size: u64) -> bool {
    let end = match start.checked_add(size) {
        Some(e) => e,
        None => return false,
    };
    regions[..region_count].iter().any(|r| {
        matches!(r.kind, MemoryKind::Free | MemoryKind::Reclaim)
            && r.base <= start
            && end <= r.base + r.size
    })
}

unsafe fn alloc_frame() -> u64 {
    let addr = unsafe { NEXT_FRAME };
    unsafe {
        if addr >= FRAME_LIMIT {
            fatal("[boot] FATAL: out of page-table frames");
        }
        NEXT_FRAME += PAGE_SIZE;
    }
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize);
    }
    addr
}

/// Map `map_size` bytes at [virt, virt+map_size) -> [phys, phys+map_size)
/// using 4 KiB pages with the given permissions inside the PT hierarchy
/// rooted at `pml4`. Requires 4 KiB-aligned addresses (guaranteed by the
/// linker script for kernel segments).
unsafe fn map_range(
    pml4: *mut u64,
    mut virt: u64,
    mut phys: u64,
    size: u64,
    writable: bool,
    executable: bool,
) {
    let end = virt + size;
    while virt < end {
        let pdp = deref_or_alloc(pml4, ((virt >> 39) & 0x1FF) as usize);
        let pd = deref_or_alloc(pdp, ((virt >> 30) & 0x1FF) as usize);
        let pt = deref_or_alloc(pd, ((virt >> 21) & 0x1FF) as usize);

        let mut entry = phys | PRESENT;
        if writable {
            entry |= WRITABLE;
        }
        if !executable {
            entry |= NO_EXECUTE;
        }
        *pt.add(((virt >> 12) & 0x1FF) as usize) = entry;

        virt += PAGE_SIZE;
        phys += PAGE_SIZE;
    }
}

/// Return the next-level table for `index`, allocating and linking a zeroed
/// one if the entry is empty. New tables are RW/NX at directory level; leaf
/// permissions decide the effective mapping.
unsafe fn deref_or_alloc(table: *mut u64, index: usize) -> *mut u64 {
    let entry = *table.add(index);
    if entry & PRESENT != 0 {
        return (entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    let new_table = alloc_frame() as *mut u64;
    // Freshly zeroed by alloc_frame; link as RW (no NX needed on directories,
    // effective permissions come from the leaves).
    *table.add(index) = new_table as u64 | PRESENT | WRITABLE;
    new_table
}

/// Build the boot page tables:
/// - identity map of the first 8 GiB (RW + NX once EFER.NXE is enabled),
/// - per-segment higher-half kernel mapping with real W^X permissions,
/// - framebuffer at FRAMEBUFFER_BASE (4 KiB granularity, exact span),
/// - environment string at ENVIRONMENT_BASE.
///
/// Table frames are allocated linearly starting above the kernel image; the
/// whole window is validated against the final memory map first (M5).
///
/// Returns the PML4 physical address.
pub unsafe fn create_page_tables(
    segments: &[Segment],
    segment_count: usize,
    fb_phys: u64,
    fb_size: u64,
    env_phys: u64,
    env_size: u64,
    regions: &[crate::MemoryRegion],
    region_count: usize,
) -> u64 {
    unsafe {
        // Start page-table allocation 1 MiB above the kernel image.
        let image_end = segments[..segment_count]
            .iter()
            .map(|s| s.phys_addr + s.map_size)
            .max()
            .unwrap_or(0);
        NEXT_FRAME = (image_end + 0x10_0000) & !0xFFF;

        // M5: bound-check the entire table-frame window against RAM before
        // writing anything.
        FRAME_LIMIT = NEXT_FRAME + MAX_TABLE_FRAMES * PAGE_SIZE;
        if !range_in_usable_ram(regions, region_count, NEXT_FRAME, FRAME_LIMIT - NEXT_FRAME) {
            fatal("[boot] FATAL: no usable RAM for page tables above the kernel image");
        }

        let pml4 = alloc_frame() as *mut u64;

        // Identity map: 0..8GB using 1GB huge pages (RW, NX).
        // NOTE: NX requires EFER.NXE which context_switch enables.
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(0) = pdp as u64 | PRESENT | WRITABLE | NO_EXECUTE;

        for i in 0..8u64 {
            *pdp.add(i as usize) =
                (i * 0x4000_0000) | PRESENT | WRITABLE | (1 << 7) | NO_EXECUTE;
        }

        // Higher-half kernel: PML4[511] => PDP[510], mapped per segment with
        // real W^X from the ELF p_flags (M1). Writable data/stack get W,
        // only executable code stays X, everything else is RO.
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(511) = pdp as u64 | PRESENT | WRITABLE;

        let pd = alloc_frame() as *mut u64;
        *pdp.add(510) = pd as u64 | PRESENT | WRITABLE;

        for seg in &segments[..segment_count] {
            map_range(
                pml4,
                seg.virt_addr,
                seg.phys_addr,
                seg.map_size,
                seg.writable(),
                seg.executable(),
            );
        }

        // Framebuffer: exact span with 4 KiB pages (L7) so neighbouring MMIO
        // is not mapped RW alongside it. Rounded to page boundaries only.
        if fb_phys != 0 && fb_size > 0 {
            let phys_lo = fb_phys & !(PAGE_SIZE - 1);
            let span = (fb_phys - phys_lo) + fb_size;
            let pages = span.div_ceil(PAGE_SIZE);
            map_range(
                pml4,
                FRAMEBUFFER_BASE & !(PAGE_SIZE - 1),
                phys_lo,
                pages * PAGE_SIZE,
                true,
                false,
            );
        }

        // Environment string (RW, NX), 4 KiB granularity.
        if env_phys != 0 && env_size > 0 {
            let phys_lo = env_phys & !(PAGE_SIZE - 1);
            let span = (env_phys - phys_lo) + env_size;
            let pages = span.div_ceil(PAGE_SIZE);
            map_range(
                pml4,
                ENVIRONMENT_BASE,
                phys_lo,
                pages * PAGE_SIZE,
                true,
                false,
            );
        }

        pml4 as u64
    }
}

/// Switch to long-mode paging with NX enabled and jump to the kernel entry.
///
/// Sets EFER.NXE so every NX bit written into the tables is actually
/// enforced (M2), loads CR3, switches stack, passes KernelArgs in RDI.
pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "xor rbp, rbp",
            // Enable IA32_EFER.NXE (bit 11) so NX page bits are enforced.
            "mov ecx, 0xC0000080",          // IA32_EFER
            "rdmsr",
            "or eax, 1 << 11",              // NXE (LME already set: we run in long mode)
            "wrmsr",
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
