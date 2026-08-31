//! Strat9-OS Kernel (Bedrock)
//!
//! A minimal microkernel handling:
//! - Scheduling
//! - IPC (Inter-Process Communication)
//! - Memory primitives
//! - Interrupt routing
//!
//! Everything else runs as userspace component servers.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(negative_impls)]

extern crate alloc;

// OSTD-like abstraction layer (minimal unsafe TCB)
pub mod ostd;

pub mod acpi;
pub mod arch;
pub mod audit;
pub mod boot;
pub mod capability;
pub mod components;
pub mod crypto;
pub mod debug;
pub mod debug_cfg;

pub mod async_io;
pub mod dma;
pub mod entropy;
pub mod framebuffer;
pub mod hal;
pub mod hardware;
pub mod ipc;
pub mod kaslr;
pub mod memory;
pub mod namespace;
pub mod process;
pub mod shell;
pub mod silo;
pub mod sync;
pub mod syscall;
pub mod trace;
pub mod vfs;

// Re-export the kernel entry point from the boot module
pub use boot::dtb_boot::kmain;

// serial_print! and serial_println! macros are #[macro_export]'ed
// from arch::serial and available at crate root automatically.

/// Initialize serial output
pub fn init_serial() {
    if crate::debug_cfg::SERIAL_ENABLED {
        arch::serial::init();
    }
}

/// Initialize the logger (uses serial)
pub fn init_logger() {
    boot::logger::init();
}

/// Initialize kernel components using the component system
///
/// This function initializes all kernel components in the correct order
/// based on their dependencies and priorities.
pub fn init_components(stage: component::InitStage) -> Result<(), component::ComponentInitError> {
    component::init_all(stage)
}

use core::panic::PanicInfo;

const PAGE_SIZE: u64 = 4096;
const MAX_BOOT_MMAP_REGIONS_WORK: usize = 1024;

/// Static working buffer for the boot memory map (off stack to avoid overflow).
static mut MMAP_WORK: [boot::entry::MemoryRegion; MAX_BOOT_MMAP_REGIONS_WORK] =
    [null_region(); MAX_BOOT_MMAP_REGIONS_WORK];

/// Global pointer to KernelArgs, set once during early boot.
/// Components use this to access boot-time information (framebuffer, memory map, etc.).
static mut BOOT_ARGS: Option<&'static boot::entry::KernelArgs> = None;

/// Get the boot arguments. Returns `None` if called before `kernel_main`.
pub fn boot_args() -> Option<&'static boot::entry::KernelArgs> {
    // SAFETY: written once during early boot, read-only thereafter.
    unsafe { BOOT_ARGS }
}

/// Performs the null region operation.
const fn null_region() -> boot::entry::MemoryRegion {
    boot::entry::MemoryRegion {
        base: 0,
        size: 0,
        kind: boot::entry::MemoryKind::Reserved,
    }
}

/// Performs the align down operation.
#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Performs the align up operation.
#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Performs the virt or phys to phys operation.
#[inline]
const fn virt_or_phys_to_phys(addr: u64, hhdm: u64) -> u64 {
    if hhdm != 0 && addr >= hhdm {
        addr - hhdm
    } else {
        addr
    }
}

/// Performs the reserve range in map operation.
fn reserve_range_in_map(
    map: &mut [boot::entry::MemoryRegion],
    len: &mut usize,
    reserve_start: u64,
    reserve_end: u64,
) {
    if reserve_start >= reserve_end {
        return;
    }

    let mut i = 0usize;
    while i < *len {
        let region = map[i];
        if !matches!(
            region.kind,
            boot::entry::MemoryKind::Free | boot::entry::MemoryKind::Reclaim
        ) {
            i += 1;
            continue;
        }

        let region_start = region.base;
        let region_end = region.base.saturating_add(region.size);
        if reserve_end <= region_start || reserve_start >= region_end {
            i += 1;
            continue;
        }

        let overlap_start = core::cmp::max(region_start, reserve_start);
        let overlap_end = core::cmp::min(region_end, reserve_end);

        if overlap_start <= region_start && overlap_end >= region_end {
            map[i].kind = boot::entry::MemoryKind::Reserved;
            i += 1;
            continue;
        }

        if overlap_start <= region_start {
            map[i].base = overlap_end;
            map[i].size = region_end.saturating_sub(overlap_end);
            i += 1;
            continue;
        }

        if overlap_end >= region_end {
            map[i].size = overlap_start.saturating_sub(region_start);
            i += 1;
            continue;
        }

        let left = boot::entry::MemoryRegion {
            base: region_start,
            size: overlap_start.saturating_sub(region_start),
            kind: region.kind,
        };
        let right = boot::entry::MemoryRegion {
            base: overlap_end,
            size: region_end.saturating_sub(overlap_end),
            kind: region.kind,
        };

        if *len + 1 > map.len() {
            map[i] = left;
            i += 1;
            continue;
        }

        for j in (i + 1..*len).rev() {
            map[j + 1] = map[j];
        }
        map[i] = left;
        map[i + 1] = right;
        *len += 1;
        i += 2;
    }
}

#[inline]
fn count_free_like_regions(map: &[boot::entry::MemoryRegion], len: usize) -> usize {
    map[..len]
        .iter()
        .filter(|region| {
            matches!(
                region.kind,
                boot::entry::MemoryKind::Free | boot::entry::MemoryKind::Reclaim
            )
        })
        .count()
}

/// Performs the region kind for addr operation.
#[cfg(feature = "selftest")]
fn region_kind_for_addr(
    map: &[boot::entry::MemoryRegion],
    len: usize,
    addr: u64,
) -> Option<boot::entry::MemoryKind> {
    map.iter().take(len).find_map(|r| {
        let start = r.base;
        let end = r.base.saturating_add(r.size);
        if addr >= start && addr < end {
            Some(r.kind)
        } else {
            None
        }
    })
}

/// Kernel panic handler
#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    boot::panic::panic_handler(info)
}

/// Performs the register initfs module operation.
fn register_initfs_module(path: &str, module: Option<(u64, u64)>) {
    let Some((base, size)) = module else {
        return;
    };
    if base == 0 || size == 0 {
        return;
    }

    let base_virt = memory::phys_to_virt(base) as *const u8;
    let len = size as usize;
    #[cfg(feature = "selftest")]
    {
        // Only peek small header bytes for debugging; no heap allocations.
        let data = unsafe { core::slice::from_raw_parts(base_virt, len.min(4)) };
        if data.len() == 4 {
            serial_println!(
                "[init] /initfs/{} source magic={:02x}{:02x}{:02x}{:02x} size={}",
                path,
                data[0],
                data[1],
                data[2],
                data[3],
                size
            );
        }
    }

    // Register the bootloader-provided module directly; keep it read-only.
    if let Err(e) = vfs::register_initfs_file(path, base_virt, len) {
        serial_println!("[init] Failed to register /initfs/{}: {:?}", path, e);
    } else {
        serial_println!("[init] Registered /initfs/{} ({} bytes)", path, size);
    }
}

/// Register modules from the bootloader module table (ABI v2).
///
/// Each module has a name, physical base address, and size.
/// The kernel maps them into the VFS at /initfs/<name>.
fn register_boot_modules(args: &boot::entry::KernelArgs) {
    let modules = args.modules();
    if modules.is_empty() {
        serial_println!("[init] No modules provided by bootloader");
        return;
    }

    serial_println!("[init] Bootloader provided {} modules:", modules.len());
    for module in modules {
        let name = module.name_str();
        let base_virt = memory::phys_to_virt(module.base);
        let size = module.size;

        if size == 0 {
            continue;
        }

        // Register the module in the VFS at /initfs/<name>
        register_initfs_module(name, Some((base_virt, size)));
    }
}

/// Performs the register initfs module operation.
#[cfg(feature = "selftest")]
fn log_boot_module_magics(stage: &str) {
    crate::serial_println!(
        "[init] Module magic [{}]: (FAT32 module loader pending)",
        stage
    );
}

/// Performs the log boot module magics operation.
#[cfg(not(feature = "selftest"))]
fn log_boot_module_magics(_stage: &str) {}

/// Main kernel initialization - called by bootloader entry points
pub unsafe fn kernel_main(args: *const boot::entry::KernelArgs) -> ! {
    // Raw COM1 trace - works before any subsystem is initialized.
    {
        let thr: u16 = 0x3F8;
        let lsr: u16 = 0x3F8 + 5;
        let msg = b"[km] kernel_main enter\r\n";
        for &b in msg {
            loop {
                let s: u8;
                core::arch::asm!("in al, dx", out("al") s, in("dx") lsr, options(nomem, nostack, preserves_flags));
                if s & 0x20 != 0 { break; }
            }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }

    // Invariant: interrupts must stay disabled throughout kernel_main until the
    // scheduler is ready and the APIC timer is started (Asterinas pattern:
    // interrupts are only enabled once, at the very end of init).
    debug_assert!(
        !arch::interrupts_enabled(),
        "interrupts must be disabled at boot entry"
    );

    // Trace: raw COM1 after debug_assert
    {
        let thr: u16 = 0x3F8;
        let lsr: u16 = 0x3F8 + 5;
        let msg = b"[km] after debug_assert\r\n";
        for &b in msg {
            loop { let s: u8; core::arch::asm!("in al, dx", out("al") s, in("dx") lsr, options(nomem, nostack, preserves_flags)); if s & 0x20 != 0 { break; } }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }

    // =============================================
    // Phase 1: serial output (earliest debug output)
    // =============================================
    arch::x86_64::boot_timestamp::init();

    // Trace: raw COM1 after boot_timestamp
    {
        let thr: u16 = 0x3F8;
        let lsr: u16 = 0x3F8 + 5;
        let msg = b"[km] after boot_timestamp\r\n";
        for &b in msg {
            loop { let s: u8; core::arch::asm!("in al, dx", out("al") s, in("dx") lsr, options(nomem, nostack, preserves_flags)); if s & 0x20 != 0 { break; } }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }

    // Skip e9_println! — it uses format_args! which may crash before
    // the full kernel is initialized. Use raw COM1 trace instead.
    //crate::e9_println!("B0 kernel_main");

    // Trace before init_serial
    {
        let thr: u16 = 0x3F8;
        let lsr: u16 = 0x3F8 + 5;
        let msg = b"[km] before init_serial\r\n";
        for &b in msg {
            loop { let s: u8; core::arch::asm!("in al, dx", out("al") s, in("dx") lsr, options(nomem, nostack, preserves_flags)); if s & 0x20 != 0 { break; } }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }

    // init_serial() — temporarily disabled: #UD during uart_16550 init
    //init_serial();

    // Enable boot log prefix (timestamp) by default; can be disabled later if needed.
    arch::serial::set_boot_log_prefix_enabled(true);

    init_logger();
    //boot_milestone!("Kernel entry");
    //arch::x86_64::speaker::beep_phase(1);

    // =============================================
    // Phase 1c: TSS + GDT + IDT
    // =============================================
    // TSS and GDT must be loaded before the IDT so that the kernel's
    // CS selector (0x08) is valid when the first exception fires.
    // Without a valid GDT entry, the IDT handler triple-faults.

    arch::tss::init();
    arch::gdt::init();
    arch::x86_64::idt::init();
    //serial_println!("[init] IDT initialized.");
    //crate::e9_println!("B2 post-IDT");
    //boot_milestone!("IDT initialized");
    //crate::e9_println!("B3 milestone");

    // Trace after IDT
    {
        let thr: u16 = 0x3F8;
        let lsr: u16 = 0x3F8 + 5;
        let msg = b"[km] IDT initialized\r\n";
        for &b in msg {
            loop { let s: u8; core::arch::asm!("in al, dx", out("al") s, in("dx") lsr, options(nomem, nostack, preserves_flags)); if s & 0x20 != 0 { break; } }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
        }
    }

    debug_assert!(
        !arch::interrupts_enabled(),
        "interrupts must be disabled after IDT init"
    );
    e9_mark!(b'4');

    // Detect CPU features (must happen before init_cpu_extensions)
    e9_mark!(b'a');
    crate::arch::x86_64::cpuid::init();
    e9_mark!(b'b');

    // Initialize FPU/SSE/XSAVE for the BSP
    e9_mark!(b'c');
    crate::arch::x86_64::init_cpu_extensions();
    e9_mark!(b'd');

    // Seed the kernel entropy pool from RDRAND (if available).
    e9_mark!(b'e');
    crate::entropy::seed_from_rdrand();
    e9_mark!(b'f');

    // Initialize KASLR offsets (requires entropy pool to be seeded).
    e9_mark!(b'g');
    crate::kaslr::init();
    e9_mark!(b'h');

    // Initialize crypto subsystem (trusted keys for module verification).
    e9_mark!(b'i');
    crate::crypto::init();
    e9_mark!(b'j');

    // Puts default panic hooks early to ensure
    //we get useful info on any panics during init.
    e9_mark!(b'k');
    boot::panic::install_default_panic_hooks();
    e9_mark!(b'l');
    boot::symbols::init();
    e9_mark!(b'm');

    // Nice logo :D
    serial_println!();
    serial_println!();
    serial_println!(r"          __                 __   ________                         ");
    serial_println!(r"  _______/  |_____________ _/  |_/   __   \           ____  ______ ");
    serial_println!(r" /  ___/\   __\_  __ \__  \\   __\____    /  ______  /  _ \/  ___/ ");
    serial_println!(r" \___ \  |  |  |  | \// __ \|  |    /    /  /_____/ (  <_> )___ \  ");
    serial_println!(r"/____  > |__|  |__|  (____  /__|   /____/            \____/____  > ");
    serial_println!(r"     \/                   \/                                   \/  ");
    serial_println!();

    serial_println!("");
    serial_println!("=======================================================================================================");
    serial_println!("  strat9-OS kernel v0.1.0 (Bedrock)");
    serial_println!("  Copyright (c) 2024-26 Guillaume Gielly - GPLv3 License");
    serial_println!("");
    serial_println!("  This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY, without");
    serial_println!(
        "  even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
    );
    serial_println!("  See the GNU General Public License for more details.");
    serial_println!("=======================================================================================================");
    serial_println!();

    // Validate arguments
    if args.is_null() {
        serial_println!("[CRIT] No KernelArgs provided. System will hang.");
        loop {
            arch::hlt();
        }
    }

    let args = &*args;
    serial_println!("[init] KernelArgs at {:p}", args);

    // Store boot args globally so components can access them.
    // SAFETY: written once here, read-only thereafter.
    unsafe { BOOT_ARGS = Some(args) };

    // SAFETY: KernelArgs is packed; read fields via addr_of! to avoid unaligned references.
    let magic = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.magic)) };
    let abi_version = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.abi_version)) };

    if magic != strat9_abi::boot::STRAT9_BOOT_MAGIC {
        serial_println!(
            "[CRIT] Bad KernelArgs magic: 0x{:08x} (expected 0x{:08x})",
            magic,
            strat9_abi::boot::STRAT9_BOOT_MAGIC
        );
        loop {
            arch::hlt();
        }
    }
    if abi_version != strat9_abi::boot::STRAT9_BOOT_ABI_VERSION {
        serial_println!(
            "[CRIT] Unsupported boot ABI version: {} (kernel expects {})",
            abi_version,
            strat9_abi::boot::STRAT9_BOOT_ABI_VERSION
        );
        loop {
            arch::hlt();
        }
    }

    // Parse kernel cmdline (early, for serial console config).
    if args.cmdline_ptr != 0 && args.cmdline_len != 0 {
        let cmdline = args.cmdline_str();
        if !cmdline.is_empty() {
            serial_println!("[init] cmdline: '{}'", cmdline);
        }
        // SAFETY: cmdline_ptr is a valid null-terminated C string from the bootloader.
        unsafe { arch::x86_64::serial::parse_cmdline(args.cmdline_ptr, args.cmdline_len) };
    } else {
        serial_println!("[init] No kernel cmdline provided");
    }

    // Le's go !
    //
    // =============================================
    // Phase 1b : HHDM offset (must be set before any physical memory access)
    // =============================================
    let hhdm = args.hhdm_offset;
    memory::set_hhdm_offset(hhdm);
    serial_println!("[init] HHDM offset: 0x{:x}", hhdm);

    let memory_map_base =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.memory_map_base)) };
    let memory_map_size =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.memory_map_size)) };
    serial_println!(
        "[init] Memory map: 0x{:x} ({} bytes)",
        memory_map_base,
        memory_map_size
    );

    log_boot_module_magics("pre-mm");

    // =============================================
    // Phase 2 : memory management (Buddy Allocator)
    // =============================================
    crate::e9_println!("MM pre-regions");
    serial_println!("[init] Memory manager...");
    serial_println!("[init] Memory map: 0x{:x} ({} bytes)", memory_map_base, memory_map_size);
    let regions = args.memory_regions();
    serial_println!("[init] Memory regions count: {}", regions.len());
    if let Some(first) = regions.first() {
        serial_println!("[init] First region: base={:#x} size={:#x} kind={:?}",
            first.base, first.size, first.kind);
    }
    crate::e9_println!("MM regions");
    // Safety: single-threaded boot, no concurrent access
    let mmap_work = unsafe { &mut *core::ptr::addr_of_mut!(MMAP_WORK) };
    crate::e9_println!("MM work array");
    let mmap_work_len = core::cmp::min(regions.len(), mmap_work.len());
    crate::e9_println!("MM len calc");
    for (dst, src) in mmap_work.iter_mut().zip(regions.iter()).take(mmap_work_len) {
        *dst = *src;
    }
    crate::e9_println!("MM copy done");

    // Modules are loaded from the FAT32 boot partition.
    // Protected ranges will be set up after module loading is implemented in Phase 4.
    let protected_ranges = [None; memory::boot_alloc::MAX_PROTECTED_RANGES];
    crate::e9_println!("MM prot ranges");
    memory::boot_alloc::set_protected_ranges(&protected_ranges);
    crate::e9_println!("MM set prot done");

    // Initialize the boot allocator before manually carving the working memory
    // map. The allocator excludes the configured protected ranges itself, so
    // it can still see the large original free extents that VMware exposes
    // before module reservations fragment them.
    crate::e9_println!("MM pre-init-boot-alloc");
    memory::boot_alloc::init_boot_allocator(&mmap_work[..mmap_work_len]);
    crate::e9_println!("MM post-init-boot-alloc before serial");
    serial_println!("[init] Boot allocator ready.");
    serial_println!("[init] Boot allocator ready.");

    let total_ram = mmap_work[..mmap_work_len]
        .iter()
        .filter(|region| {
            matches!(
                region.kind,
                boot::entry::MemoryKind::Free | boot::entry::MemoryKind::Reclaim
            )
        })
        .map(|region| region.base.saturating_add(region.size))
        .max()
        .unwrap_or(0);
    let free_like_regions = count_free_like_regions(&mmap_work[..mmap_work_len], mmap_work_len);
    let metadata_bytes = memory::frame::metadata_size_for(total_ram) as usize;
    let boot_stats = memory::boot_alloc::boot_allocator_stats();
    serial_println!(
        "[init] Frame metadata plan: total_ram={:#x} free_regions={} bytes={} boot_free={} largest_boot_region={}",
        total_ram,
        free_like_regions,
        metadata_bytes,
        boot_stats.total_free_bytes as usize,
        boot_stats.largest_region_bytes as usize,
    );

    {
        let mut boot_alloc = memory::boot_alloc::get_boot_allocator().lock();
        memory::frame::init_metadata_array(total_ram, &mut *boot_alloc);
    }
    serial_println!("[init] Frame metadata ready.");

    // TODO: Phase 4 - Reserve module memory ranges when FAT32 loader is implemented
    // For now, skip module reservation since we're using the custom bootloader + FAT32

    memory::buddy::init_buddy_allocator(&mmap_work[..mmap_work_len]);

    serial_println!("[init] Buddy allocator ready.");

    // =============================================
    // Stack switch: migrate off the 8 KB bootstrap stack
    // =============================================
    // Inspired by Unikraft: allocate a proper kernel stack from the buddy
    // allocator and switch to it. The bootstrap stack is abandoned after
    // the switch (it remains allocated but unused).
    {
        use crate::boot::dtb_boot::KERNEL_STACK_SIZE;
        let stack_phys = memory::boot_alloc::alloc_bytes_accessible(
            KERNEL_STACK_SIZE,
            16, // 16-byte alignment for SysV ABI
        );
        if let Some(phys) = stack_phys {
            let stack_top = memory::phys_to_virt(phys.as_u64()) + KERNEL_STACK_SIZE as u64;
            serial_println!(
                "[init] Kernel stack allocated: {:#x} - {:#x} ({} KB)",
                memory::phys_to_virt(phys.as_u64()),
                stack_top,
                KERNEL_STACK_SIZE / 1024
            );

            // Switch to the new stack via asm trampoline.
            // This abandons the 8 KB bootstrap stack.
            extern "C" {
                fn switch_stack(new_rsp: u64, entry: extern "C" fn() -> !) -> !;
            }
            extern "C" fn stack_switch_entry() -> ! {
                // We are now on the new 256 KB stack.
                // The old bootstrap stack is abandoned.
                // Continue with the rest of kernel_main.
                // This is a noreturn function; we use a trick to continue
                // execution after the stack switch.
                //
                // Actually, we can't easily continue kernel_main from here
                // because the stack frame is different. Instead, we store
                // the continuation address on the new stack and return to it.
                //
                // For now, we just halt : the real init continues on the
                // bootstrap stack. The stack switch is a demonstration of
                // the capability; full migration will happen when we restructure
                // the init phases.
                crate::serial_println!("[init] Stack switch: entered new stack, continuing...");
                loop {
                    unsafe {
                        core::arch::asm!("hlt");
                    }
                }
            }

            // For now, log the allocation but don't actually switch.
            // Full stack migration requires restructuring kernel_main into
            // a two-phase init (early on bootstrap, late on real stack).
            serial_println!("[init] Stack allocated (switch deferred to Phase 7)");
        } else {
            serial_println!(
                "[init] WARNING: kernel stack alloc failed, staying on bootstrap stack"
            );
        }
    }

    // Apply kernel.toml configuration (must be after buddy allocator init,
    // before VGA init so quiet_mode can suppress early debug output).
    boot::config::apply_kernel_config();

    // Initialize the vmalloc arena (VM-backed large heap allocations)
    memory::vmalloc::init();
    serial_println!("[init] Vmalloc arena ready.");

    debug_assert!(
        !arch::interrupts_enabled(),
        "interrupts must be disabled after buddy allocator init"
    );

    boot_milestone!("Memory manager ready");
    arch::speaker::beep_phase(2);
    log_boot_module_magics("post-buddy");

    // Sanity check: verify buddy allocator was initialized.
    // If this fails, the memory subsystem is fatally broken.
    if crate::memory::buddy::get_allocator().lock().is_none() {
        serial_println!("[CRIT] Buddy allocator self-test FAILED: allocator not initialized");
        serial_println!("[CRIT] System halted.");
        loop {
            arch::x86_64::hlt();
        }
    }

    // =============================================
    // Phase 2.5: paging / VMM (Must be before Console if FB is not already mapped)
    // =============================================
    crate::e9_println!("B5 pre-paging");
    serial_println!("[init] Paging...");
    memory::paging::init(hhdm);
    crate::e9_println!("B6 post-paging");

    // Map all RAM into HHDM to ensure buddy/heap allocations are accessible.
    // VMware bootloader HHDM may be sparse, causing PF on new heap pages.
    memory::paging::map_all_ram(&mmap_work[..mmap_work_len]);

    // Framebuffer is often backed by MMIO memory outside RAM (e.g. around 0xFDxxxxxx),
    // or sometimes at the very end of RAM that might be missed by the bootloader's initial map.
    // Explicitly map its full range in HHDM for all later graphics access.
    if args.framebuffer_addr != 0 && args.framebuffer_stride != 0 && args.framebuffer_height != 0 {
        let fb_phys = if args.framebuffer_addr >= hhdm {
            args.framebuffer_addr - hhdm
        } else {
            args.framebuffer_addr
        };
        let fb_size =
            (args.framebuffer_stride as u64).saturating_mul(args.framebuffer_height as u64);
        memory::paging::ensure_identity_map_range(fb_phys, fb_size);
        serial_println!(
            "[init] Framebuffer mapped: phys=0x{:x} size={} bytes",
            fb_phys,
            fb_size
        );
    }
    serial_println!("[init] Paging initialized.");
    boot_milestone!("Paging initialized");
    arch::speaker::beep_phase(3);

    // =============================================
    // Phase 3: console output (VGA or serial fallback)
    // =============================================
    serial_println!("[init] Console...");
    arch::vga::init(
        args.framebuffer_addr,
        args.framebuffer_width,
        args.framebuffer_height,
        args.framebuffer_stride,
        args.framebuffer_bpp,
        args.framebuffer_red_mask_size,
        args.framebuffer_red_mask_shift,
        args.framebuffer_green_mask_size,
        args.framebuffer_green_mask_shift,
        args.framebuffer_blue_mask_size,
        args.framebuffer_blue_mask_shift,
    );
    // Flush any log lines buffered before VGA was available.
    arch::vgabuf::vgabuf_flush_to_framebuffer();
    vga_println!("[OK] Paging initialized");
    vga_println!("[OK] Serial port initialized");
    vga_println!("[OK] Memory manager active");

    // =============================================
    // Phase 4a : TSS + GDT (already initialized in Phase 1c)
    // =============================================
    serial_println!("[init] TSS+GDT already initialized.");

    // =============================================
    // Phase 4c: SYSCALL/SYSRET MSR configuration
    // =============================================
    serial_println!("[init] SYSCALL/SYSRET...");
    vga_println!("[..] Initializing SYSCALL/SYSRET...");
    arch::syscall::init();
    serial_println!("[init] SYSCALL/SYSRET initialized.");
    vga_println!("[OK] SYSCALL/SYSRET configured");

    // =============================================
    // Phase 4d: component system - Bootstrap stage
    // =============================================
    serial_println!("[init] Components (bootstrap)...");
    vga_println!("[..] Initializing bootstrap components...");
    if let Err(e) = component::init_all(component::InitStage::Bootstrap) {
        serial_println!("[WARN] Some bootstrap components failed: {:?}", e);
    }
    serial_println!("[init] Bootstrap components initialized.");
    vga_println!("[OK] Bootstrap components ready");

    // =============================================
    // Phase 5b: paging / VMM - (Moved earlier to prevent PF on VGA init)
    // =============================================
    log_boot_module_magics("post-paging");

    // =============================================
    // Phase 5c: kernel address space
    // =============================================
    serial_println!("[init] Kernel address space...");
    vga_println!("[..] Initializing kernel address space...");
    memory::address_space::init_kernel_address_space();
    serial_println!("[init] Kernel address space initialized.");
    debug_assert!(
        !arch::interrupts_enabled(),
        "interrupts must be disabled after kernel address space init"
    );
    vga_println!("[OK] Kernel address space initialized");
    log_boot_module_magics("post-kas");

    // =============================================
    // Phase 5d: virtual file system
    // =============================================
    serial_println!("[init] VFS...");
    vga_println!("[..] Initializing virtual file system...");

    vfs::init();

    serial_println!("[init] VFS initialized.");
    vga_println!("[OK] VFS initialized");
    register_boot_modules(args);

    log_boot_module_magics("post-cow");

    // =============================================
    // Phase 6: ACPI + APIC (with PIC fallback)
    // =============================================
    serial_println!("[init] Interrupt controller...");
    vga_println!("[..] Initializing interrupt controller...");

    // Ensure RSDP is mapped (it might be in unmapped legacy region)
    memory::paging::ensure_identity_map(args.acpi_rsdp_base);

    let rsdp_virt = memory::phys_to_virt(args.acpi_rsdp_base);
    let apic_active = init_apic_subsystem(rsdp_virt);

    if !apic_active {
        // Fallback: legacy PIC + PIT
        serial_println!("[init] APIC unavailable, falling back to legacy PIC");
        vga_println!("[..] Falling back to legacy PIC...");
        arch::pic::init(
            arch::pic::PIC1_OFFSET,
            arch::pic::PIC2_OFFSET,
        );
        arch::pic::disable();
        arch::pic::enable_irq(0); // Timer
        arch::pic::enable_irq(1); // Keyboard
        serial_println!("[init] Legacy PIC initialized.");
        vga_println!("[OK] Legacy PIC initialized (IRQ0: timer, IRQ1: keyboard)");
    } else {
        serial_println!("[init] APIC subsystem initialized.");
        vga_println!("[OK] APIC + I/O APIC + APIC timer active");
    }

    // Initialize TLB shootdown system (SMP safety for COW operations).
    if apic_active {
        arch::tlb::init();
        serial_println!("[init] TLB shootdown system initialized.");
        debug_assert!(
            !arch::interrupts_enabled(),
            "interrupts must be disabled after TLB init"
        );
    }

    // ================================================
    // Phase 6j: SMP bring-up (AP boot) + per-CPU data
    // ================================================
    if apic_active {
        let bsp_apic_id = arch::apic::lapic_id();
        arch::percpu::init_boot_cpu(bsp_apic_id);
        arch::percpu::init_gs_base(0);
        serial_println!("[init] SMP: booting secondary cores...");
        vga_println!("[..] SMP: starting APs...");

        match arch::smp::init() {
            Ok(count) => {
                serial_println!("[init] SMP: {} core(s) online", count);
                vga_println!("[OK] SMP: {} core(s) online", count);
            }
            Err(e) => {
                serial_println!("[init] SMP init failed: {}", e);
                vga_println!("[WARN] SMP init failed: {}", e);
            }
        }
    } else {
        arch::percpu::init_boot_cpu(0);
    }
    boot_milestone!("APIC + SMP ready");
    arch::speaker::beep_phase(4);

    arch::keyboard::init();
    serial_println!("[init] PS/2 keyboard controller initialized.");

    // =============================================
    // Phase 6k: PS/2 mouse driver
    // =============================================
    if apic_active {
        let mouse_ok = arch::mouse::init();

        if mouse_ok {
            serial_println!("[init] PS/2 mouse initialized.");
            vga_println!("[OK] PS/2 mouse ready");
        } else {
            serial_println!("[init] PS/2 mouse not found (optional).");
        }
    }

    // =============================================
    // Phase 7: initialize scheduler
    // =============================================
    crate::e9_println!("B7 pre-sched");
    serial_println!("[init] Initializing scheduler...");
    vga_println!("[..] Setting up multitasking...");
    // Print struct layout for crash-site offset analysis (debug build only).
    crate::process::task::Task::debug_print_layout();
    process::init_scheduler();
    crate::e9_println!("B8 post-sched");

    // Sanity check: verify scheduler is initialized.
    if crate::process::scheduler::GLOBAL_SCHED_STATE
        .lock()
        .is_none()
    {
        serial_println!("[CRIT] Scheduler init failed: GLOBAL_SCHED_STATE is None");
        serial_println!("[CRIT] System halted.");
        loop {
            arch::x86_64::hlt();
        }
    }

    debug_assert!(
        !arch::interrupts_enabled(),
        "interrupts must be disabled after scheduler init"
    );

    // =============================================
    // Phase 7+: Start timer
    // =============================================
    // The BSP timer only starts when the scheduler is ready to handle interrupts.
    // This is the last point where interrupts are guaranteed disabled on BSP.
    if apic_active {
        debug_assert!(
            !arch::interrupts_enabled(),
            "interrupts must be disabled before APIC timer start"
        );
        serial_println!("[init] Starting APIC timer on BSP...");
        arch::timer::start_apic_timer_cached();
    }

    serial_println!("[init] Scheduler initialized.");
    serial_println!("[trace][bsp] after init_scheduler");
    boot_milestone!("Scheduler + timer ready");
    arch::speaker::beep_phase(5);
    vga_println!("[OK] Multitasking enabled");

    // =============================================
    // Phase 7b: component system - Kthread stage
    // =============================================
    crate::e9_println!("B9 pre-kthread");
    serial_println!("[trace][bsp] before kthread init_all");
    serial_println!("[init] Components (kthread)...");
    vga_println!("[..] Initializing kthread components...");

    if let Err(e) = component::init_all(component::InitStage::Kthread) {
        serial_println!("[WARN] Some kthread components failed: {:?}", e);
    }

    serial_println!("[trace][bsp] after kthread init_all");
    serial_println!("[init] Kthread components initialized.");
    vga_println!("[OK] Kthread components ready");

    // =============================================
    // Phase 7c: component system - Hardware stage
    // =============================================
    crate::e9_println!("BA pre-hardware");
    serial_println!("[init] Components (hardware)...");
    vga_println!("[..] Initializing hardware components...");
    if let Err(e) = component::init_all(component::InitStage::Hardware) {
        serial_println!("[WARN] Some hardware components failed: {:?}", e);
    }
    serial_println!("[init] Hardware components initialized.");
    vga_println!("[OK] Hardware components ready");
    boot_milestone!("Hardware drivers ready");

    #[cfg(feature = "selftest")]
    {
        // =============================================
        // Phase 8a: runtime self-tests
        // =============================================
        serial_println!("[init] Creating self-test tasks...");
        vga_println!("[..] Adding self-test tasks...");
        process::selftest::create_selftest_tasks();
        serial_println!("[init] Self-test tasks created.");
        vga_println!("[OK] Self-test tasks added");
    }

    // Ring3 smoke test task disabled in selftest mode: fork-test already
    // exercises Ring3 transitions and this extra task can interfere.

    #[cfg(not(feature = "selftest"))]
    {
        // =============================================
        // Phase 8c: process components
        // =============================================
        let mut init_task_id: Option<crate::process::TaskId> = None;

        crate::e9_println!("BB pre-process");
        serial_println!("[init] Components (process)...");
        vga_println!("[..] Initializing process components...");
        if let Err(e) = component::init_all(component::InitStage::Process) {
            serial_println!("[WARN] Some process components failed: {:?}", e);
        }
        serial_println!("[init] Process components initialized.");
        vga_println!("[OK] Process components ready");

        // =============================================
        // Phase 8d: device enumeration and reporting
        // =============================================
        // Hardware drivers were initialized in the Hardware stage above.
        // This block reports which devices were found.
        crate::e9_println!("BD device-report");
        serial_println!("[init] Checking for devices...");
        vga_println!("[..] Checking for devices...");

        if let Some(blk) = hardware::storage::virtio_block::get_device() {
            use hardware::storage::virtio_block::BlockDevice;
            serial_println!(
                "[INFO] VirtIO block device found. Capacity: {} sectors",
                blk.sector_count()
            );
            vga_println!("[OK] VirtIO block driver loaded");
        } else {
            serial_println!("[WARN] No VirtIO block device found");
            vga_println!("[WARN] No VirtIO block device found");
        }

        if let Some(ahci) = hardware::storage::ahci::get_device() {
            serial_println!(
                "[INFO] AHCI SATA device found. Capacity: {} sectors ({} MiB)",
                ahci.sector_count(),
                (ahci.sector_count() * 512) / 1048576, // 1024*1024 bytes per MiB, 512 bytes per sector
            );
            vga_println!("[OK] AHCI SATA driver loaded");
        } else {
            serial_println!("[INFO] No AHCI SATA device found");
        }

        if let Some(nvme) = hardware::storage::nvme::get_first_controller() {
            let nvme = nvme.lock();
            if let Some(ns) = nvme.get_namespace(0) {
                serial_println!(
                    "[INFO] NVMe device found. Namespace {} - {} blocks @ {} bytes ({} MiB)",
                    ns.nsid,
                    ns.size,
                    ns.block_size,
                    (ns.size * ns.block_size as u64) / 1048576, // 1024*1024 bytes per MiB
                );
                vga_println!("[OK] NVMe driver loaded");
            }
        } else {
            serial_println!("[INFO] No NVMe device found");
        }

        // Report all registered network interfaces (E1000 + VirtIO)
        {
            let ifaces = hardware::nic::list_interfaces();
            if ifaces.is_empty() {
                serial_println!("[WARN] No network devices found");
                vga_println!("[WARN] No network devices found");
            } else {
                for name in &ifaces {
                    if let Some(dev) = hardware::nic::get_device(name) {
                        let mac = dev.mac_address();
                        serial_println!(
                            "[INFO] Network {} ({}) MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
                            name, dev.name(),
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                            if dev.link_up() { "up" } else { "down" },
                        );
                        vga_println!("[OK] Network {} ({}) loaded", name, dev.name());
                    }
                }
            }
        }

        serial_println!("[init] Storage verification skipped (boot path)");
        vga_println!("[..] Storage verification skipped at boot");

        // Launch the init process from FAT32 boot partition.
        // TODO: Phase 4 - Implement FAT32 module loading
        let mut init_loaded = false;

        // For now, try to load from VFS if available
        if let Ok(fd) = vfs::open("/initfs/init", vfs::OpenFlags::READ) {
            if let Ok(data) = vfs::read_all(fd) {
                let init_caps = [crate::silo::create_silo_admin_capability()];
                match process::elf::load_and_run_elf_with_caps(&data, "init", &init_caps) {
                    Ok(task_id) => {
                        init_task_id = Some(task_id);
                        init_loaded = true;
                        serial_println!("[init] ELF '/initfs/init' loaded as task 'init'.");
                    }
                    Err(e) => {
                        serial_println!("[init] Failed to load init ELF: {}", e);
                    }
                }
            }
        }

        // Try to load init from modules if not already loaded
        if !init_loaded {
            for module in args.modules() {
                if module.name_str() == "init" {
                    let base_virt = memory::phys_to_virt(module.base);
                    let elf_data = unsafe {
                        core::slice::from_raw_parts(base_virt as *const u8, module.size as usize)
                    };
                    let init_caps = [crate::silo::create_silo_admin_capability()];
                    match process::elf::load_and_run_elf_with_caps(elf_data, "init", &init_caps) {
                        Ok(task_id) => {
                            init_task_id = Some(task_id);
                            serial_println!(
                                "[init] ELF loaded as task 'init' (from module table)."
                            );
                        }
                        Err(e) => {
                            serial_println!("[init] Failed to load init ELF: {}", e);
                        }
                    }
                    break;
                }
            }
        }
        // TODO: Phase 4 - Load all modules from FAT32 boot partition
        serial_println!("[init] FAT32 module loader pending (Phase 4)");
        if let (Some(task_id), Some(device)) =
            (init_task_id, hardware::storage::virtio_block::get_device())
        {
            if let Some(task) = crate::process::get_task_by_id(task_id) {
                let cap = crate::capability::get_capability_manager().create_capability(
                    crate::capability::ResourceType::Volume,
                    device as *const _ as usize,
                    crate::capability::CapPermissions {
                        read: true,
                        write: true,
                        execute: false,
                        grant: true,
                        revoke: true,
                    },
                );
                unsafe { (&mut *task.process.capabilities.get()).insert(cap) };
                serial_println!("[init] Granted volume capability to init");
            }
        }

        match process::Task::new_kernel_task_with_stack(
            shell::shell_main,
            "chevron-shell",
            process::TaskPriority::Normal,
            64 * 1024,
        ) {
            Ok(shell_task) => {
                process::add_task(shell_task);
                serial_println!("[init] Chevron shell ready.");
            }
            Err(e) => {
                serial_println!("[WARN] Failed to create shell task: {}", e);
            }
        }
        if let Ok(status_task) = process::Task::new_kernel_task_with_stack(
            arch::vga::status_line_task_main,
            "status-line",
            process::TaskPriority::Low,
            64 * 1024,
        ) {
            process::add_task(status_task);
            // Switch from live VGA debug output to buffered vgabuf path.
            // The status_line_task will flush vgabuf to the framebuffer.
            crate::debug_cfg::set_vga_debug_live(false);
        }
    }
    #[cfg(feature = "selftest")]
    {
        serial_println!("[init] Selftest mode: skipping process services and virtio drivers");
    }

    // Initialize keyboard layout to French by default
    crate::arch::keyboard_layout::set_french_layout();

    // =============================================
    // Boot complete : start preemptive multitasking
    // =============================================
    if apic_active {
        arch::smp::open_ap_scheduler_gate();
    }
    crate::e9_println!("BC pre-schedule");
    boot_milestone!("Boot complete ! Now entering in scheduler");
    arch::speaker::beep_startup();
    serial_println!("[init] Boot complete. Starting preemptive scheduler...");
    vga_println!("[OK] Starting multitasking (preemptive)");
    arch::serial::set_boot_log_prefix_enabled(false);

    // Keep interrupts disabled on the init stack. `schedule_on_cpu()` enters
    // the first task with IF=0 and `task_entry_trampoline` executes `sti`
    // after the task context is fully installed.

    // Start the scheduler - this will never return
    serial_force_println!("[trace][bsp] schedule start (never returns)");
    process::schedule();
}

/// Initialize the APIC subsystem (Local APIC + I/O APIC + APIC Timer).
///
/// Returns `true` if APIC is active, `false` if we should fall back to PIC+PIT.
/// On failure at any step, logs a warning and returns `false`.
fn init_apic_subsystem(rsdp_vaddr: u64) -> bool {
    use arch::{apic, ioapic, pic, timer};
    use timer::TIMER_HZ;

    // Step 6a: check CPUID for APIC support
    if !apic::is_present() {
        log::warn!("APIC: not present (CPUID)");
        return false;
    }
    serial_println!("[init]   6a. APIC present (CPUID)");

    // Step 6b: initialize ACPI (validate RSDP)
    match acpi::init(rsdp_vaddr) {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("APIC: no RSDP from bootloader");
            return false;
        }
        Err(e) => {
            log::warn!("APIC: ACPI init failed: {}", e);
            return false;
        }
    }
    serial_println!("[init]   6b. ACPI RSDP validated");

    // Step 6c: Parse MADT
    let madt_info = match acpi::madt::parse_madt() {
        Some(info) => info,
        None => {
            log::warn!("APIC: MADT not found");
            return false;
        }
    };
    serial_println!("[init]   6c. MADT parsed");

    if let Some(mcfg) = acpi::mcfg::parse_mcfg() {
        serial_println!(
            "[init]   6c+. MCFG parsed ({} segment(s))",
            mcfg.entries.len()
        );
        for entry in mcfg.entries.iter() {
            log::info!(
                "ACPI: MCFG seg={} ecam={:#x} buses={}..{} ({} bus(es))",
                entry.segment_group,
                entry.base_address,
                entry.start_bus,
                entry.end_bus,
                entry.bus_count()
            );
        }
    } else {
        serial_println!("[init]   6c+. MCFG not found");
    }

    // Step 6c++: Parse IVRS (AMD IOMMU)
    if let Some(ivrs) = acpi::ivrs::Ivrs::get() {
        let dev_entry_count = unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!(ivrs.header().dev_entry_count))
        };
        serial_println!(
            "[init]   6c++. IVRS parsed (flags: draint={}, coherent={}, {} device entries)",
            ivrs.header().has_draint(),
            ivrs.header().is_coherent(),
            dev_entry_count,
        );
        ivrs.dump();
    } else {
        serial_println!("[init]   6c++. IVRS not found (no AMD IOMMU)");
    }

    // Step 6d: initialize Local APIC
    // Ensure Local APIC MMIO is mapped
    memory::paging::ensure_identity_map(madt_info.local_apic_address);
    apic::init(madt_info.local_apic_address);
    serial_println!("[init]   6d. Local APIC initialized");

    // Step 6e: initialize first I/O APIC
    if madt_info.io_apic_count == 0 {
        log::warn!("APIC: no I/O APIC in MADT");
        return false;
    }
    let Some(io_apic_entry) = madt_info.io_apics[0] else {
        log::warn!("APIC: MADT I/O APIC entry[0] missing");
        return false;
    };
    // Ensure I/O APIC MMIO is mapped
    memory::paging::ensure_identity_map(io_apic_entry.address as u64);
    ioapic::init(io_apic_entry.address, io_apic_entry.gsi_base);
    serial_println!("[init]   6e. I/O APIC initialized");

    // Step 6f: remap PIC to 0x20+ then keep only PS/2 input IRQs enabled.
    // Must remap first to avoid stray interrupts at exception vectors (0-31).
    // On the current q35 + SMP path, LAPIC timer delivery is fine but legacy
    // PS/2 IRQs are not reliably arriving through the I/O APIC. Keep keyboard
    // and mouse on the remapped PIC while using APIC for the timer.
    pic::init(pic::PIC1_OFFSET, pic::PIC2_OFFSET);
    pic::disable_permanently();
    pic::enable_irq(1);
    pic::enable_irq(2);
    pic::enable_irq(12);
    serial_println!("[init]   6f. Legacy PIC remapped; PS/2 IRQ1/IRQ12 left enabled");

    // Step 6g: route only the legacy timer IRQ via I/O APIC.
    // Keyboard (IRQ1) and mouse (IRQ12) stay on the remapped PIC path above.
    let lapic_id = apic::lapic_id();
    ioapic::route_legacy_irq(0, lapic_id, 0x20, &madt_info.overrides);
    ioapic::mask_legacy_irq(1, &madt_info.overrides);
    ioapic::mask_legacy_irq(12, &madt_info.overrides);

    // Store overrides so PCI NIC drivers can route their IRQ later.
    ioapic::store_madt_overrides(&madt_info.overrides);

    serial_println!("[init]   6g. IRQ0->vec 0x20 via IOAPIC; IRQ1/IRQ12 via PIC");

    // Step 6h: calibrate APIC timer using PIT channel 2
    serial_println!("[init]   6h. Calibrating APIC timer using PIT channel 2...");
    serial_println!(
        "[timer] ================================ TIMER INIT ================================"
    );

    let ticks_per_10ms = timer::calibrate_apic_timer();

    if ticks_per_10ms == 0 {
        log::error!("APIC: timer calibration FAILED");
        log::warn!("Falling back to legacy PIT timer at 100Hz");

        // Re-enable PIC since APIC timer failed
        // (Note: I/O APIC routing is still active for keyboard/timer via PIC vectors)
        serial_println!("[timer] APIC calibration failed, initializing PIT fallback...");
        timer::init_pit(TIMER_HZ as u32);
        serial_println!(
            "[timer] PIT initialized at {}Hz ({} ms/tick)",
            TIMER_HZ,
            1_000 / TIMER_HZ
        );
        serial_println!("[init]   6h. PIT timer initialized (fallback)");

        serial_println!("[timer] ============================= TIMER INIT COMPLETE ============================");
        serial_println!("[timer] Mode: PIT (legacy fallback)");
        serial_println!("[timer] Frequency: {}Hz", TIMER_HZ);
        serial_println!("[timer] Interval: {} ms per tick", 1_000 / TIMER_HZ);
        serial_println!(
            "[timer] =========================================================================="
        );

        // Continue with PIT - don't return false
        // return false;
    } else {
        serial_println!("[init]   6h. APIC timer calibrated successfully");

        // Step 6i: DO NOT start APIC timer yet. (Asterinas style)
        // We will start it only after the scheduler is ready.
        // timer::start_apic_timer(ticks_per_10ms);

        // Step 6i+: quench legacy PIT to prevent phantom timer interrupts.
        timer::stop_pit();
        ioapic::mask_legacy_irq(0, &madt_info.overrides);
        serial_println!("[init]   6i+. Legacy PIT stopped and masked in IOAPIC");

        serial_println!("[timer] ============================= TIMER INIT COMPLETE ============================");
        serial_println!("[timer] Mode: APIC (native)");
        serial_println!("[timer] Frequency: {}Hz", TIMER_HZ);
        serial_println!("[timer] Interval: {} ms per tick", 1_000 / TIMER_HZ);
        serial_println!("[timer] Ticks per 10ms: {}", ticks_per_10ms);
        serial_println!(
            "[timer] =========================================================================="
        );
    }

    true
}

/// Boot-module lookup shim for non-x86 targets (always empty).
/// Boot-module lookup shim for non-x86 targets (always empty).
#[cfg(not(target_arch = "x86_64"))]
pub mod boot_limine_shim {
    pub fn kernel_elf_bytes() -> Option<&'static [u8]> {
        None
    }
    pub fn test_syscalls_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_mem_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_mem_stressed_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_mem_region_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_mem_region_proc_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_exec_module() -> Option<(u64, u64)> {
        None
    }

    pub fn test_exec_helper_module() -> Option<(u64, u64)> {
        None
    }

    pub fn fs_ext4_module() -> Option<(u64, u64)> {
        None
    }

    pub fn strate_fs_ramfs_module() -> Option<(u64, u64)> {
        None
    }

    pub fn init_module() -> Option<(u64, u64)> {
        None
    }

    pub fn console_admin_module() -> Option<(u64, u64)> {
        None
    }

    pub fn strate_net_module() -> Option<(u64, u64)> {
        None
    }

    pub fn strate_bus_module() -> Option<(u64, u64)> {
        None
    }

    pub fn dhcp_client_module() -> Option<(u64, u64)> {
        None
    }

    pub fn ping_module() -> Option<(u64, u64)> {
        None
    }

    pub fn telnetd_module() -> Option<(u64, u64)> {
        None
    }

    pub fn udp_tool_module() -> Option<(u64, u64)> {
        None
    }

    pub fn strate_wasm_module() -> Option<(u64, u64)> {
        None
    }

    pub fn hello_wasm_module() -> Option<(u64, u64)> {
        None
    }

    pub fn wasm_test_toml_module() -> Option<(u64, u64)> {
        None
    }

    pub fn strate_webrtc_module() -> Option<(u64, u64)> {
        None
    }

    pub fn web_admin_module() -> Option<(u64, u64)> {
        None
    }
}

/// Unified access to the `x86_64` crate surface used by shared code.
/// On x86_64 this IS the real crate; on riscv64 it is the panicking stub.
pub mod x86_crate_shim {
    #[cfg(target_arch = "x86_64")]
    pub use ::x86_64::*;
    #[cfg(target_arch = "x86_64")]
    pub use ::x86_64::{instructions, registers, structures};

    #[cfg(not(target_arch = "x86_64"))]
    pub use crate::arch::x86_64::*;
}
