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
#![feature(allocator_api)]
#![feature(alloc_error_handler)]

extern crate alloc;

// OSTD-like abstraction layer (minimal unsafe TCB)
pub mod ostd;

pub mod acpi;
pub mod arch;
pub mod boot;
pub mod capability;
pub mod components;
pub mod hardware;
pub mod ipc;
pub mod memory;
pub mod namespace;
pub mod process;
pub mod shell;
pub mod silo;
pub mod sync;
pub mod syscall;
pub mod trace;
pub mod vfs;

// Re-export boot::limine::kmain as the main entry point
pub use boot::limine::kmain;

// serial_print! and serial_println! macros are #[macro_export]'ed
// from arch::x86_64::serial and available at crate root automatically.

/// Initialize serial output
pub fn init_serial() {
    arch::x86_64::serial::init();
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

const fn null_region() -> boot::entry::MemoryRegion {
    boot::entry::MemoryRegion {
        base: 0,
        size: 0,
        kind: boot::entry::MemoryKind::Reserved,
    }
}

#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[inline]
const fn virt_or_phys_to_phys(addr: u64, hhdm: u64) -> u64 {
    if hhdm != 0 && addr >= hhdm {
        addr - hhdm
    } else {
        addr
    }
}

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

fn register_initfs_module(path: &str, module: Option<(u64, u64)>) {
    let Some((base, size)) = module else {
        return;
    };
    if base == 0 || size == 0 {
        return;
    }

    let base_virt = memory::phys_to_virt(base);
    let data = unsafe { core::slice::from_raw_parts(base_virt as *const u8, size as usize) };
    #[cfg(feature = "selftest")]
    if data.len() >= 4 {
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
    let mut owned = alloc::vec::Vec::with_capacity(data.len());
    owned.extend_from_slice(data);
    let leaked: &'static [u8] = alloc::boxed::Box::leak(owned.into_boxed_slice());

    if let Err(e) = vfs::register_initfs_file(path, leaked.as_ptr(), leaked.len()) {
        serial_println!("[init] Failed to register /initfs/{}: {:?}", path, e);
    } else {
        serial_println!("[init] Registered /initfs/{} ({} bytes)", path, size);
    }
}

fn register_boot_initfs_modules(initfs_base: u64, initfs_size: u64) {
    let boot_test_pid = if initfs_base != 0 && initfs_size != 0 {
        Some((initfs_base, initfs_size))
    } else {
        None
    };
    let initfs_modules = [
        ("test_pid", boot_test_pid),
        ("test_syscalls", crate::boot::limine::test_syscalls_module()),
        ("test_mem", crate::boot::limine::test_mem_module()),
        (
            "test_mem_stressed",
            crate::boot::limine::test_mem_stressed_module(),
        ),
        ("fs-ext4", crate::boot::limine::fs_ext4_module()),
        (
            "strate-fs-ramfs",
            crate::boot::limine::strate_fs_ramfs_module(),
        ),
        ("init", crate::boot::limine::init_module()),
        ("console-admin", crate::boot::limine::console_admin_module()),
        ("strate-net", crate::boot::limine::strate_net_module()),
        ("bin/dhcp-client", crate::boot::limine::dhcp_client_module()),
        ("bin/ping", crate::boot::limine::ping_module()),
        ("bin/telnetd", crate::boot::limine::telnetd_module()),
    ];
    for (path, module) in initfs_modules {
        register_initfs_module(path, module);
    }
}

#[inline]
fn boot_module_slice(base: u64, size: u64) -> &'static [u8] {
    let base_virt = memory::phys_to_virt(base);
    unsafe { core::slice::from_raw_parts(base_virt as *const u8, size as usize) }
}

#[cfg(feature = "selftest")]
fn log_boot_module_magics(stage: &str) {
    let modules = [
        ("init", crate::boot::limine::init_module()),
        ("console-admin", crate::boot::limine::console_admin_module()),
        ("strate-net", crate::boot::limine::strate_net_module()),
        ("bin/dhcp-client", crate::boot::limine::dhcp_client_module()),
        ("bin/ping", crate::boot::limine::ping_module()),
        ("bin/telnetd", crate::boot::limine::telnetd_module()),
    ];
    for (name, module) in modules {
        let Some((base, size)) = module else {
            continue;
        };
        if size < 4 {
            continue;
        }
        let ptr = memory::phys_to_virt(base) as *const u8;
        let m0 = unsafe { core::ptr::read_volatile(ptr) };
        let m1 = unsafe { core::ptr::read_volatile(ptr.add(1)) };
        let m2 = unsafe { core::ptr::read_volatile(ptr.add(2)) };
        let m3 = unsafe { core::ptr::read_volatile(ptr.add(3)) };
        serial_println!(
            "[init] Module magic [{}]: {} phys=0x{:x} magic={:02x}{:02x}{:02x}{:02x} size={}",
            stage,
            name,
            base,
            m0,
            m1,
            m2,
            m3,
            size
        );
    }
}

#[cfg(not(feature = "selftest"))]
fn log_boot_module_magics(_stage: &str) {}

/// Main kernel initialization - called by bootloader entry points
pub unsafe fn kernel_main(args: *const boot::entry::KernelArgs) -> ! {
    use core::fmt::Write;

    // =============================================
    // Phase 1: serial output (earliest debug output)
    // =============================================
    init_serial();
    init_logger();

    // Initialize FPU/SSE for the BSP
    crate::arch::x86_64::init_fpu();

    // Puts default panic hooks early to ensure
    //we get useful info on any panics during init.
    boot::panic::install_default_panic_hooks();

    // Nice logo :D
    serial_println!(r"          __                 __   ________                         ");
    serial_println!(r"  _______/  |_____________ _/  |_/   __   \           ____  ______ ");
    serial_println!(r" /  ___/\   __\_  __ \__  \\   __\____    /  ______  /  _ \/  ___/ ");
    serial_println!(r" \___ \  |  |  |  | \// __ \|  |    /    /  /_____/ (  <_> )___ \  ");
    serial_println!(r"/____  > |__|  |__|  (____  /__|   /____/            \____/____  > ");
    serial_println!(r"     \/                   \/                                   \/  ");
    //serial_println!();

    serial_println!("");
    serial_println!("=======================================================================================================");
    serial_println!("  strat9-OS kernel v0.1.0 (Bedrock)");
    serial_println!("  Copyright (c) 2025-26 Guillaume Gielly - GPLv3 License");
    serial_println!("");
    //serial_println!("  GNU General Public License as published by the Free Software Foundation, either version 3 of the ");
    //serial_println!("  License, or (at your option) any later version.");
    serial_println!("  This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY, without");
    serial_println!(
        "  even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
    );
    serial_println!("  See the GNU General Public License for more details.");
    serial_println!("=======================================================================================================");

    // Validate arguments
    if args.is_null() {
        serial_println!("[CRIT] No KernelArgs provided. System will hang.");
        loop {
            arch::x86_64::hlt();
        }
    }

    let args = &*args;
    serial_println!("[init] KernelArgs at {:p}", args);

    // =============================================
    // Phase 1b : HHDM offset (must be set before any physical memory access)
    // =============================================
    let hhdm = args.hhdm_offset;
    memory::set_hhdm_offset(hhdm);
    serial_println!("[init] HHDM offset: 0x{:x}", hhdm);

    serial_println!(
        "[init] Memory map: 0x{:x} ({} bytes)",
        args.memory_map_base,
        args.memory_map_size
    );

    log_boot_module_magics("pre-mm");

    // =============================================
    // Phase 2 : memory management (Buddy Allocator)
    // =============================================
    serial_println!("[init] Memory manager...");
    let mmap_ptr = args.memory_map_base as *const boot::entry::MemoryRegion;
    let mmap_len =
        args.memory_map_size as usize / core::mem::size_of::<boot::entry::MemoryRegion>();
    let mmap = core::slice::from_raw_parts(mmap_ptr, mmap_len);
    let mut mmap_work = [null_region(); MAX_BOOT_MMAP_REGIONS_WORK];
    let mut mmap_work_len = core::cmp::min(mmap.len(), mmap_work.len());
    for (dst, src) in mmap_work
        .iter_mut()
        .zip(mmap.iter())
        .take(mmap_work_len)
    {
        *dst = *src;
    }

    let reserve_modules = [
        ("test_pid", if args.initfs_base != 0 && args.initfs_size != 0 { Some((args.initfs_base, args.initfs_size)) } else { None }),
        ("test_syscalls", crate::boot::limine::test_syscalls_module()),
        ("test_mem", crate::boot::limine::test_mem_module()),
        (
            "test_mem_stressed",
            crate::boot::limine::test_mem_stressed_module(),
        ),
        ("fs-ext4", crate::boot::limine::fs_ext4_module()),
        (
            "strate-fs-ramfs",
            crate::boot::limine::strate_fs_ramfs_module(),
        ),
        ("init", crate::boot::limine::init_module()),
        ("console-admin", crate::boot::limine::console_admin_module()),
        ("strate-net", crate::boot::limine::strate_net_module()),
        ("bin/dhcp-client", crate::boot::limine::dhcp_client_module()),
        ("bin/ping", crate::boot::limine::ping_module()),
        ("bin/telnetd", crate::boot::limine::telnetd_module()),
    ];

    for (name, module) in reserve_modules {
        let Some((base, size)) = module else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let phys = virt_or_phys_to_phys(base, hhdm);
        let reserve_start = align_down(phys, PAGE_SIZE);
        let reserve_end = align_up(phys.saturating_add(size), PAGE_SIZE);
        reserve_range_in_map(
            &mut mmap_work,
            &mut mmap_work_len,
            reserve_start,
            reserve_end,
        );
        #[cfg(feature = "selftest")]
        {
            serial_println!(
                "[init] Reserved module pages: {} phys=0x{:x}..0x{:x}",
                name,
                reserve_start,
                reserve_end
            );
            let kind = region_kind_for_addr(&mmap_work, mmap_work_len, reserve_start);
            serial_println!(
                "[init] Module map kind: {} @0x{:x} => {:?}",
                name,
                reserve_start,
                kind
            );
        }
    }

    memory::buddy::init_buddy_allocator(&mmap_work[..mmap_work_len]);
    serial_println!("[init] Buddy allocator ready.");
    log_boot_module_magics("post-buddy");

    // =============================================
    // Phase 3: console output (VGA or serial fallback)
    // =============================================
    serial_println!("[init] Console...");
    arch::x86_64::vga::init(
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
    vga_println!("[OK] Serial port initialized");
    vga_println!("[OK] Memory manager active");

    // =============================================
    // Phase 4a : TSS (Task State Segment)
    // =============================================
    serial_println!("[init] TSS...");
    vga_println!("[..] Initializing TSS...");
    arch::x86_64::tss::init();
    serial_println!("[init] TSS initialized.");
    vga_println!("[OK] TSS initialized");

    // =============================================
    // Phase 4b : GDT (global Descriptor Table)
    // =============================================
    serial_println!("[init] GDT...");
    vga_println!("[..] Initializing GDT...");
    arch::x86_64::gdt::init();
    serial_println!("[init] GDT initialized.");
    vga_println!("[OK] GDT loaded (with TSS)");

    // =============================================
    // Phase 4c: SYSCALL/SYSRET MSR configuration
    // =============================================
    serial_println!("[init] SYSCALL/SYSRET...");
    vga_println!("[..] Initializing SYSCALL/SYSRET...");
    arch::x86_64::syscall::init();
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
    // Phase 5: IDT (Interrupt Descriptor Table)
    // =============================================
    serial_println!("[init] IDT...");
    vga_println!("[..] Initializing IDT...");
    arch::x86_64::idt::init();
    serial_println!("[init] IDT initialized.");
    vga_println!("[OK] IDT loaded");

    // =============================================
    // Phase 5b: paging / VMM
    // =============================================
    serial_println!("[init] Paging...");
    vga_println!("[..] Initializing page mapper...");
    memory::paging::init(hhdm);
    // Framebuffer is often backed by MMIO memory outside RAM (e.g. around 0xFDxxxxxx),
    // so explicitly map its full range in HHDM for all later graphics access.
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
    vga_println!("[OK] Paging initialized");
    log_boot_module_magics("post-paging");

    // =============================================
    // Phase 5c: kernel address space
    // =============================================
    serial_println!("[init] Kernel address space...");
    vga_println!("[..] Initializing kernel address space...");
    memory::address_space::init_kernel_address_space();
    serial_println!("[init] Kernel address space initialized.");
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
    register_boot_initfs_modules(args.initfs_base, args.initfs_size);
    #[cfg(feature = "selftest")]
    serial_println!("[init] Initializing COW metadata...");
    memory::init_cow_subsystem(&mmap_work[..mmap_work_len]);
    #[cfg(feature = "selftest")]
    serial_println!("[init] COW metadata initialized.");
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
        arch::x86_64::pic::init(
            arch::x86_64::pic::PIC1_OFFSET,
            arch::x86_64::pic::PIC2_OFFSET,
        );
        arch::x86_64::pic::disable();
        arch::x86_64::pic::enable_irq(0); // Timer
        arch::x86_64::pic::enable_irq(1); // Keyboard
        serial_println!("[init] Legacy PIC initialized.");
        vga_println!("[OK] Legacy PIC initialized (IRQ0: timer, IRQ1: keyboard)");
    } else {
        serial_println!("[init] APIC subsystem initialized.");
        vga_println!("[OK] APIC + I/O APIC + APIC timer active");
    }

    // Initialize TLB shootdown system (SMP safety for COW operations).
    if apic_active {
        arch::x86_64::tlb::init();
        serial_println!("[init] TLB shootdown system initialized.");
    }

    // ================================================
    // Phase 6j: SMP bring-up (AP boot) + per-CPU data
    // ================================================
    if apic_active {
        let bsp_apic_id = arch::x86_64::apic::lapic_id();
        arch::x86_64::percpu::init_boot_cpu(bsp_apic_id);
        arch::x86_64::percpu::init_gs_base(0);
        serial_println!("[init] SMP: booting secondary cores...");
        vga_println!("[..] SMP: starting APs...");
        match arch::x86_64::smp::init() {
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
        arch::x86_64::percpu::init_boot_cpu(0);
    }

    // =============================================
    // Phase 6k: PS/2 mouse driver
    // =============================================
    if apic_active {
        let mouse_ok = arch::x86_64::mouse::init();
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
    serial_println!("[init] Initializing scheduler...");
    vga_println!("[..] Setting up multitasking...");
    process::init_scheduler();
    serial_println!("[init] Scheduler initialized.");
    vga_println!("[OK] Multitasking enabled");

    // =============================================
    // Phase 7b: component system - Kthread stage
    // =============================================
    serial_println!("[init] Components (kthread)...");
    vga_println!("[..] Initializing kthread components...");
    if let Err(e) = component::init_all(component::InitStage::Kthread) {
        serial_println!("[WARN] Some kthread components failed: {:?}", e);
    }
    serial_println!("[init] Kthread components initialized.");
    vga_println!("[OK] Kthread components ready");

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

        serial_println!("[init] Components (process)...");
        vga_println!("[..] Initializing process components...");
        if let Err(e) = component::init_all(component::InitStage::Process) {
            serial_println!("[WARN] Some process components failed: {:?}", e);
        }
        serial_println!("[init] Process components initialized.");
        vga_println!("[OK] Process components ready");

        // =============================================
        // Phase 8d: VirtIO + hardware drivers
        // =============================================
        serial_println!("[init] Loading hardware drivers...");
        vga_println!("[..] Initializing hardware drivers...");
        hardware::init();

        serial_println!("[init] Initializing timers...");
        vga_println!("[..] Initializing HPET and RTC...");
        hardware::timer::init();
        serial_println!("[init] Timers initialized.");
        vga_println!("[OK] HPET/RTC initialized");

        serial_println!("[init] Initializing USB...");
        vga_println!("[..] Looking for USB controllers...");
        hardware::usb::init();
        serial_println!("[init] USB initialized.");
        vga_println!("[OK] USB xHCI/EHCI/UHCI initialized");

        serial_println!("[init] Initializing VirtIO block...");
        vga_println!("[..] Looking for VirtIO block device...");
        hardware::storage::virtio_block::init();
        serial_println!("[init] VirtIO block initialized.");
        vga_println!("[OK] VirtIO block driver initialized");

        serial_println!("[init] Initializing AHCI...");
        vga_println!("[..] Looking for AHCI SATA controller...");
        hardware::storage::ahci::init();
        serial_println!("[init] AHCI probe done.");
        vga_println!("[OK] AHCI probe done");

        serial_println!("[init] Initializing ATA/IDE...");
        vga_println!("[..] Looking for ATA/IDE devices...");
        hardware::storage::ata_legacy::init();
        serial_println!("[init] ATA/IDE probe done.");
        vga_println!("[OK] ATA/IDE probe done");

        serial_println!("[init] Initializing NVMe...");
        vga_println!("[..] Looking for NVMe controllers...");
        hardware::storage::nvme::init();
        serial_println!("[init] NVMe probe done.");
        vga_println!("[OK] NVMe probe done");

        serial_println!("[init] Initializing VirtIO net...");
        vga_println!("[..] Looking for VirtIO net device...");
        hardware::nic::virtio_net::init();
        serial_println!("[init] VirtIO net initialized.");
        vga_println!("[OK] VirtIO net driver initialized");

        serial_println!("[init] Initializing VirtIO RNG...");
        vga_println!("[..] Looking for VirtIO RNG device...");
        crate::hardware::virtio::rng::init();
        serial_println!("[init] VirtIO RNG initialized.");
        vga_println!("[OK] VirtIO RNG driver initialized");

        serial_println!("[init] Initializing VirtIO Console...");
        vga_println!("[..] Looking for VirtIO Console device...");
        crate::hardware::virtio::console::init();
        serial_println!("[init] VirtIO Console initialized.");
        vga_println!("[OK] VirtIO Console driver initialized");

        // VirtIO GPU + framebuffer are initialized in hardware::init()

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
            use hardware::storage::ahci::BlockDevice;
            serial_println!(
                "[INFO] AHCI SATA device found. Capacity: {} sectors ({} MiB)",
                ahci.sector_count(),
                (ahci.sector_count() * 512) / (1024 * 1024),
            );
            vga_println!("[OK] AHCI SATA driver loaded");
        } else {
            serial_println!("[INFO] No AHCI SATA device found");
        }

        if let Some(nvme) = hardware::storage::nvme::get_first_controller() {
            if let Some(ns) = nvme.get_namespace(0) {
                serial_println!(
                    "[INFO] NVMe device found. Namespace {} - {} blocks @ {} bytes ({} MiB)",
                    ns.nsid,
                    ns.size,
                    ns.block_size,
                    (ns.size * ns.block_size as u64) / (1024 * 1024),
                );
                vga_println!("[OK] NVMe driver loaded");
            }
        } else {
            serial_println!("[INFO] No NVMe device found");
        }

        // Report all registered network interfaces (E1000 + VirtIO)
        {
            use hardware::nic::NetworkDevice;
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

        // Launch the init process: prefer /initfs/init, fall back to /initfs/test_pid.
        // The fallback is tried both when the primary module is absent AND when it
        // is present but contains an invalid ELF (corrupt / wrong arch).
        let mut init_loaded = false;

        if let Some((base, size)) = crate::boot::limine::init_module() {
            let elf_data = boot_module_slice(base, size);
            match process::elf::load_and_run_elf(elf_data, "init") {
                Ok(task_id) => {
                    init_task_id = Some(task_id);
                    init_loaded = true;
                    serial_println!("[init] ELF '/initfs/init' loaded as task 'init'.");
                }
                Err(e) => {
                    serial_println!("[init] Failed to load init ELF: {}; trying fallback.", e);
                }
            }
        }

        if !init_loaded && args.initfs_base != 0 && args.initfs_size != 0 {
            let elf_data = boot_module_slice(args.initfs_base, args.initfs_size);
            match process::elf::load_and_run_elf(elf_data, "init") {
                Ok(task_id) => {
                    init_task_id = Some(task_id);
                    serial_println!(
                        "[init] ELF '/initfs/test_pid' loaded as task 'init' (fallback)."
                    );
                }
                Err(e) => {
                    serial_println!("[init] Failed to load test_pid ELF: {}", e);
                }
            }
        }
        if let Some((base, size)) = crate::boot::limine::strate_fs_ramfs_module() {
            let ram_data = boot_module_slice(base, size);
            match process::elf::load_and_run_elf(ram_data, "strate-fs-ramfs") {
                Ok(task_id) => {
                    let _ = crate::silo::register_boot_strate_task(task_id, "ramfs-default");
                    serial_println!("[init] Component 'strate-fs-ramfs' loaded.");
                }
                Err(e) => serial_println!("[init] Failed to load strate-fs-ramfs component: {}", e),
            }
        }
        if let Some((base, size)) = crate::boot::limine::fs_ext4_module() {
            let ext4_data = boot_module_slice(base, size);
            match process::elf::load_and_run_elf(ext4_data, "strate-fs-ext4") {
                Ok(task_id) => {
                    let _ = crate::silo::register_boot_strate_task(task_id, "ext4-default");
                    serial_println!("[init] Component 'strate-fs-ext4' loaded.");
                }
                Err(e) => serial_println!("[init] Failed to load strate-fs-ext4 component: {}", e),
            }
        }
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

        match process::Task::new_kernel_task(
            shell::shell_main,
            "chevron-shell",
            process::TaskPriority::Normal,
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
            arch::x86_64::vga::status_line_task_main,
            "status-line",
            process::TaskPriority::Low,
            64 * 1024,
        ) {
            process::add_task(status_task);
        }
    }
    #[cfg(feature = "selftest")]
    {
        serial_println!("[init] Selftest mode: skipping process services and virtio drivers");
    }

    // Initialize keyboard layout to French by default
    crate::arch::x86_64::keyboard_layout::set_french_layout();

    // =============================================
    // Boot complete — start preemptive multitasking
    // =============================================
    serial_println!("[init] Enabling interrupts...");
    vga_println!("[..] Enabling interrupts...");
    arch::x86_64::sti();
    serial_println!("[init] Interrupts enabled.");
    vga_println!("[OK] Interrupts enabled");
    serial_println!("[init] Boot complete. Starting preemptive scheduler...");
    vga_println!("[OK] Starting multitasking (preemptive)");

    // Diagnostic: verify RFLAGS.IF is set
    let rflags: u64;
    unsafe { core::arch::asm!("pushfq; pop {}", out(reg) rflags) };
    serial_println!("[init] RFLAGS={:#018x} IF={}", rflags, (rflags >> 9) & 1);

    // Start the scheduler - this will never return
    process::schedule();
}

/// Initialize the APIC subsystem (Local APIC + I/O APIC + APIC Timer).
///
/// Returns `true` if APIC is active, `false` if we should fall back to PIC+PIT.
/// On failure at any step, logs a warning and returns `false`.
fn init_apic_subsystem(rsdp_vaddr: u64) -> bool {
    use arch::x86_64::{apic, ioapic, pic, timer};
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

    // Step 6d: initialize Local APIC
    // Ensure Local APIC MMIO is mapped
    memory::paging::ensure_identity_map(madt_info.local_apic_address as u64);
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

    // Step 6f: remap PIC to 0x20+ then disable permanently
    // Must remap first to avoid stray interrupts at exception vectors (0-31)
    pic::init(pic::PIC1_OFFSET, pic::PIC2_OFFSET);
    pic::disable_permanently();
    serial_println!("[init]   6f. Legacy PIC remapped and disabled");

    // Step 6g: route IRQ0 (timer) and IRQ1 (keyboard) via I/O APIC
    let lapic_id = apic::lapic_id();
    ioapic::route_legacy_irq(0, lapic_id, 0x20, &madt_info.overrides);
    ioapic::route_legacy_irq(1, lapic_id, 0x21, &madt_info.overrides);
    ioapic::route_legacy_irq(12, lapic_id, 0x2C, &madt_info.overrides);
    serial_println!("[init]   6g. IRQ0->vec 0x20, IRQ1->vec 0x21, IRQ12->vec 0x2C routed");

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

        // Step 6i: start APIC timer in periodic mode
        timer::start_apic_timer(ticks_per_10ms);
        serial_println!("[init]   6i. APIC timer started ({}Hz)", TIMER_HZ);

        // Step 6i+: quench legacy PIT to prevent phantom timer interrupts.
        // The Limine bootloader leaves PIT channel 0 running (~100Hz).
        // Even though legacy_timer_handler guards against double-counting,
        // masking the source eliminates wasted interrupt cycles entirely.
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
