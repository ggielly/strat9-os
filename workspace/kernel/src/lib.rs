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
pub mod entry;
pub mod hardware;
pub mod ipc;
pub mod logger;
pub mod memory;
pub mod namespace;
pub mod panic;
pub mod process;
pub mod shell;
pub mod silo;
pub mod sync;
pub mod syscall;
pub mod trace;
pub mod vfs;

// Limine entry point module
pub mod limine_entry;

// Re-export limine_entry::kmain as the main entry point
pub use limine_entry::kmain;

// serial_print! and serial_println! macros are #[macro_export]'ed
// from arch::x86_64::serial and available at crate root automatically.

/// Initialize serial output
pub fn init_serial() {
    arch::x86_64::serial::init();
}

/// Initialize the logger (uses serial)
pub fn init_logger() {
    logger::init();
}

/// Initialize kernel components using the component system
///
/// This function initializes all kernel components in the correct order
/// based on their dependencies and priorities.
pub fn init_components(stage: component::InitStage) -> Result<(), component::ComponentInitError> {
    component::init_all(stage)
}

use core::panic::PanicInfo;

/// Kernel panic handler
#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    panic::panic_handler(info)
}

/// Main kernel initialization - called by bootloader entry points
pub unsafe fn kernel_main(args: *const entry::KernelArgs) -> ! {
    use core::fmt::Write;

    // =============================================
    // Phase 1: serial output (earliest debug output)
    // =============================================
    init_serial();
    init_logger();

    // Puts default panic hooks early to ensure
    //we get useful info on any panics during init.
    panic::install_default_panic_hooks();

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
    serial_println!("  Copyright (c) 2026 Guillaume Gielly - GPLv3 License");
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

    // =============================================
    // Phase 2 : memory management (Buddy Allocator)
    // =============================================
    serial_println!("[init] Memory manager...");
    let mmap_ptr = args.memory_map_base as *const entry::MemoryRegion;
    let mmap_len = args.memory_map_size as usize / core::mem::size_of::<entry::MemoryRegion>();
    let mmap = core::slice::from_raw_parts(mmap_ptr, mmap_len);

    memory::init_memory_manager(mmap);
    serial_println!("[init] Buddy allocator ready.");

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

    // =============================================
    // Phase 5c: kernel address space
    // =============================================
    serial_println!("[init] Kernel address space...");
    vga_println!("[..] Initializing kernel address space...");
    memory::address_space::init_kernel_address_space();
    serial_println!("[init] Kernel address space initialized.");
    vga_println!("[OK] Kernel address space initialized");

    // =============================================
    // Phase 5d: virtual file system
    // =============================================
    serial_println!("[init] VFS...");
    vga_println!("[..] Initializing virtual file system...");
    vfs::init();
    serial_println!("[init] VFS initialized.");
    vga_println!("[OK] VFS initialized");

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
        // Phase 8c: register modules in VFS
        // =============================================
        let mut init_task_id: Option<crate::process::TaskId> = None;
        if args.initfs_base != 0 && args.initfs_size != 0 {
            let elf_data = unsafe {
                core::slice::from_raw_parts(
                    args.initfs_base as *const u8,
                    args.initfs_size as usize,
                )
            };
            if let Err(e) = vfs::register_initfs_file("test_pid", elf_data.as_ptr(), elf_data.len())
            {
                serial_println!("[init] Failed to register /initfs/test_pid: {:?}", e);
            }
        }
        if let Some((base, size)) = crate::limine_entry::test_mem_module() {
            if base != 0 && size != 0 {
                let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
                if let Err(e) = vfs::register_initfs_file("test_mem", data.as_ptr(), data.len()) {
                    serial_println!("[init] Failed to register /initfs/test_mem: {:?}", e);
                } else {
                    serial_println!("[init] Registered /initfs/test_mem ({} bytes)", size);
                }
            }
        }
        if let Some((base, size)) = crate::limine_entry::test_mem_stressed_module() {
            if base != 0 && size != 0 {
                let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
                if let Err(e) =
                    vfs::register_initfs_file("test_mem_stressed", data.as_ptr(), data.len())
                {
                    serial_println!(
                        "[init] Failed to register /initfs/test_mem_stressed: {:?}",
                        e
                    );
                } else {
                    serial_println!(
                        "[init] Registered /initfs/test_mem_stressed ({} bytes)",
                        size
                    );
                }
            }
        }
        if let Some((base, size)) = crate::limine_entry::fs_ext4_module() {
            if base != 0 && size != 0 {
                let ext4_data =
                    unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
                if let Err(e) =
                    vfs::register_initfs_file("fs-ext4", ext4_data.as_ptr(), ext4_data.len())
                {
                    serial_println!("[init] Failed to register /initfs/fs-ext4: {:?}", e);
                } else {
                    serial_println!("[init] Registered /initfs/fs-ext4 ({} bytes)", size);
                }
            }
        }
        if let Some((base, size)) = crate::limine_entry::strate_fs_ramfs_module() {
            if base != 0 && size != 0 {
                let ram_data =
                    unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
                if let Err(e) =
                    vfs::register_initfs_file("strate-fs-ramfs", ram_data.as_ptr(), ram_data.len())
                {
                    serial_println!("[init] Failed to register /initfs/strate-fs-ramfs: {:?}", e);
                } else {
                    serial_println!("[init] Registered /initfs/strate-fs-ramfs ({} bytes)", size);
                }
            }
        }
        if let Some((base, size)) = crate::limine_entry::init_module() {
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            if let Err(e) = vfs::register_initfs_file("init", data.as_ptr(), data.len()) {
                serial_println!("[init] Failed to register /initfs/init: {:?}", e);
            } else {
                serial_println!("[init] Registered /initfs/init ({} bytes)", size);
            }
        }
        if let Some((base, size)) = crate::limine_entry::console_admin_module() {
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            if let Err(e) = vfs::register_initfs_file("console-admin", data.as_ptr(), data.len()) {
                serial_println!("[init] Failed to register /initfs/console-admin: {:?}", e);
            } else {
                serial_println!("[init] Registered /initfs/console-admin ({} bytes)", size);
            }
        }
        if let Some((base, size)) = crate::limine_entry::strate_net_module() {
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            if let Err(e) = vfs::register_initfs_file("strate-net", data.as_ptr(), data.len()) {
                serial_println!("[init] Failed to register /initfs/strate-net: {:?}", e);
            } else {
                serial_println!("[init] Registered /initfs/strate-net ({} bytes)", size);
            }
        }
        if let Some((base, size)) = crate::limine_entry::dhcpd_module() {
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            if let Err(e) = vfs::register_initfs_file("bin/dhcpd", data.as_ptr(), data.len()) {
                serial_println!("[init] Failed to register /initfs/bin/dhcpd: {:?}", e);
            } else {
                serial_println!("[init] Registered /initfs/bin/dhcpd ({} bytes)", size);
            }
        }
        if let Some((base, size)) = crate::limine_entry::ping_module() {
            let data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            if let Err(e) = vfs::register_initfs_file("bin/ping", data.as_ptr(), data.len()) {
                serial_println!("[init] Failed to register /initfs/bin/ping: {:?}", e);
            } else {
                serial_println!("[init] Registered /initfs/bin/ping ({} bytes)", size);
            }
        }

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

        serial_println!("[init] Initializing VirtIO block...");
        vga_println!("[..] Looking for VirtIO block device...");
        hardware::storage::virtio_block::init();
        serial_println!("[init] VirtIO block initialized.");
        vga_println!("[OK] VirtIO block driver initialized");

        serial_println!("[init] Initializing VirtIO net...");
        vga_println!("[..] Looking for VirtIO net device...");
        hardware::nic::virtio_net::init();
        serial_println!("[init] VirtIO net initialized.");
        vga_println!("[OK] VirtIO net driver initialized");

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

        if let Some((base, size)) = crate::limine_entry::init_module() {
            let elf_data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
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
            let elf_data = unsafe {
                core::slice::from_raw_parts(
                    args.initfs_base as *const u8,
                    args.initfs_size as usize,
                )
            };
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
        if let Some((base, size)) = crate::limine_entry::strate_fs_ramfs_module() {
            let ram_data = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
            match process::elf::load_and_run_elf(ram_data, "strate-fs-ramfs") {
                Ok(_) => serial_println!("[init] Component 'strate-fs-ramfs' loaded."),
                Err(e) => serial_println!("[init] Failed to load strate-fs-ramfs component: {}", e),
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
                unsafe { (&mut *task.capabilities.get()).insert(cap) };
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
    serial_println!("[init]   6g. IRQ0->vec 0x20, IRQ1->vec 0x21 routed");

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
        timer::init_pit(100); // 100Hz = 10ms per tick
        serial_println!("[timer] PIT initialized at 100Hz (10ms interval)");
        serial_println!("[init]   6h. PIT timer initialized (fallback)");

        serial_println!("[timer] ============================= TIMER INIT COMPLETE ============================");
        serial_println!("[timer] Mode: PIT (legacy fallback)");
        serial_println!("[timer] Frequency: 100Hz");
        serial_println!("[timer] Interval: 10ms per tick");
        serial_println!(
            "[timer] =========================================================================="
        );

        // Continue with PIT - don't return false
        // return false;
    } else {
        serial_println!("[init]   6h. APIC timer calibrated successfully");

        // Step 6i: start APIC timer in periodic mode
        timer::start_apic_timer(ticks_per_10ms);
        serial_println!("[init]   6i. APIC timer started (100Hz)");

        // Step 6i+: quench legacy PIT to prevent phantom timer interrupts.
        // The Limine bootloader leaves PIT channel 0 running (~100Hz).
        // Even though legacy_timer_handler guards against double-counting,
        // masking the source eliminates wasted interrupt cycles entirely.
        timer::stop_pit();
        ioapic::mask_legacy_irq(0, &madt_info.overrides);
        serial_println!("[init]   6i+. Legacy PIT stopped and masked in IOAPIC");

        serial_println!("[timer] ============================= TIMER INIT COMPLETE ============================");
        serial_println!("[timer] Mode: APIC (native)");
        serial_println!("[timer] Frequency: 100Hz");
        serial_println!("[timer] Interval: 10ms per tick");
        serial_println!("[timer] Ticks per 10ms: {}", ticks_per_10ms);
        serial_println!(
            "[timer] =========================================================================="
        );
    }

    true
}
