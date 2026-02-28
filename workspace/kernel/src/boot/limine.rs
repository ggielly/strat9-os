//! Limine Boot Protocol entry point
//!
//! This module handles the kernel entry from the Limine bootloader.
//! Limine loads us directly in 64-bit long mode with paging enabled.

use limine::{modules::InternalModule, request::*, BaseRevision};

use crate::serial_println;

/// Sets the base revision to the latest revision supported by the crate.
#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Request the memory map
#[used]
#[link_section = ".requests"]
static MEMORY_MAP: MemoryMapRequest = MemoryMapRequest::new();

/// Request the framebuffer (VGA/graphics)
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();

/// Request the kernel address
#[used]
#[link_section = ".requests"]
static EXECUTABLE_ADDRESS: ExecutableAddressRequest = ExecutableAddressRequest::new();

/// Request the kernel file
#[used]
#[link_section = ".requests"]
static EXECUTABLE_FILE: ExecutableFileRequest = ExecutableFileRequest::new();

/// Request RSDP (ACPI)
#[used]
#[link_section = ".requests"]
static RSDP: RsdpRequest = RsdpRequest::new();

/// Request the HHDM (Higher Half Direct Map)
#[used]
#[link_section = ".requests"]
static HHDM: HhdmRequest = HhdmRequest::new();

/// Request the stack size
#[used]
#[link_section = ".requests"]
static STACK_SIZE: StackSizeRequest = StackSizeRequest::new().with_size(0x10000); // 64KB

/// Internal module: request Limine to load /initfs/test_pid (first userspace PID test binary)
static TEST_PID_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/test_pid");
/// Internal module: request Limine to load /initfs/test_syscalls (verbose syscall test binary)
static TEST_SYSCALLS_MODULE: InternalModule =
    InternalModule::new().with_path(c"/initfs/test_syscalls");
/// Internal module: request Limine to load /initfs/test_mem (userspace memory test binary)
static TEST_MEM_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/test_mem");
/// Internal module: request Limine to load /initfs/test_mem_stressed (userspace stressed memory test)
static TEST_MEM_STRESSED_MODULE: InternalModule =
    InternalModule::new().with_path(c"/initfs/test_mem_stressed");
/// Internal module: request Limine to load /initfs/fs-ext4 (userspace EXT4 server)
static EXT4_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/fs-ext4");
/// Internal module: request Limine to load /initfs/strate-fs-ramfs (userspace RAMFS server)
static RAM_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/strate-fs-ramfs");
/// Internal module: request Limine to load /initfs/init (init process)
static INIT_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/init");
/// Internal module: request Limine to load /initfs/console-admin (admin silo strate)
static CONSOLE_ADMIN_MODULE: InternalModule =
    InternalModule::new().with_path(c"/initfs/console-admin");
/// Internal module: request Limine to load /initfs/strate-net (network silo)
static STRATE_NET_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/strate-net");
/// Internal module: request Limine to load /initfs/bin/dhcp-client (DHCP monitor)
static DHCP_CLIENT_MODULE: InternalModule =
    InternalModule::new().with_path(c"/initfs/bin/dhcp-client");
/// Internal module: request Limine to load /initfs/bin/ping (ICMP utility)
static PING_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/bin/ping");

/// Request modules (files loaded alongside the kernel)
#[used]
#[link_section = ".requests"]
static MODULES: ModuleRequest = ModuleRequest::new().with_internal_modules(&[
    &TEST_PID_MODULE,
    &TEST_SYSCALLS_MODULE,
    &TEST_MEM_MODULE,
    &TEST_MEM_STRESSED_MODULE,
    &EXT4_MODULE,
    &RAM_MODULE,
    &INIT_MODULE,
    &CONSOLE_ADMIN_MODULE,
    &STRATE_NET_MODULE,
    &DHCP_CLIENT_MODULE,
    &PING_MODULE,
]);

/// Optional fs-ext4 module info (set during Limine entry).
static mut FS_EXT4_MODULE: Option<(u64, u64)> = None;
/// Optional test_mem module info (set during Limine entry).
static mut TEST_MEM_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional test_syscalls module info (set during Limine entry).
static mut TEST_SYSCALLS_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional test_mem_stressed module info (set during Limine entry).
static mut TEST_MEM_STRESSED_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional strate-fs-ramfs module info (set during Limine entry).
static mut STRATE_FS_RAMFS_MODULE: Option<(u64, u64)> = None;
/// Optional init module info (set during Limine entry).
static mut INIT_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional console-admin module info (set during Limine entry).
static mut CONSOLE_ADMIN_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional strate-net module info (set during Limine entry).
static mut STRATE_NET_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional dhcp-client module info (set during Limine entry).
static mut DHCP_CLIENT_ELF_MODULE: Option<(u64, u64)> = None;
/// Optional ping module info (set during Limine entry).
static mut PING_ELF_MODULE: Option<(u64, u64)> = None;

const MAX_BOOT_MEMORY_REGIONS: usize = 256;
static mut BOOT_MEMORY_MAP: [super::entry::MemoryRegion; MAX_BOOT_MEMORY_REGIONS] =
    [super::entry::MemoryRegion {
        base: 0,
        size: 0,
        kind: super::entry::MemoryKind::Reserved,
    }; MAX_BOOT_MEMORY_REGIONS];
static mut BOOT_MEMORY_MAP_LEN: usize = 0;

/// Return the fs-ext4 module (addr, size) if present.
pub fn fs_ext4_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { FS_EXT4_MODULE }
}

/// Return the test_mem module (addr, size) if present.
pub fn test_mem_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { TEST_MEM_ELF_MODULE }
}

/// Return the test_syscalls module (addr, size) if present.
pub fn test_syscalls_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { TEST_SYSCALLS_ELF_MODULE }
}

/// Return the test_mem_stressed module (addr, size) if present.
pub fn test_mem_stressed_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { TEST_MEM_STRESSED_ELF_MODULE }
}

/// Return the strate-fs-ramfs module (addr, size) if present.
pub fn strate_fs_ramfs_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { STRATE_FS_RAMFS_MODULE }
}

/// Return the init module (addr, size) if present.
pub fn init_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { INIT_ELF_MODULE }
}

/// Return the console-admin module (addr, size) if present.
pub fn console_admin_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { CONSOLE_ADMIN_ELF_MODULE }
}

/// Return the strate-net module (addr, size) if present.
pub fn strate_net_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { STRATE_NET_ELF_MODULE }
}

/// Return the dhcp-client module (addr, size) if present.
pub fn dhcp_client_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { DHCP_CLIENT_ELF_MODULE }
}

/// Return the ping module (addr, size) if present.
pub fn ping_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { PING_ELF_MODULE }
}

fn path_matches(module_path: &[u8], expected_path: &[u8]) -> bool {
    let expected_no_leading = expected_path.strip_prefix(b"/").unwrap_or(expected_path);
    module_path == expected_path
        || module_path.ends_with(expected_path)
        || module_path == expected_no_leading
        || module_path.ends_with(expected_no_leading)
}

#[inline]
const fn module_addr_to_phys(addr: u64, hhdm_offset: u64) -> u64 {
    if hhdm_offset != 0 && addr >= hhdm_offset {
        addr - hhdm_offset
    } else {
        addr
    }
}

#[derive(Default, Clone, Copy)]
struct ResolvedModules {
    test_pid: Option<(u64, u64)>,
    test_syscalls: Option<(u64, u64)>,
    test_mem: Option<(u64, u64)>,
    test_mem_stressed: Option<(u64, u64)>,
    fs_ext4: Option<(u64, u64)>,
    fs_ram: Option<(u64, u64)>,
    init: Option<(u64, u64)>,
    console_admin: Option<(u64, u64)>,
    strate_net: Option<(u64, u64)>,
    dhcp_client: Option<(u64, u64)>,
    ping: Option<(u64, u64)>,
}

fn resolve_modules_once(modules: &[&limine::file::File], hhdm_offset: u64) -> ResolvedModules {
    let mut resolved = ResolvedModules::default();
    for module in modules {
        let path = module.path().to_bytes();
        let info = (
            module_addr_to_phys(module.addr() as u64, hhdm_offset),
            module.size(),
        );
        if path_matches(path, b"/initfs/test_pid") {
            resolved.test_pid = Some(info);
        } else if path_matches(path, b"/initfs/test_syscalls") {
            resolved.test_syscalls = Some(info);
        } else if path_matches(path, b"/initfs/test_mem") {
            resolved.test_mem = Some(info);
        } else if path_matches(path, b"/initfs/test_mem_stressed") {
            resolved.test_mem_stressed = Some(info);
        } else if path_matches(path, b"/initfs/fs-ext4") {
            resolved.fs_ext4 = Some(info);
        } else if path_matches(path, b"/initfs/strate-fs-ramfs") {
            resolved.fs_ram = Some(info);
        } else if path_matches(path, b"/initfs/init") {
            resolved.init = Some(info);
        } else if path_matches(path, b"/initfs/console-admin") {
            resolved.console_admin = Some(info);
        } else if path_matches(path, b"/initfs/strate-net") {
            resolved.strate_net = Some(info);
        } else if path_matches(path, b"/initfs/bin/dhcp-client") {
            resolved.dhcp_client = Some(info);
        } else if path_matches(path, b"/initfs/bin/ping") {
            resolved.ping = Some(info);
        }
    }
    resolved
}

fn map_limine_region_kind(kind: limine::memory_map::EntryType) -> super::entry::MemoryKind {
    if kind == limine::memory_map::EntryType::USABLE {
        super::entry::MemoryKind::Free
    } else if kind == limine::memory_map::EntryType::ACPI_RECLAIMABLE {
        super::entry::MemoryKind::Reclaim
    } else {
        super::entry::MemoryKind::Reserved
    }
}

/// Define the start and end markers for Limine requests
#[used]
#[link_section = ".requests_start_marker"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Halt the CPU
#[inline(always)]
fn hlt_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Kernel entry point called by Limine
///
/// Limine guarantees:
/// - We're in 64-bit long mode
/// - Paging is enabled with identity mapping + higher half
/// - Interrupts are disabled
/// - Stack is set up
/// - All Limine requests have been answered
#[no_mangle]
pub unsafe extern "C" fn kmain() -> ! {
    // Verify the Limine base revision is supported
    assert!(BASE_REVISION.is_supported());

    // Get memory map
    let _memory_map = match MEMORY_MAP.get_response() {
        Some(resp) => resp,
        None => hlt_loop(),
    };

    // Get framebuffer info (graphics mode provided by Limine)
    let (
        fb_addr,
        fb_width,
        fb_height,
        fb_stride,
        fb_bpp,
        fb_red_mask_size,
        fb_red_mask_shift,
        fb_green_mask_size,
        fb_green_mask_shift,
        fb_blue_mask_size,
        fb_blue_mask_shift,
    ) = if let Some(fb_response) = FRAMEBUFFER.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            (
                fb.addr() as u64,
                fb.width() as u32,
                fb.height() as u32,
                fb.pitch() as u32,
                fb.bpp(),
                fb.red_mask_size(),
                fb.red_mask_shift(),
                fb.green_mask_size(),
                fb.green_mask_shift(),
                fb.blue_mask_size(),
                fb.blue_mask_shift(),
            )
        } else {
            (0, 0, 0, 0, 0, 8, 16, 8, 8, 8, 0)
        }
    } else {
        (0, 0, 0, 0, 0, 8, 16, 8, 8, 8, 0)
    };

    // Get RSDP for ACPI
    let rsdp_addr = RSDP.get_response().map(|r| r.address() as u64).unwrap_or(0);

    // Initialize framebuffer abstraction with Limine-provided buffer
    if fb_addr != 0 && fb_width != 0 && fb_height != 0 {
        let format = crate::hardware::video::framebuffer::PixelFormat {
            red_mask: ((1 << fb_red_mask_size) - 1) << fb_red_mask_shift,
            red_shift: fb_red_mask_shift as u8,
            green_mask: ((1 << fb_green_mask_size) - 1) << fb_green_mask_shift,
            green_shift: fb_green_mask_shift as u8,
            blue_mask: ((1 << fb_blue_mask_size) - 1) << fb_blue_mask_shift,
            blue_shift: fb_blue_mask_shift as u8,
            bits_per_pixel: fb_bpp as u8,
        };

        if let Err(e) = crate::hardware::video::framebuffer::Framebuffer::init_limine(
            fb_addr,
            fb_width,
            fb_height,
            fb_stride,
            format,
        ) {
            serial_println!("[limine] Framebuffer init failed: {}", e);
        }
    }

    // Get HHDM offset — critical for accessing physical memory
    let hhdm_offset = HHDM.get_response().map(|r| r.offset()).unwrap_or(0);

    // Build a kernel-local memory map from Limine entries.
    // Keep only the first MAX_BOOT_MEMORY_REGIONS entries to avoid dynamic allocation.
    let (memory_map_base, memory_map_size) = if let Some(memory_map_response) =
        MEMORY_MAP.get_response()
    {
        let entries = memory_map_response.entries();
        let count = core::cmp::min(entries.len(), MAX_BOOT_MEMORY_REGIONS);
        unsafe {
            BOOT_MEMORY_MAP_LEN = count;
            for (i, entry) in entries.iter().take(count).enumerate() {
                BOOT_MEMORY_MAP[i] = super::entry::MemoryRegion {
                    base: entry.base,
                    size: entry.length,
                    kind: map_limine_region_kind(entry.entry_type),
                };
            }
            (
                BOOT_MEMORY_MAP.as_ptr() as u64,
                (BOOT_MEMORY_MAP_LEN * core::mem::size_of::<super::entry::MemoryRegion>()) as u64,
            )
        }
    } else {
        (0, 0)
    };

    // Resolve loaded modules by exact path, not by index/order.
    // Limine may return modules from config and internal requests in any order.
    let (initfs_base, initfs_size, ext4_base, ext4_size, ram_base, ram_size) =
        if let Some(module_response) = MODULES.get_response() {
            let modules = module_response.modules();
            crate::serial_println!("[limine] modules reported: {}", modules.len());
            for (idx, module) in modules.iter().enumerate() {
                let raw_addr = module.addr() as u64;
                let phys_addr = module_addr_to_phys(raw_addr, hhdm_offset);
                let (m0, m1, m2, m3) = if module.size() >= 4 {
                    unsafe {
                        let p = raw_addr as *const u8;
                        (
                            core::ptr::read_volatile(p),
                            core::ptr::read_volatile(p.add(1)),
                            core::ptr::read_volatile(p.add(2)),
                            core::ptr::read_volatile(p.add(3)),
                        )
                    }
                } else {
                    (0, 0, 0, 0)
                };
                crate::serial_println!(
                    "[limine] module[{}]: path='{}' addr={:#x} phys={:#x} magic={:02x}{:02x}{:02x}{:02x} size={}",
                    idx,
                    module.path().to_string_lossy(),
                    raw_addr,
                    phys_addr,
                    m0,
                    m1,
                    m2,
                    m3,
                    module.size()
                );
            }
            let resolved = resolve_modules_once(modules, hhdm_offset);
            let (init_base, init_size) = resolved.test_pid.unwrap_or((0, 0));
            let (test_syscalls_base, test_syscalls_size) =
                resolved.test_syscalls.unwrap_or((0, 0));
            let (test_mem_base, test_mem_size) = resolved.test_mem.unwrap_or((0, 0));
            let (test_mem_stressed_base, test_mem_stressed_size) =
                resolved.test_mem_stressed.unwrap_or((0, 0));
            let (ext4_base, ext4_size) = resolved.fs_ext4.unwrap_or((0, 0));
            let (ram_base, ram_size) = resolved.fs_ram.unwrap_or((0, 0));

            if test_mem_base != 0 && test_mem_size != 0 {
                unsafe { TEST_MEM_ELF_MODULE = Some((test_mem_base, test_mem_size)) };
                crate::serial_println!(
                    "[limine] /initfs/test_mem found: base={:#x} size={}",
                    test_mem_base,
                    test_mem_size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/test_mem not found in modules");
            }
            if test_syscalls_base != 0 && test_syscalls_size != 0 {
                unsafe { TEST_SYSCALLS_ELF_MODULE = Some((test_syscalls_base, test_syscalls_size)) };
                crate::serial_println!(
                    "[limine] /initfs/test_syscalls found: base={:#x} size={}",
                    test_syscalls_base,
                    test_syscalls_size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/test_syscalls not found in modules");
            }
            if test_mem_stressed_base != 0 && test_mem_stressed_size != 0 {
                unsafe {
                    TEST_MEM_STRESSED_ELF_MODULE =
                        Some((test_mem_stressed_base, test_mem_stressed_size))
                };
                crate::serial_println!(
                    "[limine] /initfs/test_mem_stressed found: base={:#x} size={}",
                    test_mem_stressed_base,
                    test_mem_stressed_size
                );
            } else {
                crate::serial_println!(
                    "[limine] WARN: /initfs/test_mem_stressed not found in modules"
                );
            }

            // New modules: init + console-admin
            if let Some((base, size)) = resolved.init {
                unsafe { INIT_ELF_MODULE = Some((base, size)) };
                crate::serial_println!(
                    "[limine] /initfs/init found: base={:#x} size={}",
                    base,
                    size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/init not found in modules");
            }
            if let Some((base, size)) = resolved.console_admin {
                unsafe { CONSOLE_ADMIN_ELF_MODULE = Some((base, size)) };
                crate::serial_println!(
                    "[limine] /initfs/console-admin found: base={:#x} size={}",
                    base,
                    size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/console-admin not found in modules");
            }
            if let Some((base, size)) = resolved.strate_net {
                unsafe { STRATE_NET_ELF_MODULE = Some((base, size)) };
                crate::serial_println!(
                    "[limine] /initfs/strate-net found: base={:#x} size={}",
                    base,
                    size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/strate-net not found in modules");
            }
            if let Some((base, size)) = resolved.dhcp_client {
                unsafe { DHCP_CLIENT_ELF_MODULE = Some((base, size)) };
                crate::serial_println!(
                    "[limine] /initfs/bin/dhcp-client found: base={:#x} size={}",
                    base,
                    size
                );
            } else {
                crate::serial_println!(
                    "[limine] WARN: /initfs/bin/dhcp-client not found in modules"
                );
            }
            if let Some((base, size)) = resolved.ping {
                unsafe { PING_ELF_MODULE = Some((base, size)) };
                crate::serial_println!(
                    "[limine] /initfs/bin/ping found: base={:#x} size={}",
                    base,
                    size
                );
            } else {
                crate::serial_println!("[limine] WARN: /initfs/bin/ping not found in modules");
            }

            if init_base == 0 {
                crate::serial_println!("[limine] WARN: /initfs/test_pid not found in modules");
            }
            if ext4_base == 0 {
                crate::serial_println!("[limine] WARN: /initfs/fs-ext4 not found in modules");
            }
            if ram_base == 0 {
                crate::serial_println!(
                    "[limine] WARN: /initfs/strate-fs-ramfs not found in modules"
                );
            }
            (
                init_base, init_size, ext4_base, ext4_size, ram_base, ram_size,
            )
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };

    if ext4_base != 0 && ext4_size != 0 {
        // SAFETY: set once during early boot.
        unsafe {
            FS_EXT4_MODULE = Some((ext4_base, ext4_size));
        }
    }

    if ram_base != 0 && ram_size != 0 {
        // SAFETY: set once during early boot.
        unsafe {
            STRATE_FS_RAMFS_MODULE = Some((ram_base, ram_size));
        }
    }

    let args = super::entry::KernelArgs {
        kernel_base: EXECUTABLE_ADDRESS
            .get_response()
            .map(|r| r.physical_base())
            .unwrap_or(0x100000),
        kernel_size: EXECUTABLE_FILE
            .get_response()
            .map(|r| r.file().size())
            .unwrap_or(0),
        stack_base: 0x80000,
        stack_size: 0x10000,
        env_base: 0,
        env_size: 0,
        acpi_rsdp_base: rsdp_addr,
        acpi_rsdp_size: if rsdp_addr != 0 { 36 } else { 0 },
        memory_map_base,
        memory_map_size,
        initfs_base,
        initfs_size,
        framebuffer_addr: fb_addr,
        framebuffer_width: fb_width,
        framebuffer_height: fb_height,
        framebuffer_stride: fb_stride,
        framebuffer_bpp: fb_bpp,
        framebuffer_red_mask_size: fb_red_mask_size,
        framebuffer_red_mask_shift: fb_red_mask_shift,
        framebuffer_green_mask_size: fb_green_mask_size,
        framebuffer_green_mask_shift: fb_green_mask_shift,
        framebuffer_blue_mask_size: fb_blue_mask_size,
        framebuffer_blue_mask_shift: fb_blue_mask_shift,
        hhdm_offset,
    };

    // Call kernel main
    crate::kernel_main(&args as *const _);
}
