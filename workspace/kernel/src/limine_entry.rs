//! Limine Boot Protocol entry point
//!
//! This module handles the kernel entry from the Limine bootloader.
//! Limine loads us directly in 64-bit long mode with paging enabled.

use limine::{modules::InternalModule, request::*, BaseRevision};

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
static INIT_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/test_pid");
/// Internal module: request Limine to load /initfs/fs-ext4 (userspace EXT4 server)
static EXT4_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/fs-ext4");
/// Internal module: request Limine to load /initfs/strate-fs-ramfs (userspace RAMFS server)
static RAM_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/strate-fs-ramfs");

/// Request modules (files loaded alongside the kernel)
#[used]
#[link_section = ".requests"]
static MODULES: ModuleRequest =
    ModuleRequest::new().with_internal_modules(&[&INIT_MODULE, &EXT4_MODULE, &RAM_MODULE]);

/// Optional fs-ext4 module info (set during Limine entry).
static mut FS_EXT4_MODULE: Option<(u64, u64)> = None;
/// Optional strate-fs-ramfs module info (set during Limine entry).
static mut STRATE_FS_RAMFS_MODULE: Option<(u64, u64)> = None;

const MAX_BOOT_MEMORY_REGIONS: usize = 256;
static mut BOOT_MEMORY_MAP: [crate::entry::MemoryRegion; MAX_BOOT_MEMORY_REGIONS] =
    [crate::entry::MemoryRegion {
        base: 0,
        size: 0,
        kind: crate::entry::MemoryKind::Reserved,
    }; MAX_BOOT_MEMORY_REGIONS];
static mut BOOT_MEMORY_MAP_LEN: usize = 0;

/// Return the fs-ext4 module (addr, size) if present.
pub fn fs_ext4_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { FS_EXT4_MODULE }
}

/// Return the strate-fs-ramfs module (addr, size) if present.
pub fn strate_fs_ramfs_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { STRATE_FS_RAMFS_MODULE }
}

fn find_module_by_path(
    modules: &[&limine::file::File],
    expected_path: &[u8],
) -> Option<(u64, u64)> {
    let expected_no_leading = expected_path.strip_prefix(b"/").unwrap_or(expected_path);
    modules.iter().find_map(|module| {
        let path = module.path().to_bytes();
        if path == expected_path
            || path.ends_with(expected_path)
            || path == expected_no_leading
            || path.ends_with(expected_no_leading)
        {
            Some((module.addr() as u64, module.size()))
        } else {
            None
        }
    })
}

fn map_limine_region_kind(kind: limine::memory_map::EntryType) -> crate::entry::MemoryKind {
    if kind == limine::memory_map::EntryType::USABLE {
        crate::entry::MemoryKind::Free
    } else if kind == limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE
        || kind == limine::memory_map::EntryType::ACPI_RECLAIMABLE
    {
        crate::entry::MemoryKind::Reclaim
    } else {
        crate::entry::MemoryKind::Reserved
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
                BOOT_MEMORY_MAP[i] = crate::entry::MemoryRegion {
                    base: entry.base,
                    size: entry.length,
                    kind: map_limine_region_kind(entry.entry_type),
                };
            }
            (
                BOOT_MEMORY_MAP.as_ptr() as u64,
                (BOOT_MEMORY_MAP_LEN * core::mem::size_of::<crate::entry::MemoryRegion>()) as u64,
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
                crate::serial_println!(
                    "[limine] module[{}]: path='{}' size={}",
                    idx,
                    module.path().to_string_lossy(),
                    module.size()
                );
            }
            let (init_base, init_size) =
                find_module_by_path(modules, b"/initfs/test_pid").unwrap_or((0, 0));
            let (ext4_base, ext4_size) =
                find_module_by_path(modules, b"/initfs/fs-ext4").unwrap_or((0, 0));
            let (ram_base, ram_size) =
                find_module_by_path(modules, b"/initfs/strate-fs-ramfs").unwrap_or((0, 0));
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

    let args = crate::entry::KernelArgs {
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
