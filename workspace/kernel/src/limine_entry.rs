//! Limine Boot Protocol entry point
//!
//! This module handles the kernel entry from the Limine bootloader.
//! Limine loads us directly in 64-bit long mode with paging enabled.

use limine::modules::InternalModule;
use limine::request::*;
use limine::BaseRevision;

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

/// Internal module: request Limine to load /initfs/init (the init ELF binary)
static INIT_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/init");
/// Internal module: request Limine to load /initfs/fs-ext4 (userspace EXT4 server)
static EXT4_MODULE: InternalModule = InternalModule::new().with_path(c"/initfs/fs-ext4");

/// Request modules (files loaded alongside the kernel)
#[used]
#[link_section = ".requests"]
static MODULES: ModuleRequest =
    ModuleRequest::new().with_internal_modules(&[&INIT_MODULE, &EXT4_MODULE]);

/// Optional fs-ext4 module info (set during Limine entry).
static mut FS_EXT4_MODULE: Option<(u64, u64)> = None;

/// Return the fs-ext4 module (addr, size) if present.
pub fn fs_ext4_module() -> Option<(u64, u64)> {
    // SAFETY: Written once during early boot, then read-only.
    unsafe { FS_EXT4_MODULE }
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

    // Get framebuffer info (for VGA)
    let fb_addr = if let Some(fb_response) = FRAMEBUFFER.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            fb.addr() as u64
        } else {
            0xB8000 // Fallback to VGA text mode
        }
    } else {
        0xB8000 // Fallback to VGA text mode
    };

    // Get RSDP for ACPI
    let rsdp_addr = RSDP.get_response().map(|r| r.address() as u64).unwrap_or(0);

    // Get HHDM offset — critical for accessing physical memory
    let hhdm_offset = HHDM.get_response().map(|r| r.offset()).unwrap_or(0);

    // Build KernelArgs from Limine data
    // Note: We pass a dummy memory map for now since allocator needs initialization
    // The real Limine memory map will be used once we refactor memory init
    let dummy_mmap = [crate::entry::MemoryRegion {
        base: 0x200000,
        size: 0xFE00000,
        kind: crate::entry::MemoryKind::Free,
    }];

    // Check for loaded modules (init ELF binary + fs-ext4)
    let (initfs_base, initfs_size, ext4_base, ext4_size) =
        if let Some(module_response) = MODULES.get_response() {
        let modules = module_response.modules();
        let (init_base, init_size) = if !modules.is_empty() {
            let module = modules[0];
            (module.addr() as u64, module.size())
        } else {
            (0u64, 0u64)
        };
        let (ext4_base, ext4_size) = if modules.len() > 1 {
            let module = modules[1];
            (module.addr() as u64, module.size())
        } else {
            (0u64, 0u64)
        };
        (init_base, init_size, ext4_base, ext4_size)
    } else {
        (0u64, 0u64, 0u64, 0u64)
    };

    if ext4_base != 0 && ext4_size != 0 {
        // SAFETY: set once during early boot.
        unsafe {
            FS_EXT4_MODULE = Some((ext4_base, ext4_size));
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
        memory_map_base: dummy_mmap.as_ptr() as u64,
        memory_map_size: core::mem::size_of_val(&dummy_mmap) as u64,
        initfs_base,
        initfs_size,
        framebuffer_addr: fb_addr,
        framebuffer_width: 80,
        framebuffer_height: 25,
        framebuffer_stride: 80,
        hhdm_offset,
    };

    // Call kernel main
    crate::kernel_main(&args as *const _);
}
