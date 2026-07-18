//! U-Boot boot protocol entry point.
//!
//! This module handles the kernel entry from the U-Boot bootloader.
//! U-Boot loads the kernel ELF and passes a Device Tree Blob (DTB) address.
//!
//! # Boot flow
//!
//! ```text
//! boot64.S (_start)
//!   → save DTB, setup 8 KB bootstrap stack, clear BSS
//!   → call kmain(dtb_ptr)
//!     → enable SSE/OSXSAVE (CPU features)
//!     → early serial output
//!     → parse DTB → build KernelArgs
//!     → call crate::kernel_main(args)
//!       → (buddy allocator init)
//!       → allocate 256 KB kernel stack
//!       → switch_stack(new_stack, continue_init)
//! ```

use crate::boot::fdt;
use crate::serial_println;

/// Size of the real kernel stack allocated after buddy allocator init.
pub const KERNEL_STACK_SIZE: usize = 256 * 1024;

/// Saved kernel ELF base address and size for symbol resolution during panic.
static mut KERNEL_ELF_BASE: u64 = 0;
static mut KERNEL_ELF_SIZE: u64 = 0;

/// Get the kernel ELF bytes as a slice. Returns None if not yet initialized.
pub fn kernel_elf_bytes() -> Option<&'static [u8]> {
    let base = unsafe { KERNEL_ELF_BASE };
    let size = unsafe { KERNEL_ELF_SIZE } as usize;
    if base == 0 || size == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(base as *const u8, size) })
}

/// Enable SSE and OSXSAVE in CR0/CR4.
///
/// Called as early as possible in Rust, before any FPU/SIMD code runs.
/// Moved out of boot64.S for audibility and testability.
#[inline(always)]
unsafe fn enable_cpu_features() {
    // CR4: set OSFXSR (9) + OSXMMEXCPT (10) + OSXSAVE (18)
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4);
    cr4 |= 0x40600;
    core::arch::asm!("mov cr4, {}", in(reg) cr4);

    // CR0: clear EM (2), set MP (1)
    let mut cr0: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0);
    cr0 &= !4;
    cr0 |= 2;
    core::arch::asm!("mov cr0, {}", in(reg) cr0);
}

/// Kernel entry point called by U-Boot or PVH boot.
///
/// For U-Boot: rdi = DTB physical address
/// For PVH: rdi = 0 (no DTB provided)
///
/// Runs on the 8 KB bootstrap stack from boot64.S. All heavy work
/// (DTB parsing, KernelArgs construction) happens here. The real kernel
/// init and stack switch happen in `crate::kernel_main` after the buddy
/// allocator is ready.
#[no_mangle]
#[allow(static_mut_refs)]
pub unsafe extern "C" fn kmain(dtb_ptr: u64) -> ! {
    // Step 1: Enable CPU features (SSE/OSXSAVE) — no asm magic, auditable.
    enable_cpu_features();

    // Step 2: Very early serial output
    {
        let mut early_port = uart_16550::SerialPort::new(0x3F8);
        early_port.init();
        let _ = core::fmt::Write::write_str(
            &mut early_port,
            "[kmain] *** Strat9-OS kernel entry ***\r\n",
        );
    }

    // Step 3: Parse DTB and build KernelArgs (runs on bootstrap stack)
    let args = if dtb_ptr == 0 {
        serial_println!("[kmain] PVH boot (no DTB)");
        build_minimal_args()
    } else {
        serial_println!("[kmain] U-Boot/DTB boot (dtb={:#x})", dtb_ptr);
        fdt::build_kernel_args_from_dtb(dtb_ptr)
    };

    if args.magic != strat9_abi::boot::STRAT9_BOOT_MAGIC {
        serial_println!(
            "[kmain] ERROR: Bad KernelArgs magic: 0x{:08x}",
            args.magic
        );
        hlt_loop();
    }

    serial_println!(
        "[kmain] KernelArgs: memory_map={:#x}/{:#x} fb={:#x} rsdp={:#x}",
        args.memory_map_base,
        args.memory_map_size,
        args.framebuffer_addr,
        args.acpi_rsdp_base,
    );

    // Step 4: Hand off to kernel_main (still on bootstrap stack).
    // kernel_main will allocate a real stack after buddy allocator init.
    crate::kernel_main(&args as *const _);
}

/// Halt the CPU forever.
#[inline(always)]
fn hlt_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Build minimal KernelArgs for PVH boot (no DTB).
fn build_minimal_args() -> super::entry::KernelArgs {
    super::entry::KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: 0,
        kernel_size: 0,
        stack_base: 0x80000,
        stack_size: 0x10000,
        env_base: 0,
        env_size: 0,
        acpi_rsdp_base: 0,
        acpi_rsdp_size: 0,
        memory_map_base: 0,
        memory_map_size: 0,
        initfs_base: 0,
        initfs_size: 0,
        framebuffer_addr: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_stride: 0,
        framebuffer_bpp: 0,
        framebuffer_red_mask_size: 8,
        framebuffer_red_mask_shift: 16,
        framebuffer_green_mask_size: 8,
        framebuffer_green_mask_shift: 8,
        framebuffer_blue_mask_size: 8,
        framebuffer_blue_mask_shift: 0,
        _padding1: [0; 4],
        hhdm_offset: 0,
        cmdline_ptr: 0,
        cmdline_len: 0,
    }
}
