//! Boot protocol entry point.
//!
//! This module handles the kernel entry from the bootloader or PVH stub.
//! The bootloader passes a pointer to a [`strat9_abi::boot::KernelArgs`] structure.
//! PVH boot passes null — a minimal KernelArgs is built internally.
//!
//! # Boot flow
//!
//! ```text
//! boot64.S (_start)
//!   => save KernelArgs pointer, setup 64 KB bootstrap stack, clear BSS
//!   => call kmain(args_ptr)
//!     => enable SSE/OSXSAVE (CPU features)
//!     => early serial output
//!     => read KernelArgs from pointer (bootloader) or build_minimal_args (PVH)
//!     => call crate::kernel_main(args)
//!       => (buddy allocator init)
//!       => allocate 256 KB kernel stack
//!       => switch_stack(new_stack, continue_init)
//! ```

use crate::boot::fdt;

/// Very early serial output using raw COM1 port I/O.
/// Safe to call before any kernel subsystem is initialized.
#[inline(always)]
unsafe fn early_print(s: &[u8]) {
    let thr: u16 = 0x3F8;
    let lsr: u16 = 0x3F8 + 5;
    for &b in s {
        loop {
            let status: u8;
            core::arch::asm!("in al, dx", out("al") status, in("dx") lsr, options(nomem, nostack, preserves_flags));
            if status & 0x20 != 0 {
                break;
            }
        }
        core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nomem, nostack, preserves_flags));
    }
}

/// Write a u64 as hex to COM1 (no alloc, no fmt traits).
unsafe fn early_print_hex(mut val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if val == 0 {
        early_print(b"0");
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 16;
    while val > 0 {
        i -= 1;
        buf[i] = HEX[(val & 0xf) as usize];
        val >>= 4;
    }
    early_print(&buf[i..]);
}

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

/// Enable SSE (OSFXSR, OSXMMEXCPT) in CR4.
#[inline(always)]
unsafe fn enable_cpu_features() {
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4);
    cr4 |= 0x600; // OSFXSR (9) | OSXMMEXCPT (10)
    core::arch::asm!("mov cr4, {}", in(reg) cr4);

    let mut cr0: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0);
    cr0 &= !4; // Clear EM (bit 2)
    cr0 |= 2; // Set MP (bit 1)
    core::arch::asm!("mov cr0, {}", in(reg) cr0);
}

/// Kernel entry point called by the bootloader or PVH boot.
///
/// For bootloader: rdi = pointer to [`strat9_abi::boot::KernelArgs`]
/// For PVH: rdi = 0 (no KernelArgs provided; build a minimal set)
///
/// Runs on the 64 KB bootstrap stack from boot64.S. The KernelArgs are
/// read (or built) here. The real kernel init and stack switch happen
/// in `crate::kernel_main` after the buddy allocator is ready.
#[no_mangle]
#[allow(static_mut_refs)]
pub unsafe extern "C" fn kmain(args_ptr: u64) -> ! {
    // Step 1: Very early serial output - before anything else.
    // Just use raw writes without init (bootloader already set up COM1).
    {
        let thr: u16 = 0x3F8;
        let s = b"[kmain] RAW entry\r\n";
        for &b in s {
            let mut lsr: u8;
            core::arch::asm!("in al, dx", in("dx") 0x3F8 + 5, out("al") lsr, options(nostack, preserves_flags));
            loop {
                core::arch::asm!("in al, dx", in("dx") 0x3F8 + 5, out("al") lsr, options(nostack, preserves_flags));
                if lsr & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("dx") thr, in("al") b, options(nostack, preserves_flags));
        }
    }

    // Step 2: Enable CPU features (SSE/OSXSAVE) : no asm magic, auditable.
    enable_cpu_features();

    // Step 3: Serial port with crate
    {
        let mut early_port = uart_16550::SerialPort::new(0x3F8);
        let _ = core::fmt::Write::write_str(
            &mut early_port,
            "[kmain] *** Strat9-OS kernel entry ***\r\n",
        );
    }

    // Step 3: Obtain KernelArgs — either from the bootloader pointer or
    //         build a minimal set for PVH.
    //
    // NOTE: We use raw COM1 port I/O for ALL output here. The global
    // serial_println! and format_args! vtable dispatch may not work
    // before the full kernel is initialized.
    let args = if args_ptr == 0 {
        early_print(b"[kmain] PVH boot (no args)\r\n");
        build_minimal_args()
    } else {
        early_print(b"[kmain] Bootloader boot (args=0x");
        early_print_hex(args_ptr);
        early_print(b")\r\n");
        // Read KernelArgs from the bootloader-provided pointer.
        // The struct is #[repr(C, packed)] so we copy field-by-field.
        let ptr = args_ptr as *const strat9_abi::boot::KernelArgs;
        strat9_abi::boot::KernelArgs {
            magic: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).magic)),
            abi_version: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).abi_version)),
            kernel_base: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).kernel_base)),
            kernel_size: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).kernel_size)),
            acpi_rsdp_base: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).acpi_rsdp_base)),
            memory_map_base: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).memory_map_base)),
            memory_map_size: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).memory_map_size)),
            framebuffer_addr: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_addr
            )),
            hhdm_offset: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).hhdm_offset)),
            cmdline_ptr: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).cmdline_ptr)),
            cmdline_len: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).cmdline_len)),
            modules_base: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).modules_base)),
            modules_size: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).modules_size)),
            framebuffer_width: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_width
            )),
            framebuffer_height: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_height
            )),
            framebuffer_stride: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_stride
            )),
            framebuffer_bpp: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).framebuffer_bpp)),
            framebuffer_red_mask_size: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_red_mask_size
            )),
            framebuffer_red_mask_shift: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_red_mask_shift
            )),
            framebuffer_green_mask_size: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_green_mask_size
            )),
            framebuffer_green_mask_shift: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_green_mask_shift
            )),
            framebuffer_blue_mask_size: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_blue_mask_size
            )),
            framebuffer_blue_mask_shift: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*ptr).framebuffer_blue_mask_shift
            )),
            bss_virt_base: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).bss_virt_base)),
            bss_virt_size: core::ptr::read_unaligned(core::ptr::addr_of!((*ptr).bss_virt_size)),
        }
    };

    if args.magic != strat9_abi::boot::STRAT9_BOOT_MAGIC {
        early_print(b"[kmain] ERROR: Bad KernelArgs magic: 0x");
        early_print_hex(
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.magic)) } as u64,
        );
        early_print(b"\r\n");
        hlt_loop();
    }

    let memory_map_base =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.memory_map_base)) };
    let memory_map_size =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.memory_map_size)) };
    let framebuffer_addr =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.framebuffer_addr)) };
    let acpi_rsdp_base =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(args.acpi_rsdp_base)) };
    early_print(b"[kmain] mmap=0x");
    early_print_hex(memory_map_base);
    early_print(b"/0x");
    early_print_hex(memory_map_size);
    early_print(b" fb=0x");
    early_print_hex(framebuffer_addr);
    early_print(b" rsdp=0x");
    early_print_hex(acpi_rsdp_base);
    early_print(b"\r\n");

    // Step 5: Hand off to kernel_main (still on bootstrap stack).
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
        acpi_rsdp_base: 0,
        memory_map_base: 0,
        memory_map_size: 0,
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
        hhdm_offset: 0,
        cmdline_ptr: 0,
        cmdline_len: 0,
        modules_base: 0,
        modules_size: 0,
        bss_virt_base: 0,
        bss_virt_size: 0,
    }
}
