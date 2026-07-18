//! U-Boot boot protocol entry point.
//!
//! This module handles the kernel entry from the U-Boot bootloader.
//! U-Boot loads the kernel ELF and passes a Device Tree Blob (DTB) address.

use crate::boot::fdt;
use crate::serial_println;

/// Saved kernel ELF base address and size for symbol resolution during panic.
static mut KERNEL_ELF_BASE: u64 = 0;
static mut KERNEL_ELF_SIZE: u64 = 0;

/// Get the kernel ELF bytes as a slice. Returns None if not yet initialized.
///
/// This is used by the panic handler for symbol resolution.
pub fn kernel_elf_bytes() -> Option<&'static [u8]> {
    let base = unsafe { KERNEL_ELF_BASE };
    let size = unsafe { KERNEL_ELF_SIZE } as usize;
    if base == 0 || size == 0 {
        return None;
    }
    // SAFETY: The memory is valid for the duration of the kernel's lifetime.
    // With U-Boot, the kernel is loaded in memory and the ELF is accessible.
    Some(unsafe { core::slice::from_raw_parts(base as *const u8, size) })
}

/// Halt the CPU
#[inline(always)]
fn hlt_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Kernel entry point called by U-Boot.
///
/// Convention: rdi = DTB physical address
///
/// U-Boot guarantees:
/// - We're in 64-bit long mode (x86_64)
/// - Paging is enabled with identity mapping
/// - Interrupts are disabled
/// - Stack is set up
/// - DTB address is passed in rdi
#[no_mangle]
#[allow(static_mut_refs)]
pub unsafe extern "C" fn kmain(dtb_ptr: u64) -> ! {
    // === VERY EARLY SERIAL OUTPUT ===
    {
        let mut early_port = uart_16550::SerialPort::new(0x3F8);
        early_port.init();
        let _ = core::fmt::Write::write_str(
            &mut early_port,
            "[kmain] *** Strat9-OS kernel entry (U-Boot) ***\r\n",
        );
    }

    // Validate DTB pointer
    if dtb_ptr == 0 {
        serial_println!("[kmain] ERROR: No DTB provided. System will hang.");
        hlt_loop();
    }

    serial_println!("[kmain] DTB at {:#x}", dtb_ptr);

    // Parse DTB and build KernelArgs
    let args = fdt::build_kernel_args_from_dtb(dtb_ptr);

    // Validate magic
    if args.magic != strat9_abi::boot::STRAT9_BOOT_MAGIC {
        serial_println!(
            "[kmain] ERROR: Bad KernelArgs magic: 0x{:08x}",
            args.magic
        );
        hlt_loop();
    }

    serial_println!(
        "[kmain] KernelArgs built: memory_map={:#x}/{:#x} fb={:#x} rsdp={:#x}",
        args.memory_map_base,
        args.memory_map_size,
        args.framebuffer_addr,
        args.acpi_rsdp_base,
    );

    // TODO: Phase 4 - Load modules from FAT32 boot partition
    // let block_dev = init_block_device_from_dtb(dtb_ptr);
    // load_modules_from_fat32(&block_dev);

    // TODO: Phase 5 - Apply kernel.toml from FAT32
    // apply_kernel_config_from_fs(&block_dev);

    // Call kernel main
    crate::kernel_main(&args as *const _);
}
