#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;

use uefi::{
    mem::memory_map::{MemoryMap, MemoryType},
    prelude::*,
    proto::{
        console::gop::{GraphicsOutput, PixelFormat},
        media::file::{File, FileAttribute, FileInfo, FileMode},
    },
    table::cfg::ConfigTableEntry,
};

mod elf;
mod modules;
mod paging;

use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

/// Maximum allowed kernel ELF file size (64 MiB).
const MAX_ELF_SIZE: usize = 64 * 1024 * 1024;

/// Bytes per pixel for linear framebuffer (BGRA/RGBA).
const BYTES_PER_PIXEL: u64 = 4;

/// COM1 base address and LSR offset for serial I/O.
const COM1_BASE: u16 = 0x3F8;
const COM1_LSR: u16 = COM1_BASE + 5;

/// Write a single byte to COM1, with timeout.
/// Returns false if the port is not ready after ~1 ms.
unsafe fn serial_write_byte(b: u8) -> bool {
    for _ in 0..16000 {
        // ~1 ms at ~16 iterations/µs
        let status: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                out("al") status,
                in("dx") COM1_LSR,
                options(nomem, nostack, preserves_flags)
            );
        }
        if status & 0x20 != 0 {
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("al") b,
                    in("dx") COM1_BASE,
                    options(nomem, nostack, preserves_flags)
                );
            }
            return true;
        }
    }
    false
}

/// Write a byte string to COM1 with timeout per byte.
/// Returns the number of bytes successfully written.
unsafe fn serial_write(msg: &[u8]) -> usize {
    let mut ok = 0;
    for &b in msg {
        if unsafe { serial_write_byte(b) } {
            ok += 1;
        } else {
            break;
        }
    }
    ok
}

/// Initialize COM1 at 115200 baud (divisor 1).
/// Returns true if COM1 appears present (write succeeded).
unsafe fn init_serial_115200() -> bool {
    let base = COM1_BASE;
    unsafe {
        core::arch::asm!("out dx, al", in("al") 0x00u8, in("dx") base + 1, options(nomem, nostack)); // Disable interrupts
        core::arch::asm!("out dx, al", in("al") 0x80u8, in("dx") base + 3, options(nomem, nostack)); // Enable DLAB
        core::arch::asm!("out dx, al", in("al") 0x01u8, in("dx") base + 0, options(nomem, nostack)); // Divisor lo = 1 (115200)
        core::arch::asm!("out dx, al", in("al") 0x00u8, in("dx") base + 1, options(nomem, nostack)); // Divisor hi = 0
        core::arch::asm!("out dx, al", in("al") 0x03u8, in("dx") base + 3, options(nomem, nostack)); // 8N1
        core::arch::asm!("out dx, al", in("al") 0xC7u8, in("dx") base + 2, options(nomem, nostack)); // Enable FIFO
        core::arch::asm!("out dx, al", in("al") 0x0Bu8, in("dx") base + 4, options(nomem, nostack));
        // IRQs, RTS/DSR
    }
    // Probe: try to write; if LSR never readies, COM1 is absent.
    unsafe { serial_write_byte(b'.') }
}

/// Halt forever with interrupts disabled.
fn halt() -> ! {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

/// Halt after a serial error message.
fn halt_msg(com1_present: bool, msg: &[u8]) -> ! {
    if com1_present {
        unsafe {
            serial_write(b"\r\n[FATAL] ");
            serial_write(msg);
            serial_write(b"\r\n");
        }
    }
    halt()
}

#[entry]
fn efi_main() -> Status {
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(
            stdout,
            "Strat9-OS UEFI bootloader. (C) Copyright Guillaume Gielly, 2024-26 - All rights reserved. Version 0.1.0."

        );
    });

    // Open filesystem
    let image_handle = uefi::boot::image_handle();
    let mut fs =
        uefi::boot::get_image_file_system(image_handle).expect("Failed to get file system");
    let mut volume = (*fs).open_volume().expect("Failed to open volume");

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] The filesystem is OK");
    });

    // Read kernel ELF
    let mut file = volume
        .open(
            cstr16!("\\boot\\kernel.elf"),
            FileMode::Read,
            FileAttribute::empty(),
        )
        .expect("Failed to open kernel.elf")
        .into_regular_file()
        .expect("kernel.elf is not a regular file");

    let mut file_info_buf = [0u8; 512];
    let file_info = file
        .get_info::<FileInfo>(&mut file_info_buf)
        .expect("Failed to get file info");
    let file_size = file_info.file_size() as usize;

    if file_size == 0 || file_size > MAX_ELF_SIZE {
        uefi::system::with_stdout(|stdout| {
            let _ = writeln!(stdout, "[boot] kernel.elf: invalid size {}", file_size);
        });
        halt();
    }

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] kernel.elf: {} bytes", file_size);
    });

    // Read kernel into memory with loop (UEFI may return partial reads)
    let mut buf = alloc::vec![0u8; file_size];
    {
        let mut offset = 0;
        while offset < file_size {
            match file.read(&mut buf[offset..]) {
                Ok(0) => break, // EOF
                Ok(n) => offset += n,
                Err(_) => halt(),
            }
        }
        if offset < file_size {
            uefi::system::with_stdout(|stdout| {
                let _ = writeln!(
                    stdout,
                    "[boot] Short read: got {} of {} bytes",
                    offset, file_size
                );
            });
            halt();
        }
    }

    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    // Prevent drop from freeing the buffer; it's accessed via kernel_data.
    core::mem::forget(buf);
    let kernel_data = unsafe { core::slice::from_raw_parts(ptr, len) };

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Kernel loaded OK, parsing ELF...");
    });

    let elf_info = match elf::parse_elf64(kernel_data) {
        Ok(info) => info,
        Err(msg) => {
            uefi::system::with_stdout(|stdout| {
                let _ = writeln!(stdout, "[boot] ELF parse failed: {}", msg);
            });
            halt();
        }
    };

    // The kernel data buffer is no longer needed after parsing.
    // Safety: we forget(buf) earlier so this is just a pointer we no longer use.
    // The memory will be reclaimed after ExitBootServices as Reclaim.
    let _ = unsafe { core::slice::from_raw_parts(ptr, 0) };

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(
            stdout,
            "[boot] ELF: entry=0x{:x}, {} segments, phys_end=0x{:x}",
            elf_info.entry, elf_info.segment_count, elf_info.phys_end
        );
    });

    // Load modules
    let module_list = modules::load_modules(image_handle);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Modules: {}", module_list.len());
    });

    // Get framebuffer via GOP (optional; skip non-linear / BltOnly modes)
    let mut fb_phys: u64 = 0;
    let mut fb_width: u32 = 0;
    let mut fb_height: u32 = 0;
    let mut fb_stride: u32 = 0;
    let fb_bpp: u16 = 32;
    let mut fb_red_size: u8 = 8;
    let mut fb_red_shift: u8 = 16;
    let mut fb_green_size: u8 = 8;
    let mut fb_green_shift: u8 = 8;
    let mut fb_blue_size: u8 = 8;
    let mut fb_blue_shift: u8 = 0;

    'gop: {
        let gop_handle = match uefi::boot::get_handle_for_protocol::<GraphicsOutput>() {
            Ok(h) => h,
            Err(_) => break 'gop,
        };
        let mut gop = match uefi::boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
            Ok(g) => g,
            Err(_) => break 'gop,
        };

        // Find best mode by pixel area
        let mut best_mode = None;
        let mut best_area: usize = 0;
        for mode in gop.modes() {
            let (w, h) = mode.info().resolution();
            let area = w.checked_mul(h).unwrap_or(0);
            if area > best_area {
                best_area = area;
                best_mode = Some(mode);
            }
        }

        if let Some(mode) = best_mode {
            if gop.set_mode(&mode).is_err() {
                break 'gop;
            }
        }

        let info = gop.current_mode_info();
        let (width, height) = info.resolution();
        let stride = info.stride();
        let pixel_format = info.pixel_format();

        let mut fb = gop.frame_buffer();
        let fb_ptr = fb.as_mut_ptr() as u64;

        // BltOnly modes have no linear framebuffer — skip
        if fb_ptr == 0 {
            break 'gop;
        }

        fb_phys = fb_ptr;
        fb_width = width as u32;
        fb_height = height as u32;
        fb_stride = stride as u32;

        let (r_s, r_sh, g_s, g_sh, b_s, b_sh) = match pixel_format {
            PixelFormat::Rgb => (8, 16, 8, 8, 8, 0),
            PixelFormat::Bgr => (8, 0, 8, 8, 8, 16),
            _ => (8, 0, 8, 8, 8, 16),
        };
        fb_red_size = r_s;
        fb_red_shift = r_sh;
        fb_green_size = g_s;
        fb_green_shift = g_sh;
        fb_blue_size = b_s;
        fb_blue_shift = b_sh;
    }

    // Get ACPI RSDP (prefer ACPI2 over ACPI)
    let rsdp_addr = uefi::system::with_config_table(|tables| {
        tables
            .iter()
            .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID)
            .or_else(|| {
                tables
                    .iter()
                    .find(|e| e.guid == ConfigTableEntry::ACPI_GUID)
            })
            .map(|e| e.address as u64)
            .unwrap_or(0)
    });

    // Build environment string
    let mut env_buf = [0u8; 4096];
    let mut env_len: usize = 0;

    fn env_write(buf: &mut [u8], pos: &mut usize, s: &str) {
        let bytes = s.as_bytes();
        let end = (*pos + bytes.len()).min(buf.len() - 1);
        buf[*pos..end].copy_from_slice(&bytes[..end - *pos]);
        *pos = end;
    }

    {
        env_write(
            &mut env_buf,
            &mut env_len,
            "loader=strat9-bootloader-uefi\n",
        );
        env_write(&mut env_buf, &mut env_len, "loader.version=0.1.0\n");

        let mut tmp = [0u8; 32];

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.phys=0x{:x}\n", fb_phys);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.virt=0x{:x}\n", paging::FRAMEBUFFER_BASE);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.width={}\n", fb_width);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.height={}\n", fb_height);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.stride={}\n", fb_stride);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "fb.bpp={}\n", fb_bpp);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "acpi.rsdp=0x{:x}\n", rsdp_addr);
        env_write(&mut env_buf, &mut env_len, w.as_str());

        env_write(&mut env_buf, &mut env_len, "console=ttyS0\n");
        env_write(&mut env_buf, &mut env_len, "console.baud=115200\n");

        let mut w = buf_str(&mut tmp);
        let _ = write!(w, "kernel.entry=0x{:x}\n", elf_info.entry);
        env_write(&mut env_buf, &mut env_len, w.as_str());
    }

    env_buf[env_len] = 0;
    let env_total_size = env_len + 1;

    // =========================================================
    // ExitBootServices
    // =========================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] ExitBootServices...");
    });

    let _mmap = uefi::boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get memory map");
    let mmap_iter = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Disable interrupts immediately after ExitBootServices to prevent
    // firmware timer / IDT triple-fault.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // Re-initialize serial at 115200 baud
    let com1_present = unsafe { init_serial_115200() };
    if com1_present {
        unsafe {
            serial_write(b"[boot] After ExitBootServices, serial OK (115200)\r\n");
        }
    }

    // =========================================================
    // Memory map conversion
    // =========================================================
    let mut regions: [MemoryRegion; 512] = [MemoryRegion {
        base: 0,
        size: 0,
        kind: MemoryKind::Null,
    }; 512];
    let mut region_count: usize = 0;

    for entry in mmap_iter.entries() {
        if region_count >= 512 {
            break;
        }
        let base = entry.phys_start;
        let size = entry.page_count.checked_mul(4096).unwrap_or(0);
        if size == 0 {
            continue;
        }

        let kind = match entry.ty {
            MemoryType::CONVENTIONAL => MemoryKind::Free,
            MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA => MemoryKind::Reclaim,
            MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => MemoryKind::Reclaim,
            _ => MemoryKind::Reserved,
        };

        regions[region_count] = MemoryRegion { base, size, kind };
        region_count += 1;
    }

    if com1_present {
        unsafe {
            serial_write(b"[boot] mmap: ");
            serial_write(decimal_str(region_count as u64));
            serial_write(b" regions\r\n");
            for i in 0..region_count.min(8) {
                let r = regions[i];
                serial_write(b"  [");
                serial_write(decimal_str(i as u64));
                serial_write(b"] base=");
                serial_write(hex8_str(r.base));
                serial_write(b" size=");
                serial_write(hex8_str(r.size));
                serial_write(b" kind=");
                serial_write(decimal_str(r.kind.0 as u64));
                serial_write(b"\r\n");
            }
        }
    }
    // =========================================================
    // Allocate boot resources BEFORE copying the memory map
    // =========================================================
    fn alloc_from_free(
        regions: &mut [MemoryRegion],
        region_count: usize,
        size: u64,
        align: u64,
    ) -> u64 {
        if align == 0 || size == 0 {
            return 0;
        }
        for i in 0..region_count {
            if regions[i].kind == MemoryKind::Free && regions[i].size >= size {
                // Debug output for allocation attempt. Keep it.
                unsafe {
                    serial_write(b"[DEBUG] [alloc] region ");
                    serial_write(decimal_str(i as u64));
                    serial_write(b" base=");
                    serial_write(hex8_str(regions[i].base));
                    serial_write(b" size=");
                    serial_write(hex8_str(regions[i].size));
                    serial_write(b" FREE match\r\n");
                }

                let aligned_base = match regions[i].base.checked_add(align - 1) {
                    Some(v) => v & !(align - 1),
                    None => continue,
                };
                // Address 0 (the zero page / IVT / BDA) must never be handed out
                // as an allocation; skip regions that would align down to 0.
                if aligned_base == 0 {
                    continue;
                }
                let padding = match aligned_base.checked_sub(regions[i].base) {
                    Some(v) => v,
                    None => continue,
                };
                let total = match size.checked_add(padding) {
                    Some(v) => v,
                    None => continue,
                };
                if regions[i].size >= total {
                    regions[i].base = match regions[i].base.checked_add(total) {
                        Some(v) => v,
                        None => continue,
                    };
                    regions[i].size = match regions[i].size.checked_sub(total) {
                        Some(v) => v,
                        None => continue,
                    };
                    return aligned_base;
                }
            }
        }
        0
    }

    // 1. Allocate kernel stack
    let stack_size: u64 = 64 * 1024;
    let stack_base = alloc_from_free(&mut regions, region_count, stack_size, 16);
    if com1_present {
        unsafe {
            serial_write(b"[boot] alloc stack: base=");
            serial_write(hex8_str(stack_base));
            serial_write(b" size=");
            serial_write(hex8_str(stack_size));
            serial_write(b" count=");
            serial_write(decimal_str(region_count as u64));
            serial_write(b"\r\n");
        }
    }
    if stack_base == 0 {
        halt_msg(com1_present, b"Failed to allocate kernel stack");
    }

    // 2. Allocate memory map region
    let mmap_count = region_count;
    let mmap_byte_size = (mmap_count as u64)
        .checked_mul(core::mem::size_of::<MemoryRegion>() as u64)
        .unwrap_or(0);
    let mmap_region_size = mmap_byte_size.checked_add(4095).unwrap_or(0) & !4095;
    let mmap_region_base = alloc_from_free(&mut regions, region_count, mmap_region_size, 4096);
    if mmap_region_base == 0 {
        halt_msg(com1_present, b"Failed to allocate memory map region");
    }

    // 3. Allocate module table
    let module_table_size = modules::module_table_size(module_list.len());
    let module_table_size_aligned = module_table_size.checked_add(4095).unwrap_or(0) & !4095;
    let module_table_base =
        alloc_from_free(&mut regions, region_count, module_table_size_aligned, 4096);
    if module_table_base != 0 {
        modules::write_module_table(module_list.as_slice(), module_table_base);
    }

    // 4. Allocate environment
    let env_size_aligned = (env_total_size as u64).checked_add(4095).unwrap_or(0) & !4095;
    let env_phys_base = alloc_from_free(&mut regions, region_count, env_size_aligned, 4096);
    if env_phys_base != 0 {
        unsafe {
            let dst = env_phys_base as *mut u8;
            core::ptr::copy_nonoverlapping(env_buf.as_ptr(), dst, env_total_size);
        }
    }

    // 5. NOW copy the memory map (includes all allocations above as non-Free)
    unsafe {
        let dst = mmap_region_base as *mut MemoryRegion;
        core::ptr::copy_nonoverlapping(regions.as_ptr(), dst, mmap_count);
    }

    // =========================================================
    // Build KernelArgs
    // =========================================================
    let kernel_size = elf_info
        .phys_end
        .checked_sub(elf_info.segments[0].phys_addr)
        .unwrap_or_else(|| halt_msg(com1_present, b"kernel_size underflow"));

    // Framebuffer size: stride (pixels/row) × height × bytes per pixel
    let fb_size_bytes = (fb_stride as u64)
        .checked_mul(fb_height as u64)
        .and_then(|v| v.checked_mul(BYTES_PER_PIXEL))
        .unwrap_or(0);

    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: elf_info.segments[0].phys_addr,
        kernel_size,
        acpi_rsdp_base: rsdp_addr,
        memory_map_base: mmap_region_base,
        memory_map_size: mmap_count as u64 * core::mem::size_of::<MemoryRegion>() as u64,
        framebuffer_addr: paging::FRAMEBUFFER_BASE,
        framebuffer_width: fb_width,
        framebuffer_height: fb_height,
        framebuffer_stride: fb_stride,
        framebuffer_bpp: fb_bpp,
        framebuffer_red_mask_size: fb_red_size,
        framebuffer_red_mask_shift: fb_red_shift,
        framebuffer_green_mask_size: fb_green_size,
        framebuffer_green_mask_shift: fb_green_shift,
        framebuffer_blue_mask_size: fb_blue_size,
        framebuffer_blue_mask_shift: fb_blue_shift,
        hhdm_offset: 0,
        cmdline_ptr: env_phys_base,
        cmdline_len: env_total_size as u64,
        modules_base: module_table_base,
        modules_size: module_table_size,
        bss_virt_base: {
            let kernel_virt_base: u64 = 0xFFFF_FFFF_8000_0000;
            let mut base = kernel_virt_base;
            for i in 0..elf_info.segment_count {
                if elf_info.segments[i].virt_addr > base {
                    base = elf_info.segments[i].virt_addr;
                }
            }
            base
        },
        bss_virt_size: {
            // BSS virtual size: highest segment end minus the page-aligned end
            // of all mapped content. The bootloader maps with 4 KiB pages.
            let kernel_virt_base: u64 = 0xFFFF_FFFF_8000_0000;
            let phys_start = elf_info.segments[0].phys_addr;
            let mapped_phys_end = elf_info.phys_end;
            // Pages needed = ceil((mapped_phys_end - phys_start) / 4096)
            let pages = mapped_phys_end
                .checked_sub(phys_start)
                .unwrap_or(0)
                .checked_add(4095)
                .unwrap_or(0)
                / 4096;
            let mapped_virt_end = kernel_virt_base + pages * 4096;
            let bss_base: u64 = {
                let mut base = kernel_virt_base;
                for i in 0..elf_info.segment_count {
                    if elf_info.segments[i].virt_addr > base {
                        base = elf_info.segments[i].virt_addr;
                    }
                }
                base
            };
            if mapped_virt_end > bss_base {
                mapped_virt_end - bss_base
            } else {
                0
            }
        },
    };

    if com1_present {
        unsafe {
            serial_write(b"[boot] Creating page tables...\r\n");
        }
    }

    let pml4_phys = unsafe {
        paging::create_page_tables(
            elf_info.segments[0].phys_addr,
            elf_info.phys_end,
            kernel_size,
            fb_phys,
            fb_size_bytes,
            env_phys_base,
            env_total_size as u64,
        )
    };

    if com1_present {
        unsafe {
            serial_write(b"[boot] Page tables ready.\r\n");
        }
    }

    // Pre-set CR4 bits (SSE mandatory on x86-64).
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 0x600; // OSFXSR (9) | OSXMMEXCPT (10)
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }

    let args_ptr = &args as *const KernelArgs;
    if com1_present {
        unsafe {
            serial_write(b"[boot] context_switch(\r\n");
            let mut tmp = [0u8; 18];
            serial_write(b"  pml4=");
            serial_write(hex_str(pml4_phys, &mut tmp));
            serial_write(b"  stack=");
            serial_write(hex_str(stack_base + stack_size, &mut tmp));
            serial_write(b"  entry=");
            serial_write(hex_str(elf_info.entry, &mut tmp));
            serial_write(b"  args=");
            serial_write(hex_str(args_ptr as u64, &mut tmp));
            serial_write(b")\r\n");
        }
    }

    unsafe {
        paging::context_switch(
            pml4_phys,
            stack_base + stack_size,
            elf_info.entry,
            args_ptr as u64,
        );
    }
}

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Write for BufWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let end = (self.pos + bytes.len()).min(self.buf.len());
        let len = end - self.pos;
        self.buf[self.pos..end].copy_from_slice(&bytes[..len]);
        self.pos = end;
        Ok(())
    }
}

impl<'a> BufWriter<'a> {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("")
    }
}

fn buf_str(buf: &mut [u8]) -> BufWriter<'_> {
    buf.fill(0);
    BufWriter { buf, pos: 0 }
}

/// Format a u64 as lowercase hex into a fixed buffer.
/// Returns the formatted bytes (without trailing \r\n).
fn hex_str(val: u64, buf: &mut [u8; 18]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 16;
    let mut v = val;
    loop {
        i -= 1;
        buf[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// Format a u64 as lowercase hex into a temporary buffer.
fn hex8_str(val: u64) -> &'static [u8] {
    static mut OUT: [u8; 18] = [0; 18];
    unsafe {
        let i = hex_str_start(val, &mut OUT);
        &OUT[i..]
    }
}

/// Write a u64 as lowercase hex into `buf`, return the starting index of the
/// written digits (the valid slice is `buf[i..]`).
fn hex_str_start(val: u64, buf: &mut [u8; 18]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 16;
    let mut v = val;
    loop {
        i -= 1;
        buf[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    i
}

/// Format a u64 as decimal into a temporary buffer.
fn decimal_str(val: u64) -> &'static [u8] {
    static mut OUT: [u8; 21] = [0; 21];
    unsafe {
        if val == 0 {
            OUT[0] = b'0';
            return &OUT[..1];
        }
        let mut v = val;
        let mut i = 21;
        while v > 0 {
            i -= 1;
            OUT[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        &OUT[i..]
    }
}
