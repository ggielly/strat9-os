#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;

use uefi::{
    mem::memory_map::{MemoryDescriptor, MemoryMap, MemoryType},
    prelude::*,
    proto::{
        console::gop::GraphicsOutput,
        loaded_image::LoadedImage,
        media::file::{File, FileAttribute, FileInfo, FileMode},
    },
    table::cfg::ConfigTableEntry,
};

mod boot_plan;
mod cpu;
mod elf;
mod memory;
mod memory_map;
mod module_name;
mod modules;
mod paging;

use boot_plan::DirectMapPlan;
use memory::{BootError, BootMemory, BootResult};
use memory_map::{MemoryMapBuilder, PhysicalRange, MAX_MEMORY_REGIONS, PAGE_SIZE};
use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

#[entry]
fn efi_main() -> Status {
    match boot_kernel() {
        Ok(()) => Status::SUCCESS,
        Err(error) => {
            uefi::system::with_stdout(|stdout| {
                let _ = writeln!(
                    stdout,
                    "[boot] ERROR: {}: {:?}",
                    error.operation, error.status
                );
            });
            error.status
        }
    }
}

fn boot_kernel() -> BootResult<()> {
    // Own permanent allocations before opening other resources, so an error
    // return closes files and drops temporary buffers before freeing their pages.
    let mut boot_memory = BootMemory::new();
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "Strat9-OS bootloader. Version 0.1.0, UEFI mode.");
        let _ = writeln!(
            stdout,
            "Copyright (C) 2026 Guillaume Gielly. All rights reserved."
        );
    });

    // Check the CPU and locate every byte of the EFI transition image.
    let cpu_features = cpu::detect().map_err(BootError::invalid)?;
    let image_handle = uefi::boot::image_handle();
    let loader_image = {
        let image = uefi::boot::open_protocol_exclusive::<LoadedImage>(image_handle)
            .map_err(|error| BootError::firmware("loaded EFI image", error.status()))?;
        let (base, size) = image.info();
        PhysicalRange {
            base: base as u64,
            size,
        }
    };
    let transition = paging::context_switch as *const () as u64;
    if transition < loader_image.base
        || transition >= loader_image.end().map_err(BootError::invalid)?
    {
        return Err(BootError::invalid(
            "transition code is outside the loaded EFI image",
        ));
    }
    // Open filesystem.
    let mut fs = uefi::boot::get_image_file_system(image_handle)
        .map_err(|error| BootError::firmware("open boot filesystem", error.status()))?;
    let mut volume = (*fs)
        .open_volume()
        .map_err(|error| BootError::firmware("open boot volume", error.status()))?;

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] The filesystem is OK");
    });

    //  kernel file
    let mut file = volume
        .open(
            cstr16!("\\boot\\kernel.elf"),
            FileMode::Read,
            FileAttribute::empty(),
        )
        .map_err(|error| BootError::firmware("open kernel.elf", error.status()))?
        .into_regular_file()
        .ok_or_else(|| BootError::invalid("kernel.elf is not a regular file"))?;

    let mut file_info_buf = [0u8; 512];
    let file_info = file
        .get_info::<FileInfo>(&mut file_info_buf)
        .map_err(|error| BootError::firmware("kernel file information", error.status()))?;
    let file_size = file_info.file_size() as usize;

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] kernel.elf: {} bytes", file_size);
    });

    // Read kernel into memory
    let mut buf = alloc::vec::Vec::new();
    buf.try_reserve_exact(file_size)
        .map_err(|_| BootError::out_of_resources("kernel file buffer"))?;
    buf.resize(file_size, 0u8);
    let read = file
        .read(&mut buf)
        .map_err(|error| BootError::firmware("read kernel.elf", error.status()))?;
    if read != file_size {
        return Err(BootError::invalid(
            "kernel.elf ended before its advertised size",
        ));
    }
    drop(file);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Kernel loaded OK");
    });

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Parsing kernel ELF file...");
    });

    let mut elf_info = elf::parse_elf64(&buf).map_err(BootError::invalid)?;
    let kernel_allocation = boot_memory.allocate_preferred(
        elf_info.phys_base,
        elf_info.image_size(),
        "kernel image pages",
    )?;
    // SAFETY: UEFI reserved this whole image before any segment is written.
    // The source Vec is a separate, still-live UEFI allocation.
    unsafe { elf_info.load_into(&buf, kernel_allocation) }.map_err(BootError::invalid)?;
    drop(buf);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(
            stdout,
            "[boot] ELF: entry=0x{:x}, {} segments, phys_end=0x{:x}",
            elf_info.entry, elf_info.segment_count, elf_info.phys_end
        );
    });

    // Load modules
    let module_list = modules::load_modules(&mut volume, &mut boot_memory)?;

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Modules: {}", module_list.len());
    });

    // Step 6: Get framebuffer (optional : may not be available in -nographic mode)
    let mut fb_phys: u64 = 0;
    let mut fb_width: u32 = 0;
    let mut fb_height: u32 = 0;
    let mut fb_stride: u32 = 0;
    let mut fb_bpp: u16 = 32;
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

        let mut best_mode = None;
        let mut best_area: usize = 0;
        for mode in gop.modes() {
            let (w, h) = mode.info().resolution();
            let area = w * h;
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
        fb_phys = fb.as_mut_ptr() as u64;
        fb_width = width as u32;
        fb_height = height as u32;
        // uefi's stride() returns PIXELS per scan line; the strat9 ABI
        // expects BYTES (see vga writer: y * pitch + x * bpp_bytes).
        let stride_bytes = (stride as u64) * ((fb_bpp as u64 + 7) / 8);
        fb_stride = stride_bytes as u32;

        let (r_s, r_sh, g_s, g_sh, b_s, b_sh) = match pixel_format {
            uefi::proto::console::gop::PixelFormat::Rgb => (8, 16, 8, 8, 8, 0),
            uefi::proto::console::gop::PixelFormat::Bgr => (8, 0, 8, 8, 8, 16),
            _ => (8, 0, 8, 8, 8, 16),
        };
        fb_red_size = r_s;
        fb_red_shift = r_sh;
        fb_green_size = g_s;
        fb_green_shift = g_sh;
        fb_blue_size = b_s;
        fb_blue_shift = b_sh;
    }

    // Get ACPI RSDP
    let rsdp_addr = uefi::system::with_config_table(|tables| {
        tables
            .iter()
            .find(|e| {
                e.guid == ConfigTableEntry::ACPI2_GUID || e.guid == ConfigTableEntry::ACPI_GUID
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

    // Allocate every object that must survive the firmware before leaving UEFI.
    let stack_size: u64 = 64 * 1024;
    let stack = boot_memory.allocate(stack_size, "kernel transition stack")?;
    let stack_base = stack.base;
    let module_table_size = modules::module_table_size();
    let module_table = boot_memory.allocate(module_table_size, "module table pages")?;
    let module_table_base = module_table.base;
    // SAFETY: the page allocation covers the complete fixed-capacity table.
    unsafe { modules::write_module_table(module_list.as_slice(), module_table) }?;
    drop(module_list);

    let environment = boot_memory.allocate(env_total_size as u64, "environment pages")?;
    let env_phys_base = environment.base;
    unsafe {
        core::ptr::copy_nonoverlapping(env_buf.as_ptr(), env_phys_base as *mut u8, env_total_size);
    }
    let args_storage = boot_memory.allocate(
        core::mem::size_of::<KernelArgs>() as u64,
        "kernel arguments page",
    )?;
    let map_storage = boot_memory.allocate(
        (MAX_MEMORY_REGIONS * core::mem::size_of::<MemoryRegion>()) as u64,
        "kernel memory map pages",
    )?;
    let mmap_region_base = map_storage.base;
    let framebuffer_size = (fb_stride as u64)
        .checked_mul(fb_height as u64)
        .ok_or_else(|| BootError::invalid("framebuffer size overflow"))?;
    let mut direct_map = DirectMapPlan::new(cpu_features.physical_limit(), loader_image)
        .map_err(BootError::invalid)?;
    let planning_map = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|error| BootError::firmware("direct map planning", error.status()))?;
    for entry in planning_map.entries() {
        let region = firmware_region(entry).map_err(BootError::invalid)?;
        if needs_direct_mapping(entry.ty) {
            direct_map
                .include(PhysicalRange {
                    base: region.base,
                    size: region.size,
                })
                .map_err(BootError::invalid)?;
        }
    }
    drop(planning_map);
    if fb_phys != 0 && framebuffer_size != 0 {
        direct_map
            .include(PhysicalRange {
                base: fb_phys,
                size: framebuffer_size,
            })
            .map_err(BootError::invalid)?;
    }
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(
            stdout,
            "[boot] Initial identity/HHDM: {} GiB, 2 MiB pages",
            direct_map.end() / boot_plan::GIB
        );
    });
    let table_pages = paging::page_table_pages(
        elf_info.image_size(),
        framebuffer_size,
        env_total_size as u64,
        direct_map,
    )
    .map_err(BootError::invalid)?;
    let table_area = boot_memory.allocate(table_pages * PAGE_SIZE, "page-table arena")?;
    let pml4_phys = unsafe {
        paging::create_page_tables(
            elf_info.phys_base,
            elf_info.image_size(),
            fb_phys,
            framebuffer_size,
            env_phys_base,
            env_total_size as u64,
            table_area,
            direct_map,
        )
    }
    .map_err(BootError::invalid)?;

    drop(volume);
    drop(fs);
    // Preflight with all permanent reservations present. ExitBootServices obtains
    // its own final map; conversion is repeated below with the same bounded buffer.
    let preview = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|error| BootError::firmware("memory map preflight", error.status()))?;
    convert_memory_map(
        &preview,
        boot_memory.reservations(),
        map_storage,
        direct_map,
    )
    .map_err(BootError::invalid)?;
    drop(preview);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] ExitBootServices...");
    });

    boot_memory.retain_for_handoff();
    let mmap_iter = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    // No firmware calls follow: stop maskable interrupts and normalize DF before
    // touching the execution environment. This asm is also a compiler memory barrier.
    unsafe { core::arch::asm!("cli", "cld", options(nostack)) };

    // No allocations, firmware calls or recoverable returns after this point.
    // Split around the exact owned pages, including every module payload.
    let region_count = convert_memory_map(
        &mmap_iter,
        boot_memory.reservations(),
        map_storage,
        direct_map,
    )
    .unwrap_or_else(|reason| halt_after_boot_services(reason));

    // Re-initialize serial port after ExitBootServices
    unsafe {
        // UART 16550 initialization
        let base: u16 = 0x3F8;
        core::arch::asm!("out dx, al", in("al") 0x00u8, in("dx") base + 1, options(nomem, nostack)); // Disable interrupts
        core::arch::asm!("out dx, al", in("al") 0x80u8, in("dx") base + 3, options(nomem, nostack)); // Enable DLAB
        core::arch::asm!("out dx, al", in("al") 0x03u8, in("dx") base + 0, options(nomem, nostack)); // Set divisor lo (38400 baud)
        core::arch::asm!("out dx, al", in("al") 0x00u8, in("dx") base + 1, options(nomem, nostack)); // Set divisor hi
        core::arch::asm!("out dx, al", in("al") 0x03u8, in("dx") base + 3, options(nomem, nostack)); // 8 bits, no parity, one stop
        core::arch::asm!("out dx, al", in("al") 0xC7u8, in("dx") base + 2, options(nomem, nostack)); // Enable FIFO
        core::arch::asm!("out dx, al", in("al") 0x0Bu8, in("dx") base + 4, options(nomem, nostack)); // IRQs enabled, RTS/DSR set

        // Test output
        let msg = b"[boot] After ExitBootServices, serial OK\r\n";
        let lsr: u16 = base + 5;
        let thr: u16 = base;
        for &b in msg {
            loop {
                let status: u8;
                core::arch::asm!("in al, dx", out("al") status, in("dx") lsr, options(nomem, nostack));
                if status & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("al") b, in("dx") thr, options(nomem, nostack));
        }
    }

    // Step 11: Build KernelArgs
    let (bss_virt_base, bss_virt_size) = elf_info.bss_range();
    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: elf_info.phys_base,
        kernel_size: elf_info.phys_end - elf_info.phys_base,
        acpi_rsdp_base: rsdp_addr,
        memory_map_base: mmap_region_base,
        memory_map_size: region_count as u64 * core::mem::size_of::<MemoryRegion>() as u64,
        framebuffer_addr: fb_phys,
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
        hhdm_offset: paging::HHDM_OFFSET,
        cmdline_ptr: env_phys_base,
        cmdline_len: env_total_size as u64,
        modules_base: module_table_base,
        modules_size: module_table_size,
        bss_virt_base,
        bss_virt_size,
    };

    // The handoff itself lives in reserved pages, not on the firmware stack.
    let args_ptr = args_storage.base as *mut KernelArgs;
    unsafe { args_ptr.write(args) };

    unsafe {
        let write_com1 = |s: &[u8]| {
            let lsr: u16 = 0x3F8 + 5;
            let thr: u16 = 0x3F8;
            for &b in s {
                loop {
                    let status: u8;
                    core::arch::asm!("in al, dx", out("al") status, in("dx") lsr, options(nomem, nostack));
                    if status & 0x20 != 0 {
                        break;
                    }
                }
                core::arch::asm!("out dx, al", in("al") b, in("dx") thr, options(nomem, nostack));
            }
        };

        fn hex_str(val: u64, buf: &mut [u8; 18]) -> &[u8] {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut i = 16;
            let mut v = val;
            buf[i] = b'\r';
            buf[17] = b'\n';
            loop {
                i -= 1;
                buf[i] = HEX[(v & 0xf) as usize];
                v >>= 4;
                if i == 0 || v == 0 {
                    break;
                }
            }
            &buf[i..]
        }

        let mut hexbuf: [u8; 18] = [0; 18];
        write_com1(b"[boot] context_switch(\r\n");
        write_com1(b"  pml4=");
        write_com1(hex_str(pml4_phys, &mut hexbuf));
        write_com1(b"  stack=");
        write_com1(hex_str(stack_base + stack_size, &mut hexbuf));
        write_com1(b"  entry=");
        write_com1(hex_str(elf_info.entry, &mut hexbuf));
        write_com1(b"  args=");
        write_com1(hex_str(args_ptr as u64, &mut hexbuf));
        write_com1(b")\r\n");
        write_com1(b"[boot] mmap_base=");
        write_com1(hex_str(mmap_region_base, &mut hexbuf));
        write_com1(b" region_count=");
        write_com1(hex_str(region_count as u64, &mut hexbuf));
        // Print first region type to verify data
        let first_kind = (*(mmap_region_base as *const MemoryRegion)).kind.0;
        write_com1(b" first_kind=");
        write_com1(hex_str(first_kind, &mut hexbuf));
        write_com1(b"\r\n");
        write_com1(b"[boot] Jumping to kernel (pause loop)...\r\n");

        // Small delay to let serial flush
        for _ in 0..100000 {
            core::arch::asm!("pause", options(nomem, nostack));
        }

        write_com1(b"[boot] Jumping to kernel (after pause)...\r\n");
    }

    unsafe {
        // Every register used by this returning asm block is an explicit input.
        core::arch::asm!(
            "out dx, al", in("dx") 0x3F8u16, in("al") b'>',
            options(nomem, nostack, preserves_flags),
        );
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

/// Convert directly into a preallocated, permanently reserved handoff buffer.
fn convert_memory_map(
    map: &impl MemoryMap,
    reservations: &[PhysicalRange],
    storage: PhysicalRange,
    direct_map: DirectMapPlan,
) -> Result<usize, &'static str> {
    let required = (MAX_MEMORY_REGIONS * core::mem::size_of::<MemoryRegion>()) as u64;
    if storage.base == 0 || storage.base % PAGE_SIZE != 0 || storage.size < required {
        return Err("invalid memory map allocation");
    }
    // SAFETY: callers supply BootMemory's exclusively owned zeroed map allocation.
    // MemoryRegion consists entirely of integer fields, so zero is a valid value.
    let output = unsafe {
        core::slice::from_raw_parts_mut(storage.base as *mut MemoryRegion, MAX_MEMORY_REGIONS)
    };
    let mut builder = MemoryMapBuilder::new(output, reservations)?;
    for entry in map.entries() {
        let region = firmware_region(entry)?;
        if needs_direct_mapping(entry.ty)
            && !direct_map.covers(PhysicalRange {
                base: region.base,
                size: region.size,
            })
        {
            return Err("final firmware map exceeds the prepared HHDM");
        }
        builder.push(region)?;
    }
    if builder.len() == 0 {
        return Err("empty firmware memory map");
    }
    Ok(builder.len())
}

fn needs_direct_mapping(ty: MemoryType) -> bool {
    // Include firmware-owned RAM holding ACPI/configuration tables as well as
    // allocatable RAM. Mapping these ranges does not make them reclaimable.
    matches!(
        ty,
        MemoryType::CONVENTIONAL
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA
            | MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA
            | MemoryType::RUNTIME_SERVICES_CODE
            | MemoryType::RUNTIME_SERVICES_DATA
            | MemoryType::ACPI_RECLAIM
            | MemoryType::ACPI_NON_VOLATILE
    )
}

fn firmware_region(entry: &MemoryDescriptor) -> Result<MemoryRegion, &'static str> {
    let size = entry
        .page_count
        .checked_mul(PAGE_SIZE)
        .ok_or("firmware memory descriptor size overflow")?;
    let kind = match entry.ty {
        MemoryType::CONVENTIONAL => MemoryKind::Free,
        MemoryType::BOOT_SERVICES_CODE
        | MemoryType::BOOT_SERVICES_DATA
        | MemoryType::LOADER_CODE
        | MemoryType::LOADER_DATA => MemoryKind::Reclaim,
        _ => MemoryKind::Reserved,
    };
    Ok(MemoryRegion {
        base: entry.phys_start,
        size,
        kind,
    })
}

/// Fatal errors after ExitBootServices must not unwind, return to UEFI, use its
/// allocator, or wait forever for a serial port that may not exist.
fn halt_after_boot_services(reason: &str) -> ! {
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    let parts: [&[u8]; 3] = [b"[boot] FATAL: ", reason.as_bytes(), b"\r\n"];
    for part in parts {
        for &byte in part {
            unsafe {
                core::arch::asm!("out 0xe9, al", in("al") byte, options(nomem, nostack));
                for _ in 0..10_000 {
                    let status: u8;
                    core::arch::asm!(
                        "in al, dx", in("dx") 0x3FDu16, out("al") status,
                        options(nomem, nostack),
                    );
                    if status & 0x20 != 0 {
                        core::arch::asm!(
                            "out dx, al", in("dx") 0x3F8u16, in("al") byte,
                            options(nomem, nostack),
                        );
                        break;
                    }
                }
            }
        }
    }
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}
