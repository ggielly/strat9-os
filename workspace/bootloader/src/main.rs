#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;

use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::proto::media::file::{File, FileInfo, FileMode, FileAttribute};
use uefi::table::cfg::ConfigTableEntry;
use uefi::mem::memory_map::{MemoryType, MemoryMap};

mod elf;
mod paging;
mod modules;

use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

/// UEFI entry point for the strat9-os bootloader.
#[entry]
fn efi_main() -> Status {
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "Strat9-OS bootloader v0.1.0 (UEFI)");
        let _ = writeln!(stdout, "  Framebuffer mapped at: 0x{:x}", paging::FRAMEBUFFER_BASE);
        let _ = writeln!(stdout, "  Environment mapped at: 0x{:x}", paging::ENVIRONMENT_BASE);
    });

    // ========================================================================
    // Step 1: Open the FAT ESP filesystem
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Opening filesystem...");
    });

    let image_handle = uefi::boot::image_handle();
    let mut fs = uefi::boot::get_image_file_system(image_handle)
        .expect("Failed to get file system");
    let mut volume = (*fs).open_volume().expect("Failed to open volume");

    // ========================================================================
    // Step 2: Load kernel ELF from /boot/kernel.elf
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Loading kernel...");
    });

    let kernel_data = {
        let mut file = volume
            .open(cstr16!("\\boot\\kernel.elf"), FileMode::Read, FileAttribute::empty())
            .expect("Failed to open kernel.elf")
            .into_regular_file()
            .expect("kernel.elf is not a regular file");

        let mut file_info_buf = [0u8; 512];
        let file_info = file.get_info::<FileInfo>(&mut file_info_buf).expect("Failed to get file info");
        let file_size = file_info.file_size() as usize;

        uefi::system::with_stdout(|stdout| {
            let _ = writeln!(stdout, "  kernel.elf: {} bytes", file_size);
        });

        let buf = alloc::vec![0u8; file_size];
        let mut buf = core::mem::ManuallyDrop::new(buf);
        file.read(&mut buf).expect("Failed to read kernel");

        unsafe {
            let ptr = buf.as_mut_ptr();
            let len = buf.len();
            core::slice::from_raw_parts_mut(ptr, len)
        }
    };

    // ========================================================================
    // Step 3: Parse kernel ELF
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Parsing kernel ELF...");
    });

    let elf_info = elf::parse_elf64(kernel_data).expect("Failed to parse kernel ELF");

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "  entry: 0x{:x}", elf_info.entry);
        let _ = writeln!(stdout, "  segments: {}", elf_info.segment_count);
        for i in 0..elf_info.segment_count {
            let (phys, _virt, memsz) = elf_info.segments[i];
            let _ = writeln!(stdout, "    segment {}: phys=0x{:x} size=0x{:x}", i, phys, memsz);
        }
    });

    // ========================================================================
    // Step 4: Load modules from /boot/initfs/
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Loading modules...");
    });

    let module_list = modules::load_modules(image_handle);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "  loaded {} modules", module_list.len());
    });

    // ========================================================================
    // Step 5: Get framebuffer via GOP
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Setting up framebuffer...");
    });

    let (fb_phys, fb_width, fb_height, fb_stride, fb_bpp,
         fb_red_size, fb_red_shift, fb_green_size, fb_green_shift,
         fb_blue_size, fb_blue_shift) = {
        let gop_handle = uefi::boot::get_handle_for_protocol::<GraphicsOutput>()
            .expect("No GraphicsOutput handle");
        let mut gop = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle)
            .expect("Failed to open GraphicsOutput");

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
            gop.set_mode(&mode).expect("Failed to set graphics mode");
        }

        let info = gop.current_mode_info();
        let (width, height) = info.resolution();
        let stride = info.stride();
        let pixel_format = info.pixel_format();

        let mut fb = gop.frame_buffer();
        let fb_phys = fb.as_mut_ptr() as u64;

        uefi::system::with_stdout(|stdout| {
            let _ = writeln!(stdout, "  framebuffer: {}x{} stride={} @ phys 0x{:x}", width, height, stride, fb_phys);
            let _ = writeln!(stdout, "  framebuffer virt: 0x{:x}", paging::FRAMEBUFFER_BASE);
        });

        match pixel_format {
            uefi::proto::console::gop::PixelFormat::Rgb => {
                (fb_phys, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 16u8, 8u8, 8u8, 8u8, 0u8)
            }
            uefi::proto::console::gop::PixelFormat::Bgr => {
                (fb_phys, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 0u8, 8u8, 8u8, 8u8, 16u8)
            }
            _ => {
                (fb_phys, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 16u8, 8u8, 8u8, 8u8, 0u8)
            }
        }
    };

    // ========================================================================
    // Step 6: Get ACPI RSDP from UEFI config tables
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Finding ACPI RSDP...");
    });

    let rsdp_addr = uefi::system::with_config_table(|tables| {
        tables.iter()
            .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID || e.guid == ConfigTableEntry::ACPI_GUID)
            .map(|e| e.address as u64)
            .unwrap_or(0)
    });

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "  RSDP: 0x{:x}", rsdp_addr);
    });

    // ========================================================================
    // Step 6b: Build environment string (BOOTBOOT-inspired key=value)
    // ========================================================================
    // Format: "key1=value1\nkey2=value2\n..."
    // Maximum 4096 bytes (like BOOTBOOT)
    let mut env_buf = [0u8; 4096];
    let mut env_len: usize = 0;

    // Helper to append a string to env_buf
    fn env_write(buf: &mut [u8], pos: &mut usize, s: &str) {
        let bytes = s.as_bytes();
        let end = (*pos + bytes.len()).min(buf.len());
        buf[*pos..end].copy_from_slice(&bytes[..end - *pos]);
        *pos = end;
    }

    // Build environment from UEFI config
    {
        env_write(&mut env_buf, &mut env_len, "loader=strat9-bootloader-uefi\n");
        env_write(&mut env_buf, &mut env_len, "loader.version=0.1.0\n");

        // Framebuffer
        {
            let mut tmp = [0u8; 32];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.phys=0x{:x}\n", fb_phys);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
        {
            let mut tmp = [0u8; 32];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.virt=0x{:x}\n", paging::FRAMEBUFFER_BASE);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
        {
            let mut tmp = [0u8; 24];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.width={}\n", fb_width);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
        {
            let mut tmp = [0u8; 24];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.height={}\n", fb_height);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
        {
            let mut tmp = [0u8; 24];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.stride={}\n", fb_stride);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
        {
            let mut tmp = [0u8; 16];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "fb.bpp={}\n", fb_bpp);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }

        // ACPI
        {
            let mut tmp = [0u8; 32];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "acpi.rsdp=0x{:x}\n", rsdp_addr);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }

        // Serial console
        env_write(&mut env_buf, &mut env_len, "console=ttyS0\n");
        env_write(&mut env_buf, &mut env_len, "console.baud=115200\n");

        // Kernel entry
        {
            let mut tmp = [0u8; 32];
            let mut w = buf_str(&mut tmp);
            let _ = write!(w, "kernel.entry=0x{:x}\n", elf_info.entry);
            env_write(&mut env_buf, &mut env_len, w.as_str());
        }
    }

    // Null-terminate the environment string
    if env_len < env_buf.len() {
        env_buf[env_len] = 0;
    }

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Environment ({} bytes):", env_len);
        // Print first few lines
        if let Ok(s) = core::str::from_utf8(&env_buf[..env_len]) {
            for (i, line) in s.lines().enumerate() {
                if i >= 5 {
                    let _ = writeln!(stdout, "  ... ({} more bytes)", env_len.saturating_sub(200));
                    break;
                }
                let _ = writeln!(stdout, "  {}", line);
            }
        }
    });

    // ========================================================================
    // Step 7: Get UEFI memory map, then ExitBootServices
    // ========================================================================
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Getting memory map...");
    });

    let _mmap = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .expect("Failed to get memory map");

    // SAFETY: We are the boot loader, this is the intended point of exit.
    let mmap_iter = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // ========================================================================
    // Step 8: After ExitBootServices - bare metal
    // ========================================================================

    // Convert UEFI memory map to our MemoryRegion format
    let mut regions: [MemoryRegion; 512] = [MemoryRegion {
        base: 0, size: 0, kind: MemoryKind::Null,
    }; 512];
    let mut region_count: usize = 0;

    for entry in mmap_iter.entries() {
        if region_count >= 512 {
            break;
        }
        let base = entry.phys_start;
        let size = entry.page_count * 4096;

        if size == 0 {
            continue;
        }

        let kind = match entry.ty {
            MemoryType::CONVENTIONAL => MemoryKind::Free,
            MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA => MemoryKind::Reclaim,
            MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA => MemoryKind::Reclaim,
            _ => MemoryKind::Reserved,
        };

        regions[region_count] = MemoryRegion { base, size, kind };
        region_count += 1;
    }

    // Find a free region for the stack (64KB)
    let stack_size: u64 = 64 * 1024;
    let mut stack_base: u64 = 0;
    for i in 0..region_count {
        if regions[i].kind == MemoryKind::Free && regions[i].size >= stack_size {
            stack_base = regions[i].base;
            regions[i].base += stack_size;
            regions[i].size -= stack_size;
            break;
        }
    }

    // Find a free region for the memory map itself (page-aligned)
    let mmap_region_size: u64 = (region_count * core::mem::size_of::<MemoryRegion>()) as u64;
    let mmap_region_size_aligned = (mmap_region_size + 4095) & !4095;
    let mut mmap_region_base: u64 = 0;
    for i in 0..region_count {
        if regions[i].kind == MemoryKind::Free && regions[i].size >= mmap_region_size_aligned {
            mmap_region_base = regions[i].base;
            regions[i].base += mmap_region_size_aligned;
            regions[i].size -= mmap_region_size_aligned;
            break;
        }
    }

    // Copy the memory map to the allocated region
    unsafe {
        let dst = mmap_region_base as *mut MemoryRegion;
        core::ptr::copy_nonoverlapping(regions.as_ptr(), dst, region_count);
    }

    // Find a free region for the module table
    let module_table_size: u64 = modules::module_table_size(module_list.len());
    let module_table_size_aligned = (module_table_size + 4095) & !4095;
    let mut module_table_base: u64 = 0;
    for i in 0..region_count {
        if regions[i].kind == MemoryKind::Free && regions[i].size >= module_table_size_aligned {
            module_table_base = regions[i].base;
            break;
        }
    }

    modules::write_module_table(module_list.as_slice(), module_table_base);

    // Find a free region for the environment string
    let env_size_aligned = (env_len as u64 + 4095) & !4095;
    let mut env_phys_base: u64 = 0;
    for i in 0..region_count {
        if regions[i].kind == MemoryKind::Free && regions[i].size >= env_size_aligned {
            env_phys_base = regions[i].base;
            regions[i].base += env_size_aligned;
            regions[i].size -= env_size_aligned;
            break;
        }
    }

    // Copy environment string to physical memory
    unsafe {
        let dst = env_phys_base as *mut u8;
        core::ptr::copy_nonoverlapping(env_buf.as_ptr(), dst, env_len);
    }

    // ========================================================================
    // Step 9: Build KernelArgs
    // ========================================================================
    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: elf_info.segments[0].0,
        kernel_size: elf_info.segments.iter()
            .take(elf_info.segment_count)
            .map(|s| s.2)
            .sum::<u64>(),
        stack_base,
        stack_size,
        env_base: 0,
        env_size: 0,
        acpi_rsdp_base: rsdp_addr,
        acpi_rsdp_size: 0,
        memory_map_base: mmap_region_base,
        memory_map_size: region_count as u64 * core::mem::size_of::<MemoryRegion>() as u64,
        initfs_base: 0,
        initfs_size: 0,
        framebuffer_addr: paging::FRAMEBUFFER_BASE,  // Fixed virtual address!
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
        _padding1: [0; 4],
        hhdm_offset: 0,
        cmdline_ptr: env_phys_base,  // Environment string physical address
        cmdline_len: env_len as u64,
    };

    // ========================================================================
    // Step 10: Set up page tables and context-switch to kernel
    // ========================================================================
    let pml4_phys = unsafe {
        paging::create_page_tables(
            elf_info.segments[0].0,
            args.kernel_size,
            fb_phys,
            fb_stride as u64 * fb_height as u64 * 4, // approximate framebuffer size
        )
    };

    // Context switch to the kernel
    let args_ptr = &args as *const KernelArgs;
    unsafe {
        paging::context_switch(
            pml4_phys,
            stack_base + stack_size,
            elf_info.entry,
            args_ptr as u64,
        );
    }
}

/// Helper: create a mutable byte buffer wrapper that implements Write
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
