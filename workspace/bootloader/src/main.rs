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

#[entry]
fn efi_main() -> Status {
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "Strat9-OS bootloader v0.1.0 (UEFI)");
    });

    // Step 1: Open filesystem
    let image_handle = uefi::boot::image_handle();
    let mut fs = uefi::boot::get_image_file_system(image_handle)
        .expect("Failed to get file system");
    let mut volume = (*fs).open_volume().expect("Failed to open volume");

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Filesystem OK");
    });

    // Step 2: Open kernel file
    let mut file = volume
        .open(cstr16!("\\boot\\kernel.elf"), FileMode::Read, FileAttribute::empty())
        .expect("Failed to open kernel.elf")
        .into_regular_file()
        .expect("kernel.elf is not a regular file");

    let mut file_info_buf = [0u8; 512];
    let file_info = file.get_info::<FileInfo>(&mut file_info_buf).expect("Failed to get file info");
    let file_size = file_info.file_size() as usize;

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] kernel.elf: {} bytes", file_size);
    });

    // Step 3: Read kernel into memory
    let mut buf = alloc::vec![0u8; file_size];
    file.read(&mut buf).expect("Failed to read kernel");

    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    core::mem::forget(buf);
    let kernel_data = unsafe { core::slice::from_raw_parts(ptr, len) };

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Kernel loaded OK");
    });

    // Step 4: Parse ELF
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Parsing ELF...");
    });

    let elf_info = elf::parse_elf64(kernel_data).expect("Failed to parse kernel ELF");

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] ELF: entry=0x{:x}, {} segments, phys_end=0x{:x}",
            elf_info.entry, elf_info.segment_count, elf_info.phys_end);
    });

    // Step 5: Load modules
    let module_list = modules::load_modules(image_handle);

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Modules: {}", module_list.len());
    });

    // Step 6: Get framebuffer
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

        let (red_s, red_sh, green_s, green_sh, blue_s, blue_sh) = match pixel_format {
            uefi::proto::console::gop::PixelFormat::Rgb => (8u8, 16u8, 8u8, 8u8, 8u8, 0u8),
            uefi::proto::console::gop::PixelFormat::Bgr => (8u8, 0u8, 8u8, 8u8, 8u8, 16u8),
            _ => (8u8, 0u8, 8u8, 8u8, 8u8, 16u8),
        };

        (fb_phys, width as u32, height as u32, stride as u32, 32u16,
         red_s, red_sh, green_s, green_sh, blue_s, blue_sh)
    };

    // Step 7: Get ACPI RSDP
    let rsdp_addr = uefi::system::with_config_table(|tables| {
        tables.iter()
            .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID || e.guid == ConfigTableEntry::ACPI_GUID)
            .map(|e| e.address as u64)
            .unwrap_or(0)
    });

    // Step 8: Build environment string
    let mut env_buf = [0u8; 4096];
    let mut env_len: usize = 0;

    fn env_write(buf: &mut [u8], pos: &mut usize, s: &str) {
        let bytes = s.as_bytes();
        let end = (*pos + bytes.len()).min(buf.len() - 1);
        buf[*pos..end].copy_from_slice(&bytes[..end - *pos]);
        *pos = end;
    }

    {
        env_write(&mut env_buf, &mut env_len, "loader=strat9-bootloader-uefi\n");
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

    // Step 9: ExitBootServices
    let _mmap = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .expect("Failed to get memory map");
    let mmap_iter = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Step 10: Convert memory map
    let mut regions: [MemoryRegion; 512] = [MemoryRegion {
        base: 0, size: 0, kind: MemoryKind::Null,
    }; 512];
    let mut region_count: usize = 0;

    for entry in mmap_iter.entries() {
        if region_count >= 512 { break; }
        let base = entry.phys_start;
        let size = entry.page_count * 4096;
        if size == 0 { continue; }

        let kind = match entry.ty {
            MemoryType::CONVENTIONAL => MemoryKind::Free,
            MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA => MemoryKind::Reclaim,
            MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => MemoryKind::Reclaim,
            _ => MemoryKind::Reserved,
        };

        regions[region_count] = MemoryRegion { base, size, kind };
        region_count += 1;
    }

    fn alloc_from_free(regions: &mut [MemoryRegion], region_count: usize, size: u64, align: u64) -> u64 {
        for i in 0..region_count {
            if regions[i].kind == MemoryKind::Free && regions[i].size >= size {
                let aligned_base = (regions[i].base + align - 1) & !(align - 1);
                let padding = aligned_base - regions[i].base;
                let total = size + padding;
                if regions[i].size >= total {
                    regions[i].base += total;
                    regions[i].size -= total;
                    return aligned_base;
                }
            }
        }
        0
    }

    let mmap_count = region_count;
    let mmap_byte_size = (mmap_count as u64) * (core::mem::size_of::<MemoryRegion>() as u64);
    let mmap_region_size = (mmap_byte_size + 4095) & !4095;
    let mmap_region_base = alloc_from_free(&mut regions, region_count, mmap_region_size, 4096);

    if mmap_region_base != 0 {
        unsafe {
            let dst = mmap_region_base as *mut MemoryRegion;
            core::ptr::copy_nonoverlapping(regions.as_ptr(), dst, mmap_count);
        }
    }

    let stack_size: u64 = 64 * 1024;
    let stack_base = alloc_from_free(&mut regions, region_count, stack_size, 16);

    let module_table_size = modules::module_table_size(module_list.len());
    let module_table_size_aligned = (module_table_size + 4095) & !4095;
    let module_table_base = alloc_from_free(&mut regions, region_count, module_table_size_aligned, 4096);

    if module_table_base != 0 {
        modules::write_module_table(module_list.as_slice(), module_table_base);
    }

    let env_size_aligned = (env_total_size as u64 + 4095) & !4095;
    let env_phys_base = alloc_from_free(&mut regions, region_count, env_size_aligned, 4096);

    if env_phys_base != 0 {
        unsafe {
            let dst = env_phys_base as *mut u8;
            core::ptr::copy_nonoverlapping(env_buf.as_ptr(), dst, env_total_size);
        }
    }

    // Step 11: Build KernelArgs
    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: elf_info.segments[0].phys_addr,
        kernel_size: elf_info.segments.iter()
            .take(elf_info.segment_count)
            .map(|s| s.mem_size)
            .sum::<u64>(),
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
    };

    // Step 12: Page tables and context switch
    let pml4_phys = unsafe {
        paging::create_page_tables(
            elf_info.segments[0].phys_addr,
            elf_info.phys_end,
            elf_info.phys_end - elf_info.segments[0].phys_addr,
            fb_phys,
            fb_stride as u64 * fb_height as u64,
            env_phys_base,
            env_total_size as u64,
        )
    };

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
