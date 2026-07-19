#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;

use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::proto::media::file::{File, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};

mod elf;
mod paging;
mod modules;
mod args;

use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

/// UEFI entry point for the strat9-os bootloader.
///
/// Following Phil Opp's approach: init uefi-services, load kernel ELF from FAT ESP,
/// set up page tables, build KernelArgs, then context-switch to the kernel.
#[entry]
fn efi_main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
    // Initialize uefi-services (allocator, serial, console)
    uefi_services::init(&mut st).unwrap();

    // Print banner to UEFI stdout
    writeln!(st.stdout(), "Strat9-OS bootloader v0.1.0 (UEFI)").unwrap();
    writeln!(st.stdout(), "  Firmware: {}", st.firmware_info()).unwrap();
    writeln!(st.stdout(), "").unwrap();

    // ========================================================================
    // Step 1: Open the FAT ESP filesystem
    // ========================================================================
    writeln!(st.stdout(), "[boot] Opening filesystem...").unwrap();
    let bs = st.boot_services();
    let fs_handle = bs.get_handle_for_protocol::<SimpleFileSystem>().unwrap();
    let mut fs = unsafe { &mut *bs.open_protocol_exclusive::<SimpleFileSystem>(fs_handle).unwrap().get() };
    let mut root = fs.open_volume().unwrap();

    // ========================================================================
    // Step 2: Load kernel ELF from /boot/kernel.elf
    // ========================================================================
    writeln!(st.stdout(), "[boot] Loading kernel...").unwrap();
    let kernel_data = {
        let mut file = root
            .open(cstr16!("\\boot\\kernel.elf"), FileMode::Read, FileAttribute::empty())
            .unwrap()
            .regular_file()
            .unwrap();

        // Get file size
        let mut file_info_buf = [0u8; 512];
        let file_info = file.get_info::<FileInfo>(&mut file_info_buf).unwrap();
        let file_size = file_info.file_size() as usize;

        writeln!(st.stdout(), "  kernel.elf: {} bytes", file_size).unwrap();

        // Allocate buffer and read
        let buf = alloc::vec![0u8; file_size];
        let mut buf = core::mem::ManuallyDrop::new(buf);
        file.read(&mut buf).unwrap();
        // Safety: we pass ownership of the vec's buffer to the returned slice
        unsafe {
            let ptr = buf.as_mut_ptr();
            let len = buf.len();
            core::slice::from_raw_parts_mut(ptr, len)
        }
    };

    // ========================================================================
    // Step 3: Parse kernel ELF
    // ========================================================================
    writeln!(st.stdout(), "[boot] Parsing kernel ELF...").unwrap();
    let elf_info = elf::parse_elf64(kernel_data).expect("Failed to parse kernel ELF");
    writeln!(st.stdout(), "  entry: 0x{:x}", elf_info.entry).unwrap();
    writeln!(st.stdout(), "  segments: {}", elf_info.segment_count).unwrap();

    for i in 0..elf_info.segment_count {
        let (phys, _virt, memsz) = elf_info.segments[i];
        writeln!(st.stdout(), "    segment {}: phys=0x{:x} size=0x{:x}", i, phys, memsz).unwrap();
    }

    // ========================================================================
    // Step 4: Load modules from /boot/initfs/
    // ========================================================================
    writeln!(st.stdout(), "[boot] Loading modules...").unwrap();
    let mut root2 = fs.open_volume().unwrap();
    let mut root3 = fs.open_volume().unwrap();
    let mut root4 = fs.open_volume().unwrap();
    let mut root5 = fs.open_volume().unwrap();
    let module_list = modules::load_modules(bs, &mut root, &mut root2, &mut root3, &mut root4, &mut root5);

    writeln!(st.stdout(), "  loaded {} modules", module_list.len()).unwrap();

    // ========================================================================
    // Step 5: Get framebuffer via GOP
    // ========================================================================
    writeln!(st.stdout(), "[boot] Setting up framebuffer...").unwrap();
    let (fb_addr, fb_width, fb_height, fb_stride, fb_bpp,
         fb_red_size, fb_red_shift, fb_green_size, fb_green_shift,
         fb_blue_size, fb_blue_shift) = {
        let gop_handle = bs.get_handle_for_protocol::<GraphicsOutput>().unwrap();
        let mut gop = unsafe { &mut *bs.open_protocol_exclusive::<GraphicsOutput>(gop_handle).unwrap().get() };

        // Pick the best mode (highest resolution)
        let modes: alloc::vec::Vec<_> = gop.modes(bs).collect();
        if let Some(best) = modes.iter().max_by_key(|m| {
            let (w, h) = m.info().resolution();
            w * h
        }) {
            gop.set_mode(best).unwrap();
        }

        let info = gop.current_mode_info();
        let (width, height) = info.resolution();
        let stride = info.stride();
        let pixel_format = info.pixel_format();

        let mut fb = gop.frame_buffer().unwrap();
        let fb_addr = fb.as_mut_ptr() as u64;

        writeln!(st.stdout(), "  framebuffer: {}x{} stride={} @ 0x{:x}", width, height, stride, fb_addr).unwrap();

        // Parse pixel format for RGB masks
        match pixel_format {
            uefi::proto::console::gop::PixelFormat::Rgb => {
                (fb_addr, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 16u8, 8u8, 8u8, 8u8, 0u8)
            }
            uefi::proto::console::gop::PixelFormat::Bgr => {
                (fb_addr, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 0u8, 8u8, 8u8, 8u8, 16u8)
            }
            _ => {
                (fb_addr, width as u32, height as u32, stride as u32, 32u16,
                 8u8, 16u8, 8u8, 8u8, 8u8, 0u8)
            }
        }
    };

    // ========================================================================
    // Step 6: Get ACPI RSDP from UEFI config tables
    // ========================================================================
    writeln!(st.stdout(), "[boot] Finding ACPI RSDP...").unwrap();
    let rsdp_addr = st.runtime_services().config_table().iter()
        .find(|e| e.guid == ACPI2_GUID || e.guid == ACPI_GUID)
        .map(|e| e.address as u64)
        .unwrap_or(0);
    writeln!(st.stdout(), "  RSDP: 0x{:x}", rsdp_addr).unwrap();

    // ========================================================================
    // Step 7: Get UEFI memory map, then ExitBootServices
    // ========================================================================
    writeln!(st.stdout(), "[boot] Getting memory map...").unwrap();

    // First call: get required buffer size
    let mut mmap_size = bs.memory_map_size().map_size;
    // Allocate buffer (over-estimate to be safe)
    let mmap_buf_size = mmap_size + 4096;
    let mmap_buf = alloc::vec![0u8; mmap_buf_size];
    let mut mmap_buf = core::mem::ManuallyDrop::new(mmap_buf);

    // We need to exit boot services before we can use the memory map
    // Phil Opp pattern: allocate what we need, then exit
    let (runtime, mmap_iter) = match bs.exit_boot_services(MemoryType::LOADER_DATA) {
        Ok((rt, mmap)) => (rt, mmap),
        Err(e) => {
            // If exit fails, we're stuck. Print and halt.
            // (stdout may not work after partial exit, but try)
            panic!("ExitBootServices failed: {:?}", e.status());
        }
    };

    // ========================================================================
    // Step 8: After ExitBootServices - we're now in bare metal
    // ========================================================================
    // At this point:
    // - UEFI runtime services still available via `runtime`
    // - No allocator, no UEFI boot services
    // - We must set up everything ourselves

    // Convert UEFI memory map to our MemoryRegion format
    // We need to write this to a known physical address
    let mut regions: [MemoryRegion; 512] = [MemoryRegion {
        base: 0, size: 0, kind: MemoryKind::Null,
    }; 512];
    let mut region_count: usize = 0;

    for entry in mmap_iter.entries() {
        if region_count >= 512 {
            break;
        }
        let base = entry.phys_start;
        let size = entry.phys_end() - entry.phys_start;

        if size == 0 {
            continue;
        }

        let kind = match entry.ty {
            uefi::table::boot::MemoryType::CONVENTIONAL => MemoryKind::Free,
            uefi::table::boot::MemoryType::BOOT_SERVICES_CODE
            | uefi::table::boot::MemoryType::BOOT_SERVICES_DATA => MemoryKind::Reclaim,
            // LOADER_CODE and LOADER_DATA are our own memory, reclaimable
            uefi::table::boot::MemoryType::LOADER_CODE
            | uefi::table::boot::MemoryType::LOADER_DATA => MemoryKind::Reclaim,
            // Everything else is reserved
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
            // Shrink this free region to account for the stack
            regions[i].base += stack_size;
            regions[i].size -= stack_size;
            break;
        }
    }

    // Find a free region for the memory map itself (4KB)
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
            regions[i].base += module_table_size_aligned;
            regions[i].size -= module_table_size_aligned;
            break;
        }
    }

    // Write the module table to memory
    modules::write_module_table(module_list.as_slice(), module_table_base);

    // ========================================================================
    // Step 9: Build KernelArgs
    // ========================================================================
    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: elf_info.segments[0].0,  // first segment physical
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
        framebuffer_addr: fb_addr,
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
        hhdm_offset: 0, // UEFI identity maps physical memory at virtual 0
        cmdline_ptr: 0,
        cmdline_len: 0,
    };

    // ========================================================================
    // Step 10: Set up page tables and context-switch to kernel
    // ========================================================================
    // Build page tables:
    //   - Identity map (UEFI already does this, but we re-establish it)
    //   - Higher-half kernel at 0xFFFFFFFF80000000
    let pml4_phys = unsafe {
        paging::create_page_tables(
            elf_info.segments[0].0,  // kernel physical base
            args.kernel_size,
        )
    };

    // Context switch to the kernel
    // Phil Opp pattern: load CR3, set RSP, put args in RDI, jump
    let args_ptr = &args as *const KernelArgs;
    unsafe {
        paging::context_switch(
            pml4_phys,
            stack_base + stack_size,  // stack grows down, so top = base + size
            elf_info.entry,
            args_ptr as u64,
        );
    }

    // Should never reach here
    Status::SUCCESS
}
