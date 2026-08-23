#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;

use uefi::{
    mem::memory_map::{MemoryMap, MemoryType},
    prelude::*,
    proto::{
        console::gop::GraphicsOutput,
        media::file::{File, FileAttribute, FileInfo, FileMode},
    },
    table::cfg::ConfigTableEntry,
};

mod elf;
mod modules;
mod paging;

/// RSDP signature "RSD PTR " (8 bytes)
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// Release-mode linker shim for uefi-rs: with optimizations enabled, LLVM
/// lowers the CStr16 length loop inside `FileInfo::from_uefi` to a call to
/// the C `wcslen`, which no UEFI-provided library implements
/// (undefined symbol at link time). Provide the obvious implementation.
///
/// See also: `cargo make bootloader-uefi-release`.
#[no_mangle]
extern "C" fn wcslen(mut s: *const u16) -> usize {
    let mut n = 0usize;
    unsafe {
        while core::ptr::read_volatile(s) != 0 {
            s = s.add(1);
            n += 1;
        }
    }
    n
}

/// Upper bound for kernel.elf on the ESP (L3: bounded allocations).
const MAX_KERNEL_FILE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Read exactly `buf.len()` bytes from `file`, looping over short reads.
/// Returns the total number of bytes read; callers must treat anything less
/// than `buf.len()` as a truncated image (M4).
fn read_full(file: &mut uefi::proto::media::file::RegularFile, buf: &mut [u8]) -> usize {
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break, // EOF before the buffer was filled
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    total
}

/// Validate RSDP checksum: sum of all bytes must be 0 mod 256
unsafe fn validate_rsdp(ptr: *const u8) -> bool {
    let mut sum: u8 = 0;
    for i in 0..20 {
        sum = sum.wrapping_add(core::ptr::read_volatile(ptr.add(i)));
    }
    sum == 0
}

/// Validate ACPI table checksum: the sum of every byte of the table (as
/// declared by its Length field) must be 0 mod 256. Tables declaring a
/// length smaller than the 36-byte SDT header, or absurdly large, are
/// rejected outright instead of trivially passing an empty sum.
unsafe fn validate_acpi_table_header(base: u64) -> bool {
    if base == 0 {
        return false;
    }
    let mut sum: u8 = 0;
    // SDT header is 36 bytes: signature(4) + length(4) + revision(1) +
    // checksum(1) + oem_id(6) + oem_table_id(8) + oem_revision(4) +
    // creator_id(4) + creator_revision(4)
    let ptr = base as *const u8;
    let length_field = core::ptr::read_volatile((ptr.add(4)) as *const u32) as usize;
    if length_field < 36 || length_field > 0x10000 {
        return false;
    }
    for i in 0..length_field {
        sum = sum.wrapping_add(core::ptr::read_volatile(ptr.add(i)));
    }
    sum == 0
}

/// Scan physical memory for RSDP signature. Checks EBDA pointer, then 0xE0000-0xFFFFF.
fn scan_for_rsdp() -> u64 {
    unsafe {
        // Try EBDA (Extended BIOS Data Area) — read from 0x40E (real mode vector)
        let ebda_seg: u16 = core::ptr::read_volatile(0x40E as *const u16);
        if ebda_seg != 0 {
            let ebda_addr = (ebda_seg as u64) << 4;
            // Scan first 1KB of EBDA
            let end = (ebda_addr + 0x400).min(0x10_0000);
            for addr in (ebda_addr..end).step_by(16) {
                if addr + 20 > 0x10_0000 {
                    break;
                }
                if core::ptr::read_volatile(addr as *const [u8; 8]) == *RSDP_SIGNATURE
                    && validate_rsdp(addr as *const u8)
                {
                    return addr;
                }
            }
        }

        // Scan legacy EBDA region 0x80000-0x9FFFF
        for addr in (0x80_000u64..0xA0_000).step_by(16) {
            if core::ptr::read_volatile(addr as *const [u8; 8]) == *RSDP_SIGNATURE
                && validate_rsdp(addr as *const u8)
            {
                return addr;
            }
        }

        // Scan ROM area 0xE0000-0xFFFFF
        for addr in (0xE0_000u64..0x100_000).step_by(16) {
            if core::ptr::read_volatile(addr as *const [u8; 8]) == *RSDP_SIGNATURE
                && validate_rsdp(addr as *const u8)
            {
                return addr;
            }
        }

        0
    }
}

use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};

#[entry]
fn efi_main() -> Status {
    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "Strat9-OS bootloader = UEFI mode. Version 0.1.0.");
    });

    // Open filesystem
    let image_handle = uefi::boot::image_handle();
    let mut fs = uefi::boot::get_image_file_system(image_handle)
        .expect("[boot] FATAL: UEFI file system protocol unavailable");
    let mut volume = (*fs)
        .open_volume()
        .expect("[boot] FATAL: Cannot open boot volume");

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
        .expect("[boot] FATAL: \\boot\\kernel.elf not found on boot volume")
        .into_regular_file()
        .expect("[boot] FATAL: \\boot\\kernel.elf exists but is not a regular file (is it a directory?)");

    let mut file_info_buf = [0u8; 512];
    let file_info = file
        .get_info::<FileInfo>(&mut file_info_buf)
        .expect("[boot] FATAL: Cannot read kernel.elf metadata (file info query failed)");
    let file_size = file_info.file_size() as usize;

    // L3: refuse absurd sizes up front instead of attempting the allocation.
    if file_size == 0 || file_size > MAX_KERNEL_FILE_SIZE {
        panic!(
            "[boot] FATAL: kernel.elf size {} bytes is outside the supported range (max {})",
            file_size, MAX_KERNEL_FILE_SIZE
        );
    }

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] kernel.elf: {} bytes", file_size);
    });

    // Read kernel into memory. Loop until the whole file is consumed: UEFI
    // file reads may return short (M4). A truncated kernel is fatal.
    let mut buf = alloc::vec![0u8; file_size];
    let bytes_read = read_full(&mut file, &mut buf);
    if bytes_read != file_size {
        panic!(
            "[boot] FATAL: kernel.elf truncated on the boot volume (read {} of {} bytes)",
            bytes_read, file_size
        );
    }

    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    core::mem::forget(buf);
    let kernel_data = unsafe { core::slice::from_raw_parts(ptr, len) };

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Kernel loaded OK");
    });

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] Parsing kernel ELF file...");
    });

    let elf_info = elf::parse_elf64(kernel_data)
        .expect("[boot] FATAL: kernel.elf is not a valid ELF64 binary");

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

    // Step 6: Get framebuffer (optional : may not be available in -nographic mode)
    // Everything stays zeroed when no GOP is available so the kernel sees a
    // consistently disabled framebuffer.
    let mut fb_phys: u64 = 0;
    let mut fb_width: u32 = 0;
    let mut fb_height: u32 = 0;
    let mut fb_stride: u32 = 0;
    let mut fb_bpp: u16 = 0;
    let mut fb_red_size: u8 = 0;
    let mut fb_red_shift: u8 = 0;
    let mut fb_green_size: u8 = 0;
    let mut fb_green_shift: u8 = 0;
    let mut fb_blue_size: u8 = 0;
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
        fb_stride = stride as u32;
        fb_bpp = 32;

        let (r_s, r_sh, g_s, g_sh, b_s, b_sh) = match pixel_format {
            uefi::proto::console::gop::PixelFormat::Rgb => (8, 16, 8, 8, 8, 0),
            uefi::proto::console::gop::PixelFormat::Bgr => (8, 0, 8, 8, 8, 16),
            uefi::proto::console::gop::PixelFormat::Bitmask => {
                if let Some(mask) = info.pixel_bitmask() {
                    let r_sh = mask.red.trailing_zeros() as u8;
                    let r_s = mask.red.count_ones() as u8;
                    let g_sh = mask.green.trailing_zeros() as u8;
                    let g_s = mask.green.count_ones() as u8;
                    let b_sh = mask.blue.trailing_zeros() as u8;
                    let b_s = mask.blue.count_ones() as u8;
                    (r_s, r_sh, g_s, g_sh, b_s, b_sh)
                } else {
                    (8, 16, 8, 8, 8, 0)
                }
            }
            _ => {
                uefi::system::with_stdout(|stdout| {
                    let _ = writeln!(
                        stdout,
                        "[boot] WARNING: Unknown pixel format, defaulting to BGR888"
                    );
                });
                (8, 0, 8, 8, 8, 16)
            }
        };
        fb_red_size = r_s;
        fb_red_shift = r_sh;
        fb_green_size = g_s;
        fb_green_shift = g_sh;
        fb_blue_size = b_s;
        fb_blue_shift = b_sh;
    }

    // Validate framebuffer — ensure physical address is valid
    if fb_phys == 0 && (fb_width != 0 || fb_height != 0) {
        uefi::system::with_stdout(|stdout| {
            let _ = writeln!(
                stdout,
                "[boot] WARNING: Framebuffer pointer is NULL despite reporting non-zero dimensions — disabling framebuffer"
            );
        });
        fb_width = 0;
        fb_height = 0;
        fb_stride = 0;
        fb_bpp = 0;
        fb_red_size = 0;
        fb_red_shift = 0;
        fb_green_size = 0;
        fb_green_shift = 0;
        fb_blue_size = 0;
        fb_blue_shift = 0;
    }

    // Get ACPI RSDP — try UEFI config tables first, fallback to physical memory scan
    let rsdp_addr = {
        let mut addr = uefi::system::with_config_table(|tables| {
            tables
                .iter()
                .find(|e| {
                    e.guid == ConfigTableEntry::ACPI2_GUID || e.guid == ConfigTableEntry::ACPI_GUID
                })
                .map(|e| e.address as u64)
                .unwrap_or(0)
        });

        if addr == 0 {
            // Fallback: scan first 1MB of physical memory for RSDP signature
            // PhilOpp pattern: check EBDA pointer, then 0xE0000-0xFFFFF
            addr = scan_for_rsdp();
            if addr != 0 {
                uefi::system::with_stdout(|stdout| {
                    let _ = writeln!(
                        stdout,
                        "[boot] RSDP found via physical memory scan at 0x{:x}",
                        addr
                    );
                });
            } else {
                uefi::system::with_stdout(|stdout| {
                    let _ = writeln!(stdout, "[boot] WARNING: RSDP not found — ACPI unavailable");
                });
            }
        }
        addr
    };

    // Validate RSDP and check XSDT vs RSDT availability
    if rsdp_addr != 0 {
        unsafe {
            let rsdp_ptr = rsdp_addr as *const u8;
            let revision: u8 = core::ptr::read_volatile(rsdp_ptr.add(15));
            if revision >= 2 {
                // ACPI 2.0+ — has XSDT at offset 24
                let xsdt_addr: u64 = core::ptr::read_volatile((rsdp_addr + 24) as *const u64);
                uefi::system::with_stdout(|stdout| {
                    let _ = writeln!(
                        stdout,
                        "[boot] ACPI {} (XSDT at 0x{:x})",
                        revision, xsdt_addr
                    );
                });
                if xsdt_addr == 0 {
                    uefi::system::with_stdout(|stdout| {
                        let _ = writeln!(
                            stdout,
                            "[boot] WARNING: ACPI revision {} but XSDT address is NULL",
                            revision
                        );
                    });
                } else {
                    // Validate XSDT header checksum
                    if validate_acpi_table_header(xsdt_addr) {
                        uefi::system::with_stdout(|stdout| {
                            let _ = writeln!(stdout, "[boot] XSDT header checksum OK");
                        });
                    } else {
                        uefi::system::with_stdout(|stdout| {
                            let _ = writeln!(
                                stdout,
                                "[boot] WARNING: XSDT header checksum invalid at 0x{:x}",
                                xsdt_addr
                            );
                        });
                    }
                }
            } else {
                // ACPI 1.0 — has RSDT at offset 16
                let rsdt_addr: u32 = core::ptr::read_volatile((rsdp_addr + 16) as *const u32);
                uefi::system::with_stdout(|stdout| {
                    let _ = writeln!(
                        stdout,
                        "[boot] ACPI {} (RSDT at 0x{:x})",
                        revision, rsdt_addr as u64
                    );
                });
                if rsdt_addr != 0 {
                    // Validate RSDT header checksum
                    if validate_acpi_table_header(rsdt_addr as u64) {
                        uefi::system::with_stdout(|stdout| {
                            let _ = writeln!(stdout, "[boot] RSDT header checksum OK");
                        });
                    } else {
                        uefi::system::with_stdout(|stdout| {
                            let _ = writeln!(
                                stdout,
                                "[boot] WARNING: RSDT header checksum invalid at 0x{:x}",
                                rsdt_addr
                            );
                        });
                    }
                }
            }
        }
    }

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

    uefi::system::with_stdout(|stdout| {
        let _ = writeln!(stdout, "[boot] ExitBootServices now...");
    });

    let _mmap = uefi::boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get memory map");
    let mmap_iter = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Re-initialize serial port after ExitBootServices
    unsafe {
        // UART 16550 initialization
        let base: u16 = 0x3F8;
        core::arch::asm!("out dx, al", in("al") 0x00u8, in("dx") base + 1, options(nomem, nostack)); // Disable interrupts
        core::arch::asm!("out dx, al", in("al") 0x80u8, in("dx") base + 3, options(nomem, nostack)); // Enable DLAB
        core::arch::asm!("out dx, al", in("al") 0x01u8, in("dx") base + 0, options(nomem, nostack)); // Set divisor lo (115200 baud)
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

    // Step 10: Convert memory map
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
        let size = entry.page_count * 4096;
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

    // Sort regions by base address
    if region_count > 1 {
        let mut sorted = true;
        while sorted {
            sorted = false;
            for i in 0..region_count - 1 {
                if regions[i].base > regions[i + 1].base {
                    regions.swap(i, i + 1);
                    sorted = true;
                }
            }
        }
    }

    // Validate no overlapping regions (merge adjacent same-type regions)
    {
        let mut write = 0;
        let mut read = 0;
        while read < region_count {
            let merged_base = regions[read].base;
            let mut merged_size = regions[read].size;
            let merged_kind = regions[read].kind;
            let mut next = read + 1;
            // Merge adjacent or overlapping regions of same type
            while next < region_count
                && regions[next].kind == merged_kind
                && regions[next].base <= merged_base + merged_size
            {
                let end = regions[next].base + regions[next].size;
                if end > merged_base + merged_size {
                    merged_size = end - merged_base;
                }
                next += 1;
            }
            regions[write] = MemoryRegion {
                base: merged_base,
                size: merged_size,
                kind: merged_kind,
            };
            write += 1;
            read = next;
        }
        region_count = write;
    }

    fn alloc_from_free(
        regions: &mut [MemoryRegion],
        region_count: usize,
        size: u64,
        align: u64,
    ) -> u64 {
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

    let mut mmap_count = region_count;
    let mmap_byte_size = (mmap_count as u64) * (core::mem::size_of::<MemoryRegion>() as u64);
    let mmap_region_size = (mmap_byte_size + 4095) & !4095;
    let mut mmap_region_base = alloc_from_free(&mut regions, region_count, mmap_region_size, 4096);

    if mmap_region_base == 0 {
        // Fallback: fixed location below 1MB (0x100000) that is not used by
        // the kernel or page tables. The page table allocator starts at
        // phys_end, so we must avoid that range. The range MUST be carved out
        // of whatever Free region contains it, otherwise the kernel would see
        // the memory map itself as usable memory.
        const FALLBACK_START: u64 = 0x90000;
        let fallback_end = FALLBACK_START + mmap_region_size;

        let mut containing: Option<usize> = None;
        for (i, region) in regions[..region_count].iter().enumerate() {
            if region.kind == MemoryKind::Free
                && region.base <= FALLBACK_START
                && fallback_end <= region.base + region.size
            {
                containing = Some(i);
                break;
            }
        }

        let Some(idx) = containing else {
            panic!(
                "Failed to place memory map: no free region contains 0x{:x}-0x{:x}",
                FALLBACK_START, fallback_end
            );
        };

        let base = regions[idx].base;
        let end = regions[idx].base + regions[idx].size;

        if FALLBACK_START == base {
            // Range starts at region start: just advance the base.
            regions[idx].base = fallback_end;
            regions[idx].size = end - fallback_end;
        } else if fallback_end == end {
            // Range ends at region end: just shrink the size.
            regions[idx].size = FALLBACK_START - base;
        } else if region_count < regions.len() {
            // Range in the middle: split into [base..FALLBACK_START] and
            // [fallback_end..end], shifting the tail entries to the right.
            regions.copy_within(idx + 1..region_count, idx + 2);
            regions[idx].size = FALLBACK_START - base;
            regions[idx + 1] = MemoryRegion {
                base: fallback_end,
                size: end - fallback_end,
                kind: MemoryKind::Free,
            };
            region_count += 1;
        } else {
            // No slot left for the split: keep only the lower part and warn.
            // The tail above the fallback range becomes untracked (lost).
            uefi::system::with_stdout(|stdout| {
                let _ = writeln!(
                    stdout,
                    "[boot] WARNING: memory map full, losing free space above 0x{:x}",
                    FALLBACK_START
                );
            });
            regions[idx].size = FALLBACK_START - base;
        }

        mmap_region_base = FALLBACK_START;
    }

    // NOTE: the map is copied to its final location only AFTER every
    // alloc_from_free() carve below (stack, module table, env), so the
    // handed-over regions reflect all bootloader allocations.

    let stack_size: u64 = 64 * 1024;
    let guard_page_size: u64 = 4096;
    let total_stack_alloc = guard_page_size + stack_size;
    let stack_region_base = alloc_from_free(&mut regions, region_count, total_stack_alloc, 4096);
    let stack_base = stack_region_base + guard_page_size;

    let module_table_size = modules::module_table_size(module_list.len());
    let module_table_size_aligned = (module_table_size + 4095) & !4095;
    let module_table_base =
        alloc_from_free(&mut regions, region_count, module_table_size_aligned, 4096);

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

    // L6: carve a page for KernelArgs itself so the struct does not live on
    // the (Reclaim-classified) firmware stack after the jump. Untracked
    // carved memory is invisible to the kernel allocator.
    let args_phys = alloc_from_free(&mut regions, region_count, 4096, 4096);
    if args_phys == 0 {
        paging::fatal("[boot] FATAL: cannot place KernelArgs");
    }

    // All carve-outs are done: copy the final region list to its location.
    // The kernel receives a map that already excludes every bootloader
    // allocation (memory map, boot stack, module table, environment, args).
    mmap_count = region_count;
    if mmap_region_base == 0 {
        paging::fatal("[boot] FATAL: memory map has no location");
    }
    unsafe {
        let dst = mmap_region_base as *mut MemoryRegion;
        core::ptr::copy_nonoverlapping(regions.as_ptr(), dst, mmap_count);
    }

    //  Build KernelArgs.
    // L4: kernel_base is the LOWEST loaded physical address and kernel_size
    // spans up to phys_end (which includes the capped BSS margins) — no
    // assumption that segments[] are ordered by address.
    let kernel_phys_lo = elf_info.segments[..elf_info.segment_count]
        .iter()
        .map(|s| s.phys_addr)
        .min()
        .unwrap_or(0);
    let args = KernelArgs {
        magic: strat9_abi::boot::STRAT9_BOOT_MAGIC,
        abi_version: strat9_abi::boot::STRAT9_BOOT_ABI_VERSION,
        kernel_base: kernel_phys_lo,
        kernel_size: elf_info.phys_end.saturating_sub(kernel_phys_lo),
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
            let kernel_virt_base: u64 = 0xFFFF_FFFF_8000_0000;
            let kernel_size = elf_info.phys_end.saturating_sub(kernel_phys_lo);
            let large_pages = ((kernel_size + 0x1FFFFF) / 0x200000).max(1);
            let mapped_end = kernel_virt_base + large_pages * 0x200000;
            let bss_base: u64 = {
                let mut base = kernel_virt_base;
                for i in 0..elf_info.segment_count {
                    if elf_info.segments[i].virt_addr > base {
                        base = elf_info.segments[i].virt_addr;
                    }
                }
                base
            };
            if mapped_end > bss_base {
                mapped_end - bss_base
            } else {
                0
            }
        },
    };

    // Publish KernelArgs at its carved physical location (L6): the struct on
    // this stack frame lives in Reclaim-classified memory after EBS.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &args as *const KernelArgs,
            args_phys as *mut KernelArgs,
            1,
        );
    }
    let args_ptr = args_phys as *const KernelArgs;

    // Page tables and context switch
    // Kernel entry validation
    let kernel_virt_base: u64 = 0xFFFF_FFFF_8000_0000;
    if elf_info.entry == 0 {
        paging::fatal(
            "[boot] FATAL: Kernel entry point is NULL (0x0) — kernel.elf is corrupt or not linked correctly",
        );
    }
    if elf_info.entry < kernel_virt_base {
        // Post-EBS: stdout is gone, warn over COM1 instead.
        paging::serial_write_str(&alloc::format!(
            "[boot] WARNING: Entry point 0x{:x} is below higher-half (0x{:x})\r\n",
            elf_info.entry,
            kernel_virt_base
        ));
    }
    // Verify entry point is within a reasonable mapped range (within 2GB of kernel base)
    let max_mapped = kernel_virt_base + 0x2000_0000; // 2GB higher-half
    if elf_info.entry > max_mapped {
        paging::fatal(&alloc::format!(
            "[boot] FATAL: Entry point 0x{:x} exceeds mapped kernel range (max 0x{:x})",
            elf_info.entry,
            max_mapped
        ));
    }
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
        write_com1(b"[boot] Creating page tables...\r\n");
    }

    // Build the boot page tables: per-segment W^X mapping of the kernel,
    // identity map, framebuffer and env. Table frames are validated against
    // the final memory map (M5).
    let pml4_phys = unsafe {
        paging::create_page_tables(
            &elf_info.segments,
            elf_info.segment_count,
            fb_phys,
            fb_stride as u64 * fb_height as u64,
            env_phys_base,
            env_total_size as u64,
            &regions,
            region_count,
        )
    };

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
        let first_kind: u64 = regions[0].kind.0;
        write_com1(b" first_kind=");
        write_com1(hex_str(first_kind, &mut hexbuf));
        write_com1(b"\r\n");

        // Paging diagnostics
        write_com1(b"[boot] Page table: pml4 at 0x");
        write_com1(hex_str(pml4_phys, &mut hexbuf));
        write_com1(b"\r\n");

        // Verify key PML4 entries
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_pml4e = core::ptr::read_volatile(pml4_ptr);
        let pml4_pml4e_511 = core::ptr::read_volatile(pml4_ptr.add(511));
        write_com1(b"[boot] PML4[0]=0x");
        write_com1(hex_str(pml4_pml4e, &mut hexbuf));
        write_com1(b" PML4[511]=0x");
        write_com1(hex_str(pml4_pml4e_511, &mut hexbuf));
        write_com1(b"\r\n");

        // Verify identity map is present (PML4[0] must have PRESENT bit)
        if pml4_pml4e & 1 == 0 {
            write_com1(b"[boot] FATAL: PML4[0] not present - identity map broken!\r\n");
        }
        // Verify higher-half map is present (PML4[511] must have PRESENT bit)
        if pml4_pml4e_511 & 1 == 0 {
            write_com1(b"[boot] FATAL: PML4[511] not present - higher-half map broken!\r\n");
        }

        write_com1(b"[boot] Jumping to kernel (pause loop)...\r\n");

        // Small delay to let serial flush
        for _ in 0..100000 {
            core::arch::asm!("pause", options(nomem, nostack));
        }

        write_com1(b"[boot] Jumping to kernel (after pause)...\r\n");
    }

    // Pre-set CR4 bits the kernel expects (only safe bits).
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 0x600; // OSFXSR (9) | OSXMMEXCPT (10) — safe on all x86-64
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }

    unsafe {
        // Force the compiler to keep pml4_phys in memory (prevent optimization)
        let pml4_val = core::ptr::read_volatile(&pml4_phys as *const u64);
        let stack_val = stack_base + stack_size;
        let entry_val = elf_info.entry;
        let args_val = args_ptr as u64;

        // Write '>' to serial to confirm we're about to call context_switch
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x3E",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
        paging::context_switch(pml4_val, stack_val, entry_val, args_val);
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
