//! Memory management commands
use crate::shell_println;
use crate::shell::ShellError;
use crate::shell::output::format_bytes;
use alloc::string::String;

/// Display memory status
pub fn cmd_mem(args: &[String]) -> Result<(), ShellError> {
    if args.len() > 0 && args[0] == "zones" {
        return cmd_mem_zones();
    }

    let (total_pages, allocated_pages) = {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            allocator.page_totals()
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    };

    let total_bytes = total_pages * 4096;
    let used_bytes = allocated_pages * 4096;
    let free_bytes = total_bytes - used_bytes;

    let (total_val, total_unit) = format_bytes(total_bytes);
    let (used_val, used_unit) = format_bytes(used_bytes);
    let (free_val, free_unit) = format_bytes(free_bytes);

    shell_println!("Memory status:");
    shell_println!(
        "  Total:     {} {} ({} pages)",
        total_val,
        total_unit,
        total_pages
    );
    shell_println!(
        "  Used:      {} {} ({} pages)",
        used_val,
        used_unit,
        allocated_pages
    );
    shell_println!(
        "  Free:      {} {} ({} pages)",
        free_val,
        free_unit,
        total_pages - allocated_pages
    );
    shell_println!("");

    Ok(())
}

/// Display detailed memory zone information
fn cmd_mem_zones() -> Result<(), ShellError> {
    const MAX_ZONES: usize = 4;
    let mut zones_info = [(0u8, 0u64, 0usize, 0usize); MAX_ZONES]; 
    let mut zone_count = 0;

    {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            zone_count = allocator.zone_snapshot(&mut zones_info);
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    }

    shell_println!("Memory zones:");
    for i in 0..zone_count {
        let (zone_type, base, page_count, allocated) = zones_info[i];
        let total_bytes = page_count * 4096;
        let free_bytes = (page_count - allocated) * 4096;

        let (total_val, total_unit) = format_bytes(total_bytes);
        let (free_val, free_unit) = format_bytes(free_bytes);

        shell_println!("  Zone {:?}:", zone_type_from_u8(zone_type));
        shell_println!("    Base:      0x{:016x}", base);
        shell_println!(
            "    Total:     {} {} ({} pages)",
            total_val,
            total_unit,
            page_count
        );
        shell_println!(
            "    Free:      {} {} ({} pages)",
            free_val,
            free_unit,
            page_count - allocated
        );
        shell_println!("    Used:      {} pages", allocated);
        shell_println!("");
    }

    Ok(())
}

fn zone_type_from_u8(val: u8) -> crate::memory::zone::ZoneType {
    match val {
        0 => crate::memory::zone::ZoneType::DMA,
        1 => crate::memory::zone::ZoneType::Normal,
        2 => crate::memory::zone::ZoneType::HighMem,
        _ => crate::memory::zone::ZoneType::DMA,
    }
}
