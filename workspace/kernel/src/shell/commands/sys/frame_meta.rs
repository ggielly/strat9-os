//! Inspect per-frame metadata (issue #38).

use crate::{memory, shell::ShellError, shell_println};
use alloc::string::String;
use x86_64::PhysAddr;

/// `frame-meta <phys_hex>` : print generation, guard bits, and vtable bits for one physical frame.
pub fn cmd_frame_meta(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: frame-meta <phys_hex>");
        return Ok(());
    }

    let raw = args[1].as_str();
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let addr = u64::from_str_radix(hex, 16).map_err(|_| ShellError::InvalidArguments)?;

    let (gen, guard, vtab) = memory::frame_meta_debug_snapshot(PhysAddr::new(addr));
    shell_println!(
        "frame phys={:#x} generation={} guard={:#x} vtable_bits={:#x}",
        addr,
        gen,
        guard,
        vtab
    );
    Ok(())
}
