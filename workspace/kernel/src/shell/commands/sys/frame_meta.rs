/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Inspect per-frame metadata (issue #38).

use crate::{arch::xshim::PhysAddr, memory, shell::ShellError, shell_println};
use alloc::string::String;

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
