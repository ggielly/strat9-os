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

//! Kernel symbol table for panic backtrace resolution.
//!
//! Parses the kernel's own ELF `.symtab`/`.strtab` sections at boot time
//! to provide function name resolution during panics.

use core::sync::atomic::{AtomicBool, Ordering};

use strat9_elf_core::{Header, Symbol};

/// A single symbol entry: address, size, name offset in string table.
#[derive(Clone, Copy)]
struct KernelSymbol {
    addr: u64,
    size: u64,
    name_offset: u32,
}

/// Global sorted symbol table and string table.
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut SYMBOLS: [KernelSymbol; 8192] = [KernelSymbol {
    addr: 0,
    size: 0,
    name_offset: 0,
}; 8192];
static mut SYMBOL_COUNT: usize = 0;
static mut STRTAB: [u8; 65536] = [0; 65536];
static mut STRTAB_LEN: usize = 0;

/// Initialize the symbol table from the kernel ELF. Called once during early boot.
pub fn init() {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let elf_bytes = match super::dtb_boot::kernel_elf_bytes() {
        Some(b) => b,
        None => return,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let elf_bytes: &[u8] = &[];

    let elf = match Header::parse(elf_bytes) {
        Ok(header) => header,
        Err(_) => return,
    };

    // Find .strtab section
    let Some(strtab_data) = section_data(&elf, elf_bytes, ".strtab") else {
        return;
    };
    if strtab_data.is_empty() {
        return;
    }
    let copy_len = strtab_data.len().min(65536);
    unsafe {
        STRTAB[..copy_len].copy_from_slice(&strtab_data[..copy_len]);
        STRTAB_LEN = copy_len;
    }

    // Find .symtab section
    let Some(symtab_data) = section_data(&elf, elf_bytes, ".symtab") else {
        return;
    };
    if symtab_data.is_empty() {
        return;
    }

    // Parse symbol entries (shared ELF64 symbol decoder).
    let max = 8192;
    let mut n = 0usize;

    for symbol in Symbol::iter(symtab_data) {
        if n == max {
            break;
        }
        // Skip undefined symbols (st_value == 0)
        if symbol.value == 0 {
            continue;
        }

        unsafe {
            SYMBOLS[n] = KernelSymbol {
                addr: symbol.value,
                size: symbol.size,
                name_offset: symbol.name,
            };
        }
        n += 1;
    }

    // Sort by address for binary search
    unsafe {
        SYMBOL_COUNT = n;
        let syms = &mut SYMBOLS[..n];
        syms.sort_unstable_by_key(|s| s.addr);
    }

    INITIALIZED.store(true, Ordering::Release);
}

/// Find a section's data by name in the ELF image.
fn section_data<'a>(header: &Header, file: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let section = header.find_section(file, name).ok().flatten()?;
    section.data(file).ok()
}

/// Look up an address in the symbol table. Returns (name, offset_from_symbol).
/// Uses binary search for O(log n) lookup.
pub fn lookup(addr: u64) -> Option<(&'static str, u64)> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let syms = unsafe { &SYMBOLS[..SYMBOL_COUNT] };

    // Binary search: find the last symbol with addr <= target
    let idx = match syms.binary_search_by_key(&addr, |s| s.addr) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                return None;
            }
            i - 1
        }
    };

    let sym = &syms[idx];
    let offset = addr.saturating_sub(sym.addr);

    // Check if addr is within the symbol's size (if size > 0)
    if sym.size > 0 && offset >= sym.size {
        return None;
    }

    let name = get_symbol_name(sym.name_offset);
    Some((name, offset))
}

/// Report whether the ELF symbol table was loaded and how many entries it has.
/// This is useful in panic output to distinguish an unknown address from a
/// missing symbol table in the boot image.
pub fn status() -> (bool, usize) {
    let initialized = INITIALIZED.load(Ordering::Acquire);
    let count = if initialized {
        // Initialization completes before normal task scheduling starts.
        unsafe { SYMBOL_COUNT }
    } else {
        0
    };
    (initialized, count)
}

/// Get a symbol name from the string table.
fn get_symbol_name(offset: u32) -> &'static str {
    let off = offset as usize;
    let tab = unsafe { &STRTAB[..STRTAB_LEN] };
    if off >= tab.len() {
        return "<unknown>";
    }
    let end = tab[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(tab.len());
    core::str::from_utf8(&tab[off..end]).unwrap_or("<unknown>")
}
