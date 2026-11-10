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

//! L2: guest boot parameters block (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/bootparams.rs"]
mod bootparams;

use bootparams::{
    BootParams, BootParamsError, CMDLINE_MAX, CMDLINE_OFFSET, MAX_MEMORY_ENTRIES,
    MAX_MODULE_ENTRIES, MEMORY_ENTRY_SIZE, MEMORY_OFFSET, MODULE_ENTRY_SIZE, MODULE_OFFSET,
    OFF_CHECKSUM, OFF_CMDLINE_LEN, OFF_FLAGS, OFF_MAGIC, OFF_MEMORY_COUNT, OFF_MODULE_COUNT,
    OFF_RSDP_GPA, OFF_SIZE, OFF_VERSION, SIZE, flags, memory_kind,
};

/// Encodes a block into an exact-size buffer.
fn encode(params: &BootParams) -> [u8; SIZE] {
    let mut bytes = [0u8; SIZE];
    params.encode(&mut bytes);
    bytes
}

/// Sum of the block bytes modulo 256.
fn checksum(bytes: &[u8]) -> u8 {
    bytes[..SIZE]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

/// Recomputes the checksum byte of a tampered block.
fn reseal(bytes: &mut [u8; SIZE]) {
    bytes[OFF_CHECKSUM] = 0;
    bytes[OFF_CHECKSUM] = 0u8.wrapping_sub(checksum(bytes));
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[test]
fn wire_constants_match_layout() {
    assert_eq!(SIZE, 1024);
    assert_eq!(bootparams::VERSION, 1);
    assert_eq!(bootparams::MAGIC, u64::from_le_bytes(*b"S9VMBP\0\0"));
    assert_eq!(MAX_MEMORY_ENTRIES, 32);
    assert_eq!(MAX_MODULE_ENTRIES, 4);
    assert_eq!(CMDLINE_MAX, 256);
    assert_eq!(MEMORY_ENTRY_SIZE, 20);
    assert_eq!(MODULE_ENTRY_SIZE, 16);
    assert_eq!(MEMORY_OFFSET, 0x38);
    assert_eq!(
        MEMORY_OFFSET + MAX_MEMORY_ENTRIES * MEMORY_ENTRY_SIZE,
        MODULE_OFFSET
    );
    assert_eq!(
        MODULE_OFFSET + MAX_MODULE_ENTRIES * MODULE_ENTRY_SIZE,
        CMDLINE_OFFSET
    );
    assert_eq!(CMDLINE_OFFSET + CMDLINE_MAX, SIZE - 8);
    assert_eq!(OFF_CHECKSUM, 0x34);
}

#[test]
fn defaults_are_empty_and_valid() {
    let params = BootParams::new();
    assert_eq!(params, BootParams::default());
    assert_eq!(params.flags(), 0);
    assert_eq!(params.rsdp_gpa(), 0);
    assert_eq!(params.console_mmio_base(), 0);
    assert_eq!(params.console_irq_line(), 0);
    assert_eq!(params.memory_count(), 0);
    assert_eq!(params.module_count(), 0);
    assert_eq!(params.cmdline_len(), 0);
    assert!(params.memory().is_empty());
    assert!(params.modules().is_empty());
    assert!(params.cmdline().is_empty());
    assert_eq!(params.validate(), Ok(()));
}

#[test]
fn encode_sets_header_and_checksum() {
    let mut params = BootParams::new();
    params.set_rsdp(0x000E_0000);
    params.set_console(0x0A00_0000, 16);
    params
        .set_flags(flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT)
        .expect("valid flags");
    params
        .add_memory(0, 0x10_0000, memory_kind::USABLE)
        .expect("entry fits");
    params.set_cmdline(b"console=ttyS0").expect("short cmdline");

    let bytes = encode(&params);
    assert_eq!(u64_at(&bytes, OFF_MAGIC), bootparams::MAGIC);
    assert_eq!(u32_at(&bytes, OFF_VERSION), bootparams::VERSION);
    assert_eq!(u32_at(&bytes, OFF_SIZE) as usize, SIZE);
    assert_eq!(u32_at(&bytes, OFF_MEMORY_COUNT), 1);
    assert_eq!(u32_at(&bytes, OFF_MODULE_COUNT), 0);
    assert_eq!(u32_at(&bytes, OFF_CMDLINE_LEN), 13);
    assert_eq!(u64_at(&bytes, OFF_RSDP_GPA), 0x000E_0000);
    assert_eq!(
        u32_at(&bytes, OFF_FLAGS),
        flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT
    );
    assert_eq!(checksum(&bytes), 0);
    // The command line is inline and NUL padded, never NUL terminated.
    assert_eq!(
        &bytes[CMDLINE_OFFSET..CMDLINE_OFFSET + 13],
        b"console=ttyS0".as_slice()
    );
    assert!(
        bytes[CMDLINE_OFFSET + 13..CMDLINE_OFFSET + CMDLINE_MAX]
            .iter()
            .all(|byte| *byte == 0)
    );
    // The 8 bytes after the command-line field are reserved zero.
    assert!(bytes[SIZE - 8..].iter().all(|byte| *byte == 0));
}

#[test]
fn rich_block_roundtrips() {
    let mut params = BootParams::new();
    params.set_rsdp(0x000E_0000);
    params.set_console(0x0A00_0000, 16);
    params
        .set_flags(flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT | flags::NETWORK_PRESENT)
        .expect("valid flags");
    params
        .add_memory(0, 0x9_F000, memory_kind::USABLE)
        .expect("fits");
    params
        .add_memory(0xA0000, 0x1_0000, memory_kind::RESERVED)
        .expect("fits");
    params
        .add_memory(0x1_0000, 0x20_0000, memory_kind::MMIO)
        .expect("fits");
    params
        .add_memory(0xE_0000, 0x20_000, memory_kind::ACPI_RECLAIMABLE)
        .expect("fits");
    params.add_module(0x4000_0000, 0x80_0000).expect("fits");
    params.add_module(0x4080_0000, 0x10_000).expect("fits");
    params
        .set_cmdline(b"console=ttyS0 root=/dev/vda init=/sbin/init")
        .expect("fits");

    let bytes = encode(&params);
    let decoded = BootParams::decode(&bytes).expect("valid block");
    assert_eq!(decoded, params);
    assert_eq!(decoded.rsdp_gpa(), 0x000E_0000);
    assert_eq!(decoded.console_mmio_base(), 0x0A00_0000);
    assert_eq!(decoded.console_irq_line(), 16);
    assert_eq!(decoded.memory().len(), 4);
    assert_eq!(decoded.memory()[0].kind, memory_kind::USABLE);
    assert_eq!(decoded.memory()[3].kind, memory_kind::ACPI_RECLAIMABLE);
    assert_eq!(decoded.modules().len(), 2);
    assert_eq!(decoded.modules()[1].base, 0x4080_0000);
    assert_eq!(decoded.modules()[1].len, 0x10_000);
    assert_eq!(decoded.cmdline(), params.cmdline());
    assert_eq!(
        decoded.flags(),
        flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT | flags::NETWORK_PRESENT
    );
}

#[test]
fn memory_capacity_is_enforced() {
    let mut params = BootParams::new();
    for index in 0..MAX_MEMORY_ENTRIES {
        let base = 0x10_0000 + (index as u64) * 0x10_000;
        params
            .add_memory(base, 0x10_000, memory_kind::USABLE)
            .expect("entry fits");
    }
    assert_eq!(params.memory_count(), MAX_MEMORY_ENTRIES);
    assert_eq!(
        params.add_memory(0, 0x1000, memory_kind::USABLE),
        Err(BootParamsError::TooManyMemoryEntries)
    );
    let decoded = BootParams::decode(&encode(&params)).expect("valid block");
    assert_eq!(decoded.memory_count(), MAX_MEMORY_ENTRIES);
    assert_eq!(
        decoded.memory()[MAX_MEMORY_ENTRIES - 1].kind,
        memory_kind::USABLE
    );
}

#[test]
fn memory_kind_is_validated() {
    let mut params = BootParams::new();
    assert_eq!(
        params.add_memory(0, 0x1000, 0),
        Err(BootParamsError::BadMemoryKind)
    );
    assert_eq!(
        params.add_memory(0, 0x1000, memory_kind::MMIO + 1),
        Err(BootParamsError::BadMemoryKind)
    );
    for kind in memory_kind::ALL {
        params.add_memory(0x1000, 0x1000, kind).expect("valid kind");
    }
    assert_eq!(params.memory_count(), memory_kind::ALL.len());
    assert_eq!(params.validate(), Ok(()));
}

#[test]
fn module_capacity_is_enforced() {
    let mut params = BootParams::new();
    for index in 0..MAX_MODULE_ENTRIES {
        params
            .add_module(0x4000_0000 + (index as u64) * 0x100_0000, 0x100_0000)
            .expect("module fits");
    }
    assert_eq!(params.module_count(), MAX_MODULE_ENTRIES);
    assert_eq!(
        params.add_module(0, 0x1000),
        Err(BootParamsError::TooManyModules)
    );
    assert_eq!(
        BootParams::decode(&encode(&params))
            .expect("valid block")
            .module_count(),
        MAX_MODULE_ENTRIES
    );
}

#[test]
fn cmdline_max_is_enforced() {
    let mut params = BootParams::new();
    let full = [b'x'; CMDLINE_MAX];
    params.set_cmdline(&full).expect("256 bytes fit");
    assert_eq!(params.cmdline_len(), CMDLINE_MAX);
    // A 256-byte command line fills the field: no NUL terminator.
    assert_eq!(params.cmdline(), full);
    let decoded = BootParams::decode(&encode(&params)).expect("valid block");
    assert_eq!(decoded.cmdline(), full);
    assert_eq!(decoded.cmdline_len(), CMDLINE_MAX);

    let too_long = [b'x'; CMDLINE_MAX + 1];
    assert_eq!(
        params.set_cmdline(&too_long),
        Err(BootParamsError::CmdlineTooLong)
    );
    assert_eq!(params.cmdline_len(), CMDLINE_MAX);
}

#[test]
fn cmdline_replacement_clears_padding() {
    let mut params = BootParams::new();
    params.set_cmdline(&[b'A'; 200]).expect("fits");
    params.set_cmdline(b"quiet").expect("fits");
    assert_eq!(params.cmdline(), b"quiet");
    let bytes = encode(&params);
    assert_eq!(u32_at(&bytes, OFF_CMDLINE_LEN), 5);
    assert!(
        bytes[CMDLINE_OFFSET + 5..CMDLINE_OFFSET + CMDLINE_MAX]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn checksum_corruption_is_rejected() {
    let mut params = BootParams::new();
    params
        .add_memory(0x1_0000, 0x10_0000, memory_kind::USABLE)
        .expect("fits");
    params.set_cmdline(b"root=/dev/vda").expect("fits");
    let mut bytes = encode(&params);
    bytes[MEMORY_OFFSET] ^= 0x01;
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::BadChecksum)
    );

    let mut bytes = encode(&params);
    bytes[CMDLINE_OFFSET] ^= 0x80;
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::BadChecksum)
    );
}

#[test]
fn bad_magic_is_rejected() {
    let params = BootParams::new();
    let mut bytes = encode(&params);
    bytes[OFF_MAGIC] ^= 0xFF;
    reseal(&mut bytes);
    assert_eq!(BootParams::decode(&bytes), Err(BootParamsError::BadMagic));
}

#[test]
fn bad_version_is_rejected() {
    let params = BootParams::new();
    let mut bytes = encode(&params);
    bytes[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&2u32.to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(BootParams::decode(&bytes), Err(BootParamsError::BadVersion));
}

#[test]
fn bad_size_is_rejected() {
    let params = BootParams::new();
    let mut bytes = encode(&params);
    bytes[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&((SIZE - 8) as u32).to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(BootParams::decode(&bytes), Err(BootParamsError::BadSize));
}

#[test]
fn truncated_input_is_rejected() {
    let params = BootParams::new();
    let bytes = encode(&params);
    for length in [0usize, 1, 8, SIZE / 2, SIZE - 1] {
        assert_eq!(
            BootParams::decode(&bytes[..length]),
            Err(BootParamsError::Truncated)
        );
    }
    // A longer slice is accepted: trailing bytes are ignored.
    let mut longer = [0u8; SIZE + 16];
    longer[..SIZE].copy_from_slice(&bytes);
    assert_eq!(BootParams::decode(&longer), Ok(params));
}

#[test]
fn counts_out_of_range_are_rejected() {
    let params = BootParams::new();
    let mut bytes = encode(&params);
    bytes[OFF_MEMORY_COUNT..OFF_MEMORY_COUNT + 4]
        .copy_from_slice(&((MAX_MEMORY_ENTRIES + 1) as u32).to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::TooManyMemoryEntries)
    );

    let mut bytes = encode(&params);
    bytes[OFF_MODULE_COUNT..OFF_MODULE_COUNT + 4]
        .copy_from_slice(&((MAX_MODULE_ENTRIES + 1) as u32).to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::TooManyModules)
    );

    let mut bytes = encode(&params);
    bytes[OFF_MEMORY_COUNT..OFF_MEMORY_COUNT + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::TooManyMemoryEntries)
    );
}

#[test]
fn cmdline_length_out_of_range_is_rejected() {
    let params = BootParams::new();
    let mut bytes = encode(&params);
    bytes[OFF_CMDLINE_LEN..OFF_CMDLINE_LEN + 4]
        .copy_from_slice(&((CMDLINE_MAX + 1) as u32).to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::CmdlineTooLong)
    );

    let mut bytes = encode(&params);
    bytes[OFF_CMDLINE_LEN..OFF_CMDLINE_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::CmdlineTooLong)
    );
}

#[test]
fn reserved_flags_are_rejected() {
    let mut params = BootParams::new();
    assert_eq!(params.set_flags(0x8), Err(BootParamsError::BadFlags));
    assert_eq!(params.set_flags(u32::MAX), Err(BootParamsError::BadFlags));
    assert_eq!(params.flags(), 0);

    let mut bytes = encode(&params);
    bytes[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&0x8u32.to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(BootParams::decode(&bytes), Err(BootParamsError::BadFlags));
}

#[test]
fn bad_memory_kind_is_rejected_on_decode() {
    let mut params = BootParams::new();
    params
        .add_memory(0x1_0000, 0x1000, memory_kind::USABLE)
        .expect("fits");
    let mut bytes = encode(&params);
    // kind is the third field of the first packed entry (base +8, len +8).
    let kind_offset = MEMORY_OFFSET + 16;
    bytes[kind_offset..kind_offset + 4].copy_from_slice(&7u32.to_le_bytes());
    reseal(&mut bytes);
    assert_eq!(
        BootParams::decode(&bytes),
        Err(BootParamsError::BadMemoryKind)
    );
}

#[test]
fn console_and_flags_roundtrip() {
    let mut params = BootParams::new();
    params.set_console(0x0A00_0000, 17);
    assert_eq!(params.flags(), flags::CONSOLE_PRESENT);
    params
        .set_flags(flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT)
        .expect("valid flags");
    let decoded = BootParams::decode(&encode(&params)).expect("valid block");
    assert_eq!(decoded.console_mmio_base(), 0x0A00_0000);
    assert_eq!(decoded.console_irq_line(), 17);
    assert_eq!(
        decoded.flags(),
        flags::CONSOLE_PRESENT | flags::BLOCK_PRESENT
    );
}

#[test]
fn encoding_is_deterministic() {
    let mut first = BootParams::new();
    first
        .add_memory(0, 0x9_F000, memory_kind::USABLE)
        .expect("fits");
    first.add_module(0x4000_0000, 0x100_0000).expect("fits");
    first.set_cmdline(b"quiet").expect("fits");
    first.set_rsdp(0x000E_0000);

    let second = first;
    for _ in 0..3 {
        assert_eq!(encode(&first), encode(&second));
    }

    let mut different = first;
    different.set_cmdline(b"debug").expect("fits");
    assert_ne!(encode(&first), encode(&different));
}

#[test]
fn adversarial_bytes_never_panic() {
    // Neither a valid checksum nor valid fields: every pattern must be
    // rejected without panicking (the checksum is verified first).
    for seed in 1..=8u8 {
        let mut bytes = [0u8; SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(seed).wrapping_add(7);
        }
        assert!(BootParams::decode(&bytes).is_err());
        // Also try a valid header magic with garbage everywhere else.
        bytes[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&bootparams::MAGIC.to_le_bytes());
        assert!(BootParams::decode(&bytes).is_err());
        // And varying lengths around the block size.
        for length in [0usize, 1, SIZE - 1, SIZE] {
            let _ = BootParams::decode(&bytes[..length]);
        }
    }
}
