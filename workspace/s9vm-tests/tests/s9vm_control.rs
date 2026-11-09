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

//! L2: encoding of the s9vm control block (real kernel code, not executed).

#[path = "../../kernel/src/s9vm/control.rs"]
mod control;

use control::{
    field, make_eptp, region_size_from_basic, revision_from_basic, FieldWidth,
};

#[test]
fn field_widths_match_architecture_encoding() {
    // Bits 14:13 of the encoding: 00 = 16, 01 = 64, 10 = 32, 11 = natural.
    assert_eq!(FieldWidth::of(field::GUEST_CS_SELECTOR), FieldWidth::Bits16);
    assert_eq!(FieldWidth::of(field::HOST_RIP), FieldWidth::Natural);
    assert_eq!(FieldWidth::of(field::GUEST_EFER), FieldWidth::Bits64);
    assert_eq!(FieldWidth::of(field::EPT_POINTER), FieldWidth::Bits64);
    assert_eq!(
        FieldWidth::of(field::PRIMARY_PROC_BASED_CONTROLS),
        FieldWidth::Bits32
    );
    assert_eq!(FieldWidth::of(field::EXIT_REASON), FieldWidth::Bits32);
    assert_eq!(FieldWidth::of(field::GUEST_RIP), FieldWidth::Natural);
    assert_eq!(FieldWidth::of(field::HOST_RSP), FieldWidth::Natural);
}

#[test]
fn critical_field_encodings_are_stable() {
    // These values are hardware invariants; a regression here would silently
    // break every guest entry.
    assert_eq!(field::GUEST_CR0, 0x6800);
    assert_eq!(field::GUEST_CR3, 0x6802);
    assert_eq!(field::GUEST_CR4, 0x6804);
    assert_eq!(field::GUEST_RSP, 0x681C);
    assert_eq!(field::GUEST_RIP, 0x681E);
    assert_eq!(field::GUEST_RFLAGS, 0x6820);
    assert_eq!(field::GUEST_PENDING_DEBUG_EXCEPTIONS, 0x6822);
    assert_eq!(field::HOST_RSP, 0x6C14);
    assert_eq!(field::HOST_RIP, 0x6C16);
    assert_eq!(field::EXIT_REASON, 0x4402);
    assert_eq!(field::EXIT_INTERRUPT_INFO, 0x4404);
    assert_eq!(field::IDT_VECTORING_INFO, 0x4408);
    assert_eq!(field::SECONDARY_PROC_BASED_CONTROLS, 0x401E);
    assert_eq!(field::TPR_THRESHOLD, 0x401C);
    assert_eq!(field::PLE_GAP, 0x4020);
    assert_eq!(field::PLE_WINDOW, 0x4022);
    assert_eq!(field::EPT_POINTER, 0x201A);
}

#[test]
fn revision_and_size_from_basic_msr() {
    // Revision 0x1A in 31 bits, size 4096 bytes (bits 44:32).
    let basic = 0x1Au64 | (4096u64 << 32);
    assert_eq!(revision_from_basic(basic), 0x1A);
    assert_eq!(region_size_from_basic(basic), 4096);
}

#[test]
fn eptp_encoding_follows_sdm_layout() {
    let root = 0x1234_5000u64;
    let eptp = make_eptp(root, 6, true, true);
    // Bits 2:0 = WB (6), bits 5:3 = 3 (4 levels), bit 6 = A/D.
    assert_eq!(eptp & 0x7, 6);
    assert_eq!((eptp >> 3) & 0x7, 3);
    assert_eq!((eptp >> 6) & 1, 1);
    assert_eq!(eptp & 0x000F_FFFF_FFFF_F000, root);

    let without_ad = make_eptp(root, 6, true, false);
    assert_eq!((without_ad >> 6) & 1, 0);
}

#[test]
fn eptp_masks_low_address_bits() {
    // Bits 11:0 of the root address are reserved: they must be zero.
    let eptp = make_eptp(0x1000_0FFF, 6, true, false);
    assert_eq!(eptp & 0xFFF, 0x1E); // WB type (6) + length (3 << 3)
    assert_eq!(eptp & 0x000F_FFFF_FFFF_F000, 0x1000_0000);
}

#[test]
fn decodes_64bit_tss_descriptor_base() {
    use control::ControlBlock;

    // Synthetic 64-bit TSS descriptor (16 bytes) whose base is
    // split as required by long mode: base[15:0] bytes 2-3,
    // base[23:16] byte 4, base[31:24] byte 7, base[63:32] bytes 8-11.
    // An incorrect decode (shift or forgotten piece) produced a non-canonical
    // address rejected at guest entry (`VMfail(8)`).
    let base: u64 = 0xFFFF_FFFF_808B_1640;
    let limit: u16 = 0x0067;
    let access: u8 = 0x89; // 64-bit TSS available, DPL 0
    let flags: u8 = 0x00;

    let low = (limit as u64)
        | (((base >> 0) & 0xFFFF) << 16)
        | (((base >> 16) & 0xFF) << 32)
        | ((access as u64) << 40)
        | (((base >> 24) & 0xFF) << 56)
        ;
    // Byte 6 (limit 19:16 + flags) inserted between access and high base.
    let low = low | ((flags as u64) << 48);
    let upper = (base >> 32) as u32;

    assert_eq!(ControlBlock::decode_tss_base(low, upper), base);

    // The decoded address must remain canonical (bits 63:48 = 0xFFFF).
    let decoded = ControlBlock::decode_tss_base(low, upper);
    assert_eq!(decoded >> 48, 0xFFFF);
    assert_eq!((decoded >> 47) & 1, 1);
}

#[test]
fn tss_base_decoder_handles_low_addresses() {
    use control::ControlBlock;

    let base: u64 = 0x0000_0000_0040_0000;
    let low = 0x67u64 | ((base & 0xFFFF) << 16) | (((base >> 16) & 0xFF) << 32);
    let upper = (base >> 32) as u32;
    assert_eq!(ControlBlock::decode_tss_base(low, upper), base);
}
