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

//! Host tests for the *guest* ACPI discovery contract.
//!
//! The kernel `AcpiBuilder` produces the firmware image the engine writes into
//! the guest's legacy window; `guest_acpi` is the exact parser the guest
//! kernel runs (included verbatim). These tests keep the two sides compatible:
//! the guest must accept the kernel image, and must reject corrupted tables
//! with the typed error it publishes.

#[path = "../../kernel/src/s9vm/acpi.rs"]
mod acpi;
#[path = "../../guest/s9vm-guest/src/guest_acpi.rs"]
mod guest_acpi;

/// Recomputes the ACPI 1.0 RSDP checksum (byte 8) after editing the 32-bit
/// RSDT field, which is covered by the first-20-byte checksum.
fn reseal_rsdp(window: &mut [u8]) {
    let sum: u8 = window[..20].iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    // The stored checksum is included in the sum, so subtract it first.
    let without = sum.wrapping_sub(window[8]);
    window[8] = 0u8.wrapping_sub(without);
}

/// Builds the kernel ACPI image at the conventional guest window base and
/// places it at the start of a window-sized buffer.
fn kernel_window() -> (Vec<u8>, acpi::AcpiImage) {
    let mut image = vec![0u8; acpi::MAX_IMAGE_LEN];
    let builder = acpi::AcpiBuilder::new(guest_acpi::WINDOW_BASE, &[0u8]);
    let encoded = builder
        .encode(&mut image)
        .expect("kernel ACPI image encodes");
    let mut window = vec![0u8; guest_acpi::WINDOW_LEN];
    window[..encoded.len].copy_from_slice(&image[..encoded.len]);
    (window, encoded)
}

#[test]
fn guest_accepts_the_kernel_acpi_image() {
    let (window, _) = kernel_window();
    assert_eq!(
        guest_acpi::find_rsdp(&window),
        Some(0),
        "the RSDP must be at the window base"
    );
    let info = guest_acpi::scan(&window).expect("guest must accept the kernel image");
    assert!(info.xsdt, "the kernel RSDP revision 2 must select the XSDT");
    assert!(info.madt, "the MADT must be discovered");
    assert!(info.fadt, "the FADT must be discovered");
    assert!(info.tables >= 2, "XSDT lists FADT and MADT");
}

#[test]
fn guest_rejects_a_missing_rsdp() {
    let window = vec![0u8; guest_acpi::WINDOW_LEN];
    assert!(matches!(
        guest_acpi::scan(&window),
        Err(guest_acpi::AcpiError::NoRsdp)
    ));
    assert_eq!(guest_acpi::AcpiError::NoRsdp.code(), 1);
}

#[test]
fn guest_falls_back_to_the_rsdt_root() {
    let (mut window, encoded) = kernel_window();
    // Corrupt the XSDT signature: the RSDP still validates, the XSDT walk is
    // rejected and the legacy RSDT view must still provide the tables.
    window[encoded.xsdt_offset] = b'Z';
    let info = guest_acpi::scan(&window).expect("RSDT fallback must succeed");
    assert!(!info.xsdt, "the XSDT was unusable, the RSDT was used");
    assert!(info.madt);
    assert!(info.fadt);
}

#[test]
fn guest_rejects_a_corrupted_root_table() {
    let (mut window, encoded) = kernel_window();
    // Corrupt both root tables: no fallback can succeed.
    window[encoded.xsdt_offset] = b'Z';
    window[encoded.rsdt_offset.expect("kernel image has a RSDT")] = b'Z';
    assert!(matches!(
        guest_acpi::scan(&window),
        Err(guest_acpi::AcpiError::BadRootTable)
    ));
}

#[test]
fn guest_rejects_a_corrupted_listed_table() {
    let (mut window, encoded) = kernel_window();
    // Flip a byte inside the first listed table (FADT) without fixing its
    // checksum: the walk must reject it.
    window[encoded.fadt_offset + 40] ^= 0xFF;
    assert!(matches!(
        guest_acpi::scan(&window),
        Err(guest_acpi::AcpiError::BadTable)
    ));
}

#[test]
fn guest_falls_back_when_the_xsdt_pointer_is_out_of_window() {
    let (mut window, _) = kernel_window();
    // XSDT pointer field of the RSDP lives at offset 24.
    window[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let info = guest_acpi::scan(&window).expect("RSDT fallback must succeed");
    assert!(info.madt);
}

#[test]
fn guest_rejects_an_out_of_window_root_pointer_when_no_fallback_exists() {
    let (mut window, _) = kernel_window();
    // Break both root pointers: the XSDT is out of the window and the RSDT
    // pointer is cleared, so no root table can be followed.
    window[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    window[16..20].copy_from_slice(&0u32.to_le_bytes());
    reseal_rsdp(&mut window);
    assert!(matches!(
        guest_acpi::scan(&window),
        Err(guest_acpi::AcpiError::BadRoot)
    ));
}
