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

//! s9vm — static ACPI tables presented to guests.
//!
//! A guest discovers the machine it runs on through firmware description
//! tables: the `RSDP` points at the `XSDT`, which lists the `FADT` and the
//! `MADT`, and the `FADT` points at a `DSDT` holding the (minimal) AML
//! namespace. s9vm has no firmware image, so the kernel synthesises these
//! tables with pure code and copies them into one guest-physical window; this
//! module builds that window.
//!
//! # Image layout
//!
//! [`AcpiBuilder`] first computes an [`AcpiLayout`] (total size and the offset
//! of every table), then [`AcpiBuilder::encode`] writes a byte image of
//! exactly that size. Offsets are relative to the image; every pointer stored
//! inside a table is `image_base + offset`, which is why the caller chooses
//! the guest-physical base address. Layout of the image:
//!
//! | Offset | Table | Size |
//! |---|---|---|
//! | 0 | RSDP revision 2 | 36 |
//! | 64-aligned | XSDT (lists FADT, MADT) | 52 |
//! | 64-aligned | FADT revision 6 | 276 |
//! | 64-aligned | MADT (local APICs, I/O APIC, ISA overrides) | 44 + entries |
//! | 64-aligned, optional | RSDT v1 view (lists FADT, MADT) | 44 |
//! | 64-aligned | DSDT (`Scope (\_SB) {}`) | 43 |
//!
//! Each table starts on a 64-byte boundary and the image itself must be copied
//! to a 16-byte aligned guest-physical address, so every table is aligned as
//! the ACPI specification requires. The RSDP sits at offset [`RSDP_OFFSET`]
//! (zero), hence at the image base: placing the image at a 16-byte aligned
//! address inside the conventional low firmware window
//! (`0x000E_0000..=0x000F_FFFF`) makes it discoverable by the standard guest
//! search of the EBDA and of that window.
//!
//! Every table carries its own checksum (the bytes of the table sum to zero
//! modulo 256); the RSDP additionally carries the ACPI 1.0 checksum over its
//! first 20 bytes, so legacy guests can validate it even though the `XSDT`
//! pointer is the one they should follow.
//!
//! The image is bounded by [`MAX_IMAGE_LEN`] (32 KiB), which keeps it inside
//! the low window. Building never panics: invalid input (no vCPU, too many
//! vCPUs, duplicate APIC ids, misaligned or unrepresentable base, oversized
//! image, short output buffer) is reported as an [`AcpiError`].
//!
//! This module is pure `core` code and is host-tested by `s9vm-tests`.

/// Guest-physical alignment required for the image base (ACPI RSDP rule).
pub const IMAGE_ALIGN: u64 = 16;
/// Alignment of every table inside the image (conservative cache-line align).
pub const TABLE_ALIGN: usize = 64;
/// Maximum size of the encoded image, in bytes.
pub const MAX_IMAGE_LEN: usize = 32 * 1024;
/// Offset of the RSDP inside the image (always zero).
pub const RSDP_OFFSET: usize = 0;
/// Length of the ACPI 1.0 part of the RSDP, covered by its first checksum.
pub const RSDP_V1_LEN: usize = 20;
/// Length of the RSDP revision 2 structure.
pub const RSDP_LEN: usize = 36;
/// Length of a standard ACPI system description table header.
pub const SDT_HEADER_LEN: usize = 36;
/// Length of the XSDT: header plus one 64-bit pointer per listed table.
pub const XSDT_LEN: usize = SDT_HEADER_LEN + 3 * 8;
/// Length of the RSDT v1 view: header plus one 32-bit pointer per table.
pub const RSDT_LEN: usize = SDT_HEADER_LEN + 3 * 4;
/// Length of the FADT revision 6 layout.
pub const FADT_LEN: usize = 276;
/// Length of the MADT fixed header.
pub const MADT_HEADER_LEN: usize = 44;

/// Signature of the root pointer structure.
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
/// Revision of the emitted RSDP (ACPI 2.0 and later).
pub const RSDP_REVISION: u8 = 2;
/// Signature of the extended root system description table.
pub const XSDT_SIGNATURE: &[u8; 4] = b"XSDT";
/// Revision of the emitted XSDT.
pub const XSDT_REVISION: u8 = 1;
/// Signature of the legacy root system description table.
pub const RSDT_SIGNATURE: &[u8; 4] = b"RSDT";
/// Revision of the emitted RSDT.
pub const RSDT_REVISION: u8 = 1;
/// Signature of the fixed ACPI description table.
pub const FADT_SIGNATURE: &[u8; 4] = b"FACP";
/// Revision of the emitted FADT (ACPI 6.x layout).
pub const FADT_REVISION: u8 = 6;
/// Signature of the multiple APIC description table.
pub const MADT_SIGNATURE: &[u8; 4] = b"APIC";
/// Revision of the emitted MADT (ACPI 6.x, includes x2APIC entries).
pub const MADT_REVISION: u8 = 5;
/// Signature of the differentiated system description table.
pub const DSDT_SIGNATURE: &[u8; 4] = b"DSDT";
/// Revision of the emitted DSDT (ACPI 2.0 names).
pub const DSDT_REVISION: u8 = 2;
/// Signature of the serial port console redirection table.
pub const SPCR_SIGNATURE: &[u8; 4] = b"SPCR";
/// Revision of the emitted SPCR (ACPI 6.x layout).
pub const SPCR_REVISION: u8 = 2;
/// Length of the SPCR table.
pub const SPCR_LEN: usize = 80;
/// SPCR interface type: 8250/16550-compatible UART.
pub const SPCR_INTERFACE_16550: u8 = 0;
/// SPCR interrupt type: the line is delivered through the I/O APIC.
pub const SPCR_INTERRUPT_IOAPIC: u8 = 1;
/// SPCR baud-rate selector: 115200 baud.
pub const SPCR_BAUD_115200: u8 = 4;
/// SPCR parity selector: none.
pub const SPCR_PARITY_NONE: u8 = 0;
/// SPCR stop-bit selector: one stop bit.
pub const SPCR_STOP_ONE: u8 = 1;
/// SPCR flow-control selector: none.
pub const SPCR_FLOW_NONE: u8 = 0;
/// SPCR terminal type: VT-100 (the value used by PC firmware).
pub const SPCR_TERMINAL_VT100: u8 = 0;
/// COM1 I/O port exposed through the SPCR programming interface.
pub const SPCR_COM1_PORT: u16 = 0x3F8;
/// Global system interrupt COM1 is wired to (ISA IRQ4, identity-mapped).
pub const SPCR_COM1_GSI: u32 = 4;

/// OEM id written in every table header (six ASCII bytes).
pub const OEM_ID: &[u8; 6] = b"S9VM  ";
/// OEM table id written in every table header (eight ASCII bytes).
pub const OEM_TABLE_ID: &[u8; 8] = b"S9VMACPI";
/// OEM revision written in every table header.
pub const OEM_REVISION: u32 = 1;
/// Creator id written in every table header (four ASCII bytes).
pub const CREATOR_ID: &[u8; 4] = b"S9VM";
/// Creator revision written in every table header.
pub const CREATOR_REVISION: u32 = 1;

/// Guest-physical address of the virtual local APIC page.
pub const LOCAL_APIC_ADDRESS: u32 = 0xFEE0_0000;
/// `Enabled` bit of a MADT local APIC / x2APIC entry.
pub const LOCAL_APIC_ENABLED: u32 = 1;
/// MADT flags: the machine is PC/AT compatible (dual 8259 present).
pub const MADT_PCAT_COMPAT: u32 = 1;
/// Id of the modelled I/O APIC.
pub const IOAPIC_ID: u8 = 0;
/// Guest-physical address of the modelled I/O APIC page.
pub const IOAPIC_ADDRESS: u32 = 0xFEC0_0000;
/// First GSI handled by the modelled I/O APIC.
pub const IOAPIC_GSI_BASE: u32 = 0;
/// Bus id of the legacy ISA interrupt source bus.
pub const ISA_BUS: u8 = 0;
/// Number of legacy ISA interrupt lines (IRQ0..=IRQ15).
pub const ISA_IRQ_COUNT: usize = 16;
/// Maximum number of vCPUs described by one image.
pub const MAX_VCPUS: usize = 64;

/// Length of a MADT local APIC entry (type 0).
pub const LOCAL_APIC_ENTRY_LEN: usize = 8;
/// Length of a MADT local x2APIC entry (type 9).
pub const LOCAL_X2APIC_ENTRY_LEN: usize = 16;
/// Length of a MADT I/O APIC entry (type 1).
pub const IOAPIC_ENTRY_LEN: usize = 12;
/// Length of a MADT interrupt source override entry (type 2).
pub const INT_SOURCE_OVERRIDE_LEN: usize = 10;

/// SCI interrupt line (ISA IRQ 9, level, active high).
pub const SCI_IRQ: u16 = 9;
/// 32-bit I/O port of the PM1a event block.
pub const PM1A_EVENT_BLOCK: u32 = 0x0600;
/// 32-bit I/O port of the PM1a control block.
pub const PM1A_CONTROL_BLOCK: u32 = 0x0604;
/// 32-bit I/O port of the ACPI power management timer.
pub const PM_TIMER_BLOCK: u32 = 0x0608;
/// 32-bit I/O port of the GPE0 block.
pub const GPE0_BLOCK: u32 = 0xAFE0;
/// Length in bytes of the PM1 event blocks.
pub const PM1_EVENT_LENGTH: u8 = 4;
/// Length in bytes of the PM1 control blocks.
pub const PM1_CONTROL_LENGTH: u8 = 2;
/// Length in bytes of the PM timer block.
pub const PM_TIMER_LENGTH: u8 = 4;
/// Length in bytes of the GPE0 block.
pub const GPE0_LENGTH: u8 = 4;
/// I/O port of the ACPI reset register.
pub const RESET_REGISTER_PORT: u64 = 0x0CF9;
/// Value written to [`RESET_REGISTER_PORT`] to reset the machine.
pub const RESET_VALUE: u8 = 0x0E;
/// FADT flag: `WBINVD` is supported.
pub const FADT_FLAG_WBINVD: u32 = 1 << 0;
/// FADT flag: the reset register fields are valid.
pub const FADT_FLAG_RESET_REG_SUP: u32 = 1 << 10;
/// FADT flags emitted by the builder.
pub const FADT_FLAGS: u32 = FADT_FLAG_WBINVD | FADT_FLAG_RESET_REG_SUP;
/// FADT `P_LVL2_LAT` value meaning "C2 not supported".
pub const P_LVL2_LATENCY: u16 = 101;
/// FADT `P_LVL3_LAT` value meaning "C3 not supported".
pub const P_LVL3_LATENCY: u16 = 1001;
/// FADT `CENTURY` value: the CMOS RTC exposes its century byte at 0x32.
pub const RTC_CENTURY: u8 = 0x32;
/// FADT `IAPC_BOOT_ARCH` value: no legacy 8042 or MSI support advertised.
pub const IAPC_BOOT_ARCH: u16 = 0;
/// Minimum decoded AML: `Scope (\_SB) {}`.
///
/// `0x10` is `ScopeOp`, `0x06` is the package length (its own byte plus the
/// five-byte name string), `0x5C` is the root namespace prefix and `_SB_` is
/// the predefined system bus name segment.
pub const DSDT_AML: [u8; 7] = [0x10, 0x06, 0x5C, 0x5F, 0x53, 0x42, 0x5F];
/// Full length of the emitted DSDT.
pub const DSDT_LEN: usize = SDT_HEADER_LEN + DSDT_AML.len();

/// One interrupt source override required by the PC/AT interrupt model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsaOverride {
    /// Legacy ISA interrupt line (`IRQ0..=IRQ15`).
    pub irq_source: u8,
    /// Global system interrupt the line is wired to.
    pub gsi: u32,
    /// MPS INTI flags: polarity in bits 1:0, trigger mode in bits 3:2.
    pub flags: u16,
}

/// Overrides written to the MADT for lines whose GSI differs from the IRQ or
/// whose signal semantics are not the bus defaults.
///
/// - `IRQ0` is wired to `GSI2` (the 8254 timer cascade);
/// - `IRQ9` is wired to `GSI9` with level, active high semantics.
///
/// All other ISA lines are identity-mapped with bus-default semantics and
/// therefore need no override. Device lines above the ISA range (the s9vm
/// virtio devices use `GSI16..=GSI18`) are identity-mapped as well.
pub const ISA_OVERRIDES: [IsaOverride; 2] = [
    IsaOverride {
        irq_source: 0,
        gsi: 2,
        flags: 0,
    },
    IsaOverride {
        irq_source: 9,
        gsi: 9,
        flags: 0x000D,
    },
];

/// Table construction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// The output buffer is shorter than the encoded image.
    BufferTooSmall {
        /// Size of the encoded image, in bytes.
        needed: usize,
        /// Size of the supplied buffer, in bytes.
        provided: usize,
    },
    /// The encoded image would exceed [`MAX_IMAGE_LEN`].
    ImageTooLarge {
        /// Size the image would need, in bytes.
        needed: usize,
        /// Maximum accepted size, in bytes.
        limit: usize,
    },
    /// The image base is not aligned on [`IMAGE_ALIGN`].
    MisalignedBase,
    /// A 32-bit table pointer would not fit in the low 4 GiB.
    AddressNotRepresentable,
    /// No vCPU was described, so no local APIC entry exists.
    NoVcpu,
    /// More vCPUs were described than [`MAX_VCPUS`].
    VcpuLimitExceeded,
    /// Two vCPUs share the same local APIC id.
    DuplicateApicId,
}

/// Offset of every table inside an encoded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiLayout {
    /// Total size of the encoded image, in bytes.
    pub total_len: usize,
    /// Offset of the RSDP (always [`RSDP_OFFSET`]).
    pub rsdp_offset: usize,
    /// Offset of the XSDT.
    pub xsdt_offset: usize,
    /// Offset of the FADT.
    pub fadt_offset: usize,
    /// Offset of the MADT.
    pub madt_offset: usize,
    /// Offset of the SPCR (serial console redirection).
    pub spcr_offset: usize,
    /// Offset of the RSDT v1 view, when one is emitted.
    pub rsdt_offset: Option<usize>,
    /// Offset of the DSDT.
    pub dsdt_offset: usize,
}

/// Result of a successful [`AcpiBuilder::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiImage {
    /// Number of bytes written at the start of the output buffer.
    pub len: usize,
    /// Offset of the RSDP (always [`RSDP_OFFSET`]).
    pub rsdp_offset: usize,
    /// Offset of the XSDT.
    pub xsdt_offset: usize,
    /// Offset of the FADT.
    pub fadt_offset: usize,
    /// Offset of the MADT.
    pub madt_offset: usize,
    /// Offset of the SPCR (serial console redirection).
    pub spcr_offset: usize,
    /// Offset of the RSDT v1 view, when one is emitted.
    pub rsdt_offset: Option<usize>,
    /// Offset of the DSDT.
    pub dsdt_offset: usize,
}

impl AcpiImage {
    /// Builds the image descriptor from a computed layout.
    const fn from_layout(layout: AcpiLayout) -> Self {
        Self {
            len: layout.total_len,
            rsdp_offset: layout.rsdp_offset,
            xsdt_offset: layout.xsdt_offset,
            fadt_offset: layout.fadt_offset,
            madt_offset: layout.madt_offset,
            spcr_offset: layout.spcr_offset,
            rsdt_offset: layout.rsdt_offset,
            dsdt_offset: layout.dsdt_offset,
        }
    }

    /// Guest-physical address of the RSDP once the image is copied to
    /// `image_base`.
    ///
    /// The RSDP is at offset zero, so this is simply the image base; the
    /// helper exists to make the caller's intent explicit.
    pub const fn rsdp_address(&self, image_base: u64) -> u64 {
        image_base + self.rsdp_offset as u64
    }
}

/// Builder for the static ACPI image of one guest machine.
///
/// The builder is a small `Copy` value: it borrows the caller's vCPU APIC ids
/// and stores the policy flags. [`AcpiBuilder::layout`] validates the request
/// and returns the sizes and offsets; [`AcpiBuilder::encode`] writes the
/// image.
#[derive(Debug, Clone, Copy)]
pub struct AcpiBuilder<'a> {
    base_gpa: u64,
    vcpu_apic_ids: &'a [u8],
    x2apic: bool,
    legacy_rsdt: bool,
}

impl<'a> AcpiBuilder<'a> {
    /// Creates a builder for an image placed at `base_gpa` and describing one
    /// local APIC per entry of `vcpu_apic_ids`.
    ///
    /// Defaults: local APIC entries (type 0) and a legacy RSDT v1 view.
    pub fn new(base_gpa: u64, vcpu_apic_ids: &'a [u8]) -> Self {
        Self {
            base_gpa,
            vcpu_apic_ids,
            x2apic: false,
            legacy_rsdt: true,
        }
    }

    /// Selects the local APIC representation: `true` emits local x2APIC entries
    /// (type 9) instead of local APIC entries (type 0).
    pub const fn with_x2apic(mut self, enabled: bool) -> Self {
        self.x2apic = enabled;
        self
    }

    /// Enables or disables the RSDT v1 view for legacy guests.
    ///
    /// When disabled, the RSDP still carries the ACPI 1.0 checksum but its
    /// 32-bit RSDT address is zero, and no RSDT is emitted.
    pub const fn with_legacy_rsdt(mut self, enabled: bool) -> Self {
        self.legacy_rsdt = enabled;
        self
    }

    /// Guest-physical base address of the image.
    pub const fn base(&self) -> u64 {
        self.base_gpa
    }

    /// Number of vCPUs described.
    pub const fn vcpu_count(&self) -> usize {
        self.vcpu_apic_ids.len()
    }

    /// Computes the image size and the offset of every table.
    ///
    /// This is the allocation step: the caller allocates [`AcpiLayout::total_len`]
    /// bytes (or a page holding the image) before calling [`Self::encode`].
    pub fn layout(&self) -> Result<AcpiLayout, AcpiError> {
        if self.base_gpa % IMAGE_ALIGN != 0 {
            return Err(AcpiError::MisalignedBase);
        }
        let vcpu_count = self.vcpu_apic_ids.len();
        if vcpu_count == 0 {
            return Err(AcpiError::NoVcpu);
        }
        if vcpu_count > MAX_VCPUS {
            return Err(AcpiError::VcpuLimitExceeded);
        }
        for (index, apic_id) in self.vcpu_apic_ids.iter().enumerate() {
            if self.vcpu_apic_ids[..index].contains(apic_id) {
                return Err(AcpiError::DuplicateApicId);
            }
        }

        let madt_len = self.madt_length();

        let offset = RSDP_LEN;
        let xsdt_offset = align_up(offset, TABLE_ALIGN);
        let offset = xsdt_offset + XSDT_LEN;
        let fadt_offset = align_up(offset, TABLE_ALIGN);
        let offset = fadt_offset + FADT_LEN;
        let madt_offset = align_up(offset, TABLE_ALIGN);
        let offset = madt_offset + madt_len;
        let spcr_offset = align_up(offset, TABLE_ALIGN);
        let offset = spcr_offset + SPCR_LEN;
        let (rsdt_offset, offset) = if self.legacy_rsdt {
            let rsdt_offset = align_up(offset, TABLE_ALIGN);
            (Some(rsdt_offset), rsdt_offset + RSDT_LEN)
        } else {
            (None, offset)
        };
        let dsdt_offset = align_up(offset, TABLE_ALIGN);
        let total_len = dsdt_offset + DSDT_LEN;

        if total_len > MAX_IMAGE_LEN {
            return Err(AcpiError::ImageTooLarge {
                needed: total_len,
                limit: MAX_IMAGE_LEN,
            });
        }
        let Some(end) = self.base_gpa.checked_add(total_len as u64) else {
            return Err(AcpiError::AddressNotRepresentable);
        };
        // FADT and RSDP carry 32-bit table pointers: the whole image must live
        // in the low 4 GiB for those to be representable.
        if end > u64::from(u32::MAX) + 1 {
            return Err(AcpiError::AddressNotRepresentable);
        }
        Ok(AcpiLayout {
            total_len,
            rsdp_offset: RSDP_OFFSET,
            xsdt_offset,
            fadt_offset,
            madt_offset,
            spcr_offset,
            rsdt_offset,
            dsdt_offset,
        })
    }

    /// Length of the MADT for the current policy.
    fn madt_length(&self) -> usize {
        let local_entry_len = if self.x2apic {
            LOCAL_X2APIC_ENTRY_LEN
        } else {
            LOCAL_APIC_ENTRY_LEN
        };
        MADT_HEADER_LEN
            + self.vcpu_apic_ids.len() * local_entry_len
            + IOAPIC_ENTRY_LEN
            + ISA_OVERRIDES.len() * INT_SOURCE_OVERRIDE_LEN
    }

    /// Encodes the image into `out` and returns the written size and offsets.
    ///
    /// The first [`AcpiLayout::total_len`] bytes of `out` are overwritten; the
    /// rest is left untouched.
    pub fn encode(&self, out: &mut [u8]) -> Result<AcpiImage, AcpiError> {
        let layout = self.layout()?;
        if out.len() < layout.total_len {
            return Err(AcpiError::BufferTooSmall {
                needed: layout.total_len,
                provided: out.len(),
            });
        }
        let buffer = &mut out[..layout.total_len];
        buffer.fill(0);
        self.write_rsdp(buffer, &layout);
        self.write_xsdt(buffer, &layout);
        self.write_fadt(buffer, &layout);
        self.write_madt(buffer, &layout);
        self.write_spcr(buffer, &layout);
        if let Some(rsdt_offset) = layout.rsdt_offset {
            self.write_rsdt(buffer, &layout, rsdt_offset);
        }
        self.write_dsdt(buffer, &layout);
        Ok(AcpiImage::from_layout(layout))
    }

    /// Writes the RSDP revision 2 with both checksums.
    fn write_rsdp(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.rsdp_offset;
        put_bytes(buffer, offset, RSDP_SIGNATURE);
        put_u8(buffer, offset + 8, 0);
        put_bytes(buffer, offset + 9, OEM_ID);
        put_u8(buffer, offset + 15, RSDP_REVISION);
        let rsdt_address = match layout.rsdt_offset {
            Some(rsdt_offset) => address(self.base_gpa, rsdt_offset) as u32,
            None => 0,
        };
        put_u32(buffer, offset + 16, rsdt_address);
        put_u32(buffer, offset + 20, RSDP_LEN as u32);
        put_u64(
            buffer,
            offset + 24,
            address(self.base_gpa, layout.xsdt_offset),
        );
        put_u8(buffer, offset + 32, 0);
        // ACPI 1.0 checksum over the first 20 bytes, then the extended one.
        let first = checksum(&buffer[offset..offset + RSDP_V1_LEN]);
        buffer[offset + 8] = 0u8.wrapping_sub(first);
        let extended = checksum(&buffer[offset..offset + RSDP_LEN]);
        buffer[offset + 32] = 0u8.wrapping_sub(extended);
    }

    /// Writes the XSDT listing the FADT, the MADT and the SPCR.
    fn write_xsdt(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.xsdt_offset;
        write_sdt_header(buffer, offset, XSDT_SIGNATURE, XSDT_LEN, XSDT_REVISION);
        put_u64(
            buffer,
            offset + SDT_HEADER_LEN,
            address(self.base_gpa, layout.fadt_offset),
        );
        put_u64(
            buffer,
            offset + SDT_HEADER_LEN + 8,
            address(self.base_gpa, layout.madt_offset),
        );
        put_u64(
            buffer,
            offset + SDT_HEADER_LEN + 16,
            address(self.base_gpa, layout.spcr_offset),
        );
        seal_table(buffer, offset, XSDT_LEN);
    }

    /// Writes the legacy RSDT v1 view listing the FADT, the MADT and the SPCR.
    fn write_rsdt(&self, buffer: &mut [u8], layout: &AcpiLayout, rsdt_offset: usize) {
        write_sdt_header(buffer, rsdt_offset, RSDT_SIGNATURE, RSDT_LEN, RSDT_REVISION);
        put_u32(
            buffer,
            rsdt_offset + SDT_HEADER_LEN,
            address(self.base_gpa, layout.fadt_offset) as u32,
        );
        put_u32(
            buffer,
            rsdt_offset + SDT_HEADER_LEN + 4,
            address(self.base_gpa, layout.madt_offset) as u32,
        );
        put_u32(
            buffer,
            rsdt_offset + SDT_HEADER_LEN + 8,
            address(self.base_gpa, layout.spcr_offset) as u32,
        );
        seal_table(buffer, rsdt_offset, RSDT_LEN);
    }

    /// Writes the FADT revision 6 subset.
    fn write_fadt(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.fadt_offset;
        let dsdt_address = address(self.base_gpa, layout.dsdt_offset);
        write_sdt_header(buffer, offset, FADT_SIGNATURE, FADT_LEN, FADT_REVISION);
        // 0x24: FIRMWARE_CTRL (no FACS), 0x28: DSDT.
        put_u32(buffer, offset + 0x24, 0);
        put_u32(buffer, offset + 0x28, dsdt_address as u32);
        // 0x2C: reserved, 0x2D: preferred PM profile (unspecified).
        put_u8(buffer, offset + 0x2C, 0);
        put_u8(buffer, offset + 0x2D, 0);
        // 0x2E: SCI interrupt; 0x30: SMI command port (none, ACPI always on).
        put_u16(buffer, offset + 0x2E, SCI_IRQ);
        put_u32(buffer, offset + 0x30, 0);
        put_u8(buffer, offset + 0x34, 0);
        put_u8(buffer, offset + 0x35, 0);
        put_u8(buffer, offset + 0x36, 0);
        put_u8(buffer, offset + 0x37, 0);
        // 0x38: PM1a/PM1b event blocks, 0x40: control blocks.
        put_u32(buffer, offset + 0x38, PM1A_EVENT_BLOCK);
        put_u32(buffer, offset + 0x3C, 0);
        put_u32(buffer, offset + 0x40, PM1A_CONTROL_BLOCK);
        put_u32(buffer, offset + 0x44, 0);
        // 0x48: PM2 control block (none), 0x4C: PM timer.
        put_u32(buffer, offset + 0x48, 0);
        put_u32(buffer, offset + 0x4C, PM_TIMER_BLOCK);
        // 0x50: GPE0 block, 0x54: GPE1 block (none).
        put_u32(buffer, offset + 0x50, GPE0_BLOCK);
        put_u32(buffer, offset + 0x54, 0);
        // 0x58: block lengths and GPE1 base.
        put_u8(buffer, offset + 0x58, PM1_EVENT_LENGTH);
        put_u8(buffer, offset + 0x59, PM1_CONTROL_LENGTH);
        put_u8(buffer, offset + 0x5A, 0);
        put_u8(buffer, offset + 0x5B, PM_TIMER_LENGTH);
        put_u8(buffer, offset + 0x5C, GPE0_LENGTH);
        put_u8(buffer, offset + 0x5D, 0);
        put_u8(buffer, offset + 0x5E, 0);
        put_u8(buffer, offset + 0x5F, 0);
        // 0x60: P_LVL2_LAT, 0x62: P_LVL3_LAT, 0x64: flush size/stride.
        put_u16(buffer, offset + 0x60, P_LVL2_LATENCY);
        put_u16(buffer, offset + 0x62, P_LVL3_LATENCY);
        put_u16(buffer, offset + 0x64, 0);
        put_u16(buffer, offset + 0x66, 0);
        // 0x68: duty cycle, 0x6A: RTC alarm, 0x6C: RTC century.
        put_u8(buffer, offset + 0x68, 0);
        put_u8(buffer, offset + 0x69, 0);
        put_u8(buffer, offset + 0x6A, 0);
        put_u8(buffer, offset + 0x6B, 0);
        put_u8(buffer, offset + 0x6C, RTC_CENTURY);
        // 0x6D: IAPC boot architecture, 0x6F: reserved, 0x70: flags.
        put_u16(buffer, offset + 0x6D, IAPC_BOOT_ARCH);
        put_u8(buffer, offset + 0x6F, 0);
        put_u32(buffer, offset + 0x70, FADT_FLAGS);
        // 0x74: reset register (system I/O port), 0x80: reset value.
        write_gas(buffer, offset + 0x74, 1, 8, 0, 1, RESET_REGISTER_PORT);
        put_u8(buffer, offset + 0x80, RESET_VALUE);
        // 0x81: ARM boot architecture, 0x83: minor revision.
        put_u16(buffer, offset + 0x81, 0);
        put_u8(buffer, offset + 0x83, 0);
        // 0x84: X_FIRMWARE_CTRL (none), 0x8C: X_DSDT.
        put_u64(buffer, offset + 0x84, 0);
        put_u64(buffer, offset + 0x8C, dsdt_address);
        // 0x94..: 64-bit GAS views of the PM blocks; absent ones stay zero.
        write_gas(
            buffer,
            offset + 0x94,
            1,
            32,
            0,
            4,
            u64::from(PM1A_EVENT_BLOCK),
        );
        write_gas(
            buffer,
            offset + 0xAC,
            1,
            16,
            0,
            2,
            u64::from(PM1A_CONTROL_BLOCK),
        );
        write_gas(
            buffer,
            offset + 0xD0,
            1,
            32,
            0,
            4,
            u64::from(PM_TIMER_BLOCK),
        );
        write_gas(buffer, offset + 0xDC, 1, 32, 0, 4, u64::from(GPE0_BLOCK));
        // 0xE8..0x114: GPE1, sleep registers and hypervisor id stay zero.
        seal_table(buffer, offset, FADT_LEN);
    }

    /// Writes the MADT: local APICs, I/O APIC and ISA overrides.
    fn write_madt(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.madt_offset;
        let length = self.madt_length();
        write_sdt_header(buffer, offset, MADT_SIGNATURE, length, MADT_REVISION);
        put_u32(buffer, offset + SDT_HEADER_LEN, LOCAL_APIC_ADDRESS);
        put_u32(buffer, offset + SDT_HEADER_LEN + 4, MADT_PCAT_COMPAT);

        let mut entry = offset + MADT_HEADER_LEN;
        for (processor, apic_id) in self.vcpu_apic_ids.iter().enumerate() {
            if self.x2apic {
                // Type 9: local x2APIC, reserved, id, flags, processor uid.
                put_u8(buffer, entry, 9);
                put_u8(buffer, entry + 1, LOCAL_X2APIC_ENTRY_LEN as u8);
                put_u32(buffer, entry + 4, u32::from(*apic_id));
                put_u32(buffer, entry + 8, LOCAL_APIC_ENABLED);
                put_u32(buffer, entry + 12, processor as u32);
                entry += LOCAL_X2APIC_ENTRY_LEN;
            } else {
                // Type 0: local APIC, processor id, APIC id, flags.
                put_u8(buffer, entry, 0);
                put_u8(buffer, entry + 1, LOCAL_APIC_ENTRY_LEN as u8);
                put_u8(buffer, entry + 2, processor as u8);
                put_u8(buffer, entry + 3, *apic_id);
                put_u32(buffer, entry + 4, LOCAL_APIC_ENABLED);
                entry += LOCAL_APIC_ENTRY_LEN;
            }
        }
        // Type 1: I/O APIC.
        put_u8(buffer, entry, 1);
        put_u8(buffer, entry + 1, IOAPIC_ENTRY_LEN as u8);
        put_u8(buffer, entry + 2, IOAPIC_ID);
        put_u8(buffer, entry + 3, 0);
        put_u32(buffer, entry + 4, IOAPIC_ADDRESS);
        put_u32(buffer, entry + 8, IOAPIC_GSI_BASE);
        entry += IOAPIC_ENTRY_LEN;
        // Type 2: interrupt source overrides.
        for source in ISA_OVERRIDES.iter() {
            put_u8(buffer, entry, 2);
            put_u8(buffer, entry + 1, INT_SOURCE_OVERRIDE_LEN as u8);
            put_u8(buffer, entry + 2, ISA_BUS);
            put_u8(buffer, entry + 3, source.irq_source);
            put_u32(buffer, entry + 4, source.gsi);
            put_u16(buffer, entry + 8, source.flags);
            entry += INT_SOURCE_OVERRIDE_LEN;
        }
        seal_table(buffer, offset, length);
    }

    /// Writes the SPCR: the serial console redirection description.
    ///
    /// ACPI-aware kernels use it to bring up an early console (`earlycon`)
    /// before any driver probing: it names the 16550-compatible COM1 at
    /// [`SPCR_COM1_PORT`] with its I/O APIC global system interrupt, the baud
    /// rate and the line parameters. The guest serial model is
    /// byte-compatible with it.
    fn write_spcr(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.spcr_offset;
        write_sdt_header(buffer, offset, SPCR_SIGNATURE, SPCR_LEN, SPCR_REVISION);
        put_u8(buffer, offset + 36, SPCR_INTERFACE_16550);
        // 37..39: reserved.
        // 40: generic address structure of the register file.
        put_u8(buffer, offset + 40, 1); // address space: system I/O
        put_u8(buffer, offset + 41, 8); // register bit width
        put_u8(buffer, offset + 42, 0); // register bit offset
        put_u8(buffer, offset + 43, 1); // access size: byte
        put_u64(buffer, offset + 44, u64::from(SPCR_COM1_PORT));
        // 52: interrupt type, 53: IRQ (8259 only), 54..57: GSI.
        put_u8(buffer, offset + 52, SPCR_INTERRUPT_IOAPIC);
        put_u8(buffer, offset + 53, 0);
        put_u32(buffer, offset + 54, SPCR_COM1_GSI);
        // 58: baud rate, 59: parity, 60: stop bits, 61: flow control.
        put_u8(buffer, offset + 58, SPCR_BAUD_115200);
        put_u8(buffer, offset + 59, SPCR_PARITY_NONE);
        put_u8(buffer, offset + 60, SPCR_STOP_ONE);
        put_u8(buffer, offset + 61, SPCR_FLOW_NONE);
        // 62: terminal type, 63: language (0 = complete/ASCII).
        put_u8(buffer, offset + 62, SPCR_TERMINAL_VT100);
        put_u8(buffer, offset + 63, 0);
        // 64..: PCI device/vendor/bus/device/function/flags/segment, no device.
        seal_table(buffer, offset, SPCR_LEN);
    }

    /// Writes the DSDT holding the minimal AML namespace.
    fn write_dsdt(&self, buffer: &mut [u8], layout: &AcpiLayout) {
        let offset = layout.dsdt_offset;
        write_sdt_header(buffer, offset, DSDT_SIGNATURE, DSDT_LEN, DSDT_REVISION);
        put_bytes(buffer, offset + SDT_HEADER_LEN, &DSDT_AML);
        seal_table(buffer, offset, DSDT_LEN);
    }
}

/// Rounds `value` up to the next multiple of `align` (`align` is a power of
/// two).
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Guest-physical address of a table at `offset` inside an image based at
/// `base`.
fn address(base: u64, offset: usize) -> u64 {
    base + offset as u64
}

/// Writes a standard ACPI table header at `offset`.
fn write_sdt_header(
    buffer: &mut [u8],
    offset: usize,
    signature: &[u8; 4],
    length: usize,
    revision: u8,
) {
    put_bytes(buffer, offset, signature);
    put_u32(buffer, offset + 4, length as u32);
    put_u8(buffer, offset + 8, revision);
    put_u8(buffer, offset + 9, 0);
    put_bytes(buffer, offset + 10, OEM_ID);
    put_bytes(buffer, offset + 16, OEM_TABLE_ID);
    put_u32(buffer, offset + 24, OEM_REVISION);
    put_bytes(buffer, offset + 28, CREATOR_ID);
    put_u32(buffer, offset + 32, CREATOR_REVISION);
}

/// Writes a generic address structure at `offset`.
fn write_gas(
    buffer: &mut [u8],
    offset: usize,
    address_space: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
) {
    put_u8(buffer, offset, address_space);
    put_u8(buffer, offset + 1, bit_width);
    put_u8(buffer, offset + 2, bit_offset);
    put_u8(buffer, offset + 3, access_size);
    put_u64(buffer, offset + 4, address);
}

/// Fills in the checksum of the table at `offset` so its bytes sum to zero.
fn seal_table(buffer: &mut [u8], offset: usize, length: usize) {
    buffer[offset + 9] = 0;
    let value = checksum(&buffer[offset..offset + length]);
    buffer[offset + 9] = 0u8.wrapping_sub(value);
}

/// Sums the bytes of `bytes` modulo 256.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

/// Writes `bytes` at `offset`.
fn put_bytes(buffer: &mut [u8], offset: usize, bytes: &[u8]) {
    buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Writes a byte at `offset`.
fn put_u8(buffer: &mut [u8], offset: usize, value: u8) {
    buffer[offset] = value;
}

/// Writes a little-endian `u16` at `offset`.
fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    put_bytes(buffer, offset, &value.to_le_bytes());
}

/// Writes a little-endian `u32` at `offset`.
fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    put_bytes(buffer, offset, &value.to_le_bytes());
}

/// Writes a little-endian `u64` at `offset`.
fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    put_bytes(buffer, offset, &value.to_le_bytes());
}

