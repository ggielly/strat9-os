//! DMAR : the ACPI "DMA Remapping Reporting" table (Intel VT-d).
//!
//! The DMAR describes the IOMMU hardware units ([`Drhd`]), the memory regions
//! reserved for devices ([`Rmrr`]) and the PCIe root ports that may issue
//! Address Translation Service requests ([`Atsr`]).
//!
//! The parser is deliberately defensive: firmware tables are untrusted input.
//! Every length is bounds-checked against the table length, and the standard
//! ACPI checksum is verified before the table is used.
//!
//! Reference: ACPI Specification 6.5, section 5.2.11 "DMA Remapping Table".
//! Inspired by Theseus OS `acpi/dmar.rs`.

use super::sdt::Sdt;
use alloc::vec::Vec;

/// ACPI signature of the DMAR table.
pub const DMAR_SIGNATURE: &[u8; 4] = b"DMAR";

/// Size of the DMAR fixed header (SDT header + host address width + flags).
pub const DMAR_HEADER_LEN: usize = 48;

/// Hard upper bound on the table size, to reject absurd firmware values.
pub const DMAR_MAX_LEN: usize = 1 << 20;

// Remapping structure types.
/// DMA Remapping Hardware Unit Definition.
pub const TYPE_DRHD: u16 = 0;
/// Reserved Memory Region Reporting.
pub const TYPE_RMRR: u16 = 1;
/// Root Port ATS Capability Reporting.
pub const TYPE_ATSR: u16 = 2;
/// Remapping Hardware Static Affinity.
pub const TYPE_RHSA: u16 = 3;
/// ACPI Name-space Device Declaration.
pub const TYPE_ANVS: u16 = 4;
/// SoC Integrated Address Translation Cache Reporting.
pub const TYPE_SAT: u16 = 5;

// DRHD flags.
/// The unit handles all PCI devices not covered by another DRHD.
pub const DRHD_INCLUDE_PCI_ALL: u8 = 1 << 0;

// ATSR flags.
/// All PCIe root ports in the segment are ATS capable.
pub const ATSR_ALL_PORTS: u8 = 1 << 0;

// DMAR table flags.
/// Interrupt remapping is supported.
pub const DMAR_FLAG_INTR_REMAP: u8 = 1 << 0;
/// The platform requests that x2APIC mode be left disabled.
pub const DMAR_FLAG_X2APIC_OPT_OUT: u8 = 1 << 1;
/// DMA control platform opt-in (ACPI 6.0+).
pub const DMAR_FLAG_DMA_CTRL_PLATFORM_OPT_IN: u8 = 1 << 2;

/// Errors returned while parsing a DMAR table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// The table is shorter than the fixed header.
    TooShort,
    /// The ACPI signature is not `DMAR`.
    BadSignature,
    /// The length field is inconsistent with the buffer or absurd.
    BadLength,
    /// The ACPI checksum does not sum to zero.
    BadChecksum,
    /// A remapping structure has an invalid length or type.
    BadStructure,
    /// A device scope is malformed.
    BadScope,
}

/// A device scope entry inside a DRHD, RMRR or ATSR structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    pub kind: ScopeKind,
    /// IOAPIC id, HPET id or ACPI device handle, depending on `kind`.
    pub enumeration_id: u8,
    /// First bus number covered by this scope.
    pub start_bus: u8,
    /// Bridge path from `start_bus` to the target device.
    ///
    /// For an endpoint scope the last entry identifies the device/function;
    /// earlier entries identify intermediate bridges.
    pub path: Vec<PathEntry>,
}

/// One (device, function) pair in a device scope path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathEntry {
    pub device: u8,
    pub function: u8,
}

/// Kind of a [`DeviceScope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// A single PCI endpoint.
    PciEndpoint,
    /// A PCI sub-hierarchy (a bridge and everything below it).
    PciSubHierarchy,
    /// An I/O APIC.
    IoApic,
    /// An MSI-capable HPET.
    Hpet,
    /// An ACPI name-space device.
    AcpiNamespace,
    /// A scope type this kernel does not know yet.
    Unknown(u8),
}

impl ScopeKind {
    /// Decode a raw DMAR scope type.
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0x01 => ScopeKind::PciEndpoint,
            0x02 => ScopeKind::PciSubHierarchy,
            0x03 => ScopeKind::IoApic,
            0x04 => ScopeKind::Hpet,
            0x05 => ScopeKind::AcpiNamespace,
            other => ScopeKind::Unknown(other),
        }
    }

    /// True when the scope describes a PCI function.
    pub const fn is_pci(self) -> bool {
        matches!(
            self,
            ScopeKind::PciEndpoint | ScopeKind::PciSubHierarchy
        )
    }
}

impl DeviceScope {
    /// Return `(bus, device, function)` for an endpoint scope.
    ///
    /// A sub-hierarchy with an empty path denotes a whole bus range and has no
    /// single endpoint identity, so it returns `None`.
    pub fn endpoint(&self) -> Option<(u8, u8, u8)> {
        match self.kind {
            ScopeKind::PciEndpoint => self
                .path
                .last()
                .map(|p| (self.start_bus, p.device, p.function)),
            _ => None,
        }
    }

    /// True when this scope covers the given PCI function on `segment`.
    pub fn covers(&self, bus: u8, device: u8, function: u8) -> bool {
        match self.kind {
            ScopeKind::PciEndpoint => self
                .path
                .last()
                .map(|p| self.start_bus == bus && p.device == device && p.function == function)
                .unwrap_or(false),
            ScopeKind::PciSubHierarchy => {
                if self.path.is_empty() {
                    bus >= self.start_bus
                } else {
                    // The last path entry is the target; earlier entries are
                    // bridges, which this simple predicate does not traverse.
                    self.start_bus == bus
                        && self
                            .path
                            .last()
                            .map(|p| p.device == device && p.function == function)
                            .unwrap_or(false)
                }
            }
            _ => false,
        }
    }
}

/// A DMA Remapping Hardware Unit (DRHD) definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drhd {
    pub flags: u8,
    pub segment: u16,
    /// Physical address of the unit's memory-mapped register block.
    pub register_base: u64,
    pub scopes: Vec<DeviceScope>,
}

impl Drhd {
    /// True when the unit is responsible for PCI devices not named by any
    /// other DRHD in the same segment.
    pub const fn include_pci_all(&self) -> bool {
        self.flags & DRHD_INCLUDE_PCI_ALL != 0
    }

    /// True when this unit covers the given PCI function.
    pub fn covers(&self, segment: u16, bus: u8, device: u8, function: u8) -> bool {
        if self.segment != segment {
            return false;
        }
        self.include_pci_all() || self.scopes.iter().any(|s| s.covers(bus, device, function))
    }
}

/// A Reserved Memory Region Reporting (RMRR) structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rmrr {
    pub segment: u16,
    /// Inclusive start of the reserved physical range.
    pub base: u64,
    /// Inclusive end of the reserved physical range.
    pub limit: u64,
    pub scopes: Vec<DeviceScope>,
}

impl Rmrr {
    /// True when `phys` falls inside the reserved range.
    pub const fn contains(&self, phys: u64) -> bool {
        phys >= self.base && phys <= self.limit
    }

    /// True when any scope of this region covers the given PCI function.
    pub fn covers(&self, segment: u16, bus: u8, device: u8, function: u8) -> bool {
        self.segment == segment
            && self
                .scopes
                .iter()
                .any(|s| s.covers(bus, device, function))
    }
}

/// A Root Port ATS Capability Reporting (ATSR) structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atsr {
    pub flags: u8,
    pub segment: u16,
    pub scopes: Vec<DeviceScope>,
}

impl Atsr {
    /// True when every root port of the segment is ATS capable.
    pub const fn all_ports(&self) -> bool {
        self.flags & ATSR_ALL_PORTS != 0
    }
}

/// One raw remapping structure, yielded by [`Dmar::structures`].
#[derive(Debug, Clone, Copy)]
pub struct RemappingStructure<'a> {
    pub kind: u16,
    /// Payload after the 4-byte type/length header.
    pub payload: &'a [u8],
}

/// Iterator over the remapping structures of a DMAR table.
pub struct StructureIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> Iterator for StructureIter<'a> {
    type Item = Result<RemappingStructure<'a>, DmarError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset >= self.bytes.len() {
            return None;
        }
        let rest = &self.bytes[self.offset..];
        if rest.len() < 4 {
            self.failed = true;
            return Some(Err(DmarError::BadStructure));
        }
        let kind = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if len < 4 || len > rest.len() {
            self.failed = true;
            return Some(Err(DmarError::BadStructure));
        }
        self.offset += len;
        Some(Ok(RemappingStructure {
            kind,
            payload: &rest[4..len],
        }))
    }
}

/// Parsed view over a DMAR table.
#[derive(Debug, Clone, Copy)]
pub struct Dmar {
    bytes: &'static [u8],
}

impl Dmar {
    /// Locate the DMAR table through ACPI and validate it.
    pub fn get() -> Option<Self> {
        // SAFETY: `find_table` returns a pointer to a table registered by the
        // ACPI subsystem during boot; the table lives for the kernel lifetime.
        unsafe {
            let ptr = super::find_table(DMAR_SIGNATURE)?;
            let sdt = &*(ptr as *const Sdt);
            let len = sdt.length as usize;
            if !(DMAR_HEADER_LEN..=DMAR_MAX_LEN).contains(&len) {
                return None;
            }
            let bytes = core::slice::from_raw_parts(ptr as *const u8, len);
            Self::parse(bytes).ok()
        }
    }

    /// Parse and validate a DMAR table from a byte slice.
    ///
    /// The slice must include the ACPI SDT header.
    pub fn parse(bytes: &'static [u8]) -> Result<Self, DmarError> {
        if bytes.len() < DMAR_HEADER_LEN {
            return Err(DmarError::TooShort);
        }
        if &bytes[0..4] != DMAR_SIGNATURE {
            return Err(DmarError::BadSignature);
        }
        let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        if declared != bytes.len() || declared > DMAR_MAX_LEN {
            return Err(DmarError::BadLength);
        }
        let mut sum = 0u8;
        for byte in bytes {
            sum = sum.wrapping_add(*byte);
        }
        if sum != 0 {
            return Err(DmarError::BadChecksum);
        }
        Ok(Self { bytes })
    }

    /// Raw table bytes, including the ACPI header.
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// Length of the table in bytes.
    pub const fn length(&self) -> usize {
        self.bytes.len()
    }

    /// Host address width in bits (the ACPI field stores width - 1).
    pub fn host_address_width(&self) -> u8 {
        (self.bytes[36] & 0x3f) + 1
    }

    /// Raw DMAR flags byte.
    pub const fn flags(&self) -> u8 {
        self.bytes[37]
    }

    /// True when the platform supports interrupt remapping.
    pub const fn intr_remap_supported(&self) -> bool {
        self.flags() & DMAR_FLAG_INTR_REMAP != 0
    }

    /// True when the firmware asks the OS to keep x2APIC disabled.
    pub const fn x2apic_opt_out(&self) -> bool {
        self.flags() & DMAR_FLAG_X2APIC_OPT_OUT != 0
    }

    /// True when the platform opted in to DMA control (ACPI 6.0+).
    pub const fn dma_control_platform_opt_in(&self) -> bool {
        self.flags() & DMAR_FLAG_DMA_CTRL_PLATFORM_OPT_IN != 0
    }

    /// Iterate over the remapping structures that follow the fixed header.
    pub const fn structures(&self) -> StructureIter<'static> {
        StructureIter {
            bytes: self.bytes,
            offset: DMAR_HEADER_LEN,
            failed: false,
        }
    }

    /// Parse every DRHD structure.
    pub fn drhds(&self) -> Result<Vec<Drhd>, DmarError> {
        let mut out = Vec::new();
        for entry in self.structures() {
            let entry = entry?;
            if entry.kind == TYPE_DRHD {
                out.push(parse_drhd(entry.payload)?);
            }
        }
        Ok(out)
    }

    /// Parse every RMRR structure.
    pub fn rmrrs(&self) -> Result<Vec<Rmrr>, DmarError> {
        let mut out = Vec::new();
        for entry in self.structures() {
            let entry = entry?;
            if entry.kind == TYPE_RMRR {
                out.push(parse_rmrr(entry.payload)?);
            }
        }
        Ok(out)
    }

    /// Parse every ATSR structure.
    pub fn atsrs(&self) -> Result<Vec<Atsr>, DmarError> {
        let mut out = Vec::new();
        for entry in self.structures() {
            let entry = entry?;
            if entry.kind == TYPE_ATSR {
                out.push(parse_atsr(entry.payload)?);
            }
        }
        Ok(out)
    }

    /// Find the DRHD responsible for a PCI function, if any.
    pub fn unit_for(&self, segment: u16, bus: u8, device: u8, function: u8) -> Option<Drhd> {
        let units = self.drhds().ok()?;
        // Prefer an explicit scope, then fall back to the segment's catch-all.
        units
            .iter()
            .find(|u| u.covers(segment, bus, device, function))
            .or_else(|| {
                units
                    .iter()
                    .find(|u| u.segment == segment && u.include_pci_all())
            })
            .cloned()
    }
}

fn split_scope_prefix(payload: &[u8], prefix: usize) -> Result<&[u8], DmarError> {
    if payload.len() < prefix {
        return Err(DmarError::BadStructure);
    }
    Ok(&payload[prefix..])
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

fn parse_drhd(payload: &[u8]) -> Result<Drhd, DmarError> {
    // flags(1) reserved(1) segment(2) register base(8) + scopes
    if payload.len() < 12 {
        return Err(DmarError::BadStructure);
    }
    Ok(Drhd {
        flags: payload[0],
        segment: read_u16(payload, 2),
        register_base: read_u64(payload, 4),
        scopes: parse_scopes(split_scope_prefix(payload, 12)?)?,
    })
}

fn parse_rmrr(payload: &[u8]) -> Result<Rmrr, DmarError> {
    // reserved(2) segment(2) reserved(2) base(8) limit(8) + scopes
    if payload.len() < 22 {
        return Err(DmarError::BadStructure);
    }
    Ok(Rmrr {
        segment: read_u16(payload, 2),
        base: read_u64(payload, 6),
        limit: read_u64(payload, 14),
        scopes: parse_scopes(split_scope_prefix(payload, 22)?)?,
    })
}

fn parse_atsr(payload: &[u8]) -> Result<Atsr, DmarError> {
    // flags(1) reserved(1) segment(2) + scopes
    if payload.len() < 4 {
        return Err(DmarError::BadStructure);
    }
    Ok(Atsr {
        flags: payload[0],
        segment: read_u16(payload, 2),
        scopes: parse_scopes(split_scope_prefix(payload, 4)?)?,
    })
}

fn parse_scopes(mut bytes: &[u8]) -> Result<Vec<DeviceScope>, DmarError> {
    let mut scopes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 6 {
            return Err(DmarError::BadScope);
        }
        let kind = ScopeKind::from_raw(bytes[0]);
        let len = bytes[1] as usize;
        if len < 6 || len > bytes.len() {
            return Err(DmarError::BadScope);
        }
        let enumeration_id = bytes[3];
        let start_bus = bytes[4];
        let path_bytes = &bytes[6..len];
        if kind.is_pci() {
            if path_bytes.len() % 2 != 0 {
                return Err(DmarError::BadScope);
            }
        } else if !path_bytes.is_empty() {
            return Err(DmarError::BadScope);
        }
        let path = path_bytes
            .chunks_exact(2)
            .map(|pair| PathEntry {
                device: pair[0],
                function: pair[1] & 0x7,
            })
            .collect();
        scopes.push(DeviceScope {
            kind,
            enumeration_id,
            start_bus,
            path,
        });
        bytes = &bytes[len..];
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn push_structure(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
        let len = (payload.len() + 4) as u16;
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn scope(kind: u8, start_bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
        let mut out = vec![kind, (6 + path.len() * 2) as u8, 0, 0, start_bus];
        for (device, function) in path {
            out.push(*device);
            out.push(*function);
        }
        out
    }

    fn build_table(structures: &[u8]) -> Vec<u8> {
        let total = DMAR_HEADER_LEN + structures.len();
        let mut out = vec![0u8; total];
        out[0..4].copy_from_slice(b"DMAR");
        out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        out[8] = 1; // revision
        out[36] = 0x2f; // host address width - 1
        out[37] = DMAR_FLAG_INTR_REMAP;
        out[DMAR_HEADER_LEN..].copy_from_slice(structures);
        // ACPI checksum: make the whole table sum to zero.
        let mut sum = 0u8;
        for byte in &out {
            sum = sum.wrapping_add(*byte);
        }
        out[9] = 0u8.wrapping_sub(sum);
        out
    }

    fn leak(bytes: Vec<u8>) -> &'static [u8] {
        alloc::boxed::Box::leak(bytes.into_boxed_slice())
    }

    #[test]
    fn parses_drhd_scope() {
        let mut structures = Vec::new();
        let drhd_payload = {
            let mut p = vec![0u8, 0, 0, 0]; // flags, reserved, segment
            p.extend_from_slice(&0xdead_0000u64.to_le_bytes());
            p.extend_from_slice(&scope(0x01, 0, &[(3, 0)]));
            p
        };
        push_structure(&mut structures, TYPE_DRHD, &drhd_payload);
        let table = leak(build_table(&structures));
        let dmar = Dmar::parse(table).expect("valid table");

        assert_eq!(dmar.host_address_width(), 0x30);
        assert!(dmar.intr_remap_supported());
        let units = dmar.drhds().expect("drhd");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].register_base, 0xdead_0000);
        assert_eq!(units[0].scopes.len(), 1);
        assert_eq!(units[0].scopes[0].endpoint(), Some((0, 3, 0)));
        assert!(units[0].covers(0, 0, 3, 0));
        assert!(!units[0].covers(0, 0, 4, 0));
    }

    #[test]
    fn parses_rmrr_and_atsr() {
        let mut structures = Vec::new();
        let rmrr_payload = {
            let mut p = vec![0u8; 6]; // reserved x2, segment, reserved
            p[2..4].copy_from_slice(&0u16.to_le_bytes());
            p.extend_from_slice(&0x1000u64.to_le_bytes());
            p.extend_from_slice(&0x2fffu64.to_le_bytes());
            p.extend_from_slice(&scope(0x01, 0, &[(1, 0)]));
            p
        };
        push_structure(&mut structures, TYPE_RMRR, &rmrr_payload);
        let atsr_payload = {
            let mut p = vec![ATSR_ALL_PORTS, 0, 0, 0];
            p.extend_from_slice(&scope(0x02, 0, &[]));
            p
        };
        push_structure(&mut structures, TYPE_ATSR, &atsr_payload);

        let table = leak(build_table(&structures));
        let dmar = Dmar::parse(table).expect("valid table");
        let rmrrs = dmar.rmrrs().expect("rmrr");
        assert_eq!(rmrrs.len(), 1);
        assert!(rmrrs[0].contains(0x1000));
        assert!(rmrrs[0].contains(0x2fff));
        assert!(!rmrrs[0].contains(0x3000));
        assert!(rmrrs[0].covers(0, 0, 1, 0));

        let atsrs = dmar.atsrs().expect("atsr");
        assert_eq!(atsrs.len(), 1);
        assert!(atsrs[0].all_ports());
    }

    #[test]
    fn rejects_bad_checksum_and_truncated_table() {
        let mut bytes = build_table(&[]);
        bytes[40] ^= 0xff;
        assert!(matches!(
            Dmar::parse(leak(bytes)),
            Err(DmarError::BadChecksum)
        ));

        let short = leak(vec![0u8; DMAR_HEADER_LEN - 1]);
        assert!(matches!(Dmar::parse(short), Err(DmarError::TooShort)));
    }

    #[test]
    fn rejects_malformed_scope() {
        let mut structures = Vec::new();
        // Scope declares a length larger than the remaining payload.
        let drhd_payload = {
            let mut p = vec![0u8, 0, 0, 0];
            p.extend_from_slice(&0u64.to_le_bytes());
            p.extend_from_slice(&[0x01, 0x40, 0, 0, 0, 0]);
            p
        };
        push_structure(&mut structures, TYPE_DRHD, &drhd_payload);
        let table = leak(build_table(&structures));
        let dmar = Dmar::parse(table).expect("header valid");
        assert_eq!(dmar.drhds(), Err(DmarError::BadScope));
    }
}
