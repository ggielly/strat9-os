//! L0/L1 — remaining `strat9_abi::data` types (pass 2 coverage).
//!
//! SiloMode subset logic, DirentHeader packing, PCI probe criteria and
//! struct size pins for everything crossing the kernel boundary that the
//! pass-1 suite did not already cover.

use strat9_abi::data::*;
use zerocopy::IntoBytes;

// ===========================================================================
// SiloMode: 9-bit octal permissions [control:3][hardware:3][registry:3]
// ===========================================================================

#[test]
fn silo_mode_subset_logic() {
    let full = SiloMode(0o777);
    let ro = SiloMode(0o444); // read-only everywhere
    let none = SiloMode(0);

    assert!(none.is_subset_of(&full));
    assert!(ro.is_subset_of(&full));
    assert!(full.is_subset_of(&full)); // subset includes equality
    assert!(!full.is_subset_of(&ro));
    assert!(!ro.is_subset_of(&none));

    // Per-group independence: write in hardware only.
    let hw_write = SiloMode(0o020);
    assert!(hw_write.is_subset_of(&full));
    assert!(!hw_write.is_subset_of(&ro));
}

#[test]
fn silo_mode_bit_layout_is_lsb_registry() {
    // Documented layout: [control:3][hardware:3][registry:3], LSB = registry.
    let registry_only = SiloMode(0o007);
    let hardware_only = SiloMode(0o070);
    let control_only = SiloMode(0o700);
    for m in [registry_only, hardware_only, control_only] {
        assert!(m.is_subset_of(&SiloMode(0o777)));
        assert!(!m.is_subset_of(&SiloMode(0)));
    }
}

// ===========================================================================
// IPC file flags & DirentHeader
// ===========================================================================

#[test]
fn ipc_file_flag_bits_are_pinned() {
    assert_eq!(IPC_FILE_FLAG_DIRECTORY, 1 << 0);
    assert_eq!(IPC_FILE_FLAG_DEVICE, 1 << 1);
    assert_eq!(IPC_FILE_FLAG_PIPE, 1 << 2);
    assert_eq!(IPC_FILE_FLAG_APPEND, 1 << 3);
    assert_eq!(IPC_FILE_FLAG_CHUNK_READ, 1 << 4);
    assert_eq!(IPC_FILE_FLAG_CHUNK_WRITE, 1 << 5);
}

#[test]
fn dirent_header_packing() {
    assert_eq!(DirentHeader::SIZE, 12);
    let h = DirentHeader { ino: 7, file_type: 4, name_len: 11, _padding: 0 };
    // header + name + NUL
    assert_eq!(h.entry_size(), 12 + 11 + 1);
    assert_eq!(size_of::<DirentHeader>(), DirentHeader::SIZE);
}

#[test]
fn dirent_header_zero_name() {
    let h = DirentHeader { ino: 0, file_type: 0, name_len: 0, _padding: 0 };
    assert_eq!(h.entry_size(), 13); // 12 header + NUL only
}

// ===========================================================================
// Struct size pins (kernel ↔ userspace wire contracts)
// ===========================================================================

#[test]
fn data_struct_sizes_are_pinned() {
    assert_eq!(size_of::<StatVfs>(), 88); // 11 × u64
    assert_eq!(size_of::<Map>(), 32); // usize+usize+u32+u32+usize (64-bit)
    assert_eq!(size_of::<HandleInfo>(), 16); // u32+u32+u64
    assert_eq!(size_of::<MemoryRegionInfo>(), 24); // 2×u64 + u32 + u32
    assert_eq!(size_of::<AsyncRingLayout>(), 40); // 4×u64 + u32+u32
    assert_eq!(size_of::<PciAddress>(), 4); // align(4): b+d+f+pad
    assert_eq!(size_of::<PciProbeCriteria>(), 12); // 4+2+2+1+1+1+1
    assert_eq!(size_of::<SiloConfig>() % 8, 0, "SiloConfig must stay pointer-aligned");
}

#[test]
fn pci_match_flags_are_pinned() {
    assert_eq!(PCI_MATCH_VENDOR_ID, 1 << 0);
    assert_eq!(PCI_MATCH_DEVICE_ID, 1 << 1);
    assert_eq!(PCI_MATCH_CLASS_CODE, 1 << 2);
    assert_eq!(PCI_MATCH_SUBCLASS, 1 << 3);
    assert_eq!(PCI_MATCH_PROG_IF, 1 << 4);
}

#[test]
fn pci_probe_criteria_layout_offsets() {
    let c = PciProbeCriteria {
        match_flags: 3,
        vendor_id: 0x8086,
        device_id: 0x100E,
        class_code: 2,
        subclass: 0,
        prog_if: 0,
        _reserved: 0,
    };
    let base = &c as *const _ as usize;
    assert_eq!(&c.match_flags as *const _ as usize - base, 0);
    assert_eq!(&c.vendor_id as *const _ as usize - base, 4);
    assert_eq!(&c.device_id as *const _ as usize - base, 6);
    assert_eq!(&c.class_code as *const _ as usize - base, 8);

    // E1000 classic identification.
    assert_eq!(c.vendor_id, 0x8086);
    assert_eq!(c.device_id, 0x100E);
}

#[test]
fn async_ring_layout_roundtrip_through_ipc_payload() {
    use strat9_abi::ipc_codec::{decode_fixed, encode_fixed};

    let l = AsyncRingLayout {
        sq_base: 0x1000_0000,
        cq_base: 0x1001_0000,
        sq_size: 4096,
        cq_size: 4096,
        entries: 64,
        _reserved: 0,
    };
    let msg = encode_fixed(0x99, &l);
    let back: &AsyncRingLayout = decode_fixed(&msg).expect("decode");
    assert_eq!(back.sq_base, l.sq_base);
    assert_eq!(back.entries, 64);
}
