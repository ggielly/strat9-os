//! L0 : boot handoff ABI conformance tests (anti-regression golden values).
//!
//! These tests pin the contract shared by the UEFI bootloader and the
//! kernel. A failure here means the two sides would disagree at boot, so
//! the golden value must only change together with
//! `STRAT9_BOOT_ABI_VERSION` and a matching update on both sides.

use core::mem::{align_of, size_of};

use strat9_abi::boot::{
    KernelArgs, MemoryKind, MemoryRegion, ModuleEntry, ModuleTable, MAX_BOOT_MEMORY_REGIONS,
    MAX_BOOT_MODULES, MODULE_TABLE_SIZE, STRAT9_BOOT_ABI_VERSION, STRAT9_BOOT_MAGIC,
};

fn args() -> KernelArgs {
    KernelArgs {
        magic: STRAT9_BOOT_MAGIC,
        abi_version: STRAT9_BOOT_ABI_VERSION,
        kernel_base: 0,
        kernel_size: 0,
        acpi_rsdp_base: 0,
        memory_map_base: 0,
        memory_map_size: 0,
        framebuffer_addr: 0,
        hhdm_offset: 0,
        cmdline_ptr: 0,
        cmdline_len: 0,
        modules_base: 0,
        modules_size: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_stride: 0,
        framebuffer_bpp: 0,
        framebuffer_red_mask_size: 0,
        framebuffer_red_mask_shift: 0,
        framebuffer_green_mask_size: 0,
        framebuffer_green_mask_shift: 0,
        framebuffer_blue_mask_size: 0,
        framebuffer_blue_mask_shift: 0,
        bss_virt_base: 0,
        bss_virt_size: 0,
    }
}

#[test]
fn handoff_layout_is_frozen() {
    assert_eq!(size_of::<KernelArgs>(), 132);
    assert_eq!(align_of::<KernelArgs>(), 1);
    assert_eq!(STRAT9_BOOT_MAGIC, 0x5354_3942); // "ST9B"
    assert_eq!(STRAT9_BOOT_ABI_VERSION, 5);

    assert_eq!(size_of::<MemoryRegion>(), 24);
    assert_eq!(align_of::<MemoryRegion>(), 8);
    assert_eq!(size_of::<MemoryKind>(), 8);

    assert_eq!(MAX_BOOT_MODULES, 64);
    assert_eq!(MAX_BOOT_MEMORY_REGIONS, 1024);
    assert_eq!(size_of::<ModuleEntry>(), 80);
    assert_eq!(MODULE_TABLE_SIZE, 5128);
}

#[test]
fn memory_kinds_have_distinct_stable_values() {
    let kinds = [
        MemoryKind::Null,
        MemoryKind::Free,
        MemoryKind::Reclaim,
        MemoryKind::Reserved,
        MemoryKind::Bad,
        MemoryKind::AcpiNvs,
    ];
    for (index, kind) in kinds.iter().enumerate() {
        assert_eq!(kind.0, index as u64, "MemoryKind value {index} changed");
    }
}

#[test]
fn empty_handoff_ranges_are_accepted() {
    let args = args();
    assert_eq!(unsafe { args.memory_regions() }.unwrap().len(), 0);
    assert_eq!(unsafe { args.modules() }.unwrap().len(), 0);
    assert!(args.cmdline_bytes().is_empty());
    assert!(args.env_get("console.baud").is_none());
}

#[test]
fn oversized_memory_map_is_rejected_before_dereference() {
    let mut args = args();
    // One descriptor over capacity: the pointer is never validated, the
    // length check must trigger first (base is 0x1000, never dereferenced).
    args.memory_map_base = 0x1000;
    args.memory_map_size = (MAX_BOOT_MEMORY_REGIONS as u64 + 1) * size_of::<MemoryRegion>() as u64;
    assert!(unsafe { args.memory_regions() }.is_err());
}

#[test]
fn misaligned_or_partial_memory_map_is_rejected() {
    let mut args = args();
    args.memory_map_base = 0x1000;
    // Not a multiple of the descriptor size.
    args.memory_map_size = size_of::<MemoryRegion>() as u64 + 8;
    assert!(unsafe { args.memory_regions() }.is_err());

    // Descriptor-sized but base is not 8-byte aligned.
    args.memory_map_base = 0x1001;
    args.memory_map_size = size_of::<MemoryRegion>() as u64;
    assert!(unsafe { args.memory_regions() }.is_err());
}

#[test]
fn environment_is_parsed_from_the_handoff_string() {
    static ENV: &[u8] = b"loader=strat9-bootloader-uefi\nconsole.baud=115200\n\0";
    let mut args = args();
    args.cmdline_ptr = ENV.as_ptr() as u64;
    args.cmdline_len = ENV.len() as u64;

    assert_eq!(args.env_get("loader"), Some("strat9-bootloader-uefi"));
    assert_eq!(args.env_get("console.baud"), Some("115200"));
    assert_eq!(args.env_get("missing"), None);
    // The trailing NUL is stripped; the final newline is part of the payload.
    assert!(args.cmdline_str().ends_with("console.baud=115200\n"));
}

#[test]
fn module_table_roundtrip_keeps_guard_bytes() {
    #[repr(align(8))]
    struct Guarded([u8; MODULE_TABLE_SIZE + 32]);
    let mut storage = Guarded([0xA5; MODULE_TABLE_SIZE + 32]);

    let entries = [
        ModuleEntry {
            name: {
                let mut name = [0u8; 64];
                name[..4].copy_from_slice(b"init");
                name
            },
            base: 0x20_0000,
            size: 4096,
        },
        ModuleEntry {
            name: {
                let mut name = [0u8; 64];
                name[..6].copy_from_slice(b"config");
                name
            },
            base: 0x30_0000,
            size: 128,
        },
    ];
    ModuleTable::write_into(&mut storage.0[..MODULE_TABLE_SIZE], &entries).unwrap();
    assert_eq!(storage.0[MODULE_TABLE_SIZE..], [0xA5; 32]);

    let read = ModuleTable::read_from(&storage.0[..MODULE_TABLE_SIZE]).unwrap();
    assert_eq!(read, entries);
    assert_eq!(read[0].checked_name().unwrap(), "init");
}
