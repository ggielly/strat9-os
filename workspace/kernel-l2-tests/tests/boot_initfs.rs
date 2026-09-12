//! Pure initfs handoff/name regressions. No firmware, paging or kernel is run.
#[path = "../../kernel/src/boot/modules.rs"]
mod kernel_modules;
#[path = "../../bootloader/src/module_name.rs"]
mod module_name;

use kernel_modules::{validate_modules, InitfsModule};
use module_name::ModuleFileName;
use strat9_abi::boot::{ModuleEntry, ModuleTable, MODULE_TABLE_SIZE};

const HHDM: u64 = 0xFFFF_FF00_0000_0000;

fn entry(name: &str, base: u64, size: u64) -> ModuleEntry {
    let mut bytes = [0; 64];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    ModuleEntry {
        name: bytes,
        base,
        size,
    }
}

#[test]
fn physical_module_is_converted_to_hhdm_exactly_once() {
    let module = entry("strate-init", 0x1000_0000, 4096);
    let view = InitfsModule::from_physical(&module, HHDM).unwrap();
    assert_eq!(view.virtual_base, 0xFFFF_FF00_1000_0000);
    assert_eq!(view.name, "strate-init");
    assert_eq!(view.len, 4096);
    let already_virtual = entry("strate-init", view.virtual_base, 4096);
    assert!(InitfsModule::from_physical(&already_virtual, HHDM).is_err());
}

#[test]
fn names_up_to_the_full_abi_limit_keep_every_ucs2_character() {
    for len in [1, 50, 51, 52, 63] {
        let text = "a".repeat(len);
        let raw: Vec<u16> = text.encode_utf16().collect();
        let name = ModuleFileName::new(&raw).unwrap();
        let expected: Vec<u16> = format!("\\boot\\initfs\\{text}\0").encode_utf16().collect();
        assert_eq!(name.path(), expected);
        assert_eq!(name.as_str(), text);
        assert_eq!(&name.abi_name()[..len], text.as_bytes());
        assert_eq!(name.abi_name()[len], 0);
    }
}

#[test]
fn unicode_and_long_names_cannot_alias_another_file() {
    for text in ["café", "cafe\u{0301}", "init😀", ""] {
        assert!(ModuleFileName::new(&text.encode_utf16().collect::<Vec<_>>()).is_err());
    }
    assert!(ModuleFileName::new(&vec![b'a' as u16; 64]).is_err());
    assert!(ModuleFileName::new(&[0xD800]).is_err());
    assert!(ModuleFileName::new(&[b'a' as u16, 0, b'b' as u16]).is_err());
    assert!(ModuleFileName::new(&[b'c' as u16, b'a' as u16, b'f' as u16]).is_ok());
}

#[test]
fn invalid_path_components_are_rejected_at_both_ends() {
    for text in [
        ".", "..", "../init", "a/b", "a\\b", "a:", "a*", "a?", "a b", "init.", "\tinit",
    ] {
        assert!(ModuleFileName::new(&text.encode_utf16().collect::<Vec<_>>()).is_err());
        assert!(entry(text, 4096, 1).checked_name().is_err());
    }
}

#[test]
fn duplicate_names_are_rejected_including_fat_case_collisions() {
    for second in ["strate-init", "STRATE-INIT"] {
        let modules = [entry("strate-init", 4096, 1), entry(second, 8192, 1)];
        assert!(validate_modules(&modules, HHDM).is_err());
    }
}

#[test]
fn invalid_payload_ranges_are_rejected_without_dereferencing_them() {
    for (base, size, hhdm) in [
        (0, 1, HHDM),
        (4096, u64::MAX, HHDM),
        (u64::MAX - 1, 4, 0),
        (1 << 47, 1, 0),
        ((1 << 47) - 1, 2, 0),
        (u64::MAX - HHDM, 2, HHDM),
    ] {
        assert!(InitfsModule::from_physical(&entry("init", base, size), hhdm).is_err());
    }
}

#[test]
fn malformed_abi_names_are_rejected_without_truncation() {
    let mut module = entry("init", 4096, 1);
    module.name.fill(b'a');
    assert!(module.checked_name().is_err());
    module.name = [0; 64];
    assert!(module.checked_name().is_err());
    module.name[..3].copy_from_slice(&[0xFF, b'a', 0]);
    assert!(module.checked_name().is_err());
}

#[test]
fn module_count_is_bounded_and_zero_length_data_files_are_preserved() {
    let modules: Vec<_> = (0..65)
        .map(|i| entry(&format!("module-{i}"), 4096 + i * 4096, 0))
        .collect();
    assert!(validate_modules(&modules[..64], HHDM).is_ok());
    assert!(validate_modules(&modules, HHDM).is_err());
    let view = InitfsModule::from_physical(&modules[0], HHDM).unwrap();
    assert_eq!(view.len, 0);
    assert_ne!(view.virtual_base, 0);
}

#[test]
fn table_to_initfs_view_preserves_the_actual_payload_bytes() {
    #[repr(align(8))]
    struct Storage([u8; MODULE_TABLE_SIZE]);
    let payload = b"\x7fELFknown initfs payload";
    let mut storage = Storage([0; MODULE_TABLE_SIZE]);
    let module = entry("strate-init", payload.as_ptr() as u64, payload.len() as u64);
    ModuleTable::write_into(&mut storage.0, &[module]).unwrap();
    let modules = ModuleTable::read_from(&storage.0).unwrap();
    // Identity translation permits inspecting the same pipeline on the host.
    validate_modules(modules, 0).unwrap();
    let view = InitfsModule::from_physical(&modules[0], 0).unwrap();
    let bytes = unsafe { core::slice::from_raw_parts(view.virtual_base as *const u8, view.len) };
    assert_eq!(bytes, payload);
}
