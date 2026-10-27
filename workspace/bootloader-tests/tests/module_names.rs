//! Initfs module names: UCS-2 to the ASCII subset the boot ABI accepts, and the
//! exact `\boot\initfs\NAME` path opened from the volume.
//!
//! `ModuleFileName` backs a fixed-capacity array in the loader, so its sizes
//! and the `EMPTY` placeholder are pinned here as well.

#[path = "../../bootloader/src/module_name.rs"]
mod module_name;

use module_name::ModuleFileName;

fn ucs2(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

const PREFIX_CHARS: usize = r"\boot\initfs\".len();

#[test]
fn valid_names_keep_their_abi_form_and_prefixed_path() {
    let name = ModuleFileName::new(&ucs2("strate-init")).expect("valid name");
    assert_eq!(name.as_str(), "strate-init");
    assert_eq!(name.path().len(), PREFIX_CHARS + "strate-init".len() + 1);
    assert_eq!(
        name.path()[PREFIX_CHARS..PREFIX_CHARS + "strate-init".len()],
        ucs2("strate-init")[..]
    );
    assert_eq!(
        name.path()[PREFIX_CHARS + "strate-init".len()],
        0,
        "path is NUL terminated"
    );

    let abi = name.abi_name();
    assert_eq!(&abi[.."strate-init".len()], b"strate-init");
    assert_eq!(abi["strate-init".len()], 0, "ABI name stays NUL padded");

    // The portable subset accepts dots, dashes and underscores.
    for accepted in ["init", "fs-ext4", "lib_c", "net.v2", "a"] {
        assert!(
            ModuleFileName::new(&ucs2(accepted)).is_ok(),
            "{accepted} should be accepted"
        );
    }
}

#[test]
fn names_outside_the_portable_subset_are_rejected() {
    for rejected in [
        "",
        "..",
        ".",
        "a.",
        "with space",
        "slash/name",
        "back\\slash",
        "é",
    ] {
        assert!(
            ModuleFileName::new(&ucs2(rejected)).is_err(),
            "{rejected:?} should be rejected"
        );
    }
    // 63 characters fit, 64 do not, and neither does an unpaired wide char.
    assert!(ModuleFileName::new(&ucs2(&"a".repeat(63))).is_ok());
    assert!(ModuleFileName::new(&ucs2(&"a".repeat(64))).is_err());
    assert!(ModuleFileName::new(&[]).is_err());
    assert!(ModuleFileName::new(&[0x0100]).is_err());
}

#[test]
fn the_empty_placeholder_is_a_usable_array_slot() {
    // Fixed-capacity arrays are filled with this value; it must never look
    // like a real module and must keep the same size as a parsed name.
    let empty = ModuleFileName::EMPTY;
    assert_eq!(empty.as_str(), "");
    assert_eq!(empty.path().len(), PREFIX_CHARS + 1);
    assert!(empty.path().iter().all(|&unit| unit == 0));
    assert_eq!(empty.abi_name(), [0u8; 64]);
}
