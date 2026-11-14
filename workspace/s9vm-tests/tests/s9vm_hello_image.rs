//! L2: the FreeDOS Hello/DIR demo floppy.

#[test]
fn hello_image_is_bootable_and_carries_the_greeting() {
    let image = include_bytes!("../../assets/disks/freedos-hello.img");
    assert_eq!(image.len(), 1_474_560);
    assert_eq!(image[510], 0x55);
    assert_eq!(image[511], 0xAA);
    assert_eq!(&image[3..11], b"FRDOS5.1");

    let contains = |needle: &[u8]| image.windows(needle.len()).any(|window| window == needle);
    assert!(contains(b"Hello world, from FreeDOS"));
    assert!(contains(b"@ECHO OFF\r\nECHO Hello world, from FreeDOS\r\nDIR\r\nS9VMK.COM"));
    assert!(contains(b"SHELL=\\FREEDOS\\BIN\\COMMAND.COM"));
    assert!(!contains(b"@echo off\r\n!COUNTRY"));
}
