//! L2: ISA-class device models added for DOS-class guests (8042, VGA, 8237).
//!
//! These models are pure: no memory, no vCPU. The tests pin the behaviours a
//! legacy guest depends on (idle keyboard status, retrace polling, register
//! round-trips, port ownership) so a regression is caught without VT-x.

#[path = "../../kernel/src/s9vm/dma.rs"]
mod dma;
#[path = "../../kernel/src/s9vm/keyboard.rs"]
mod keyboard;
#[path = "../../kernel/src/s9vm/vga.rs"]
mod vga;

use dma::Dma;
use keyboard::KeyboardController;
use vga::Vga;

#[test]
fn keyboard_controller_reports_the_idle_state() {
    let mut controller = KeyboardController::new();
    assert!(keyboard::handles_port(keyboard::DATA_PORT));
    assert!(keyboard::handles_port(keyboard::STATUS_PORT));
    assert!(!keyboard::handles_port(0x62));

    let status = controller.read(keyboard::STATUS_PORT).expect("status");
    // Output buffer empty (bit 0), input buffer empty (bit 1), system flag
    // (bit 2) set, keyboard enabled (bit 4) set: a DOS init loop must not see
    // a stuck "input full" or "output full" bit.
    assert_eq!(status & 0x03, 0, "no buffer may look full: {status:#04x}");
    assert_eq!(status & 0x04, 0x04, "system flag must be set: {status:#04x}");
    assert_eq!(status & 0x10, 0x10, "keyboard must be enabled: {status:#04x}");

    // No scancode is queued: the BIOS service owns the key path.
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0));
}

#[test]
fn keyboard_controller_accepts_commands_and_stays_idle() {
    let mut controller = KeyboardController::new();
    controller.write(keyboard::STATUS_PORT, 0xD1); // write output port
    controller.write(keyboard::DATA_PORT, 0xFF);
    assert_eq!(controller.last_command(), 0xD1);
    assert_eq!(
        controller.read(keyboard::STATUS_PORT).expect("status") & 0x03,
        0
    );
}

#[test]
fn vga_status_port_always_reaches_retrace() {
    let mut model = Vga::new();
    assert!(vga::handles_port(0x3D4));
    assert!(vga::handles_port(0x3DA));
    assert!(vga::handles_port(0x3C0));
    assert!(!vga::handles_port(0x3F8));

    // A retrace poll loops on bit 3; the model must report it on one of the
    // two next reads so the poll terminates.
    let a = model.read(0x3DA).expect("status");
    let b = model.read(0x3DA).expect("status");
    assert!(
        a & 0x08 != 0 || b & 0x08 != 0,
        "vertical retrace must appear within two reads: {a:#04x} {b:#04x}"
    );
    // The display-enable phase reports bit 0.
    assert!(a & 0x01 != 0 || b & 0x01 != 0);
}

#[test]
fn vga_crtc_and_sequencer_registers_round_trip() {
    let mut model = Vga::new();
    // CRTC: index 0x0E then data byte.
    model.write(0x3D4, 0x0E);
    model.write(0x3D5, 0x12);
    assert_eq!(model.crtc_index(), 0x0E);
    model.write(0x3D4, 0x0E);
    assert_eq!(model.read(0x3D5), Some(0x12));
    // Mono aliases map to the same file.
    model.write(0x3B4, 0x0E);
    assert_eq!(model.read(0x3B5), Some(0x12));

    // Sequencer index/data.
    model.write(0x3C4, 0x02);
    model.write(0x3C5, 0xA5);
    model.write(0x3C4, 0x02);
    assert_eq!(model.read(0x3C5), Some(0xA5));

    // Graphics controller index/data.
    model.write(0x3CE, 0x05);
    model.write(0x3CF, 0x10);
    model.write(0x3CE, 0x05);
    assert_eq!(model.read(0x3CF), Some(0x10));
}

#[test]
fn vga_attribute_controller_selects_index_with_bit_five() {
    let mut model = Vga::new();
    model.write(0x3C0, 0x20 | 0x03); // index 3
    model.write(0x3C0, 0x42); // data
    assert_eq!(model.attribute_index(), 0x04, "index auto-increments");
    model.write(0x3C0, 0x20 | 0x03);
    assert_eq!(model.read(0x3C1), Some(0x42));
}

#[test]
fn dma_registers_round_trip_and_ignore_the_post_port() {
    let mut model = Dma::new();
    assert!(dma::handles_port(0x04));
    assert!(dma::handles_port(0x81));
    assert!(dma::handles_port(0xD0));
    // 0x80 is the platform POST port, not a page register.
    assert!(!dma::handles_port(0x80));

    model.write(0x04, 0x5A); // channel 1 address low
    assert_eq!(model.read(0x04), Some(0x5A));
    model.write(0x81, 0x02); // channel 1 page
    assert_eq!(model.read(0x81), Some(0x02));
    model.write(0xD0, 0x7F); // slave channel 4 address low
    assert_eq!(model.read(0xD0), Some(0x7F));
    assert_eq!(model.read(0x10), None);
}
