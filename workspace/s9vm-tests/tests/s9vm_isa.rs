//! L2: ISA-class device models added for DOS-class guests (8042, VGA, 8237).
//!
//! These models are pure: no memory, no vCPU. The tests pin the behaviours a
//! legacy guest depends on (idle keyboard status, retrace polling, register
//! round-trips, port ownership) so a regression is caught without VT-x.

extern crate alloc;

#[path = "../../kernel/src/s9vm/dma.rs"]
mod dma;
#[path = "../../kernel/src/s9vm/keyboard.rs"]
mod keyboard;
#[path = "../../kernel/src/s9vm/pic.rs"]
mod pic;
#[path = "../../kernel/src/s9vm/vga.rs"]
mod vga;

use dma::Dma;
use keyboard::KeyboardController;
use pic::Pic;
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
fn keyboard_controller_answers_the_self_tests() {
    let mut controller = KeyboardController::new();
    controller.write(keyboard::STATUS_PORT, 0xAA); // controller self-test
    let status = controller.read(keyboard::STATUS_PORT).expect("status");
    assert_ne!(status & 0x01, 0, "output buffer full");
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0x55));

    controller.write(keyboard::STATUS_PORT, 0xAB); // keyboard interface test
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0x00));

    controller.write(keyboard::DATA_PORT, 0xFF); // keyboard reset
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0xFA));
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0xAA));
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

#[test]
fn dma_channel_two_decodes_the_floppy_programming_sequence() {
    // The exact sequence SeaBIOS uses in `dma_floppy`: mask, clear flip-flop,
    // address low/high, clear flip-flop, count low/high, mode, page, unmask.
    let mut model = Dma::new();
    model.write(0x0A, 0x06); // mask channel 2
    model.write(0x0C, 0x00); // clear flip-flop
    model.write(0x04, 0x00); // address low
    model.write(0x04, 0x7C); // address high -> 0x7C00
    model.write(0x0C, 0x00); // clear flip-flop
    model.write(0x05, 0xFF); // count low
    model.write(0x05, 0x01); // count high -> 0x01FF (512 bytes)
    model.write(0x0B, 0x46); // single mode, increment, read (device -> memory)
    model.write(0x81, 0x00); // page 0
    model.write(0x0A, 0x02); // unmask channel 2

    let channel = model.channel(dma::FLOPPY_CHANNEL).expect("channel 2");
    assert_eq!(channel.physical_address(), 0x0000_7C00);
    assert_eq!(channel.remaining(), 512);
    assert!(!channel.masked);
    assert!(!channel.is_write(), "0x46 is a read transfer");

    model.complete(dma::FLOPPY_CHANNEL, 512);
    let channel = model.channel(dma::FLOPPY_CHANNEL).expect("channel 2");
    assert_eq!(channel.physical_address(), 0x0000_7E00);
    assert_eq!(channel.count, 0);
}

// ---------------------------------------------------------------------------
// Host keyboard input (8042 scancode queue)
// ---------------------------------------------------------------------------

#[test]
fn keyboard_queues_host_scancodes_and_reports_the_buffer_full() {
    let mut controller = KeyboardController::new();
    assert!(!controller.has_scancode());

    assert!(controller.push_scancode(0x1E)); // 'a' make
    assert!(controller.has_scancode());
    assert_eq!(controller.pending_scancodes(), 1);
    // Status bit 0 ("output buffer full") is what a DOS driver polls.
    assert_eq!(controller.read(keyboard::STATUS_PORT).expect("status") & 0x01, 1);
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0x1E));
    assert!(!controller.has_scancode());
    assert_eq!(controller.read(keyboard::STATUS_PORT).expect("status") & 0x01, 0);
}

#[test]
fn keyboard_controller_replies_come_before_scancodes() {
    // A real 8042 has a single output buffer: a controller reply queued first
    // (the ACK of a keyboard command) is read before the next scancode.
    let mut controller = KeyboardController::new();
    controller.write(keyboard::DATA_PORT, 0xF2); // read ID -> ACK then two ID bytes
    assert!(controller.push_scancode(0x1E));
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0xFA));
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0xAB));
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0x83));
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0x1E));
}

#[test]
fn keyboard_scancode_queue_is_bounded() {
    let mut controller = KeyboardController::new();
    for index in 0..keyboard::INPUT_CAPACITY {
        assert!(controller.push_scancode(index as u8), "byte {index}");
    }
    assert!(!controller.push_scancode(0xFF), "queue must be full");
    assert_eq!(
        controller.pending_scancodes() as usize,
        keyboard::INPUT_CAPACITY
    );
    // Draining one byte frees exactly one slot.
    assert_eq!(controller.read(keyboard::DATA_PORT), Some(0));
    assert!(controller.push_scancode(0xFE));
}

#[test]
fn text_becomes_us_layout_make_and_break_scancodes() {
    let mut codes = Vec::new();
    keyboard::text_to_scancodes(b"aA\r", &mut codes);
    assert_eq!(
        codes,
        vec![
            0x1E, 0x9E, // a: make, break
            0x2A, 0x1E, 0x9E, 0xAA, // A: shift down, a, a break, shift up
            0x1C, 0x9C, // Enter
        ]
    );

    // Symbols that need shift are bracketed by the shift press/release.
    let mut codes = Vec::new();
    keyboard::text_to_scancodes(b"!?", &mut codes);
    assert_eq!(codes, vec![0x2A, 0x02, 0x82, 0xAA, 0x2A, 0x35, 0xB5, 0xAA]);

    // Characters a PC keyboard cannot type are skipped, not encoded blindly.
    let mut codes = Vec::new();
    keyboard::text_to_scancodes(b"a\x07b", &mut codes);
    assert_eq!(codes, vec![0x1E, 0x9E, 0x30, 0xB0]);
}

// ---------------------------------------------------------------------------
// 8259 pair in firmware-handoff state
// ---------------------------------------------------------------------------

#[test]
fn pic_hands_over_the_vectors_a_bios_leaves() {
    let mut pic = Pic::bios_default();
    assert_eq!(pic.master().vector_base(), 0x08);
    assert_eq!(pic.slave().vector_base(), 0x70);
    // Timer (IR0) and keyboard (IR1) are live, everything else is masked.
    assert_eq!(pic.master().mask(), 0xF8);

    pic.raise(0);
    assert!(pic.has_pending());
    assert_eq!(pic.acknowledge(), Some(0x08));
    assert!(!pic.has_pending(), "the timer request is now in service");
    // The in-service register blocks a second delivery until the EOI.
    pic.raise(0);
    assert_eq!(pic.acknowledge(), None);
    pic.eoi();
    assert_eq!(pic.acknowledge(), Some(0x08));

    // Leave the timer request out of service before checking the keyboard.
    pic.eoi();
    pic.raise(1);
    assert_eq!(pic.acknowledge(), Some(0x09));

    // A slave device is delivered through the cascade with its own vector once
    // the guest unmasks its line on the slave chip.
    pic.eoi();
    pic.write(pic::port::SLAVE_DATA, 0xFE);
    pic.raise(8);
    assert_eq!(pic.acknowledge(), Some(0x70));
}

#[test]
fn pic_reads_back_its_masks_for_the_guest() {
    let mut pic = Pic::bios_default();
    assert_eq!(pic.read(pic::port::MASTER_DATA), Some(0xF8));
    assert_eq!(pic.read(pic::port::SLAVE_DATA), Some(0xFF));
    // OCW1: the guest unmasks IRQ0 only.
    pic.write(pic::port::MASTER_DATA, 0xFE);
    assert_eq!(pic.read(pic::port::MASTER_DATA), Some(0xFE));
    pic.raise(0);
    assert_eq!(pic.acknowledge(), Some(0x08));
}
