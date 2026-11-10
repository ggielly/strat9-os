//! L2: guest 8259A PIC and I/O APIC models (real kernel modules, not executed).

#[path = "../../kernel/src/s9vm/ioapic.rs"]
mod ioapic;
#[path = "../../kernel/src/s9vm/pic.rs"]
mod pic;

use ioapic::{IoApic, PIN_COUNT, REDIRECTION_BASE, REG_SELECT, REG_WINDOW};
use pic::{port, Chip, Pic, CASCADE_IRQ};

fn init_pic() -> Pic {
    let mut pic = Pic::new();
    pic.write(port::MASTER_COMMAND, 0x11); // ICW1: edge triggered, ICW4
    pic.write(port::MASTER_DATA, 0x08); // ICW2: vector base
    pic.write(port::MASTER_DATA, 0x04); // ICW3: slave on IR2
    pic.write(port::MASTER_DATA, 0x01); // ICW4: 8086 mode
    pic.write(port::SLAVE_COMMAND, 0x11);
    pic.write(port::SLAVE_DATA, 0x70);
    pic.write(port::SLAVE_DATA, 0x02);
    pic.write(port::SLAVE_DATA, 0x01);
    pic.write(port::MASTER_DATA, 0x00); // unmask master
    pic.write(port::SLAVE_DATA, 0x00); // unmask slave
    pic
}

#[test]
fn pic_initialisation_sets_vector_bases() {
    let pic = init_pic();
    assert_eq!(pic.master().vector_base(), 0x08);
    assert_eq!(pic.slave().vector_base(), 0x70);
    assert!(!pic.master().initializing());
    assert_eq!(pic.master().mask(), 0x00);
}

#[test]
fn pic_reset_masks_everything() {
    let mut chip = Chip::new();
    assert_eq!(chip.mask(), 0xFF);
    chip.raise(0);
    assert_eq!(chip.acknowledge(), None);
    assert!(!chip.initializing());
}

#[test]
fn pic_acknowledge_returns_vector_and_sets_isr() {
    let mut pic = init_pic();
    pic.raise(0);
    assert_eq!(pic.acknowledge(), Some(0x08));
    assert_eq!(pic.master().isr(), 0x01);
    assert_eq!(pic.master().irr(), 0x00);
    pic.eoi();
    assert_eq!(pic.master().isr(), 0x00);
}

#[test]
fn pic_highest_priority_wins() {
    let mut pic = init_pic();
    pic.raise(5);
    pic.raise(1);
    assert_eq!(pic.acknowledge(), Some(0x09));
    assert_eq!(pic.master().isr(), 0x02);
}

#[test]
fn pic_mask_blocks_delivery() {
    let mut pic = init_pic();
    pic.write(port::MASTER_DATA, 0x01); // mask IRQ0
    pic.raise(0);
    assert_eq!(pic.acknowledge(), None);
    pic.write(port::MASTER_DATA, 0x00);
    assert_eq!(pic.acknowledge(), Some(0x08));
}

#[test]
fn pic_slave_requests_cascade_through_master() {
    let mut pic = init_pic();
    pic.raise(9); // slave IRQ1
    assert_eq!(pic.acknowledge(), Some(0x71));
    assert_eq!(pic.master().isr(), 1 << CASCADE_IRQ);
    assert_eq!(pic.slave().isr(), 0x02);
    pic.eoi();
    assert_eq!(pic.slave().isr(), 0x00);
    assert_eq!(pic.master().isr(), 0x00);
}

#[test]
fn pic_master_request_beats_cascade() {
    let mut pic = init_pic();
    pic.raise(0);
    pic.raise(9);
    assert_eq!(pic.acknowledge(), Some(0x08));
    assert_eq!(pic.master().isr(), 0x01);
    pic.eoi();
    assert_eq!(pic.acknowledge(), Some(0x71));
}

#[test]
fn pic_read_registers_and_ocw3() {
    let mut pic = init_pic();
    // OCW3: read ISR (0x0B).
    pic.write(port::MASTER_COMMAND, 0x0B);
    assert_eq!(pic.read(port::MASTER_COMMAND), Some(0x00));
    // OCW3: read IRR (0x0A), then raise IRQ3.
    pic.write(port::MASTER_COMMAND, 0x0A);
    pic.raise(3);
    assert_eq!(pic.read(port::MASTER_COMMAND), Some(0x08));
    // Data port returns the mask.
    assert_eq!(pic.read(port::MASTER_DATA), Some(0x00));
}

#[test]
fn pic_ports_are_recognised() {
    assert!(Pic::handles_port(0x20));
    assert!(Pic::handles_port(0xA1));
    assert!(!Pic::handles_port(0x40));
    let mut pic = init_pic();
    assert!(!pic.write(0x40, 0));
    assert_eq!(pic.read(0x40), None);
}

fn write_entry(ioapic: &mut IoApic, pin: usize, low: u32, high: u32) {
    let index = REDIRECTION_BASE + 2 * pin as u32;
    ioapic.mmio_write(REG_SELECT, index);
    ioapic.mmio_write(REG_WINDOW, low);
    ioapic.mmio_write(REG_SELECT, index + 1);
    ioapic.mmio_write(REG_WINDOW, high);
}

#[test]
fn ioapic_reset_state() {
    let ioapic = IoApic::new(7);
    assert_eq!(ioapic.apic_id(), 7);
    assert_eq!(ioapic.mmio_read(REG_SELECT), 0);
    assert_eq!(PIN_COUNT, 24);
    for pin in 0..PIN_COUNT {
        assert!(ioapic.entry(pin).unwrap().masked());
    }
}

#[test]
fn ioapic_version_register() {
    let mut ioapic = IoApic::new(0);
    ioapic.mmio_write(REG_SELECT, 0x01);
    assert_eq!(ioapic.mmio_read(REG_WINDOW), ioapic::VERSION);
}

#[test]
fn ioapic_redirection_round_trip() {
    let mut ioapic = IoApic::new(0);
    // Pin 0: vector 0x30, fixed, physical, edge, unmasked, destination 2.
    write_entry(&mut ioapic, 0, 0x30, 2 << 24);

    let entry = ioapic.entry(0).unwrap();
    assert_eq!(entry.vector(), 0x30);
    assert!(!entry.masked());
    assert!(!entry.level_triggered());
    assert_eq!(entry.destination(), 2);
    assert_eq!(entry.delivery_mode(), 0);
    assert_eq!(ioapic.vector_for_pin(0), Some(0x30));

    // Read back through IOWIN, both halves.
    ioapic.mmio_write(REG_SELECT, REDIRECTION_BASE);
    assert_eq!(ioapic.mmio_read(REG_WINDOW), 0x30);
    ioapic.mmio_write(REG_SELECT, REDIRECTION_BASE + 1);
    assert_eq!(ioapic.mmio_read(REG_WINDOW), 2 << 24);
}

#[test]
fn ioapic_mask_and_delivery_mode() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin(3, 0x40, false);
    assert_eq!(ioapic.vector_for_pin(3), Some(0x40));
    ioapic.set_pin(3, 0x40, true);
    assert_eq!(ioapic.vector_for_pin(3), None);

    // NMI delivery mode (4) is not a fixed vector.
    write_entry(&mut ioapic, 4, (4 << 8) | 0x22, 0);
    let entry = ioapic.entry(4).unwrap();
    assert_eq!(entry.delivery_mode(), 4);
    assert_eq!(ioapic.vector_for_pin(4), None);
}

#[test]
fn ioapic_out_of_range_pin_is_none() {
    let ioapic = IoApic::new(0);
    assert!(ioapic.entry(PIN_COUNT).is_none());
    assert!(ioapic.vector_for_pin(PIN_COUNT).is_none());
}

#[test]
fn ioapic_level_assert_sets_remote_irr_and_eoi_reinjects() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin_mode(2, 0x50, false, true, false);
    assert_eq!(ioapic.set_line_level(2, true), Some(0x50));
    assert!(ioapic.remote_irr(2));
    // Re-asserting while the interrupt is in service does not queue a second
    // delivery.
    assert_eq!(ioapic.set_line_level(2, true), None);
    // EOI clears the remote IRR and re-raises because the line is still high.
    assert_eq!(ioapic.eoi(0x50), Some(0x50));
    assert!(ioapic.remote_irr(2));
    // Deassert then EOI: nothing is re-injected.
    assert_eq!(ioapic.set_line_level(2, false), None);
    assert_eq!(ioapic.eoi(0x50), None);
    assert!(!ioapic.remote_irr(2));
}

#[test]
fn ioapic_level_deassert_before_eoi_does_not_reinject() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin_mode(3, 0x51, false, true, false);
    assert_eq!(ioapic.set_line_level(3, true), Some(0x51));
    assert_eq!(ioapic.set_line_level(3, false), None);
    assert_eq!(ioapic.eoi(0x51), None);
    assert!(!ioapic.remote_irr(3));
}

#[test]
fn ioapic_masked_level_is_recorded_and_raised_on_unmask() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin_mode(4, 0x52, true, true, false);
    assert_eq!(ioapic.set_line_level(4, true), None);
    assert!(ioapic.line_asserted(4));
    assert!(!ioapic.remote_irr(4));
    // Unmask and re-evaluate: the already-asserted line is delivered.
    ioapic.set_pin_mode(4, 0x52, false, true, false);
    assert_eq!(ioapic.refresh_pin(4), Some(0x52));
    assert!(ioapic.remote_irr(4));
}

#[test]
fn ioapic_edge_line_is_not_reinjected_by_eoi() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin_mode(5, 0x53, false, false, false);
    assert_eq!(ioapic.set_line_level(5, true), Some(0x53));
    // A second assertion at the same level is not a new edge.
    assert_eq!(ioapic.set_line_level(5, true), None);
    assert_eq!(ioapic.eoi(0x53), None);
    assert!(!ioapic.remote_irr(5));
}

#[test]
fn ioapic_trigger_polarity_and_delivery_bits_decode() {
    let mut ioapic = IoApic::new(0);
    // vector 0x60, level-triggered, active-low, NMI delivery.
    write_entry(&mut ioapic, 6, 0x60 | (4 << 8) | (1 << 13) | (1 << 15), 0);
    let entry = ioapic.entry(6).unwrap();
    assert_eq!(entry.vector(), 0x60);
    assert!(entry.level_triggered());
    assert!(entry.active_low());
    assert_eq!(entry.delivery_mode(), 4);
    assert_eq!(ioapic.vector_for_pin(6), None);
}

#[test]
fn ioapic_level_with_nonfixed_delivery_is_not_raised() {
    let mut ioapic = IoApic::new(0);
    write_entry(&mut ioapic, 7, 0x61 | (5 << 8) | (1 << 15), 0);
    assert_eq!(ioapic.set_line_level(7, true), None);
    assert!(!ioapic.remote_irr(7));
}

#[test]
fn ioapic_eoi_only_clears_matching_vector() {
    let mut ioapic = IoApic::new(0);
    ioapic.set_pin_mode(8, 0x54, false, true, false);
    assert_eq!(ioapic.set_line_level(8, true), Some(0x54));
    assert_eq!(ioapic.eoi(0x55), None);
    assert!(ioapic.remote_irr(8));
    assert_eq!(ioapic.eoi(0x54), Some(0x54));
}

#[test]
fn ioapic_adversarial_level_values_do_not_panic() {
    let mut ioapic = IoApic::new(0);
    for pin in 0..PIN_COUNT + 4 {
        let _ = ioapic.set_line_level(pin, true);
        let _ = ioapic.set_line_level(pin, false);
        let _ = ioapic.refresh_pin(pin);
        let _ = ioapic.eoi(pin as u8);
    }
    ioapic.set_pin_mode(0, 0xFF, false, true, true);
    assert_eq!(ioapic.set_line_level(0, true), Some(0xFF));
}
