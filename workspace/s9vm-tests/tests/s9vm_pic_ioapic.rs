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
