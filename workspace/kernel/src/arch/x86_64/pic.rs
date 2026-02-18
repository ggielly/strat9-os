//! 8259 Programmable Interrupt Controller (PIC) driver
//! Inspired by MaestroOS `pic.rs`
//!
//! The PIC handles hardware interrupts (IRQs) and maps them to
//! CPU interrupt vectors. We remap IRQs to vectors 0x20-0x2F.

use super::io::{inb, outb};

/// Master PIC command port
const MASTER_COMMAND: u16 = 0x20;
/// Master PIC data port
const MASTER_DATA: u16 = 0x21;
/// Slave PIC command port
const SLAVE_COMMAND: u16 = 0xA0;
/// Slave PIC data port
const SLAVE_DATA: u16 = 0xA1;

/// ICW1: Initialization + ICW4 needed
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
/// ICW3: Slave PIC on IRQ2
const ICW3_SLAVE_PIC: u8 = 0x04;
/// ICW3: Cascade identity for slave
const ICW3_CASCADE: u8 = 0x02;
/// ICW4: 8086 mode
const ICW4_8086: u8 = 0x01;

/// End-of-interrupt command
const COMMAND_EOI: u8 = 0x20;

/// IRQ offset for master PIC (IRQ0 -> interrupt 0x20)
pub const PIC1_OFFSET: u8 = 0x20;
/// IRQ offset for slave PIC (IRQ8 -> interrupt 0x28)
pub const PIC2_OFFSET: u8 = 0x28;

/// Initialize the PIC with the given offsets.
///
/// Remaps IRQ0-7 to `offset1` and IRQ8-15 to `offset2`.
pub fn init(offset1: u8, offset2: u8) {
    unsafe {
        // Save masks
        let mask1 = inb(MASTER_DATA);
        let mask2 = inb(SLAVE_DATA);

        // Start initialization sequence
        outb(MASTER_COMMAND, ICW1_INIT | ICW1_ICW4);
        super::io::io_wait();
        outb(SLAVE_COMMAND, ICW1_INIT | ICW1_ICW4);
        super::io::io_wait();

        // Set vector offsets
        outb(MASTER_DATA, offset1);
        super::io::io_wait();
        outb(SLAVE_DATA, offset2);
        super::io::io_wait();

        // Configure cascading
        outb(MASTER_DATA, ICW3_SLAVE_PIC);
        super::io::io_wait();
        outb(SLAVE_DATA, ICW3_CASCADE);
        super::io::io_wait();

        // Set 8086 mode
        outb(MASTER_DATA, ICW4_8086);
        super::io::io_wait();
        outb(SLAVE_DATA, ICW4_8086);
        super::io::io_wait();

        // Restore saved masks
        outb(MASTER_DATA, mask1);
        outb(SLAVE_DATA, mask2);
    }
}

/// Disable all IRQs on both PICs.
pub fn disable() {
    unsafe {
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
    }
}

/// Disable the 8259 PIC permanently by masking all IRQs.
///
/// Call this after remapping the PIC (to avoid stray interrupts at
/// CPU exception vectors) and after the I/O APIC is ready to take over.
pub fn disable_permanently() {
    unsafe {
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
    }
    log::info!("Legacy 8259 PIC disabled permanently");
}

/// Enable a specific IRQ line.
pub fn enable_irq(mut irq: u8) {
    let port = if irq < 8 {
        MASTER_DATA
    } else {
        irq -= 8;
        SLAVE_DATA
    };
    unsafe {
        let value = inb(port) & !(1 << irq);
        outb(port, value);
    }
}

/// Disable a specific IRQ line.
pub fn disable_irq(mut irq: u8) {
    let port = if irq < 8 {
        MASTER_DATA
    } else {
        irq -= 8;
        SLAVE_DATA
    };
    unsafe {
        let value = inb(port) | (1 << irq);
        outb(port, value);
    }
}

/// Send End-Of-Interrupt to the PIC for the given IRQ.
pub fn end_of_interrupt(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(SLAVE_COMMAND, COMMAND_EOI);
        }
        outb(MASTER_COMMAND, COMMAND_EOI);
    }
}
