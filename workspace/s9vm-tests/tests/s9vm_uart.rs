//! L2: s9vm 16550A UART device model (COM1, real kernel code).

extern crate alloc;

#[path = "../../kernel/src/s9vm/uart.rs"]
mod uart;

use uart::{BASE_PORT, IRQ_LINE, PORT_COUNT, Uart, handles_port, ier, iir, lsr, mcr, reg};

fn divisor(uart: &mut Uart, low: u8, high: u8) {
    uart.write(reg::LCR, 0x80);
    uart.write(reg::RBR_THR, low);
    uart.write(reg::IER, high);
}

#[test]
fn handles_port_covers_com1_only() {
    assert_eq!(BASE_PORT, 0x3F8);
    assert_eq!(PORT_COUNT, 8);
    assert_eq!(IRQ_LINE, 4);
    assert!(!handles_port(0x3F7));
    for offset in 0..PORT_COUNT {
        assert!(handles_port(BASE_PORT + offset));
    }
    assert!(!handles_port(BASE_PORT + PORT_COUNT));
    assert!(!handles_port(0));
}

#[test]
fn reset_state_matches_16550_defaults() {
    let mut uart = Uart::new();
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
    assert_eq!(uart.read(reg::LSR), 0x60);
    assert_eq!(uart.read(reg::MSR), 0xB0);
    assert_eq!(uart.read(reg::IER), 0);
    assert_eq!(uart.read(reg::LCR), 0);
    assert_eq!(uart.read(reg::MCR), 0);
    assert_eq!(uart.read(reg::SCR), 0);
    assert!(!uart.irq_asserted());
    assert!(uart.drain_output().is_empty());
}

#[test]
fn transmitted_bytes_are_drained_once() {
    let mut uart = Uart::new();
    uart.write(reg::RBR_THR, b'H');
    uart.write(reg::RBR_THR, b'i');
    uart.write(reg::RBR_THR, b'!');
    assert_eq!(uart.drain_output(), b"Hi!".to_vec());
    assert!(uart.drain_output().is_empty());
    // The transmitter is always ready in this model.
    assert_eq!(uart.read(reg::LSR) & 0x60, 0x60);
}

#[test]
fn input_fifo_sets_and_clears_data_ready() {
    let mut uart = Uart::new();
    assert_eq!(uart.push_input(b"abc"), 3);
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, lsr::DATA_READY);
    assert_eq!(uart.read(reg::RBR_THR), b'a');
    assert_eq!(uart.read(reg::RBR_THR), b'b');
    assert_eq!(uart.read(reg::RBR_THR), b'c');
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, 0);
    // Reading an empty receive buffer returns zero.
    assert_eq!(uart.read(reg::RBR_THR), 0);
}

#[test]
fn input_fifo_is_bounded() {
    let mut uart = Uart::new();
    let bytes = [0xAAu8; 32];
    assert_eq!(uart.push_input(&bytes), uart::INPUT_CAPACITY);
    for _ in 0..uart::INPUT_CAPACITY {
        assert_eq!(uart.read(reg::RBR_THR), 0xAA);
    }
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, 0);
}

#[test]
fn rx_interrupt_is_masked_by_ier_and_cleared_by_rbr() {
    let mut uart = Uart::new();
    uart.write(reg::IER, ier::RX_DATA);
    uart.push_input(b"x");
    assert!(uart.irq_asserted());
    assert_eq!(uart.read(reg::IIR_FCR), iir::RX_DATA);
    // Reading IIR does not consume the received byte: still pending.
    assert!(uart.irq_asserted());
    // Masking the source drops the interrupt line, not the pending byte.
    uart.write(reg::IER, 0);
    assert!(!uart.irq_asserted());
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
    // Consuming the byte clears the source.
    assert_eq!(uart.read(reg::RBR_THR), b'x');
    uart.write(reg::IER, ier::RX_DATA);
    assert!(!uart.irq_asserted());
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
}

#[test]
fn thre_interrupt_is_cleared_by_reading_iir() {
    let mut uart = Uart::new();
    uart.write(reg::IER, ier::THR_EMPTY);
    assert!(!uart.irq_asserted());
    uart.write(reg::RBR_THR, b'A');
    assert!(uart.irq_asserted());
    assert_eq!(uart.read(reg::IIR_FCR), iir::THR_EMPTY);
    assert!(!uart.irq_asserted());
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
}

#[test]
fn iir_priority_prefers_rx_data_over_thre() {
    let mut uart = Uart::new();
    uart.write(reg::IER, ier::RX_DATA | ier::THR_EMPTY);
    uart.push_input(b"x");
    uart.write(reg::RBR_THR, b'y');
    // RX data has priority over THR empty.
    assert_eq!(uart.read(reg::IIR_FCR), iir::RX_DATA);
    assert_eq!(uart.read(reg::RBR_THR), b'x');
    // The first IIR read acknowledged THRE; with RX consumed nothing remains.
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
}

#[test]
fn iir_priority_prefers_line_status_over_rx_data() {
    let mut uart = Uart::new();
    uart.write(reg::IER, ier::LINE_STATUS | ier::RX_DATA);
    // LCR.SET_BREAK forces a break (LSR.BI) and thus a line-status interrupt.
    uart.write(reg::LCR, 0x40);
    uart.push_input(b"x");
    assert_ne!(uart.read(reg::LSR) & lsr::BREAK, 0);
    assert_eq!(uart.read(reg::IIR_FCR), iir::LINE_STATUS);
    uart.write(reg::LCR, 0);
    assert_eq!(uart.read(reg::IIR_FCR), iir::RX_DATA);
    assert_eq!(uart.read(reg::RBR_THR), b'x');
    assert_eq!(uart.read(reg::IIR_FCR), iir::NONE);
}

#[test]
fn dlab_switches_offsets_zero_and_one_to_divisors() {
    let mut uart = Uart::new();
    uart.write(reg::IER, ier::THR_EMPTY);
    divisor(&mut uart, 0x01, 0x00);
    // While DLAB is set, offsets 0/1 expose DLL/DLM, not RBR/IER.
    assert_eq!(uart.read(reg::RBR_THR), 0x01);
    assert_eq!(uart.read(reg::IER), 0x00);
    assert!(uart.drain_output().is_empty());
    // THR writes while DLAB is set program the divisor, they do not transmit.
    uart.write(reg::RBR_THR, 0xAA);
    assert!(uart.drain_output().is_empty());
    // Back to normal registers.
    uart.write(reg::LCR, 0);
    assert_eq!(uart.read(reg::IER), ier::THR_EMPTY);
    assert_eq!(uart.read(reg::RBR_THR), 0);
}

#[test]
fn loopback_feeds_transmitted_bytes_to_the_receiver() {
    let mut uart = Uart::new();
    uart.write(reg::MCR, mcr::LOOPBACK);
    uart.write(reg::RBR_THR, b'L');
    // The byte is looped back and must not reach the host log.
    assert!(uart.drain_output().is_empty());
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, lsr::DATA_READY);
    assert_eq!(uart.read(reg::RBR_THR), b'L');
    // Disabling loopback restores the external transmit path.
    uart.write(reg::MCR, 0);
    uart.write(reg::RBR_THR, b'X');
    assert_eq!(uart.drain_output(), b"X".to_vec());
}

#[test]
fn mcr_loopback_drives_msr_inputs_and_deltas() {
    let mut uart = Uart::new();
    // Reset MSR: CTS|DSR|DCD, no delta.
    assert_eq!(uart.read(reg::MSR), 0xB0);
    // Loopback with all modem outputs asserted maps RTS→CTS, DTR→DSR,
    // OUT1→RI, OUT2→DCD.
    uart.write(
        reg::MCR,
        mcr::LOOPBACK | mcr::DTR | mcr::RTS | mcr::OUT1 | mcr::OUT2,
    );
    let status = uart.read(reg::MSR);
    assert_eq!(status & 0xF0, 0xF0);
    assert_ne!(status & 0x0F, 0);
    // Delta bits are cleared by the read above.
    assert_eq!(uart.read(reg::MSR) & 0x0F, 0);
    // Dropping the outputs changes the inputs again.
    uart.write(reg::MCR, mcr::LOOPBACK);
    let status = uart.read(reg::MSR);
    assert_eq!(status & 0xF0, 0);
    assert_ne!(status & 0x0F, 0);
}

#[test]
fn scratch_register_and_unknown_offsets() {
    let mut uart = Uart::new();
    uart.write(reg::SCR, 0x5A);
    assert_eq!(uart.read(reg::SCR), 0x5A);
    // Out-of-window offsets are ignored/read as zero, never panic.
    uart.write(8, 0xFF);
    uart.write(0xFFFF, 0xFF);
    assert_eq!(uart.read(8), 0);
    assert_eq!(uart.read(0xFFFF), 0);
    // LSR/MSR are read-only.
    uart.write(reg::LSR, 0x00);
    assert_eq!(uart.read(reg::LSR) & 0x60, 0x60);
}

#[test]
fn fcr_receive_clear_empties_the_input_fifo() {
    let mut uart = Uart::new();
    uart.push_input(b"abc");
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, lsr::DATA_READY);
    uart.write(reg::IIR_FCR, 0x02);
    assert_eq!(uart.read(reg::LSR) & lsr::DATA_READY, 0);
    assert_eq!(uart.read(reg::RBR_THR), 0);
}
