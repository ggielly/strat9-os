//! L2: 82077AA floppy controller model used by the SeaBIOS boot path.
//!
//! The controller is pure: it decodes commands, queues results and raises IRQ
//! flags, while the caller performs the DMA transfer. The tests pin the
//! command sequence SeaBIOS issues during `INT 13h`.

extern crate alloc;

use alloc::{vec, vec::Vec};

#[path = "../../kernel/src/s9vm/fdc.rs"]
mod fdc;

use fdc::{
    blank_image, FdcEvent, FloppyController, CMD_READ_DATA, CMD_READ_ID, CMD_RECALIBRATE,
    CMD_SENSE_INTERRUPT, CMD_WRITE_DATA, DATA_PORT, DOR_IRQ_DMA, DOR_PORT, DOR_RESET, MSR_DIO,
    MSR_PORT, MSR_RQM,
};

fn controller_with_image() -> FloppyController {
    let mut controller = FloppyController::new();
    controller.load_image(&blank_image());
    controller
}

fn send(controller: &mut FloppyController, bytes: &[u8]) -> FdcEvent {
    let mut event = FdcEvent::None;
    for byte in bytes {
        event = controller.write(DATA_PORT, *byte);
    }
    event
}

fn read_result(controller: &mut FloppyController, count: usize) -> Vec<u8> {
    (0..count)
        .map(|_| controller.read(DATA_PORT).expect("data port"))
        .collect()
}

#[test]
fn reset_raises_irq_and_reports_ready() {
    let mut controller = controller_with_image();
    // SeaBIOS clears reset first, then sets reset+IRQ+DMA: the 0 -> 1 edge is
    // the controller initialisation completion.
    let event = controller.write(DOR_PORT, 0);
    assert_eq!(event, FdcEvent::None);
    let event = controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    assert_eq!(event, FdcEvent::Irq);
    assert!(controller.take_irq());
    assert!(!controller.take_irq());
    let status = controller.read(MSR_PORT).expect("msr");
    assert_eq!(status & MSR_RQM, MSR_RQM, "ready for a byte: {status:#04x}");
    assert_eq!(status & MSR_DIO, 0, "host may write: {status:#04x}");
}

#[test]
fn sense_interrupt_returns_two_bytes() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    let event = send(&mut controller, &[CMD_SENSE_INTERRUPT]);
    assert_eq!(event, FdcEvent::None);
    let result = read_result(&mut controller, 2);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0] & 0xC0, 0, "normal completion");
    assert_eq!(
        controller.read(MSR_PORT).expect("msr") & MSR_DIO,
        0,
        "result drained"
    );
}

#[test]
fn read_id_reports_the_geometry() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    // Recalibrate first, as SeaBIOS does before media sense.
    let event = send(&mut controller, &[CMD_RECALIBRATE, 0]);
    assert_eq!(event, FdcEvent::Irq);
    assert!(controller.take_irq());
    // CHECKIRQ result from the recalibrate is not read by this test.
    let _ = send(&mut controller, &[CMD_SENSE_INTERRUPT]);
    let _ = read_result(&mut controller, 2);

    let event = send(&mut controller, &[CMD_READ_ID, 0]);
    assert_eq!(event, FdcEvent::Irq);
    assert!(controller.take_irq());
    let result = read_result(&mut controller, 7);
    assert_eq!(result[0] & 0x03, 0, "drive 0");
    assert_eq!(result[3], 0, "cylinder");
    assert_eq!(result[4], 0, "head");
    assert_eq!(result[5], 1, "sector id starts at 1");
    assert_eq!(result[6], 2, "512-byte sectors");
}

#[test]
fn read_data_requests_a_dma_transfer() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    // READ DATA: drive/head, C, H, R, N, EOT, GPL, DTL.
    let event = send(
        &mut controller,
        &[
            CMD_READ_DATA,
            0x00,
            0x00,
            0x00,
            0x01,
            0x02,
            0x01,
            0x1B,
            0xFF,
        ],
    );
    assert_eq!(
        event,
        FdcEvent::Transfer(fdc::FdcTransfer {
            write: false,
            lba: 0,
            sectors: 1,
        })
    );
    assert!(controller.take_irq());
    let result = read_result(&mut controller, 7);
    assert_eq!(result[0] & 0xC0, 0, "normal completion");
    assert_eq!(result[3], 0, "cylinder");
    assert_eq!(result[5], 1, "sector");
    assert_eq!(controller.last_transfer().map(|t| t.lba), Some(0));
}

#[test]
fn write_data_requests_a_device_to_memory_transfer() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    let event = send(
        &mut controller,
        &[
            CMD_WRITE_DATA,
            0x00,
            0x00,
            0x00,
            0x01,
            0x02,
            0x01,
            0x1B,
            0xFF,
        ],
    );
    match event {
        FdcEvent::Transfer(transfer) => assert!(transfer.write),
        other => panic!("expected a write transfer, got {other:?}"),
    }
}

#[test]
fn out_of_range_cylinder_fails_without_a_transfer() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    let event = send(
        &mut controller,
        &[CMD_READ_DATA, 0x00, 80, 0x00, 0x01, 0x02, 0x01, 0x1B, 0xFF],
    );
    assert_eq!(event, FdcEvent::Irq);
    assert!(controller.take_irq());
    let result = read_result(&mut controller, 7);
    assert_ne!(result[0] & 0xC0, 0, "abnormal termination");
    assert!(controller.last_transfer().is_none());
}

#[test]
fn unknown_command_completes_with_invalid_status() {
    let mut controller = controller_with_image();
    controller.write(DOR_PORT, DOR_RESET | DOR_IRQ_DMA);
    let _ = controller.take_irq();
    let event = send(&mut controller, &[0x7F]);
    assert_eq!(event, FdcEvent::Irq);
    assert!(controller.take_irq());
    assert_eq!(read_result(&mut controller, 1), vec![0x80]);
}
