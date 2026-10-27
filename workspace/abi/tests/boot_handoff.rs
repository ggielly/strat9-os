//! L0/L1 : boot handoff (`KernelArgs`) layout and boot-log ring geometry.
//!
//! The loader and the kernel are built separately and only meet through this
//! struct, so every field offset is pinned here. A silent reordering would
//! otherwise boot into nonsense instead of failing at compile time.

use core::mem::{offset_of, size_of};

use strat9_abi::boot::{
    BootLogSpans, KernelArgs, MAX_BOOT_LOG_SIZE, MIN_BOOT_LOG_SIZE, STRAT9_BOOT_ABI_VERSION,
};

fn blank_args() -> KernelArgs {
    // SAFETY: every field is an integer, so the all-zero bit pattern is valid.
    let mut args: KernelArgs = unsafe { core::mem::zeroed() };
    args.magic = strat9_abi::boot::STRAT9_BOOT_MAGIC;
    args.abi_version = STRAT9_BOOT_ABI_VERSION;
    args
}

fn ring(size: u64, written: u64) -> KernelArgs {
    let mut args = blank_args();
    args.boot_log_base = 0x4000_0000;
    args.boot_log_size = size;
    args.boot_log_written = written;
    args
}

#[test]
fn kernel_args_layout_is_pinned() {
    assert_eq!(STRAT9_BOOT_ABI_VERSION, 6);
    assert_eq!(size_of::<KernelArgs>(), 156);
    assert_eq!(core::mem::align_of::<KernelArgs>(), 1);

    // Fields added by earlier versions keep their offsets: only the tail grew.
    assert_eq!(offset_of!(KernelArgs, magic), 0);
    assert_eq!(offset_of!(KernelArgs, abi_version), 4);
    assert_eq!(offset_of!(KernelArgs, kernel_base), 8);
    assert_eq!(offset_of!(KernelArgs, acpi_rsdp_base), 24);
    assert_eq!(offset_of!(KernelArgs, memory_map_base), 32);
    assert_eq!(offset_of!(KernelArgs, framebuffer_addr), 48);
    assert_eq!(offset_of!(KernelArgs, hhdm_offset), 56);
    assert_eq!(offset_of!(KernelArgs, cmdline_ptr), 64);
    assert_eq!(offset_of!(KernelArgs, modules_base), 80);
    assert_eq!(offset_of!(KernelArgs, framebuffer_width), 96);
    assert_eq!(offset_of!(KernelArgs, framebuffer_bpp), 108);
    assert_eq!(offset_of!(KernelArgs, bss_virt_base), 116);
    // v6 tail.
    assert_eq!(offset_of!(KernelArgs, boot_log_base), 132);
    assert_eq!(offset_of!(KernelArgs, boot_log_size), 140);
    assert_eq!(offset_of!(KernelArgs, boot_log_written), 148);
}

#[test]
fn absent_boot_log_is_not_an_error() {
    assert_eq!(blank_args().boot_log_spans(), Ok(BootLogSpans::EMPTY));
    // A ring allocated but never written is empty too.
    assert_eq!(ring(4096, 0).boot_log_spans(), Ok(BootLogSpans::EMPTY));
}

#[test]
fn half_available_or_partial_geometry_is_rejected() {
    let mut args = ring(4096, 0);
    args.boot_log_size = 0;
    assert!(args.boot_log_spans().is_err());
    let mut args = ring(4096, 0);
    args.boot_log_base = 0;
    assert!(args.boot_log_spans().is_err());

    // Not a power of two, below the page floor, above the sanity ceiling.
    assert!(ring(3000, 0).boot_log_spans().is_err());
    assert!(ring(MIN_BOOT_LOG_SIZE / 2, 0).boot_log_spans().is_err());
    assert!(ring(MAX_BOOT_LOG_SIZE * 2, 0).boot_log_spans().is_err());
    // A ring that is not page aligned cannot be a reserved page range.
    let mut args = ring(4096, 0);
    args.boot_log_base += 8;
    assert!(args.boot_log_spans().is_err());
}

#[test]
fn unwrapped_log_runs_from_offset_zero() {
    let spans = ring(4096, 100).boot_log_spans().unwrap();
    assert_eq!(
        spans,
        BootLogSpans {
            start: 0,
            first: 100,
            second: 0
        }
    );
    // Exactly one full ring is still a single span.
    let spans = ring(4096, 4096).boot_log_spans().unwrap();
    assert_eq!((spans.start, spans.first, spans.second), (0, 4096, 0));
}

#[test]
fn wrapped_log_is_reported_oldest_first_in_two_spans() {
    // Exactly one ring written: the reader starts at offset 0.
    let spans = ring(4096, 4096).boot_log_spans().unwrap();
    assert_eq!((spans.start, spans.first, spans.second), (0, 4096, 0));
    assert_eq!(spans.len(), 4096);
    assert!(!spans.is_empty());

    // 4196 written into a 4096-byte ring: the 100 oldest bytes still sit at
    // offset 4096-100=3996 and the newest 3996 wrap to the start.
    let spans = ring(4096, 4196).boot_log_spans().unwrap();
    assert_eq!((spans.start, spans.first, spans.second), (100, 3996, 100));
    assert_eq!(spans.len(), 4096);

    // The two spans always tile the valid window exactly.
    for written in [1u64, 4095, 4096, 4097, 8192, 16_383, 100_000] {
        let spans = ring(4096, written).boot_log_spans().unwrap();
        let expected = written.min(4096) as usize;
        assert_eq!(spans.len(), expected, "written={written}");
        assert!(spans.first <= 4096 && spans.second <= 4096);
        assert!(spans.start < 4096);
        // A non-empty second span means the first one ran exactly to the end.
        if spans.second != 0 {
            assert_eq!(spans.start + spans.first, 4096, "written={written}");
        }
    }
}

#[test]
fn a_saturated_counter_still_yields_a_valid_window() {
    // The counter is monotonic and may sit anywhere; only its remainder matters.
    let spans = ring(4096, u64::MAX).boot_log_spans().unwrap();
    assert_eq!(spans.len(), 4096);
    assert_eq!(
        spans.start,
        (u64::MAX - 4096) as usize % 4096,
        "start must be written - size, modulo the ring"
    );
}
