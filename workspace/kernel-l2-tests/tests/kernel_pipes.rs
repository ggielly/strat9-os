//! L2 — Kernel pipes (verbatim code): FIFO semantics, EOF, EPIPE, EAGAIN,
//! ring wraparound, and the PipeScheme registry.
//!
//! Blocking paths are avoided (single-threaded host); non-blocking variants
//! pin the WouldBlock/EPIPE/EOF contracts. If a test accidentally blocks,
//! the fake `process::block_current_task` panics loudly.

use std::sync::Arc;

use kernel_l2_tests::sync::SpinLock;
use kernel_l2_tests::syscall::error::SyscallError as SyscallErrorAlias;
use kernel_l2_tests::vfs::pipe::{Pipe, PipeScheme};

// ===========================================================================
// Basic data plane
// ===========================================================================

#[test]
fn pipe_write_then_read_fifo() {
    let p = Pipe::new();
    assert_eq!(p.write(b"hello", true), Ok(5));
    let mut buf = [0u8; 5];
    assert_eq!(p.read(&mut buf, true), Ok(5));
    assert_eq!(&buf, b"hello");
}

#[test]
fn pipe_partial_reads_consume_in_order() {
    let p = Pipe::new();
    p.write(b"abcdef", true).unwrap();

    let mut buf = [0u8; 2];
    assert_eq!(p.read(&mut buf, true), Ok(2));
    assert_eq!(&buf, b"ab");
    assert_eq!(p.read(&mut buf, true), Ok(2));
    assert_eq!(&buf, b"cd");
    // Partial tail: only what's available.
    assert_eq!(p.read(&mut buf, true), Ok(2));
    assert_eq!(&buf, b"ef");
    assert_eq!(p.read(&mut buf, true), Err(SyscallErrorAlias::Again));
}

#[test]
fn pipe_empty_read_nonblocking_is_eagain() {
    let p = Pipe::new();
    let mut buf = [0u8; 4];
    assert!(matches!(
        p.read(&mut buf, true),
        Err(SyscallErrorAlias::Again)
    ));
}

#[test]
fn pipe_empty_write_is_noop() {
    let p = Pipe::new();
    assert_eq!(p.write(b"", true), Ok(0));
}

// ===========================================================================
// Ring wraparound: PIPE_BUF_SIZE = 4096
// ===========================================================================

#[test]
fn pipe_ring_positions_wrap_modulo_4096() {
    let p = Pipe::new();
    const PIPE_BUF_SIZE: usize = 4096;

    // Fill completely, drain completely — twice — to force both positions
    // through the modulo boundary.
    let chunk = vec![0xA7u8; 1024];
    for _ in 0..4 {
        assert_eq!(p.write(&chunk, true), Ok(1024));
    }
    assert!(matches!(p.write(b"x", true), Err(SyscallErrorAlias::Again)));

    let mut buf = vec![0u8; 4096];
    assert_eq!(p.read(&mut buf, true), Ok(4096));
    assert!(buf.iter().all(|&b| b == 0xA7));

    for _ in 0..4 {
        assert_eq!(p.write(&chunk, true), Ok(1024));
    }
    let mut buf2 = vec![0u8; 4096];
    assert_eq!(p.read(&mut buf2, true), Ok(4096));
    assert!(buf2.iter().all(|&b| b == 0xA7), "wraparound corrupted data");
}

// ===========================================================================
// Lifecycle: EOF on writer close, EPIPE on reader close
// ===========================================================================

#[test]
fn pipe_close_writer_gives_eof_not_eagain() {
    let p = Pipe::new();
    p.close_write();
    let mut buf = [0u8; 4];
    // Empty + write-closed → Ok(0) = EOF, even in blocking mode.
    assert_eq!(p.read(&mut buf, false), Ok(0));
}

#[test]
fn pipe_drain_survives_writer_close() {
    let p = Pipe::new();
    p.write(b"last bytes", true).unwrap();
    p.close_write();
    let mut buf = [0u8; 32];
    assert_eq!(p.read(&mut buf, false), Ok(10));
    assert_eq!(&buf[..10], b"last bytes");
    assert_eq!(p.read(&mut buf, false), Ok(0)); // then EOF
}

#[test]
fn pipe_close_reader_makes_write_fail_with_epipe() {
    eprintln!("[cr] start");
    let p = Pipe::new();
    eprintln!("[cr] created");
    assert!(p.close_read(), "first close_read must report the transition");
    eprintln!("[cr] read end closed");
    let r = p.write(b"data", true);
    eprintln!("[cr] write returned {:?}", r);
    assert!(matches!(r, Err(SyscallErrorAlias::Pipe)));
}

// ===========================================================================
// PipeScheme registry
// ===========================================================================

#[test]
fn pipe_scheme_creates_distinct_pipes() {
    let scheme: SpinLock<PipeScheme> = SpinLock::new(PipeScheme::new());
    let (id1, p1) = scheme.lock().create_pipe();
    let (id2, p2) = scheme.lock().create_pipe();
    assert_ne!(id1, id2);
    assert!(!Arc::ptr_eq(&p1, &p2));

    // Pipes are independent channels.
    p1.write(b"one", true).unwrap();
    p2.write(b"two", true).unwrap();
    let mut buf = [0u8; 3];
    p1.read(&mut buf, true).unwrap();
    assert_eq!(&buf, b"one");
    p2.read(&mut buf, true).unwrap();
    assert_eq!(&buf, b"two");
}
