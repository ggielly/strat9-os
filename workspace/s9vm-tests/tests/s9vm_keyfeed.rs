//! L2: the host-keyboard feed that types into a DOS guest.
//!
//! A key has two encodings and a PC guest consumes exactly one of them: PS/2
//! scancodes from the 8042 (a guest owning `INT 9`) or `(scan, ASCII)` pairs in
//! the firmware keyboard buffer (a guest keeping `INT 16h` at the firmware).
//! The feed stores whole keys so the two views share one cursor; these tests
//! drive it directly, which covers the interactive path without VT-x.

extern crate alloc;

#[path = "../../kernel/src/s9vm/bios.rs"]
mod bios;
#[path = "../../kernel/src/s9vm/keyboard.rs"]
mod keyboard;
#[path = "../../kernel/src/s9vm/keyfeed.rs"]
mod keyfeed;

use alloc::vec::Vec;

use bios::BiosState;
use keyboard::KeyboardController;
use keyfeed::KeyboardFeed;

#[test]
fn feed_translates_text_into_the_same_scancodes_as_the_keyboard_model() {
    // The feed must not invent its own translation: whatever
    // `text_to_scancodes` produces for the 8042 is what the guest expects.
    let mut expected = Vec::new();
    keyboard::text_to_scancodes(b"dir\r", &mut expected);
    let mut controller = KeyboardController::new();
    let mut feed = KeyboardFeed::new(b"dir\r");
    let accepted = feed.fill(&mut controller, expected.len());
    assert_eq!(accepted, expected.len());
    for &code in &expected {
        assert_eq!(controller.read(keyboard::DATA_PORT), Some(code));
    }
    // The model replies with a zero byte once the queue is empty, like the
    // controller's idle data-port read.
    assert!(!controller.has_scancode());
}

#[test]
fn feed_keeps_one_buffer_entry_per_key_with_its_ascii() {
    let mut feed = KeyboardFeed::new(b"ab\r");
    let mut state = BiosState::new();
    assert_eq!(feed.fill_bios(&mut state, 8), 3);
    assert_eq!(state.keyboard.pop_front(), Some((0, b'a')));
    assert_eq!(state.keyboard.pop_front(), Some((0, b'b')));
    // `INT 16h` reports Enter as CR, whatever the host newline was.
    assert_eq!(state.keyboard.pop_front(), Some((0, b'\r')));
    assert!(state.keyboard.is_empty());
}

#[test]
fn feed_translates_an_extended_key_for_both_consumers() {
    // `0x80` is the kernel's up-arrow byte: the 8042 sees the `0xE0`-prefixed
    // make/break pair and the firmware buffer sees the scan code alone.
    let mut feed = KeyboardFeed::new(&[0x80]);
    let mut controller = KeyboardController::new();
    assert_eq!(feed.fill(&mut controller, 8), 4);
    let mut sequence = Vec::new();
    for _ in 0..4 {
        sequence.push(controller.read(keyboard::DATA_PORT).expect("scancode"));
    }
    assert_eq!(sequence, alloc::vec![0xE0, 0x48, 0xE0, 0xC8]);

    let mut feed = KeyboardFeed::new(&[0x80]);
    let mut state = BiosState::new();
    assert_eq!(feed.fill_bios(&mut state, 8), 1);
    assert_eq!(state.keyboard.pop_front(), Some((0x48, 0)));
}

#[test]
fn feed_skips_bytes_a_pc_keyboard_cannot_type() {
    let mut feed = KeyboardFeed::new(&[0x07, b'a']);
    let mut controller = KeyboardController::new();
    let mut state = BiosState::new();
    // Only the printable key survives, and both views agree on the count.
    assert_eq!(feed.remaining(), 1);
    assert_eq!(feed.fill(&mut controller, 8), 2);
    assert_eq!(feed.fill_bios(&mut state, 8), 0);
    assert!(state.keyboard.is_empty());
}

#[test]
fn fill_stops_at_the_controller_capacity_and_resumes_later() {
    // A guest that has not drained the 8042 must not overflow it, and the feed
    // must never split a make/break pair: whole keys only.
    let mut feed = KeyboardFeed::new(b"0123456789abcdefghijklmnopqrstuvwxyz");
    let mut controller = KeyboardController::new();
    let accepted = feed.fill(&mut controller, 4096);
    assert!(accepted > 0, "some keys must fit");
    assert!(feed.remaining() > 0, "the rest must stay queued");
    assert_eq!(feed.fill(&mut controller, 4096), 0, "queue is still full");
    // Draining the controller lets the remaining keys through.
    while controller.has_scancode() {
        let _ = controller.read(keyboard::DATA_PORT);
    }
    assert!(feed.fill(&mut controller, 4096) > 0);
}

#[test]
fn fill_never_splits_a_key_on_a_byte_budget() {
    // A shifted key occupies four scancodes: a budget of three must queue
    // nothing rather than half a key.
    let mut feed = KeyboardFeed::new(b"!");
    let mut controller = KeyboardController::new();
    assert_eq!(feed.fill(&mut controller, 3), 0);
    assert_eq!(feed.remaining(), 1);
    assert_eq!(feed.fill(&mut controller, 4), 4);
    assert_eq!(feed.remaining(), 0);
}

#[test]
fn from_pending_resumes_exactly_and_accepts_new_text() {
    // The hand-over carries whole keys, so the guest never sees a key twice.
    let mut partial = KeyboardFeed::new(b"ab");
    let mut controller = KeyboardController::new();
    assert_eq!(partial.fill(&mut controller, 2), 2);
    assert_eq!(partial.remaining(), 1);

    let mut resumed = KeyboardFeed::from_pending(partial.remaining_keys());
    assert_eq!(resumed.remaining(), 1);
    let mut state = BiosState::new();
    assert_eq!(resumed.fill_bios(&mut state, 8), 1);
    assert_eq!(state.keyboard.pop_front(), Some((0, b'b')));

    resumed.extend(b"c");
    assert_eq!(resumed.remaining(), 1);
    let mut controller = KeyboardController::new();
    assert_eq!(resumed.fill(&mut controller, 8), 2);
    assert_eq!(resumed.remaining(), 0);
    let mut expected = Vec::new();
    keyboard::text_to_scancodes(b"c", &mut expected);
    for &code in &expected {
        assert_eq!(controller.read(keyboard::DATA_PORT), Some(code));
    }
}

#[test]
fn an_empty_feed_reports_nothing_left() {
    let mut feed = KeyboardFeed::empty();
    assert_eq!(feed.remaining(), 0);
    assert!(feed.remaining_keys().is_empty());
    let mut controller = KeyboardController::new();
    let mut state = BiosState::new();
    assert_eq!(feed.fill(&mut controller, 8), 0);
    assert_eq!(feed.fill_bios(&mut state, 8), 0);
}
