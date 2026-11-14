//! L2: the host-keyboard feed that types into a DOS guest.
//!
//! The feed is pure: it only translates host text into the two views a PC guest
//! consumes (8042 scancodes and firmware keyboard-buffer entries) and carries
//! the remainders across a slice hand-over. These tests drive it directly, so
//! the interactive path is covered without VT-x.

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
    assert_eq!(controller.read(keyboard::DATA_PORT), None);
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
    assert_eq!(feed.fill(&mut controller, 8), 2);
    assert_eq!(feed.fill_bios(&mut state, 8), 1);
    assert_eq!(state.keyboard.pop_front(), Some((0, b'a')));
}

#[test]
fn fill_stops_at_the_controller_capacity_and_resumes_later() {
    // A guest that has not drained the 8042 must not overflow it: the feed keeps
    // the rest for the next slice.
    let mut feed = KeyboardFeed::new(b"0123456789abcdefghijklmnopqrstuvwxyz");
    let mut controller = KeyboardController::new();
    let accepted = feed.fill(&mut controller, 4096);
    let total = feed.scancodes.len();
    assert!(accepted > 0 && accepted < total, "accepted {accepted}/{total}");
    assert_eq!(feed.fill(&mut controller, 4096), 0, "queue is still full");
    // Draining the controller lets the remaining scancodes through.
    while controller.read(keyboard::DATA_PORT).is_some() {}
    assert!(feed.fill(&mut controller, 4096) > 0);
}

#[test]
fn from_pending_resumes_exactly_and_accepts_new_text() {
    // A slice hand-over carries both remainders; rebuilding from the original
    // text would re-type keys the guest already received.
    let mut partial = KeyboardFeed::new(b"ab");
    partial.next = 1;
    partial.next_key = 1;
    let expected_scancodes = partial.scancodes[1..].to_vec();
    let expected_keys = partial.keys[1..].to_vec();
    let mut resumed = KeyboardFeed::from_pending(
        partial.scancodes[1..].to_vec(),
        partial.keys[1..].to_vec(),
    );
    assert_eq!(resumed.scancodes, expected_scancodes);
    assert_eq!(resumed.keys, expected_keys);
    assert!(resumed.remaining() > 0);

    resumed.extend(b"c");
    assert_eq!(resumed.keys.last(), Some(&(0, b'c')));
    let mut state = BiosState::new();
    assert_eq!(resumed.fill_bios(&mut state, 8), 2);
    assert_eq!(state.keyboard.pop_front(), Some((0, b'b')));
    assert_eq!(state.keyboard.pop_front(), Some((0, b'c')));
}

#[test]
fn an_empty_feed_reports_nothing_left() {
    let mut feed = KeyboardFeed::empty();
    assert_eq!(feed.remaining(), 0);
    let mut controller = KeyboardController::new();
    let mut state = BiosState::new();
    assert_eq!(feed.fill(&mut controller, 8), 0);
    assert_eq!(feed.fill_bios(&mut state, 8), 0);
}
