//! L1: line diff behind `vm dos console`.
//!
//! The diff decides what the interactive console reprints after each guest
//! slice. The scroll case is the one users notice: the DOS prompt is on the
//! last row, so pressing Enter moves the whole screen up and a positional
//! comparison would reprint every line (the console appears to scroll
//! backwards). These tests pin the scroll handling and the in-place changes.

extern crate alloc;

#[path = "../../kernel/src/shell/commands/screendiff.rs"]
mod screendiff;

use screendiff::changed_lines;

/// Renders a screen from its lines, padded to 80 columns like the VGA grid.
fn screen(lines: &[&str]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for line in lines {
        out.push_str(line);
        out.push_str(&" ".repeat(80usize.saturating_sub(line.len())));
        out.push('\n');
    }
    out
}

#[test]
fn first_render_prints_every_non_empty_line() {
    let current = screen(&["FreeDOS", "", "A:\\>"]);
    assert_eq!(
        changed_lines("", &current),
        alloc::vec![
            alloc::string::String::from("FreeDOS"),
            alloc::string::String::from("A:\\>"),
        ]
    );
}

#[test]
fn unchanged_screen_prints_nothing() {
    let current = screen(&["FreeDOS", "A:\\>"]);
    assert!(changed_lines(&current, &current).is_empty());
}

#[test]
fn an_in_place_change_prints_only_that_line() {
    let mut before = alloc::vec!["C:\\>dir"; 24];
    before[23] = "A:\\>";
    let mut after = before.clone();
    after[23] = "A:\\>ver";
    let changed = changed_lines(&screen(&before), &screen(&after));
    assert_eq!(changed, alloc::vec![alloc::string::String::from("A:\\>ver")]);
}

#[test]
fn a_scroll_prints_only_the_new_bottom_line() {
    // The exact reported bug: the prompt sits on the last row, Enter scrolls
    // the screen up by one line and the new prompt lands at the bottom. Only
    // that line may be printed; reprinting the 23 survivor lines is what made
    // the console look like it scrolled backwards.
    let before: alloc::vec::Vec<&str> = (0..23)
        .map(|_| "kernel banner")
        .chain(core::iter::once("A:\\>"))
        .collect();
    let mut after: alloc::vec::Vec<&str> = before[1..].to_vec();
    after[22] = "A:\\>dir";
    let changed = changed_lines(&screen(&before), &screen(&after));
    assert_eq!(changed, alloc::vec![alloc::string::String::from("A:\\>dir")]);
}

#[test]
fn a_multi_line_scroll_prints_only_the_new_lines() {
    let before: alloc::vec::Vec<&str> = (0..22).map(|_| "banner").chain(["A:\\>", "x"]).collect();
    let mut after: alloc::vec::Vec<&str> = before[3..].to_vec();
    after.extend(["new 1", "new 2", "A:\\>"]);
    let changed = changed_lines(&screen(&before), &screen(&after));
    assert_eq!(
        changed,
        alloc::vec![
            alloc::string::String::from("new 1"),
            alloc::string::String::from("new 2"),
            alloc::string::String::from("A:\\>"),
        ]
    );
}

#[test]
fn a_scroll_without_new_text_prints_nothing() {
    // Scrolling alone (blank lines pushed in) must not reprint the survivors.
    let before: alloc::vec::Vec<&str> =
        (0..23).map(|index| if index == 22 { "A:\\>" } else { "x" }).collect();
    let mut after = before[1..].to_vec();
    after.push(""); // the scrolled-in row is blank
    assert!(changed_lines(&screen(&before), &screen(&after)).is_empty());
}

#[test]
fn trailing_padding_is_not_a_change() {
    // The VGA text reader pads every row to 80 columns; a line that only
    // differs in padding has not changed.
    let before = "A:\\>";
    let after = "A:\\>          ";
    assert!(changed_lines(before, after).is_empty());
}
