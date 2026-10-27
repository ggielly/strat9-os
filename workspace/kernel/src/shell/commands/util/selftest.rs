//! Self-tests for the pure logic behind the shell tool and utility commands.
//!
//! Runs only under `feature = "selftest"`. These commands are thin wrappers
//! around formatting, parsing and validation, so the tests target that logic
//! directly: the argument parsers that used to accept a typo silently, the
//! escape expander, the lossy line splitter, the NTP reply validator, the
//! environment assignment grammar and the table layout helpers.
//!
//! Assertions are reported over serial in the same shape as the other
//! `*_test.rs` modules; see `process/selftest.rs` for the orchestrator.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::{
    contains_ignore_case,
    date::rtc_fields_plausible,
    env::{is_computed_key, setenv_action, EnvOp, SetenvError, COMPUTED_KEYS},
    expand_escapes, first_nul, for_each_line,
    ntpdate::{
        encode_transmit_timestamp, is_valid_stratum, leap_indicator, ntp_mode, ntp_version,
        root_dispersion, validate_ntp_response, NtpError,
    },
    parse_count, parse_grep_options,
    watch::{interval_ticks, parse_watch_args, watched_label, WatchError},
};
use crate::hardware::timer::rtc::RtcDateTime;

fn log_section(title: &str) {
    crate::serial_println!(
        "[shell-util-test][STEP] ========================================================"
    );
    crate::serial_println!("[shell-util-test][STEP] {}", title);
    crate::serial_println!(
        "[shell-util-test][STEP] ========================================================"
    );
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[shell-util-test][ASSERT][SCENARIO] {:<52} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

/// Asserts an equality that has a `Debug` on both sides.
fn expect_eq<T, U>(label: &str, got: T, want: U) -> bool
where
    T: core::fmt::Debug + PartialEq<U>,
    U: core::fmt::Debug,
{
    let ok = got == want;
    if !ok {
        crate::serial_println!(
            "[shell-util-test][ASSERT] FAIL: {} => got {:?}, want {:?}",
            label,
            got,
            want
        );
    }
    ok
}

/// Builds an NTP reply with the given header fields, for the validator tests.
fn ntp_reply(li_vn_mode: u8, stratum: u8, root_dispersion: u32, tx_secs: u32) -> [u8; 48] {
    let mut r = [0u8; 48];
    r[0] = li_vn_mode;
    r[1] = stratum;
    r[4..8].copy_from_slice(&root_dispersion.to_be_bytes());
    r[40..44].copy_from_slice(&tx_secs.to_be_bytes());
    r[44..48].copy_from_slice(&0u32.to_be_bytes());
    r
}

fn run_argument_parsing_suite(passed: &mut usize, total: &mut usize) {
    log_section("1. COUNT ARGUMENT PARSING (dmesg / audit)");

    //  A typo used to fall back to the default silently, so `dmesg abc` printed
    //  50 lines and reported success.
    record(
        "parse_count(\"50\") == Some(50)",
        expect_eq("parse_count(50)", parse_count("50"), Some(50usize)),
        passed,
        total,
    );
    record(
        "parse_count(\"0\") == Some(0)",
        expect_eq("parse_count(0)", parse_count("0"), Some(0usize)),
        passed,
        total,
    );
    let mut bad = true;
    for arg in [
        "",
        "abc",
        "-1",
        " 5",
        "5 ",
        "+5",
        "99999999999999999999999999",
    ] {
        let got = parse_count(arg);
        crate::serial_println!(
            "[shell-util-test][STEP] parse_count({:?}) => {:?}",
            arg,
            got
        );
        if got.is_some() {
            crate::serial_println!(
                "[shell-util-test][ASSERT] FAIL: parse_count({:?}) should be None",
                arg
            );
            bad = false;
        }
    }
    record(
        "parse_count rejects non-digits and empties",
        bad,
        passed,
        total,
    );

    log_section("2. ESCAPE EXPANSION (echo -e)");

    record(
        "expand_escapes returns None when there is no backslash",
        expect_eq(
            "expand_escapes(plain)",
            expand_escapes("plain"),
            None::<String>,
        ),
        passed,
        total,
    );
    record(
        "expand_escapes handles \\n \\t \\\\",
        expect_eq(
            "expand_escapes(a\\nb)",
            expand_escapes("a\\nb"),
            Some(String::from("a\nb")),
        ),
        passed,
        total,
    );
    record(
        "expand_escapes(\"\\\\\\\\\") == \"\\\\\"",
        expect_eq(
            "expand_escapes(backslash)",
            expand_escapes("\\\\"),
            Some(String::from("\\")),
        ),
        passed,
        total,
    );
    //  An unknown escape must be emitted verbatim: a stray backslash must never
    //  silently swallow the character after it.
    record(
        "expand_escapes keeps an unknown \\X verbatim",
        expect_eq(
            "expand_escapes(\\q)",
            expand_escapes("\\q"),
            Some(String::from("\\q")),
        ),
        passed,
        total,
    );
    record(
        "expand_escapes keeps a trailing lone backslash",
        expect_eq(
            "expand_escapes(trailing)",
            expand_escapes("tail\\"),
            Some(String::from("tail\\")),
        ),
        passed,
        total,
    );
}

fn run_grep_suite(passed: &mut usize, total: &mut usize) {
    log_section("3. GREP LINE SPLITTING AND MATCHING");

    record(
        "first_nul finds an embedded NUL",
        expect_eq("first_nul", first_nul(b"ab\0cd"), Some(2usize)),
        passed,
        total,
    );
    record(
        "first_nul is None for clean text",
        expect_eq("first_nul(clean)", first_nul(b"abcd"), None),
        passed,
        total,
    );

    record(
        "contains_ignore_case is case-insensitive",
        expect_eq(
            "contains_ignore_case",
            contains_ignore_case("Hello World", "hello"),
            true,
        ),
        passed,
        total,
    );
    record(
        "contains_ignore_case is exact when not ignoring case",
        expect_eq(
            "contains_ignore_case exact",
            contains_ignore_case("Hello", "hello"),
            false,
        ),
        passed,
        total,
    );
    record(
        "contains_ignore_case: empty needle matches",
        expect_eq(
            "contains_ignore_case empty",
            contains_ignore_case("abc", ""),
            true,
        ),
        passed,
        total,
    );
    record(
        "contains_ignore_case: needle longer than haystack",
        expect_eq(
            "contains_ignore_case long",
            contains_ignore_case("ab", "abcdef"),
            false,
        ),
        passed,
        total,
    );

    //  The regression that mattered: one invalid UTF-8 byte used to discard the
    //  whole file, so grep reported "no match" on any binary input.
    let mut lines: Vec<String> = Vec::new();
    for_each_line(b"first\nsec\xFFond\nthird", |l| {
        lines.push(String::from(l));
        true
    });
    let lossy_ok = lines.len() == 3
        && lines[0] == "first"
        && lines[2] == "third"
        && lines[1].contains('\u{FFFD}');
    if !lossy_ok {
        crate::serial_println!(
            "[shell-util-test][ASSERT] FAIL: lossy split produced {:?}",
            lines
        );
    }
    record(
        "for_each_line survives invalid UTF-8",
        lossy_ok,
        passed,
        total,
    );

    let mut crlf: Vec<String> = Vec::new();
    for_each_line(b"one\r\ntwo\r\n", |l| {
        crlf.push(String::from(l));
        true
    });
    record(
        "for_each_line strips CRLF",
        expect_eq(
            "crlf",
            crlf,
            alloc::vec![String::from("one"), String::from("two")],
        ),
        passed,
        total,
    );

    let mut seen = 0usize;
    for_each_line(b"a\nb\nc", |_| {
        seen += 1;
        seen < 2
    });
    record(
        "for_each_line stops when the visitor returns false",
        expect_eq("early exit", seen, 2usize),
        passed,
        total,
    );

    let args: Vec<String> = ["-in", "pat", "file"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match parse_grep_options(&args) {
        Some((opts, idx)) => {
            let ok = opts.ignore_case && opts.line_numbers && !opts.invert && idx == 1;
            crate::serial_println!(
                "[shell-util-test][STEP] parse_grep_options(-in pat file) => i={} n={} v={} idx={}",
                opts.ignore_case,
                opts.line_numbers,
                opts.invert,
                idx
            );
            record("parse_grep_options parses a cluster", ok, passed, total);
        }
        None => record("parse_grep_options parses a cluster", false, passed, total),
    }

    let bad: Vec<String> = ["-z", "pat"].iter().map(|s| s.to_string()).collect();
    record(
        "parse_grep_options rejects an unknown flag",
        expect_eq(
            "parse_grep_options(-z)",
            parse_grep_options(&bad).is_none(),
            true,
        ),
        passed,
        total,
    );
}

fn run_env_suite(passed: &mut usize, total: &mut usize) {
    log_section("4. ENVIRONMENT ASSIGNMENT GRAMMAR");

    match setenv_action("KERNEL=strat9") {
        EnvOp::Set { key, value } => record(
            "setenv KERNEL=strat9",
            key == "KERNEL" && value == "strat9",
            passed,
            total,
        ),
        _ => record("setenv KERNEL=strat9", false, passed, total),
    }
    match setenv_action("EMPTY=") {
        EnvOp::Set { key, value } => record(
            "setenv EMPTY= sets an explicit empty value",
            key == "EMPTY" && value.is_empty(),
            passed,
            total,
        ),
        _ => record(
            "setenv EMPTY= sets an explicit empty value",
            false,
            passed,
            total,
        ),
    }
    //  POSIX: `setenv NAME` with no '=' unsets. It used to create NAME="".
    record(
        "setenv BARE unsets (POSIX)",
        matches!(setenv_action("BARE"), EnvOp::Unset { key } if key == "BARE"),
        passed,
        total,
    );
    record(
        "setenv =value is refused (empty name)",
        matches!(
            setenv_action("=value"),
            EnvOp::Invalid(SetenvError::EmptyName)
        ),
        passed,
        total,
    );
    record(
        "setenv '' is refused",
        matches!(setenv_action(""), EnvOp::Invalid(SetenvError::EmptyName)),
        passed,
        total,
    );
    //  The computed names used to be settable, which let `env` print the same
    //  name twice with two different values.
    record(
        "setenv on a computed name is refused",
        matches!(
            setenv_action("UPTIME_SECS=5"),
            EnvOp::Invalid(SetenvError::ComputedName)
        ),
        passed,
        total,
    );
    record(
        "is_computed_key recognises all three computed names",
        COMPUTED_KEYS.iter().all(|k| is_computed_key(k)) && !is_computed_key("KERNEL"),
        passed,
        total,
    );
    record(
        "COMPUTED_KEYS holds the three expected names",
        expect_eq(
            "COMPUTED_KEYS",
            COMPUTED_KEYS,
            ["UPTIME_SECS", "SILO_COUNT", "MOUNT_COUNT"],
        ),
        passed,
        total,
    );
}

fn run_watch_suite(passed: &mut usize, total: &mut usize) {
    log_section("5. WATCH ARGUMENT PARSING AND INTERVALS");

    let args: Vec<String> = ["2", "ps"].iter().map(|s| s.to_string()).collect();
    match parse_watch_args(&args) {
        Ok(plan) => record(
            "parse_watch_args accepts <secs> <command>",
            expect_eq("interval_secs", plan.interval_secs, 2u64)
                && plan.command.len() == 1
                && plan.command[0] == "ps",
            passed,
            total,
        ),
        Err(e) => {
            crate::serial_println!("[shell-util-test][STEP] parse_watch_args => {:?}", e);
            record(
                "parse_watch_args accepts <secs> <command>",
                false,
                passed,
                total,
            )
        }
    }
    record(
        "parse_watch_args rejects a missing command",
        expect_eq(
            "no command",
            parse_watch_args(&[]).err(),
            Some(WatchError::Usage),
        ),
        passed,
        total,
    );
    let zero: Vec<String> = ["0", "ps"].iter().map(|s| s.to_string()).collect();
    record(
        "parse_watch_args rejects a zero interval",
        expect_eq(
            "zero interval",
            parse_watch_args(&zero).err(),
            Some(WatchError::ZeroInterval),
        ),
        passed,
        total,
    );
    let bad: Vec<String> = ["x", "ps"].iter().map(|s| s.to_string()).collect();
    record(
        "parse_watch_args rejects a non-numeric interval",
        expect_eq(
            "not a number",
            parse_watch_args(&bad).err(),
            Some(WatchError::NotANumber),
        ),
        passed,
        total,
    );

    let hz = crate::arch::timer::TIMER_HZ.max(1);
    record(
        "interval_ticks scales by the timer frequency",
        expect_eq("interval_ticks(2)", interval_ticks(2), 2 * hz),
        passed,
        total,
    );
    record(
        "interval_ticks never returns zero",
        expect_eq("interval_ticks(0)", interval_ticks(0) > 0, true),
        passed,
        total,
    );
    //  A huge interval used to wrap the multiplication to a tiny value.
    record(
        "interval_ticks does not overflow on a huge interval",
        expect_eq(
            "interval_ticks(u64::MAX)",
            interval_ticks(u64::MAX) >= hz,
            true,
        ),
        passed,
        total,
    );
    record(
        "watched_label renders the command",
        expect_eq(
            "watched_label",
            watched_label(&["ps".to_string()]),
            String::from("ps"),
        ),
        passed,
        total,
    );
}

fn run_ntp_suite(passed: &mut usize, total: &mut usize) {
    log_section("6. NTP REPLY VALIDATION");

    record(
        "leap_indicator extracts bits 6..8",
        expect_eq("li(0xC4)", leap_indicator(0xC4), 3u8),
        passed,
        total,
    );
    record(
        "ntp_mode extracts bits 0..3",
        expect_eq("mode(0x24)", ntp_mode(0x24), 4u8),
        passed,
        total,
    );
    record(
        "ntp_version extracts bits 3..6",
        expect_eq("vn(0x24)", ntp_version(0x24), 4u8),
        passed,
        total,
    );

    //  Stratum 0 is a kiss-of-death, 1..15 usable, 16+ reserved.
    record(
        "stratum 0 rejected",
        expect_eq("s0", is_valid_stratum(0), false),
        passed,
        total,
    );
    record(
        "stratum 1 accepted",
        expect_eq("s1", is_valid_stratum(1), true),
        passed,
        total,
    );
    record(
        "stratum 15 accepted",
        expect_eq("s15", is_valid_stratum(15), true),
        passed,
        total,
    );
    record(
        "stratum 16 rejected",
        expect_eq("s16", is_valid_stratum(16), false),
        passed,
        total,
    );

    let mut d = ntp_reply(0x24, 2, 0, 1_000_000);
    record(
        "root_dispersion decodes big-endian",
        expect_eq("root_dispersion", root_dispersion(&d), 0u32),
        passed,
        total,
    );
    d[4..8].copy_from_slice(&1_000u32.to_be_bytes());
    record(
        "root_dispersion decodes a non-zero value",
        expect_eq("root_dispersion", root_dispersion(&d), 1_000u32),
        passed,
        total,
    );

    //  A well-formed reply is accepted.
    let good = ntp_reply(0x24, 2, 100, 3_000_000_000);
    record(
        "a valid reply is accepted",
        expect_eq("valid", validate_ntp_response(&good).is_ok(), true),
        passed,
        total,
    );
    //  LI=3 means the server considers itself unsynchronised: its time is not a
    //  time, and the old validator accepted it.
    record(
        "an unsynchronised reply (LI=3) is rejected",
        expect_eq(
            "LI=3",
            validate_ntp_response(&ntp_reply(0xE4, 2, 100, 3_000_000_000)).err(),
            Some(NtpError::Unsynchronised),
        ),
        passed,
        total,
    );
    record(
        "a kiss-of-death (stratum 0) is rejected",
        expect_eq(
            "stratum 0",
            validate_ntp_response(&ntp_reply(0x24, 0, 100, 3_000_000_000)).err(),
            Some(NtpError::Stratum),
        ),
        passed,
        total,
    );
    record(
        "a client-mode reply is rejected",
        expect_eq(
            "mode 3",
            validate_ntp_response(&ntp_reply(0x23, 2, 100, 3_000_000_000)).err(),
            Some(NtpError::NotServer),
        ),
        passed,
        total,
    );
    record(
        "an absurd root dispersion is rejected",
        expect_eq(
            "dispersion",
            validate_ntp_response(&ntp_reply(0x24, 2, u32::MAX, 3_000_000_000)).err(),
            Some(NtpError::RootDispersion),
        ),
        passed,
        total,
    );
    record(
        "a short reply is rejected without panicking",
        expect_eq(
            "short",
            validate_ntp_response(&[0x24, 0x02]).err(),
            Some(NtpError::Short),
        ),
        passed,
        total,
    );
    record(
        "a pre-1970 transmit timestamp is rejected",
        expect_eq(
            "timestamp",
            validate_ntp_response(&ntp_reply(0x24, 2, 100, 0)).err(),
            Some(NtpError::Timestamp),
        ),
        passed,
        total,
    );

    let ts = encode_transmit_timestamp(1_700_000_000, 500_000_000);
    let secs = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]);
    let frac = u32::from_be_bytes([ts[4], ts[5], ts[6], ts[7]]);
    let expect_frac = (((500_000_000u128) << 32) / 1_000_000_000u128) as u32;
    record(
        "encode_transmit_timestamp sets both halves",
        expect_eq("tx seconds", secs, 1_700_000_000u32)
            && expect_eq("tx fraction", frac, expect_frac),
        passed,
        total,
    );
    let zero = encode_transmit_timestamp(0, 0);
    record(
        "encode_transmit_timestamp(0, 0) is all zero (allowed by RFC 5905)",
        zero == [0u8; 8],
        passed,
        total,
    );
}

fn run_rtc_suite(passed: &mut usize, total: &mut usize) {
    log_section("7. RTC FIELD PLAUSIBILITY (date)");

    let mk = |year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8| RtcDateTime {
        second,
        minute,
        hour,
        weekday: 3,
        day,
        month,
        year,
        century: 20,
    };

    record(
        "a sane CMOS reading is accepted",
        rtc_fields_plausible(&mk(2026, 9, 26, 12, 30, 15)),
        passed,
        total,
    );
    //  The riscv64 port stubs port I/O, so every CMOS register reads back as
    //  zero. Without this guard `date` would confidently print 1999-12-01.
    record(
        "an all-zero CMOS is rejected",
        expect_eq(
            "all zero",
            rtc_fields_plausible(&mk(0, 0, 0, 0, 0, 0)),
            false,
        ),
        passed,
        total,
    );
    record(
        "month 13 is rejected",
        expect_eq(
            "month 13",
            rtc_fields_plausible(&mk(2026, 13, 1, 0, 0, 0)),
            false,
        ),
        passed,
        total,
    );
    record(
        "day 32 is rejected",
        expect_eq(
            "day 32",
            rtc_fields_plausible(&mk(2026, 1, 32, 0, 0, 0)),
            false,
        ),
        passed,
        total,
    );
    record(
        "hour 24 is rejected",
        expect_eq(
            "hour 24",
            rtc_fields_plausible(&mk(2026, 1, 1, 24, 0, 0)),
            false,
        ),
        passed,
        total,
    );
    record(
        "minute 60 is rejected",
        expect_eq(
            "minute 60",
            rtc_fields_plausible(&mk(2026, 1, 1, 0, 60, 0)),
            false,
        ),
        passed,
        total,
    );
    //  February 30 cannot exist.
    record(
        "30 February is rejected",
        expect_eq(
            "feb 30",
            rtc_fields_plausible(&mk(2026, 2, 30, 0, 0, 0)),
            false,
        ),
        passed,
        total,
    );
}

fn run_layout_suite(passed: &mut usize, total: &mut usize) {
    use crate::shell::commands::{
        hw::{format_pci_address, pad_row, separator},
        mem::{
            format_count_pair, format_field, format_frag_scores, format_largest,
            format_largest_tag, order_bytes, page_bytes,
        },
    };

    log_section("8. TABLE LAYOUT HELPERS (lspci / lsns)");

    let widths = [4usize, 6, 3];
    let sep = separator(&widths);
    record(
        "separator spans the table width",
        expect_eq("separator len", sep.chars().count(), 4 + 6 + 3),
        passed,
        total,
    );
    let row = pad_row(&widths, &["00", "8086", "00"]);
    record(
        "pad_row places each cell at its column",
        expect_eq("pad_row", row.as_str(), "00   8086 00 "),
        passed,
        total,
    );
    record(
        "format_pci_address renders bus:dev.func",
        expect_eq(
            "pci address",
            format_pci_address(0, 0x1f, 2),
            String::from("00:1f.2"),
        ),
        passed,
        total,
    );
    record(
        "format_pci_address pads a full bus number",
        expect_eq(
            "pci address ff",
            format_pci_address(0xff, 0x0a, 0),
            String::from("ff:0a.0"),
        ),
        passed,
        total,
    );

    log_section("9. MEMORY SIZE HELPERS");

    let page = crate::memory::frame::PAGE_SIZE as usize;
    record(
        "page_bytes scales by the page size",
        expect_eq("page_bytes(2)", page_bytes(2), (2 * page) as u64),
        passed,
        total,
    );
    record(
        "order_bytes(0) is one page",
        expect_eq("order 0", order_bytes(0), page as u64),
        passed,
        total,
    );
    record(
        "order_bytes(1) is two pages",
        expect_eq("order 1", order_bytes(1), (2 * page) as u64),
        passed,
        total,
    );
    //  An absurd order read from allocator state used to wrap or panic.
    record(
        "order_bytes(63) does not wrap",
        expect_eq("order 63", order_bytes(63) > page_bytes(1), true),
        passed,
        total,
    );
    let f = format_field("Used", "12");
    record(
        "format_field aligns the value in a fixed column",
        expect_eq(
            "format_field",
            f.chars().count(),
            f.trim_end().chars().count() + 3,
        ),
        passed,
        total,
    );
    record(
        "format_largest(None) is 'none'",
        expect_eq("largest none", format_largest(None), String::from("none")),
        passed,
        total,
    );
    record(
        "format_largest_tag(None) is 'none'",
        expect_eq(
            "largest tag",
            format_largest_tag(None),
            String::from("none"),
        ),
        passed,
        total,
    );
    record(
        "format_largest(Some(0)) names an order",
        format_largest(Some(0)).contains("order 0"),
        passed,
        total,
    );
    record(
        "format_frag_scores renders each score",
        format_frag_scores(&[0, 50, 100]).contains("50"),
        passed,
        total,
    );
    record(
        "format_frag_scores saturates an out-of-range score",
        format_frag_scores(&[200]).contains("100"),
        passed,
        total,
    );
    record(
        "format_count_pair renders both numbers",
        format_count_pair(3, 4).contains('3') && format_count_pair(3, 4).contains('4'),
        passed,
        total,
    );
}

fn run_shell_output_suite(passed: &mut usize, total: &mut usize) {
    log_section("10. SHARED OUTPUT FORMATTERS");

    use crate::shell::output::{format_epoch_time, format_ticks, format_uptime, human_bytes};

    record(
        "format_uptime renders HH:MM:SS",
        expect_eq("uptime", format_uptime(3661), String::from("01:01:01")),
        passed,
        total,
    );
    record(
        "format_uptime(0) is 00:00:00",
        expect_eq("uptime 0", format_uptime(0), String::from("00:00:00")),
        passed,
        total,
    );

    let hz = crate::arch::timer::TIMER_HZ.max(1);
    record(
        "format_ticks(0) is (0, 0)",
        expect_eq("ticks 0", format_ticks(0), (0u64, 0u32)),
        passed,
        total,
    );
    record(
        "format_ticks(hz) is (1, 0)",
        expect_eq("ticks hz", format_ticks(hz), (1u64, 0u32)),
        passed,
        total,
    );
    record(
        "format_ticks scales with TIMER_HZ, not a hardcoded 100",
        expect_eq("ticks 2hz", format_ticks(2 * hz).0, 2u64),
        passed,
        total,
    );

    record(
        "human_bytes renders a unit suffix",
        human_bytes(4096).ends_with("KB"),
        passed,
        total,
    );
    record(
        "human_bytes(0) is 0B",
        expect_eq("human 0", human_bytes(0), String::from("0B")),
        passed,
        total,
    );

    //  The calendar conversion is the one piece with real arithmetic in it: a
    //  365-day year with a 28-day February put every timestamp from March
    //  onwards one day out, and drifted further each year.
    record(
        "format_epoch_time(0) is the Unix epoch",
        expect_eq("epoch", format_epoch_time(0), String::from("Jan  1 00:00")),
        passed,
        total,
    );
    record(
        "format_epoch_time handles a leap day",
        format_epoch_time(1_709_164_800).starts_with("Feb 29"),
        passed,
        total,
    );
    record(
        "format_epoch_time handles a non-leap February 28",
        format_epoch_time(1_708_521_600).starts_with("Feb 28"),
        passed,
        total,
    );
    record(
        "format_epoch_time handles a 31-day month boundary",
        format_epoch_time(1_709_164_800 + 86_400).starts_with("Mar  1"),
        passed,
        total,
    );
    //  Round-trip against the RTC's own forward conversion.
    let probe = 1_700_000_000u64;
    let dt = crate::hardware::timer::rtc::RtcDateTime::from_timestamp(probe);
    record(
        "RtcDateTime round-trips through from_timestamp/to_timestamp",
        expect_eq("round trip", dt.to_timestamp(), probe),
        passed,
        total,
    );
}

fn run_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    run_argument_parsing_suite(&mut passed, &mut total);
    run_grep_suite(&mut passed, &mut total);
    run_env_suite(&mut passed, &mut total);
    run_watch_suite(&mut passed, &mut total);
    run_ntp_suite(&mut passed, &mut total);
    run_rtc_suite(&mut passed, &mut total);
    run_layout_suite(&mut passed, &mut total);
    run_shell_output_suite(&mut passed, &mut total);

    log_section("SHELL UTIL TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!(
        "[shell-util-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    if !ok {
        crate::serial_println!(
            "[shell-util-test][ASSERT] {} scenario(s) FAILED",
            total - passed
        );
    }
    crate::serial_println!(
        "[shell-util-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    let _ = format!("{}/{}", passed, total);
    ok
}

extern "C" fn shell_util_test_main() -> ! {
    crate::serial_println!("[shell-util-test][SETUP] task start");
    let _ = run_suite();
    crate::serial_println!("[shell-util-test][DONE] task done");
    crate::process::scheduler::exit_current_task(0);
}

/// Creates the shell utility self-test task.
pub fn create_shell_util_test_task() {
    match crate::process::Task::new_kernel_task(
        shell_util_test_main,
        "shell-util-test",
        crate::process::TaskPriority::Normal,
    ) {
        Ok(task) => crate::process::add_task(task),
        Err(_) => crate::serial_println!("[shell-util-test][SETUP] failed to create task"),
    }
}
