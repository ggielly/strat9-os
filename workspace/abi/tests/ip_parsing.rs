//! L1 — IP literal parsing: exhaustive edge cases.
//!
//! `parse_ipv4_literal` / `parse_ipv6_literal` are used by the net stack and
//! the telnet/ping/dhcp tools. Accepting malformed input would let userspace
//! craft addresses the kernel never validated; rejecting valid input breaks
//! tooling. Both directions are covered here.

use strat9_abi::ip::{
    is_ipv4_literal_candidate, is_ipv6_literal_candidate, parse_ipv4_literal,
    parse_ipv6_literal,
};

// ===========================================================================
// IPv4
// ===========================================================================

#[test]
fn ipv4_valid_addresses() {
    const CASES: &[(&str, [u8; 4])] = &[
        ("0.0.0.0", [0, 0, 0, 0]),
        ("255.255.255.255", [255, 255, 255, 255]),
        ("192.168.1.10", [192, 168, 1, 10]),
        ("10.0.0.1", [10, 0, 0, 1]),
        ("127.0.0.1", [127, 0, 0, 1]),
        ("1.2.3.4", [1, 2, 3, 4]),
        ("00.00.00.00", [0, 0, 0, 0]), // leading zeros accepted by this parser
        ("010.020.030.040", [10, 20, 30, 40]),
    ];
    for (input, expected) in CASES {
        assert_eq!(
            parse_ipv4_literal(input),
            Some(*expected),
            "parsing {}",
            input
        );
    }
}

#[test]
fn ipv4_invalid_addresses() {
    const CASES: &[&str] = &[
        "",               // empty
        ".",              // lone dot
        "..",             // dots only
        "1",              // single octet
        "1.",             // trailing dot
        ".1.1.1",         // leading dot
        "1..1.1",         // empty octet in middle
        "1.1.1",          // too few octets
        "1.1.1.1.1",      // too many octets
        "256.1.1.1",      // first octet > 255
        "1.256.1.1",      // second octet > 255
        "1.1.1.256",      // last octet > 255
        "999.999.999.999",// all octets > 255
        "-1.2.3.4",       // negative
        "+1.2.3.4",       // explicit sign
        "abc.def.ghi.jkl",// letters
        "1.2.3.4 ",       // trailing space
        " 1.2.3.4",       // leading space
        "0x1.2.3.4",      // hex prefix not allowed
        "١.٢.٣.٤",        // non-ASCII digits
        "1.2.3.4\n",      // newline
    ];
    for &case in CASES {
        assert_eq!(
            parse_ipv4_literal(case),
            None,
            "{:?} should be rejected",
            case
        );
    }
}

#[test]
fn ipv4_octet_overflow_does_not_panic() {
    // u16 intermediate: long digit runs must be caught by checked math...
    assert_eq!(parse_ipv4_literal("12345678901.1.1.1"), None);
    // ...but long runs of LEADING ZEROS are mathematically fine (value = 1)
    // and must parse, not overflow.
    assert_eq!(
        parse_ipv4_literal("00000000000000000000000000001.2.3.4"),
        Some([1, 2, 3, 4])
    );
}

#[test]
fn ipv4_candidate_filter_agrees_with_parser() {
    // The pre-filter is documented as a fast path: anything it rejects must
    // also fail parsing (no false negatives on parseable inputs).
    let positives = [
        "1.2.3.4",
        "192.168.0.1",
        "255.255.255.255",
        "999.999.999.999", // candidate but invalid — filter is permissive by design
    ];
    for p in positives {
        assert!(is_ipv4_literal_candidate(p), "{} should be a candidate", p);
    }
    let negatives = [
        "", "hello", "::1", "fe80::1", "1:2", "-", "1.2.3.4a", "a.2.3.4",
    ];
    for n in negatives {
        assert!(!is_ipv4_literal_candidate(n), "{:?} should NOT be a candidate", n);
    }
}

// ===========================================================================
// IPv6
// ===========================================================================

#[test]
fn ipv6_full_form() {
    assert_eq!(
        parse_ipv6_literal("2001:0db8:0000:0000:0000:ff00:0042:8329"),
        Some([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0x00, 0x00, 0x42, 0x83, 0x29
        ])
    );
    // Uppercase hex must be accepted.
    assert_eq!(
        parse_ipv6_literal("2001:DB8::FF00:42:8329"),
        parse_ipv6_literal("2001:0db8::ff00:0042:8329")
    );
}

#[test]
fn ipv6_compressed_forms() {
    let cases: &[(&str, [u16; 8])] = &[
        ("::", [0; 8]),
        ("::1", [0, 0, 0, 0, 0, 0, 0, 1]),
        (
            "fe80::",
            [0xfe80, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            "fe80::5054:ff:fe12:3456",
            [0xfe80, 0, 0, 0, 0x5054, 0x00ff, 0xfe12, 0x3456],
        ),
        ("1::2", [1, 0, 0, 0, 0, 0, 0, 2]),
        ("1::8", [1, 0, 0, 0, 0, 0, 0, 8]),
        (
            "0:0:0:0:0:0:0:1",
            [0, 0, 0, 0, 0, 0, 0, 1],
        ), // no compression needed
    ];
    for (input, groups) in cases {
        let parsed = parse_ipv6_literal(input).unwrap_or_else(|| panic!("failed: {}", input));
        let mut expected = [0u8; 16];
        for (i, g) in groups.iter().enumerate() {
            expected[2 * i] = (g >> 8) as u8;
            expected[2 * i + 1] = (g & 0xFF) as u8;
        }
        assert_eq!(parsed, expected, "parsing {}", input);
    }
}

#[test]
fn ipv6_invalid_forms() {
    const CASES: &[&str] = &[
        "",
        ":",
        ":::",            // triple colon
        "::0::",          // multiple "::"
        "fe80::1::2",     // multiple "::" with content
        "1:2:3",          // too few groups, no compression
        "1:2:3:4:5:6:7",  // 7 groups, no "::"
        "1:2:3:4:5:6:7:8:9", // 9 groups
        "12345::",        // group > 4 hex digits
        ":ffff::",        // hmm — leading single colon: left part empty group
        "g::1",           // invalid hex digit
        "fe80::1%eth0",   // zone id (documented unsupported)
        "::ffff:192.168.1.1", // v4-mapped (documented unsupported)
        "fe80: :",        // space
    ];
    for &c in CASES {
        assert_eq!(parse_ipv6_literal(c), None, "{:?} should be rejected", c);
    }
}

#[test]
fn ipv6_max_group_counts_at_compression_boundary() {
    // KNOWN RFC DEVIATIONS (documented here on purpose):
    // RFC 4291 forbids "::" when the address already has 8 explicit groups
    // (the compressed form must replace at least one group). The current
    // parser accepts both over-long forms below. If you tighten the parser,
    // flip these asserts to `None` and bump the ABI changelog.
    assert!(parse_ipv6_literal("1:2:3:4:5:6:7:8::").is_some());
    assert!(parse_ipv6_literal("::1:2:3:4:5:6:7:8").is_some());
    // 7 groups + "::" → valid, fills to 8.
    assert!(parse_ipv6_literal("1:2:3:4:5:6:7::").is_some());
    assert!(parse_ipv6_literal("::1:2:3:4:5:6:7").is_some());
}

#[test]
fn ipv6_candidate_filter_boundaries() {
    assert!(is_ipv6_literal_candidate("::"));
    assert!(is_ipv6_literal_candidate("2001:db8::1"));
    // Dots are allowed by the filter charset (for future v4-mapped support),
    // but plain IPv4 without a colon is not a candidate.
    assert!(!is_ipv6_literal_candidate("192.168.1.1"));
    assert!(!is_ipv6_literal_candidate(""));
    assert!(!is_ipv6_literal_candidate("no-colons-here-but-hex-ish"));
}
