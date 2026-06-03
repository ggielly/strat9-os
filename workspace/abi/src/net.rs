/// Returns true when the input looks like a dotted IPv4 literal candidate.
pub fn is_ipv4_literal_candidate(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.iter().all(|b| b.is_ascii_digit() || *b == b'.')
        && bytes.contains(&b'.')
}

/// Returns true when the input looks like an IPv6 literal candidate.
pub fn is_ipv6_literal_candidate(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_hexdigit() || *b == b':' || *b == b'.')
        && bytes.contains(&b':')
}

/// Parses an IPv4 literal into network-order octets.
pub fn parse_ipv4_literal(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut val: u16 = 0;
    let mut has_digit = false;

    for &b in s.as_bytes() {
        if b == b'.' {
            if !has_digit || idx >= 3 || val > 255 {
                return None;
            }
            octets[idx] = val as u8;
            idx += 1;
            val = 0;
            has_digit = false;
            continue;
        }

        if !b.is_ascii_digit() {
            return None;
        }

        val = val.checked_mul(10)?.checked_add((b - b'0') as u16)?;
        has_digit = true;
    }

    if !has_digit || idx != 3 || val > 255 {
        return None;
    }

    octets[3] = val as u8;
    Some(octets)
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 4 {
        return None;
    }

    let mut value = 0u16;
    for &b in s.as_bytes() {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u16,
            b'a'..=b'f' => 10 + (b - b'a') as u16,
            b'A'..=b'F' => 10 + (b - b'A') as u16,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }

    Some(value)
}

/// Parses an IPv6 literal into network-order octets.
pub fn parse_ipv6_literal(s: &str) -> Option<[u8; 16]> {
    let mut groups = [0u16; 8];

    if let Some(dc) = s.find("::") {
        let left = &s[..dc];
        let right = &s[dc + 2..];
        let mut left_count = 0usize;
        if !left.is_empty() {
            for part in left.split(':') {
                if left_count >= 8 {
                    return None;
                }
                groups[left_count] = parse_hex_u16(part)?;
                left_count += 1;
            }
        }

        let mut right_groups = [0u16; 8];
        let mut right_count = 0usize;
        if !right.is_empty() {
            for part in right.split(':') {
                if right_count >= 8 {
                    return None;
                }
                right_groups[right_count] = parse_hex_u16(part)?;
                right_count += 1;
            }
        }

        if left_count + right_count > 8 {
            return None;
        }

        let start = 8 - right_count;
        for i in 0..right_count {
            groups[start + i] = right_groups[i];
        }
    } else {
        let mut count = 0usize;
        for part in s.split(':') {
            if count >= 8 {
                return None;
            }
            groups[count] = parse_hex_u16(part)?;
            count += 1;
        }
        if count != 8 {
            return None;
        }
    }

    let mut octets = [0u8; 16];
    for (idx, &group) in groups.iter().enumerate() {
        octets[2 * idx] = (group >> 8) as u8;
        octets[2 * idx + 1] = (group & 0xFF) as u8;
    }

    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::{parse_ipv4_literal, parse_ipv6_literal};

    #[test]
    fn parses_ipv4_literal() {
        assert_eq!(parse_ipv4_literal("192.168.1.10"), Some([192, 168, 1, 10]));
    }

    #[test]
    fn parses_full_ipv6_literal() {
        assert_eq!(
            parse_ipv6_literal("2001:0db8:0000:0000:0000:ff00:0042:8329"),
            Some([
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x42,
                0x83, 0x29,
            ])
        );
    }

    #[test]
    fn parses_compressed_ipv6_literal() {
        assert_eq!(
            parse_ipv6_literal("fe80::5054:ff:fe12:3456"),
            Some([
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12,
                0x34, 0x56,
            ])
        );
    }

    #[test]
    fn rejects_multiple_double_colons() {
        assert_eq!(parse_ipv6_literal("fe80::5054::ff::fe12::3456"), None);
    }
}
