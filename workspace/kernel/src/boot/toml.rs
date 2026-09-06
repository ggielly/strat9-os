//! Minimal TOML subset parser for kernel boot configuration.
//!
//! Zero-copy design: keys, section names and unescaped string values borrow
//! directly from the source buffer (`Cow::Borrowed`); only values requiring
//! escape-sequence expansion allocate. Entries are stored in one flat,
//! sorted `Vec` (binary-search lookups) instead of nested maps — the config
//! is parsed once at boot and read-only afterwards.
//!
//! # Lifetime contract
//!
//! [`TomlConfig<'a>`] borrows the input buffer: the caller must keep the
//! TOML text alive for as long as the config is used. This is natural for
//! boot configs read from persistent regions (initfs / mapped file).
//!
//! # Supported subset
//!
//! - `[section]` headers (no nested tables, non-empty names)
//! - `key = value` inside a section (keys before any header are rejected)
//! - Value types: integers (decimal + `0x` hex), booleans, basic strings
//! - `#` comments, full-line or trailing, respecting quoted strings
//! - Basic-string escapes: `\n \t \r \" \\`
//!
//! Not supported by design: floats, arrays, inline tables, multi-line
//! strings, dotted keys, duplicate keys (rejected at parse time).
use alloc::{borrow::Cow, vec::Vec};

/// A single configuration value.
#[derive(Debug, Clone)]
pub enum ConfigValue<'a> {
    Integer(i64),
    Boolean(bool),
    /// `Cow::Borrowed` when the raw text needed no unescaping (common case),
    /// `Cow::Owned` only when `\n`-style escapes had to be expanded.
    String(Cow<'a, str>),
}

/// Parsed TOML configuration: flat `(section, key, value)` triples kept
/// sorted for O(log n) binary-search lookups with minimal memory overhead.
#[derive(Debug, Clone)]
pub struct TomlConfig<'a> {
    entries: Vec<(&'a str, &'a str, ConfigValue<'a>)>,
}

impl<'a> TomlConfig<'a> {
    fn lookup(&self, section: &str, key: &str) -> Option<&ConfigValue<'a>> {
        let idx = self
            .entries
            .binary_search_by(|(s, k, _)| (*s, *k).cmp(&(section, key)))
            .ok()?;
        Some(&self.entries[idx].2)
    }

    pub fn get_int(&self, section: &str, key: &str) -> Option<i64> {
        match self.lookup(section, key)? {
            ConfigValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        match self.lookup(section, key)? {
            ConfigValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_str(&self, section: &str, key: &str) -> Option<&str> {
        match self.lookup(section, key)? {
            // Return tied to &self: the Cow may be Borrowed ('a) or Owned,
            // so the public view is just a shared str borrow of the config.
            ConfigValue::String(v) => Some(v.as_ref()),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a TOML-subset document. The returned config borrows `data`.
///
/// Errors are `&'static str` diagnostics suitable for early-boot logging.
pub fn parse_toml<'a>(data: &'a [u8]) -> Result<TomlConfig<'a>, &'static str> {
    let text = core::str::from_utf8(data).map_err(|_| "invalid UTF-8 in TOML")?;

    // Pre-size once: one entry max per line keeps reallocations away.
    let approx_lines = text.bytes().filter(|&b| b == b'\n').count();
    let mut entries: Vec<(&'a str, &'a str, ConfigValue<'a>)> = Vec::with_capacity(approx_lines);

    let mut sec: &'a str = "";
    let mut seen_section = false;

    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if name.contains('.') {
                return Err("nested tables not supported");
            }
            if name.trim().is_empty() {
                return Err("empty section name");
            }
            sec = name.trim();
            seen_section = true;
            continue;
        }

        if !seen_section {
            return Err("key-value pair before any [section] header");
        }

        // Spec: only the FIRST '=' separates key and value; everything
        // after it belongs to the value (so `path = "a=b"` works).
        let (key, val) = line.split_once('=').ok_or("invalid TOML syntax")?;
        let key = key.trim();
        let val = val.trim();

        let v = if val == "true" {
            ConfigValue::Boolean(true)
        } else if val == "false" {
            ConfigValue::Boolean(false)
        } else if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            ConfigValue::Integer(i64::from_str_radix(hex, 16).map_err(|_| "invalid hex")?)
        } else if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            let inner = &val[1..val.len() - 1];
            ConfigValue::String(unescape_cow(inner))
        } else {
            ConfigValue::Integer(val.parse().map_err(|_| {
                "unsupported value type (expected bool, int, hex, or quoted string)"
            })?)
        };

        entries.push((sec, key, v));
    }

    // Sort once; equal (section, key) pairs become adjacent, so duplicate
    // detection is a single adjacent scan instead of a map lookup per row.
    entries.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for w in entries.windows(2) {
        if w[0].0 == w[1].0 && w[0].1 == w[1].1 {
            return Err("duplicate key in TOML section");
        }
    }

    Ok(TomlConfig { entries })
}

/// Strip a trailing `#` comment, ignoring `#` inside quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Expand basic-string escapes, borrowing when there is nothing to expand.
fn unescape_cow(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = alloc::string::String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                // Unknown escapes: keep literally (lenient on purpose).
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let toml = b"
# Comment
[buddy]
compaction_threshold = 35
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("buddy", "compaction_threshold"), Some(35));
    }

    #[test]
    fn test_parse_multiple_sections() {
        let toml = b"
[section1]
key1 = 100
key2 = true

[section2]
key3 = \"hello\"
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("section1", "key1"), Some(100));
        assert_eq!(config.get_bool("section1", "key2"), Some(true));
        assert_eq!(config.get_str("section2", "key3"), Some("hello"));
    }

    #[test]
    fn test_parse_hex() {
        let toml = b"
[test]
value = 0xFF
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("test", "value"), Some(255));
    }

    #[test]
    fn test_trailing_comment_outside_string() {
        let toml = b"
[s]
threshold = 35  # annotation
name = \"a#b\"  # hash inside string stays
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("s", "threshold"), Some(35));
        assert_eq!(config.get_str("s", "name"), Some("a#b"));
    }

    #[test]
    fn test_escape_sequences() {
        let toml = b"
[s]
path = \"C:\\\\boot\\\\kernel\"
msg = \"line\\\\nnext\"
plain = \"no\\\\escapes\"
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_str("s", "path"), Some("C:\\boot\\kernel"));
        assert_eq!(config.get_str("s", "msg"), Some("line\nnext"));
        assert_eq!(config.get_str("s", "plain"), Some("no\\escapes"));
    }

    #[test]
    fn test_value_containing_equals() {
        let toml = b"
[s]
pair = \"key=value\"
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_str("s", "pair"), Some("key=value"));
    }

    #[test]
    fn test_reject_key_before_section() {
        let toml = b"orphan = 1\n[s]\nx = 1\n";
        assert_eq!(
            parse_toml(toml).err(),
            Some("key-value pair before any [section] header")
        );
    }

    #[test]
    fn test_reject_duplicate_key() {
        let toml = b"
[s]
k = 1
k = 2
";
        assert_eq!(
            parse_toml(toml).err(),
            Some("duplicate key in TOML section")
        );
    }

    #[test]
    fn test_reject_empty_section_name() {
        let toml = b"
[]
x = 1
";
        assert_eq!(parse_toml(toml).err(), Some("empty section name"));
    }

    #[test]
    fn test_reject_nested_table() {
        let toml = b"
[a.b]
x = 1
";
        assert_eq!(parse_toml(toml).err(), Some("nested tables not supported"));
    }

    #[test]
    fn test_float_error_message() {
        let toml = b"
[s]
ratio = 0.5
";
        assert_eq!(
            parse_toml(toml).err(),
            Some("unsupported value type (expected bool, int, hex, or quoted string)")
        );
    }

    #[test]
    fn test_malformed_quote_is_not_a_string() {
        // Unterminated quote falls through to the int parser and must be
        // rejected with the explicit message rather than silently truncated.
        let toml = b"
[s]
val = \"not-closed
";
        assert!(parse_toml(toml)
            .err()
            .unwrap()
            .starts_with("unsupported value type"));
    }
}
