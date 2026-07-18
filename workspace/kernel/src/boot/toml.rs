//! Simple TOML parser for kernel boot configuration.
//!
//! This module provides a minimal TOML parser that can handle:
//! - `[section]` headers
//! - `key = value` pairs (string, integer, boolean)
//! - Comments (lines starting with `#`)
//!
//! The parser is designed for embedded use in a no-std kernel environment.
//! It does not support:
//! - Nested tables (`[a.b]`)
//! - Arrays
//! - Inline tables
//! - Multi-line strings
//!
//! # Example
//!
//! ```toml
//! [buddy]
//! compaction_threshold = 35
//! ```

use core::str;

/// Parsed configuration value.
#[derive(Debug, Clone)]
pub enum ConfigValue {
    /// Integer value.
    Integer(i64),
    /// Boolean value.
    Boolean(bool),
    /// String value.
    String(alloc::string::String),
}

/// Configuration section containing key-value pairs.
#[derive(Debug, Clone)]
pub struct ConfigSection {
    /// Section name (without brackets).
    pub name: alloc::string::String,
    /// Key-value pairs in this section.
    pub entries: alloc::vec::Vec<(alloc::string::String, ConfigValue)>,
}

/// Parsed TOML configuration.
#[derive(Debug, Clone)]
pub struct TomlConfig {
    /// All sections in the configuration.
    pub sections: alloc::vec::Vec<ConfigSection>,
}

impl TomlConfig {
    /// Create an empty configuration.
    pub fn new() -> Self {
        Self {
            sections: alloc::vec::Vec::new(),
        }
    }

    /// Get a value from a section.
    ///
    /// Returns `None` if the section or key doesn't exist.
    pub fn get(&self, section: &str, key: &str) -> Option<&ConfigValue> {
        for s in &self.sections {
            if s.name == section {
                for (k, v) in &s.entries {
                    if k == key {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    /// Get an integer value from a section.
    ///
    /// Returns `None` if the section or key doesn't exist, or if the value is not an integer.
    pub fn get_int(&self, section: &str, key: &str) -> Option<i64> {
        match self.get(section, key) {
            Some(ConfigValue::Integer(v)) => Some(*v),
            _ => None,
        }
    }

    /// Get a boolean value from a section.
    ///
    /// Returns `None` if the section or key doesn't exist, or if the value is not a boolean.
    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        match self.get(section, key) {
            Some(ConfigValue::Boolean(v)) => Some(*v),
            _ => None,
        }
    }

    /// Get a string value from a section.
    ///
    /// Returns `None` if the section or key doesn't exist, or if the value is not a string.
    pub fn get_str(&self, section: &str, key: &str) -> Option<&str> {
        match self.get(section, key) {
            Some(ConfigValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }
}

/// Parse a TOML configuration from a byte slice.
///
/// # Errors
///
/// Returns an error message if the TOML is malformed.
pub fn parse_toml(data: &[u8]) -> Result<TomlConfig, &'static str> {
    let text = str::from_utf8(data).map_err(|_| "invalid UTF-8 in TOML")?;
    let mut config = TomlConfig::new();
    let mut current_section: Option<alloc::string::String> = None;

    for (line_num, line) in text.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header: [section_name]
        if line.starts_with('[') && line.ends_with(']') {
            let section_name = &line[1..line.len() - 1];
            if section_name.is_empty() {
                return Err("empty section name");
            }
            current_section = Some(alloc::string::String::from(section_name));
            config.sections.push(ConfigSection {
                name: alloc::string::String::from(section_name),
                entries: alloc::vec::Vec::new(),
            });
            continue;
        }

        // Key-value pair: key = value
        if let Some((key, value_str)) = line.split_once('=') {
            let key = key.trim();
            let value_str = value_str.trim();

            if key.is_empty() {
                return Err("empty key name");
            }

            let value = parse_value(value_str)?;

            // Add to current section or create a default section
            if let Some(ref section_name) = current_section {
                if let Some(section) = config
                    .sections
                    .iter_mut()
                    .find(|s| s.name == *section_name)
                {
                    section
                        .entries
                        .push((alloc::string::String::from(key), value));
                }
            } else {
                // No section yet, create a default one
                if config.sections.is_empty() {
                    config.sections.push(ConfigSection {
                        name: alloc::string::String::new(),
                        entries: alloc::vec::Vec::new(),
                    });
                }
                config.sections[0]
                    .entries
                    .push((alloc::string::String::from(key), value));
            }
            continue;
        }

        // Unknown syntax
        return Err("invalid TOML syntax");
    }

    Ok(config)
}

/// Parse a TOML value from a string.
fn parse_value(s: &str) -> Result<ConfigValue, &'static str> {
    // Boolean
    if s == "true" {
        return Ok(ConfigValue::Boolean(true));
    }
    if s == "false" {
        return Ok(ConfigValue::Boolean(false));
    }

    // Integer (decimal, hex, octal, binary)
    if let Some(v) = parse_integer(s) {
        return Ok(ConfigValue::Integer(v));
    }

    // String (quoted)
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
    {
        let inner = &s[1..s.len() - 1];
        return Ok(ConfigValue::String(alloc::string::String::from(inner)));
    }

    Err("invalid TOML value")
}

/// Parse an integer value from a string.
fn parse_integer(s: &str) -> Option<i64> {
    // Hex: 0x...
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }

    // Octal: 0o...
    if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        return i64::from_str_radix(oct, 8).ok();
    }

    // Binary: 0b...
    if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        return i64::from_str_radix(bin, 2).ok();
    }

    // Decimal (with optional sign)
    s.parse::<i64>().ok()
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
}
