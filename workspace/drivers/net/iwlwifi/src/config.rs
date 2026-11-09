/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Wi-Fi configuration (TOML) and validation.
//!
//! The on-disk format is intentionally small: one `[wifi]` table (and an
//! optional `[roam]` table) with the handful of keys the AX201 driver core
//! understands.  A full TOML parser would drag `serde`/`toml` into the
//! kernel, so this module implements the subset below:
//!
//! ```toml
//! [wifi]
//! enabled    = true
//! interface  = "wlan0"
//! country    = "FR"
//! ssid       = "HomeNet"
//! passphrase = "correct horse battery staple"
//! # or, instead of passphrase, a pre-computed 64-hex-digit PMK:
//! # psk      = "0123...ef"
//! firmware   = "/initfs/iwlwifi-QuZ-a0-hr-b0-77.ucode"
//! hidden     = false
//! # bssid    = "aa:bb:cc:dd:ee:ff"
//! ```
//!
//! Supported values: bare/quoted strings, booleans, decimal integers, and
//! `#` comments.  Unknown keys are rejected so a typo cannot silently leave
//! the interface unconfigured.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::{derive_pmk, PMK_LEN};

pub const MAX_SSID: usize = 32;
pub const MAX_PASSPHRASE: usize = 63;
pub const MAX_PATH: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    Syntax,
    UnknownKey,
    MissingKey,
    InvalidValue,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    pub line: usize,
    pub kind: ConfigErrorKind,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self.kind {
            ConfigErrorKind::Syntax => "syntax",
            ConfigErrorKind::UnknownKey => "unknown key",
            ConfigErrorKind::MissingKey => "missing key",
            ConfigErrorKind::InvalidValue => "invalid value",
            ConfigErrorKind::Unsupported => "unsupported option",
        };
        write!(f, "wifi config line {}: {}", self.line, kind)
    }
}

#[derive(Clone, Debug)]
pub struct WifiConfig {
    pub enabled: bool,
    pub interface: String,
    pub country: [u8; 2],
    pub ssid: [u8; MAX_SSID],
    pub ssid_len: usize,
    pub passphrase: [u8; MAX_PASSPHRASE],
    pub passphrase_len: usize,
    /// Pre-computed PMK (from `psk = "<64 hex digits>"`), if provided.
    pub psk: Option<[u8; PMK_LEN]>,
    /// Firmware path inside the initfs namespace.
    pub firmware: String,
    pub hidden: bool,
    pub bssid: Option<[u8; 6]>,
    /// Optional channel hint; required for a direct join without scanning.
    pub channel: Option<u8>,
}

impl Default for WifiConfig {
    fn default() -> Self {
        let mut fw = String::new();
        fw.push_str("/initfs/iwlwifi-QuZ-a0-hr-b0-77.ucode");
        Self {
            enabled: false,
            interface: String::from("wlan0"),
            country: *b"FR",
            ssid: [0u8; MAX_SSID],
            ssid_len: 0,
            passphrase: [0u8; MAX_PASSPHRASE],
            passphrase_len: 0,
            psk: None,
            firmware: fw,
            hidden: false,
            bssid: None,
            channel: None,
        }
    }
}

impl WifiConfig {
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.passphrase[..self.passphrase_len]
    }

    /// True when the config has enough material to join a WPA2-PSK network.
    pub fn is_complete(&self) -> bool {
        self.enabled
            && self.ssid_len > 0
            && (self.psk.is_some() || self.passphrase_len >= 8)
    }

    /// PMK from the configured passphrase, or the configured raw PSK.
    pub fn pmk(&self) -> Option<[u8; PMK_LEN]> {
        if let Some(psk) = self.psk {
            return Some(psk);
        }
        if self.passphrase_len >= 8 {
            Some(derive_pmk(self.passphrase(), self.ssid()))
        } else {
            None
        }
    }
}

/// Parse a `wifi.toml` document.
pub fn parse(text: &str) -> Result<WifiConfig, ConfigError> {
    let mut cfg = WifiConfig::default();
    let mut section = String::new();
    let mut saw_wifi_section = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(err(line_no, ConfigErrorKind::Syntax));
            }
            section.clear();
            section.push_str(line[1..line.len() - 1].trim());
            if section == "wifi" {
                saw_wifi_section = true;
            } else if section != "roam" {
                return Err(err(line_no, ConfigErrorKind::UnknownKey));
            }
            continue;
        }

        let (key_raw, value_raw) = line
            .split_once('=')
            .ok_or_else(|| err(line_no, ConfigErrorKind::Syntax))?;
        let key = key_raw.trim();
        let value = value_raw.trim();

        // Only `[wifi]` keys are implemented.  `[roam]` is accepted for
        // forward compatibility but currently has no effect.
        if section == "roam" {
            continue;
        }
        if !saw_wifi_section && section.is_empty() {
            return Err(err(line_no, ConfigErrorKind::Syntax));
        }

        match key {
            "enabled" => cfg.enabled = parse_bool(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?,
            "hidden" => cfg.hidden = parse_bool(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?,
            "interface" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                if s.is_empty() || s.len() > 16 {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.interface = String::from(s);
            }
            "country" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                let b = s.as_bytes();
                if b.len() != 2 || !b.iter().all(|c| c.is_ascii_alphabetic()) {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.country = [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()];
            }
            "ssid" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                let b = s.as_bytes();
                if b.is_empty() || b.len() > MAX_SSID {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.ssid = [0u8; MAX_SSID];
                cfg.ssid[..b.len()].copy_from_slice(b);
                cfg.ssid_len = b.len();
            }
            "passphrase" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                let b = s.as_bytes();
                if b.len() < 8 || b.len() > MAX_PASSPHRASE {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.passphrase = [0u8; MAX_PASSPHRASE];
                cfg.passphrase[..b.len()].copy_from_slice(b);
                cfg.passphrase_len = b.len();
            }
            "psk" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                cfg.psk = Some(parse_hex_array(s.as_bytes(), line_no)?);
            }
            "firmware" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                if s.is_empty() || s.len() > MAX_PATH {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.firmware = String::from(s);
            }
            "channel" => {
                let v = value
                    .trim_matches('"')
                    .parse::<u8>()
                    .map_err(|_| err(line_no, ConfigErrorKind::InvalidValue))?;
                if v == 0 || v > 196 {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.channel = Some(v);
            }
            "bssid" => {
                let s = parse_string(value).ok_or_else(|| err(line_no, ConfigErrorKind::InvalidValue))?;
                let mut out = [0u8; 6];
                let mut n = 0usize;
                for part in s.split([':', '-']) {
                    if n >= 6 {
                        return Err(err(line_no, ConfigErrorKind::InvalidValue));
                    }
                    out[n] = u8::from_str_radix(part, 16)
                        .map_err(|_| err(line_no, ConfigErrorKind::InvalidValue))?;
                    n += 1;
                }
                if n != 6 {
                    return Err(err(line_no, ConfigErrorKind::InvalidValue));
                }
                cfg.bssid = Some(out);
            }
            _ => return Err(err(line_no, ConfigErrorKind::UnknownKey)),
        }
    }

    if !saw_wifi_section {
        return Err(err(1, ConfigErrorKind::MissingKey));
    }
    if cfg.enabled && cfg.ssid_len == 0 {
        return Err(err(1, ConfigErrorKind::MissingKey));
    }
    if cfg.enabled && cfg.psk.is_none() && cfg.passphrase_len < 8 {
        return Err(err(1, ConfigErrorKind::MissingKey));
    }
    Ok(cfg)
}

fn err(line: usize, kind: ConfigErrorKind) -> ConfigError {
    ConfigError { line, kind }
}

fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escape = false;
    for (i, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_str => escape = true,
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Parse a quoted string with the small escape set TOML permits in basic
/// strings.  Returns `None` for unterminated or unquoted values.
fn parse_string(v: &str) -> Option<String> {
    let bytes = v.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return None;
    }
    let mut out = String::new();
    let mut i = 1usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if i != bytes.len() - 1 {
                    return None; // trailing garbage
                }
                return Some(out);
            }
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => return None,
                }
            }
            b => out.push(b as char),
        }
        i += 1;
    }
    None
}

fn parse_hex_array(bytes: &[u8], line: usize) -> Result<[u8; PMK_LEN], ConfigError> {
    if bytes.len() != PMK_LEN * 2 {
        return Err(err(line, ConfigErrorKind::InvalidValue));
    }
    let mut out = [0u8; PMK_LEN];
    for i in 0..PMK_LEN {
        let hi = hexval(bytes[i * 2]).ok_or_else(|| err(line, ConfigErrorKind::InvalidValue))?;
        let lo = hexval(bytes[i * 2 + 1]).ok_or_else(|| err(line, ConfigErrorKind::InvalidValue))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Load and parse a config from raw bytes (the kernel reads
/// `/initfs/wifi.toml` through the VFS).
pub fn parse_bytes(bytes: &[u8]) -> Result<WifiConfig, ConfigError> {
    let text = core::str::from_utf8(bytes).map_err(|_| err(1, ConfigErrorKind::InvalidValue))?;
    parse(text)
}

/// Build a `Vec` of errors for diagnostics, used by the kernel glue to log
/// all problems at once.
pub fn validate(cfg: &WifiConfig) -> Vec<ConfigError> {
    let mut errors = Vec::new();
    if cfg.enabled {
        if cfg.ssid_len == 0 {
            errors.push(err(1, ConfigErrorKind::MissingKey));
        }
        if cfg.psk.is_none() && cfg.passphrase_len < 8 {
            errors.push(err(1, ConfigErrorKind::MissingKey));
        }
        if cfg.firmware.is_empty() {
            errors.push(err(1, ConfigErrorKind::MissingKey));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# Example
[wifi]
enabled = true
interface = "wlan0"
country = "fr"
ssid = "HomeNet"   # trailing comment
passphrase = "correct horse battery staple"
firmware = "/initfs/iwlwifi-QuZ-a0-hr-b0-77.ucode"
hidden = false
"#;

    #[test]
    fn parses_sample() {
        let cfg = parse(SAMPLE).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.interface, "wlan0");
        assert_eq!(cfg.country, *b"FR");
        assert_eq!(cfg.ssid(), b"HomeNet");
        assert_eq!(cfg.passphrase(), b"correct horse battery staple");
        assert!(cfg.is_complete());
        assert!(cfg.pmk().is_some());
    }

    #[test]
    fn accepts_psk_hex() {
        let psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let text = alloc::format!(
            "[wifi]\nenabled=true\nssid=\"x\"\npsk=\"{}\"\n",
            psk
        );
        let cfg = parse(&text).unwrap();
        assert_eq!(cfg.psk.unwrap()[0], 0x00);
        assert_eq!(cfg.psk.unwrap()[31], 0xff);
    }

    #[test]
    fn rejects_unknown_key() {
        let e = parse("[wifi]\nenabled=true\nssid=\"x\"\npassphrase=\"12345678\"\nbogus=1\n")
            .unwrap_err();
        assert_eq!(e.kind, ConfigErrorKind::UnknownKey);
        assert_eq!(e.line, 5);
    }

    #[test]
    fn rejects_short_passphrase() {
        let e = parse("[wifi]\nenabled=true\nssid=\"x\"\npassphrase=\"short\"\n").unwrap_err();
        assert_eq!(e.kind, ConfigErrorKind::InvalidValue);
    }

    #[test]
    fn parse_string_handles_escapes() {
        assert_eq!(parse_string(r#""a\nb""#).as_deref(), Some("a\nb"));
        assert_eq!(parse_string(r#""a\tb""#).as_deref(), Some("a\tb"));
        assert_eq!(parse_string(r#""a\rb""#).as_deref(), Some("a\rb"));
        assert_eq!(parse_string(r#""a\"b""#).as_deref(), Some("a\"b"));
        assert_eq!(parse_string(r#""a\\b""#).as_deref(), Some("a\\b"));
        assert_eq!(parse_string(r#""a\qb""#), None);
    }

    #[test]
    fn comment_after_escaped_quote_is_preserved() {
        let line = r##"ssid = "a\"#b" # comment"##;
        assert_eq!(strip_comment(line), r##"ssid = "a\"#b" "##);
    }

    #[test]
    fn comment_inside_string_is_preserved() {
        let cfg = parse("[wifi]\nenabled=true\nssid=\"a#b\"\npassphrase=\"12345678\"\n").unwrap();
        assert_eq!(cfg.ssid(), b"a#b");
    }
}
