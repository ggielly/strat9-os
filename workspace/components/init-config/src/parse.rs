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

//! TOML-subset parser for the boot configuration.
//!
//! Supported constructs are `[[silos]]`, `[[silos.strates]]`, `key = value`,
//! inline comments and blank lines. Unknown keys (such as `cpu_features` and
//! `probe_mode`) are ignored, and unknown sections are reported and ignored
//! instead of leaking into the current silo.

use alloc::{format, string::String, vec::Vec};

use crate::{
    model::{
        Diagnostic, Family, FaultPolicy, Mode, Sid, SiloDef, StrateDef, StrateKind, StrateRef,
        SID_AUTO_SENTINEL,
    },
    policy::RestartPolicy,
};

/// Result of parsing one configuration buffer.
#[derive(Clone, Debug, Default)]
pub struct ParsedConfig {
    pub silos: Vec<SiloDef>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Parses the silo configuration.
pub fn parse_config(data: &str) -> ParsedConfig {
    #[derive(Clone, Copy)]
    enum Section {
        /// Keys belong to the current silo.
        Silo,
        /// Keys belong to the last `[[silos.strates]]` of the current silo.
        Strate,
        /// Keys are ignored (unknown or misplaced section).
        Ignored,
    }

    let mut out = ParsedConfig::default();
    let mut current_silo: Option<SiloDef> = None;
    let mut section = Section::Silo;
    let mut current_target = StrateRef::default();

    for (index, raw_line) in data.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line == "[[silos]]" {
            if let Some(silo) = current_silo.take() {
                out.silos.push(silo);
            }
            let mut silo = SiloDef::default();
            silo.line = line_no;
            current_silo = Some(silo);
            section = Section::Silo;
            current_target = StrateRef::default();
            continue;
        }

        if line == "[[silos.strates]]" {
            match current_silo.as_mut() {
                Some(silo) => {
                    // One TOML table, one strate: a new table always starts a
                    // new definition instead of overwriting the previous one.
                    let mut strate = StrateDef::default();
                    strate.line = line_no;
                    silo.strates.push(strate);
                    current_target = StrateRef::default();
                    section = Section::Strate;
                }
                None => {
                    out.diagnostics.push(Diagnostic::new(
                        line_no,
                        String::from("config: [[silos.strates]] before any [[silos]], ignored\n"),
                    ));
                    section = Section::Ignored;
                }
            }
            continue;
        }

        if line.starts_with('[') {
            out.diagnostics.push(Diagnostic::new(
                line_no,
                format!(
                    "config: unsupported section '{}', its keys are ignored\n",
                    line
                ),
            ));
            section = Section::Ignored;
            continue;
        }

        let Some(idx) = line.find('=') else {
            continue;
        };
        let key = line[..idx].trim();
        let Some(val) = parse_value(&line[idx + 1..]) else {
            out.diagnostics.push(Diagnostic::new(
                line_no,
                format!("config: unterminated string for key '{}', ignored\n", key),
            ));
            continue;
        };

        let Some(silo) = current_silo.as_mut() else {
            out.diagnostics.push(Diagnostic::new(
                line_no,
                format!("config: key '{}' outside any [[silos]], ignored\n", key),
            ));
            continue;
        };

        match section {
            Section::Silo => match key {
                "name" => silo.name = String::from(val),
                "label" => silo.label = Some(String::from(val)),
                "sid" => {
                    silo.sid = match val.parse::<u32>() {
                        Ok(SID_AUTO_SENTINEL) => Sid::Auto,
                        Ok(sid) => Sid::Fixed(sid),
                        Err(_) => Sid::Invalid(String::from(val)),
                    }
                }
                "family" => silo.family = Family::from_name(val),
                "mode" => silo.mode = Mode::parse_octal(val).ok_or_else(|| String::from(val)),
                "admin" => silo.admin = parse_toml_bool(val),
                "graphics_enabled" => silo.graphics.enabled = parse_toml_bool(val),
                "graphics_mode" => silo.graphics.mode = String::from(val),
                "graphics_read_only" => silo.graphics.read_only = parse_toml_bool(val),
                "graphics_max_sessions" => silo.graphics.max_sessions = val.parse().unwrap_or(0),
                "graphics_session_ttl_sec" => {
                    silo.graphics.session_ttl_sec = val.parse().unwrap_or(0)
                }
                "graphics_turn_policy" => silo.graphics.turn_policy = String::from(val),
                "dma_max_domains" => silo.dma.max_domains = val.parse().unwrap_or(0),
                "dma_max_bytes" => silo.dma.max_bytes = parse_u64_auto(val).unwrap_or(0),
                "dma_iova_base" => silo.dma.iova_base = parse_u64_auto(val).unwrap_or(0),
                "dma_iova_limit" => silo.dma.iova_limit = parse_u64_auto(val).unwrap_or(0),
                "dma_fault_policy" => silo.dma.fault_policy = FaultPolicy::from_name_or_num(val),
                "restart" => match RestartPolicy::from_name(val) {
                    Some(policy) => silo.restart = policy,
                    None => out.diagnostics.push(Diagnostic::new(
                        line_no,
                        format!("config: unknown restart policy '{}', using 'always'\n", val),
                    )),
                },
                "critical" => silo.critical = parse_toml_bool(val),
                "max_restarts" => silo.max_restarts = val.parse().unwrap_or(3),
                _ => {}
            },
            Section::Strate => {
                if let Some(strate) = silo.strates.last_mut() {
                    match key {
                        "name" => strate.name = String::from(val),
                        "binary" => strate.binary = String::from(val),
                        "type" => strate.kind = kind_from(val, &current_target),
                        "target_strate" => {
                            current_target = StrateRef(String::from(val));
                            strate.target = current_target.clone();
                            if let StrateKind::WasmApp { runtime } = &mut strate.kind {
                                *runtime = current_target.clone();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Section::Ignored => {}
        }
    }

    if let Some(silo) = current_silo {
        out.silos.push(silo);
    }
    out
}

/// Maps a configured strate type onto its [`StrateKind`].
fn kind_from(val: &str, target: &StrateRef) -> StrateKind {
    match val {
        "elf" => StrateKind::Elf,
        "wasm-runtime" => StrateKind::WasmRuntime,
        "wasm-app" => StrateKind::WasmApp {
            runtime: target.clone(),
        },
        other => StrateKind::Unknown(String::from(other)),
    }
}

/// Removes a TOML inline comment, ignoring `#` inside quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut in_basic_string = false;
    let mut in_literal_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\\' if in_basic_string => escaped = !escaped,
            '"' if !in_literal_string => {
                if !escaped {
                    in_basic_string = !in_basic_string;
                }
                escaped = false;
            }
            '\'' if !in_basic_string => in_literal_string = !in_literal_string,
            '#' if !in_basic_string && !in_literal_string => return &line[..index],
            _ => escaped = false,
        }
    }
    line
}

/// Extracts the value of a `key = value` line.
///
/// Basic (`"..."`) and literal (`'...'`) strings are unquoted; anything else is
/// taken verbatim. Returns `None` for an unterminated string so the caller can
/// report the mistake instead of using half a value. Escape sequences are not
/// decoded: this configuration only carries identifiers, paths and numbers.
fn parse_value(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            match ch {
                '\\' => escaped = !escaped,
                '"' if !escaped => return Some(&rest[..index]),
                _ => escaped = false,
            }
        }
        None
    } else if let Some(rest) = raw.strip_prefix('\'') {
        rest.find('\'').map(|end| &rest[..end])
    } else {
        Some(raw)
    }
}

fn parse_toml_bool(s: &str) -> bool {
    matches!(s, "true" | "True" | "TRUE" | "1" | "yes" | "on")
}

/// Parse a decimal or `0x`-prefixed hexadecimal u64.
fn parse_u64_auto(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
