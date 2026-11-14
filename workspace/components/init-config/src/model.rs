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

//! Strongly typed boot configuration model.
//!
//! Every string/int that used to be threaded through the parser and the boot
//! loop is modelled explicitly here. The kernel ABI types (`SiloConfig`,
//! `SiloMode`) are deliberately **not** referenced: this crate stays free of
//! `strat9-syscall` so it can be unit tested on the host.

use alloc::{string::String, vec, vec::Vec};

use crate::policy::RestartPolicy;

/// `sid` value the shipped configuration uses to request automatic allocation.
///
/// It is kept as a sentinel (instead of removing the key) so the boot files
/// stay readable and the kernel-visible SID is always allocated by init.
pub const SID_AUTO_SENTINEL: u32 = 42;
/// First SID handed out to a system-family silo (`SYS`, `DRV`, `FS`, `NET`).
pub const SID_SYSTEM_FIRST: u32 = 100;
/// First SID handed out to a user-family silo (`WASM`, `USR`).
pub const SID_USER_FIRST: u32 = 1000;

/// A diagnostic produced while parsing, validating or planning.
///
/// `message` is the exact text `strate-init` used to log (without the
/// `[init] ` prefix), so the execution boundary can reproduce the historic
/// log lines verbatim. `line` is 1-based and `0` when no source line applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub line: usize,
    pub message: String,
}

impl Diagnostic {
    pub fn new(line: usize, message: String) -> Self {
        Self { line, message }
    }
}

/// 9-bit octal permission mode.
///
/// Mirrors `strat9_abi::data::SiloMode` bit-for-bit: three groups of three
/// bits (`control`, `hardware`, `registry`), LSB = registry. The subset
/// predicate is copied verbatim so host and kernel agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode(pub u16);

impl Mode {
    /// Returns true if `self` bits are a subset of `other`'s bits.
    pub const fn is_subset_of(&self, other: &Mode) -> bool {
        let (s_c, s_h, s_r) = ((self.0 >> 6) & 0o7, (self.0 >> 3) & 0o7, self.0 & 0o7);
        let (o_c, o_h, o_r) = ((other.0 >> 6) & 0o7, (other.0 >> 3) & 0o7, other.0 & 0o7);
        (s_c & !o_c) == 0 && (s_h & !o_h) == 0 && (s_r & !o_r) == 0
    }

    /// Parses a C-style octal string (`"076"` or `"0o76"`).
    pub fn parse_octal(s: &str) -> Option<Mode> {
        let trimmed = s.strip_prefix("0o").unwrap_or(s);
        u16::from_str_radix(trimmed, 8).ok().map(Mode)
    }
}

/// A silo family, carrying its kernel id and maximum operations mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Family {
    Sys,
    Drv,
    Fs,
    Net,
    Wasm,
    Usr,
    /// Family name that is not part of the ABI; validation rejects it.
    Unknown(String),
}

impl Family {
    /// Maps a configuration name onto a family, keeping unknown names intact.
    pub fn from_name(name: &str) -> Family {
        match name {
            "SYS" => Family::Sys,
            "DRV" => Family::Drv,
            "FS" => Family::Fs,
            "NET" => Family::Net,
            "WASM" => Family::Wasm,
            "USR" => Family::Usr,
            other => Family::Unknown(String::from(other)),
        }
    }

    /// Family identifier expected by the kernel ABI, or `None` when unknown.
    pub fn id(&self) -> Option<u8> {
        Some(match self {
            Family::Sys => 0,
            Family::Drv => 1,
            Family::Fs => 2,
            Family::Net => 3,
            Family::Wasm => 4,
            Family::Usr => 5,
            Family::Unknown(_) => return None,
        })
    }

    /// Highest operations mode a silo of this family may be granted.
    pub fn ceiling(&self) -> Option<Mode> {
        Some(match self {
            Family::Sys => Mode(0o777),
            Family::Drv | Family::Fs | Family::Net => Mode(0o076),
            Family::Wasm => Mode(0o006),
            Family::Usr => Mode(0o004),
            Family::Unknown(_) => return None,
        })
    }

    /// SYS/DRV/FS/NET allocate from the system range; WASM/USR from user.
    pub fn system_range(&self) -> bool {
        matches!(self.id(), Some(id) if id <= 3)
    }

    /// The configured name of the family (the raw string for unknown ones).
    pub fn as_str(&self) -> &str {
        match self {
            Family::Sys => "SYS",
            Family::Drv => "DRV",
            Family::Fs => "FS",
            Family::Net => "NET",
            Family::Wasm => "WASM",
            Family::Usr => "USR",
            Family::Unknown(name) => name,
        }
    }
}

/// SID requested by the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sid {
    /// Allocate the next free SID of the family range.
    Auto,
    /// Explicit SID; rejected when it is already taken.
    Fixed(u32),
    /// The configured value is not a number; the silo must be skipped.
    Invalid(String),
}

impl Sid {
    /// The explicit SID, if any (used to reserve SIDs ahead of allocation).
    pub fn fixed(&self) -> Option<u32> {
        match self {
            Sid::Fixed(sid) => Some(*sid),
            _ => None,
        }
    }
}

/// DMA/IOMMU fault policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FaultPolicy {
    /// 0: log the fault and continue.
    #[default]
    Log,
    /// 1: notify the owning silo.
    Notify,
    /// 2: kill the owning silo.
    Kill,
    /// 3: panic the kernel.
    Panic,
}

impl FaultPolicy {
    /// Parses the named policy, falling back to the numeric encoding.
    pub fn from_name_or_num(s: &str) -> FaultPolicy {
        match s {
            "log" => FaultPolicy::Log,
            "notify" => FaultPolicy::Notify,
            "kill" => FaultPolicy::Kill,
            "panic" => FaultPolicy::Panic,
            other => match other.parse::<u8>() {
                Ok(1) => FaultPolicy::Notify,
                Ok(2) => FaultPolicy::Kill,
                Ok(3) => FaultPolicy::Panic,
                _ => FaultPolicy::Log,
            },
        }
    }

    /// Numeric encoding expected by `SiloConfig::dma_fault_policy`.
    pub fn to_u8(self) -> u8 {
        match self {
            FaultPolicy::Log => 0,
            FaultPolicy::Notify => 1,
            FaultPolicy::Kill => 2,
            FaultPolicy::Panic => 3,
        }
    }
}

/// Graphics subsystem configuration for a silo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graphics {
    pub enabled: bool,
    pub mode: String,
    pub read_only: bool,
    pub max_sessions: u16,
    pub session_ttl_sec: u32,
    pub turn_policy: String,
}

impl Default for Graphics {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: String::new(),
            read_only: false,
            max_sessions: 0,
            session_ttl_sec: 0,
            turn_policy: String::from("auto"),
        }
    }
}

/// DMA/IOMMU limits for a silo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dma {
    pub max_domains: u32,
    pub max_bytes: u64,
    pub iova_base: u64,
    pub iova_limit: u64,
    pub fault_policy: FaultPolicy,
}

/// Reference to a runtime strate (the `target_strate` value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrateRef(pub String);

impl Default for StrateRef {
    fn default() -> Self {
        Self(String::from("default"))
    }
}

/// How a strate is launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrateKind {
    /// A native ELF module.
    Elf,
    /// A wasm runtime service: launched like an ELF but also hosts wasm apps.
    WasmRuntime,
    /// A wasm application launched through `runtime`.
    WasmApp { runtime: StrateRef },
    /// A type name that is not understood; validation/logging drops the strate.
    Unknown(String),
}

impl Default for StrateKind {
    fn default() -> Self {
        StrateKind::Elf
    }
}

/// One strate declared inside a silo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrateDef {
    /// 1-based source line of the `[[silos.strates]]` table.
    pub line: usize,
    pub name: String,
    pub binary: String,
    /// `target_strate` value. For a wasm runtime it is the service label; for
    /// a wasm app it names the runtime strate.
    pub target: StrateRef,
    pub kind: StrateKind,
}

impl Default for StrateDef {
    fn default() -> Self {
        Self {
            line: 0,
            name: String::new(),
            binary: String::new(),
            target: StrateRef::default(),
            kind: StrateKind::Elf,
        }
    }
}

/// One silo as parsed from configuration.
#[derive(Clone, Debug)]
pub struct SiloDef {
    /// 1-based source line of the `[[silos]]` table.
    pub line: usize,
    pub name: String,
    pub label: Option<String>,
    pub sid: Sid,
    pub family: Family,
    /// Parsed octal mode, or the offending raw string when malformed.
    pub mode: Result<Mode, String>,
    pub admin: bool,
    pub graphics: Graphics,
    pub dma: Dma,
    /// Restart policy applied to every strate of this silo.
    pub restart: RestartPolicy,
    /// A critical strate is logged loudly when it exhausts its restart budget.
    pub critical: bool,
    /// Maximum restarts admitted within the intensity window.
    pub max_restarts: u8,
    pub strates: Vec<StrateDef>,
}

impl Default for SiloDef {
    fn default() -> Self {
        Self {
            line: 0,
            name: String::new(),
            label: None,
            sid: Sid::Auto,
            family: Family::Usr,
            mode: Ok(Mode(0o000)),
            admin: false,
            graphics: Graphics::default(),
            dma: Dma::default(),
            restart: RestartPolicy::Always,
            critical: false,
            max_restarts: 3,
            strates: Vec::new(),
        }
    }
}

impl SiloDef {
    /// Builds the fallback definition of a mandatory silo.
    ///
    /// Deliberately identical to the entry the UEFI image ships, so a missing
    /// configuration key cannot change the machine.
    pub fn fallback(name: &str, family: &str, strate: &str, binary: &str) -> Self {
        Self {
            name: String::from(name),
            family: Family::from_name(family),
            mode: Ok(Mode(0o076)),
            strates: vec![StrateDef {
                name: String::from(strate),
                binary: String::from(binary),
                ..StrateDef::default()
            }],
            ..Self::default()
        }
    }
}
