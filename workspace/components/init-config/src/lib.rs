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

//! Pure, host-testable boot configuration for `strate-init`.
//!
//! This crate owns everything that used to live inline in `strate-init`'s
//! `main.rs` and does not need a running kernel: the TOML-subset parser, the
//! family/mode policy validation, SID assignment and the construction of the
//! ordered [`BootPlan`]. `strate-init` only maps the resulting plan onto the
//! kernel ABI types at the execution boundary.
//!
//! It is allocation based and builds both on the host (unit tests) and for
//! `x86_64-unknown-none` (`no_std` + `alloc`).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod model;
pub mod parse;
pub mod plan;
pub mod policy;
pub mod sha256;
pub mod validate;

pub use model::{
    Diagnostic, Dma, Family, FaultPolicy, Grant, GrantKind, Graphics, Mode, PciAddress, Policy,
    Profile, Selection, ServicePath, Sha256Digest, Sid, SiloDef, StrateDef, StrateKind, StrateRef,
    DEFAULT_ADMIN_ALLOW, SID_AUTO_SENTINEL, SID_SYSTEM_FIRST, SID_USER_FIRST,
};
pub use parse::{parse_config, ParsedConfig};
pub use plan::{
    build_plan, build_plan_with_policy, build_plan_with_reserved, ensure_required_silos,
    merge_overlay, BootPlan, PlannedKind, PlannedSilo, PlannedStrate,
};
pub use policy::{classify, Backoff, ExitKind, RestartBudget, RestartPolicy};
pub use sha256::{hex as sha256_hex, sha256};
pub use validate::{validate_silo, validate_silo_with_allowlist, Validated};

#[cfg(test)]
mod tests;
