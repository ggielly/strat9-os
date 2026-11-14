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

//! Policy validation for one parsed silo.
//!
//! Each failure produces a [`Diagnostic`] carrying the offending source line
//! and the historic log text, instead of the old `continue` + inline log. The
//! planner accumulates these across the whole configuration.

use alloc::format;

use crate::model::{Diagnostic, Family, Mode, SiloDef};

/// A silo that passed policy validation, with resolved family metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validated {
    /// Kernel family identifier.
    pub family_id: u8,
    /// Parsed and accepted operations mode.
    pub mode: Mode,
    /// True when the silo allocates its SID from the system range.
    pub system_range: bool,
}

/// Validates one silo against the family policy.
///
/// Returns the first failing check, matching the historic boot order: unknown
/// family, invalid mode, admin outside SYS, then the family mode ceiling.
pub fn validate_silo(def: &SiloDef) -> Result<Validated, Diagnostic> {
    let Some(family_id) = def.family.id() else {
        return Err(Diagnostic::new(
            def.line,
            format!(
                "Invalid family '{}' for silo {}, skipped\n",
                def.family.as_str(),
                def.name
            ),
        ));
    };
    let ceiling = def
        .family
        .ceiling()
        .expect("a family with an id always has a ceiling");

    let mode = match &def.mode {
        Ok(mode) => *mode,
        Err(raw) => {
            return Err(Diagnostic::new(
                def.line,
                format!(
                    "CONFIG ERROR: invalid mode '{}' for silo {}, skipped\n",
                    raw, def.name
                ),
            ))
        }
    };

    // Administrator capability: explicit opt-in from the boot config, only
    // accepted for the SYS family.
    if def.admin && !matches!(def.family, Family::Sys) {
        return Err(Diagnostic::new(
            def.line,
            format!(
                "SECURITY VIOLATION: admin requested for non-SYS silo {}, skipped\n",
                def.name
            ),
        ));
    }

    if !mode.is_subset_of(&ceiling) {
        return Err(Diagnostic::new(
            def.line,
            format!(
                "SECURITY VIOLATION: silo {} exceeds family ceiling\n",
                def.name
            ),
        ));
    }

    Ok(Validated {
        family_id,
        mode,
        system_range: family_id <= 3,
    })
}
