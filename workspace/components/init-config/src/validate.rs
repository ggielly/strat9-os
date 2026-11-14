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

use alloc::{format, string::String, vec::Vec};

use crate::model::{Diagnostic, Family, GrantKind, Mode, SiloDef, DEFAULT_ADMIN_ALLOW};

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

/// Validates one silo against the family policy using the shipped default
/// administrator allowlist.
pub fn validate_silo(def: &SiloDef) -> Result<Validated, Diagnostic> {
    let allow: Vec<String> = DEFAULT_ADMIN_ALLOW
        .iter()
        .map(|s| String::from(*s))
        .collect();
    validate_silo_with_allowlist(def, &allow)
}

/// Validates one silo against the family policy and the policy admin allowlist.
///
/// Returns the first failing check, matching the historic boot order: unknown
/// family, invalid mode, admin outside SYS, admin allowlist, family mode
/// ceiling, then the grant ceiling and duplicate grants.
pub fn validate_silo_with_allowlist(
    def: &SiloDef,
    admin_allow: &[String],
) -> Result<Validated, Diagnostic> {
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
    // accepted for the SYS family and only for allowlisted names.
    if def.admin {
        if !matches!(def.family, Family::Sys) {
            return Err(Diagnostic::new(
                def.line,
                format!(
                    "SECURITY VIOLATION: admin requested for non-SYS silo {}, skipped\n",
                    def.name
                ),
            ));
        }
        if !admin_allow.iter().any(|name| name == &def.name) {
            return Err(Diagnostic::new(
                def.line,
                format!(
                    "SECURITY VIOLATION: admin silo {} is not in the admin_allow list, skipped\n",
                    def.name
                ),
            ));
        }
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

    // Grant ceiling: hardware/DMA grants are reserved to DRV/SYS; a read-write
    // path grant requires the registry write bit in the family ceiling while a
    // read-only path is available to every family.
    let host_family = matches!(def.family, Family::Sys | Family::Drv);
    let write_bit = ceiling.0 & 0o002 != 0;
    for (index, grant) in def.grants.iter().enumerate() {
        if def.grants[..index].iter().any(|earlier| earlier == grant) {
            return Err(Diagnostic::new(
                def.line,
                format!(
                    "CONFIG ERROR: duplicate grant '{}' for silo {}, skipped\n",
                    grant.as_str(),
                    def.name
                ),
            ));
        }
        match &grant.kind {
            GrantKind::Irq(_) | GrantKind::Pci(_) | GrantKind::Dma(_) => {
                if !host_family {
                    return Err(Diagnostic::new(
                        def.line,
                        format!(
                            "SECURITY VIOLATION: grant '{}' not allowed for {} silo {}, skipped\n",
                            grant.as_str(),
                            def.family.as_str(),
                            def.name
                        ),
                    ));
                }
            }
            GrantKind::Path { write: true, .. } => {
                if !write_bit {
                    return Err(Diagnostic::new(
                        def.line,
                        format!(
                            "SECURITY VIOLATION: write grant '{}' exceeds {} family ceiling, silo {} skipped\n",
                            grant.as_str(),
                            def.family.as_str(),
                            def.name
                        ),
                    ));
                }
            }
            GrantKind::Path { write: false, .. } => {}
        }
    }

    Ok(Validated {
        family_id,
        mode,
        system_range: family_id <= 3,
    })
}
