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

//! Turns parsed silos into an ordered, kernel-ready [`BootPlan`].
//!
//! This keeps the current boot semantics: mandatory-silo fallbacks, the
//! wasm-test overlay merge (add-by-name only), bus-first reordering, SID
//! assignment and per-silo policy validation. A dependency graph is a later
//! step.

use alloc::{format, string::String, vec::Vec};

use crate::{
    model::{Diagnostic, Dma, Graphics, Mode, Sid, SiloDef, SID_SYSTEM_FIRST, SID_USER_FIRST},
    policy::RestartPolicy,
    validate,
};

/// The ordered plan `strate-init` executes.
#[derive(Clone, Debug, Default)]
pub struct BootPlan {
    pub silos: Vec<PlannedSilo>,
    pub diagnostics: Vec<Diagnostic>,
}

/// A silo that survived validation, with its SID assigned.
#[derive(Clone, Debug)]
pub struct PlannedSilo {
    pub name: String,
    pub label: Option<String>,
    pub sid: u32,
    pub family_id: u8,
    pub mode: Mode,
    pub admin: bool,
    pub graphics: Graphics,
    pub dma: Dma,
    pub restart: RestartPolicy,
    pub critical: bool,
    pub max_restarts: u8,
    pub strates: Vec<PlannedStrate>,
}

/// A strate ready to launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedStrate {
    pub name: String,
    pub binary: String,
    pub kind: PlannedKind,
    /// Restart policy inherited from the owning silo.
    pub restart: RestartPolicy,
    /// Critical flag inherited from the owning silo.
    pub critical: bool,
    /// Restart cap inherited from the owning silo.
    pub max_restarts: u8,
}

/// Resolved strate launch kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedKind {
    /// Native ELF module.
    Elf,
    /// Wasm runtime service (launched like an ELF).
    WasmRuntime,
    /// Wasm application with its resolved service label.
    WasmApp { service_label: String },
}

/// Builds the boot plan from parsed silos and any diagnostics already
/// collected (parse or overlay).
pub fn build_plan(mut silos: Vec<SiloDef>, mut diagnostics: Vec<Diagnostic>) -> BootPlan {
    ensure_required_silos(&mut silos, &mut diagnostics);
    reorder_bus_first(&mut silos);

    // SIDs the configuration pins explicitly: automatic allocation must not
    // take one of them, even when the explicit silo appears later in the list.
    let mut fixed_sids: Vec<u32> = Vec::new();
    for silo in &silos {
        if let Sid::Fixed(sid) = silo.sid {
            fixed_sids.push(sid);
        }
    }
    // SIDs handed out during this boot, explicit or automatic.
    let mut used_sids: Vec<u32> = Vec::new();
    let mut next_system_sid = SID_SYSTEM_FIRST;
    let mut next_user_sid = SID_USER_FIRST;
    let mut planned: Vec<PlannedSilo> = Vec::new();

    for def in silos {
        let valid = match validate::validate_silo(&def) {
            Ok(valid) => valid,
            Err(diag) => {
                diagnostics.push(diag);
                continue;
            }
        };

        let sid = match &def.sid {
            Sid::Invalid(raw) => {
                diagnostics.push(Diagnostic::new(
                    def.line,
                    format!(
                        "CONFIG ERROR: invalid sid '{}' for silo {}, skipped\n",
                        raw, def.name
                    ),
                ));
                continue;
            }
            Sid::Fixed(sid) => {
                if used_sids.contains(sid) {
                    diagnostics.push(Diagnostic::new(
                        def.line,
                        format!(
                            "CONFIG ERROR: sid {} is already used, silo {} skipped\n",
                            sid, def.name
                        ),
                    ));
                    continue;
                }
                used_sids.push(*sid);
                *sid
            }
            Sid::Auto => {
                let next = if valid.system_range {
                    &mut next_system_sid
                } else {
                    &mut next_user_sid
                };
                let mut sid = *next;
                while used_sids.contains(&sid) || fixed_sids.contains(&sid) {
                    sid += 1;
                }
                *next = sid + 1;
                used_sids.push(sid);
                sid
            }
        };

        planned.push(PlannedSilo {
            name: def.name,
            label: def.label,
            sid,
            family_id: valid.family_id,
            mode: valid.mode,
            admin: def.admin,
            graphics: def.graphics,
            dma: def.dma,
            restart: def.restart,
            critical: def.critical,
            max_restarts: def.max_restarts,
            strates: plan_strates(
                &def.strates,
                def.restart,
                def.critical,
                def.max_restarts,
                &mut diagnostics,
            ),
        });
    }

    BootPlan {
        silos: planned,
        diagnostics,
    }
}

/// Resolves strate launch kinds, including wasm-app runtime target resolution.
///
/// A wasm app names a runtime strate in `target_strate`; the service label is
/// that runtime's own `target_strate`. If the runtime is not seen earlier in
/// the list, the app's raw target is used, and an empty label falls back to
/// `"default"` — matching the historic execution loop.
fn plan_strates(
    strates: &[crate::model::StrateDef],
    restart: RestartPolicy,
    critical: bool,
    max_restarts: u8,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<PlannedStrate> {
    use crate::model::StrateKind;

    let mut runtime_targets: Vec<(String, String)> = Vec::new();
    let mut planned: Vec<PlannedStrate> = Vec::new();

    for def in strates {
        match &def.kind {
            StrateKind::Elf => planned.push(PlannedStrate {
                name: def.name.clone(),
                binary: def.binary.clone(),
                kind: PlannedKind::Elf,
                restart,
                critical,
                max_restarts,
            }),
            StrateKind::WasmRuntime => {
                runtime_targets.push((def.name.clone(), def.target.0.clone()));
                planned.push(PlannedStrate {
                    name: def.name.clone(),
                    binary: def.binary.clone(),
                    kind: PlannedKind::WasmRuntime,
                    restart,
                    critical,
                    max_restarts,
                });
            }
            StrateKind::WasmApp { runtime } => {
                let target = runtime.0.as_str();
                let mut label = String::new();
                if !target.is_empty() {
                    match runtime_targets.iter().find(|(name, _)| name == target) {
                        Some((_, runtime_label)) => label = runtime_label.clone(),
                        None => label = String::from(target),
                    }
                }
                if label.is_empty() {
                    label = String::from("default");
                }
                planned.push(PlannedStrate {
                    name: def.name.clone(),
                    binary: def.binary.clone(),
                    kind: PlannedKind::WasmApp {
                        service_label: label,
                    },
                    restart,
                    critical,
                    max_restarts,
                });
            }
            StrateKind::Unknown(other) => {
                diagnostics.push(Diagnostic::new(
                    def.line,
                    format!(
                        "  -> Strate '{}': unknown type '{}', ignored\n",
                        def.name, other
                    ),
                ));
            }
        }
    }

    planned
}

/// Adds the mandatory silo fallbacks when they are absent from the config.
pub fn ensure_required_silos(silos: &mut Vec<SiloDef>, diagnostics: &mut Vec<Diagnostic>) {
    let mut has_bus = false;
    let mut has_network = false;
    let mut has_dhcp = false;
    for silo in silos.iter() {
        match silo.name.as_str() {
            "bus" => has_bus = true,
            "network" => has_network = true,
            "dhcp-client" => has_dhcp = true,
            _ => {}
        }
    }

    if !has_bus {
        diagnostics.push(Diagnostic::new(
            0,
            String::from("Missing mandatory silo 'bus' in config, adding fallback\n"),
        ));
        silos.push(SiloDef::fallback(
            "bus",
            "DRV",
            "strate-bus",
            "/initfs/strate-bus",
        ));
    }

    if !has_network {
        diagnostics.push(Diagnostic::new(
            0,
            String::from("Missing mandatory silo 'network' in config, adding fallback\n"),
        ));
        silos.push(SiloDef::fallback(
            "network",
            "NET",
            "strate-net",
            "/initfs/strate-net-silo",
        ));
    }

    if !has_dhcp {
        diagnostics.push(Diagnostic::new(
            0,
            String::from("Missing mandatory silo 'dhcp-client' in config, adding fallback\n"),
        ));
        silos.push(SiloDef::fallback(
            "dhcp-client",
            "NET",
            "dhcp-client",
            "/initfs/dhcp-client",
        ));
    }
}

/// Moves `bus` to the front (it must launch first for PCI discovery),
/// preserving the relative order of all other silos.
pub fn reorder_bus_first(silos: &mut Vec<SiloDef>) {
    if let Some(bus_pos) = silos.iter().position(|s| s.name == "bus") {
        if bus_pos != 0 {
            let bus_def = silos.remove(bus_pos);
            silos.insert(0, bus_def);
        }
    }
}

/// Adds overlay silos that are not already present by name.
///
/// Returns the number of silos actually added.
pub fn merge_overlay(silos: &mut Vec<SiloDef>, overlay: Vec<SiloDef>) -> usize {
    let mut added = 0;
    for over in overlay {
        if silos.iter().any(|s| s.name == over.name) {
            continue;
        }
        silos.push(over);
        added += 1;
    }
    added
}
