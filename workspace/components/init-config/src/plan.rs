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
//! This keeps the boot semantics: mandatory-silo fallbacks, the wasm-test
//! overlay merge (add-by-name only), target/profile selection, SID assignment
//! and per-silo policy validation. Ordering is derived from the declared
//! `provides`/`requires` dependency graph instead of a hard-coded "bus first"
//! special case; silos without dependencies keep declaration order.

use alloc::{format, string::String, vec, vec::Vec};

use crate::{
    model::{
        Diagnostic, Dma, Family, Grant, Graphics, Mode, Policy, Profile, ServicePath, Sha256Digest,
        Sid, SiloDef, SID_SYSTEM_FIRST, SID_USER_FIRST,
    },
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
    /// Service paths published by the silo (silo + strate tables).
    pub provides: Vec<ServicePath>,
    /// Service paths consumed by the silo (silo + strate tables).
    pub requires: Vec<ServicePath>,
    /// Expected digest of the silo's main strate, when declared.
    pub sha256: Option<Sha256Digest>,
    /// Resource grants declared on the silo or its strates.
    pub grants: Vec<Grant>,
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
    /// Service paths published by this strate.
    pub provides: Vec<ServicePath>,
    /// Service paths consumed by this strate.
    pub requires: Vec<ServicePath>,
    /// Expected binary digest, when declared.
    pub sha256: Option<Sha256Digest>,
    /// Resource grants declared on this strate.
    pub grants: Vec<Grant>,
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
/// collected (parse or overlay), using the default [`Policy`].
pub fn build_plan(silos: Vec<SiloDef>, diagnostics: Vec<Diagnostic>) -> BootPlan {
    build_plan_with_policy(silos, diagnostics, Policy::default())
}

/// Builds the boot plan applying an explicit policy (admin allowlist and
/// target/profile selection).
pub fn build_plan_with_policy(
    silos: Vec<SiloDef>,
    diagnostics: Vec<Diagnostic>,
    policy: Policy,
) -> BootPlan {
    build_plan_with_reserved(silos, diagnostics, policy, &[])
}

/// Builds the boot plan while treating `reserved` SIDs as already used.
///
/// A reload passes the SIDs of live children so automatic allocation can never
/// hand one of them to a newly added silo.
pub fn build_plan_with_reserved(
    mut silos: Vec<SiloDef>,
    mut diagnostics: Vec<Diagnostic>,
    policy: Policy,
    reserved: &[u32],
) -> BootPlan {
    ensure_required_silos(&mut silos, &mut diagnostics);
    let silos = apply_selection(silos, &policy);

    // Validate before building the graph so only legal silos can provide a
    // service or become a dependency.
    let mut valid: Vec<(SiloDef, validate::Validated)> = Vec::new();
    for def in silos {
        match validate::validate_silo_with_allowlist(&def, &policy.admin_allow) {
            Ok(checked) => valid.push((def, checked)),
            Err(diag) => diagnostics.push(diag),
        }
    }

    // An unparsable SID is a per-silo failure: report it before graph work so
    // its dependents can be dropped with the normal cascade.
    let mut with_sids: Vec<(SiloDef, validate::Validated)> = Vec::new();
    for (def, checked) in valid {
        if let Sid::Invalid(raw) = &def.sid {
            diagnostics.push(Diagnostic::new(
                def.line,
                format!(
                    "CONFIG ERROR: invalid sid '{}' for silo {}, skipped\n",
                    raw, def.name
                ),
            ));
            continue;
        }
        with_sids.push((def, checked));
    }

    let with_sids = drop_duplicate_providers(with_sids, &mut diagnostics);
    let ordered = resolve_order(with_sids, &mut diagnostics);

    // SIDs the configuration pins explicitly: automatic allocation must not
    // take one of them, even when the explicit silo appears later in the list.
    let mut fixed_sids: Vec<u32> = Vec::new();
    for (silo, _) in &ordered {
        if let Sid::Fixed(sid) = silo.sid {
            fixed_sids.push(sid);
        }
    }
    // SIDs handed out during this boot, explicit or automatic.
    let mut used_sids: Vec<u32> = Vec::new();
    let mut next_system_sid = SID_SYSTEM_FIRST;
    let mut next_user_sid = SID_USER_FIRST;
    // Reserved SIDs are live; skip them and advance each cursor past any
    // reserved value inside its range.
    for &sid in reserved {
        if !used_sids.contains(&sid) {
            used_sids.push(sid);
        }
        if sid >= next_system_sid && sid < SID_USER_FIRST {
            next_system_sid = sid + 1;
        }
        if sid >= next_user_sid {
            next_user_sid = sid + 1;
        }
    }
    let mut planned: Vec<PlannedSilo> = Vec::new();

    for (def, valid) in ordered {
        let sid = match &def.sid {
            Sid::Invalid(_) => continue,
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

        let provides = effective_provides(&def);
        let requires = effective_requires(&def);
        let grants = effective_grants(&def);
        let strates = plan_strates(
            &def.strates,
            def.restart,
            def.critical,
            def.max_restarts,
            &mut diagnostics,
        );
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
            provides,
            requires,
            sha256: def.sha256,
            grants,
            strates,
        });
    }

    BootPlan {
        silos: planned,
        diagnostics,
    }
}

/// Applies the target/profile selection.
///
/// Rules (documented once here):
/// * `disabled` always drops the named silos.
/// * `Full` keeps everything else.
/// * `Minimal` keeps the console-critical families `SYS`, `DRV`, `FS`, `NET`
///   and drops user families (`WASM`, `USR`).
/// * `Rescue` keeps the `SYS` family plus any silo named in the admin
///   allowlist, and drops everything else.
fn apply_selection(silos: Vec<SiloDef>, policy: &Policy) -> Vec<SiloDef> {
    silos
        .into_iter()
        .filter(|def| {
            if policy.selection.is_disabled(&def.name) {
                return false;
            }
            match policy.selection.profile {
                Profile::Full => true,
                Profile::Minimal => matches!(
                    def.family,
                    Family::Sys | Family::Drv | Family::Fs | Family::Net
                ),
                Profile::Rescue => {
                    matches!(def.family, Family::Sys)
                        || policy.admin_allow.iter().any(|name| name == &def.name)
                }
            }
        })
        .collect()
}

/// Service paths a silo publishes, aggregating its strate tables.
fn effective_provides(def: &SiloDef) -> Vec<ServicePath> {
    let mut out = def.provides.clone();
    for strate in &def.strates {
        out.extend(strate.provides.iter().cloned());
    }
    out
}

/// Service paths a silo consumes, aggregating its strate tables.
fn effective_requires(def: &SiloDef) -> Vec<ServicePath> {
    let mut out = def.requires.clone();
    for strate in &def.strates {
        out.extend(strate.requires.iter().cloned());
    }
    out
}

/// Resource grants a silo owns, aggregating its strate tables.
fn effective_grants(def: &SiloDef) -> Vec<Grant> {
    let mut out = def.grants.clone();
    for strate in &def.strates {
        out.extend(strate.grants.iter().cloned());
    }
    out
}

/// Drops the later silo when two silos publish the same service path.
fn drop_duplicate_providers(
    entries: Vec<(SiloDef, validate::Validated)>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<(SiloDef, validate::Validated)> {
    let mut seen: Vec<ServicePath> = Vec::new();
    let mut kept = Vec::new();
    for (def, checked) in entries {
        let provides = effective_provides(&def);
        let duplicate = provides
            .iter()
            .enumerate()
            .find(|(index, path)| seen.contains(path) || provides[..*index].contains(path))
            .map(|(_, path)| path.clone());
        if let Some(path) = duplicate {
            diagnostics.push(Diagnostic::new(
                def.line,
                format!(
                    "CONFIG ERROR: service '{}' is provided by multiple silos, {} skipped\n",
                    path.as_str(),
                    def.name
                ),
            ));
            continue;
        }
        seen.extend(provides);
        kept.push((def, checked));
    }
    kept
}

/// Orders silos topologically over `provides`/`requires`, dropping unknown,
/// cyclic and transitively-broken silos.
///
/// Independents preserve declaration order; each drop emits exactly one
/// diagnostic.
fn resolve_order(
    entries: Vec<(SiloDef, validate::Validated)>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<(SiloDef, validate::Validated)> {
    let count = entries.len();
    let provides: Vec<Vec<ServicePath>> = entries
        .iter()
        .map(|(def, _)| effective_provides(def))
        .collect();
    let requires: Vec<Vec<ServicePath>> = entries
        .iter()
        .map(|(def, _)| effective_requires(def))
        .collect();

    // service path -> providing silo index (unique after duplicate filtering).
    let mut providers: Vec<(ServicePath, usize)> = Vec::new();
    for (index, paths) in provides.iter().enumerate() {
        for path in paths {
            providers.push((path.clone(), index));
        }
    }
    let provider_of = |service: &ServicePath| -> Option<usize> {
        providers
            .iter()
            .find(|(path, _)| path == service)
            .map(|(_, index)| *index)
    };

    let mut dropped = vec![false; count];

    // 1. Unknown requires: no silo provides the service.
    for (index, required) in requires.iter().enumerate() {
        for service in required {
            match provider_of(service) {
                Some(provider) if provider == index => {}
                Some(_) => {}
                None => {
                    diagnostics.push(Diagnostic::new(
                        entries[index].0.line,
                        format!(
                            "CONFIG ERROR: silo {} requires unprovided service '{}', skipped\n",
                            entries[index].0.name,
                            service.as_str()
                        ),
                    ));
                    dropped[index] = true;
                    break;
                }
            }
        }
    }

    // 2. Cycles: drop every member of a strongly connected component.
    let cycle_groups = cycle_groups(&requires, &dropped, &provider_of);
    for group in cycle_groups {
        let mut names: Vec<String> = group
            .iter()
            .map(|index| entries[*index].0.name.clone())
            .collect();
        names.sort();
        diagnostics.push(Diagnostic::new(
            entries[group[0]].0.line,
            format!(
                "CONFIG ERROR: dependency cycle among silos: {}, skipped\n",
                names.join(", ")
            ),
        ));
        for index in group {
            dropped[index] = true;
        }
    }

    // 3. Cascade: drop any silo depending on a dropped provider.
    loop {
        let mut changed = false;
        for index in 0..count {
            if dropped[index] {
                continue;
            }
            for service in &requires[index] {
                if let Some(provider) = provider_of(service) {
                    if provider != index && dropped[provider] {
                        diagnostics.push(Diagnostic::new(
                            entries[index].0.line,
                            format!(
                                "CONFIG ERROR: silo {} depends on dropped silo {}, skipped\n",
                                entries[index].0.name, entries[provider].0.name
                            ),
                        ));
                        dropped[index] = true;
                        changed = true;
                        break;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // 4. Stable topological order of the survivors.
    let mut slots: Vec<Option<(SiloDef, validate::Validated)>> =
        entries.into_iter().map(Some).collect();
    let mut emitted = vec![false; count];
    let mut ordered = Vec::new();
    loop {
        let mut progress = false;
        for index in 0..count {
            if dropped[index] || emitted[index] {
                continue;
            }
            let ready = requires[index]
                .iter()
                .all(|service| match provider_of(service) {
                    Some(provider) if provider != index && !dropped[provider] => emitted[provider],
                    _ => true,
                });
            if ready {
                emitted[index] = true;
                progress = true;
                ordered.push(slots[index].take().expect("unemitted silo slot"));
            }
        }
        if !progress {
            break;
        }
    }

    // Defensive: an alive-but-unemitted silo would mean an unresolved cycle.
    for index in 0..count {
        if !dropped[index] && !emitted[index] {
            if let Some((def, _)) = &slots[index] {
                diagnostics.push(Diagnostic::new(
                    def.line,
                    format!(
                        "CONFIG ERROR: unresolved dependency order for silo {}, skipped\n",
                        def.name
                    ),
                ));
            }
        }
    }

    ordered
}

/// Returns the strongly connected components (size > 1) of the dependency
/// graph restricted to surviving silos.
fn cycle_groups(
    requires: &[Vec<ServicePath>],
    dropped: &[bool],
    provider_of: &impl Fn(&ServicePath) -> Option<usize>,
) -> Vec<Vec<usize>> {
    let count = requires.len();
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (index, required) in requires.iter().enumerate() {
        if dropped[index] {
            continue;
        }
        for service in required {
            if let Some(provider) = provider_of(service) {
                if provider != index && !dropped[provider] {
                    edges[index].push(provider);
                }
            }
        }
    }

    let mut index_of: Vec<Option<usize>> = vec![None; count];
    let mut low = vec![0usize; count];
    let mut on_stack = vec![false; count];
    let mut stack = Vec::new();
    let mut next = 0usize;
    let mut groups = Vec::new();

    fn strong_connect(
        vertex: usize,
        edges: &[Vec<usize>],
        dropped: &[bool],
        index_of: &mut [Option<usize>],
        low: &mut [usize],
        on_stack: &mut [bool],
        stack: &mut Vec<usize>,
        next: &mut usize,
        groups: &mut Vec<Vec<usize>>,
    ) {
        index_of[vertex] = Some(*next);
        low[vertex] = *next;
        *next += 1;
        stack.push(vertex);
        on_stack[vertex] = true;

        for &neighbour in &edges[vertex] {
            if dropped[neighbour] {
                continue;
            }
            if index_of[neighbour].is_none() {
                strong_connect(
                    neighbour, edges, dropped, index_of, low, on_stack, stack, next, groups,
                );
                low[vertex] = low[vertex].min(low[neighbour]);
            } else if on_stack[neighbour] {
                low[vertex] = low[vertex].min(index_of[neighbour].unwrap_or(0));
            }
        }

        if Some(low[vertex]) == index_of[vertex] {
            let mut group = Vec::new();
            loop {
                let member = stack.pop().expect("strongly connected stack");
                on_stack[member] = false;
                group.push(member);
                if member == vertex {
                    break;
                }
            }
            if group.len() > 1 {
                groups.push(group);
            }
        }
    }

    for vertex in 0..count {
        if dropped[vertex] || index_of[vertex].is_some() {
            continue;
        }
        strong_connect(
            vertex,
            &edges,
            dropped,
            &mut index_of,
            &mut low,
            &mut on_stack,
            &mut stack,
            &mut next,
            &mut groups,
        );
    }

    groups
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
                provides: def.provides.clone(),
                requires: def.requires.clone(),
                sha256: def.sha256,
                grants: def.grants.clone(),
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
                    provides: def.provides.clone(),
                    requires: def.requires.clone(),
                    sha256: def.sha256,
                    grants: def.grants.clone(),
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
                    provides: def.provides.clone(),
                    requires: def.requires.clone(),
                    sha256: def.sha256,
                    grants: def.grants.clone(),
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
