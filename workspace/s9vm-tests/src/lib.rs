//! Harnais de tests hôte du moteur de virtualisation `s9vm`.
//!
//! Les tests vivent dans `tests/` et includent les modules purs du noyau via
//! `#[path = "../../kernel/src/s9vm/<module>.rs"]`. Aucun code de ce crate
//! n'est compilé dans le noyau.

#![allow(dead_code)]
