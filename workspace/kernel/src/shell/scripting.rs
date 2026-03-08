//! Minimal shell scripting: variable expansion, `if`, `for`, `while`.
//!
//! # Supported constructs
//!
//! - **Variables**: `set VAR=VALUE`, `$VAR` expansion, `$?` for last exit code.
//! - **For loops**: `for VAR in A B C ; do COMMAND ; done`
//! - **While loops**: `while COMMAND ; do BODY ; done`
//! - **If/then**: `if COMMAND ; then BODY ; fi` or `if COMMAND ; then A ; else B ; fi`

use crate::sync::SpinLock;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

static SHELL_VARS: SpinLock<BTreeMap<String, String>> = SpinLock::new(BTreeMap::new());
static LAST_EXIT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

/// Set the exit code of the last executed command.
pub fn set_last_exit(code: i32) {
    LAST_EXIT.store(code, core::sync::atomic::Ordering::Relaxed);
}

/// Get the exit code of the last executed command.
pub fn last_exit() -> i32 {
    LAST_EXIT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Set a shell variable.
pub fn set_var(key: &str, val: &str) {
    SHELL_VARS
        .lock()
        .insert(String::from(key), String::from(val));
}

/// Get a shell variable.
pub fn get_var(key: &str) -> Option<String> {
    SHELL_VARS.lock().get(key).cloned()
}

/// Remove a shell variable.
pub fn unset_var(key: &str) {
    SHELL_VARS.lock().remove(key);
}

/// Expand `$VAR` and `$?` references in a string.
pub fn expand_vars(input: &str) -> String {
    let mut result = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'?' {
                result.push_str(&alloc::format!("{}", last_exit()));
                i += 1;
            } else {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if i == start {
                    // Keep literal '$' when no variable name follows.
                    result.push('$');
                    continue;
                }
                let var_name = core::str::from_utf8(&bytes[start..i]).unwrap_or("");
                if let Some(val) = get_var(var_name) {
                    result.push_str(&val);
                } else if let Some(env_val) = super::commands::util::shell_getenv(var_name) {
                    result.push_str(&env_val);
                }
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Script construct types recognized by the parser.
pub enum ScriptConstruct {
    /// Simple command line (possibly with pipes).
    Simple(String),
    /// `set VAR=VALUE`
    SetVar { key: String, val: String },
    /// `unset VAR`
    UnsetVar(String),
    /// `for VAR in ITEMS ; do BODY ; done`
    ForLoop {
        var: String,
        items: Vec<String>,
        body: Vec<String>,
    },
    /// `while COND ; do BODY ; done`
    WhileLoop { cond: String, body: Vec<String> },
    /// `if COND ; then THEN_BODY [; else ELSE_BODY] ; fi`
    IfElse {
        cond: String,
        then_body: Vec<String>,
        else_body: Vec<String>,
    },
}

/// Parse a full line into a script construct.
///
/// The parser splits on `;` to find keywords. For simple commands
/// (no scripting keywords), returns [`ScriptConstruct::Simple`].
pub fn parse_script(line: &str) -> ScriptConstruct {
    let trimmed = line.trim();

    if trimmed.starts_with("set ") {
        let rest = &trimmed[4..];
        if let Some(eq) = rest.find('=') {
            return ScriptConstruct::SetVar {
                key: String::from(rest[..eq].trim()),
                val: String::from(rest[eq + 1..].trim()),
            };
        }
        return ScriptConstruct::Simple(String::from(trimmed));
    }

    if trimmed.starts_with("unset ") {
        return ScriptConstruct::UnsetVar(String::from(trimmed[6..].trim()));
    }

    let parts: Vec<&str> = trimmed.split(';').map(|s| s.trim()).collect();

    if parts.first().map(|p| p.starts_with("for ")) == Some(true) {
        return parse_for_loop(&parts);
    }
    if parts.first().map(|p| p.starts_with("while ")) == Some(true) {
        return parse_while_loop(&parts);
    }
    if parts.first().map(|p| p.starts_with("if ")) == Some(true) {
        return parse_if_else(&parts);
    }

    ScriptConstruct::Simple(String::from(trimmed))
}

/// `for VAR in A B C ; do cmd1 ; cmd2 ; done`
fn parse_for_loop(parts: &[&str]) -> ScriptConstruct {
    if parts.is_empty() {
        return ScriptConstruct::Simple(String::new());
    }
    let header = parts[0];
    let tokens: Vec<&str> = header.split_whitespace().collect();
    if tokens.len() < 4 || tokens[0] != "for" || tokens[2] != "in" {
        return ScriptConstruct::Simple(String::from(header));
    }

    let var = tokens.get(1).unwrap_or(&"_").to_string();
    let items: Vec<String> = tokens
        .iter()
        .skip(3) // skip "for VAR in"
        .map(|s| String::from(*s))
        .collect();

    let Some(do_idx) = parts.iter().position(|p| *p == "do") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    let Some(done_idx) = parts.iter().position(|p| *p == "done") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    if done_idx <= do_idx {
        return ScriptConstruct::Simple(String::from(header));
    }

    let body: Vec<String> = parts[do_idx + 1..done_idx]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| String::from(*s))
        .collect();

    ScriptConstruct::ForLoop {
        var: String::from(var),
        items,
        body,
    }
}

/// `while cond ; do body ; done`
fn parse_while_loop(parts: &[&str]) -> ScriptConstruct {
    if parts.is_empty() {
        return ScriptConstruct::Simple(String::new());
    }
    let header = parts[0];
    let Some(cond) = header.strip_prefix("while ") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    let Some(do_idx) = parts.iter().position(|p| *p == "do") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    let Some(done_idx) = parts.iter().position(|p| *p == "done") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    if done_idx <= do_idx {
        return ScriptConstruct::Simple(String::from(header));
    }

    let body: Vec<String> = parts[do_idx + 1..done_idx]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| String::from(*s))
        .collect();

    ScriptConstruct::WhileLoop {
        cond: String::from(cond),
        body,
    }
}

/// `if cond ; then body ; [else body ;] fi`
fn parse_if_else(parts: &[&str]) -> ScriptConstruct {
    if parts.is_empty() {
        return ScriptConstruct::Simple(String::new());
    }
    let header = parts[0];
    let Some(cond) = header.strip_prefix("if ") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    let Some(then_idx) = parts.iter().position(|p| *p == "then") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    let else_idx = parts.iter().position(|p| *p == "else");
    let Some(fi_idx) = parts.iter().position(|p| *p == "fi") else {
        return ScriptConstruct::Simple(String::from(header));
    };
    if fi_idx <= then_idx {
        return ScriptConstruct::Simple(String::from(header));
    }

    let then_end = else_idx.unwrap_or(fi_idx);
    let then_body: Vec<String> = parts[then_idx + 1..then_end]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| String::from(*s))
        .collect();

    let else_body: Vec<String> = if let Some(ei) = else_idx {
        parts[ei + 1..fi_idx]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| String::from(*s))
            .collect()
    } else {
        Vec::new()
    };

    ScriptConstruct::IfElse {
        cond: String::from(cond),
        then_body,
        else_body,
    }
}
