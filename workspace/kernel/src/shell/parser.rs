//! Shell command parser with pipeline and redirection support.
//!
//! Supports:
//! - Simple commands: `ls /tmp`
//! - Pipes: `cat /tmp/foo | grep bar`
//! - Output redirect (truncate): `ls > /tmp/out`
//! - Output redirect (append): `ls >> /tmp/out`
//! - Input redirect: `grep pattern < /tmp/input`
//! - Combinations: `cat /tmp/data | grep key > /tmp/result`

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Parsed command structure.
#[derive(Debug)]
pub struct Command {
    /// Command name (e.g., "mem", "silo", "ps").
    pub name: String,
    /// Arguments (e.g., ["ls"] for "silo ls").
    pub args: Vec<String>,
}

/// Output redirection target.
#[derive(Debug, Clone)]
pub enum Redirect {
    /// Truncate and write (`>`).
    Truncate(String),
    /// Append (`>>`).
    Append(String),
}

/// A single stage in a pipeline.
#[derive(Debug)]
pub struct PipelineStage {
    /// The command to execute.
    pub command: Command,
    /// Optional output redirect (`>` or `>>`).
    pub stdout_redirect: Option<Redirect>,
    /// Optional input redirect (`<`).
    pub stdin_redirect: Option<String>,
}

/// A parsed pipeline (one or more stages connected by `|`).
#[derive(Debug)]
pub struct Pipeline {
    /// Ordered stages; output of stage N feeds into stage N+1.
    pub stages: Vec<PipelineStage>,
}

/// Parse a full command line into a [`Pipeline`].
///
/// Returns `None` if the line is empty or whitespace-only.
pub fn parse_pipeline(line: &str) -> Option<Pipeline> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let segments: Vec<&str> = trimmed.split('|').collect();
    let mut stages = Vec::new();

    for seg in &segments {
        let stage = parse_stage(seg.trim())?;
        stages.push(stage);
    }

    if stages.is_empty() {
        return None;
    }

    Some(Pipeline { stages })
}

/// Parse a single pipeline stage (command + optional redirections).
fn parse_stage(segment: &str) -> Option<PipelineStage> {
    let tokens = tokenize(segment);
    if tokens.is_empty() {
        return None;
    }

    let mut cmd_tokens: Vec<String> = Vec::new();
    let mut stdout_redirect: Option<Redirect> = None;
    let mut stdin_redirect: Option<String> = None;

    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == ">>" {
            i += 1;
            if i < tokens.len() {
                stdout_redirect = Some(Redirect::Append(tokens[i].clone()));
            }
        } else if tokens[i] == ">" {
            i += 1;
            if i < tokens.len() {
                stdout_redirect = Some(Redirect::Truncate(tokens[i].clone()));
            }
        } else if tokens[i] == "<" {
            i += 1;
            if i < tokens.len() {
                stdin_redirect = Some(tokens[i].clone());
            }
        } else {
            cmd_tokens.push(tokens[i].clone());
        }
        i += 1;
    }

    if cmd_tokens.is_empty() {
        return None;
    }

    let name = cmd_tokens.remove(0);
    Some(PipelineStage {
        command: Command {
            name,
            args: cmd_tokens,
        },
        stdout_redirect,
        stdin_redirect,
    })
}

/// Tokenize a segment, keeping `>>`, `>`, `<` as distinct tokens.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '>' => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    tokens.push(String::from(">>"));
                    i += 2;
                } else {
                    tokens.push(String::from(">"));
                    i += 1;
                }
            }
            '<' => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
                tokens.push(String::from("<"));
                i += 1;
            }
            ' ' | '\t' => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
                i += 1;
            }
            ch => {
                current.push(ch);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Parse a simple command line (no pipe/redirect support).
///
/// Returns `None` if the line is empty or whitespace-only.
pub fn parse(line: &str) -> Option<Command> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let name = parts.next()?.to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();

    Some(Command { name, args })
}
