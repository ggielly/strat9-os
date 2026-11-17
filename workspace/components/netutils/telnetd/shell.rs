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

//! Command interpreter for the telnet console: every VFS operation exposed
//! to userspace (ls, cat, cd, mkdir, rm, mv, cp, stat, tree, ...), plus
//! quoting, `>` / `>>` redirection and a few network helpers.

use crate::{
    out::{ColorMode, Out, Style},
    sys::{self, DT_DIR, DT_LNK, EAGAIN, S_IFDIR, S_IFLNK, S_IFMT},
    telnet::Session,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Write as _;
use strat9_syscall::{call, error::Error, flag::OpenFlags};

type CmdFn = fn(&mut Session, &mut Out, &[String]);

struct Cmd {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    run: CmdFn,
}

const fn cmd(name: &'static str, usage: &'static str, help: &'static str, run: CmdFn) -> Cmd {
    Cmd { name, usage, help, run }
}

/// Command table (also drives `help` and Tab completion).
static COMMANDS: &[Cmd] = &[
    cmd("help", "[cmd]", "show this help", cmd_help),
    cmd("pwd", "", "print working directory", cmd_pwd),
    cmd("cd", "[dir]", "change directory", cmd_cd),
    cmd("ls", "[-l] [-a] [-1] [path...]", "list directory contents", cmd_ls),
    cmd("cat", "<file...>", "print files", cmd_cat),
    cmd("head", "[-n N] <file>", "first lines of a file", cmd_head),
    cmd("tail", "[-n N] <file>", "last lines of a file", cmd_tail),
    cmd("wc", "<file...>", "count lines, words and bytes", cmd_wc),
    cmd("grep", "[-i] [-n] [-v] <pat> <file...>", "search for text", cmd_grep),
    cmd("hexdump", "<file> [offset] [len]", "hex + ASCII dump", cmd_hexdump),
    cmd("stat", "<path...>", "file metadata", cmd_stat),
    cmd("tree", "[-a] [-L depth] [path]", "directory tree", cmd_tree),
    cmd("mkdir", "[-p] <dir...>", "create directories", cmd_mkdir),
    cmd("touch", "<file...>", "create empty files", cmd_touch),
    cmd("rm", "[-r] [-f] <path...>", "remove files / directories", cmd_rm),
    cmd("rmdir", "<dir...>", "remove empty directories", cmd_rmdir),
    cmd("mv", "<src> <dst>", "move / rename", cmd_mv),
    cmd("cp", "[-r] <src> <dst>", "copy files / directories", cmd_cp),
    cmd("write", "<file> <text...>", "overwrite a file with text", cmd_write),
    cmd("append", "<file> <text...>", "append text to a file", cmd_append),
    cmd("echo", "[-n] [text...]", "print text (supports > and >>)", cmd_echo),
    cmd("df", "", "mount points and their status", cmd_df),
    cmd("mount", "", "list mount points", cmd_df),
    cmd("ip", "", "show IPv4 address", cmd_ip),
    cmd("net", "", "show network configuration", cmd_net),
    cmd("history", "", "command history", cmd_history),
    cmd("term", "", "terminal information", cmd_term),
    cmd("color", "[auto|16|256|off]", "choose the color mode", cmd_color),
    cmd("clear", "", "clear the screen", cmd_clear),
    cmd("exit", "", "close the session (also: quit, logout)", cmd_noop),
];

fn cmd_noop(_: &mut Session, _: &mut Out, _: &[String]) {}

// ── Parsing ─────────────────────────────────────────────────────────────────

enum Tok {
    Word(String),
    Redir { append: bool },
}

fn tokenize(line: &str) -> Result<Vec<Tok>, &'static str> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut quote: Option<char> = None;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    match it.next() {
                        Some(n) if n == '"' || n == '\\' => cur.push(n),
                        Some(n) => {
                            cur.push('\\');
                            cur.push(n);
                        }
                        None => cur.push('\\'),
                    }
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    have = true;
                }
                '\\' => {
                    if let Some(n) = it.next() {
                        cur.push(n);
                        have = true;
                    }
                }
                ' ' | '\t' => {
                    if have {
                        toks.push(Tok::Word(core::mem::take(&mut cur)));
                        have = false;
                    }
                }
                '>' => {
                    if have {
                        toks.push(Tok::Word(core::mem::take(&mut cur)));
                        have = false;
                    }
                    let append = it.peek() == Some(&'>');
                    if append {
                        it.next();
                    }
                    toks.push(Tok::Redir { append });
                }
                _ => {
                    cur.push(c);
                    have = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err("unterminated quote");
    }
    if have {
        toks.push(Tok::Word(cur));
    }
    Ok(toks)
}

/// Split `-abc` style flags from operands. `--` ends flag parsing.
fn parse_flags(args: &[String]) -> (String, Vec<&str>) {
    let mut flags = String::new();
    let mut ops = Vec::new();
    let mut done = false;
    for a in args {
        if !done && a == "--" {
            done = true;
        } else if !done && a.len() > 1 && a.starts_with('-') {
            flags.push_str(&a[1..]);
        } else {
            ops.push(a.as_str());
        }
    }
    (flags, ops)
}

/// Run one command line. Returns `false` when the session should end.
pub fn run_line(sess: &mut Session, out: &mut Out, line: &str) -> bool {
    let toks = match tokenize(line) {
        Ok(t) => t,
        Err(e) => {
            out.error("shell", format_args!("{}", e));
            return true;
        }
    };
    let mut args: Vec<String> = Vec::new();
    let mut redirect: Option<(String, bool)> = None;
    let mut it = toks.into_iter();
    while let Some(t) = it.next() {
        match t {
            Tok::Word(w) => args.push(w),
            Tok::Redir { append } => match it.next() {
                Some(Tok::Word(p)) => redirect = Some((p, append)),
                _ => {
                    out.error("shell", format_args!("syntax error: missing file after '>'"));
                    return true;
                }
            },
        }
    }
    if args.is_empty() {
        return true;
    }

    let name = args[0].as_str();
    if matches!(name, "exit" | "quit" | "logout") {
        return false;
    }
    let Some(command) = COMMANDS.iter().find(|c| c.name == name) else {
        out.error(name, format_args!("command not found (try 'help')"));
        return true;
    };

    let mut redirect_fd = None;
    if let Some((path, append)) = redirect {
        let abs = sys::resolve(&sess.cwd, &path);
        let mode = if append { OpenFlags::APPEND } else { OpenFlags::TRUNCATE };
        match sys::open(&abs, OpenFlags::WRITE | OpenFlags::CREATE | mode) {
            Ok(fd) => {
                out.set_redirect(Some(fd));
                redirect_fd = Some(fd);
            }
            Err(e) => {
                out.error("shell", format_args!("{}: {}", abs, sys::err_text(e)));
                return true;
            }
        }
    }

    (command.run)(sess, out, &args[1..]);

    out.set_redirect(None);
    if let Some(fd) = redirect_fd {
        let _ = call::close(fd);
    }
    if out.interrupted {
        out.styled(Style::Dim, "^C\n");
    }
    true
}

// ── Tab completion ──────────────────────────────────────────────────────────

pub struct Cand {
    /// Full replacement text for the token being completed.
    pub name: String,
    /// Short label shown when listing alternatives.
    pub label: String,
    pub is_dir: bool,
}

/// Returns `(token_start, candidates)` for the text before the cursor.
pub fn complete(cwd: &str, line: &[u8]) -> (usize, Vec<Cand>) {
    let start = line.iter().rposition(|&b| b == b' ').map(|i| i + 1).unwrap_or(0);
    let Ok(token) = core::str::from_utf8(&line[start..]) else {
        return (start, Vec::new());
    };
    let mut cands = Vec::new();

    let first_word = !line[..start].iter().any(|&b| b != b' ');
    if first_word && !token.contains('/') {
        for c in COMMANDS.iter().filter(|c| c.name.starts_with(token)) {
            cands.push(Cand {
                name: String::from(c.name),
                label: String::from(c.name),
                is_dir: false,
            });
        }
        for extra in ["quit", "logout"] {
            if extra.starts_with(token) && !token.is_empty() {
                cands.push(Cand {
                    name: String::from(extra),
                    label: String::from(extra),
                    is_dir: false,
                });
            }
        }
        return (start, cands);
    }

    let (dir_part, base) = match token.rfind('/') {
        Some(i) => (&token[..=i], &token[i + 1..]),
        None => ("", token),
    };
    let dir_abs = if dir_part.is_empty() {
        String::from(cwd)
    } else {
        sys::resolve(cwd, dir_part)
    };
    if let Ok(entries) = sys::read_dir(&dir_abs) {
        for e in entries {
            if !e.name.starts_with(base) || (e.name.starts_with('.') && !base.starts_with('.')) {
                continue;
            }
            let is_dir = e.file_type == DT_DIR;
            let mut full = String::from(dir_part);
            full.push_str(&e.name);
            if is_dir {
                full.push('/');
            }
            let mut label = e.name.clone();
            if is_dir {
                label.push('/');
            }
            cands.push(Cand { name: full, label, is_dir });
        }
    }
    (start, cands)
}

// ── Output helpers ──────────────────────────────────────────────────────────

fn style_for_type(t: u8) -> Style {
    match t {
        DT_DIR => Style::Dir,
        DT_LNK => Style::Link,
        2 | 6 => Style::Device,
        _ => Style::File,
    }
}

fn style_for_mode(mode: u32) -> Style {
    match mode & S_IFMT {
        S_IFDIR => Style::Dir,
        S_IFLNK => Style::Link,
        0o020000 | 0o060000 => Style::Device,
        _ => Style::File,
    }
}

fn path_err(out: &mut Out, cmd: &str, path: &str, e: Error) {
    out.error(cmd, format_args!("{}: {}", path, sys::err_text(e)));
}

fn usage(out: &mut Out, name: &str) {
    if let Some(c) = COMMANDS.iter().find(|c| c.name == name) {
        out.style(Style::Warn);
        let _ = write!(out, "usage: {} {}", c.name, c.usage);
        out.style(Style::Reset);
        out.text("\n");
    }
}

// ── Commands: navigation and listing ────────────────────────────────────────

fn cmd_help(_: &mut Session, out: &mut Out, args: &[String]) {
    if let Some(name) = args.first() {
        match COMMANDS.iter().find(|c| c.name == name.as_str()) {
            Some(c) => {
                out.styled(Style::Head, c.name);
                let _ = write!(out, " {}\n  {}\n", c.usage, c.help);
            }
            None => out.error("help", format_args!("no such command: {}", name)),
        }
        return;
    }
    out.styled(Style::Head, "Strat9 telnet shell");
    out.text(" - commands:\n");
    for c in COMMANDS {
        out.text("  ");
        out.style(Style::Ok);
        let _ = write!(out, "{:<8}", c.name);
        out.style(Style::Reset);
        out.style(Style::Dim);
        let _ = write!(out, " {:<34}", c.usage);
        out.style(Style::Reset);
        let _ = write!(out, " {}\n", c.help);
    }
    out.styled(
        Style::Dim,
        "\nQuotes ('..' \"..\") and \\ escapes work; use > file or >> file to redirect output.\n\
         Keys: Tab complete, Up/Down history, Ctrl-A/E/K/U/W edit, Ctrl-C cancel, Ctrl-D logout.\n",
    );
}

fn cmd_pwd(sess: &mut Session, out: &mut Out, _: &[String]) {
    let cwd = sess.cwd.clone();
    out.text(&cwd);
    out.text("\n");
}

fn cmd_cd(sess: &mut Session, out: &mut Out, args: &[String]) {
    let target = match args.first().map(|s| s.as_str()) {
        None | Some("~") => String::from("/"),
        Some(t) => sys::resolve(&sess.cwd, t),
    };
    match sys::open(&target, OpenFlags::READ | OpenFlags::DIRECTORY) {
        Ok(fd) => {
            let _ = call::close(fd);
            sess.cwd = target;
        }
        Err(e) => path_err(out, "cd", &target, e),
    }
}

struct Item {
    name: String,
    style: Style,
    suffix: &'static str,
}

fn print_columns(out: &mut Out, items: &[Item], width: usize) {
    if items.is_empty() {
        return;
    }
    let colw = items
        .iter()
        .map(|i| i.name.chars().count() + i.suffix.len())
        .max()
        .unwrap_or(1)
        + 2;
    let cols = (width / colw).max(1);
    let rows = (items.len() + cols - 1) / cols;
    for r in 0..rows {
        for c in 0..cols {
            let idx = c * rows + r;
            if idx >= items.len() {
                break;
            }
            let it = &items[idx];
            out.style(it.style);
            out.text(&it.name);
            out.text(it.suffix);
            out.style(Style::Reset);
            if idx + rows < items.len() {
                let used = it.name.chars().count() + it.suffix.len();
                for _ in used..colw {
                    out.text(" ");
                }
            }
        }
        out.text("\n");
    }
}

fn print_long(out: &mut Out, name: &str, full: &str, fallback_type: u8) {
    match sys::stat(full) {
        Ok(st) => {
            let _ = write!(
                out,
                "{} {:>3} {:>4} {:>4} {:>9} {} ",
                sys::format_mode(st.st_mode),
                st.st_nlink,
                st.st_uid,
                st.st_gid,
                st.st_size,
                sys::format_time(st.st_mtime.tv_sec)
            );
            out.style(style_for_mode(st.st_mode));
            out.text(name);
            if st.st_mode & S_IFMT == S_IFDIR {
                out.text("/");
            }
            out.style(Style::Reset);
            out.text("\n");
        }
        Err(_) => {
            let t = if fallback_type == DT_DIR { 'd' } else { '-' };
            let _ = write!(out, "{}?????????  ?    ?    ?         ? ", t);
            out.style(style_for_type(fallback_type));
            out.text(name);
            out.style(Style::Reset);
            out.text("\n");
        }
    }
}

fn cmd_ls(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (flags, ops) = parse_flags(args);
    let long = flags.contains('l');
    let all = flags.contains('a');
    let single = flags.contains('1') || out.redirected();
    let width = sess.term.cols as usize;
    let targets: Vec<&str> = if ops.is_empty() { alloc::vec!["."] } else { ops };
    let multi = targets.len() > 1;

    for (n, t) in targets.iter().enumerate() {
        if out.stop() {
            return;
        }
        let path = sys::resolve(&sess.cwd, t);
        if multi {
            if n > 0 {
                out.text("\n");
            }
            out.styled(Style::Head, &path);
            out.text(":\n");
        }
        match sys::read_dir(&path) {
            Ok(entries) => {
                let shown: Vec<&sys::DirEntry> = entries
                    .iter()
                    .filter(|e| all || !e.name.starts_with('.'))
                    .collect();
                if shown.is_empty() {
                    out.styled(Style::Dim, "(empty)\n");
                } else if long {
                    for e in shown {
                        if out.stop() {
                            return;
                        }
                        print_long(out, &e.name, &sys::join(&path, &e.name), e.file_type);
                    }
                } else if single {
                    for e in shown {
                        out.styled(style_for_type(e.file_type), &e.name);
                        out.text("\n");
                    }
                } else {
                    let items: Vec<Item> = shown
                        .iter()
                        .map(|e| Item {
                            name: e.name.clone(),
                            style: style_for_type(e.file_type),
                            suffix: if e.file_type == DT_DIR { "/" } else { "" },
                        })
                        .collect();
                    print_columns(out, &items, width);
                }
            }
            Err(dir_err) => match sys::stat(&path) {
                Ok(st) if st.st_mode & S_IFMT != S_IFDIR => {
                    if long {
                        print_long(out, t, &path, 0);
                    } else {
                        out.styled(style_for_mode(st.st_mode), t);
                        out.text("\n");
                    }
                }
                _ => match sys::read_file(&path, 64 * 1024) {
                    // Virtual scheme roots (e.g. /net) answer with plain text.
                    Ok(d) if !d.is_empty() => {
                        out.data(&d);
                        if d.last() != Some(&b'\n') {
                            out.text("\n");
                        }
                    }
                    _ => path_err(out, "ls", &path, dir_err),
                },
            },
        }
    }
}

// ── Commands: reading files ─────────────────────────────────────────────────

fn cmd_cat(sess: &mut Session, out: &mut Out, args: &[String]) {
    if args.is_empty() {
        return usage(out, "cat");
    }
    for a in args {
        let path = sys::resolve(&sess.cwd, a);
        let fd = match sys::open(&path, OpenFlags::READ) {
            Ok(fd) => fd,
            Err(e) => {
                path_err(out, "cat", &path, e);
                continue;
            }
        };
        let mut buf = [0u8; 1024];
        let mut last = b'\n';
        let mut waits = 0u32;
        loop {
            if out.stop() {
                break;
            }
            match call::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    waits = 0;
                    out.data(&buf[..n]);
                    last = buf[n - 1];
                }
                Err(e) if e.to_errno() == EAGAIN && waits < 100 => {
                    waits += 1;
                    sys::sleep_ms(10);
                }
                Err(e) => {
                    path_err(out, "cat", &path, e);
                    break;
                }
            }
        }
        let _ = call::close(fd);
        if last != b'\n' && !out.redirected() {
            out.text("\n");
        }
    }
}

const READ_CAP: usize = 2 * 1024 * 1024;

/// Parse `-n N` (or `-N`) for head/tail. Returns `(count, file)`.
fn lines_args<'a>(args: &'a [String]) -> Option<(usize, &'a str)> {
    let mut n = 10usize;
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-n" {
            i += 1;
            n = args.get(i)?.parse().ok()?;
        } else if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| c.is_ascii_digit()) {
            n = a[1..].parse().ok()?;
        } else {
            file = Some(a);
        }
        i += 1;
    }
    file.map(|f| (n, f))
}

fn cmd_head(sess: &mut Session, out: &mut Out, args: &[String]) {
    let Some((n, file)) = lines_args(args) else {
        return usage(out, "head");
    };
    let path = sys::resolve(&sess.cwd, file);
    match sys::read_file(&path, READ_CAP) {
        Ok(d) => {
            let mut count = 0;
            let mut last = b'\n';
            for line in d.split_inclusive(|&b| b == b'\n') {
                if count >= n || out.stop() {
                    break;
                }
                out.data(line);
                last = line[line.len() - 1];
                count += 1;
            }
            if last != b'\n' && !out.redirected() {
                out.text("\n");
            }
        }
        Err(e) => path_err(out, "head", &path, e),
    }
}

fn cmd_tail(sess: &mut Session, out: &mut Out, args: &[String]) {
    let Some((n, file)) = lines_args(args) else {
        return usage(out, "tail");
    };
    let path = sys::resolve(&sess.cwd, file);
    match sys::read_file(&path, READ_CAP) {
        Ok(d) => {
            let lines: Vec<&[u8]> = d.split_inclusive(|&b| b == b'\n').collect();
            let skip = lines.len().saturating_sub(n);
            for line in &lines[skip..] {
                out.data(line);
            }
            if d.last().map_or(false, |&b| b != b'\n') && !out.redirected() && !d.is_empty() {
                out.text("\n");
            }
        }
        Err(e) => path_err(out, "tail", &path, e),
    }
}

fn cmd_wc(sess: &mut Session, out: &mut Out, args: &[String]) {
    if args.is_empty() {
        return usage(out, "wc");
    }
    let mut totals = (0usize, 0usize, 0usize);
    for a in args {
        let path = sys::resolve(&sess.cwd, a);
        match sys::read_file(&path, 64 * 1024 * 1024) {
            Ok(d) => {
                let lines = d.iter().filter(|&&b| b == b'\n').count();
                let words = d
                    .split(|b| b.is_ascii_whitespace())
                    .filter(|w| !w.is_empty())
                    .count();
                totals = (totals.0 + lines, totals.1 + words, totals.2 + d.len());
                let _ = write!(out, "{:>8} {:>8} {:>8} {}\n", lines, words, d.len(), a);
            }
            Err(e) => path_err(out, "wc", &path, e),
        }
    }
    if args.len() > 1 {
        let _ = write!(out, "{:>8} {:>8} {:>8} total\n", totals.0, totals.1, totals.2);
    }
}

fn cmd_grep(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (flags, ops) = parse_flags(args);
    if ops.len() < 2 {
        return usage(out, "grep");
    }
    let icase = flags.contains('i');
    let numbers = flags.contains('n');
    let invert = flags.contains('v');
    let pattern = if icase { ops[0].to_ascii_lowercase() } else { String::from(ops[0]) };
    let files = &ops[1..];
    let multi = files.len() > 1;

    for f in files {
        let path = sys::resolve(&sess.cwd, f);
        let data = match sys::read_file(&path, READ_CAP) {
            Ok(d) => d,
            Err(e) => {
                path_err(out, "grep", &path, e);
                continue;
            }
        };
        let text = String::from_utf8_lossy(&data);
        for (i, line) in text.lines().enumerate() {
            if out.stop() {
                return;
            }
            let hay = if icase { line.to_ascii_lowercase() } else { String::from(line) };
            let found = hay.contains(pattern.as_str());
            if found == invert {
                continue;
            }
            if multi {
                out.styled(Style::Accent, f);
                out.text(":");
            }
            if numbers {
                out.styled(Style::Ok, &alloc::format!("{}", i + 1));
                out.text(":");
            }
            if invert || pattern.is_empty() {
                out.text(line);
            } else {
                // Highlight every match (to_ascii_lowercase keeps byte offsets).
                let mut from = 0;
                while let Some(p) = hay[from..].find(pattern.as_str()) {
                    let s = from + p;
                    let e = s + pattern.len();
                    out.text(&line[from..s]);
                    out.styled(Style::Error, &line[s..e]);
                    from = e;
                }
                out.text(&line[from..]);
            }
            out.text("\n");
        }
    }
}

fn cmd_hexdump(sess: &mut Session, out: &mut Out, args: &[String]) {
    let Some(file) = args.first() else {
        return usage(out, "hexdump");
    };
    let offset: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let len: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(256).min(64 * 1024);
    let path = sys::resolve(&sess.cwd, file);
    let data = match sys::read_file(&path, offset.saturating_add(len)) {
        Ok(d) => d,
        Err(e) => return path_err(out, "hexdump", &path, e),
    };
    let slice = data.get(offset..).unwrap_or(&[]);
    for (row, chunk) in slice.chunks(16).enumerate() {
        if out.stop() {
            return;
        }
        out.style(Style::Dim);
        let _ = write!(out, "{:08x}  ", offset + row * 16);
        out.style(Style::Reset);
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(out, "{:02x} ", b);
                }
                None => out.text("   "),
            }
            if i == 7 {
                out.text(" ");
            }
        }
        out.style(Style::Ok);
        out.text(" |");
        for &b in chunk {
            let c = if (0x20..0x7f).contains(&b) { b as char } else { '.' };
            let _ = out.write_char(c);
        }
        out.text("|");
        out.style(Style::Reset);
        out.text("\n");
    }
}

fn cmd_stat(sess: &mut Session, out: &mut Out, args: &[String]) {
    if args.is_empty() {
        return usage(out, "stat");
    }
    for a in args {
        let path = sys::resolve(&sess.cwd, a);
        match sys::stat(&path) {
            Ok(st) => {
                let kind = match st.st_mode & S_IFMT {
                    0o040000 => "directory",
                    0o100000 => "regular file",
                    0o120000 => "symbolic link",
                    0o010000 => "FIFO",
                    0o060000 => "block device",
                    0o020000 => "character device",
                    0o140000 => "socket",
                    _ => "unknown",
                };
                let rows: [(&str, String); 9] = [
                    ("File", path.clone()),
                    ("Type", String::from(kind)),
                    ("Size", alloc::format!("{} bytes ({} blocks)", st.st_size, st.st_blocks)),
                    (
                        "Mode",
                        alloc::format!("{:04o} ({})", st.st_mode & 0o7777, sys::format_mode(st.st_mode)),
                    ),
                    ("Links", alloc::format!("{}", st.st_nlink)),
                    ("Inode", alloc::format!("{}", st.st_ino)),
                    ("Owner", alloc::format!("uid={} gid={}", st.st_uid, st.st_gid)),
                    ("Modify", sys::format_time(st.st_mtime.tv_sec)),
                    ("Access", sys::format_time(st.st_atime.tv_sec)),
                ];
                for (k, v) in rows {
                    out.styled(Style::Head, &alloc::format!("  {:<7}", k));
                    out.text(&v);
                    out.text("\n");
                }
            }
            Err(e) => path_err(out, "stat", &path, e),
        }
    }
}

// ── tree ────────────────────────────────────────────────────────────────────

struct TreeCtx {
    all: bool,
    max_depth: usize,
    unicode: bool,
    dirs: usize,
    files: usize,
}

fn tree_walk(out: &mut Out, ctx: &mut TreeCtx, path: &str, prefix: &str, depth: usize) {
    if depth >= ctx.max_depth {
        return;
    }
    let Ok(entries) = sys::read_dir(path) else {
        return;
    };
    let entries: Vec<&sys::DirEntry> = entries
        .iter()
        .filter(|e| ctx.all || !e.name.starts_with('.'))
        .collect();
    let n = entries.len();
    for (i, e) in entries.iter().enumerate() {
        if out.stop() {
            return;
        }
        let last = i + 1 == n;
        let (branch, cont) = match (ctx.unicode, last) {
            (true, false) => ("\u{251c}\u{2500}\u{2500} ", "\u{2502}   "),
            (true, true) => ("\u{2514}\u{2500}\u{2500} ", "    "),
            (false, false) => ("|-- ", "|   "),
            (false, true) => ("`-- ", "    "),
        };
        out.styled(Style::Dim, &alloc::format!("{}{}", prefix, branch));
        out.styled(style_for_type(e.file_type), &e.name);
        if e.file_type == DT_DIR {
            out.text("/");
            ctx.dirs += 1;
        } else {
            ctx.files += 1;
        }
        out.text("\n");
        if e.file_type == DT_DIR {
            let child = sys::join(path, &e.name);
            let next_prefix = alloc::format!("{}{}", prefix, cont);
            tree_walk(out, ctx, &child, &next_prefix, depth + 1);
        }
    }
}

fn cmd_tree(sess: &mut Session, out: &mut Out, args: &[String]) {
    let mut ctx = TreeCtx {
        all: false,
        max_depth: 8,
        unicode: out.color != ColorMode::None && !out.redirected(),
        dirs: 0,
        files: 0,
    };
    let mut target = ".";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => ctx.all = true,
            "-L" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(d) => ctx.max_depth = d,
                    None => return usage(out, "tree"),
                }
            }
            a => target = a,
        }
        i += 1;
    }
    let path = sys::resolve(&sess.cwd, target);
    if !sys::is_dir(&path) {
        out.error("tree", format_args!("{}: not a directory", path));
        return;
    }
    out.styled(Style::Path, &path);
    out.text("\n");
    tree_walk(out, &mut ctx, &path, "", 0);
    out.style(Style::Dim);
    let _ = write!(out, "\n{} directories, {} files\n", ctx.dirs, ctx.files);
    out.style(Style::Reset);
}

// ── Commands: modifying the filesystem ──────────────────────────────────────

fn cmd_mkdir(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (flags, ops) = parse_flags(args);
    if ops.is_empty() {
        return usage(out, "mkdir");
    }
    let parents = flags.contains('p');
    for o in ops {
        let path = sys::resolve(&sess.cwd, o);
        if parents {
            let mut cur = String::new();
            for comp in path.split('/').filter(|c| !c.is_empty()) {
                cur.push('/');
                cur.push_str(comp);
                if sys::is_dir(&cur) {
                    continue;
                }
                if let Err(e) = sys::mkdir(&cur, 0o755) {
                    path_err(out, "mkdir", &cur, e);
                    break;
                }
            }
        } else if let Err(e) = sys::mkdir(&path, 0o755) {
            path_err(out, "mkdir", &path, e);
        }
    }
}

fn cmd_touch(sess: &mut Session, out: &mut Out, args: &[String]) {
    if args.is_empty() {
        return usage(out, "touch");
    }
    for a in args {
        let path = sys::resolve(&sess.cwd, a);
        if sys::stat(&path).is_ok() {
            continue;
        }
        match sys::open(&path, OpenFlags::WRITE | OpenFlags::CREATE) {
            Ok(fd) => {
                let _ = call::close(fd);
            }
            Err(e) => path_err(out, "touch", &path, e),
        }
    }
}

fn remove_tree(out: &mut Out, path: &str) -> Result<(), Error> {
    if sys::is_dir(path) {
        for e in sys::read_dir(path)? {
            if out.stop() {
                return Err(Error::Interrupted);
            }
            remove_tree(out, &sys::join(path, &e.name))?;
        }
        sys::rmdir(path).or_else(|_| sys::unlink(path))
    } else {
        sys::unlink(path)
    }
}

fn cmd_rm(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (flags, ops) = parse_flags(args);
    if ops.is_empty() {
        return usage(out, "rm");
    }
    let recursive = flags.contains('r') || flags.contains('R');
    let force = flags.contains('f');
    for o in ops {
        let path = sys::resolve(&sess.cwd, o);
        if path == "/" {
            out.error("rm", format_args!("refusing to remove '/'"));
            continue;
        }
        let res = if sys::is_dir(&path) {
            if recursive {
                remove_tree(out, &path)
            } else {
                out.error("rm", format_args!("{}: is a directory (use -r)", path));
                continue;
            }
        } else {
            sys::unlink(&path)
        };
        if let Err(e) = res {
            if !(force && e == Error::NotFound) {
                path_err(out, "rm", &path, e);
            }
        }
    }
}

fn cmd_rmdir(sess: &mut Session, out: &mut Out, args: &[String]) {
    if args.is_empty() {
        return usage(out, "rmdir");
    }
    for a in args {
        let path = sys::resolve(&sess.cwd, a);
        if let Err(e) = sys::rmdir(&path) {
            path_err(out, "rmdir", &path, e);
        }
    }
}

/// Stream-copy one file.
fn copy_file(out: &mut Out, src: &str, dst: &str) -> Result<(), Error> {
    let sfd = sys::open(src, OpenFlags::READ)?;
    let dfd = match sys::open(dst, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = call::close(sfd);
            return Err(e);
        }
    };
    let mut buf = [0u8; 1024];
    let mut res = Ok(());
    loop {
        if out.stop() {
            res = Err(Error::Interrupted);
            break;
        }
        match call::read(sfd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !sys::write_all(dfd, &buf[..n]) {
                    res = Err(Error::IoError);
                    break;
                }
            }
            Err(e) => {
                res = Err(e);
                break;
            }
        }
    }
    let _ = call::close(sfd);
    let _ = call::close(dfd);
    res
}

fn copy_tree(out: &mut Out, src: &str, dst: &str) -> Result<(), Error> {
    if sys::is_dir(src) {
        if !sys::is_dir(dst) {
            sys::mkdir(dst, 0o755)?;
        }
        for e in sys::read_dir(src)? {
            copy_tree(out, &sys::join(src, &e.name), &sys::join(dst, &e.name))?;
        }
        Ok(())
    } else {
        copy_file(out, src, dst)
    }
}

/// `dst` itself, or `dst/<basename src>` if `dst` is an existing directory.
fn dest_path(src: &str, dst: String) -> String {
    if sys::is_dir(&dst) {
        sys::join(&dst, sys::basename(src))
    } else {
        dst
    }
}

fn cmd_cp(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (flags, ops) = parse_flags(args);
    if ops.len() != 2 {
        return usage(out, "cp");
    }
    let recursive = flags.contains('r') || flags.contains('R');
    let src = sys::resolve(&sess.cwd, ops[0]);
    let dst = dest_path(&src, sys::resolve(&sess.cwd, ops[1]));
    if sys::is_dir(&src) {
        if !recursive {
            return out.error("cp", format_args!("{}: is a directory (use -r)", src));
        }
        if dst == src || dst.starts_with(&alloc::format!("{}/", src.trim_end_matches('/'))) {
            return out.error("cp", format_args!("cannot copy a directory into itself"));
        }
    }
    match copy_tree(out, &src, &dst) {
        Ok(()) => {
            out.style(Style::Ok);
            let _ = write!(out, "{} -> {}", src, dst);
            out.style(Style::Reset);
            out.text("\n");
        }
        Err(e) => path_err(out, "cp", &dst, e),
    }
}

fn cmd_mv(sess: &mut Session, out: &mut Out, args: &[String]) {
    let (_, ops) = parse_flags(args);
    if ops.len() != 2 {
        return usage(out, "mv");
    }
    let src = sys::resolve(&sess.cwd, ops[0]);
    let dst = dest_path(&src, sys::resolve(&sess.cwd, ops[1]));
    match sys::rename(&src, &dst) {
        Ok(()) => {}
        Err(Error::NotSupported) | Err(Error::NotImplemented) => {
            // Cross-mount move: copy then remove.
            let res = copy_tree(out, &src, &dst).and_then(|_| remove_tree(out, &src));
            if let Err(e) = res {
                path_err(out, "mv", &src, e);
            }
        }
        Err(e) => path_err(out, "mv", &src, e),
    }
}

fn write_text(sess: &Session, out: &mut Out, cmd: &str, args: &[String], append: bool) {
    if args.len() < 2 {
        return usage(out, cmd);
    }
    let path = sys::resolve(&sess.cwd, &args[0]);
    let text = args[1..].join(" ");
    let mode = if append { OpenFlags::APPEND } else { OpenFlags::TRUNCATE };
    match sys::open(&path, OpenFlags::WRITE | OpenFlags::CREATE | mode) {
        Ok(fd) => {
            if sys::write_all(fd, text.as_bytes()) {
                out.style(Style::Ok);
                let _ = write!(out, "{} bytes -> {}", text.len(), path);
                out.style(Style::Reset);
                out.text("\n");
            } else {
                out.error(cmd, format_args!("{}: write failed", path));
            }
            let _ = call::close(fd);
        }
        Err(e) => path_err(out, cmd, &path, e),
    }
}

fn cmd_write(sess: &mut Session, out: &mut Out, args: &[String]) {
    write_text(sess, out, "write", args, false);
}

fn cmd_append(sess: &mut Session, out: &mut Out, args: &[String]) {
    write_text(sess, out, "append", args, true);
}

fn cmd_echo(_: &mut Session, out: &mut Out, args: &[String]) {
    let (newline, rest) = match args.first().map(|s| s.as_str()) {
        Some("-n") => (false, &args[1..]),
        _ => (true, args),
    };
    out.text(&rest.join(" "));
    if newline {
        out.text("\n");
    }
}

// ── Commands: system / network / session ────────────────────────────────────

fn cmd_df(_: &mut Session, out: &mut Out, _: &[String]) {
    let entries = match sys::read_dir("/") {
        Ok(e) => e,
        Err(e) => return path_err(out, "df", "/", e),
    };
    out.styled(Style::Head, &alloc::format!("{:<20} {}\n", "Mount", "Status"));
    for e in &entries {
        let path = sys::join("/", &e.name);
        out.style(Style::Dir);
        let _ = write!(out, "{:<20} ", path);
        out.style(Style::Reset);
        if sys::is_dir(&path) {
            out.styled(Style::Ok, "accessible\n");
        } else {
            out.styled(Style::Warn, "unavailable\n");
        }
    }
    out.style(Style::Dim);
    let _ = write!(out, "{} mount(s)\n", entries.len());
    out.style(Style::Reset);
}

fn print_net_file(out: &mut Out, label: &str, path: &str) {
    let mut buf = [0u8; 128];
    let n = sys::read_text_file(path, &mut buf);
    out.styled(Style::Head, &alloc::format!("{:<6}", label));
    if n > 0 {
        out.data(&buf[..n]);
        if buf[n - 1] != b'\n' {
            out.text("\n");
        }
    } else {
        out.styled(Style::Dim, "n/a\n");
    }
}

fn cmd_ip(_: &mut Session, out: &mut Out, _: &[String]) {
    print_net_file(out, "IP:", "/net/ip");
}

fn cmd_net(_: &mut Session, out: &mut Out, _: &[String]) {
    print_net_file(out, "IP:", "/net/ip");
    print_net_file(out, "GW:", "/net/gateway");
    print_net_file(out, "DNS:", "/net/dns");
    print_net_file(out, "ROUTE:", "/net/route");
}

fn cmd_history(sess: &mut Session, out: &mut Out, _: &[String]) {
    let lines: Vec<String> = sess
        .history()
        .map(|h| String::from_utf8_lossy(h).into_owned())
        .collect();
    for (i, l) in lines.iter().enumerate() {
        out.style(Style::Dim);
        let _ = write!(out, "{:>4}  ", i + 1);
        out.style(Style::Reset);
        out.text(l);
        out.text("\n");
    }
}

fn cmd_term(sess: &mut Session, out: &mut Out, _: &[String]) {
    let name = if sess.term.name.is_empty() { "(not reported)" } else { sess.term.name.as_str() };
    let mode = match out.color {
        ColorMode::None => "off",
        ColorMode::Ansi => "16 colors",
        ColorMode::Xterm256 => "256 colors",
    };
    let _ = write!(
        out,
        "TERM={}  size={}x{}  color={}{}\n",
        name,
        sess.term.cols,
        sess.term.rows,
        mode,
        if sess.color_forced { " (forced)" } else { "" }
    );
    out.text("palette: ");
    for s in [
        Style::Dir,
        Style::Link,
        Style::Device,
        Style::Ok,
        Style::Warn,
        Style::Error,
        Style::Accent,
        Style::Head,
        Style::Dim,
    ] {
        out.styled(s, "\u{2588}\u{2588}");
        out.text(" ");
    }
    out.text("\n");
}

fn cmd_color(sess: &mut Session, out: &mut Out, args: &[String]) {
    match args.first().map(|s| s.as_str()) {
        Some("auto") => {
            sess.color_forced = false;
            out.color = sess.term.detected;
        }
        Some("16") | Some("ansi") | Some("on") => {
            sess.color_forced = true;
            out.color = ColorMode::Ansi;
        }
        Some("256") => {
            sess.color_forced = true;
            out.color = ColorMode::Xterm256;
        }
        Some("off") | Some("none") => {
            sess.color_forced = true;
            out.color = ColorMode::None;
        }
        _ => return usage(out, "color"),
    }
    cmd_term(sess, out, &[]);
}

fn cmd_clear(_: &mut Session, out: &mut Out, _: &[String]) {
    out.raw(b"\x1b[2J\x1b[H");
}
