//! Bounded, quote-aware scripting. Expansion happens at execution, never before parsing.

use crate::sync::SpinLock;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use super::parser::{self, ParseError, Pipeline, Token, Word};

static SHELL_VARS: SpinLock<BTreeMap<String, String>> = SpinLock::new(BTreeMap::new());
static LAST_EXIT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

pub fn set_last_exit(code: i32) { LAST_EXIT.store(code, core::sync::atomic::Ordering::Relaxed); }
pub fn last_exit() -> i32 { LAST_EXIT.load(core::sync::atomic::Ordering::Relaxed) }
pub fn set_var(key: &str, val: &str) { SHELL_VARS.lock().insert(String::from(key), String::from(val)); }
pub fn get_var(key: &str) -> Option<String> { SHELL_VARS.lock().get(key).cloned() }
pub fn unset_var(key: &str) { SHELL_VARS.lock().remove(key); }

/// Expand one lexical word fragment, preserving Unicode and literal replacement values.
pub fn expand_vars(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' { result.push(ch); continue; }
        if chars.peek() == Some(&'?') {
            chars.next(); result.push_str(&alloc::format!("{}", last_exit())); continue;
        }
        let mut name = String::new();
        while let Some(&next) = chars.peek() {
            if !next.is_ascii_alphanumeric() && next != '_' { break; }
            name.push(next); chars.next();
        }
        if name.is_empty() { result.push('$'); }
        else if let Some(value) = get_var(&name).or_else(|| super::commands::util::shell_getenv(&name)) {
            result.push_str(&value);
        }
    }
    result
}

/// Resolve one variable name produced by the quote-aware lexer.
///
/// Unlike [`expand_vars`], the lexer has already separated literal text from
/// `$name` fragments, so this only has to look the name up (and handle `$?`).
pub fn resolve_var(name: &str) -> String {
    if name == "?" {
        return alloc::format!("{}", last_exit());
    }
    get_var(name)
        .or_else(|| super::commands::util::shell_getenv(name))
        .unwrap_or_default()
}

#[derive(Debug)]
pub enum ScriptConstruct {
    Simple(Pipeline),
    SetVar { key: String, val: Word },
    UnsetVar(String),
    ForLoop { var: String, items: Vec<Word>, body: Vec<ScriptConstruct> },
    WhileLoop { cond: Vec<ScriptConstruct>, body: Vec<ScriptConstruct> },
    IfElse { cond: Vec<ScriptConstruct>, then_body: Vec<ScriptConstruct>, else_body: Vec<ScriptConstruct> },
}

const MAX_SCRIPT_DEPTH: usize = 16;

struct ScriptParser { tokens: Vec<Token>, pos: usize }
impl ScriptParser {
    fn keyword(&self, keyword: &str) -> bool {
        matches!(self.tokens.get(self.pos), Some(Token::Word(word)) if word.keyword(keyword))
    }
    fn separators(&mut self) {
        while matches!(self.tokens.get(self.pos), Some(Token::Semicolon)) { self.pos += 1; }
    }
    fn expect(&mut self, keyword: &'static str) -> Result<(), ParseError> {
        if !self.keyword(keyword) { return Err(ParseError::MissingKeyword(keyword)); }
        self.pos += 1; Ok(())
    }
    fn word(&mut self) -> Result<Word, ParseError> {
        let Some(Token::Word(word)) = self.tokens.get(self.pos) else { return Err(ParseError::UnexpectedToken); };
        let word = word.clone(); self.pos += 1; Ok(word)
    }
    fn statements(&mut self, stop: &[&str], depth: usize) -> Result<Vec<ScriptConstruct>, ParseError> {
        if depth > MAX_SCRIPT_DEPTH { return Err(ParseError::TooDeep); }
        let mut statements = Vec::new();
        loop {
            self.separators();
            if self.pos == self.tokens.len() || stop.iter().any(|keyword| self.keyword(keyword)) { break; }
            statements.push(self.construct(depth)?);
            if self.pos < self.tokens.len() && !matches!(self.tokens[self.pos], Token::Semicolon) {
                // Control terminators need a command boundary, just like simple commands.
                return Err(ParseError::UnexpectedToken);
            }
        }
        Ok(statements)
    }
    fn construct(&mut self, depth: usize) -> Result<ScriptConstruct, ParseError> {
        if self.keyword("for") {
            self.pos += 1;
            let var = self.word()?.literal();
            if !parser::valid_variable_name(&var) { return Err(ParseError::InvalidVariable); }
            self.expect("in")?;
            let mut items = Vec::new();
            while !matches!(self.tokens.get(self.pos), Some(Token::Semicolon)) {
                if self.pos == self.tokens.len() { return Err(ParseError::MissingKeyword("do")); }
                items.push(self.word()?);
            }
            self.separators(); self.expect("do")?;
            let body = self.statements(&["done"], depth + 1)?;
            self.expect("done")?;
            return Ok(ScriptConstruct::ForLoop { var, items, body });
        }
        if self.keyword("while") {
            self.pos += 1;
            let cond = self.statements(&["do"], depth + 1)?;
            if cond.is_empty() { return Err(ParseError::MissingCommand); }
            self.expect("do")?;
            let body = self.statements(&["done"], depth + 1)?;
            self.expect("done")?;
            return Ok(ScriptConstruct::WhileLoop { cond, body });
        }
        if self.keyword("if") {
            self.pos += 1;
            let cond = self.statements(&["then"], depth + 1)?;
            if cond.is_empty() { return Err(ParseError::MissingCommand); }
            self.expect("then")?;
            let then_body = self.statements(&["else", "fi"], depth + 1)?;
            let else_body = if self.keyword("else") {
                self.pos += 1;
                self.statements(&["fi"], depth + 1)?
            } else { Vec::new() };
            self.expect("fi")?;
            return Ok(ScriptConstruct::IfElse { cond, then_body, else_body });
        }
        let start = self.pos;
        while self.pos < self.tokens.len() && !matches!(self.tokens[self.pos], Token::Semicolon) { self.pos += 1; }
        let tokens = &self.tokens[start..self.pos];
        if matches!(tokens.first(), Some(Token::Word(word)) if word.keyword("set")) {
            if tokens.len() != 2 { return Err(ParseError::UnexpectedToken); }
            let Token::Word(word) = &tokens[1] else { return Err(ParseError::UnexpectedToken); };
            let (key, val) = word.assignment().ok_or(ParseError::InvalidVariable)?;
            return Ok(ScriptConstruct::SetVar { key, val });
        }
        if matches!(tokens.first(), Some(Token::Word(word)) if word.keyword("unset")) {
            if tokens.len() != 2 { return Err(ParseError::UnexpectedToken); }
            let Token::Word(word) = &tokens[1] else { return Err(ParseError::UnexpectedToken); };
            let name = word.literal();
            if !parser::valid_variable_name(&name) { return Err(ParseError::InvalidVariable); }
            return Ok(ScriptConstruct::UnsetVar(name));
        }
        if ["then", "else", "fi", "do", "done"].iter().any(|keyword| self.keyword_at(start, keyword)) {
            return Err(ParseError::UnexpectedToken);
        }
        Ok(ScriptConstruct::Simple(parser::pipeline_from_tokens(tokens)?))
    }
    fn keyword_at(&self, pos: usize, keyword: &str) -> bool {
        matches!(self.tokens.get(pos), Some(Token::Word(word)) if word.keyword(keyword))
    }
}

pub fn parse_script(line: &str) -> Result<Vec<ScriptConstruct>, ParseError> {
    let mut parser = ScriptParser { tokens: parser::lex(line)?, pos: 0 };
    let statements = parser.statements(&[], 0)?;
    if parser.pos != parser.tokens.len() { return Err(ParseError::UnexpectedToken); }
    Ok(statements)
}

/// Reconstruct already parsed arguments without turning their contents into syntax.
pub fn quote_argument(arg: &str) -> String {
    let mut result = String::from("'");
    for ch in arg.chars() {
        if ch == '\'' { result.push_str("'\\''"); } else { result.push(ch); }
    }
    result.push('\''); result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn inline_and_nested_control_bodies_parse() {
        let script = parse_script("for i in a b; do if echo $i; then echo 'é;|'; else echo no; fi; done").unwrap();
        let ScriptConstruct::ForLoop { body, .. } = &script[0] else { panic!("for expected"); };
        assert!(matches!(body[0], ScriptConstruct::IfElse { .. }));
    }
    #[test] fn malformed_control_syntax_is_rejected() {
        for line in ["if echo x; else echo y; fi", "while echo x; do echo y", "for 1 in x; do echo y; done", "set =x", "echo x; fi"] {
            assert!(parse_script(line).is_err(), "{}", line);
        }
    }
    #[test] fn unicode_expansion_is_not_reinterpreted() {
        set_var("CHEVRON_TEST", "$? | reboot");
        assert_eq!(expand_vars("été $CHEVRON_TEST"), "été $? | reboot");
        unset_var("CHEVRON_TEST");
    }
    #[test] fn quoted_argument_round_trips() {
        let input = "é '$x' | ; >";
        let line = alloc::format!("echo {}", quote_argument(input));
        let command = parser::parse(&line).unwrap();
        assert_eq!(command.args[0], input);
    }
}
