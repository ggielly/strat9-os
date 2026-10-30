//! Quote-aware Chevron lexer and pipeline parser.
//! Operators are recognized before expansion: variable values are always data.

use alloc::{string::String, vec::Vec};

pub const MAX_LINE_BYTES: usize = 4096;
pub const MAX_PIPELINE_STAGES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    LineTooLong,
    UnclosedQuote,
    DanglingEscape,
    MissingCommand,
    MissingRedirectTarget,
    DuplicateRedirect,
    TooManyStages,
    UnexpectedToken,
    InvalidVariable,
    MissingKeyword(&'static str),
    TooDeep,
}

#[derive(Debug, Clone)]
struct WordPart {
    text: String,
    expand: bool,
}

#[derive(Debug, Clone)]
pub struct Word {
    parts: Vec<WordPart>,
    quoted: bool,
}

impl Word {
    fn new() -> Self {
        Self {
            parts: Vec::new(),
            quoted: false,
        }
    }

    fn push(&mut self, ch: char, expand: bool) {
        if let Some(part) = self.parts.last_mut().filter(|part| part.expand == expand) {
            part.text.push(ch);
        } else {
            let mut text = String::new();
            text.push(ch);
            self.parts.push(WordPart { text, expand });
        }
    }

    fn push_var(&mut self, name: &str) {
        self.parts.push(WordPart {
            text: String::from(name),
            expand: true,
        });
    }

    pub fn literal(&self) -> String {
        self.parts.iter().map(|part| part.text.as_str()).collect()
    }

    pub fn resolve(&self, expand: impl Fn(&str) -> String) -> String {
        let mut result = String::new();
        for part in &self.parts {
            if part.expand {
                result.push_str(&expand(&part.text));
            } else {
                result.push_str(&part.text);
            }
        }
        result
    }

    pub(crate) fn keyword(&self, keyword: &str) -> bool {
        !self.quoted && self.literal() == keyword
    }

    pub(crate) fn assignment(&self) -> Option<(String, Word)> {
        let literal = self.literal();
        let eq = literal.find('=')?;
        let key = &literal[..eq];
        if !valid_variable_name(key) {
            return None;
        }
        let mut value = Self::new();
        value.quoted = self.quoted;
        let mut offset = 0;
        for part in &self.parts {
            let end = offset + part.text.len();
            if end > eq + 1 {
                let start = (eq + 1).saturating_sub(offset);
                value.parts.push(WordPart {
                    text: String::from(&part.text[start..]),
                    expand: part.expand,
                });
            }
            offset = end;
        }
        Some((String::from(key), value))
    }
}

pub(crate) fn valid_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Scan the variable name right after a `$` (already consumed).
///
/// Returns `None` when the `$` is literal (`$`, `$-`, `$ `): the caller then
/// keeps it as plain text. `$?` is the last exit status and resolves to the
/// pseudo-variable name `?`.
fn scan_variable(chars: &mut core::iter::Peekable<core::str::Chars<'_>>) -> Option<String> {
    let mut name = String::new();
    if chars.peek() == Some(&'?') {
        chars.next();
        name.push('?');
        return Some(name);
    }
    while let Some(&next) = chars.peek() {
        if !next.is_ascii_alphanumeric() && next != '_' {
            break;
        }
        name.push(next);
        chars.next();
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Token {
    Word(Word),
    Pipe,
    Input,
    Output,
    Append,
    Semicolon,
}

pub(crate) fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    if input.len() > MAX_LINE_BYTES {
        return Err(ParseError::LineTooLong);
    }
    let mut tokens = Vec::new();
    let mut word = Word::new();
    let mut active = false;
    let mut quote = None;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            } else {
                word.push(ch, false);
            }
            continue;
        }
        if ch == '\\' {
            let next = chars.next().ok_or(ParseError::DanglingEscape)?;
            word.quoted = true;
            active = true;
            // Within double quotes, only shell-significant characters are escaped.
            if quote == Some('"') && !matches!(next, '$' | '"' | '\\') {
                word.push('\\', false);
            }
            word.push(next, false);
            continue;
        }
        if quote == Some('"') {
            if ch == '"' {
                quote = None;
            } else if ch == '$' {
                match scan_variable(&mut chars) {
                    Some(name) => word.push_var(&name),
                    None => word.push('$', false),
                }
            } else {
                word.push(ch, false);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            word.quoted = true;
            active = true;
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() || matches!(ch, '|' | '<' | '>' | ';') {
            if active {
                tokens.push(Token::Word(core::mem::replace(&mut word, Word::new())));
                active = false;
            }
            match ch {
                '|' => tokens.push(Token::Pipe),
                '<' => tokens.push(Token::Input),
                '>' if chars.peek() == Some(&'>') => {
                    chars.next();
                    tokens.push(Token::Append);
                }
                '>' => tokens.push(Token::Output),
                ';' => tokens.push(Token::Semicolon),
                _ => {}
            }
        } else if ch == '$' {
            // Only `$name` / `$?` expand; every literal character is kept as
            // plain text (pushing it expandable would resolve it as a
            // variable and silently blank the whole word).
            active = true;
            match scan_variable(&mut chars) {
                Some(name) => word.push_var(&name),
                None => word.push('$', false),
            }
        } else {
            active = true;
            word.push(ch, false);
        }
    }
    if quote.is_some() {
        return Err(ParseError::UnclosedQuote);
    }
    if active {
        tokens.push(Token::Word(word));
    }
    Ok(tokens)
}

#[derive(Debug)]
pub struct Command {
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CommandWords {
    pub name: Word,
    pub args: Vec<Word>,
}
impl CommandWords {
    pub fn resolve(&self, expand: impl Fn(&str) -> String + Copy) -> Command {
        Command {
            name: self.name.resolve(expand),
            args: self.args.iter().map(|word| word.resolve(expand)).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Redirect {
    Truncate(Word),
    Append(Word),
}

#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub command: CommandWords,
    pub stdout_redirect: Option<Redirect>,
    pub stdin_redirect: Option<Word>,
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub stages: Vec<PipelineStage>,
}

pub(crate) fn pipeline_from_tokens(tokens: &[Token]) -> Result<Pipeline, ParseError> {
    let mut stages = Vec::new();
    for stage_tokens in tokens.split(|token| matches!(token, Token::Pipe)) {
        if stages.len() == MAX_PIPELINE_STAGES {
            return Err(ParseError::TooManyStages);
        }
        let mut words = Vec::new();
        let mut stdout_redirect = None;
        let mut stdin_redirect = None;
        let mut tokens = stage_tokens.iter();
        while let Some(token) = tokens.next() {
            match token {
                Token::Word(word) => words.push(word.clone()),
                Token::Input | Token::Output | Token::Append => {
                    let Some(Token::Word(target)) = tokens.next() else {
                        return Err(ParseError::MissingRedirectTarget);
                    };
                    match token {
                        Token::Input => {
                            if stdin_redirect.is_some() {
                                return Err(ParseError::DuplicateRedirect);
                            }
                            stdin_redirect = Some(target.clone());
                        }
                        _ => {
                            if stdout_redirect.is_some() {
                                return Err(ParseError::DuplicateRedirect);
                            }
                            stdout_redirect = Some(if matches!(token, Token::Append) {
                                Redirect::Append(target.clone())
                            } else {
                                Redirect::Truncate(target.clone())
                            });
                        }
                    }
                }
                _ => return Err(ParseError::UnexpectedToken),
            }
        }
        let mut words = words.into_iter();
        let name = words.next().ok_or(ParseError::MissingCommand)?;
        stages.push(PipelineStage {
            command: CommandWords {
                name,
                args: words.collect(),
            },
            stdout_redirect,
            stdin_redirect,
        });
    }
    Ok(Pipeline { stages })
}

pub fn try_parse_pipeline(line: &str) -> Result<Option<Pipeline>, ParseError> {
    let tokens = lex(line)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    pipeline_from_tokens(&tokens).map(Some)
}

pub fn parse_pipeline(line: &str) -> Option<Pipeline> {
    try_parse_pipeline(line).ok().flatten()
}

pub fn parse(line: &str) -> Option<Command> {
    let pipeline = parse_pipeline(line)?;
    if pipeline.stages.len() != 1 {
        return None;
    }
    let stage = pipeline.stages.into_iter().next()?;
    if stage.stdin_redirect.is_some() || stage.stdout_redirect.is_some() {
        return None;
    }
    Some(stage.command.resolve(|text| String::from(text)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_operators_and_empty_words_are_arguments() {
        let p = try_parse_pipeline("echo 'a|b;>' \"\" a\\ b")
            .unwrap()
            .unwrap();
        let cmd = p.stages[0].command.resolve(|text| String::from(text));
        assert_eq!(cmd.args, ["a|b;>", "", "a b"]);
    }
    #[test]
    fn expansion_cannot_inject_operators_and_single_quotes_are_literal() {
        let p = parse_pipeline("echo $X '$X'").unwrap();
        let cmd = p.stages[0]
            .command
            .resolve(|text| text.replace("$X", "é | reboot"));
        assert_eq!(p.stages.len(), 1);
        assert_eq!(cmd.args, ["é | reboot", "$X"]);
    }
    #[test]
    fn malformed_pipelines_are_rejected() {
        for line in [
            "echo >",
            "| echo",
            "echo |",
            "echo > > out",
            "echo > a > b",
            "echo 'x",
            "echo \\",
        ] {
            assert!(try_parse_pipeline(line).is_err(), "{}", line);
        }
    }
}
