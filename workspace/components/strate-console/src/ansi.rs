//! ANSI escape sequence parser.
//! Handles CSI sequences: SGR (colors), cursor movement, erase, scroll regions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnsiAction {
    CursorUp(u16),
    CursorDown(u16),
    CursorForward(u16),
    CursorBack(u16),
    CursorPosition(u16, u16),
    CursorHorizontalAbsolute(u16),
    EraseDisplay(EraseMode),
    EraseLine(EraseMode),
    Sgr(SgrParam),
    ScrollUp(u16),
    ScrollDown(u16),
    SetScrollRegion(u16, u16),
    SetMode(u16, bool),
    ResetMode(u16, bool),
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseMode {
    Below,
    Above,
    All,
    Saved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgrParam {
    Reset,
    Bold(bool),
    Underline(bool),
    Inverse(bool),
    FgColor(u8),
    BgColor(u8),
    FgRgb(u8, u8, u8),
    BgRgb(u8, u8, u8),
    DefaultColor,
}

pub struct AnsiParser {
    buf: [u8; 64],
    len: usize,
    intermediate: bool,
}

impl AnsiParser {
    pub const fn new() -> Self {
        AnsiParser {
            buf: [0u8; 64],
            len: 0,
            intermediate: false,
        }
    }

    pub fn feed(&mut self, byte: u8) -> Option<AnsiAction> {
        if byte == 0x1B {
            self.len = 0;
            self.intermediate = false;
            return None;
        }
        if byte == b'[' && self.len == 0 && !self.intermediate {
            self.intermediate = true;
            return None;
        }
        if self.intermediate {
            if byte >= 0x30 && byte <= 0x3F {
                if self.len < self.buf.len() {
                    self.buf[self.len] = byte;
                    self.len += 1;
                }
                return None;
            }
            if byte >= 0x40 && byte <= 0x7E {
                let action = self.dispatch(byte);
                self.len = 0;
                self.intermediate = false;
                return Some(action);
            }
            self.len = 0;
            self.intermediate = false;
            return Some(AnsiAction::Ignore);
        }
        None
    }

    fn dispatch(&self, final_byte: u8) -> AnsiAction {
        let params = self.parse_params();
        match final_byte {
            b'A' => AnsiAction::CursorUp(params.first(1)),
            b'B' => AnsiAction::CursorDown(params.first(1)),
            b'C' => AnsiAction::CursorForward(params.first(1)),
            b'D' => AnsiAction::CursorBack(params.first(1)),
            b'H' | b'f' => AnsiAction::CursorPosition(
                params.first(1).max(1),
                params.get(1).unwrap_or(1).max(1),
            ),
            b'G' => AnsiAction::CursorHorizontalAbsolute(params.first(1)),
            b'J' => AnsiAction::EraseDisplay(match params.first(0) {
                1 => EraseMode::Above,
                2 => EraseMode::All,
                3 => EraseMode::Saved,
                _ => EraseMode::Below,
            }),
            b'K' => AnsiAction::EraseLine(match params.first(0) {
                1 => EraseMode::Above,
                2 => EraseMode::All,
                _ => EraseMode::Below,
            }),
            b'S' => AnsiAction::ScrollUp(params.first(1)),
            b'T' => AnsiAction::ScrollDown(params.first(1)),
            b'r' => AnsiAction::SetScrollRegion(
                params.first(1),
                params.get(1).unwrap_or(0),
            ),
            b'm' => self.dispatch_sgr(&params),
            b'h' => AnsiAction::SetMode(params.first(0), true),
            b'l' => AnsiAction::ResetMode(params.first(0), true),
            _ => AnsiAction::Ignore,
        }
    }

    fn dispatch_sgr(&self, params: &ParamList) -> AnsiAction {
        if params.len() == 0 {
            return AnsiAction::Sgr(SgrParam::Reset);
        }
        match params.first(0) {
            0 => AnsiAction::Sgr(SgrParam::Reset),
            1 => AnsiAction::Sgr(SgrParam::Bold(true)),
            2 => AnsiAction::Sgr(SgrParam::Bold(false)),
            4 => AnsiAction::Sgr(SgrParam::Underline(true)),
            5 | 6 => AnsiAction::Sgr(SgrParam::Inverse(true)),
            7 => AnsiAction::Sgr(SgrParam::Inverse(true)),
            21 => AnsiAction::Sgr(SgrParam::Bold(false)),
            22 => AnsiAction::Sgr(SgrParam::Bold(false)),
            24 => AnsiAction::Sgr(SgrParam::Underline(false)),
            27 => AnsiAction::Sgr(SgrParam::Inverse(false)),
            30..=37 => AnsiAction::Sgr(SgrParam::FgColor((params.first(0) - 30) as u8)),
            38 => {
                if params.get(1) == Some(5) && params.len() >= 3 {
                    AnsiAction::Sgr(SgrParam::FgColor(params.get(2).unwrap_or(0) as u8))
                } else if params.get(1) == Some(2) && params.len() >= 6 {
                    AnsiAction::Sgr(SgrParam::FgRgb(
                        params.get(3).unwrap_or(0) as u8,
                        params.get(4).unwrap_or(0) as u8,
                        params.get(5).unwrap_or(0) as u8,
                    ))
                } else {
                    AnsiAction::Sgr(SgrParam::DefaultColor)
                }
            }
            39 => AnsiAction::Sgr(SgrParam::DefaultColor),
            40..=47 => AnsiAction::Sgr(SgrParam::BgColor((params.first(0) - 40) as u8)),
            48 => {
                if params.get(1) == Some(5) && params.len() >= 3 {
                    AnsiAction::Sgr(SgrParam::BgColor(params.get(2).unwrap_or(0) as u8))
                } else if params.get(1) == Some(2) && params.len() >= 6 {
                    AnsiAction::Sgr(SgrParam::BgRgb(
                        params.get(3).unwrap_or(0) as u8,
                        params.get(4).unwrap_or(0) as u8,
                        params.get(5).unwrap_or(0) as u8,
                    ))
                } else {
                    AnsiAction::Sgr(SgrParam::DefaultColor)
                }
            }
            49 => AnsiAction::Sgr(SgrParam::DefaultColor),
            _ => AnsiAction::Ignore,
        }
    }

    fn parse_params(&self) -> ParamList<'_> {
        ParamList {
            buf: &self.buf[..self.len],
        }
    }
}

struct ParamList<'a> {
    buf: &'a [u8],
}

impl<'a> ParamList<'a> {
    fn len(&self) -> usize {
        if self.buf.is_empty() {
            return 0;
        }
        let mut count = 1;
        for &b in self.buf {
            if b == b';' {
                count += 1;
            }
        }
        count
    }

    fn first(&self, default: u16) -> u16 {
        self.get(0).unwrap_or(default)
    }

    fn get(&self, index: usize) -> Option<u16> {
        let mut current = 0u16;
        let mut idx = 0;
        for &b in self.buf.iter() {
            if b == b';' {
                if idx == index {
                    return Some(current);
                }
                current = 0;
                idx += 1;
            } else {
                current = current * 10 + (b - b'0') as u16;
            }
        }
        if idx == index {
            Some(current)
        } else {
            None
        }
    }
}
