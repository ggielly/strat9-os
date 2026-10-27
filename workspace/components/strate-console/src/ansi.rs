use alloc::vec::Vec;
use vte::Parser as VteParser;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseMode {
    Below,
    Above,
    All,
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
    DefaultFg,
    DefaultBg,
}

pub struct AnsiParser {
    parser: VteParser,
    actions: Vec<AnsiAction>,
}

impl AnsiParser {
    pub fn new() -> Self {
        AnsiParser {
            parser: VteParser::new(),
            actions: Vec::new(),
        }
    }

    pub fn feed_bytes(&mut self, bytes: &[u8]) -> &[AnsiAction] {
        self.actions.clear();
        let mut collector = ActionCollector(&mut self.actions);
        self.parser.advance(&mut collector, bytes);
        &self.actions
    }
}

fn param_or(params: &vte::Params, idx: usize) -> u16 {
    params
        .iter()
        .nth(idx)
        .and_then(|p| p.first().copied())
        .unwrap_or(0)
}

fn has_params(params: &vte::Params, idx: usize) -> bool {
    params.iter().nth(idx).is_some()
}

struct ActionCollector<'a>(&'a mut Vec<AnsiAction>);

impl vte::Perform for ActionCollector<'_> {
    fn print(&mut self, _c: char) {}
    fn execute(&mut self, _b: u8) {}
    fn hook(&mut self, _params: &vte::Params, _intermediates: &[u8], _ignore: bool, _action: char) {
    }
    fn put(&mut self, _b: u8) {}
    fn unhook(&mut self) {}
    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {}

    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        _intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        let a = match action {
            'A' => AnsiAction::CursorUp(param_or(params, 0)),
            'B' => AnsiAction::CursorDown(param_or(params, 0)),
            'C' => AnsiAction::CursorForward(param_or(params, 0)),
            'D' => AnsiAction::CursorBack(param_or(params, 0)),
            'H' | 'f' => {
                AnsiAction::CursorPosition(param_or(params, 0).max(1), param_or(params, 1).max(1))
            }
            'G' => AnsiAction::CursorHorizontalAbsolute(param_or(params, 0)),
            'J' => AnsiAction::EraseDisplay(match param_or(params, 0) {
                1 => EraseMode::Above,
                2 | 3 => EraseMode::All,
                _ => EraseMode::Below,
            }),
            'K' => AnsiAction::EraseLine(match param_or(params, 0) {
                1 => EraseMode::Above,
                2 => EraseMode::All,
                _ => EraseMode::Below,
            }),
            'S' => AnsiAction::ScrollUp(param_or(params, 0)),
            'T' => AnsiAction::ScrollDown(param_or(params, 0)),
            'r' => AnsiAction::SetScrollRegion(param_or(params, 0), param_or(params, 1)),
            'm' => AnsiAction::Sgr(parse_sgr(params)),
            _ => return,
        };
        self.0.push(a);
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {}
}

fn parse_sgr(params: &vte::Params) -> SgrParam {
    if params.len() == 0 {
        return SgrParam::Reset;
    }
    let first = param_or(params, 0);
    match first {
        0 => SgrParam::Reset,
        1 => SgrParam::Bold(true),
        2 | 21 | 22 => SgrParam::Bold(false),
        4 => SgrParam::Underline(true),
        5 | 6 | 7 => SgrParam::Inverse(true),
        24 => SgrParam::Underline(false),
        27 => SgrParam::Inverse(false),
        30..=37 => SgrParam::FgColor((first - 30) as u8),
        38 => parse_sgr_colorspace(params, true),
        39 => SgrParam::DefaultFg,
        40..=47 => SgrParam::BgColor((first - 40) as u8),
        48 => parse_sgr_colorspace(params, false),
        49 => SgrParam::DefaultBg,
        _ => SgrParam::Reset,
    }
}

fn parse_sgr_colorspace(params: &vte::Params, is_fg: bool) -> SgrParam {
    let second = param_or(params, 1);
    if second == 5 && has_params(params, 2) {
        let c = param_or(params, 2) as u8;
        if is_fg {
            SgrParam::FgColor(c)
        } else {
            SgrParam::BgColor(c)
        }
    } else if second == 2 && has_params(params, 3) && has_params(params, 4) && has_params(params, 5)
    {
        let (r, g, b) = (
            param_or(params, 3) as u8,
            param_or(params, 4) as u8,
            param_or(params, 5) as u8,
        );
        if is_fg {
            SgrParam::FgRgb(r, g, b)
        } else {
            SgrParam::BgRgb(r, g, b)
        }
    } else {
        if is_fg {
            SgrParam::FgColor(7)
        } else {
            SgrParam::BgColor(0)
        }
    }
}
