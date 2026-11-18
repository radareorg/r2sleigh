//! What each part of a listing is, and the one palette both the visual mode
//! and the shell paint it with.
//!
//! The roles are facts the engine states about a line, not guesses from how
//! the text looks. Syntax roles keep radare2's default theme; proof roles use
//! hues no syntax role uses (doc/adr-display.md, "Colour roles").

use ratatui::style::{Color, Modifier, Style};

/// What a span of listing text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// An instruction address.
    Offset,
    /// An instruction that only falls through.
    Mnemonic,
    Call,
    Jump,
    ConditionalJump,
    Return,
    Nop,
    /// An instruction that traps or has no semantics.
    Trap,
    /// Bytes that do not decode.
    Invalid,
    Register,
    Number,
    /// A name the table gives an address an operand uses.
    Name,
    /// C: a keyword the renderer wrote.
    Keyword,
    /// C: a type.
    Type,
    /// C: a string or character literal.
    String,
    /// C: a comment, the proof line among them.
    Comment,
    /// C: the function a call calls.
    Function,
    /// C: a name outside the function.
    External,
    /// C: a construct the rendering could not prove, which traps.
    Residual,
    /// The mark cell of a refusal, `!`.
    ProofRefused,
    /// The reason after a refusal's `!`.
    ProofReason,
    /// The mark cell of a question with no answer, `?`.
    ProofUnknown,
    /// A bound, `~`.
    ProofBound,
    /// A fact under a premise, `*`.
    ProofPremise,
    /// A declaration found by a name, `^`.
    ProofDeclared,
    /// A width or a use, no type, `.`.
    ProofRead,
    /// A convention's default, `_`.
    ProofAssumed,
    /// A flow lane and its arrow.
    Flow,
    /// The back edge of a loop the engine states.
    FlowLoop,
    /// The function rail and `pdd`'s indentation rails: decoration.
    Rail,
}

impl Role {
    /// The role a note's mark cell is painted in, so colour repeats the mark; none for the space.
    pub const fn marked(cell: char) -> Option<Self> {
        Some(match cell {
            '!' => Self::ProofRefused,
            '?' => Self::ProofUnknown,
            '_' => Self::ProofAssumed,
            '.' => Self::ProofRead,
            '^' => Self::ProofDeclared,
            '~' => Self::ProofBound,
            '*' => Self::ProofPremise,
            _ => return None,
        })
    }

    /// The role's SGR parameters at each depth, from radare2's palette (`libr/cons/pal.c`) and
    /// doc/adr-display.md "Colour roles"; none for a role painted as plain text.
    const fn table(self) -> Option<[&'static str; 3]> {
        Some(match self {
            Self::Mnemonic => return None,
            Self::Offset | Self::Jump | Self::ConditionalJump | Self::Flow => {
                ["32", "38;5;71", "38;2;95;175;95"]
            }
            Self::Call | Self::Function => ["92", "38;5;83", "38;2;95;255;135"],
            Self::Return => ["31", "38;5;160", "38;2;255;95;95"],
            Self::Nop | Self::Type => ["34", "38;5;69", "38;2;95;135;255"],
            Self::Trap | Self::Invalid | Self::Residual => {
                ["1;91", "1;38;5;203", "1;38;2;255;95;95"]
            }
            Self::Register => ["36", "38;5;37", "38;2;0;175;175"],
            Self::Number => ["33", "38;5;178", "38;2;215;175;0"],
            Self::Name | Self::External => ["96", "38;5;80", "38;2;95;215;215"],
            Self::Keyword => ["35", "38;5;170", "38;2;215;95;215"],
            Self::String => ["93", "38;5;222", "38;2;255;215;135"],
            Self::Comment => ["90", "38;5;248", "38;2;168;168;168"],
            Self::ProofRefused => ["41;97", "48;5;88;38;5;231", "48;2;135;0;0;38;2;255;255;255"],
            Self::ProofReason => ["39", "38;5;210", "38;2;255;135;135"],
            Self::ProofUnknown => ["43;30", "48;5;214;38;5;16", "48;2;230;159;0;38;2;0;0;0"],
            Self::ProofBound => ["94", "38;5;74", "38;2;86;180;233"],
            Self::ProofPremise => ["95", "38;5;227", "38;2;240;228;66"],
            Self::ProofDeclared => ["95", "38;5;175", "38;2;204;121;167"],
            Self::ProofRead => ["94", "38;5;36", "38;2;43;197;154"],
            Self::ProofAssumed => ["95", "38;5;173", "38;2;215;135;95"],
            Self::FlowLoop => ["35", "38;5;140", "38;2;175;135;215"],
            Self::Rail => ["90", "38;5;240", "38;2;88;88;88"],
        })
    }

    /// The SGR parameters the shell writes before text in this role at `depth`.
    pub const fn sgr(self, depth: Depth) -> Option<&'static str> {
        match self.table() {
            Some(table) => Some(table[depth as usize - 1]),
            None => None,
        }
    }

    /// The visual mode's style: the same table at depth 1, read as ratatui's colours.
    pub fn style(self) -> Style {
        self.sgr(Depth::Ansi16).map_or_else(Style::new, styled)
    }
}

/// How many colours a terminal is painted with: radare2's `scr.color` 1, 2 and 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Depth {
    Ansi16 = 1,
    Ansi256 = 2,
    Truecolor = 3,
}

impl Depth {
    /// The depth `scr.color` names; none for 0, which paints nothing.
    pub const fn of(level: u8) -> Option<Self> {
        match level {
            1 => Some(Self::Ansi16),
            2 => Some(Self::Ansi256),
            3 => Some(Self::Truecolor),
            _ => None,
        }
    }
}

/// SGR parameters as a ratatui style: the sixteen colours by name, 256 and truecolor by value.
fn styled(params: &str) -> Style {
    const NAMED: [Color; 16] = [
        Color::Black,
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
        Color::Gray,
        Color::DarkGray,
        Color::LightRed,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightBlue,
        Color::LightMagenta,
        Color::LightCyan,
        Color::White,
    ];
    let mut codes = params.split(';').filter_map(|code| code.parse::<u8>().ok());
    let mut style = Style::new();
    while let Some(code) = codes.next() {
        let mut extended = || match codes.next() {
            Some(5) => codes.next().map(Color::Indexed),
            Some(2) => Some(Color::Rgb(codes.next()?, codes.next()?, codes.next()?)),
            _ => None,
        };
        style = match code {
            1 => style.add_modifier(Modifier::BOLD),
            30..=37 => style.fg(NAMED[usize::from(code - 30)]),
            90..=97 => style.fg(NAMED[usize::from(code - 82)]),
            39 => style.fg(Color::Reset),
            40..=47 => style.bg(NAMED[usize::from(code - 40)]),
            38 => extended().map_or(style, |color| style.fg(color)),
            48 => extended().map_or(style, |color| style.bg(color)),
            _ => style,
        };
    }
    style
}

/// Spans of `text` in a role, in order and not overlapping.
pub type Roles = Vec<(std::ops::Range<usize>, Role)>;

/// Roles over a whole text, cut at its lines: one list per line, each with
/// offsets into that line. A span crossing a line break is cut there.
pub fn by_line(text: &str, roles: &[(std::ops::Range<usize>, Role)]) -> Vec<Roles> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut next = 0;
    for line in text.split('\n') {
        let end = start + line.len();
        let mut own = Roles::new();
        while next < roles.len() && roles[next].0.start < end {
            let (range, role) = &roles[next];
            let from = range.start.max(start) - start;
            let to = range.end.min(end) - start;
            if from < to {
                own.push((from..to, *role));
            }
            if range.end > end {
                break;
            }
            next += 1;
        }
        lines.push(own);
        start = end + 1;
    }
    lines
}

/// `text` with every role span wrapped in its escape at `depth`, for a terminal.
pub fn ansi(text: &str, roles: &[(std::ops::Range<usize>, Role)], depth: Depth) -> String {
    let mut out = String::with_capacity(text.len() + roles.len() * 10);
    let mut at = 0;
    for (range, role) in roles {
        if range.start < at || range.end > text.len() {
            continue;
        }
        out.push_str(&text[at..range.start]);
        match role.sgr(depth) {
            Some(params) => {
                out.push_str("\x1b[");
                out.push_str(params);
                out.push('m');
                out.push_str(&text[range.clone()]);
                out.push_str("\x1b[0m");
            }
            None => out.push_str(&text[range.clone()]),
        }
        at = range.end;
    }
    out.push_str(&text[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_is_painted_where_it_has_a_colour_and_the_text_is_kept() {
        let text = "call sym.main";
        let roles = vec![(0..4, Role::Call), (5..13, Role::Name)];
        assert_eq!(
            ansi(text, &roles, Depth::Ansi16),
            "\x1b[92mcall\x1b[0m \x1b[96msym.main\x1b[0m"
        );
        assert_eq!(
            ansi("mov", &[(0..3, Role::Mnemonic)], Depth::Truecolor),
            "mov"
        );
    }

    const ROLES: [Role; 30] = [
        Role::Offset,
        Role::Mnemonic,
        Role::Call,
        Role::Jump,
        Role::ConditionalJump,
        Role::Return,
        Role::Nop,
        Role::Trap,
        Role::Invalid,
        Role::Register,
        Role::Number,
        Role::Name,
        Role::Keyword,
        Role::Type,
        Role::String,
        Role::Comment,
        Role::Function,
        Role::External,
        Role::Residual,
        Role::ProofRefused,
        Role::ProofReason,
        Role::ProofUnknown,
        Role::ProofBound,
        Role::ProofPremise,
        Role::ProofDeclared,
        Role::ProofRead,
        Role::ProofAssumed,
        Role::Flow,
        Role::FlowLoop,
        Role::Rail,
    ];

    const MARKS: [char; 7] = ['!', '?', '_', '.', '^', '~', '*'];

    /// SGR parameters split into codes, with each extended colour taken whole: `(fg, bg, plain)`.
    fn parsed(params: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>) {
        let mut codes = params
            .split(';')
            .map(|code| code.parse::<u8>().expect("a code"));
        let (mut fg, mut bg, mut plain) = (None, None, Vec::new());
        while let Some(code) = codes.next() {
            let extended = |codes: &mut dyn Iterator<Item = u8>| match codes.next() {
                Some(5) => vec![codes.next().expect("an index")],
                Some(2) => (0..3).map(|_| codes.next().expect("a channel")).collect(),
                other => panic!("an extended colour, not {other:?}"),
            };
            match code {
                38 => fg = Some(extended(&mut codes)),
                48 => bg = Some(extended(&mut codes)),
                _ => plain.push(code),
            }
        }
        (fg, bg, plain)
    }

    /// WCAG relative luminance of an sRGB colour.
    fn luminance(rgb: &[u8]) -> f64 {
        let linear = |channel: u8| {
            let c = f64::from(channel) / 255.0;
            match c <= 0.04045 {
                true => c / 12.92,
                false => ((c + 0.055) / 1.055).powf(2.4),
            }
        };
        0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2])
    }

    fn contrast(a: &[u8], b: &[u8]) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// Each proof mark has its own role, so two roles sharing a hue at depth 1 differ by glyph.
    #[test]
    fn each_proof_role_has_its_own_glyph() {
        let mut roles = MARKS.map(|cell| Role::marked(cell).expect("a proof role"));
        roles.sort_by_key(|role| *role as u8);
        assert!(roles.windows(2).all(|pair| pair[0] != pair[1]));
        assert_eq!(Role::marked(' '), None);
        assert!(!roles.contains(&Role::ProofReason));
    }

    /// No proof role reuses a syntax hue at depth 1, and no role uses dim or italic.
    #[test]
    fn proof_roles_use_no_syntax_hue_and_no_role_is_dim_or_italic() {
        const SYNTAX: [&str; 11] = [
            "31", "32", "33", "34", "35", "36", "90", "92", "93", "96", "1;91",
        ];
        let proof = MARKS.map(|cell| Role::marked(cell).expect("a proof role"));
        for role in proof.into_iter().chain([Role::ProofReason]) {
            let code = role.sgr(Depth::Ansi16).expect("painted");
            assert!(!SYNTAX.contains(&code), "{role:?} {code}");
        }
        for role in ROLES {
            for depth in [Depth::Ansi16, Depth::Ansi256, Depth::Truecolor] {
                let Some(params) = role.sgr(depth) else {
                    continue;
                };
                let (_, _, plain) = parsed(params);
                assert!(
                    !plain.contains(&2) && !plain.contains(&3),
                    "{role:?} {params}"
                );
            }
        }
    }

    /// Each truecolor foreground reaches 4.5:1 on black, or on its own background; the rail is
    /// decoration and exempt.
    #[test]
    fn each_truecolor_foreground_reaches_four_and_a_half_to_one() {
        for role in ROLES.into_iter().filter(|role| *role != Role::Rail) {
            let Some(params) = role.sgr(Depth::Truecolor) else {
                continue;
            };
            let (fg, bg, _) = parsed(params);
            let fg = fg.unwrap_or_else(|| panic!("{role:?} states its foreground"));
            let bg = bg.unwrap_or_else(|| vec![0, 0, 0]);
            let ratio = contrast(&fg, &bg);
            assert!(ratio >= 4.5, "{role:?} {params}: {ratio:.2}");
        }
    }

    /// The visual mode reads the same table: a refusal is white on red, a reason the default.
    #[test]
    fn the_visual_mode_style_is_the_depth_one_entry() {
        assert_eq!(
            Role::ProofRefused.style(),
            Style::new().bg(Color::Red).fg(Color::White)
        );
        assert_eq!(
            Role::Residual.style(),
            Style::new()
                .add_modifier(Modifier::BOLD)
                .fg(Color::LightRed)
        );
        assert_eq!(Role::Mnemonic.style(), Style::new());
    }
}
