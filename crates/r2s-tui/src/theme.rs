//! What each part of a listing is, and the one palette both the visual mode
//! and the shell paint it with.
//!
//! The roles are facts the engine states about a line -- which word is a
//! register, which number is an address the table names, where control goes
//! -- not guesses from how the text looks. The colours are radare2's default
//! theme, so a radare2 user reads the same colours for the same things.

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
}

impl Role {
    /// radare2's default colour for the role (`ec` in `libr/cons/pal.c`).
    pub const fn color(self) -> Option<Color> {
        Some(match self {
            Self::Offset => Color::Green,
            Self::Mnemonic => return None,
            Self::Call => Color::LightGreen,
            Self::Jump | Self::ConditionalJump => Color::Green,
            Self::Return => Color::Red,
            Self::Nop => Color::Blue,
            Self::Trap | Self::Invalid => Color::LightRed,
            Self::Register => Color::Cyan,
            Self::Number => Color::Yellow,
            Self::Name => Color::LightCyan,
        })
    }

    pub fn style(self) -> Style {
        let style = self
            .color()
            .map_or_else(Style::new, |color| Style::new().fg(color));
        match self {
            Self::Trap | Self::Invalid => style.add_modifier(Modifier::BOLD),
            _ => style,
        }
    }

    /// The SGR sequence the shell writes before text in this role, and none
    /// for a role painted as plain text.
    pub fn ansi(self) -> Option<&'static str> {
        Some(match self.color()? {
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Cyan => "\x1b[36m",
            Color::LightRed => "\x1b[1;91m",
            Color::LightGreen => "\x1b[92m",
            Color::LightCyan => "\x1b[96m",
            _ => return None,
        })
    }
}

/// Spans of `text` in a role, in order and not overlapping.
pub type Roles = Vec<(std::ops::Range<usize>, Role)>;

/// `text` with every role span wrapped in its escape, for a terminal.
pub fn ansi(text: &str, roles: &[(std::ops::Range<usize>, Role)]) -> String {
    let mut out = String::with_capacity(text.len() + roles.len() * 10);
    let mut at = 0;
    for (range, role) in roles {
        if range.start < at || range.end > text.len() {
            continue;
        }
        out.push_str(&text[at..range.start]);
        match role.ansi() {
            Some(escape) => {
                out.push_str(escape);
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
            ansi(text, &roles),
            "\x1b[92mcall\x1b[0m \x1b[96msym.main\x1b[0m"
        );
        assert_eq!(ansi("mov", &[(0..3, Role::Mnemonic)]), "mov");
    }
}
