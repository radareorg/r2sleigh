//! Colouring a line of the decompiled C.
//!
//! Presentation only, and lexical: the shell hands the pane text, and the
//! colour of a token is what C's own lexical classes say it is. A residual --
//! a construct the engine could not prove and spelled as a call that traps --
//! is the one class read off its name, because that name is the engine's own
//! contract for it (`r2sleigh_residual_<T>`), and it is what a reader must not
//! miss.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

const KEYWORD: Style = Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD);
const TYPE: Style = Style::new().fg(Color::Blue);
const NUMBER: Style = Style::new().fg(Color::Cyan);
const STRING: Style = Style::new().fg(Color::Yellow);
const COMMENT: Style = Style::new().fg(Color::DarkGray);
const RESIDUAL: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);
const HELPER: Style = Style::new().fg(Color::LightYellow);

const KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "return", "switch", "case", "default", "break", "continue",
    "goto", "sizeof",
];

const TYPES: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "bool",
    "_Bool",
    "struct",
    "union",
    "enum",
    "const",
    "volatile",
    "static",
    "extern",
    "inline",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "__int128_t",
    "__uint128_t",
    "size_t",
    "uintptr_t",
    "intptr_t",
];

/// What a token of C is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Plain,
    Keyword,
    Type,
    Number,
    String,
    Comment,
    /// A construct the engine refused to claim: `r2sleigh_residual_<T>`.
    Residual,
    /// One of the engine's total helpers: `r2sleigh_load_u32` and the like.
    Helper,
}

impl Class {
    fn style(self) -> Style {
        match self {
            Class::Plain => Style::new(),
            Class::Keyword => KEYWORD,
            Class::Type => TYPE,
            Class::Number => NUMBER,
            Class::String => STRING,
            Class::Comment => COMMENT,
            Class::Residual => RESIDUAL,
            Class::Helper => HELPER,
        }
    }
}

/// The line cut into tokens, each with its class, covering every character.
///
/// `in_comment` says whether the line starts inside a `/* */` comment an
/// earlier line opened; it is updated to whether this one leaves it open.
pub fn classify<'a>(line: &'a str, in_comment: &mut bool) -> Vec<(Class, &'a str)> {
    let mut out = Vec::new();
    let mut rest = line;
    while !rest.is_empty() {
        if *in_comment {
            let (comment, after) = match rest.find("*/") {
                Some(end) => {
                    *in_comment = false;
                    rest.split_at(end + 2)
                }
                None => (rest, ""),
            };
            out.push((Class::Comment, comment));
            rest = after;
            continue;
        }
        if rest.starts_with("/*") {
            *in_comment = true;
            continue;
        }
        if rest.starts_with("//") {
            out.push((Class::Comment, rest));
            break;
        }
        let first = rest.chars().next().unwrap_or(' ');
        let length = if first == '"' || first == '\'' {
            quoted(rest, first)
        } else if first.is_ascii_digit() {
            rest.find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len())
        } else if first.is_alphabetic() || first == '_' {
            rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len())
        } else {
            first.len_utf8()
        };
        let (token, after) = rest.split_at(length);
        let class = if first == '"' || first == '\'' {
            Class::String
        } else if first.is_ascii_digit() {
            Class::Number
        } else if token.starts_with("r2sleigh_residual") {
            Class::Residual
        } else if token.starts_with("r2sleigh_") {
            Class::Helper
        } else if KEYWORDS.contains(&token) {
            Class::Keyword
        } else if TYPES.contains(&token) {
            Class::Type
        } else {
            Class::Plain
        };
        out.push((class, token));
        rest = after;
    }
    out
}

/// The length of a quoted literal starting at the quote, escapes included,
/// to its closing quote or the end of the line.
fn quoted(text: &str, quote: char) -> usize {
    let mut escaped = false;
    for (at, c) in text.char_indices().skip(1) {
        match (escaped, c) {
            (true, _) => escaped = false,
            (false, '\\') => escaped = true,
            (false, c) if c == quote => return at + c.len_utf8(),
            _ => {}
        }
    }
    text.len()
}

/// The line as styled spans.
pub fn spans(line: &str, in_comment: &mut bool) -> Vec<Span<'static>> {
    classify(line, in_comment)
        .into_iter()
        .map(|(class, token)| Span::styled(token.to_owned(), class.style()))
        .collect()
}

/// What the rendering's proof comment says, where the line is one:
/// `/* r2dec proof: 4 constructs are marked below; ... */` gives
/// `4 constructs are marked below`.
pub fn proof(line: &str) -> Option<&str> {
    let after = line.split_once("r2dec proof:")?.1;
    Some(after.split(';').next().unwrap_or(after).trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(line: &str) -> Vec<(Class, String)> {
        let mut in_comment = false;
        classify(line, &mut in_comment)
            .into_iter()
            .filter(|(_, token)| !token.trim().is_empty())
            .map(|(class, token)| (class, token.to_owned()))
            .collect()
    }

    #[test]
    fn every_character_is_in_exactly_one_token() {
        for line in [
            "    if (7 >= (uint32_t)x) { return r2sleigh_residual_u64(3); }",
            "char *s = \"a \\\"quoted\\\" word\"; // and a comment",
            "/* open",
        ] {
            let mut in_comment = false;
            let joined: String = classify(line, &mut in_comment)
                .into_iter()
                .map(|(_, token)| token)
                .collect();
            assert_eq!(joined, line);
        }
    }

    #[test]
    fn a_residual_stands_out_from_a_helper_and_both_from_a_call() {
        let found = classes("x = r2sleigh_residual_u32(1) + r2sleigh_load_u32(p) + f(0x10);");
        assert!(found.contains(&(Class::Residual, "r2sleigh_residual_u32".to_owned())));
        assert!(found.contains(&(Class::Helper, "r2sleigh_load_u32".to_owned())));
        assert!(found.contains(&(Class::Plain, "f".to_owned())));
        assert!(found.contains(&(Class::Number, "0x10".to_owned())));
    }

    #[test]
    fn a_comment_runs_across_lines_until_it_closes() {
        let mut in_comment = false;
        let first = classify("int a; /* starts", &mut in_comment);
        assert!(in_comment);
        assert_eq!(first.last().map(|(class, _)| *class), Some(Class::Comment));
        let second = classify("ends */ return a;", &mut in_comment);
        assert!(!in_comment);
        assert_eq!(second[0], (Class::Comment, "ends */"));
        assert!(second.contains(&(Class::Keyword, "return")));
    }

    #[test]
    fn the_proof_comment_is_read_to_its_first_clause() {
        let line = "    /* r2dec proof: 4 constructs are marked below; 28 source obligations */";
        assert_eq!(proof(line), Some("4 constructs are marked below"));
        assert_eq!(proof("return 0;"), None);
    }
}
