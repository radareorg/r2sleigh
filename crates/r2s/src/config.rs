//! `e`: the keys that change how the shell presents what it prints.
//!
//! Each key is radare2's, so a script that sets one runs against either. Only
//! a key the shell acts on exists: a key that is accepted and then ignored
//! says the output is something it is not. Where radare2 coerces a value it
//! cannot read (`asm.bytes=maybe` reads as false, `scr.color=7` as 3), the
//! shell refuses it and keeps the value it had.

use crate::session::Session;

/// One configuration key.
pub(crate) struct Key {
    pub name: &'static str,
    /// What it changes, as `e` lists it and completion describes it.
    pub summary: &'static str,
    get: fn(&Session) -> String,
    set: fn(&mut Session, &str) -> Result<(), String>,
}

/// Every key, in the order `e` lists them.
pub(crate) const KEYS: &[Key] = &[
    Key {
        name: "asm.bytes",
        summary: "display the bytes of each instruction",
        get: |session| session.bytes.to_string(),
        set: |session, value| {
            session.bytes = boolean("asm.bytes", value)?;
            Ok(())
        },
    },
    Key {
        name: "asm.proof",
        summary: "name each note's basis and each setter's call (r2s only)",
        get: |session| session.proof.to_string(),
        set: |session, value| {
            session.proof = boolean("asm.proof", value)?;
            Ok(())
        },
    },
    Key {
        name: "asm.lines",
        summary: "show ASCII-art lines at disassembly",
        get: |session| session.lines.to_string(),
        set: |session, value| {
            session.lines = boolean("asm.lines", value)?;
            Ok(())
        },
    },
    Key {
        name: "asm.lines.width",
        summary: "number of columns for program flow arrows",
        get: |session| session.gutter().width.to_string(),
        set: |session, value| {
            // Two cells are the arrow's shaft and head; the rest are lanes (D565).
            session.lines_width = match value.parse::<usize>() {
                Ok(width @ 2..=64) => Some(width),
                _ => return Err(format!("asm.lines.width takes 2 to 64, not '{value}'")),
            };
            Ok(())
        },
    },
    Key {
        name: "asm.cmt.col",
        summary: "column to align comments",
        get: |session| session.cmt_col.to_string(),
        set: |session, value| {
            session.cmt_col = match value.parse::<usize>() {
                Ok(column @ ..=1024) => column,
                _ => return Err(format!("asm.cmt.col takes 0 to 1024, not '{value}'")),
            };
            Ok(())
        },
    },
    Key {
        name: "scr.color",
        summary: "enable colors (0: none, 1: ansi, 2: 256 colors, 3: truecolor)",
        get: |session| session.color.to_string(),
        set: |session, value| {
            // radare2's four levels (`libr/core/cconfig.c:4997`); each is one column of the theme table.
            session.color = match value {
                "0" | "1" | "2" | "3" => value.parse().expect("one digit"),
                _ => return Err(format!("scr.color takes 0 to 3, not '{value}'")),
            };
            Ok(())
        },
    },
    Key {
        name: "scr.utf8",
        summary: "show UTF-8 characters instead of ANSI",
        get: |session| session.utf8.to_string(),
        set: |session, value| {
            session.utf8 = boolean("scr.utf8", value)?;
            Ok(())
        },
    },
];

/// The key spelled `name`.
pub(crate) fn find(name: &str) -> Option<&'static Key> {
    KEYS.iter().find(|key| key.name == name)
}

/// `e`: every key and its value; `e key`: its value; `e key=value`: set it.
pub(crate) fn run(session: &mut Session, argument: &str) -> Result<String, String> {
    let argument = argument.trim();
    if argument.is_empty() {
        return Ok(KEYS
            .iter()
            .map(|key| format!("{} = {}", key.name, (key.get)(session)))
            .collect::<Vec<_>>()
            .join("\n"));
    }
    let (name, value) = match argument.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim())),
        None => (argument, None),
    };
    let key = find(name).ok_or_else(|| format!("Invalid config key {name}"))?;
    match value {
        Some(value) => (key.set)(session, value).map(|()| String::new()),
        None => Ok((key.get)(session)),
    }
}

/// A boolean as radare2 spells one.
fn boolean(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("{name} takes true or false, not '{value}'")),
    }
}
