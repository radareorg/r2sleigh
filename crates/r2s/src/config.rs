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
        name: "scr.color",
        summary: "enable colors (0: none, 1: ansi)",
        get: |session| u8::from(session.color).to_string(),
        set: |session, value| {
            session.color = match value {
                "0" => false,
                "1" => true,
                // The palette is the sixteen ANSI colours; a deeper level would
                // be accepted and then painted as this one.
                "2" | "3" => return Err("scr.color: only 1, ansi colour, is painted".to_owned()),
                _ => return Err(format!("scr.color takes 0 or 1, not '{value}'")),
            };
            Ok(())
        },
    },
    Key {
        name: "dec.pipeline",
        summary: "which decompiler writes pdd (legacy, staged)",
        get: |session| match session.tier {
            r2engine::RenderTier::Staged => "staged".to_owned(),
            _ => "legacy".to_owned(),
        },
        set: |session, value| {
            session.tier = match value {
                "legacy" => r2engine::RenderTier::C,
                "staged" => r2engine::RenderTier::Staged,
                _ => {
                    return Err(format!(
                        "dec.pipeline takes legacy or staged, not '{value}'"
                    ));
                }
            };
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
