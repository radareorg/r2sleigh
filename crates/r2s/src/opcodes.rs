//! `ao` and `aoj`: radare2's field names where the fact is the same, then the lift's own
//! `reads`, `writes` and `il`; no `type`, `esil` or `cycles`, which the engine does not state.

use crate::commands::{parse_count, parse_number};
use crate::session::Session;
use r2engine::NoteJson;
use r2engine::query::{Completion, Instruction, Line, Listing, Register, Stop};

/// `ao [n]`: each instruction's facts, one `key: value` line each.
pub(crate) fn text(session: &mut Session, argument: &str) -> Result<String, String> {
    let mut out = String::new();
    for one in read(session, argument, true)? {
        out.push_str(&format!("address: {:#x}\n", one.address));
        out.push_str(&format!("opcode: {}\n", one.opcode));
        out.push_str(&format!("disasm: {}\n", one.disasm));
        out.push_str(&format!("mnemonic: {}\n", one.mnemonic));
        out.push_str(&format!("bytes: {}\n", one.bytes));
        out.push_str(&format!("size: {}\n", one.size));
        match &one.registers {
            Ok((reads, writes)) => {
                out.push_str(&listed("reads", reads));
                out.push_str(&listed("writes", writes));
            }
            Err(refused) => out.push_str(&format!("refused: {refused}\n")),
        }
        if let Some(il) = &one.il {
            out.push_str("il:\n");
            for (index, operation) in il.iter().enumerate() {
                out.push_str(&format!("  {index:3}: {operation}\n"));
            }
        }
        if !one.notes.is_empty() {
            out.push_str("notes:\n");
            out.extend(one.notes.iter().map(explained));
        }
    }
    Ok(out.trim_end().to_owned())
}

/// One note in full: the line `pdf` prints, then its basis, grade and premises, or its refusal.
fn explained(note: &NoteJson) -> String {
    let mut out = format!("  {} {}\n", note.mark, note.text);
    match (&note.refusal, note.basis, note.grade) {
        (Some(refusal), ..) => out.push_str(&format!("    refused: {}\n", refusal.reason)),
        (None, Some(basis), Some(grade)) => {
            let premises = match note.premises.is_empty() {
                true => "none".to_owned(),
                false => note.premises.join(" "),
            };
            out.push_str(&format!("    basis: {basis}\n    grade: {grade}\n"));
            out.push_str(&format!("    premises: {premises}\n"));
        }
        (None, ..) => {}
    }
    if let Some(citation) = &note.citation {
        out.push_str(&format!("    citation: {citation}\n"));
    }
    out
}

/// One `key: a b c` line, with no space after the key when the list is empty.
fn listed(key: &str, names: &[String]) -> String {
    match names.is_empty() {
        true => format!("{key}:\n"),
        false => format!("{key}: {}\n", names.join(" ")),
    }
}

/// `aoj [n]`: the same facts, one object per instruction.
pub(crate) fn json(session: &mut Session, argument: &str) -> Result<String, String> {
    // No notes: they read the holder's analysis, and `aoj` stays instruction-cheap (D582's stop).
    let rows = read(session, argument, false)?
        .into_iter()
        .map(|one| {
            let mut row = serde_json::json!({
                "addr": one.address,
                "opcode": one.opcode,
                "disasm": one.disasm,
                "mnemonic": one.mnemonic,
                "bytes": one.bytes,
                "size": one.size,
            });
            match one.registers {
                Ok((reads, writes)) => {
                    row["reads"] = reads.into();
                    row["writes"] = writes.into();
                }
                Err(refused) => row["refused"] = refused.into(),
            }
            if let Some(il) = one.il {
                row["il"] = il.into();
            }
            row
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&rows).map_err(|error| error.to_string())
}

/// `pdfj`: the function `pdf` lists, one object: each line's address, bytes, text and notes.
pub(crate) fn function_json(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let listing = session.program.function_listing(addr)?;
    let lines = &listing.lines.value;
    if lines.is_empty() {
        return Err(format!("no blocks at {addr:#x}"));
    }
    let names = session.program.names();
    let name = names.of(addr).map(|name| name.spelled());
    let next = crate::listing::next_calls(lines);
    let rows = (lines.iter().zip(next))
        .map(|(line, next)| {
            serde_json::json!({
                "addr": line.address,
                "bytes": hex(&line.bytes),
                "disasm": crate::listing::spelled(line, &names, session.demangle),
                "notes": noted(session, line, next),
            })
        })
        .collect::<Vec<_>>();
    let function = serde_json::json!({ "addr": addr, "name": name, "lines": rows });
    serde_json::to_string(&function).map_err(|error| error.to_string())
}

/// The line's notes as `pdf` spells them, each with its standing as typed fields.
fn noted(session: &Session, line: &Line, next_call: Option<u64>) -> Vec<NoteJson> {
    let notes = crate::listing::notes(session, line, next_call).into_iter();
    notes
        .map(|note| match note.annotation {
            Some(annotation) => NoteJson::of(annotation, note.text),
            None => NoteJson::fact("noreturn", note.confidence, note.text),
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One instruction, spelled.
struct Spelled {
    address: u64,
    opcode: String,
    disasm: String,
    mnemonic: String,
    bytes: String,
    size: usize,
    /// The registers it reads and writes, or why they are not stated.
    registers: Result<(Vec<String>, Vec<String>), String>,
    /// Its operations as `pdil` prints them, absent where it did not lift.
    il: Option<Vec<String>>,
    /// What `pdf` notes on the line, from the listing of the function holding it.
    notes: Vec<NoteJson>,
}

/// `n` instructions from the seek, radare2's default of one; with `notes`, each line's `pdf` notes.
fn read(session: &mut Session, argument: &str, notes: bool) -> Result<Vec<Spelled>, String> {
    let count = parse_count(argument, 1)?;
    let answer = session.program.instructions(Listing {
        start: session.addr,
        stop: Stop::After(count),
    })?;
    if let Completion::Unmapped { at } = answer.completion
        && answer.value.is_empty()
    {
        return Err(format!("nothing mapped at {at:#x}"));
    }
    let names = session.program.names();
    let held = match notes {
        true => holder_lines(session, session.addr),
        false => Vec::new(),
    };
    let next = crate::listing::next_calls(&held);
    let mut spelled_all = Vec::new();
    for one in &answer.value {
        let at = held.binary_search_by_key(&one.line.address, |line| line.address);
        let (line, next_call) = match at {
            Ok(at) => (&held[at], next[at]),
            Err(_) => (&one.line, None),
        };
        let notes = match notes {
            true => noted(session, line, next_call),
            false => Vec::new(),
        };
        spelled_all.push(Spelled {
            notes,
            ..spelled(one, &names)
        });
    }
    Ok(spelled_all)
}

/// The lines `pdf` lists for the first function holding `address`, sorted: where `ao` reads its
/// notes. None outside every function, or where its listing refuses.
fn holder_lines(session: &mut Session, address: u64) -> Vec<Line> {
    let holders = session
        .program
        .functions_holding(address)
        .unwrap_or_default();
    let Some(entry) = holders.first() else {
        return Vec::new();
    };
    let listing = session.program.function_listing(*entry);
    let mut lines = listing
        .map(|listing| listing.lines.value)
        .unwrap_or_default();
    lines.sort_by_key(|line| line.address);
    lines
}

fn spelled(one: &Instruction, names: &r2engine::names::NameDb) -> Spelled {
    let line = &one.line;
    let (opcode, mnemonic) = match &line.syntax {
        Some(syntax) if syntax.body.is_empty() => {
            (syntax.mnemonic.clone(), syntax.mnemonic.clone())
        }
        Some(syntax) => (
            format!("{} {}", syntax.mnemonic, syntax.body),
            syntax.mnemonic.clone(),
        ),
        None => ("invalid".to_owned(), "invalid".to_owned()),
    };
    let disasm = match line.decoded() {
        true => crate::listing::spelled(line, names, false),
        false => opcode.clone(),
    };
    let named = |registers: &[Register]| registers.iter().map(register).collect();
    let (registers, il) = match &one.semantics {
        Ok(semantics) => (
            semantics
                .registers
                .as_ref()
                .map(|registers| (named(&registers.reads), named(&registers.writes)))
                .map_err(ToString::to_string),
            Some(semantics.operations.clone()),
        ),
        Err(unlifted) => (Err(unlifted.to_string()), None),
    };
    Spelled {
        address: line.address,
        opcode,
        disasm,
        mnemonic,
        bytes: hex(&line.bytes),
        size: line.bytes.len(),
        registers,
        il,
        notes: Vec::new(),
    }
}

/// A register by the listing's name, or by its storage as the low tier spells one the specification does not name.
fn register(register: &Register) -> String {
    register.name.clone().unwrap_or_else(|| {
        format!(
            "reg:{:#x}[{}]",
            register.storage.offset, register.storage.size
        )
    })
}
