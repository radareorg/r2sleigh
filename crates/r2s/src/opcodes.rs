//! `ao` and `aoj`: radare2's field names where the fact is the same, then the lift's own
//! `reads`, `writes` and `il`; no `type`, `esil` or `cycles`, which the engine does not state.

use crate::commands::parse_count;
use crate::session::Session;
use r2engine::query::{Completion, Instruction, Listing, Register, Stop};

/// `ao [n]`: each instruction's facts, one `key: value` line each.
pub(crate) fn text(session: &mut Session, argument: &str) -> Result<String, String> {
    let mut out = String::new();
    for one in read(session, argument)? {
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
    }
    Ok(out.trim_end().to_owned())
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
    let rows = read(session, argument)?
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
}

/// `n` instructions from the seek, radare2's default of one.
fn read(session: &mut Session, argument: &str) -> Result<Vec<Spelled>, String> {
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
    Ok(answer
        .value
        .iter()
        .map(|one| spelled(one, &names))
        .collect())
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
        bytes: line
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        size: line.bytes.len(),
        registers,
        il,
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
