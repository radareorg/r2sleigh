//! The command surface, spelled the way radare2 spells it.
//!
//! Output follows radare2's layout so the two can be diffed against each other
//! over a corpus. Columns radare2 fills from analysis this engine does not have
//! yet are left out rather than filled with zeroes, so a diff reports a missing
//! column rather than a wrong value.

use crate::session::Session;
#[cfg(feature = "sleigh")]
use r2engine::program::OpenProgram;

pub fn run(session: &mut Session, line: &str) -> Result<String, String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(String::new());
    }

    // `~` greps the output of the command to its left, as radare2 does.
    if let Some((command, pattern)) = line.split_once('~') {
        let output = run(session, command)?;
        let (pattern, invert) = match pattern.strip_prefix('!') {
            Some(rest) => (rest, true),
            None => (pattern, false),
        };
        let kept: Vec<&str> = output
            .lines()
            .filter(|candidate| candidate.contains(pattern) != invert)
            .collect();
        return Ok(kept.join("\n"));
    }

    // `@` runs a command somewhere else and leaves the cursor where it was.
    if let Some((command, address)) = line.split_once('@') {
        let address = parse_number(session, address)?;
        let was = session.addr;
        session.addr = address;
        let answer = run(session, command);
        session.addr = was;
        return answer;
    }

    let (verb, argument) = split_verb(line);
    match verb {
        "q" | "quit" | "exit" => Err("quit".to_owned()),
        "?e" => Ok(argument.to_owned()),
        "s" => seek(session, argument),
        "i" => info(session),
        "ie" => entries(session),
        "iS" => sections(session),
        "is" => symbols(session),
        "ir" => relocations(session),
        "px" => hexdump(session, argument),
        "pd" => disassemble(session, argument),
        "pdf" => disassemble_function(session, argument),
        "pdd" => decompile(session, argument),
        "afl" => discovered(session),
        "f" => flags(session),
        "ax" => cross_references(session, argument),
        "axt" => references_to(session, argument),
        "iz" => strings(session),
        "w" => write_text(session, argument),
        "wx" => write_hex(session, argument),
        "wc" => patches(session),
        "wcr" => revert(session),
        "pdil" => low_tier(session, argument),
        "pdim" => medium_tier(session, argument),
        "pdih" => high_tier(session, argument),
        "pddo" => obligations(session, argument),
        other => Err(format!("unknown command '{}'", other)),
    }
}

/// Split a command from its argument, honouring radare2's optional space.
fn split_verb(line: &str) -> (&str, &str) {
    let end = line.find(|c: char| c.is_whitespace()).unwrap_or(line.len());
    (&line[..end], line[end..].trim())
}

fn parse_number(session: &Session, text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(session.addr);
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_err(|_| format!("bad address '{}'", text));
    }
    // `s entry0` on a file with no declared entry keeps the session's start.
    if text == "entry0" {
        return Ok(session
            .program
            .image
            .entry_points()
            .iter()
            .find(|entry| entry.kind == r2engine::program::EntryKind::Main)
            .map(|entry| entry.vaddr)
            .unwrap_or(session.addr));
    }
    text.parse::<u64>()
        .map_err(|_| format!("bad address '{}'", text))
}

fn parse_count(argument: &str, default: usize) -> Result<usize, String> {
    if argument.is_empty() {
        return Ok(default);
    }
    argument
        .parse::<usize>()
        .map_err(|_| format!("bad count '{}'", argument))
}

fn seek(session: &mut Session, argument: &str) -> Result<String, String> {
    if argument.is_empty() {
        return Ok(format!("{:#x}", session.addr));
    }
    session.addr = parse_number(session, argument)?;
    Ok(String::new())
}

fn info(session: &Session) -> Result<String, String> {
    let image = &session.program.image;
    let arch = image.arch();
    let mut out = String::new();
    out.push_str(&format!("file     {}\n", session.path));
    out.push_str(&format!("format   {:?}\n", image.format()));
    out.push_str(&format!("arch     {}\n", arch.name));
    out.push_str(&format!("bits     {}\n", arch.bits));
    out.push_str(&format!(
        "endian   {}\n",
        match arch.endian {
            r2engine::program::Endian::Little => "little",
            r2engine::program::Endian::Big => "big",
        }
    ));
    out.push_str(&format!("baddr    {:#010x}\n", image.base_address()));
    if let Some(entry) = image
        .entry_points()
        .iter()
        .find(|entry| entry.kind == r2engine::program::EntryKind::Main)
    {
        out.push_str(&format!("entry    {:#010x}", entry.vaddr));
    } else {
        out.push_str("entry    none");
    }
    Ok(out)
}

fn entries(session: &Session) -> Result<String, String> {
    let mut out = String::from("paddr      vaddr      type\n");
    out.push_str(&"-".repeat(32));
    for entry in session
        .program
        .image
        .entry_points()
        .iter()
        .filter(|entry| entry.kind == r2engine::program::EntryKind::Main)
    {
        let paddr = file_offset_of(session, entry.vaddr);
        out.push_str(&format!(
            "\n{} {:#010x} {}",
            paddr
                .map(|offset| format!("{:#010x}", offset))
                .unwrap_or_else(|| "----------".to_owned()),
            entry.vaddr,
            match entry.kind {
                r2engine::program::EntryKind::Main => "program",
                r2engine::program::EntryKind::Init => "init",
                r2engine::program::EntryKind::Fini => "fini",
                r2engine::program::EntryKind::Symbol => "symbol",
                r2engine::program::EntryKind::CMain => "main",
                r2engine::program::EntryKind::Declared => "declared",
            }
        ));
    }
    Ok(out)
}

/// Every function the program has, with how far each answer can be trusted.
///
/// The list was the symbol table, so a stripped binary had none -- while its
/// entry point, its initialiser array and a linkage stub per import were
/// already parsed and only the program entry was read. Discovery starts from
/// all of them and closes over what the bodies call.
#[cfg(feature = "sleigh")]
fn discovered(session: &mut Session) -> Result<String, String> {
    // The machine first: the stub table is decoded when it loads, and reading
    // it before then is reading an empty map.
    session.program.ensure_current()?;
    let mut seeds = stated_seeds(&session.program.image);
    // A linkage stub is a function the format declares: the loader's own
    // table says where each one begins, which is why they are stated rather
    // than inferred. These were decoded already and read only for naming.
    seeds.extend(
        session
            .program
            .imports
            .keys()
            .map(|vaddr| (*vaddr, r2engine::discovery::Confidence::Stated)),
    );
    let addr = session.addr;
    let found = with_native(session, addr, |target, program| {
        Ok(r2engine::discovery::functions(program, seeds, |entry| {
            r2engine::native::transfers(target, program, entry)
        }))
    })?;
    let mut out = String::from("vaddr      confidence name\n");
    out.push_str(&"-".repeat(46));
    for one in &found {
        // Spelled as a listing spells it, which is how radare2 writes it and
        // what makes the two comparable. The engine keeps the plain name.
        let name = session
            .program
            .names
            .of(one.address)
            .map(r2engine::names::Name::spelled)
            .or_else(|| one.name.clone())
            .unwrap_or_else(|| "-".to_owned());
        out.push_str(&format!(
            "\n{:#010x} {:<10} {name}",
            one.address,
            match one.confidence {
                r2engine::discovery::Confidence::Stated => "stated",
                r2engine::discovery::Confidence::Called => "called",
                r2engine::discovery::Confidence::Handed => "handed",
                r2engine::discovery::Confidence::Reached => "reached",
            },
        ));
    }
    out.push_str(&format!("\n\n{} functions", found.len()));
    Ok(out)
}

/// Write text at the cursor.
fn write_text(session: &mut Session, argument: &str) -> Result<String, String> {
    patch(session, argument.as_bytes())
}

/// Write bytes spelled in hex at the cursor.
fn write_hex(session: &mut Session, argument: &str) -> Result<String, String> {
    let digits = argument.replace(' ', "");
    if !digits.len().is_multiple_of(2) {
        return Err("r2s: a byte is two hex digits".to_owned());
    }
    let bytes = digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "r2s: not hex".to_owned())?;
            u8::from_str_radix(text, 16).map_err(|_| format!("r2s: '{text}' is not hex"))
        })
        .collect::<Result<Vec<u8>, String>>()?;
    patch(session, &bytes)
}

/// Put bytes in the patch layer at the cursor.
///
/// Nothing reaches the file. The analysis of a patched program is the analysis
/// of the program as patched, because the engine keys a prepared function by
/// the bytes it captured and patched bytes are a different key.
fn patch(session: &mut Session, bytes: &[u8]) -> Result<String, String> {
    let addr = session.addr;
    session
        .program
        .image
        .write(addr, bytes)
        .map_err(|error| format!("r2s: {error}"))?;
    Ok(format!("{} bytes at {addr:#x}", bytes.len()))
}

/// Every byte written over the file's own.
fn patches(session: &mut Session) -> Result<String, String> {
    let mut out = String::from("vaddr      byte\n");
    out.push_str(&"-".repeat(16));
    let mut count = 0usize;
    for (vaddr, byte) in session.program.image.patches() {
        count += 1;
        out.push_str(&format!("\n{vaddr:#010x} {byte:02x}"));
    }
    out.push_str(&format!("\n\n{count} patched bytes"));
    Ok(out)
}

/// Drop every patch, so the image reads as the file does.
fn revert(session: &mut Session) -> Result<String, String> {
    let count = session.program.image.patches().count();
    session.program.image.revert();
    Ok(format!("{count} patched bytes reverted"))
}

/// Every reference the program makes, from every function discovery believes.
///
/// A cross-reference is a query over the lift, not a scan: a body that names
/// an address names it in an operation, and every function is asked once.
#[cfg(feature = "sleigh")]
fn references(session: &mut Session) -> Result<Vec<r2engine::DataRefFact>, String> {
    session.program.ensure_current()?;
    let mut seeds = stated_seeds(&session.program.image);
    seeds.extend(
        session
            .program
            .imports
            .keys()
            .map(|vaddr| (*vaddr, r2engine::discovery::Confidence::Stated)),
    );
    let addr = session.addr;
    with_native(session, addr, |target, program| {
        // Discovery walks every body it believes, and the reverse index wants
        // what that same walk already saw. Asking twice walked and lifted each
        // function again for the half the first ask threw away.
        let mut seen = std::collections::BTreeMap::new();
        let found = r2engine::discovery::functions(program, seeds, |entry| {
            let survey = r2engine::native::surveyed(target, program, entry)?;
            seen.insert(entry, survey.data_refs);
            Some(survey.transfers)
        });
        let mut refs = found
            .iter()
            .filter_map(|one| seen.remove(&one.address))
            .flatten()
            .collect::<Vec<_>>();
        refs.sort_unstable();
        refs.dedup();
        Ok(refs)
    })
}

/// Where each address is named from.
#[cfg(feature = "sleigh")]
fn cross_references(session: &mut Session, argument: &str) -> Result<String, String> {
    if !argument.trim().is_empty() {
        return Err("r2s: ax takes no argument; use axt <address>".to_owned());
    }
    let refs = references(session)?;
    let mut out = String::from("from       to         kind\n");
    out.push_str(&"-".repeat(34));
    for fact in &refs {
        out.push_str(&format!(
            "\n{:#010x} {:#010x} {}",
            fact.from,
            fact.to,
            fact.kind.as_str()
        ));
    }
    out.push_str(&format!("\n\n{} references", refs.len()));
    Ok(out)
}

/// Every place one address is named from.
#[cfg(feature = "sleigh")]
fn references_to(session: &mut Session, argument: &str) -> Result<String, String> {
    let wanted = parse_number(session, argument)?;
    let refs = references(session)?;
    let mut out = String::new();
    let mut count = 0usize;
    for fact in refs.iter().filter(|fact| fact.to == wanted) {
        count += 1;
        out.push_str(&format!("{:#010x} {}\n", fact.from, fact.kind.as_str()));
    }
    out.push_str(&format!("\n{count} references to {wanted:#x}"));
    Ok(out)
}

/// Every string the data sections hold.
#[cfg(feature = "sleigh")]
fn strings(session: &mut Session) -> Result<String, String> {
    // The strings are read out of the image, so a patched image has other ones.
    session.program.ensure_current()?;
    let mut out = String::from("vaddr       size string\n");
    out.push_str(&"-".repeat(46));
    let mut count = 0usize;
    for (vaddr, name) in session.program.names.iter() {
        if name.namespace != r2engine::names::Namespace::String {
            continue;
        }
        count += 1;
        out.push_str(&format!("\n{:#010x} {:>5} {}", vaddr, name.size, name.text));
    }
    out.push_str(&format!("\n\n{count} strings"));
    Ok(out)
}

#[cfg(not(feature = "sleigh"))]
fn cross_references(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature, so nothing can be lifted".to_owned())
}

#[cfg(not(feature = "sleigh"))]
fn references_to(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature, so nothing can be lifted".to_owned())
}

#[cfg(not(feature = "sleigh"))]
fn strings(_session: &mut Session) -> Result<String, String> {
    Err("r2s: built without the sleigh feature, so the data cannot be read".to_owned())
}

/// Every address this binary has a name for, spelled as radare2 spells it.
#[cfg(feature = "sleigh")]
fn flags(session: &mut Session) -> Result<String, String> {
    // The linkage stubs are named once there is a decoder to read them with,
    // so asking for the machine first is what makes the listing complete.
    session.program.ensure_current()?;
    let mut out = String::from("vaddr       size name\n");
    out.push_str(&"-".repeat(46));
    for (vaddr, name) in session.program.names.iter() {
        out.push_str(&format!(
            "\n{:#010x} {:>6} {}",
            vaddr,
            name.size,
            name.spelled()
        ));
    }
    out.push_str(&format!("\n\n{} flags", session.program.names.len()));
    Ok(out)
}

#[cfg(not(feature = "sleigh"))]
fn flags(_session: &mut Session) -> Result<String, String> {
    Err("r2s: built without the sleigh feature, so the stubs cannot be read".to_owned())
}

#[cfg(not(feature = "sleigh"))]
fn discovered(_session: &mut Session) -> Result<String, String> {
    Err("r2s: built without the sleigh feature, so discovery cannot walk".to_owned())
}

/// What the image states about where code begins.
///
/// Every one of these was already computed and only the program's own entry
/// point was read.
#[cfg(feature = "sleigh")]
fn stated_seeds(image: &r2engine::program::Image) -> Vec<(u64, r2engine::discovery::Confidence)> {
    use r2engine::discovery::Confidence;
    image
        .entry_points()
        .iter()
        .map(|entry| entry.vaddr)
        .chain(
            image
                .symbols()
                .iter()
                .filter(|symbol| {
                    symbol.defined && symbol.kind == r2engine::program::SymbolKind::Function
                })
                .map(|symbol| symbol.vaddr),
        )
        .map(|vaddr| (vaddr, Confidence::Stated))
        .collect()
}

fn sections(session: &Session) -> Result<String, String> {
    let mut out = String::from("nth paddr           size vaddr          vsize perm name\n");
    out.push_str(&"-".repeat(70));
    for (index, section) in session.program.image.sections().iter().enumerate() {
        let permissions = session
            .program
            .image
            .segment_at(section.vaddr)
            .map(|segment| segment.permissions)
            .unwrap_or_default();
        out.push_str(&format!(
            "\n{:<3} {:#010x} {:>10x} {:#010x} {:>10x} -{}{}{} {}",
            index,
            section.file_offset,
            section.file_size,
            section.vaddr,
            section.vsize,
            if permissions.read { 'r' } else { '-' },
            if permissions.write { 'w' } else { '-' },
            if permissions.execute { 'x' } else { '-' },
            section.name
        ));
    }
    Ok(out)
}

fn symbols(session: &Session) -> Result<String, String> {
    let mut out = String::from("nth vaddr      size type name\n");
    out.push_str(&"-".repeat(60));
    for (index, symbol) in session
        .program
        .image
        .symbols()
        .iter()
        .filter(|symbol| symbol.defined)
        .enumerate()
    {
        out.push_str(&format!(
            "\n{:<3} {:#010x} {:>4} {:<4} {}",
            index,
            symbol.vaddr,
            symbol.size,
            match symbol.kind {
                r2engine::program::SymbolKind::Function => "FUNC",
                r2engine::program::SymbolKind::Data => "OBJ",
                r2engine::program::SymbolKind::Section => "SECT",
                r2engine::program::SymbolKind::Other => "NOTY",
            },
            symbol.name
        ));
    }
    Ok(out)
}

fn hexdump(session: &Session, argument: &str) -> Result<String, String> {
    let count = parse_count(argument, 64)?;
    let addr = session.addr;
    let bytes = session
        .program
        .image
        .read_upto(addr, count)
        .ok_or_else(|| format!("nothing mapped at {:#x}", addr))?;

    // The header counts columns from the address's own low byte, two hex
    // digits wide, and the legend starts at its low nibble rather than at zero.
    let low = addr as u8;
    let mut out = String::from("- offset -  ");
    for column in 0..8u8 {
        out.push_str(&format!(
            "{:2X}{:2X} ",
            low.wrapping_add(column * 2),
            low.wrapping_add(column * 2 + 1)
        ));
    }
    out.push(' ');
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for index in 0..16usize {
        out.push(DIGITS[(index + (addr as usize & 0xf)) % 16] as char);
    }

    for (row, chunk) in bytes.chunks(16).enumerate() {
        let row_addr = addr + (row * 16) as u64;
        out.push_str(&format!("\n{:#010x}  ", row_addr));
        for pair in 0..8 {
            match (chunk.get(pair * 2), chunk.get(pair * 2 + 1)) {
                (Some(high), Some(low)) => out.push_str(&format!("{:02x}{:02x} ", high, low)),
                (Some(high), None) => out.push_str(&format!("{:02x}   ", high)),
                _ => out.push_str("     "),
            }
        }
        out.push(' ');
        for byte in chunk {
            out.push(if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            });
        }
    }
    Ok(out)
}

#[cfg(not(feature = "sleigh"))]
fn disassemble(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("built without the sleigh feature, so pd cannot decode".to_owned())
}

/// `ir`: the slots the loader fills, and what it fills them with.
fn relocations(session: &Session) -> Result<String, String> {
    let mut out = String::from("vaddr      name\n");
    out.push_str(&"-".repeat(40));
    out.push('\n');
    for relocation in session.program.image.relocations() {
        out.push_str(&format!(
            "{:#010x} {}\n",
            relocation.vaddr, relocation.symbol
        ));
    }
    Ok(out.trim_end().to_owned())
}

#[cfg(not(feature = "sleigh"))]
fn decompile(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("built without the sleigh feature, so pdd cannot decompile".to_owned())
}

/// The lift tier: the operations Sleigh produced, before any analysis.
#[cfg(feature = "sleigh")]
fn low_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    with_native(session, addr, |target, program| {
        r2engine::native::lifted(target, program, addr).map_err(|refusal| refusal.to_string())
    })
}

#[cfg(not(feature = "sleigh"))]
fn low_tier(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature".to_owned())
}

/// The analysis tier for one function: blocks, phis, operations, edges.
///
/// The renderer's input, printed. A defect in the C is either already here or
/// is the lowering's, and that is the whole reason this exists.
#[cfg(feature = "sleigh")]
fn medium_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    with_native(session, addr, |target, program| {
        let prepared = program
            .analysed(target, addr)
            .map_err(|refusal: r2engine::native::NativeRefusal| refusal.to_string())?;
        let ssa = prepared.artifact().artifact().function().dump();
        // Beside the operations, what the renderer decided about each value.
        // The operations alone never answered the question that cost the most
        // time: which variable a value became, or why nothing spells it.
        let values = r2engine::native::rendered(
            target,
            addr,
            r2engine::RenderTier::Values,
            &prepared,
            program.control(),
        )
        .output
        .into_text();
        Ok(format!("{ssa}\n{values}"))
    })
}

#[cfg(not(feature = "sleigh"))]
fn medium_tier(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature".to_owned())
}

/// The structured tier: the tree the C is generated from.
///
/// Read against `pdd`, this says whether a defect is already in the tree or
/// belongs to the generation below it.
#[cfg(feature = "sleigh")]
fn high_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    with_native(session, addr, |target, program| {
        let prepared = program.analysed(target, addr).map_err(|r| r.to_string())?;
        Ok(r2engine::native::rendered(
            target,
            addr,
            r2engine::RenderTier::Structured,
            &prepared,
            program.control(),
        )
        .output
        .into_text())
    })
}

#[cfg(not(feature = "sleigh"))]
fn high_tier(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature".to_owned())
}

/// `pdd`: decompile the function at the cursor, with no radare2 anywhere.
#[cfg(feature = "sleigh")]
fn decompile(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    with_native(session, addr, |target, program| {
        let prepared = program.analysed(target, addr).map_err(|r| r.to_string())?;
        Ok(r2engine::native::rendered(
            target,
            addr,
            r2engine::RenderTier::C,
            &prepared,
            program.control(),
        )
        .output
        .into_text())
    })
}

/// `pddo`: what became of every obligation the function's source imposes.
///
/// `pdd` says what the C is; this says what the C owes and whether it paid.
/// Until now the breakdown existed only behind an environment variable, so a
/// refusal could be counted but not explained.
#[cfg(feature = "sleigh")]
fn obligations(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    with_native(session, addr, |target, program| {
        let prepared = program.analysed(target, addr).map_err(|r| r.to_string())?;
        let response = r2engine::native::rendered(
            target,
            addr,
            r2engine::RenderTier::C,
            &prepared,
            program.control(),
        );
        // What the analysis could not read is part of what the rendering owes:
        // a call to a callee nothing proved renders from the call site alone.
        let unread = match prepared.unread() {
            [] => String::new(),
            missing => {
                missing
                    .iter()
                    .fold(String::from("\ncallees not read\n"), |mut out, callee| {
                        out.push_str(&format!("  {callee}\n"));
                        out
                    })
            }
        };
        response.obligation_ledger.as_ref().map_or_else(
            || Ok("no obligation ledger: the function did not reach native rendering\n".to_owned()),
            |ledger| Ok(format!("{}\n{unread}", ledger.report())),
        )
    })
}

#[cfg(not(feature = "sleigh"))]
fn obligations(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature".to_owned())
}

/// Ask one question of the open program.
///
/// Every tier is asked for through here, so the machine, the conventions and
/// the compiler specification are assembled once and shared.
#[cfg(feature = "sleigh")]
fn with_native<T>(
    session: &mut Session,
    addr: u64,
    ask: impl FnOnce(&r2engine::native::NativeTarget<'_>, &OpenProgram) -> Result<T, String>,
) -> Result<T, String> {
    session.program.ensure_assembled(addr)?;
    let program = &session.program;
    ask(&program.target(addr)?, program)
}

#[cfg(feature = "sleigh")]
fn disassemble(session: &mut Session, argument: &str) -> Result<String, String> {
    use r2engine::query::{Listing, Memory, listing};

    let count = parse_count(argument, 16)?;
    let start = session.addr;
    session.program.ensure_current()?;
    let session: &Session = session;

    let answered = r2engine::query::Answered {
        decoders: &session.program,
        memory: Memory {
            program: &session.program,
            endian: session.program.endian(),
        },
        facts: None,
    };
    let answer = listing(
        &answered,
        Listing { start, count },
        r2engine::query::Work::BlockLocal,
        session.program.revision(),
    );
    if let r2engine::query::Completion::Unmapped { at } = answer.completion
        && answer.value.is_empty()
    {
        return Err(format!("nothing mapped at {at:#x}"));
    }
    let mut out = String::new();
    for line in &answer.value {
        out.push_str(&listed(session, line));
    }
    Ok(out.trim_end().to_owned())
}

/// One listing line, in the columns radare2 writes them in.
#[cfg(feature = "sleigh")]
fn listed(session: &Session, line: &r2engine::query::Line) -> String {
    let mut hex: String = line.bytes.iter().map(|b| format!("{:02x}", b)).collect();
    // radare2 caps the byte column at twelve characters and marks the cut.
    if hex.len() > 12 {
        hex.truncate(10);
        hex.push_str("..");
    }
    let text = match line.decoded() {
        false => "invalid".to_owned(),
        true => spelled(line, &session.program.names),
    };
    format!(
        "            {:#010x}      {:<14} {}{}\n",
        line.address,
        hex,
        text,
        held(session, line)
    )
}

#[cfg(feature = "sleigh")]
/// One line, with a name written wherever a number is one.
///
/// Substitution is by span rather than by value. Scanning the finished text
/// for hexadecimal runs cannot tell an address from a displacement that
/// happens to equal one, which is how a `-0x4` became a symbol's name, and it
/// cannot tell two operands of one instruction apart when both hold the same
/// number. A span says which number is being claimed about, and the sign it
/// was written with is part of it: a negative literal names no address however
/// well its magnitude matches.
fn spelled(line: &r2engine::query::Line, names: &r2engine::names::NameDb) -> String {
    let Some(syntax) = &line.syntax else {
        return String::new();
    };
    let mut body = syntax.body.clone();
    // Rewritten from the end, so an earlier span's offsets stay true.
    for number in syntax.numbers.iter().rev() {
        let Ok(value) = u64::try_from(number.value) else {
            continue;
        };
        // Only where the engine says the instruction uses that number as an
        // address. Naming every number the table happens to know spelled
        // `adrp x17, reloc.humanize_number` over a page base the next
        // instruction was about to move fifty bytes past.
        if claim(line, *number).is_none() {
            continue;
        }
        let Some(name) = names.of(value) else {
            continue;
        };
        body.replace_range(number.start..number.end, &name.spelled());
    }
    match body.is_empty() {
        true => syntax.mnemonic.clone(),
        false => format!("{} {}", syntax.mnemonic, body),
    }
}

/// `pdf`: the function at the cursor, listed with what the engine proved.
///
/// The listing radare2 cannot write. `pd` stays cheap and claims only what one
/// instruction and its neighbours show; this pays for the walk and the
/// preparation, and every line can then carry the range its value was proved
/// to lie in.
#[cfg(feature = "sleigh")]
fn disassemble_function(session: &mut Session, argument: &str) -> Result<String, String> {
    use r2engine::query::{Listing, Memory, listing};

    let addr = parse_number(session, argument)?;
    session.program.ensure_assembled(addr)?;
    let session: &Session = session;
    let target = session.program.target(addr)?;
    let prepared = session
        .program
        .analysed(&target, addr)
        .map_err(|refusal| refusal.to_string())?;
    // The function is exactly what the analysis covers, so its extent is the
    // artifact's own rather than a guess from the next symbol's address.
    let function = prepared.artifact().artifact().function();
    let (start, end) = function
        .blocks()
        .iter()
        .fold((u64::MAX, 0), |(low, high), block| {
            (
                low.min(block.addr),
                high.max(block.addr + u64::from(block.size)),
            )
        });
    if start == u64::MAX {
        return Err(format!("no blocks at {addr:#x}"));
    }
    let answered = r2engine::query::Answered {
        decoders: &session.program,
        memory: Memory {
            program: &session.program,
            endian: session.program.endian(),
        },
        facts: Some(prepared.artifact().artifact()),
    };
    let answer = listing(
        &answered,
        Listing {
            start,
            // One line per instruction, and no instruction is shorter than a
            // byte, so the extent bounds the count.
            count: usize::try_from(end - start).unwrap_or(usize::MAX),
        },
        r2engine::query::Work::Function,
        session.program.revision(),
    );
    let mut out = String::new();
    for line in answer.value.iter().take_while(|line| line.address < end) {
        out.push_str(&listed(session, line));
    }
    Ok(out.trim_end().to_owned())
}

#[cfg(not(feature = "sleigh"))]
fn disassemble_function(_session: &mut Session, _argument: &str) -> Result<String, String> {
    Err("r2s: built without the sleigh feature".to_owned())
}

/// How well supported a claim about this number is, where anything claims it.
///
/// A number no annotation claims is a coincidence: the table knows an address
/// of that value and nothing in the instruction says this is one.
#[cfg(feature = "sleigh")]
fn claim(
    line: &r2engine::query::Line,
    number: r2engine::NumberSpan,
) -> Option<r2engine::query::Support> {
    line.annotations
        .iter()
        .filter(|annotation| annotation.operand == Some(number))
        .map(|annotation| annotation.support)
        .min()
}

/// What this revision holds where the instruction reads, as a trailing note.
///
/// The value is stated beside the read rather than substituted into it. A pool
/// load used to be spelled `ldr r3, sym.foo`, which says the load returns that
/// address; all this program states is that the word there is that address
/// now, and the instruction text stays what the machine encodes.
#[cfg(feature = "sleigh")]
fn held(session: &Session, line: &r2engine::query::Line) -> String {
    let notes = line
        .annotations
        .iter()
        .filter_map(|annotation| note(session, line.address, annotation.kind))
        .collect::<Vec<_>>();
    match notes.is_empty() {
        true => String::new(),
        false => format!(" ; {}", notes.join(" ")),
    }
}

/// One annotation, as a reader reads it.
#[cfg(feature = "sleigh")]
fn note(session: &Session, at: u64, kind: r2engine::query::AnnotationKind) -> Option<String> {
    match kind {
        r2engine::query::AnnotationKind::Holds {
            address,
            width,
            value,
        } => {
            let named = session
                .program
                .names
                .of(value)
                .map(r2engine::names::Name::spelled);
            Some(format!(
                "[{address:#x}:{width}]={value:#x}{}",
                named.map(|name| format!(" {name}")).unwrap_or_default()
            ))
        }
        // What the analysis proved the value lies in, wherever it is live. A
        // single value is written as itself; a range says so. The machine's
        // words only: every flag a line sets is proved to hold nought or one,
        // which is true and says nothing.
        r2engine::query::AnnotationKind::Bounds {
            storage, low, high, ..
        } => session
            .program
            .is_machine_word(at, storage)
            .then(|| session.program.spell_storage(at, storage))
            .flatten()
            .map(|name| match low == high {
                true => format!("{name} = {low:#x}"),
                false => format!("{name} in [{low:#x}, {high:#x}]"),
            }),
        _ => None,
    }
}

fn file_offset_of(session: &Session, vaddr: u64) -> Option<u64> {
    let segment = session.program.image.segment_at(vaddr)?;
    let offset_in_segment = vaddr - segment.vaddr;
    (offset_in_segment < segment.file_size).then(|| segment.file_offset + offset_in_segment)
}

#[cfg(all(test, feature = "sleigh"))]
mod tests {
    use super::spelled;
    use r2engine::discovery::Confidence;
    use r2engine::names::{Name, NameDb, Namespace};
    use r2engine::query::Line;

    fn db() -> NameDb {
        let mut db = NameDb::new();
        db.insert(
            0x100000340,
            Name {
                text: "_add_two".to_owned(),
                namespace: Namespace::Symbol,
                size: 0,
                confidence: Confidence::Stated,
            },
        );
        db.insert(
            0x4,
            Name {
                text: "_nl_current".to_owned(),
                namespace: Namespace::Label,
                size: 0,
                confidence: Confidence::Stated,
            },
        );
        db
    }

    /// A line whose every number the instruction is said to transfer to.
    fn line(mnemonic: &str, body: &str) -> Line {
        claiming(mnemonic, body, true)
    }

    /// The same, with nothing claiming any of its numbers.
    fn unclaimed(mnemonic: &str, body: &str) -> Line {
        claiming(mnemonic, body, false)
    }

    fn claiming(mnemonic: &str, body: &str, claimed: bool) -> Line {
        let numbers = r2engine::number_spans(body);
        let annotations = match claimed {
            false => Vec::new(),
            true => numbers
                .iter()
                .filter_map(|number| {
                    Some(r2engine::query::Annotation {
                        kind: r2engine::query::AnnotationKind::Target {
                            address: u64::try_from(number.value).ok()?,
                            call: true,
                        },
                        support: r2engine::query::Support::Decoded,
                        operand: Some(*number),
                    })
                })
                .collect(),
        };
        Line {
            address: 0x1000,
            bytes: vec![0x90],
            syntax: Some(r2engine::Syntax {
                mnemonic: mnemonic.to_owned(),
                body: body.to_owned(),
                size: 1,
                numbers,
            }),
            annotations,
        }
    }

    #[test]
    fn a_named_address_is_spelled_by_its_name() {
        assert_eq!(
            spelled(&line("call", "0x100000340"), &db()),
            "call sym._add_two"
        );
    }

    #[test]
    fn an_address_with_no_name_stays_a_number() {
        assert_eq!(
            spelled(&line("call", "0x100000341"), &db()),
            "call 0x100000341"
        );
        assert_eq!(spelled(&line("sub", "rsp, 0x10"), &db()), "sub rsp, 0x10");
    }

    #[test]
    fn a_negative_displacement_is_not_an_address() {
        // The defect this replaced: a `-0x4` written against a register came
        // out as the name of whatever sits at address four.
        assert_eq!(
            spelled(&line("ldr", "r3, [sp, -0x4]"), &db()),
            "ldr r3, [sp, -0x4]"
        );
    }

    #[test]
    fn each_operand_holding_one_number_is_written_once() {
        // Substituting by value rewrote the whole line at once; by span, each
        // occurrence is its own decision and the count comes out right.
        assert_eq!(
            spelled(&line("mov", "0x100000340, [0x100000340]"), &db()),
            "mov sym._add_two, [sym._add_two]"
        );
    }

    #[test]
    fn a_number_nothing_claims_is_a_coincidence_and_stays_a_number() {
        // `adrp x17, 0x100008000` computes a page base that happens to equal a
        // named address; the instruction after it moves fifty bytes past.
        assert_eq!(
            spelled(&unclaimed("adrp", "x17, 0x100000340"), &db()),
            "adrp x17, 0x100000340"
        );
    }

    #[test]
    fn a_binary_with_no_names_changes_nothing() {
        assert_eq!(
            spelled(&line("call", "0x1030"), &NameDb::new()),
            "call 0x1030"
        );
    }
}
