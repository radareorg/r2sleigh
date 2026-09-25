//! The command surface, spelled the way radare2 spells it.
//!
//! Output follows radare2's layout so the two can be diffed against each other
//! over a corpus. Columns radare2 fills from analysis this engine does not have
//! yet are left out rather than filled with zeroes, so a diff reports a missing
//! column rather than a wrong value.

use crate::grep::Suffix;
use crate::line::{Command, Statement};
use crate::session::Session;
use r2engine::RenderTier;
use r2engine::query::Role;

/// Run one statement: its command, where it asks, then its grep. The answer
/// is the text to print, as radare2 prints it: every line ends in a newline,
/// so an empty line is printed and no line is nothing.
///
/// The statement arrives cut and its grep parsed, so a grep that cannot be
/// honoured was refused before this runs anything. Only a line of the output
/// that radare2's grep would print broken is refused after the command ran;
/// every command that changes anything prints ASCII, so none reaches it.
pub fn run(session: &mut Session, statement: &Statement) -> Result<String, String> {
    let grep = match &statement.grep {
        Some(Suffix::Help) => return Ok(format!("{}\n", crate::grep::help())),
        Some(Suffix::Filter(grep)) => Some(grep),
        None => None,
    };
    let output = match &statement.at {
        Some(address) => elsewhere(session, address, &statement.command)?,
        None => dispatch(session, &statement.command)?,
    };
    Ok(match grep {
        Some(grep) => grep.apply(&output)?,
        None => output,
    })
}

/// `@`: run a command somewhere else and leave the cursor where it was.
fn elsewhere(session: &mut Session, address: &str, command: &Command) -> Result<String, String> {
    let address = parse_number(session, address)?;
    let was = session.addr;
    session.addr = address;
    let answer = dispatch(session, command);
    session.addr = was;
    answer
}

/// What a command prints. `?e` prints its line even when it is empty, as
/// radare2's does; every other command's text is its lines, and an empty text
/// is no line.
fn dispatch(session: &mut Session, command: &Command) -> Result<String, String> {
    let text = match command {
        Command::Echo(line) => return Ok(format!("{line}\n")),
        Command::Write(bytes) => write_text(session, bytes)?,
        Command::Plain { verb, argument } => plain(session, verb, argument)?,
    };
    Ok(if text.is_empty() {
        text
    } else {
        format!("{text}\n")
    })
}

/// A command whose argument is plain text: `?e` and `w` read theirs as the
/// line does, so they are not here.
fn plain(session: &mut Session, verb: &str, argument: &str) -> Result<String, String> {
    match verb {
        "" => Ok(String::new()),
        "q" | "quit" | "exit" => Err("quit".to_owned()),
        "s" => seek(session, argument),
        "i" => info(session),
        "ie" => entries(session),
        "iS" => sections(session),
        "is" => symbols(session),
        "ir" => relocations(session),
        "px" => hexdump(session, argument),
        "pd" => crate::listing::disassemble(session, argument),
        "pdf" => crate::listing::disassemble_function(session, argument),
        "pdd" => decompile(session, argument),
        "pddj" => decompile_json(session, argument),
        "afl" => discovered(session),
        "afi" => crate::function::info(session, argument),
        "afv" => crate::function::variables(session, argument),
        "f" => flags(session),
        "ax" => cross_references(session, argument),
        "axt" => references_to(session, argument),
        "iz" => strings(session),
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

/// An address as radare2 reads one: hex, decimal, or a name `f` lists.
pub(crate) fn parse_number(session: &mut Session, text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(session.addr);
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_err(|_| format!("bad address '{}'", text));
    }
    if let Ok(number) = text.parse::<u64>() {
        return Ok(number);
    }
    session
        .program
        .address_named(text)?
        .ok_or_else(|| format!("unknown address or flag '{}'", text))
}

pub(crate) fn parse_count(argument: &str, default: usize) -> Result<usize, String> {
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
    let image = session.image();
    let arch = image.arch();
    let mut out = String::new();
    out.push_str(&format!("file     {}\n", session.path));
    out.push_str(&format!("format   {:?}\n", image.format()));
    out.push_str(&format!("arch     {}\n", arch.name));
    out.push_str(&format!("bits     {}\n", arch.bits));
    out.push_str(&format!(
        "endian   {}\n",
        match arch.endian {
            r2image::Endian::Little => "little",
            r2image::Endian::Big => "big",
        }
    ));
    out.push_str(&format!("baddr    {:#010x}\n", image.base_address()));
    if let Some(entry) = image
        .entry_points()
        .iter()
        .find(|entry| entry.kind == r2image::EntryKind::Main)
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
        .image()
        .entry_points()
        .iter()
        .filter(|entry| entry.kind == r2image::EntryKind::Main)
    {
        let paddr = file_offset_of(session, entry.vaddr);
        out.push_str(&format!(
            "\n{} {:#010x} {}",
            paddr
                .map(|offset| format!("{:#010x}", offset))
                .unwrap_or_else(|| "----------".to_owned()),
            entry.vaddr,
            match entry.kind {
                r2image::EntryKind::Main => "program",
                r2image::EntryKind::Init => "init",
                r2image::EntryKind::Fini => "fini",
                r2image::EntryKind::Symbol => "symbol",
                r2image::EntryKind::CMain => "main",
                r2image::EntryKind::Declared => "declared",
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
fn discovered(session: &mut Session) -> Result<String, String> {
    let found = session.program.functions()?;
    let mut out = String::from("vaddr      confidence name\n");
    out.push_str(&"-".repeat(46));
    for one in &found {
        // Spelled as a listing spells it, which is how radare2 writes it and
        // what makes the two comparable. The engine keeps the plain name.
        let name = session
            .program
            .names()
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

/// Write text at the cursor, as `w` read it. radare2 writes nothing, and says
/// nothing, when the text is empty (cmd_write.inc.c:1673-1678).
fn write_text(session: &mut Session, bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    patch(session, bytes)
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
        .image_mut()
        .write(addr, bytes)
        .map_err(|error| format!("r2s: {error}"))?;
    Ok(format!("{} bytes at {addr:#x}", bytes.len()))
}

/// Every byte written over the file's own.
fn patches(session: &mut Session) -> Result<String, String> {
    let mut out = String::from("vaddr      byte\n");
    out.push_str(&"-".repeat(16));
    let mut count = 0usize;
    for (vaddr, byte) in session.image().patches() {
        count += 1;
        out.push_str(&format!("\n{vaddr:#010x} {byte:02x}"));
    }
    out.push_str(&format!("\n\n{count} patched bytes"));
    Ok(out)
}

/// Drop every patch, so the image reads as the file does.
fn revert(session: &mut Session) -> Result<String, String> {
    let count = session.image().patches().count();
    session.image_mut().revert();
    Ok(format!("{count} patched bytes reverted"))
}

/// Where each address is named from, how, and on what evidence.
fn cross_references(session: &mut Session, argument: &str) -> Result<String, String> {
    if !argument.trim().is_empty() {
        return Err("r2s: ax takes no argument; use axt <address>".to_owned());
    }
    let index = session.program.references()?.value;
    let mut out = String::from("from       to         role     size support\n");
    out.push_str(&"-".repeat(46));
    for fact in index.facts() {
        let size = match fact.role {
            Role::Read { width } | Role::Write { width } => width.to_string(),
            Role::Call | Role::Jump | Role::Value => "-".to_owned(),
        };
        out.push_str(&format!(
            "\n{:#010x} {:#010x} {} {size:>4} {}",
            fact.from,
            fact.to,
            role(fact.role),
            crate::listing::rung(fact.support)
        ));
    }
    out.push_str(&format!("\n\n{} references", index.facts().len()));
    for (entry, why) in &index.coverage.unread {
        let why = match why {
            r2engine::query::Unread::Refused(refusal) => refusal.to_string(),
            r2engine::query::Unread::NoSsa => "its SSA did not build".to_owned(),
        };
        out.push_str(&format!("\n; {entry:#x} unread: {why}"));
    }
    out.push_str(&coverage(&index.coverage));
    Ok(out)
}

/// A role as radare2 spells a reference's type and permissions.
fn role(role: Role) -> &'static str {
    match role {
        Role::Call => "CALL:--x",
        Role::Jump => "JUMP:--x",
        Role::Read { .. } => "DATA:r--",
        Role::Write { .. } => "DATA:-w-",
        Role::Value => "DATA:---",
    }
}

/// Every place one address is named from, one line per function holding it, as radare2 lays `axt` out.
fn references_to(session: &mut Session, argument: &str) -> Result<String, String> {
    let wanted = parse_number(session, argument)?;
    let index = session.program.references()?.value;
    let names = session.program.names();
    let mut out = String::new();
    let mut count = 0usize;
    for (fact, source) in index.to(wanted) {
        count += 1;
        let text = crate::listing::spelled(&source.line, names);
        for owner in &source.owners {
            out.push_str(&format!(
                "{} {:#x} [{}] {text}\n",
                names.function(*owner),
                fact.from,
                role(fact.role)
            ));
        }
    }
    out.push_str(&format!("\n{count} references to {wanted:#x}"));
    if count == 0 {
        out.push_str(&format!(
            "\n; none within the functions read, which is not proof {wanted:#x} is unreferenced"
        ));
    }
    out.push_str(&coverage(&index.coverage));
    Ok(out)
}

/// What a reference index was read over, as a trailing comment.
fn coverage(coverage: &r2engine::query::Coverage) -> String {
    let read = coverage.read.len();
    if coverage.is_closed() {
        return format!("\n; covers {read} functions, every body walked to its end");
    }
    let indirect = coverage.indirect_count();
    let other = coverage.unresolved_count() - indirect;
    let gaps = [
        (
            indirect,
            "unresolved indirect transfer",
            "unresolved indirect transfers",
        ),
        (
            other,
            "unreadable transfer target",
            "unreadable transfer targets",
        ),
        (coverage.unread.len(), "body unread", "bodies unread"),
    ];
    let gaps = gaps
        .iter()
        .filter(|(count, ..)| *count > 0)
        .map(|&(count, one, many)| format!("{count} {}", if count == 1 { one } else { many }))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\n; covers {read} functions; {gaps} — absence is not proof")
}

/// Every string the data sections hold.
fn strings(session: &mut Session) -> Result<String, String> {
    // The strings are read out of the image, so a patched image has other ones.
    session.program.ensure_current()?;
    let mut out = String::from("vaddr       size string\n");
    out.push_str(&"-".repeat(46));
    let mut count = 0usize;
    for (vaddr, name) in session.program.names().iter() {
        if name.namespace != r2engine::names::Namespace::String {
            continue;
        }
        count += 1;
        out.push_str(&format!("\n{:#010x} {:>5} {}", vaddr, name.size, name.text));
    }
    out.push_str(&format!("\n\n{count} strings"));
    Ok(out)
}

/// Every address this binary has a name for, spelled as radare2 spells it.
fn flags(session: &mut Session) -> Result<String, String> {
    // The linkage stubs are named once there is a decoder to read them with,
    // so asking for the machine first is what makes the listing complete.
    session.program.ensure_current()?;
    let mut out = String::from("vaddr       size name\n");
    out.push_str(&"-".repeat(46));
    for (vaddr, name) in session.program.names().iter() {
        out.push_str(&format!(
            "\n{:#010x} {:>6} {}",
            vaddr,
            name.size,
            name.spelled()
        ));
    }
    out.push_str(&format!("\n\n{} flags", session.program.names().len()));
    Ok(out)
}

fn sections(session: &Session) -> Result<String, String> {
    let mut out = String::from("nth paddr           size vaddr          vsize perm name\n");
    out.push_str(&"-".repeat(70));
    for (index, section) in session.image().sections().iter().enumerate() {
        let permissions = session
            .image()
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
        .image()
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
                r2image::SymbolKind::Function => "FUNC",
                r2image::SymbolKind::Data => "OBJ",
                r2image::SymbolKind::Section => "SECT",
                r2image::SymbolKind::Other => "NOTY",
                r2image::SymbolKind::Mapping(_) => "SPCL",
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
        .image()
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

/// `ir`: the slots the loader fills, and what it fills them with.
fn relocations(session: &Session) -> Result<String, String> {
    let mut out = String::from("vaddr      name\n");
    out.push_str(&"-".repeat(40));
    out.push('\n');
    for relocation in session.image().relocations() {
        out.push_str(&format!(
            "{:#010x} {}\n",
            relocation.vaddr, relocation.symbol
        ));
    }
    Ok(out.trim_end().to_owned())
}

/// The lift tier: the operations Sleigh produced, before any analysis.
fn low_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    session.program.lifted(addr)
}

/// The analysis tier for one function: blocks, phis, operations, edges.
///
/// The renderer's input, printed. A defect in the C is either already here or
/// is the lowering's, and that is the whole reason this exists. Beside the
/// operations, what the renderer decided about each value: the operations
/// alone never answered which variable a value became, or why nothing spells
/// it.
fn medium_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let rendering = session.program.rendered(addr, RenderTier::Values)?;
    let ssa = rendering.prepared.artifact().artifact().function().dump();
    Ok(format!("{ssa}\n{}", rendering.response.output.into_text()))
}

/// The structured tier: the tree the C is generated from.
///
/// Read against `pdd`, this says whether a defect is already in the tree or
/// belongs to the generation below it.
fn high_tier(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let rendering = session.program.rendered(addr, RenderTier::Structured)?;
    Ok(rendering.response.output.into_text())
}

/// `pdd`: decompile the function at the cursor, with no radare2 anywhere.
fn decompile(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let rendering = session.program.rendered(addr, RenderTier::C)?;
    Ok(rendering.response.output.into_text())
}

/// `pddj`: the rendering `pdd` prints, as one object a tool reads.
///
/// The code is a translation unit that compiles on its own, with where each
/// line came from, what each name is, where each outside name resolves in the
/// program, and what became of every obligation. It is the same rendering, so
/// the two cannot disagree.
fn decompile_json(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let rendering = session.program.rendered(addr, RenderTier::C)?;
    let name = session
        .program
        .names()
        .of(addr)
        .map_or_else(|| format!("fcn.{addr:08x}"), r2engine::names::Name::spelled);
    serde_json::to_string(&rendering.answer(&name, addr)).map_err(|error| error.to_string())
}

/// `pddo`: what became of every obligation the function's source imposes.
///
/// `pdd` says what the C is; this says what the C owes and whether it paid.
/// What the analysis could not read is part of what the rendering owes: a
/// call to a callee nothing proved renders from the call site alone.
fn obligations(session: &mut Session, argument: &str) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let rendering = session.program.rendered(addr, RenderTier::C)?;
    let Some(ledger) = rendering.response.obligation_ledger.as_ref() else {
        return Ok(
            "no obligation ledger: the function did not reach native rendering\n".to_owned(),
        );
    };
    let mut out = format!("{}\n", ledger.report());
    if !rendering.prepared.unread().is_empty() {
        out.push_str("\ncallees not read\n");
    }
    for callee in rendering.prepared.unread() {
        out.push_str(&format!("  {callee}\n"));
    }
    Ok(out)
}

fn file_offset_of(session: &Session, vaddr: u64) -> Option<u64> {
    let segment = session.image().segment_at(vaddr)?;
    let offset_in_segment = vaddr - segment.vaddr;
    (offset_in_segment < segment.file_size).then(|| segment.file_offset + offset_in_segment)
}
