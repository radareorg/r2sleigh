//! The command surface, spelled the way radare2 spells it.
//!
//! Output follows radare2's layout so the two can be diffed against each other
//! over a corpus. Columns radare2 fills from analysis this engine does not have
//! yet are left out rather than filled with zeroes, so a diff reports a missing
//! column rather than a wrong value.

use crate::session::Session;

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
        "pdd" => decompile(session, argument),
        "afl" => discovered(session),
        "f" => flags(session),
        "pdil" => low_tier(session, argument),
        "pdim" => medium_tier(session, argument),
        "pdih" => high_tier(session, argument),
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
            .image
            .entry_points()
            .iter()
            .find(|entry| entry.kind == r2image::EntryKind::Main)
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
    let image = &session.image;
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
        .image
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
    session.ensure_machine()?;
    let mut seeds = stated_seeds(&session.image);
    // A linkage stub is a function the format declares: the loader's own
    // table says where each one begins, which is why they are stated rather
    // than inferred. These were decoded already and read only for naming.
    seeds.extend(
        session
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
        out.push_str(&format!(
            "\n{:#010x} {:<10} {}",
            one.address,
            match one.confidence {
                r2engine::discovery::Confidence::Stated => "stated",
                r2engine::discovery::Confidence::Called => "called",
                r2engine::discovery::Confidence::Reached => "reached",
            },
            one.name.as_deref().unwrap_or("-")
        ));
    }
    out.push_str(&format!("\n\n{} functions", found.len()));
    Ok(out)
}

/// Every address this binary has a name for, spelled as radare2 spells it.
#[cfg(feature = "sleigh")]
fn flags(session: &mut Session) -> Result<String, String> {
    // The linkage stubs are named once there is a decoder to read them with,
    // so asking for the machine first is what makes the listing complete.
    session.ensure_machine()?;
    let mut out = String::from("vaddr       size name\n");
    out.push_str(&"-".repeat(46));
    for (vaddr, name) in session.names.iter() {
        out.push_str(&format!(
            "\n{:#010x} {:>6} {}",
            vaddr,
            name.size,
            name.spelled()
        ));
    }
    out.push_str(&format!("\n\n{} flags", session.names.len()));
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
fn stated_seeds(image: &r2image::Image) -> Vec<(u64, r2engine::discovery::Confidence)> {
    use r2engine::discovery::Confidence;
    image
        .entry_points()
        .iter()
        .map(|entry| entry.vaddr)
        .chain(
            image
                .symbols()
                .iter()
                .filter(|symbol| symbol.defined && symbol.kind == r2image::SymbolKind::Function)
                .map(|symbol| symbol.vaddr),
        )
        .map(|vaddr| (vaddr, Confidence::Stated))
        .collect()
}

fn sections(session: &Session) -> Result<String, String> {
    let mut out = String::from("nth paddr           size vaddr          vsize perm name\n");
    out.push_str(&"-".repeat(70));
    for (index, section) in session.image.sections().iter().enumerate() {
        let permissions = session
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
                r2image::SymbolKind::Function => "FUNC",
                r2image::SymbolKind::Data => "OBJ",
                r2image::SymbolKind::Section => "SECT",
                r2image::SymbolKind::Other => "NOTY",
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
    for relocation in session.image.relocations() {
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
        let ssa = r2engine::native::prepared(target, program, addr)
            .map(|artifact| artifact.artifact().function().dump())
            .map_err(|refusal: r2engine::native::NativeRefusal| refusal.to_string())?;
        // Beside the operations, what the renderer decided about each value.
        // The operations alone never answered the question that cost the most
        // time: which variable a value became, or why nothing spells it.
        let values = r2engine::native::values(target, program, addr)
            .map(|response| response.output)
            .unwrap_or_else(|refusal| format!("values refused: {refusal}\n"));
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
        r2engine::native::structured(target, program, addr)
            .map(|response| response.output)
            .map_err(|refusal| refusal.to_string())
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
        r2engine::native::decompile(target, program, addr)
            .map(|response| response.output)
            .map_err(|refusal| refusal.to_string())
    })
}

/// Open the binary the way the engine wants it, and ask one question.
///
/// Every tier is asked for through here, so the machine, the conventions, the
/// compiler specification and the image are assembled once.
#[cfg(feature = "sleigh")]
fn with_native<T>(
    session: &mut Session,
    addr: u64,
    ask: impl FnOnce(&r2engine::native::NativeTarget<'_>, &OpenImage<'_>) -> Result<T, String>,
) -> Result<T, String> {
    session.ensure_machine()?;
    let machine = session
        .machine_at(addr)
        .ok_or("no Sleigh specification for this architecture")?;

    let bits = session.image.arch().bits;
    let conventions = r2abi::Conventions::for_arch(machine.arch.name.as_str(), bits)
        .ok_or_else(|| format!("no calling conventions for {} {}", machine.arch.name, bits))?;
    let convention = conventions
        .default_convention()
        .ok_or("the convention data names no default")?;
    let compiler = r2abi::CompilerSpec::parse(machine.compiler_spec);

    // The format says which platform's own declarations apply: `_Exit` is
    // declared by the platform, not by the table every target shares.
    let mut prototypes = r2abi::Prototypes::embedded_for(match session.image.format() {
        r2image::Format::Elf => r2abi::Platform::Linux,
        r2image::Format::MachO => r2abi::Platform::Darwin,
        _ => r2abi::Platform::Unknown,
    });
    // What the binary's own debug information says beats the shared table: the
    // table describes what a library is expected to look like, and this
    // describes what this one is.
    prototypes.declare(session.image.debug_prototypes().prototypes());
    let target = r2engine::native::NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    // The specification names the register; the architecture says where it
    // lives, and the lift spells writes to it in those coordinates.
    let link = compiler.return_address.as_ref().and_then(|name| {
        machine
            .arch
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .map(|register| r2il::Varnode {
                space: r2il::SpaceId::Register,
                offset: register.offset,
                size: register.size,
                meta: None,
            })
    });
    let program = OpenImage {
        image: &session.image,
        link,
        imports: &session.imports,
        slots: &session.slots,
        defined: &session.defined,
        names: &session.names,
    };
    ask(&target, &program)
}

/// The open binary, as the engine asks about it.
#[cfg(feature = "sleigh")]
struct OpenImage<'a> {
    image: &'a r2image::Image,
    /// The register a call returns through, as the compiler specification
    /// names it, resolved to the storage the lift spells.
    link: Option<r2il::Varnode>,
    imports: &'a std::collections::BTreeMap<u64, String>,
    slots: &'a std::collections::BTreeMap<u64, String>,
    defined: &'a std::collections::BTreeMap<u64, crate::session::Definition>,
    names: &'a r2engine::names::NameDb,
}

#[cfg(feature = "sleigh")]
impl r2ssa::body::Program for OpenImage<'_> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.image
            .read_upto(vaddr, max)
            .map(std::borrow::Cow::into_owned)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        // A stub is a function of the program's as much as a body is: control
        // that reaches one has left the function it came from.
        self.imports.contains_key(&vaddr)
            || self
                .defined
                .get(&vaddr)
                .is_some_and(|definition| definition.function)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.link.clone()
    }
}

#[cfg(feature = "sleigh")]
impl r2engine::native::Program for OpenImage<'_> {
    fn name_at(&self, vaddr: u64) -> Option<String> {
        // The plain name, with no namespace on it: this keys the prototype
        // table and spells a call, where a listing asks the same entry for
        // `sym.imp.printf`. A slot the loader fills is not in the table --
        // only a stub is an address the program transfers to -- so it is
        // asked for separately.
        self.names
            .text_at(vaddr)
            .map(str::to_owned)
            .or_else(|| self.slots.get(&vaddr).cloned())
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.image.sections().iter().any(|section| {
            section.loaded
                && !section.is_code
                && vaddr >= section.vaddr
                && vaddr - section.vaddr < section.vsize
        })
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.imports
            .get(&vaddr)
            .or_else(|| self.slots.get(&vaddr))
            .cloned()
    }
}

#[cfg(feature = "sleigh")]
fn disassemble(session: &mut Session, argument: &str) -> Result<String, String> {
    /// Sleigh fetches a whole window whatever the instruction needs.
    const DECODE_WINDOW: usize = 16;

    let count = parse_count(argument, 16)?;
    let start = session.addr;
    session.ensure_machine()?;
    let machine = session
        .machine_at(start)
        .ok_or("no decoder for this architecture")?;
    let decoder = &machine.disasm;
    // Bytes that do not decode are stepped over by the width the machine
    // addresses instructions at. Stepping one byte put the next instruction at
    // an odd address on ARM, where no instruction can begin, and every line
    // after it decoded from the wrong place.
    let step = u64::from(machine.arch.alignment.max(1));

    let mut out = String::new();
    let mut pc = start;
    for index in 0..count {
        let Some(window) = session.image.read_upto(pc, DECODE_WINDOW) else {
            if index == 0 {
                return Err(format!("nothing mapped at {:#x}", start));
            }
            break;
        };
        let available = window.len();
        let mut fetch = window.into_owned();
        fetch.resize(DECODE_WINDOW, 0);

        let (mnemonic, size) = match decoder.disasm_native(&fetch, pc) {
            Ok(decoded) => decoded,
            Err(_) => {
                out.push_str(&format!(
                    "            {:#010x}      {:<14} invalid\n",
                    pc,
                    format!("{:02x}", fetch[0])
                ));
                pc += step;
                continue;
            }
        };
        if size == 0 || size > available {
            out.push_str(&format!(
                "            {:#010x}      {:<14} invalid\n",
                pc,
                format!("{:02x}", fetch[0])
            ));
            pc += step;
            continue;
        }

        let mut hex: String = fetch[..size].iter().map(|b| format!("{:02x}", b)).collect();
        // radare2 caps the byte column at twelve characters and marks the cut.
        if hex.len() > 12 {
            hex.truncate(10);
            hex.push_str("..");
        }
        out.push_str(&format!(
            "            {:#010x}      {:<14} {}\n",
            pc,
            hex,
            crate::names::spell(
                &session.names,
                &r2_mnemonic(&mnemonic, session.image.arch().name),
            )
        ));
        pc += size as u64;
    }
    Ok(out.trim_end().to_owned())
}

/// Radare2 spells an instruction lowercase, with a space after each comma and
/// no `#` before an immediate, where Sleigh keeps the assembler's own prefix.
#[cfg(feature = "sleigh")]
fn r2_mnemonic(text: &str, arch: &str) -> String {
    let lowered = text.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut chars = lowered.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '#' {
            continue;
        }
        out.push(c);
        if c == ',' && chars.peek().is_some_and(|next| *next != ' ') {
            out.push(' ');
        }
    }
    // Sleigh writes the x86 memory-operand size as `dword ptr [..]` and a
    // negative displacement as `+ -0x4`; radare2 writes `dword [..]` and
    // `- 0x4`. Same operand, and the two spellings are only spellings.
    let out = out.replace(" ptr [", " [").replace("+ -", "- ");
    let out = bare_effective_address(&out);
    if arch == "ARM" {
        arm_role_registers(&out)
    } else {
        out
    }
}

/// radare2 spells the three ARM registers that have a job by that job.
///
/// The procedure call standard gives r11, r12, r13 and r14 the roles of frame
/// pointer, intra-procedure scratch, stack pointer and link register, and
/// every ARM disassembler but Sleigh's prints the role.
#[cfg(feature = "sleigh")]
fn arm_role_registers(text: &str) -> String {
    const ROLES: [(&str, &str); 5] = [
        ("r11", "fp"),
        ("r12", "ip"),
        ("r13", "sp"),
        ("r14", "lr"),
        ("r15", "pc"),
    ];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('r') {
        out.push_str(&rest[..start]);
        let taken = ROLES.iter().find(|(spelling, _)| {
            rest[start..].starts_with(spelling)
                && !rest[start + spelling.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
        });
        match taken {
            Some((spelling, role)) => {
                out.push_str(role);
                rest = &rest[start + spelling.len()..];
            }
            None => {
                out.push('r');
                rest = &rest[start + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `lea` loads an address rather than what is there, and radare2 writes that
/// address without the brackets that would say it was read.
///
/// Only where the brackets hold one thing: `lea r8, [0x8f0]` is that address,
/// while `lea rax, [rbp - 0x4]` is a computation and keeps its shape.
#[cfg(feature = "sleigh")]
fn bare_effective_address(text: &str) -> String {
    let Some(rest) = text.strip_prefix("lea ") else {
        return text.to_owned();
    };
    let Some(open) = rest.find('[') else {
        return text.to_owned();
    };
    let Some(close) = rest.rfind(']') else {
        return text.to_owned();
    };
    let inside = &rest[open + 1..close];
    if close + 1 != rest.len() || inside.contains(' ') || inside.is_empty() {
        return text.to_owned();
    }
    format!("lea {}{}", &rest[..open], inside)
}

fn file_offset_of(session: &Session, vaddr: u64) -> Option<u64> {
    let segment = session.image.segment_at(vaddr)?;
    let offset_in_segment = vaddr - segment.vaddr;
    (offset_in_segment < segment.file_size).then(|| segment.file_offset + offset_in_segment)
}
