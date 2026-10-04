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
    // A grep reads the text, and an escape in it would split what it matches.
    session.grepped = grep.is_some();
    let output = match &statement.at {
        Some(address) => elsewhere(session, address, &statement.command),
        None => dispatch(session, &statement.command),
    };
    session.grepped = false;
    let output = output?;
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

/// Who a verb is for. Maintainer verbs print the engine's tiers and are
/// listed apart, as AGENTS.md's command surface says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Public,
    Maintainer,
}

/// What a verb is given past its name: help spells it, and a completer will
/// offer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arguments {
    None,
    /// An address or a name `f` lists, the seek when absent.
    Address,
    /// How many, from the seek.
    Count,
    /// Text the line reads with its quotes and escapes (`?e`, `w`).
    Text,
    /// Hex bytes.
    Bytes,
    /// A configuration key, and the value to set it to.
    Key,
}

impl Arguments {
    const fn spelled(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Address => "[addr]",
            Self::Count => "[n]",
            Self::Text => "<text>",
            Self::Bytes => "<hex>",
            Self::Key => "[key[=value]]",
        }
    }
}

type Handler = fn(&mut Session, &str) -> Result<String, String>;

/// One verb of the command surface: every name it answers to, what it takes,
/// what it does, and the function that does it.
///
/// The table below is the surface. Dispatch reads it, `?` and `verb?` print
/// it, and a completer offers it, so none of the three can name a verb the
/// others do not know. `?e` and `w` read their argument as the line does and
/// are parsed there; they are here so help lists them, with no handler.
pub(crate) struct Verb {
    pub names: &'static [&'static str],
    pub arguments: Arguments,
    pub summary: &'static str,
    pub tier: Tier,
    run: Option<Handler>,
}

impl Verb {
    pub(crate) fn name(&self) -> &'static str {
        self.names[0]
    }

    fn usage(&self) -> String {
        let arguments = self.arguments.spelled();
        if arguments.is_empty() {
            self.name().to_owned()
        } else {
            format!("{} {arguments}", self.name())
        }
    }
}

macro_rules! verb {
    ([$($name:literal),+], $arguments:ident, $tier:ident, $summary:literal, $run:expr) => {
        Verb {
            names: &[$($name),+],
            arguments: Arguments::$arguments,
            summary: $summary,
            tier: Tier::$tier,
            run: $run,
        }
    };
}

/// Every verb, in the order help lists them.
pub(crate) const VERBS: &[Verb] = &[
    verb!(
        ["q", "quit", "exit"],
        None,
        Public,
        "quit",
        Some(|_, _| Err("quit".to_owned()))
    ),
    verb!(["?e"], Text, Public, "print the text", None),
    verb!(
        ["s"],
        Address,
        Public,
        "seek to an address, or print the seek",
        Some(seek)
    ),
    verb!(
        ["e"],
        Key,
        Public,
        "read or set a configuration key",
        Some(crate::config::run)
    ),
    verb!(
        ["i"],
        None,
        Public,
        "what the binary is",
        Some(|session, _| info(session))
    ),
    verb!(
        ["ie"],
        None,
        Public,
        "entry points",
        Some(|session, _| entries(session, false))
    ),
    verb!(
        ["iee"],
        None,
        Public,
        "entry points and initialisers",
        Some(|session, _| entries(session, true))
    ),
    verb!(
        ["iS"],
        None,
        Public,
        "sections",
        Some(|session, _| Ok(sections(session).spelled()))
    ),
    verb!(
        ["is"],
        None,
        Public,
        "symbols",
        Some(|session, _| symbols(session).map(|table| table.spelled()))
    ),
    verb!(
        ["ir"],
        None,
        Public,
        "relocations",
        Some(|session, _| Ok(relocations(session).spelled()))
    ),
    verb!(
        ["iz"],
        None,
        Public,
        "strings in data sections",
        Some(|session, _| strings(session).map(|table| table.spelled()))
    ),
    verb!(
        ["izz"],
        None,
        Public,
        "strings anywhere in the file",
        Some(|session, _| every_string(session))
    ),
    verb!(
        ["px"],
        Count,
        Public,
        "hexdump",
        Some(|session, argument| hexdump(session, argument))
    ),
    verb!(
        ["pd"],
        Count,
        Public,
        "disassemble",
        Some(crate::listing::disassemble)
    ),
    verb!(
        ["pdf"],
        Address,
        Public,
        "disassemble a function",
        Some(crate::listing::disassemble_function)
    ),
    verb!(
        ["pdd"],
        Address,
        Public,
        "decompile a function",
        Some(decompile)
    ),
    verb!(
        ["pddj"],
        Address,
        Public,
        "decompile a function as JSON",
        Some(decompile_json)
    ),
    verb!(
        ["afl"],
        None,
        Public,
        "list functions",
        Some(|session, _| discovered(session).map(|table| table.spelled()))
    ),
    verb!(
        ["aflj"],
        None,
        Public,
        "list functions as JSON",
        Some(|session, _| discovered_json(session))
    ),
    verb!(
        ["afi"],
        Address,
        Public,
        "what a function is",
        Some(crate::function::info)
    ),
    verb!(
        ["afb"],
        Address,
        Public,
        "a function's basic blocks",
        Some(crate::function::blocks)
    ),
    verb!(
        ["afv"],
        Address,
        Public,
        "a function's arguments and variables",
        Some(crate::function::variables)
    ),
    verb!(
        ["agf"],
        Address,
        Public,
        "a function's control-flow graph",
        Some(crate::visual::agf)
    ),
    verb!(
        ["f"],
        None,
        Public,
        "flags",
        Some(|session, _| flags(session))
    ),
    verb!(
        ["ax"],
        Address,
        Public,
        "references from an address",
        Some(cross_references)
    ),
    verb!(
        ["axt"],
        Address,
        Public,
        "references to an address",
        Some(references_to)
    ),
    verb!(
        ["/as"],
        None,
        Public,
        "system calls",
        Some(|session, _| syscalls(session))
    ),
    verb!(["w"], Text, Public, "write text at the seek", None),
    verb!(
        ["wx"],
        Bytes,
        Public,
        "write hex bytes at the seek",
        Some(write_hex)
    ),
    verb!(
        ["wc"],
        None,
        Public,
        "list the writes",
        Some(|session, _| patches(session))
    ),
    verb!(
        ["wcr"],
        None,
        Public,
        "revert every write",
        Some(|session, _| revert(session))
    ),
    verb!(
        ["V"],
        None,
        Public,
        "visual mode",
        Some(|session, _| crate::visual::open(session))
    ),
    verb!(
        ["pdil"],
        Address,
        Maintainer,
        "the low IL tier",
        Some(low_tier)
    ),
    verb!(
        ["pdim"],
        Address,
        Maintainer,
        "the medium IL tier",
        Some(medium_tier)
    ),
    verb!(
        ["pdih"],
        Address,
        Maintainer,
        "the high IL tier",
        Some(high_tier)
    ),
    verb!(
        ["pddo"],
        Address,
        Maintainer,
        "a function's source obligations",
        Some(obligations)
    ),
];

/// The verb a name names.
pub(crate) fn find(name: &str) -> Option<&'static Verb> {
    VERBS.iter().find(|verb| verb.names.contains(&name))
}

/// `?`: every verb, public ones first, as radare2 lays out its help.
fn help() -> String {
    let width = VERBS
        .iter()
        .map(|verb| verb.usage().len())
        .max()
        .unwrap_or(0);
    let mut out = String::from("Usage: [cmd][~grep][@addr]  append ? to a command for its usage");
    for (tier, heading) in [(Tier::Public, ""), (Tier::Maintainer, "\nMaintainer:")] {
        out.push_str(heading);
        for verb in VERBS.iter().filter(|verb| verb.tier == tier) {
            out.push_str(&format!("\n| {:width$}  {}", verb.usage(), verb.summary));
        }
    }
    out
}

/// `verb?`: one verb's usage, and the other names it answers to.
fn usage(verb: &Verb) -> String {
    let mut out = format!("Usage: {}  {}", verb.usage(), verb.summary);
    if verb.names.len() > 1 {
        out.push_str(&format!("\naliases: {}", verb.names[1..].join(" ")));
    }
    out
}

/// A command whose argument is plain text: `?e` and `w` read theirs as the
/// line does, so they never reach here.
fn plain(session: &mut Session, verb: &str, argument: &str) -> Result<String, String> {
    if verb.is_empty() {
        return Ok(String::new());
    }
    if verb == "?" {
        return Ok(help());
    }
    if let Some(named) = verb.strip_suffix('?').and_then(find) {
        return Ok(usage(named));
    }
    match find(verb).and_then(|verb| verb.run) {
        Some(run) => run(session, argument),
        None => Err(format!("unknown command '{verb}'")),
    }
}

/// `/as`: every instruction that enters the kernel, and the call it makes,
/// one per line as radare2 writes them: `0x00401016 write`. A number the
/// kernel's table does not name is written as the number, and one the body
/// does not prove as `?`, rather than as a guess.
fn syscalls(session: &mut Session) -> Result<String, String> {
    Ok(session
        .program
        .syscalls()?
        .into_iter()
        .map(|call| {
            let what = match (call.name, call.number) {
                (Some(name), _) => name,
                (None, Some(number)) => number.to_string(),
                (None, None) => "?".to_owned(),
            };
            format!("{:#010x} {what}", call.address)
        })
        .collect::<Vec<_>>()
        .join("\n"))
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

/// `ie` and `iee`: where the loader starts the program, or what it runs
/// before and after it, as radare2 lays them out.
///
/// radare2 splits them: `ie` is the program's entry, `iee` the functions an
/// initialiser or terminator array names. `phaddr` and `vhaddr` are where the
/// container states each: the header field, or the array slot.
fn entries(session: &Session, initialisers: bool) -> Result<String, String> {
    let mut out = String::from("paddr      vaddr      phaddr     vhaddr     type\n");
    out.push_str(&"-".repeat(48));
    let spelled = |value: Option<u64>| {
        value.map_or_else(|| "----------".to_owned(), |value| format!("{value:#010x}"))
    };
    for entry in session.image().entry_points() {
        let kind = match entry.kind {
            r2image::EntryKind::Main if !initialisers => "program",
            r2image::EntryKind::Init if initialisers => "init",
            r2image::EntryKind::Fini if initialisers => "fini",
            r2image::EntryKind::Preinit if initialisers => "preinit",
            _ => continue,
        };
        out.push_str(&format!(
            "\n{} {:#010x} {} {} {kind}",
            spelled(file_offset_of(session, entry.vaddr)),
            entry.vaddr,
            spelled(entry.stated_at.map(|at| at.offset)),
            spelled(entry.stated_at.and_then(|at| at.vaddr)),
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
pub(crate) fn discovered(session: &mut Session) -> Result<Table, String> {
    // radare2's layout, with no header: `addr nbbs size name`, so the two
    // diff line for line. How sure discovery is moved to `aflj`.
    let mut table = Table::default();
    for row in listed_functions(session)? {
        table.row(
            Some(row.address),
            format!(
                "{:#010x} {:>4} {:>6} {}",
                row.address, row.blocks, row.size, row.name
            ),
        );
    }
    Ok(table)
}

/// `aflj`: the same rows as JSON objects, with radare2's keys and the reason
/// discovery believes each one.
fn discovered_json(session: &mut Session) -> Result<String, String> {
    let rows = listed_functions(session)?
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "addr": row.address,
                "name": row.name,
                "size": row.size,
                "nbbs": row.blocks,
                "confidence": row.confidence,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&rows).map_err(|error| error.to_string())
}

/// One row of `afl`.
struct ListedFunction {
    address: u64,
    blocks: usize,
    size: u64,
    name: String,
    confidence: String,
}

/// Every function discovery found, with the blocks and span its walk traced.
fn listed_functions(session: &mut Session) -> Result<Vec<ListedFunction>, String> {
    let found = session.program.functions()?;
    let extents = session.program.function_extents()?;
    Ok(found
        .iter()
        .map(|one| {
            let extent = extents.get(&one.address);
            ListedFunction {
                address: one.address,
                blocks: extent.map_or(0, |extent| extent.blocks),
                size: extent.map_or(0, |extent| extent.bytes),
                // Spelled as a listing spells it, which is how radare2 writes
                // it and what makes the two comparable.
                name: session
                    .program
                    .names()
                    .of(one.address)
                    .map(r2engine::names::Name::spelled)
                    .or_else(|| one.name.clone())
                    .unwrap_or_else(|| format!("fcn.{:08x}", one.address)),
                confidence: one.confidence.to_string(),
            }
        })
        .collect())
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
    Ok(references_table(session, wanted)?.spelled())
}

/// Every reference to `wanted`, a row per referring function, each about the
/// address the reference is made from.
pub(crate) fn references_table(session: &mut Session, wanted: u64) -> Result<Table, String> {
    let index = session.program.references()?.value;
    let names = session.program.names();
    let mut table = Table::default();
    let mut count = 0usize;
    for (fact, source) in index.to(wanted) {
        count += 1;
        let text = match &source.line.syntax {
            Some(_) => crate::listing::spelled(&source.line, names),
            // A word in data, which the loader fills with the address: spelled as radare2 spells a pointer-sized datum.
            None => format!("{} {wanted:#010x}", datum(session)),
        };
        // A source in no function is radare2's `(nofunc)`.
        let owners = match source.owners.is_empty() {
            true => vec!["(nofunc)".to_owned()],
            false => source
                .owners
                .iter()
                .map(|owner| names.function(*owner))
                .collect(),
        };
        for owner in owners {
            table.row(
                Some(fact.from),
                format!("{owner} {:#x} [{}] {text}", fact.from, role(fact.role)),
            );
        }
    }
    // A blank line between the rows and the count, where there are rows.
    if !table.rows.is_empty() {
        table.foot.push('\n');
    }
    table
        .foot
        .push_str(&format!("\n{count} references to {wanted:#x}"));
    if count == 0 {
        table.foot.push_str(&format!(
            "\n; none within the functions read, which is not proof {wanted:#x} is unreferenced"
        ));
    }
    table.foot.push_str(&coverage(&index.coverage));
    Ok(table)
}

/// A listing as a command prints it: header lines, then a row per thing
/// listed with the address the row is about, where it is about one, then
/// whatever follows the rows. The visual mode lists the same rows and seeks
/// to their addresses, so it reads no address back out of the text.
#[derive(Debug, Default)]
pub(crate) struct Table {
    head: Vec<String>,
    pub(crate) rows: Vec<(Option<u64>, String)>,
    foot: String,
}

impl Table {
    fn headed(head: impl IntoIterator<Item = String>) -> Self {
        Self {
            head: head.into_iter().collect(),
            ..Self::default()
        }
    }

    fn row(&mut self, address: Option<u64>, text: String) {
        self.rows.push((address, text));
    }

    /// The text the command prints.
    pub(crate) fn spelled(&self) -> String {
        let mut lines = self.head.iter().map(String::as_str).collect::<Vec<_>>();
        lines.extend(self.rows.iter().map(|(_, text)| text.as_str()));
        let mut out = lines.join("\n");
        out.push_str(&self.foot);
        out
    }
}

/// How radare2 spells a pointer-sized datum: `.qword` or `.dword` by the program's width.
fn datum(session: &Session) -> &'static str {
    match session.image().arch().bits {
        64 => ".qword",
        _ => ".dword",
    }
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
/// `iz`: every string the program's own data holds, as radare2 lays them out.
///
/// The strings the name table holds, which it reads only out of sections the
/// container states hold the program's data, and only where the loader
/// leaves the bytes alone. Spelled with escapes, one per line.
pub(crate) fn strings(session: &mut Session) -> Result<Table, String> {
    // The strings are read out of the image, so a patched image has other ones.
    session.program.ensure_current()?;
    let found: Vec<(u64, String)> = session
        .program
        .names()
        .iter()
        .filter(|(_, name)| name.namespace == r2engine::names::Namespace::String)
        .map(|(vaddr, name)| (vaddr, name.text.clone()))
        .collect();
    Ok(string_table(session, &found))
}

/// `izz`: every run of text in every section's bytes, whatever the section holds.
///
/// A list of candidates, not of strings the program has: the interpreter's
/// path, the loader's names and a run of the unwind tables all read as text.
/// It spells radare2's `izz`, whose runs are at least four characters long.
fn every_string(session: &Session) -> Result<String, String> {
    const RADARE2_IZZ_MINIMUM: usize = 4;
    let image = session.image();
    let mut found = Vec::new();
    for section in image
        .sections()
        .iter()
        .filter(|section| section.file_size > 0)
    {
        let Some(bytes) = image.file_bytes(section.file_offset, section.file_size) else {
            continue;
        };
        let mut at = 0usize;
        while at < bytes.len() {
            let Some(text) = r2engine::names::text_in(&bytes[at..]) else {
                at += 1;
                continue;
            };
            if text.chars().count() >= RADARE2_IZZ_MINIMUM {
                let vaddr = match section.loaded {
                    true => section.vaddr + at as u64,
                    false => 0,
                };
                found.push((section.file_offset + at as u64, vaddr, text.to_owned()));
            }
            at += text.len() + 1;
        }
    }
    let mut out = String::from("nth paddr      vaddr      len size section         type  string\n");
    out.push_str(&"-".repeat(66));
    for (nth, (paddr, vaddr, text)) in found.iter().enumerate() {
        out.push_str(&format!(
            "\n{nth:<3} {paddr:#010x} {vaddr:#010x} {:<3} {:<4} {:<15} {:<5} {}",
            text.chars().count(),
            text.len() + 1,
            section_of(session, *paddr, true),
            text_type(text),
            escaped(text)
        ));
    }
    Ok(out)
}

/// The rows of a string listing, as radare2's `iz` lays them out.
fn string_table(session: &Session, found: &[(u64, String)]) -> Table {
    let mut table = Table::headed([
        "nth paddr      vaddr      len size section type  string".to_owned(),
        "-".repeat(55),
    ]);
    for (nth, (vaddr, text)) in found.iter().enumerate() {
        let paddr = file_offset_of(session, *vaddr).map_or_else(
            || "----------".to_owned(),
            |offset| format!("{offset:#010x}"),
        );
        table.row(
            Some(*vaddr),
            format!(
                "{nth:<3} {paddr} {vaddr:#010x} {:<3} {:<4} {} {:<5} {}",
                text.chars().count(),
                text.len() + 1,
                section_of(session, *vaddr, false),
                text_type(text),
                escaped(text)
            ),
        );
    }
    table
}

/// The name of the section holding an address, or a file offset where `file` is set.
fn section_of(session: &Session, at: u64, file: bool) -> String {
    let holds = |section: &&r2image::Section| match file {
        true => at >= section.file_offset && at - section.file_offset < section.file_size,
        false => section.loaded && at >= section.vaddr && at - section.vaddr < section.vsize,
    };
    session
        .image()
        .sections()
        .iter()
        .find(holds)
        .map_or_else(String::new, |section| section.name.clone())
}

/// What radare2 calls a string's encoding: `ascii`, or `utf8` where it is not.
fn text_type(text: &str) -> &'static str {
    match text.is_ascii() {
        true => "ascii",
        false => "utf8",
    }
}

/// A string as radare2 prints one: each control character escaped, so one string is one line.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
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

/// `iS`: every section the container states, with its own permissions, flags and type, as radare2 lays them out.
///
/// radare2 numbers ELF sections by their header index and Mach-O ones from
/// zero; a Mach-O section is named with its segment, which is half its
/// identity. An unloaded section permits nothing, whatever its address says.
pub(crate) fn sections(session: &Session) -> Table {
    let mut table = Table::headed([
        "nth paddr        size vaddr       vsize perm flags type        name".to_owned(),
        "-".repeat(67),
    ]);
    for section in session.image().sections() {
        let permissions = section.permissions;
        let (nth, flags, kind, name) = match section.stated {
            r2image::SectionStatement::Elf { sh_type, sh_flags } => (
                section.index,
                sh_flags,
                elf_section_type(sh_type),
                section.name.clone(),
            ),
            r2image::SectionStatement::MachO { flags } => (
                section.index.saturating_sub(1),
                u64::from(flags & !0xff),
                macho_section_type(flags & 0xff),
                match &section.segment {
                    Some(segment) => format!("{segment}.{}", section.name),
                    None => section.name.clone(),
                },
            ),
            r2image::SectionStatement::Coff { characteristics } => (
                section.index,
                u64::from(characteristics),
                String::new(),
                section.name.clone(),
            ),
            r2image::SectionStatement::Unstated => {
                (section.index, 0, String::new(), section.name.clone())
            }
        };
        // A section the loader does not map is at no address to seek to.
        table.row(
            section.loaded.then_some(section.vaddr),
            format!(
                "{nth:<3} {:#010x} {:>6} {:#010x} {:>6} -{}{}{} {:<5} {kind:<11} {name}",
                section.file_offset,
                format!("{:#x}", section.file_size),
                section.vaddr,
                format!("{:#x}", section.vsize),
                if permissions.read { 'r' } else { '-' },
                if permissions.write { 'w' } else { '-' },
                if permissions.execute { 'x' } else { '-' },
                format!("{flags:#x}"),
            ),
        );
    }
    table
}

/// An ELF section type, as radare2 spells it.
fn elf_section_type(sh_type: u32) -> String {
    match sh_type {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        19 => "RELR",
        0x6fff_fff5 => "GNU_ATTRIBUTES",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fff7 => "GNU_LIBLIST",
        0x6fff_fffd => "GNU_VERDEF",
        0x6fff_fffe => "GNU_VERNEED",
        0x6fff_ffff => "GNU_VERSYM",
        other => return format!("{other:#x}"),
    }
    .to_owned()
}

/// A Mach-O section type, as radare2 spells it.
fn macho_section_type(kind: u32) -> String {
    const NAMES: [&str; 23] = [
        "REGULAR",
        "ZEROFILL",
        "CSTRINGS",
        "4BYTE_LITERALS",
        "8BYTE_LITERALS",
        "LITERAL_POINTERS",
        "NONLAZY_POINTERS",
        "LAZY_POINTERS",
        "SYMBOL_STUBS",
        "MOD_INIT_FUNC_POINTERS",
        "MOD_TERM_FUNC_POINTERS",
        "COALESCED",
        "GB_ZEROFILL",
        "INTERPOSING",
        "16BYTE_LITERALS",
        "DTRACE_DOF",
        "LAZY_DYLIB_SYMBOL_POINTERS",
        "THREAD_LOCAL_REGULAR",
        "THREAD_LOCAL_ZEROFILL",
        "THREAD_LOCAL_VARIABLES",
        "THREAD_LOCAL_VARIABLE_POINTERS",
        "THREAD_LOCAL_INIT_FUNCTION_POINTERS",
        "INIT_FUNC_OFFSETS",
    ];
    NAMES
        .get(kind as usize)
        .map_or_else(|| format!("{kind:#x}"), |name| (*name).to_owned())
}

/// `is`: every symbol the container states, then every import, as radare2 lays them out.
///
/// Each with the binding and type its table states and its index there. An
/// import is listed at the stub that stands for it, where one does, which
/// is the address a call to it names; the dynamic table states the imports
/// where there is one, since the static table repeats them under versioned
/// names.
pub(crate) fn symbols(session: &mut Session) -> Result<Table, String> {
    // The stubs are read out of the code, so there must be a decoder first.
    session.program.ensure_current()?;
    let mut table = Table::headed([
        "nth paddr      vaddr      bind   type   size lib name".to_owned(),
        "-".repeat(60),
    ]);
    let spelled = |value: Option<u64>| {
        value.map_or_else(|| "----------".to_owned(), |value| format!("{value:#010x}"))
    };
    let mut stated: Vec<&r2image::Symbol> = session
        .image()
        .symbols()
        .iter()
        .filter(|symbol| !symbol.import)
        .collect();
    // Numbered as the static table numbers them, where it states them.
    let nth = |symbol: &r2image::Symbol| {
        symbol
            .origin
            .table
            .map_or((true, symbol.origin.dynamic), |index| (false, Some(index)))
    };
    stated.sort_by_key(|symbol| nth(symbol));
    for symbol in stated {
        let mapped = symbol.defined.then_some(symbol.vaddr);
        table.row(
            mapped,
            format!(
                "{:<3} {} {} {:<6} {:<6} {:<4}     {}",
                nth(symbol).1.unwrap_or_default(),
                spelled(mapped.and_then(|vaddr| file_offset_of(session, vaddr))),
                spelled(Some(symbol.vaddr)),
                binding(symbol.binding),
                symbol_type(symbol.kind),
                symbol.size,
                symbol.name
            ),
        );
    }
    let dynamic = session
        .image()
        .symbols()
        .iter()
        .any(|symbol| symbol.import && symbol.origin.dynamic.is_some());
    let index = |symbol: &r2image::Symbol| match dynamic {
        true => symbol.origin.dynamic,
        false => symbol.origin.table,
    };
    let mut imports: Vec<&r2image::Symbol> = session
        .image()
        .symbols()
        .iter()
        .filter(|symbol| symbol.import && index(symbol).is_some())
        .collect();
    imports.sort_by_key(|symbol| index(symbol));
    let stubs = session.program.imports();
    for symbol in imports {
        let stub = stubs.iter().find(|(_, stub)| stub.symbol == symbol.name);
        let at = stub.map(|(at, _)| *at);
        table.row(
            at,
            format!(
                "{:<3} {} {} {:<6} {:<6} {:<4}     imp.{}",
                index(symbol).unwrap_or_default(),
                spelled(at.and_then(|at| file_offset_of(session, at))),
                spelled(at),
                binding(symbol.binding),
                symbol_type(symbol.kind),
                // An import's size is the stub's, which is what a call to it reaches.
                stub.map_or(symbol.size, |(_, stub)| stub.size),
                symbol.name
            ),
        );
    }
    Ok(table)
}

/// A symbol's binding, as radare2 spells it.
fn binding(binding: r2image::Binding) -> String {
    match binding {
        r2image::Binding::Local => "LOCAL".to_owned(),
        r2image::Binding::Global => "GLOBAL".to_owned(),
        r2image::Binding::Weak => "WEAK".to_owned(),
        r2image::Binding::Other(other) => format!("{other}"),
    }
}

/// A symbol's type, as radare2 spells it.
fn symbol_type(kind: r2image::SymbolKind) -> &'static str {
    match kind {
        r2image::SymbolKind::Function => "FUNC",
        r2image::SymbolKind::Data => "OBJ",
        r2image::SymbolKind::Section => "SECT",
        r2image::SymbolKind::File => "FILE",
        r2image::SymbolKind::Other | r2image::SymbolKind::Mapping(_) => "NOTYPE",
    }
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

/// `ir`: every relocation record the loader applies, as radare2 lays them out.
///
/// `type` is radare2's: how many bits the record writes, `ADD_` where the
/// loader adds a stated addend and `SET_` where it sets the word outright;
/// `ntype` is the format's own number. A record naming no symbol is spelled
/// by its addend, which for a relative relocation is the address it writes.
pub(crate) fn relocations(session: &Session) -> Table {
    let mut table = Table::headed([
        "vaddr      paddr      type   ntype name".to_owned(),
        "-".repeat(40),
    ]);
    // In address order, as radare2 lists them; the container keeps the order they are applied in.
    let mut records: Vec<&r2image::Relocation> = session.image().relocations().iter().collect();
    records.sort_by_key(|relocation| (relocation.vaddr, relocation.record));
    for relocation in records {
        let paddr = file_offset_of(session, relocation.vaddr).map_or_else(
            || "----------".to_owned(),
            |offset| format!("{offset:#010x}"),
        );
        let additive = relocation.addend.is_some()
            && relocation.ntype != 0
            && !matches!(
                relocation.applies,
                r2image::Applies::Symbol | r2image::Applies::Resolver
            );
        let kind = format!(
            "{}_{}",
            if additive { "ADD" } else { "SET" },
            relocation.width * 8
        );
        let mut name = relocation
            .symbol
            .as_ref()
            .map(|symbol| symbol.name.clone())
            .unwrap_or_default();
        match relocation.addend {
            Some(addend) if addend < 0 => name.push_str(&format!(" - {:#010x}", -addend)),
            Some(addend) if addend > 0 && !name.is_empty() => {
                name.push_str(&format!(" + {addend:#010x}"));
            }
            Some(addend) if addend > 0 => name.push_str(&format!(" {addend:#010x}")),
            _ => {}
        }
        table.row(
            Some(relocation.vaddr),
            format!(
                "{:#010x} {paddr} {kind:<6} {:<5} {name}",
                relocation.vaddr, relocation.ntype
            ),
        );
    }
    table
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
    let roles = match (&rendering.response.output, session.paints()) {
        (r2engine::EngineRendering::Function(rendered), true) => {
            Some(crate::listing::c_roles(rendered.emission().roles()))
        }
        _ => None,
    };
    let text = rendering.response.output.into_text();
    let mut out = match roles {
        Some(roles) => r2s_tui::theme::ansi(&text, &roles),
        None => text,
    };
    // A callee whose analysis panicked is a defect in the engine, not a fact
    // about the program, so it is printed with the rendering it degraded
    // rather than only in the ledger `pddo` prints.
    let panicked = rendering
        .prepared
        .unread()
        .iter()
        .filter(|callee| callee.panicked());
    for callee in panicked {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("/* callee not read: {callee} */\n"));
    }
    Ok(out)
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
