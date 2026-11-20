//! Listings: `pd` and `pdf`, laid out the way radare2 lays them out.
//!
//! The engine answers with records -- the instruction's spelling, where each
//! number in it sits, what the instruction was proved to touch and hold. This
//! is the column layout and the words a reader reads, and nothing else.

use crate::commands::{parse_count, parse_number};
use crate::session::Session;
use r2engine::Flow;
use r2engine::query::{Completion, Listing, Stop};
use r2s_tui::theme::{Role, Roles};

pub(crate) fn disassemble(session: &mut Session, argument: &str) -> Result<String, String> {
    let count = parse_count(argument, 16)?;
    let answer = session.program.listing(Listing {
        start: session.addr,
        stop: Stop::After(count),
    })?;
    if let Completion::Unmapped { at } = answer.completion
        && answer.value.is_empty()
    {
        return Err(format!("nothing mapped at {at:#x}"));
    }
    let mut out = Vec::new();
    for (line, next) in answer.value.iter().zip(next_calls(&answer.value)) {
        let rows = labels(line)
            .into_iter()
            .chain([listed(session, line, next)]);
        out.extend(rows.map(|row| composed(session, (MARGIN.to_owned(), Roles::new()), row)));
    }
    Ok(out.join("\n").trim_end().to_owned())
}

/// What `pd` writes before the address: the cells `pdf`'s rail and lanes take in the plain grid.
const MARGIN: &str = "            ";

/// One printed row before its gutter: its text and roles, where its instruction starts, and where
/// its first `;` stands, the instruction ending there.
pub(crate) struct Row {
    text: String,
    roles: Roles,
    instruction: usize,
    notes: Option<usize>,
}

impl Row {
    /// A row of comment text alone, which no column moves.
    fn comment(text: String) -> Self {
        Self {
            text,
            roles: Roles::new(),
            instruction: 0,
            notes: None,
        }
    }
}

/// A row behind its gutter, its first `;` at `asm.cmt.col` (a longer instruction pushes only its
/// own notes), cut to a terminal's width (plain mode never cuts), then painted.
fn composed(session: &Session, lead: (String, Roles), row: Row) -> String {
    let cells = |text: &str| text.chars().count();
    let (mut text, mut roles) = lead;
    let end = row.notes.unwrap_or(row.text.len());
    let before = cells(&text) + cells(&row.text[..row.instruction]);
    let instruction = cells(&row.text[row.instruction..end]);
    let notes = cells(&row.text[end..]);
    let gap = match row.notes {
        Some(_) => session.cmt_col.saturating_sub(before + instruction).max(1),
        None => 0,
    };
    let kept = match session.width() {
        Some(width) => crate::flow::cut(before, instruction, gap, notes, width),
        None => crate::flow::Kept {
            instruction: None,
            gap,
            mark: notes > 0,
            words: None,
        },
    };
    let mut keep = |text: &mut String, range: std::ops::Range<usize>, cells: Option<usize>| {
        let bytes = cells.map_or(range.end, |cells| {
            let mut chars = row.text[range.clone()].char_indices();
            chars
                .nth(cells)
                .map_or(range.end, |(at, _)| range.start + at)
        });
        let shift = text.len();
        text.push_str(&row.text[range.start..bytes]);
        for (span, role) in &row.roles {
            let (from, to) = (span.start.max(range.start), span.end.min(bytes));
            if from < to {
                roles.push((from - range.start + shift..to - range.start + shift, *role));
            }
        }
        if cells.is_some_and(|cells| cells > 0) {
            text.push_str("..");
        }
    };
    keep(&mut text, 0..row.instruction, None);
    keep(&mut text, row.instruction..end, kept.instruction);
    text.extend(std::iter::repeat_n(' ', kept.gap));
    if kept.mark {
        let mark = row.text[end..]
            .char_indices()
            .nth(3)
            .map_or(row.text.len(), |(at, _)| end + at);
        keep(&mut text, end..mark, None);
        keep(&mut text, mark..row.text.len(), kept.words);
    }
    match session.paints() {
        Some(depth) => r2s_tui::theme::ansi(&text, &roles, depth),
        None => text,
    }
}

/// What a line says, past its address and bytes: the instruction as `pd`
/// spells it and what it was proven to hold. The visual mode lays this out in
/// its own columns, so a pane says what `pd` says.
pub(crate) fn instruction_text(session: &Session, line: &r2engine::query::Line) -> String {
    instruction_painted(session, line).0
}

/// [`instruction_text`], with what each part of it is.
pub(crate) fn instruction_painted(
    session: &Session,
    line: &r2engine::query::Line,
) -> (String, Roles) {
    let (mut text, mut roles) = match line.decoded() {
        false => ("invalid".to_owned(), vec![(0..7, Role::Invalid)]),
        true => painted(line, &session.program.names(), session.demangle),
    };
    // A pane shows one line, so a setter names its call's address.
    let (notes, marks) = held(session, line, None);
    let at = text.len();
    roles.extend(
        marks
            .into_iter()
            .map(|(range, role)| (range.start + at..range.end + at, role)),
    );
    text.push_str(&notes);
    (text, roles)
}

/// One listing line, in the columns radare2 writes them in, from its address on.
fn listed(session: &Session, line: &r2engine::query::Line, next_call: Option<u64>) -> Row {
    let mut hex: String = line.bytes.iter().map(|b| format!("{:02x}", b)).collect();
    // radare2 caps the byte column at twelve characters and marks the cut.
    if hex.len() > 12 {
        hex.truncate(10);
        hex.push_str("..");
    }
    let (instruction, instruction_roles) = match line.decoded() {
        false => ("invalid".to_owned(), vec![(0..7, Role::Invalid)]),
        true => painted(line, &session.program.names(), session.demangle),
    };
    let mut text = format!("{:#010x}", line.address);
    let mut roles = vec![(0..text.len(), Role::Offset)];
    text.push_str("      ");
    // Without the bytes, the text takes the column they stood in.
    if session.bytes {
        text.push_str(&format!("{hex:<14} "));
    }
    let at = text.len();
    text.push_str(&instruction);
    roles.extend(
        instruction_roles
            .into_iter()
            .map(|(span, role)| (span.start + at..span.end + at, role)),
    );
    let (notes, marks) = held(session, line, next_call);
    // `held` opens each note with ` ; `: the column puts the first `;` itself.
    let notes = notes.strip_prefix(' ').map(|notes| (text.len(), notes, 1));
    let start = notes.map(|(start, _, _)| start);
    if let Some((start, notes, skipped)) = notes {
        text.push_str(notes);
        let shift =
            |span: std::ops::Range<usize>| span.start + start - skipped..span.end + start - skipped;
        roles.extend(marks.into_iter().map(|(span, role)| (shift(span), role)));
    }
    Row {
        text,
        roles,
        instruction: at,
        notes: start,
    }
}

/// The case and default labels a dispatch puts on this line, each on its own row above it as radare2 writes them.
fn labels(line: &r2engine::query::Line) -> Vec<Row> {
    use r2engine::query::AnnotationKind;
    let mut out = Vec::new();
    let mut label = |text: String, dispatch: u64| {
        let text = format!(";-- {text}:");
        out.push(Row {
            notes: Some(text.len()),
            text: format!("{text}; from {dispatch:#010x}"),
            roles: Roles::new(),
            instruction: 0,
        });
    };
    for annotation in &line.annotations {
        match annotation.kind {
            AnnotationKind::Case {
                ref values,
                dispatch,
            } => {
                for (first, last) in runs(values) {
                    match first == last {
                        true => label(format!("case {first}"), dispatch),
                        false => label(format!("case {first}...{last}"), dispatch),
                    }
                }
            }
            AnnotationKind::Default { dispatch, .. } => label("default".to_owned(), dispatch),
            _ => {}
        }
    }
    out
}

/// Sorted values as their maximal runs of consecutive ones.
fn runs(values: &[u64]) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &value in values {
        match runs.last_mut() {
            Some((_, last)) if last.checked_add(1) == Some(value) => *last = value,
            _ => runs.push((value, value)),
        }
    }
    runs
}

/// One line, with a name written wherever a number is one.
///
/// Substitution is by span rather than by value. Scanning the finished text
/// for hexadecimal runs cannot tell an address from a displacement that
/// happens to equal one, which is how a `-0x4` became a symbol's name, and it
/// cannot tell two operands of one instruction apart when both hold the same
/// number. A span says which number is being claimed about, and the sign it
/// was written with is part of it: a negative literal names no address however
/// well its magnitude matches.
pub(crate) fn spelled(
    line: &r2engine::query::Line,
    names: &r2engine::names::NameDb,
    demangle: bool,
) -> String {
    painted(line, names, demangle).0
}

/// [`spelled`], with what each part of it is: the mnemonic by where the
/// instruction sends control, each register the decoder named, each number,
/// and each name written over one, demangled where `demangle` holds.
pub(crate) fn painted(
    line: &r2engine::query::Line,
    names: &r2engine::names::NameDb,
    demangle: bool,
) -> (String, Roles) {
    let Some(syntax) = &line.syntax else {
        return (String::new(), Vec::new());
    };
    let flow = match line.flow {
        Some(Flow::Call) => Role::Call,
        Some(Flow::Jump) => Role::Jump,
        Some(Flow::ConditionalJump) => Role::ConditionalJump,
        Some(Flow::Return) => Role::Return,
        Some(Flow::Nop) => Role::Nop,
        Some(Flow::Trap) => Role::Trap,
        Some(Flow::Fall) | None => Role::Mnemonic,
    };
    let mut text = syntax.mnemonic.clone();
    let mut roles = vec![(0..text.len(), flow)];
    if syntax.body.is_empty() {
        return (text, roles);
    }
    text.push(' ');
    // The body's tokens in the order they are written: numbers, each spelled
    // as the name the table gives it where the engine says the instruction
    // uses it as an address, and registers. The two never overlap: a number
    // starts with a digit and a register with a letter.
    let mut tokens = syntax
        .numbers
        .iter()
        .map(|number| {
            // Only where the engine says the instruction uses that number as
            // an address. Naming every number the table happens to know
            // spelled `adrp x17, reloc.humanize_number` over a page base the
            // next instruction was about to move fifty bytes past.
            // The claim's address, not the spelling: Sleigh writes an address with its top bit set
            // as a negative number, which radare2 writes, and the table names, unsigned.
            let claimed = claimed_address(line, *number);
            let name = claimed
                .and_then(|address| names.of(address))
                .map(|name| name.shown(demangle).into_owned());
            let role = if name.is_some() {
                Role::Name
            } else {
                Role::Number
            };
            let unsigned = claimed
                .filter(|_| number.value < 0)
                .map(|address| format!("{address:#x}"));
            (number.start, number.end, name.or(unsigned), role)
        })
        .chain(
            syntax
                .registers
                .iter()
                .map(|span| (span.start, span.end, None, Role::Register)),
        )
        .collect::<Vec<_>>();
    tokens.sort_by_key(|(start, ..)| *start);
    let mut at = 0;
    for (start, end, named, role) in tokens {
        if start < at || end > syntax.body.len() {
            continue;
        }
        // `lea` computes the address it brackets, so a name standing for it takes the brackets:
        // radare2 writes `lea r8, sym.fini` and `lea r8, [0x11e0]`.
        let (start, end) = match role == Role::Name
            && syntax.mnemonic == "lea"
            && syntax.body[..start].ends_with('[')
            && syntax.body[end..].starts_with(']')
            && start > at
        {
            true => (start - 1, end + 1),
            false => (start, end),
        };
        text.push_str(&syntax.body[at..start]);
        let from = text.len();
        text.push_str(named.as_deref().unwrap_or(&syntax.body[start..end]));
        roles.push((from..text.len(), role));
        at = end;
    }
    text.push_str(&syntax.body[at..]);
    (text, roles)
}

/// `pdf`: the function at the cursor, listed with what the engine proved.
///
/// The listing radare2 cannot write. `pd` stays cheap and claims only what one
/// instruction and its neighbours show; this pays for the walk and the
/// preparation, and every line can then carry the range its value was proved
/// to lie in.
pub(crate) fn disassemble_function(
    session: &mut Session,
    argument: &str,
) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let listing = session.program.function_listing(addr)?;
    let answer = &listing.lines;
    // A walk refused at the entry lists nothing: the record is the answer (ROADMAP D29).
    match (&listing.refused, answer.value.is_empty()) {
        (Some(refused), true) => {
            let rows = unanalysed(refused)
                .into_iter()
                .map(|row| format!("{MARGIN}{row}"));
            return Ok(rows.collect::<Vec<_>>().join("\n"));
        }
        (None, true) => return Err(format!("no blocks at {addr:#x}")),
        _ => {}
    }
    let lines = &answer.value;
    let mut rows = Vec::new();
    let mut row_of = Vec::with_capacity(lines.len());
    let mut gaps = listing.gaps.iter().peekable();
    for (line, next) in lines.iter().zip(next_calls(lines)) {
        // The engine's gaps come in listing order, each ending at the line it precedes (D622).
        if let Some(gap) = gaps.next_if(|gap| gap.range.end == line.address) {
            rows.push(gap_row(gap));
        }
        rows.extend(labels(line));
        row_of.push(rows.len());
        rows.push(listed(session, line, next));
    }
    rows.extend(stopped(answer.completion).map(Row::comment));
    if let Some(refused) = &listing.refused {
        rows.extend(unanalysed(refused).into_iter().map(Row::comment));
    }
    // The engine states the edges by address; a row is where its line was laid out.
    let row = |address: u64| {
        let line = lines
            .binary_search_by_key(&address, |line| line.address)
            .ok()?;
        Some(row_of[line])
    };
    let edges = (listing.edges.iter()).filter_map(|edge| {
        Some(crate::flow::Edge {
            from: row(edge.from)?,
            to: row(edge.to)?,
            latch: edge.latch,
        })
    });
    let edges = edges.collect::<Vec<_>>();
    let unknown = (lines.iter().enumerate())
        .filter(|(_, line)| unresolved(line))
        .map(|(at, _)| row_of[at])
        .collect::<Vec<_>>();
    let gutters = crate::flow::gutters(rows.len(), &edges, &unknown, session.gutter());
    let body = (rows.into_iter().zip(gutters)).map(|(row, gutter)| composed(session, gutter, row));
    let out = header(session, addr, &listing, lines)
        .into_iter()
        .chain(body);
    Ok(out.collect::<Vec<_>>().join("\n").trim_end().to_owned())
}

/// `pdf`'s header in radare2's grammar (`libr/core/disasm.c:1723-1734`, `:1849-1866`), in the
/// order doc/adr-display.md "Round 15 as built: listing" (D566) gives.
fn header(
    session: &Session,
    entry: u64,
    listing: &r2engine::program::FunctionListing,
    lines: &[r2engine::query::Line],
) -> Vec<String> {
    let names = session.program.names();
    let name = |address: u64| names.function(address, session.demangle);
    let header = &listing.header;
    let mut out = xrefs(header, &name);
    let gutter = session.gutter();
    let info = header.info.as_ref();
    let size = info.map_or_else(
        || lines.iter().map(|line| line.bytes.len() as u64).sum(),
        r2engine::program::info::FunctionInfo::real_size,
    );
    let (mut text, mut roles) = (String::new(), Roles::new());
    text.push(gutter.head());
    roles.push((0..text.len(), Role::Rail));
    text.push_str(&format!(" {size}: "));
    let at = text.len();
    text.push_str(&name(entry));
    roles.push((at..text.len(), Role::Name));
    let arguments = crate::function::arguments(info);
    text.push_str(&format!(" ({arguments});"));
    out.push((text, roles));
    let rail = |mark: r2engine::query::Mark, said: &str| {
        let mut text = String::new();
        text.push(gutter.rail());
        let mut roles = vec![(0..text.len(), Role::Rail)];
        text.push_str(" ; ");
        noted(&mut text, &mut roles, mark, said, None);
        (text, roles)
    };
    for (mark, said) in info
        .into_iter()
        .flat_map(|info| crate::function::header_notes(session, info))
    {
        out.push(rail(mark, &said));
    }
    let low = lines.first().map_or(entry, |line| line.address);
    if low < entry {
        let high = lines
            .last()
            .map_or(entry, |line| line.address + line.bytes.len() as u64 - 1);
        let blocks = info.map_or(0, |info| info.blocks.len());
        let said =
            format!("{blocks} blocks over {low:#010x}..{high:#010x}; blocks below the entry first");
        out.push(rail(r2engine::query::Mark::Holds, &said));
    }
    out.into_iter()
        .map(|(text, roles)| match session.paints() {
            Some(depth) => r2s_tui::theme::ansi(&text, &roles, depth),
            None => text,
        })
        .collect()
}

/// The header's xref lines, folded past radare2's `asm.xrefs.fold`, then the `?` line where the
/// engine does not count every transfer no walk followed.
fn xrefs(header: &r2engine::program::Header, name: &dyn Fn(u64) -> String) -> Vec<(String, Roles)> {
    let comment = |text: String| {
        let roles = vec![(0..text.len(), Role::Comment)];
        (text, roles)
    };
    let count = header.calls.len() + header.tails.len();
    // radare2 folds past `asm.xrefs.fold` (5, `libr/core/cconfig.c:4203`).
    let mut out = match count > 5 {
        true => vec![comment(format!("; XREFS({count})"))],
        false => [("CALL", &header.calls), ("CODE", &header.tails)]
            .into_iter()
            .flat_map(|(kind, xrefs)| {
                xrefs
                    .chunk_by(|a, b| a.from == b.from)
                    .map(move |group| (kind, group))
            })
            .map(|(kind, group)| {
                let plural = if group.len() > 1 { "S" } else { "" };
                let sites = group.iter().map(|xref| format!("{:#x}(x)", xref.site));
                let sites = sites.collect::<Vec<_>>().join(", ");
                let from = name(group[0].from);
                comment(format!("; {kind} XREF{plural} from {from} @ {sites}"))
            })
            .collect(),
    };
    // Default-deny: the list is complete only where the engine counts no unfollowed transfer.
    let short = match header.unresolved {
        Some(0) => None,
        Some(1) => Some("xrefs may be short: 1 indirect transfer unresolved".to_owned()),
        Some(count) => Some(format!(
            "xrefs may be short: {count} indirect transfers unresolved"
        )),
        None => Some("xrefs may be short: indirect transfers unread".to_owned()),
    };
    if let Some(short) = short {
        let mut text = "; ".to_owned();
        let mut roles = Roles::new();
        let unknown = r2engine::query::Mark::Unknown;
        noted(&mut text, &mut roles, unknown, &short, Some(Role::Comment));
        out.push((text, roles));
    }
    out
}

/// A gap row: bytes not in this function, some held by another body, or with `?` bytes no walked body holds.
fn gap_row(gap: &r2engine::query::Gap) -> Row {
    let (start, last) = (gap.range.start, gap.range.end - 1);
    let size = gap.range.end - start;
    if gap.held {
        return Row::comment(format!(
            ";-- {size} bytes not in this function: {start:#010x}..{last:#010x}"
        ));
    }
    let mut text = ";-- ".to_owned();
    let mut roles = Roles::new();
    let said = format!("{size} bytes in no block: {start:#010x}..{last:#010x}");
    noted(
        &mut text,
        &mut roles,
        r2engine::query::Mark::Unknown,
        &said,
        Some(Role::Comment),
    );
    Row {
        text,
        roles,
        ..Row::comment(String::new())
    }
}

/// Whether the line is an indirect jump no walk followed: an unknown-kind note says so.
fn unresolved(line: &r2engine::query::Line) -> bool {
    let unresolved = |annotation: &r2engine::query::Annotation| {
        matches!(annotation.kind, r2engine::query::AnnotationKind::Unresolved)
    };
    line.annotations.iter().any(unresolved)
}

/// Why a listing carries no analysis, and each dispatch whose arms it therefore does not reach, as trailing comment rows.
fn unanalysed(refused: &r2engine::program::AnalysisRefused) -> Vec<String> {
    let mut out = vec![format!("; analysis refused: {}", refused.reason)];
    for dispatch in &refused.unresolved {
        out.push(format!(
            "; indirect branch at {dispatch:#x} unresolved: what it reaches is not listed"
        ));
    }
    out
}

/// Where a listing ended short of what was asked, as a trailing comment row.
fn stopped(completion: Completion) -> Option<String> {
    match completion {
        Completion::Complete => None,
        Completion::Unmapped { at } => {
            Some(format!("; listing stopped: nothing mapped at {at:#x}"))
        }
    }
}

/// The address the engine claims a number stands for, where it uses the number as one: a number
/// no reference claims is a coincidence, and naming it put names in `pdf` that `ax` never listed.
fn claimed_address(line: &r2engine::query::Line, number: r2engine::NumberSpan) -> Option<u64> {
    line.annotations
        .iter()
        .filter(|annotation| annotation.operand == Some(number) && annotation.reference)
        .min_by_key(|annotation| &annotation.confidence)
        .and_then(|annotation| annotation.kind.address())
}

/// Each line's next call line in the listing, in one pass from the end: a setter of that call names
/// no address.
pub(crate) fn next_calls(lines: &[r2engine::query::Line]) -> Vec<Option<u64>> {
    let mut next = None;
    let mut out = vec![None; lines.len()];
    for (at, line) in lines.iter().enumerate().rev() {
        out[at] = next;
        let calls = line.annotations.iter().any(|annotation| {
            matches!(
                annotation.kind,
                r2engine::query::AnnotationKind::Call { .. }
            )
        });
        if calls {
            next = Some(line.address);
        }
    }
    out
}

/// One note of a line as `pdf` spells it, and the annotation it spells: none for the callee's
/// `noreturn` beside its call. `ao` and `pdfj` read the same notes (D582).
pub(crate) struct Note<'l> {
    pub(crate) mark: r2engine::query::Mark,
    pub(crate) confidence: &'l r2engine::query::Confidence,
    pub(crate) standing: r2engine::query::Standing,
    pub(crate) text: String,
    pub(crate) annotation: Option<&'l r2engine::query::Annotation>,
}

impl Note<'_> {
    /// The role of the note's words: a string the word holds is painted as one.
    pub(crate) fn words(&self) -> Option<Role> {
        let text = |annotation: &r2engine::query::Annotation| {
            matches!(
                annotation.kind,
                r2engine::query::AnnotationKind::Text { .. }
            )
        };
        self.annotation.is_some_and(text).then_some(Role::String)
    }
}

/// Each note on the line as `; M text`, weakest first, with the mark cell's role and a refusal's
/// reason; `asm.proof` adds the basis (doc/adr-display.md). A held value is stated beside the read.
fn held(
    session: &Session,
    line: &r2engine::query::Line,
    next_call: Option<u64>,
) -> (String, Roles) {
    let mut text = String::new();
    let mut roles = Roles::new();
    for note in notes(session, line, next_call) {
        text.push_str(" ; ");
        noted(&mut text, &mut roles, note.mark, &note.text, note.words());
        // A refusal or an unknown stands on no basis, so none is printed.
        if session.proof && note.standing == r2engine::query::Standing::Fact {
            text.push_str(&format!(" ({})", note.confidence));
        }
    }
    (text, roles)
}

/// The line's notes as a reader reads them, weakest first.
pub(crate) fn notes<'l>(
    session: &Session,
    line: &'l r2engine::query::Line,
    next_call: Option<u64>,
) -> Vec<Note<'l>> {
    use r2engine::query::{AnnotationKind, Mark, Standing};
    let indirect = line
        .annotations
        .iter()
        .any(|annotation| matches!(annotation.kind, AnnotationKind::Call { callee: None, .. }));
    let mut notes = Vec::new();
    for annotation in &line.annotations {
        let said = match annotation.kind {
            // An indirect call's target a table it reads holds: no operand of the instruction names it.
            AnnotationKind::Target {
                address,
                call: true,
            } if indirect => Some(format!("calls {address:#x}{}", named(session, address))),
            AnnotationKind::Call {
                callee,
                ref arguments,
                ..
            } => Some(called(session, line, callee, arguments.as_deref())),
            _ => note(session, line.address, &annotation.kind, next_call),
        };
        let standing = annotation.kind.standing();
        notes.extend(said.map(|text| Note {
            mark: annotation.mark(),
            confidence: &annotation.confidence,
            standing,
            text,
            annotation: Some(annotation),
        }));
        // The callee's own `Never`, a fact of its own beside what the call hands on.
        if let AnnotationKind::Call {
            noreturn: Some(ref never),
            ..
        } = annotation.kind
        {
            let confidence = &never.confidence;
            notes.push(Note {
                mark: confidence.mark(),
                confidence,
                standing: Standing::Fact,
                text: "noreturn".into(),
                annotation: None,
            });
        }
    }
    notes.sort_by(|a, b| Mark::weakest_first((a.mark, a.confidence), (b.mark, b.confidence)));
    notes
}

/// `M words` appended to `text`: the mark cell in its proof role, and the words in `ProofReason`
/// after a refusal, else in `words`. `afi` and the listing write notes through this one function.
pub(crate) fn noted(
    text: &mut String,
    roles: &mut Roles,
    mark: r2engine::query::Mark,
    said: &str,
    words: Option<Role>,
) {
    let at = text.len();
    text.push(mark.cell());
    roles.extend(Role::marked(mark.cell()).map(|role| (at..text.len(), role)));
    text.push(' ');
    let at = text.len();
    text.push_str(said);
    let words = match mark {
        r2engine::query::Mark::Refused => Some(Role::ProofReason),
        _ => words,
    };
    roles.extend(words.map(|role| (at..text.len(), role)));
}

/// What the program calls the address a word holds, after a space, or nothing where it calls it nothing.
fn named(session: &Session, value: u64) -> String {
    session
        .program
        .names()
        .of(value)
        .map(|name| format!(" {}", name.shown(session.demangle)))
        .unwrap_or_default()
}

/// One annotation, as a reader reads it.
fn note(
    session: &Session,
    at: u64,
    kind: &r2engine::query::AnnotationKind,
    next_call: Option<u64>,
) -> Option<String> {
    match *kind {
        r2engine::query::AnnotationKind::Holds {
            address,
            width,
            value,
        } => Some(format!(
            "[{address:#x}:{width}]={value:#x}{} in file",
            named(session, value)
        )),
        // What the loader writes there, which the file does not hold: spelled apart from what the revision holds.
        r2engine::query::AnnotationKind::Loaded {
            address,
            width,
            value,
        } => Some(format!(
            "[{address:#x}:{width}]={value:#x}{} after relocation",
            named(session, value)
        )),
        // The value this line defines, over its whole life: not what the storage holds at this point.
        r2engine::query::AnnotationKind::Bounds {
            storage, low, high, ..
        } => session
            .program
            .spell_storage(at, storage)
            .map(|name| match low == high {
                true => format!("defines {name} = {low:#x}"),
                false => format!("defines {name} in [{low:#x}, {high:#x}]"),
            }),
        r2engine::query::AnnotationKind::Text { ref text, .. }
        | r2engine::query::AnnotationKind::TextIfAddress { ref text, .. } => {
            Some(format!("\"{}\"", r2engine::names::escaped(text)))
        }
        // The call a setter feeds is named where it is not the next call line, or `asm.proof` asks.
        r2engine::query::AnnotationKind::ArgumentOf { call, index } => {
            Some(match session.proof || next_call != Some(call) {
                true => format!("a{} of {call:#x}", index + 1),
                false => format!("a{}", index + 1),
            })
        }
        r2engine::query::AnnotationKind::Switch {
            ref arms, table, ..
        } => Some(switched(arms.len(), table.map(|table| table.address))),
        r2engine::query::AnnotationKind::Unresolved => {
            Some("indirect branch unresolved".to_owned())
        }
        r2engine::query::AnnotationKind::Loop {
            ref latches,
            ref exits,
        } => Some(format!(
            "loop: latches {}, exits {}",
            addresses(latches),
            addresses(exits)
        )),
        r2engine::query::AnnotationKind::Induction {
            storage,
            init,
            step,
            width_bits,
        } => {
            let name = session.program.spell_storage(at, storage)?;
            let init = match init {
                Some(init) => format!(" = {},", operand(session, at, init)?),
                None => String::new(),
            };
            let bits = bits(width_bits);
            Some(format!(
                "induction {name}{init} {} per trip{bits}",
                stepped(step)
            ))
        }
        r2engine::query::AnnotationKind::Trips(ref trips) => {
            Some(format!("trips {}", counted(session, at, trips)?))
        }
        r2engine::query::AnnotationKind::Returns {
            storage,
            ref standing,
        } => resulted(session.program.spell_storage(at, storage?)?, standing),
        // A case or default is a label above the line, not a note beside it.
        _ => None,
    }
}

/// The result as `afi` states it: decided, unproven with its cause, or refused (D584).
fn resulted(name: String, standing: &r2engine::query::ResultStanding) -> Option<String> {
    use r2engine::query::ResultStanding;
    Some(match standing {
        ResultStanding::Decided(_) => format!("returns {name}"),
        ResultStanding::Unproven(cause) => {
            let cause = ResultStanding::cause_name(*cause);
            format!("result unproven ({name}, {cause})")
        }
        ResultStanding::Refused(refusal) => {
            let refusal = ResultStanding::refusal_name(*refusal);
            format!("result refused ({name}, {refusal})")
        }
    })
}

/// A dispatch, in radare2's words where the table it reads is known.
fn switched(cases: usize, table: Option<u64>) -> String {
    match table {
        Some(table) => format!("switch table ({cases} cases) at {table:#x}"),
        None => format!("switch ({cases} cases)"),
    }
}

/// How an induction moves on each trip.
fn stepped(step: r2engine::query::InductionStep) -> String {
    match step {
        r2engine::query::InductionStep::AddConst(value) => format!("+{value:#x}"),
        r2engine::query::InductionStep::SubConst(value) => format!("-{value:#x}"),
        r2engine::query::InductionStep::Affine { multiplier, addend } => {
            format!("*{multiplier:#x} +{addend:#x}")
        }
    }
}

/// A call's arguments once, as its boundary proved them, each exact where it is one; or why the
/// boundary refused them, in r2ssa's words. The callee is named only where no operand names it.
fn called(
    session: &Session,
    line: &r2engine::query::Line,
    callee: Option<u64>,
    arguments: Result<&[r2engine::query::CallArgument], &r2engine::query::CallBoundaryRefusal>,
) -> String {
    let at = line.address;
    let numbers = line.syntax.iter().flat_map(|syntax| &syntax.numbers);
    let apart = callee.filter(|callee| {
        let mut numbers = numbers.clone();
        !numbers.any(|number| claimed_address(line, *number) == Some(*callee))
    });
    let names = session.program.names();
    let apart = apart
        .and_then(|callee| names.of(callee))
        .map(|name| name.spelled());
    let arguments = match (arguments, apart.as_deref()) {
        (Ok(arguments), _) => arguments,
        (Err(why), Some(name)) => return format!("args of {name}: {why}"),
        (Err(why), None) => return format!("args: {why}"),
    };
    // Positions name the arguments only where they run from the first without a gap.
    let dense = (arguments.iter().enumerate()).all(|(at, argument)| argument.index == at);
    let spelled = arguments.iter().map(|argument| {
        let value = match (argument.value, argument.slot) {
            (Some(value), _) => format!("{value:#x}"),
            (None, r2engine::query::ArgumentSlot::Register(storage)) => {
                let carrier = session.program.spell_storage(at, storage);
                carrier.unwrap_or_else(|| "?".to_owned())
            }
            (None, r2engine::query::ArgumentSlot::Stack(offset)) => {
                format!("stack{}", signed(offset))
            }
        };
        match dense {
            true => value,
            false => format!("a{}={value}", argument.index + 1),
        }
    });
    let spelled = spelled.collect::<Vec<_>>().join(", ");
    format!("{}({spelled})", apart.unwrap_or_default())
}

/// An offset with its sign and magnitude, as `afv` spells one: `-0x2c`, never its two's complement.
fn signed(offset: i64) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    format!("{sign}{:#x}", offset.unsigned_abs())
}

/// A value a claim names, exactly or as what a register held on entry.
fn operand(session: &Session, at: u64, operand: r2engine::query::Operand) -> Option<String> {
    match operand {
        r2engine::query::Operand::Exact(value) => Some(format!("{value:#x}")),
        r2engine::query::Operand::Entry(storage) => session
            .program
            .spell_storage(at, storage)
            .map(|name| format!("{name}@entry")),
    }
}

/// A trip count, exact or affine over what the function was entered with.
fn counted(session: &Session, at: u64, trips: &r2engine::query::Trips) -> Option<String> {
    match *trips {
        r2engine::query::Trips::Exact(count) => Some(format!("{count:#x}")),
        r2engine::query::Trips::Affine {
            ref terms,
            constant,
            width_bits,
        } => {
            let mut spelled = terms
                .iter()
                .map(|(storage, coefficient)| {
                    let name = session.program.spell_storage(at, *storage)?;
                    Some(match coefficient {
                        1 => format!("{name}@entry"),
                        _ => format!("{coefficient:#x}*{name}@entry"),
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            if constant != 0 || spelled.is_empty() {
                spelled.push(format!("{constant:#x}"));
            }
            Some(format!("{}{}", spelled.join(" + "), bits(width_bits)))
        }
    }
}

/// A width a value wraps at, where it is narrower than sixty-four bits.
fn bits(width_bits: u32) -> String {
    match width_bits < 64 {
        true => format!(" ({width_bits} bits)"),
        false => String::new(),
    }
}

/// Block addresses, as a list.
fn addresses(blocks: &[u64]) -> String {
    let spelled = blocks.iter().map(|block| format!("{block:#x}"));
    spelled.collect::<Vec<_>>().join(" ")
}

/// The rung a claim stands on, as a reader reads it.
pub(crate) fn rung(support: r2engine::discovery::Basis) -> &'static str {
    support.spelled()
}

/// The renderer's roles in the palette's terms.
pub(crate) fn c_roles(roles: &[(std::ops::Range<usize>, r2engine::CRole)]) -> Roles {
    use r2engine::CRole;
    roles
        .iter()
        .map(|(range, role)| {
            let role = match role {
                CRole::Keyword => Role::Keyword,
                CRole::Type => Role::Type,
                CRole::Number => Role::Number,
                CRole::String => Role::String,
                CRole::Comment => Role::Comment,
                CRole::Function => Role::Function,
                CRole::External => Role::External,
                CRole::Residual => Role::Residual,
            };
            (range.clone(), role)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{signed, spelled, stopped};
    use r2engine::names::{Name, NameDb, Namespace};
    use r2engine::query::Line;

    fn db() -> NameDb {
        let mut db = NameDb::new();
        db.insert(
            0x100000340,
            Name {
                text: "_add_two".into(),
                namespace: Namespace::Symbol,
                size: 0,
            },
        );
        db.insert(
            0x4,
            Name {
                text: "_nl_current".into(),
                namespace: Namespace::Label,
                size: 0,
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
                        confidence: r2engine::discovery::Basis::Decoded.into(),
                        operand: Some(*number),
                        reference: true,
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
                registers: Vec::new(),
            }),
            flow: None,
            annotations,
        }
    }

    #[test]
    fn a_named_address_is_spelled_by_its_name() {
        assert_eq!(
            spelled(&line("call", "0x100000340"), &db(), false),
            "call sym._add_two"
        );
    }

    #[test]
    fn a_named_effective_address_takes_its_brackets_and_a_named_read_keeps_them() {
        assert_eq!(
            spelled(&line("lea", "r8, [0x100000340]"), &db(), false),
            "lea r8, sym._add_two"
        );
        assert_eq!(
            spelled(&line("lea", "r8, [0x100000341]"), &db(), false),
            "lea r8, [0x100000341]"
        );
        assert_eq!(
            spelled(&line("mov", "rax, qword [0x100000340]"), &db(), false),
            "mov rax, qword [sym._add_two]"
        );
    }

    #[test]
    fn an_address_with_no_name_stays_a_number() {
        assert_eq!(
            spelled(&line("call", "0x100000341"), &db(), false),
            "call 0x100000341"
        );
        assert_eq!(
            spelled(&line("sub", "rsp, 0x10"), &db(), false),
            "sub rsp, 0x10"
        );
    }

    #[test]
    fn a_negative_displacement_is_not_an_address() {
        // The defect this replaced: a `-0x4` written against a register came
        // out as the name of whatever sits at address four.
        assert_eq!(
            spelled(&line("ldr", "r3, [sp, -0x4]"), &db(), false),
            "ldr r3, [sp, -0x4]"
        );
    }

    #[test]
    fn a_claimed_address_spelled_negative_is_written_unsigned() {
        // Sleigh writes an address with its top bit set as a negative number; the claim states the
        // address, which radare2 writes unsigned and the table may name (audit: ibknoreloc64).
        let mut line = unclaimed("call", "qword [-0xef18]");
        let number = line.syntax.as_ref().expect("syntax").numbers[0];
        line.annotations.push(r2engine::query::Annotation {
            kind: r2engine::query::AnnotationKind::Reads {
                address: 0xffff_ffff_ffff_10e8,
                width: 8,
            },
            confidence: r2engine::discovery::Basis::Decoded.into(),
            operand: Some(number),
            reference: true,
        });
        assert_eq!(
            spelled(&line, &db(), false),
            "call qword [0xffffffffffff10e8]"
        );
    }

    #[test]
    fn each_operand_holding_one_number_is_written_once() {
        // Substituting by value rewrote the whole line at once; by span, each
        // occurrence is its own decision and the count comes out right.
        assert_eq!(
            spelled(&line("mov", "0x100000340, [0x100000340]"), &db(), false),
            "mov sym._add_two, [sym._add_two]"
        );
    }

    #[test]
    fn a_number_nothing_claims_is_a_coincidence_and_stays_a_number() {
        // `adrp x17, 0x100008000` computes a page base that happens to equal a
        // named address; the instruction after it moves fifty bytes past.
        assert_eq!(
            spelled(&unclaimed("adrp", "x17, 0x100000340"), &db(), false),
            "adrp x17, 0x100000340"
        );
    }

    #[test]
    fn a_binary_with_no_names_changes_nothing() {
        assert_eq!(
            spelled(&line("call", "0x1030"), &NameDb::new(), false),
            "call 0x1030"
        );
    }

    #[test]
    fn a_negative_stack_offset_is_spelled_signed() {
        // crackme0x05 0x80484e2 printed `arg1@stack+0xffffffffffffffd4` for the slot at -0x2c (D583).
        assert_eq!(signed(-0x2c), "-0x2c");
        assert_eq!(signed(0x8), "+0x8");
        assert_eq!(signed(i64::MIN), "-0x8000000000000000");
    }

    /// On an 80-column terminal every `pdf` line fits, a cut line ends in `..`, and colour adds
    /// only escapes (D565).
    #[test]
    fn a_terminal_listing_is_cut_to_its_width_and_painted_over_the_cut() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/coverage/pinned/hashes_gcc_x64_O2"
        );
        let mut session = crate::session::Session::open(path).expect("the fixture opens");
        session.columns = Some(80);
        let plain = super::disassemble_function(&mut session, "0x401330").expect("it lists");
        session.color = 1;
        let painted = super::disassemble_function(&mut session, "0x401330").expect("it lists");
        let mut stripped = String::new();
        let mut rest = painted.as_str();
        while let Some((before, after)) = rest.split_once('\x1b') {
            stripped.push_str(before);
            rest = after.split_once('m').map_or("", |(_, after)| after);
        }
        stripped.push_str(rest);
        assert_eq!(stripped, plain);
        assert!(
            plain.lines().all(|line| line.chars().count() <= 80),
            "{plain}"
        );
        assert!(plain.lines().any(|line| line.ends_with("..")), "{plain}");
    }

    #[test]
    fn a_listing_cut_short_by_unmapped_bytes_says_where() {
        use r2engine::query::Completion;
        assert_eq!(stopped(Completion::Complete), None);
        assert_eq!(
            stopped(Completion::Unmapped { at: 0x401360 }).as_deref(),
            Some("; listing stopped: nothing mapped at 0x401360")
        );
    }
}
