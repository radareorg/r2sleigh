//! `pdd` laid out for a person: a rail per nesting level, each line's lowest instruction, and the
//! proof comment in the mark grammar (D568). Plain `pdd` is the definition's bytes.

use crate::session::Session;
use r2engine::query::Mark;
use r2s_tui::theme::{Role, Roles};

/// Past this depth the rails fold to a depth count, `│ N>`.
const FOLD: usize = 24;

/// The cells a laid out line fills before it wraps at a break point (D620).
const WIDTH: usize = 160;

/// The cells a continuation line indents past its statement's rails.
const CONTINUED: &str = "    ";

/// The proof comment's replacement: refused and undecided facts first, then bounds and premises,
/// at most 2 lines; the full list stays in plain `pdd` and `pddo`.
pub(crate) fn notes(
    session: &mut Session,
    entry: u64,
    response: &r2engine::program::RenderedResponse,
    residuals: usize,
) -> Vec<Vec<(Mark, String)>> {
    let held = session.program.function_info(entry).ok();
    let mut refused = Vec::new();
    let mut bounded = Vec::new();
    for (mark, said) in held
        .iter()
        .flat_map(|info| crate::function::notes(session, info))
    {
        match mark {
            Mark::Refused | Mark::Unknown => refused.push((mark, said)),
            _ => bounded.push((mark, said)),
        }
    }
    if residuals > 0 {
        refused.push((Mark::Refused, format!("{residuals} residuals")));
    }
    // The proof line's refusals by type and by unassigned read, counted from its typed clauses.
    if let Some(clauses) = response.output.proof_clauses() {
        let types = clauses.refused_object_types().len();
        if types > 0 {
            let noun = if types == 1 { "type" } else { "types" };
            refused.push((Mark::Refused, format!("{types} data object {noun} refused")));
        }
        for (cause, names) in clauses.unassigned() {
            let said = format!("{} {}", names.len(), cause.spelled(names.len()));
            refused.push((Mark::Refused, said));
        }
    }
    // The ledger's columns the proof line counts: refused and residual first, assumed after.
    if let Some(closed) = response
        .obligation_ledger
        .as_ref()
        .map(|ledger| ledger.close())
    {
        let counted = [
            (Mark::Refused, closed.refused, "obligations refused"),
            (Mark::Refused, closed.gapped, "obligations residual"),
        ];
        for (mark, count, said) in counted.into_iter().filter(|(_, count, _)| *count > 0) {
            refused.push((mark, format!("{count} {said}")));
        }
        if closed.assumed > 0 {
            let said = format!("{} assumed: frame extent unproven", closed.assumed);
            bounded.insert(0, (Mark::Assumed, said));
        }
        if closed.compiler_inserted > 0 {
            bounded.push((
                Mark::Premise,
                format!("{} compiler-inserted", closed.compiler_inserted),
            ));
        }
    }
    if !response.premises.is_empty() {
        let premises = response.premises.iter().map(|premise| premise.spelled());
        let premises = premises.collect::<Vec<_>>().join(", ");
        bounded.push((Mark::Premise, format!("if {premises}")));
    }
    [refused, bounded]
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect()
}

/// What the renderer states of one definition's lines: its text, roles, depths, the proof
/// comment's line and each line's lowest instruction.
pub(crate) struct Stated<'a> {
    pub text: &'a str,
    /// The bytes one level of `depths` indents by.
    pub indent: usize,
    pub roles: Roles,
    pub depths: &'a [u8],
    pub proof: Option<usize>,
    pub lowest: Vec<Option<u64>>,
    /// Where each line may break, by line then offset.
    pub breaks: &'a [r2engine::BreakPoint],
}

/// The definition with its rails, address column and proof comment laid out, and its roles.
pub(crate) fn laid(
    session: &Session,
    stated: &Stated<'_>,
    notes: &[Vec<(Mark, String)>],
) -> (String, Roles) {
    let (text, roles, depths, lowest) = (stated.text, &stated.roles, stated.depths, &stated.lowest);
    let mut out = String::with_capacity(text.len() * 2);
    let mut painted = Roles::new();
    let mut start = 0;
    let mut breaks = stated.breaks.iter().peekable();
    for (line, source) in text.split_inclusive('\n').enumerate() {
        let mut points = Vec::new();
        while let Some(point) = breaks.next_if(|point| point.line as usize <= line) {
            if point.line as usize == line {
                points.push(*point);
            }
        }
        let depth = usize::from(depths.get(line).copied().unwrap_or(0));
        let end = start + source.len();
        let column = |out: &mut String, painted: &mut Roles, address: Option<u64>| {
            if !session.pdd_addr {
                return;
            }
            let at = out.len();
            match address {
                Some(address) => out.push_str(&format!("{address:#010x} ")),
                None => out.push_str("           "),
            }
            painted.extend(address.map(|_| (at..out.len() - 1, Role::Offset)));
        };
        // A blank line stays blank: no column, no rail.
        if source.trim().is_empty() {
            out.push_str(source);
            start = end;
            continue;
        }
        if session.railed() && stated.proof == Some(line) {
            for said in notes {
                column(&mut out, &mut painted, None);
                railed(session, &mut out, &mut painted, depth);
                commented(&mut out, &mut painted, said);
            }
            start = end;
            continue;
        }
        let laid_from = out.len();
        column(&mut out, &mut painted, lowest.get(line).copied().flatten());
        let indent = depth * stated.indent;
        let stripped =
            match session.railed() && source.as_bytes().iter().take(indent).all(|b| *b == b' ') {
                true => {
                    railed(session, &mut out, &mut painted, depth);
                    indent.min(source.len())
                }
                false => 0,
            };
        let prefix = out[laid_from..].chars().count();
        let cuts = match session.railed() {
            true => wrapped(&source[stripped..], stripped, &points, prefix),
            false => Vec::new(),
        };
        let mut from = stripped;
        for to in cuts.into_iter().chain([source.len()]) {
            if from > stripped {
                out.push('\n');
                column(&mut out, &mut painted, None);
                railed(session, &mut out, &mut painted, depth);
                out.push_str(CONTINUED);
            }
            let shift = out.len();
            out.push_str(&source[from..to]);
            for (span, role) in roles {
                let (low, high) = (span.start.max(start + from), span.end.min(start + to));
                if low < high {
                    painted.push((
                        low - start - from + shift..high - start - from + shift,
                        *role,
                    ));
                }
            }
            from = to;
        }
        start = end;
    }
    (out, painted)
}

/// The bytes of a line where it wraps past [`WIDTH`] cells: greedy, each cut the fitting point of
/// lowest depth, then latest offset (Oppen, TOPLAS 1980). `rest` starts at byte `skipped` of the
/// line and is laid after `prefix` cells. `O(line length)`.
fn wrapped(
    rest: &str,
    skipped: usize,
    points: &[r2engine::BreakPoint],
    prefix: usize,
) -> Vec<usize> {
    let text = rest.trim_end_matches('\n');
    // The cells before each byte of `text`, so a run's width is one subtraction.
    let mut before = Vec::with_capacity(text.len() + 1);
    let mut count = 0;
    for byte in text.bytes() {
        before.push(count);
        count += usize::from(byte & 0xc0 != 0x80);
    }
    before.push(count);
    let cells = |from: usize, to: usize| before[to - skipped] - before[from - skipped];
    let end = skipped + text.len();
    let mut cuts = Vec::new();
    let mut from = skipped;
    let mut room = WIDTH.saturating_sub(prefix);
    let mut next = 0;
    while cells(from, end) > room {
        let mut best: Option<r2engine::BreakPoint> = None;
        let mut overflow = None;
        while let Some(point) = points.get(next) {
            let at = point.offset as usize;
            if at <= from {
                next += 1;
                continue;
            }
            if at >= end || cells(from, at) > room {
                overflow = Some(at).filter(|at| *at < end);
                break;
            }
            if best.is_none_or(|kept| point.depth <= kept.depth) {
                best = Some(*point);
            }
            next += 1;
        }
        // No point fits: the run up to the next one stays wider than the room.
        let Some(cut) = best.map(|point| point.offset as usize).or(overflow) else {
            break;
        };
        cuts.push(cut);
        from = cut;
        room = WIDTH.saturating_sub(prefix + CONTINUED.len());
        next = points.partition_point(|point| (point.offset as usize) <= from);
    }
    cuts
}

/// One `│` and three spaces per level in `Rail`; past [`FOLD`] levels, `│ N>` and a space.
fn railed(session: &Session, out: &mut String, painted: &mut Roles, depth: usize) {
    let rail = session.gutter().rail();
    if depth > FOLD {
        let at = out.len();
        out.push(rail);
        out.push_str(&format!(" {depth}>"));
        painted.push((at..out.len(), Role::Rail));
        out.push(' ');
        return;
    }
    for _ in 0..depth {
        let at = out.len();
        out.push(rail);
        painted.push((at..out.len(), Role::Rail));
        out.push_str("   ");
    }
}

/// `/* M words; M words */`, each mark in its proof role and the rest in `Comment`.
fn commented(out: &mut String, painted: &mut Roles, said: &[(Mark, String)]) {
    let at = out.len();
    out.push_str("/* ");
    painted.push((at..out.len(), Role::Comment));
    for (index, (mark, words)) in said.iter().enumerate() {
        if index > 0 {
            let at = out.len();
            out.push_str("; ");
            painted.push((at..out.len(), Role::Comment));
        }
        crate::listing::noted(out, painted, *mark, words, Some(Role::Comment));
    }
    let at = out.len();
    out.push_str(" */");
    painted.push((at..out.len(), Role::Comment));
    out.push('\n');
}
