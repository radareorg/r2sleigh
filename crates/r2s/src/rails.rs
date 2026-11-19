//! `pdd` laid out for a person: a rail per nesting level, each line's lowest instruction, and the
//! proof comment in the mark grammar (D568). Plain `pdd` is the definition's bytes.

use crate::session::Session;
use r2engine::query::Mark;
use r2s_tui::theme::{Role, Roles};

/// Past this depth the rails fold to a depth count, `│ N>`.
const FOLD: usize = 24;

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
    for (line, source) in text.split_inclusive('\n').enumerate() {
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
        let shift = out.len();
        let from = start + stripped;
        out.push_str(&source[stripped..]);
        for (span, role) in roles {
            let (low, high) = (span.start.max(from), span.end.min(end));
            if low < high {
                painted.push((low - from + shift..high - from + shift, *role));
            }
        }
        start = end;
    }
    (out, painted)
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
