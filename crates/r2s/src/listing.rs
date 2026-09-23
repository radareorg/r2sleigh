//! Listings: `pd` and `pdf`, laid out the way radare2 lays them out.
//!
//! The engine answers with records -- the instruction's spelling, where each
//! number in it sits, what the instruction was proved to touch and hold. This
//! is the column layout and the words a reader reads, and nothing else.

use crate::commands::{parse_count, parse_number};
use crate::session::Session;
use r2engine::query::{Completion, Listing, Stop};

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
    let mut out = String::new();
    for line in &answer.value {
        out.push_str(&listed(session, line));
    }
    Ok(out.trim_end().to_owned())
}

/// One listing line, in the columns radare2 writes them in.
fn listed(session: &Session, line: &r2engine::query::Line) -> String {
    let mut hex: String = line.bytes.iter().map(|b| format!("{:02x}", b)).collect();
    // radare2 caps the byte column at twelve characters and marks the cut.
    if hex.len() > 12 {
        hex.truncate(10);
        hex.push_str("..");
    }
    let text = match line.decoded() {
        false => "invalid".to_owned(),
        true => spelled(line, session.program.names()),
    };
    format!(
        "            {:#010x}      {:<14} {}{}\n",
        line.address,
        hex,
        text,
        held(session, line)
    )
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
pub(crate) fn disassemble_function(
    session: &mut Session,
    argument: &str,
) -> Result<String, String> {
    let addr = parse_number(session, argument)?;
    let answer = session.program.function_listing(addr)?;
    if answer.value.is_empty() {
        return Err(format!("no blocks at {addr:#x}"));
    }
    let mut out: String = answer
        .value
        .iter()
        .map(|line| listed(session, line))
        .collect();
    out.push_str(&stopped(answer.completion));
    Ok(out.trim_end().to_owned())
}

/// Where a listing ended short of what was asked, as a trailing comment line.
fn stopped(completion: Completion) -> String {
    match completion {
        Completion::Complete => String::new(),
        Completion::Unmapped { at } => {
            format!("            ; listing stopped: nothing mapped at {at:#x}\n")
        }
    }
}

/// How well supported a claim about this number is, where anything claims it.
///
/// A number no annotation claims is a coincidence: the table knows an address
/// of that value and nothing in the instruction says this is one.
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
fn note(session: &Session, at: u64, kind: r2engine::query::AnnotationKind) -> Option<String> {
    match kind {
        r2engine::query::AnnotationKind::Holds {
            address,
            width,
            value,
        } => {
            let named = session
                .program
                .names()
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

#[cfg(test)]
mod tests {
    use super::{spelled, stopped};
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

    #[test]
    fn a_listing_cut_short_by_unmapped_bytes_says_where() {
        use r2engine::query::Completion;
        assert_eq!(stopped(Completion::Complete), "");
        assert_eq!(
            stopped(Completion::Unmapped { at: 0x401360 }).trim(),
            "; listing stopped: nothing mapped at 0x401360"
        );
    }
}
