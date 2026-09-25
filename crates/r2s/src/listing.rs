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
        "{}            {:#010x}      {:<14} {}{}\n",
        labels(line),
        line.address,
        hex,
        text,
        held(session, line)
    )
}

/// The case and default labels a dispatch puts on this line, each on its own line above it as radare2 writes them.
fn labels(line: &r2engine::query::Line) -> String {
    use r2engine::query::AnnotationKind;
    let mut out = String::new();
    let mut label = |text: String, dispatch: u64| {
        let text = format!("            ;-- {text}:");
        out.push_str(&format!("{text:<71}; from {dispatch:#010x}\n"));
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
pub(crate) fn spelled(line: &r2engine::query::Line, names: &r2engine::names::NameDb) -> String {
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
    let listing = session.program.function_listing(addr)?;
    let answer = &listing.lines;
    if answer.value.is_empty() {
        return Err(format!("no blocks at {addr:#x}"));
    }
    let mut out: String = answer
        .value
        .iter()
        .map(|line| listed(session, line))
        .collect();
    out.push_str(&stopped(answer.completion));
    if let Some(refused) = &listing.refused {
        out.push_str(&unanalysed(refused));
    }
    Ok(out.trim_end().to_owned())
}

/// Why a listing carries no analysis, and each dispatch whose arms it therefore does not reach, as trailing comment lines.
fn unanalysed(refused: &r2engine::program::AnalysisRefused) -> String {
    let mut out = format!("            ; analysis refused: {}\n", refused.reason);
    for dispatch in &refused.unresolved {
        out.push_str(&format!(
            "            ; indirect branch at {dispatch:#x} unresolved: what it reaches is not listed\n"
        ));
    }
    out
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

/// How well supported the claim that this number is an address of the program is, where the engine makes one.
///
/// A number no reference claims is a coincidence: the table knows an address
/// of that value and nothing proves this is one. A range proved for the value
/// is not that proof, and naming by it put names in `pdf` that `ax` never listed.
fn claim(
    line: &r2engine::query::Line,
    number: r2engine::NumberSpan,
) -> Option<r2engine::query::Support> {
    line.annotations
        .iter()
        .filter(|annotation| annotation.operand == Some(number) && annotation.reference)
        .map(|annotation| annotation.support)
        .min()
}

/// What this revision holds and what was proved at the line, as trailing notes each ending in its rung.
///
/// The value is stated beside the read rather than substituted into it. A pool
/// load used to be spelled `ldr r3, sym.foo`, which says the load returns that
/// address; all this program states is that the word there is that address
/// now, and the instruction text stays what the machine encodes.
fn held(session: &Session, line: &r2engine::query::Line) -> String {
    line.annotations
        .iter()
        .filter_map(|annotation| {
            let said = note(session, line.address, &annotation.kind)?;
            Some(format!(" ; {said} ({})", rung(annotation.support)))
        })
        .collect()
}

/// What the program calls the address a word holds, after a space, or nothing where it calls it nothing.
fn named(session: &Session, value: u64) -> String {
    session
        .program
        .names()
        .of(value)
        .map(|name| format!(" {}", name.spelled()))
        .unwrap_or_default()
}

/// One annotation, as a reader reads it.
fn note(session: &Session, at: u64, kind: &r2engine::query::AnnotationKind) -> Option<String> {
    match *kind {
        r2engine::query::AnnotationKind::Holds {
            address,
            width,
            value,
        } => Some(format!(
            "[{address:#x}:{width}]={value:#x}{}",
            named(session, value)
        )),
        // What the loader writes there, which the file does not hold: spelled apart from what the revision holds.
        r2engine::query::AnnotationKind::Loaded {
            address,
            width,
            value,
        } => Some(format!(
            "[{address:#x}:{width}] loaded {value:#x}{}",
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
        r2engine::query::AnnotationKind::Text { ref text, .. } => Some(format!("{text:?}")),
        r2engine::query::AnnotationKind::Call {
            callee,
            ref arguments,
            uncounted,
        } => Some(called(session, at, callee, arguments.as_deref(), uncounted)),
        r2engine::query::AnnotationKind::ArgumentOf { call, index } => {
            Some(format!("arg{} of {call:#x}", index + 1))
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
        r2engine::query::AnnotationKind::Returns { storage } => session
            .program
            .spell_storage(at, storage)
            .map(|name| format!("returns {name}")),
        // A case or default is a label above the line, not a note beside it.
        _ => None,
    }
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

/// A call as its boundary proved it: the callee and each argument, exact where it is one.
fn called(
    session: &Session,
    at: u64,
    callee: Option<u64>,
    arguments: Option<&[r2engine::query::CallArgument]>,
    uncounted: Option<&'static str>,
) -> String {
    let callee = callee.map_or_else(
        || "indirect call".to_owned(),
        |address| {
            let name = session.program.names().of(address);
            name.map_or_else(|| format!("{address:#x}"), |name| name.spelled())
        },
    );
    // A refused variadic count is why the arguments are unproven, so it is said there.
    let Some(arguments) = arguments else {
        return match uncounted {
            Some(reason) => {
                format!("{callee}: arguments unproven, variadic tail uncounted: {reason}")
            }
            None => format!("{callee}: arguments unproven"),
        };
    };
    let spelled = arguments
        .iter()
        .map(|argument| {
            let name = format!("arg{}", argument.index + 1);
            match (argument.value, argument.slot) {
                (Some(value), _) => format!("{name}={value:#x}"),
                (None, r2engine::query::ArgumentSlot::Register(storage)) => {
                    let carrier = session.program.spell_storage(at, storage);
                    format!("{name}@{}", carrier.unwrap_or_else(|| "?".to_owned()))
                }
                (None, r2engine::query::ArgumentSlot::Stack(offset)) => {
                    format!("{name}@stack{offset:+#x}")
                }
            }
        })
        .collect::<Vec<_>>();
    format!("{callee}({})", spelled.join(", "))
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
pub(crate) fn rung(support: r2engine::query::Support) -> &'static str {
    use r2engine::query::Support;
    match support {
        Support::Stated => "stated",
        Support::Decoded => "decoded",
        Support::Folded => "folded",
        Support::Certified => "certified",
        Support::Solved => "solved",
        Support::Dereferenced => "dereferenced",
        Support::Declared => "declared",
    }
}

#[cfg(test)]
mod tests {
    use super::{spelled, stopped};
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
            },
        );
        db.insert(
            0x4,
            Name {
                text: "_nl_current".to_owned(),
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
                        support: r2engine::query::Support::Decoded,
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
