//! The proof line: what the rendering did and did not show, and the reads it left as residuals.

use std::fmt::Write as _;

use crate::ast::{CFunction, CStmt};
use crate::codegen::sanitize_comment_text_keeping;

/// What the closed world decided of the result, as the proof line words it (D166).
#[derive(Clone, Copy)]
enum Closed {
    Read,
    Cycle,
    Unread,
}

/// The proof line's columns that appear only when they are not zero, in reading order.
fn proof_columns(
    closure: &crate::ledger::LedgerClosure,
    ledger: &crate::ledger::ObligationLedger,
    decided: Closed,
) -> String {
    let split = ledger.split_rendered();
    let mut line = String::new();
    if closure.compiler_inserted > 0 {
        // Each decided check passes under its premise: a canary the UB-free source, Go's stack
        // check the runtime's contract. A closed world is the result's, spelled below.
        let premises = (ledger.premises().iter())
            .filter(|premise| **premise != r2source::Premise::ClosedWorld)
            .map(|premise| premise.spelled());
        let _ = write!(
            &mut line,
            ", {} compiler-inserted (assuming {})",
            closure.compiler_inserted,
            premises.collect::<Vec<_>>().join(", ")
        );
    }
    let (exits, premises) = ledger.exits();
    if exits > 0 {
        let premises = premises.iter().map(|premise| premise.spelled());
        let _ = write!(
            &mut line,
            ", {exits} {} never {} (assuming {})",
            if exits == 1 { "call" } else { "calls" },
            if exits == 1 { "returns" } else { "return" },
            premises.collect::<Vec<_>>().join(", ")
        );
    }
    // The closed world decided the result: a reading call makes it a value, every call dead a void
    // or unread one (doc/adr-call-boundary.md, D166).
    if ledger.premises().contains(&r2source::Premise::ClosedWorld) {
        line.push_str(match decided {
            Closed::Read => ", a call reads the result (assuming closed-world)",
            Closed::Cycle => {
                ", a call returns the result on through a cycle (assuming closed-world)"
            }
            Closed::Unread => ", no call reads the result (assuming closed-world)",
        });
    }
    if closure.assumed > 0 {
        let _ = write!(
            &mut line,
            ", {} assumed (frame extent unproven)",
            closure.assumed
        );
    }
    // A function with a residual is rendered, not proven: the count is how many obligations residuals stand in for.
    if closure.gapped > 0 {
        let _ = write!(&mut line, ", {} residual", closure.gapped);
    }
    // Rendered, through a variable split out of a shared one so every read sees its value.
    if split > 0 {
        let _ = write!(&mut line, " ({split} through a split variable)");
    }
    // Spelled whenever not zero: saying nothing here let a gutted body report as clean.
    if closure.unattributed > 0 {
        let _ = write!(&mut line, ", {} unaccounted", closure.unattributed);
    }
    if closure.conflicts > 0 {
        let _ = write!(&mut line, ", {} conflicting", closure.conflicts);
    }
    line
}

/// State what the rendering did and did not show; always emitted, since silence would claim
/// everything was proven (doc/adr-decompiler-rewrite.md, "The proof line").
pub(crate) fn note_unproven_constructs(
    func: &mut CFunction,
    ledger: Option<&crate::ledger::ObligationLedger>,
    radare2_variadic_format_counts: usize,
    radare2_prototypes: usize,
    radare2_local_names: usize,
    (unassigned, open_second_result, laid_out): (&[UnassignedRead], bool, usize),
    unproven: Option<Option<r2types::UnprovenCause>>,
    floor: Option<(usize, &r2source::SourceArityFloor)>,
) {
    let rendered_nothing = func.body.is_empty();
    // Each residual is a construct the rendering says it did not prove, and
    // it traps where it stands: a residual call, or a marked gap.
    let residuals = crate::prelude::count_residuals(func);
    let detail = if rendered_nothing {
        "rendering produced no statements".to_string()
    } else {
        match residuals {
            0 => "no individual construct is marked".to_string(),
            1 => "1 construct is marked below".to_string(),
            n => format!("{n} constructs are marked below"),
        }
    };
    let mut detail = match ledger.map(|ledger| (ledger, ledger.close())) {
        Some((ledger, closure)) if closure.total > 0 => {
            let mut line = format!(
                "{detail}; {} source obligations: {} rendered, {} elided, {} refused",
                closure.total, closure.rendered, closure.elided, closure.refused
            );
            let decided = match unproven {
                Some(Some(r2types::UnprovenCause::ForwardCycle)) => Closed::Cycle,
                // A value no body proves, decided only by its reading calls.
                None if func.ret_type != crate::ast::CType::Void => Closed::Read,
                _ => Closed::Unread,
            };
            line.push_str(&proof_columns(&closure, ledger, decided));
            let _ = write!(
                &mut line,
                "; {} statements rendered",
                count_body_statements(&func.body)
            );
            line
        }
        _ => detail,
    };
    note_unassigned_reads(&mut detail, unassigned);
    let source_typed_objects =
        func.extern_objects
            .iter()
            .filter(|object| {
                object.type_fact.as_ref().is_some_and(|fact| {
                    fact.provenance == r2types::DataObjectTypeProvenance::Source
                })
            })
            .count();
    let refused_object_types = func
        .extern_objects
        .iter()
        .filter(|object| object.type_fact.is_none() && object.type_refusal.is_some())
        .count();
    if source_typed_objects > 0 {
        let noun = if source_typed_objects == 1 {
            "data object type"
        } else {
            "data object types"
        };
        let _ = write!(
            &mut detail,
            "; {source_typed_objects} {noun} supplied by the source"
        );
    }
    if refused_object_types > 0 {
        let noun = if refused_object_types == 1 {
            "data object type"
        } else {
            "data object types"
        };
        let _ = write!(&mut detail, "; {refused_object_types} {noun} refused");
    }
    if radare2_variadic_format_counts > 0 {
        let noun = if radare2_variadic_format_counts == 1 {
            "variadic callsite argument count"
        } else {
            "variadic callsite argument counts"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_variadic_format_counts} {noun} supplied by the source's format literals"
        );
    }
    if radare2_prototypes > 0 {
        let noun = if radare2_prototypes == 1 {
            "callee prototype"
        } else {
            "callee prototypes"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_prototypes} {noun} supplied by the source"
        );
    }
    note_floor(&mut detail, floor);
    if open_second_result {
        detail.push_str("; the result's second register is open: no call read decides it");
    }
    if let Some(cause) = unproven {
        let carried = crate::prelude::count_carried(func);
        let cause = cause.map_or("no return reached", r2types::UnprovenCause::name);
        let _ = write!(
            &mut detail,
            "; the result is unproven ({cause}): {carried} unproven-return carried"
        );
    }
    // A layout the accesses prove, spelled as a structure no declaration states (doc/adr-aggregates.md).
    match laid_out {
        0 => {}
        1 => detail.push_str("; 1 structure laid out from a parameter's accesses"),
        n => {
            let _ = write!(
                &mut detail,
                "; {n} structures laid out from parameters' accesses"
            );
        }
    }
    if radare2_local_names > 0 {
        let noun = if radare2_local_names == 1 {
            "local name"
        } else {
            "local names"
        };
        let _ = write!(
            &mut detail,
            "; {radare2_local_names} {noun} supplied by the source"
        );
    }
    // The names are identifiers the body declares, so the sanitizer keeps them.
    let text = {
        let symbols = func.symbols.borrow();
        sanitize_comment_text_keeping(&format!("r2dec proof: {detail}"), |token| {
            symbols.by_name(token).is_some()
        })
    };
    func.body.insert(0, CStmt::comment(text));
}

/// The header lists what is proven; a floor says more may be passed (D100).
fn note_floor(detail: &mut String, floor: Option<(usize, &r2source::SourceArityFloor)>) {
    if let Some((count, floor)) = floor {
        let causes = floor.causes().iter().map(floor_cause).collect::<Vec<_>>();
        let _ = write!(
            detail,
            "; the parameters are a floor: at least {count} ({})",
            causes.join(", ")
        );
    }
}

/// Why the parameters are only a floor, as the proof line words it (D37).
fn floor_cause(cause: &r2source::SourceFloorCause) -> String {
    use r2source::{SourceFloorCause as C, SourceUnprovenCall as U};
    match cause {
        C::UnresolvedTransfer => "a transfer is unresolved".into(),
        C::SupervisorEntry => "a supervisor entry".into(),
        C::ArgumentAreaUnplaced => "the argument area is unplaced".into(),
        C::ArgumentAreaRead => "the argument area is read past an unfull register section".into(),
        C::ArgumentAreaPastBudget => {
            "the argument area is read past the slots recovery holds".into()
        }
        C::RegisterRead => "a register past them is read".into(),
        C::Homed => "a register past them is only homed".into(),
        C::HandedOn(U::Indirect) => "a register past them reaches an indirect call".into(),
        C::HandedOn(U::Unstated(at) | U::Floor(at) | U::Stated(at)) => {
            format!("a register past them reaches the call to {at:#x}")
        }
        C::Unplaced(_) => "a declared parameter has no location".into(),
    }
}

/// Why a read the rendering spells as a residual has no value C can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnassignedCause {
    /// Held from entry, in storage no convention argument slot delivers.
    Held,
    /// Delivered in an argument slot no recovered parameter admits.
    UnadmittedArgument,
    /// A variadic body's tail register, or the vector count handed with it (`al`).
    VariadicTail,
    /// Declared and never assigned, with no value from entry behind it: a
    /// result a call left in a register nothing claimed, for one.
    Unassigned,
    /// Assigned, but where the block that reads it is not behind its definition: some path to the
    /// read leaves it unassigned.
    NotDominated,
}

impl UnassignedCause {}

/// One object whose every read is now a residual, and why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnassignedRead {
    pub(crate) cause: UnassignedCause,
    pub(crate) name: String,
}

/// Name the objects whose reads became residuals, by why each had no value.
///
/// A count cannot say which reads it excuses, so each is named. An argument
/// slot no parameter admits is named apart: the signature says the function
/// was not given that value, so reading it is a gap in the interface, not a
/// value held from entry.
fn note_unassigned_reads(detail: &mut String, unassigned: &[UnassignedRead]) {
    for (cause, one, many) in [
        (UnassignedCause::Held, "held from entry", "held from entry"),
        (
            UnassignedCause::UnadmittedArgument,
            "argument slot read with no parameter",
            "argument slots read with no parameter",
        ),
        (
            UnassignedCause::VariadicTail,
            "variadic tail register",
            "variadic tail registers",
        ),
        (
            UnassignedCause::Unassigned,
            "never assigned",
            "never assigned",
        ),
        (
            UnassignedCause::NotDominated,
            "assigned on only some paths to its read",
            "assigned on only some paths to their reads",
        ),
    ] {
        let names = unassigned
            .iter()
            .filter(|read| read.cause == cause)
            .map(|read| read.name.as_str())
            .collect::<Vec<_>>();
        if names.is_empty() {
            continue;
        }
        let noun = if names.len() == 1 { one } else { many };
        let _ = write!(
            detail,
            "; {} {noun}, read as residuals ({})",
            names.len(),
            names.join(", ")
        );
    }
}

/// Statements the body holds, counting the ones nested inside control flow.
fn count_body_statements(stmts: &[CStmt]) -> usize {
    fn visit(stmt: &CStmt) -> usize {
        match stmt.unobserved() {
            // A gap marks a cell that was not rendered; it is not one of
            // the statements the proof line counts as body.
            CStmt::Comment(_) | CStmt::Empty | CStmt::Gap(_) => 0,
            CStmt::Block(inner) => inner.iter().map(visit).sum(),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => 1 + visit(then_body) + else_body.as_deref().map(visit).unwrap_or(0),
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => 1 + visit(body),
            CStmt::For { init, body, .. } => {
                1 + init.as_deref().map(visit).unwrap_or(0) + visit(body)
            }
            CStmt::Switch { cases, default, .. } => {
                1 + cases
                    .iter()
                    .map(|case| case.body.iter().map(visit).sum::<usize>())
                    .sum::<usize>()
                    + default
                        .as_ref()
                        .map(|body| body.iter().map(visit).sum::<usize>())
                        .unwrap_or(0)
            }
            _ => 1,
        }
    }
    stmts.iter().map(visit).sum()
}
