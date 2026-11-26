//! The proof line: what the rendering did and did not show, and the reads it left as residuals.

use std::fmt::Write as _;

use r2source::Premise;

use crate::ast::{CFunction, CStmt};
use crate::codegen::escape_comment_text;

/// The proof line's columns that appear only when they are not zero, in reading order.
fn proof_columns(
    closure: &crate::ledger::LedgerClosure,
    ledger: &crate::ledger::ObligationLedger,
) -> String {
    let split = ledger.split_rendered();
    let mut line = String::new();
    if closure.compiler_inserted > 0 {
        // Each decided check passes under its premise: a canary the UB-free source, Go's stack
        // check the runtime's contract. A closed world is the result's, spelled below.
        let premises = (ledger.premises().iter())
            .filter(|premise| !matches!(premise, Premise::ClosedWorld | Premise::FrameIsolation))
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
    let unproven = ledger.unproven_exits();
    if unproven > 0 {
        let calls = if unproven == 1 {
            "call ends"
        } else {
            "calls end"
        };
        let _ = write!(
            &mut line,
            ", {unproven} {calls} where no return was reached (unproven)"
        );
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

/// The clauses the proof line adds: unassigned reads, the result's open lane and disputes, the
/// structures laid out, and the tags stated as two kinds.
type Clauses<'a> = (
    &'a ProofClauses,
    ((bool, bool), &'a [Disputed]),
    (usize, usize, usize),
    &'a [String],
    &'a [(usize, r2types::PointerRefusal)],
);

/// The frame-isolation clause, where an indirect call's promotion rests on it (D471).
fn note_frame_isolation(detail: &mut String, ledger: Option<&crate::ledger::ObligationLedger>) {
    if ledger.is_some_and(|ledger| ledger.premises().contains(&Premise::FrameIsolation)) {
        detail.push_str("; an indirect call writes no frame slot this function did not expose (assuming frame-isolation)");
    }
}

/// The pads the walk held apart: their flow enters no analysis until D598.
fn note_landing_pads(detail: &mut String, landing_pads: u32) {
    let noun = if landing_pads == 1 {
        "landing pad"
    } else {
        "landing pads"
    };
    if landing_pads > 0 {
        let _ = write!(
            detail,
            "; {landing_pads} {noun} not rendered: exceptional flow, a store read only there may be elided"
        );
    }
}

/// State what the rendering did and did not show; always emitted, since silence would claim
/// everything was proven (doc/adr-decompiler-rewrite.md, "The proof line").
pub(crate) fn note_unproven_constructs(
    func: &mut CFunction,
    ledger: Option<&crate::ledger::ObligationLedger>,
    radare2_variadic_format_counts: usize,
    radare2_prototypes: usize,
    radare2_local_names: usize,
    (clauses, ((open_second_result, integer_lane), disputed), laid_out, conflicting, parameters): Clauses<'_>,
    unproven: Option<Option<r2types::UnprovenCause>>,
    floor: Option<(usize, &r2source::SourceArityFloor)>,
    landing_pads: u32,
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
            line.push_str(&proof_columns(&closure, ledger));
            let _ = write!(
                &mut line,
                "; {} statements rendered",
                count_body_statements(&func.body)
            );
            line
        }
        _ => detail,
    };
    note_unassigned_reads(&mut detail, clauses);
    let source_typed_objects =
        func.extern_objects
            .iter()
            .filter(|object| {
                object.type_fact.as_ref().is_some_and(|fact| {
                    fact.provenance == r2types::DataObjectTypeProvenance::Source
                })
            })
            .count();
    let library_typed_objects = (func.extern_objects.iter())
        .filter(|object| {
            object.type_fact.as_ref().is_some_and(|fact| {
                matches!(
                    fact.provenance,
                    r2types::DataObjectTypeProvenance::Library { .. }
                )
            })
        })
        .count();
    let refused_object_types = clauses.refused_object_types.len();
    if library_typed_objects > 0 {
        let noun = if library_typed_objects == 1 {
            "data object type"
        } else {
            "data object types"
        };
        let _ = write!(
            &mut detail,
            "; {library_typed_objects} {noun} from C library rows the loader's copy binds"
        );
    }
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
    if let Some(index) = clauses.unclassed {
        let _ = write!(
            &mut detail,
            "; the signature is refused: parameter {index}'s C class is unknown, so the parameters listed are a floor"
        );
    }
    note_frame_isolation(&mut detail, ledger);
    note_landing_pads(&mut detail, landing_pads);
    if let Some(premises) = ledger.map(crate::ledger::ObligationLedger::result_premises)
        && !premises.is_empty()
    {
        let assumed = premises.iter().map(|premise| premise.spelled());
        let assumed = assumed.collect::<Vec<_>>().join(", ");
        let _ = write!(
            &mut detail,
            "{} (assuming {assumed})",
            closed_world(func, unproven, integer_lane)
        );
    }
    if open_second_result {
        detail.push_str("; the result's second register is open: no call read decides it");
    }
    if let Some(cause) = unproven {
        note_unproven(&mut detail, func, cause);
    }
    note_unproven_parameters(&mut detail, parameters);
    note_disputed(&mut detail, disputed);
    // A layout the accesses prove, spelled as a structure no declaration states (doc/adr-aggregates.md).
    // A tag two graphs state as different kinds has no one declaration: its pointers are words.
    for tag in conflicting {
        let _ = write!(
            &mut detail,
            "; tag `{tag}` is stated as both a struct and a union, so a pointer to it is spelled at its class"
        );
    }
    let (laid_out, through_loaded, recursive) = laid_out;
    match through_loaded {
        0 => {}
        1 => detail.push_str("; 1 structure laid out from a loaded pointer's accesses"),
        n => {
            let _ = write!(
                &mut detail,
                "; {n} structures laid out from loaded pointers' accesses"
            );
        }
    }
    match recursive {
        0 => {}
        1 => detail.push_str("; 1 record refused: a pointer field leads back to it (Recursive)"),
        n => {
            let _ = write!(
                &mut detail,
                "; {n} records refused: a pointer field leads back to each (Recursive)"
            );
        }
    }
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
    let text = escape_comment_text(&format!("r2dec proof: {detail}"));
    func.body.insert(0, CStmt::comment(text));
}

/// A premise is its own clause: what the closed world decided of the result (D166, D234), or of
/// the integer result register alone, which says nothing of the result (D440).
fn closed_world(
    func: &CFunction,
    unproven: Option<Option<r2types::UnprovenCause>>,
    integer_lane: bool,
) -> String {
    let result = match unproven {
        Some(Some(r2types::UnprovenCause::ForwardCycle)) => {
            Some("; a call returns the result on through a cycle")
        }
        // A value no body proves, decided only by its reading calls, or one whose width they leave open.
        None if func.ret_type != crate::ast::CType::Void => Some("; a call reads the result"),
        Some(Some(
            r2types::UnprovenCause::WidthUnbounded
            | r2types::UnprovenCause::WidthBetween
            | r2types::UnprovenCause::PointerWide,
        )) => Some("; a call reads the result"),
        _ if integer_lane => None,
        _ => Some("; no call reads the result"),
    };
    let lane = integer_lane.then_some("; no call reads the integer result register");
    result.into_iter().chain(lane).collect()
}

/// A result lane where the body's returns contradict the declaration, and what they leave there.
type Disputed = (r2source::SourceTypedLane, r2source::SourceBodyLane);

/// The declaration stays, and each lane its body disputes is named (D331): refusal evidence.
fn note_disputed(detail: &mut String, disputed: &[Disputed]) {
    use r2source::{SourceBodyLane as Body, SourceTypedLane as Lane};
    for (lane, body) in disputed {
        let lane = match lane {
            Lane::Integer => "integer",
            Lane::Float => "float",
        };
        let found = match body {
            Body::None => "no return defines",
            Body::Written => "a return defines",
            Body::Open => continue,
        };
        let _ = write!(
            detail,
            "; the declared result is kept against the body: {found} the {lane} result register"
        );
    }
}

/// A parameter spelled at its carrier names why no type is proven (D610).
fn note_unproven_parameters(detail: &mut String, parameters: &[(usize, r2types::PointerRefusal)]) {
    for (index, cause) in parameters {
        let _ = write!(detail, "; parameter {index} is unproven ({})", cause.name());
    }
}

/// Every return of the unproven result, counted once: carried, or a residual (D233).
fn note_unproven(detail: &mut String, func: &CFunction, cause: Option<r2types::UnprovenCause>) {
    let (carried, residual) = crate::prelude::unproven_returns(func);
    let cause = cause.map_or("no return reached", r2types::UnprovenCause::name);
    let _ = write!(
        detail,
        "; the result is unproven ({cause}): {carried} unproven-return carried"
    );
    if residual > 0 {
        let _ = write!(detail, ", {residual} unproven-return residual");
    }
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
        C::ArgumentAreaRead => "the argument area is read past the parameters".into(),
        C::ArgumentAreaPastBudget => {
            "the argument area is read past the slots recovery holds".into()
        }
        C::ArgumentAreaEscapes => "an address of the argument area escapes".into(),
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
pub enum UnassignedCause {
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

impl UnassignedCause {
    /// The cause's stable name in a typed response.
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::UnadmittedArgument => "unadmitted-argument",
            Self::VariadicTail => "variadic-tail",
            Self::Unassigned => "never-assigned",
            Self::NotDominated => "not-dominated",
        }
    }

    /// The proof line's words for `count` reads of this cause.
    pub const fn spelled(self, count: usize) -> &'static str {
        let one = count == 1;
        match self {
            Self::Held => "held from entry",
            Self::UnadmittedArgument if one => "argument slot read with no parameter",
            Self::UnadmittedArgument => "argument slots read with no parameter",
            Self::VariadicTail if one => "variadic tail register",
            Self::VariadicTail => "variadic tail registers",
            Self::Unassigned => "never assigned",
            Self::NotDominated if one => "assigned on only some paths to its read",
            Self::NotDominated => "assigned on only some paths to their reads",
        }
    }
}

/// One object whose every read is now a residual, and why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnassignedRead {
    pub(crate) cause: UnassignedCause,
    pub(crate) name: String,
}

/// Name the objects whose reads became residuals, by why each had no value.
///
/// A count cannot say which reads it excuses, so each is named.
fn note_unassigned_reads(detail: &mut String, clauses: &ProofClauses) {
    for (cause, names) in &clauses.unassigned {
        let _ = write!(
            detail,
            "; {} {}, read as residuals ({})",
            names.len(),
            cause.spelled(names.len()),
            names.join(", ")
        );
    }
}

/// The proof line's typed clauses, which its text is spelled from and a typed response
/// carries (D621): each refused data object type and each unassigned cause, by name. `O(clauses)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProofClauses {
    refused_object_types: Vec<String>,
    unassigned: Vec<(UnassignedCause, Vec<String>)>,
    /// The first formal whose C class is unknown: the signature is refused there (D661).
    unclassed: Option<u32>,
}

impl ProofClauses {
    /// The clauses of `func`, whose data objects are declared, with the reads left unassigned.
    pub(crate) fn of(
        func: &CFunction,
        unassigned: &[UnassignedRead],
        unclassed: Option<u32>,
    ) -> Self {
        let refused_object_types = (func.extern_objects.iter())
            .filter(|object| object.type_fact.is_none() && object.type_refusal.is_some())
            .map(|object| object.name.clone())
            .collect();
        let mut by_cause: Vec<(UnassignedCause, Vec<String>)> = Vec::new();
        let mut reads = unassigned.to_vec();
        reads.sort();
        for read in reads {
            match by_cause.last_mut() {
                Some((cause, names)) if *cause == read.cause => names.push(read.name),
                _ => by_cause.push((read.cause, vec![read.name])),
            }
        }
        Self {
            refused_object_types,
            unassigned: by_cause,
            unclassed,
        }
    }

    /// The data objects whose type was refused, by name, in declaration order.
    pub fn refused_object_types(&self) -> &[String] {
        &self.refused_object_types
    }

    /// Each cause a read was left unassigned for, with the names read, in cause order.
    pub fn unassigned(&self) -> &[(UnassignedCause, Vec<String>)] {
        &self.unassigned
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A formal whose C class is unknown refuses the signature: the header lists the formals before
    /// it as a floor and never spells `(void)`, which states no parameters (C17 6.7.6.3p10, D661).
    #[test]
    fn an_unclassed_formal_refuses_the_signature_and_never_spells_void() {
        let mut func = CFunction::new("f", crate::ast::CType::Void);
        func.params_known = false;
        let clauses = ProofClauses {
            refused_object_types: Vec::new(),
            unassigned: Vec::new(),
            unclassed: Some(0),
        };
        let parameters = (
            &clauses,
            ((false, false), &[][..]),
            (0, 0, 0),
            &[][..],
            &[][..],
        );
        note_unproven_constructs(&mut func, None, 0, 0, 0, parameters, None, None, 0);
        let mut codegen =
            crate::codegen::CodeGenerator::new(crate::codegen::CodeGenConfig::default());
        let ready = crate::codegen::prepare_function_for_emission(func);
        let code = codegen.generate_function(&ready);
        assert!(code.contains("void f()"), "{code}");
        assert!(code.contains("parameter 0's C class is unknown"), "{code}");
    }
}
