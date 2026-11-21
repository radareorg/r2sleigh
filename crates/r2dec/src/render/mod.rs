//! The staged decompiler (doc/adr-decompiler-rewrite.md): one pass per stage over the sealed facts,
//! a residual wherever they stop. D0 is the input, D1 the control, D2 the values, D3 the terms.

mod calls;
mod control;
pub(crate) mod globals;
mod input;
pub(crate) mod proof;
mod spelled;
mod tags;
mod terms;
mod values;

use std::collections::BTreeMap;

pub use input::RenderInput;

use crate::ast::{CExpr, CFunction, CStmt, CType, RenderObservationId};
use crate::codegen::{
    CodeGenConfig, CodeGenerator, EmissionReadyFunction, escape_comment_text,
    prepare_function_for_emission,
};
use crate::control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
use crate::ledger::{ObligationLedger, Outcome};
use crate::structure::certify::StatementRole;
use crate::structure::shape::{Evidence, Occurrences, site_of};

/// One function the staged pipeline rendered, and what became of each obligation.
pub struct Rendered {
    function: crate::codegen::RenderedFunction,
    ledger: ObligationLedger,
    /// A stop that came once the control was written and certified: the body is what was reached.
    stopped: Option<DecompileExecutionStop>,
}

impl Rendered {
    pub fn into_parts(self) -> (crate::codegen::RenderedFunction, ObligationLedger) {
        (self.function, self.ledger)
    }

    /// The stop the rendering was asked for after its body was certified, if any.
    pub const fn stopped(&self) -> Option<&DecompileExecutionStop> {
        self.stopped.as_ref()
    }
}

/// An import stub's C, as r2engine's route decides it; it has no body, so no obligation is owed.
pub fn import_stub(stub: &r2types::ImportStub, ptr_bits: u32) -> crate::codegen::RenderedFunction {
    let ready = import_stub_declaration(stub);
    let emission = CodeGenerator::new(CodeGenConfig::default()).emit(&ready, ptr_bits);
    crate::codegen::RenderedFunction::new(emission, ready.into_function())
}

/// Why the staged pipeline wrote no function.
#[derive(Debug, Clone)]
pub enum RenderStop {
    Stopped(DecompileExecutionStop),
    /// The written control is not the machine's graph: the §3 certificate says where.
    Refused(String),
}

impl From<DecompileExecutionStop> for RenderStop {
    fn from(stop: DecompileExecutionStop) -> Self {
        Self::Stopped(stop)
    }
}

/// Render one sealed function through the stages that exist.
pub fn render(
    input: &RenderInput<'_>,
    control: &dyn r2ssa::SsaWorkControl,
) -> Result<Rendered, RenderStop> {
    let work = DecompileWorkControl::new(control, DecompileWorkPhase::Structuring);
    work.poll()?;
    let name = rendered_name_of(input.name(), input.function().cfg().entered_at());
    let tags = tags::Tags::of(input);
    let function = input.function();
    let placement = crate::structure::place::Placement::compute(
        function.cfg(),
        function.domtree(),
        function.natural_loops(),
        function.root(),
    );
    let order = crate::structure::place::placed_in_order(function);
    let (mut c, values, spelled) = spell_function(input, &tags, &name, &order, &work)?;
    let written = control::write(input, spelled, &placement, &work);
    if let Some(stop) = written.stopped {
        return Err(stop.into());
    }
    let control::Written {
        body,
        labels,
        blocks,
        addresses,
        ..
    } = written;
    let never_return = values
        .as_ref()
        .map(values::Values::never_returning)
        .unwrap_or_default();
    let distinct_return =
        |addr: u64| (values.as_ref()).is_some_and(|values| values.returns_distinct_merge(addr));
    let evidence = Evidence::new(&never_return, &distinct_return);
    let mut occurrences = Occurrences::new(blocks, addresses);
    let mut body = structured(input, body, &labels, &evidence, &mut occurrences);
    let selections = select(&c, &mut body, &|id| occurrences.block_of(id));
    let role = |stmt: &CStmt| statement_role(stmt, &evidence, &selections);
    let certified = certifier(input, &labels, &role);
    let mut body = classes(
        input,
        (&c, values.as_ref()),
        body,
        &mut occurrences,
        &certified,
    );
    certify_control(input, &body, &occurrences, &labels, &role)?;
    crate::structure::condition::respell_negations(&mut body);
    // What remains is linear emission of a certified body, so a stop here keeps what was reached.
    let stopped = work.with_phase(DecompileWorkPhase::Rendering).poll().err();
    declare(&mut c, input, values.as_ref());
    c.body = match body {
        CStmt::Block(stmts) => stmts,
        stmt => vec![stmt],
    };
    drop_unmentioned_locals(&mut c);
    crate::ast::respell_nonconforming_main(&mut c, input.function().entry);
    let ledger = close_ledger(input, values.as_ref());
    let unassigned = values.as_ref().map(values::Values::unassigned);
    let clauses = proof::ProofClauses::of(&c, unassigned.as_deref().unwrap_or_default());
    open_proof_line(&mut c, input, &ledger, &clauses, &tags);
    let mut ready = ready_with_carriers(c, &tags);
    // Each marker names the instruction its statement was written for, so each line names its own.
    ready.seal_observation_markers(
        &mut crate::codegen::ObservationSealAuthority::staged(),
        crate::codegen::ObservationLocations::new(occurrences.into_addresses()),
    );
    let emission = CodeGenerator::new(CodeGenConfig::default())
        .emit(&ready, input.ptr_bits())
        .with_clauses(clauses);
    Ok(Rendered {
        function: crate::codegen::RenderedFunction::new(emission, ready.into_function()),
        ledger,
        stopped,
    })
}

/// The proof line every rendering opens with: what became of each obligation the source owes.
fn open_proof_line(
    c: &mut CFunction,
    input: &RenderInput<'_>,
    ledger: &ObligationLedger,
    clauses: &proof::ProofClauses,
    tags: &tags::Tags,
) {
    proof::note_unproven_constructs(
        c,
        Some(ledger),
        0,
        input.declared_call_prototypes(),
        0,
        (
            clauses,
            (
                (input.open_second_result(), input.integer_lane_unread_only()),
                &input.body_disputed_lanes(),
            ),
            input.records().definitions.len(),
            &tags.conflicting(),
            &input.unproven_parameters(),
        ),
        (input.return_type())
            .filter(|fact| fact.is_unproven())
            .map(r2types::ReturnTypeFact::unproven_cause),
        input.arity_floor(),
        input.artifact().landing_pads(),
    );
}

/// D2 over every placed block. A late edge's copy is promised to render; when one gaps, spell again with
/// that merge owing one more (ADR D58). Each attempt adds a merge to `forced`, so they end.
fn spell_function<'a>(
    input: &RenderInput<'a>,
    tags: &tags::Tags,
    name: &str,
    order: &[u64],
    work: &DecompileWorkControl<'_>,
) -> Result<(CFunction, Option<values::Values<'a>>, spelled::Spelled), DecompileExecutionStop> {
    let mut forced = r2ssa::dense::IdSet::new(input.graph().values.len());
    loop {
        let mut c = CFunction::new(name.to_owned(), result_type(input, tags));
        spell_unproven_carrier(&mut c, input);
        let values = values::Values::new(input, tags, std::rc::Rc::clone(&c.symbols), &forced);
        let spelled = spelled::spell(input, tags, values.as_ref(), order, work)?;
        let broken = values
            .as_ref()
            .map(values::Values::broken)
            .unwrap_or_default();
        if broken.is_empty() {
            return Ok((c, values, spelled));
        }
        r2il::refusal_evidence!(
            "late-copy-gapped",
            "{name}: {} merges read as variables on a promise a late copy broke; spelling again",
            broken.len()
        );
        broken
            .into_iter()
            .for_each(|merge| _ = forced.insert(merge));
    }
}

/// What the values stage declared for `c`, or that its parameters are unknown.
fn declare(c: &mut CFunction, input: &RenderInput<'_>, values: Option<&values::Values>) {
    match values {
        Some(values) => {
            c.params = values.params();
            c.variadic = input.variadic();
            c.locals = values.locals();
            c.externs = values.externs();
            c.extern_objects = values.extern_objects();
        }
        None => c.params_known = false,
    }
}

/// `c` ready to emit: a wide carrier is a struct the unit defines, with the helpers that take it
/// apart, and each declared tag it spells is defined after them.
fn ready_with_carriers(c: CFunction, tags: &tags::Tags) -> crate::codegen::EmissionReadyFunction {
    let helpers = crate::bitvector::helpers_called(&c);
    let mut carriers = std::collections::BTreeSet::new();
    carriers.extend(helpers.iter().flat_map(|helper| helper.carriers()));
    carriers.extend(
        c.locals
            .iter()
            .map(|local| &local.ty)
            .chain(c.params.iter().map(|param| &param.ty))
            .filter_map(|ty| match ty {
                CType::BitVector(bits) => Some(*bits),
                _ => None,
            }),
    );
    let declared = tags.definitions(&c);
    let mut ready = prepare_function_for_emission(c);
    ready.set_aggregate_definitions(
        (carriers.into_iter())
            .filter_map(crate::bitvector::carrier_definition)
            .chain(declared)
            .collect(),
    );
    ready.set_bitvector_helpers(helpers);
    ready
}

/// D1.1: SD's stages over the placed body, each kept only while the control certificate still holds
/// (ADR §5): condition chains, `shape`, the latch's copies, loop rotation, and the noreturn guards.
fn structured(
    input: &RenderInput<'_>,
    body: Vec<CStmt>,
    labels: &BTreeMap<u64, String>,
    evidence: &Evidence<'_>,
    marks: &mut Occurrences,
) -> CStmt {
    let unselected = std::collections::BTreeSet::new();
    let role = |stmt: &CStmt| statement_role(stmt, evidence, &unselected);
    let certified = certifier(input, labels, &role);
    let chains = |body: &mut CStmt, marks: &mut Occurrences| {
        crate::structure::condition::collapse(body, marks).collapsed != 0
    };
    let body = stage(
        "condition chains",
        CStmt::Block(body),
        marks,
        &certified,
        chains,
    );
    // The readability rewrites below copy a block's text as a new occurrence of that block.
    let body = crate::structure::shape::shape(marks, evidence, body);
    let body = stage("latch copies", body, marks, &certified, |body, marks| {
        crate::structure::latch::hoist(body, marks) != 0
    });
    let body = stage("loop rotation", body, marks, &certified, |body, marks| {
        crate::structure::rotate::rotate(body, marks) != 0
    });
    let body = stage("noreturn guards", body, marks, &certified, |body, marks| {
        crate::structure::guard::guard(body, evidence, marks) != 0
    });
    stage("equality chains", body, marks, &certified, |body, marks| {
        let block_of = |id| marks.block_of(id);
        crate::structure::chain::switch(body, &|block| tested(input, block), &block_of, 0) != 0
    })
}

/// The value a test block compares for equality and the constant its other operand is proven to
/// be, as r2types states the branch (D474); a block whose fact says less tests nothing.
fn tested(input: &RenderInput<'_>, block: u64) -> Option<(r2ssa::ValueId, u64)> {
    let fact = input.control()?.branch_for_block(block)?;
    let comparison = fact.render_comparison.or(fact.comparison)?;
    if !matches!(
        comparison.kind,
        r2ssa::CompareKind::Equal | r2ssa::CompareKind::NotEqual
    ) {
        return None;
    }
    let artifact = input.artifact();
    let (lhs, rhs) = (comparison.lhs, comparison.rhs);
    match (artifact.proven_constant(lhs), artifact.proven_constant(rhs)) {
        (None, Some(constant)) => Some((lhs, constant)),
        (Some(constant), None) => Some((rhs, constant)),
        _ => None,
    }
}

/// SD's §3 certificate over a body.
fn control_certificate(
    input: &RenderInput<'_>,
    body: &CStmt,
    occurrences: &Occurrences,
    labels: &BTreeMap<u64, String>,
    role: &dyn Fn(&CStmt) -> StatementRole,
) -> crate::structure::certify::ControlCertificate {
    let function = input.function();
    let label_block = labels
        .iter()
        .map(|(addr, name)| (name.as_str(), *addr))
        .collect::<BTreeMap<_, _>>();
    crate::structure::certify::certify(
        body,
        function.cfg(),
        function.domtree(),
        function.root(),
        occurrences,
        &|name| label_block.get(name).copied(),
        role,
    )
}

/// The certificate over the shaped body, or the refusal that names its first violation.
fn certify_control(
    input: &RenderInput<'_>,
    body: &CStmt,
    occurrences: &Occurrences,
    labels: &BTreeMap<u64, String>,
    role: &dyn Fn(&CStmt) -> StatementRole,
) -> Result<(), RenderStop> {
    let certificate = control_certificate(input, body, occurrences, labels, role);
    if certificate.ok() {
        return Ok(());
    }
    Err(RenderStop::Refused(format!(
        "control certificate: {certificate} {:?}",
        certificate.violations.first()
    )))
}

/// The control certificate over a candidate body and its markers: `Err` names the first violation.
type Certified<'a> = dyn Fn(&CStmt, &Occurrences) -> Result<(), String> + 'a;

/// The control certificate as a stage reads it: `Ok` where it holds, else its first violation.
fn certifier<'a, 'b: 'a>(
    input: &'a RenderInput<'b>,
    labels: &'a BTreeMap<u64, String>,
    role: &'a dyn Fn(&CStmt) -> StatementRole,
) -> impl Fn(&CStmt, &Occurrences) -> Result<(), String> + 'a {
    move |stmt, marks| {
        let certificate = control_certificate(input, stmt, marks, labels, role);
        match certificate.ok() {
            true => Ok(()),
            false => Err(format!(
                "{certificate} {:?}",
                certificate.violations.first()
            )),
        }
    }
}

/// Run one structure stage on `body`; its result stands only if the certificate still holds.
/// `apply` says whether it changed anything, and an unchanged body is not certified again.
fn stage(
    name: &str,
    body: CStmt,
    marks: &mut Occurrences,
    certified: &Certified<'_>,
    apply: impl FnOnce(&mut CStmt, &mut Occurrences) -> bool,
) -> CStmt {
    let issued = marks.issued();
    let mut candidate = body.clone();
    if !apply(&mut candidate, marks) {
        return body;
    }
    match certified(&candidate, marks) {
        Ok(()) => candidate,
        Err(why) => {
            r2il::refusal_evidence!(
                "stage-reverted",
                "{name} broke the control certificate: {why}"
            );
            marks.retract(issued);
            body
        }
    }
}

/// D1.1's selections, each arm converted to `x`'s type as its own assignment converted it.
fn select(
    c: &CFunction,
    body: &mut CStmt,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> std::collections::BTreeSet<RenderObservationId> {
    let convert = |target: crate::symbol::SymbolId, value: CExpr| {
        let symbols = c.symbols.borrow();
        let ty = symbols.ty(target);
        match value.unobserved() {
            CExpr::Var(symbol) if symbols.ty(*symbol) == ty => value,
            _ => terms::at_sink(ty, CExpr::cast(ty.clone(), value)),
        }
    };
    let mut selections = std::collections::BTreeSet::new();
    crate::structure::shape::select(body, &convert, block_of, &mut selections);
    selections
}

/// D470: each class's members spelled as one symbol where the finished text proves it, then each
/// loop whose arms that emptied rotated; each stage kept only under the control certificate.
fn classes(
    input: &RenderInput<'_>,
    (c, values): (&CFunction, Option<&values::Values<'_>>),
    body: CStmt,
    marks: &mut Occurrences,
    certified: &Certified<'_>,
) -> CStmt {
    let Some(values) = values else {
        return body;
    };
    let members = class_members(input, c, values);
    if members.is_empty() {
        return body;
    }
    let symbols = c.symbols.borrow();
    let same_type = |a, b| symbols.ty(a) == symbols.ty(b);
    let mut deleted = Vec::new();
    let body = stage("local classes", body, marks, certified, |body, _| {
        let renamed = crate::structure::classes::rename(body, &members, symbols.len(), &same_type);
        r2il::refusal_evidence!(
            "local-classes",
            "{}: {} members, {} joined, kept {:?}, spelled {:?}",
            input.name().unwrap_or_default(),
            renamed.members,
            renamed.joined,
            renamed.kept,
            (renamed.spelled.iter())
                .map(|(from, to)| format!("{}>{}", symbols.name(*from), symbols.name(*to)))
                .collect::<Vec<_>>()
        );
        deleted = renamed.deleted;
        deleted.sort();
        renamed.joined != 0
    });
    if deleted.is_empty() {
        return body;
    }
    stage("loop rotation", body, marks, certified, |body, marks| {
        crate::structure::classes::rotate_emptied(body, &deleted, marks) != 0
    })
}

/// The carriers whose values r2ssa classes with another carrier's, by class then value.
fn class_members(
    input: &RenderInput<'_>,
    c: &CFunction,
    values: &values::Values<'_>,
) -> Vec<crate::structure::classes::Member> {
    let classes = &input.artifact().facts().classes;
    let symbols = c.symbols.borrow();
    let mut members = (values.named())
        .filter(|(_, symbol)| symbols.get(*symbol).role == crate::symbol::SymbolRole::Carrier)
        .map(|(value, symbol)| crate::structure::classes::Member {
            class: classes.class_of(value).0,
            value: value.0,
            symbol,
        })
        .collect::<Vec<_>>();
    members.sort();
    let shared = |at: usize| {
        let class = members[at].class;
        (at > 0 && members[at - 1].class == class)
            || members.get(at + 1).is_some_and(|next| next.class == class)
    };
    let keep = (0..members.len()).map(shared).collect::<Vec<_>>();
    let mut keep = keep.into_iter();
    members.retain(|_| keep.next().unwrap_or(false));
    members
}

/// What the certificate reads a statement as: a selection the stage recorded, or one ending control.
fn statement_role(
    stmt: &CStmt,
    evidence: &Evidence<'_>,
    selections: &std::collections::BTreeSet<RenderObservationId>,
) -> StatementRole {
    match stmt
        .observation_ids()
        .iter()
        .any(|id| selections.contains(id))
    {
        true => StatementRole::Selects,
        false => (traps(stmt) || evidence.never_returns(site_of(stmt))).into(),
    }
}

/// A local nothing in the text names, every read of it a residual, declares nothing.
fn drop_unmentioned_locals(c: &mut CFunction) {
    let mut mentioned = std::collections::BTreeSet::new();
    c.visit_body_exprs(&mut |node| {
        if let CExpr::Var(symbol) = node {
            mentioned.insert(*symbol);
        }
    });
    c.locals.retain(|local| mentioned.contains(&local.name));
}

/// What became of each obligation: D2's account, or every one a gap where D2 did not run.
fn close_ledger(input: &RenderInput<'_>, values: Option<&values::Values<'_>>) -> ObligationLedger {
    let mut ledger = ObligationLedger::open(input.obligations(), input.graph())
        .with_premises(input.function().premises_with_result())
        .with_result_premises(
            (input.artifact().machine_context().function_interface())
                .map_or(&[], r2source::SourceFunctionInterface::closed_premises),
        )
        .with_exits(input.function().assumed_exits());
    match values {
        Some(values) => values.close(&mut ledger),
        None => {
            for id in input.obligations().obligations().keys() {
                ledger.record(*id, Outcome::Gapped);
            }
        }
    }
    ledger
}

/// Whether a statement ends control: a residual or a marked gap traps where it is evaluated.
fn traps(stmt: &CStmt) -> bool {
    matches!(stmt, CStmt::Gap(marker) if marker.kind.ends_control())
        || matches!(stmt, CStmt::Expr(CExpr::Call { func, .. }) if crate::prelude::is_residual_callee(func).is_some())
}

/// The function's result type: what the analysis decided, spelled as a parameter is where C spells
/// it, else the machine word.
fn result_type(input: &RenderInput<'_>, tags: &tags::Tags) -> CType {
    let declared = input
        .return_type()
        .and_then(r2types::ReturnTypeFact::declared);
    declared.map_or_else(
        || word(input),
        |declared| {
            calls::spellable(declared, &|tag, union| tags.names(tag, union))
                .unwrap_or_else(|| declared.clone())
        },
    )
}

/// The bits of an unproven result's carrier, where it is an integer C names.
fn unproven_carrier_bits(input: &RenderInput<'_>) -> Option<u32> {
    let fact = input.return_type().filter(|fact| fact.is_unproven())?;
    match fact.declared()? {
        CType::Int { bits, .. } if crate::prelude::carrier(*bits).is_some() => Some(*bits),
        _ => None,
    }
}

/// An unproven result's header states only where the machine leaves a value: the prelude typedef
/// `r2sleigh_result_uN`, which claims no C type (doc/adr-scratch-result.md, "Rendering of Unproven").
fn spell_unproven_carrier(c: &mut CFunction, input: &RenderInput<'_>) {
    if let Some(bits) = unproven_carrier_bits(input) {
        c.ret_type = crate::prelude::result_carrier(bits);
    }
}

/// The machine word, unsigned: the storage a result carrier holds.
fn word(input: &RenderInput<'_>) -> CType {
    word_type(input.ptr_bits())
}

fn word_type(bits: u32) -> CType {
    CType::Int {
        bits,
        signedness: r2types::Signedness::Unsigned,
    }
}

/// The C name a rendering gives a function, from what it is called and where
/// it starts.
pub fn rendered_name_of(name: Option<&str>, entry: u64) -> String {
    name.and_then(r2types::sanitize_c_identifier)
        .unwrap_or_else(|| r2source::unnamed_identifier(entry))
}

/// A function the renderer refused: the reason, and no definition.
///
/// A definition with nothing proven in it would still have to claim a return
/// type and a parameter list, and a comment in place of both is not C. What is
/// known is why nothing is defined, so that is what is written.
/// An import stub as C, as r2engine's route decides it: the import's declaration and a comment
/// naming it, or the comment alone where nothing states its prototype.
pub(crate) fn import_stub_declaration(stub: &r2types::ImportStub) -> EmissionReadyFunction {
    let name = crate::ast::c_identifier(&stub.name);
    let entry = stub.entry;
    let Some(signature) = stub.signature.as_ref() else {
        let reason = format!(
            "r2sleigh: import stub at {entry:#x}; this symbol is the import `{name}`, \
             whose prototype nothing states."
        );
        return prepare_function_for_emission(residual_function_for_render_boundary(
            &name, &reason,
        ));
    };
    let reason = format!(
        "r2sleigh: import stub at {entry:#x}; this symbol is the import `{name}` and \
         has no body of its own."
    );
    let mut function = CFunction::new(name.clone(), signature.return_type.clone())
        .as_declaration_only(escape_comment_text(&reason));
    function.externs = vec![crate::ast::CExternDecl {
        name,
        ret_type: signature.return_type.clone(),
        params: Some(signature.params.clone()),
        variadic: signature.variadic,
        noreturn: false,
        address: Some(entry),
    }];
    prepare_function_for_emission(function)
}

pub(crate) fn residual_function_for_render_boundary(func_name: &str, reason: &str) -> CFunction {
    CFunction::new(func_name.to_string(), CType::Unknown)
        .with_unknown_params()
        .as_declaration_only(format!(
            "r2dec refused {}: {}",
            crate::ast::c_identifier(func_name),
            escape_comment_text(reason)
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::test_render_observation_id;
    use std::collections::BTreeSet;

    fn id(index: usize) -> RenderObservationId {
        RenderObservationId::from_dense_index(index)
    }

    /// Markers 0 and 1 for blocks 0x10 and 0x20, the second on the body's one statement.
    fn start() -> (CStmt, Occurrences) {
        let body = CStmt::observe_all([id(1)], CStmt::Break);
        (
            body,
            Occurrences::new(vec![0x10, 0x20], vec![Some(0x11), Some(0x21)]),
        )
    }

    /// A stage that writes a copy of the body under a marker of its own, and one more marker.
    fn copies(body: &mut CStmt, marks: &mut Occurrences) -> bool {
        *body = marks.fresh(body);
        marks.copy_of(id(0));
        true
    }

    #[test]
    fn a_stage_that_breaks_the_certificate_leaves_neither_its_text_nor_its_markers() {
        let (body, mut marks) = start();
        let refuse = |_: &CStmt, _: &Occurrences| Err("broken".to_owned());
        let kept = stage("copies", body.clone(), &mut marks, &refuse, copies);
        assert_eq!(kept, body);
        assert_eq!((marks.issued(), marks.block_of(id(1))), (2, Some(0x20)));
        assert_eq!(marks.into_addresses(), [Some(0x11), Some(0x21)]);
    }

    #[test]
    fn a_stage_that_keeps_the_certificate_keeps_its_text_and_its_markers() {
        let (body, mut marks) = start();
        let accept = |candidate: &CStmt, marks: &Occurrences| {
            let copied = candidate.observation_ids().into_owned();
            assert_eq!((copied.len(), marks.block_of(copied[0])), (1, Some(0x20)));
            Ok(())
        };
        let kept = stage("copies", body, &mut marks, &accept, copies);
        assert_eq!(kept.observation_ids().into_owned(), [id(2)]);
        assert_eq!(marks.issued(), 4);
    }

    #[test]
    fn a_call_ends_control_by_its_site_s_proof_whatever_it_passes() {
        let declared = crate::structure::support::declared();
        let none = r2ssa::dense::IdSet::new(0);
        for (set, role) in [
            (&declared, StatementRole::Ends),
            (&none, StatementRole::Plain),
        ] {
            let evidence = Evidence::new(set, &|_| false);
            // A selection the call does not carry leaves its role to the declaration.
            let selected = [
                BTreeSet::new(),
                BTreeSet::from([test_render_observation_id(9)]),
            ];
            let calls = crate::structure::support::exit_calls();
            for (call, selections) in
                calls.flat_map(|call| selected.iter().map(move |s| (call.clone(), s)))
            {
                assert_eq!(
                    statement_role(&call, &evidence, selections),
                    role,
                    "{call:?} {selections:?}"
                );
            }
        }
    }
}
