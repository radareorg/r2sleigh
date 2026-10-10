//! The staged decompiler (doc/adr-decompiler-rewrite.md): one pass per stage over the sealed facts,
//! a residual wherever they stop. D0 is the input, D1 the control, D2 the values, D3 the terms.

mod calls;
mod control;
mod frame;
pub(crate) mod globals;
mod input;
pub(crate) mod proof;
mod tags;
mod terms;
mod values;

use std::collections::BTreeMap;

pub use input::RenderInput;

use crate::ast::{CExpr, CFunction, CStmt, CType, RenderObservationId};
use crate::codegen::{
    CodeGenConfig, CodeGenerator, EmissionReadyFunction, prepare_function_for_emission,
    sanitize_comment_text,
};
use crate::control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
use crate::ledger::{ObligationLedger, Outcome};
use crate::structure::certify::StatementRole;

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
    let name = rendered_name_of(input.name(), input.function().root());
    let mut c = CFunction::new(name, result_type(input));
    let tags = tags::Tags::of(input);
    let values = values::Values::new(input, &tags, std::rc::Rc::clone(&c.symbols));
    let written = control::write(input, values.as_ref(), &work);
    if let Some(stop) = written.stopped {
        return Err(stop.into());
    }
    let control::Written {
        body,
        labels,
        mut blocks,
        mut addresses,
        ..
    } = written;
    // D1.1: SD's readability rewrites; a block's text they copy is a new occurrence of its block.
    let mut fresh = |stmt: &CStmt| {
        control::remint(stmt, &mut |id| {
            let at = id.index() as usize;
            let copy = crate::ast::RenderObservationId::from_dense_index(blocks.len());
            blocks.push(blocks[at]);
            addresses.push(addresses[at]);
            copy
        })
    };
    let mut body = crate::structure::shape::shape(&mut fresh, CStmt::Block(body));
    let selections = select(&c, &mut body, &|id| {
        blocks.get(id.index() as usize).copied()
    });
    let never_return = values
        .as_ref()
        .map(values::Values::never_returning)
        .unwrap_or_default();
    let role = |stmt: &CStmt| statement_role(stmt, &never_return, &selections);
    certify_control(input, &body, &blocks, &labels, &role)?;
    // What remains is linear emission of a certified body, so a stop here keeps what was reached.
    let stopped = work.with_phase(DecompileWorkPhase::Rendering).poll().err();
    match &values {
        Some(values) => {
            c.params = values.params();
            c.locals = values.locals();
            c.externs = values.externs();
            c.extern_objects = values.extern_objects();
        }
        None => c.params_known = false,
    }
    c.body = match body {
        CStmt::Block(stmts) => stmts,
        stmt => vec![stmt],
    };
    drop_unmentioned_locals(&mut c);
    crate::ast::respell_nonconforming_main(&mut c, input.function().entry);
    let ledger = close_ledger(input, values.as_ref());
    let unassigned = values.as_ref().map(values::Values::unassigned);
    // The proof line every rendering opens with: what became of each obligation the source owes.
    proof::note_unproven_constructs(
        &mut c,
        Some(&ledger),
        0,
        input.declared_call_prototypes(),
        0,
        unassigned.as_deref().unwrap_or_default(),
    );
    let mut ready = ready_with_carriers(c, &tags);
    // Each marker names the instruction its statement was written for, so each line names its own.
    ready.seal_observation_markers(
        &mut crate::codegen::ObservationSealAuthority::staged(),
        crate::codegen::ObservationLocations::new(addresses.into_iter().map(Some).collect()),
    );
    let emission = CodeGenerator::new(CodeGenConfig::default()).emit(&ready, input.ptr_bits());
    Ok(Rendered {
        function: crate::codegen::RenderedFunction::new(emission, ready.into_function()),
        ledger,
        stopped,
    })
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

/// SD's §3 certificate over the shaped body, or the refusal that names its first violation.
fn certify_control(
    input: &RenderInput<'_>,
    body: &CStmt,
    blocks: &[u64],
    labels: &BTreeMap<u64, String>,
    role: &dyn Fn(&CStmt) -> StatementRole,
) -> Result<(), RenderStop> {
    let function = input.function();
    let label_block = labels
        .iter()
        .map(|(addr, name)| (name.as_str(), *addr))
        .collect::<BTreeMap<_, _>>();
    let certificate = crate::structure::certify::certify(
        body,
        function.cfg(),
        function.domtree(),
        function.root(),
        &|id| blocks.get(id.index() as usize).copied(),
        &|name| label_block.get(name).copied(),
        role,
    );
    if certificate.ok() {
        return Ok(());
    }
    Err(RenderStop::Refused(format!(
        "control certificate: {certificate} {:?}",
        certificate.violations.first()
    )))
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

/// What the certificate reads a statement as: a selection the stage recorded, or one ending control.
fn statement_role(
    stmt: &CStmt,
    never_return: &std::collections::BTreeSet<String>,
    selections: &std::collections::BTreeSet<RenderObservationId>,
) -> StatementRole {
    match stmt
        .observation_ids()
        .iter()
        .any(|id| selections.contains(id))
    {
        true => StatementRole::Selects,
        false => (traps(stmt) || calls_never_returning(stmt, never_return)).into(),
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
    let mut ledger = ObligationLedger::open(input.obligations(), input.graph());
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

/// Whether a statement is a call to a callee declared never to return, which ends control there.
fn calls_never_returning(stmt: &CStmt, never_return: &std::collections::BTreeSet<String>) -> bool {
    matches!(stmt, CStmt::Expr(CExpr::Call { func, .. })
        if matches!(&**func, CExpr::External { name, .. } if never_return.contains(name)))
}

/// The function's result type: what the analysis decided, else the machine word.
fn result_type(input: &RenderInput<'_>) -> CType {
    input
        .return_type()
        .and_then(r2types::ReturnTypeFact::decided)
        .cloned()
        .unwrap_or_else(|| word(input))
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
        .as_declaration_only(sanitize_comment_text(&reason));
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
            sanitize_comment_text(reason)
        ))
}
