//! The staged decompiler (doc/adr-decompiler-rewrite.md): one pass per stage over the sealed facts,
//! a residual wherever they stop. D0 is the input, D1 the control, D2 the values, D3 the terms.

mod calls;
mod control;
mod frame;
mod globals;
mod input;
mod tags;
mod terms;
mod values;

use std::collections::BTreeMap;

pub use input::RenderInput;

use crate::ast::{CExpr, CFunction, CStmt, CType};
use crate::codegen::{CodeGenConfig, CodeGenerator, prepare_function_for_emission};
use crate::control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
use crate::ledger::{ObligationLedger, Outcome};

/// One function the staged pipeline rendered, and what became of each obligation.
pub struct Rendered {
    function: crate::RenderedFunction,
    ledger: ObligationLedger,
    /// A stop that came once the control was written and certified: the body is what was reached.
    stopped: Option<DecompileExecutionStop>,
}

impl Rendered {
    pub fn into_parts(self) -> (crate::RenderedFunction, ObligationLedger) {
        (self.function, self.ledger)
    }

    /// The stop the rendering was asked for after its body was certified, if any.
    pub const fn stopped(&self) -> Option<&DecompileExecutionStop> {
        self.stopped.as_ref()
    }
}

/// An import stub's C, as r2engine's route decides it; it has no body, so no obligation is owed.
pub fn import_stub(stub: &r2types::ImportStub, ptr_bits: u32) -> crate::RenderedFunction {
    let ready = crate::import_stub_declaration(stub);
    let emission = CodeGenerator::new(CodeGenConfig::default()).emit(&ready, ptr_bits);
    crate::RenderedFunction::new(emission, ready.into_function())
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
    let name = crate::rendered_name_of(input.name(), input.function().root());
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
    let body = crate::structure::ControlFlowStructurer::shape(&mut fresh, CStmt::Block(body));
    let never_return = values
        .as_ref()
        .map(values::Values::never_returning)
        .unwrap_or_default();
    certify_control(input, &body, &blocks, &labels, &never_return)?;
    let mut body = body;
    body.visit_stmts_mut(&mut |stmt| select_one_assignment(&c.symbols.borrow(), stmt));
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
    crate::note_unproven_constructs(
        &mut c,
        Some(&ledger),
        0,
        input.declared_call_prototypes(),
        0,
        unassigned.as_deref().unwrap_or_default(),
    );
    let mut ready = ready_with_carriers(c, &tags);
    // Each marker names the instruction its statement was written for, so each line names its own.
    let markers = addresses.len();
    ready.seal_observation_markers(
        &mut crate::observation_journal::ObservationSealAuthority::staged(),
        crate::codegen::ObservationLocations::new(
            addresses.into_iter().map(Some).collect(),
            vec![None; markers],
            vec![None; markers],
        ),
    );
    let emission = CodeGenerator::new(CodeGenConfig::default()).emit(&ready, input.ptr_bits());
    Ok(Rendered {
        function: crate::RenderedFunction::new(emission, ready.into_function()),
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
    never_return: &std::collections::BTreeSet<String>,
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
        &|stmt| traps(stmt) || calls_never_returning(stmt, never_return),
    );
    if certificate.ok() {
        return Ok(());
    }
    Err(RenderStop::Refused(format!(
        "control certificate: {certificate} {:?}",
        certificate.violations.first()
    )))
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

/// `if (c) { x = a; } else { x = b; }` is `x = c ? a : b;`: C evaluates `c`, then the one arm it
/// selects, either way. After the certificate, which reads each arm's block where it stands; the
/// one statement keeps both arms' markers, and each arm is converted to `x`'s type, as its own
/// assignment converted it, before the two meet.
fn select_one_assignment(symbols: &crate::symbol::SymbolTable, stmt: &mut CStmt) {
    if !matches!(
        stmt,
        CStmt::If {
            else_body: Some(_),
            ..
        }
    ) {
        return;
    }
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = std::mem::replace(stmt, CStmt::Empty)
    else {
        unreachable!("an if with an else, matched above");
    };
    *stmt = match (sole_assignment(&then_body), sole_assignment(&else_body)) {
        (Some((then_ids, target, then_value)), Some((else_ids, other, else_value)))
            if target == other =>
        {
            let ty = symbols.ty(target);
            let converted = |value: CExpr| match value.unobserved() {
                CExpr::Var(symbol) if symbols.ty(*symbol) == ty => value,
                _ => terms::at_sink(ty, CExpr::cast(ty.clone(), value)),
            };
            let selected = CExpr::Ternary {
                cond: Box::new(cond),
                then_expr: Box::new(converted(then_value)),
                else_expr: Box::new(converted(else_value)),
            };
            let assignment = CExpr::assign(CExpr::var(target), selected);
            CStmt::observe_all([then_ids, else_ids].concat(), CStmt::Expr(assignment))
        }
        _ => CStmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        },
    };
}

/// An arm that is one assignment to a plain variable, with nothing else but empty statements: its
/// markers, the variable and the value.
fn sole_assignment(
    arm: &CStmt,
) -> Option<(
    Vec<crate::ast::RenderObservationId>,
    crate::symbol::SymbolId,
    CExpr,
)> {
    let mut ids = arm.observation_ids().into_owned();
    let stmts = match arm.unobserved() {
        CStmt::Block(stmts) => stmts.as_slice(),
        single => std::slice::from_ref(single),
    };
    let mut assignment = None;
    for stmt in stmts {
        ids.extend(stmt.observation_ids().iter().copied());
        match stmt.unobserved() {
            CStmt::Empty => {}
            CStmt::Expr(CExpr::Binary {
                op: crate::ast::BinaryOp::Assign,
                left,
                right,
            }) if assignment.is_none() => match left.unobserved() {
                CExpr::Var(target) if left.observation_ids().is_empty() => {
                    assignment = Some((*target, right.as_ref().clone()));
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    let (target, value) = assignment?;
    Some((ids, target, value))
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
    matches!(stmt, CStmt::Gap(marker) if control::ends_control(marker))
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
