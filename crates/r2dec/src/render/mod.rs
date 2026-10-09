//! The staged decompiler (doc/adr-decompiler-rewrite.md): one pass per stage over the sealed facts,
//! a residual wherever they stop. D0 is the input, D1 the control, D2 the values, D3 the terms.

mod calls;
mod control;
mod frame;
mod globals;
mod input;
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
}

impl Rendered {
    pub fn into_parts(self) -> (crate::RenderedFunction, ObligationLedger) {
        (self.function, self.ledger)
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
    let values = values::Values::new(input, std::rc::Rc::clone(&c.symbols));
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
    certify_control(input, &body, &blocks, &labels)?;
    work.with_phase(DecompileWorkPhase::Rendering).poll()?;
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
    let ledger = close_ledger(input, values.as_ref());
    // The proof line every rendering opens with: what became of each obligation the source owes.
    crate::note_unproven_constructs(
        &mut c,
        Some(&ledger),
        0,
        input.declared_call_prototypes(),
        0,
        &[],
    );
    let mut ready = ready_with_carriers(c);
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
    })
}

/// `c` ready to emit: a wide carrier is a struct the unit defines, with the helpers that take it
/// apart.
fn ready_with_carriers(c: CFunction) -> crate::codegen::EmissionReadyFunction {
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
    let mut ready = prepare_function_for_emission(c);
    ready.set_aggregate_definitions(
        carriers
            .into_iter()
            .filter_map(crate::bitvector::carrier_definition)
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
        &traps,
    );
    if certificate.ok() {
        return Ok(());
    }
    Err(RenderStop::Refused(format!(
        "control certificate: {certificate} {:?}",
        certificate.violations.first()
    )))
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

/// Whether a statement ends control: a residual traps where it is evaluated.
fn traps(stmt: &CStmt) -> bool {
    matches!(stmt, CStmt::Expr(CExpr::Call { func, .. }) if crate::prelude::is_residual_callee(func).is_some())
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
