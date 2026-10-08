//! The staged decompiler (doc/adr-decompiler-rewrite.md): one pass per stage over the sealed facts,
//! a residual wherever they stop. D0 is the input, D1 the control; values are gaps until D2.

mod control;
mod input;

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
    let written = control::write(input);
    let function = input.function();
    let mut body = CStmt::Block(written.body);
    let label_block = written
        .labels
        .iter()
        .map(|(addr, name)| (name.as_str(), *addr))
        .collect::<BTreeMap<_, _>>();
    let certificate = crate::structure::certify::certify(
        &body,
        function.cfg(),
        function.domtree(),
        function.root(),
        &|id| written.blocks.get(id.index() as usize).copied(),
        &|name| label_block.get(name).copied(),
        &traps,
    );
    if !certificate.ok() {
        return Err(RenderStop::Refused(format!(
            "control certificate: {certificate} {:?}",
            certificate.violations.first()
        )));
    }
    crate::ast::strip_stmt_observations(&mut body);
    work.with_phase(DecompileWorkPhase::Rendering).poll()?;
    let name = crate::rendered_name_of(input.name(), function.root());
    let mut c = CFunction::new(name, result_type(input)).with_unknown_params();
    c.body = match body {
        CStmt::Block(stmts) => stmts,
        stmt => vec![stmt],
    };
    let ready = prepare_function_for_emission(c);
    let emission = CodeGenerator::new(CodeGenConfig::default()).emit(&ready, input.ptr_bits());
    let mut ledger = ObligationLedger::open(input.obligations(), input.graph());
    for id in input.obligations().obligations().keys() {
        ledger.record(*id, Outcome::Gapped);
    }
    Ok(Rendered {
        function: crate::RenderedFunction::new(emission, ready.function().clone()),
        ledger,
    })
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
    CType::Int {
        bits: input.ptr_bits(),
        signedness: r2types::Signedness::Unsigned,
    }
}
