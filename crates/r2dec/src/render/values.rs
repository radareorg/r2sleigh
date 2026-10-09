//! D2: which values the text computes and where (doc/adr-decompiler-rewrite.md, "D2 and D3, as
//! they are built"). Every value is its own local, so a term is valid wherever its producer dominates.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use r2rewrite::{CanonicalRoots, ExpansionQuery, Multiplicity, TermArena, TermId, TermKind};
use r2ssa::{
    InstId, InstPayload, MachineExprId, MachineExprKind, MachineProjection, MachineType, ObjectId,
    SSAOp, SemanticInstructionState, SemanticObligationComponent, SemanticObligationInventory,
    SemanticObligationKind, SsaArtifact, SsaGraph, StructuredAccessId, ValueId,
};

use super::RenderInput;
use super::calls::{self, CallPlan};
use super::terms::{self, Spell};
use crate::ast::{CExpr, CExternDecl, CLocal, CParam, CStmt, CType, GapMarker};
use crate::prelude::{Helper, ResidualType};
use crate::symbol::{SymbolId, SymbolRole, SymbolTable};

/// The values of one function: what each live instruction writes and what each edge copies.
pub(super) struct Values<'a> {
    artifact: &'a SsaArtifact,
    graph: &'a SsaGraph,
    inventory: &'a SemanticObligationInventory,
    readers: Readers<'a>,
    projection: MachineProjection,
    roots: CanonicalRoots,
    /// By value index: the parameter or local a value is read through.
    names: Vec<Option<(SymbolId, MachineType)>>,
    /// The parameters declared at the pointer type the source states, read as their integer class.
    pointers: Vec<bool>,
    /// By instruction index: whether a statement assigns the instruction's output where it stands.
    bound: Vec<bool>,
    /// The frame array each stack object a spelled term names is declared as, on first use.
    frame: Option<super::frame::Frame>,
    /// The frame array, once a spelled term names an object in it.
    frame_array: RefCell<Option<SymbolId>>,
    symbols: Rc<RefCell<SymbolTable>>,
    params: Vec<CParam>,
    locals: RefCell<Vec<CLocal>>,
    /// By instruction index: whether the text discharged it, which the ledger reads.
    rendered: RefCell<Vec<bool>>,
    /// By instruction index: frame teardown a spelled C `return` performs.
    restored: RefCell<Vec<bool>>,
    /// The instructions whose rendered text evaluates a residual: their obligations are residual.
    residual: RefCell<Vec<bool>>,
    /// The switch dispatch operations r2ssa's certificates own.
    dispatch: r2ssa::dense::IdSet<InstId>,
    elisions: crate::certified::Elisions,
    /// The calls the facts describe, by instruction.
    calls: r2ssa::dense::IdMap<InstId, CallPlan>,
    /// The values a described call's statement assigns.
    results: r2ssa::dense::IdSet<ValueId>,
    /// One declaration per callee, which every call to it here must agree with.
    externs: RefCell<BTreeMap<String, CExternDecl>>,
    little_endian: bool,
    ptr_bits: u32,
    /// The function itself as a call to its own entry names it: its name, parameters and result.
    own: Own,
}

/// What a recursive call needs of the function it is in.
struct Own {
    entry: u64,
    name: String,
    /// The parameters' classes, where every one is known.
    params: Option<Vec<MachineType>>,
    /// The result's class; `None` for a `void` function.
    result: Option<MachineType>,
}

/// Whether an instruction between a producer and its reader is one a moved read or trap may not cross.
fn has_effect(inventory: &SemanticObligationInventory, inst: InstId) -> bool {
    match inventory.instruction_for_inst(inst).map(|d| d.state) {
        Some(SemanticInstructionState::LiveObligation) => {
            inventory.obligations_for_inst(inst).any(|obligation| {
                !matches!(
                    obligation.id.kind,
                    SemanticObligationKind::LiveValueProducer
                        | SemanticObligationKind::ObservableMemoryRead
                        | SemanticObligationKind::ControlPredicate
                        | SemanticObligationKind::LoopCarriedState
                        | SemanticObligationKind::LiveStateTransition
                )
            })
        }
        Some(SemanticInstructionState::UnsupportedUnknown) => true,
        _ => false,
    }
}

/// Why an instruction renders no statement: a switch's dispatch, which the structured `switch`
/// names, or what a certificate elides (`crate::certified::Elisions`, legacy's rule too).
fn certified_elision(
    artifact: &SsaArtifact,
    (elisions, dispatch): (&crate::certified::Elisions, &r2ssa::dense::IdSet<InstId>),
    inst: InstId,
) -> Option<crate::ledger::ElisionReason> {
    if dispatch.contains(inst) {
        return Some(crate::ledger::ElisionReason::DirectControlTarget);
    }
    elisions.reason(artifact, inst)
}

/// Whether a machine expression reads memory or can trap, so it must stay where the machine runs it.
fn machine_effectful(projection: &MachineProjection, id: MachineExprId) -> bool {
    let Some(expr) = projection.expr(id) else {
        return true;
    };
    match expr.kind() {
        MachineExprKind::MemoryRead { .. }
        | MachineExprKind::GuardedRead { .. }
        | MachineExprKind::Divide { .. }
        | MachineExprKind::Remainder { .. }
        | MachineExprKind::BlockAnswer { .. }
        | MachineExprKind::ExclusiveStoreSucceeded { .. } => true,
        MachineExprKind::Source { .. } | MachineExprKind::Constant { .. } => false,
        kind => kind
            .children()
            .into_iter()
            .any(|child| machine_effectful(projection, child)),
    }
}

fn effectful(projection: &MachineProjection, arena: &TermArena, root: TermId) -> bool {
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        match arena.term(id).kind {
            TermKind::Load { .. } | TermKind::Subscript { .. } => return true,
            TermKind::Opaque(expr) if machine_effectful(projection, expr) => return true,
            kind => stack.extend(kind.children()),
        }
    }
    false
}

/// The values a term reads by name: its leaves, and the sources under its opaque nodes.
fn term_reads(projection: &MachineProjection, arena: &TermArena, root: TermId) -> Vec<ValueId> {
    let mut reads = Vec::new();
    let mut stack = vec![root];
    let mut machine = Vec::new();
    while let Some(id) = stack.pop() {
        match arena.term(id).kind {
            TermKind::Leaf(read) => machine.push(read.expr),
            TermKind::Opaque(expr) => machine.push(expr),
            kind => stack.extend(kind.children()),
        }
    }
    while let Some(id) = machine.pop() {
        match projection.expr(id).map(|expr| expr.kind()) {
            Some(MachineExprKind::Source { binding, .. }) => reads.push(binding.value()),
            Some(kind) => machine.extend(kind.children()),
            None => {}
        }
    }
    reads.sort_unstable();
    reads.dedup();
    reads
}

fn sanitized(name: &str) -> String {
    name.chars()
        .map(|c| match c.is_ascii_alphanumeric() {
            true => c.to_ascii_lowercase(),
            false => '_',
        })
        .collect()
}

/// Demand: which values are bound, found from the statements the obligations owe.
struct Demand<'d> {
    graph: &'d SsaGraph,
    readers: &'d Readers<'d>,
    projection: &'d MachineProjection,
    roots: &'d CanonicalRoots,
    bound: Vec<bool>,
    /// By instruction index: computed inside a term some statement or bound value renders.
    discharged: Vec<bool>,
    work: Vec<ValueId>,
}

impl Demand<'_> {
    /// The canonical term `reader` computes in place of reading `value`, where it may.
    fn absorbed(&self, value: ValueId, reader: InstId) -> Option<TermId> {
        self.readers
            .absorbed((self.projection, self.roots), value, reader)
    }

    fn bind(&mut self, value: ValueId) {
        let Some(def) = self.graph.def_inst(value) else {
            return;
        };
        let slot = &mut self.bound[def.0 as usize];
        if !*slot {
            *slot = true;
            self.work.push(value);
        }
    }

    fn read(&mut self, term: TermId) {
        for value in term_reads(self.projection, self.roots.arena(), term) {
            self.bind(value);
        }
    }

    fn operand(&mut self, value: ValueId, reader: InstId) {
        match self.absorbed(value, reader) {
            Some(term) => {
                if let Some(def) = self.graph.def_inst(value) {
                    self.discharged[def.0 as usize] = true;
                }
                self.discharge(value);
                self.read(term);
            }
            None => self.bind(value),
        }
    }

    fn discharge(&mut self, value: ValueId) {
        let Some(canonical) = self.roots.value(value) else {
            return;
        };
        for inst in discharged_insts(self.graph, canonical.discharges.iter()) {
            self.discharged[inst.0 as usize] = true;
        }
    }

    /// Which instructions bind their value: the statements' reads first, so a producer they absorb
    /// is not also bound, then each producer that owes more than its value, readers first.
    fn bind_all(
        mut self,
        input: &RenderInput<'_>,
        planned: &r2ssa::dense::IdMap<InstId, CallPlan>,
        certified: (&crate::certified::Elisions, &r2ssa::dense::IdSet<InstId>),
    ) -> Vec<bool> {
        let (artifact, inventory) = (input.artifact(), input.obligations());
        let live = |inst: InstId| {
            matches!(
                inventory.instruction_for_inst(inst).map(|d| d.state),
                Some(SemanticInstructionState::LiveObligation)
            ) && certified_elision(artifact, certified, inst).is_none()
        };
        for inst in &self.graph.insts {
            let InstPayload::Op(op) = &inst.payload else {
                continue;
            };
            if live(inst.id) {
                self.statement(input, planned, inst, op);
                self.drain();
            } else if let Some(selector) = self.selector(artifact, inst, op) {
                self.operand(selector, inst.id);
                self.drain();
            }
        }
        for inst in self.graph.insts.iter().rev() {
            let index = inst.id.0 as usize;
            let owes = match &inst.payload {
                InstPayload::Phi { .. } => false,
                InstPayload::Op(op) => {
                    writes_value(op)
                        && inventory
                            .obligations_for_inst(inst.id)
                            .any(|o| o.id.kind != SemanticObligationKind::LiveValueProducer)
                }
            };
            if let Some(output) = inst.output
                && owes
                && live(inst.id)
                && !self.bound[index]
                && !self.discharged[index]
            {
                self.bind(output);
                self.drain();
            }
        }
        self.bound
    }

    /// A table dispatch's selector, which the `switch` reads though the dispatch itself is elided.
    fn selector(
        &self,
        artifact: &SsaArtifact,
        inst: &r2ssa::GraphInst,
        op: &SSAOp<ValueId>,
    ) -> Option<ValueId> {
        matches!(op, SSAOp::BranchInd { .. })
            .then(|| self.graph.block(inst.block))
            .flatten()
            .and_then(|block| artifact.certificates().switches.get(&block.addr))
            .and_then(|switch| switch.selector)
    }

    /// What one live instruction's statement reads.
    fn statement(
        &mut self,
        input: &RenderInput<'_>,
        planned: &r2ssa::dense::IdMap<InstId, CallPlan>,
        inst: &r2ssa::GraphInst,
        op: &SSAOp<ValueId>,
    ) {
        let (artifact, inventory) = (input.artifact(), input.obligations());
        match op {
            SSAOp::Store { addr, val, .. } => {
                match self.roots.access(store_access(inventory, inst.id)) {
                    Some(access) => self.read(access.canonical),
                    None => self.operand(*addr, inst.id),
                }
                self.operand(*val, inst.id);
            }
            SSAOp::Call { .. } | SSAOp::CallInd { .. } | SSAOp::Branch { .. } => {
                let plan = planned.get(inst.id);
                for (argument, _) in plan.map_or(&[][..], |plan| &plan.arguments[..]) {
                    self.operand(*argument, inst.id);
                }
            }
            SSAOp::CBranch { cond, .. } => self.operand(*cond, inst.id),
            SSAOp::Switch { selector } => self.operand(*selector, inst.id),
            // A tail transfer reads its arguments, and its target where it goes through one.
            SSAOp::BranchInd { target, .. } if planned.get(inst.id).is_some() => {
                let plan = planned.get(inst.id).expect("planned above");
                for (argument, _) in &plan.arguments {
                    self.operand(*argument, inst.id);
                }
                if matches!(plan.callee, calls::Callee::Through(_)) {
                    self.operand(*target, inst.id);
                }
            }
            SSAOp::BranchInd { .. } => {
                if let Some(selector) = self.selector(artifact, inst, op) {
                    self.operand(selector, inst.id);
                }
            }
            SSAOp::Return { .. } => {
                for value in returned_values(inventory, inst.id) {
                    self.operand(value, inst.id);
                }
            }
            _ => {}
        }
    }

    fn drain(&mut self) {
        while let Some(value) = self.work.pop() {
            let Some(def) = self
                .graph
                .def_inst(value)
                .and_then(|id| self.graph.inst(id))
            else {
                continue;
            };
            self.read_definition(
                value,
                def.id,
                matches!(def.payload, InstPayload::Phi { .. }),
            );
        }
    }

    /// A merge reads each input on its edge; an operation, what its term reads.
    fn read_definition(&mut self, value: ValueId, def: InstId, merge: bool) {
        if merge {
            let inputs = self
                .graph
                .inst(def)
                .map(|inst| inst.inputs.clone())
                .unwrap_or_default();
            for input in inputs {
                self.operand(input, def);
            }
        } else if let Some(canonical) = self.roots.value(value) {
            self.discharge(value);
            self.read(canonical.canonical);
        }
    }
}

/// Each `CALLUSE` of `block` and the call it hands its carrier to, the next in the block.
fn call_uses(
    graph: &SsaGraph,
    block: &r2ssa::GraphBlock,
    used_by: &mut r2ssa::dense::IdMap<InstId, InstId>,
) {
    let mut pending = Vec::new();
    for inst in block.insts.iter().filter_map(|id| graph.inst(*id)) {
        match &inst.payload {
            InstPayload::Op(SSAOp::CallUse { .. }) => pending.push(inst.id),
            InstPayload::Op(
                SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::Branch { .. }
                | SSAOp::BranchInd { .. },
            ) => {
                for using in pending.drain(..) {
                    used_by.insert(using, inst.id);
                }
            }
            _ => {}
        }
    }
}

/// The canonical terms: a value is inlined where it is duplicable, or where its one reader can
/// move it there; any other is bound.
fn canonical_roots(
    artifact: &SsaArtifact,
    projection: &MachineProjection,
    readers: &Readers<'_>,
) -> Option<CanonicalRoots> {
    let graph = artifact.graph();
    let policy = |query: &ExpansionQuery<'_>| {
        if r2rewrite::term_is_duplicable(
            query.projection,
            query.arena,
            query.entry_never_redefined,
            query.producer_term,
        ) {
            return true;
        }
        let read_by = readers.of(query.value);
        let (Some(def), [only]) = (graph.def_inst(query.value), read_by.as_slice()) else {
            return false;
        };
        readers.movable(
            (query.projection, query.arena),
            def,
            *only,
            query.producer_term,
        )
    };
    r2rewrite::canonicalize_with(artifact, projection, &policy, &|_| None).ok()
}

/// Each call's plan, by its instruction, and the values those calls assign their results to.
fn plan_calls(
    input: &RenderInput<'_>,
) -> (
    r2ssa::dense::IdMap<InstId, CallPlan>,
    r2ssa::dense::IdSet<ValueId>,
) {
    let (artifact, graph, inventory) = (input.artifact(), input.graph(), input.obligations());
    let mut planned = r2ssa::dense::IdMap::new(graph.insts.len());
    let mut results = r2ssa::dense::IdSet::new(graph.values.len());
    for inst in &graph.insts {
        let call = matches!(
            inst.payload,
            InstPayload::Op(
                SSAOp::Call { .. }
                    | SSAOp::CallInd { .. }
                    | SSAOp::Branch { .. }
                    | SSAOp::BranchInd { .. }
            )
        );
        let Some(plan) = call
            .then(|| calls::plan(artifact, input.callee_resolution(), inventory, inst.id))
            .flatten()
        else {
            continue;
        };
        if let Some((result, _)) = plan.result {
            results.insert(result);
        }
        planned.insert(inst.id, plan);
    }
    (planned, results)
}

/// The instructions a term computes in place of reading their values.
fn discharged_insts<'g>(
    graph: &'g SsaGraph,
    discharges: impl Iterator<Item = &'g r2ssa::CanonicalInstructionId> + 'g,
) -> impl Iterator<Item = InstId> + 'g {
    discharges.filter_map(|id| match id.site {
        r2ssa::CanonicalInstructionSite::Op(op) => graph.inst_for_op(op),
        _ => None,
    })
}

/// Who reads each value: its live graph readers, and the returns whose boundary reads it with no
/// graph use. A dead reader computes nothing, so it does not count.
struct Readers<'a> {
    graph: &'a SsaGraph,
    inventory: &'a SemanticObligationInventory,
    /// The returns and calls whose boundary reads a value, by value.
    boundary: r2ssa::dense::IdMap<ValueId, Vec<InstId>>,
    /// The call a `CALLUSE` hands its carrier to: the next call in its block.
    used_by: r2ssa::dense::IdMap<InstId, InstId>,
}

impl<'a> Readers<'a> {
    fn new(graph: &'a SsaGraph, inventory: &'a SemanticObligationInventory) -> Self {
        let mut boundary = r2ssa::dense::IdMap::new(graph.values.len());
        for obligation in inventory.obligations().values() {
            if !matches!(
                obligation.id.kind,
                SemanticObligationKind::ReturnValue | SemanticObligationKind::CallArgument
            ) {
                continue;
            }
            let Some(inst) = obligation.source.graph_inst() else {
                continue;
            };
            for input in &obligation.inputs {
                boundary.get_or_insert_with(*input, Vec::new).push(inst);
            }
        }
        let mut used_by = r2ssa::dense::IdMap::new(graph.insts.len());
        for block in &graph.blocks {
            call_uses(graph, block, &mut used_by);
        }
        Self {
            graph,
            inventory,
            boundary,
            used_by,
        }
    }

    fn of(&self, value: ValueId) -> Vec<InstId> {
        let live = self
            .graph
            .use_sites(value)
            .iter()
            .map(|site| self.used_by.get(site.inst).copied().unwrap_or(site.inst))
            .filter(|inst| {
                matches!(
                    self.inventory.instruction_for_inst(*inst).map(|d| d.state),
                    Some(
                        SemanticInstructionState::LiveObligation
                            | SemanticInstructionState::UnsupportedUnknown
                    )
                )
            });
        let mut readers = live
            .chain(self.boundary.get(value).into_iter().flatten().copied())
            .collect::<Vec<_>>();
        readers.sort_unstable();
        readers.dedup();
        readers
    }

    /// Whether `reader` may compute the producer's term in place of `def`: later in its block, no
    /// effect between where the term reads memory or traps; a phi reads at each carrying edge.
    fn movable(
        &self,
        (projection, arena): (&MachineProjection, &TermArena),
        def: InstId,
        reader: InstId,
        term: TermId,
    ) -> bool {
        let graph = self.graph;
        let (Some(def), Some(reader)) = (graph.inst(def), graph.inst(reader)) else {
            return false;
        };
        let sites = match &reader.payload {
            InstPayload::Phi { predecessors } => reader
                .inputs
                .iter()
                .zip(predecessors)
                .filter(|(input, _)| graph.def_inst(**input) == Some(def.id))
                .map(|(_, pred)| (*pred, graph.block(*pred).map_or(0, |b| b.insts.len())))
                .collect::<Vec<_>>(),
            InstPayload::Op(_) => vec![(reader.block, reader.ordinal)],
        };
        let pure = !effectful(projection, arena, term);
        !sites.is_empty()
            && sites.iter().all(|(block, at)| {
                def.block == *block
                    && def.ordinal < *at
                    && (pure
                        || graph
                            .insts_between(*block, def.ordinal, *at)
                            .iter()
                            .all(|between| !has_effect(self.inventory, *between)))
            })
    }

    /// The canonical term `reader` computes in place of reading `value`, where it may.
    fn absorbed(
        &self,
        (projection, roots): (&MachineProjection, &CanonicalRoots),
        value: ValueId,
        reader: InstId,
    ) -> Option<TermId> {
        let canonical = roots.value(value)?;
        let term = canonical.canonical;
        // A leaf of the value itself is a value no producer computes: it is read by name.
        if reads_itself(projection, roots.arena(), term, value) {
            return None;
        }
        let def = self.graph.def_inst(value);
        // A merge is the variable its edges assign.
        if def.is_some_and(|def| {
            matches!(
                self.graph.inst(def).map(|inst| &inst.payload),
                Some(InstPayload::Phi { .. })
            )
        }) {
            return None;
        }
        // A literal, or a term over entry values never redefined, reads the same anywhere.
        if canonical.multiplicity == Multiplicity::Any {
            return Some(term);
        }
        let def = def?;
        (self.of(value) == [reader] && self.movable((projection, roots.arena()), def, reader, term))
            .then_some(term)
    }
}

fn leaf_value(projection: &MachineProjection, expr: MachineExprId) -> Option<ValueId> {
    match projection.expr(expr)?.kind() {
        MachineExprKind::Source { binding, .. } => Some(binding.value()),
        _ => None,
    }
}

/// The access a live store writes, by its write obligation.
fn store_access(inventory: &SemanticObligationInventory, inst: InstId) -> StructuredAccessId {
    let ordinal = inventory
        .obligations_for_inst(inst)
        .find_map(|obligation| match obligation.id.component {
            SemanticObligationComponent::MemoryAccess(ordinal)
                if obligation.id.kind == SemanticObligationKind::ObservableMemoryWrite =>
            {
                Some(ordinal)
            }
            _ => None,
        })
        .unwrap_or(0);
    StructuredAccessId { inst, ordinal }
}

impl<'a> Values<'a> {
    /// Canonicalise the function once under D2's expansion policy, then find what is bound.
    pub(super) fn new(input: &RenderInput<'a>, symbols: Rc<RefCell<SymbolTable>>) -> Option<Self> {
        let artifact: &'a SsaArtifact = input.artifact();
        let graph = input.graph();
        let inventory = input.obligations();
        let projection = MachineProjection::from_artifact(artifact).ok()?;
        let readers = Readers::new(graph, inventory);
        let roots = canonical_roots(artifact, &projection, &readers)?;
        let (planned, results) = plan_calls(input);
        let elisions = crate::certified::Elisions::of(artifact);
        let mut dispatch = r2ssa::dense::IdSet::new(graph.insts.len());
        for switch in artifact.certificates().switches.values() {
            for inst in &switch.dispatch {
                dispatch.insert(*inst);
            }
        }
        let bound = Demand {
            graph,
            readers: &readers,
            projection: &projection,
            roots: &roots,
            bound: vec![false; graph.insts.len()],
            discharged: vec![false; graph.insts.len()],
            work: Vec::new(),
        }
        .bind_all(input, &planned, (&elisions, &dispatch));
        let mut values = Self {
            artifact,
            graph,
            inventory,
            readers,
            names: vec![None; graph.values.len()],
            pointers: vec![false; graph.values.len()],
            bound,
            frame: super::frame::Frame::of(artifact),
            frame_array: RefCell::new(None),
            symbols,
            params: Vec::new(),
            locals: RefCell::new(Vec::new()),
            rendered: RefCell::new(vec![false; graph.insts.len()]),
            restored: RefCell::new(vec![false; graph.insts.len()]),
            residual: RefCell::new(vec![false; graph.insts.len()]),
            dispatch,
            elisions,
            calls: planned,
            results,
            externs: RefCell::new(BTreeMap::new()),
            ptr_bits: input.ptr_bits(),
            own: Own {
                entry: input.function().root(),
                name: crate::rendered_name_of(input.name(), input.function().root()),
                params: None,
                result: match input
                    .return_type()
                    .and_then(r2types::ReturnTypeFact::decided)
                {
                    Some(CType::Void) => None,
                    Some(ty) => ty
                        .bits(input.ptr_bits())
                        .and_then(|bits| class_of(ty, bits)),
                    None => Some(MachineType::Integer {
                        width_bits: input.ptr_bits(),
                        signedness: r2ssa::MachineSignedness::Unsigned,
                    }),
                },
            },
            little_endian: matches!(
                artifact
                    .machine_context()
                    .memory_model()
                    .default_endianness(),
                r2ssa::MachineMemoryEndianness::Little
            ),
            projection,
            roots,
        };
        let parameters = parameters(input, artifact);
        values.own.params = parameters
            .as_ref()
            .map(|parameters| parameters.iter().map(|(_, _, class)| *class).collect());
        values.declare(input, parameters);
        Some(values)
    }

    /// Parameters in their ABI order, then a local per bound value. A parameter the source declares
    /// a pointer is declared so, as the caller passes it, and read as the word its class is.
    fn declare(
        &mut self,
        input: &RenderInput<'_>,
        parameters: Option<Vec<(u32, ValueId, MachineType)>>,
    ) {
        for (index, value, ty) in parameters.into_iter().flatten() {
            let pointer = input
                .parameter_declaration(index as usize, ty.width_bits())
                .filter(|declared| {
                    matches!(declared.unaliased(), r2types::CTypeLike::Pointer(_))
                        && matches!(ty, MachineType::Integer { width_bits, .. } if width_bits == self.ptr_bits)
                });
            let c = match pointer {
                Some(declared) => {
                    self.pointers[value.0 as usize] = true;
                    declared
                }
                None => terms::c_type(&ty).expect("a classed parameter has a C type"),
            };
            let name = self.symbols.borrow_mut().declare(
                format!("arg{index}"),
                c.clone(),
                SymbolRole::Parameter(index),
            );
            self.names[value.0 as usize] = Some((name, ty));
            self.params.push(CParam { ty: c, name });
        }
        for inst in &self.graph.insts {
            let Some(output) = inst.output.filter(|_| self.bound[inst.id.0 as usize]) else {
                continue;
            };
            let Some(ty) = self.value_type(output) else {
                continue;
            };
            let Some(c) = terms::c_type(&ty) else {
                continue;
            };
            let name = sanitized(&self.graph.var(output).display_name());
            let id = self
                .symbols
                .borrow_mut()
                .declare(name, c.clone(), SymbolRole::Carrier);
            self.names[output.0 as usize] = Some((id, ty));
            self.locals.get_mut().push(CLocal {
                ty: c,
                name: id,
                stack_offset: None,
                align: None,
            });
        }
    }

    /// A frame object's address in the function's one frame array (D4), and its extent: the
    /// array is declared on first use, aligned as the machine's frame is.
    fn object(&self, object: ObjectId) -> Option<terms::Placed> {
        let frame = self.frame.as_ref()?;
        let (index, size) = frame.at(object)?;
        let array = *self.frame_array.borrow_mut().get_or_insert_with(|| {
            let ty = CType::Array(
                Box::new(CType::Int {
                    bits: 8,
                    signedness: r2types::Signedness::Unsigned,
                }),
                Some(frame.bytes() as usize),
            );
            let id =
                self.symbols
                    .borrow_mut()
                    .declare("frame", ty.clone(), SymbolRole::StackLocal(0));
            self.locals.borrow_mut().push(CLocal {
                ty,
                name: id,
                stack_offset: None,
                align: Some(frame.alignment()),
            });
            id
        });
        let base = CExpr::binary(
            crate::ast::BinaryOp::Add,
            CExpr::var(array),
            CExpr::UIntLit(u64::from(index)),
        );
        Some(terms::Placed { base, extent: size })
    }

    /// The machine type a value is held at: its name's, its producer's term's, else its width.
    fn value_type(&self, value: ValueId) -> Option<MachineType> {
        if let Some((_, held)) = self.names.get(value.0 as usize).and_then(Option::as_ref) {
            return Some(*held);
        }
        if let Some(canonical) = self.roots.value(value) {
            return Some(self.roots.arena().term(canonical.canonical).ty);
        }
        Some(MachineType::Integer {
            width_bits: self.graph.var(value).size * 8,
            signedness: r2ssa::MachineSignedness::Unsigned,
        })
    }

    pub(super) fn params(&self) -> Vec<CParam> {
        self.params.clone()
    }

    pub(super) fn locals(&self) -> Vec<CLocal> {
        self.locals.borrow().clone()
    }

    fn spelling<R>(&self, read: impl FnOnce(&Spell<'_>) -> R) -> R {
        let bound = |value: ValueId, ty: &MachineType| match self.names.get(value.0 as usize)? {
            Some((name, held)) => terms::reclass(self.read_name(value, *name, held)?, held, ty),
            // What a register held at entry that no parameter admits: C cannot read it.
            None if self.graph.def_inst(value).is_none() => crate::prelude::residual(
                &terms::c_type(ty)?,
                crate::prelude::ResidualCause::HeldFromEntry,
            ),
            None => None,
        };
        let object = |object: ObjectId| self.object(object);
        read(&Spell {
            projection: &self.projection,
            arena: self.roots.arena(),
            bound: &bound,
            object: &object,
            little_endian: self.little_endian,
        })
    }

    fn spell(&self, term: TermId) -> Option<CExpr> {
        self.spelling(|spell| spell.term(term))
    }

    fn mark(&self, inst: InstId) {
        if let Some(slot) = self.rendered.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
    }

    fn mark_discharged(&self, value: ValueId) {
        if let Some(canonical) = self.roots.value(value) {
            for inst in discharged_insts(self.graph, canonical.discharges.iter()) {
                self.mark(inst);
            }
        }
    }

    /// `value` as `reader` reads it: its term where it is absorbed, else its name.
    fn operand(&self, value: ValueId, reader: InstId) -> Option<CExpr> {
        let absorbed = self
            .readers
            .absorbed((&self.projection, &self.roots), value, reader);
        match absorbed {
            Some(term) => {
                let spelled = self.spell(term)?;
                if let Some(def) = self.graph.def_inst(value) {
                    self.mark(def);
                }
                self.mark_discharged(value);
                Some(spelled)
            }
            None => {
                let (name, held) = self.names.get(value.0 as usize)?.as_ref()?;
                self.read_name(value, *name, held)
            }
        }
    }

    /// A name as its class reads it: a parameter declared a pointer is read as its word.
    fn read_name(&self, value: ValueId, name: SymbolId, held: &MachineType) -> Option<CExpr> {
        let var = CExpr::var(name);
        match self.pointers.get(value.0 as usize) {
            Some(true) => Some(CExpr::cast(terms::c_type(held)?, var)),
            _ => Some(var),
        }
    }

    /// What a block's live instructions write, in order, each with the instruction it stands at; a
    /// run that cannot be spelled is one gap.
    pub(super) fn statements(&self, addr: u64) -> Vec<(u64, CStmt)> {
        let mut out: Vec<(u64, CStmt)> = Vec::new();
        let Some(block) = self
            .graph
            .block_id_for_addr(addr)
            .and_then(|id| self.graph.block(id))
        else {
            return out;
        };
        for inst in block.insts.iter().filter_map(|id| self.graph.inst(*id)) {
            let InstPayload::Op(op) = &inst.payload else {
                continue;
            };
            let state = self
                .inventory
                .instruction_for_inst(inst.id)
                .map(|d| d.state);
            let stmt = match state {
                _ if certified_elision(
                    self.artifact,
                    (&self.elisions, &self.dispatch),
                    inst.id,
                )
                .is_some() =>
                {
                    Ok(None)
                }
                Some(SemanticInstructionState::LiveObligation) => {
                    self.statement(inst.id, op, inst.output)
                }
                Some(SemanticInstructionState::UnsupportedUnknown) => Err(Gap::Unsupported),
                _ => Ok(None),
            };
            let at = self.graph.instruction_for_inst(inst.id).unwrap_or(addr);
            match stmt {
                Ok(Some(stmt)) => {
                    self.mark(inst.id);
                    self.residual_in(inst.id, &stmt);
                    out.push((at, stmt));
                }
                Ok(None) => {}
                Err(gap) => self.gap(&mut out, (addr, at), inst.id, gap),
            }
        }
        out
    }

    /// Extend the gap the block's text ends with, or open one at this instruction.
    fn gap(&self, out: &mut Vec<(u64, CStmt)>, (addr, at): (u64, u64), inst: InstId, gap: Gap) {
        let op_idx = self.graph.op_ordinal(inst).unwrap_or(0);
        if let Some((_, CStmt::Gap(marker))) = out.last_mut()
            && marker.op_idx + marker.ops == op_idx
            && marker.kind == gap.kind()
        {
            marker.ops += 1;
            return;
        }
        out.push((
            at,
            CStmt::Gap(GapMarker {
                kind: gap.kind().to_owned(),
                origin: "render::values".to_owned(),
                block_addr: addr,
                op_idx,
                ops: 1,
            }),
        ));
    }

    /// The statement one live instruction owes: `Ok(None)` where it owes none here, `Err` where
    /// it owes one the facts cannot spell.
    fn statement(
        &self,
        inst: InstId,
        op: &SSAOp<ValueId>,
        output: Option<ValueId>,
    ) -> Result<Option<CStmt>, Gap> {
        match op {
            SSAOp::CBranch { .. }
            | SSAOp::Branch { .. }
            | SSAOp::Switch { .. }
            | SSAOp::Return { .. }
            | SSAOp::BranchInd { .. } => Ok(None),
            SSAOp::Store { addr, val, .. } => {
                self.store(inst, *addr, *val).map(Some).ok_or(Gap::Store)
            }
            SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                self.call(inst).map(Some).ok_or(Gap::Call)
            }
            // The described call's statement assigns its result.
            SSAOp::CallDefine { .. } if output.is_some_and(|o| self.results.contains(o)) => {
                Ok(None)
            }
            SSAOp::CallDefine { .. } if output.is_some_and(|o| self.is_named(o)) => {
                Err(Gap::Unknown)
            }
            _ if writes_value(op) => {
                let Some(output) = output else {
                    return Ok(None);
                };
                if !self.bound[inst.0 as usize] {
                    return Ok(None);
                }
                let (name, _) = self.names[output.0 as usize].ok_or(Gap::Type)?;
                let canonical = self.roots.value(output).ok_or(Gap::Term)?;
                if reads_itself(
                    &self.projection,
                    self.roots.arena(),
                    canonical.canonical,
                    output,
                ) {
                    return Err(Gap::Unknown);
                }
                let value = self.spell(canonical.canonical).ok_or(Gap::Term)?;
                self.mark_discharged(output);
                Ok(Some(CStmt::Expr(CExpr::binary(
                    crate::ast::BinaryOp::Assign,
                    CExpr::var(name),
                    value,
                ))))
            }
            _ if self.inventory.obligations_for_inst(inst).next().is_none() => Ok(None),
            _ => Err(Gap::Effect),
        }
    }

    /// `value` written at the store's cell: its canonical access where import built one, else its
    /// own address operand at the value's width.
    fn is_named(&self, value: ValueId) -> bool {
        self.names
            .get(value.0 as usize)
            .is_some_and(Option::is_some)
    }

    /// A described call: its callee by name, each argument at the class its signature passes it
    /// in, its result assigned.
    fn call(&self, inst: InstId) -> Option<CStmt> {
        let plan = self.calls.get(inst)?;
        if self.calls_itself(plan) {
            return self.recursive_call(inst, plan);
        }
        let call = self.call_expr(inst, plan, plan.result.as_ref().map(|(_, class)| class))?;
        self.assign_call(inst, plan, call)
    }

    fn calls_itself(&self, plan: &CallPlan) -> bool {
        matches!(&plan.callee, calls::Callee::Named { address, .. } if *address == Some(self.own.entry))
    }

    /// The call's expression, returning `ret`: a named callee is declared once, and one reached
    /// through its target value is cast to the function type it is called at.
    fn call_expr(&self, inst: InstId, plan: &CallPlan, ret: Option<&MachineType>) -> Option<CExpr> {
        let mut arguments = Vec::with_capacity(plan.arguments.len());
        let mut types = Vec::with_capacity(plan.arguments.len());
        for ((argument, class), stacked) in plan.arguments.iter().zip(&plan.stacked) {
            let held = self.value_type(*argument)?;
            // A float the caller stored as bits would travel in a float register once C declares it.
            if *stacked && matches!(held, MachineType::Float { .. }) {
                return None;
            }
            arguments.push(fit(self.operand(*argument, inst)?, &held, class)?);
            types.push(terms::c_type(class)?);
        }
        let ret_type = match ret {
            Some(class) => terms::c_type(class)?,
            None => CType::Void,
        };
        let (name, kind, address) = match &plan.callee {
            calls::Callee::Named {
                name,
                kind,
                address,
            } => (name, *kind, *address),
            calls::Callee::Through(target) => {
                // The printer spells a function type in a cast as the pointer to it: `ret (*)(params)`.
                let pointer = CType::Function {
                    ret: Box::new(ret_type),
                    params: types.into_boxed_slice(),
                };
                let address = terms::fit_integer(self.operand(*target, inst)?, self.ptr_bits)?;
                return Some(CExpr::call_at(
                    inst,
                    CExpr::cast(pointer, address),
                    arguments,
                ));
            }
        };
        types.truncate(plan.fixed);
        let declaration = CExternDecl {
            name: name.clone(),
            ret_type,
            params: Some(types),
            variadic: plan.variadic,
            noreturn: plan.noreturn,
            address,
        };
        // One declaration describes every call to a callee, so calls that disagree cannot both be C.
        match self.externs.borrow_mut().entry(name.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(declaration);
            }
            std::collections::btree_map::Entry::Occupied(slot) if *slot.get() != declaration => {
                return None;
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
        let callee = CExpr::External {
            name: name.clone(),
            kind,
        };
        Some(CExpr::call_at(inst, callee, arguments))
    }

    /// A tail transfer as C: the call and a bare `return` where the function returns nothing, else
    /// the return of what the callee leaves in the function's own result register.
    pub(super) fn tail_call(
        &self,
        addr: u64,
        ty: &CType,
        decided: Option<&CType>,
    ) -> Option<Vec<CStmt>> {
        let (inst, _) = self.terminator(addr)?;
        let plan = self.calls.get(inst)?;
        let tail = plan.tail.as_ref()?;
        if plan.noreturn || self.calls_itself(plan) {
            return None;
        }
        let returns = self
            .artifact
            .machine_context()
            .function_interface()?
            .return_kind();
        let stmts = match (returns, tail) {
            (r2source::SourceFunctionReturn::Void, _) => {
                let call = self.call_expr(inst, plan, tail.as_ref().map(|(_, class)| class))?;
                vec![CStmt::Expr(call), CStmt::Return(None)]
            }
            (r2source::SourceFunctionReturn::Register { storage }, Some((carried, class)))
                if storage == *carried =>
            {
                let carrier = carrier_class(self.artifact, storage, storage.size * 8);
                let own = match decided {
                    Some(CType::Void) => return None,
                    Some(decided) => agreed(class_of(decided, storage.size * 8), carrier)?,
                    None => match carrier? {
                        class @ MachineType::Integer { .. } => class,
                        _ => return None,
                    },
                };
                let call = self.call_expr(inst, plan, Some(class))?;
                let spelled = fit(call, class, &own)?;
                vec![CStmt::Return(Some(CExpr::cast(ty.clone(), spelled)))]
            }
            _ => return None,
        };
        self.mark(inst);
        for stmt in &stmts {
            self.residual_in(inst, stmt);
        }
        Some(stmts)
    }

    /// The call as a statement, its result assigned to the value the boundary defines after it.
    fn assign_call(&self, _inst: InstId, plan: &CallPlan, call: CExpr) -> Option<CStmt> {
        let Some((result, class)) = &plan.result else {
            return Some(CStmt::Expr(call));
        };
        let Some((name, held)) = self.names.get(result.0 as usize).and_then(Option::as_ref) else {
            return Some(CStmt::Expr(call));
        };
        let value = fit(call, class, held)?;
        if let Some(def) = self.graph.def_inst(*result) {
            self.mark(def);
        }
        Some(assign(*name, value))
    }

    /// A call to the function's own entry: by its own name and at its own parameters' classes, so
    /// the call agrees with the definition it stands in.
    fn recursive_call(&self, inst: InstId, plan: &CallPlan) -> Option<CStmt> {
        let params = self.own.params.as_ref()?;
        if params.len() != plan.arguments.len() {
            return None;
        }
        let mut arguments = Vec::with_capacity(params.len());
        for ((argument, _), class) in plan.arguments.iter().zip(params) {
            let held = self.value_type(*argument)?;
            arguments.push(fit(self.operand(*argument, inst)?, &held, class)?);
        }
        let callee = CExpr::External {
            name: self.own.name.clone(),
            kind: crate::symbol::ExternalKind::Function,
        };
        let call = CExpr::call_at(inst, callee, arguments);
        let named = plan
            .result
            .and_then(|(result, _)| Some((result, self.names.get(result.0 as usize)?.as_ref()?)));
        let Some((result, (name, held))) = named else {
            return Some(CStmt::Expr(call));
        };
        let value = fit(call, &self.own.result?, held)?;
        if let Some(def) = self.graph.def_inst(result) {
            self.mark(def);
        }
        Some(assign(*name, value))
    }

    pub(super) fn externs(&self) -> Vec<CExternDecl> {
        self.externs.borrow().values().cloned().collect()
    }

    fn store(&self, inst: InstId, address: ValueId, value: ValueId) -> Option<CStmt> {
        if !self.little_endian {
            return None;
        }
        let arena = self.roots.arena();
        let (address, cell) = match self.roots.access(store_access(self.inventory, inst)) {
            Some(access) => {
                let cell = arena.term(access.canonical);
                let bytes = cell.ty.width_bits() / 8;
                let address = match cell.kind {
                    TermKind::Load { object, address } => {
                        self.spelling(|spell| spell.address(address, bytes, Some(object)))?
                    }
                    TermKind::Subscript { base, index } => {
                        self.spelling(|spell| spell.subscript((base, index), bytes, None))?
                    }
                    _ => return None,
                };
                for discharged in discharged_insts(self.graph, access.discharges.iter()) {
                    self.mark(discharged);
                }
                (address, cell.ty)
            }
            None => (self.operand(address, inst)?, self.value_type(value)?),
        };
        let ty = terms::c_type(&cell)?;
        let residual = ResidualType::of(&ty)?;
        let written = terms::reclass(self.operand(value, inst)?, &self.value_type(value)?, &cell)?;
        let written = CExpr::cast(ty, written);
        let pointer = CExpr::cast(CType::Pointer(Box::new(CType::Void)), address);
        Some(CStmt::Expr(
            Helper::Store(residual).call(vec![pointer, written]),
        ))
    }

    /// The test a conditional branch ending `addr` takes its true edge on.
    pub(super) fn condition(&self, addr: u64) -> Option<CExpr> {
        let (inst, op) = self.terminator(addr)?;
        let SSAOp::CBranch { cond, .. } = op else {
            return None;
        };
        self.operand(*cond, inst)
    }

    /// The selector a switch ending `addr` reads.
    pub(super) fn selector(&self, addr: u64) -> Option<CExpr> {
        let (inst, op) = self.terminator(addr)?;
        let selector = match op {
            SSAOp::Switch { selector } => *selector,
            // A table dispatch: the certificate states the value its cases are values of.
            SSAOp::BranchInd { .. } => self.artifact.certificates().switches.get(&addr)?.selector?,
            _ => return None,
        };
        self.operand(selector, inst)
    }

    /// What the return ending `addr` hands back as `ty`: `None` where the facts do not state it.
    pub(super) fn returned(&self, addr: u64, ty: Option<&CType>) -> Option<Option<CExpr>> {
        let (inst, op) = self.terminator(addr)?;
        if !matches!(op, SSAOp::Return { .. }) {
            return None;
        }
        let unproven = self
            .inventory
            .obligations_for_inst(inst)
            .any(|o| o.id.kind == SemanticObligationKind::ReturnValue && o.inputs.is_empty());
        let values = returned_values(self.inventory, inst);
        let [value] = values.as_slice() else {
            return matches!(ty, Some(CType::Void)).then_some(None);
        };
        if unproven {
            return None;
        }
        let held = self.value_type(*value)?;
        let carrier =
            self.inventory
                .obligations_for_inst(inst)
                .find_map(|o| match o.id.component {
                    SemanticObligationComponent::RegisterSlot { storage, .. }
                        if o.id.kind == SemanticObligationKind::ReturnValue =>
                    {
                        carrier_class(self.artifact, storage, storage.size * 8)
                    }
                    _ => None,
                });
        // The C return type says which register C returns in: a decided type, else the machine
        // word, which is right only where the convention returns the value in a general register.
        let (ty, class) = match ty {
            Some(CType::Void) => return Some(None),
            Some(ty) => (
                ty.clone(),
                agreed(class_of(ty, held.width_bits()), carrier)?,
            ),
            None => match carrier? {
                class @ MachineType::Integer { .. } => (super::word_type(self.ptr_bits), class),
                _ => return None,
            },
        };
        let spelled = fit(self.operand(*value, inst)?, &held, &class)?;
        Some(Some(CExpr::cast(ty, spelled)))
    }

    fn terminator(&self, addr: u64) -> Option<(InstId, &'a SSAOp<ValueId>)> {
        let block = self.graph.block(self.graph.block_id_for_addr(addr)?)?;
        let inst = self.graph.inst(*block.insts.last()?)?;
        match &inst.payload {
            InstPayload::Op(op) => Some((inst.id, op)),
            InstPayload::Phi { .. } => None,
        }
    }

    /// Whether `stmt`, written for `inst`, evaluates a residual, which makes `inst`'s obligations residual.
    pub(super) fn residual_in(&self, inst: InstId, stmt: &CStmt) {
        let mut held = false;
        stmt.visit_exprs(&mut |expr| held |= crate::prelude::holds_residual(expr));
        if held && let Some(slot) = self.residual.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
    }

    /// Record a terminator the text spelled as `spelled`; a C `return` also restores the frame.
    pub(super) fn spelled_terminator(&self, addr: u64, spelled: &CStmt) {
        let Some((inst, _)) = self.terminator(addr) else {
            return;
        };
        self.mark(inst);
        self.residual_in(inst, spelled);
        let mut restored = self.restored.borrow_mut();
        for restore in self.restores(inst) {
            restored[restore.0 as usize] = true;
        }
    }

    /// The producers only a return's return address and exit stack pointer read.
    fn restores(&self, inst: InstId) -> Vec<InstId> {
        let Some(boundary) = self.artifact.facts().boundaries.returns.get(inst) else {
            return Vec::new();
        };
        let mut work = boundary
            .return_address
            .as_ref()
            .map(|address| address.value)
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(r2ssa::SourceReturnStackPointerFact::ReachingValue { value, .. }) =
            boundary.exit_stack_pointer
        {
            work.push(value);
        }
        let mut seen = std::collections::BTreeSet::new();
        while let Some(value) = work.pop() {
            let Some(def) = self.graph.def_inst(value) else {
                continue;
            };
            if self.bound[def.0 as usize] || !seen.insert(def) {
                continue;
            }
            let inputs = self.graph.inst(def).map_or(&[][..], |i| &i.inputs[..]);
            work.extend(inputs.iter().copied().filter(|input| {
                (self.graph.use_sites(*input).iter()).all(|site| seen.contains(&site.inst))
            }));
        }
        seen.into_iter().collect()
    }

    /// The parallel copy into `to`'s merges along the edge from `from`, ordered so no copy reads a
    /// variable an earlier one wrote; a cycle goes through temporaries.
    pub(super) fn copies(&self, from: u64, to: u64) -> Vec<CStmt> {
        let (Some(from_id), Some(to_block)) = (
            self.graph.block_id_for_addr(from),
            self.graph
                .block_id_for_addr(to)
                .and_then(|id| self.graph.block(id)),
        ) else {
            return Vec::new();
        };
        let mut copies = Vec::new();
        for inst in to_block.insts.iter().filter_map(|id| self.graph.inst(*id)) {
            let InstPayload::Phi { predecessors } = &inst.payload else {
                break;
            };
            let Some(output) = inst.output.filter(|_| self.bound[inst.id.0 as usize]) else {
                continue;
            };
            let Some(slot) = predecessors.iter().position(|pred| *pred == from_id) else {
                continue;
            };
            let input = inst.inputs[slot];
            let reads = match self
                .readers
                .absorbed((&self.projection, &self.roots), input, inst.id)
            {
                Some(term) => term_reads(&self.projection, self.roots.arena(), term),
                None => vec![input],
            };
            copies.push((inst.id, output, self.operand(input, inst.id), reads));
        }
        let mut out = Vec::new();
        let writes = copies
            .iter()
            .map(|(_, output, ..)| *output)
            .collect::<Vec<_>>();
        let clobbers = copies.iter().enumerate().any(|(i, (.., reads))| {
            writes
                .iter()
                .enumerate()
                .any(|(j, written)| i != j && reads.contains(written))
        });
        let mut staged = Vec::new();
        for (inst, output, source, _) in copies {
            let (Some(source), Some((name, ty))) = (source, self.names[output.0 as usize].as_ref())
            else {
                out.push(CStmt::Gap(GapMarker {
                    kind: "ValuesNotRendered".to_owned(),
                    origin: "render::values".to_owned(),
                    block_addr: to,
                    op_idx: 0,
                    ops: 0,
                }));
                continue;
            };
            self.mark(inst);
            self.residual_in(inst, &CStmt::Expr(source.clone()));
            match clobbers {
                false => out.push(assign(*name, source)),
                true => {
                    let c = terms::c_type(ty).expect("a named value has a C type");
                    // The name is read before the table is borrowed to declare the temporary.
                    let next = format!("{}_next", self.symbols.borrow().name(*name));
                    let temp =
                        self.symbols
                            .borrow_mut()
                            .declare(next, c.clone(), SymbolRole::Carrier);
                    self.locals.borrow_mut().push(CLocal {
                        ty: c,
                        name: temp,
                        stack_offset: None,
                        align: None,
                    });
                    out.push(assign(temp, source));
                    staged.push(assign(*name, CExpr::var(temp)));
                }
            }
        }
        out.extend(staged);
        out
    }

    /// What became of each obligation: rendered where the text discharged its instruction.
    pub(super) fn close(&self, ledger: &mut crate::ledger::ObligationLedger) {
        use crate::ledger::{ElisionReason, Outcome};
        let (rendered, restored) = (self.rendered.borrow(), self.restored.borrow());
        let residual = self.residual.borrow();
        for obligation in self.inventory.obligations().values() {
            let index = obligation.source.graph_inst().map(|inst| inst.0 as usize);
            let certified = obligation.source.graph_inst().and_then(|inst| {
                certified_elision(self.artifact, (&self.elisions, &self.dispatch), inst)
            });
            let outcome = match (obligation.id.kind, certified) {
                (SemanticObligationKind::CompilerInserted, _) => {
                    Outcome::Elided(ElisionReason::CompilerInserted)
                }
                (SemanticObligationKind::NoNativeSemantics, _) => {
                    Outcome::Elided(ElisionReason::NoNativeSemantics)
                }
                (_, Some(reason)) => Outcome::Elided(reason),
                _ if index.is_some_and(|i| rendered[i] && residual[i]) => Outcome::Gapped,
                _ if index.is_some_and(|i| rendered[i]) => Outcome::Rendered,
                _ if index.is_some_and(|i| restored[i]) => {
                    Outcome::Elided(ElisionReason::StackFrame)
                }
                _ => Outcome::Gapped,
            };
            let _ = ledger.record(obligation.id, outcome);
        }
    }
}

/// The class C passes a value of declared type `ty` in, held at `width_bits`: a float of its own
/// width, or an integer for an integer, boolean, pointer or enum. `None` for anything else.
pub(super) fn class_of(ty: &r2types::CTypeLike, width_bits: u32) -> Option<MachineType> {
    match ty.unaliased() {
        // A float may travel as the low lane of a wider vector register.
        r2types::CTypeLike::Float(bits @ (32 | 64))
            if *bits <= width_bits && matches!(width_bits, 32 | 64 | 128) =>
        {
            Some(MachineType::Float { width_bits: *bits })
        }
        r2types::CTypeLike::Int { .. }
        | r2types::CTypeLike::Bool
        | r2types::CTypeLike::Pointer(_)
        | r2types::CTypeLike::Enum(_)
            if matches!(width_bits, 8 | 16 | 32 | 64) =>
        {
            Some(MachineType::Integer {
                width_bits,
                signedness: r2ssa::MachineSignedness::Unsigned,
            })
        }
        _ => None,
    }
}

/// The class a value `width_bits` wide passes in, held in `storage`: its slot says general or
/// float register, `storage`'s size the width (a float's lane); `None` outside every slot.
pub(super) fn carrier_class(
    artifact: &SsaArtifact,
    storage: r2source::CanonicalStorageId,
    width_bits: u32,
) -> Option<MachineType> {
    let slots = artifact.machine_context().convention_slots()?;
    let within = |slot: &r2source::CanonicalStorageId| {
        slot.space == storage.space
            && slot.offset <= storage.offset
            && storage.offset + u64::from(storage.size) <= slot.offset + u64::from(slot.size)
    };
    let general = slots
        .argument_slots()
        .iter()
        .chain(&slots.result_slot())
        .any(within);
    let float = (slots.float_argument_slots().iter())
        .chain(&slots.float_result_slot())
        .any(within);
    match (general, float) {
        (true, false) if matches!(width_bits, 8 | 16 | 32 | 64) => Some(MachineType::Integer {
            width_bits,
            signedness: r2ssa::MachineSignedness::Unsigned,
        }),
        (false, true) if matches!(width_bits, 32 | 64) => Some(MachineType::Float { width_bits }),
        _ => None,
    }
}

/// One class from a declared type and the carrier, where either states it and they agree.
pub(super) fn agreed(
    declared: Option<MachineType>,
    carrier: Option<MachineType>,
) -> Option<MachineType> {
    // The register says which kind; the declaration, where there is one, says the width within it.
    let float = |ty: &MachineType| matches!(ty, MachineType::Float { .. });
    match (declared, carrier) {
        (Some(declared), Some(carrier)) => (float(&declared) == float(&carrier)
            && declared.width_bits() <= carrier.width_bits())
        .then_some(declared),
        (one, other) => one.or(other),
    }
}

/// The parameters in ABI order at the class C passes them in (a declared float a float, else an
/// integer of its width); `None` where any is unknown (doc/adr-decompiler-rewrite.md).
fn parameters(
    input: &RenderInput<'_>,
    artifact: &SsaArtifact,
) -> Option<Vec<(u32, ValueId, MachineType)>> {
    let graph = artifact.graph();
    artifact
        .facts()
        .boundaries
        .parameters
        .values()
        .map(|parameter| {
            let width_bits = graph.var(parameter.value).size * 8;
            let declared = input
                .parameter_declaration(parameter.index as usize, width_bits)
                .map(|declared| class_of(&declared, width_bits));
            let carrier = carrier_class(artifact, parameter.abi_storage, width_bits);
            let class = match declared {
                Some(None) => return None,
                Some(Some(declared)) => agreed(Some(declared), carrier)?,
                None => carrier?,
            };
            // A parameter is declared at its value's own width: a lane of it is read by name.
            if class.width_bits() != width_bits {
                return None;
            }
            Some((parameter.index, parameter.value, class))
        })
        .collect()
}

/// Why a live instruction's statement is a gap: the marker's kind, which says what is missing.
#[derive(Debug, Clone, Copy)]
enum Gap {
    /// The inventory could not account for the instruction.
    Unsupported,
    /// A call, until its callsite facts are rendered.
    Call,
    /// An effect with no C statement here: a fence, an atomic, a block transfer, a user operation.
    Effect,
    Store,
    /// A value whose term has no exact C spelling.
    Term,
    /// A value with no C type to hold it.
    Type,
    /// A value no producer computes, such as what a call leaves in a register.
    Unknown,
}

impl Gap {
    const fn kind(self) -> &'static str {
        match self {
            Self::Unsupported => "UnsupportedInstruction",
            Self::Call => "CallNotRendered",
            Self::Effect => "EffectNotRendered",
            Self::Store => "StoreNotSpelled",
            Self::Term => "TermNotSpelled",
            Self::Type => "ValueHasNoCType",
            Self::Unknown => "ValueNotComputed",
        }
    }
}

/// An integer held at one width passed or returned at another: a cast keeps the low bits a narrower
/// one carries and zero-extends into a wider one; a float only as `reclass` reinterprets it.
fn fit(expr: CExpr, from: &MachineType, to: &MachineType) -> Option<CExpr> {
    let float = |ty: &MachineType| matches!(ty, MachineType::Float { .. });
    let lane = |bits: u32| MachineType::Integer {
        width_bits: bits,
        signedness: r2ssa::MachineSignedness::Unsigned,
    };
    if terms::c_type(from)? == terms::c_type(to)? {
        return Some(expr);
    }
    let (wide, narrow) = (from.width_bits(), to.width_bits());
    // A wide carrier's low field is its value at a narrower class, through the bitvector helper.
    if terms::wide(wide) && narrow < wide {
        let low = terms::wide_extract(wide, narrow, expr, 0)?;
        return terms::reclass(low, &lane(narrow), to);
    }
    if terms::wide(narrow) && wide < narrow {
        let bits = terms::reclass(expr, from, &lane(wide))?;
        return terms::wide_zero_extend(wide, narrow, bits);
    }
    match (float(from), float(to)) {
        (false, false) => Some(CExpr::cast(
            terms::c_type(to)?,
            CExpr::cast(terms::c_type(from)?, expr),
        )),
        // A float passed in the low lane of a wider register: its low bits, read as the float.
        (false, true) if wide > narrow => {
            let low = CExpr::cast(terms::c_type(&lane(narrow))?, expr);
            terms::reclass(low, &lane(narrow), to)
        }
        // A float returned in a wider register: its bits, the rest zero as the ABI leaves them unstated.
        (true, false) if narrow > wide => {
            let bits = terms::reclass(expr, from, &lane(wide))?;
            Some(CExpr::cast(terms::c_type(to)?, bits))
        }
        _ => terms::reclass(expr, from, to),
    }
}

fn assign(name: SymbolId, value: CExpr) -> CStmt {
    CStmt::Expr(CExpr::binary(
        crate::ast::BinaryOp::Assign,
        CExpr::var(name),
        value,
    ))
}

/// Whether a value's canonical term is a read of the value itself: no producer the term models.
fn reads_itself(
    projection: &MachineProjection,
    arena: &TermArena,
    term: TermId,
    value: ValueId,
) -> bool {
    matches!(arena.term(term).kind, TermKind::Leaf(read) if leaf_value(projection, read.expr) == Some(value))
}

/// The values a return hands back, by its return-value obligations.
fn returned_values(inventory: &SemanticObligationInventory, inst: InstId) -> Vec<ValueId> {
    inventory
        .obligations_for_inst(inst)
        .filter(|o| o.id.kind == SemanticObligationKind::ReturnValue)
        .flat_map(|o| o.inputs.iter().copied())
        .collect()
}

/// Whether an operation's effect is its output alone, so a local assigned its term states it.
fn writes_value(op: &SSAOp<ValueId>) -> bool {
    !matches!(
        op,
        SSAOp::Store { .. }
            | SSAOp::Call { .. }
            | SSAOp::CallInd { .. }
            | SSAOp::CallDefine { .. }
            | SSAOp::CallUse { .. }
            | SSAOp::CallOther { .. }
            | SSAOp::Fence { .. }
            | SSAOp::LoadLinked { .. }
            | SSAOp::LoadGuarded { .. }
            | SSAOp::StoreConditional { .. }
            | SSAOp::StoreGuarded { .. }
            | SSAOp::AtomicCAS(_)
            | SSAOp::BlockTransfer(_)
            | SSAOp::Breakpoint
            | SSAOp::Unimplemented
            | SSAOp::CpuId { .. }
            | SSAOp::New { .. }
    ) && op.dst().is_some()
}
