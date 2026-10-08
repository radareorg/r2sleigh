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
    /// The switch dispatch operations r2ssa's certificates own.
    dispatch: r2ssa::dense::IdSet<InstId>,
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

/// Why r2ssa certifies an instruction needs no C: a frame save the matching restore undoes, or a
/// compiler-inserted check.
fn certified_elision(
    artifact: &SsaArtifact,
    dispatch: &r2ssa::dense::IdSet<InstId>,
    inst: InstId,
) -> Option<crate::ledger::ElisionReason> {
    // A switch's dispatch reaches the case the structured `switch` names; its certificate owns it.
    if dispatch.contains(inst) {
        return Some(crate::ledger::ElisionReason::DirectControlTarget);
    }
    let certificates = artifact.certificates();
    if certificates.compiler_inserted.contains(inst) {
        return Some(crate::ledger::ElisionReason::CompilerInserted);
    }
    // The push recording where a call comes back to: the C call is that transfer.
    if certificates.call_return_address_stores.contains(inst) {
        return Some(crate::ledger::ElisionReason::CallReturnAddress);
    }
    certificates
        .stack_frame_round_trip_by_inst
        .contains(inst)
        .then_some(crate::ledger::ElisionReason::StackFrame)
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

    fn drain(&mut self) {
        while let Some(value) = self.work.pop() {
            let Some(def) = self
                .graph
                .def_inst(value)
                .and_then(|id| self.graph.inst(id))
            else {
                continue;
            };
            match &def.payload {
                InstPayload::Phi { .. } => {
                    for input in def.inputs.clone() {
                        self.operand(input, def.id);
                    }
                }
                InstPayload::Op(_) => {
                    if let Some(canonical) = self.roots.value(value) {
                        self.discharge(value);
                        self.read(canonical.canonical);
                    }
                }
            }
        }
    }
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
            let mut pending = Vec::new();
            for inst in block.insts.iter().filter_map(|id| graph.inst(*id)) {
                match &inst.payload {
                    InstPayload::Op(SSAOp::CallUse { .. }) => pending.push(inst.id),
                    InstPayload::Op(SSAOp::Call { .. } | SSAOp::CallInd { .. }) => {
                        for using in pending.drain(..) {
                            used_by.insert(using, inst.id);
                        }
                    }
                    _ => {}
                }
            }
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

    /// Whether `reader` may compute the producer's term in place of `def`: later in the same
    /// block, with no effect between where the term reads memory or can trap. A phi reads at the
    /// end of each predecessor whose edge carries the value.
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
        let roots = r2rewrite::canonicalize_with(artifact, &projection, &policy, &|_| None).ok()?;
        let mut planned = r2ssa::dense::IdMap::new(graph.insts.len());
        let mut results = r2ssa::dense::IdSet::new(graph.values.len());
        for inst in &graph.insts {
            if matches!(
                inst.payload,
                InstPayload::Op(SSAOp::Call { .. } | SSAOp::CallInd { .. })
            ) && let Some(plan) =
                calls::plan(artifact, input.callee_resolution(), inventory, inst.id)
            {
                if let Some((result, _)) = plan.result {
                    results.insert(result);
                }
                planned.insert(inst.id, plan);
            }
        }
        let mut demand = Demand {
            graph,
            readers: &readers,
            projection: &projection,
            roots: &roots,
            bound: vec![false; graph.insts.len()],
            discharged: vec![false; graph.insts.len()],
            work: Vec::new(),
        };
        let mut dispatch = r2ssa::dense::IdSet::new(graph.insts.len());
        for switch in artifact.certificates().switches.values() {
            for inst in &switch.dispatch {
                dispatch.insert(*inst);
            }
        }
        let live = |inst: InstId| {
            matches!(
                inventory.instruction_for_inst(inst).map(|d| d.state),
                Some(SemanticInstructionState::LiveObligation)
            ) && certified_elision(artifact, &dispatch, inst).is_none()
        };
        // The statements first, so a producer they absorb is not also bound.
        for inst in &graph.insts {
            let InstPayload::Op(op) = &inst.payload else {
                continue;
            };
            if !live(inst.id) {
                continue;
            }
            match op {
                SSAOp::Store { addr, val, .. } => {
                    match roots.access(store_access(inventory, inst.id)) {
                        Some(access) => demand.read(access.canonical),
                        None => demand.operand(*addr, inst.id),
                    }
                    demand.operand(*val, inst.id);
                }
                SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                    for (argument, _) in planned
                        .get(inst.id)
                        .map_or(&[][..], |plan| &plan.arguments[..])
                    {
                        demand.operand(*argument, inst.id);
                    }
                }
                SSAOp::CBranch { cond, .. } => demand.operand(*cond, inst.id),
                SSAOp::Switch { selector } => demand.operand(*selector, inst.id),
                SSAOp::BranchInd { .. } => {
                    let selector = graph
                        .block(inst.block)
                        .and_then(|block| artifact.certificates().switches.get(&block.addr))
                        .and_then(|switch| switch.selector);
                    if let Some(selector) = selector {
                        demand.operand(selector, inst.id);
                    }
                }
                SSAOp::Return { .. } => {
                    for value in returned_values(inventory, inst.id) {
                        demand.operand(value, inst.id);
                    }
                }
                _ => {}
            }
            demand.drain();
        }
        // A producer that owes more than its value is bound where it stands; readers come first.
        for inst in graph.insts.iter().rev() {
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
                && !demand.bound[index]
                && !demand.discharged[index]
            {
                demand.bind(output);
                demand.drain();
            }
        }
        let bound = demand.bound;
        let mut values = Self {
            artifact,
            graph,
            inventory,
            readers,
            names: vec![None; graph.values.len()],
            bound,
            frame: super::frame::Frame::of(artifact),
            frame_array: RefCell::new(None),
            symbols,
            params: Vec::new(),
            locals: RefCell::new(Vec::new()),
            rendered: RefCell::new(vec![false; graph.insts.len()]),
            restored: RefCell::new(vec![false; graph.insts.len()]),
            dispatch,
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
        values.declare(parameters);
        Some(values)
    }

    /// Parameters in their ABI order, then a local per bound value.
    fn declare(&mut self, parameters: Option<Vec<(u32, ValueId, MachineType)>>) {
        for (index, value, ty) in parameters.into_iter().flatten() {
            let c = terms::c_type(&ty).expect("a classed parameter has a C type");
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
        let indexed = matches!(
            self.artifact
                .certificates()
                .stack_slots
                .get(&object)
                .map(|slot| &slot.array_layout),
            Some(r2ssa::StackArrayLayoutDisposition::Proven(_))
        );
        Some(terms::Placed {
            base,
            extent: size,
            indexed,
        })
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
        let bound = |value: ValueId, ty: &MachineType| {
            let (name, held) = self.names.get(value.0 as usize)?.as_ref()?;
            terms::reclass(CExpr::var(*name), held, ty)
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
                let (name, _) = self.names.get(value.0 as usize)?.as_ref()?;
                Some(CExpr::var(*name))
            }
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
                _ if certified_elision(self.artifact, &self.dispatch, inst.id).is_some() => {
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
        if plan.address == Some(self.own.entry) {
            return self.recursive_call(inst, plan);
        }
        let mut arguments = Vec::with_capacity(plan.arguments.len());
        let mut types = Vec::with_capacity(plan.arguments.len());
        for (argument, class) in &plan.arguments {
            let held = self.value_type(*argument)?;
            arguments.push(terms::reclass(
                self.operand(*argument, inst)?,
                &held,
                class,
            )?);
            types.push(terms::c_type(class)?);
        }
        let ret_type = match &plan.result {
            Some((_, class)) => terms::c_type(class)?,
            None => CType::Void,
        };
        types.truncate(plan.fixed);
        let declaration = CExternDecl {
            name: plan.name.clone(),
            ret_type,
            params: Some(types),
            variadic: plan.variadic,
            noreturn: plan.noreturn,
            address: plan.address,
        };
        // One declaration describes every call to a callee, so calls that disagree cannot both be C.
        match self.externs.borrow_mut().entry(plan.name.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(declaration);
            }
            std::collections::btree_map::Entry::Occupied(slot) if *slot.get() != declaration => {
                return None;
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
        let callee = CExpr::External {
            name: plan.name.clone(),
            kind: plan.kind,
        };
        let call = CExpr::call_at(inst, callee, arguments);
        let Some((result, class)) = &plan.result else {
            return Some(CStmt::Expr(call));
        };
        let Some((name, held)) = self.names.get(result.0 as usize).and_then(Option::as_ref) else {
            return Some(CStmt::Expr(call));
        };
        let value = terms::reclass(call, class, held)?;
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
                        carrier_class(self.artifact, storage, held.width_bits())
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
        let spelled = terms::reclass(self.operand(*value, inst)?, &held, &class)?;
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

    /// Record a terminator the text spelled; a C `return` also restores the frame the machine's did.
    pub(super) fn spelled_terminator(&self, addr: u64) {
        let Some((inst, _)) = self.terminator(addr) else {
            return;
        };
        self.mark(inst);
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
            for input in self.graph.inst(def).map_or(&[][..], |i| &i.inputs[..]) {
                if self
                    .graph
                    .use_sites(*input)
                    .iter()
                    .all(|site| seen.contains(&site.inst))
                {
                    work.push(*input);
                }
            }
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
        for obligation in self.inventory.obligations().values() {
            let index = obligation.source.graph_inst().map(|inst| inst.0 as usize);
            let certified = obligation
                .source
                .graph_inst()
                .and_then(|inst| certified_elision(self.artifact, &self.dispatch, inst));
            let outcome = match (obligation.id.kind, certified) {
                (SemanticObligationKind::CompilerInserted, _) => {
                    Outcome::Elided(ElisionReason::CompilerInserted)
                }
                (SemanticObligationKind::NoNativeSemantics, _) => {
                    Outcome::Elided(ElisionReason::NoNativeSemantics)
                }
                (_, Some(reason)) => Outcome::Elided(reason),
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
        r2types::CTypeLike::Float(bits @ (32 | 64)) if *bits == width_bits => {
            Some(MachineType::Float { width_bits })
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

/// The class the convention passes a value of `width_bits` held in `storage` in: the slot it lies
/// in says general or float register. `None` where no slot of the convention holds it.
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
    match (declared, carrier) {
        (Some(declared), Some(carrier)) => (declared == carrier).then_some(declared),
        (one, other) => one.or(other),
    }
}

/// The parameters in ABI order at the class C passes them in: a declared float is a float, a
/// declared integer, pointer or enum is an integer of its width. `None` where any is unknown, since
/// C would pass a guessed class in another register (doc/adr-decompiler-rewrite.md).
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
    match (float(from), float(to)) {
        (false, false) => Some(CExpr::cast(
            terms::c_type(to)?,
            CExpr::cast(terms::c_type(from)?, expr),
        )),
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
