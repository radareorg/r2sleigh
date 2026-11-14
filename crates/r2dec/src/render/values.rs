//! D2: which values the text computes and where (doc/adr-decompiler-rewrite.md, "D2 and D3, as
//! they are built"). Every value is its own local, so a term is valid wherever its producer dominates.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use r2rewrite::{CanonicalRoots, ExpansionQuery, Multiplicity, TermArena, TermId, TermKind};
use r2ssa::{
    InstId, InstPayload, MachineExprId, MachineExprKind, MachineProjection, MachineType, ObjectId,
    SSAOp, SemanticInstructionState, SemanticObligationComponent, SemanticObligationInventory,
    SemanticObligationKind, SsaArtifact, SsaGraph, StructuredAccessId, ValueId,
};

mod atomic;
mod transfer;

use super::RenderInput;
use super::calls::{self, CallPlan};
use super::terms::{self, MemberCell, Spell};
use crate::ast::{
    CExpr, CExternDecl, CLocal, CParam, CStmt, CType, CallGap, CallRefusal, GapCallee, GapKind,
    GapMarker,
};
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
    /// The parameters declared at a type the source states other than their class's C type: a
    /// read converts it to the class.
    declared: Vec<bool>,
    /// The structure member each cell term is, by term index: the accesses through a parameter
    /// that points to its structure, and through a projected pointer member (D359).
    members: Vec<Option<MemberCell>>,
    /// By value index: the definitions a named value owes before a read of it is a variable; a merge
    /// owes one per early forward edge in, and a back edge pays none (doc/adr-decompiler-rewrite.md, Merges).
    owed: RefCell<Vec<u32>>,
    /// The merges the last attempt read as variables on a late edge's promise and that edge gapped.
    broken: RefCell<Vec<ValueId>>,
    /// The merges that owe one definition more than any edge pays, which no read of them clears.
    forced: r2ssa::dense::IdSet<ValueId>,
    /// The dominator tree and root, which tell a forward edge from a back edge.
    dom: &'a r2ssa::domtree::DomTree,
    root: u64,
    /// The block whose text is being spelled: a name reads as a variable only where its definition
    /// has run (doc/adr-decompiler-rewrite.md, "D2's spelling order").
    reading: Cell<u64>,
    /// By instruction index: whether a statement assigns the instruction's output where it stands.
    bound: Vec<bool>,
    /// The frame array each stack object a spelled term names is declared as, on first use.
    frame: Option<super::frame::Frame>,
    /// The frame array, once a spelled term names an object in it.
    frame_array: RefCell<Option<SymbolId>>,
    /// Each stack formal: its index, name, class, and whether it is declared other than its class.
    frame_formals: Vec<(u32, SymbolId, MachineType, bool)>,
    symbols: Rc<RefCell<SymbolTable>>,
    params: Vec<CParam>,
    locals: RefCell<Vec<CLocal>>,
    /// By instruction index: whether the text discharged it, which the ledger reads.
    rendered: RefCell<Vec<bool>>,
    /// By instruction index: frame teardown a spelled C `return` performs.
    restored: RefCell<Vec<bool>>,
    /// By instruction index: a value the kept text spells as `&object` where it is read (D254).
    addressed: RefCell<Vec<bool>>,
    /// The instructions whose rendered text evaluates a residual: their obligations are residual.
    residual: RefCell<Vec<bool>>,
    /// By instruction index: a gap stands for its atomic effect beside the value the text assigns.
    effect: RefCell<Vec<bool>>,
    /// The values read as residuals because C has no value for them, which the proof line names.
    unassigned: RefCell<Vec<super::proof::UnassignedRead>>,
    /// What the text being spelled reads and absorbs, kept only once a statement or test holding it is.
    pending: RefCell<Attempt>,
    /// The switch dispatch operations r2ssa's certificates own.
    dispatch: r2ssa::dense::IdSet<InstId>,
    elisions: crate::certified::Elisions,
    /// The calls the facts describe, by instruction.
    calls: r2ssa::dense::IdMap<InstId, CallPlan>,
    /// The calls they do not, with the callee and the first fact each lacks.
    unplanned: r2ssa::dense::IdMap<InstId, CallGap>,
    /// The values a described call's statement assigns.
    results: r2ssa::dense::IdSet<ValueId>,
    /// Each named callee's one declaration where every call stating one states it; `None` where
    /// two disagree, so every call to it refuses (D350).
    prototypes: BTreeMap<String, Option<CExternDecl>>,
    /// The declarations of the calls written, which the function declares.
    externs: RefCell<BTreeMap<String, CExternDecl>>,
    /// The text the capture proves at each address, which a passed constant address is.
    strings: &'a BTreeMap<u64, String>,
    /// The objects the program names that an access here reaches, each declared once.
    globals: super::globals::Globals<'a>,
    little_endian: bool,
    ptr_bits: u32,
    /// The slot the caller pushed the return address into, where nothing here writes it.
    return_address: Option<ObjectId>,
    /// The function itself as a call to its own entry names it: its name, parameters and result.
    own: Own,
}

/// What a recursive call needs of the function it is in.
/// One statement attempt: the residual reads and absorbed producers its text holds.
#[derive(Default)]
struct Attempt {
    reads: Vec<super::proof::UnassignedRead>,
    marks: Vec<InstId>,
    /// Producers whose values the text spells as the frame object each addresses.
    addressed: Vec<InstId>,
}

struct Own {
    entry: u64,
    name: String,
    /// The parameters' classes, where every one is known.
    params: Option<Vec<MachineType>>,
    /// The result's class; `None` for a `void` function.
    result: Option<MachineType>,
}

impl Own {
    /// The function's own entry, name and result class; its parameters are declared later.
    fn of(input: &RenderInput<'_>) -> Self {
        let decided = input
            .return_type()
            .and_then(r2types::ReturnTypeFact::decided);
        let result = match decided {
            Some(CType::Void) => None,
            Some(ty) => ty
                .bits(input.ptr_bits())
                .and_then(|bits| class_of(ty, bits)),
            None => Some(MachineType::Integer {
                width_bits: input.ptr_bits(),
                signedness: r2ssa::MachineSignedness::Unsigned,
            }),
        };
        Self {
            entry: input.function().root(),
            name: super::rendered_name_of(input.name(), input.function().root()),
            params: None,
            result,
        }
    }
}

/// `value`, or the refusal evidence that the staged call at `inst` lacks `what`.
fn needed<T>(value: Option<T>, inst: InstId, why: CallRefusal) -> Result<T, CallRefusal> {
    value.ok_or_else(|| {
        r2il::refusal_evidence!("staged-call", "{inst:?}: {why:?}");
        why
    })
}

/// An integer class as the unstated word over it; any other type as it is.
fn unstated_class(ty: &CType) -> CType {
    match ty {
        CType::Int {
            bits: bits @ (8 | 16 | 32 | 64),
            signedness: r2types::Signedness::Unsigned,
        } => r2types::unstated_word(*bits),
        ty => ty.clone(),
    }
}

/// The declaration a call to a named callee states, `types` its arguments' types, the prototype's
/// where the plan has one: none for a call through a value.
fn extern_decl(plan: &CallPlan, mut types: Vec<CType>, ret_type: CType) -> Option<CExternDecl> {
    let calls::Callee::Named { name, address, .. } = &plan.callee else {
        return None;
    };
    let declared = plan
        .declared
        .as_ref()
        .map_or(&[][..], |declared| &declared.params[..]);
    for (at, ty) in types.iter_mut().enumerate() {
        match declared.get(at).cloned().flatten() {
            Some(to) if !crate::prelude::is_unread_slot(ty) => *ty = to,
            Some(_) => {}
            // A class no declaration types states no sign: the header's unstated word (D265).
            None => *ty = unstated_class(ty),
        }
    }
    types.truncate(plan.fixed);
    Some(CExternDecl {
        name: name.clone(),
        ret_type,
        params: Some(types),
        variadic: plan.variadic,
        noreturn: plan.noreturn,
        address: *address,
    })
}

/// Whether an instruction between a producer and its reader is one a moved read or trap may not cross.
fn has_effect(inventory: &SemanticObligationInventory, inst: InstId) -> bool {
    match inventory.state_of(inst) {
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
/// names, or what a certificate elides (`crate::certified::Elisions`).
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
    artifact: &'d SsaArtifact,
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
        let discharges = (self.roots).discharges(self.artifact, self.projection, value);
        for inst in discharged_insts(self.graph, discharges.iter()) {
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
                inventory.state_of(inst),
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
                    (writes_value(op) || reads_beside_effect(op))
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
            _ if op.is_call() || matches!(op, SSAOp::Branch { .. }) => {
                let plan = planned.get(inst.id);
                for argument in plan.into_iter().flat_map(CallPlan::passed_values) {
                    self.operand(argument, inst.id);
                }
            }
            SSAOp::CBranch { cond, .. } => self.operand(*cond, inst.id),
            SSAOp::Switch { selector } => self.operand(*selector, inst.id),
            SSAOp::BlockTransfer(transfer) => {
                for value in [transfer.destination, transfer.source, transfer.count] {
                    self.operand(value, inst.id);
                }
            }
            SSAOp::Atomic(access) => {
                self.operand(access.addr, inst.id);
                for value in access.operands() {
                    self.operand(*value, inst.id);
                }
            }
            // A tail transfer reads its arguments, and its target where it goes through one.
            SSAOp::BranchInd { target, .. } if planned.get(inst.id).is_some() => {
                let plan = planned.get(inst.id).expect("planned above");
                for argument in plan.passed_values() {
                    self.operand(argument, inst.id);
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
            // An arm r2ssa states no path reads binds nothing (ROADMAP D214).
            let merges = self.artifact.unobserved_merges();
            let inputs = self.graph.inputs(def).to_vec();
            let read = (inputs.into_iter().enumerate()).filter(|(at, _)| merges.arm_read(def, *at));
            for (_, input) in read {
                self.operand(input, def);
            }
        } else if transfer::reads_answer(self.graph, value) {
            // The walk assigns it from its own variables; its term reads nothing by name.
        } else if let Some(canonical) = self.roots.value(value) {
            self.discharge(value);
            self.read(canonical.canonical);
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
        if transfer::reads_answer(graph, query.value) {
            return false;
        }
        if r2rewrite::term_is_duplicable(
            query.projection,
            query.arena,
            query.entry_never_redefined,
            query.producer_term,
        ) {
            return true;
        }
        let read_by = readers.of(query.value);
        let (Some(def), [only]) = (graph.def_inst(query.value), read_by) else {
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

/// Each call's plan, or the gap it leaves, by its instruction, and the values planned calls assign
/// their results to.
fn plan_calls(
    input: &RenderInput<'_>,
    tags: &super::tags::Tags,
) -> (
    r2ssa::dense::IdMap<InstId, CallPlan>,
    r2ssa::dense::IdMap<InstId, CallGap>,
    r2ssa::dense::IdSet<ValueId>,
) {
    let (artifact, graph, inventory) = (input.artifact(), input.graph(), input.obligations());
    let mut planned = r2ssa::dense::IdMap::new(graph.insts.len());
    let mut unplanned = r2ssa::dense::IdMap::new(graph.insts.len());
    let mut results = r2ssa::dense::IdSet::new(graph.values.len());
    for inst in &graph.insts {
        let call = matches!(&inst.payload, InstPayload::Op(op) if calls::plans_a_call(op));
        let mut plan = match call
            .then(|| calls::plan(artifact, input.callee_resolution(), inventory, inst.id))
            .flatten()
        {
            Some(Ok(plan)) => plan,
            Some(Err(gap)) => {
                unplanned.insert(inst.id, gap);
                continue;
            }
            None if matches!(&inst.payload, InstPayload::Op(op) if op.is_call()) => {
                let callee = calls::gap_callee(artifact, input.callee_resolution(), inst.id);
                let reason = CallRefusal::NoCallSite;
                unplanned.insert(inst.id, CallGap { callee, reason });
                continue;
            }
            None => continue,
        };
        if matches!(plan.callee, calls::Callee::Named { .. }) {
            let signature = input.declared_callee_signature(inst.id);
            let callee = input.callee_type_graph(inst.id);
            let declares = |tag: &str, is_union| tags.declares(tag, is_union, callee);
            plan.declared = signature
                .and_then(|signature| calls::Prototype::of(signature, plan.fixed, &declares));
            // A declaration that states no result names its carrier, whatever its types spell.
            plan.carrier = (signature.and(input.callee_unproven_bits(inst.id)))
                .filter(|bits| crate::prelude::carrier(*bits).is_some());
            if let Some(signature) = signature {
                classed_evidence(inst.id, signature, plan.declared.as_ref());
            }
            // No declaration: the callee's own projection, as its header spells it (W46).
            if signature.is_none() {
                let (fixed, returns) = (plan.fixed, plan.result.is_some());
                let projected = input.callee_projection(inst.id);
                let admits = |tag: &str, is_union| tags.admits(tag, is_union, callee);
                plan.declared = projected.and_then(|(signature, unproven)| {
                    calls::Prototype::of_projection(signature, fixed, returns, unproven, &admits)
                });
            }
        }
        for result in plan.result.iter().flat_map(calls::CallResult::values) {
            results.insert(result);
        }
        planned.insert(inst.id, plan);
    }
    (planned, unplanned, results)
}

/// Evidence for each parameter `signature` declares that the call passes at its class.
fn classed_evidence(
    inst: InstId,
    signature: &r2types::FunctionType,
    declared: Option<&calls::Prototype>,
) {
    let spelled = |at: usize| declared.and_then(|declared| declared.params.get(at)?.as_ref());
    for (at, ty) in signature.params.iter().enumerate() {
        if spelled(at).is_none() {
            r2il::refusal_evidence!("staged-call-prototype", "{inst:?}: {at} {ty:?}");
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

/// The instruction a canonical id names: an operation, or the merge of its storage in its block.
fn canonical_inst(graph: &SsaGraph, id: &r2ssa::CanonicalInstructionId) -> Option<InstId> {
    match id.site {
        r2ssa::CanonicalInstructionSite::Op(op) => graph.inst_for_op(op),
        r2ssa::CanonicalInstructionSite::Phi(storage) => {
            let block = graph.block_id_for_addr(id.block_addr)?;
            (graph.phi_insts(block).iter().copied()).find(|phi| {
                (graph.inst(*phi)).and_then(|inst| graph.written_storage(inst)) == Some(storage)
            })
        }
        r2ssa::CanonicalInstructionSite::NativeSpan { .. } => None,
    }
}

/// Who reads each value, as the obligation inventory says ([`r2ssa::ValueReaders`]).
struct Readers<'a> {
    graph: &'a SsaGraph,
    inventory: &'a SemanticObligationInventory,
    index: r2ssa::ValueReaders,
}

impl<'a> Readers<'a> {
    fn new(graph: &'a SsaGraph, inventory: &'a SemanticObligationInventory) -> Self {
        let index = r2ssa::ValueReaders::of(inventory, graph);
        Self {
            graph,
            inventory,
            index,
        }
    }

    fn of(&self, value: ValueId) -> &[InstId] {
        self.index.get(value)
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
            InstPayload::Phi { predecessors } => graph
                .inputs(reader.id)
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
        // A part of a block operation's answer is the walk's to assign: it is read by name.
        if transfer::reads_answer(self.graph, value) {
            return None;
        }
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

/// The object the caller pushed the return address into, where the body reads it and never
/// writes it: what it reads there is that address. One pass over the accesses.
fn return_address_slot(artifact: &SsaArtifact) -> Option<ObjectId> {
    let accesses = &artifact.structured().memory_accesses;
    let mut slot = None;
    for access in accesses.values() {
        if !artifact.return_address_stack_object(access.object) {
            continue;
        }
        if access.is_write {
            return None;
        }
        slot = Some(access.object);
    }
    slot
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
    pub(super) fn new(
        input: &RenderInput<'a>,
        tags: &super::tags::Tags,
        symbols: Rc<RefCell<SymbolTable>>,
        forced: &r2ssa::dense::IdSet<ValueId>,
    ) -> Option<Self> {
        let artifact: &'a SsaArtifact = input.artifact();
        let graph = input.graph();
        let inventory = input.obligations();
        let projection = MachineProjection::from_artifact(artifact).ok()?;
        let readers = Readers::new(graph, inventory);
        let roots = canonical_roots(artifact, &projection, &readers)?;
        let (planned, unplanned, results) = plan_calls(input, tags);
        let elisions = crate::certified::Elisions::of(artifact);
        let mut dispatch = r2ssa::dense::IdSet::new(graph.insts.len());
        let switches = artifact.certificates().switches.values();
        dispatch.extend(switches.flat_map(|switch| switch.dispatch.iter().copied()));
        let bound = Demand {
            artifact,
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
            declared: vec![false; graph.values.len()],
            members: Vec::new(),
            owed: RefCell::new(vec![1; graph.values.len()]),
            broken: RefCell::new(Vec::new()),
            forced: forced.clone(),
            dom: input.function().domtree(),
            root: input.function().root(),
            reading: Cell::new(input.function().root()),
            bound,
            frame: super::frame::Frame::of(artifact),
            frame_array: RefCell::new(None),
            frame_formals: Vec::new(),
            symbols,
            params: Vec::new(),
            locals: RefCell::new(Vec::new()),
            rendered: RefCell::new(vec![false; graph.insts.len()]),
            restored: RefCell::new(vec![false; graph.insts.len()]),
            addressed: RefCell::new(vec![false; graph.insts.len()]),
            residual: RefCell::new(vec![false; graph.insts.len()]),
            effect: RefCell::new(vec![false; graph.insts.len()]),
            unassigned: RefCell::new(Vec::new()),
            pending: RefCell::new(Attempt::default()),
            dispatch,
            elisions,
            calls: planned,
            unplanned,
            results,
            prototypes: BTreeMap::new(),
            externs: RefCell::new(BTreeMap::new()),
            strings: input.string_literals(),
            globals: super::globals::Globals::of(input),
            ptr_bits: input.ptr_bits(),
            return_address: return_address_slot(artifact),
            own: Own::of(input),
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
        values.declare(input, tags, parameters);
        values.prototypes = values.decide_prototypes();
        Some(values)
    }

    /// Each cell a parameter that points to its inferred structure addresses, as that member. All
    /// or nothing per parameter: one access with no member keeps the byte spelling for every one.
    fn members_of(
        &self,
        input: &RenderInput<'_>,
        tags: &super::tags::Tags,
        pointing: Vec<(usize, String, CExpr, bool)>,
    ) -> Vec<Option<MemberCell>> {
        let mut members = Vec::new();
        // A member is read and written by a byte copy, which only a little-endian target matches.
        if !self.little_endian {
            return members;
        }
        let fields = &self.artifact.certificates().parameter_fields;
        let through = self.accesses_by_parameter(&pointing);
        for (slot, tag, base, stated) in pointing {
            if let Some(cells) = stated
                .then(|| self.projected_members(slot, &base, through.get(slot)?))
                .flatten()
            {
                self.place(&mut members, cells);
                continue;
            }
            let Some(structure) = input.parameter_structures().get(&slot) else {
                continue;
            };
            let (Some(definition), Ok(key)) = (
                (structure.tag == tag)
                    .then(|| input.inferred_aggregates().get(&tag))
                    .flatten(),
                u32::try_from(slot),
            ) else {
                continue;
            };
            let Some(r2ssa::ParameterFields::Constant(accesses)) = fields.get(&key) else {
                continue;
            };
            let cells = accesses.iter().map(|access| {
                let (_, name) = definition
                    .members
                    .get(*structure.fields.get(&access.offset)?)?;
                let cell = self.roots.access(access.access)?.canonical;
                let member = CExpr::PtrMember {
                    base: Box::new(base.clone()),
                    member: name.clone(),
                };
                Some((cell, MemberCell::At(CExpr::addr_of(member))))
            });
            if let Some(cells) = cells.collect::<Option<Vec<_>>>() {
                self.place(&mut members, cells);
            }
        }
        if let Some(cells) = self.member_rooted(tags) {
            self.place(&mut members, cells);
        }
        members
    }

    /// Each cell a projection roots at a loaded pointer member, as a member of the struct that
    /// member points at, where the unit defines its tag (D359). O(projections).
    fn member_rooted(&self, tags: &super::tags::Tags) -> Option<Vec<(TermId, MemberCell)>> {
        let interface = self.artifact.machine_context().function_interface()?;
        let graph = interface.type_graph()?;
        let projections = (self.artifact.aggregate_accesses())
            .projections_for_revision(interface.revision_identity())?;
        let cells = (projections.values()).filter_map(|projection| {
            let r2ssa::AggregateRoot::Member(root) = projection.root else {
                return None;
            };
            let whole = projection.graph == r2ssa::GraphOf::Interface
                && projection.element_index.is_none()
                && !projection.member_indexed();
            let r2ssa::AggregateAccessBinding::Read { result } =
                whole.then(|| projections.get(&root))??.binding
            else {
                return None;
            };
            let word = self.roots.access(root)?.canonical;
            let layout = (graph.aggregates().get(projection.aggregate_id as usize))
                .filter(|layout| layout.id() == projection.aggregate_id)?;
            let tag = tags.defines(layout.name(), false).then(|| layout.name())?;
            let cell = self.roots.access(projection.access)?.canonical;
            Some((
                cell,
                MemberCell::Through {
                    pointer: CType::Pointer(Box::new(CType::Struct(tag.to_owned()))),
                    member: projection.member_name.to_string(),
                    result,
                    word,
                },
            ))
        });
        Some(cells.collect())
    }

    /// Each cell's member address in `members`, a table over the arena allocated at the first.
    fn place(&self, members: &mut Vec<Option<MemberCell>>, cells: Vec<(TermId, MemberCell)>) {
        if members.is_empty() {
            *members = vec![None; self.roots.arena().len()];
        }
        for (cell, address) in cells {
            if let Some(at) = members.get_mut(cell.index()) {
                *at = Some(address);
            }
        }
    }

    /// The accesses through each stated pointing parameter, indexed by slot, in one pass over the
    /// body's accesses: O(accesses + slots).
    fn accesses_by_parameter(
        &self,
        pointing: &[(usize, String, CExpr, bool)],
    ) -> Vec<Vec<r2ssa::StructuredAccessId>> {
        let stated = (pointing.iter()).filter(|(_, _, _, stated)| *stated);
        let Some(slots) = stated.map(|(slot, ..)| slot + 1).max() else {
            return Vec::new();
        };
        let mut through = vec![Vec::new(); slots];
        let facts = self.artifact.facts();
        for access in facts.structured.memory_accesses.values() {
            if let Some(expression) = facts.addresses.parameter_expression(access.address)
                && let Some(accesses) = through.get_mut(expression.parameter)
            {
                accesses.push(access.id);
            }
        }
        through
    }

    /// Each cell an access through parameter `slot` (`through`), declared a pointer to the struct
    /// its root projects into, addresses as `&base->member` (D359); `None` where one is unprojected.
    fn projected_members(
        &self,
        slot: usize,
        base: &CExpr,
        through: &[r2ssa::StructuredAccessId],
    ) -> Option<Vec<(TermId, MemberCell)>> {
        let interface = self.artifact.machine_context().function_interface()?;
        let projections = (self.artifact.aggregate_accesses())
            .projections_for_revision(interface.revision_identity())?;
        let cells = (through.iter())
            .map(|id| {
                // A parameter root's struct is the declared pointee's node (`parameter_target`).
                let projection = projections.get(id)?;
                let named = projection.root == r2ssa::AggregateRoot::Parameter(slot as u32)
                    && projection.graph == r2ssa::GraphOf::Interface
                    && projection.element_index.is_none()
                    && !projection.member_indexed();
                let cell = self.roots.access(*id)?.canonical;
                let member = CExpr::PtrMember {
                    base: Box::new(base.clone()),
                    member: projection.member_name.to_string(),
                };
                named.then(|| (cell, MemberCell::At(CExpr::addr_of(member))))
            })
            .collect::<Option<Vec<_>>>()?;
        (!cells.is_empty()).then_some(cells)
    }

    /// A declared type is spelled as stated, a tag the graph states incomplete; an analysed one
    /// naming only tags the unit defines, an unstated sign as its word (D265).
    fn parameter_type(
        &self,
        input: &RenderInput<'_>,
        tags: &super::tags::Tags,
        (index, ty): (u32, &MachineType),
        stated: Option<&CType>,
    ) -> Option<CType> {
        match stated {
            Some(declared) => calls::spellable(declared, &|tag, union| tags.names(tag, union))
                .or_else(|| calls::untagged_pointer(declared)),
            None => (input.parameter_declaration(index as usize, ty.width_bits())).and_then(
                |analysed| {
                    calls::spellable(&analysed, &|tag, union| tags.defines(tag, union))
                        .or_else(|| calls::analysed_pointer(&analysed))
                },
            ),
        }
        .filter(|declared| calls::held_as(declared, ty, self.ptr_bits))
    }

    /// Parameters in their ABI order, then a local per bound value. A parameter the source declares
    /// a pointer is declared so, as the caller passes it, and read as the word its class is.
    fn declare(
        &mut self,
        input: &RenderInput<'_>,
        tags: &super::tags::Tags,
        parameters: Option<Vec<(u32, r2ssa::FormalHome, MachineType)>>,
    ) {
        let mut pointing = Vec::new();
        for (index, home, ty) in parameters.into_iter().flatten() {
            let class = terms::c_type(&ty).expect("a classed parameter has a C type");
            let stated = input.declared_parameter(index as usize, ty.width_bits());
            let declared = self.parameter_type(input, tags, (index, &ty), stated.as_ref());
            // A hole states no type: r2types spells its class's typedef, which claims none (D165).
            let hole = (input.parameter_declaration(index as usize, ty.width_bits()))
                .filter(crate::prelude::is_unread_slot);
            // The word is the class the body reads through: no read is cast.
            let differs = hole.is_none()
                && (declared.as_ref()).is_some_and(|declared| {
                    *declared != class && !r2types::is_unstated_word(declared)
                });
            // The source's own declaration, so its struct is the node r2ssa projects into (D359).
            let stated = stated.is_some() && hole.is_none() && declared.is_some();
            let c = hole.or(declared).unwrap_or_else(|| unstated_class(&class));
            let named = crate::ast::c_identifier(&input.parameter_name(index as usize));
            // The body reads the unstated word as its integer; only the header spells the word.
            let name = self.symbols.borrow_mut().declare(
                Some(named)
                    .filter(|name| spells_an_identifier(name))
                    .unwrap_or_else(|| r2source::positional_parameter_name(index as usize)),
                terms::word_free(&c).clone(),
                SymbolRole::Parameter(index),
            );
            match home {
                r2ssa::FormalHome::Register { value, .. } => {
                    self.declared[value.0 as usize] = differs;
                    self.names[value.0 as usize] = Some((name, ty));
                    self.owed.get_mut()[value.0 as usize] = 0;
                }
                r2ssa::FormalHome::Frame { .. } => {
                    self.frame_formals.push((index, name, ty, differs))
                }
            }
            // An incomplete tag has no member to name.
            if let CType::Pointer(pointee) = &c
                && let CType::Struct(tag) = pointee.as_ref()
                && tags.defines(tag, false)
            {
                pointing.push((index as usize, tag.clone(), CExpr::Var(name), stated));
            }
            self.params.push(CParam { ty: c, name });
        }
        self.members = self.members_of(input, tags, pointing);
        let mut forward = vec![None; self.graph.blocks.len()];
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
            let forced = u32::from(self.forced.contains(output));
            self.owed.get_mut()[output.0 as usize] = match inst.payload {
                InstPayload::Phi { .. } => {
                    forced
                        + *forward[inst.block.0 as usize]
                            .get_or_insert_with(|| self.forward_in(input, inst.block))
                }
                InstPayload::Op(_) => 1,
            };
            self.locals.get_mut().push(CLocal {
                ty: c,
                name: id,
                stack_offset: None,
                align: None,
            });
        }
    }

    /// The copies a merge in `block` owes: one per placed predecessor it does not dominate that is
    /// spelled before it; a later one pays after the first reads and is verified (`broken`). `O(preds)`.
    fn forward_in(&self, input: &RenderInput<'_>, block: r2ssa::BlockId) -> u32 {
        let Some(block) = self.graph.block(block) else {
            return 1;
        };
        let (dom, root) = (self.dom, self.root);
        let mut forward = (input.function().cfg().predecessors(block.addr).into_iter())
            .filter(|pred| {
                crate::structure::place::is_placed(dom, root, *pred)
                    && !dom.is_back_edge(*pred, block.addr)
            })
            .collect::<Vec<_>>();
        forward.dedup();
        let early = (forward.iter())
            .filter(|pred| self.graph.block_id_for_addr(**pred) < Some(block.id))
            .count();
        u32::try_from(if forward.is_empty() { 1 } else { early }).unwrap_or(u32::MAX)
    }

    /// The merges this attempt read as variables on a late edge's promise that the edge then broke:
    /// the next attempt owes them one more, so no read of them is a variable. Sorted, once each.
    pub(super) fn broken(&self) -> Vec<ValueId> {
        let mut broken = self.broken.borrow().clone();
        broken.sort_unstable();
        broken.dedup();
        broken
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
            None if self.graph.def_inst(value).is_none() => self.entry_read(value, ty),
            None => None,
        };
        let object = |object: ObjectId| self.object(object);
        let global = |at: u64, class: &MachineType, store: bool| self.global(at, class, store);
        let caller = |object: ObjectId, ty: &MachineType| self.caller_read(object, ty);
        let member = |term: TermId| self.members.get(term.index()).cloned().flatten();
        read(&Spell {
            projection: &self.projection,
            arena: self.roots.arena(),
            bound: &bound,
            object: &object,
            global: &global,
            little_endian: self.little_endian,
            return_address: self.return_address.map(|object| (object, self.ptr_bits)),
            caller: &caller,
            member: &member,
        })
    }

    fn spell(&self, term: TermId) -> Option<CExpr> {
        self.spelling(|spell| spell.term(term))
    }

    /// Record `inst` discharged by the text being spelled, once that text is kept.
    fn mark(&self, inst: InstId) {
        self.pending.borrow_mut().marks.push(inst);
    }

    /// Record `inst` discharged by text already written.
    fn commit(&self, inst: InstId) {
        if let Some(slot) = self.rendered.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
    }

    fn mark_discharged(&self, value: ValueId) {
        let discharges = (self.roots).discharges(self.artifact, &self.projection, value);
        for inst in discharged_insts(self.graph, discharges.iter()) {
            self.mark(inst);
        }
        let addressed = self.roots.addressed(value);
        let addressed = (addressed.iter()).filter_map(|id| canonical_inst(self.graph, id));
        self.pending.borrow_mut().addressed.extend(addressed);
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
            None => match self.names.get(value.0 as usize)?.as_ref() {
                Some((name, held)) => self.read_name(value, *name, held),
                None if self.graph.def_inst(value).is_none() => {
                    self.entry_read(value, &self.value_type(value)?)
                }
                None => None,
            },
        }
    }

    /// A name as its class reads it: a parameter declared a pointer is read as its word, and a name
    /// still owed a definition or defined out of this block's scope is never assigned.
    fn read_name(&self, value: ValueId, name: SymbolId, held: &MachineType) -> Option<CExpr> {
        let owed = self.owed.borrow().get(value.0 as usize).copied();
        let at = self.reading.get();
        let scope = || self.artifact.value_defined_before(value, at, usize::MAX);
        if let Err(cause) = variable_or_residual(owed == Some(0), scope) {
            let read = crate::prelude::residual(
                &terms::c_type(held)?,
                crate::prelude::ResidualCause::NeverAssigned,
            );
            if cause == super::proof::UnassignedCause::NotDominated {
                r2il::refusal_evidence!(
                    "read-not-dominated",
                    "{} is read in {at:#x}, which its definition does not dominate",
                    self.graph.var(value).display_name()
                );
            }
            self.unassigned_read(value, cause, held);
            return read;
        }
        let var = CExpr::var(name);
        match self.declared.get(value.0 as usize) {
            Some(true) => Some(CExpr::cast(terms::c_type(held)?, var)),
            _ => Some(var),
        }
    }

    /// Spell the text of the block at `addr` from here: its names are read there.
    pub(super) fn enter(&self, addr: u64) {
        self.reading.set(addr);
    }

    /// The variable `expr` reads as its word, where the variable is declared `to` already and the
    /// word is as wide as `to`, so the reading changes no bit.
    fn declared_variable(&self, expr: &CExpr, to: &CType) -> Option<CExpr> {
        let CExpr::Cast {
            ty, expr: inner, ..
        } = expr
        else {
            return None;
        };
        let CExpr::Var(id) = &**inner else {
            return None;
        };
        let bits = |ty: &CType| match ty.unaliased() {
            CType::Int { bits, .. } => Some(*bits),
            CType::Pointer(_) | CType::Function { .. } | CType::UnprototypedFunction(_) => {
                Some(self.ptr_bits)
            }
            _ => None,
        };
        let symbols = self.symbols.try_borrow().ok()?;
        (symbols.get(*id).ty == *to && bits(ty).is_some() && bits(ty) == bits(to))
            .then(|| (**inner).clone())
    }

    /// An entry register no parameter admits, which C cannot read: an unadmitted argument slot
    /// (the convention's), else a value held from entry.
    fn entry_read(&self, value: ValueId, ty: &MachineType) -> Option<CExpr> {
        let storage = (self.graph.formal_projection_storage(value)).or(self
            .graph
            .values
            .get(value.0 as usize)?
            .canonical_storage);
        let context = self.artifact.machine_context();
        let slots = context.convention();
        let position = storage.zip(slots).and_then(|(storage, slots)| {
            (slots
                .arguments(r2source::convention::SlotClass::Integer)
                .iter())
            .position(|slot| slot.space == storage.space && slot.offset == storage.offset)
        });
        // A variadic body's tail: an argument slot past its parameters, or the vector count.
        // The integer section's own parameters: a float one takes no integer slot.
        let integers = |interface: &r2ssa::SourceFunctionInterface| {
            (interface.parameters().iter())
                .filter_map(r2source::SourceAbiParameterSpec::register_storage)
                .filter(|storage| {
                    (slots.into_iter().flat_map(|slots| {
                        slots.arguments(r2source::convention::SlotClass::Integer)
                    }))
                    .any(|slot| slot.space == storage.space && slot.offset == storage.offset)
                })
                .count()
        };
        let tail = context.function_interface().is_some_and(|interface| {
            interface.is_variadic()
                && (position.is_some_and(|slot| slot >= integers(interface))
                    || storage
                        .zip(slots.and_then(|model| model.forms.count_register))
                        .is_some_and(|(storage, count)| {
                            storage.space == count.space
                                && storage.offset < count.offset + u64::from(count.size)
                                && count.offset < storage.offset + u64::from(storage.size)
                        }))
        });
        let residual = match position {
            Some(_) => crate::prelude::ResidualCause::UnadmittedArgument,
            None => crate::prelude::ResidualCause::HeldFromEntry,
        };
        let cause = match (tail, position) {
            (true, _) => super::proof::UnassignedCause::VariadicTail,
            (false, Some(_)) => super::proof::UnassignedCause::UnadmittedArgument,
            (false, None) => super::proof::UnassignedCause::Held,
        };
        let read = crate::prelude::residual(&terms::c_type(ty)?, residual)?;
        self.unassigned_read(value, cause, ty);
        Some(read)
    }

    /// A read of a caller's stack slot r2ssa certifies only read (`caller_stack_slots`), which C
    /// cannot read: named by its entry offset, with what r2ssa says it holds.
    fn caller_read(&self, object: ObjectId, ty: &MachineType) -> Option<CExpr> {
        let slot = self
            .artifact
            .certificates()
            .caller_stack_slots
            .get(&object)?;
        let (cause, residual) = match slot.supply {
            r2ssa::CallerSlotSupply::UnadmittedArgument => (
                super::proof::UnassignedCause::UnadmittedArgument,
                crate::prelude::ResidualCause::UnadmittedArgument,
            ),
            r2ssa::CallerSlotSupply::HeldFromEntry => (
                super::proof::UnassignedCause::Held,
                crate::prelude::ResidualCause::HeldFromEntry,
            ),
            r2ssa::CallerSlotSupply::Formal(index) => return self.frame_formal(index, ty),
        };
        let read = crate::prelude::residual(&terms::c_type(ty)?, residual)?;
        self.unassigned_named(r2ssa::frame_object_name(slot.entry_offset), cause, ty);
        Some(read)
    }

    /// A whole read of stack formal `index` at its home: the parameter, at the class `ty` reads.
    fn frame_formal(&self, index: u32, ty: &MachineType) -> Option<CExpr> {
        let (_, name, held, differs) =
            self.frame_formals.iter().find(|formal| formal.0 == index)?;
        let var = CExpr::var(*name);
        let var = match differs {
            true => CExpr::cast(terms::c_type(held)?, var),
            false => var,
        };
        terms::reclass(var, held, ty)
    }

    /// Record a read the proof line names once its text is kept; the name is declared, as the value
    /// it names, so the line keeps it, and no statement spells it.
    fn unassigned_read(
        &self,
        value: ValueId,
        cause: super::proof::UnassignedCause,
        ty: &MachineType,
    ) {
        self.unassigned_named(self.graph.var(value).display_name(), cause, ty);
    }

    fn unassigned_named(
        &self,
        name: String,
        cause: super::proof::UnassignedCause,
        ty: &MachineType,
    ) {
        if let (Ok(mut symbols), Some(c)) = (self.symbols.try_borrow_mut(), terms::c_type(ty))
            && symbols.by_name(&name).is_none()
        {
            symbols.declare(name.clone(), c, SymbolRole::Carrier);
        }
        (self.pending.borrow_mut().reads).push(super::proof::UnassignedRead { cause, name });
    }

    /// `value` as `reader` reads it, with what its spelling reads and absorbs, kept apart.
    fn operand_alone(&self, value: ValueId, reader: InstId) -> Option<(CExpr, Attempt)> {
        self.attempt();
        let spelled = self.operand(value, reader);
        let attempt = std::mem::take(&mut *self.pending.borrow_mut());
        Some((spelled?, attempt))
    }

    /// Start spelling a statement or a test: what an abandoned attempt read or absorbed is not.
    fn attempt(&self) {
        *self.pending.borrow_mut() = Attempt::default();
    }

    /// Keep what the text just written reads and absorbs.
    fn keep(&self) {
        let Attempt {
            reads,
            marks,
            addressed,
        } = std::mem::take(&mut *self.pending.borrow_mut());
        self.unassigned.borrow_mut().extend(reads);
        for inst in marks {
            self.commit(inst);
        }
        let mut held = self.addressed.borrow_mut();
        for inst in addressed {
            held[inst.0 as usize] = true;
        }
    }

    /// The values read as residuals for want of a value, each once, by cause and name.
    pub(super) fn unassigned(&self) -> Vec<super::proof::UnassignedRead> {
        let mut reads = self.unassigned.borrow().clone();
        reads.sort();
        reads.dedup();
        reads
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
            self.attempt();
            let state = self.inventory.state_of(inst.id);
            let at = self.graph.instruction_for_inst(inst.id).unwrap_or(addr);
            let stmt = match state {
                _ if certified_elision(
                    self.artifact,
                    (&self.elisions, &self.dispatch),
                    inst.id,
                )
                .is_some() =>
                {
                    Ok(Vec::new())
                }
                Some(SemanticInstructionState::LiveObligation)
                    if reads_beside_effect(op)
                        || (matches!(op, SSAOp::Load { .. }) && self.owes_atomicity(inst.id)) =>
                {
                    self.effect_gap(&mut out, (addr, at), inst.id);
                    self.value(inst.id, inst.output)
                }
                Some(SemanticInstructionState::LiveObligation) => {
                    self.statement(inst.id, op, inst.output)
                }
                Some(SemanticInstructionState::UnsupportedUnknown) => Err(match op {
                    SSAOp::CallOther { userop, .. } => Gap::UserOperation(*userop),
                    // A call or tail jump r2ssa's boundary leaves unproven is a call gap, by that refusal.
                    op if calls::plans_a_call(op) => (self.unplanned.get(inst.id))
                        .map_or(Gap::Unsupported, |gap| Gap::Call(gap.reason)),
                    _ => Gap::Unsupported,
                }),
                _ => Ok(Vec::new()),
            };
            match stmt {
                Ok(stmts) => {
                    for stmt in stmts {
                        self.wrote(inst, &stmt);
                        out.push((at, stmt));
                    }
                }
                Err(gap) => self.gap(&mut out, (addr, at), inst.id, gap),
            }
        }
        out
    }

    /// Extend the gap the block's text ends with, or open one at this instruction.
    fn gap(&self, out: &mut Vec<(u64, CStmt)>, (addr, at): (u64, u64), inst: InstId, gap: Gap) {
        if let Some(slot) = self.residual.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
        self.marker(out, (addr, at), inst, self.gap_kind(inst, gap));
    }

    /// The gap for an atomic effect C has no statement of, beside the value its text still assigns.
    fn effect_gap(&self, out: &mut Vec<(u64, CStmt)>, (addr, at): (u64, u64), inst: InstId) {
        if let Some(slot) = self.effect.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
        self.marker(out, (addr, at), inst, GapKind::EffectNotRendered);
    }

    fn marker(
        &self,
        out: &mut Vec<(u64, CStmt)>,
        (addr, at): (u64, u64),
        inst: InstId,
        kind: GapKind,
    ) {
        let op_idx = self.graph.op_ordinal(inst).unwrap_or(0);
        if let Some((_, CStmt::Gap(marker))) = out.last_mut()
            && marker.op_idx + marker.ops == op_idx
            && marker.kind == kind
        {
            marker.ops += 1;
            return;
        }
        out.push((
            at,
            CStmt::Gap(GapMarker {
                kind,
                origin: "render::values".to_owned(),
                block_addr: addr,
                op_idx,
                ops: 1,
            }),
        ));
    }

    /// The marker's kind: a call by its callee and reason; a user operation by the name the
    /// specification gives it, else only that the inventory could not account for it.
    fn gap_kind(&self, inst: InstId, gap: Gap) -> GapKind {
        match gap {
            Gap::Call(reason) => GapKind::CallNotRendered(self.call_gap(inst, reason)),
            Gap::UserOperation(userop) => self
                .artifact
                .user_operations()
                .get(userop as usize)
                .map_or(GapKind::UnsupportedInstruction, |name| {
                    GapKind::UserOperation(name.clone())
                }),
            Gap::Unsupported => GapKind::UnsupportedInstruction,
            Gap::Effect => GapKind::EffectNotRendered,
            Gap::Store => GapKind::StoreNotSpelled,
            Gap::Term => GapKind::TermNotSpelled,
            Gap::Type => GapKind::ValueHasNoCType,
            Gap::Unknown => GapKind::ValueNotComputed,
        }
    }

    /// The statements one live instruction owes, in order (a pair call owes several): none where
    /// it owes none here, `Err` where it owes one the facts cannot spell.
    fn statement(
        &self,
        inst: InstId,
        op: &SSAOp<ValueId>,
        output: Option<ValueId>,
    ) -> Result<Vec<CStmt>, Gap> {
        match op {
            SSAOp::CBranch { .. }
            | SSAOp::Branch { .. }
            | SSAOp::Switch { .. }
            | SSAOp::Return { .. }
            | SSAOp::BranchInd { .. } => Ok(Vec::new()),
            // A store inside an access no typed statement holds is no plain C store.
            SSAOp::Store { .. } if self.owes_atomicity(inst) => Err(Gap::Effect),
            SSAOp::Store { addr, val, .. } => self
                .store(inst, *addr, *val)
                .map(|stmt| vec![stmt])
                .ok_or(Gap::Store),
            SSAOp::Atomic(access) => self
                .atomic(inst, access, output)
                .map(|stmt| vec![stmt])
                .ok_or(Gap::Effect),
            _ if op.is_call() => self.call(inst).map_err(Gap::Call),
            SSAOp::BlockTransfer(transfer) => self
                .block_transfer(inst, transfer)
                .map(|stmt| vec![stmt])
                .ok_or(Gap::Effect),
            // The block operation's statement assigns the part of its answer this reads.
            SSAOp::Subpiece { .. }
                if output.is_some_and(|o| transfer::reads_answer(self.graph, o)) =>
            {
                Ok(Vec::new())
            }
            // The described call's statement assigns its result.
            SSAOp::CallDefine { .. } if output.is_some_and(|o| self.results.contains(o)) => {
                Ok(Vec::new())
            }
            SSAOp::CallDefine { .. } if output.is_some_and(|o| self.is_named(o)) => {
                Err(Gap::Unknown)
            }
            _ if writes_value(op) => self.value(inst, output),
            _ if self.inventory.obligations_for_inst(inst).next().is_none() => Ok(Vec::new()),
            _ => Err(Gap::Effect),
        }
    }

    /// The binding of `inst`'s output to its term's spelling, where a statement owes it one.
    fn value(&self, inst: InstId, output: Option<ValueId>) -> Result<Vec<CStmt>, Gap> {
        let Some(output) = output else {
            return Ok(Vec::new());
        };
        if !self.bound[inst.0 as usize] {
            return Ok(Vec::new());
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
        Ok(vec![self.binding(output, name, canonical.canonical, value)])
    }

    /// `value` written at the store's cell: its canonical access where import built one, else its
    /// own address operand at the value's width.
    /// What writing `inst`'s statement records: the instruction rendered, the residuals its text
    /// evaluates, and the named value it assigns.
    fn wrote(&self, inst: &r2ssa::GraphInst, stmt: &CStmt) {
        self.mark(inst.id);
        self.residual_in(inst.id, stmt);
        if let Some(output) = inst.output.filter(|value| self.is_named(*value)) {
            self.defines(output);
        }
    }

    /// A statement written assigns `value` itself, which owes nothing more.
    fn defines(&self, value: ValueId) {
        if let Some(slot) = self.owed.borrow_mut().get_mut(value.0 as usize) {
            *slot = 0;
        }
    }

    /// The statement binding `output` to `value`, its term's spelling: a read nothing uses still
    /// reads, so the statement performs it and discards the value.
    fn binding(&self, output: ValueId, name: SymbolId, term: TermId, value: CExpr) -> CStmt {
        if self.readers.of(output).is_empty()
            && effectful(&self.projection, self.roots.arena(), term)
        {
            return CStmt::Expr(CExpr::cast(CType::Void, value));
        }
        self.assign_value(output, name, value)
    }

    /// `name = value`, `value` spelled as C converts it to the type `output` is held at.
    fn assign_value(&self, output: ValueId, name: SymbolId, value: CExpr) -> CStmt {
        let held = self.names[output.0 as usize].as_ref().map(|(_, held)| held);
        let value = match held.and_then(terms::c_type) {
            Some(ty) => terms::at_sink(&ty, value),
            None => value,
        };
        assign(name, value)
    }

    fn is_named(&self, value: ValueId) -> bool {
        self.names
            .get(value.0 as usize)
            .is_some_and(Option::is_some)
    }

    /// A described call: its callee by name, each argument at the class its signature passes it
    /// in, its result assigned.
    fn call(&self, inst: InstId) -> Result<Vec<CStmt>, CallRefusal> {
        let Some(plan) = self.calls.get(inst) else {
            return Err(
                (self.unplanned.get(inst)).map_or(CallRefusal::NoCallSite, |gap| gap.reason)
            );
        };
        if self.calls_itself(plan) {
            let call = self.recursive_call(inst, plan).map(|stmt| vec![stmt]);
            return needed(call, inst, CallRefusal::SelfCallNotSpelled);
        }
        let call = self.call_expr(inst, plan)?;
        needed(
            self.assign_call(inst, plan, call),
            inst,
            CallRefusal::ResultNotSpelled,
        )
    }

    /// The gap a call the text states no statement for leaves: its callee and `reason`.
    fn call_gap(&self, inst: InstId, reason: CallRefusal) -> CallGap {
        let callee = match (self.calls.get(inst), self.unplanned.get(inst)) {
            (Some(plan), _) => match &plan.callee {
                calls::Callee::Named { name, .. } => GapCallee::Named(name.clone()),
                calls::Callee::Through(_) => GapCallee::Indirect,
            },
            (None, Some(gap)) => gap.callee.clone(),
            (None, None) => GapCallee::Indirect,
        };
        CallGap { callee, reason }
    }

    /// The text `value` points at where `reader` passes it as a constant address in `class`, and
    /// the capture proves text there.
    fn passed_text(&self, value: ValueId, class: &MachineType, reader: InstId) -> Option<&'a str> {
        if !matches!(class, MachineType::Integer { width_bits, .. } if *width_bits == self.ptr_bits)
        {
            return None;
        }
        let term = self
            .readers
            .absorbed((&self.projection, &self.roots), value, reader)?;
        let node = self.roots.arena().term(term);
        let address = match node.kind {
            _ if node.ty.width_bits() != self.ptr_bits => return None,
            TermKind::Literal(bits) => bits.bits(),
            TermKind::Leaf(r2rewrite::LeafRead { expr, .. }) | TermKind::Opaque(expr) => {
                match self.projection.expr(expr)?.kind() {
                    MachineExprKind::Constant { value, .. } => value.bits(),
                    _ => return None,
                }
            }
            _ => return None,
        };
        self.strings.get(&address).map(String::as_str)
    }

    fn calls_itself(&self, plan: &CallPlan) -> bool {
        matches!(&plan.callee, calls::Callee::Named { address, .. } if *address == Some(self.own.entry))
    }

    /// The literals among `arguments`: a constant a fixed, prototyped parameter holds passes as
    /// itself (a variadic one is not converted), and proven text as its string.
    fn literals_passed(
        &self,
        arguments: &mut [CExpr],
        types: &[CType],
        texts: Vec<Option<&str>>,
        fixed: usize,
    ) {
        let passed = arguments.iter_mut().zip(types).take(fixed);
        for (argument, ty) in passed.filter(|(_, ty)| !crate::prelude::is_unread_slot(ty)) {
            *argument = terms::at_sink(ty, std::mem::replace(argument, CExpr::IntLit(0)));
        }
        for ((argument, ty), text) in arguments.iter_mut().zip(types).zip(texts) {
            if let Some(text) =
                text.filter(|_| super::globals::string_literal_serves(ty, self.ptr_bits))
            {
                *argument = calls::text_as(text, ty);
            }
        }
    }

    /// Each argument the call at `inst` passes, at its class: the expression and its C type.
    fn passed(
        &self,
        inst: InstId,
        plan: &CallPlan,
    ) -> Result<(Vec<CExpr>, Vec<CType>), CallRefusal> {
        let mut arguments = Vec::with_capacity(plan.arguments.len());
        let mut types = Vec::with_capacity(plan.arguments.len());
        for (position, ((argument, class), stacked)) in
            plan.arguments.iter().zip(&plan.stacked).enumerate()
        {
            let (held, ty) = self.argument_type(inst, *argument, class, *stacked)?;
            // A slot the callee ignores passes its typed residual: no caller value reaches it.
            if let Some(hole) = plan
                .ignored(position)
                .then(|| crate::prelude::unread_slot(&ty))
            {
                let hole = needed(hole, inst, CallRefusal::ArgumentType)?;
                arguments.push(CExpr::cast(hole.clone(), CExpr::IntLit(0)));
                types.push(hole);
                continue;
            }
            let operand = self.operand(*argument, inst);
            let operand = needed(operand, inst, CallRefusal::ArgumentOperand)?;
            let fitted = fit(operand, &held, class);
            arguments.push(needed(fitted, inst, CallRefusal::ArgumentFit)?);
            types.push(ty);
        }
        Ok((arguments, types))
    }

    /// The type an argument is held at and the C type its class passes it as, from the facts alone.
    fn argument_type(
        &self,
        inst: InstId,
        argument: ValueId,
        class: &MachineType,
        stacked: bool,
    ) -> Result<(MachineType, CType), CallRefusal> {
        let held = needed(self.value_type(argument), inst, CallRefusal::ArgumentType)?;
        // A float the caller stored as bits would travel in a float register once C declares it.
        if stacked && matches!(held, MachineType::Float { .. }) {
            return needed(None, inst, CallRefusal::FloatOnStack);
        }
        let ty = needed(terms::c_type(class), inst, CallRefusal::ArgumentType)?;
        Ok((held, ty))
    }

    /// The C type the call returns: its declared prototype's, else its result's class, else `void`.
    fn return_type(&self, inst: InstId, plan: &CallPlan) -> Result<CType, CallRefusal> {
        // An unstated result is the carrier typedef at every call; a read at another class is no C.
        if let Some(bits) = plan.carrier {
            let read = plan.returns().map(terms::c_type);
            let held = read.is_none_or(|ty| ty == Some(CType::uint(bits)));
            let carrier = held.then(|| crate::prelude::result_carrier(bits));
            return needed(carrier, inst, CallRefusal::ResultNotSpelled);
        }
        let ret = match (plan.returns(), plan.unread) {
            (Some(class), _) => needed(terms::c_type(class), inst, CallRefusal::ResultNotSpelled)?,
            (None, Some(bits)) if plan.tail.is_none() => crate::prelude::result_carrier(bits),
            (None, _) => CType::Void,
        };
        Ok(plan
            .declared
            .as_ref()
            .and_then(|declared| declared.ret.clone())
            .unwrap_or(ret))
    }

    /// What the call at `inst` declares of its named callee, a function of its plan alone: the same
    /// whichever block is written first. `Ok(None)` for a call through a value.
    fn declaration(
        &self,
        inst: InstId,
        plan: &CallPlan,
    ) -> Result<Option<CExternDecl>, CallRefusal> {
        let calls::Callee::Named { .. } = &plan.callee else {
            return Ok(None);
        };
        let mut types = Vec::with_capacity(plan.arguments.len());
        for (position, ((argument, class), stacked)) in
            plan.arguments.iter().zip(&plan.stacked).enumerate()
        {
            let ty = self.argument_type(inst, *argument, class, *stacked)?.1;
            types.push(match plan.ignored(position) {
                true => needed(
                    crate::prelude::unread_slot(&ty),
                    inst,
                    CallRefusal::ArgumentType,
                )?,
                false => ty,
            });
        }
        let ret_type = self.return_type(inst, plan)?;
        Ok(extern_decl(plan, types, ret_type))
    }

    /// Each named callee's declaration, joined over the calls that state one (D350).
    fn decide_prototypes(&self) -> BTreeMap<String, Option<CExternDecl>> {
        let stated = self.calls.iter();
        joined(stated.filter_map(|(inst, plan)| self.declaration(inst, plan).ok().flatten()))
    }

    /// The call's expression: a named callee is declared as `prototypes` has it, one reached
    /// through a value is cast to the function type it is called at.
    fn call_expr(&self, inst: InstId, plan: &CallPlan) -> Result<CExpr, CallRefusal> {
        let (mut arguments, mut types) = self.passed(inst, plan)?;
        let texts = (plan.arguments.iter())
            .map(|(argument, class)| self.passed_text(*argument, class, inst))
            .collect();
        let ret_type = self.return_type(inst, plan)?;
        // A declared prototype passes and returns at the types the source states.
        if let Some(declared) = &plan.declared {
            let passed = (arguments.iter_mut().zip(&mut types))
                .zip(declared.params.iter().map(Option::as_ref))
                .filter_map(|(passed, to)| Some((passed, to?)))
                .filter(|((_, ty), _)| !crate::prelude::is_unread_slot(ty));
            for ((argument, ty), to) in passed {
                let taken = std::mem::replace(argument, CExpr::IntLit(0));
                *argument = match self.declared_variable(&taken, to) {
                    Some(variable) => variable,
                    None => calls::to_declared(taken, ty, to),
                };
                *ty = to.clone();
            }
        }
        self.literals_passed(&mut arguments, &types, texts, plan.fixed);
        let (name, kind) = match &plan.callee {
            calls::Callee::Named { name, kind, .. } => (name, *kind),
            calls::Callee::Through(target) => {
                // The printer spells a function type in a cast as the pointer to it: `ret (*)(params)`.
                let pointer = CType::Function {
                    ret: Box::new(ret_type),
                    params: types.into_boxed_slice(),
                };
                let address = (self.operand(*target, inst))
                    .and_then(|target| terms::fit_integer(target, self.ptr_bits));
                let address = needed(address, inst, CallRefusal::TargetNotSpelled)?;
                return Ok(CExpr::call_at(
                    inst,
                    CExpr::cast(pointer, address),
                    arguments,
                ));
            }
        };
        // A parameter or local of the callee's name would shadow the function it calls.
        if (self.symbols.try_borrow()).map_or(true, |symbols| symbols.by_name(name).is_some()) {
            return needed(None, inst, CallRefusal::CalleeShadowed);
        }
        // One declaration describes every call to a callee, so calls that disagree cannot both be C.
        let declaration = extern_decl(plan, types, ret_type);
        match (declaration, self.prototypes.get(name)) {
            (Some(declaration), Some(Some(decided))) if declaration == *decided => {
                self.externs
                    .borrow_mut()
                    .entry(name.clone())
                    .or_insert(declaration);
            }
            _ => return needed(None, inst, CallRefusal::DeclarationDisagrees),
        }
        let callee = CExpr::External {
            name: name.clone(),
            kind,
        };
        Ok(CExpr::call_at(inst, callee, arguments))
    }

    /// The call a tail transfer at `addr` stands for: the refusal of its plan, or no call site.
    pub(super) fn tail_gap(
        &self,
        addr: u64,
        resolution: Option<&r2types::CalleeResolutionFacts>,
    ) -> Option<CallGap> {
        let (inst, op) = self.terminator(addr)?;
        if let Some(gap) = self.unplanned.get(inst) {
            return Some(gap.clone());
        }
        op.jump().is_some().then(|| CallGap {
            callee: calls::gap_callee(self.artifact, resolution, inst),
            reason: CallRefusal::NoCallSite,
        })
    }

    /// A tail transfer as C: the call and a bare `return` where the function returns nothing, else
    /// the return of what the callee leaves in the function's own result register.
    pub(super) fn tail_call(
        &self,
        addr: u64,
        ty: &CType,
        decided: Option<&CType>,
    ) -> Option<Vec<CStmt>> {
        self.attempt();
        let (inst, _) = self.terminator(addr)?;
        let plan = self.calls.get(inst)?;
        let tail = plan.tail.as_ref()?;
        if plan.ends || self.calls_itself(plan) {
            return None;
        }
        let returns = self
            .artifact
            .machine_context()
            .function_interface()?
            .return_kind();
        let stmts = match (returns, tail) {
            (r2source::SourceFunctionReturn::Void, _) => {
                let call = self.call_expr(inst, plan).ok()?;
                vec![CStmt::Expr(call), CStmt::Return(None)]
            }
            (r2source::SourceFunctionReturn::Register { storage }, Some((carried, class)))
                if storage == *carried =>
            {
                let carrier = located_class(self.artifact, storage, storage.size * 8);
                let own = match decided {
                    Some(CType::Void) => return None,
                    Some(decided) => agreed(class_of(decided, storage.size * 8), carrier)?,
                    None => match carrier? {
                        class @ MachineType::Integer { .. } => class,
                        _ => return None,
                    },
                };
                let call = self.call_expr(inst, plan).ok()?;
                // The function's caller reads the bytes r2ssa says its declared result occupies.
                let demanded = (self.artifact.machine_context().function_interface())
                    .and_then(r2ssa::returned_bytes)
                    .and_then(|result| 1u64.checked_shl(result.size))
                    .map_or(u64::MAX, |n| n - 1);
                let spelled = fit(
                    calls::read_result(plan, call, class, demanded)?,
                    class,
                    &own,
                )?;
                // A call is returned as it is where it is declared the function's own type, or an
                // integer where the function returns one: `return` converts it as the cast would.
                let declared = match plan.declared.as_ref().and_then(|d| d.ret.as_ref()) {
                    Some(declared) => declared.clone(),
                    None => terms::c_type(class)?,
                };
                let returned = match returned_call(spelled, ty) {
                    Ok(call) if declared == *ty || integer(&declared) && integer(ty) => call,
                    Ok(call) | Err(call) => CExpr::cast(ty.clone(), call),
                };
                vec![CStmt::Return(Some(returned))]
            }
            // A void tail callee leaves an unproven or written result nothing: the return traps.
            (
                r2source::SourceFunctionReturn::Register { .. }
                | r2source::SourceFunctionReturn::Unproven,
                None,
            ) if plan
                .declared
                .as_ref()
                .is_some_and(|declared| declared.ret == Some(CType::Void)) =>
            {
                let call = self.call_expr(inst, plan).ok()?;
                let undefined =
                    crate::prelude::residual(ty, crate::prelude::ResidualCause::UnprovenReturn)?;
                vec![CStmt::Expr(call), CStmt::Return(Some(undefined))]
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
    fn assign_call(&self, inst: InstId, plan: &CallPlan, call: CExpr) -> Option<Vec<CStmt>> {
        let (result, class) = match &plan.result {
            None => return Some(vec![CStmt::Expr(call)]),
            Some(calls::CallResult::One(result, class)) => (result, class),
            Some(calls::CallResult::Pair { low, high, class }) => {
                return self.assign_pair(inst, call, (*low, *high), class);
            }
        };
        let Some((name, held)) = self.names.get(result.0 as usize).and_then(Option::as_ref) else {
            // No rendered text reads the result, so the call written for its effect discards it.
            if let Some(def) = self.graph.def_inst(*result) {
                self.mark(def);
            }
            return Some(vec![CStmt::Expr(call)]);
        };
        let demanded = (self.artifact.facts().demanded.as_ref())
            .map_or(u64::MAX, |demanded| demanded.bytes(*result));
        let value = fit(
            calls::read_result(plan, call, class, demanded)?,
            class,
            held,
        )?;
        if let Some(def) = self.graph.def_inst(*result) {
            self.mark(def);
        }
        self.defines(*result);
        Some(vec![assign(*name, value)])
    }

    /// A pair call: the value it returns held once in a local of both widths, each half that is
    /// read assigned its bits (doc/adr-language-profile.md, item 1).
    fn assign_pair(
        &self,
        inst: InstId,
        call: CExpr,
        halves: (Option<ValueId>, Option<ValueId>),
        class: &MachineType,
    ) -> Option<Vec<CStmt>> {
        let named = |value: Option<ValueId>| {
            let value = value?;
            let (name, held) = self.names.get(value.0 as usize)?.as_ref()?;
            Some((value, *name, *held))
        };
        let read: Vec<_> = [named(halves.0), named(halves.1)]
            .into_iter()
            .zip([0, 1])
            .collect();
        let mut stmts = Vec::with_capacity(3);
        if read.iter().any(|(named, _)| named.is_some()) {
            let bits = class.width_bits();
            let ty = terms::c_type(class)?;
            let at = self.graph.instruction_for_inst(inst)?;
            let pair = (self.symbols.borrow_mut()).declare(
                format!("pair_{at:x}"),
                ty.clone(),
                SymbolRole::Carrier,
            );
            let half = MachineType::Integer {
                width_bits: bits / 2,
                signedness: r2ssa::MachineSignedness::Unsigned,
            };
            stmts.push(assign(pair, call));
            for (named, index) in &read {
                let Some((_, name, held)) = named else {
                    continue;
                };
                let bits_of = terms::extract((bits, bits / 2), CExpr::var(pair), index * bits / 2)?;
                stmts.push(assign(*name, fit(bits_of, &half, held)?));
            }
            self.locals.borrow_mut().push(CLocal {
                ty,
                name: pair,
                stack_offset: None,
                align: None,
            });
        } else {
            stmts.push(CStmt::Expr(call));
        }
        for value in read
            .iter()
            .filter_map(|(named, _)| named.map(|(value, ..)| value))
        {
            self.defines(value);
        }
        for value in [halves.0, halves.1].into_iter().flatten() {
            if let Some(def) = self.graph.def_inst(value) {
                self.mark(def);
            }
        }
        Some(stmts)
    }

    /// A call to the function's own entry: by its own name and at the types its header declares,
    /// so the call agrees with the definition it stands in.
    fn recursive_call(&self, inst: InstId, plan: &CallPlan) -> Option<CStmt> {
        let params = self.own.params.as_ref()?;
        if params.len() != plan.arguments.len() {
            return None;
        }
        let mut arguments = Vec::with_capacity(params.len());
        for (position, ((argument, _), class)) in plan.arguments.iter().zip(params).enumerate() {
            if plan.ignored(position) {
                let hole = crate::prelude::unread_slot(&terms::c_type(class)?)?;
                arguments.push(CExpr::cast(hole, CExpr::IntLit(0)));
                continue;
            }
            let held = self.value_type(*argument)?;
            let fitted = fit(self.operand(*argument, inst)?, &held, class)?;
            let (classed, declared) = (terms::c_type(class)?, &self.params.get(position)?.ty);
            arguments.push(match self.declared_variable(&fitted, declared) {
                Some(variable) => variable,
                None => calls::to_declared(fitted, &classed, declared),
            });
        }
        let callee = CExpr::External {
            name: self.own.name.clone(),
            kind: crate::symbol::ExternalKind::Function,
        };
        let call = CExpr::call_at(inst, callee, arguments);
        // A pair calls itself through no one value: refused.
        let result = match &plan.result {
            None => None,
            Some(calls::CallResult::One(result, _)) => Some(*result),
            Some(calls::CallResult::Pair { .. }) => return None,
        };
        let named =
            result.and_then(|result| Some((result, self.names.get(result.0 as usize)?.as_ref()?)));
        let Some((result, (name, held))) = named else {
            // No rendered text reads the result, so the call written for its effect discards it.
            if let Some(def) = result.and_then(|result| self.graph.def_inst(result)) {
                self.mark(def);
            }
            return Some(CStmt::Expr(call));
        };
        let value = fit(call, &self.own.result?, held)?;
        if let Some(def) = self.graph.def_inst(result) {
            self.mark(def);
        }
        self.defines(result);
        Some(assign(*name, value))
    }

    /// The written calls a proof says never come back, by call instruction (D384).
    pub(super) fn never_returning(&self) -> r2ssa::dense::IdSet<InstId> {
        let mut ends = r2ssa::dense::IdSet::new(self.graph.insts.len());
        for (inst, plan) in self.calls.iter() {
            if self.ends_here(inst, plan) {
                ends.insert(inst);
            }
        }
        ends
    }

    /// Whether the written call at `inst` is proven never to come back. Only a named callee says so
    /// to C; a call through a pointer or to the own entry still ends its block at the trap.
    fn ends_here(&self, inst: InstId, plan: &calls::CallPlan) -> bool {
        plan.ends
            && matches!(plan.callee, calls::Callee::Named { .. })
            && !self.calls_itself(plan)
            && self.rendered.borrow().get(inst.0 as usize) == Some(&true)
    }

    /// Whether the block at `addr` ends in a written call its callee is declared never to return from.
    pub(super) fn ends_never_returning(&self, addr: u64) -> bool {
        let Some(block) = (self.graph.block_id_for_addr(addr)).and_then(|id| self.graph.block(id))
        else {
            return false;
        };
        let last_call = calls::last_call(self.graph, block);
        last_call.is_some_and(|inst| {
            (self.calls.get(inst)).is_some_and(|plan| self.ends_here(inst, plan))
        })
    }

    pub(super) fn externs(&self) -> Vec<CExternDecl> {
        self.externs.borrow().values().cloned().collect()
    }

    pub(super) fn extern_objects(&self) -> Vec<crate::ast::CExternObject> {
        self.globals.objects()
    }

    /// The object the program names at `at`, unless its identifier names something else here.
    fn global(&self, at: u64, class: &MachineType, store: bool) -> Option<super::globals::Named> {
        self.globals.at(at, class, store, |name| {
            name == self.own.name
                || self.prototypes.contains_key(name)
                || (self.symbols.try_borrow())
                    .map_or(true, |symbols| symbols.by_name(name).is_some())
        })
    }

    fn store(&self, inst: InstId, address: ValueId, value: ValueId) -> Option<CStmt> {
        if !self.little_endian {
            return None;
        }
        let arena = self.roots.arena();
        let access_id = store_access(self.inventory, inst);
        let (address, cell) = match self.roots.access(access_id) {
            Some(access) => {
                let cell = arena.term(access.canonical);
                let bytes = cell.ty.width_bits() / 8;
                let member = self.spelling(|spell| spell.member_address(access.canonical));
                let address = match cell.kind {
                    _ if member.is_some() => member?,
                    TermKind::Load { object, address } => {
                        self.spelling(|spell| spell.address(address, bytes, Some(object)))?
                    }
                    TermKind::Subscript { base, index } => {
                        self.spelling(|spell| spell.subscript((base, index), bytes, None))?
                    }
                    _ => return None,
                };
                let discharges =
                    (self.roots).access_discharges(self.artifact, &self.projection, access_id);
                for discharged in discharged_insts(self.graph, discharges.iter()) {
                    self.mark(discharged);
                }
                (address, cell.ty)
            }
            None => (self.operand(address, inst)?, self.value_type(value)?),
        };
        let ty = terms::c_type(&cell)?;
        let written = terms::reclass(self.operand(value, inst)?, &self.value_type(value)?, &cell)?;
        // C casts only to a scalar (C17 6.5.4): a carrier is already its own type.
        let written = match ty {
            CType::BitVector(_) => written,
            _ => CExpr::cast(ty.clone(), written),
        };
        let named = crate::ast::literal_value(&address).and_then(|at| self.global(at, &cell, true));
        let address = match named {
            Some(super::globals::Named {
                object: Some((object, declared)),
                ..
            }) => {
                let written = calls::to_declared(written, &ty, &declared);
                return Some(CStmt::Expr(CExpr::assign(object, written)));
            }
            Some(named) => named.address,
            None => address,
        };
        let pointer = CExpr::cast(CType::Pointer(Box::new(CType::Void)), address);
        Some(CStmt::Expr(match ty {
            CType::BitVector(bits) => {
                crate::bitvector::BitVectorHelper::store(bits)?.call(vec![pointer, written])
            }
            ty => Helper::Store(ResidualType::of(&ty)?).call(vec![pointer, written]),
        }))
    }

    /// The test a conditional branch ending `addr` takes its true edge on.
    pub(super) fn condition(&self, addr: u64) -> Option<CExpr> {
        let (inst, op) = self.terminator(addr)?;
        let SSAOp::CBranch { cond, .. } = op else {
            return None;
        };
        self.attempt();
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
        self.attempt();
        self.operand(selector, inst)
    }

    /// Record the jump ending `addr` written: the certified control states its one edge.
    pub(super) fn transferred(&self, addr: u64) {
        match self.terminator(addr) {
            Some((inst, SSAOp::Branch { .. })) => self.commit(inst),
            // A conditional branch r2ssa owes no predicate goes to one block, as a branch does.
            Some((inst, SSAOp::CBranch { .. }))
                if !(self.inventory.obligations_for_inst(inst))
                    .any(|o| o.id.kind == SemanticObligationKind::ControlPredicate) =>
            {
                self.commit(inst);
            }
            _ => {}
        }
    }

    /// Whether the return ending `addr` hands back a merge of its block whose edges in copy
    /// pairwise-distinct canonical terms: returns the compiler joined (ADR §5).
    pub(super) fn returns_distinct_merge(&self, addr: u64) -> bool {
        let Some((inst, SSAOp::Return { .. })) = self.terminator(addr) else {
            return false;
        };
        let values = returned_values(self.inventory, inst);
        let [value] = values.as_slice() else {
            return false;
        };
        let Some(merge) = (self.graph.def_inst(*value)).and_then(|def| self.graph.inst(def)) else {
            return false;
        };
        let here = self.graph.block_id_for_addr(addr);
        if !matches!(merge.payload, InstPayload::Phi { .. })
            || Some(merge.block) != here
            || !self.bound[merge.id.0 as usize]
        {
            return false;
        }
        // Two defs of one computation are one value: edges are told apart by canonical term.
        let inputs = self.graph.inputs(merge.id);
        let mut told = inputs
            .iter()
            .map(|input| match self.roots.value(*input) {
                Some(canonical) => (Some(canonical.canonical), None),
                None => (None, Some(*input)),
            })
            .collect::<Vec<_>>();
        told.sort_unstable();
        told.dedup();
        inputs.len() >= 2 && told.len() == inputs.len() && !inputs.contains(value)
    }

    /// What the return ending `addr` hands back as `ty`: `None` where the facts do not state it.
    pub(super) fn returned(&self, addr: u64, ty: Option<&CType>) -> Option<Option<CExpr>> {
        self.attempt();
        let (inst, op) = self.terminator(addr)?;
        if !matches!(op, SSAOp::Return { .. }) {
            return None;
        }
        let unproven = self
            .inventory
            .obligations_for_inst(inst)
            .any(|o| o.id.kind == SemanticObligationKind::ReturnValue && o.inputs.is_empty());
        let returns = (self.artifact.machine_context().function_interface())
            .map(r2source::SourceFunctionInterface::return_kind);
        if let Some(r2source::SourceFunctionReturn::Pair { low, high }) = returns {
            return self.returned_pair(inst, (low, high), ty).map(Some);
        }
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
                        located_class(self.artifact, storage, storage.size * 8)
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
        // The word is its integer: the cast converts to that (D265).
        let to = terms::word_free(&ty).clone();
        Some(Some(terms::at_sink(&ty, CExpr::cast(to, spelled))))
    }

    /// A pair's return: its two registers' values joined, the high half above the low, as the one
    /// integer of both widths (doc/adr-language-profile.md, item 1).
    fn returned_pair(
        &self,
        inst: InstId,
        (low, high): (r2ssa::CanonicalStorageId, r2ssa::CanonicalStorageId),
        ty: Option<&CType>,
    ) -> Option<CExpr> {
        let half = |storage: r2ssa::CanonicalStorageId| -> Option<CExpr> {
            let value =
                (self.inventory.obligations_for_inst(inst)).find_map(|o| match o.id.component {
                    SemanticObligationComponent::RegisterSlot { storage: slot, .. }
                        if o.id.kind == SemanticObligationKind::ReturnValue && slot == storage =>
                    {
                        o.inputs.first().copied()
                    }
                    _ => None,
                })?;
            let held = self.value_type(value)?;
            let class = MachineType::Integer {
                width_bits: storage.size * 8,
                signedness: r2ssa::MachineSignedness::Unsigned,
            };
            fit(self.operand(value, inst)?, &held, &class)
        };
        let bits = (low.size + high.size) * 8;
        let joined = terms::concat(bits, low.size * 8, half(high)?, half(low)?)?;
        let ty = match ty {
            Some(ty) => ty.clone(),
            None => CType::uint(bits),
        };
        Some(terms::at_sink(
            &ty,
            CExpr::cast(terms::word_free(&ty).clone(), joined),
        ))
    }

    fn terminator(&self, addr: u64) -> Option<(InstId, &'a SSAOp<ValueId>)> {
        let block = self.graph.block(self.graph.block_id_for_addr(addr)?)?;
        let inst = self.graph.inst(*block.insts.last()?)?;
        match &inst.payload {
            InstPayload::Op(op) => Some((inst.id, op)),
            InstPayload::Phi { .. } => None,
        }
    }

    /// The address of the instruction that ends the block at `addr`.
    pub(super) fn terminator_address(&self, addr: u64) -> Option<u64> {
        let (inst, _) = self.terminator(addr)?;
        self.graph.instruction_for_inst(inst)
    }

    /// Whether `stmt`, written for `inst`, evaluates a residual, which makes `inst`'s obligations residual.
    pub(super) fn residual_in(&self, inst: InstId, stmt: &CStmt) {
        self.keep();
        let mut held = false;
        stmt.visit_exprs(&mut |expr| held |= crate::prelude::holds_residual(expr));
        if held && let Some(slot) = self.residual.borrow_mut().get_mut(inst.0 as usize) {
            *slot = true;
        }
    }

    /// Record that the text stands a residual or trap for the block's terminator, where no
    /// statement already discharged that instruction.
    pub(super) fn residual_terminator(&self, addr: u64) {
        let Some((inst, _)) = self.terminator(addr) else {
            return;
        };
        if !self.rendered.borrow()[inst.0 as usize] {
            self.residual.borrow_mut()[inst.0 as usize] = true;
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
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "debt: keyed by a function's entity, to become an index over dense ids (ROADMAP LX2)"
        )
    )]
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
        // A use r2ssa states no observation depends on (a flag `add sp` computes) reads nothing.
        let unobserved = self.artifact.unobserved_merges().unobserved_uses();
        while let Some(value) = work.pop() {
            let Some(def) = self.graph.def_inst(value) else {
                continue;
            };
            if self.bound[def.0 as usize] || !seen.insert(def) {
                continue;
            }
            let inputs = self.graph.inputs(def);
            work.extend(inputs.iter().copied().filter(|input| {
                (self.graph.use_sites(*input).iter())
                    .all(|site| seen.contains(&site.inst) || unobserved.contains(site))
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
        let forward = !self.dom.is_back_edge(from, to);
        let late = forward && from_id > to_block.id;
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
            // An arm no path reads is no assignment: the edge pays the merge with nothing.
            if !(self.artifact.unobserved_merges()).arm_read(inst.id, slot) {
                self.pay(output, forward && !late);
                continue;
            }
            let input = self.graph.inputs(inst.id)[slot];
            let reads = match self
                .readers
                .absorbed((&self.projection, &self.roots), input, inst.id)
            {
                Some(term) => term_reads(&self.projection, self.roots.arena(), term),
                None => vec![input],
            };
            let source = self.operand_alone(input, inst.id);
            // r2ssa states an edge that carries the merge itself as the merge's own id (adr-decompiler-rewrite, "Merges").
            if input == output
                && let Some((spelled, attempt)) = source
            {
                self.account_copy(inst.id, output, attempt, (&CStmt::Expr(spelled), false));
                continue;
            }
            copies.push((inst.id, output, source, reads));
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
            let (Some((source, attempt)), Some((name, ty))) =
                (source, self.names[output.0 as usize].as_ref())
            else {
                out.push(self.gapped_copy((inst, output), (from, to), (forward, late)));
                continue;
            };
            let copy = CStmt::Expr(source.clone());
            self.promised((from, to), late);
            self.account_copy(inst, output, attempt, (&copy, forward && !late));
            match clobbers {
                false => out.push(self.assign_value(output, *name, source)),
                true => {
                    let temp = self.next_carrier(*name, ty);
                    out.push(assign(temp, source));
                    staged.push(assign(*name, CExpr::var(temp)));
                }
            }
        }
        out.extend(staged);
        out
    }

    /// A late edge's copy rendered: the early reads of its merge were right to rest on it.
    fn promised(&self, (from, to): (u64, u64), late: bool) {
        if late {
            r2il::refusal_evidence!(
                "late-forward-edge",
                "{from:#x} -> {to:#x} pays a merge after {to:#x} was spelled; its reads rest on the copy rendering"
            );
        }
    }

    /// The gap that stands for a merge and the value its copy could not carry. On a forward edge it keeps
    /// the merge owed; on a late one it breaks the promise the merge's early reads were made on.
    fn gapped_copy(
        &self,
        (inst, output): (InstId, ValueId),
        (from, to): (u64, u64),
        (forward, late): (bool, bool),
    ) -> CStmt {
        self.residual.borrow_mut()[inst.0 as usize] = true;
        if forward {
            r2il::refusal_evidence!(
                "gapped-forward-copy",
                "{from:#x} -> {to:#x} renders no copy, so every read of the merge stays residual"
            );
        }
        if late && !self.forced.contains(output) {
            self.broken.borrow_mut().push(output);
        }
        unrendered_copy(to)
    }

    /// The merge `inst` has a copy on this edge, rendered whether or not `stmt` is written. Only a copy
    /// that `pays` (on an early forward edge) lowers what the merge owes, once per edge.
    fn account_copy(
        &self,
        inst: InstId,
        output: ValueId,
        attempt: Attempt,
        (stmt, pays): (&CStmt, bool),
    ) {
        *self.pending.borrow_mut() = attempt;
        self.mark(inst);
        self.residual_in(inst, stmt);
        self.pay(output, pays);
    }

    /// One early forward edge of the merge `output` is rendered: it owes one copy fewer.
    fn pay(&self, output: ValueId, pays: bool) {
        if let (true, Some(owed)) = (pays, self.owed.borrow_mut().get_mut(output.0 as usize)) {
            debug_assert!(*owed > 0, "a forward edge pays a merge once");
            *owed = owed.saturating_sub(1);
        }
    }

    /// A local `<name>_next` of the merge's type, where a cycle of copies goes through.
    fn next_carrier(&self, name: SymbolId, ty: &MachineType) -> SymbolId {
        let c = terms::c_type(ty).expect("a named value has a C type");
        // The name is read before the table is borrowed to declare the temporary.
        let next = format!("{}_next", self.symbols.borrow().name(name));
        let temp = (self.symbols.borrow_mut()).declare(next, c.clone(), SymbolRole::Carrier);
        self.locals.borrow_mut().push(CLocal {
            ty: c,
            name: temp,
            stack_offset: None,
            align: None,
        });
        temp
    }

    /// What became of each obligation: rendered where the text discharged its instruction, residual
    /// where a site in the text stands for it; one with neither stays unaccounted in the proof line.
    pub(super) fn close(&self, ledger: &mut crate::ledger::ObligationLedger) {
        use crate::ledger::{ElisionReason, Outcome};
        let (rendered, restored) = (self.rendered.borrow(), self.restored.borrow());
        let (effect, addressed) = (self.effect.borrow(), self.addressed.borrow());
        let covered = self.covered_by_residuals();
        let certificates = self.artifact.certificates();
        let frame_setup = &certificates.stack_geometry.frame_setup;
        let object_addresses = &certificates.stack_geometry.object_addresses;
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
                _ if index.is_some_and(|i| covered[i]) => Outcome::Gapped,
                (SemanticObligationKind::Atomicity | SemanticObligationKind::MemoryOrdering, _)
                    if index.is_some_and(|i| effect[i]) =>
                {
                    Outcome::Gapped
                }
                _ if index.is_some_and(|i| rendered[i]) => {
                    match self.artifact.obligation_extent_assumption(obligation.id) {
                        Some(_) => Outcome::Assumed,
                        None => Outcome::Rendered,
                    }
                }
                _ if index.is_some_and(|i| restored[i]) => {
                    Outcome::Elided(ElisionReason::StackFrame)
                }
                // One frame object's address on every path, spelled `&object` where the text reads it.
                (
                    SemanticObligationKind::LiveValueProducer
                    | SemanticObligationKind::LoopCarriedState
                    | SemanticObligationKind::LiveStateTransition,
                    _,
                ) if (obligation.source.graph_inst())
                    .is_some_and(|i| object_addresses.contains(i) && addressed[i.0 as usize]) =>
                {
                    Outcome::Elided(ElisionReason::FrameAddress)
                }
                // Stack-pointer arithmetic r2ssa states only locates the frame the array names.
                (
                    SemanticObligationKind::LiveValueProducer
                    | SemanticObligationKind::LoopCarriedState
                    | SemanticObligationKind::LiveStateTransition,
                    _,
                ) if obligation
                    .source
                    .graph_inst()
                    .is_some_and(|i| frame_setup.contains(i)) =>
                {
                    Outcome::Elided(ElisionReason::StackFrame)
                }
                _ => continue,
            };
            let _ = ledger.record(obligation.id, outcome);
        }
    }

    /// By instruction index: a residual site's own instruction, the carriers a residual call reads,
    /// and each unwritten producer (or merge) of a value one of them reads or owes. Each is pushed
    /// once: O(V + E).
    fn covered_by_residuals(&self) -> Vec<bool> {
        let rendered = self.rendered.borrow();
        let mut covered = self.residual.borrow().clone();
        let mut work = (0..covered.len())
            .filter(|i| covered[*i])
            .collect::<Vec<_>>();
        while let Some(index) = work.pop() {
            let Some(inst) = self.graph.inst(InstId(index as u32)) else {
                continue;
            };
            let owed = self.inventory.obligations_for_inst(inst.id);
            let inputs = self
                .graph
                .inputs(inst.id)
                .iter()
                .chain(owed.flat_map(|o| o.inputs.iter()));
            let unwritten = |producer: &InstId| {
                !rendered[producer.0 as usize]
                    && certified_elision(self.artifact, (&self.elisions, &self.dispatch), *producer)
                        .is_none()
            };
            // A call the text could not write also stands for the carriers it reads.
            let reads = match &inst.payload {
                InstPayload::Op(op) if op.is_call() => self.graph.call_boundary_reads(inst.id),
                _ => Vec::new(),
            };
            let producers = (inputs.filter_map(|v| self.graph.def_inst(*v)))
                .chain(reads)
                .filter(unwritten)
                .map(|p| p.0 as usize)
                .collect::<Vec<_>>();
            work.extend(
                (producers.into_iter()).filter(|at| !std::mem::replace(&mut covered[*at], true)),
            );
        }
        covered
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
        | r2types::CTypeLike::Function { .. }
        | r2types::CTypeLike::UnprototypedFunction(_)
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

/// The type a value `width_bits` wide spells in `storage`, of the class the convention gives it
/// (`ConventionModel::class_of`); `None` outside every slot.
pub(super) fn located_class(
    artifact: &SsaArtifact,
    storage: r2source::CanonicalStorageId,
    width_bits: u32,
) -> Option<MachineType> {
    let class = artifact.machine_context().convention()?.class_of(storage)?;
    match class {
        r2source::convention::SlotClass::Integer if matches!(width_bits, 8 | 16 | 32 | 64) => {
            Some(MachineType::Integer {
                width_bits,
                signedness: r2ssa::MachineSignedness::Unsigned,
            })
        }
        r2source::convention::SlotClass::Float if matches!(width_bits, 32 | 64) => {
            Some(MachineType::Float { width_bits })
        }
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

/// Whether `name` is an identifier C leaves to the program: no keyword, nothing reserved to the
/// implementation (C11 7.1.3), and none of the helpers' own prefix.
fn spells_an_identifier(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
        "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while", "bool", "true", "false",
    ];
    let reserved = name.starts_with("__")
        || (name.starts_with('_') && name[1..].starts_with(|c: char| c.is_ascii_uppercase()))
        || name.starts_with("r2sleigh_");
    !name.starts_with(|c: char| c.is_ascii_digit()) && !reserved && !KEYWORDS.contains(&name)
}

/// The parameters in ABI order at the class C passes them in (a declared float a float, else an
/// integer of its width); `None` where any is unknown (doc/adr-decompiler-rewrite.md).
fn parameters(
    input: &RenderInput<'_>,
    artifact: &SsaArtifact,
) -> Option<Vec<(u32, r2ssa::FormalHome, MachineType)>> {
    artifact
        .facts()
        .boundaries
        .parameters
        .values()
        .map(|parameter| {
            let width_bits = parameter.bytes() * 8;
            let declared = input
                .parameter_declaration(parameter.index as usize, width_bits)
                .map(|declared| class_of(&declared, width_bits));
            // A register's class is the convention's; a stack slot carries any, so its declaration
            // decides and the machine word is the class only where none is declared.
            let register = parameter.register();
            let class = match (declared, register) {
                (Some(None), _) => return None,
                (Some(Some(declared)), Some((abi_storage, _))) => agreed(
                    Some(declared),
                    located_class(artifact, abi_storage, width_bits),
                )?,
                (Some(Some(declared)), None) => declared,
                (None, Some((abi_storage, _))) => located_class(artifact, abi_storage, width_bits)?,
                (None, None) => {
                    class_of(&r2types::CTypeLike::machine_bits(width_bits), width_bits)?
                }
            };
            // A parameter is declared at its value's own width: a lane of it is read by name.
            if class.width_bits() != width_bits {
                return None;
            }
            Some((parameter.index, parameter.home, class))
        })
        .collect()
}

/// Why a live instruction's statement is a gap: the marker's kind, which says what is missing.
#[derive(Debug, Clone, Copy)]
enum Gap {
    /// The inventory could not account for the instruction.
    Unsupported,
    /// A user operation the specification names and no model gives an effect: r2ssa accounts for
    /// it as an unknown effect, which no C statement states.
    UserOperation(u32),
    /// A call the facts do not describe, or whose C the text cannot spell, and why.
    Call(CallRefusal),
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
/// The call `spelled` is, through a cast to the function's own type `ty` at most; else `spelled`.
fn returned_call(spelled: CExpr, ty: &CType) -> Result<CExpr, CExpr> {
    match spelled {
        call @ CExpr::Call { .. } => Ok(call),
        CExpr::Cast { ty: to, expr, .. } if to == *ty && matches!(*expr, CExpr::Call { .. }) => {
            Ok(*expr)
        }
        other => Err(other),
    }
}

fn integer(ty: &CType) -> bool {
    matches!(ty.unaliased(), CType::Int { .. })
}

/// A merge copy into `to` the values could not spell: a gap on the edge.
fn unrendered_copy(to: u64) -> CStmt {
    CStmt::Gap(GapMarker {
        kind: GapKind::ValuesNotRendered,
        origin: "render::values".to_owned(),
        block_addr: to,
        op_idx: 0,
        ops: 0,
    })
}

fn returned_values(inventory: &SemanticObligationInventory, inst: InstId) -> Vec<ValueId> {
    inventory
        .obligations_for_inst(inst)
        .filter(|o| o.id.kind == SemanticObligationKind::ReturnValue)
        .flat_map(|o| o.inputs.iter().copied())
        .collect()
}

/// A linked load reads what a plain one reads (`r2ssa` machine lowering): its value is assigned,
/// and its link and ordering, which C has no statement of, are a gap beside it.
fn reads_beside_effect(op: &SSAOp<ValueId>) -> bool {
    matches!(op, SSAOp::LoadLinked { .. })
}

/// Whether an operation's effect is its output alone, so a local assigned its term states it.
fn writes_value(op: &SSAOp<ValueId>) -> bool {
    !op.is_call()
        && !matches!(
            op,
            SSAOp::Store { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallUse { .. }
                | SSAOp::CallOther { .. }
                | SSAOp::Fence { .. }
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
                | SSAOp::StoreConditional { .. }
                | SSAOp::StoreGuarded { .. }
                | SSAOp::Atomic(_)
                | SSAOp::IndivisibleAccess
                | SSAOp::BlockTransfer(_)
                | SSAOp::Breakpoint
                | SSAOp::Unimplemented
                | SSAOp::CpuId { .. }
                | SSAOp::New { .. }
        )
        && op.dst().is_some()
}

/// Whether a bound name reads as its variable: its writes are all spelled (`assigned`) and its
/// definition stands behind the read (`scope`, asked only then); else why it is a residual.
fn variable_or_residual(
    assigned: bool,
    scope: impl FnOnce() -> bool,
) -> Result<(), super::proof::UnassignedCause> {
    use super::proof::UnassignedCause;
    if !assigned {
        Err(UnassignedCause::Unassigned)
    } else if !scope() {
        Err(UnassignedCause::NotDominated)
    } else {
        Ok(())
    }
}

/// Each name's declaration over `stated`: a join over none, one and disagreeing in which
/// disagreeing absorbs, so no call order chooses one (D350). O(calls log callees).
fn joined(stated: impl IntoIterator<Item = CExternDecl>) -> BTreeMap<String, Option<CExternDecl>> {
    let mut decided = BTreeMap::<String, Option<CExternDecl>>::new();
    for declaration in stated {
        match decided.get_mut(&declaration.name) {
            None => {
                decided.insert(declaration.name.clone(), Some(declaration));
            }
            Some(held) => {
                if held.as_ref().is_some_and(|held| *held != declaration) {
                    *held = None;
                }
            }
        }
    }
    decided
}

#[cfg(test)]
mod tests {
    use super::super::proof::UnassignedCause;

    /// A name read where its definition does not dominate is a residual, however many of its writes
    /// were spelled before: reverse postorder is not dominance (ROADMAP D68).
    #[test]
    fn a_name_is_a_variable_only_where_it_is_assigned_and_its_definition_stands_behind_the_read() {
        assert_eq!(super::variable_or_residual(true, || true), Ok(()));
        assert_eq!(
            super::variable_or_residual(true, || false),
            Err(UnassignedCause::NotDominated)
        );
        // A name still owed a write is unassigned, and scope is not asked.
        assert_eq!(
            super::variable_or_residual(false, || panic!("asked")),
            Err(UnassignedCause::Unassigned)
        );
    }

    /// A declared name another language allows can still be a C keyword or reserved spelling.
    #[test]
    fn a_declared_name_c_reserves_is_no_identifier() {
        for name in ["n", "values", "_count", "x2"] {
            assert!(super::spells_an_identifier(name), "{name}");
        }
        for name in ["double", "char", "__x", "_Value", "r2sleigh_load_u8", "2x"] {
            assert!(!super::spells_an_identifier(name), "{name}");
        }
    }

    /// Two calls stating different declarations of one callee leave it none in either order, and
    /// every call to it refuses; calls that agree declare it (D350).
    #[test]
    fn disagreeing_declarations_decide_none_in_any_order() {
        use crate::ast::{CExternDecl, CType};
        let declared = |ret: CType| CExternDecl {
            name: "f".to_owned(),
            ret_type: ret,
            params: Some(Vec::new()),
            variadic: false,
            noreturn: false,
            address: Some(0x1000),
        };
        let (void, word) = (declared(CType::Void), declared(CType::uint(64)));
        for order in [[void.clone(), word.clone()], [word.clone(), void.clone()]] {
            assert_eq!(super::joined(order).get("f"), Some(&None));
        }
        let agreed = super::joined([word.clone(), word.clone()]);
        assert_eq!(agreed.get("f"), Some(&Some(word)));
        // A third call that agrees with either one does not undo the disagreement.
        let three = super::joined([void.clone(), declared(CType::uint(64)), void]);
        assert_eq!(three.get("f"), Some(&None));
    }
}
