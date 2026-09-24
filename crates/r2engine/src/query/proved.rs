//! What the analysis of the whole function says about each line, each claim on the smallest rung that establishes it.

use std::collections::BTreeMap;

use r2ssa::{
    CallArgumentLocation, CallsiteCertificate, CanonicalStorageId, CanonicalStorageSpace,
    InductionFact, InstId, InstPayload, InstructionBound, LoopTrips, ReturnCarrier, SSAOp,
    SsaArtifact, SsaGraph, StridedInterval, TripCount, ValueId,
};

use super::Support;
use super::records::{AnnotationKind, Answered, ArgumentSlot, CallArgument, Operand, Trips};
use crate::native::Prepared;

/// A prepared function, with every claim its certificates anchor at an instruction, by the line it is on.
pub struct Proved<'a> {
    prepared: &'a Prepared,
    anchored: BTreeMap<u64, Vec<(AnnotationKind, Support)>>,
}

impl<'a> Proved<'a> {
    /// One pass over each family of certificates: calls with their arguments, dispatches, loops and returns.
    pub fn new(prepared: &'a Prepared) -> Self {
        let artifact = prepared.artifact().artifact();
        let mut anchored = Anchored::default();
        anchored.calls(artifact);
        anchored.switches(prepared, artifact);
        anchored.unresolved(prepared);
        anchored.loops(artifact);
        anchored.returns(artifact);
        Self {
            prepared,
            anchored: anchored.0,
        }
    }

    pub fn prepared(&self) -> &Prepared {
        self.prepared
    }

    /// What the certificates say of the line at this address.
    fn at(&self, address: u64) -> &[(AnnotationKind, Support)] {
        self.anchored.get(&address).map_or(&[], Vec::as_slice)
    }
}

/// The claims being gathered, by line.
#[derive(Default)]
struct Anchored(BTreeMap<u64, Vec<(AnnotationKind, Support)>>);

impl Anchored {
    fn push(&mut self, line: u64, kind: AnnotationKind, support: Support) {
        self.0.entry(line).or_default().push((kind, support));
    }

    /// Each call's line says what it hands on, and each line that sets an argument says which call takes it.
    fn calls(&mut self, artifact: &SsaArtifact) {
        let graph = artifact.graph();
        for call in artifact.certificates().callsites.values() {
            let Some(line) = graph.instruction_for_inst(call.at) else {
                continue;
            };
            // An arity read off the registers written before the call is no proof the callee reads them.
            let proven = call.arguments_complete && call.described;
            let handed = proven.then(|| handed(artifact, call));
            let support = handed
                .as_ref()
                .map_or(Support::Certified, |(_, rung)| *rung);
            let uncounted = call
                .variadic
                .then_some(call.variadic_argument_count_refusal)
                .flatten()
                .map(|refusal| refusal.kind());
            let kind = AnnotationKind::Call {
                callee: call.direct_target,
                arguments: handed.map(|(arguments, _)| arguments),
                uncounted,
            };
            self.push(line, kind, support);
            if !proven {
                continue;
            }
            // The inversion of each argument's defining instruction, one entry per argument.
            let set = call.argument_certificates.iter().filter_map(|argument| {
                let set = graph.instruction_for_inst(argument.source_inst?)?;
                Some((set, argument.index))
            });
            for (set, index) in set.collect::<Vec<_>>() {
                let kind = AnnotationKind::ArgumentOf { call: line, index };
                self.push(set, kind, Support::Certified);
            }
        }
    }

    /// The dispatch line says where its table is, each arm's first line which cases reach it, and the default its guard.
    fn switches(&mut self, prepared: &Prepared, artifact: &SsaArtifact) {
        let graph = artifact.graph();
        for switch in artifact.certificates().switches.values() {
            let Some(dispatch) = transfer_line(graph, switch.block_addr) else {
                continue;
            };
            let guarded = switch.guard.and_then(|guard| {
                let line = transfer_line(graph, guard.block_addr)?;
                Some((guard.default, line))
            });
            // A default the dispatch itself names is reached from the dispatch.
            let default = guarded.or(switch.default.map(|target| (target, dispatch)));
            let kind = AnnotationKind::Switch {
                arms: switch.cases.clone(),
                default: default.map(|(target, _)| target),
                table: prepared.table_at(dispatch).copied(),
            };
            // The selector's domain is a range the value analysis solved, and the arms are words the revision holds.
            self.push(dispatch, kind, Support::Solved);
            let mut reaching = BTreeMap::<u64, Vec<u64>>::new();
            for (value, target) in &switch.cases {
                reaching.entry(*target).or_default().push(*value);
            }
            for (target, mut values) in reaching {
                values.sort_unstable();
                values.dedup();
                let kind = AnnotationKind::Case { values, dispatch };
                self.push(target, kind, Support::Solved);
            }
            if let Some((target, guard)) = default {
                let kind = AnnotationKind::Default { dispatch, guard };
                self.push(target, kind, Support::Solved);
            }
        }
    }

    /// An indirect transfer the walk stopped at says so, and no case is invented for it; a dispatch or a tail call there is already said.
    fn unresolved(&mut self, prepared: &Prepared) {
        for stop in &prepared.body().unresolved {
            if stop.reason != r2ssa::body::UnresolvedReason::IndirectBranch {
                continue;
            }
            let claims = self.0.get(&stop.addr).map_or(&[][..], Vec::as_slice);
            if !claims.iter().any(|(kind, _)| followed(kind)) {
                self.push(stop.addr, AnnotationKind::Unresolved, Support::Decoded);
            }
        }
    }

    /// Each loop header says which blocks return to it and where control leaves, what it carries, and how often it runs.
    fn loops(&mut self, artifact: &SsaArtifact) {
        let graph = artifact.graph();
        let structured = artifact.structured();
        // One pass groups the inductions by their loop, so no loop rescans them.
        let mut carried = BTreeMap::<_, Vec<_>>::new();
        for induction in structured.inductions.values() {
            carried
                .entry(induction.loop_id)
                .or_default()
                .push(induction);
        }
        for (id, fact) in &structured.loops {
            let kind = AnnotationKind::Loop {
                latches: fact.latches.clone(),
                exits: fact.exits.clone(),
            };
            self.push(fact.header, kind, Support::Certified);
            let inductions = carried.remove(id).unwrap_or_default();
            let valid = inductions.into_iter().filter(|one| one.validate(graph));
            for (kind, support) in valid.filter_map(|one| carries(artifact, one)) {
                self.push(fact.header, kind, support);
            }
            // A count needs the ranges that rule out a wrap, so it stands on the solver.
            if let Some(count) = fact
                .trips
                .as_ref()
                .ok()
                .and_then(|trips| counted(graph, trips))
            {
                self.push(fact.header, AnnotationKind::Trips(count), Support::Solved);
            }
        }
    }

    /// Each return says which register carries what it hands back.
    fn returns(&mut self, artifact: &SsaArtifact) {
        let graph = artifact.graph();
        for certificate in &artifact.certificates().returns {
            let Some(ReturnCarrier::Register { storage }) = certificate.carrier else {
                continue;
            };
            if let Some(line) = graph.instruction_for_inst(certificate.at) {
                let kind = AnnotationKind::Returns { storage };
                self.push(line, kind, Support::Certified);
            }
        }
    }
}

/// The arguments a call's boundary proved it hands on, and the highest rung any exact value among them stands on.
fn handed(artifact: &SsaArtifact, call: &CallsiteCertificate) -> (Vec<CallArgument>, Support) {
    let mut support = Support::Certified;
    let arguments = call.argument_certificates.iter().map(|argument| {
        let value = exact(artifact, argument.value);
        support = support.max(value.map_or(Support::Certified, |(_, rung)| rung));
        let slot = match argument.location {
            CallArgumentLocation::Register { storage } => ArgumentSlot::Register(storage),
            CallArgumentLocation::Stack { offset, .. }
            | CallArgumentLocation::Variable { offset } => ArgumentSlot::Stack(offset),
        };
        CallArgument {
            index: argument.index,
            slot,
            value: value.map(|(value, _)| value),
        }
    });
    (arguments.collect(), support)
}

/// Whether a claim already says where an indirect transfer goes: a dispatch or a call.
fn followed(kind: &AnnotationKind) -> bool {
    matches!(
        kind,
        AnnotationKind::Switch { .. } | AnnotationKind::Call { .. }
    )
}

/// What a header's induction carries, from what it starts at, on the rung its start stands on.
fn carries(artifact: &SsaArtifact, induction: &InductionFact) -> Option<(AnnotationKind, Support)> {
    let storage = register(artifact.graph(), induction.phi)?;
    let init = operand(artifact, induction.init);
    let kind = AnnotationKind::Induction {
        storage,
        init: init.map(|(init, _)| init),
        step: induction.step,
        width_bits: induction.width_bits,
    };
    let support = init.map_or(Support::Certified, |(_, rung)| rung);
    Some((kind, support.max(Support::Certified)))
}

/// A trip count as a claim names it: exact, or affine over what registers held on entry.
fn counted(graph: &SsaGraph, trips: &LoopTrips) -> Option<Trips> {
    match &trips.count {
        TripCount::Exact(count) => Some(Trips::Exact(*count)),
        TripCount::Symbolic { form, .. } => {
            let term = |(value, coefficient): (&ValueId, &u64)| {
                Some((entry(graph, *value)?, *coefficient))
            };
            let terms = form.terms.iter().map(term).collect::<Option<Vec<_>>>()?;
            Some(Trips::Affine {
                terms,
                constant: form.constant,
                width_bits: form.width_bits,
            })
        }
    }
}

/// The line of the instruction that ends a block's control: its indirect transfer, else its last operation.
fn transfer_line(graph: &SsaGraph, block_addr: u64) -> Option<u64> {
    let block = graph.block(graph.block_id_for_addr(block_addr)?)?;
    let transfer = |inst: &&InstId| {
        graph.inst(**inst).is_some_and(|inst| {
            matches!(
                inst.payload,
                InstPayload::Op(
                    SSAOp::BranchInd { .. } | SSAOp::Switch { .. } | SSAOp::CBranch { .. }
                )
            )
        })
    };
    let last = block
        .insts
        .iter()
        .rev()
        .find(transfer)
        .or(block.insts.last())?;
    graph.instruction_for_inst(*last)
}

/// The one value a value is, and the rung that shows it: the def-use's fold, else a singleton range.
fn exact(artifact: &SsaArtifact, value: ValueId) -> Option<(u64, Support)> {
    if let Some(folded) = artifact.folded_value(value) {
        return Some((folded, Support::Certified));
    }
    let range = artifact.values().get(value)?.as_constant()?;
    Some((range, Support::Solved))
}

/// A value as a claim may name it: exactly, or as what a register held on entry.
fn operand(artifact: &SsaArtifact, value: ValueId) -> Option<(Operand, Support)> {
    if let Some((value, support)) = exact(artifact, value) {
        return Some((Operand::Exact(value), support));
    }
    let storage = entry(artifact.graph(), value)?;
    Some((Operand::Entry(storage), Support::Certified))
}

/// The register a value was entered with, where the caller supplied it.
fn entry(graph: &SsaGraph, value: ValueId) -> Option<CanonicalStorageId> {
    if !graph.caller_supplied(value) {
        return None;
    }
    let storage = graph
        .formal_projection_storage(value)
        .or_else(|| graph.value(value)?.canonical_storage)?;
    (storage.space == CanonicalStorageSpace::Register).then_some(storage)
}

/// The register a value lives in.
fn register(graph: &SsaGraph, value: ValueId) -> Option<CanonicalStorageId> {
    let storage = graph.value(value)?.canonical_storage?;
    (storage.space == CanonicalStorageSpace::Register).then_some(storage)
}

/// The range proved for each machine word a line leaves, where it says anything, and what the certificates anchor there; `folded` is what the run leaves.
pub(super) fn proved_about(
    answered: &Answered<'_>,
    address: u64,
    folded: &dyn Fn(CanonicalStorageId) -> Option<u64>,
) -> Vec<(AnnotationKind, Support)> {
    let Some(proved) = answered.proved else {
        return Vec::new();
    };
    let mut claims = bounded(answered, proved.prepared, address, folded);
    claims.extend(proved.at(address).iter().cloned());
    claims
}

/// The range proved for each machine word a line leaves, where it says anything.
fn bounded(
    answered: &Answered<'_>,
    prepared: &Prepared,
    address: u64,
    folded: &dyn Fn(CanonicalStorageId) -> Option<u64>,
) -> Vec<(AnnotationKind, Support)> {
    let (Some(body), Some(machine)) = (answered.body, answered.decoders.at(address)) else {
        return Vec::new();
    };
    let facts = prepared.artifact().artifact();
    // A flag is proved to hold nought or one on every line that sets it, which says only that it is a flag.
    let word = |storage: &CanonicalStorageId| {
        storage.space == CanonicalStorageSpace::Register && storage.size == machine.arch.addr_size
    };
    // What the line defines is what it leaves: an earlier write it overwrites is not live after it.
    facts
        .graph()
        .left_by(address)
        .into_iter()
        .filter(|(storage, _)| word(storage))
        .filter_map(|(storage, output)| {
            let own = body.own_bound(address, storage)?;
            let range = facts.values().get(output)?;
            let certified = || facts.folded_value(output);
            let (range, support) = claimed(range, own, folded(storage), certified)?;
            let (low, high) = range.bounds()?;
            let kind = AnnotationKind::Bounds {
                storage,
                low,
                high,
                stride: range.stride().unwrap_or(0),
            };
            Some((kind, support))
        })
        .collect()
}

/// The range a line can claim and its rung: nothing where it is one value the instruction fixes or only the width it wrote.
///
/// `folded` is the one value the run leaves, and `certified` the one value the function's def-use folds it to.
fn claimed(
    range: StridedInterval,
    own: InstructionBound,
    folded: Option<u64>,
    certified: impl FnOnce() -> Option<u64>,
) -> Option<(StridedInterval, Support)> {
    let bound = own.range;
    if range.is_bottom() || range.width_bits() != bound.width_bits() {
        return None;
    }
    // Where the function proves no more, the claim is the instruction's own bound, unless that is one value or only the width written.
    if bound.join(&range) == range {
        let says_nothing = bound.as_constant().is_some() || own.spans_width_written;
        return (!says_nothing).then_some((bound, Support::Decoded));
    }
    // One value inside that bound needs the run where the run folds it, else the def-use where that does; any other range needs the solver.
    let Some(value) = range.as_constant() else {
        return Some((range, Support::Solved));
    };
    let support = if folded == Some(value) {
        Support::Folded
    } else if certified() == Some(value) {
        Support::Certified
    } else {
        Support::Solved
    };
    Some((range, support))
}
