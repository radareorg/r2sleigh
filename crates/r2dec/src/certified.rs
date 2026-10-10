//! What the certificates of a prepared function say renders no statement, read off r2ssa's facts
//! alone; the values and the ledger read the one set (ROADMAP D5).

use std::collections::BTreeSet;

use r2ssa::{InstId, UseSite, ValueId};

/// Exact graph uses that consume a source-certified machine return target.
///
/// This is a per-use answer. A return-address value may also have an ordinary
/// program use, which must remain renderable even though the `Return` operand
/// itself is machine control and has no C occurrence.
/// The exact `Return` uses of a certified return address.
fn certified_return_transfer_sites(source: &r2ssa::SsaArtifact) -> BTreeSet<UseSite> {
    let graph = source.graph();
    source
        .facts()
        .boundaries
        .returns
        .iter()
        .filter_map(|(at, boundary)| {
            let fact = boundary.return_address?;
            let site = UseSite {
                inst: at,
                input_idx: 0,
            };
            (boundary.at == at
                && graph.inst(at).is_some_and(|inst| {
                    matches!(
                        inst.payload,
                        r2ssa::InstPayload::Op(r2ssa::SSAOp::Return { .. })
                    ) && inst.inputs.as_slice() == [fact.value]
                })
                && graph.use_sites(fact.value).contains(&site))
            .then_some(site)
        })
        .collect()
}

/// The instructions a return-control certificate answers for.
///
/// Two kinds. The copy that moves a link register into the program counter
/// defines a value the structured form never emits, so its write is accounted
/// here rather than being left for a rendering that will not happen. And the
/// store that saved the return address in the first place, where the
/// certificate absorbed it: that write has no reader once the reload is
/// elided, and leaving it out of this set is what rendered it as an assignment
/// to a variable no one reads.
pub(crate) fn certified_return_control_insts(source: &r2ssa::SsaArtifact) -> BTreeSet<InstId> {
    let graph = source.graph();
    let mut insts = certified_return_control_values(source)
        .into_iter()
        .filter_map(|value| graph.def_inst(value))
        .collect::<BTreeSet<_>>();
    insts.extend(
        source
            .certificates()
            .machine_return_controls
            .values()
            .flat_map(|certificate| certificate.insts.iter().copied()),
    );
    insts
}

/// Close a control-only value set over the copies that carry those values.
///
/// A value every one of whose uses is a copy producing something already in the
/// set is itself in it. Re-scanning every value once per pass was quadratic in
/// the value count; a value can only become eligible when one of the copies it
/// feeds enters the set, so only those are re-examined.
fn close_over_control_copies(graph: &r2ssa::SsaGraph, values: &mut BTreeSet<ValueId>) {
    let mut work = values.iter().copied().collect::<Vec<_>>();
    while let Some(output) = work.pop() {
        let Some(def) = graph.def_of.get(output.0 as usize).copied().flatten() else {
            continue;
        };
        let Some(carrier) = graph.inst(def) else {
            continue;
        };
        if !matches!(
            carrier.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. })
        ) {
            continue;
        }
        for input in carrier.inputs.iter().copied() {
            if values.contains(&input) {
                continue;
            }
            let uses = graph.use_sites(input);
            if uses.is_empty() {
                continue;
            }
            let reaches_only_control = uses.iter().all(|site| {
                graph.inst(site.inst).is_some_and(|inst| {
                    matches!(
                        inst.payload,
                        r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. })
                    ) && inst.output.is_some_and(|output| values.contains(&output))
                })
            });
            if reaches_only_control {
                values.insert(input);
                work.push(input);
            }
        }
    }
}

pub(crate) fn certified_return_control_values(source: &r2ssa::SsaArtifact) -> BTreeSet<ValueId> {
    let graph = source.graph();
    let sites = certified_return_transfer_sites(source);
    let mut values = sites
        .iter()
        .filter_map(|site| graph.inst(site.inst)?.inputs.get(site.input_idx).copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|value| {
            let uses = graph.use_sites(*value);
            !uses.is_empty() && uses.iter().all(|site| sites.contains(site))
        })
        .collect::<BTreeSet<_>>();
    values.extend(
        source
            .certificates()
            .machine_return_controls
            .values()
            .flat_map(|certificate| certificate.values.iter().copied()),
    );

    // Follow the copies a return address arrives through.
    //
    // AArch64's `ret` lifts to a copy of the link register into the program
    // counter and then a return on that. The return's own input is certified,
    // but the link register one copy upstream is not, so it was bound to an
    // object no rendering ever emitted and the seal refused the function for a
    // value nothing rendered.
    //
    // A value every one of whose uses is a copy producing something already
    // control-only is itself control-only: it reaches nothing but the return.
    close_over_control_copies(graph, &mut values);
    values
}

/// Exact direct-call target uses the call expression renders as the callee.
///
/// Only a site whose certificate names a direct target qualifies: the call
/// spells the callee's name and the operand is elided beside it. A site with
/// no direct target reads a value the program computed, and that value keeps
/// its ordinary rendering contract.
pub(crate) fn certified_direct_call_target_sites(source: &r2ssa::SsaArtifact) -> BTreeSet<UseSite> {
    let graph = source.graph();
    source
        .certificates()
        .callsites
        .values()
        .filter_map(|certificate| {
            certificate.direct_target?;
            let inst = graph.inst(certificate.at)?;
            let value = certificate.target;
            let site = UseSite {
                inst: certificate.at,
                input_idx: 0,
            };
            (inst.inputs.first().copied() == Some(value) && graph.use_sites(value).contains(&site))
                .then_some(site)
        })
        .collect()
}

/// Direct-call target values whose complete use domain is the callee's name.
pub(crate) fn certified_direct_call_target_values(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<ValueId> {
    let graph = source.graph();
    let sites = certified_direct_call_target_sites(source);
    let mut values = sites
        .iter()
        .filter_map(|site| graph.inst(site.inst)?.inputs.get(site.input_idx).copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|value| {
            let uses = graph.use_sites(*value);
            !uses.is_empty() && uses.iter().all(|site| sites.contains(site))
        })
        .collect::<BTreeSet<_>>();

    // Follow the copies a callee's address arrives through, for the same
    // reason the return-address closure above does. A lift that materializes
    // the target into a temporary first leaves the call's own operand
    // certified and the copy one step upstream not, and that copy then lowered
    // to an assignment of an object the plan had already elided.
    close_over_control_copies(graph, &mut values);
    values
}

/// Definitions whose whole result is a callee's address on its way to the call.
///
/// The copy that materializes a call target renders nothing -- the call spells
/// the callee's name -- so its write and its operands are accounted here rather
/// than left for a statement that will not be emitted.
pub(crate) fn certified_direct_call_target_insts(source: &r2ssa::SsaArtifact) -> BTreeSet<InstId> {
    let graph = source.graph();
    certified_direct_call_target_values(source)
        .into_iter()
        .filter_map(|value| graph.def_inst(value))
        .collect()
}

/// The instructions a certificate says render no statement, indexed once per function.
pub(crate) struct Elisions {
    return_control: BTreeSet<InstId>,
    direct_call_targets: BTreeSet<InstId>,
    round_trips: r2ssa::dense::IdSet<InstId>,
}

impl Elisions {
    pub(crate) fn of(prepared: &r2ssa::SsaArtifact) -> Self {
        let round_trips = (prepared.certificates().memory_round_trips.values())
            .flat_map(|certificate| {
                [certificate.write, certificate.read]
                    .into_iter()
                    .chain(certificate.redundant_reads.iter().copied())
                    .map(|access| access.inst)
            })
            .collect();
        Self {
            return_control: certified_return_control_insts(prepared),
            direct_call_targets: certified_direct_call_target_insts(prepared),
            round_trips,
        }
    }

    /// Why a certificate says `inst` renders no statement, or `None`.
    pub(crate) fn reason(
        &self,
        prepared: &r2ssa::SsaArtifact,
        inst: InstId,
    ) -> Option<crate::ledger::ElisionReason> {
        use crate::ledger::ElisionReason;
        let certificates = prepared.certificates();
        let graph = prepared.graph();
        let output = graph.inst(inst).and_then(|inst| inst.output);
        let call_define = graph.inst(inst).is_some_and(|inst| {
            matches!(
                inst.payload,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::CallDefine { .. })
            )
        });
        if certificates.compiler_inserted.contains(inst) {
            Some(ElisionReason::CompilerInserted)
        } else if certificates.stack_frame_round_trip_by_inst.contains(inst) {
            Some(ElisionReason::StackFrame)
        } else if certificates.machine_return_control_by_inst.contains(inst)
            || self.return_control.contains(&inst)
        {
            Some(ElisionReason::ReturnControl)
        } else if certificates.dead_frame_stores.contains(inst)
            || certificates.dead_frame_store_values.contains(inst)
        {
            // A store into a slot this function owns and nothing reads.
            Some(ElisionReason::DeadFrameSlotStore)
        } else if self.round_trips.contains(inst) {
            Some(ElisionReason::MemoryRoundTrip)
        } else if output.is_some_and(|value| graph.formal_projection_storage(value).is_some()) {
            // The lane of an entry register a formal was minted from: the declaration defines it.
            Some(ElisionReason::CallerSuppliedEntryValue)
        } else if call_define
            && output.is_some_and(|value| !certificates.call_results.contains(value))
        {
            // What a call left in a register no result certificate claims.
            Some(ElisionReason::UnclaimedCallClobber)
        } else if certificates.call_return_address_stores.contains(inst) {
            Some(ElisionReason::CallReturnAddress)
        } else if self.direct_call_targets.contains(&inst) {
            Some(ElisionReason::DirectCallTarget)
        } else if certificates.stack_geometry.insts.contains(inst) {
            Some(ElisionReason::DeadStackBase)
        } else {
            None
        }
    }
}
