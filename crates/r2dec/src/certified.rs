//! What the certificates of a prepared function say renders no statement, read off r2ssa's facts
//! alone; the legacy binding plan and the staged ledger read the one set (ROADMAP D5).

use std::collections::BTreeSet;

use r2ssa::{InstId, UseSite, ValueId};

/// Every value a certificate reads as a decomposed store's lane.
///
/// The journal answers such a read from the value's binding symbol, so a value
/// in here cannot be folded into its reader. The membership question is
/// `certified_lane_read` and nothing else: this only enumerates the candidates
/// a certificate could name, so there is no second answer to drift from.
pub(crate) fn certified_lane_read_values(source: &r2ssa::SsaArtifact) -> BTreeSet<ValueId> {
    let mut values = BTreeSet::new();
    for run in source.structured().member_run_stores.values() {
        for member in &run.members {
            if let r2ssa::MemberRunSource::Lane(value) = member.source
                && certified_lane_read(source, value, member.access)
            {
                values.insert(value);
            }
        }
    }
    values
}

/// Whether `value` is the lane a decomposed wide store assigns at `access`.
pub(crate) fn certified_lane_read(
    source: &r2ssa::SsaArtifact,
    value: ValueId,
    access: r2ssa::StructuredAccessId,
) -> bool {
    source
        .structured()
        .memory_accesses
        .get(&access)
        .is_some_and(|fact| fact.id == access && fact.is_write && fact.value == Some(value))
        && source
            .structured()
            .member_run_stores
            .get(access.inst)
            .is_some_and(|run| {
                run.members.iter().any(|member| {
                    member.access == access && member.source == r2ssa::MemberRunSource::Lane(value)
                })
            })
}

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

/// Return-target values whose complete use domain is machine return control.
///
/// Only these values may be globally elided from the binding domain. The
/// per-use accounting above remains independent so a mixed-use value stays
/// bound while its exact `Return` use is still justified as non-rendered.
/// Every use that only ever carries a return address to its return.
///
/// The transfer itself, and the copies a return address reaches it through.
/// AArch64's `ret` lifts to a copy of the link register into the program
/// counter and a return on that, so the copy's read of the link register is
/// as much return control as the return's own read, and neither is rendered:
/// the structured form says `return`.
pub(crate) fn certified_return_control_sites(source: &r2ssa::SsaArtifact) -> BTreeSet<UseSite> {
    let graph = source.graph();
    let mut sites = certified_return_transfer_sites(source);
    for value in certified_return_control_values(source) {
        sites.extend(graph.use_sites(value).iter().copied());
    }
    sites
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

/// The instructions a return-control certificate took over from the prologue.
///
/// A save is shared -- with the frame certificate, when one `stp` does both
/// jobs, and with every other return in the function. So where an account of
/// these instructions already exists, this certificate agrees with it rather
/// than contradicting it, and the journal keeps the one that was there.
pub(crate) fn certified_return_control_absorbed_insts(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<InstId> {
    source
        .certificates()
        .machine_return_controls
        .values()
        .flat_map(|certificate| certificate.absorbed_insts.iter().copied())
        .collect()
}

/// The stack slots a return-control certificate claims.
///
/// A slot whose only write is the prologue's save of the return address and
/// whose only read is the reload the certificate already answers for is not a
/// local. Both binding derivations ask this the same way, so it is answered
/// once.
pub(crate) fn certified_return_control_stack_objects(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<r2ssa::ObjectId> {
    source
        .certificates()
        .machine_return_controls
        .values()
        .filter_map(r2ssa::MachineReturnControlCertificate::claimed_stack_object)
        .collect()
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

/// Exact direct-branch target uses already represented by CFG topology.
///
/// `Branch` and `CBranch` target operand zero qualify, and so does a
/// `BranchInd` whose switch is certified: the case topology is what expresses
/// it. Unresolved indirect branches, call, predicate, and return operands have
/// different rendering contracts.
///
/// A branch r2ssa certified as a call site is a call, whatever its shape: the
/// callee's name is what expresses it, not the topology, and its operand is
/// accounted as a call target. Deciding that from the op variant alone gave
/// one use two owners.
pub(crate) fn certified_direct_control_target_sites(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<UseSite> {
    let graph = source.graph();
    graph
        .insts
        .iter()
        .filter_map(|inst| {
            if certified_call_site(source, inst.id).is_some() {
                return None;
            }
            let target = match &inst.payload {
                r2ssa::InstPayload::Op(
                    r2ssa::SSAOp::Branch { target, .. } | r2ssa::SSAOp::CBranch { target, .. },
                ) => target,
                // A resolved jump table is control too. The structured form
                // prints `switch` on the selector and puts each case where its
                // block sits, so the computed target it dispatches through is
                // expressed by the topology exactly as a direct branch's is.
                // Only where the switch is certified: an indirect branch nobody
                // resolved keeps its ordinary rendering contract.
                r2ssa::InstPayload::Op(r2ssa::SSAOp::BranchInd { target, .. }) => {
                    let block_addr = graph.block(inst.block).map(|block| block.addr);
                    if !block_addr
                        .is_some_and(|addr| source.certificates().switches.contains_key(&addr))
                    {
                        return None;
                    }
                    target
                }
                _ => return None,
            };
            let value = *target;
            let site = UseSite {
                inst: inst.id,
                input_idx: 0,
            };
            (inst.inputs.first().copied() == Some(value) && graph.use_sites(value).contains(&site))
                .then_some(site)
        })
        .collect()
}

/// The call site r2ssa certified `at` as, if any.
///
/// Membership is the certificate's, not the operation's shape. r2ssa
/// certifies an ordinary call as `Call` or `CallInd` and a tail call as
/// `Branch` or `BranchInd` carrying `TailCall`, and it owns the map from
/// instruction to call site. Re-deciding membership here from the op variant
/// admitted a strict subset of what was proven: an import thunk is
/// `jmp [reloc.X]`, a `BranchInd` through a relocated slot, and every one of
/// them was refused for that alone.
pub(crate) fn certified_call_site(
    source: &r2ssa::SsaArtifact,
    at: InstId,
) -> Option<&r2ssa::CallsiteCertificate> {
    let certificates = source.certificates();
    let certificate = certificates
        .callsites
        .get(source.call_sites().by_inst.get(at)?)?;
    (certificate.at == at).then_some(certificate)
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

/// The stores that push a call's return address, and the values they consume.
///
/// A `call` on amd64 subtracts from the stack pointer and writes the address of
/// the instruction after it, and Sleigh lifts both. The structured form says
/// `f(...)`, which is the transfer; rendering the push beside it emits the
/// machine's bookkeeping as if it were program text, through a stack pointer
/// the function never assigned. That is where `murmur3_32`'s
/// `RSP_0 = RSP_0 - 8; *(int64_t*)RSP_0 = 0x1000009ce;` comes from.
///
/// A store qualifies only when the value it writes is the constant address the
/// call site falls through to, and it precedes that call in its own block.
/// Nothing else in a function stores its own continuation address.
pub(crate) fn certified_call_return_address_insts(source: &r2ssa::SsaArtifact) -> BTreeSet<InstId> {
    source
        .certificates()
        .call_return_address_stores
        .iter()
        .collect()
}

/// The return addresses those pushes write.
///
/// The constant is the machine's continuation address. Nothing in the C names
/// it, because the call statement is the transfer, so once the push is elided
/// the literal has no occurrence and no other answerer.
pub(crate) fn certified_call_return_address_values(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<ValueId> {
    let graph = source.graph();
    let pushes = certified_call_return_address_insts(source);
    pushes
        .iter()
        .filter_map(|inst| graph.inst(*inst)?.inputs.get(1).copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|value| {
            let uses = graph.use_sites(*value);
            !uses.is_empty() && uses.iter().all(|site| pushes.contains(&site.inst))
        })
        .collect()
}

/// Accesses to a frame slot this function writes and never reads.
///
/// A store into memory is an effect, and the ledger holds the rendering to it,
/// which is why a dead frame slot cannot simply be dropped: the obligation
/// would go unanswered. But observable means observable from outside, and a
/// `CalleeStackAllocationCertificate` is the proof that the object lies wholly
/// inside storage this function owns at every access. Where every one of those
/// accesses is a write, nothing here or anywhere else can read what was stored,
/// and the store has no meaning the C has to carry.
///
/// Ownership is not privacy: an object whose address escapes, or that a call's
/// argument area reaches, is read outside the body (`r2ssa::FrameReach`).
pub(crate) fn certified_dead_frame_slot_accesses(source: &r2ssa::SsaArtifact) -> BTreeSet<InstId> {
    let certificates = source.certificates();
    let reach = &source.objects().frame_reach;
    let (mut every_object, mut by_calls) = (false, BTreeSet::new());
    for (_, call) in reach.calls() {
        match call {
            r2ssa::CallFrameReach::Whole => every_object = true,
            r2ssa::CallFrameReach::Objects(objects) => by_calls.extend(objects.iter().copied()),
        }
    }
    let reached_by_a_call = |object| every_object || by_calls.contains(&object);
    let mut accesses = BTreeSet::new();
    for slot in certificates.stack_slots.values() {
        let Some(allocation) = slot.callee_allocation.as_ref() else {
            continue;
        };
        if reach.escaped(allocation.object) || reached_by_a_call(allocation.object) {
            continue;
        }
        let Some(owned) = allocation
            .accesses
            .iter()
            .map(|access| certificates.memory_accesses.get(access))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if owned.is_empty() || owned.iter().any(|access| !access.is_write) {
            continue;
        }
        accesses.extend(owned.iter().map(|access| access.access.inst));
    }
    accesses
}

/// Direct-control target values whose complete use domain is CFG topology.
pub(crate) fn certified_direct_control_target_values(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<ValueId> {
    let graph = source.graph();
    let sites = certified_direct_control_target_sites(source);
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
    // And everything a certified dispatch computes on the way to that target.
    // The structured `switch` is made of those operations, so no statement
    // renders them and nothing is left to spell the values they define.
    values.extend(
        source
            .certificates()
            .switches
            .values()
            .flat_map(|switch| switch.dispatch.iter().copied())
            .filter_map(|inst| graph.inst(inst)?.output),
    );
    values
}

/// Every operation a certificate already answers for, so it renders nothing of
/// its own.
///
/// Asked by the statement loop, which emits nothing for one, and by the plan,
/// which must agree about which values then have nowhere to be spelled. It was
/// a chain of certificate lookups written out inside the statement loop, so
/// the plan could not ask it and the two could disagree about the same
/// operation.
///
/// Built once for the function rather than asked per operation. Two of the
/// answers are sets derived from the whole value list, so asking per operation
/// rebuilt both of them per operation.
pub(crate) struct CertifiedSilence {
    insts: BTreeSet<r2ssa::InstId>,
}

impl CertifiedSilence {
    pub(crate) fn for_function(source: &r2ssa::SsaArtifact) -> Self {
        let graph = source.graph();
        let certificates = source.certificates();
        let mut insts: BTreeSet<r2ssa::InstId> =
            certificates.stack_frame_round_trip_by_inst.keys().collect();
        // Every instruction a return-control certificate answers for, not only
        // the ones it claims exclusively: the prologue's save of the return
        // address is shared with the frame's own setup and with every other
        // return, so it is deliberately claimed by none of them, and asking
        // only about exclusive claims left it to be rendered as a store to a
        // slot the plan had already elided.
        insts.extend(certified_return_control_insts(source));
        insts.extend(certificates.stack_geometry.insts.iter());
        // A decided stack-protector check's own loads and stores, which the C has no statement for.
        insts.extend(certificates.compiler_inserted.iter());
        // The copy that puts a callee's address in a temporary before the
        // call. The call spells the callee's name, so this assigns an object
        // the plan has elided and no statement can name.
        insts.extend(certified_direct_call_target_insts(source));
        // The push that records where the call comes back to. The call
        // statement is the transfer.
        insts.extend(certificates.call_return_address_stores.iter());
        // The halves of a memory round trip. The object ends holding what it
        // held, so the store assigns nothing and the read it puts back
        // produces a value no statement names.
        for certificate in certificates.memory_round_trips.values() {
            insts.extend(
                [certificate.write, certificate.read]
                    .into_iter()
                    .chain(certificate.redundant_reads.iter().copied())
                    .map(|access| access.inst),
            );
        }
        // The dispatch of a certified switch: scaling the selector, addressing
        // the table, reading the entry, transferring through it. The `switch`
        // is made of those, so none of them is a statement beside it.
        insts.extend(
            certificates
                .switches
                .values()
                .flat_map(|switch| switch.dispatch.iter().copied()),
        );
        // The lane of an entry register a formal was minted from: the
        // declaration is its definition.
        insts.extend(
            graph
                .insts
                .iter()
                .filter(|inst| {
                    inst.output
                        .is_some_and(|value| graph.formal_projection_storage(value).is_some())
                })
                .map(|inst| inst.id),
        );
        Self { insts }
    }

    pub(crate) fn contains(&self, inst: r2ssa::InstId) -> bool {
        self.insts.contains(&inst)
    }
}

/// Values whose complete use domain belongs to an exact upstream frame
/// save/reload certificate. The certificate collector already proved the
/// closure; this is only its renderer-facing projection.
pub(crate) fn certified_stack_frame_values(source: &r2ssa::SsaArtifact) -> BTreeSet<ValueId> {
    source
        .certificates()
        .stack_frame_round_trips
        .values()
        .flat_map(|certificate| certificate.values.iter().copied())
        .collect()
}

/// The values a decided stack-protector check's inserted operations define (`ElisionReason::CompilerInserted`).
pub(crate) fn certified_compiler_inserted_values(source: &r2ssa::SsaArtifact) -> BTreeSet<ValueId> {
    let graph = source.graph();
    source
        .certificates()
        .compiler_inserted
        .iter()
        .filter_map(|inst| graph.inst(inst)?.output)
        .collect()
}

/// The instructions whose operand reads a certificate already answers for.
///
/// These are read from the same certificates the observation journal reads, so
/// this is the same fact asked a different way rather than a second opinion:
/// the journal needs the elision reason per use, and the binding plan needs
/// only to know that the instruction's reads are not rendered.
///
/// It matters because folding a value into a read that never appears loses the
/// definition: `push rbp` is a certified frame round trip, so the store that
/// carries the frame pointer is elided, and the copy feeding it then had no
/// rendered occurrence anywhere. The ledger scored the effect refused and the
/// whole function fell back to no decompilation at all.
pub(crate) fn certified_elided_read_instructions(
    source: &r2ssa::SsaArtifact,
) -> BTreeSet<r2ssa::InstId> {
    let certificates = source.certificates();
    certificates
        .stack_frame_round_trips
        .values()
        .flat_map(|certificate| certificate.insts.iter().copied())
        .chain(
            certificates
                .machine_return_controls
                .values()
                .flat_map(|certificate| certificate.insts.iter().copied()),
        )
        .chain(certificates.stack_geometry.insts.iter())
        .chain(certificates.compiler_inserted.iter())
        .chain(certified_return_control_insts(source))
        .chain(certified_call_return_address_insts(source))
        .chain(certified_direct_call_target_insts(source))
        // A store that puts back what it read, and the read it puts back. The
        // certificate says the object ends holding what it held, so neither
        // renders and a value folded into either goes with it.
        .chain(
            certificates
                .memory_round_trips
                .values()
                .flat_map(|certificate| {
                    [certificate.write, certificate.read]
                        .into_iter()
                        .chain(certificate.redundant_reads.iter().copied())
                })
                .map(|access| access.inst),
        )
        // A store into a frame slot the function owns and never reads. The
        // effect ledger already answers for the store itself with
        // `DeadFrameSlotStore`, and the statement is not emitted; a value
        // folded into it goes with it.
        .chain(certified_dead_frame_slot_accesses(source))
        .collect()
}

pub(crate) fn certified_stack_geometry_values(
    source: &r2ssa::SsaArtifact,
) -> &r2ssa::dense::IdSet<ValueId> {
    &source.certificates().stack_geometry.values
}

/// The instructions a certificate says render no statement, indexed once per function.
pub(crate) struct Elisions {
    return_control: BTreeSet<InstId>,
    direct_call_targets: BTreeSet<InstId>,
    dead_frame_slots: BTreeSet<InstId>,
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
            dead_frame_slots: certified_dead_frame_slot_accesses(prepared),
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
        } else if self.dead_frame_slots.contains(&inst) {
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
