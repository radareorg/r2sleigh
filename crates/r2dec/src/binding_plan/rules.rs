//! The rules both binding-component derivations obey.
//!
//! A binding's membership is worked out twice: once by `construction`, which
//! unions values as it walks the certificates, and once by `seal`, which
//! recomputes the same components by a sorted traversal that cannot see the
//! construction pass's representatives, union schedule or accumulator. The
//! duplication is the point. The seal is a proof that the plan the renderer
//! will use is the plan the facts imply, and a proof that shared the
//! construction's working would prove nothing.
//!
//! What must not be duplicated is the *rules*. Two independent derivations of
//! one answer are a cross-check; two independently written statements of the
//! same rule are two answerers that can drift, and when they drift the seal
//! rejects a plan that is correct. So the rules live here, once, and both
//! derivations call them while keeping their own traversals.
//!
//! ## What may license a coalescing
//!
//! Three things, and they are proofs rather than exemptions. Two of them
//! propose a set of values as one object in `construction`: a *storage span*,
//! which says the values share a machine location, and a *certified entity*,
//! which says an upstream certificate found them to be one object. The rules
//! below then decline either proposal where it would put two values one
//! instruction reads at once into one object, or where one member is still
//! read after another has been given a new value.
//!
//! The third is newer and lives with the elision it licenses, in
//! `observation_journal::boundary_restores_carrier`: the *convention's
//! preserved-carrier statement*, which says a call leaves a named carrier
//! where it found it. It matters because the declines above are declines for
//! want of proof rather than prohibitions -- the comment beside the program
//! copy rule names "a save and restore around a clobber" as the shape that
//! must not fold, and the reason given is that nothing shows the object
//! survived. A call boundary's restore is exactly that shape and the source
//! does show it, naming the carrier it means, so the fold is admitted on the
//! proof and declined without it. Anything widening this further should
//! supply a fact of the same kind rather than a test on an operation's
//! spelling, which is what would turn the rule into a hole.

use std::collections::{BTreeMap, BTreeSet};

use crate::binding_plan::BindingCertificateSource;
use crate::ledger::ElisionReason;
use r2ssa::{InstId, SsaGraph, UseSite, ValueId};
use r2types::SourceOwnedFunctionFacts;

use super::{
    BindingPlanBuildError, BindingPlanSourceMismatch, ParameterRefusal, SemanticId,
    certified_direct_call_target_values, certified_direct_control_target_values,
    certified_elided_read_instructions, certified_return_control_values,
    certified_stack_frame_values, certified_stack_geometry_values, declaration_width_is_supported,
};

/// One ABI slot's evidence, before either derivation turns it into a
/// disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ParameterCandidate {
    Exact {
        entity: SemanticId,
        width_bytes: u32,
        entry_values: BTreeSet<ValueId>,
    },
    Refused(ParameterRefusal),
}

/// Collect the dense exact ABI-parameter domain without consulting names.
///
/// The source interface supplies unused formals; a matching render entity
/// supplies its exact entry-value membership and source-var carrier width.
/// Two claims on one slot refuse it, and the first refusal stands: a later
/// claim on a slot already refused does not change why it was refused, and
/// construction and the seal once disagreed about exactly that -- one
/// overwrote the reason, the other kept it -- so the seal refused every
/// function in which a slot was claimed three times, for a plan that was
/// right. One statement here is what keeps them from disagreeing again.
/// The role a declared slot plays for the object at `base`+`offset`.
///
/// A slot the source marks as a stack parameter's own storage is that only
/// where it sits at the coordinate the convention gives the parameter. A
/// debugger's location list can give the same variable a second frame slot
/// over a later range, and the source carries both under the parameter's
/// index; the second is a local the function copied the parameter into, and
/// binding it to the parameter would make two objects one symbol.
/// Whether a stack object sits outside this function's own frame.
///
/// The frame grows down from the entry stack pointer, so an object at or above
/// it is the caller's storage: the return address, a stack-passed argument, or
/// -- at a process entry -- what the loader left there. Nothing in this body
/// assigns it, and requiring a definition asks for one that cannot exist.
/// Whether the caller supplied what this binding holds.
///
/// One question, one answer. A member with no defining instruction entered
/// the function already holding its value, and a source that is the caller's
/// storage says the same thing about a slot. The plan and the seal both ask
/// here: while they asked separately they disagreed about the slot a call
/// pushes the return address into, and the seal refused every function that
/// reads it.
pub(super) fn is_caller_supplied<'a>(
    source_owned: &SourceOwnedFunctionFacts,
    graph: &SsaGraph,
    members: impl IntoIterator<Item = &'a ValueId>,
    sources: impl IntoIterator<Item = &'a BindingCertificateSource>,
) -> bool {
    members
        .into_iter()
        .any(|value| graph.caller_supplied(*value))
        || sources.into_iter().any(|source| match source {
            BindingCertificateSource::CertifiedEntity(SemanticId::StackSlot(object)) => {
                stack_object_is_caller_storage(source_owned, *object)
            }
            _ => false,
        })
}

pub(super) fn stack_object_is_caller_storage(
    source_owned: &SourceOwnedFunctionFacts,
    object: r2ssa::ObjectId,
) -> bool {
    matches!(
        source_owned.source().objects().object(object).map(|o| &o.kind),
        Some(r2ssa::ObjectKind::StackSlot {
            base: r2ssa::StackAddressBase::StackPointer,
            offset,
            ..
        }) if *offset >= 0
    )
}

/// Whether this object is the slot the caller pushed the return address into.
///
/// The machine states where that is: a convention whose call pushes the return
/// address says so as a return mechanism, and the slot it names is at the
/// pointer the function was entered with. It is caller storage like a stack
/// argument, but it is not an argument -- nothing in the program assigns it,
/// and a rendering that declares it as a local reads a name it never wrote.
pub(super) fn stack_object_is_return_address(
    source_owned: &SourceOwnedFunctionFacts,
    object: r2ssa::ObjectId,
) -> bool {
    let Some(mechanism) = source_owned
        .source()
        .machine_context()
        .function_interface()
        .and_then(r2ssa::SourceFunctionInterface::return_mechanism)
    else {
        return false;
    };
    matches!(
        source_owned.source().objects().object(object).map(|o| &o.kind),
        Some(r2ssa::ObjectKind::StackSlot {
            base: r2ssa::StackAddressBase::StackPointer,
            offset,
            ..
        }) if *offset == mechanism.stack_offset()
    )
}

pub(super) fn effective_stack_slot_role(
    source_owned: &SourceOwnedFunctionFacts,
    slot: &r2ssa::SourceStackSlotSpec,
    base: r2ssa::StackAddressBase,
    offset: i64,
) -> r2ssa::SourceStackSlotRole {
    let role = slot.role();
    let r2ssa::SourceStackSlotRole::Parameter { parameter_index } = role else {
        return role;
    };
    let declared = source_owned
        .source()
        .machine_context()
        .function_interface()
        .and_then(|interface| {
            interface
                .parameters()
                .iter()
                .find(|parameter| parameter.index() == parameter_index)
        })
        .and_then(|parameter| parameter.location().stack());
    match declared {
        Some((declared_offset, _))
            if base == r2ssa::StackAddressBase::StackPointer && declared_offset == offset =>
        {
            role
        }
        _ => r2ssa::SourceStackSlotRole::Local,
    }
}

/// Whether the function stores the parameter itself into the slot radare2 calls
/// its home. radare2 links a register argument to a slot by the register's
/// name, and a register a compiler reuses stores later values under that name
/// too; only a store of the parameter, at its width or narrowed to it, makes
/// the slot its home.
pub(super) fn parameter_home_is_written(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
    canonical: &r2rewrite::CanonicalRoots,
    dispositions: &[super::ValueDisposition],
    object: r2ssa::ObjectId,
    parameter: super::BindingId,
) -> bool {
    source_owned.report().render().is_some_and(|render| {
        render.memory_accesses().any(|fact| {
            fact.is_write
                && fact.object == object
                && fact.value.is_some_and(|value| {
                    value_is_parameter(projection, canonical, dispositions, value, parameter)
                })
        })
    })
}

fn value_is_parameter(
    projection: &r2ssa::MachineProjection,
    canonical: &r2rewrite::CanonicalRoots,
    dispositions: &[super::ValueDisposition],
    value: ValueId,
    parameter: super::BindingId,
) -> bool {
    match dispositions.get(value.0 as usize) {
        Some(super::ValueDisposition::Bound { binding }) => *binding == parameter,
        Some(super::ValueDisposition::Inline { term, .. }) => {
            term_is_parameter(projection, canonical, dispositions, *term, parameter)
        }
        _ => false,
    }
}

/// The term reads the parameter, possibly through a width change that keeps
/// its low bits: what a spill of a narrower-than-register parameter looks like.
fn term_is_parameter(
    projection: &r2ssa::MachineProjection,
    canonical: &r2rewrite::CanonicalRoots,
    dispositions: &[super::ValueDisposition],
    term: r2rewrite::TermId,
    parameter: super::BindingId,
) -> bool {
    use r2rewrite::TermKind;
    match canonical.arena().term(term).kind {
        TermKind::Leaf(read) => match projection.expr(read.expr).map(|expr| expr.kind()) {
            Some(r2ssa::MachineExprKind::Source { binding, .. }) => value_is_parameter(
                projection,
                canonical,
                dispositions,
                binding.value(),
                parameter,
            ),
            _ => false,
        },
        TermKind::Cast {
            kind:
                r2ssa::MachineCastKind::ZeroExtend
                | r2ssa::MachineCastKind::SignExtend
                | r2ssa::MachineCastKind::BitReinterpret,
            input,
        } => term_is_parameter(projection, canonical, dispositions, input, parameter),
        TermKind::Extract { input, lsb_bits: 0 } => {
            term_is_parameter(projection, canonical, dispositions, input, parameter)
        }
        _ => false,
    }
}

/// The role a slot takes once radare2's home claim is checked against the
/// stores: an unwritten home is a local of its own.
pub(super) fn verified_stack_slot_role(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
    canonical: &r2rewrite::CanonicalRoots,
    dispositions: &[super::ValueDisposition],
    parameter_binding: impl Fn(u32) -> Option<super::BindingId>,
    object: r2ssa::ObjectId,
    role: r2ssa::SourceStackSlotRole,
) -> r2ssa::SourceStackSlotRole {
    match role {
        r2ssa::SourceStackSlotRole::ParameterHome {
            parameter_index, ..
        } => {
            let binding = parameter_binding(parameter_index);
            let written = binding.is_some_and(|binding| {
                parameter_home_is_written(
                    source_owned,
                    projection,
                    canonical,
                    dispositions,
                    object,
                    binding,
                )
            });
            // A home nothing writes the parameter into is a local that
            // happens to sit where the convention would have put one. The
            // plan and the seal both ask this, and an answer that differs
            // between them is why an object's binding disagrees.
            r2il::refusal_evidence!(
                "stack-slot-role",
                "{object:?} home of parameter {parameter_index}: binding={binding:?} written={written}"
            );
            match written {
                true => role,
                false if binding.is_some() => r2ssa::SourceStackSlotRole::Local,
                false => role,
            }
        }
        _ => role,
    }
}

/// The width of the parameter's one home slot, where the frame gave it exactly
/// one. Two homes of different widths are two answers, and the rule below rests
/// on the frame stating a single number, so it declines rather than picking.
fn parameter_home_width_bytes(source_owned: &SourceOwnedFunctionFacts, slot: u32) -> Option<u32> {
    let mut homes = source_owned
        .report()
        .render()?
        .certified_entities
        .values()
        .filter_map(|entity| match entity {
            r2types::CertifiedEntity::StackSlot {
                size, source_slot, ..
            } => source_slot
                .filter(|source| {
                    matches!(
                        source.role(),
                        r2ssa::SourceStackSlotRole::ParameterHome { parameter_index, .. }
                            if parameter_index == slot
                    )
                })
                .and(*size),
            _ => None,
        });
    let first = homes.next()?;
    homes.all(|other| other == first).then_some(first)
}

/// What the parameter's declaration says it is, exact first.
fn declared_parameter_type(
    source_owned: &SourceOwnedFunctionFacts,
    slot: u32,
) -> Option<&r2types::CTypeLike> {
    let exact = source_owned
        .report()
        .render()
        .and_then(|render| render.certified_entities.get(&SemanticId::Parameter(slot)))
        .and_then(|entity| match entity {
            r2types::CertifiedEntity::Parameter { ty, .. } => ty.as_ref(),
            _ => None,
        });
    exact.or_else(|| {
        source_owned
            .report()
            .type_facts()
            .render_authorized_signature()?
            .params
            .get(usize::try_from(slot).ok()?)?
            .ty
            .as_ref()
    })
}

/// The parameter's width, where its declaration and its home agree on one.
///
/// A register carrier is eight bytes because registers are; `int flags` in
/// `esi` is four. Two independent statements settle it: the declared type's
/// width, and the width of the home the compiler gave the parameter in the
/// frame. Where they are the same number, that is the parameter, and its home
/// is the variable it names. Where they differ, or either is missing, the
/// carrier stands -- the same construction-and-seal twin the plan uses
/// elsewhere, rather than one source trusted alone.
fn declared_parameter_width_bytes(
    source_owned: &SourceOwnedFunctionFacts,
    slot: u32,
    carrier_bytes: u32,
    ptr_bits: u32,
) -> Option<u32> {
    let bits = declaration_type_width(declared_parameter_type(source_owned, slot)?, ptr_bits)?;
    let bytes = (bits % 8 == 0).then_some(bits / 8)?;
    if bytes == 0 || bytes >= carrier_bytes {
        return None;
    }
    (parameter_home_width_bytes(source_owned, slot) == Some(bytes)).then_some(bytes)
}

pub(super) fn parameter_candidates(
    source_owned: &SourceOwnedFunctionFacts,
) -> Vec<Option<ParameterCandidate>> {
    let ptr_bits = source_owned
        .source()
        .machine_context()
        .memory_model()
        .default_address_bits();
    let mut candidates = Vec::new();
    if let Some(interface) = source_owned.source().machine_context().function_interface() {
        for (position, parameter) in interface.parameters().iter().enumerate() {
            // A parameter declared narrower than its carrier is the low lane
            // of that carrier: `unsigned len` in rdx is four bytes wide, and
            // its four-byte home is its home. The carrier width is only the
            // answer where the interface states no narrower lane.
            let carrier_bytes = parameter.location().size_bytes();
            let width_bytes = interface
                .parameter_logical_value(position)
                .and_then(|logical| match logical.carrier().kind() {
                    r2ssa::SourceCarrierKind::LowBits => {
                        u32::try_from(logical.carrier().size_bits() / 8).ok()
                    }
                    r2ssa::SourceCarrierKind::Full => None,
                })
                .or_else(|| {
                    declared_parameter_width_bytes(
                        source_owned,
                        parameter.index(),
                        carrier_bytes,
                        ptr_bits,
                    )
                })
                .unwrap_or(carrier_bytes);
            insert_formal_parameter_candidate(&mut candidates, parameter.index(), width_bytes);
        }
    }
    let Some(render) = source_owned.report().render() else {
        return candidates;
    };
    for (key, certified) in &render.certified_entities {
        let r2types::CertifiedEntity::Parameter {
            id,
            slot,
            entry_values,
            carrier_width,
            ..
        } = certified
        else {
            continue;
        };
        let Ok(index) = usize::try_from(*slot) else {
            continue;
        };
        if index >= candidates.len() {
            candidates.resize_with(index.saturating_add(1), || None);
        }
        let canonical = SemanticId::Parameter(*slot);
        if *key != *id || *id != canonical {
            candidates[index] = Some(ParameterCandidate::Refused(
                ParameterRefusal::ConflictingEntityOwnership {
                    entity: *id,
                    expected_slot: *slot,
                    claimed_slot: match *id {
                        SemanticId::Parameter(claimed) => claimed,
                        _ => u32::MAX,
                    },
                },
            ));
            continue;
        }
        candidates[index] = Some(match &candidates[index] {
            Some(ParameterCandidate::Exact { entity, .. }) if *entity != *id => {
                ParameterCandidate::Refused(ParameterRefusal::ConflictingSlotOwnership {
                    slot: *slot,
                    first: *entity,
                    second: *id,
                })
            }
            Some(ParameterCandidate::Refused(reason)) => ParameterCandidate::Refused(*reason),
            Some(ParameterCandidate::Exact { .. }) | None => ParameterCandidate::Exact {
                entity: *id,
                width_bytes: declared_parameter_width_bytes(
                    source_owned,
                    *slot,
                    *carrier_width,
                    ptr_bits,
                )
                .unwrap_or(*carrier_width),
                entry_values: entry_values.clone(),
            },
        });
    }
    candidates
}

pub(super) fn insert_formal_parameter_candidate(
    candidates: &mut Vec<Option<ParameterCandidate>>,
    slot: u32,
    width_bytes: u32,
) {
    let index = slot as usize;
    if index >= candidates.len() {
        candidates.resize_with(index.saturating_add(1), || None);
    }
    let entity = SemanticId::Parameter(slot);
    candidates[index] = Some(match &candidates[index] {
        None => ParameterCandidate::Exact {
            entity,
            width_bytes,
            entry_values: BTreeSet::new(),
        },
        Some(ParameterCandidate::Exact { entity: first, .. }) => {
            ParameterCandidate::Refused(ParameterRefusal::ConflictingSlotOwnership {
                slot,
                first: *first,
                second: entity,
            })
        }
        Some(ParameterCandidate::Refused(reason)) => ParameterCandidate::Refused(*reason),
    });
}

/// The declaration width of one parameter slot, from its carrier width.
pub(super) fn parameter_width(
    entity: SemanticId,
    slot: u32,
    width_bytes: u32,
) -> Result<u32, ParameterRefusal> {
    if width_bytes == 0 {
        return Err(ParameterRefusal::MissingWidth { entity, slot });
    }
    let width_bits = width_bytes
        .checked_mul(8)
        .ok_or(ParameterRefusal::InvalidWidth {
            entity,
            slot,
            size_bytes: width_bytes,
        })?;
    declaration_width_is_supported(width_bits)
        .then_some(width_bits)
        .ok_or(ParameterRefusal::UnsupportedWidth {
            entity,
            slot,
            width_bits,
        })
}

/// Which values can be members of a binding at all.
///
/// A constant is an expression that initializes or updates an object, not an
/// object. The rest are values some other part of the model already answers
/// for -- an unobserved merge or value, a return-control or direct
/// control-flow target, the stack frame and its geometry, and values the
/// obligation ledger records as structurally unused, and the target of a direct
/// call, which the call expression spells as the callee's name. A binding for
/// one of those would be a second answer about the same value.
#[cfg(test)]
pub(super) fn component_eligible_values(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
) -> Result<Vec<bool>, BindingPlanBuildError> {
    Ok(rewrite_inlining_partition(source_owned, projection)?.component_eligible)
}

/// Which values can be an object at all.
///
/// This depends on nothing the plan decides afterwards: a value the inlining
/// pass folds into its reader is still a member of the object it would have
/// been, so the partition is computed once and no later answer refines it.
pub(super) fn component_eligible_with(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
) -> Result<Vec<bool>, BindingPlanBuildError> {
    let source = source_owned.source();
    let graph = source.graph();
    let unobserved_merges = source.unobserved_merges();
    let unobserved_values = source.unobserved_values();
    let return_controls = certified_return_control_values(source);
    let direct_control_targets = certified_direct_control_target_values(source);
    let direct_call_targets = certified_direct_call_target_values(source);
    let stack_frame_values = certified_stack_frame_values(source);
    let stack_geometry_values = certified_stack_geometry_values(source);
    let certified = super::readers::BoundaryReads::compute(source);
    let facts = PlanFacts {
        owned: source_owned,
        projection,
        boundary: &certified,
    };
    let unread = unread_defined_values(facts);
    let structural_unused = source
        .obligations()
        .structural_unused_values(graph, source.unobserved_merges().unobserved_uses())
        .ok_or(BindingPlanBuildError::Seal(
            BindingPlanSourceMismatch::Authority,
        ))?;
    Ok(graph
        .values
        .iter()
        .map(|value| {
            value.var.constant_bits().is_none()
                && !unobserved_merges.contains(value.id)
                && !unobserved_values.contains(&value.id)
                && !return_controls.contains(&value.id)
                && !direct_control_targets.contains(&value.id)
                && !direct_call_targets.contains(&value.id)
                && !stack_frame_values.contains(&value.id)
                && !stack_geometry_values.contains(&value.id)
                && !structural_unused.contains(&value.id)
                && !unread.contains(&value.id)
        })
        .collect())
}

/// Values whose every reader stopped reading them when the terms were
/// rewritten.
///
/// The graph's use table is the complete read domain, so this subtracts from it
/// rather than rebuilding it: a use survives unless the reader's own canonical
/// term provably no longer mentions the value. One value can be folded into
/// several readers at once -- the three condition codes of a subtraction
/// collapse into a single comparison -- and counting the graph's uses then
/// leaves it bound with nothing to render it, which the seal refuses.
///
/// Every uncertainty keeps the value. A reader with no canonical term of its
/// own says nothing, a certified boundary read still counts, and the definition
/// itself has to be removable, so an instruction with an effect is never called
/// dead because its result is.
pub(super) fn unrendered_defined_values(
    facts: PlanFacts<'_>,
    canonical: &r2rewrite::CanonicalRoots,
) -> BTreeSet<ValueId> {
    let (source, projection, certified) = (facts.source(), facts.projection, facts.boundary);
    let graph = source.graph();
    // A merge the structurer writes at a shared exit reads its target and its
    // sources, and it does so from the control shape rather than from any term,
    // so no canonical term can speak for those reads. A merge nothing observes
    // writes nothing and is not one of them.
    let unobserved_merges = source.unobserved_merges();
    let merged = graph
        .insts
        .iter()
        .filter(|inst| matches!(inst.payload, r2ssa::InstPayload::Phi { .. }))
        .filter(|inst| {
            !inst
                .output
                .is_some_and(|output| unobserved_merges.contains(output))
        })
        .flat_map(|inst| inst.output.iter().chain(inst.inputs.iter()).copied())
        .collect::<BTreeSet<_>>();
    graph
        .values
        .iter()
        .filter(|value| !merged.contains(&value.id))
        .filter(|value| removable_definition(source, projection, value.id))
        .filter(|value| canonical.value(value.id).is_some())
        .filter(|value| !certified.any(value.id))
        .filter(|value| !graph.caller_supplied(value.id))
        .filter(|value| !graph.use_sites(value.id).is_empty())
        // Only where the reader's own term is a faithful account of what it
        // reads: a producer the import embedded rather than named leaves no
        // leaf behind, and its reader's silence then proves nothing. A term
        // whose leaves do not cover every operand of its instruction is such a
        // term, and it keeps the value.
        .filter(|value| {
            graph.use_sites(value.id).iter().all(|site| {
                graph
                    .inst(site.inst)
                    .and_then(|inst| inst.output)
                    .and_then(|output| canonical.value(output))
                    .is_some_and(|reader| {
                        !reader.reads.contains(&value.id)
                            && graph.inst(site.inst).is_some_and(|inst| {
                                inst.inputs.iter().all(|input| {
                                    graph.value(*input).is_none_or(|operand| {
                                        operand.var.constant_bits().is_some()
                                            || reader.reads.contains(input)
                                    })
                                })
                            })
                    })
            })
        })
        .map(|value| value.id)
        .collect()
}

/// Whether removing this value removes its definition: the definition exists
/// and every cell it touches is an ordinary exact one, so nothing else happens
/// there that the rendering would lose.
fn removable_definition(
    source: &r2ssa::SsaArtifact,
    projection: &r2ssa::MachineProjection,
    value: ValueId,
) -> bool {
    let Some(definition) = source.graph().def_inst(value) else {
        return false;
    };
    matches!(
        projection.write_disposition(definition),
        Some(r2ssa::MachineWriteDisposition::Exact(_))
    ) && source.graph().inst(definition).is_some_and(|instruction| {
        (0..instruction.inputs.len()).all(|input_idx| {
            matches!(
                projection.use_disposition(r2ssa::UseSite {
                    inst: definition,
                    input_idx,
                }),
                Some(
                    r2ssa::MachineUseDisposition::Exact(_)
                        | r2ssa::MachineUseDisposition::MemoryAddress(_)
                )
            )
        })
    })
}

/// What every rule below reads about one function.
///
/// The three travel together through every rule -- the facts the plan is
/// derived from, the machine projection that says how each cell renders, and
/// the graphless reads the certificates state -- so they are one thing rather
/// than three parameters each rule repeats.
#[derive(Clone, Copy)]
pub(super) struct PlanFacts<'a> {
    pub(super) owned: &'a SourceOwnedFunctionFacts,
    pub(super) projection: &'a r2ssa::MachineProjection,
    pub(super) boundary: &'a super::readers::BoundaryReads,
}

impl<'a> PlanFacts<'a> {
    pub(super) fn source(self) -> &'a r2ssa::SsaArtifact {
        self.owned.source()
    }

    pub(super) fn graph(self) -> &'a r2ssa::SsaGraph {
        self.owned.source().graph()
    }
}

/// Values whose defining instruction performs a memory effect of its own.
///
/// A load's read of memory happens whether or not anything uses what it
/// produced, so such a value can be unread while its instruction still
/// renders. Every other dead-value reason means the instruction renders
/// nothing; this set is what separates the two, and the plan and its seal read
/// the same answer from here.
pub(super) fn effectful_definition_values(source: &r2ssa::SsaArtifact) -> BTreeSet<ValueId> {
    let graph = source.graph();
    source
        .obligations()
        .obligations()
        .values()
        .filter(|obligation| {
            matches!(
                obligation.id.kind,
                r2ssa::SemanticObligationKind::ObservableMemoryRead
                    | r2ssa::SemanticObligationKind::ObservableMemoryWrite
            )
        })
        .filter_map(|obligation| match obligation.id.instruction.site {
            r2ssa::CanonicalInstructionSite::Op(op_idx) => {
                graph.inst_id_for_op_site(obligation.id.instruction.block_addr, op_idx as usize)
            }
            _ => None,
        })
        .filter_map(|inst| graph.inst(inst).and_then(|inst| inst.output))
        .collect()
}

/// Values defined in this function that no graph or certified boundary reads.
///
/// Entry values are deliberately outside this set: an exact interface can own
/// an unused parameter declaration independently of a body read. Constants
/// likewise have no defining instruction to remove. For a defined value, the
/// graph use table plus the complete graphless boundary-reader inventory is the
/// closed read domain, so membership is a linear pass with `O(log n)` indexed
/// certificate lookups.
pub(super) fn unread_defined_values(facts: PlanFacts<'_>) -> BTreeSet<ValueId> {
    let (source, projection, certified) = (facts.source(), facts.projection, facts.boundary);
    // A use the certificates elide spells nothing, so a value only such uses
    // read is unread and owes no object. A call's `CallUse` of a register its
    // prototype does not name was the only reason counted, which left a call
    // result read by an unobserved merge looking read: `indirect_store`'s
    // result fed the next loop's dead phi and was bound to a variable nothing
    // assigns from or reads. A merge the certificates prove unobserved spells
    // nothing either, and counts the same way.
    let elided = certificate_elided_cells(source, projection)
        .map(|cells| cells.uses)
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, reason)| {
            matches!(
                reason,
                crate::ledger::ElisionReason::CallBoundaryCarrier
                    | crate::ledger::ElisionReason::UnobservedMerge
            )
        })
        .map(|(site, _)| site)
        .collect::<BTreeSet<_>>();
    if let Some(want) = crate::debug::traced_inline_name() {
        for value in &source.graph().values {
            if want != "all" && !value.var.display_name().eq_ignore_ascii_case(want) {
                continue;
            }
            let definition = source.graph().def_inst(value.id);
            eprintln!(
                "UNREAD {} {:?}: definition={:?} write={:?} uses={:?} certified={:?} caller_supplied={}",
                value.var.display_name(),
                value.id,
                definition,
                definition.and_then(|definition| projection.write_disposition(definition)),
                source
                    .graph()
                    .use_sites(value.id)
                    .iter()
                    .map(|site| (
                        site.inst,
                        source.graph().inst(site.inst).map(|inst| &inst.payload),
                        projection.use_disposition(*site)
                    ))
                    .collect::<Vec<_>>(),
                certified.of(value.id),
                source.graph().caller_supplied(value.id)
            );
        }
    }
    source
        .graph()
        .values
        .iter()
        .filter(|value| {
            let Some(definition) = source.graph().def_inst(value.id) else {
                return false;
            };
            matches!(
                projection.write_disposition(definition),
                Some(r2ssa::MachineWriteDisposition::Exact(_))
            ) && source.graph().inst(definition).is_some_and(|instruction| {
                (0..instruction.inputs.len()).all(|input_idx| {
                    matches!(
                        projection.use_disposition(r2ssa::UseSite {
                            inst: definition,
                            input_idx,
                        }),
                        Some(
                            r2ssa::MachineUseDisposition::Exact(_)
                                | r2ssa::MachineUseDisposition::MemoryAddress(_)
                        )
                    )
                })
            })
        })
        .filter(|value| {
            source
                .graph()
                .use_sites(value.id)
                .iter()
                .all(|site| elided.contains(site))
        })
        .filter(|value| !certified.any(value.id))
        // A formal the body never reads is still declared; it is not dead.
        .filter(|value| !source.graph().caller_supplied(value.id))
        .map(|value| value.id)
        .collect()
}

/// How many program readers a value has, counting each one once.
///
/// A graph use site and a certified boundary read can name the same
/// instruction, and that is one reader, not two. Two use sites on one
/// instruction remain two readers: `a + a` spells the value twice.
/// The frame objects whose address leaves this function as a value.
///
/// An out-parameter is the case: the callee writes through the pointer, so the
/// object is defined by a statement this function does not contain. Reading it
/// afterwards is ordinary C and needs no assignment here. A read that is the
/// address of a memory access, or the frame geometry itself, is not an escape.
/// Frame objects a callee may touch: those whose address leaves this body
/// (`escaped`), and among them those a call is proven to reach through an
/// argument, with everything the reach covers (`reached_by_callee`).
pub(super) struct EscapedFrameObjects {
    pub escaped: BTreeSet<r2ssa::ObjectId>,
    pub reached_by_callee: BTreeSet<r2ssa::ObjectId>,
}

pub(super) fn frame_objects_with_escaped_address(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
) -> EscapedFrameObjects {
    let source = source_owned.source();
    let graph = source.graph();
    let geometry = &source.certificates().stack_geometry.insts;
    let boundary_readers = super::readers::BoundaryReads::compute(source);
    let mut escaped = BTreeSet::new();
    let mut reached_by_callee = BTreeSet::new();
    for value in &graph.values {
        let Some(object) = r2rewrite::exact_stack_object_address(source, value.id) else {
            continue;
        };
        let escapes = boundary_readers.any(value.id)
            || graph.use_sites(value.id).iter().any(|site| {
                !geometry.contains(&site.inst)
                    && !matches!(
                        projection.use_disposition(*site),
                        Some(r2ssa::MachineUseDisposition::MemoryAddress(_))
                    )
            });
        if !escapes {
            continue;
        }
        escaped.insert(object);
        // A callee handed `&value` may reach every object from `value` to
        // the end of what it is proven to touch: the declared aggregate, the
        // bytes its body is proven to read or write, and, where it touches
        // memory the summary cannot bound, everything above the address in
        // this frame.
        let Some(reach) = escaped_pointee_reach(source_owned, value.id) else {
            continue;
        };
        reached_by_callee.insert(object);
        let objects = source.objects();
        let Some(root) = objects
            .stack_objects
            .iter()
            .find(|(_, other)| **other == object)
            .map(|(key, _)| key.root)
        else {
            continue;
        };
        let end = match reach {
            EscapeReach::Bytes(size) => {
                let Some(end) = i64::try_from(size)
                    .ok()
                    .and_then(|size| root.offset.checked_add(size))
                else {
                    continue;
                };
                Some(end)
            }
            EscapeReach::Frame => None,
        };
        // Upward through the frame in address order. An unbounded reach
        // stops at the first object that is not this function's own local:
        // a saved register the epilogue restores. The callee was handed a
        // local and what it may touch is the allocation, not the frame's
        // bookkeeping above it.
        let mut above = objects
            .stack_objects
            .iter()
            .filter(|(key, _)| key.root.base == root.base && key.root.offset > root.offset)
            .collect::<Vec<_>>();
        above.sort_by_key(|(key, _)| key.root.offset);
        let round_trips = &source.certificates().stack_frame_round_trips;
        for (key, other) in above {
            if let Some(end) = end
                && key.root.offset >= end
            {
                break;
            }
            if end.is_none() && round_trips.contains_key(other) {
                break;
            }
            r2il::refusal_evidence!(
                "escape-reaches",
                "{object:?} at {root:?} escapes {reach:?} and covers {other:?} at {:?}",
                key.root
            );
            escaped.insert(*other);
            reached_by_callee.insert(*other);
        }
    }
    EscapedFrameObjects {
        escaped,
        reached_by_callee,
    }
}

/// How far a callee may reach through a frame address it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeReach {
    /// This many bytes from the address.
    Bytes(u64),
    /// Anything above the address in this frame: the callee touches memory
    /// the summary cannot bound.
    Frame,
}

/// How far the callee an address is passed to may reach through it: the
/// size of the declared aggregate, else what its body is proven to touch.
fn escaped_pointee_reach(
    source_owned: &SourceOwnedFunctionFacts,
    value: ValueId,
) -> Option<EscapeReach> {
    let source = source_owned.source();
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    let type_graph = source
        .machine_context()
        .function_interface()
        .and_then(r2ssa::SourceFunctionInterface::type_graph);
    let callsites = source_owned.report().callsites()?;
    // The argument is the address or a register's copy of it.
    let graph = source.graph();
    let through_copies = |mut value: ValueId| {
        for _ in 0..8 {
            let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
                break;
            };
            let r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. }) = inst.payload else {
                break;
            };
            let Some(source) = inst.inputs.first() else {
                break;
            };
            value = *source;
        }
        value
    };
    callsites.by_callsite.values().find_map(|facts| {
        let argument = facts
            .argument_values
            .iter()
            .find(|argument| through_copies(argument.value) == value)?;
        r2il::refusal_evidence!(
            "escape-callee",
            "{value:?} is argument {} at {:?}: signature={:?}",
            argument.index,
            facts.callsite,
            facts
                .callee_signature
                .as_ref()
                .map(|signature| &signature.params)
        );
        // The declared pointee, where the signature is a source's. radare2's
        // inferred `uint64_t` is evidence and says nothing about a pointee.
        let declared = facts
            .callee_signature
            .as_ref()
            .filter(|_| facts.callee_signature_from_source_types)
            .and_then(|signature| match signature.params.get(argument.index)? {
                r2types::CTypeLike::Pointer(pointee) => Some(pointee.as_ref().clone()),
                _ => None,
            });
        // An aggregate pointee bounds the write: the callee stays inside the
        // object it was declared to take.
        if let Some(r2types::CTypeLike::Struct(name) | r2types::CTypeLike::Union(name)) = &declared
        {
            return type_graph?
                .aggregates()
                .iter()
                .find(|aggregate| aggregate.name() == name)
                .map(|aggregate| EscapeReach::Bytes(aggregate.size_bits().div_ceil(8)));
        }
        // A scalar pointee is an element, not an extent: `char *s` is as often
        // an array as one byte. It is the floor under what the callee's own
        // body proves it writes.
        let scalar_floor = declared
            .as_ref()
            .and_then(|scalar| {
                r2types::declaration_type_width_bits(scalar, ptr_bits)
                    .map(|bits| u64::from(bits).div_ceil(8))
            })
            .map(EscapeReach::Bytes);
        // The callee's own body: the bytes it is proven to write through this
        // argument, and nothing if it hands the pointer on to something the
        // summary does not see.
        let Some(summary) = source_owned
            .report()
            .interproc_summary_set()
            .and_then(|set| {
                set.summaries
                    .get(&r2ssa::InterprocFunctionId(facts.direct_target?))
            })
        else {
            r2il::refusal_evidence!(
                "escape-callee",
                "no summary for {:?} (set present: {})",
                facts.direct_target,
                source_owned.report().interproc_summary_set().is_some()
            );
            // A callee nothing describes may reach anything the address leads to.
            return Some(EscapeReach::Frame);
        };
        r2il::refusal_evidence!(
            "escape-callee",
            "summary for {:#x}: unknown_calls={} unknown_memory={} effects={:?}",
            facts.direct_target?,
            summary.has_unknown_calls,
            summary.touches_unknown_memory,
            summary.memory_effects
        );
        if summary.has_unknown_calls || summary.touches_unknown_memory {
            return Some(EscapeReach::Frame);
        }
        // A bounded transfer into the argument writes at most its length,
        // where the length is a constant at this call.
        let constant_argument = |index: usize| {
            let value = facts
                .argument_values
                .iter()
                .find(|argument| argument.index == index)?
                .value;
            let mut value = value;
            for _ in 0..8 {
                if let Some(bits) = graph.value(value)?.var.constant_bits() {
                    return Some(bits);
                }
                let inst = graph.def_inst(value).and_then(|inst| graph.inst(inst))?;
                let r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. }) = inst.payload else {
                    return None;
                };
                value = *inst.inputs.first()?;
            }
            None
        };
        let mut end = None::<i64>;
        for transfer in &summary.transfer_effects {
            let r2ssa::SummaryMemoryRegion::Arg { index } = transfer.dst.region else {
                continue;
            };
            if index != argument.index {
                continue;
            }
            let length = match transfer.len {
                r2ssa::SummaryTransferLength::Const(length) => Some(length),
                r2ssa::SummaryTransferLength::Arg(length) => constant_argument(length),
                r2ssa::SummaryTransferLength::Unknown => None,
            };
            let length = length.and_then(|length| i64::try_from(length).ok())?;
            end = Some(end.map_or(length - 1, |end| end.max(length - 1)));
        }
        let has_transfer = end.is_some();
        for effect in &summary.memory_effects {
            let r2ssa::SummaryMemoryRegion::Arg { index } = effect.location.region else {
                continue;
            };
            if index != argument.index {
                continue;
            }
            // A read is a reach as much as a write: the object it lands on
            // is observed, and a store into it is not dead. An address the
            // callee keeps or frees may be followed anywhere.
            match effect.kind {
                r2ssa::SummaryMemoryEffectKind::Write | r2ssa::SummaryMemoryEffectKind::Read => {}
                r2ssa::SummaryMemoryEffectKind::Escape | r2ssa::SummaryMemoryEffectKind::Free => {
                    return Some(EscapeReach::Frame);
                }
            }
            // An access the transfer already bounds carries no range of its own.
            let Some(range) = effect.location.range else {
                if has_transfer {
                    continue;
                }
                return Some(EscapeReach::Frame);
            };
            end = Some(end.map_or(range.offset_hi, |end| end.max(range.offset_hi)));
        }
        let proven = end
            .and_then(|end| u64::try_from(end.checked_add(1)?).ok())
            .map(EscapeReach::Bytes);
        match (proven, scalar_floor) {
            (Some(EscapeReach::Bytes(proven)), Some(EscapeReach::Bytes(floor))) => {
                Some(EscapeReach::Bytes(proven.max(floor)))
            }
            (proven, floor) => proven.or(floor),
        }
    })
}

/// The type one object is declared with.
///
/// Until now every binding was declared `CType::machine_bits(width)` -- the
/// unsigned integer of its storage's width -- and the recovered type was
/// reported by the typed-recovery score rather than asserted in the C. That
/// makes every parameter a `uint64_t`, so nothing the evidence solver proves
/// about a pointer or a narrower result reaches a reader or a recompile.
///
/// The evidence decides it now, and only where it agrees with itself and with
/// the storage. Every member of one binding is one object, so members that
/// carry different evidence types are a genuine conflict and the machine word
/// stands; a type whose width does not match the storage is not a description
/// of this object and is refused the same way. A pointer is the one type whose
/// width is the pointer width rather than the declared object's, and it is
/// admitted at exactly that width.
///
/// Casts follow the declaration -- the typed boundaries read a bound value
/// at its declared type -- so asserting here changes the operands too,
/// which is what keeps the emitted C compiling under `-Werror` rather than
/// converting an argument's signedness against its own declaration.
pub(super) fn declaration_type_for_binding(
    source_owned: &SourceOwnedFunctionFacts,
    members: impl IntoIterator<Item = ValueId>,
    width_bits: u32,
    ptr_bits: u32,
    floating_bits: Option<u32>,
) -> r2types::CTypeLike {
    let machine = r2types::CTypeLike::machine_bits(width_bits);
    let evidence = source_owned.evidence_types();
    let mut agreed: Option<r2types::CTypeLike> = None;
    for value in members {
        let Some(ty) = evidence.value_type(value) else {
            continue;
        };
        match &agreed {
            None => agreed = Some(ty.clone()),
            Some(existing) if existing == ty => {}
            Some(_) => return machine,
        }
    }
    // With nothing stated, an object the machine defines or only ever reads
    // as a floating value is one; its integer reads reinterpret.
    let Some(agreed) = agreed.or(floating_bits.map(r2types::CTypeLike::Float)) else {
        return machine;
    };
    admit_declaration(agreed, width_bits, ptr_bits)
}

/// How the machine projection views one value: the floating width its
/// definition produces, and the floating and other widths its reads take.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct FloatingView {
    pub(super) defined: Option<u32>,
    pub(super) float_read: Option<u32>,
    pub(super) other_reads: u32,
}

/// One pass over the projection: every value's floating view.
pub(super) fn floating_views(
    projection: &r2ssa::MachineProjection,
) -> std::collections::BTreeMap<ValueId, FloatingView> {
    let mut views: std::collections::BTreeMap<ValueId, FloatingView> = Default::default();
    // A copy or a merge reads whatever type its source has; such a read says
    // nothing about the source's class.
    let mut neutral = std::collections::BTreeSet::new();
    for entity in projection.entities() {
        let Some(root) = projection.expr(entity.root()) else {
            continue;
        };
        if let r2ssa::MachineType::Float { width_bits } = *root.ty() {
            views.entry(entity.output().value()).or_default().defined = Some(width_bits);
        }
        match root.kind() {
            r2ssa::MachineExprKind::Copy { input } => {
                neutral.insert(*input);
            }
            r2ssa::MachineExprKind::Phi { inputs } => neutral.extend(inputs.iter().copied()),
            _ => {}
        }
    }
    for (id, expr) in projection.arena().iter() {
        let r2ssa::MachineExprKind::Source { binding, .. } = expr.kind() else {
            continue;
        };
        if neutral.contains(&id) {
            continue;
        }
        let view = views.entry(binding.value()).or_default();
        match expr.ty() {
            r2ssa::MachineType::Float { width_bits } => view.float_read = Some(*width_bits),
            _ => view.other_reads += 1,
        }
    }
    views
}

/// The floating width a component is declared at, if any member is defined
/// floating or every read of every member is floating at one width.
pub(super) fn floating_width_of_component(
    views: &std::collections::BTreeMap<ValueId, FloatingView>,
    members: &std::collections::BTreeSet<ValueId>,
) -> Option<u32> {
    if let Some(width) = members
        .iter()
        .find_map(|value| views.get(value).and_then(|view| view.defined))
    {
        return Some(width);
    }
    let mut width = None;
    for value in members {
        let view = views.get(value).copied().unwrap_or_default();
        if view.other_reads > 0 {
            return None;
        }
        match (width, view.float_read) {
            (_, None) => {}
            (None, Some(read)) => width = Some(read),
            (Some(agreed), Some(read)) if agreed == read => {}
            _ => return None,
        }
    }
    width
}

/// The type a stack object is declared with.
///
/// A spilled pointer is a pointer. Declaring the slot the machine word while
/// the register it is spilled from is a pointer makes the reload
/// `p = slot;` -- an integer assigned to a pointer, which does not compile --
/// so the object and the values that flow through it have to be declared from
/// the same evidence.
pub(super) fn declaration_type_for_stack_object(
    source_owned: &SourceOwnedFunctionFacts,
    object: r2ssa::ObjectId,
    width_bits: u32,
    ptr_bits: u32,
) -> r2types::CTypeLike {
    let machine = r2types::CTypeLike::machine_bits(width_bits);
    let source = source_owned.source();
    // Storage read at more than one width is bytes, not a scalar: each access
    // spells itself through the slot's address at its own width.
    if source
        .certificates()
        .stack_slots
        .get(&object)
        .is_some_and(|certificate| certificate.byte_array)
    {
        return r2types::CTypeLike::Array(
            Box::new(r2types::CTypeLike::uint(8)),
            Some((width_bits / 8) as usize),
        );
    }
    // The slot's declared type, when the source interface carries it as a
    // node of its type graph, is exact and outranks every recovered hint: it
    // is what the program declared, at the width the storage has.
    if let Some(r2types::CertifiedEntity::StackSlot {
        ty: Some(ty), size, ..
    }) = source_owned.report().render().and_then(|render| {
        render
            .certified_entities
            .get(&r2ssa::SemanticId::stack_slot(object))
    }) {
        // An aggregate has no scalar width to check, so what vouches for it is
        // the slot's own extent: the declaration and the extent share a source.
        // Asked through the name, because a named type is still the type it
        // names: `bz_stream` reaching here as a name is the same aggregate.
        if ty.is_aggregate() && size.and_then(|bytes| bytes.checked_mul(8)) == Some(width_bits) {
            // Only if the rendering will be able to define the tag. Declaring
            // a value of one it cannot define does not compile, and a
            // rendering that does not compile scores nothing -- six of the
            // fifteen `bzip2` functions that fail to compile are exactly this,
            // `storage size of X isn't known`. The slot's bytes are the honest
            // fallback: same extent, always definable.
            let definable = ty.aggregate_tag().is_some_and(|tag| {
                source
                    .machine_context()
                    .function_interface()
                    .and_then(r2ssa::SourceFunctionInterface::type_graph)
                    .is_some_and(|graph| r2types::aggregate_is_definable(graph, tag))
            });
            if definable {
                return ty.clone();
            }
            return r2types::CTypeLike::Array(
                Box::new(r2types::CTypeLike::uint(8)),
                Some((width_bits / 8) as usize),
            );
        }
        return admit_declaration(ty.clone(), width_bits, ptr_bits);
    }
    let array_layout = source
        .certificates()
        .stack_slots
        .get(&object)
        .map(|certificate| &certificate.array_layout);
    match array_layout {
        Some(r2ssa::StackArrayLayoutDisposition::Proven(layout)) => {
            if layout.object == object
                && layout.element_width == layout.stride
                && layout.element_width > 0
                && layout
                    .extent
                    .is_multiple_of(u64::from(layout.element_width))
                && layout.extent.checked_mul(8) == Some(u64::from(width_bits))
                && let Ok(count) = usize::try_from(layout.extent / u64::from(layout.element_width))
                && let Some(element_bits) = layout.element_width.checked_mul(8)
            {
                return r2types::CTypeLike::Array(
                    Box::new(r2types::CTypeLike::machine_bits(element_bits)),
                    Some(count),
                );
            }
            // A malformed aggregate certificate cannot be retried from type
            // evidence: that would give the object a second geometry owner.
            return machine;
        }
        Some(r2ssa::StackArrayLayoutDisposition::Refused(_)) => {
            // Refusal is authoritative. In particular, conflicting access
            // widths and a missing constant bound must remain scalar even if
            // advisory type evidence happens to resemble an array.
            return machine;
        }
        Some(r2ssa::StackArrayLayoutDisposition::NotIndexed) | None => {}
    }
    let Some(fact) = source.objects().object(object) else {
        return machine;
    };
    let (base, offset) = match fact.kind {
        r2ssa::ObjectKind::StackSlot { base, offset, .. }
        | r2ssa::ObjectKind::FrameObject { base, offset, .. } => (base, offset),
        _ => return machine,
    };
    let key = r2types::StackSlotKey {
        base: match base {
            r2ssa::StackAddressBase::FramePointer => r2types::ExternalStackBase::FramePointer,
            r2ssa::StackAddressBase::StackPointer => r2types::ExternalStackBase::StackPointer,
            r2ssa::StackAddressBase::Realigned => r2types::ExternalStackBase::Realigned,
        },
        offset,
    };
    let Some((_, ty)) = source_owned
        .evidence_types()
        .stack_slot_types()
        .find(|(slot, _)| **slot == key)
    else {
        return machine;
    };
    admit_declaration(ty.clone(), width_bits, ptr_bits)
}

/// Admit a recovered type only where it describes an object of this storage.
///
/// A type whose width is not the storage's width is not a description of this
/// object, whatever else it may be true of, and the machine word stands. A
/// pointer is the one type whose width is the pointer width rather than the
/// declared object's, and it is admitted at exactly that width.
pub(crate) fn admit_declaration(
    ty: r2types::CTypeLike,
    width_bits: u32,
    ptr_bits: u32,
) -> r2types::CTypeLike {
    r2types::admit_declaration_type(ty, width_bits, ptr_bits)
}

/// The storage width a declared type describes.
///
/// This is what the seal checks a declaration against. It used to compare the
/// declaration to `CType::machine_bits(width)` outright, which is a check that
/// the declaration is the machine word rather than a check that it describes
/// the storage -- so it rejected every recovered type on sight. The width is
/// the part the seal can re-derive from the source; what the evidence proved
/// beyond it is not something a second derivation of the *plan* can confirm.
pub(super) fn declaration_type_width(ty: &r2types::CTypeLike, ptr_bits: u32) -> Option<u32> {
    r2types::declaration_type_width_bits(ty, ptr_bits)
}

/// Whether a declaration describes an object of exactly this storage width.
pub(super) fn declaration_type_describes_width(
    ty: &r2types::CTypeLike,
    width_bits: u32,
    ptr_bits: u32,
) -> bool {
    declaration_type_width(ty, ptr_bits) == Some(width_bits)
}

/// Whether this value is a literal the machine put somewhere: a copy of a
/// constant. Such a value decides no object of its own.
pub(super) fn literal_defined(graph: &SsaGraph, value: ValueId) -> bool {
    graph
        .def_inst(value)
        .and_then(|inst| graph.inst(inst))
        .is_some_and(|inst| {
            matches!(
                inst.payload,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. })
            ) && inst.inputs.iter().all(|input| {
                graph
                    .value(*input)
                    .is_some_and(|input| input.var.is_const())
            })
        })
}

/// Takes the projection rather than building one.
///
/// It used to build its own, and the seal asked it per value inside a loop, so
/// one render lowered the whole machine arena once for every inlined value.
/// That was seventy-two per cent of a render on `xxhash32`. The projection is
/// derived from the artifact and is the same object either way; deriving it
/// again is not a second opinion, only the same answer at a cost.
#[derive(Debug, Clone)]
pub(crate) struct RewriteInliningPartition {
    pub(super) canonical: r2rewrite::CanonicalRoots,
    pub(super) inlinable: BTreeSet<ValueId>,
    pub(super) component_eligible: Vec<bool>,
    /// The one partition: every value that can be an object, grouped once,
    /// before anything is inlined. A member later inlined stays a member
    /// whose definition prints nothing; a component none of whose members is
    /// bound gets no binding.
    pub(super) components: Vec<super::BindingComponent>,
    /// Liveness as the text has it: reads a folded definition made happen at
    /// its reader. The components were judged against this, and the seal
    /// judges them again against the same.
    pub(super) liveness: r2ssa::liveness::ValueLiveness,
}

/// The partition and the inlining, brought to agreement.
///
/// Objects decide which folds are safe, and folds decide which values occupy
/// an object and where their reads happen, so neither is first. The
/// resolution is a descending chain. The partition is built over every value
/// that can be an object and the folds are decided against it; then the
/// partition is rebuilt without the folded values, with the reads they made
/// relocated to their readers, and every fold is checked again against that
/// partition, keeping only those still safe. A fold never returns once
/// dropped, so the chain ends, and it ends with a partition judged exactly
/// against the values the text binds and a set of folds each safe against
/// that partition. Two rounds is the usual count.
pub(super) fn rewrite_inlining_partition(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &r2ssa::MachineProjection,
) -> Result<RewriteInliningPartition, BindingPlanBuildError> {
    let source = source_owned.source();
    let graph = source.graph();
    // The graphless reads the certificates state, built once for every rule
    // below that needs them.
    let boundary_reads = super::readers::BoundaryReads::compute(source);
    let facts = PlanFacts {
        owned: source_owned,
        projection,
        boundary: &boundary_reads,
    };
    let mut eligible = component_eligible_with(source_owned, projection)?;
    // A value every reader stopped reading when the terms were rewritten is
    // no object either. That needs the canonical terms, which do not depend
    // on the partition except for how a pointer is spelled, so one seed
    // canonicalisation without the pointer oracle decides it for every round.
    let unrendered = {
        let seed =
            r2rewrite::canonicalize_with(source, projection, &seed_absorbs_literal, &|_| None)
                .map_err(BindingPlanBuildError::Canonicalisation)?;
        unrendered_defined_values(facts, &seed)
    };
    for value in &unrendered {
        eligible[value.0 as usize] = false;
    }
    crate::stage_timing::mark("plan_component_eligible");
    let mut inlined = BTreeSet::<ValueId>::new();
    let mut readers = BTreeMap::<ValueId, r2ssa::InstId>::new();
    let mut round = 0_usize;
    loop {
        round += 1;
        let relocations = inlined
            .iter()
            .filter_map(|value| Some((graph.def_inst(*value)?, *readers.get(value)?)))
            .collect::<BTreeMap<_, _>>();
        let liveness = source.liveness().with_relocations(graph, &relocations);
        let round_eligible = eligible
            .iter()
            .enumerate()
            .map(|(index, eligible)| *eligible && !inlined.contains(&ValueId(index as u32)))
            .collect::<Vec<_>>();
        let components =
            super::construction::binding_components_with(source_owned, &round_eligible, &liveness)?;
        crate::stage_timing::mark("plan_components");
        // Which component each value belongs to; a value that is no object has none.
        let mut groups = vec![u32::MAX; graph.values.len()];
        let mut group_members = BTreeMap::<u32, Vec<ValueId>>::new();
        for (index, component) in components.iter().enumerate() {
            for member in &component.members {
                groups[member.0 as usize] = index as u32;
            }
            group_members.insert(index as u32, component.members.iter().copied().collect());
        }
        // The rewriter has no type system, so which operand of a sum is a
        // pointer is a question it cannot answer alone: `buf + len` came out
        // spelled `len[buf]` because address provenance proves only that
        // *some* parameter reaches memory through that address, and `len` was
        // the only parameter in it. The types answer here, asked of the object
        // rather than of the version -- at -O0 the value an address is built
        // from is a reload, and the solution typed whichever version it could
        // see.
        let declared_pointers = |value: ValueId| {
            declared_pointer_of_object(source_owned, &groups, &group_members, value)
        };
        // Absorbed exactly as the rendering absorbs, so a value is proven constant only through producers this round folds.
        let round_canonical = r2rewrite::canonicalize_with(
            source,
            projection,
            &|query: &r2rewrite::ExpansionQuery<'_>| term_absorbs_producer(&inlined, query),
            &declared_pointers,
        )
        .map_err(BindingPlanBuildError::Canonicalisation)?;
        crate::stage_timing::mark("plan_seed");
        // Alone in its object: a one-member component, or a value the
        // previous round folded and this round's partition therefore does
        // not hold at all -- it has no object to share.
        let mut alone = components
            .iter()
            .filter(|component| component.members.len() == 1)
            .filter_map(|component| component.members.first().copied())
            .collect::<BTreeSet<_>>();
        alone.extend(inlined.iter().copied());
        let admitted =
            duplicable_bound_constants(projection, source_owned, &round_canonical, &alone);
        if let Some(want) = crate::debug::traced_inline_name() {
            for value in &graph.values {
                if want != "all" && !value.var.display_name().eq_ignore_ascii_case(want) {
                    continue;
                }
                let members = group_members
                    .get(&groups[value.id.0 as usize])
                    .map(|members| {
                        members
                            .iter()
                            .filter_map(|member| graph.value(*member))
                            .map(|member| member.var.display_name())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                eprintln!(
                    "INLINE {} {:?} round {round}: component {members:?}; alone {}; admitted {}",
                    value.var.display_name(),
                    value.id,
                    alone.contains(&value.id),
                    admitted.contains(&value.id)
                );
            }
        }
        let folds = inlinable_core(
            facts,
            Round {
                canonical: &round_canonical,
                admitted: &admitted,
                unrendered: &unrendered,
                pre_partition: &groups,
            },
        );
        crate::stage_timing::mark("plan_inlinable");
        // Later rounds only shrink the fold set, except for a literal the
        // shrinking left alone in its object: spelling it at its readers
        // removes a write and no read, so it disturbs nothing decided before.
        let next: BTreeSet<ValueId> = if round == 1 {
            folds.values
        } else {
            folds
                .values
                .iter()
                .copied()
                .filter(|value| inlined.contains(value) || admitted.contains(value))
                .collect()
        };
        readers = folds
            .readers
            .into_iter()
            .filter(|(value, _)| next.contains(value))
            .collect();
        if round > 1 && next == inlined {
            r2il::refusal_evidence!(
                "plan-rounds",
                "{:#x}: partition and inlining agreed after {round} rounds",
                source.function().entry
            );
            // The round's own terms, which the settled fold set no longer changes.
            return Ok(RewriteInliningPartition {
                canonical: round_canonical,
                inlinable: inlined,
                component_eligible: round_eligible,
                components,
                liveness,
            });
        }
        inlined = next;
    }
}

/// The declared answer for the C object a value belongs to.
///
/// The type solution types versions, and an address at -O0 is built from a
/// reload the solution never saw. The object is what has a declared type, and
/// the pre-partition already says which values share one -- the same question
/// `declaration_type_for_binding` asks of the finished component, asked here of
/// the coarser partition that is available before the plan exists. A group
/// whose members disagree says nothing rather than guessing.
///
/// A declared prototype outranks the solution. `alloc_and_copy(char *src,
/// size_t len)` is the case the whole oracle exists for, and the solution types
/// `len` as `char *`: with nothing to contradict it, the address `buf + len`
/// had two pointer atoms, the parameter won, and the store rendered as
/// `len[buf]`. The signature is the one statement of what a formal is.
fn declared_pointer_of_object(
    source_owned: &SourceOwnedFunctionFacts,
    pre_partition: &[u32],
    group_members: &BTreeMap<u32, Vec<ValueId>>,
    value: ValueId,
) -> Option<bool> {
    let source = source_owned.source();
    let group = pre_partition.get(value.0 as usize).copied()?;
    let members = group_members.get(&group)?;
    let mut agreed: Option<bool> = None;
    let mut agree = |answer: bool| -> Option<bool> {
        match agreed {
            None => {
                agreed = Some(answer);
                Some(answer)
            }
            Some(existing) if existing == answer => Some(answer),
            Some(_) => None,
        }
    };
    let mut declared = false;
    for member in members {
        let Some(ty) = declared_formal_type(source_owned, *member) else {
            continue;
        };
        declared = true;
        let Some(answer) = declared_pointer_for_value(ty) else {
            continue;
        };
        agree(answer)?;
    }
    if declared {
        return agreed;
    }
    for member in members {
        let Some(answer) = source_owned
            .evidence_types()
            .value_type(*member)
            .and_then(declared_pointer_for_value)
        else {
            continue;
        };
        agree(answer)?;
    }
    let _ = source;
    agreed
}

/// The declared type of the formal this value is the entry read of.
///
/// Only from a signature the source's own type graph projected. Every function
/// has a signature -- a stripped one is recovered as machine words -- and
/// treating `uint64_t RDI_0` as a declaration that the parameter is not a
/// pointer would silence the provenance inference that is the only evidence
/// such a function has. That is not hypothetical: it took every byte-loop
/// subscript in the corpus away.
fn declared_formal_type(
    source_owned: &SourceOwnedFunctionFacts,
    value: ValueId,
) -> Option<&r2types::CTypeLike> {
    let facts = source_owned.report().type_facts();
    if !facts.signature_certificate.as_ref().is_some_and(|cert| {
        cert.sources
            .contains(&r2types::SignatureCertificateSource::SourceInterface)
    }) {
        return None;
    }
    let source = source_owned.source();
    let var = &source.graph().value(value)?.var;
    let index = source
        .function()
        .decompile_prep_facts()?
        .formal_parameter_of(var)?;
    let ty = facts
        .merged_signature
        .as_ref()?
        .params
        .get(index)?
        .ty
        .as_ref()?;
    // A bare integer is what a recovered signature says when it knows nothing:
    // every stripped function's parameters come back as machine words, and
    // reading that as "declared not a pointer" silences the provenance
    // inference such a function depends on. A name -- `size_t`, an enum, a
    // typedef -- is a statement someone made.
    if matches!(ty, r2types::CTypeLike::Int { .. }) {
        return None;
    }
    Some(ty)
}

/// Whether a declared type makes its value a pointer, where it decides at all.
///
/// A pointer or an array is one; an arithmetic type is not, and saying so is
/// the point -- an address base has to be chosen between the atoms of a sum,
/// and a declared size ruling itself out is what leaves the pointer alone in
/// that position. Everything else says nothing and leaves the rewriter's own
/// evidence in charge.
fn declared_pointer_for_value(ty: &r2types::CTypeLike) -> Option<bool> {
    match ty {
        r2types::CTypeLike::Pointer(_) | r2types::CTypeLike::Array(_, _) => Some(true),
        r2types::CTypeLike::Int { .. }
        | r2types::CTypeLike::Bool
        | r2types::CTypeLike::Float(_)
        | r2types::CTypeLike::BitVector(_)
        | r2types::CTypeLike::Enum(_) => Some(false),
        r2types::CTypeLike::Typedef { ty, .. } | r2types::CTypeLike::Const(ty) => {
            declared_pointer_for_value(ty)
        }
        r2types::CTypeLike::Void
        | r2types::CTypeLike::Struct(_)
        | r2types::CTypeLike::Union(_)
        | r2types::CTypeLike::Function { .. }
        | r2types::CTypeLike::Unknown => None,
    }
}

/// Whether a reader's term may absorb the producer of `value`.
///
/// One question with one answer: a term absorbs a producer exactly when the
/// plan renders that producer's value without a local. Both are
/// `inlinable_values`, so there is nothing here for the two to disagree
/// about, and the plan and the seal each derive the set from their own
/// projection and then call this.
///
/// # Why duplicability is not a second reason
///
/// The policy used to admit a producer whose term is duplicable -- literals
/// and entry values the function never writes -- on the ground that
/// duplicability is a property of the term rather than of the plan's
/// disposition. That is true of duplicability and beside the point of this
/// question. Absorbing a producer does not remove the producer's own
/// statement; only the plan's disposition does. A value the plan bound is
/// therefore rendered twice: once as `name = ...`, and again inside every
/// term that absorbed it. The rewriter then reports that producer as
/// discharged by each of those terms, because its value is no longer a leaf
/// of them, and the renderer marks the vanished instruction's write on the
/// expression standing in for it -- a second answerer for a write the
/// producer's own statement already renders.
///
/// That went unnoticed while nothing rendered from the canonical terms. The
/// subscript renderer does, and `elem_at`, `elem_before`, `bounded_fetch` and
/// `half_stride` at x86-64 -O1 and -O2 stopped rendering: their index is
/// `sext(esi)`, whose value the plan binds because a width change has no
/// inline form, and whose term is duplicable because `esi` is an entry value.
/// Placement found the absorbed write inside the right-hand side of an
/// assignment, where C states no order between it and the reads beside it,
/// and refused with `ambiguous_observation_execution_order`.
pub(super) fn term_absorbs_producer(
    inlinable: &BTreeSet<ValueId>,
    query: &r2rewrite::ExpansionQuery<'_>,
) -> bool {
    inlinable.contains(&query.value)
}

/// Frame constants held in a machine location that are alone in their object.
///
/// A literal in a lowering temporary is admitted by the gate in
/// `inlinable_core` without asking anything else, because the lifter's own
/// scratch is never coalesced. This is the rest: a literal the machine keeps
/// in a register or a memory cell, which may be an object's only write, and
/// is safe to spell at its readers exactly when nothing shares that object.
fn duplicable_bound_constants(
    projection: &r2ssa::MachineProjection,
    source_owned: &SourceOwnedFunctionFacts,
    canonical: &r2rewrite::CanonicalRoots,
    alone: &BTreeSet<ValueId>,
) -> BTreeSet<ValueId> {
    let graph = source_owned.source().graph();
    let mut expr_by_value = std::collections::BTreeMap::new();
    for entity in projection.entities() {
        expr_by_value.insert(entity.output().value(), entity.root());
    }
    graph
        .values
        .iter()
        .filter(|value| alone.contains(&value.id))
        .filter(|value| frame_constant(projection, canonical, &expr_by_value, value.id))
        .map(|value| value.id)
        .collect()
}

/// A value that is the same at every reader and costs nothing to spell there:
/// a literal, or the address of a frame object.
fn frame_constant(
    projection: &r2ssa::MachineProjection,
    canonical: &r2rewrite::CanonicalRoots,
    expr_by_value: &std::collections::BTreeMap<ValueId, r2ssa::MachineExprId>,
    value: ValueId,
) -> bool {
    // Asked of the canonical term, which is what the renderer spells and what
    // the effect ledger already scores as a repeated literal. Asking the
    // machine projection instead saw one instruction at a time, so an arm64
    // constant built by `movz` then `movk` read as an `or` of a value rather
    // than as the literal the rewriter had already folded it into, and every
    // such constant took a declaration of its own.
    // What the two answers were, so a constant that keeps a declaration of
    // its own names the term that failed to be one.
    if r2il::refusal_evidence::tracing() {
        r2il::refusal_evidence!(
            "frame-constant",
            "{value:?} machine={:?} canonical={:?}",
            expr_by_value
                .get(&value)
                .copied()
                .map(|root| r2rewrite::machine_expr_is_literal(projection, root)),
            canonical
                .value(value)
                .map(|canonical_value| canonical.arena().term(canonical_value.canonical).kind)
        );
    }
    expr_by_value
        .get(&value)
        .copied()
        .is_some_and(|root| r2rewrite::machine_expr_is_literal(projection, root))
        || canonical.value(value).is_some_and(|canonical_value| {
            matches!(
                canonical.arena().term(canonical_value.canonical).kind,
                r2rewrite::TermKind::ObjectAddress(_) | r2rewrite::TermKind::Literal(_)
            )
        })
}

/// Whether the seed may absorb this producer: only one that computes the same
/// value at every reader and observes nothing.
///
/// The seed exists to answer questions that must not depend on the partition,
/// and it was built substituting nothing at all. That made it unable to
/// answer the question asked of it most: a constant the machine assembles
/// across two instructions -- `movz` then `movk` on arm64 -- reads there as an
/// `or` of a value, while the arena the renderer uses substitutes and folds it
/// to the constant it is, so the plan called a constant something else and
/// gave it a declaration of its own.
///
/// The condition is the default policy's second arm, which reads only
/// literals and entry values nothing redefines. It cannot depend on the
/// partition, so the seed stays an answer every round can share.
fn seed_absorbs_literal(query: &r2rewrite::ExpansionQuery<'_>) -> bool {
    r2rewrite::term_is_duplicable(
        query.projection,
        query.arena,
        query.entry_never_redefined,
        query.producer_term,
    )
}

/// Which values fold into their one reader, and for each non-literal fold
/// which instruction that reader is: the read the fold moves happens there.
struct Folds {
    values: BTreeSet<ValueId>,
    readers: BTreeMap<ValueId, r2ssa::InstId>,
}

/// What one round of the fold decision proposes: the terms it canonicalised,
/// the literals it admitted, the values it found unrendered, and the partition
/// it computed those against.
#[derive(Clone, Copy)]
struct Round<'a> {
    canonical: &'a r2rewrite::CanonicalRoots,
    admitted: &'a BTreeSet<ValueId>,
    unrendered: &'a BTreeSet<ValueId>,
    pre_partition: &'a [u32],
}

fn inlinable_core(facts: PlanFacts<'_>, round: Round<'_>) -> Folds {
    let Round {
        canonical,
        admitted,
        unrendered,
        pre_partition,
    } = round;
    let (source_owned, projection) = (facts.owned, facts.projection);
    let source = facts.source();
    let graph = facts.graph();
    // A certificate that reads a value as a lane is answered from that value's
    // binding symbol, so it must keep one. An address read is not: a folded
    // address is spelled by its own expression.
    let certified_read_values = super::certified_lane_read_values(source);
    // A certificate on a value nothing reads states a read that renders nothing.
    let dead_readers = unread_defined_values(facts);
    let readers = super::readers::RenderedReaders::compute(facts, unrendered, &dead_readers);
    // A read is a read only if what it feeds reaches the page. At -O0 and again
    // under x86-64's flag lanes a value carries several graph readers and one
    // rendered one, and counting the graph's is what keeps it named.

    // The obligation inventory already answers this, transitively and once:
    // a value outside the observed closure whose definition it proved dead
    // reaches the page nowhere, and construction elides it as
    // `UnobservedValue`, so the journal, the effect ledger and placement all
    // agree about it already. Asking only the two narrower sets is what let a
    // flag temporary -- read by the copy into an architectural flag nothing
    // reads -- count as a rendered reader.
    let unobserved = source.unobserved_values();
    let renders_nothing = |inst: InstId| {
        graph
            .inst(inst)
            .and_then(|node| node.output)
            .is_some_and(|output| {
                dead_readers.contains(&output)
                    || unrendered.contains(&output)
                    || unobserved.contains(&output)
            })
    };
    // Of those graphless reads, call arguments are the one kind the renderer
    // can currently consume from an inline expression. Return, switch and
    // derived-result markers require a binding symbol, so they count as reads
    // for deadness but remain explicit inlining refusals below.
    let mut call_arg_readers = BTreeMap::<ValueId, BTreeSet<InstId>>::new();
    if let Some(callsites) = source_owned.report().callsites() {
        for (site, facts) in &callsites.by_callsite {
            let Some(inst) = graph.inst_id_for_op_site(site.block_addr, site.op_index) else {
                continue;
            };
            for argument in &facts.argument_values {
                call_arg_readers
                    .entry(argument.value)
                    .or_default()
                    .insert(inst);
            }
        }
    }
    let mut expr_by_value = std::collections::BTreeMap::new();
    for entity in projection.entities() {
        expr_by_value.insert(entity.output().value(), entity.root());
    }
    // One statement of which reads the certificates elide, shared with the
    // observation journal. A certificate the cells cannot be built from is a
    // function the journal will refuse, so there is nothing to fold for.
    let Ok(cells) = certificate_elided_cells(source, projection) else {
        return Folds {
            values: BTreeSet::new(),
            readers: BTreeMap::new(),
        };
    };
    let elided_reads = cells.read_elided_instructions;
    // A use the certificates elide is not a read the text performs, so there is
    // no occurrence for a folded expression to move into. The switch is the
    // case that matters: its computed target is expressed by the case topology,
    // so the `BranchInd` renders while the operand it dispatches through is
    // spelled nowhere, and folding the jump-table address into it left that
    // address's producer obligation owed by nobody.
    let elided_uses = cells.uses;
    // A return is the second kind the renderer consumes from an inline
    // expression: it spells the certified value and records a certified read
    // only when that value is bound. Requiring a binding here left a promoted
    // slot's last read as a temporary of its own -- `t = slot; return t;` --
    // where the object itself is what the return names.
    let mut return_readers = BTreeMap::<ValueId, BTreeSet<InstId>>::new();
    for (at, index) in &source.certificates().returns_by_inst {
        let Some(certificate) = source.certificates().returns.get(*index) else {
            continue;
        };
        if certificate.at != *at {
            continue;
        }
        return_readers
            .entry(certificate.value)
            .or_default()
            .insert(*at);
    }
    // Which gate turned a value away, by name. Reading this function said a
    // flag copy passes every test in it, and the corpus said it stays bound;
    // the two could only be reconciled by asking the function itself, one
    // value at a time. `R2SLEIGH_TRACE_INLINE=<display name>` or `=all`.
    let trace = crate::debug::traced_inline_name();
    let mut inlinable = BTreeSet::new();
    // The values each fold candidate's expression reads directly, and the
    // candidates whose hazard is still to be decided. The hazard cannot be
    // decided in this loop: a leaf that is itself folded contributes what *it*
    // reads, and the leaf may be a later value, so the answer is a closure over
    // the whole candidate set rather than something a single pass can carry.
    let mut direct_reads = BTreeMap::<ValueId, Vec<ValueId>>::new();
    let mut hazard_candidates = Vec::<(ValueId, r2ssa::InstId, r2ssa::InstId)>::new();
    let group_of = |value: ValueId| {
        pre_partition
            .get(value.0 as usize)
            .copied()
            .filter(|group| *group != u32::MAX)
    };
    for value in &graph.values {
        let traced = trace.is_some_and(|want| {
            want == "all" || value.var.display_name().eq_ignore_ascii_case(want)
        });
        let rejected = |gate: &str| {
            if traced {
                eprintln!(
                    "INLINE {} {:?} stays bound: {gate}",
                    value.var.display_name(),
                    value.id
                );
            }
        };
        // A lane of an entry register is the formal it was minted for: the
        // declaration is its only spelling, so it is never folded into a
        // reader (doc/adr-register-identity.md §8, 6).
        if graph.formal_projection_storage(value.id).is_some() {
            rejected("formal projection");
            continue;
        }
        if certified_read_values.contains(&value.id) {
            rejected("a certified lane read is answered from a binding");
            continue;
        }
        // Who reads this value in the rendered text, stated once in
        // `readers` rather than re-derived here.
        let readers_of = readers.get(value.id);
        if readers_of.all == 0 {
            rejected("no readers");
            continue;
        }
        let use_sites = readers_of.sites.as_slice();
        let boundary_readers = readers_of.boundary.as_slice();
        let reader_count = readers_of.rendered();
        // A value that reads nothing but literals is the same at every reader
        // and costs nothing to spell there, so the single-reader rule does not
        // apply to it. The broader question `r2rewrite` answers for expansion,
        // whether rendering twice observes anything twice, is satisfied by an
        // entry value the function never writes as well -- but copying an
        // expression over two parameters to three readers is three copies of a
        // real computation, not a local removed, so the plan asks the stricter
        // question.
        // ...and whose own storage is a lowering temporary. A register or a
        // memory cell holding a literal is a machine object other values are
        // coalesced with, and its write is frequently the only definition the
        // resulting C object has: `RAX_1 = 0xcbf29ce484222325` initialises
        // the accumulator that the loop then updates, and the two are one
        // binding. Spelling the constant at each reader deletes that
        // definition, and placement then finds the object read before it is
        // assigned -- ten of the fifty-four corpus cells, all on x86-64,
        // where the initialiser is a bare register literal.
        //
        // The honest test is not the storage class but whether the value is
        // coalesced with anything, and that cannot be asked here: the
        // partition is computed *from* this answer. A `Unique` slot is the
        // lifter's own scratch, which is the case this can decide without the
        // partition. Widening it needs the two-pass structure described in
        // the handoff, and is a design question rather than a bug.
        let literal_only = frame_constant(projection, canonical, &expr_by_value, value.id)
            && (value.canonical_storage.is_none_or(|storage| {
                matches!(storage.space, r2ssa::CanonicalStorageSpace::Unique)
            }) || admitted.contains(&value.id));
        let root_kind = expr_by_value
            .get(&value.id)
            .and_then(|root| projection.expr(*root))
            .map_or("<no entity>", |expr| machine_expr_kind_name(expr.kind()));
        // Every program reader, including certificate-owned boundary reads.
        // An arbitrary certificate-elided instruction still counts: dropping
        // those readers made values live across later object rewrites look
        // single-use and produced wrong hashes. Only source-certified dead-phi
        // edges on lowering temporaries are absent above.
        if !literal_only && reader_count != 1 {
            rejected(&readers_of.describe(graph, &elided_reads, root_kind));
            continue;
        }
        let renderable = expr_by_value
            .get(&value.id)
            .and_then(|root| projection.expr(*root))
            .is_some_and(|expr| expression_renders_inline(expr.kind()))
            && canonical.value(value.id).is_some_and(|value| {
                term_renders_inline_transitively(canonical.arena(), value.canonical)
            });
        if !renderable {
            let term = canonical
                .value(value.id)
                .map(|value| canonical.arena().term(value.canonical).kind);
            rejected(&format!(
                "expression kind does not render inline: {root_kind} term={term:?}"
            ));
            continue;
        }
        if boundary_readers.iter().any(|reader| {
            !call_arg_readers
                .get(&value.id)
                .is_some_and(|arguments| arguments.contains(reader))
                && !return_readers
                    .get(&value.id)
                    .is_some_and(|returns| returns.contains(reader))
        }) {
            rejected("a certified boundary reader requires a bound value");
            continue;
        }
        let Some(definition) = graph.def_inst(value.id) else {
            rejected("no defining instruction");
            continue;
        };
        // The renderer will ask the plan for a write observation on the
        // definition and a use observation on each of its operands, and either
        // can answer refused for something never meant to be rendered here.
        // Asking now is the difference between declining to fold and failing to
        // generate: plan and renderer agree before the tree exists.
        if !matches!(
            projection.write_disposition(definition),
            Some(r2ssa::MachineWriteDisposition::Exact(_))
        ) {
            rejected("definition has no exact write disposition");
            continue;
        }
        let Some(def_inst) = graph.inst(definition) else {
            rejected("defining instruction missing from the graph");
            continue;
        };
        if !(0..def_inst.inputs.len()).all(|input_idx| {
            matches!(
                projection.use_disposition(r2ssa::UseSite {
                    inst: definition,
                    input_idx,
                }),
                Some(
                    r2ssa::MachineUseDisposition::Exact(_)
                        | r2ssa::MachineUseDisposition::MemoryAddress(_)
                )
            )
        }) {
            rejected("an operand of the definition has no exact use disposition");
            continue;
        }
        // The read this expression would move into has to be a read that
        // actually appears. A value whose one use sits in an instruction a
        // certificate elides -- the prologue's `push rbp` is a certified frame
        // round trip -- disappears together with that instruction, and the
        // effect its definition answered for is then owed by nobody. The
        // ledger scores that as a refusal and the function falls back to no
        // decompilation at all, which is what `murmur3_32` and `xxhash32` did.
        if use_sites
            .iter()
            .any(|site| elided_reads.contains(&site.inst) || elided_uses.contains_key(site))
            || boundary_readers
                .iter()
                .any(|inst| elided_reads.contains(inst))
        {
            rejected("a reader sits in a certificate-elided instruction");
            continue;
        }
        if literal_only {
            // Nothing is being moved past anything. The tests below ask whether
            // a computation stays correct where it lands, and a literal is the
            // same in both places.
            direct_reads.insert(value.id, Vec::new());
            inlinable.insert(value.id);
            continue;
        }
        // The one reader, whether the graph recorded it or a boundary
        // certificate did. Only its position is wanted from here on: which
        // block it sits in, and what runs between the definition and it.
        let reader = readers_of
            .sole()
            .expect("a value that is not literal-only was required to have one reader");
        let Some(use_inst) = graph.inst(reader) else {
            rejected("reading instruction missing from the graph");
            continue;
        };
        // A merge reads its operands on edges, not at a position in a block, so
        // comparing ordinals against one says nothing and moving a computation
        // into a merge operand moves it across the edge that operand arrives
        // on. `crc32_bitwise` and `pearson` are the cases: their loop carriers
        // are merges, and folding into them computed the wrong answer while
        // every other check passed.
        if matches!(use_inst.payload, r2ssa::InstPayload::Phi { .. }) {
            rejected("the one reader is a merge");
            continue;
        }
        // A term that reads nothing computes the same value wherever it is
        // spelled, so where its reader sits says nothing about whether it may
        // be spelled there. A loop-invariant constant hoisted above the loop
        // that reads it was kept as a declaration for exactly this reason.
        let duplicable = canonical.value(value.id).is_some_and(|canonical_value| {
            canonical.import().is_duplicable(
                projection,
                canonical.arena(),
                canonical_value.canonical,
            )
        });
        if !duplicable && (def_inst.block != use_inst.block || def_inst.ordinal >= use_inst.ordinal)
        {
            rejected("the one reader is in another block or does not follow the definition");
            continue;
        }
        // Every object the *rendered* expression reads, not only the ones the
        // defining instruction lists. A machine expression is a tree over the
        // arena, so moving it moves every leaf in it, and a leaf can name a
        // read the instruction itself never mentions. Checking only the
        // instruction's inputs let three corpus cells compute the wrong answer.
        //
        // The object is the pre-partition's group, not the machine location.
        // The location is too coarse -- every version of a register shares one,
        // so a fresh reload refuses a fold that is stable -- and the storage
        // span alone is too fine, because the plan coalesces spans that a
        // certificate joins into one C object.
        let mut reads = BTreeSet::<ValueId>::new();
        let source_reads_machine_location = |source: ValueId| {
            let storage_is_lowering_temporary = graph.value(source).is_some_and(|value| {
                value
                    .canonical_storage
                    .is_some_and(|storage| storage.space == r2ssa::CanonicalStorageSpace::Unique)
            });
            if !storage_is_lowering_temporary {
                return true;
            }
            expr_by_value
                .get(&source)
                .and_then(|root| projection.expr(*root))
                .is_some_and(|source_expr| expression_renders_inline(source_expr.kind()))
                && canonical.value(source).is_some_and(|value| {
                    term_renders_inline(&canonical.arena().term(value.canonical).kind)
                })
        };
        let mut pending = vec![*expr_by_value.get(&value.id).expect("checked above")];
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if !seen.insert(node) {
                continue;
            }
            let Some(expr) = projection.expr(node) else {
                continue;
            };
            if let r2ssa::MachineExprKind::Source { binding, .. } = expr.kind() {
                // A source whose own producer has no inline C form is read
                // through its planned binding, not through the machine
                // location that once carried it.  A later reuse of a Sleigh
                // Unique slot therefore cannot change that C object.  This is
                // the reload/copy shape in x64 -O0 djb2: the load remains a
                // statement, while its register copy may move past reuse of
                // the load temporary.  Keep the hazard for sources that can
                // themselves expand, because their ultimate read may still
                // move with this expression.
                if source_reads_machine_location(binding.value()) {
                    reads.insert(binding.value());
                }
            }
            pending.extend(expr.kind().children());
        }
        reads.extend(
            def_inst
                .inputs
                .iter()
                .copied()
                .filter(|input| source_reads_machine_location(*input)),
        );
        direct_reads.insert(value.id, reads.into_iter().collect());
        hazard_candidates.push((value.id, definition, reader));
    }

    // The objects each candidate's *rendered* expression reads, closed over the
    // candidates it reads through. A leaf the plan binds is read as its own
    // object; a leaf the plan folds has no object, so reading it is reading
    // whatever that leaf's expression reads, however far down that goes.
    //
    // Closing over every candidate rather than over the values that survive
    // below is deliberate and is what makes this answerable at all. The set
    // only ever shrinks from here, and a smaller folded set means shorter
    // expansions and fewer reads, so a hazard computed from the candidates
    // covers the hazard of any subset. There is no fixpoint to iterate.
    let mut hazard = BTreeMap::<ValueId, BTreeSet<u32>>::new();
    // The same closure over the values themselves. A write that stores one of
    // them into an object the expression reads leaves the object holding what
    // the expression would have read anyway, so it is not a hazard.
    let mut hazard_values = BTreeMap::<ValueId, BTreeSet<ValueId>>::new();
    let mut visited = BTreeSet::<ValueId>::new();
    for root in direct_reads.keys().copied().collect::<Vec<_>>() {
        if hazard.contains_key(&root) {
            continue;
        }
        let mut stack = vec![(root, false)];
        while let Some((value, expanded)) = stack.pop() {
            if expanded {
                let mut groups = BTreeSet::new();
                let mut values = BTreeSet::new();
                for read in direct_reads.get(&value).into_iter().flatten() {
                    values.insert(*read);
                    if let Some(closed) = hazard_values.get(read) {
                        values.extend(closed.iter().copied());
                    }
                    // The leaf's own object, whether or not it folds: a leaf
                    // that is a candidate may still stay bound, and then a
                    // write to its object between here and the reader is the
                    // hazard. Its expansion is added beside that, for the case
                    // where it does fold. Both kept is the answer that covers
                    // either outcome; keeping only the expansion let
                    // `q = p + 1` move past a later write of `p`.
                    groups.extend(group_of(*read));
                    if let Some(closed) = hazard.get(read) {
                        groups.extend(closed.iter().copied());
                    }
                }
                hazard.insert(value, groups);
                hazard_values.insert(value, values);
                continue;
            }
            if hazard.contains_key(&value) || !visited.insert(value) {
                continue;
            }
            stack.push((value, true));
            for read in direct_reads.get(&value).into_iter().flatten() {
                if direct_reads.contains_key(read) && !hazard.contains_key(read) {
                    stack.push((*read, false));
                }
            }
        }
    }

    // Which objects a merge assigns at the end of each block. A merge's carrier
    // is written on the edge, so the write sits at the end of the predecessor
    // the edge leaves, whatever block defined the value it carries. An edge
    // whose value is already the merge's object writes nothing, and the
    // partition asked here is the one rendered, so that answer is exact.
    let mut edge_writes_by_block = vec![Vec::<u32>::new(); graph.blocks.len()];
    for inst in &graph.insts {
        let r2ssa::InstPayload::Phi { predecessors } = &inst.payload else {
            continue;
        };
        let Some(written) = inst.output.and_then(group_of) else {
            continue;
        };
        for (input, predecessor) in inst.inputs.iter().zip(predecessors) {
            if group_of(*input) == Some(written) {
                continue;
            }
            if let Some(writes) = edge_writes_by_block.get_mut(predecessor.0 as usize) {
                writes.push(written);
            }
        }
    }
    // Later definitions first. A write that could disturb a candidate's read
    // sits between its definition and its reader, so it is a later definition
    // in the same block, and if that definition is itself a candidate it has
    // already been decided by the time this one is asked. A write that folds
    // prints no statement and disturbs nothing; asking in this order makes
    // that exact rather than a guess.
    hazard_candidates.sort_by_key(|(_, definition, _)| {
        graph
            .inst(*definition)
            .map_or((0, 0), |inst| (inst.block.0, usize::MAX - inst.ordinal))
    });
    let mut folded = BTreeSet::<r2ssa::InstId>::new();
    let mut readers = BTreeMap::new();
    for (value, definition, reader) in hazard_candidates {
        let read_groups = hazard.get(&value).cloned().unwrap_or_default();
        let read_values = hazard_values.get(&value).cloned().unwrap_or_default();
        let (Some(def_inst), Some(use_inst)) = (graph.inst(definition), graph.inst(reader)) else {
            continue;
        };
        // Only this block's operations can sit between the definition and the
        // reader, so only this block's are read. Asking every operation in the
        // function was the same answer at the cost of the whole graph, once per
        // candidate value.
        let rewritten_by = graph
            .block(def_inst.block)
            .into_iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| graph.inst(*inst))
            .find(|inst| {
                inst.ordinal > def_inst.ordinal
                    && inst.ordinal < use_inst.ordinal
                    // A write nothing observes prints no statement, so it
                    // cannot disturb a read moved past it; nor does one
                    // already decided to fold into its own reader.
                    && !renders_nothing(inst.id)
                    && !folded.contains(&inst.id)
                    && inst
                        .output
                        .and_then(group_of)
                        .is_some_and(|group| read_groups.contains(&group))
                    // A copy of a value the expression reads stores what that
                    // expression would have read anyway, so reading the object
                    // after it is reading the same bits. `subs x1, x1, 1`
                    // writes the difference into the counter, and the flag
                    // tests that difference.
                    && !(matches!(inst.payload, r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. }))
                        && inst.inputs.iter().all(|input| read_values.contains(input)))
            });
        let rewritten = rewritten_by.is_some();
        // A merge this block feeds is copied to its carrier at the block's end,
        // so a read moved to the terminator reads the next iteration's value:
        // `ZF = R8 == 1` folded into the branch below `R8 = R8 - 1` ends the
        // loop one turn late.
        let carried = !rewritten
            && transfers_control(use_inst)
            && edge_writes_by_block
                .get(def_inst.block.0 as usize)
                .is_some_and(|writes| writes.iter().any(|group| read_groups.contains(group)));
        let traced = trace.is_some_and(|want| {
            want == "all"
                || graph
                    .value(value)
                    .is_some_and(|v| v.var.display_name().eq_ignore_ascii_case(want))
        });
        if traced {
            let name = graph
                .value(value)
                .map(|v| v.var.display_name())
                .unwrap_or_default();
            let verdict = if rewritten {
                "stays bound: an object the expression reads is written between definition and reader"
            } else if carried {
                "stays bound: a merge this block feeds carries an object the expression reads"
            } else {
                "folds"
            };
            eprintln!(
                "INLINE {name} {value:?} {verdict}; reads {read_groups:?} written_by {:?}",
                rewritten_by.map(|inst| (inst.id, inst.output))
            );
        }
        if !rewritten && !carried {
            inlinable.insert(value);
            folded.insert(definition);
            readers.insert(value, reader);
        }
    }

    Folds {
        values: inlinable,
        readers,
    }
}

/// Whether this instruction leaves its block, so a merge's carrier copy is
/// already written when it runs.
fn transfers_control(inst: &r2ssa::GraphInst) -> bool {
    matches!(
        inst.payload,
        r2ssa::InstPayload::Op(
            r2ssa::SSAOp::Branch { .. }
                | r2ssa::SSAOp::CBranch { .. }
                | r2ssa::SSAOp::BranchInd { .. }
                | r2ssa::SSAOp::Switch { .. }
                | r2ssa::SSAOp::Return { .. }
        )
    )
}

/// The name of a machine expression's kind, for the inlining probe.
fn machine_expr_kind_name(kind: &r2ssa::MachineExprKind) -> &'static str {
    use r2ssa::MachineExprKind as Kind;
    match kind {
        Kind::Source { .. } => "Source",
        Kind::Constant { .. } => "Constant",
        Kind::MemoryRead { .. } => "MemoryRead",
        Kind::Arithmetic { .. } => "Arithmetic",
        Kind::Bitwise { .. } => "Bitwise",
        Kind::BitwiseNot { .. } => "BitwiseNot",
        Kind::Boolean { .. } => "Boolean",
        Kind::BooleanNot { .. } => "BooleanNot",
        Kind::Compare { .. } => "Compare",
        Kind::Copy { .. } => "Copy",
        Kind::Negate { .. } => "Negate",
        Kind::Select { .. } => "Select",
        Kind::Shift { .. } => "Shift",
        Kind::Cast { .. } => "Cast",
        _ => "other",
    }
}

/// Whether the renderer has a form for this expression at a reader.
///
/// The list is exactly what `materialize_machine_expr` can build, and it is
/// asked of every folding candidate: a plan that promises an inline the
/// renderer cannot produce refuses the function rather than declining to
/// fold.
///
/// `Constant` belongs here and was missing, which is why a literal-only value
/// was admitted by the duplicable rule above and then turned away by this
/// one. That is the whole of the literal-only declaration column: the plan
/// agreed the value was cheap to spell at each reader and then asked whether
/// a constant renders inline, and this said no. It is the first arm of the
/// materialiser.
///
/// A computation *over* constants is not a constant. `machine_expr_is_literal`
/// is true of `popcount(0xf0f0)`, because it asks only whether every leaf is
/// a constant; the materialiser has no form for a population count, so the
/// shape is still asked here and that expression still keeps its statement.
fn expression_renders_inline(kind: &r2ssa::MachineExprKind) -> bool {
    use r2ssa::MachineExprKind as Kind;
    // Exhaustive on purpose. This list is a hand-written mirror of what
    // `materialize_machine_expr` can build, and it has drifted before:
    // `Constant` was missing, so the plan agreed a literal-only value was
    // cheap to spell at each reader and then this said the renderer had no
    // form for it, which is the whole of the literal-only declaration column.
    // A `matches!` lets a new kind arrive as a silent `false` -- a value that
    // gets a name instead of being inlined, which is the direction that costs
    // `byte_match`. A `match` makes the compiler ask.
    match kind {
        Kind::Constant { .. }
        | Kind::Arithmetic { .. }
        | Kind::Bitwise { .. }
        | Kind::BitwiseNot { .. }
        | Kind::Boolean { .. }
        | Kind::BooleanNot { .. }
        | Kind::Compare { .. }
        | Kind::Copy { .. }
        | Kind::Negate { .. }
        | Kind::Select { .. }
        | Kind::Shift { .. }
        | Kind::Cast { .. }
        | Kind::Extract { .. }
        | Kind::Concat { .. }
        | Kind::ArithmeticFlag { .. }
        | Kind::FloatArithmetic { .. }
        | Kind::FloatUnary { .. }
        | Kind::FloatCompare { .. } => true,
        // A read is a memory effect, a merge is not an expression, and a
        // conditional store's outcome belongs to the statement that performs
        // the store; the rest have no form in the materialiser.
        Kind::Source { .. }
        | Kind::MemoryRead { .. }
        | Kind::Phi { .. }
        | Kind::InsertLane { .. }
        | Kind::PopulationCount { .. }
        | Kind::Divide { .. }
        | Kind::Remainder { .. }
        | Kind::ExclusiveStoreSucceeded { .. }
        | Kind::GuardedRead { .. } => false,
    }
}

/// The canonical forms admitted by `expression_renders_inline`.
///
/// Keep this list identical to `materialize_term`. A machine `Copy` imports as
/// its child and the three unary machine kinds import as the corresponding
/// unary term kinds, so the two enums do not have identical spellings.
/// Whether the whole term renders inline, not just its root.
///
/// `materialize_term` descends into every child, so a root of an admitted kind
/// over an `Opaque` child is a term the plan admits and the renderer refuses --
/// `InvalidPlannedInline`. Nothing had noticed while the reader count kept such
/// values bound anyway.
fn term_renders_inline_transitively(arena: &r2rewrite::TermArena, root: r2rewrite::TermId) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let kind = arena.term(id).kind;
        if !term_renders_inline(&kind) {
            return false;
        }
        stack.extend(kind.children());
    }
    true
}

fn term_renders_inline(kind: &r2rewrite::TermKind) -> bool {
    use r2rewrite::TermKind as Kind;
    matches!(
        kind,
        Kind::Leaf(_)
            | Kind::Literal(_)
            | Kind::Arithmetic { .. }
            | Kind::Negate(_)
            | Kind::Bitwise { .. }
            | Kind::BitwiseNot(_)
            | Kind::Boolean { .. }
            | Kind::BooleanNot(_)
            | Kind::Compare { .. }
            | Kind::Cast { .. }
            | Kind::Extract { .. }
            | Kind::Concat { .. }
            | Kind::Select { .. }
            | Kind::Shift { .. }
            | Kind::Flag { .. }
            | Kind::ObjectAddress(_)
    )
}

/// The use and write cells the upstream certificates answer for before any
/// statement is rendered.
///
/// This is one statement of the rule, read by every consumer that has to agree
/// with it: the observation journal seeds its cells from `uses` and `writes`
/// and refuses a rendered marker that contradicts them; the binding plan
/// refuses to fold a value into a read listed in `read_elided_instructions`,
/// because a value folded into a read that never appears loses its rendered
/// occurrence; and a rewrite must leave an instruction alone when a
/// certificate has already said what it renders. Two independently written
/// statements of which cells a certificate elides were two answerers that could
/// drift, and when they drift the seal rejects a plan that is correct.
///
/// The two views are deliberately not one set. The journal needs the reason
/// per use, and is exact per operand: a machine return control certificate
/// elides only the operand sites it names, and a stack-geometry operand that is
/// also a memory address keeps its rendered occurrence. The binding plan needs
/// only to know that an instruction's reads are not rendered, and it is asked
/// per instruction, including instructions -- a dead frame-slot store -- whose
/// cells the effect ledger answers for rather than these maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CertificateElidedCells {
    pub(crate) uses: BTreeMap<UseSite, ElisionReason>,
    pub(crate) writes: BTreeMap<InstId, ElisionReason>,
    pub(crate) read_elided_instructions: BTreeSet<InstId>,
}

/// Why the certificates could not be turned into cells.
///
/// Each variant names the same condition the observation journal reports for
/// it; the journal maps these onto its own error type without reinterpreting
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateElidedCellsError {
    InvalidWrite(InstId),
    InvalidValue(ValueId),
    ConflictingUse(UseSite),
    ConflictingWrite(InstId),
}

fn insert_elided_use(
    uses: &mut BTreeMap<UseSite, ElisionReason>,
    site: UseSite,
    reason: ElisionReason,
) -> Result<(), CertificateElidedCellsError> {
    match uses.insert(site, reason) {
        Some(existing) if existing != reason => {
            if r2il::refusal_evidence::tracing() {
                eprintln!(
                    "conflicting use {site:?}: certificate reason {existing:?}, new reason {reason:?}"
                );
            }
            Err(CertificateElidedCellsError::ConflictingUse(site))
        }
        _ => Ok(()),
    }
}

fn insert_elided_write(
    writes: &mut BTreeMap<InstId, ElisionReason>,
    inst: InstId,
    reason: ElisionReason,
) -> Result<(), CertificateElidedCellsError> {
    match writes.insert(inst, reason) {
        Some(existing) if existing != reason => {
            Err(CertificateElidedCellsError::ConflictingWrite(inst))
        }
        _ => Ok(()),
    }
}

/// The cells the certificates of `source` elide, in the order the certificates
/// are consulted.
///
/// Order matters where domains overlap: an earlier machine or frame
/// certificate wins deterministically, and the unobserved-value domain only
/// fills cells nothing earlier has claimed. The `projection` is the machine
/// projection the plan was built from; it decides which stack-geometry
/// operands are memory addresses that keep their own rendered occurrence.
pub(crate) fn certificate_elided_cells(
    source: &r2ssa::SsaArtifact,
    projection: &r2ssa::MachineProjection,
) -> Result<CertificateElidedCells, CertificateElidedCellsError> {
    let graph = source.graph();
    let certificates = source.certificates();
    let mut uses = BTreeMap::new();
    let mut writes = BTreeMap::new();
    for certificate in certificates.stack_frame_round_trips.values() {
        for inst in &certificate.insts {
            let definition = graph
                .inst(*inst)
                .ok_or(CertificateElidedCellsError::InvalidWrite(*inst))?;
            for input_idx in 0..definition.inputs.len() {
                let site = UseSite {
                    inst: *inst,
                    input_idx,
                };
                insert_elided_use(&mut uses, site, ElisionReason::StackFrame)?;
            }
            if definition.output.is_some() {
                insert_elided_write(&mut writes, *inst, ElisionReason::StackFrame)?;
            }
        }
    }
    for certificate in certificates.machine_return_controls.values() {
        for site in &certificate.uses {
            insert_elided_use(&mut uses, *site, ElisionReason::ReturnControl)?;
        }
        for inst in &certificate.insts {
            let definition = graph
                .inst(*inst)
                .ok_or(CertificateElidedCellsError::InvalidWrite(*inst))?;
            if definition.output.is_some() {
                insert_elided_write(&mut writes, *inst, ElisionReason::ReturnControl)?;
            }
        }
    }
    for certificate in source.structured().member_run_stores.values() {
        insert_elided_use(
            &mut uses,
            certificate.value_use,
            ElisionReason::DecomposedWideStore,
        )?;
    }
    // Which way a block operation walks. The rendering writes one walk, so the
    // operand that selected it has no C expression to sit on.
    for inst in &graph.insts {
        let r2ssa::InstPayload::Op(r2ssa::SSAOp::BlockTransfer(transfer)) = &inst.payload else {
            continue;
        };
        let Some(direction) = graph.value_id_for_var(&transfer.direction) else {
            continue;
        };
        for (input_idx, input) in inst.inputs.iter().enumerate() {
            if *input == direction {
                insert_elided_use(
                    &mut uses,
                    r2ssa::UseSite {
                        inst: inst.id,
                        input_idx,
                    },
                    ElisionReason::BlockTransferDirection,
                )?;
            }
        }
    }
    // The reads a call boundary makes. `SSAOp::CallUse` says what the call
    // consumes so liveness can keep the producers; it renders nothing itself,
    // because an argument the call passes is spelled inside the call
    // expression and a carrier the callee does not take is spelled nowhere.
    for inst in &graph.insts {
        if !matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallUse { .. })
        ) {
            continue;
        }
        for input_idx in 0..inst.inputs.len() {
            insert_elided_use(
                &mut uses,
                UseSite {
                    inst: inst.id,
                    input_idx,
                },
                ElisionReason::CallBoundaryCarrier,
            )?;
        }
    }
    // A register a call clobbered and no result certificate claims is declared
    // and not assigned: the object holds whatever the callee left, and there is
    // nothing in this function to assign it from. The `CallDefine` that mints
    // it therefore has no statement, exactly as a caller-supplied entry value
    // has none, and its write cell is answered here rather than left
    // unaccounted at the seal -- which planned a gap over six operations and
    // took with it the definition of the value the return certificate names.
    for inst in &graph.insts {
        if !matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallDefine { .. })
        ) {
            continue;
        }
        let Some(output) = inst.output else {
            continue;
        };
        if certificates.call_results.contains_key(&output) {
            continue;
        }
        insert_elided_write(
            &mut writes,
            inst.id,
            ElisionReason::CallClobberedDeclaration,
        )?;
    }
    // A lane of an entry register is defined by the formal's declaration: the
    // `Subpiece` minting it from the root's entry value has no statement, and
    // its read of the root is not an occurrence (doc/adr-register-identity.md).
    for (value, _) in graph.formal_projections() {
        let Some(inst) = graph.def_inst(*value) else {
            continue;
        };
        let definition = graph
            .inst(inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(inst))?;
        insert_elided_write(&mut writes, inst, ElisionReason::CallerSuppliedEntryValue)?;
        for input_idx in 0..definition.inputs.len() {
            insert_elided_use(
                &mut uses,
                UseSite { inst, input_idx },
                ElisionReason::CallerSuppliedEntryValue,
            )?;
        }
    }
    for site in &certificates.stack_geometry.uses {
        // A stack-root value has no standalone C occurrence, but an exact
        // stack-object address operand still has its own contextual per-use
        // projection. The value and use ledgers are independent: seed only
        // geometry uses that disappear with their defining operation, and let
        // the rendered memory-address marker account for the surviving
        // operand.
        if matches!(
            projection.use_disposition(*site),
            Some(r2ssa::MachineUseDisposition::MemoryAddress(_))
        ) {
            continue;
        }
        insert_elided_use(&mut uses, *site, ElisionReason::DeadStackBase)?;
    }
    for inst in &certificates.stack_geometry.insts {
        let definition = graph
            .inst(*inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(*inst))?;
        if definition.output.is_some() {
            insert_elided_write(&mut writes, *inst, ElisionReason::DeadStackBase)?;
        }
    }
    // The SSA liveness owner publishes the complete pure domain outside the
    // transitive observation slice. Seed non-phi operations here; dead merges
    // keep their more specific reason below. Earlier machine/frame
    // certificates win deterministically when domains overlap.
    let unobserved = source.unobserved_merges();
    for site in unobserved.unobserved_uses() {
        if graph
            .inst(site.inst)
            .is_some_and(|inst| matches!(inst.payload, r2ssa::InstPayload::Phi { .. }))
        {
            continue;
        }
        uses.entry(*site).or_insert(ElisionReason::UnobservedValue);
    }
    for inst in unobserved.unobserved_insts() {
        let definition = graph
            .inst(*inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(*inst))?;
        if matches!(definition.payload, r2ssa::InstPayload::Phi { .. }) {
            continue;
        }
        if definition.output.is_some() {
            writes
                .entry(*inst)
                .or_insert(ElisionReason::UnobservedValue);
        }
    }
    for value in unobserved.iter() {
        let inst = graph
            .def_inst(value)
            .ok_or(CertificateElidedCellsError::InvalidValue(value))?;
        let definition = graph
            .inst(inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(inst))?;
        if !matches!(definition.payload, r2ssa::InstPayload::Phi { .. })
            || definition.output != Some(value)
        {
            return Err(CertificateElidedCellsError::InvalidWrite(inst));
        }
        writes.insert(inst, ElisionReason::UnobservedMerge);
        for input_idx in 0..definition.inputs.len() {
            uses.insert(UseSite { inst, input_idx }, ElisionReason::UnobservedMerge);
        }
    }
    for site in super::certified_return_control_sites(source) {
        // A merge the analysis already answered for keeps its answer. The link
        // register reaches a return through phis that merge it with itself,
        // and once the certificate covers the register those phi operands are
        // named twice -- as an unobserved merge and as return control. Both
        // say the same thing, and calling that a conflict refused every
        // function whose return address survives a branch.
        // Likewise a read by a definition nothing observes: the copy that once
        // carried the link register to its save is forwarded and dead, and the
        // dead-value account of its operand says the same thing this would.
        if matches!(
            uses.get(&site),
            Some(ElisionReason::UnobservedMerge | ElisionReason::UnobservedValue)
        ) {
            continue;
        }
        insert_elided_use(&mut uses, site, ElisionReason::ReturnControl)?;
    }
    // Instructions the certificate took over from the prologue are shared with
    // whatever else describes them: one `stp x29, x30` is the frame's setup and
    // the return address's save at once, and one save serves every return.
    // Where such an instruction is already accounted for, that account stands;
    // both say it renders nothing, and treating the second one as a
    // contradiction refused the whole function.
    let shared = super::certified_return_control_absorbed_insts(source);
    for inst in super::certified_return_control_insts(source) {
        let definition = graph
            .inst(inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(inst))?;
        if shared.contains(&inst) {
            if definition.output.is_some() {
                writes.entry(inst).or_insert(ElisionReason::ReturnControl);
            }
            for input_idx in 0..definition.inputs.len() {
                uses.entry(UseSite { inst, input_idx })
                    .or_insert(ElisionReason::ReturnControl);
            }
            continue;
        }
        if definition.output.is_some() {
            insert_elided_write(&mut writes, inst, ElisionReason::ReturnControl)?;
        }
        // The instruction renders nothing, so it reads nothing. Its write was
        // already accounted on that ground and its operands stand on the same
        // one: an occurrence inside a statement no structured form emits is
        // not a read. On AArch64 the return address arrives through a copy of
        // the link register and the copy's operand is control-only in its own
        // right, so this was never needed; on amd64 `ret` lifts to a load of
        // the return address through the stack pointer, and the stack pointer
        // is read elsewhere for ordinary reasons, so nothing else could ever
        // close that cell.
        for input_idx in 0..definition.inputs.len() {
            insert_elided_use(
                &mut uses,
                UseSite { inst, input_idx },
                ElisionReason::ReturnControl,
            )?;
        }
    }
    for site in super::certified_direct_control_target_sites(source) {
        insert_elided_use(&mut uses, site, ElisionReason::DirectControlTarget)?;
    }
    // A direct call names its callee. The name comes from the symbol table,
    // not from any object the function holds, so the operand's occurrence is
    // not a read and the value it names is elided beside it.
    for site in super::certified_direct_call_target_sites(source) {
        insert_elided_use(&mut uses, site, ElisionReason::DirectCallTarget)?;
    }
    for inst in super::certified_call_return_address_insts(source) {
        let definition = graph
            .inst(inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(inst))?;
        if definition.output.is_some() {
            insert_elided_write(&mut writes, inst, ElisionReason::CallReturnAddress)?;
        }
        for input_idx in 0..definition.inputs.len() {
            insert_elided_use(
                &mut uses,
                UseSite { inst, input_idx },
                ElisionReason::CallReturnAddress,
            )?;
        }
    }
    for inst in super::certified_direct_call_target_insts(source) {
        let definition = graph
            .inst(inst)
            .ok_or(CertificateElidedCellsError::InvalidWrite(inst))?;
        if definition.output.is_some() {
            insert_elided_write(&mut writes, inst, ElisionReason::DirectCallTarget)?;
        }
        for input_idx in 0..definition.inputs.len() {
            insert_elided_use(
                &mut uses,
                UseSite { inst, input_idx },
                ElisionReason::DirectCallTarget,
            )?;
        }
    }
    Ok(CertificateElidedCells {
        uses,
        writes,
        read_elided_instructions: certified_elided_read_instructions(source),
    })
}

/// Merges that have no C operation of their own because every edge is an
/// identity.
///
/// A materialised merge edge whose incoming value and the merge's output are
/// one renderer binding renders as `x = x`. When every edge of a merge is like
/// that, the merge performs nothing: whatever wrote the binding has already
/// written it.
///
/// The merge's value stays `Bound` all the same, because its readers need a
/// name and the plan is what promises one. What the merge loses is a statement
/// of its own, not an object. Saying it were elided would make the ledger
/// claim the opposite of what happens: the value is rendered, under the
/// binding's name, by whatever wrote that binding.
///
/// `group_of` names whichever object a value belongs to on the caller's side --
/// the plan passes its `BindingId`, the seal its own component index. The
/// question is whether two values share one object, not what that object is
/// called, so neither derivation has to agree with the other about names in
/// order to agree about the answer.
///
/// An entry value among the inputs is no exception: a binding holding one is
/// caller-supplied and declared as such, so its edge copy says `x = x` too.
pub(super) fn identity_merge_values(
    graph: &SsaGraph,
    group_of: impl Fn(ValueId) -> Option<u32>,
) -> BTreeSet<ValueId> {
    let mut merges = BTreeSet::new();
    for inst in &graph.insts {
        if !matches!(inst.payload, r2ssa::InstPayload::Phi { .. }) || inst.inputs.is_empty() {
            continue;
        }
        let Some(output) = inst.output else {
            continue;
        };
        let Some(output_group) = group_of(output) else {
            continue;
        };
        if inst
            .inputs
            .iter()
            .all(|input| group_of(*input) == Some(output_group))
        {
            merges.insert(output);
        }
    }
    merges
}
