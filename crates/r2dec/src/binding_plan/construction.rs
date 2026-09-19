use super::*;

use super::rules::{ParameterCandidate, parameter_candidates, parameter_width};

fn refuse_conflicting_parameter_bindings(parameters: &mut [Option<ParameterDisposition>]) {
    let mut parameter_slots_by_binding = BTreeMap::<BindingId, Vec<u32>>::new();
    for (index, disposition) in parameters.iter().enumerate() {
        let Some(ParameterDisposition::Bound { binding, .. }) = disposition else {
            continue;
        };
        parameter_slots_by_binding
            .entry(*binding)
            .or_default()
            .push(index as u32);
    }
    for (binding, slots) in parameter_slots_by_binding {
        if slots.len() < 2 {
            continue;
        }
        let reason = ParameterRefusal::ConflictingBindingOwnership {
            binding,
            first_slot: slots[0],
            second_slot: slots[1],
        };
        for slot in slots {
            parameters[slot as usize] = Some(ParameterDisposition::Refused { reason });
        }
    }
}

/// Give a full-width parameter object the type used by its declarator.
///
/// The binding remains owned by its certified machine width. A source parameter
/// can name only a low slice of that binding (for example, `edi` inside a
/// binding that also owns `rdi`); narrowing the shared object to the formal
/// width would invalidate the machine projection before its upstream refusal
/// can be reported. Same-width pointer and signedness refinements are safe and
/// keep later assignments consistent with the function declarator.
fn apply_parameter_declaration_types(
    source_owned: &SourceOwnedFunctionFacts,
    parameters: &[Option<ParameterDisposition>],
    bindings: &mut [Binding],
    ptr_bits: u32,
) {
    let signature = source_owned
        .report()
        .type_facts()
        .render_authorized_signature();
    for (slot, disposition) in parameters.iter().enumerate() {
        let Some(ParameterDisposition::Bound { binding, .. }) = disposition else {
            continue;
        };
        // The exact declared type, resolved through the source interface's
        // type graph, outranks the signature's spelling: the spelling names a
        // typedef whose width nothing here can measure, and a parameter that
        // was `z_streamp` in the source rendered as a machine word for it.
        let exact = u32::try_from(slot).ok().and_then(|slot| {
            source_owned
                .report()
                .render()
                .and_then(|render| render.certified_entities.get(&SemanticId::Parameter(slot)))
                .and_then(|entity| match entity {
                    r2types::CertifiedEntity::Parameter { ty, .. } => ty.as_ref(),
                    _ => None,
                })
        });
        r2il::refusal_evidence!(
            "parameter-declaration",
            "parameter {slot} exact {:?} signature {:?}",
            exact,
            signature.and_then(|signature| signature.params.get(slot).and_then(|p| p.ty.as_ref()))
        );
        let Some(ty) = exact.or_else(|| {
            signature?
                .params
                .get(slot)
                .and_then(|parameter| parameter.ty.as_ref())
        }) else {
            continue;
        };
        let Some(binding) = bindings.get_mut(binding.0 as usize) else {
            continue;
        };
        let Some(binding_width_bits) =
            super::rules::declaration_type_width(binding.declaration_type(), ptr_bits)
        else {
            continue;
        };
        if super::rules::declaration_type_width(ty, ptr_bits) != Some(binding_width_bits) {
            r2il::refusal_evidence!(
                "parameter-declaration",
                "parameter {slot} declared {:?} at {:?} bits but its binding is {} bits wide",
                ty,
                super::rules::declaration_type_width(ty, ptr_bits),
                binding_width_bits
            );
            continue;
        }
        binding.declaration_type =
            super::rules::admit_declaration(ty.clone(), binding_width_bits, ptr_bits);
    }
}

/// Compute the transitive closure of every exact upstream coalescing set.
///
/// Constants are deliberately outside the relation: they are expressions that
/// initialize or update an object, not C objects themselves. Certified sets are
/// filtered to the non-literal values they authorize before joining, and the
/// same filtering is used again when the completed plan is sealed.
#[cfg(test)]
pub(super) fn binding_components(
    source_owned: &SourceOwnedFunctionFacts,
    projection: &MachineProjection,
) -> Result<Vec<BindingComponent>, BindingPlanBuildError> {
    let eligible = super::rules::component_eligible_values(source_owned, projection)?;
    binding_components_with(
        source_owned,
        &eligible,
        source_owned.source().value_liveness(),
    )
}

/// The same partition from a stated eligibility.
///
/// `inlinable_values` builds one of these from its conservative first pass,
/// to ask whether a literal is alone in its object before deciding whether to
/// spell it at its readers. Taking eligibility as an argument is what keeps
/// that from being a second answerer: the inlining decision is still made in
/// one place, and this is the partition that decision is read against.
/// The one binding every value is bound to, when there is one.
///
/// An empty set, an unbound member, or two bindings all answer `None`: the
/// caller then owns its object rather than sharing one.
pub(super) fn unanimous_value_binding(
    dispositions: &[ValueDisposition],
    values: impl IntoIterator<Item = ValueId>,
) -> Option<BindingId> {
    let mut found = None;
    for value in values {
        let ValueDisposition::Bound { binding } = dispositions.get(value.0 as usize)? else {
            return None;
        };
        match found {
            Some(existing) if existing != *binding => return None,
            _ => found = Some(*binding),
        }
    }
    found
}

/// The binding a slot shares with its reloads, when that binding holds
/// nothing else.
///
/// A carrier the program goes on to modify in place is a different variable,
/// and naming the slot after it would turn `rax - 2` into a write of the slot.
pub(super) fn shared_reload_binding(
    dispositions: &[ValueDisposition],
    bound_value_counts: &BTreeMap<BindingId, usize>,
    reload_values: &BTreeSet<ValueId>,
    stored_values: &BTreeSet<ValueId>,
    declaration_type: &CType,
) -> Option<BindingId> {
    // A register holds the bytes of an aggregate, never the aggregate.
    if matches!(
        declaration_type,
        r2types::CTypeLike::Struct(_)
            | r2types::CTypeLike::Union(_)
            | r2types::CTypeLike::Array(..)
    ) {
        return None;
    }
    // The binding holds the reloads and whichever stored values joined it.
    unanimous_value_binding(dispositions, reload_values.iter().copied()).filter(|binding| {
        let stored = stored_values
            .iter()
            .filter(|value| {
                matches!(
                    dispositions.get(value.0 as usize),
                    Some(ValueDisposition::Bound { binding: bound }) if bound == binding
                )
            })
            .count();
        bound_value_counts.get(binding).copied() == Some(reload_values.len() + stored)
    })
}

/// The binding a stack object takes, sharing one with the values its reloads
/// Whether a call left this register changed and nothing says what is in it.
///
/// The convention says a call may clobber the carrier, and no result
/// certificate claims the callee returned a value there, so the program reads
/// whatever the callee happened to leave.
fn value_is_unclaimed_call_clobber(
    source_owned: &SourceOwnedFunctionFacts,
    graph: &r2ssa::SsaGraph,
    value: ValueId,
) -> bool {
    let Some(inst) = graph.def_inst(value) else {
        return false;
    };
    let defined_by_call = graph.inst(inst).is_some_and(|inst| {
        matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallDefine { .. })
        )
    });
    defined_by_call
        && !source_owned
            .source()
            .facts()
            .certificates
            .call_results
            .contains_key(&value)
}

/// certify as its contents where there is one.
fn bind_stack_object(
    bindings: &mut Vec<Binding>,
    shared: Option<BindingId>,
    entity: r2ssa::SemanticId,
    declaration_type: CType,
    presentation_name_hint: Option<String>,
    caller_supplied: bool,
) -> Result<BindingId, BindingPlanBuildError> {
    if let Some(binding) = shared {
        let existing = &mut bindings[binding.index()];
        existing.declaration_type = declaration_type;
        existing.presentation_name_hint = presentation_name_hint;
        // Joining the caller's storage makes the binding caller-supplied; the
        // values it already held do not make it any less so.
        existing.caller_supplied |= caller_supplied;
        return Ok(binding);
    }
    let Some(binding) = BindingId::from_dense_index(bindings.len()) else {
        return Err(BindingPlanBuildError::TooManyBindings {
            count: bindings.len().saturating_add(1),
        });
    };
    bindings.push(Binding {
        declaration_type,
        certificate: BindingCertificate {
            sources: Box::new([BindingCertificateSource::CertifiedEntity(entity)]),
        },
        presentation_name_hint,
        caller_supplied,
        call_clobbered: false,
    });
    Ok(binding)
}

pub(super) fn binding_components_with(
    source_owned: &SourceOwnedFunctionFacts,
    eligible: &[bool],
    liveness: &r2ssa::liveness::ValueLiveness,
) -> Result<Vec<BindingComponent>, BindingPlanBuildError> {
    let source = source_owned.source();
    let graph = source.graph();
    let value_count = graph.values.len();
    let mut parent = (0..value_count).collect::<Vec<_>>();
    let mut rank = vec![0_u8; value_count];
    // One circular list per component, in a flat array: `ring[value]` names the
    // next value round its component and a lone value points at itself. Two
    // components join by swapping their two links, so nothing is copied when
    // they merge and no component owns a vector. This was a vector per value --
    // one heap allocation for each of thirty thousand singletons, seven times
    // per render.
    let mut ring = (0..value_count as u32).collect::<Vec<u32>>();

    /// The values sharing a component with `root`, walked from it.
    fn ring_members(ring: &[u32], root: usize) -> impl Iterator<Item = ValueId> + '_ {
        let start = root as u32;
        let mut current = Some(start);
        std::iter::from_fn(move || {
            let value = current?;
            let next = ring[value as usize];
            current = (next != start).then_some(next);
            Some(ValueId(value))
        })
    }

    fn find(parent: &mut [usize], mut value: usize) -> usize {
        while parent[value] != value {
            let grandparent = parent[parent[value]];
            parent[value] = grandparent;
            value = grandparent;
        }
        value
    }

    // Each root carries the values in its component. Asking which values a set
    // of roots holds by scanning every value in the function is what made the
    // interference question cost the function rather than the candidate.
    fn union(
        parent: &mut [usize],
        rank: &mut [u8],
        ring: &mut [u32],
        left: ValueId,
        right: ValueId,
    ) {
        let left = find(parent, left.0 as usize);
        let right = find(parent, right.0 as usize);
        if left == right {
            return;
        }
        let (root, child) = match rank[left].cmp(&rank[right]) {
            std::cmp::Ordering::Greater => (left, right),
            std::cmp::Ordering::Less => (right, left),
            std::cmp::Ordering::Equal if left < right => {
                rank[left] += 1;
                (left, right)
            }
            std::cmp::Ordering::Equal => {
                rank[right] += 1;
                (right, left)
            }
        };
        parent[child] = root;
        ring.swap(root, child);
    }

    // A value that is a literal decides no object. It is spelled at its
    // readers when it is alone, and it joins an object only where one exists
    // for other reasons and it fits; letting it seed a run bound `RDX_7 =
    // 0x80078071` as a variable and put a constant's live range in the way
    // of a loop carrier's union. So literals are set aside here and offered
    // to their run last.
    let literal_defined = |value: ValueId| super::rules::literal_defined(graph, value);
    let mut certificate_sets = Vec::<(BindingCertificateSource, BTreeSet<ValueId>)>::new();
    let mut values_by_span = BTreeMap::<SpanId, BTreeSet<ValueId>>::new();
    let mut literals_by_span = BTreeMap::<SpanId, Vec<ValueId>>::new();
    for (index, value) in graph.values.iter().enumerate() {
        if value.id.0 as usize != index {
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::ValueTopology {
                    index,
                    value: value.id,
                },
            ));
        }
        if !eligible[index] {
            continue;
        }
        let span = source
            .storage_spans()
            .span_of(value.id)
            .ok_or(BindingPlanBuildError::MissingStorageSpan { value: value.id })?;
        if literal_defined(value.id) {
            literals_by_span.entry(span).or_default().push(value.id);
        } else {
            values_by_span.entry(span).or_default().insert(value.id);
        }
    }
    // Whether merging every one of these values into one object would put a
    // value where another is still needed. Each run's liveness is kept at its
    // root and grown as runs join, so a merge is judged against everything
    // already in the runs it touches and never against the whole function.
    let mut live_by_root = vec![None::<r2ssa::liveness::ComponentLiveness>; value_count];
    // A stack slot or a parameter is one object by identity, whatever its
    // values' live ranges say. A run that would carry two of them is two runs.
    let mut identity_by_root = vec![None::<r2ssa::SemanticId>; value_count];
    let identity_conflict = |parent: &mut Vec<usize>,
                             identity_by_root: &[Option<r2ssa::SemanticId>],
                             values: &BTreeSet<ValueId>,
                             claimed: Option<r2ssa::SemanticId>| {
        let mut identities = values
            .iter()
            .filter_map(|value| identity_by_root[find(parent, value.0 as usize)])
            .chain(claimed)
            .collect::<BTreeSet<_>>();
        let first = identities.pop_first();
        first.zip(identities.pop_first())
    };
    let merge_would_interfere = |parent: &mut Vec<usize>,
                                 ring: &[u32],
                                 live_by_root: &mut Vec<
        Option<r2ssa::liveness::ComponentLiveness>,
    >,
                                 values: &BTreeSet<ValueId>| {
        let roots = values
            .iter()
            .map(|value| find(parent, value.0 as usize))
            .collect::<BTreeSet<_>>();
        let mut merged = None::<r2ssa::liveness::ComponentLiveness>;
        for root in roots {
            let component = live_by_root[root]
                .get_or_insert_with(|| {
                    let mut component = r2ssa::liveness::ComponentLiveness::default();
                    for member in ring_members(ring, root) {
                        component.absorb(r2ssa::liveness::ComponentLiveness::of(liveness, member));
                    }
                    component
                })
                .clone();
            match merged.as_mut() {
                None => merged = Some(component),
                Some(merged) => {
                    if let Some((left, right)) = merged.first_interference(&component, liveness) {
                        r2il::refusal_evidence!(
                            "union-declined",
                            "{} is live where {} is written",
                            graph.value(left).map_or("?".to_string(), |value| value
                                .var
                                .display_name()
                                .to_string()),
                            graph.value(right).map_or("?".to_string(), |value| value
                                .var
                                .display_name()
                                .to_string())
                        );
                        return true;
                    }
                    merged.absorb(component);
                }
            }
        }
        false
    };

    if let Some(render) = source_owned.report().render() {
        for entity in render.certified_entities.values() {
            let Some(values) = entity.coalescing_values() else {
                // StackSlot has object identity but no exact ValueId set.
                continue;
            };
            let values = values
                .into_iter()
                .filter_map(|value| {
                    let index = value.0 as usize;
                    if index >= value_count {
                        return Some(Err(BindingPlanBuildError::InvalidCertifiedEntityValue {
                            entity: entity.id(),
                            value,
                        }));
                    }
                    (eligible[index] && !literal_defined(value)).then_some(Ok(value))
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if values.is_empty() {
                continue;
            }
            // A certificate says these values are one object. It cannot say so
            // about two values that are read by one instruction, because that
            // instruction needs both at once. Where it does, the coalescing is
            // declined and the values keep their own objects, which costs an
            // assignment in the output and nothing in correctness.
            let identity = match entity.id() {
                id @ (r2ssa::SemanticId::StackSlot(_) | r2ssa::SemanticId::Parameter(_)) => {
                    Some(id)
                }
                _ => None,
            };
            if let Some(first) = values.first().copied() {
                if let Some((left, right)) =
                    identity_conflict(&mut parent, &identity_by_root, &values, identity)
                {
                    r2il::refusal_evidence!(
                        "coalescing-declined",
                        "entity {:?} members {values:?}: {left:?} and {right:?} are two objects",
                        entity.id()
                    );
                    continue;
                }
                if merge_would_interfere(&mut parent, &ring, &mut live_by_root, &values) {
                    r2il::refusal_evidence!(
                        "coalescing-declined",
                        "entity {:?} members {values:?}: a member is live where another is written",
                        entity.id()
                    );
                    continue;
                }
                let joined = identity.or_else(|| {
                    values
                        .iter()
                        .find_map(|value| identity_by_root[find(&mut parent, value.0 as usize)])
                });
                for value in values.iter().copied().skip(1) {
                    union(&mut parent, &mut rank, &mut ring, first, value);
                    live_by_root[find(&mut parent, first.0 as usize)] = None;
                }
                identity_by_root[find(&mut parent, first.0 as usize)] = joined;
                r2il::refusal_evidence!(
                    "coalescing-union",
                    "entity {:?} members {values:?} identity {joined:?}",
                    entity.id()
                );
            }
            certificate_sets.push((
                BindingCertificateSource::CertifiedEntity(entity.id()),
                values,
            ));
        }
    }

    for (span, values) in &values_by_span {
        let values = values.clone();
        let span = *span;
        if values.len() > 1 {
            // A storage span says these values share a machine location. That
            // is not on its own a licence to share a C object, and this asked
            // nothing before unioning: the certificate path below has always
            // asked, and one instruction reading two members is exactly as
            // impossible whichever derivation proposed the merge. `crc32_bitwise`
            // at arm64 -O2 is the case -- one p-code temporary carries both
            // `w10` and `w11`, and `eor w10, w10, w11` reads two of its versions.
            if let Some((left, right)) =
                identity_conflict(&mut parent, &identity_by_root, &values, None)
            {
                r2il::refusal_evidence!(
                    "span-declined",
                    "{span:?} members {values:?}: {left:?} and {right:?} are two objects"
                );
                continue;
            }
            if merge_would_interfere(&mut parent, &ring, &mut live_by_root, &values) {
                r2il::refusal_evidence!("span-declined", "{span:?} members {values:?}");
                continue;
            }
            let joined = values
                .iter()
                .find_map(|value| identity_by_root[find(&mut parent, value.0 as usize)]);
            let first = values.first().copied().expect("multi-member span");
            for value in values.iter().copied().skip(1) {
                union(&mut parent, &mut rank, &mut ring, first, value);
                live_by_root[find(&mut parent, first.0 as usize)] = None;
            }
            identity_by_root[find(&mut parent, first.0 as usize)] = joined;
            certificate_sets.push((BindingCertificateSource::StorageSpan(span), values));
        }
    }

    // A value stored into a slot is the slot's value at that point, offered on
    // its own: it joins where nothing it is live across writes the object and
    // no other identity claims it, and otherwise the store stays a copy.
    if let Some(render) = source_owned.report().render() {
        for entity in render.certified_entities.values() {
            let r2types::CertifiedEntity::StackSlot {
                id, stored_values, ..
            } = entity
            else {
                continue;
            };
            let Some(mates) = entity.coalescing_values() else {
                continue;
            };
            let Some(mate) = mates
                .into_iter()
                .find(|value| (value.0 as usize) < value_count && eligible[value.0 as usize])
            else {
                continue;
            };
            for stored in stored_values.iter().copied() {
                let index = stored.0 as usize;
                if index >= value_count || !eligible[index] || literal_defined(stored) {
                    continue;
                }
                if find(&mut parent, index) == find(&mut parent, mate.0 as usize) {
                    continue;
                }
                let proposed = BTreeSet::from([stored, mate]);
                // A value that is already another object -- a parameter, a
                // different slot -- was copied into this slot, not renamed by
                // it. The conflict check below sees that only when the mate
                // carries an identity of its own, which a slot whose own
                // coalescing was declined does not.
                if let Some(other) = identity_by_root[find(&mut parent, index)]
                    && other != *id
                {
                    r2il::refusal_evidence!(
                        "store-declined",
                        "{id:?} stored {stored:?}: the value is {other:?}, another object"
                    );
                    continue;
                }
                if let Some((left, right)) =
                    identity_conflict(&mut parent, &identity_by_root, &proposed, None)
                {
                    r2il::refusal_evidence!(
                        "store-declined",
                        "{id:?} stored {stored:?}: {left:?} and {right:?} are two objects"
                    );
                    continue;
                }
                if merge_would_interfere(&mut parent, &ring, &mut live_by_root, &proposed) {
                    r2il::refusal_evidence!(
                        "store-declined",
                        "{id:?} stored {stored:?} stays a copy"
                    );
                    continue;
                }
                r2il::refusal_evidence!(
                    "coalescing-union",
                    "{id:?} stored {stored:?} joins mate {mate:?} (identities {:?} and {:?})",
                    identity_by_root[find(&mut parent, index)],
                    identity_by_root[find(&mut parent, mate.0 as usize)]
                );
                union(&mut parent, &mut rank, &mut ring, mate, stored);
                let root = find(&mut parent, mate.0 as usize);
                live_by_root[root] = None;
                identity_by_root[root] = Some(*id);
                certificate_sets.push((BindingCertificateSource::CertifiedEntity(*id), proposed));
            }
        }
    }

    // Now the literals, each offered to whatever its run became. One that
    // fits is a write to that object; one that does not stays alone and is
    // spelled where it is read.
    for (span, literals) in literals_by_span {
        let Some(mate) = values_by_span
            .get(&span)
            .and_then(|values| values.first().copied())
        else {
            continue;
        };
        for literal in literals {
            let proposed = BTreeSet::from([literal, mate]);
            if merge_would_interfere(&mut parent, &ring, &mut live_by_root, &proposed) {
                r2il::refusal_evidence!(
                    "span-declined",
                    "{span:?} literal {literal:?} stays alone"
                );
                continue;
            }
            union(&mut parent, &mut rank, &mut ring, mate, literal);
            live_by_root[find(&mut parent, mate.0 as usize)] = None;
            certificate_sets.push((BindingCertificateSource::StorageSpan(span), proposed));
        }
    }

    let mut members_by_root = BTreeMap::<usize, BTreeSet<ValueId>>::new();
    for (index, is_eligible) in eligible.iter().copied().enumerate() {
        if !is_eligible {
            continue;
        }
        let root = find(&mut parent, index);
        members_by_root
            .entry(root)
            .or_default()
            .insert(ValueId(index as u32));
    }
    let mut sources_by_root = BTreeMap::<usize, BTreeSet<BindingCertificateSource>>::new();
    for (source, values) in certificate_sets {
        let Some(first) = values.first().copied() else {
            continue;
        };
        let root = find(&mut parent, first.0 as usize);
        if values
            .iter()
            .all(|value| find(&mut parent, value.0 as usize) == root)
        {
            sources_by_root.entry(root).or_default().insert(source);
        } else {
            r2il::refusal_evidence!(
                "certificate-membership",
                "{source:?} names {values:?}, which are not one run"
            );
            return Err(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::CertificateMembership {
                    binding: BindingId(u32::MAX),
                },
            ));
        }
    }

    let mut components = members_by_root
        .into_iter()
        .map(|(root, members)| {
            let mut sources = sources_by_root.remove(&root).unwrap_or_default();
            if sources.is_empty() && members.len() == 1 {
                sources.insert(BindingCertificateSource::Singleton);
            }
            BindingComponent { members, sources }
        })
        .collect::<Vec<_>>();
    components.sort_by_key(|component| component.members.first().copied());
    Ok(components)
}

/// What one member's reads ask of the object: the bit past the widest read,
/// or a refusal where a read is incoherent with the member.
///
/// A read the projection cannot state, the address of the object, and a value
/// the caller reads at the return keep the member whole. A value the function
/// entered with is read at the width the machine handed it over in: its
/// carrier, so this function's idea of its parameters agrees with the
/// declaration a caller writes for it. A merge or a copy reads nothing of its
/// own: what it asks is what its consumers ask. A member nothing reads keeps
/// its width.
pub(super) fn member_read_end_bits(
    source_owned: &SourceOwnedFunctionFacts,
    machine_projection: &MachineProjection,
    value: ValueId,
) -> Result<Result<u32, ValueRefusal>, BindingPlanBuildError> {
    let mut visited = std::collections::BTreeSet::new();
    let read_end_bits = match read_end_bits_through_merges(
        source_owned,
        machine_projection,
        value,
        &mut visited,
    )? {
        Ok(bits) => bits,
        Err(reason) => return Ok(Err(reason)),
    };
    Ok(Ok(if read_end_bits == 0 {
        value_width_bits(source_owned, value)?
    } else {
        read_end_bits
    }))
}

fn value_width_bits(
    source_owned: &SourceOwnedFunctionFacts,
    value: ValueId,
) -> Result<u32, BindingPlanBuildError> {
    let graph_value =
        source_owned
            .source()
            .graph()
            .value(value)
            .ok_or(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::ValueTopology {
                    index: value.0 as usize,
                    value,
                },
            ))?;
    graph_value
        .var
        .size
        .checked_mul(8)
        .filter(|bits| *bits > 0)
        .ok_or(BindingPlanBuildError::InvalidValueWidth {
            value,
            size_bytes: graph_value.var.size,
        })
}

/// The bit past the widest read of `value`, following merges and copies to
/// the reads of their outputs; zero where nothing reads it.
fn read_end_bits_through_merges(
    source_owned: &SourceOwnedFunctionFacts,
    machine_projection: &MachineProjection,
    value: ValueId,
    visited: &mut std::collections::BTreeSet<ValueId>,
) -> Result<Result<u32, ValueRefusal>, BindingPlanBuildError> {
    let source = source_owned.source();
    let graph = source.graph();
    let member_width_bits = value_width_bits(source_owned, value)?;
    // A member C cannot spell is not declared at any width: rounding it up
    // would claim bits nothing defines.
    if !declaration_width_is_supported(member_width_bits) {
        return Ok(Err(ValueRefusal::UnsupportedDeclarationWidth {
            value,
            width_bits: member_width_bits,
        }));
    }
    if !visited.insert(value) {
        return Ok(Ok(0));
    }
    let computed = graph.def_inst(value).is_some();
    let mut read_end_bits = if source.live_out().contains(value) {
        member_width_bits
    } else {
        0
    };
    for site in graph.use_sites(value) {
        // A call's conventional read of a register the certified call does
        // not pass is not a read the text performs.
        if source.ignored_reads().contains(site) {
            continue;
        }
        let Some(MachineUseDisposition::Exact(slice)) = machine_projection.use_disposition(*site)
        else {
            read_end_bits = read_end_bits.max(member_width_bits);
            continue;
        };
        let valid_end = slice
            .bit_offset()
            .checked_add(slice.width_bits())
            .is_some_and(|end| end <= slice.carrier_width_bits());
        if slice.width_bits() == 0 || slice.carrier_width_bits() < member_width_bits || !valid_end {
            return Ok(Err(ValueRefusal::IncoherentUseProjection { site: *site }));
        }
        let reader = graph.inst(site.inst);
        let forwarded_output = reader.and_then(|inst| match inst.payload {
            r2ssa::InstPayload::Phi { .. } | r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. }) => {
                inst.output
            }
            _ => None,
        });
        let site_end_bits = if !computed {
            slice.carrier_width_bits()
        } else if let Some(output) = forwarded_output
            && value_width_bits(source_owned, output)? == member_width_bits
        {
            match read_end_bits_through_merges(source_owned, machine_projection, output, visited)? {
                Ok(bits) => bits,
                Err(_) => member_width_bits,
            }
        } else {
            machine_projection
                .use_read_end_bits(*site)
                .unwrap_or(member_width_bits)
        };
        r2il::refusal_evidence!(
            "binding-width",
            "{value:?} {:?} read at {:?} to bit {site_end_bits} by {:?}",
            graph
                .value(value)
                .map(|graph_value| graph_value.var.display_name()),
            site,
            reader.map(|inst| &inst.payload)
        );
        read_end_bits = read_end_bits.max(site_end_bits);
    }
    if let Some(definition) = graph.def_inst(value)
        && let Some(&MachineWriteDisposition::Exact(MachineWriteProjection::ZeroExtend {
            from_width_bits,
            to_width_bits,
        })) = machine_projection.write_disposition(definition)
        && (from_width_bits == 0
            || from_width_bits >= to_width_bits
            || to_width_bits < member_width_bits)
    {
        return Ok(Err(ValueRefusal::IncoherentWriteProjection { value }));
    }
    Ok(Ok(read_end_bits))
}

/// The narrowest declaration width that holds `bits`.
pub(super) fn declaration_width_holding(bits: u32) -> Option<u32> {
    [8, 16, 32, 64, 128, 256, 512]
        .into_iter()
        .find(|width| *width >= bits)
}

/// An object is as wide as the widest read any member takes of it, rounded
/// up to a width C declares. Its definitions may be wider: the assignment
/// truncates, and nothing reads the bits it drops.
fn binding_width(
    source_owned: &SourceOwnedFunctionFacts,
    machine_projection: &MachineProjection,
    component: &BindingComponent,
) -> Result<BindingWidth, BindingPlanBuildError> {
    let mut read_end_bits = 0_u32;
    for value in &component.members {
        match member_read_end_bits(source_owned, machine_projection, *value)? {
            Ok(bits) => read_end_bits = read_end_bits.max(bits),
            Err(reason) => return Ok(BindingWidth::Refused(reason)),
        }
    }
    match declaration_width_holding(read_end_bits) {
        Some(width_bits) => Ok(BindingWidth::Exact(width_bits)),
        None => Ok(BindingWidth::Refused(
            ValueRefusal::UnsupportedDeclarationWidth {
                value: component
                    .members
                    .first()
                    .copied()
                    .expect("binding components are non-empty"),
                width_bits: read_end_bits,
            },
        )),
    }
}

impl BindingPlan {
    /// Seal the conservative Stage 4 shadow partition for one exact source.
    ///
    /// Binding identity is the transitive closure of exact upstream storage-span
    /// and certified-entity membership. It never depends on a register location,
    /// renderer alias, or hash-map iteration order.
    #[cfg(test)]
    pub(crate) fn build_shadow(
        source_owned: &SourceOwnedFunctionFacts,
    ) -> Result<Self, BindingPlanBuildError> {
        Self::build_shadow_with_control(source_owned, &r2ssa::SsaExecutionControl::default())
    }

    /// The same plan, counting its work.
    ///
    /// The plan is the largest measured stage of a render -- 1.81 s of the
    /// 6.48 s dpkg-divert -O0 spends -- and it is linear in the graph's values,
    /// so a unit per value is what it costs. Without this the meter charged
    /// almost nothing for the phase it most needed to bound.
    pub(crate) fn build_shadow_with_control(
        source_owned: &SourceOwnedFunctionFacts,
        control: &dyn r2ssa::SsaWorkControl,
    ) -> Result<Self, BindingPlanBuildError> {
        let source = source_owned.source();
        let machine_projection = MachineProjection::from_artifact(source)
            .map_err(BindingPlanBuildError::MachineProjection)?;
        crate::stage_timing::mark("plan_projection");
        let graph = source.graph();
        let return_controls = certified_return_control_values(source);
        let direct_control_targets = certified_direct_control_target_values(source);
        let direct_call_targets = super::certified_direct_call_target_values(source);
        let call_return_addresses = super::certified_call_return_address_values(source);
        let stack_frame_values = certified_stack_frame_values(source);
        let stack_geometry_values = certified_stack_geometry_values(source);
        let unobserved_values = source.unobserved_values();
        let structural_unused = source
            .obligations()
            .structural_unused_values(graph, source.unobserved_merges().unobserved_uses())
            .ok_or(BindingPlanBuildError::Seal(
                BindingPlanSourceMismatch::Authority,
            ))?;
        crate::stage_timing::mark("plan_certified");
        let boundary_reads = super::readers::BoundaryReads::compute(source);
        let plan_facts = super::rules::PlanFacts {
            owned: source_owned,
            projection: &machine_projection,
            boundary: &boundary_reads,
        };
        let unread = super::rules::unread_defined_values(plan_facts);
        crate::stage_timing::mark("plan_unread");
        // One derivation, three readers. The partition is a pure function of the
        // source facts and the projection, and neither the seal nor the shadow
        // oracle can influence either, so deriving it again for each of them
        // could only ever produce this same answer -- at the price of a whole
        // term arena per derivation, six per function before this.
        let partition =
            super::rules::rewrite_inlining_partition(source_owned, &machine_projection)?;
        crate::stage_timing::mark("plan_canonical");
        let canonical = &partition.canonical;
        // A value every reader stopped reading when the terms were rewritten is
        // dead, and it needs an elision reason of its own: leaving it merely
        // ineligible for a binding gives it no disposition at all, which the
        // plan reports as a missing binding certificate.
        let unrendered = super::rules::unrendered_defined_values(plan_facts, canonical);
        let inlinable = &partition.inlinable;
        let mut dispositions = graph
            .values
            .iter()
            .map(|graph_value| ValueDisposition::Refused {
                reason: ValueRefusal::MissingBindingCertificate {
                    value: graph_value.id,
                },
            })
            .collect::<Vec<_>>();

        for (index, graph_value) in graph.values.iter().enumerate() {
            control.poll().map_err(BindingPlanBuildError::Stopped)?;
            if graph_value.id.0 as usize != index {
                return Err(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::ValueTopology {
                        index,
                        value: graph_value.id,
                    },
                ));
            }
            if return_controls.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::ReturnControl,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if direct_control_targets.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::DirectControlTarget,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if direct_call_targets.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::DirectCallTarget,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if stack_frame_values.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::StackFrame,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if stack_geometry_values.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::DeadStackBase,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if source.unobserved_merges().contains(graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::UnobservedMerge,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if unobserved_values.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::UnobservedValue,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if structural_unused.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::UnusedStructuralValue,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if call_return_addresses.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::CallReturnAddress,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if unread.contains(&graph_value.id) || unrendered.contains(&graph_value.id) {
                dispositions[index] = ValueDisposition::Elided {
                    reason: r2ssa::ledger::ElisionReason::DeadUnusedTemporary,
                    proof: ValueElisionProof {
                        authority: source.authority().clone(),
                        value: graph_value.id,
                    },
                };
            } else if graph_value.var.constant_bits().is_none()
                && inlinable.contains(&graph_value.id)
                && let Some(term) = canonical
                    .value(graph_value.id)
                    .map(|canonical| canonical.canonical)
            {
                dispositions[index] = ValueDisposition::Inline {
                    term,
                    proof: InlineProof {
                        authority: source.authority().clone(),
                        term,
                    },
                };
            } else if graph_value.var.constant_bits().is_some() {
                dispositions[index] = match canonical
                    .value(graph_value.id)
                    .map(|canonical| canonical.canonical)
                {
                    Some(term) => ValueDisposition::Inline {
                        term,
                        proof: InlineProof {
                            authority: source.authority().clone(),
                            term,
                        },
                    },
                    None => {
                        if r2il::refusal_evidence::tracing() {
                            eprintln!(
                                "missing literal projection {:?} bits={:?} name={:?} uses={} def={:?} users={users:?}",
                                graph_value.id,
                                graph_value.var.constant_bits(),
                                graph_value.var.name(),
                                graph.use_sites(graph_value.id).len(),
                                graph
                                    .def_inst(graph_value.id)
                                    .and_then(|inst| graph.inst(inst))
                                    .map(|inst| format!("{:?}", inst.payload)
                                        .chars()
                                        .take(110)
                                        .collect::<String>()),
                                users = graph
                                    .use_sites(graph_value.id)
                                    .iter()
                                    .filter_map(|site| graph.inst(site.inst))
                                    .map(|inst| format!("{:?}", inst.payload)
                                        .chars()
                                        .take(90)
                                        .collect::<String>())
                                    .collect::<Vec<_>>(),
                            );
                        }
                        // A constant the arena never interned because the only
                        // thing that reads it is a user-operation the machine
                        // projection does not lower. Say that, rather than
                        // reporting a projection defect the arena does not have.
                        let unmodelled_userop = graph
                            .use_sites(graph_value.id)
                            .iter()
                            .filter_map(|site| graph.inst(site.inst))
                            .find_map(|inst| match &inst.payload {
                                r2ssa::InstPayload::Op(r2ssa::SSAOp::CallOther {
                                    userop, ..
                                }) => Some(*userop),
                                _ => None,
                            });
                        ValueDisposition::Refused {
                            reason: match unmodelled_userop {
                                Some(userop) => ValueRefusal::UnmodelledUserOperation {
                                    value: graph_value.id,
                                    userop,
                                },
                                None => ValueRefusal::MissingLiteralProjection {
                                    value: graph_value.id,
                                },
                            },
                        }
                    }
                };
            }
        }

        crate::stage_timing::mark("plan_dispositions");
        let components = partition.components.clone();
        if u32::try_from(components.len()).is_err() {
            return Err(BindingPlanBuildError::TooManyBindings {
                count: components.len(),
            });
        }

        crate::stage_timing::mark("plan_partition");
        let mut bindings = Vec::with_capacity(components.len());
        let floating_views = super::rules::floating_views(&machine_projection);

        let mut call_clobbers = BTreeSet::new();
        for mut component in components {
            // A member already answered for -- folded into its reader, or
            // elided -- keeps that answer; the object is the members that
            // still need one, and a component with none is no object.
            component.members.retain(|value| {
                matches!(
                    dispositions[value.0 as usize],
                    ValueDisposition::Refused {
                        reason: ValueRefusal::MissingBindingCertificate { .. }
                    }
                )
            });
            if component.members.is_empty() {
                continue;
            }
            let width_bits = match binding_width(source_owned, &machine_projection, &component)? {
                BindingWidth::Exact(width_bits) => width_bits,
                BindingWidth::Refused(reason) => {
                    for value in component.members {
                        dispositions[value.0 as usize] = ValueDisposition::Refused { reason };
                    }
                    continue;
                }
            };
            let binding = BindingId(bindings.len() as u32);
            for value in &component.members {
                dispositions[value.0 as usize] = ValueDisposition::Bound { binding };
            }
            let first = component
                .members
                .first()
                .and_then(|value| graph.value(*value))
                .ok_or(BindingPlanBuildError::Seal(
                    BindingPlanSourceMismatch::CertificateMembership { binding },
                ))?;
            // A member with no defining instruction entered this function
            // already holding its value, so the object exists from entry; so
            // does a lane of an entry register, which is minted from its root
            // (doc/adr-register-identity.md §8, 6).
            let caller_supplied = super::rules::is_caller_supplied(
                source_owned,
                graph,
                &component.members,
                &component.sources,
            );
            let mut call_clobbered = false;
            for value in &component.members {
                if value_is_unclaimed_call_clobber(source_owned, graph, *value) {
                    call_clobbers.insert(*value);
                    call_clobbered = true;
                }
            }
            bindings.push(Binding {
                declaration_type: super::rules::declaration_type_for_binding(
                    source_owned,
                    component.members.iter().copied(),
                    width_bits,
                    source
                        .machine_context()
                        .memory_model()
                        .default_address_bits(),
                    super::rules::floating_width_of_component(&floating_views, &component.members),
                ),
                certificate: BindingCertificate {
                    sources: component
                        .sources
                        .into_iter()
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                },
                // A promoted frame slot is the one object at that frame
                // position, so it keeps the frame's own spelling rather than
                // one of its versions -- the same name the slot had before it
                // left memory.
                presentation_name_hint: Some(
                    if first.var.name_kind() == r2ssa::SSAVarNameKind::Frame {
                        first.var.name().replace(':', "_")
                    } else {
                        first.var.display_name()
                    },
                ),
                caller_supplied,
                call_clobbered,
            });
        }

        let candidates = parameter_candidates(source_owned);
        let mut parameters = vec![None; candidates.len()];
        for (index, candidate) in candidates.into_iter().enumerate() {
            let Some(candidate) = candidate else {
                continue;
            };
            let slot = u32::try_from(index).expect("dense parameter domain fits u32");
            let (entity, width_bytes, entry_values) = match candidate {
                ParameterCandidate::Exact {
                    entity,
                    width_bytes,
                    entry_values,
                } => (entity, width_bytes, entry_values),
                ParameterCandidate::Refused(reason) => {
                    parameters[index] = Some(ParameterDisposition::Refused { reason });
                    continue;
                }
            };
            r2il::refusal_evidence!(
                "parameter-width",
                "parameter {slot} carrier {} bytes",
                width_bytes
            );
            let width_bits = match parameter_width(entity, slot, width_bytes) {
                Ok(width_bits) => width_bits,
                Err(reason) => {
                    parameters[index] = Some(ParameterDisposition::Refused { reason });
                    continue;
                }
            };

            let mut value_binding = None;
            let mut missing_value = None;
            for value in entry_values {
                match dispositions.get(value.0 as usize) {
                    Some(ValueDisposition::Bound { binding })
                        if value_binding.is_none_or(|existing| existing == *binding) =>
                    {
                        value_binding = Some(*binding);
                    }
                    _ => {
                        missing_value = Some(value);
                        break;
                    }
                }
            }
            if let Some(value) = missing_value {
                parameters[index] = Some(ParameterDisposition::Refused {
                    reason: ParameterRefusal::MissingValueBinding {
                        entity,
                        slot,
                        value,
                    },
                });
                continue;
            }

            let binding = match value_binding {
                Some(binding) => binding,
                None => {
                    let Some(binding) = BindingId::from_dense_index(bindings.len()) else {
                        return Err(BindingPlanBuildError::TooManyBindings {
                            count: bindings.len().saturating_add(1),
                        });
                    };
                    bindings.push(Binding {
                        declaration_type: CType::machine_bits(width_bits),
                        certificate: BindingCertificate {
                            sources: Box::new([BindingCertificateSource::CertifiedEntity(entity)]),
                        },
                        presentation_name_hint: None,
                        caller_supplied: false,
                        call_clobbered: false,
                    });
                    binding
                }
            };

            parameters[index] = Some(ParameterDisposition::Bound {
                binding,
                width_bits,
            });
        }
        refuse_conflicting_parameter_bindings(&mut parameters);
        apply_parameter_declaration_types(
            source_owned,
            &parameters,
            &mut bindings,
            source
                .machine_context()
                .memory_model()
                .default_address_bits(),
        );

        crate::stage_timing::mark("plan_bindings");
        let mut stack_objects = BTreeMap::new();
        let mut bound_value_counts = BTreeMap::<BindingId, usize>::new();
        for disposition in &dispositions {
            if let ValueDisposition::Bound { binding } = disposition {
                *bound_value_counts.entry(*binding).or_default() += 1;
            }
        }
        if let Some(render) = source_owned.report().render() {
            for entity in render.certified_entities.values() {
                let r2types::CertifiedEntity::StackSlot {
                    id,
                    object,
                    base,
                    offset,
                    size,
                    array_layout,
                    source_slot,
                    reload_values,
                    stored_values,
                    callee_allocation,
                    ty: _,
                } = entity
                else {
                    continue;
                };
                if source.frame_managed_stack_object(*object) {
                    stack_objects.insert(
                        *object,
                        StackObjectDisposition::Elided {
                            reason: r2ssa::ledger::ElisionReason::StackFrame,
                        },
                    );
                    continue;
                }
                // Identity needs a geometry, not an endorsement. A declared
                // slot and a callee allocation are the two strong forms and
                // still cannot both answer at once; where neither does, the
                // width the object's own accesses agree on is enough to name
                // it. Radare2 reports no stack variables at all for some
                // functions, and every local in them was refused for that
                // silence.
                if source_slot.is_none() && callee_allocation.is_none() && size.is_none()
                    || source_slot.is_some() && callee_allocation.is_some()
                {
                    // Three inputs decide this and the refusal names none of
                    // them. Which one is missing is which layer to fix: a
                    // source slot is radare2's, a width consensus is the
                    // dataflow's, a callee allocation is a certificate's.
                    r2il::refusal_evidence!(
                        "stack-object-identity",
                        "object={:?} at {:?}{:+} source_slot={} callee_allocation={} size={:?}",
                        object,
                        base,
                        offset,
                        source_slot.is_some(),
                        callee_allocation.is_some(),
                        size
                    );
                    stack_objects.insert(
                        *object,
                        StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::MissingSourceIdentity { object: *object },
                        },
                    );
                    continue;
                }
                let Some(size_bytes) = *size else {
                    stack_objects.insert(
                        *object,
                        StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::MissingWidth { object: *object },
                        },
                    );
                    continue;
                };
                let Some(width_bits) = size_bytes.checked_mul(8).filter(|width| *width > 0) else {
                    stack_objects.insert(
                        *object,
                        StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::InvalidWidth {
                                object: *object,
                                size_bytes,
                            },
                        },
                    );
                    continue;
                };
                if let Some(certificate) = callee_allocation {
                    if source_slot.is_some()
                        || certificate.object != *object
                        || certificate.size_bytes != size_bytes
                        || certificate.accesses.is_empty()
                        || certificate.active_sp_offsets.is_empty()
                    {
                        r2il::refusal_evidence!(
                            "stack-object-identity",
                            "object={:?} callee allocation disagrees: source_slot={} certificate_object={:?} certificate_size={} size={} accesses={} active_sp_offsets={}",
                            object,
                            source_slot.is_some(),
                            certificate.object,
                            certificate.size_bytes,
                            size_bytes,
                            certificate.accesses.len(),
                            certificate.active_sp_offsets.len()
                        );
                        stack_objects.insert(
                            *object,
                            StackObjectDisposition::Refused {
                                reason: StackObjectRefusal::MissingSourceIdentity {
                                    object: *object,
                                },
                            },
                        );
                        continue;
                    }
                    let declaration_type = super::rules::declaration_type_for_stack_object(
                        source_owned,
                        *object,
                        width_bits,
                        source
                            .machine_context()
                            .memory_model()
                            .default_address_bits(),
                    );
                    let binding = bind_stack_object(
                        &mut bindings,
                        shared_reload_binding(
                            &dispositions,
                            &bound_value_counts,
                            reload_values,
                            stored_values,
                            &declaration_type,
                        ),
                        *id,
                        declaration_type,
                        Some(if certificate.entry_offset < 0 {
                            format!("stack_m{}", certificate.entry_offset.unsigned_abs())
                        } else {
                            format!("stack_p{}", certificate.entry_offset.unsigned_abs())
                        }),
                        super::rules::stack_object_is_caller_storage(source_owned, *object),
                    )?;
                    stack_objects.insert(*object, StackObjectDisposition::Bound { binding });
                    continue;
                }
                let Some(source_slot) = *source_slot else {
                    // Named by the width its own accesses agree on, at the
                    // position the object model proved. A local like any other;
                    // only the origin of its geometry differs.
                    let declaration_type = super::rules::declaration_type_for_stack_object(
                        source_owned,
                        *object,
                        width_bits,
                        source
                            .machine_context()
                            .memory_model()
                            .default_address_bits(),
                    );
                    let binding = bind_stack_object(
                        &mut bindings,
                        shared_reload_binding(
                            &dispositions,
                            &bound_value_counts,
                            reload_values,
                            stored_values,
                            &declaration_type,
                        ),
                        *id,
                        declaration_type,
                        Some(if *offset < 0 {
                            format!("stack_m{}", offset.unsigned_abs())
                        } else {
                            format!("stack_p{}", offset.unsigned_abs())
                        }),
                        super::rules::stack_object_is_caller_storage(source_owned, *object),
                    )?;
                    stack_objects.insert(*object, StackObjectDisposition::Bound { binding });
                    continue;
                };
                let recovered_array_size_matches = matches!(
                    array_layout,
                    r2ssa::StackArrayLayoutDisposition::Proven(layout)
                        if layout.object == *object
                            && u32::try_from(layout.extent).ok() == Some(size_bytes)
                            && (source_slot.size_bytes() == size_bytes
                                || source_slot.size_bytes() == layout.element_width)
                );
                if source_slot.base() != *base
                    || source_slot.offset() != *offset
                    || size_bytes != source_slot.size_bytes() && !recovered_array_size_matches
                {
                    // Three fields can disagree and the refusal names none of
                    // them, which is the difference between a trace and a
                    // search: a slot the source declared one byte wide under
                    // an object the body reads four bytes of is a different
                    // repair from one at another offset.
                    r2il::refusal_evidence!(
                        "stack-object-identity",
                        "{object:?}: body says {base:?}{offset:+} size {size_bytes}, \
                         source slot says {:?}{:+} size {}, recovered array {}",
                        source_slot.base(),
                        source_slot.offset(),
                        source_slot.size_bytes(),
                        recovered_array_size_matches
                    );
                    stack_objects.insert(
                        *object,
                        StackObjectDisposition::Refused {
                            reason: StackObjectRefusal::MissingSourceIdentity { object: *object },
                        },
                    );
                    continue;
                }
                let role = super::rules::effective_stack_slot_role(
                    source_owned,
                    &source_slot,
                    *base,
                    *offset,
                );
                let role = super::rules::verified_stack_slot_role(
                    source_owned,
                    &machine_projection,
                    canonical,
                    &dispositions,
                    |index| match parameters.get(index as usize).copied().flatten() {
                        Some(ParameterDisposition::Bound { binding, .. }) => Some(binding),
                        _ => None,
                    },
                    *object,
                    role,
                );
                match role {
                    r2ssa::SourceStackSlotRole::Local => {
                        let declaration_type = super::rules::declaration_type_for_stack_object(
                            source_owned,
                            *object,
                            width_bits,
                            source
                                .machine_context()
                                .memory_model()
                                .default_address_bits(),
                        );
                        let name_hint = Some(if *offset < 0 {
                            format!("stack_m{}", offset.unsigned_abs())
                        } else {
                            format!("stack_p{}", offset.unsigned_abs())
                        });
                        let binding = bind_stack_object(
                            &mut bindings,
                            shared_reload_binding(
                                &dispositions,
                                &bound_value_counts,
                                reload_values,
                                stored_values,
                                &declaration_type,
                            ),
                            *id,
                            declaration_type,
                            name_hint,
                            super::rules::stack_object_is_caller_storage(source_owned, *object),
                        )?;
                        stack_objects.insert(*object, StackObjectDisposition::Bound { binding });
                    }
                    r2ssa::SourceStackSlotRole::ParameterHome {
                        parameter_index, ..
                    } => {
                        let Some(ParameterDisposition::Bound {
                            binding,
                            width_bits: parameter_width_bits,
                        }) = parameters.get(parameter_index as usize).copied().flatten()
                        else {
                            stack_objects.insert(
                                *object,
                                StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::ParameterHomeUnavailable {
                                        object: *object,
                                        parameter_index,
                                    },
                                },
                            );
                            continue;
                        };
                        if parameter_width_bits != width_bits {
                            stack_objects.insert(
                                *object,
                                StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::ParameterHomeWidthMismatch {
                                        object: *object,
                                        parameter_index,
                                        slot_width_bits: width_bits,
                                        parameter_width_bits,
                                    },
                                },
                            );
                            continue;
                        }
                        stack_objects.insert(*object, StackObjectDisposition::Bound { binding });
                    }
                    // A parameter the convention passes on the stack is its
                    // own slot: the object is the parameter, so it takes the
                    // parameter's binding, and every read of it is a read of
                    // a value the caller supplied.
                    r2ssa::SourceStackSlotRole::Parameter { parameter_index } => {
                        let Some(ParameterDisposition::Bound {
                            binding,
                            width_bits: parameter_width_bits,
                        }) = parameters.get(parameter_index as usize).copied().flatten()
                        else {
                            stack_objects.insert(
                                *object,
                                StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::StackParameterUnavailable {
                                        object: *object,
                                        parameter_index,
                                    },
                                },
                            );
                            continue;
                        };
                        if parameter_width_bits != width_bits {
                            stack_objects.insert(
                                *object,
                                StackObjectDisposition::Refused {
                                    reason: StackObjectRefusal::StackParameterWidthMismatch {
                                        object: *object,
                                        parameter_index,
                                        slot_width_bits: width_bits,
                                        parameter_width_bits,
                                    },
                                },
                            );
                            continue;
                        }
                        stack_objects.insert(*object, StackObjectDisposition::Bound { binding });
                    }
                    r2ssa::SourceStackSlotRole::UnclassifiedResource => {
                        stack_objects.insert(
                            *object,
                            StackObjectDisposition::Refused {
                                reason: StackObjectRefusal::UnclassifiedSourceRole {
                                    object: *object,
                                },
                            },
                        );
                    }
                }
            }
        }

        let access_syntax = source_owned
            .report()
            .render()
            .map(|render| {
                super::access_syntax::derive(&super::access_syntax::AccessSyntaxInputs {
                    render,
                    objects: source.objects(),
                    canonical: &partition.canonical,
                    projection: &machine_projection,
                    dispositions: &dispositions,
                    stack_objects: &stack_objects,
                    bindings: &bindings,
                    type_graph: source
                        .machine_context()
                        .function_interface()
                        .and_then(r2ssa::SourceFunctionInterface::type_graph),
                    ptr_bits: source
                        .machine_context()
                        .memory_model()
                        .default_address_bits(),
                })
            })
            .unwrap_or_default();
        crate::stage_timing::mark("plan_objects");
        let super::rules::EscapedFrameObjects {
            escaped: escaped_frame_objects,
            reached_by_callee: callee_reached_frame_objects,
        } = super::rules::frame_objects_with_escaped_address(source_owned, &machine_projection);
        let plan = Self {
            authority: source.authority().clone(),
            machine_projection,
            partition,
            bindings: bindings.into_boxed_slice(),
            dispositions: dispositions.into_boxed_slice(),
            parameters: parameters.into_boxed_slice(),
            stack_objects,
            call_clobbers,
            escaped_frame_objects,
            callee_reached_frame_objects,
            access_syntax,
            typed: std::cell::OnceCell::new(),
        };
        crate::stage_timing::mark("plan_assembled");
        plan.validate_seal(source_owned)?;
        crate::stage_timing::mark("plan_seal");
        Ok(plan)
    }
}

#[cfg(test)]
mod parameter_tests {
    use super::*;

    #[test]
    fn sparse_out_of_order_slots_keep_their_exact_indices() {
        let mut candidates = Vec::new();
        super::super::rules::insert_formal_parameter_candidate(&mut candidates, 3, 8);
        super::super::rules::insert_formal_parameter_candidate(&mut candidates, 1, 4);

        assert_eq!(candidates.len(), 4);
        assert!(candidates[0].is_none());
        assert!(matches!(
            candidates[1],
            Some(ParameterCandidate::Exact {
                entity: SemanticId::Parameter(1),
                width_bytes: 4,
                ..
            })
        ));
        assert!(candidates[2].is_none());
        assert!(matches!(
            candidates[3],
            Some(ParameterCandidate::Exact {
                entity: SemanticId::Parameter(3),
                width_bytes: 8,
                ..
            })
        ));
    }

    #[test]
    fn three_slot_binding_conflict_has_one_deterministic_reason() {
        let binding = BindingId::from_dense_index(7).expect("binding");
        let mut parameters = vec![
            Some(ParameterDisposition::Bound {
                binding,
                width_bits: 64,
            });
            3
        ];
        refuse_conflicting_parameter_bindings(&mut parameters);

        let expected = Some(ParameterDisposition::Refused {
            reason: ParameterRefusal::ConflictingBindingOwnership {
                binding,
                first_slot: 0,
                second_slot: 1,
            },
        });
        assert!(
            parameters
                .iter()
                .all(|disposition| *disposition == expected)
        );
    }
}
