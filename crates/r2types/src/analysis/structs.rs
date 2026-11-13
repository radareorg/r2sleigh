//! Aggregates the frame proves, and how they meet the declared ones.

use super::*;

/// What the prepared function states of its parameters' indexed accesses; the named-SSA struct
/// walk and its scores are gone (ROADMAP T step 3: they reached no output).
pub(crate) fn infer_local_struct_artifacts_from_prepared_ssa(
    prepared: &SsaArtifact,
) -> LocalStructArtifacts {
    LocalStructArtifacts {
        pointee_strides: parameter_pointee_strides(prepared),
        source_fields: field_access_certificates_from_source_aggregate_accesses(prepared),
        indexed_accesses: prepared_parameter_indexed_accesses(prepared),
    }
}

/// Each interface parameter's pointee aggregate size, by the parameter's type id: a typedef is
/// an alias of its target's id, so no name is read (D345). O(parameters).
fn parameter_pointee_strides(prepared: &SsaArtifact) -> Vec<Option<u64>> {
    use r2ssa::SourceTypeKind;
    let Some(interface) = prepared.machine_context().function_interface() else {
        return Vec::new();
    };
    let Some(graph) = interface.type_graph() else {
        return Vec::new();
    };
    let node = |id: u32| graph.types().get(usize::try_from(id).ok()?);
    (0..interface.parameters().len())
        .map(|index| {
            let pointer = node(interface.parameter_logical_value(index)?.type_id())?;
            let SourceTypeKind::Pointer { target_type_id, .. } = pointer.kind() else {
                return None;
            };
            let (SourceTypeKind::Struct { aggregate_id } | SourceTypeKind::Union { aggregate_id }) =
                node(target_type_id)?.kind()
            else {
                return None;
            };
            let aggregate = graph
                .aggregates()
                .get(usize::try_from(aggregate_id).ok()?)?;
            let bits = aggregate.size_bits();
            (bits > 0 && bits.is_multiple_of(8)).then_some(bits / 8)
        })
        .collect()
}

pub(crate) fn prepared_parameter_indexed_accesses(
    prepared: &SsaArtifact,
) -> Vec<ScalarArrayRenderCandidate> {
    let mut candidates = Vec::new();
    for access in prepared.certificates().memory_accesses.values() {
        if access.space != r2il::SpaceId::Ram {
            continue;
        }
        let Some(address) = prepared.addresses().parameter_expression(access.address) else {
            continue;
        };
        let [index] = address.terms.as_slice() else {
            continue;
        };
        let Ok(element_stride) = u64::try_from(index.coefficient) else {
            continue;
        };
        let Ok(field_offset) = u64::try_from(address.offset) else {
            continue;
        };
        if element_stride == 0
            || field_offset >= element_stride
            || u64::from(access.width) > element_stride - field_offset
            || !prepared
                .certificates()
                .renderable_expressions
                .contains(index.value)
        {
            continue;
        }
        let Some(op) = prepared.graph().op_for_inst(access.access.inst) else {
            continue;
        };
        candidates.push(ScalarArrayRenderCandidate {
            slot: address.parameter,
            op,
            is_write: access.is_write,
            field_offset,
            element_stride,
            access_width: access.width,
            index_value: Some(index.value),
        });
    }
    candidates.sort();
    candidates.dedup();
    candidates
}
