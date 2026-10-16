//! What each parameter's pointee is read as: its constant-offset fields, or the first access
//! that is not one (doc/adr-aggregates.md).

use super::*;

/// One certified access a parameter's value addresses, at a constant offset from it; ordered by
/// offset, then width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParameterFieldAccess {
    pub offset: i64,
    pub width: u32,
    pub access: StructuredAccessId,
    pub value: Option<ValueId>,
    pub is_write: bool,
}

/// Why a memory operation a parameter reaches is no constant field of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParameterFieldRefusal {
    /// No certificate covers the operation, so the layout would miss what it reads.
    Uncertified,
    /// Its address adds a variable to the parameter: an element, not a field.
    Indexed,
    /// Its address is not affine in the parameter, as through a merge of two offsets.
    NotAffine,
    /// A linked, guarded, atomic or block access, which a layout of plain fields does not model.
    Unmodelled,
}

/// Every memory operation a parameter's value reaches, as constant fields, or the first one that
/// is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterFields {
    Constant(Vec<ParameterFieldAccess>),
    Refused {
        inst: InstId,
        reason: ParameterFieldRefusal,
    },
}

/// Each formal's pointee fields. Reach runs through every operation and merge P feeds and its
/// home's reloads, and ends at a load's output, a new root; each value is expanded once.
pub(crate) fn collect_parameter_fields(
    graph: &SsaGraph,
    boundaries: &SourceBoundaryFacts,
    addresses: &crate::AddressProvenanceFacts,
    stack_reloads: &crate::dense::IdMap<ValueId, StackReloadSourceCertificate>,
    memory_accesses: &BTreeMap<StructuredAccessId, MemoryAccessCertificate>,
    memory_accesses_by_inst: &crate::dense::IdMap<InstId, ByDirection<Vec<StructuredAccessId>>>,
) -> BTreeMap<u32, ParameterFields> {
    let mut reloads_of = crate::dense::IdMap::<ValueId, Vec<ValueId>>::default();
    for reload in stack_reloads.values() {
        if reload.relation == crate::view::ViewRelation::Identity
            && reload.value_width == reload.memory_width
        {
            (reloads_of.get_or_insert_with(reload.canonical_source, Vec::new)).push(reload.value);
        }
    }
    let mut out = BTreeMap::new();
    for (slot, parameter) in &boundaries.parameters {
        let operations = reached_memory_operations(graph, &reloads_of, parameter.value);
        if operations.is_empty() {
            continue;
        }
        let fields = fields_of(
            *slot,
            &operations,
            addresses,
            memory_accesses,
            memory_accesses_by_inst,
        );
        out.insert(*slot, fields);
    }
    out
}

/// How a memory operation the parameter's value reaches uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reached {
    Read,
    Write,
    Unmodelled,
}

/// The memory operations the parameter's value reaches: RAM loads and stores by their address, and
/// any other memory operation it feeds at all.
fn reached_memory_operations(
    graph: &SsaGraph,
    reloads_of: &crate::dense::IdMap<ValueId, Vec<ValueId>>,
    parameter: ValueId,
) -> Vec<(InstId, Reached)> {
    let mut operations = Vec::new();
    let mut reached = crate::dense::IdSet::default();
    let mut pending = vec![parameter];
    while let Some(value) = pending.pop() {
        if !reached.insert(value) {
            continue;
        }
        pending.extend(reloads_of.get(value).into_iter().flatten().copied());
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                continue;
            };
            match &inst.payload {
                InstPayload::Op(SSAOp::Load {
                    space: SpaceId::Ram,
                    addr,
                    ..
                }) if *addr == value => {
                    operations.push((inst.id, Reached::Read));
                }
                InstPayload::Op(SSAOp::Store {
                    space: SpaceId::Ram,
                    addr,
                    ..
                }) if *addr == value => {
                    operations.push((inst.id, Reached::Write));
                }
                // A spilled value comes back through its home's reloads; anything else a load,
                // store or call does with it leaves the pointee alone.
                InstPayload::Op(op)
                    if op.is_call()
                        || matches!(
                            op,
                            SSAOp::Load { .. } | SSAOp::Store { .. } | SSAOp::CallOther { .. }
                        ) => {}
                // What a linked, guarded or atomic load returns is memory's, never the parameter.
                InstPayload::Op(op) if op.is_memory_read() || op.is_memory_write() => {
                    operations.push((inst.id, Reached::Unmodelled));
                }
                _ => pending.extend(inst.output),
            }
        }
    }
    // In instruction order, each once: the first refusal is the earliest instruction's.
    operations.sort_unstable();
    operations.dedup();
    operations
}

fn fields_of(
    slot: u32,
    operations: &[(InstId, Reached)],
    addresses: &crate::AddressProvenanceFacts,
    memory_accesses: &BTreeMap<StructuredAccessId, MemoryAccessCertificate>,
    memory_accesses_by_inst: &crate::dense::IdMap<InstId, ByDirection<Vec<StructuredAccessId>>>,
) -> ParameterFields {
    let mut fields = Vec::new();
    for &(inst, reached) in operations {
        let refused = |reason| ParameterFields::Refused { inst, reason };
        let is_write = match reached {
            Reached::Read => false,
            Reached::Write => true,
            Reached::Unmodelled => return refused(ParameterFieldRefusal::Unmodelled),
        };
        let ids =
            (memory_accesses_by_inst.get(inst)).map_or(&[][..], |ids| ids.get(is_write).as_slice());
        let certified = ids.iter().filter_map(|id| memory_accesses.get(id));
        let mut any = false;
        for certificate in certified {
            any = true;
            let Some(expression) = addresses.parameter_expression(certificate.address) else {
                return refused(ParameterFieldRefusal::NotAffine);
            };
            if usize::try_from(slot) != Ok(expression.parameter) {
                return refused(ParameterFieldRefusal::NotAffine);
            }
            if !expression.terms.is_empty() {
                return refused(ParameterFieldRefusal::Indexed);
            }
            fields.push(ParameterFieldAccess {
                access: certificate.access,
                offset: expression.offset,
                width: certificate.width,
                value: certificate.value,
                is_write,
            });
        }
        if !any {
            return refused(ParameterFieldRefusal::Uncertified);
        }
    }
    fields.sort();
    ParameterFields::Constant(fields)
}
