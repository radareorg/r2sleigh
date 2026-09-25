//! What more than one certificate asks.

use super::super::*;

/// Exact producer chain for the machine return target consumed by one source
/// return boundary. The rendered `return` remains outside `insts`; only copies
/// and an optional exact stack reload whose complete value-use domain ends at
/// that control operand are certified for non-rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineReturnControlCertificate {
    pub at: InstId,
    pub storage: CanonicalStorageId,
    pub control_value: ValueId,
    pub insts: BTreeSet<InstId>,
    pub values: BTreeSet<ValueId>,
    pub uses: BTreeSet<UseSite>,
    /// The instructions this certificate took over from the prologue: the
    /// save of the return address and the copies feeding it.
    ///
    /// They are recorded apart from the rest because they are shared. One
    /// `stp x29, x30` both sets up the frame and saves the return address, so
    /// the frame's certificate and this one describe the same instruction from
    /// two sides; and one save serves every return the function has. Both
    /// accounts say it renders nothing, so neither has to be the only one.
    pub absorbed_insts: BTreeSet<InstId>,
    /// The slot the return address was reloaded from: the entry slot a call
    /// pushed it into, or the callee's own save of a link register.
    pub reload_object: Option<ObjectId>,
}

impl MachineReturnControlCertificate {
    /// The save slot this certificate answers for: its one write is the
    /// prologue's save, its one read the reload, and both are absorbed here.
    pub fn claimed_stack_object(&self) -> Option<ObjectId> {
        self.reload_object
            .filter(|_| !self.absorbed_insts.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnCarrier {
    Register {
        storage: CanonicalStorageId,
    },
    StackSlot {
        object: ObjectId,
        offset: i64,
        memory_access: Option<StructuredAccessId>,
    },
}

/// A value read back from a stack slot, and how it relates to what was stored.
///
/// `relation` is the view's answer (`crate::view`): `Identity` where `value`
/// is the reload's bits at the reload's width, `Derived` where it was only
/// computed from them -- an extension, a lane, the sign word of one. Only an
/// identity is the slot's value; a derived value is evidence of where its
/// input came from and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackReloadSourceCertificate {
    pub value: ValueId,
    pub relation: crate::view::ViewRelation,
    pub reload: ValueId,
    pub source: ValueId,
    pub canonical_source: ValueId,
    pub object: ObjectId,
    pub base: StackAddressBase,
    pub offset: i64,
    pub value_width: u32,
    pub memory_width: u32,
    pub store_access: StructuredAccessId,
    pub load_access: StructuredAccessId,
    pub store_inst: InstId,
    pub load_inst: InstId,
}

pub(crate) fn exact_copy_chain_to_entry_storage(
    graph: &SsaGraph,
    start: ValueId,
    width: u32,
) -> Option<(
    CanonicalStorageId,
    ValueId,
    BTreeSet<InstId>,
    BTreeSet<ValueId>,
)> {
    let mut insts = BTreeSet::new();
    let mut values = BTreeSet::from([start]);
    let mut current = start;
    loop {
        let Some(inst) = graph.def_inst(current) else {
            let value = graph.value(current)?;
            let storage = value.canonical_storage?;
            if value.var.version != 0
                || value.var.size != width
                || storage.space != CanonicalStorageSpace::Register
                || storage.size != width
            {
                return None;
            }
            return Some((storage, current, insts, values));
        };
        let definition = graph.inst(inst)?;
        let InstPayload::Op(SSAOp::Copy { dst, src }) = &definition.payload else {
            return None;
        };
        let source = graph.value_id_for_var(src)?;
        if definition.output != Some(current)
            || definition.inputs.as_slice() != [source]
            || dst.size != width
            || src.size != width
            || !insts.insert(inst)
            || !values.insert(source)
        {
            return None;
        }
        current = source;
    }
}

/// What has been derived from the body by the time the certificates are proved
/// over it.
#[derive(Clone, Copy)]
pub(crate) struct Derived<'a> {
    pub(crate) values: &'a crate::values::ValueRanges,
    pub(crate) boundaries: &'a SourceBoundaryFacts,
    pub(crate) objects: &'a ObjectModel,
    pub(crate) memory: &'a MemorySSAFacts,
    pub(crate) predicates: &'a PredicateFacts,
    pub(crate) call_sites: &'a CallSiteFacts,
    pub(crate) structured: &'a StructuredDataflowFacts,
}

pub(crate) fn expression_phi_is_identity(inst: &crate::graph::GraphInst) -> bool {
    let Some(first) = inst.inputs.first() else {
        return false;
    };
    inst.inputs.iter().all(|input| input == first)
}

pub(crate) fn ram_memory_access_matches_source(
    function: &SSAFunction,
    graph: &SsaGraph,
    objects: &ObjectModel,
    access: &StructuredMemoryAccessFact,
) -> bool {
    if access.space != SpaceId::Ram
        || !access.provenance_complete
        || access.id.ordinal != 0
        || graph.op_site_for_inst(access.id.inst) != Some((access.block_addr, access.op_index))
        || objects.object_for_value(access.address, SpaceId::Ram) != Some(access.object)
        || objects
            .object(access.object)
            .is_none_or(|object| object.kind.space() != SpaceId::Ram)
    {
        return false;
    }
    let Some(graph_inst) = graph.inst(access.id.inst) else {
        return false;
    };
    let Some(prepared_op) = function
        .get_block(access.block_addr)
        .and_then(|block| block.ops.get(access.op_index))
    else {
        return false;
    };
    let InstPayload::Op(graph_op) = &graph_inst.payload else {
        return false;
    };
    if graph_op != prepared_op {
        return false;
    }
    match graph_op {
        SSAOp::Load {
            space: SpaceId::Ram,
            dst,
            addr,
        } => {
            !access.is_write
                && graph.value_id_for_var(addr) == Some(access.address)
                && graph.value_id_for_var(dst) == access.value
                && access.width == dst.size
        }
        SSAOp::Store {
            space: SpaceId::Ram,
            addr,
            val,
        } => {
            access.is_write
                && graph.value_id_for_var(addr) == Some(access.address)
                && graph.value_id_for_var(val) == access.value
                && access.width == val.size
        }
        _ => false,
    }
}

pub(crate) fn return_carrier_for_boundary_slot(slot: CallBoundarySlot) -> Option<ReturnCarrier> {
    match slot {
        CallBoundarySlot::Register { storage, .. } => Some(ReturnCarrier::Register { storage }),
        CallBoundarySlot::Stack(_) => None,
    }
}

pub(crate) fn stack_object_root(
    objects: &ObjectModel,
    object: ObjectId,
) -> Option<(StackAddressBase, i64)> {
    let fact = objects.object(object)?;
    match fact.kind {
        ObjectKind::StackSlot {
            space: SpaceId::Ram,
            base,
            offset,
        }
        | ObjectKind::FrameObject {
            space: SpaceId::Ram,
            base,
            offset,
        } => Some((base, offset)),
        _ => None,
    }
}
