//! `SavedRegister` (doc/adr-call-boundary.md, S11): a store of the entry value of a preserved
//! register or lane (AAPCS64 6.1.2's `d8`), read by promotion, the frame and the round trip.

use std::collections::BTreeSet;

use crate::frame_address::Definitions;
use crate::function::SSAFunction;
use crate::graph::{InstPayload, SsaGraph, ValueId};
use crate::op::SSAOp;
use crate::value_table::VarId;
use crate::{CanonicalStorageId, CanonicalStorageSpace, InstId};

/// The bytes `width` wide at byte `offset` of a register root.
fn lane(root: CanonicalStorageId, offset: u32, width: u32) -> Option<CanonicalStorageId> {
    (root.space == CanonicalStorageSpace::Register && offset + width <= root.size).then_some(
        CanonicalStorageId {
            space: root.space,
            offset: root.offset + u64::from(offset),
            size: width,
        },
    )
}

/// Whether the convention keeps a lane across calls; with no convention every register is kept.
pub(crate) fn preserved(
    effect: Option<&r2source::SourceCallEffect>,
    stack_pointer: Option<CanonicalStorageId>,
    lane: CanonicalStorageId,
) -> bool {
    Some(lane) != stack_pointer && effect.is_none_or(|effect| effect.preserves(lane))
}

/// The entry lane an unsealed value holds: an entry register through copies, or a lane of one.
pub(crate) fn entry_lane_of_var(
    func: &SSAFunction,
    defs: &Definitions,
    var: VarId,
) -> Option<CanonicalStorageId> {
    let entry = |var: VarId| {
        (func.var(var).version == 0)
            .then(|| func.storage_of(var))
            .flatten()
            .filter(|storage| storage.space == CanonicalStorageSpace::Register)
    };
    let var = defs.copied(var);
    if let Some(storage) = entry(var) {
        return Some(storage);
    }
    match defs.op(var)?.1 {
        SSAOp::Subpiece { dst, src, offset } => {
            lane(entry(defs.copied(src))?, offset, func.var(dst).size)
        }
        _ => None,
    }
}

/// An entry lane a sealed value holds, with the instructions and values that carry it there.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one save or restore chain: a few ids, where a dense index would cost O(values) per chain"
    )
)]
pub(crate) struct EntryLane {
    pub(crate) lane: CanonicalStorageId,
    /// The caller's value: the register's, or the root's a lane is read from.
    pub(crate) entry: ValueId,
    pub(crate) insts: BTreeSet<InstId>,
    pub(crate) values: BTreeSet<ValueId>,
}

/// The entry lane `start` holds at `width` bytes: copies back to an entry register, or to a
/// `Subpiece` of an entry root. `O(chain)`.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one save or restore chain: a few ids, where a dense index would cost O(values) per chain"
    )
)]
pub(crate) fn entry_lane(graph: &SsaGraph, start: ValueId, width: u32) -> Option<EntryLane> {
    let mut insts = BTreeSet::new();
    let mut values = BTreeSet::from([start]);
    let mut current = start;
    loop {
        let Some(inst) = graph.def_inst(current) else {
            let value = graph.value(current)?;
            let storage = value.canonical_storage?;
            let whole = value.var.version == 0
                && value.var.size == width
                && storage.space == CanonicalStorageSpace::Register
                && storage.size == width;
            return whole.then_some(EntryLane {
                lane: storage,
                entry: current,
                insts,
                values,
            });
        };
        let definition = graph.inst(inst)?;
        let source = match definition.payload {
            InstPayload::Op(SSAOp::Copy { src, .. }) => src,
            InstPayload::Op(SSAOp::Subpiece { src, offset, .. }) => {
                let root = graph.value(src)?;
                let storage = root.canonical_storage?;
                let entry = graph.def_inst(src).is_none() && root.var.version == 0;
                let lane = lane(storage, offset, width).filter(|_| entry)?;
                insts.insert(inst).then_some(())?;
                return Some(EntryLane {
                    lane,
                    entry: src,
                    insts,
                    values,
                });
            }
            _ => return None,
        };
        if definition.output != Some(current)
            || graph.inputs(definition.id) != [source]
            || graph.var(source).size != width
            || !insts.insert(inst)
            || !values.insert(source)
        {
            return None;
        }
        current = source;
    }
}

/// What a reload passes through to restore `lane`, read by nothing after: copies into the register,
/// or an insert into its root and then inserts that leave the lane alone. `O(chain)`.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one save or restore chain: a few ids, where a dense index would cost O(values) per chain"
    )
)]
pub(crate) fn restore(
    graph: &SsaGraph,
    start: ValueId,
    lane: CanonicalStorageId,
) -> Option<(BTreeSet<InstId>, BTreeSet<ValueId>)> {
    let mut insts = BTreeSet::new();
    let mut values = BTreeSet::from([start]);
    let mut current = start;
    // Once inside the root, the bytes of the lane hold the reload.
    let mut rooted = false;
    loop {
        let value = graph.value(current)?;
        let uses = graph.use_sites(current);
        if value.canonical_storage == Some(lane) || rooted && uses.is_empty() {
            return uses.is_empty().then_some((insts, values));
        }
        let [site] = uses else {
            return None;
        };
        let definition = graph.inst(site.inst)?;
        let output = definition.output?;
        let follows = match &definition.payload {
            InstPayload::Op(SSAOp::Copy { .. }) if !rooted => {
                graph.var(output).size == lane.size && graph.var(current).size == lane.size
            }
            InstPayload::Op(SSAOp::Insert(insert)) => {
                let root = graph
                    .value(output)
                    .and_then(|value| value.canonical_storage);
                let at = graph.var(insert.position).constant_bits();
                let width = u64::from(graph.var(insert.value).size);
                let contains = root.is_some_and(|root| {
                    root.space == lane.space
                        && root.offset <= lane.offset
                        && lane.offset + u64::from(lane.size) <= root.offset + u64::from(root.size)
                });
                let lane_at = root.map(|root| (lane.offset - root.offset.min(lane.offset)) * 8);
                match (rooted, at, lane_at) {
                    // The reload enters the root at exactly the lane's bits.
                    (false, Some(at), Some(lane_at)) => {
                        contains
                            && insert.value == current
                            && at == lane_at
                            && width == u64::from(lane.size)
                    }
                    // A later write of other bits of the root leaves the lane as it was.
                    (true, Some(at), Some(lane_at)) => {
                        contains
                            && insert.src == current
                            && insert.value != current
                            && (at + width * 8 <= lane_at
                                || lane_at + u64::from(lane.size) * 8 <= at)
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if !follows || !insts.insert(site.inst) || !values.insert(output) {
            return None;
        }
        rooted |= matches!(definition.payload, InstPayload::Op(SSAOp::Insert(_)));
        current = output;
    }
}

/// A frame store of a preserved lane's entry value: the slot it saves to and its width. No local
/// holds the caller's register, so such a store is the frame's bookkeeping.
pub(crate) fn frame_slot(
    facts: &crate::DecompilePrepFacts,
    graph: &SsaGraph,
    op: &SSAOp<ValueId>,
    preserved: impl Fn(CanonicalStorageId) -> bool,
) -> Option<(crate::StackAddressRoot, i64)> {
    let SSAOp::Store {
        space: r2il::SpaceId::Ram,
        addr,
        val,
    } = *op
    else {
        return None;
    };
    let root = crate::semantic::resolve_stack_root(Some(facts), addr)?;
    let size = graph.var(val).size;
    let saved = entry_lane(graph, val, size)?.lane;
    if !preserved(saved) {
        return None;
    }
    r2il::refusal_evidence!(
        "frame-boundary",
        "{root:?} saves {saved:?}, preserved across calls"
    );
    Some((root, i64::from(size)))
}
