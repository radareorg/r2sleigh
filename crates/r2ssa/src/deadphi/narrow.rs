//! Operands that contribute no observed byte stop being read.
//!
//! The byte-dependence relation says, for each operand of an operation, which
//! of its bytes the observed bytes of the value depend on. An operand none of
//! whose bytes are asked for does not affect anything observed, so any value
//! in its place gives the same observations. This pass puts the one value C
//! needs no declaration for there: zero. A lane write whose root contributes
//! no observed byte stops reading the root (`xorps xmm0, xmm0` lifted as four
//! lane writes over the caller's `xmm0` stops reading the caller's `xmm0`;
//! `movsx ax, dil` returned at two bytes stops reading the caller's `rax`),
//! and a lane write whose lane contributes nothing is its root.
//!
//! What is observed here is decided before the fact tables exist, so the
//! observations are the structural ones, taken wide enough to contain every
//! observation those tables will name: each operand of an operation with an
//! effect, read whole; at every call, tail transfer and operation this
//! function cannot see into, the value each register holds, read whole; and at
//! a return, the result the interface states, at its width -- or, where no
//! interface states one, every register, whole. A call reading a register the
//! convention says it does not is still counted: a vector argument the
//! convention's integer slots do not name, or a callee relying on what a
//! sibling left, costs a narrowing, never a byte. A return is read only as the
//! interface says because that is all the rendering returns: the caller of a
//! C function reads its result and nothing else.
//!
//! Runs inside the optimizer's fixpoint beside the other folds: a zeroed root
//! folds with the constants around it, and a fold can leave another operand
//! unobserved. Each round removes at least one read of a non-constant value
//! or stops, so the rounds are bounded by the reads the function has.
//!
//! Cost per round: the graph, one reaching-definitions pass over the written
//! registers, and the byte closure -- O((V + E) * w) for values of at most
//! `w` bytes, plus O(B * R) for the reaching sets of `R` written registers.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::{ByteMask, ResultDemand, dependence::operand_bytes, dependency_closure};
use crate::graph::{BlockId, InstPayload, SsaGraph, ValueId};
use crate::{CanonicalStorageId, CanonicalStorageSpace, SSAFunction, SSAOp, SSAVar};

/// What a return hands the caller, as far as the optimizer knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Returned {
    /// No interface states a result: every register may be it.
    Unstated,
    /// The interface states this result.
    Result(ResultDemand),
    /// The interface states that nothing is returned.
    Nothing,
}

impl Returned {
    /// What `interface` states about its result; `Unstated` without one, and
    /// for a result the body has not proven.
    pub(crate) fn of(interface: Option<&r2source::SourceFunctionInterface>) -> Self {
        let Some(interface) = interface else {
            return Self::Unstated;
        };
        match interface.return_kind() {
            r2source::SourceFunctionReturn::Void => Self::Nothing,
            r2source::SourceFunctionReturn::Unproven => Self::Unstated,
            r2source::SourceFunctionReturn::Register { .. } => {
                ResultDemand::of_interface(interface).map_or(Self::Unstated, Self::Result)
            }
        }
    }
}

/// Stop every read of an operand no observed byte depends on; answers
/// whether anything changed.
pub(crate) fn drop_unobserved_operands(func: &mut SSAFunction, returned: Returned) -> bool {
    let mut changed = false;
    loop {
        let graph = SsaGraph::from_function_with_storage(func);
        let roots = structural_roots(&graph, returned);
        let demand = dependency_closure(&graph, roots).bytes;
        let rewrites = rewrites(&graph, &demand);
        if rewrites.is_empty() {
            break;
        }
        for ((addr, index), op) in rewrites {
            if let Some(slot) = func
                .get_block_mut(addr)
                .and_then(|block| block.ops.get_mut(index))
            {
                *slot = op;
            }
        }
        changed = true;
    }
    changed
}

/// The operations to replace, by block address and index: each observed
/// operation with an operand the observed bytes do not depend on.
fn rewrites(
    graph: &SsaGraph,
    demand: &BTreeMap<ValueId, ByteMask>,
) -> BTreeMap<(u64, usize), SSAOp> {
    let mut rewrites = BTreeMap::new();
    for inst in &graph.insts {
        let (InstPayload::Op(op), Some(output)) = (&inst.payload, inst.output) else {
            continue;
        };
        // A value nothing observes is dead, not narrowed.
        let Some(observed) = demand.get(&output).copied().filter(|mask| !mask.is_empty()) else {
            continue;
        };
        let asked = operand_bytes(op, observed);
        let Some(rewritten) = without_unasked_operands(op, &asked) else {
            continue;
        };
        if let Some(site) = graph.op_site_for_inst(inst.id) {
            rewrites.insert(site, rewritten);
        }
    }
    rewrites
}

/// `op` with every non-constant operand `asked` names no byte of replaced by
/// zero, and a lane write reduced to what is left of it; `None` where no
/// operand is unasked.
///
/// Every rewrite removes a read of a non-constant value or a lane write, so
/// the rounds of [`drop_unobserved_operands`] end.
fn without_unasked_operands(op: &SSAOp, asked: &[ByteMask]) -> Option<SSAOp> {
    let sources = op.sources();
    if let SSAOp::Insert(insert) = op {
        // The root or the lane, constant or not: dropping either removes the
        // lane write.
        let (no_root, no_lane) = (asked.first()?.is_empty(), asked.get(1)?.is_empty());
        return (no_root || no_lane)
            .then(|| lane_write_without(insert, no_root, no_lane))
            .filter(|rewritten| rewritten != op);
    }
    let unasked = sources
        .iter()
        .zip(asked)
        .map(|(source, mask)| mask.is_empty() && source.constant_bits().is_none())
        .collect::<Vec<_>>();
    if !unasked.contains(&true) {
        return None;
    }
    let position = Cell::new(0usize);
    let replaced = crate::optimize::map_sources_in_op(op, &|source: &SSAVar| {
        let index = position.get();
        position.set(index + 1);
        if unasked.get(index).copied().unwrap_or(false) {
            SSAVar::constant(0, source.size)
        } else {
            source.clone()
        }
    });
    // The operands are visited in `sources` order; anything else leaves the
    // operation as it was.
    (position.get() == sources.len()).then_some(replaced)
}

/// A lane write whose root, or lane, contributes nothing observed.
///
/// Without its root it is the lane in place over zero: at position zero that
/// is the lane's zero extension, the one spelling every consumer already has.
/// Without its lane it is its root.
fn lane_write_without(insert: &crate::op::InsertOp, no_root: bool, no_lane: bool) -> SSAOp {
    let dst = insert.dst.clone();
    if no_lane {
        return SSAOp::Copy {
            dst,
            src: insert.src.clone(),
        };
    }
    debug_assert!(no_root);
    let at_zero = insert.position.constant_bits() == Some(0);
    match (at_zero, insert.value.size.cmp(&dst.size)) {
        (true, std::cmp::Ordering::Less) => SSAOp::IntZExt {
            dst,
            src: insert.value.clone(),
        },
        (true, std::cmp::Ordering::Equal) => SSAOp::Copy {
            dst,
            src: insert.value.clone(),
        },
        _ => SSAOp::Insert(Box::new(crate::op::InsertOp {
            src: SSAVar::constant(0, dst.size),
            dst,
            value: insert.value.clone(),
            position: insert.position.clone(),
        })),
    }
}

/// What the program observes, as far as its own operations say: every
/// operand of an operation with an effect, and every register's value where
/// control or a callee could read it.
fn structural_roots(graph: &SsaGraph, returned: Returned) -> Vec<(ValueId, ByteMask)> {
    let mut roots = Vec::new();
    for inst in &graph.insts {
        let InstPayload::Op(op) = &inst.payload else {
            continue;
        };
        if inst.output.is_none() || observes_its_operands(op) {
            roots.extend(inst.inputs.iter().map(|input| (*input, ByteMask::All)));
        }
    }
    roots.extend(observed_registers(graph, returned));
    roots
}

/// An operation whose operands something outside the value graph reads: an
/// effect, a transfer, a read of memory, or one that may trap.
fn observes_its_operands(op: &SSAOp) -> bool {
    op.has_observable_effects(true)
        || matches!(
            op,
            SSAOp::IntDiv { .. }
                | SSAOp::IntSDiv { .. }
                | SSAOp::IntRem { .. }
                | SSAOp::IntSRem { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. }
        )
}

/// Whether control enters code this function cannot see at this operation:
/// every register is read there.
fn reads_every_register(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::Call { .. }
            | SSAOp::CallInd { .. }
            | SSAOp::CallOther { .. }
            | SSAOp::BranchInd { .. }
            | SSAOp::Unimplemented
    )
}

/// The value each written register holds at every call, every exit and
/// every operation this function cannot see into; at a return, what the
/// caller is handed.
fn observed_registers(graph: &SsaGraph, returned: Returned) -> Vec<(ValueId, ByteMask)> {
    let storage_of = |value: ValueId| {
        graph
            .value(value)
            .and_then(|value| value.canonical_storage)
            .filter(|storage| storage.space == CanonicalStorageSpace::Register)
    };
    let reaching = ReachingValues::compute(graph, &storage_of);
    let mut roots = Vec::new();
    for block in &graph.blocks {
        let mut current = reaching.entering(block.id);
        let mut returns = false;
        for inst_id in &block.insts {
            let Some(inst) = graph.inst(*inst_id) else {
                continue;
            };
            if let InstPayload::Op(op) = &inst.payload {
                if reads_every_register(op) {
                    read(&current, Returned::Unstated, &mut roots);
                }
                returns |= matches!(op, SSAOp::Return { .. });
            }
            if let Some((output, storage)) = inst.output.and_then(|o| Some((o, storage_of(o)?))) {
                current.insert(storage, BTreeSet::from([output]));
            }
        }
        // Control leaves the function here: to the caller, which reads what
        // the interface returns, or to a tail callee, which may read anything.
        if block.successors.is_empty() {
            let handed = if returns {
                returned
            } else {
                Returned::Unstated
            };
            read(&current, handed, &mut roots);
        }
    }
    roots
}

/// What `returned` reads of the values in `current`: every one whole where no
/// result is stated, the result carrier's at its bytes where one is, and
/// nothing where the interface returns nothing.
fn read(
    current: &BTreeMap<CanonicalStorageId, BTreeSet<ValueId>>,
    returned: Returned,
    roots: &mut Vec<(ValueId, ByteMask)>,
) {
    for (storage, values) in current {
        let bytes = match returned {
            Returned::Unstated => ByteMask::All,
            Returned::Result(result) => result.bytes_of(*storage).unwrap_or(ByteMask::NONE),
            Returned::Nothing => ByteMask::NONE,
        };
        if !bytes.is_empty() {
            roots.extend(values.iter().map(|value| (*value, bytes)));
        }
    }
}

/// Which values of each register may reach the start of each block.
struct ReachingValues {
    entering: BTreeMap<BlockId, BTreeMap<CanonicalStorageId, BTreeSet<ValueId>>>,
}

impl ReachingValues {
    /// The least fixpoint of `in(B) = U out(P)`, `out(B) = in(B)` overwritten
    /// by `B`'s own last definitions. Sets only grow, and are bounded by the
    /// values each register has, so the iteration ends.
    fn compute(
        graph: &SsaGraph,
        storage_of: &impl Fn(ValueId) -> Option<CanonicalStorageId>,
    ) -> Self {
        let own = graph
            .blocks
            .iter()
            .map(|block| {
                let mut last = BTreeMap::new();
                for inst in block.insts.iter().filter_map(|id| graph.inst(*id)) {
                    if let Some((output, storage)) =
                        inst.output.and_then(|o| Some((o, storage_of(o)?)))
                    {
                        last.insert(storage, output);
                    }
                }
                (block.id, last)
            })
            .collect::<BTreeMap<_, _>>();
        let mut entering: BTreeMap<BlockId, BTreeMap<CanonicalStorageId, BTreeSet<ValueId>>> =
            BTreeMap::new();
        let mut changed = true;
        while changed {
            changed = false;
            for block in &graph.blocks {
                for successor in &block.successors {
                    let mut leaving = entering.get(&block.id).cloned().unwrap_or_default();
                    for (storage, value) in own.get(&block.id).into_iter().flatten() {
                        leaving.insert(*storage, BTreeSet::from([*value]));
                    }
                    let target = entering.entry(*successor).or_default();
                    for (storage, values) in leaving {
                        let set = target.entry(storage).or_default();
                        let before = set.len();
                        set.extend(values);
                        changed |= set.len() != before;
                    }
                }
            }
        }
        Self { entering }
    }

    fn entering(&self, block: BlockId) -> BTreeMap<CanonicalStorageId, BTreeSet<ValueId>> {
        self.entering.get(&block).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
