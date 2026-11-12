//! Which in-edges of a block each of its conditions can hold under, so a merge arm that no path
//! reads is not read (ROADMAP D214; doc/adr-result-side.md, "Parameter side").

use crate::bytes::Rule;
use crate::graph::{BlockId, InstId, InstPayload, SsaGraph, ValueId};
use crate::op::SSAOp;

/// In-edges of one block: bit `k` is `predecessors[k]`.
pub(crate) type Edges = u64;

/// Every in-edge: nothing is folded.
pub(crate) const ALL: Edges = Edges::MAX;

/// Operations one condition's fold may walk under one in-edge; past it the condition is unknown.
const FUEL: u32 = 64;

/// What one block's conditions fold to under each in-edge.
#[derive(Debug, Default)]
struct BlockFold {
    /// The successor the terminator names and the in-edges it may be taken under, then those it
    /// may fall through under.
    branch: Option<(BlockId, Edges, Edges)>,
    /// Each select of the block, in instruction order: the in-edges its condition may be true
    /// under, then false.
    selects: Vec<(InstId, Edges, Edges)>,
}

/// The folds of a function's blocks, each computed when first asked.
/// Work: `O(in-edges x (selects + 1) x FUEL)` per block asked.
pub(crate) struct EdgeFolds<'g> {
    graph: &'g SsaGraph,
    blocks: Vec<Option<BlockFold>>,
}

/// What a condition is worth on the edge a branch on it leaves by.
#[derive(Debug, Clone, Copy)]
struct Held {
    cond: ValueId,
    bits: u64,
}

impl<'g> EdgeFolds<'g> {
    pub(crate) fn new(graph: &'g SsaGraph) -> Self {
        Self {
            graph,
            blocks: Vec::new(),
        }
    }

    /// The in-edges of its own block under which `input` (operand `index` of `inst`) is read,
    /// where `inst`'s value is read under `under`. Default deny: `ALL` wherever nothing folds.
    pub(crate) fn read_under(
        &mut self,
        inst: &crate::graph::GraphInst,
        index: usize,
        input: ValueId,
        under: Edges,
    ) -> Edges {
        let graph = self.graph;
        let defined_in = || Some(graph.inst(graph.def_inst(input)?)?.block);
        match &inst.payload {
            InstPayload::Phi { predecessors } => {
                if predecessors.len() <= Edges::BITS as usize && under & (1 << index) == 0 {
                    return 0;
                }
                match predecessors.get(index) {
                    Some(from) if defined_in() == Some(*from) => self.leaving(*from, inst.block),
                    _ => ALL,
                }
            }
            InstPayload::Op(op) => {
                // A block entered only from the one that defines `input` reads it on that edge.
                let entered = (self.graph.block(inst.block)).map(|block| &block.predecessors[..]);
                // Read under every in-edge by an operation that selects nothing, in a block with
                // no one way in: nothing narrows it, wherever `input` is defined.
                let one_way = matches!(entered, Some([_]));
                if under == ALL && !one_way && !matches!(op, SSAOp::Select(_)) {
                    return ALL;
                }
                let defined_in = defined_in();
                match (entered, defined_in) {
                    _ if defined_in == Some(inst.block) => {}
                    (Some([from]), Some(defined)) if *from == defined => {
                        return self.leaving(defined, inst.block);
                    }
                    _ => return ALL,
                }
                match (op, index) {
                    (SSAOp::Select(_), 1) => under & self.select(inst).0,
                    (SSAOp::Select(_), 2) => under & self.select(inst).1,
                    _ => under,
                }
            }
        }
    }

    /// The in-edges of `from` under which its terminator may leave to `to`.
    fn leaving(&mut self, from: BlockId, to: BlockId) -> Edges {
        match self.fold(from).branch {
            Some((taken, when_taken, _)) if taken == to => when_taken,
            Some((_, _, when_not)) => when_not,
            None => ALL,
        }
    }

    /// The in-edges of its block under which `select`'s condition may be true, then false.
    fn select(&mut self, select: &crate::graph::GraphInst) -> (Edges, Edges) {
        let selects = &self.fold(select.block).selects;
        match selects.binary_search_by_key(&select.id, |(inst, ..)| *inst) {
            Ok(at) => (selects[at].1, selects[at].2),
            Err(_) => (ALL, ALL),
        }
    }

    fn fold(&mut self, block: BlockId) -> &BlockFold {
        let at = block.0 as usize;
        if self.blocks.len() <= at {
            self.blocks
                .resize_with(self.graph.blocks.len().max(at + 1), || None);
        }
        if self.blocks[at].is_none() {
            self.blocks[at] = Some(block_fold(self.graph, block));
        }
        self.blocks[at].as_ref().expect("just folded")
    }
}

/// Whether any block's fold drops an in-edge: where none does, every value is read however its
/// block is entered and no walk needs the folds. One fold per block, as `EdgeFolds` asks.
pub(crate) fn narrows(graph: &SsaGraph) -> bool {
    graph.blocks.iter().any(|block| {
        let fold = block_fold(graph, block.id);
        let branch = fold
            .branch
            .is_some_and(|(_, taken, not)| (taken & not) != ALL);
        branch || (fold.selects.iter()).any(|(_, yes, no)| (yes & no) != ALL)
    })
}

/// The successor a conditional branch ending `block` names, its condition, and the other
/// successor: `None` unless the block ends in a branch between two distinct blocks.
fn conditional(graph: &SsaGraph, block: BlockId) -> Option<(BlockId, ValueId, BlockId)> {
    let block = graph.block(block)?;
    let last = graph.inst(*block.insts.last()?)?;
    let InstPayload::Op(SSAOp::CBranch { target, cond }) = &last.payload else {
        return None;
    };
    // The target is an address the lift states, in the code space or as a constant.
    let storage = graph.value(*target)?.canonical_storage?;
    let stated = matches!(
        storage.space,
        crate::CanonicalStorageSpace::Ram | crate::CanonicalStorageSpace::Constant
    );
    let named = stated.then(|| graph.block_id_for_addr(storage.offset))??;
    let [one, other] = block.successors[..] else {
        return None;
    };
    match (one == named, other == named) {
        (true, false) => Some((named, *cond, other)),
        (false, true) => Some((named, *cond, one)),
        _ => None,
    }
}

/// Whether `value` is defined by an operation whose result is nought or one.
fn boolean(graph: &SsaGraph, value: ValueId) -> bool {
    use r2il::eval::Operation as O;
    (graph.def_inst(value).and_then(|inst| graph.op(inst)))
        .and_then(SSAOp::operation)
        .is_some_and(|operation| {
            matches!(
                operation,
                O::Equal
                    | O::NotEqual
                    | O::Less
                    | O::SLess
                    | O::LessEqual
                    | O::SLessEqual
                    | O::Carry
                    | O::SCarry
                    | O::SBorrow
                    | O::BoolAnd
                    | O::BoolOr
                    | O::BoolXor
                    | O::BoolNot
            )
        })
}

fn block_fold(graph: &SsaGraph, id: BlockId) -> BlockFold {
    let Some(block) = graph.block(id) else {
        return BlockFold::default();
    };
    let edges = block.predecessors.len();
    // The entry block is also entered by the call, an in-edge no merge arm stands for.
    if id == graph.entry
        || !(2..=Edges::BITS as usize).contains(&edges)
        || graph.phi_insts(id).is_empty()
    {
        return BlockFold::default();
    }
    let conditional = conditional(graph, id);
    let mut fold = BlockFold {
        branch: conditional.map(|(taken, ..)| (taken, ALL, ALL)),
        selects: Vec::new(),
    };
    let selects = (block.insts.iter())
        .filter(|inst| matches!(graph.op(**inst), Some(SSAOp::Select(_))))
        .map(|inst| (*inst, graph.inputs(*inst)[0]));
    fold.selects = selects.clone().map(|(inst, _)| (inst, ALL, ALL)).collect();
    for edge in 0..edges {
        let mut under = Under {
            graph,
            block: id,
            edge,
            held: held_on_edge(graph, block.predecessors[edge], id),
            fuel: 0,
        };
        if let (Some((_, cond, _)), Some((_, taken, not))) = (conditional, fold.branch.as_mut()) {
            under.narrow(cond, taken, not);
        }
        for ((_, cond), (_, when_true, when_false)) in selects.clone().zip(&mut fold.selects) {
            under.narrow(cond, when_true, when_false);
        }
    }
    r2il::refusal_evidence!(
        "edge-fold",
        "block {:#x}: its branch folds to {:?}, its selects to {:?}",
        block.addr,
        fold.branch,
        fold.selects
    );
    fold
}

/// One block entered by one in-edge.
struct Under<'g> {
    graph: &'g SsaGraph,
    block: BlockId,
    edge: usize,
    /// What the in-edge's own branch states of its condition.
    held: Option<Held>,
    fuel: u32,
}

impl Under<'_> {
    /// Drop this in-edge from `when_true` or `when_false` where `cond` folds to the other.
    fn narrow(&mut self, cond: ValueId, when_true: &mut Edges, when_false: &mut Edges) {
        self.fuel = FUEL;
        match self.whole(cond, true) {
            Some(1) => *when_false &= !(1 << self.edge),
            Some(0) => *when_true &= !(1 << self.edge),
            _ => {}
        }
    }

    fn whole(&mut self, value: ValueId, own: bool) -> Option<u64> {
        self.lane(value, 0, self.graph.var(value).size, own)
    }

    /// The `bytes` bytes of `value` from byte `first`, where they fold to a constant. `own` while
    /// the walk is among this block's values: inside an arm its merges are another entry's.
    fn lane(&mut self, value: ValueId, first: u32, bytes: u32, own: bool) -> Option<u64> {
        self.fuel = self.fuel.checked_sub(1)?;
        let var = self.graph.var(value);
        let end = first.checked_add(bytes)?;
        if bytes == 0 || bytes > 8 || end > var.size {
            return None;
        }
        let cut = |bits: u64| match (first, bytes) {
            (8.., _) => None,
            (_, 8) => Some(bits),
            _ => Some((bits >> (8 * first)) & ((1u64 << (8 * bytes)) - 1)),
        };
        if let Some(bits) = var.constant_bits().filter(|_| var.size <= 8) {
            return cut(bits);
        }
        let inst = self.graph.inst(self.graph.def_inst(value)?)?;
        // A condition this block computes again is no longer the one its in-edge branched on.
        if let Some(held) = self.held
            && held.cond == value
            && !(own && inst.block == self.block)
        {
            return cut(held.bits);
        }
        let inputs = self.graph.inputs(inst.id);
        let op = match &inst.payload {
            InstPayload::Phi { predecessors } => {
                // Only this block's merges are the in-edge's arms; an arm's own merges are unknown.
                predecessors
                    .get(self.edge)
                    .filter(|_| own && inst.block == self.block)?;
                return self.lane(*inputs.get(self.edge)?, first, bytes, false);
            }
            InstPayload::Op(op) => op,
        };
        let rule = crate::bytes::rule(op, |value| crate::op::var_facts(self.graph.var(*value)));
        match rule {
            Rule::Copy => self.lane(inputs[0], first, bytes, own),
            Rule::Slice { offset } => self.lane(inputs[0], first.checked_add(offset)?, bytes, own),
            Rule::Extend { sign: false, from } if end <= from => {
                self.lane(inputs[0], first, bytes, own)
            }
            Rule::Extend { sign: false, from } if first >= from => Some(0),
            Rule::Insert {
                first: at,
                lane_bytes,
            } => {
                let lane_end = at.checked_add(lane_bytes)?;
                if first >= at && end <= lane_end {
                    self.lane(inputs[1], first - at, bytes, own)
                } else if end <= at || first >= lane_end {
                    self.lane(inputs[0], first, bytes, own)
                } else {
                    None
                }
            }
            _ => {
                let whole = self.computed(inst, op, own)?;
                (var.size <= 8).then(|| cut(whole))?
            }
        }
    }

    /// What `inst` computes from operands that each fold whole, as `r2il::eval` states it; a
    /// select reads only the arm its folded condition takes.
    fn computed(
        &mut self,
        inst: &crate::graph::GraphInst,
        op: &SSAOp<ValueId>,
        own: bool,
    ) -> Option<u64> {
        let inputs = self.graph.inputs(inst.id);
        if let SSAOp::Select(_) = op {
            return match self.whole(inputs[0], own)? {
                1 => self.whole(inputs[1], own),
                0 => self.whole(inputs[2], own),
                _ => None,
            };
        }
        let folded = (inputs.iter())
            .map(|input| Some((*input, self.whole(*input, own)?)))
            .collect::<Option<Vec<_>>>()?;
        crate::constant::fold_inst(self.graph, inst, |value| {
            (folded.iter()).find_map(|(input, bits)| (*input == value).then_some(*bits))
        })
    }
}

/// What the branch ending `from` states of its condition on its edge into `into`.
fn held_on_edge(graph: &SsaGraph, from: BlockId, into: BlockId) -> Option<Held> {
    let (taken, cond, other) = conditional(graph, from)?;
    if taken == into && boolean(graph, cond) {
        Some(Held { cond, bits: 1 })
    } else if other == into {
        Some(Held { cond, bits: 0 })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::SSAFunction;
    use crate::graph::{SsaGraph, ValueId};
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    const RAX: u64 = 0;
    const RCX: u64 = 8;
    const RDI: u64 = 0x38;
    const FLAG: u64 = 0x300;
    const ZF: u64 = 0x206;

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
        R2ILBlock {
            addr,
            size: 4,
            ops,
            ..R2ILBlock::default()
        }
    }

    fn copy(dst: Varnode, src: Varnode) -> R2ILOp {
        R2ILOp::Copy { dst, src }
    }

    /// `zf = a == 0; if zf goto target`.
    fn branch_if_zero(a: Varnode, target: u64) -> [R2ILOp; 2] {
        let b = Varnode::constant(0, a.size);
        [
            R2ILOp::IntEqual {
                dst: reg(ZF, 1),
                a,
                b,
            },
            R2ILOp::CBranch {
                cond: reg(ZF, 1),
                target: Varnode::constant(target, 8),
            },
        ]
    }

    fn graph_of(blocks: &[R2ILBlock]) -> SsaGraph {
        let mut spec = ArchSpec::new("x86-64");
        spec.addr_size = 8;
        for (name, offset, size) in [
            ("RAX", RAX, 8),
            ("RCX", RCX, 8),
            ("RDI", RDI, 8),
            ("FLAG", FLAG, 1),
            ("ZF", ZF, 1),
        ] {
            spec.add_register(RegisterDef::new(name, offset, size));
        }
        let arch = crate::Arch::new(spec);
        let function = SSAFunction::from_blocks_with_arch(blocks, Some(&arch)).expect("ssa");
        SsaGraph::from_function(&function)
    }

    /// Whether what the operation at `(block, ordinal)` writes depends on the RCX the function
    /// was entered with.
    fn reads_entry_rcx(graph: &SsaGraph, at: (u64, usize)) -> bool {
        let written = (graph.inst_spelled_at(at.0, at.1))
            .and_then(|inst| graph.inst(inst)?.output)
            .expect("an operation with a value");
        let entry = |value: ValueId| {
            let held = graph.value(value).expect("a value");
            graph.def_inst(value).is_none()
                && held.var.version == 0
                && held.canonical_storage.is_some_and(|storage| {
                    storage.space == crate::CanonicalStorageSpace::Register && storage.offset == RCX
                })
        };
        let roots = [(written, crate::bytes::ByteMask::All, super::ALL)];
        let closure = crate::bytes::closure_under(graph, roots);
        closure.values.iter().any(entry)
    }

    /// `flag` is `on_arrival` where RCX is as it arrived and 0 where 7 is written to it; only
    /// `flag == 0` reaches `rax = rcx` at 0x1014.
    fn flagged(on_arrival: R2ILOp) -> SsaGraph {
        let [test, skip] = branch_if_zero(reg(RDI, 8), 0x1008);
        let [flag_test, leave] = branch_if_zero(reg(FLAG, 1), 0x1014);
        let jump = R2ILOp::Branch {
            target: Varnode::constant(0x100c, 8),
        };
        let done = || R2ILOp::Return {
            target: reg(RDI, 8),
        };
        graph_of(&[
            block(0x1000, vec![test, skip]),
            block(0x1004, vec![on_arrival, jump]),
            block(
                0x1008,
                vec![
                    copy(reg(RCX, 8), Varnode::constant(7, 8)),
                    copy(reg(FLAG, 1), Varnode::constant(0, 1)),
                ],
            ),
            block(0x100c, vec![flag_test, leave]),
            block(0x1010, vec![done()]),
            block(0x1014, vec![copy(reg(RAX, 8), reg(RCX, 8)), done()]),
        ])
    }

    #[test]
    fn a_merge_arm_is_unread_where_its_block_never_leaves_to_the_read_under_it() {
        let graph = flagged(copy(reg(FLAG, 1), Varnode::constant(1, 1)));
        assert!(!reads_entry_rcx(&graph, (0x1014, 0)));
    }

    #[test]
    fn a_merge_arm_is_read_where_its_flag_is_no_constant_on_the_edge() {
        let loaded = R2ILOp::Load {
            dst: reg(FLAG, 1),
            space: SpaceId::Ram,
            addr: reg(RDI, 8),
        };
        assert!(reads_entry_rcx(&flagged(loaded), (0x1014, 0)));
    }

    /// `rcx = 7` on the fall-through of a branch on `zf`, then `rax = select(cond, rdi, rcx)`
    /// where the edges merge.
    fn selected(cond: Varnode) -> SsaGraph {
        let [test, skip] = branch_if_zero(reg(RDI, 8), 0x1008);
        let select = R2ILOp::Select {
            dst: reg(RAX, 8),
            cond,
            if_true: reg(RDI, 8),
            if_false: reg(RCX, 8),
        };
        graph_of(&[
            block(0x1000, vec![test, skip]),
            block(0x1004, vec![copy(reg(RCX, 8), Varnode::constant(7, 8))]),
            block(
                0x1008,
                vec![
                    select,
                    R2ILOp::Return {
                        target: reg(RDI, 8),
                    },
                ],
            ),
        ])
    }

    #[test]
    fn a_select_arm_is_unread_on_the_edge_whose_branch_decides_its_condition() {
        // The taken edge holds `zf` at 1 and carries the RCX the function arrived with.
        assert!(!reads_entry_rcx(&selected(reg(ZF, 1)), (0x1008, 0)));
    }

    #[test]
    fn a_select_arm_is_read_where_no_edge_decides_its_condition() {
        assert!(reads_entry_rcx(&selected(reg(FLAG, 1)), (0x1008, 0)));
    }
}
