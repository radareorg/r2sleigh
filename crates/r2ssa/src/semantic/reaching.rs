//! What one storage holds at the points a pass asks: the reaching walk's least fixpoint, solved
//! over the blocks a question needs (doc/adr-next-pass.md, model 2).

use super::*;

/// A storage's state before an instruction, and at the start and end of its machine instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StorageBoundary {
    pub(crate) before: ReachingStorageState,
    pub(crate) instruction_start: ReachingStorageState,
    pub(crate) instruction_end: ReachingStorageState,
    /// No operation of the block before this one writes the storage.
    pub(crate) entered: bool,
}

/// One storage's reaching states, solved where asked.
pub(crate) struct ReachingStorage<'a> {
    function: &'a SSAFunction,
    graph: &'a SsaGraph,
    storage: CanonicalStorageId,
    /// Each solved block's entry state.
    entries: BTreeMap<u64, ReachingStorageState>,
    /// Each block's last write to the storage, where it has one: what it hands its successors.
    kills: BTreeMap<u64, Option<ReachingStorageState>>,
    root_entry: Option<ReachingStorageState>,
    /// Every instruction of each block a query scanned.
    boundaries: crate::dense::IdMap<InstId, StorageBoundary>,
    scanned: BTreeSet<u64>,
}

impl<'a> ReachingStorage<'a> {
    pub(crate) fn new(
        function: &'a SSAFunction,
        graph: &'a SsaGraph,
        storage: CanonicalStorageId,
    ) -> Self {
        Self {
            function,
            graph,
            storage,
            entries: BTreeMap::new(),
            kills: BTreeMap::new(),
            root_entry: None,
            boundaries: crate::dense::IdMap::default(),
            scanned: BTreeSet::new(),
        }
    }

    pub(crate) const fn storage(&self) -> CanonicalStorageId {
        self.storage
    }

    /// The state before `inst`; none for an instruction no block operation is (a phi).
    pub(crate) fn before(&mut self, inst: InstId) -> Option<ReachingStorageState> {
        self.at(inst).map(|boundary| boundary.before)
    }

    /// The states around `inst`. O(its block) the first time its block is asked, O(1) after.
    pub(crate) fn at(&mut self, inst: InstId) -> Option<StorageBoundary> {
        if let Some(boundary) = self.boundaries.get(inst) {
            return Some(*boundary);
        }
        let block = self.graph.block_addr_of(inst)?;
        if self.scanned.insert(block) {
            self.scan(block);
        }
        self.boundaries.get(inst).copied()
    }

    /// The state each predecessor hands `inst`'s block, where nothing in the block writes the
    /// storage before it: a merge keeps no phi of a storage nothing reads there. O(preds).
    pub(crate) fn arriving(&mut self, inst: InstId) -> Vec<ReachingStorageState> {
        let Some(block_addr) = self.graph.block_addr_of(inst) else {
            return Vec::new();
        };
        let entered = self.at(inst).is_some_and(|boundary| boundary.entered);
        if !entered || block_addr == self.function.root() {
            return Vec::new();
        }
        let solved = BTreeMap::new();
        (self.function.predecessors(block_addr).into_iter())
            .map(|predecessor| self.exit(predecessor, &solved))
            .collect()
    }

    fn scan(&mut self, block_addr: u64) {
        let mut state = self.entry(block_addr);
        let Some(block) = self.graph.block_id_for_addr(block_addr) else {
            return;
        };
        // The machine instruction being walked: its stamp, its start state and its insts.
        let mut pending: (Option<u64>, ReachingStorageState, Vec<InstId>) =
            (None, state, Vec::new());
        let mut entered = true;
        for &inst in self.graph.op_insts(block) {
            let instruction = self.graph.instruction_for_inst(inst);
            if instruction.is_none() || instruction != pending.0 {
                self.close(pending.2.drain(..), state);
                pending.0 = instruction;
                pending.1 = state;
            }
            self.boundaries.insert(
                inst,
                StorageBoundary {
                    before: state,
                    instruction_start: pending.1,
                    instruction_end: state,
                    entered,
                },
            );
            pending.2.push(inst);
            let write = written(self.graph, inst, self.storage);
            entered &= write.is_none();
            state = write.unwrap_or(state);
        }
        self.close(pending.2, state);
    }

    /// The machine instruction `insts` make up ends in `end`.
    fn close(&mut self, insts: impl IntoIterator<Item = InstId>, end: ReachingStorageState) {
        for inst in insts {
            if let Some(boundary) = self.boundaries.get_mut(inst) {
                boundary.instruction_end = end;
            }
        }
    }

    /// The state a block hands on where it writes the storage: its last write decides it.
    fn kill(&mut self, block_addr: u64) -> Option<ReachingStorageState> {
        if let Some(kill) = self.kills.get(&block_addr) {
            return *kill;
        }
        let kill = match self.graph.block_id_for_addr(block_addr) {
            None => Some(ReachingStorageState::Conflict),
            Some(block) => (self.graph.op_insts(block).iter().rev())
                .find_map(|inst| written(self.graph, *inst, self.storage)),
        };
        self.kills.insert(block_addr, kill);
        kill
    }

    fn entry(&mut self, block_addr: u64) -> ReachingStorageState {
        if let Some(state) = self.entries.get(&block_addr) {
            return *state;
        }
        let root = self.function.root();
        // The region: each unsolved block whose entry this one needs, with its predecessors.
        let mut region = BTreeMap::<u64, Vec<u64>>::new();
        let mut stack = vec![block_addr];
        while let Some(block) = stack.pop() {
            if region.contains_key(&block) || self.entries.contains_key(&block) {
                continue;
            }
            let predecessors = match block == root {
                true => Vec::new(),
                false => self.function.predecessors(block),
            };
            let unsolved = predecessors.iter().copied().filter(|predecessor| {
                !self.entries.contains_key(predecessor) && self.kill(*predecessor).is_none()
            });
            stack.extend(unsolved);
            region.insert(block, predecessors);
        }
        // A transparent block's entry is its exit, read by its successors in the region.
        let mut readers = BTreeMap::<u64, Vec<u64>>::new();
        let edges = region.iter().flat_map(|(block, predecessors)| {
            predecessors
                .iter()
                .map(move |predecessor| (*predecessor, *block))
        });
        for (predecessor, block) in
            edges.filter(|(predecessor, _)| region.contains_key(predecessor))
        {
            readers.entry(predecessor).or_default().push(block);
        }
        // The walk's worklist over the region: each entry rises from `Unknown` at most twice.
        let mut solving = region
            .keys()
            .map(|block| (*block, ReachingStorageState::Unknown))
            .collect::<BTreeMap<_, _>>();
        let mut pending = region.keys().copied().collect::<BTreeSet<_>>();
        while let Some(block) = pending.pop_first() {
            let state = self.join(block, &region[&block], &solving);
            if solving.insert(block, state) == Some(state) {
                continue;
            }
            if self.kill(block).is_none() {
                pending.extend(readers.get(&block).into_iter().flatten().copied());
            }
        }
        self.entries.extend(solving);
        self.entries[&block_addr]
    }

    /// A block's entry from its predecessors' exits, as the reaching walk joined them.
    fn join(
        &mut self,
        block_addr: u64,
        predecessors: &[u64],
        solving: &BTreeMap<u64, ReachingStorageState>,
    ) -> ReachingStorageState {
        if block_addr == self.function.root() {
            return *self
                .root_entry
                .get_or_insert_with(|| entry_storage_state(self.graph, self.storage));
        }
        if predecessors.is_empty() {
            return ReachingStorageState::Conflict;
        }
        let known = predecessors
            .iter()
            .map(|predecessor| self.exit(*predecessor, solving))
            .filter(|state| *state != ReachingStorageState::Unknown)
            .collect::<Vec<_>>();
        let Some(first) = known.first().copied() else {
            return ReachingStorageState::Unknown;
        };
        if known.contains(&ReachingStorageState::Conflict) {
            return ReachingStorageState::Conflict;
        }
        match storage_phi_value(self.graph, block_addr, self.storage) {
            Ok(Some(value)) => ReachingStorageState::Value(value),
            Err(()) => ReachingStorageState::Conflict,
            Ok(None) if known.iter().all(|state| *state == first) => first,
            Ok(None) => ReachingStorageState::Conflict,
        }
    }

    fn exit(
        &mut self,
        block_addr: u64,
        solving: &BTreeMap<u64, ReachingStorageState>,
    ) -> ReachingStorageState {
        if let Some(kill) = self.kill(block_addr) {
            return kill;
        }
        solving
            .get(&block_addr)
            .or_else(|| self.entries.get(&block_addr))
            .copied()
            .unwrap_or(ReachingStorageState::Unknown)
    }
}

/// The state an operation leaves the storage in, where it decides one: a write of the storage
/// is its value, a write of part of it or an operation the graph lost is a conflict.
fn written(
    graph: &SsaGraph,
    inst: InstId,
    storage: CanonicalStorageId,
) -> Option<ReachingStorageState> {
    let Some(inst) = graph.inst(inst) else {
        return Some(ReachingStorageState::Conflict);
    };
    let written = graph.written_storage(inst)?;
    if !register_storages_overlap(written, storage) {
        return None;
    }
    if written != storage {
        return Some(ReachingStorageState::Conflict);
    }
    Some(
        inst.output
            .map(ReachingStorageState::Value)
            .unwrap_or(ReachingStorageState::Conflict),
    )
}

fn entry_storage_state(graph: &SsaGraph, storage: CanonicalStorageId) -> ReachingStorageState {
    let candidates = graph
        .values
        .iter()
        .filter(|value| {
            graph.def_inst(value.id).is_none()
                && value.var.version == 0
                && value.var.size == storage.size
                && value.canonical_storage == Some(storage)
        })
        .map(|value| value.id)
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [value] => ReachingStorageState::Value(*value),
        [] => ReachingStorageState::PreservedEntry,
        _ => ReachingStorageState::Conflict,
    }
}

fn storage_phi_value(
    graph: &SsaGraph,
    block_addr: u64,
    storage: CanonicalStorageId,
) -> Result<Option<ValueId>, ()> {
    let block = graph.block_id_for_addr(block_addr).ok_or(())?;
    let values = (graph.phi_insts(block).iter())
        .filter_map(|phi| graph.inst(*phi))
        .filter(|phi| graph.written_storage(phi) == Some(storage))
        .filter_map(|phi| phi.output)
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn ssa(blocks: &[R2ILBlock]) -> SSAFunction {
        let mut arch = ArchSpec::new("reaching");
        arch.add_register(RegisterDef::new("x", 0, 8));
        arch.add_register(RegisterDef::new("y", 8, 8));
        arch.add_register(RegisterDef::new("cond", 32, 1));
        arch.add_register(RegisterDef::new("pc", 0x80, 8));
        SSAFunction::from_blocks_raw(blocks, Some(&crate::Arch::from(arch))).expect("fixture SSA")
    }

    fn function(blocks: &[R2ILBlock]) -> (SSAFunction, SsaGraph) {
        let function = ssa(blocks);
        let graph = SsaGraph::from_function_with_storage(&function);
        (function, graph)
    }

    fn copy(dst: Varnode, src: Varnode) -> R2ILOp {
        R2ILOp::Copy { dst, src }
    }

    fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
        let mut block = R2ILBlock::new(addr, 4);
        for op in ops {
            block.push(op);
        }
        block
    }

    /// The instructions of a block in order, and the storage `x` is, read off its write.
    fn insts(graph: &SsaGraph, addr: u64) -> Vec<InstId> {
        graph
            .op_insts(graph.block_id_for_addr(addr).expect("block"))
            .to_vec()
    }

    fn written_storage(graph: &SsaGraph, inst: InstId) -> (CanonicalStorageId, ValueId) {
        let inst = graph.inst(inst).expect("inst");
        (
            graph.written_storage(inst).expect("storage"),
            inst.output.expect("output"),
        )
    }

    #[test]
    fn a_value_reaches_round_a_loop_whose_latch_does_not_write_it() {
        let branch = |target| R2ILOp::Branch {
            target: Varnode::constant(target, 8),
        };
        let (function, graph) = function(&[
            block(
                0x1000,
                vec![copy(reg(0, 8), Varnode::constant(7, 8)), branch(0x1004)],
            ),
            block(
                0x1004,
                vec![R2ILOp::CBranch {
                    target: Varnode::constant(0x100c, 8),
                    cond: reg(32, 1),
                }],
            ),
            block(0x1008, vec![copy(reg(8, 8), reg(0, 8)), branch(0x1004)]),
            block(
                0x100c,
                vec![R2ILOp::Return {
                    target: reg(0x80, 8),
                }],
            ),
        ]);
        let (x, seven) = written_storage(&graph, insts(&graph, 0x1000)[0]);
        let mut reaching = ReachingStorage::new(&function, &graph, x);
        // The latch is asked first: its entry is its header's, which the latch's own exit feeds.
        let latch = insts(&graph, 0x1008)[0];
        assert_eq!(
            reaching.before(latch),
            Some(ReachingStorageState::Value(seven))
        );
        let header = insts(&graph, 0x1004)[0];
        assert_eq!(
            reaching.before(header),
            Some(ReachingStorageState::Value(seven))
        );
    }

    #[test]
    fn a_merge_of_two_writes_with_no_phi_is_a_conflict() {
        let branch = |target| R2ILOp::Branch {
            target: Varnode::constant(target, 8),
        };
        let (function, graph) = function(&[
            block(
                0x1000,
                vec![R2ILOp::CBranch {
                    target: Varnode::constant(0x1008, 8),
                    cond: reg(32, 1),
                }],
            ),
            block(
                0x1004,
                vec![copy(reg(0, 8), Varnode::constant(1, 8)), branch(0x100c)],
            ),
            block(
                0x1008,
                vec![copy(reg(0, 8), Varnode::constant(2, 8)), branch(0x100c)],
            ),
            block(
                0x100c,
                vec![
                    copy(reg(8, 8), Varnode::constant(3, 8)),
                    R2ILOp::Return {
                        target: reg(0x80, 8),
                    },
                ],
            ),
        ]);
        let (x, _) = written_storage(&graph, insts(&graph, 0x1004)[0]);
        // A merge nothing reads after keeps no phi once a pass drops it; the arms then disagree.
        let mut function = function;
        function
            .edit_block(0x100c)
            .expect("merge")
            .retain_phis(crate::Pass::Fixture, |phi| phi.canonical_storage != Some(x));
        let graph = SsaGraph::from_function_with_storage(&function);
        let mut reaching = ReachingStorage::new(&function, &graph, x);
        let merge = insts(&graph, 0x100c)[0];
        assert_eq!(reaching.before(merge), Some(ReachingStorageState::Conflict));
    }

    #[test]
    fn a_write_inside_a_block_decides_the_points_after_it() {
        let (function, graph) = function(&[block(
            0x1000,
            vec![
                copy(reg(8, 8), Varnode::constant(1, 8)),
                copy(reg(0, 8), Varnode::constant(5, 8)),
                copy(reg(8, 8), Varnode::constant(2, 8)),
                R2ILOp::Return {
                    target: reg(0x80, 8),
                },
            ],
        )]);
        let insts = insts(&graph, 0x1000);
        let (x, five) = written_storage(&graph, insts[1]);
        let mut reaching = ReachingStorage::new(&function, &graph, x);
        let first = reaching.at(insts[0]).expect("first");
        let write = reaching.at(insts[1]).expect("write");
        let third = reaching.at(insts[2]).expect("third");
        assert_ne!(first.before, ReachingStorageState::Value(five));
        assert_eq!(third.before, ReachingStorageState::Value(five));
        // An operation no machine instruction stamps is an instruction of its own.
        assert_eq!(write.instruction_start, first.before);
        assert_eq!(write.instruction_end, ReachingStorageState::Value(five));
        assert_eq!(third.instruction_start, third.before);
    }
    #[test]
    fn an_operation_derived_for_an_instruction_is_read_as_part_of_it() {
        let mut lifted = block(
            0x1000,
            vec![
                copy(reg(8, 8), Varnode::constant(1, 8)),
                copy(reg(0, 8), Varnode::constant(5, 8)),
            ],
        );
        lifted.stamp_instruction(0, 0x1000);
        lifted.stamp_instruction(1, 0x1004);
        let mut function = ssa(&[lifted]);
        let write = (function.blocks()[0].sited().nth(1))
            .map(|(id, _)| id)
            .expect("write");
        // A pass adds an operation on behalf of the write: the graph says it executes for 0x1004.
        let scratch = crate::SSAVar::new("tmp:9000", 1, 8);
        (function.edit_block(0x1000).expect("block")).push_op(
            SSAOp::Copy {
                dst: scratch,
                src: crate::SSAVar::constant(7, 8),
            },
            Some(write),
            crate::Pass::Fixture,
        );
        let graph = SsaGraph::from_function_with_storage(&function);
        let insts = insts(&graph, 0x1000);
        assert_eq!(graph.instruction_for_inst(insts[2]), Some(0x1004));
        let (x, five) = written_storage(&graph, insts[1]);
        let mut reaching = ReachingStorage::new(&function, &graph, x);
        let written = reaching.at(insts[1]).expect("write");
        let derived = reaching.at(insts[2]).expect("derived");
        // It starts where its instruction starts, before the write, and ends where it ends.
        assert_eq!(derived.instruction_start, written.instruction_start);
        assert_ne!(derived.instruction_start, ReachingStorageState::Value(five));
        assert_eq!(written.instruction_end, ReachingStorageState::Value(five));
    }
}
