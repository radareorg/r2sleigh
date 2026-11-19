//! The constant a register holds where a call reads it, off the walk's own lift: reaching
//! definitions, then each definition folded, `O((B + E) x k)` (D590, doc/adr-radare2-function-walk.md).

use std::collections::BTreeMap;

use r2il::eval::independence::{Known, Operand, ignored_operands};
use r2il::eval::{Operation, Word, apply};
use r2il::{Endianness, R2ILOp, SpaceId, Varnode};
use r2source::{CanonicalStorageId, CanonicalStorageSpace};

use crate::site_boundary::Lifted;

/// One storage read before one operation of a body: block and operation by index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seed {
    pub block: usize,
    pub op: usize,
    pub storage: CanonicalStorageId,
}

/// What reaches a seed: one definition that folds to a constant, or the witness that none does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaching {
    Constant(u64),
    NotConstant(Unreached),
}

/// Why no constant reaches a seed, at the operation or block that decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreached {
    /// The function's entry value, which its caller supplies.
    Entry,
    /// A load writes the storage: memory no lift-grade reader states.
    Load { block: usize, op: usize },
    /// A call may write the storage under its convention.
    Call { block: usize, op: usize },
    /// Two definitions meet at this block: a merge, which the seal folds to nothing.
    Join { block: usize },
    /// An operation writes part of the storage, or computes what `r2il::eval` does not fold.
    Written { block: usize, op: usize },
    /// No path from the entry reaches the seed.
    Unreachable,
}

/// The read-only words the capture would hold for the body, and the machine's byte order: a load
/// at a literal address of these reads them on every run, as the seal folds it (`read_only.rs`).
pub struct Memory {
    windows: BTreeMap<u64, Box<[u8]>>,
    endian: Endianness,
}

impl Memory {
    pub fn new(windows: Vec<(u64, Vec<u8>)>, endian: Endianness) -> Self {
        let windows = (windows.into_iter())
            .map(|(address, bytes)| (address, bytes.into_boxed_slice()))
            .collect();
        Self { windows, endian }
    }

    fn bits(&self, address: u64, size: u32) -> Option<u64> {
        crate::read_only::bits_in(&self.windows, address, size, self.endian.into())
    }

    /// How far up from the low byte `inner` sits inside `outer`, in bytes, as registers lay out;
    /// none in a byte order neither big nor little.
    fn shift(&self, outer: &Varnode, inner: &Varnode) -> Option<u64> {
        let end = |varnode: &Varnode| varnode.offset + u64::from(varnode.size);
        match self.endian {
            Endianness::Big => Some(end(outer) - end(inner)),
            Endianness::Little => Some(inner.offset - outer.offset),
            Endianness::Mixed | Endianness::Custom => None,
        }
    }
}

/// A body's blocks and the flow between them, as the walk states it.
pub struct Flow<'a, B> {
    blocks: &'a [B],
    entry: usize,
    /// Each block's predecessors: `items[starts[b]..starts[b + 1]]`.
    starts: Vec<u32>,
    items: Vec<u32>,
}

impl<'a, B: Lifted> Flow<'a, B> {
    /// `edges` are `(block, address control reaches after it)`; an address no block starts at is
    /// no edge. `entry` is the block the function is entered at.
    pub fn new(
        blocks: &'a [B],
        entry: usize,
        edges: impl IntoIterator<Item = (usize, u64)>,
    ) -> Self {
        let mut starts = (blocks.iter().enumerate())
            .map(|(at, block)| (block.lifted().addr, at))
            .collect::<Vec<_>>();
        starts.sort_unstable();
        let block_at = |address: u64| {
            let at = starts.binary_search_by_key(&address, |(start, _)| *start);
            at.ok().map(|at| starts[at].1)
        };
        let mut pairs = (edges.into_iter())
            .filter_map(|(from, address)| Some((index(block_at(address)?), index(from))))
            .collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs.dedup();
        let mut offsets = vec![0u32; blocks.len() + 1];
        for (to, _) in &pairs {
            offsets[*to as usize + 1] += 1;
        }
        for at in 0..blocks.len() {
            offsets[at + 1] += offsets[at];
        }
        Self {
            blocks,
            entry,
            starts: offsets,
            items: pairs.into_iter().map(|(_, from)| from).collect(),
        }
    }

    fn predecessors(&self, block: usize) -> &[u32] {
        &self.items[self.starts[block] as usize..self.starts[block + 1] as usize]
    }

    fn ops(&self, block: usize) -> &[R2ILOp] {
        &self.blocks[block].lifted().ops
    }
}

fn index(at: usize) -> u32 {
    u32::try_from(at).expect("fewer than 2^32 blocks")
}

/// The constant each seed reads, in seed order. `call_writes` says whether a call may write a
/// register storage, as the convention the calls run under states it.
pub fn reaching_constants<B: Lifted>(
    flow: &Flow<'_, B>,
    (call_writes, memory): (&dyn Fn(CanonicalStorageId) -> bool, &Memory),
    seeds: &[Seed],
) -> Vec<Reaching> {
    let mut solver = Solver {
        flow,
        call_writes,
        memory,
        nodes: Vec::new(),
        node_of: BTreeMap::new(),
        incoming: Vec::new(),
        defs: Vec::new(),
        def_of: BTreeMap::new(),
        pending: Vec::new(),
    };
    let roots = (seeds.iter())
        .map(|seed| match varnode_of(seed.storage) {
            Some(storage) => solver.before(seed.block, seed.op, &storage),
            None => Reach::Stop(Unreached::Written {
                block: seed.block,
                op: seed.op,
            }),
        })
        .collect::<Vec<_>>();
    solver.expand();
    let reached = solver.solve();
    let mut folded = Folded {
        values: vec![None; solver.defs.len()],
        open: vec![false; solver.defs.len()],
    };
    let answers = roots
        .iter()
        .map(|root| match solver.value(*root, &reached, &mut folded) {
            Ok(value) => Reaching::Constant(value),
            Err(why) => Reaching::NotConstant(why),
        });
    answers.collect()
}

/// The lift's varnode for a storage; none for one no lift names.
fn varnode_of(storage: CanonicalStorageId) -> Option<Varnode> {
    let space = match storage.space {
        CanonicalStorageSpace::Register => SpaceId::Register,
        CanonicalStorageSpace::Unique => SpaceId::Unique,
        CanonicalStorageSpace::Ram => SpaceId::Ram,
        CanonicalStorageSpace::Constant => SpaceId::Const,
        CanonicalStorageSpace::Custom(id) => SpaceId::Custom(id),
        CanonicalStorageSpace::Unknown => return None,
    };
    Some(Varnode {
        space,
        offset: storage.offset,
        size: storage.size,
    })
}

fn storage_of(varnode: &Varnode) -> Option<CanonicalStorageId> {
    (varnode.space == SpaceId::Register).then_some(CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: varnode.offset,
        size: varnode.size,
    })
}

/// A space's place in a key's order.
const fn space_key(space: SpaceId) -> (u8, u32) {
    match space {
        SpaceId::Ram => (0, 0),
        SpaceId::Register => (1, 0),
        SpaceId::Unique => (2, 0),
        SpaceId::Const => (3, 0),
        SpaceId::Custom(id) => (4, id),
    }
}

fn key(block: usize, storage: &Varnode) -> (usize, (u8, u32), u64, u32) {
    (
        block,
        space_key(storage.space),
        storage.offset,
        storage.size,
    )
}

fn overlaps(a: &Varnode, b: &Varnode) -> bool {
    a.space == b.space
        && a.offset < b.offset.saturating_add(u64::from(b.size))
        && b.offset < a.offset.saturating_add(u64::from(a.size))
}

/// Where a storage's value at one point comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A literal operand.
    Literal(u64),
    /// The definition at this index of `Solver::defs`.
    Def(u32),
    /// `bytes` of the definition at this index, `shift` bytes up from its low byte: a wider write
    /// read narrower.
    Lane { def: u32, shift: u64, bytes: u32 },
    /// A block's entry value of one storage: the node at this index.
    Node(u32),
    /// A definition no fold reads through, with its witness.
    Stop(Unreached),
}

/// The definitions reaching one block entry: `Top` until a path brings one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    Top,
    One(Reach),
    Many,
}

impl Reached {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Top, other) | (other, Self::Top) => other,
            (Self::One(a), Self::One(b)) if a == b => self,
            _ => Self::Many,
        }
    }
}

/// One operation that writes a storage the reader asked, and where each of its inputs comes from.
#[derive(Debug, Clone)]
struct Def {
    block: usize,
    op: usize,
    inputs: Vec<(Reach, Varnode)>,
}

/// Each definition's fold, computed once per call; `open` marks one being folded.
struct Folded {
    values: Vec<Option<Result<u64, Unreached>>>,
    open: Vec<bool>,
}

struct Solver<'s, 'a, B> {
    flow: &'s Flow<'a, B>,
    call_writes: &'s dyn Fn(CanonicalStorageId) -> bool,
    memory: &'s Memory,
    /// Each demanded block entry: the block and the storage.
    nodes: Vec<(usize, Varnode)>,
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "the demand graph of one body, keyed by block and varnode"
        )
    )]
    node_of: BTreeMap<(usize, (u8, u32), u64, u32), u32>,
    /// Each node's reach at the exit of each predecessor; filled by `expand`.
    incoming: Vec<Vec<Reach>>,
    defs: Vec<Def>,
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "the definitions one body's demand reads, by block and op"
        )
    )]
    def_of: BTreeMap<(usize, usize), u32>,
    pending: Vec<Pending>,
}

/// Work `expand` has left: a node's predecessors, or a definition's inputs.
#[derive(Debug, Clone, Copy)]
enum Pending {
    Node(u32),
    Def(u32),
}

impl<B: Lifted> Solver<'_, '_, B> {
    fn node(&mut self, block: usize, storage: &Varnode) -> u32 {
        if let Some(node) = self.node_of.get(&key(block, storage)) {
            return *node;
        }
        let node = u32::try_from(self.nodes.len()).expect("fewer than 2^32 demands");
        self.nodes.push((block, storage.clone()));
        self.incoming.push(Vec::new());
        self.node_of.insert(key(block, storage), node);
        self.pending.push(Pending::Node(node));
        node
    }

    fn def(&mut self, block: usize, op: usize) -> u32 {
        if let Some(def) = self.def_of.get(&(block, op)) {
            return *def;
        }
        let def = u32::try_from(self.defs.len()).expect("fewer than 2^32 definitions");
        self.defs.push(Def {
            block,
            op,
            inputs: Vec::new(),
        });
        self.def_of.insert((block, op), def);
        self.pending.push(Pending::Def(def));
        def
    }

    /// Where `storage`'s value before operation `op` of `block` comes from: the last write in the
    /// block, else the block's entry. `O(op)`.
    fn before(&mut self, block: usize, op: usize, storage: &Varnode) -> Reach {
        let flow = self.flow;
        for at in (0..op).rev() {
            let operation = &flow.ops(block)[at];
            if operation.is_call()
                && storage_of(storage).is_some_and(|storage| (self.call_writes)(storage))
            {
                return Reach::Stop(Unreached::Call { block, op: at });
            }
            let Some(dst) = operation.output() else {
                continue;
            };
            if !overlaps(dst, storage) {
                continue;
            }
            let covers = dst.offset <= storage.offset
                && storage.offset + u64::from(storage.size) <= dst.offset + u64::from(dst.size);
            let literal = |addr: &Varnode| addr.space == SpaceId::Const;
            let def = match operation {
                R2ILOp::Load { addr, .. } if literal(addr) => self.def(block, at),
                R2ILOp::Load { .. } => return Reach::Stop(Unreached::Load { block, op: at }),
                _ => self.def(block, at),
            };
            let shift = covers.then(|| self.memory.shift(dst, storage)).flatten();
            return match (dst == storage, shift) {
                (true, _) => Reach::Def(def),
                (false, Some(shift)) => Reach::Lane {
                    def,
                    shift,
                    bytes: storage.size,
                },
                (false, None) => Reach::Stop(Unreached::Written { block, op: at }),
            };
        }
        match block == flow.entry {
            true => Reach::Stop(Unreached::Entry),
            false => Reach::Node(self.node(block, storage)),
        }
    }

    /// Every demanded node's predecessors and every definition's inputs, each read once.
    /// Terminates: each (block, storage) node and each (block, op) definition is queued once.
    fn expand(&mut self) {
        while let Some(pending) = self.pending.pop() {
            match pending {
                Pending::Node(node) => {
                    let (block, storage) = self.nodes[node as usize].clone();
                    let predecessors = self.flow.predecessors(block).to_vec();
                    let exits = (predecessors.iter())
                        .map(|from| {
                            let from = *from as usize;
                            self.before(from, self.flow.ops(from).len(), &storage)
                        })
                        .collect();
                    self.incoming[node as usize] = exits;
                }
                Pending::Def(def) => {
                    let Def { block, op, .. } = self.defs[def as usize];
                    let operation = &self.flow.ops(block)[op];
                    let Some((_, _, inputs)) = Operation::of(operation) else {
                        continue;
                    };
                    let inputs = inputs.into_iter().cloned().collect::<Vec<_>>();
                    let reaches = (inputs.into_iter())
                        .map(|input| {
                            let reach = match input.space {
                                SpaceId::Const => Reach::Literal(input.offset),
                                _ => self.before(block, op, &input),
                            };
                            (reach, input)
                        })
                        .collect();
                    self.defs[def as usize].inputs = reaches;
                }
            }
        }
    }

    /// The definitions reaching each node, least fixpoint from `Top`. Terminates: a node only
    /// falls, `Top` to one definition to many, so it re-queues its dependents at most twice.
    fn solve(&self) -> Vec<Reached> {
        let mut reached = vec![Reached::Top; self.nodes.len()];
        let mut dependents = vec![Vec::new(); self.nodes.len()];
        for (node, reaches) in self.incoming.iter().enumerate() {
            for reach in reaches {
                if let Reach::Node(read) = reach {
                    dependents[*read as usize].push(node);
                }
            }
        }
        let mut queued = vec![true; self.nodes.len()];
        let mut queue = (0..self.nodes.len()).collect::<std::collections::VecDeque<_>>();
        while let Some(node) = queue.pop_front() {
            queued[node] = false;
            let joined = (self.incoming[node].iter())
                .map(|reach| match reach {
                    Reach::Node(read) => reached[*read as usize],
                    other => Reached::One(*other),
                })
                .fold(Reached::Top, Reached::join);
            if joined == reached[node] {
                continue;
            }
            reached[node] = joined;
            for dependent in &dependents[node] {
                if !queued[*dependent] {
                    queued[*dependent] = true;
                    queue.push_back(*dependent);
                }
            }
        }
        reached
    }

    /// The constant `reach` folds to, or why it does not.
    fn value(
        &self,
        reach: Reach,
        reached: &[Reached],
        folded: &mut Folded,
    ) -> Result<u64, Unreached> {
        match reach {
            Reach::Literal(value) => Ok(value),
            Reach::Stop(why) => Err(why),
            Reach::Def(def) => self.fold(def, reached, folded),
            Reach::Lane { def, shift, bytes } => {
                let bits = self.fold(def, reached, folded)?;
                let shifted = bits.checked_shr(u32::try_from(8 * shift).unwrap_or(u32::MAX));
                let mask = 1u64.checked_shl(8 * bytes).map_or(u64::MAX, |bit| bit - 1);
                Ok(shifted.unwrap_or(0) & mask)
            }
            Reach::Node(node) => match reached[node as usize] {
                Reached::Top => Err(Unreached::Unreachable),
                Reached::Many => Err(Unreached::Join {
                    block: self.nodes[node as usize].0,
                }),
                Reached::One(Reach::Node(_)) => Err(Unreached::Unreachable),
                Reached::One(reach) => self.value(reach, reached, folded),
            },
        }
    }

    /// What `operation` computes from `inputs`: an input the result ignores by `r2il`'s
    /// independence (`x ^ x`, `x & 0`) need not fold, as the seal's identities read it.
    fn computed(
        &self,
        operation: Operation,
        width: u32,
        inputs: &[(Reach, Varnode)],
        (reached, folded): (&[Reached], &mut Folded),
    ) -> Option<Result<u64, Unreached>> {
        let values = (inputs.iter())
            .map(|(reach, _)| self.value(*reach, reached, folded))
            .collect::<Vec<_>>();
        let same = |at: usize| {
            inputs[..at]
                .iter()
                .position(|(_, varnode)| *varnode == inputs[at].1)
        };
        let operands = (values.iter().enumerate())
            .map(|(at, value)| Operand {
                bytes: inputs[at].1.size,
                known: match (value, same(at)) {
                    (Ok(value), _) => Known::Value(u128::from(*value)),
                    (Err(_), Some(earlier)) => Known::Same(earlier),
                    (Err(_), None) => Known::Nothing,
                },
            })
            .collect::<Vec<_>>();
        let ignored = ignored_operands(operation, &operands);
        let mut words = Vec::with_capacity(values.len());
        for (at, (value, operand)) in values.iter().zip(&operands).enumerate() {
            let bits = match (value, ignored >> at & 1 == 1) {
                (_, true) => 0,
                (Ok(value), false) => u128::from(*value),
                (Err(why), false) => return Some(Err(*why)),
            };
            words.push(Word::new(bits, operand.bytes).ok()?);
        }
        let value = apply(operation, &words, width).ok()?;
        Some(Ok(u64::try_from(value).ok()?))
    }

    /// One definition folded with `r2il::eval` from its inputs; a definition reached again while
    /// it folds reads itself round a cycle, which no entry path does, so it folds to nothing.
    fn fold(&self, def: u32, reached: &[Reached], folded: &mut Folded) -> Result<u64, Unreached> {
        let at = def as usize;
        if let Some(value) = folded.values[at] {
            return value;
        }
        let Def { block, op, .. } = self.defs[at];
        let written = Unreached::Written { block, op };
        if folded.open[at] {
            return Err(Unreached::Unreachable);
        }
        folded.open[at] = true;
        let operation = &self.flow.ops(block)[op];
        let value = match (operation, Operation::of(operation)) {
            (R2ILOp::Load { addr, dst, .. }, _) => {
                (self.memory.bits(addr.offset, dst.size)).ok_or(Unreached::Load { block, op })
            }
            (_, None) => Err(written),
            (_, Some((operation, dst, _))) => self
                .computed(
                    operation,
                    dst.size,
                    &self.defs[at].inputs,
                    (reached, folded),
                )
                .ok_or(written)
                .and_then(|value| value),
        };
        folded.open[at] = false;
        folded.values[at] = Some(value);
        value
    }
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, RegisterDef};

    use super::*;
    use crate::{DecompileInputs, SsaArtifact};

    const RAX: u64 = 0;
    const RDI: u64 = 8;
    const RBX: u64 = 32;

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Register,
            offset,
            size,
        }
    }

    fn constant(value: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId::Const,
            offset: value,
            size,
        }
    }

    fn storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn set(offset: u64, value: u64) -> R2ILOp {
        R2ILOp::Copy {
            dst: reg(offset, 8),
            src: constant(value, 8),
        }
    }

    fn call(target: u64) -> R2ILOp {
        R2ILOp::Call {
            target: Varnode {
                space: SpaceId::Ram,
                offset: target,
                size: 8,
            },
        }
    }

    fn branch(target: u64) -> R2ILOp {
        R2ILOp::Branch {
            target: Varnode {
                space: SpaceId::Ram,
                offset: target,
                size: 8,
            },
        }
    }

    fn cbranch(target: u64) -> R2ILOp {
        R2ILOp::CBranch {
            target: Varnode {
                space: SpaceId::Ram,
                offset: target,
                size: 8,
            },
            cond: reg(RAX, 1),
        }
    }

    fn ret() -> R2ILOp {
        R2ILOp::Return {
            target: constant(0, 8),
        }
    }

    fn arch() -> crate::Arch {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rax", RAX, 8));
        arch.add_register(RegisterDef::new("al", RAX, 1));
        arch.add_register(RegisterDef::new("eax", RAX, 4));
        arch.add_register(RegisterDef::new("rdi", RDI, 8));
        arch.add_register(RegisterDef::new("edi", RDI, 4));
        arch.add_register(RegisterDef::new("rbx", RBX, 8));
        crate::Arch::new(std::sync::Arc::new(arch))
    }

    /// Calls clobber rax and rdi and keep rbx.
    fn writes(storage: CanonicalStorageId) -> bool {
        storage.offset < RBX
    }

    /// The reader's answer for rdi before the first call of the block at `site`, and the seal's.
    fn both(blocks: &[(u64, Vec<R2ILOp>, Vec<u64>)], site: u64) -> (Reaching, Option<u64>) {
        let lifted = (blocks.iter())
            .map(|(addr, ops, _)| R2ILBlock {
                addr: *addr,
                size: 16,
                ops: ops.clone(),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let edges = (blocks.iter().enumerate())
            .flat_map(|(at, (_, _, to))| to.iter().map(move |to| (at, *to)));
        let flow = Flow::new(&lifted, 0, edges);
        let block = blocks
            .iter()
            .position(|(addr, ..)| *addr == site)
            .expect("site block");
        let op = blocks[block]
            .1
            .iter()
            .position(R2ILOp::is_call)
            .expect("a call");
        let seed = Seed {
            block,
            op,
            storage: storage(RDI, 8),
        };
        let memory = Memory::new(Vec::new(), Endianness::Little);
        let reader = reaching_constants(&flow, (&writes, &memory), &[seed])[0];
        let conventions =
            crate::testing::conventions([storage(RAX, 8), storage(RDI, 8)], [storage(RBX, 8)]);
        let arch = arch();
        let inputs = DecompileInputs {
            arch: Some(&arch),
            conventions,
            ..Default::default()
        };
        let artifact = SsaArtifact::for_decompile_with(&lifted, inputs).expect("artifact");
        (
            reader,
            artifact.folded_before_first_call(site, storage(RDI, 8)),
        )
    }

    /// The reader folds where the seal folds, to the same constant, and nowhere else.
    fn agrees((reader, sealed): (Reaching, Option<u64>)) -> Reaching {
        let read = match reader {
            Reaching::Constant(value) => Some(value),
            Reaching::NotConstant(_) => None,
        };
        assert_eq!(read, sealed, "reader {reader:?}, seal {sealed:?}");
        reader
    }

    #[test]
    fn a_constant_crosses_a_block_edge() {
        let blocks = [
            (0x1000, vec![set(RDI, 0x4000), branch(0x1010)], vec![0x1010]),
            (0x1010, vec![call(0x9000), ret()], vec![]),
        ];
        assert_eq!(agrees(both(&blocks, 0x1010)), Reaching::Constant(0x4000));
    }

    #[test]
    fn two_constants_at_a_join_are_none() {
        let blocks = [
            (0x1000, vec![cbranch(0x1020)], vec![0x1010, 0x1020]),
            (0x1010, vec![set(RDI, 0x4000), branch(0x1030)], vec![0x1030]),
            (0x1020, vec![set(RDI, 0x5000), branch(0x1030)], vec![0x1030]),
            (0x1030, vec![call(0x9000), ret()], vec![]),
        ];
        let reader = agrees(both(&blocks, 0x1030));
        assert_eq!(reader, Reaching::NotConstant(Unreached::Join { block: 3 }));
    }

    /// Two definitions of one constant still merge, and the seal folds a merge to nothing.
    #[test]
    fn one_constant_from_two_definitions_is_a_merge() {
        let blocks = [
            (0x1000, vec![cbranch(0x1020)], vec![0x1010, 0x1020]),
            (0x1010, vec![set(RDI, 0x4000), branch(0x1030)], vec![0x1030]),
            (0x1020, vec![set(RDI, 0x4000), branch(0x1030)], vec![0x1030]),
            (0x1030, vec![call(0x9000), ret()], vec![]),
        ];
        let reader = agrees(both(&blocks, 0x1030));
        assert_eq!(reader, Reaching::NotConstant(Unreached::Join { block: 3 }));
    }

    /// One definition reaching a block along two paths is no merge.
    #[test]
    fn one_definition_on_two_paths_holds() {
        let blocks = [
            (
                0x1000,
                vec![set(RDI, 0x4000), cbranch(0x1020)],
                vec![0x1010, 0x1020],
            ),
            (0x1010, vec![branch(0x1030)], vec![0x1030]),
            (0x1020, vec![branch(0x1030)], vec![0x1030]),
            (0x1030, vec![call(0x9000), ret()], vec![]),
        ];
        assert_eq!(agrees(both(&blocks, 0x1030)), Reaching::Constant(0x4000));
    }

    #[test]
    fn a_call_between_writes_what_it_does_not_keep() {
        let clobbered = [(
            0x1000,
            vec![set(RDI, 0x4000), call(0x8000), call(0x9000), ret()],
            vec![],
        )];
        let reader = agrees(both(&clobbered, 0x1000));
        assert_eq!(
            reader,
            Reaching::Constant(0x4000),
            "the first call is the site"
        );
        let between = [
            (
                0x1000,
                vec![set(RDI, 0x4000), call(0x8000), branch(0x1010)],
                vec![0x1010],
            ),
            (0x1010, vec![call(0x9000), ret()], vec![]),
        ];
        let reader = agrees(both(&between, 0x1010));
        assert_eq!(
            reader,
            Reaching::NotConstant(Unreached::Call { block: 0, op: 1 })
        );
        let kept = [
            (
                0x1000,
                vec![set(RBX, 0x4000), call(0x8000), branch(0x1010)],
                vec![0x1010],
            ),
            (
                0x1010,
                vec![
                    R2ILOp::Copy {
                        dst: reg(RDI, 8),
                        src: reg(RBX, 8),
                    },
                    call(0x9000),
                    ret(),
                ],
                vec![],
            ),
        ];
        assert_eq!(agrees(both(&kept, 0x1010)), Reaching::Constant(0x4000));
    }

    #[test]
    fn a_loop_that_writes_nothing_keeps_the_constant() {
        let blocks = [
            (0x1000, vec![set(RDI, 0x4000), branch(0x1010)], vec![0x1010]),
            (
                0x1010,
                vec![
                    R2ILOp::IntAdd {
                        dst: reg(RAX, 8),
                        a: reg(RAX, 8),
                        b: constant(1, 8),
                    },
                    cbranch(0x1010),
                ],
                vec![0x1010, 0x1020],
            ),
            (0x1020, vec![call(0x9000), ret()], vec![]),
        ];
        assert_eq!(agrees(both(&blocks, 0x1020)), Reaching::Constant(0x4000));
        let written = [
            (0x1000, vec![set(RDI, 0x4000), branch(0x1010)], vec![0x1010]),
            (
                0x1010,
                vec![
                    R2ILOp::IntAdd {
                        dst: reg(RDI, 8),
                        a: reg(RDI, 8),
                        b: constant(8, 8),
                    },
                    cbranch(0x1010),
                ],
                vec![0x1010, 0x1020],
            ),
            (0x1020, vec![call(0x9000), ret()], vec![]),
        ];
        let reader = agrees(both(&written, 0x1020));
        assert!(matches!(
            reader,
            Reaching::NotConstant(Unreached::Join { .. })
        ));
    }

    #[test]
    fn a_narrow_write_widened_folds() {
        let blocks = [(
            0x1000,
            vec![
                R2ILOp::Copy {
                    dst: reg(RDI, 4),
                    src: constant(0x10, 4),
                },
                R2ILOp::IntZExt {
                    dst: reg(RDI, 8),
                    src: reg(RDI, 4),
                },
                call(0x9000),
                ret(),
            ],
            vec![],
        )];
        assert_eq!(agrees(both(&blocks, 0x1000)), Reaching::Constant(0x10));
    }

    #[test]
    fn an_entry_value_is_none() {
        let blocks = [(0x1000, vec![call(0x9000), ret()], vec![])];
        let reader = agrees(both(&blocks, 0x1000));
        assert_eq!(reader, Reaching::NotConstant(Unreached::Entry));
    }

    /// `xor edi, edi`: the result ignores the value it cancels, as the seal's identity does.
    #[test]
    fn a_register_cancelled_against_itself_is_zero() {
        let blocks = [(
            0x1000,
            vec![
                R2ILOp::IntXor {
                    dst: reg(RDI, 8),
                    a: reg(RDI, 8),
                    b: reg(RDI, 8),
                },
                call(0x9000),
                ret(),
            ],
            vec![],
        )];
        assert_eq!(agrees(both(&blocks, 0x1000)), Reaching::Constant(0));
    }

    /// `mov eax, 1; mov edi, eax`: the narrow read of a register a wider write zero-extended is
    /// that write's low lane.
    #[test]
    fn a_narrow_read_of_a_wider_write_is_its_low_lane() {
        let blocks = [(
            0x1000,
            vec![
                R2ILOp::Copy {
                    dst: reg(RAX, 4),
                    src: constant(1, 4),
                },
                R2ILOp::IntZExt {
                    dst: reg(RAX, 8),
                    src: reg(RAX, 4),
                },
                R2ILOp::Copy {
                    dst: reg(RDI, 4),
                    src: reg(RAX, 4),
                },
                R2ILOp::IntZExt {
                    dst: reg(RDI, 8),
                    src: reg(RDI, 4),
                },
                call(0x9000),
                ret(),
            ],
            vec![],
        )];
        assert_eq!(agrees(both(&blocks, 0x1000)), Reaching::Constant(1));
    }

    /// A load at a literal address reads the capture's read-only word, and nothing where the
    /// capture holds none.
    #[test]
    fn a_literal_load_of_read_only_bytes_reads_them() {
        let lifted = [R2ILBlock {
            addr: 0x1000,
            size: 16,
            ops: vec![
                R2ILOp::Load {
                    dst: reg(RDI, 8),
                    space: SpaceId::Ram,
                    addr: constant(0x2000, 8),
                },
                call(0x9000),
                ret(),
            ],
            ..Default::default()
        }];
        let flow = Flow::new(&lifted, 0, []);
        let seed = Seed {
            block: 0,
            op: 1,
            storage: storage(RDI, 8),
        };
        let word = vec![(0x2000, vec![0x00, 0x40, 0, 0, 0, 0, 0, 0])];
        let held = Memory::new(word, Endianness::Little);
        assert_eq!(
            reaching_constants(&flow, (&writes, &held), &[seed]),
            [Reaching::Constant(0x4000)]
        );
        let none = Memory::new(Vec::new(), Endianness::Little);
        let load = Reaching::NotConstant(Unreached::Load { block: 0, op: 0 });
        assert_eq!(reaching_constants(&flow, (&writes, &none), &[seed]), [load]);
    }
}
