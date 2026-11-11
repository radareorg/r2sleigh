//! One instruction's forward local branches, if-converted: every straight run
//! of operations between labels and branches runs under one predicate.
//!
//! A run no branch jumps over runs whenever the instruction does and is kept as
//! it is. Any other run computes its values into candidates, selects them into
//! place under its predicate, and guards its accesses by it, so nested skips,
//! diamonds and a skip into another's tail (ties-to-even rounding) are one
//! rewrite. A run holding an operation that can be neither speculated nor
//! guarded poisons every run its branches guard. Cost: O(n + e) over operations
//! and edges, one operation per edge term and one `BoolOr` per extra edge.

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};

use r2il::{MemoryOrdering, OpMetadata, R2ILBlock, R2ILOp, SpaceId, Varnode};

use super::{InstructionTempAllocator, LocalBranch, local_branch, overlaps, transfer_target_size};

type Meta = Option<OpMetadata>;

enum Node {
    Op(R2ILOp, Meta),
    /// A local branch, by the label it lands on; unconditional without `cond`.
    Skip {
        cond: Option<Varnode>,
        label: usize,
        meta: Meta,
    },
    Label(usize),
}

/// The branch ending a block.
struct Exit {
    cond: Option<Varnode>,
    to: usize,
    meta: Meta,
}

#[derive(Default)]
struct Block {
    ops: Vec<(R2ILOp, Meta)>,
    exit: Option<Exit>,
}

/// When a block runs.
#[derive(Clone)]
enum Predicate {
    Always,
    Never,
    /// Exactly when `cond` holds, or fails where `negated`: the one edge into the block.
    Literal {
        cond: Varnode,
        negated: bool,
    },
    /// The disjunction of the edge terms into the block, made at its start.
    Computed,
}

/// One edge into a block: its source, and the literal the branch adds, if any.
struct Edge {
    from: usize,
    literal: Option<(Varnode, bool)>,
}

pub(super) fn normalize(block: &mut R2ILBlock) {
    let Some(nodes) = nodes(block) else {
        return;
    };
    let end = block.ops.len();
    let next = block.addr.wrapping_add(u64::from(block.size));
    let nodes = transfers_to_next(nodes, end, next);
    let mut allocator = InstructionTempAllocator::for_ops(
        &nodes
            .iter()
            .filter_map(|node| match node {
                Node::Op(op, _) => Some(op.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
    );
    let blocks = blocks(nodes);
    let ops = if_converted(&blocks, &mut allocator);
    block.ops.clear();
    block.op_metadata.clear();
    for (op, meta) in ops {
        if let Some(meta) = meta {
            block.op_metadata.insert(block.ops.len(), meta);
        }
        block.ops.push(op);
    }
}

/// The instruction as operations, skips and the labels they land on; `None` without a local branch.
fn nodes(block: &mut R2ILBlock) -> Option<Vec<Node>> {
    let branches: Vec<_> = (0..block.ops.len())
        .map(|index| local_branch(block, index, &block.ops[index]))
        .collect();
    if branches.iter().all(Option::is_none) {
        return None;
    }
    let end = block.ops.len();
    let forward = |index: usize, target: usize| target > index && target <= end;
    let targets: BTreeSet<usize> = branches
        .iter()
        .flatten()
        .filter(|(index, _, target)| forward(*index, *target))
        .map(|(_, _, target)| *target)
        .collect();
    let mut nodes = Vec::with_capacity(end + targets.len());
    let mut metadata = std::mem::take(&mut block.op_metadata);
    let ops = std::mem::take(&mut block.ops);
    for (index, (op, branch)) in ops.into_iter().zip(branches).enumerate() {
        if targets.contains(&index) {
            nodes.push(Node::Label(index));
        }
        let meta = metadata.remove(&index);
        nodes.push(match branch {
            Some((_, branch, target)) if forward(index, target) => Node::Skip {
                cond: match branch {
                    LocalBranch::Unconditional(_) => None,
                    LocalBranch::Conditional { cond, .. } => Some(cond),
                },
                label: target,
                meta,
            },
            // A loop neither unrolled nor counted, or a label past the instruction.
            Some(_) => Node::Op(R2ILOp::Unimplemented, meta),
            None => Node::Op(op, meta),
        });
    }
    if targets.contains(&end) {
        nodes.push(Node::Label(end));
    }
    Some(nodes)
}

/// ARM predicates a whole instruction, transfers included: `bxeq lr` returns or falls through,
/// and a straight skip over a transfer to the instruction's end is a machine edge to the next.
fn transfers_to_next(mut nodes: Vec<Node>, end: usize, next: u64) -> Vec<Node> {
    for at in 0..nodes.len() {
        let Node::Skip {
            cond: Some(_),
            label,
            ..
        } = &nodes[at]
        else {
            continue;
        };
        if *label != end {
            continue;
        }
        let range = nodes[at + 1..]
            .iter()
            .take_while(|node| matches!(node, Node::Op(..)));
        let size = range.clone().find_map(|node| match node {
            Node::Op(op, _) => transfer_target_size(op),
            _ => None,
        });
        let straight = nodes[at + 1..]
            .iter()
            .find(|node| !matches!(node, Node::Op(..)))
            .is_some_and(|node| matches!(node, Node::Label(label) if *label == end));
        if let (Some(size), true) = (size, straight) {
            let Node::Skip {
                cond: Some(cond),
                meta,
                ..
            } = std::mem::replace(&mut nodes[at], Node::Label(usize::MAX))
            else {
                unreachable!("matched above");
            };
            let target = Varnode {
                space: SpaceId::Ram,
                offset: next,
                size,
            };
            nodes[at] = Node::Op(R2ILOp::CBranch { cond, target }, meta);
        }
    }
    nodes
}

/// The straight runs: a block begins at a label and ends at a skip.
fn blocks(nodes: Vec<Node>) -> Vec<Block> {
    let mut blocks = vec![Block::default()];
    let mut labels = BTreeMap::new();
    for node in nodes {
        let current = blocks.last().expect("one block");
        let begins = match &node {
            Node::Label(_) => !current.ops.is_empty() || current.exit.is_some(),
            _ => current.exit.is_some(),
        };
        if begins {
            blocks.push(Block::default());
        }
        let at = blocks.len() - 1;
        match node {
            Node::Label(label) => {
                labels.insert(label, at);
            }
            Node::Op(op, meta) => blocks[at].ops.push((op, meta)),
            // By its label until every label has its block.
            Node::Skip { cond, label, meta } => {
                blocks[at].exit = Some(Exit {
                    cond,
                    to: label,
                    meta,
                })
            }
        }
    }
    for exit in blocks.iter_mut().filter_map(|block| block.exit.as_mut()) {
        exit.to = labels[&exit.to];
    }
    blocks
}

fn predicable(op: &R2ILOp) -> bool {
    op.is_speculatable_value() || is_access(op) || op.is_integer_division()
}

/// The plain accesses `Predicated::op` rewrites into their guarded forms; an exclusive or atomic one has none.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        r2il_op_property_outside_r2il,
        reason = "the accesses this pass can guard, not every memory access"
    )
)]
fn is_access(op: &R2ILOp) -> bool {
    matches!(
        op,
        R2ILOp::Load { .. }
            | R2ILOp::Store { .. }
            | R2ILOp::LoadGuarded { .. }
            | R2ILOp::StoreGuarded { .. }
    )
}

fn if_converted(blocks: &[Block], allocator: &mut InstructionTempAllocator) -> Vec<(R2ILOp, Meta)> {
    let predicates = predicates(blocks);
    let poisoned = refused_runs(blocks, &predicates);
    let live_after = live_after(blocks, &predicates);
    let mut emitted = Vec::new();
    // The term each edge into a computed block contributes, made at the end of its source.
    let mut terms: Vec<Vec<Varnode>> = (0..blocks.len()).map(|_| Vec::new()).collect();
    for (at, block) in blocks.iter().enumerate() {
        let always = matches!(predicates[at], Predicate::Always);
        if poisoned[at] && !always {
            poison(&mut emitted, block.ops.iter().map(|(_, meta)| meta));
            poison(&mut emitted, block.exit.iter().map(|exit| &exit.meta));
            continue;
        }
        if matches!(predicates[at], Predicate::Never) {
            continue;
        }
        let mut region = Vec::new();
        let mut predicated = Predicated {
            emitted: &mut region,
            allocator: &mut *allocator,
            candidates: FxHashMap::default(),
            preserved: Vec::new(),
            cond: None,
            value: None,
        };
        let entering = std::mem::take(&mut terms[at]);
        let made = predicated
            .block(block, &predicates[at], entering, &live_after[at])
            .and_then(|()| match poisoned[at] {
                false => predicated.edges(at, block, &predicates, &mut terms),
                true => Some(()),
            });
        match made {
            Some(()) => emitted.append(&mut region),
            // Out of temporaries: nothing short of refusing is honest.
            None => poison(&mut emitted, block.ops.iter().map(|(_, meta)| meta)),
        }
        // The branch into a refused run refuses with it.
        if made.is_none() || poisoned[at] {
            poison(&mut emitted, block.exit.iter().map(|exit| &exit.meta));
        }
    }
    emitted
}

/// When each block runs, in block order, which is topological: every edge is forward.
fn predicates(blocks: &[Block]) -> Vec<Predicate> {
    let count = blocks.len();
    let mut incoming: Vec<Vec<Edge>> = (0..count).map(|_| Vec::new()).collect();
    // How many edges jump over each block; one nothing jumps over runs on every path.
    let mut spans = vec![0isize; count + 1];
    for (from, block) in blocks.iter().enumerate() {
        let fallthrough = match &block.exit {
            Some(Exit { cond, to, .. }) => {
                incoming[*to].push(Edge {
                    from,
                    literal: cond.clone().map(|cond| (cond, false)),
                });
                spans[from + 1] += 1;
                spans[*to] -= 1;
                cond.clone().map(|cond| Some((cond, true)))
            }
            None => Some(None),
        };
        if let Some(literal) = fallthrough.filter(|_| from + 1 < count) {
            incoming[from + 1].push(Edge { from, literal });
        }
    }
    let mut predicates = Vec::with_capacity(count);
    let mut jumped = 0;
    for (at, edges) in incoming.iter_mut().enumerate() {
        jumped += spans[at];
        edges.retain(|edge| !matches!(predicates[edge.from], Predicate::Never));
        let predicate = match edges.as_slice() {
            _ if at == 0 => Predicate::Always,
            [] => Predicate::Never,
            _ if jumped == 0 => Predicate::Always,
            [
                Edge {
                    from,
                    literal: Some((cond, negated)),
                },
            ] if matches!(predicates[*from], Predicate::Always) => Predicate::Literal {
                cond: cond.clone(),
                negated: *negated,
            },
            _ => Predicate::Computed,
        };
        predicates.push(predicate);
    }
    predicates
}

/// The blocks that refuse: every block of a run (a maximal stretch that does not run on every
/// path, independent of any other) holding an operation it cannot predicate, and the branch into it.
fn refused_runs(blocks: &[Block], predicates: &[Predicate]) -> Vec<bool> {
    let count = blocks.len();
    let mut poisoned = vec![false; count];
    let mut at = 0;
    while at < count {
        let run = at..(at..count)
            .find(|k| matches!(predicates[*k], Predicate::Always))
            .unwrap_or(count);
        let refused = run.clone().any(|k| {
            !matches!(predicates[k], Predicate::Never)
                && !blocks[k].ops.iter().all(|(op, _)| predicable(op))
        });
        if refused {
            poisoned[run.clone()]
                .iter_mut()
                .for_each(|flag| *flag = true);
            // The block before the run ends in the branch that guards it.
            if let Some(before) = run.start.checked_sub(1) {
                poisoned[before] |= blocks[before].exit.is_some();
            }
        }
        at = run.end.max(at + 1);
    }
    poisoned
}

fn poison<'m>(emitted: &mut Vec<(R2ILOp, Meta)>, metas: impl Iterator<Item = &'m Meta>) {
    emitted.extend(metas.map(|meta| (R2ILOp::Unimplemented, meta.clone())));
}

/// What is live before `op`, from what is live after it.
fn live_before(live: &mut FxHashSet<Varnode>, op: &R2ILOp) {
    if let Some(output) = op.output() {
        live.remove(output);
    }
    live.extend(op.inputs().into_iter().cloned());
}

/// What each block leaves read later. A predicated block reads a name only where it did not
/// write it first (its own reads take candidates), and its select keeps a later-read name live.
fn live_after(blocks: &[Block], predicates: &[Predicate]) -> Vec<FxHashSet<Varnode>> {
    let mut live = FxHashSet::default();
    let mut after = vec![FxHashSet::default(); blocks.len()];
    for (at, block) in blocks.iter().enumerate().rev() {
        after[at].clone_from(&live);
        let cond = block.exit.as_ref().and_then(|exit| exit.cond.as_ref());
        match &predicates[at] {
            Predicate::Never => {}
            Predicate::Always => {
                live.extend(cond.cloned());
                block
                    .ops
                    .iter()
                    .rev()
                    .for_each(|(op, _)| live_before(&mut live, op));
            }
            predicate => {
                let mut written = FxHashSet::default();
                for (op, _) in &block.ops {
                    let exposed = op
                        .inputs()
                        .into_iter()
                        .filter(|input| !written.contains(*input));
                    live.extend(exposed.cloned());
                    written.extend(op.output().cloned());
                }
                live.extend(cond.filter(|cond| !written.contains(*cond)).cloned());
                if let Predicate::Literal { cond, .. } = predicate {
                    live.insert(cond.clone());
                }
            }
        }
    }
    after
}

struct Predicated<'a> {
    emitted: &'a mut Vec<(R2ILOp, Meta)>,
    allocator: &'a mut InstructionTempAllocator,
    candidates: FxHashMap<Varnode, Varnode>,
    /// What survives the block, in the order of each one's last write.
    preserved: Vec<(Varnode, Varnode, Meta)>,
    /// The varnode the block's predicate tests and whether the block runs when it holds; `None`
    /// for a block that always runs.
    cond: Option<(Varnode, bool)>,
    /// The predicate as a value, once something needs it.
    value: Option<Varnode>,
}

impl Predicated<'_> {
    /// Emits one block under its predicate.
    fn block(
        &mut self,
        block: &Block,
        predicate: &Predicate,
        terms: Vec<Varnode>,
        live: &FxHashSet<Varnode>,
    ) -> Option<()> {
        let first = block
            .ops
            .first()
            .map(|(_, meta)| meta.clone())
            .unwrap_or_default();
        self.cond = match predicate {
            Predicate::Always | Predicate::Never => {
                self.emitted.extend(block.ops.iter().cloned());
                return Some(());
            }
            Predicate::Literal { cond, negated } => {
                // A select of the tested varnode must not move what the other selects read.
                let rewritten = block
                    .ops
                    .iter()
                    .any(|(op, _)| op.output().is_some_and(|output| overlaps(output, cond)));
                let cond = match rewritten {
                    true => self.copied(cond, &first)?,
                    false => cond.clone(),
                };
                Some((cond, !*negated))
            }
            Predicate::Computed => {
                let mut terms = terms.into_iter();
                let mut disjunction = terms.next()?;
                for term in terms {
                    let either = self.allocator.allocate(1)?;
                    self.emitted.push((
                        R2ILOp::BoolOr {
                            dst: either.clone(),
                            a: disjunction,
                            b: term,
                        },
                        first.clone(),
                    ));
                    disjunction = either;
                }
                Some((disjunction, true))
            }
        };
        for (op, meta) in &block.ops {
            self.op(op.clone(), meta)?;
        }
        let (cond, holds) = self.cond.clone()?;
        for (dst, candidate, meta) in std::mem::take(&mut self.preserved) {
            if dst.space == SpaceId::Unique && !live.contains(&dst) {
                continue;
            }
            let (if_true, if_false) = match holds {
                true => (candidate, dst.clone()),
                false => (dst.clone(), candidate),
            };
            self.emitted.push((
                R2ILOp::Select {
                    dst,
                    cond: cond.clone(),
                    if_true,
                    if_false,
                },
                meta,
            ));
        }
        Some(())
    }

    /// The terms the block's edges add to the computed blocks they enter.
    fn edges(
        &mut self,
        at: usize,
        block: &Block,
        predicates: &[Predicate],
        terms: &mut [Vec<Varnode>],
    ) -> Option<()> {
        let computed = |to: usize| matches!(predicates.get(to), Some(Predicate::Computed));
        let meta = block.exit.as_ref().map_or(&None, |exit| &exit.meta);
        let cond = block
            .exit
            .as_ref()
            .and_then(|exit| exit.cond.as_ref())
            .map(|cond| self.candidates.get(cond).unwrap_or(cond).clone());
        let mut edges = Vec::new();
        match &block.exit {
            Some(exit) => {
                edges.push((exit.to, cond.clone().map(|cond| (cond, false))));
                if let Some(cond) = cond {
                    edges.push((at + 1, Some((cond, true))));
                }
            }
            None => edges.push((at + 1, None)),
        }
        for (to, literal) in edges.into_iter().filter(|(to, _)| computed(*to)) {
            let term = self.term(literal, meta)?;
            terms[to].push(term);
        }
        Some(())
    }

    /// The block's predicate as a value, made the first time something needs it.
    fn value(&mut self, meta: &Meta) -> Option<Option<Varnode>> {
        if self.value.is_some() {
            return Some(self.value.clone());
        }
        let Some((cond, holds)) = self.cond.clone() else {
            return Some(None);
        };
        let value = match holds {
            true => cond,
            false => {
                let negated = self.allocator.allocate(1)?;
                self.emitted.push((
                    R2ILOp::BoolNot {
                        dst: negated.clone(),
                        src: cond,
                    },
                    meta.clone(),
                ));
                negated
            }
        };
        self.value = Some(value);
        Some(self.value.clone())
    }

    fn copied(&mut self, varnode: &Varnode, meta: &Meta) -> Option<Varnode> {
        let copy = self.allocator.allocate(varnode.size)?;
        self.emitted.push((
            R2ILOp::Copy {
                dst: copy.clone(),
                src: varnode.clone(),
            },
            meta.clone(),
        ));
        Some(copy)
    }

    /// Where the block does not run, a division's quotient or a conversion's integer is discarded,
    /// so it divides by one or converts zero there and cannot stop ahead of its guard (audit W22).
    fn guard_operand(&mut self, op: &mut R2ILOp, meta: &Meta) -> Option<()> {
        let (operand, harmless) = match op {
            R2ILOp::IntDiv { b, .. }
            | R2ILOp::IntSDiv { b, .. }
            | R2ILOp::IntRem { b, .. }
            | R2ILOp::IntSRem { b, .. } => (b, 1),
            R2ILOp::Trunc { src, .. } | R2ILOp::Float2Int { src, .. } => (src, 0),
            _ => return Some(()),
        };
        let (cond, holds) = self.cond.clone()?;
        let safe = self.allocator.allocate(operand.size)?;
        let harmless = Varnode::constant(harmless, operand.size);
        let (if_true, if_false) = match holds {
            true => (operand.clone(), harmless),
            false => (harmless, operand.clone()),
        };
        self.emitted.push((
            R2ILOp::Select {
                dst: safe.clone(),
                cond,
                if_true,
                if_false,
            },
            meta.clone(),
        ));
        *operand = safe;
        Some(())
    }

    /// One operation under the block's predicate: a value into a candidate, an access guarded.
    fn op(&mut self, mut op: R2ILOp, meta: &Meta) -> Option<()> {
        for input in op.inputs_mut() {
            if let Some(candidate) = self.candidates.get(input) {
                *input = candidate.clone();
            }
        }
        self.guard_operand(&mut op, meta)?;
        let guard = match is_access(&op) {
            true => self.value(meta)??,
            false => Varnode::constant(1, 1),
        };
        let mut op = match op {
            // The read goes to a temporary and the destination takes it through a copy, whose
            // select states that the destination keeps its value where the guard fails.
            R2ILOp::Load { dst, space, addr } => {
                // Written on every path, so where the guard fails the copy reads a value and the
                // select keeps the destination's.
                let read = self.allocator.allocate(dst.size)?;
                self.emitted.push((
                    R2ILOp::Copy {
                        dst: read.clone(),
                        src: Varnode::constant(0, dst.size),
                    },
                    meta.clone(),
                ));
                self.emitted.push((
                    R2ILOp::LoadGuarded {
                        dst: read.clone(),
                        space,
                        addr,
                        guard,
                        // A predicated access orders nothing; a barrier is spelled beside it.
                        ordering: MemoryOrdering::Relaxed,
                    },
                    meta.clone(),
                ));
                R2ILOp::Copy { dst, src: read }
            }
            R2ILOp::Store { space, addr, val } => {
                self.emitted.push((
                    R2ILOp::StoreGuarded {
                        space,
                        addr,
                        val,
                        guard,
                        ordering: MemoryOrdering::Relaxed,
                    },
                    meta.clone(),
                ));
                return Some(());
            }
            R2ILOp::LoadGuarded { .. } | R2ILOp::StoreGuarded { .. } => {
                let both = self.allocator.allocate(1)?;
                let (R2ILOp::LoadGuarded { guard: inner, .. }
                | R2ILOp::StoreGuarded { guard: inner, .. }) = &mut op
                else {
                    unreachable!("matched above");
                };
                self.emitted.push((
                    R2ILOp::BoolAnd {
                        dst: both.clone(),
                        a: inner.clone(),
                        b: guard,
                    },
                    meta.clone(),
                ));
                *inner = both;
                self.emitted.push((op, meta.clone()));
                return Some(());
            }
            op => op,
        };
        let dst = op.output()?.clone();
        let candidate = self.allocator.allocate(dst.size)?;
        *op.output_mut()? = candidate.clone();
        self.emitted.push((op, meta.clone()));
        self.candidates.insert(dst.clone(), candidate.clone());
        self.preserved.retain(|(kept, ..)| kept != &dst);
        self.preserved.push((dst, candidate, meta.clone()));
        Some(())
    }

    /// The edge term `predicate && literal`, taken now into a fresh varnode later writes cannot move.
    fn term(&mut self, literal: Option<(Varnode, bool)>, meta: &Meta) -> Option<Varnode> {
        let own = self.value(meta)?;
        let term = self.allocator.allocate(1)?;
        let op = match (own, literal) {
            (None, None) => R2ILOp::Copy {
                dst: term.clone(),
                src: Varnode::constant(1, 1),
            },
            (Some(own), None) => R2ILOp::Copy {
                dst: term.clone(),
                src: own,
            },
            (None, Some((cond, false))) => R2ILOp::Copy {
                dst: term.clone(),
                src: cond,
            },
            (None, Some((cond, true))) => R2ILOp::BoolNot {
                dst: term.clone(),
                src: cond,
            },
            (Some(own), Some((cond, negated))) => {
                let cond = match negated {
                    false => cond,
                    true => {
                        let not = self.allocator.allocate(1)?;
                        self.emitted.push((
                            R2ILOp::BoolNot {
                                dst: not.clone(),
                                src: cond,
                            },
                            meta.clone(),
                        ));
                        not
                    }
                };
                R2ILOp::BoolAnd {
                    dst: term.clone(),
                    a: own,
                    b: cond,
                }
            }
        };
        self.emitted.push((op, meta.clone()));
        Some(term)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::Endianness;
    use r2il::eval::{Flow, State, step};

    const A: Varnode = Varnode {
        space: SpaceId::Register,
        offset: 0x10,
        size: 1,
    };
    const B: Varnode = Varnode {
        space: SpaceId::Register,
        offset: 0x11,
        size: 1,
    };
    const X: Varnode = Varnode {
        space: SpaceId::Register,
        offset: 0x20,
        size: 8,
    };
    const Y: Varnode = Varnode {
        space: SpaceId::Register,
        offset: 0x28,
        size: 8,
    };

    fn skip(cond: Option<&Varnode>, distance: u64) -> R2ILOp {
        let target = Varnode::constant(distance, 4);
        match cond {
            Some(cond) => R2ILOp::CBranch {
                target,
                cond: cond.clone(),
            },
            None => R2ILOp::Branch { target },
        }
    }

    fn set(dst: &Varnode, value: u64) -> R2ILOp {
        R2ILOp::Copy {
            dst: dst.clone(),
            src: Varnode::constant(value, dst.size),
        }
    }

    fn normalized(ops: Vec<R2ILOp>) -> Vec<R2ILOp> {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = ops;
        normalize(&mut block);
        assert!(
            !block.ops.iter().any(|op| matches!(
                op,
                R2ILOp::Branch { .. } | R2ILOp::CBranch { .. } | R2ILOp::Unimplemented
            )),
            "{:?}",
            block.ops
        );
        block.ops
    }

    /// `x` and `y` after running `ops` from `x = y = 0` with the two conditions given.
    fn run(ops: &[R2ILOp], a: bool, b: bool) -> (u128, u128) {
        let mut state = State::new(Endianness::Little, |_| None, 1 << 10).expect("state");
        for (register, value) in [(&A, a.into()), (&B, b.into()), (&X, 0), (&Y, 0)] {
            state
                .set_register(register.offset, register.size, value)
                .expect("register");
        }
        for op in ops {
            assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
        }
        (
            state.register(X.offset, X.size).expect("x"),
            state.register(Y.offset, Y.size).expect("y"),
        )
    }

    /// `if (a) goto E; x = 1; if (b) goto E; x = 2; E:` -- the inner skip used to leave
    /// `x = 1` running whatever `a` said.
    #[test]
    fn a_nested_skip_runs_under_both_conditions() {
        let ops = normalized(vec![
            skip(Some(&A), 4),
            set(&X, 1),
            skip(Some(&B), 2),
            set(&X, 2),
        ]);
        for (a, b, x) in [
            (true, true, 0),
            (true, false, 0),
            (false, true, 1),
            (false, false, 2),
        ] {
            assert_eq!(run(&ops, a, b).0, x, "a={a} b={b}: {ops:?}");
        }
    }

    /// `if (a) goto E; x = *y; E:` -- the skipped load left its temporary unwritten, and the
    /// copy out of it stopped the run before the select could keep `x`.
    #[test]
    fn a_skipped_load_keeps_its_destination() {
        let ops = normalized(vec![
            skip(Some(&A), 2),
            R2ILOp::Load {
                dst: X,
                space: SpaceId::Ram,
                addr: Y,
            },
        ]);
        for (a, x) in [(true, 0), (false, 0x5a5a_5a5a_5a5a_5a5a)] {
            let mut state = State::new(Endianness::Little, |_| Some(0x5a), 1 << 10).expect("state");
            for (register, value) in [(&A, a.into()), (&X, 0), (&Y, 0x100)] {
                state
                    .set_register(register.offset, register.size, value)
                    .expect("register");
            }
            for op in &ops {
                assert_eq!(step(op, &mut state), Flow::Next, "a={a}: {op:?}");
            }
            assert_eq!(state.register(X.offset, X.size), Some(x), "a={a}: {ops:?}");
        }
    }

    /// `if (a) goto L; x = 1; goto E; L: x = 2; E:`.
    #[test]
    fn a_diamond_takes_one_arm() {
        let ops = normalized(vec![
            skip(Some(&A), 3),
            set(&X, 1),
            skip(None, 2),
            set(&X, 2),
        ]);
        for (a, x) in [(true, 2), (false, 1)] {
            assert_eq!(run(&ops, a, false).0, x, "a={a}: {ops:?}");
        }
    }

    /// Ties-to-even's shape, a skip into the tail of another's range: `if (a) goto L; if (b) goto
    /// E; x = 1; L: y = 2; E:`.
    #[test]
    fn a_skip_into_another_tail_runs_the_tail_on_both_paths() {
        let ops = normalized(vec![
            skip(Some(&A), 3),
            skip(Some(&B), 3),
            set(&X, 1),
            set(&Y, 2),
        ]);
        for (a, b, expected) in [
            (true, true, (0, 2)),
            (true, false, (0, 2)),
            (false, true, (0, 0)),
            (false, false, (1, 2)),
        ] {
            assert_eq!(run(&ops, a, b), expected, "a={a} b={b}: {ops:?}");
        }
    }

    /// Both skips over a store guard it: its guard is the conjunction of their negations.
    #[test]
    fn a_store_under_nested_skips_carries_both_guards() {
        let ops = normalized(vec![
            skip(Some(&A), 3),
            skip(Some(&B), 2),
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: X.clone(),
                val: Y.clone(),
            },
        ]);
        let (store, guard) = ops
            .iter()
            .enumerate()
            .find_map(|(at, op)| match op {
                R2ILOp::StoreGuarded { guard, .. } => Some((at, guard.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{ops:?}"));
        for (a, b) in [(true, true), (true, false), (false, true), (false, false)] {
            let mut state = State::new(Endianness::Little, |_| None, 1 << 10).expect("state");
            state.set_register(A.offset, 1, a.into()).expect("a");
            state.set_register(B.offset, 1, b.into()).expect("b");
            for op in &ops[..store] {
                assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
            }
            assert_eq!(state.value(&guard), Ok(u128::from(!a && !b)), "a={a} b={b}");
        }
    }

    /// AArch64 `sdiv`'s shape, `q = 0; if (b == 0) goto E; q = a / b; E: x = q`: a zero divisor
    /// leaves nought, and the division never runs on it, where it used to be hoisted unguarded.
    #[test]
    fn a_division_skipped_at_a_zero_divisor_never_divides_by_it() {
        let (zero, quotient) = (Varnode::unique(0x100, 1), Varnode::unique(0x108, 8));
        let (dst, a, b) = (quotient.clone(), X.clone(), Y.clone());
        for (divided, division) in [
            (R2ILOp::IntSDiv { dst, a, b }, true),
            (
                R2ILOp::IntDiv {
                    dst: quotient.clone(),
                    a: X.clone(),
                    b: Y.clone(),
                },
                true,
            ),
            (
                R2ILOp::IntSRem {
                    dst: quotient.clone(),
                    a: X.clone(),
                    b: Y.clone(),
                },
                false,
            ),
        ] {
            let ops = normalized(vec![
                set(&quotient, 0),
                R2ILOp::IntEqual {
                    dst: zero.clone(),
                    a: Y.clone(),
                    b: Varnode::constant(0, 8),
                },
                skip(Some(&zero), 2),
                divided,
                R2ILOp::Copy {
                    dst: X.clone(),
                    src: quotient.clone(),
                },
            ]);
            assert!(
                !ops.iter()
                    .any(|op| op.is_integer_division() && op.inputs().contains(&&Y)),
                "{ops:?}"
            );
            assert_eq!(divided_by(&ops, 0), 0, "{ops:?}");
            assert_eq!(divided_by(&ops, 2), if division { 3 } else { 1 }, "{ops:?}");
        }
    }

    /// The saturating `fcvt*u` shape, `q = 0; if (big) goto E; q = trunc(y); E: x = q`: a `y` past
    /// the range leaves nought and is never converted, where the hoisted `trunc` stopped eval.
    #[test]
    fn a_conversion_skipped_out_of_range_never_converts_it() {
        let integer = Varnode::unique(0x108, 8);
        let ops = normalized(vec![
            set(&integer, 0),
            skip(Some(&A), 2),
            R2ILOp::Trunc {
                dst: integer.clone(),
                src: Y.clone(),
            },
            R2ILOp::Copy {
                dst: X.clone(),
                src: integer.clone(),
            },
        ]);
        for (value, past, converted) in [(1e300, 1, 0), (2.5, 0, 2)] {
            let mut state = State::new(Endianness::Little, |_| None, 1 << 10).expect("state");
            state
                .set_register(Y.offset, 8, f64::to_bits(value).into())
                .expect("y");
            state.set_register(A.offset, 1, past).expect("big");
            for op in &ops {
                assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
            }
            assert_eq!(state.register(X.offset, 8), Some(converted), "{ops:?}");
        }
    }

    /// `x` after running `ops` from `x = 7` and `y = divisor`.
    fn divided_by(ops: &[R2ILOp], divisor: u128) -> u128 {
        let mut state = State::new(Endianness::Little, |_| None, 1 << 10).expect("state");
        state.set_register(X.offset, 8, 7).expect("x");
        state.set_register(Y.offset, 8, divisor).expect("y");
        for op in ops {
            assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
        }
        state.register(X.offset, 8).expect("x")
    }

    /// A skip over what can be neither speculated nor guarded refuses with all it skips, and the
    /// skip around it refuses too.
    #[test]
    fn a_refused_skip_poisons_every_operation_it_guards() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.ops = vec![
            skip(Some(&A), 4),
            set(&X, 1),
            skip(Some(&B), 2),
            R2ILOp::CallOther {
                output: Some(Y.clone()),
                userop: 7,
                inputs: Vec::new(),
            },
            set(&Y, 3),
        ];
        normalize(&mut block);
        assert_eq!(
            block.ops,
            [vec![R2ILOp::Unimplemented; 4], vec![set(&Y, 3)]].concat()
        );
    }
}
