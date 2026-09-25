//! Instruction-local loops whose every decision is a constant.
//!
//! Sleigh writes some instructions as p-code that loops. PDEP and PEXT walk a
//! mask bit from one end of the register to the other, PCLMULQDQ walks a bit
//! index from 0 to 63, and ENTER copies one frame pointer per nesting level.
//! What decides each pass of those loops is not data: it is a counter the
//! instruction starts from a constant (the width, or an immediate the encoding
//! holds) and steps by a constant.
//!
//! So the p-code is walked in execution order over the values that are
//! constants, and only those. Every local branch whose condition is then a
//! constant is decided, and what is left is the program the machine runs: the
//! loop repeated exactly as many times as the p-code repeats it, with the
//! data-dependent skips inside each pass kept as forward skips, which the
//! select rewrite in the parent module already speaks for.
//!
//! Invariant: on every input, the rewritten sequence performs the operations
//! the p-code performs, in the same order, apart from the local branches it
//! decided. A condition is decided only from constants and from values the walk
//! derived through [`r2il::eval::apply`], the engine's one statement of what an
//! operation computes, on every path that reaches it: an operation inside a
//! skip may not run, so what it writes becomes unknown rather than known.
//!
//! Refusal: the walk gives up, and the instruction is left as the specification
//! wrote it (and refuses as before), where a decision depends on data. That
//! is a backward branch whose condition is not a constant, a backward branch
//! reached on only some paths, a forward skip that would leave the pass it was
//! taken in, or a program longer than [`STEP_BUDGET`].
//!
//! Cost: one step per operation of the unrolled program, each linear in the
//! handful of constants the instruction holds, within the budget.

use std::collections::BTreeMap;

use r2il::eval::{Operation, Word, apply};
use r2il::{OpMetadata, R2ILBlock, R2ILOp, SpaceId, Varnode};

use super::{LocalBranch, local_branch, overlaps, same};

/// The most operations the walk visits before it gives the loop up.
///
/// The longest constant-decided loop a supported specification writes is
/// x86 PDEP and PEXT at 64 bits and PCLMULQDQ: 64 passes of at most twelve
/// operations, under 800 steps. The budget is twenty times that, so it bounds a
/// specification that loops without end rather than any loop the machine runs;
/// past it the loop stays the refusal it was.
const STEP_BUDGET: usize = 1 << 14;

/// The instruction with every local decision that is a constant taken, or
/// `None` where one depends on data.
pub(super) fn unrolled(block: &R2ILBlock) -> Option<(Vec<R2ILOp>, BTreeMap<usize, OpMetadata>)> {
    let mut walk = Walk {
        block,
        known: Vec::new(),
        emitted: Vec::new(),
        origins: Vec::new(),
        open: Vec::new(),
        landings: BTreeMap::new(),
    };
    walk.run()?;
    Some(walk.finish())
}

struct Walk<'a> {
    block: &'a R2ILBlock,
    /// Each storage whose value is the same on every path to where the walk stands.
    known: Vec<(Varnode, u128)>,
    emitted: Vec<R2ILOp>,
    /// The operation each emitted one was copied from, for its metadata.
    origins: Vec<usize>,
    /// Forward skips emitted whose target the walk has not reached yet:
    /// the target operation, and where the skip was emitted.
    open: Vec<(usize, usize)>,
    /// Where each emitted skip lands, by the position it was emitted at.
    landings: BTreeMap<usize, usize>,
}

impl Walk<'_> {
    fn run(&mut self) -> Option<()> {
        let len = self.block.ops.len();
        let mut at = 0;
        let mut steps = 0usize;
        while at < len {
            steps += 1;
            if steps > STEP_BUDGET {
                return None;
            }
            self.land(at);
            at = match local_branch(self.block, at, &self.block.ops[at]) {
                Some((_, branch, target)) => self.decide(at, branch, target)?,
                None => {
                    self.execute(at);
                    at + 1
                }
            };
        }
        self.land(len);
        self.open.is_empty().then_some(())
    }

    /// Place every open skip that targets `at` where the walk now emits.
    fn land(&mut self, at: usize) {
        let position = self.emitted.len();
        let landings = &mut self.landings;
        self.open.retain(|&(target, skip)| {
            let lands = target == at;
            if lands {
                landings.insert(skip, position);
            }
            !lands
        });
    }

    /// Where the walk goes from the local branch at `at`, or `None` where the
    /// branch is a decision on data this walk cannot take.
    fn decide(&mut self, at: usize, branch: LocalBranch, target: usize) -> Option<usize> {
        if target > self.block.ops.len() {
            return None;
        }
        let (taken, cond) = match branch {
            LocalBranch::Unconditional(_) => (Some(true), None),
            LocalBranch::Conditional { cond, .. } => {
                (self.value(&cond).map(|v| v != 0), Some(cond))
            }
        };
        match (taken, target <= at) {
            (Some(false), _) => Some(at + 1),
            // Another pass: only where every path of this one has come
            // together, or a skip taken in it would land in the next pass.
            (Some(true), true) => self.open.is_empty().then_some(target),
            (Some(true), false) => Some(self.jump(at, target)),
            (None, false) => {
                self.skip(at, cond, target);
                Some(at + 1)
            }
            (None, true) => None,
        }
    }

    /// A forward branch that is always taken where the walk reaches it.
    ///
    /// The operations it passes over are dropped, unless an open skip lands
    /// among them: then they run on that skip's path, so the branch stays and
    /// the walk goes on through them.
    fn jump(&mut self, at: usize, target: usize) -> usize {
        if self.open.iter().any(|&(open, _)| open < target) {
            self.skip(at, None, target);
            at + 1
        } else {
            target
        }
    }

    fn skip(&mut self, at: usize, cond: Option<Varnode>, target: usize) {
        // The target is patched to the landing once the walk reaches it.
        let placeholder = Varnode::constant(0, 4);
        let op = match cond {
            Some(cond) => R2ILOp::CBranch {
                target: placeholder,
                cond,
            },
            None => R2ILOp::Branch {
                target: placeholder,
            },
        };
        self.open.push((target, self.emitted.len()));
        self.emit(at, op);
    }

    /// Emit an operation, and learn what it writes where every path runs it.
    fn execute(&mut self, at: usize) {
        let op = &self.block.ops[at];
        let value = self.open.is_empty().then(|| self.evaluate(op)).flatten();
        if let Some(output) = op.output() {
            self.known.retain(|(known, _)| !overlaps(known, output));
            if let Some(value) = value {
                self.known.push((output.clone(), value));
            }
        }
        self.emit(at, op.clone());
    }

    fn emit(&mut self, at: usize, op: R2ILOp) {
        self.emitted.push(op);
        self.origins.push(at);
    }

    /// What a value operation computes, where every operand is known.
    fn evaluate(&self, op: &R2ILOp) -> Option<u128> {
        let (operation, dst, operands) = Operation::of(op)?;
        let operands = operands
            .into_iter()
            .map(|operand| Word::new(self.value(operand)?, operand.size).ok())
            .collect::<Option<Vec<_>>>()?;
        apply(operation, &operands, dst.size).ok()
    }

    fn value(&self, varnode: &Varnode) -> Option<u128> {
        match varnode.space {
            SpaceId::Const => Some(u128::from(varnode.offset)),
            _ => self
                .known
                .iter()
                .find(|(known, _)| same(known, varnode))
                .map(|(_, value)| *value),
        }
    }

    /// The emitted operations with every skip pointing at its landing.
    fn finish(self) -> (Vec<R2ILOp>, BTreeMap<usize, OpMetadata>) {
        let Walk {
            block,
            mut emitted,
            origins,
            landings,
            ..
        } = self;
        for (skip, landing) in landings {
            let distance = Varnode::constant((landing - skip) as u64, 4);
            if let R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } = &mut emitted[skip] {
                *target = distance;
            }
        }
        let metadata = origins
            .iter()
            .enumerate()
            .filter_map(|(position, origin)| {
                let meta = block.op_metadata.get(origin)?;
                Some((position, meta.clone()))
            })
            .collect();
        (emitted, metadata)
    }
}
