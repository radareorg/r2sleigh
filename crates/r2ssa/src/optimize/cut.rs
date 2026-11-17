//! The blocks a branch decided over constants cuts off, by SCCP's transfer read backward from each
//! condition (D447, doc/adr-one-ir.md "D447 as built").

use r2abi::statement::LoadBase;

use super::{Op, eval_const_op};
use crate::dense::IdVec;
use crate::frame_address::Definitions;
use crate::value_table::{Minting, VarId};
use crate::{BlockTerminator, SSAFunction, SSAOp};

/// A variable in the evaluation: not reached, on the stack, or its one value on every run.
#[derive(Debug, Clone, Copy)]
enum State {
    Unseen,
    Busy,
    Known(Option<u64>),
}

/// The values the evaluated conditions read, each variable expanded once.
struct Values<'f> {
    func: &'f SSAFunction,
    defs: &'f Definitions,
    minting: Minting<'f>,
    state: IdVec<VarId, State>,
}

/// What SCCP gives no value: memory, a call, an operation whose effect no model states.
fn opaque(op: &Op) -> bool {
    op.is_call()
        || matches!(
            op,
            SSAOp::Load { .. } | SSAOp::CallOther { .. } | SSAOp::CpuId { .. } | SSAOp::New { .. }
        )
}

impl<'f> Values<'f> {
    fn new(func: &'f SSAFunction, defs: &'f Definitions) -> Self {
        Self {
            func,
            defs,
            minting: Minting::new(func.values()),
            state: IdVec::filled(func.values().len(), State::Unseen),
        }
    }

    /// A literal, or a variable already evaluated; `None` while it is unreached or on the stack.
    fn known(&self, var: VarId) -> Option<u64> {
        match self.func.var(var).constant_bits() {
            Some(bits) => Some(bits),
            None => match self.state[var] {
                State::Known(value) => value,
                State::Unseen | State::Busy => None,
            },
        }
    }

    /// The operands `var`'s value is computed from: none for an input or an opaque definition.
    fn operands(&self, var: VarId) -> Vec<VarId> {
        if self.func.var(var).version == 0 {
            return Vec::new();
        }
        match self.defs.op(var) {
            Some((_, op)) if opaque(op) => Vec::new(),
            Some((_, op)) => op.sources().into_iter().copied().collect(),
            None => self.defs.phi_sources(var).to_vec(),
        }
    }

    /// `var`'s value from its operands' (SCCP's transfer); a merge only where every input is one
    /// constant, pessimistic where SCCP is optimistic, so every cut is an SCCP cut.
    fn evaluated(&self, var: VarId) -> Option<u64> {
        if self.func.var(var).version == 0 {
            return None;
        }
        match self.defs.op(var) {
            Some((_, op)) if opaque(op) => None,
            Some((_, op)) => eval_const_op(op, &self.minting, |id| self.known(id)),
            None => {
                let mut inputs = self
                    .defs
                    .phi_sources(var)
                    .iter()
                    .map(|src| self.known(*src));
                let first = inputs.next()??;
                inputs.all(|input| input == Some(first)).then_some(first)
            }
        }
    }

    /// `root`'s value on every run. An explicit stack expands each variable once; a variable met
    /// again while on the stack is a cycle and reads `None`. `O(slice operations and operands)`.
    fn of(&mut self, root: VarId) -> Option<u64> {
        let mut stack = vec![(root, false)];
        while let Some((var, expanded)) = stack.pop() {
            if expanded {
                self.state[var] = State::Known(self.evaluated(var));
                continue;
            }
            let literal = self.func.var(var).constant_bits().is_some();
            if literal || !matches!(self.state[var], State::Unseen) {
                continue;
            }
            self.state[var] = State::Busy;
            stack.push((var, true));
            let unseen = (self.operands(var).into_iter())
                .filter(|source| matches!(self.state[*source], State::Unseen));
            stack.extend(unseen.map(|source| (source, false)).collect::<Vec<_>>());
        }
        self.known(root)
    }
}

/// `cut(b) = cut(idom b) or edge_cut(idom b, b)`, one answer per block up the dominator chain.
struct Cuts<'f> {
    func: &'f SSAFunction,
    defs: &'f Definitions,
    /// Allocated at the first condition evaluated.
    values: Option<Values<'f>>,
    /// Each block's answer, by its position in `func.blocks()`.
    answers: Vec<Option<bool>>,
}

impl Cuts<'_> {
    fn of(&mut self, block: u64) -> bool {
        let func = self.func;
        let mut chain = Vec::new();
        let mut at = block;
        let mut cut = loop {
            let Some(position) = func.block_position(at) else {
                return false;
            };
            if let Some(answer) = self.answers[position] {
                break answer;
            }
            chain.push((at, position));
            match func.idom(at) {
                Some(up) => at = up,
                None => break false,
            }
        };
        for (at, position) in chain.into_iter().rev() {
            cut = match func.idom(at) {
                Some(up) => cut || self.edge_cut(up, at),
                None => false,
            };
            self.answers[position] = Some(cut);
        }
        cut
    }

    /// `d` ends in a two-way branch, `b` is one arm and has no other predecessor, and `d`'s
    /// condition is a constant choosing the other arm.
    fn edge_cut(&mut self, d: u64, b: u64) -> bool {
        let func = self.func;
        let Some(BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        }) = func.cfg().get_block(d).map(|block| &block.terminator)
        else {
            return false;
        };
        let (taken_if_true, taken_if_false) = (*true_target, *false_target);
        if taken_if_true == taken_if_false || ![taken_if_true, taken_if_false].contains(&b) {
            return false;
        }
        if func.predecessors(b) != [d] {
            return false;
        }
        let condition = (func.get_block(d).map(|block| block.ops())).and_then(|ops| {
            ops.iter().rev().find_map(|op| match op {
                SSAOp::CBranch { cond, .. } => Some(*cond),
                _ => None,
            })
        });
        let Some(condition) = condition else {
            return false;
        };
        let defs = self.defs;
        let values = self.values.get_or_insert_with(|| Values::new(func, defs));
        match values.of(condition) {
            Some(0) => b != taken_if_false,
            Some(_) => b != taken_if_true,
            None => false,
        }
    }
}

/// Which of `blocks` a decided branch cuts off; none unless the image is linked at its addresses
/// (gABI ch. 5, "Base Address": slide 0), no effect is unmodelled and no kept transfer unresolved.
pub(crate) fn cut(
    func: &SSAFunction,
    defs: &Definitions,
    load: LoadBase,
    blocks: &[u64],
) -> Vec<bool> {
    let kept = vec![false; blocks.len()];
    if load != LoadBase::Linked || blocks.is_empty() {
        return kept;
    }
    let mut cuts = Cuts {
        func,
        defs,
        values: None,
        answers: vec![None; func.num_blocks()],
    };
    let cut = (blocks.iter())
        .map(|block| cuts.of(*block))
        .collect::<Vec<_>>();
    if !cut.contains(&true) {
        return cut;
    }
    // SCCP's `after_unmodelled_effects`: an effect no model states may write what a condition read.
    let unmodelled = (func.blocks().iter()).any(|block| {
        (block.ops().iter()).any(|op| {
            matches!(
                op,
                SSAOp::CallOther { output: None, .. } | SSAOp::Unimplemented
            )
        })
    });
    if unmodelled {
        r2il::refusal_evidence!("decided-cut", "{:#x}: an unmodelled effect", func.entry);
        return kept;
    }
    // An edge the graph lacks may enter a cut block from a kept transfer the source could not follow.
    let Some(unresolved) = func.unresolved_transfers() else {
        r2il::refusal_evidence!("decided-cut", "{:#x}: no declared transfers", func.entry);
        return kept;
    };
    let entered = (unresolved.iter()).find(|block| !cuts.of(**block));
    if let Some(block) = entered {
        let entry = func.entry;
        r2il::refusal_evidence!(
            "decided-cut",
            "{entry:#x}: unresolved transfer at {block:#x}"
        );
        return kept;
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{CFG, DeclaredSuccessors};
    use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    /// `rax = 7; zf = rax == 7; if zf goto 0x1010`, `extra` before the compare; the fall-through
    /// at 0x1008 calls 0x2000 and returns, and so does 0x1010.
    fn decided(extra: Vec<R2ILOp>) -> Vec<R2ILBlock> {
        let mut head = R2ILBlock::new(0x1000, 8);
        head.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: Varnode::constant(7, 8),
        });
        extra.into_iter().for_each(|op| head.push(op));
        head.push(R2ILOp::IntEqual {
            dst: reg(0x206, 1),
            a: reg(0, 8),
            b: Varnode::constant(7, 8),
        });
        head.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1010, 8),
            cond: reg(0x206, 1),
        });
        let returning = |addr| {
            let mut block = R2ILBlock::new(addr, 8);
            block.push(R2ILOp::Call {
                target: Varnode::constant(0x2000, 8),
            });
            block.push(R2ILOp::Return {
                target: reg(0x288, 8),
            });
            block
        };
        vec![head, returning(0x1008), returning(0x1010)]
    }

    /// The source's statement of `decided`, with `unresolved` blocks it could not follow.
    fn declared(unresolved: &[u64]) -> DeclaredSuccessors {
        let mut declared = DeclaredSuccessors::entered_at(0x1000);
        declared.insert(0x1000, [0x1008, 0x1010]);
        declared.insert(0x1008, []);
        declared.insert(0x1010, []);
        unresolved
            .iter()
            .for_each(|block| declared.mark_unresolved(*block));
        declared
    }

    /// Whether the call block 0x1008 is cut.
    fn cut_of(blocks: &[R2ILBlock], declared: Option<&DeclaredSuccessors>, load: LoadBase) -> bool {
        let cfg = CFG::from_blocks_with_declared_successors(blocks, declared).expect("a graph");
        let unresolved = declared.and_then(|declared| declared.unresolved_in(blocks, &cfg));
        let control = crate::control::UncheckedSsaWorkControl;
        let func =
            SSAFunction::from_blocks_raw_with_policy_and_control(cfg, None, None, &[], &control)
                .expect("ssa")
                .with_unresolved_transfers(unresolved);
        let defs = Definitions::of(&func);
        cut(&func, &defs, load, &[0x1008])[0]
    }

    #[test]
    fn a_branch_over_equal_constants_cuts_its_other_arm_only_where_linked() {
        let blocks = decided(Vec::new());
        assert!(cut_of(&blocks, Some(&declared(&[])), LoadBase::Linked));
        assert!(!cut_of(&blocks, Some(&declared(&[])), LoadBase::Slid));
        assert!(!cut_of(&blocks, Some(&declared(&[])), LoadBase::Unstated));
    }

    #[test]
    fn no_declaration_cuts_nothing() {
        assert!(!cut_of(&decided(Vec::new()), None, LoadBase::Linked));
    }

    #[test]
    fn an_unmodelled_effect_cuts_nothing() {
        let syscall = R2ILOp::CallOther {
            output: None,
            userop: 0,
            inputs: Vec::new(),
        };
        let blocks = decided(vec![syscall]);
        assert!(!cut_of(&blocks, Some(&declared(&[])), LoadBase::Linked));
    }

    #[test]
    fn a_kept_unresolved_transfer_cuts_nothing_and_a_cut_one_does() {
        let blocks = decided(Vec::new());
        assert!(!cut_of(
            &blocks,
            Some(&declared(&[0x1010])),
            LoadBase::Linked
        ));
        assert!(cut_of(
            &blocks,
            Some(&declared(&[0x1008])),
            LoadBase::Linked
        ));
    }

    #[test]
    fn a_loaded_condition_cuts_nothing() {
        let load = R2ILOp::Load {
            dst: reg(0, 8),
            space: SpaceId::Ram,
            addr: reg(0x38, 8),
        };
        let blocks = decided(vec![load]);
        assert!(!cut_of(&blocks, Some(&declared(&[])), LoadBase::Linked));
    }
}
