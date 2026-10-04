//! Which bytes of each value the function's meaning reads.
//!
//! A machine writes registers by lanes: `setg al` puts one byte in RAX and
//! leaves the other seven holding whatever the caller left there. When nothing
//! downstream reads those seven -- `movzbl %al` keeps one byte, a 32-bit OR
//! keeps four -- the entry value they came from is not an input of anything the
//! function computes, and a reading of the C that names it reads a value no
//! statement assigned for bytes nobody uses.
//!
//! The fact is a byte mask per value, computed backwards over the graph:
//!
//! - **Roots.** A value leaving through a return register is demanded whole --
//!   being read by the caller is a use (`FunctionLiveOut`), and so is a
//!   carrier a call boundary reads (`CallUse`, read at its widest). Those are
//!   all the roots only where every exit is one of them: a tail jump or a
//!   transfer the walk could not follow hands every register to code this
//!   graph does not see, and a return whose value was not found names no
//!   root, so such a function releases nothing ([`exits_are_named`]). Every operation
//!   this module does not model exactly demands its inputs whole, whether or
//!   not its own result is read: a division or a load can trap, a store or a
//!   call has effects, and none of that may depend on bytes this pass calls
//!   free.
//! - **Exact transfer**, for operations that are pure and cannot trap: copies,
//!   zero and sign extension (a sign extension past its source also reads the
//!   source's top byte), lane extraction and concatenation, the three bitwise
//!   operations, a byte-aligned INSERT, and merges.
//!
//! The masks only grow, each at most to its value's width, so the worklist
//! ends after O((V + E) * W) steps for width W in bytes.
//!
//! The one rewrite it licenses: an INSERT whose demanded bytes all lie in the
//! inserted lane does not read its base, and the base is replaced by zero --
//! no demanded bit changes, and the value the base held loses a reader it
//! never needed. This is the demanded-bits simplification compilers apply,
//! done with the proof rather than a pattern.

use crate::SSAFunction;
use crate::cfg::BlockTerminator;
use crate::function::EditPlan;
use crate::graph::{GraphInst, InstPayload, SsaGraph, ValueId};
use crate::liveout::FunctionLiveOut;
use crate::op::SSAOp;
use crate::var::SSAVar;

/// Every byte of a value `size` bytes wide.
const fn whole(size: u32) -> u64 {
    if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    }
}

/// The bytes of a constant that are not zero, as a byte mask.
fn nonzero_bytes(bits: u64) -> u64 {
    (0..8)
        .filter(|byte| (bits >> (byte * 8)) & 0xff != 0)
        .fold(0, |mask, byte| mask | (1 << byte))
}

/// The bytes an INSERT's value occupies in its result, where its position is
/// a byte-aligned constant.
fn inserted_lane(value: &SSAVar, position: &SSAVar) -> Option<(u32, u64)> {
    let bits = position.constant_bits()?;
    if bits % 8 != 0 || bits / 8 >= 64 {
        return None;
    }
    let first = u32::try_from(bits / 8).ok()?;
    Some((first, whole(value.size).checked_shl(first).unwrap_or(0)))
}

/// How an operation's inputs are demanded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Pure, and the bytes of each input it reads follow from the bytes of
    /// its output that are read (`transfer`).
    Exact,
    /// Pure and cannot trap: it reads its inputs whole, but only where its
    /// own result is read. A flag computed and never tested reads nothing.
    Pure,
    /// Touches memory, transfers control, calls, can trap, or is a user
    /// operation: it reads its inputs whole whatever becomes of its result.
    Effect,
}

fn kind(graph: &SsaGraph, inst: &GraphInst) -> Kind {
    let op = match &inst.payload {
        InstPayload::Phi { .. } => return Kind::Exact,
        InstPayload::Op(op) => op,
    };
    match op {
        SSAOp::Copy { .. }
        | SSAOp::IntZExt { .. }
        | SSAOp::IntSExt { .. }
        | SSAOp::Subpiece { .. }
        | SSAOp::Piece { .. }
        | SSAOp::IntAnd { .. }
        | SSAOp::IntOr { .. }
        | SSAOp::IntXor { .. } => Kind::Exact,
        SSAOp::Insert(insert) => {
            match inserted_lane(graph.var(insert.value), graph.var(insert.position)) {
                Some(_) => Kind::Exact,
                None => Kind::Pure,
            }
        }
        SSAOp::IntAdd { .. }
        | SSAOp::IntSub { .. }
        | SSAOp::IntMult { .. }
        | SSAOp::IntNegate { .. }
        | SSAOp::IntCarry { .. }
        | SSAOp::IntSCarry { .. }
        | SSAOp::IntSBorrow { .. }
        | SSAOp::IntNot { .. }
        | SSAOp::IntLeft { .. }
        | SSAOp::IntRight { .. }
        | SSAOp::IntSRight { .. }
        | SSAOp::IntEqual { .. }
        | SSAOp::IntNotEqual { .. }
        | SSAOp::IntLess { .. }
        | SSAOp::IntSLess { .. }
        | SSAOp::IntLessEqual { .. }
        | SSAOp::IntSLessEqual { .. }
        | SSAOp::BoolNot { .. }
        | SSAOp::BoolAnd { .. }
        | SSAOp::BoolOr { .. }
        | SSAOp::BoolXor { .. }
        | SSAOp::PopCount { .. }
        | SSAOp::Lzcount { .. }
        | SSAOp::FloatAdd { .. }
        | SSAOp::FloatSub { .. }
        | SSAOp::FloatMult { .. }
        | SSAOp::FloatDiv { .. }
        | SSAOp::FloatNeg { .. }
        | SSAOp::FloatAbs { .. }
        | SSAOp::FloatSqrt { .. }
        | SSAOp::FloatCeil { .. }
        | SSAOp::FloatFloor { .. }
        | SSAOp::FloatRound { .. }
        | SSAOp::FloatNaN { .. }
        | SSAOp::FloatEqual { .. }
        | SSAOp::FloatNotEqual { .. }
        | SSAOp::FloatLess { .. }
        | SSAOp::FloatLessEqual { .. }
        | SSAOp::Int2Float { .. }
        | SSAOp::Float2Int { .. }
        | SSAOp::FloatFloat { .. }
        | SSAOp::Trunc { .. }
        | SSAOp::PtrAdd { .. }
        | SSAOp::PtrSub { .. }
        | SSAOp::Cast { .. }
        | SSAOp::Extract { .. }
        | SSAOp::Select(_)
        | SSAOp::Nop => Kind::Pure,
        _ => Kind::Effect,
    }
}

/// The bytes of each input an exact operation reads when `demanded` of its
/// output is read, in input order.
fn transfer(
    graph: &SsaGraph,
    inst: &GraphInst,
    demanded: u64,
    size: impl Fn(ValueId) -> u32,
) -> Vec<u64> {
    let of = |index: usize| {
        inst.inputs
            .get(index)
            .map_or(0, |value| whole(size(*value)))
    };
    match &inst.payload {
        InstPayload::Phi { .. } => (0..inst.inputs.len())
            .map(|index| demanded & of(index))
            .collect(),
        InstPayload::Op(op) => match op {
            // A byte the constant operand clears is zero whatever the other
            // operand holds there, so the other is not read at that byte.
            SSAOp::IntAnd { a, b, .. } => {
                let kept = |other: &ValueId| match size(*other) <= 8 {
                    true => graph
                        .var(*other)
                        .constant_bits()
                        .map_or(u64::MAX, nonzero_bytes),
                    false => u64::MAX,
                };
                vec![demanded & kept(b) & of(0), demanded & kept(a) & of(1)]
            }
            SSAOp::Copy { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. } => (0..inst.inputs.len())
                .map(|index| demanded & of(index))
                .collect(),
            SSAOp::IntSExt { src, .. } => {
                let within = whole(size(*src));
                let sign = match demanded & !within {
                    0 => 0,
                    _ => 1u64.checked_shl(size(*src).saturating_sub(1)).unwrap_or(0),
                };
                vec![(demanded & within) | sign]
            }
            SSAOp::Subpiece { offset, .. } => {
                vec![demanded.checked_shl(*offset).unwrap_or(0) & of(0)]
            }
            SSAOp::Piece { lo, .. } => vec![
                demanded.checked_shr(size(*lo)).unwrap_or(0) & of(0),
                demanded & of(1),
            ],
            SSAOp::Insert(insert) => {
                let Some((first, lane)) =
                    inserted_lane(graph.var(insert.value), graph.var(insert.position))
                else {
                    return vec![of(0), of(1), of(2)];
                };
                vec![
                    demanded & !lane & of(0),
                    demanded.checked_shr(first).unwrap_or(0) & of(1),
                    of(2),
                ]
            }
            _ => (0..inst.inputs.len()).map(of).collect(),
        },
    }
}

/// Whether every way control leaves the function reads registers this
/// module sees: a return whose outgoing values were named, or a call that
/// does not come back, whose arguments its `CallUse`s read.
///
/// A conditional exit, an indirect branch, a jump out of the body, or a block
/// the walk could not end hands the registers to code whose reads are not in
/// the graph, so none of their bytes may be called free.
pub(crate) fn exits_are_named(function: &SSAFunction, live_out: &FunctionLiveOut) -> bool {
    if live_out.unresolved_blocks().next().is_some() {
        return false;
    }
    let cfg = function.cfg();
    cfg.blocks().all(|block| {
        let successors = block.successors();
        let leaves =
            successors.is_empty() || successors.iter().any(|next| cfg.get_block(*next).is_none());
        match &block.terminator {
            BlockTerminator::Return => true,
            BlockTerminator::ConditionalExit { .. } => false,
            BlockTerminator::Call { .. } | BlockTerminator::IndirectCall { .. } => {
                successors.is_empty() || !leaves
            }
            _ => !leaves,
        }
    })
}

/// The bytes of each value something reads.
pub(crate) struct Demand {
    bytes: Vec<u64>,
}

impl Demand {
    pub(crate) fn of(graph: &SsaGraph, live_out: &FunctionLiveOut) -> Self {
        let size = |value: ValueId| graph.value(value).map_or(64, |value| value.var.size);
        let mut demand = Self {
            bytes: vec![0u64; graph.values.len()],
        };
        let mut pending = Vec::new();
        for value in live_out.iter() {
            demand.raise(value, whole(size(value)), &mut pending);
        }
        for inst in graph
            .insts
            .iter()
            .filter(|inst| kind(graph, inst) == Kind::Effect)
        {
            for input in &inst.inputs {
                demand.raise(*input, whole(size(*input)), &mut pending);
            }
        }
        while let Some(value) = pending.pop() {
            let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
                continue;
            };
            let masks = match kind(graph, inst) {
                Kind::Exact => transfer(graph, inst, demand.bytes(value), size),
                Kind::Pure => inst
                    .inputs
                    .iter()
                    .map(|input| whole(size(*input)))
                    .collect(),
                Kind::Effect => continue,
            };
            for (input, mask) in inst.inputs.iter().zip(masks) {
                demand.raise(*input, mask, &mut pending);
            }
        }
        demand
    }

    /// Add `mask` to what `value` has demanded, queueing it where that grew.
    fn raise(&mut self, value: ValueId, mask: u64, pending: &mut Vec<ValueId>) {
        let Some(held) = self.bytes.get_mut(value.0 as usize) else {
            return;
        };
        if *held | mask != *held {
            *held |= mask;
            pending.push(value);
        }
    }

    /// The bytes of `value` something reads.
    pub(crate) fn bytes(&self, value: ValueId) -> u64 {
        self.bytes
            .get(value.0 as usize)
            .copied()
            .unwrap_or(u64::MAX)
    }
}

impl SSAFunction {
    /// The plan that replaces by zero the base of every INSERT whose demanded
    /// bytes all lie in its inserted lane, computed over `graph`, a graph of
    /// this function as it stands. Empty where nothing is released.
    pub(crate) fn release_undemanded_insert_bases(
        &self,
        graph: &SsaGraph,
        demand: &Demand,
    ) -> EditPlan {
        let mut plan = EditPlan::new();
        let mut minting = crate::value_table::Minting::new(self.values());
        for inst in &graph.insts {
            let InstPayload::Op(SSAOp::Insert(insert)) = &inst.payload else {
                continue;
            };
            let base = graph.var(insert.src);
            if base.constant_bits().is_some() {
                continue;
            }
            let (Some(output), Some((_, lane))) = (
                inst.output,
                inserted_lane(graph.var(insert.value), graph.var(insert.position)),
            ) else {
                continue;
            };
            if demand.bytes(output) & !lane & whole(base.size) != 0 {
                r2il::refusal_evidence!(
                    "demanded-bytes",
                    "{} keeps its base {}: bytes {:#x} are read, the lane is {lane:#x}",
                    graph.var(insert.dst),
                    base,
                    demand.bytes(output)
                );
                continue;
            }
            // The operation as the function holds it, which the graph's
            // payload restates.
            let Some((id, SSAOp::Insert(insert))) = graph.op_for_inst(inst.id).and_then(|id| {
                let block = self.get_block(graph.block_addr_of(inst.id)?)?;
                Some((id, block.ops().get(block.position(id)?)?))
            }) else {
                continue;
            };
            r2il::refusal_evidence!(
                "demanded-bytes",
                "{} reads no byte of its base {} outside the inserted lane",
                self.var(insert.dst),
                self.var(insert.src)
            );
            let mut released = insert.clone();
            released.src = minting.constant(0, self.var(insert.src).size);
            plan.replace(id, SSAOp::Insert(released));
        }
        plan.adopt(minting.finish());
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn x86_64_arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("EAX", 0, 4));
        arch.add_register(RegisterDef::new("RCX", 0x8, 8));
        arch.add_register(RegisterDef::new("RDX", 0x10, 8));
        arch.add_register(RegisterDef::new("DL", 0x10, 1));
        arch.add_register(RegisterDef::new("RIP", 0x288, 8));
        arch
    }

    /// `rcx = rdx; dl = 1; eax = zext(dl)`, then `exit`. (The copy is there
    /// so the function touches all of RDX, which makes `dl` a lane of it.)
    /// Answers whether the INSERT that put `dl` into RDX was released from
    /// its base.
    fn released(exit: R2ILOp) -> bool {
        let block = R2ILBlock {
            addr: 0x1000,
            size: 8,
            ops: vec![
                R2ILOp::Copy {
                    dst: reg(0x8, 8),
                    src: reg(0x10, 8),
                },
                R2ILOp::Copy {
                    dst: reg(0x10, 1),
                    src: Varnode::constant(1, 1),
                },
                R2ILOp::IntZExt {
                    dst: reg(0, 4),
                    src: reg(0x10, 1),
                },
                exit,
            ],
            ..R2ILBlock::default()
        };
        let function = SSAFunction::from_blocks_raw(&[block], Some(&x86_64_arch())).expect("ssa");
        assert!(
            function
                .named_blocks()
                .iter()
                .flat_map(|block| block.ops())
                .any(|op| matches!(op, SSAOp::Insert(_))),
            "the byte write is an INSERT into RDX"
        );
        let graph = SsaGraph::from_function(&function);
        let rax = crate::CanonicalStorageId {
            space: crate::CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        };
        let live_out = FunctionLiveOut::compute(&function, &graph, &[rax]);
        if !exits_are_named(&function, &live_out) {
            return false;
        }
        let demand = Demand::of(&graph, &live_out);
        !function
            .release_undemanded_insert_bases(&graph, &demand)
            .is_empty()
    }

    #[test]
    fn a_returning_function_does_not_read_the_bytes_a_lane_write_left() {
        assert!(released(R2ILOp::Return {
            target: reg(0x288, 8),
        }));
    }

    /// The target of a jump out of the body may take RDX as an argument, and
    /// what it reads there is no use in this graph.
    #[test]
    fn a_jump_out_of_the_function_releases_nothing() {
        assert!(!released(R2ILOp::Branch {
            target: Varnode::new(SpaceId::Ram, 0x2000, 8),
        }));
    }
}
