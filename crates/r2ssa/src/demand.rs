//! Which bytes of each value the function's meaning reads (doc/adr-byte-relation.md),
//! and the one rewrite it licenses: an INSERT read only in its lane does not read its base.

use std::collections::BTreeSet;

use crate::SSAFunction;
use crate::bytes::ByteMask;
use crate::cfg::BlockTerminator;
use crate::function::EditPlan;
use crate::graph::{GraphInst, InstPayload, SsaGraph, UseSite, ValueId};
use crate::liveout::FunctionLiveOut;
use crate::op::SSAOp;
use crate::var::{CanonicalStorageId, SSAVar};

/// Every byte of a value `size` bytes wide.
const fn whole(size: u32) -> u64 {
    if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    }
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

/// Whether an operation reads its inputs whatever becomes of its result
/// (memory, control, a call, a trap, a user operation), unlike a pure one.
pub(crate) fn has_effect(inst: &GraphInst) -> bool {
    let op = match &inst.payload {
        InstPayload::Phi { .. } => return false,
        InstPayload::Op(op) => op,
    };
    !matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::Subpiece { .. }
            | SSAOp::Piece { .. }
            | SSAOp::IntAnd { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. }
            | SSAOp::Insert(_)
            | SSAOp::IntAdd { .. }
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
            | SSAOp::Nop
    )
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

/// The bytes of each value something reads: the one byte closure
/// (`crate::bytes::closure`) from the return values and every input of an
/// operation with an effect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemandedBytes {
    bytes: crate::dense::IdMap<ValueId, ByteMask>,
}

impl DemandedBytes {
    pub(crate) fn of(graph: &SsaGraph, live_out: &FunctionLiveOut) -> Self {
        Self::of_returning(graph, live_out, None, &BTreeSet::new())
    }

    /// The same, where a return reads of its values only the bytes in `result`, the result
    /// carrier the function's interface states (`None` reads them whole), and no `ignored` read.
    pub(crate) fn of_returning(
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        result: Option<CanonicalStorageId>,
        ignored: &BTreeSet<UseSite>,
    ) -> Self {
        let returned = live_out.iter().map(|value| {
            let storage = graph.value(value).and_then(|value| value.canonical_storage);
            let mask = match (storage, result) {
                (Some(storage), Some(result)) if storage.location() == result.location() => {
                    ByteMask::whole(result.size.min(storage.size))
                }
                _ => ByteMask::All,
            };
            (value, mask)
        });
        let effects = graph
            .insts
            .iter()
            .filter(|inst| has_effect(inst))
            .flat_map(|inst| {
                let read = |(input_idx, _): &(usize, &ValueId)| {
                    !ignored.contains(&UseSite {
                        inst: inst.id,
                        input_idx: *input_idx,
                    })
                };
                (inst.inputs.iter().enumerate())
                    .filter(read)
                    .map(|(_, input)| (*input, ByteMask::All))
            });
        Self {
            bytes: crate::bytes::closure_of(graph, returned.chain(effects)).bytes,
        }
    }

    /// The bytes of `value` something reads, bit `b` for byte `b`.
    pub fn bytes(&self, value: ValueId) -> u64 {
        match self.bytes.get(value) {
            None => 0,
            Some(ByteMask::Bytes(bytes)) => *bytes,
            Some(ByteMask::All) => u64::MAX,
        }
    }
}

impl SSAFunction {
    /// The plan that replaces by zero the base of every INSERT whose demanded
    /// bytes all lie in its inserted lane, computed over `graph`, a graph of
    /// this function as it stands. Empty where nothing is released.
    pub(crate) fn release_undemanded_insert_bases(
        &self,
        graph: &SsaGraph,
        demand: &DemandedBytes,
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

    fn x86_64_arch() -> crate::Arch {
        crate::Arch::new(x86_64_arch_spec())
    }

    fn x86_64_arch_spec() -> ArchSpec {
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
        let demand = DemandedBytes::of(&graph, &live_out);
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
