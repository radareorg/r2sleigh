//! SSA operation definitions.
//!
//! These mirror r2il::R2ILOp but use SSAVar instead of Varnode,
//! providing versioned variables for dataflow analysis.

use serde::{Deserialize, Serialize};

use crate::var::SSAVar;
use r2il::{MemoryOrdering, SpaceId};

/// An SSA operation representing a single semantic action with versioned variables.
///
/// Each operation uses SSAVar which includes version numbers, enabling
/// precise tracking of definitions and uses for dataflow analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SSAOp<V = SSAVar> {
    // ========== SSA-specific Operations ==========
    /// Phi function: merges values from different control flow paths.
    /// `dst = phi(sources[0], sources[1], ...)`
    Phi { dst: V, sources: Vec<V> },

    // ========== Data Movement ==========
    /// Copy src to dst: dst = src
    Copy { dst: V, src: V },

    /// Load from memory: `dst = *[space]addr`
    Load { dst: V, space: SpaceId, addr: V },

    /// Store to memory: `*[space]addr = val`
    Store { space: SpaceId, addr: V, val: V },

    /// One repeated string operation, as the block it is (`r2il::R2ILOp::BlockTransfer`).
    BlockTransfer(Box<BlockTransferOp<V>>),

    /// Memory fence/barrier.
    Fence { ordering: MemoryOrdering },

    /// Load-linked from memory.
    LoadLinked {
        dst: V,
        space: SpaceId,
        addr: V,
        ordering: MemoryOrdering,
    },

    /// Store-conditional to memory.
    StoreConditional {
        result: Option<V>,
        space: SpaceId,
        addr: V,
        val: V,
        ordering: MemoryOrdering,
    },

    /// Atomic compare-and-swap.
    AtomicCAS(Box<AtomicCasOp<V>>),

    /// Guarded memory load.
    LoadGuarded {
        dst: V,
        space: SpaceId,
        addr: V,
        guard: V,
        ordering: MemoryOrdering,
    },

    /// Guarded memory store.
    StoreGuarded {
        space: SpaceId,
        addr: V,
        val: V,
        guard: V,
        ordering: MemoryOrdering,
    },

    // ========== Integer Arithmetic ==========
    /// Integer addition: dst = a + b
    IntAdd { dst: V, a: V, b: V },

    /// Integer subtraction: dst = a - b
    IntSub { dst: V, a: V, b: V },

    /// Integer multiplication: dst = a * b
    IntMult { dst: V, a: V, b: V },

    /// Unsigned integer division: dst = a / b
    IntDiv { dst: V, a: V, b: V },

    /// Signed integer division: dst = a / b (signed)
    IntSDiv { dst: V, a: V, b: V },

    /// Unsigned integer remainder: dst = a % b
    IntRem { dst: V, a: V, b: V },

    /// Signed integer remainder: dst = a % b (signed)
    IntSRem { dst: V, a: V, b: V },

    /// Two's complement negation: dst = -src
    IntNegate { dst: V, src: V },

    /// Addition with carry: dst = a + b + carry
    IntCarry { dst: V, a: V, b: V },

    /// Signed carry (overflow): dst = overflow(a + b)
    IntSCarry { dst: V, a: V, b: V },

    /// Signed borrow: dst = borrow(a - b)
    IntSBorrow { dst: V, a: V, b: V },

    // ========== Logical Operations ==========
    /// Bitwise AND: dst = a & b
    IntAnd { dst: V, a: V, b: V },

    /// Bitwise OR: dst = a | b
    IntOr { dst: V, a: V, b: V },

    /// Bitwise XOR: dst = a ^ b
    IntXor { dst: V, a: V, b: V },

    /// Bitwise NOT: dst = ~src
    IntNot { dst: V, src: V },

    // ========== Shift Operations ==========
    /// Left shift: dst = a << b
    IntLeft { dst: V, a: V, b: V },

    /// Logical right shift: dst = a >> b (unsigned)
    IntRight { dst: V, a: V, b: V },

    /// Arithmetic right shift: dst = a >> b (signed)
    IntSRight { dst: V, a: V, b: V },

    // ========== Comparison Operations ==========
    /// Equality: dst = (a == b) ? 1 : 0
    IntEqual { dst: V, a: V, b: V },

    /// Inequality: dst = (a != b) ? 1 : 0
    IntNotEqual { dst: V, a: V, b: V },

    /// Unsigned less than: dst = (a < b) ? 1 : 0
    IntLess { dst: V, a: V, b: V },

    /// Signed less than: dst = (a < b) ? 1 : 0 (signed)
    IntSLess { dst: V, a: V, b: V },

    /// Unsigned less or equal: dst = (a <= b) ? 1 : 0
    IntLessEqual { dst: V, a: V, b: V },

    /// Signed less or equal: dst = (a <= b) ? 1 : 0 (signed)
    IntSLessEqual { dst: V, a: V, b: V },

    // ========== Extension Operations ==========
    /// Zero extension: dst = zext(src)
    IntZExt { dst: V, src: V },

    /// Sign extension: dst = sext(src)
    IntSExt { dst: V, src: V },

    // ========== Boolean Operations ==========
    /// Boolean NOT: dst = !src
    BoolNot { dst: V, src: V },

    /// Boolean AND: dst = a && b
    BoolAnd { dst: V, a: V, b: V },

    /// Boolean OR: dst = a || b
    BoolOr { dst: V, a: V, b: V },

    /// Boolean XOR: dst = a ^^ b
    BoolXor { dst: V, a: V, b: V },

    // ========== Bit Manipulation ==========
    /// Concatenate two values: dst = (hi << lo.size*8) | lo
    Piece { dst: V, hi: V, lo: V },

    /// Extract a portion of a value: `dst = src[offset:size]`
    Subpiece { dst: V, src: V, offset: u32 },

    /// Population count (number of 1 bits): dst = popcount(src)
    PopCount { dst: V, src: V },

    /// Count leading zeros: dst = clz(src)
    Lzcount { dst: V, src: V },

    // ========== Control Flow ==========
    /// Unconditional branch to target.
    ///
    /// `instruction` is the native instruction the transfer was lifted from,
    /// absent for a synthetic transfer. It is the one coordinate of a call or
    /// tail transfer that every later rewrite of the operation stream leaves
    /// alone, so it is how a fact recorded against the raw input finds this
    /// operation again.
    Branch {
        target: V,
        #[serde(default)]
        instruction: Option<u64>,
    },

    /// Conditional branch: if (cond) goto target
    CBranch { target: V, cond: V },

    /// Indirect branch: goto *target
    BranchInd {
        target: V,
        #[serde(default)]
        instruction: Option<u64>,
    },

    /// Multiway branch on `selector`; the block's terminator carries the cases.
    Switch { selector: V },

    /// Call a subroutine
    Call {
        target: V,
        #[serde(default)]
        instruction: Option<u64>,
    },

    /// Indirect call: call *target
    CallInd {
        target: V,
        #[serde(default)]
        instruction: Option<u64>,
    },

    /// Fresh unknown register value defined by a call boundary.
    ///
    /// Decompiler-safe SSA emits this after calls for return/caller-saved
    /// registers so later reads cannot reuse pre-call versions.
    CallDefine { dst: V },

    /// The carrier a call boundary leaves holding the value it found there.
    ///
    /// The sibling of `CallDefine`, and the same kind of fact: both say what
    /// the boundary did to a register, and neither is an operation this
    /// function's code performs. Where `CallDefine` says the callee left a
    /// register holding something unknowable, this says the callee put one
    /// back.
    ///
    /// The stack pointer is why it exists. A call instruction's own p-code
    /// spends whatever the architecture spends to transfer control -- on
    /// x86-64 `RSP = RSP - 8` and the store of the return address -- and the
    /// callee's return refunds it. The callee is not part of this function, so
    /// without this the refund never happens and the caller's stack pointer
    /// drifts by one return-address slot at every call it makes.
    CallRestore { dst: V, src: V },

    /// A carrier a call boundary may read, as the convention names it.
    ///
    /// The third of the same family as `CallDefine` and `CallRestore`, and the
    /// one that was missing. A call instruction's own p-code names only the
    /// callee, so nothing downstream could see that a call consumes its
    /// arguments: liveness could not keep their producers, and the obligation
    /// inventory had to keep every definition reaching an incomplete boundary
    /// out of `ProvenDead` by declaring it an unknown effect instead.
    ///
    /// This says the true thing in the graph. The carriers are the
    /// convention's argument registers, so the set is bounded by the
    /// architecture rather than by the function's size, and a carrier the
    /// callee does not actually take is a read of a value that is live anyway.
    CallUse { src: V },

    /// Return from subroutine
    Return { target: V },

    // ========== Floating Point ==========
    /// Float addition: dst = a + b
    FloatAdd { dst: V, a: V, b: V },

    /// Float subtraction: dst = a - b
    FloatSub { dst: V, a: V, b: V },

    /// Float multiplication: dst = a * b
    FloatMult { dst: V, a: V, b: V },

    /// Float division: dst = a / b
    FloatDiv { dst: V, a: V, b: V },

    /// Float negation: dst = -src
    FloatNeg { dst: V, src: V },

    /// Float absolute value: dst = |src|
    FloatAbs { dst: V, src: V },

    /// Float square root: dst = sqrt(src)
    FloatSqrt { dst: V, src: V },

    /// Float ceiling: dst = ceil(src)
    FloatCeil { dst: V, src: V },

    /// Float floor: dst = floor(src)
    FloatFloor { dst: V, src: V },

    /// Float round: dst = round(src)
    FloatRound { dst: V, src: V },

    /// Float is NaN: dst = isnan(src)
    FloatNaN { dst: V, src: V },

    /// Float equality: dst = (a == b) ? 1 : 0
    FloatEqual { dst: V, a: V, b: V },

    /// Float not equal: dst = (a != b) ? 1 : 0
    FloatNotEqual { dst: V, a: V, b: V },

    /// Float less than: dst = (a < b) ? 1 : 0
    FloatLess { dst: V, a: V, b: V },

    /// Float less or equal: dst = (a <= b) ? 1 : 0
    FloatLessEqual { dst: V, a: V, b: V },

    /// Convert int to float: dst = (float)src
    Int2Float { dst: V, src: V },

    /// Convert float to int: dst = (int)src
    Float2Int { dst: V, src: V },

    /// Convert float to different size float: dst = (float_new_size)src
    FloatFloat { dst: V, src: V },

    /// Truncate float to int: dst = trunc(src)
    Trunc { dst: V, src: V },

    // ========== Special Operations ==========
    /// Call a user-defined operation (CALLOTHER in P-code)
    CallOther {
        /// Optional output varnode
        output: Option<V>,
        /// User-defined operation index
        userop: u32,
        /// Input arguments
        inputs: Vec<V>,
    },

    /// No operation (placeholder)
    Nop,

    /// Unimplemented instruction
    Unimplemented,

    /// CPU identification (CPUID-like)
    CpuId { dst: V },

    /// Insert a breakpoint
    Breakpoint,

    /// Pointer addition: dst = base + (index * element_size)
    PtrAdd {
        dst: V,
        base: V,
        index: V,
        element_size: u32,
    },

    /// Pointer subtraction: dst = base - (index * element_size)
    PtrSub {
        dst: V,
        base: V,
        index: V,
        element_size: u32,
    },

    /// Segment calculation: dst = segment:offset
    SegmentOp { dst: V, segment: V, offset: V },

    /// New (allocation, used in high-level analysis)
    New { dst: V, src: V },

    /// Cast (type cast, used in high-level analysis)
    Cast { dst: V, src: V },

    /// Extract (bit field extraction)
    Extract { dst: V, src: V, position: V },

    /// Insert (bit field insertion)
    Insert(Box<InsertOp<V>>),

    /// Conditional merge of two values from instruction-local P-code control.
    Select(Box<SelectOp<V>>),
}

/// A repeated string operation, as one block operation.
///
/// Held out of line for the same reason as [`SelectOp`]: four variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransferOp<V = SSAVar> {
    pub space: SpaceId,
    pub kind: r2il::BlockTransferKind,
    pub destination: V,
    pub source: V,
    pub count: V,
    pub direction: V,
    pub element_size: u32,
    /// A scan's or a compare's count reached and the last element or pair it compared.
    pub answer: Option<V>,
}

impl BlockTransferOp {
    /// The direction's position among the inputs, after the destination, the source and the count.
    pub const DIRECTION_INPUT: usize = 3;
}

/// A compare-and-swap on one memory cell.
///
/// Held out of line for the same reason as [`SelectOp`]: four variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicCasOp<V = SSAVar> {
    pub dst: V,
    pub space: SpaceId,
    pub addr: V,
    pub expected: V,
    pub replacement: V,
    pub ordering: MemoryOrdering,
}

/// A field written into a value at a position.
///
/// Held out of line for the same reason as [`SelectOp`]: four variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertOp<V = SSAVar> {
    pub dst: V,
    pub src: V,
    pub value: V,
    pub position: V,
}

/// A conditional choice between two values.
///
/// Held out of line: it names four variables where nearly every other
/// operation names three, and an enum is as wide as its widest variant, so
/// those four set the width of every operation the function holds, of the
/// graph's copy of them and of normalization's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectOp<V = SSAVar> {
    pub dst: V,
    pub cond: V,
    pub if_true: V,
    pub if_false: V,
}

impl<V> BlockTransferOp<V> {
    /// The same operation over other operands; see [`SSAOp::map`].
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> BlockTransferOp<W> {
        BlockTransferOp {
            space: self.space,
            kind: self.kind,
            destination: f(&self.destination),
            source: f(&self.source),
            count: f(&self.count),
            direction: f(&self.direction),
            element_size: self.element_size,
            answer: self.answer.as_ref().map(&mut *f),
        }
    }
}

impl<V> AtomicCasOp<V> {
    /// The same operation over other operands; see [`SSAOp::map`].
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> AtomicCasOp<W> {
        AtomicCasOp {
            dst: f(&self.dst),
            space: self.space,
            addr: f(&self.addr),
            expected: f(&self.expected),
            replacement: f(&self.replacement),
            ordering: self.ordering,
        }
    }
}

impl<V> InsertOp<V> {
    /// The same operation over other operands; see [`SSAOp::map`].
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> InsertOp<W> {
        InsertOp {
            dst: f(&self.dst),
            src: f(&self.src),
            value: f(&self.value),
            position: f(&self.position),
        }
    }
}

impl<V> SelectOp<V> {
    /// The same operation over other operands; see [`SSAOp::map`].
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> SelectOp<W> {
        SelectOp {
            dst: f(&self.dst),
            cond: f(&self.cond),
            if_true: f(&self.if_true),
            if_false: f(&self.if_false),
        }
    }
}

/// An operand's width in bytes and, for a constant, its bits: what the
/// structural readers of an operation ask of an operand, read off the
/// variable itself. A graph operation's operand answers the same through its
/// value's variable.
pub(crate) fn var_facts(var: &SSAVar) -> (u32, Option<u64>) {
    (var.size, var.constant_bits())
}

/// The name a block operation is printed under, and the comparison that stops it.
pub(crate) const fn block_transfer_spelling(
    kind: r2il::BlockTransferKind,
) -> (&'static str, &'static str) {
    use r2il::{BlockStop, BlockTransferKind};
    match kind {
        BlockTransferKind::Move => ("MOVE", ""),
        BlockTransferKind::Fill => ("FILL", ""),
        BlockTransferKind::Scan(BlockStop::Equal) => ("SCAN", " until equal"),
        BlockTransferKind::Scan(BlockStop::Unequal) => ("SCAN", " until unequal"),
        BlockTransferKind::Compare(BlockStop::Equal) => ("COMPARE", " until equal"),
        BlockTransferKind::Compare(BlockStop::Unequal) => ("COMPARE", " until unequal"),
    }
}

impl<V> SSAOp<V> {
    /// The same operation with each source mapped by `f` and its
    /// destination kept. The destination is told apart by where it is held,
    /// not by its value.
    pub fn map_sources(&self, f: impl Fn(&V) -> V) -> SSAOp<V>
    where
        V: Clone,
    {
        let dst = self.dst().map(std::ptr::from_ref);
        self.map(&mut |operand: &V| {
            if Some(std::ptr::from_ref(operand)) == dst {
                operand.clone()
            } else {
                f(operand)
            }
        })
    }

    /// The same operation over other operands: each operand, destination
    /// and source alike, mapped by `f` in field order; everything else kept.
    pub fn map<W>(&self, f: &mut impl FnMut(&V) -> W) -> SSAOp<W> {
        use SSAOp::*;
        match self {
            Phi { dst, sources } => Phi {
                dst: f(dst),
                sources: sources.iter().map(&mut *f).collect(),
            },
            Copy { dst, src } => Copy {
                dst: f(dst),
                src: f(src),
            },
            Load { dst, space, addr } => Load {
                dst: f(dst),
                space: *space,
                addr: f(addr),
            },
            Store { space, addr, val } => Store {
                space: *space,
                addr: f(addr),
                val: f(val),
            },
            BlockTransfer(op) => BlockTransfer(Box::new(op.map(f))),
            Fence { ordering } => Fence {
                ordering: *ordering,
            },
            LoadLinked {
                dst,
                space,
                addr,
                ordering,
            } => LoadLinked {
                dst: f(dst),
                space: *space,
                addr: f(addr),
                ordering: *ordering,
            },
            StoreConditional {
                result,
                space,
                addr,
                val,
                ordering,
            } => StoreConditional {
                result: result.as_ref().map(&mut *f),
                space: *space,
                addr: f(addr),
                val: f(val),
                ordering: *ordering,
            },
            AtomicCAS(op) => AtomicCAS(Box::new(op.map(f))),
            LoadGuarded {
                dst,
                space,
                addr,
                guard,
                ordering,
            } => LoadGuarded {
                dst: f(dst),
                space: *space,
                addr: f(addr),
                guard: f(guard),
                ordering: *ordering,
            },
            StoreGuarded {
                space,
                addr,
                val,
                guard,
                ordering,
            } => StoreGuarded {
                space: *space,
                addr: f(addr),
                val: f(val),
                guard: f(guard),
                ordering: *ordering,
            },
            IntAdd { dst, a, b } => IntAdd {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSub { dst, a, b } => IntSub {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntMult { dst, a, b } => IntMult {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntDiv { dst, a, b } => IntDiv {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSDiv { dst, a, b } => IntSDiv {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntRem { dst, a, b } => IntRem {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSRem { dst, a, b } => IntSRem {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntNegate { dst, src } => IntNegate {
                dst: f(dst),
                src: f(src),
            },
            IntCarry { dst, a, b } => IntCarry {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSCarry { dst, a, b } => IntSCarry {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSBorrow { dst, a, b } => IntSBorrow {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntAnd { dst, a, b } => IntAnd {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntOr { dst, a, b } => IntOr {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntXor { dst, a, b } => IntXor {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntNot { dst, src } => IntNot {
                dst: f(dst),
                src: f(src),
            },
            IntLeft { dst, a, b } => IntLeft {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntRight { dst, a, b } => IntRight {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSRight { dst, a, b } => IntSRight {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntEqual { dst, a, b } => IntEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntNotEqual { dst, a, b } => IntNotEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntLess { dst, a, b } => IntLess {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSLess { dst, a, b } => IntSLess {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntLessEqual { dst, a, b } => IntLessEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntSLessEqual { dst, a, b } => IntSLessEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            IntZExt { dst, src } => IntZExt {
                dst: f(dst),
                src: f(src),
            },
            IntSExt { dst, src } => IntSExt {
                dst: f(dst),
                src: f(src),
            },
            BoolNot { dst, src } => BoolNot {
                dst: f(dst),
                src: f(src),
            },
            BoolAnd { dst, a, b } => BoolAnd {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            BoolOr { dst, a, b } => BoolOr {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            BoolXor { dst, a, b } => BoolXor {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            Piece { dst, hi, lo } => Piece {
                dst: f(dst),
                hi: f(hi),
                lo: f(lo),
            },
            Subpiece { dst, src, offset } => Subpiece {
                dst: f(dst),
                src: f(src),
                offset: *offset,
            },
            PopCount { dst, src } => PopCount {
                dst: f(dst),
                src: f(src),
            },
            Lzcount { dst, src } => Lzcount {
                dst: f(dst),
                src: f(src),
            },
            Branch {
                target,
                instruction,
            } => Branch {
                target: f(target),
                instruction: *instruction,
            },
            CBranch { target, cond } => CBranch {
                target: f(target),
                cond: f(cond),
            },
            BranchInd {
                target,
                instruction,
            } => BranchInd {
                target: f(target),
                instruction: *instruction,
            },
            Switch { selector } => Switch {
                selector: f(selector),
            },
            Call {
                target,
                instruction,
            } => Call {
                target: f(target),
                instruction: *instruction,
            },
            CallInd {
                target,
                instruction,
            } => CallInd {
                target: f(target),
                instruction: *instruction,
            },
            CallDefine { dst } => CallDefine { dst: f(dst) },
            CallRestore { dst, src } => CallRestore {
                dst: f(dst),
                src: f(src),
            },
            CallUse { src } => CallUse { src: f(src) },
            Return { target } => Return { target: f(target) },
            FloatAdd { dst, a, b } => FloatAdd {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatSub { dst, a, b } => FloatSub {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatMult { dst, a, b } => FloatMult {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatDiv { dst, a, b } => FloatDiv {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatNeg { dst, src } => FloatNeg {
                dst: f(dst),
                src: f(src),
            },
            FloatAbs { dst, src } => FloatAbs {
                dst: f(dst),
                src: f(src),
            },
            FloatSqrt { dst, src } => FloatSqrt {
                dst: f(dst),
                src: f(src),
            },
            FloatCeil { dst, src } => FloatCeil {
                dst: f(dst),
                src: f(src),
            },
            FloatFloor { dst, src } => FloatFloor {
                dst: f(dst),
                src: f(src),
            },
            FloatRound { dst, src } => FloatRound {
                dst: f(dst),
                src: f(src),
            },
            FloatNaN { dst, src } => FloatNaN {
                dst: f(dst),
                src: f(src),
            },
            FloatEqual { dst, a, b } => FloatEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatNotEqual { dst, a, b } => FloatNotEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatLess { dst, a, b } => FloatLess {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            FloatLessEqual { dst, a, b } => FloatLessEqual {
                dst: f(dst),
                a: f(a),
                b: f(b),
            },
            Int2Float { dst, src } => Int2Float {
                dst: f(dst),
                src: f(src),
            },
            Float2Int { dst, src } => Float2Int {
                dst: f(dst),
                src: f(src),
            },
            FloatFloat { dst, src } => FloatFloat {
                dst: f(dst),
                src: f(src),
            },
            Trunc { dst, src } => Trunc {
                dst: f(dst),
                src: f(src),
            },
            CallOther {
                output,
                userop,
                inputs,
            } => CallOther {
                output: output.as_ref().map(&mut *f),
                userop: *userop,
                inputs: inputs.iter().map(&mut *f).collect(),
            },
            Nop => Nop,
            Unimplemented => Unimplemented,
            CpuId { dst } => CpuId { dst: f(dst) },
            Breakpoint => Breakpoint,
            PtrAdd {
                dst,
                base,
                index,
                element_size,
            } => PtrAdd {
                dst: f(dst),
                base: f(base),
                index: f(index),
                element_size: *element_size,
            },
            PtrSub {
                dst,
                base,
                index,
                element_size,
            } => PtrSub {
                dst: f(dst),
                base: f(base),
                index: f(index),
                element_size: *element_size,
            },
            SegmentOp {
                dst,
                segment,
                offset,
            } => SegmentOp {
                dst: f(dst),
                segment: f(segment),
                offset: f(offset),
            },
            New { dst, src } => New {
                dst: f(dst),
                src: f(src),
            },
            Cast { dst, src } => Cast {
                dst: f(dst),
                src: f(src),
            },
            Extract { dst, src, position } => Extract {
                dst: f(dst),
                src: f(src),
                position: f(position),
            },
            Insert(op) => Insert(Box::new(op.map(f))),
            Select(op) => Select(Box::new(op.map(f))),
        }
    }
    /// What `r2il::eval` computes this operation's value with, from its `sources` in order.
    pub fn operation(&self) -> Option<r2il::eval::Operation> {
        use SSAOp::*;
        use r2il::eval::Operation as O;
        Some(match self {
            Copy { .. } => O::Copy,
            IntAdd { .. } => O::Add,
            IntSub { .. } => O::Sub,
            IntMult { .. } => O::Mult,
            IntDiv { .. } => O::Div,
            IntSDiv { .. } => O::SDiv,
            IntRem { .. } => O::Rem,
            IntSRem { .. } => O::SRem,
            IntAnd { .. } => O::And,
            IntOr { .. } => O::Or,
            IntXor { .. } => O::Xor,
            IntLeft { .. } => O::Left,
            IntRight { .. } => O::Right,
            IntSRight { .. } => O::SRight,
            IntEqual { .. } => O::Equal,
            IntNotEqual { .. } => O::NotEqual,
            IntLess { .. } => O::Less,
            IntSLess { .. } => O::SLess,
            IntLessEqual { .. } => O::LessEqual,
            IntSLessEqual { .. } => O::SLessEqual,
            IntCarry { .. } => O::Carry,
            IntSCarry { .. } => O::SCarry,
            IntSBorrow { .. } => O::SBorrow,
            BoolAnd { .. } => O::BoolAnd,
            BoolOr { .. } => O::BoolOr,
            BoolXor { .. } => O::BoolXor,
            IntNegate { .. } => O::Negate,
            IntNot { .. } => O::Not,
            BoolNot { .. } => O::BoolNot,
            IntZExt { .. } => O::ZExt,
            IntSExt { .. } => O::SExt,
            PopCount { .. } => O::PopCount,
            Lzcount { .. } => O::Lzcount,
            Subpiece { offset, .. } => O::Subpiece { offset: *offset },
            Piece { .. } => O::Piece,
            PtrAdd { element_size, .. } => O::PtrAdd {
                element_size: *element_size,
            },
            PtrSub { element_size, .. } => O::PtrSub {
                element_size: *element_size,
            },
            Select(_) => O::Select,
            _ => return None,
        })
    }

    /// Exact address space touched by a memory operation.
    pub const fn memory_space(&self) -> Option<SpaceId> {
        match self {
            Self::Load { space, .. }
            | Self::Store { space, .. }
            | Self::LoadLinked { space, .. }
            | Self::StoreConditional { space, .. }
            | Self::LoadGuarded { space, .. }
            | Self::StoreGuarded { space, .. } => Some(*space),
            Self::AtomicCAS(swap) => Some(swap.space),
            Self::BlockTransfer(transfer) => Some(transfer.space),
            _ => None,
        }
    }

    /// Get the destination variable if this operation has one.
    pub fn dst(&self) -> Option<&V> {
        use SSAOp::*;
        match self {
            Phi { dst, .. }
            | Copy { dst, .. }
            | Load { dst, .. }
            | LoadLinked { dst, .. }
            | LoadGuarded { dst, .. }
            | IntAdd { dst, .. }
            | IntSub { dst, .. }
            | IntMult { dst, .. }
            | IntDiv { dst, .. }
            | IntSDiv { dst, .. }
            | IntRem { dst, .. }
            | IntSRem { dst, .. }
            | IntNegate { dst, .. }
            | IntCarry { dst, .. }
            | IntSCarry { dst, .. }
            | IntSBorrow { dst, .. }
            | IntAnd { dst, .. }
            | IntOr { dst, .. }
            | IntXor { dst, .. }
            | IntNot { dst, .. }
            | IntLeft { dst, .. }
            | IntRight { dst, .. }
            | IntSRight { dst, .. }
            | IntEqual { dst, .. }
            | IntNotEqual { dst, .. }
            | IntLess { dst, .. }
            | IntSLess { dst, .. }
            | IntLessEqual { dst, .. }
            | IntSLessEqual { dst, .. }
            | IntZExt { dst, .. }
            | IntSExt { dst, .. }
            | BoolNot { dst, .. }
            | BoolAnd { dst, .. }
            | BoolOr { dst, .. }
            | BoolXor { dst, .. }
            | Piece { dst, .. }
            | Subpiece { dst, .. }
            | PopCount { dst, .. }
            | Lzcount { dst, .. }
            | FloatAdd { dst, .. }
            | FloatSub { dst, .. }
            | FloatMult { dst, .. }
            | FloatDiv { dst, .. }
            | FloatNeg { dst, .. }
            | FloatAbs { dst, .. }
            | FloatSqrt { dst, .. }
            | FloatCeil { dst, .. }
            | FloatFloor { dst, .. }
            | FloatRound { dst, .. }
            | FloatNaN { dst, .. }
            | FloatEqual { dst, .. }
            | FloatNotEqual { dst, .. }
            | FloatLess { dst, .. }
            | FloatLessEqual { dst, .. }
            | Int2Float { dst, .. }
            | Float2Int { dst, .. }
            | FloatFloat { dst, .. }
            | Trunc { dst, .. }
            | CpuId { dst, .. }
            | PtrAdd { dst, .. }
            | PtrSub { dst, .. }
            | SegmentOp { dst, .. }
            | New { dst, .. }
            | Cast { dst, .. }
            | Extract { dst, .. }
            | CallDefine { dst }
            | CallRestore { dst, .. } => Some(dst),

            AtomicCAS(swap) => Some(&swap.dst),
            Insert(insert) => Some(&insert.dst),
            Select(select) => Some(&select.dst),

            CallOther { output, .. } | StoreConditional { result: output, .. } => output.as_ref(),
            BlockTransfer(transfer) => transfer.answer.as_ref(),

            Store { .. }
            | Fence { .. }
            | StoreGuarded { .. }
            | CallUse { .. }
            | Branch { .. }
            | CBranch { .. }
            | BranchInd { .. }
            | Switch { .. }
            | Call { .. }
            | CallInd { .. }
            | Return { .. }
            | Nop
            | Unimplemented
            | Breakpoint => None,
        }
    }

    /// Visit all source variables used by this operation in operand order.
    pub fn for_each_source<'a, F: FnMut(&'a V)>(&'a self, mut f: F) {
        use SSAOp::*;
        match self {
            Phi { sources, .. } => {
                for src in sources {
                    f(src);
                }
            }

            Copy { src, .. }
            | IntNegate { src, .. }
            | IntNot { src, .. }
            | IntZExt { src, .. }
            | IntSExt { src, .. }
            | BoolNot { src, .. }
            | Subpiece { src, .. }
            | PopCount { src, .. }
            | Lzcount { src, .. }
            | FloatNeg { src, .. }
            | FloatAbs { src, .. }
            | FloatSqrt { src, .. }
            | FloatCeil { src, .. }
            | FloatFloor { src, .. }
            | FloatRound { src, .. }
            | FloatNaN { src, .. }
            | Int2Float { src, .. }
            | Float2Int { src, .. }
            | FloatFloat { src, .. }
            | Trunc { src, .. }
            | New { src, .. }
            | Cast { src, .. } => f(src),

            Load { addr, .. } | LoadLinked { addr, .. } => f(addr),

            Store { addr, val, .. } | StoreConditional { addr, val, .. } => {
                f(addr);
                f(val);
            }

            BlockTransfer(transfer) => {
                let (destination, source, count) =
                    (&transfer.destination, &transfer.source, &transfer.count);
                let direction = &transfer.direction;
                f(destination);
                f(source);
                f(count);
                f(direction);
            }

            AtomicCAS(swap) => {
                f(&swap.addr);
                f(&swap.expected);
                f(&swap.replacement);
            }

            LoadGuarded { addr, guard, .. } => {
                f(addr);
                f(guard);
            }

            StoreGuarded {
                addr, val, guard, ..
            } => {
                f(addr);
                f(val);
                f(guard);
            }

            IntAdd { a, b, .. }
            | IntSub { a, b, .. }
            | IntMult { a, b, .. }
            | IntDiv { a, b, .. }
            | IntSDiv { a, b, .. }
            | IntRem { a, b, .. }
            | IntSRem { a, b, .. }
            | IntCarry { a, b, .. }
            | IntSCarry { a, b, .. }
            | IntSBorrow { a, b, .. }
            | IntAnd { a, b, .. }
            | IntOr { a, b, .. }
            | IntXor { a, b, .. }
            | IntLeft { a, b, .. }
            | IntRight { a, b, .. }
            | IntSRight { a, b, .. }
            | IntEqual { a, b, .. }
            | IntNotEqual { a, b, .. }
            | IntLess { a, b, .. }
            | IntSLess { a, b, .. }
            | IntLessEqual { a, b, .. }
            | IntSLessEqual { a, b, .. }
            | BoolAnd { a, b, .. }
            | BoolOr { a, b, .. }
            | BoolXor { a, b, .. }
            | FloatAdd { a, b, .. }
            | FloatSub { a, b, .. }
            | FloatMult { a, b, .. }
            | FloatDiv { a, b, .. }
            | FloatEqual { a, b, .. }
            | FloatNotEqual { a, b, .. }
            | FloatLess { a, b, .. }
            | FloatLessEqual { a, b, .. } => {
                f(a);
                f(b);
            }

            Piece { hi, lo, .. } => {
                f(hi);
                f(lo);
            }

            Extract { src, position, .. } => {
                f(src);
                f(position);
            }

            Insert(insert) => {
                f(&insert.src);
                f(&insert.value);
                f(&insert.position);
            }

            Select(select) => {
                f(&select.cond);
                f(&select.if_true);
                f(&select.if_false);
            }

            PtrAdd { base, index, .. } | PtrSub { base, index, .. } => {
                f(base);
                f(index);
            }

            SegmentOp {
                segment, offset, ..
            } => {
                f(segment);
                f(offset);
            }

            Branch { target, .. }
            | BranchInd { target, .. }
            | Call { target, .. }
            | CallInd { target, .. }
            | Return { target } => f(target),

            Switch { selector } => f(selector),

            CBranch { target, cond } => {
                f(target);
                f(cond);
            }

            CallOther { inputs, .. } => {
                for input in inputs {
                    f(input);
                }
            }

            CallRestore { src, .. } | CallUse { src } => f(src),

            Fence { .. } | Nop | Unimplemented | Breakpoint | CpuId { .. } | CallDefine { .. } => {}
        }
    }

    /// Get all source variables used by this operation.
    pub fn sources(&self) -> Vec<&V> {
        let mut sources = Vec::new();
        self.for_each_source(|src| sources.push(src));
        sources
    }

    /// What this operation does with the values it reads, as the lifted operation it mirrors says.
    pub fn value_use(&self) -> r2il::ValueUse {
        use r2il::ValueUse;
        match self {
            SSAOp::Phi { .. }
            | SSAOp::Copy { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::Subpiece { .. }
            | SSAOp::Cast { .. }
            | SSAOp::CallRestore { .. }
            | SSAOp::Select(_) => ValueUse::Carries,
            SSAOp::IntAdd { .. }
            | SSAOp::IntSub { .. }
            | SSAOp::IntMult { .. }
            | SSAOp::IntDiv { .. }
            | SSAOp::IntSDiv { .. }
            | SSAOp::IntRem { .. }
            | SSAOp::IntSRem { .. }
            | SSAOp::IntNegate { .. }
            | SSAOp::IntAnd { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. }
            | SSAOp::IntNot { .. }
            | SSAOp::IntLeft { .. }
            | SSAOp::IntRight { .. }
            | SSAOp::IntSRight { .. }
            | SSAOp::Piece { .. }
            | SSAOp::PtrAdd { .. }
            | SSAOp::PtrSub { .. }
            | SSAOp::SegmentOp { .. }
            | SSAOp::Extract { .. }
            | SSAOp::Insert(_) => ValueUse::Derives,
            SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::PopCount { .. }
            | SSAOp::Lzcount { .. } => ValueUse::Tests,
            _ => ValueUse::Consumes,
        }
    }

    /// Returns true if this operation is a control flow operation.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            SSAOp::Branch { .. }
                | SSAOp::CBranch { .. }
                | SSAOp::BranchInd { .. }
                | SSAOp::Switch { .. }
                | SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::Return { .. }
        )
    }

    /// Returns true if this operation reads from memory.
    pub fn is_memory_read(&self) -> bool {
        matches!(
            self,
            SSAOp::Load { .. }
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
                | SSAOp::AtomicCAS { .. }
        ) || matches!(self, SSAOp::BlockTransfer(transfer) if transfer.kind.reads_memory())
    }

    /// Returns true if this operation writes to memory.
    pub fn is_memory_write(&self) -> bool {
        matches!(
            self,
            SSAOp::Store { .. }
                | SSAOp::StoreConditional { .. }
                | SSAOp::StoreGuarded { .. }
                | SSAOp::AtomicCAS { .. }
        ) || matches!(self, SSAOp::BlockTransfer(transfer) if transfer.kind.writes_memory())
    }

    /// Returns true when removing this operation can change observable behavior.
    ///
    /// Ordinary loads are optional because some consumers can prove that a load
    /// reads only compiler-owned stack plumbing. Atomic and guarded loads remain
    /// observable regardless of that policy.
    pub fn has_observable_effects(&self, preserve_memory_reads: bool) -> bool {
        if self.is_control_flow() || self.is_memory_write() {
            return true;
        }
        // A block operation reads a whole extent, and how far it reached is data dependent.
        if matches!(
            self,
            SSAOp::Fence { .. }
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
                | SSAOp::BlockTransfer(_)
        ) {
            return true;
        }
        if preserve_memory_reads && self.is_memory_read() {
            return true;
        }
        matches!(
            self,
            SSAOp::CallOther { .. }
                | SSAOp::Breakpoint
                | SSAOp::Unimplemented
                | SSAOp::CpuId { .. }
                | SSAOp::New { .. }
                // The read a call boundary makes. Removing it would delete
                // the only statement that keeps an argument's producer live.
                | SSAOp::CallUse { .. }
        )
    }

    /// Returns true if this is a phi node.
    pub fn is_phi(&self) -> bool {
        matches!(self, SSAOp::Phi { .. })
    }
}

impl<V: std::fmt::Display> std::fmt::Display for SSAOp<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSAOp::Phi { dst, sources } => {
                write!(f, "{} = PHI(", dst)?;
                for (i, src) in sources.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", src)?;
                }
                write!(f, ")")
            }
            SSAOp::Copy { dst, src } => write!(f, "{} = COPY {}", dst, src),
            SSAOp::Load { dst, space, addr } => write!(f, "{} = LOAD [{}]{}", dst, space, addr),
            SSAOp::Store { space, addr, val } => write!(f, "STORE [{}]{} = {}", space, addr, val),
            SSAOp::BlockTransfer(transfer) => {
                let (space, destination, source, count, element_size, direction) = (
                    &transfer.space,
                    &transfer.destination,
                    &transfer.source,
                    &transfer.count,
                    &transfer.element_size,
                    &transfer.direction,
                );
                if let Some(answer) = &transfer.answer {
                    write!(f, "{answer} = ")?;
                }
                let (name, stop) = block_transfer_spelling(transfer.kind);
                write!(
                    f,
                    "BLOCK{name} [{space}]{destination} <- {source} x {count}{stop} ({element_size} bytes each, direction {direction})"
                )
            }
            SSAOp::Fence { ordering } => write!(f, "FENCE({:?})", ordering),
            SSAOp::LoadLinked {
                dst,
                space,
                addr,
                ordering,
            } => write!(
                f,
                "{} = LOAD_LINKED({:?}) [{}]{}",
                dst, ordering, space, addr
            ),
            SSAOp::StoreConditional {
                result,
                space,
                addr,
                val,
                ordering,
            } => {
                if let Some(out) = result {
                    write!(f, "{} = ", out)?;
                }
                write!(
                    f,
                    "STORE_CONDITIONAL({:?}) [{}]{} = {}",
                    ordering, space, addr, val
                )
            }
            SSAOp::AtomicCAS(swap) => write!(
                f,
                "{} = ATOMIC_CAS({:?}) [{}]{}, {}, {}",
                swap.dst, swap.ordering, swap.space, swap.addr, swap.expected, swap.replacement
            ),
            SSAOp::LoadGuarded {
                dst,
                space,
                addr,
                guard,
                ordering,
            } => write!(
                f,
                "{} = LOAD_GUARDED({:?}) [{}]{}, guard={}",
                dst, ordering, space, addr, guard
            ),
            SSAOp::StoreGuarded {
                space,
                addr,
                val,
                guard,
                ordering,
            } => write!(
                f,
                "STORE_GUARDED({:?}) [{}]{} = {}, guard={}",
                ordering, space, addr, val, guard
            ),
            SSAOp::IntAdd { dst, a, b } => write!(f, "{} = {} + {}", dst, a, b),
            SSAOp::IntSub { dst, a, b } => write!(f, "{} = {} - {}", dst, a, b),
            SSAOp::IntMult { dst, a, b } => write!(f, "{} = {} * {}", dst, a, b),
            SSAOp::IntDiv { dst, a, b } => write!(f, "{} = {} / {}", dst, a, b),
            SSAOp::IntSDiv { dst, a, b } => write!(f, "{} = {} s/ {}", dst, a, b),
            SSAOp::IntRem { dst, a, b } => write!(f, "{} = {} % {}", dst, a, b),
            SSAOp::IntSRem { dst, a, b } => write!(f, "{} = {} s% {}", dst, a, b),
            SSAOp::IntNegate { dst, src } => write!(f, "{} = -{}", dst, src),
            SSAOp::IntCarry { dst, a, b } => write!(f, "{} = CARRY({}, {})", dst, a, b),
            SSAOp::IntSCarry { dst, a, b } => write!(f, "{} = SCARRY({}, {})", dst, a, b),
            SSAOp::IntSBorrow { dst, a, b } => write!(f, "{} = SBORROW({}, {})", dst, a, b),
            SSAOp::IntAnd { dst, a, b } => write!(f, "{} = {} & {}", dst, a, b),
            SSAOp::IntOr { dst, a, b } => write!(f, "{} = {} | {}", dst, a, b),
            SSAOp::IntXor { dst, a, b } => write!(f, "{} = {} ^ {}", dst, a, b),
            SSAOp::IntNot { dst, src } => write!(f, "{} = ~{}", dst, src),
            SSAOp::IntLeft { dst, a, b } => write!(f, "{} = {} << {}", dst, a, b),
            SSAOp::IntRight { dst, a, b } => write!(f, "{} = {} >> {}", dst, a, b),
            SSAOp::IntSRight { dst, a, b } => write!(f, "{} = {} s>> {}", dst, a, b),
            SSAOp::IntEqual { dst, a, b } => write!(f, "{} = {} == {}", dst, a, b),
            SSAOp::IntNotEqual { dst, a, b } => write!(f, "{} = {} != {}", dst, a, b),
            SSAOp::IntLess { dst, a, b } => write!(f, "{} = {} < {}", dst, a, b),
            SSAOp::IntSLess { dst, a, b } => write!(f, "{} = {} s< {}", dst, a, b),
            SSAOp::IntLessEqual { dst, a, b } => write!(f, "{} = {} <= {}", dst, a, b),
            SSAOp::IntSLessEqual { dst, a, b } => write!(f, "{} = {} s<= {}", dst, a, b),
            SSAOp::IntZExt { dst, src } => write!(f, "{} = ZEXT({})", dst, src),
            SSAOp::IntSExt { dst, src } => write!(f, "{} = SEXT({})", dst, src),
            SSAOp::BoolNot { dst, src } => write!(f, "{} = !{}", dst, src),
            SSAOp::BoolAnd { dst, a, b } => write!(f, "{} = {} && {}", dst, a, b),
            SSAOp::BoolOr { dst, a, b } => write!(f, "{} = {} || {}", dst, a, b),
            SSAOp::BoolXor { dst, a, b } => write!(f, "{} = {} ^^ {}", dst, a, b),
            SSAOp::Piece { dst, hi, lo } => write!(f, "{} = PIECE({}, {})", dst, hi, lo),
            SSAOp::Subpiece { dst, src, offset } => {
                write!(f, "{} = SUBPIECE({}, {})", dst, src, offset)
            }
            SSAOp::PopCount { dst, src } => write!(f, "{} = POPCOUNT({})", dst, src),
            SSAOp::Lzcount { dst, src } => write!(f, "{} = LZCOUNT({})", dst, src),
            SSAOp::Branch { target, .. } => write!(f, "BRANCH {}", target),
            SSAOp::CBranch { target, cond } => write!(f, "CBRANCH {} if {}", target, cond),
            SSAOp::BranchInd { target, .. } => write!(f, "BRANCHIND {}", target),
            SSAOp::Switch { selector } => write!(f, "SWITCH {}", selector),
            SSAOp::Call { target, .. } => write!(f, "CALL {}", target),
            SSAOp::CallInd { target, .. } => write!(f, "CALLIND {}", target),
            SSAOp::CallDefine { dst } => write!(f, "{} = CALLDEF", dst),
            SSAOp::CallRestore { dst, src } => write!(f, "{} = CALLRESTORE {}", dst, src),
            SSAOp::CallUse { src } => write!(f, "CALLUSE {}", src),
            SSAOp::Return { target } => write!(f, "RETURN {}", target),
            SSAOp::FloatAdd { dst, a, b } => write!(f, "{} = {} f+ {}", dst, a, b),
            SSAOp::FloatSub { dst, a, b } => write!(f, "{} = {} f- {}", dst, a, b),
            SSAOp::FloatMult { dst, a, b } => write!(f, "{} = {} f* {}", dst, a, b),
            SSAOp::FloatDiv { dst, a, b } => write!(f, "{} = {} f/ {}", dst, a, b),
            SSAOp::FloatNeg { dst, src } => write!(f, "{} = f-{}", dst, src),
            SSAOp::FloatAbs { dst, src } => write!(f, "{} = FABS({})", dst, src),
            SSAOp::FloatSqrt { dst, src } => write!(f, "{} = FSQRT({})", dst, src),
            SSAOp::FloatCeil { dst, src } => write!(f, "{} = FCEIL({})", dst, src),
            SSAOp::FloatFloor { dst, src } => write!(f, "{} = FFLOOR({})", dst, src),
            SSAOp::FloatRound { dst, src } => write!(f, "{} = FROUND({})", dst, src),
            SSAOp::FloatNaN { dst, src } => write!(f, "{} = FNAN({})", dst, src),
            SSAOp::FloatEqual { dst, a, b } => write!(f, "{} = {} f== {}", dst, a, b),
            SSAOp::FloatNotEqual { dst, a, b } => write!(f, "{} = {} f!= {}", dst, a, b),
            SSAOp::FloatLess { dst, a, b } => write!(f, "{} = {} f< {}", dst, a, b),
            SSAOp::FloatLessEqual { dst, a, b } => write!(f, "{} = {} f<= {}", dst, a, b),
            SSAOp::Int2Float { dst, src } => write!(f, "{} = INT2FLOAT({})", dst, src),
            SSAOp::Float2Int { dst, src } => write!(f, "{} = FLOAT2INT({})", dst, src),
            SSAOp::FloatFloat { dst, src } => write!(f, "{} = FLOAT2FLOAT({})", dst, src),
            SSAOp::Trunc { dst, src } => write!(f, "{} = TRUNC({})", dst, src),
            SSAOp::CallOther {
                output,
                userop,
                inputs,
            } => {
                if let Some(out) = output {
                    write!(f, "{} = ", out)?;
                }
                write!(f, "CALLOTHER({})", userop)?;
                if !inputs.is_empty() {
                    write!(f, " [")?;
                    for (i, inp) in inputs.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", inp)?;
                    }
                    write!(f, "]")?;
                }
                Ok(())
            }
            SSAOp::Nop => write!(f, "NOP"),
            SSAOp::Unimplemented => write!(f, "UNIMPLEMENTED"),
            SSAOp::CpuId { dst } => write!(f, "{} = CPUID", dst),
            SSAOp::Breakpoint => write!(f, "BREAKPOINT"),
            SSAOp::PtrAdd {
                dst,
                base,
                index,
                element_size,
            } => write!(f, "{} = PTRADD({}, {}, {})", dst, base, index, element_size),
            SSAOp::PtrSub {
                dst,
                base,
                index,
                element_size,
            } => write!(f, "{} = PTRSUB({}, {}, {})", dst, base, index, element_size),
            SSAOp::SegmentOp {
                dst,
                segment,
                offset,
            } => write!(f, "{} = SEGMENT({}, {})", dst, segment, offset),
            SSAOp::New { dst, src } => write!(f, "{} = NEW({})", dst, src),
            SSAOp::Cast { dst, src } => write!(f, "{} = CAST({})", dst, src),
            SSAOp::Extract { dst, src, position } => {
                write!(f, "{} = EXTRACT({}, {})", dst, src, position)
            }
            SSAOp::Insert(insert) => write!(
                f,
                "{} = INSERT({}, {}, {})",
                insert.dst, insert.src, insert.value, insert.position
            ),
            SSAOp::Select(select) => write!(
                f,
                "{} = SELECT({}, {}, {})",
                select.dst, select.cond, select.if_true, select.if_false
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mapping every operand to itself gives the operation back, and every
    /// operand is visited once, in field order, whatever holds it: a field,
    /// an `Option`, a `Vec`, or an operation held out of line.
    #[test]
    fn map_visits_every_operand_once_in_field_order() {
        let v = |name: &str| SSAVar::new(name, 1, 8);
        let ops: Vec<SSAOp> = vec![
            SSAOp::IntAdd {
                dst: v("a"),
                a: v("b"),
                b: v("c"),
            },
            SSAOp::Phi {
                dst: v("a"),
                sources: vec![v("b"), v("c"), v("d")],
            },
            SSAOp::CallOther {
                output: Some(v("a")),
                userop: 7,
                inputs: vec![v("b"), v("c")],
            },
            SSAOp::Load {
                dst: v("a"),
                space: SpaceId::Ram,
                addr: v("b"),
            },
            SSAOp::Select(Box::new(SelectOp {
                dst: v("a"),
                cond: v("b"),
                if_true: v("c"),
                if_false: v("d"),
            })),
            SSAOp::Nop,
        ];
        for op in &ops {
            assert_eq!(&op.map(&mut SSAVar::clone), op);
            let mut seen = Vec::new();
            let numbered = op.map(&mut |var: &SSAVar| {
                seen.push(var.name().to_owned());
                seen.len()
            });
            let expected = (1..=seen.len()).collect::<Vec<_>>();
            let mut got = numbered.dst().into_iter().copied().collect::<Vec<_>>();
            got.extend(numbered.sources().into_iter().copied());
            got.sort_unstable();
            assert_eq!(got, expected, "{op}");
            let names = seen.iter().map(String::as_str).collect::<Vec<_>>();
            let mut sorted = names.clone();
            sorted.sort_unstable();
            assert_eq!(
                names, sorted,
                "field order is a, b, c, d in each fixture: {op}"
            );
        }
    }

    #[test]
    fn test_dst_extraction() {
        let dst = SSAVar::new("RAX", 1, 8);
        let src = SSAVar::new("RBX", 0, 8);

        let op = SSAOp::Copy {
            dst: dst.clone(),
            src,
        };
        assert_eq!(op.dst(), Some(&dst));

        let op: SSAOp = SSAOp::Nop;
        assert_eq!(op.dst(), None);
    }

    #[test]
    fn observable_effect_classification_distinguishes_plain_and_atomic_loads() {
        let load = SSAOp::Load {
            dst: SSAVar::new("RAX", 1, 8),
            space: r2il::SpaceId::Ram,
            addr: SSAVar::new("RSP", 0, 8),
        };
        assert!(!load.has_observable_effects(false));
        assert!(load.has_observable_effects(true));

        let linked = SSAOp::LoadLinked {
            dst: SSAVar::new("RAX", 1, 8),
            space: r2il::SpaceId::Ram,
            addr: SSAVar::new("RSP", 0, 8),
            ordering: r2il::MemoryOrdering::Relaxed,
        };
        assert!(linked.has_observable_effects(false));

        let call_other: SSAOp = SSAOp::CallOther {
            output: None,
            userop: 1,
            inputs: Vec::new(),
        };
        assert!(call_other.has_observable_effects(false));
    }

    #[test]
    fn test_sources_extraction() {
        let a = SSAVar::new("RAX", 0, 8);
        let b = SSAVar::new("RBX", 0, 8);
        let dst = SSAVar::new("RCX", 1, 8);

        let op = SSAOp::IntAdd {
            dst,
            a: a.clone(),
            b: b.clone(),
        };
        let sources = op.sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], &a);
        assert_eq!(sources[1], &b);
    }

    #[test]
    fn test_phi_sources() {
        let dst = SSAVar::new("RAX", 2, 8);
        let s1 = SSAVar::new("RAX", 0, 8);
        let s2 = SSAVar::new("RAX", 1, 8);

        let op = SSAOp::Phi {
            dst,
            sources: vec![s1.clone(), s2.clone()],
        };
        let sources = op.sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], &s1);
        assert_eq!(sources[1], &s2);
    }

    #[test]
    fn test_display() {
        let op = SSAOp::Copy {
            dst: SSAVar::new("RAX", 1, 8),
            src: SSAVar::new("RAX", 0, 8),
        };
        assert_eq!(format!("{}", op), "RAX_1 = COPY RAX_0");
    }

    #[test]
    fn test_display_phi() {
        let op = SSAOp::Phi {
            dst: SSAVar::new("RAX", 2, 8),
            sources: vec![SSAVar::new("RAX", 0, 8), SSAVar::new("RAX", 1, 8)],
        };
        assert_eq!(format!("{}", op), "RAX_2 = PHI(RAX_0, RAX_1)");
    }

    #[test]
    fn test_display_load_store() {
        let load = SSAOp::Load {
            dst: SSAVar::new("RAX", 1, 8),
            space: r2il::SpaceId::Ram,
            addr: SSAVar::new("RSP", 0, 8),
        };
        assert_eq!(format!("{}", load), "RAX_1 = LOAD [ram]RSP_0");

        let store = SSAOp::Store {
            space: r2il::SpaceId::Ram,
            addr: SSAVar::new("RSP", 0, 8),
            val: SSAVar::new("RAX", 1, 8),
        };
        assert_eq!(format!("{}", store), "STORE [ram]RSP_0 = RAX_1");
    }

    #[test]
    fn test_for_each_source_matches_sources() {
        let ops = vec![
            SSAOp::Phi {
                dst: SSAVar::new("RAX", 2, 8),
                sources: vec![SSAVar::new("RAX", 0, 8), SSAVar::new("RAX", 1, 8)],
            },
            SSAOp::IntAdd {
                dst: SSAVar::new("RCX", 1, 8),
                a: SSAVar::new("RAX", 1, 8),
                b: SSAVar::new("RBX", 0, 8),
            },
            SSAOp::Store {
                space: r2il::SpaceId::Ram,
                addr: SSAVar::new("RSP", 0, 8),
                val: SSAVar::new("RAX", 1, 8),
            },
            SSAOp::CallOther {
                output: None,
                userop: 1,
                inputs: vec![SSAVar::new("RDI", 0, 8), SSAVar::new("RSI", 0, 8)],
            },
        ];

        for op in &ops {
            let from_sources: Vec<String> = op.sources().iter().map(|v| v.display_name()).collect();
            let mut from_visitor = Vec::new();
            op.for_each_source(|v| from_visitor.push(v.display_name()));
            assert_eq!(
                from_sources, from_visitor,
                "for_each_source must preserve order and membership for {:?}",
                op
            );
        }
    }
}
