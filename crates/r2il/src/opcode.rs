//! r2il opcode definitions.
//!
//! These opcodes are based on Ghidra's P-code operations, providing a strongly-typed
//! intermediate representation for processor instruction semantics.

use serde::{Deserialize, Serialize};

use crate::space::SpaceId;
use crate::varnode::Varnode;

/// An r2il operation representing a single semantic action.
///
/// Operations are organized into categories:
/// - Data movement (Copy, Load, Store)
/// - Integer arithmetic (Add, Sub, Mult, Div, etc.)
/// - Logical operations (And, Or, Xor, Not)
/// - Comparison operations (Equal, NotEqual, Less, etc.)
/// - Bit manipulation (Shift, Rotate, etc.)
/// - Control flow (Branch, CBranch, Call, Return)
/// - Floating point (FloatAdd, FloatSub, etc.)
/// - Special operations (Piece, Subpiece, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum R2ILOp {
    // ========== Data Movement ==========
    /// Copy src to dst: dst = src
    Copy {
        dst: Varnode,
        src: Varnode,
    },

    /// Load from memory: dst = *[space]addr
    Load {
        dst: Varnode,
        space: SpaceId,
        addr: Varnode,
    },

    /// Store to memory: *[space]addr = val
    Store {
        space: SpaceId,
        addr: Varnode,
        val: Varnode,
    },

    // ========== Integer Arithmetic ==========
    /// Integer addition: dst = a + b
    IntAdd {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Integer subtraction: dst = a - b
    IntSub {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Integer multiplication: dst = a * b
    IntMult {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Unsigned integer division: dst = a / b
    IntDiv {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed integer division: dst = a / b (signed)
    IntSDiv {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Unsigned integer remainder: dst = a % b
    IntRem {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed integer remainder: dst = a % b (signed)
    IntSRem {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Two's complement negation: dst = -src
    IntNegate {
        dst: Varnode,
        src: Varnode,
    },

    /// Addition with carry: dst = a + b + carry
    IntCarry {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed carry (overflow): dst = overflow(a + b)
    IntSCarry {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed borrow: dst = borrow(a - b)
    IntSBorrow {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    // ========== Logical Operations ==========
    /// Bitwise AND: dst = a & b
    IntAnd {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Bitwise OR: dst = a | b
    IntOr {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Bitwise XOR: dst = a ^ b
    IntXor {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Bitwise NOT: dst = ~src
    IntNot {
        dst: Varnode,
        src: Varnode,
    },

    // ========== Shift Operations ==========
    /// Left shift: dst = a << b
    IntLeft {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Logical right shift: dst = a >> b (unsigned)
    IntRight {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Arithmetic right shift: dst = a >> b (signed)
    IntSRight {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    // ========== Comparison Operations ==========
    /// Equality: dst = (a == b) ? 1 : 0
    IntEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Inequality: dst = (a != b) ? 1 : 0
    IntNotEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Unsigned less than: dst = (a < b) ? 1 : 0
    IntLess {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed less than: dst = (a < b) ? 1 : 0 (signed)
    IntSLess {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Unsigned less or equal: dst = (a <= b) ? 1 : 0
    IntLessEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Signed less or equal: dst = (a <= b) ? 1 : 0 (signed)
    IntSLessEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    // ========== Extension Operations ==========
    /// Zero extension: dst = zext(src)
    IntZExt {
        dst: Varnode,
        src: Varnode,
    },

    /// Sign extension: dst = sext(src)
    IntSExt {
        dst: Varnode,
        src: Varnode,
    },

    // ========== Boolean Operations ==========
    /// Boolean NOT: dst = !src
    BoolNot {
        dst: Varnode,
        src: Varnode,
    },

    /// Boolean AND: dst = a && b
    BoolAnd {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Boolean OR: dst = a || b
    BoolOr {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Boolean XOR: dst = a ^^ b
    BoolXor {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    // ========== Bit Manipulation ==========
    /// Concatenate two values: dst = (a << b.size*8) | b
    Piece {
        dst: Varnode,
        hi: Varnode,
        lo: Varnode,
    },

    /// Extract a portion of a value: dst = src[offset:size]
    Subpiece {
        dst: Varnode,
        src: Varnode,
        offset: u32,
    },

    /// Population count (number of 1 bits): dst = popcount(src)
    PopCount {
        dst: Varnode,
        src: Varnode,
    },

    /// Count leading zeros: dst = clz(src)
    Lzcount {
        dst: Varnode,
        src: Varnode,
    },

    // ========== Control Flow ==========
    /// Unconditional branch to target
    Branch {
        target: Varnode,
    },

    /// Conditional branch: if (cond) goto target
    CBranch {
        target: Varnode,
        cond: Varnode,
    },

    /// Indirect branch: goto *target
    BranchInd {
        target: Varnode,
    },

    /// Call a subroutine
    Call {
        target: Varnode,
    },

    /// Indirect call: call *target
    CallInd {
        target: Varnode,
    },

    /// Return from subroutine
    Return {
        target: Varnode,
    },

    // ========== Floating Point ==========
    /// Float addition: dst = a + b
    FloatAdd {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float subtraction: dst = a - b
    FloatSub {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float multiplication: dst = a * b
    FloatMult {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float division: dst = a / b
    FloatDiv {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float negation: dst = -src
    FloatNeg {
        dst: Varnode,
        src: Varnode,
    },

    /// Float absolute value: dst = |src|
    FloatAbs {
        dst: Varnode,
        src: Varnode,
    },

    /// Float square root: dst = sqrt(src)
    FloatSqrt {
        dst: Varnode,
        src: Varnode,
    },

    /// Float ceiling: dst = ceil(src)
    FloatCeil {
        dst: Varnode,
        src: Varnode,
    },

    /// Float floor: dst = floor(src)
    FloatFloor {
        dst: Varnode,
        src: Varnode,
    },

    /// Float round: dst = round(src)
    FloatRound {
        dst: Varnode,
        src: Varnode,
    },

    /// Float is NaN: dst = isnan(src)
    FloatNaN {
        dst: Varnode,
        src: Varnode,
    },

    /// Float equality: dst = (a == b) ? 1 : 0
    FloatEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float not equal: dst = (a != b) ? 1 : 0
    FloatNotEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float less than: dst = (a < b) ? 1 : 0
    FloatLess {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Float less or equal: dst = (a <= b) ? 1 : 0
    FloatLessEqual {
        dst: Varnode,
        a: Varnode,
        b: Varnode,
    },

    /// Convert int to float: dst = (float)src
    Int2Float {
        dst: Varnode,
        src: Varnode,
    },

    /// Convert float to int: dst = (int)src
    Float2Int {
        dst: Varnode,
        src: Varnode,
    },

    /// Convert float to different size float: dst = (float_new_size)src
    FloatFloat {
        dst: Varnode,
        src: Varnode,
    },

    /// Truncate float to int: dst = trunc(src)
    Trunc {
        dst: Varnode,
        src: Varnode,
    },

    // ========== Special Operations ==========
    /// Call a user-defined operation (CALLOTHER in P-code)
    CallOther {
        /// Optional output varnode
        output: Option<Varnode>,
        /// User-defined operation index
        userop: u32,
        /// Input arguments
        inputs: Vec<Varnode>,
    },

    /// No operation (placeholder)
    Nop,

    /// Unimplemented instruction
    Unimplemented,

    /// CPU identification (CPUID-like)
    CpuId {
        dst: Varnode,
    },

    /// Insert a breakpoint
    Breakpoint,

    /// Multiequal (SSA phi function, used in analysis)
    Multiequal {
        dst: Varnode,
        inputs: Vec<Varnode>,
    },

    /// Indirect reference (used in analysis)
    Indirect {
        dst: Varnode,
        src: Varnode,
        indirect: Varnode,
    },

    /// Pointer addition: dst = base + (index * element_size)
    PtrAdd {
        dst: Varnode,
        base: Varnode,
        index: Varnode,
        element_size: u32,
    },

    /// Pointer subtraction: dst = base - (index * element_size)
    PtrSub {
        dst: Varnode,
        base: Varnode,
        index: Varnode,
        element_size: u32,
    },

    /// Segment calculation: dst = segment:offset
    SegmentOp {
        dst: Varnode,
        segment: Varnode,
        offset: Varnode,
    },

    /// New (allocation, used in high-level analysis)
    New {
        dst: Varnode,
        src: Varnode,
    },

    /// Cast (type cast, used in high-level analysis)
    Cast {
        dst: Varnode,
        src: Varnode,
    },

    /// Extract (bit field extraction)
    Extract {
        dst: Varnode,
        src: Varnode,
        position: Varnode,
    },

    /// Insert (bit field insertion)
    Insert {
        dst: Varnode,
        src: Varnode,
        value: Varnode,
        position: Varnode,
    },
}

impl R2ILOp {
    /// Returns true if this operation is a control flow operation.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            R2ILOp::Branch { .. }
                | R2ILOp::CBranch { .. }
                | R2ILOp::BranchInd { .. }
                | R2ILOp::Call { .. }
                | R2ILOp::CallInd { .. }
                | R2ILOp::Return { .. }
        )
    }

    /// Returns true if this operation reads from memory.
    pub fn is_memory_read(&self) -> bool {
        matches!(self, R2ILOp::Load { .. })
    }

    /// Returns true if this operation writes to memory.
    pub fn is_memory_write(&self) -> bool {
        matches!(self, R2ILOp::Store { .. })
    }

    /// Returns the output varnode if this operation has one.
    pub fn output(&self) -> Option<&Varnode> {
        match self {
            R2ILOp::Copy { dst, .. }
            | R2ILOp::Load { dst, .. }
            | R2ILOp::IntAdd { dst, .. }
            | R2ILOp::IntSub { dst, .. }
            | R2ILOp::IntMult { dst, .. }
            | R2ILOp::IntDiv { dst, .. }
            | R2ILOp::IntSDiv { dst, .. }
            | R2ILOp::IntRem { dst, .. }
            | R2ILOp::IntSRem { dst, .. }
            | R2ILOp::IntNegate { dst, .. }
            | R2ILOp::IntCarry { dst, .. }
            | R2ILOp::IntSCarry { dst, .. }
            | R2ILOp::IntSBorrow { dst, .. }
            | R2ILOp::IntAnd { dst, .. }
            | R2ILOp::IntOr { dst, .. }
            | R2ILOp::IntXor { dst, .. }
            | R2ILOp::IntNot { dst, .. }
            | R2ILOp::IntLeft { dst, .. }
            | R2ILOp::IntRight { dst, .. }
            | R2ILOp::IntSRight { dst, .. }
            | R2ILOp::IntEqual { dst, .. }
            | R2ILOp::IntNotEqual { dst, .. }
            | R2ILOp::IntLess { dst, .. }
            | R2ILOp::IntSLess { dst, .. }
            | R2ILOp::IntLessEqual { dst, .. }
            | R2ILOp::IntSLessEqual { dst, .. }
            | R2ILOp::IntZExt { dst, .. }
            | R2ILOp::IntSExt { dst, .. }
            | R2ILOp::BoolNot { dst, .. }
            | R2ILOp::BoolAnd { dst, .. }
            | R2ILOp::BoolOr { dst, .. }
            | R2ILOp::BoolXor { dst, .. }
            | R2ILOp::Piece { dst, .. }
            | R2ILOp::Subpiece { dst, .. }
            | R2ILOp::PopCount { dst, .. }
            | R2ILOp::Lzcount { dst, .. }
            | R2ILOp::FloatAdd { dst, .. }
            | R2ILOp::FloatSub { dst, .. }
            | R2ILOp::FloatMult { dst, .. }
            | R2ILOp::FloatDiv { dst, .. }
            | R2ILOp::FloatNeg { dst, .. }
            | R2ILOp::FloatAbs { dst, .. }
            | R2ILOp::FloatSqrt { dst, .. }
            | R2ILOp::FloatCeil { dst, .. }
            | R2ILOp::FloatFloor { dst, .. }
            | R2ILOp::FloatRound { dst, .. }
            | R2ILOp::FloatNaN { dst, .. }
            | R2ILOp::FloatEqual { dst, .. }
            | R2ILOp::FloatNotEqual { dst, .. }
            | R2ILOp::FloatLess { dst, .. }
            | R2ILOp::FloatLessEqual { dst, .. }
            | R2ILOp::Int2Float { dst, .. }
            | R2ILOp::Float2Int { dst, .. }
            | R2ILOp::FloatFloat { dst, .. }
            | R2ILOp::Trunc { dst, .. }
            | R2ILOp::CpuId { dst }
            | R2ILOp::Multiequal { dst, .. }
            | R2ILOp::Indirect { dst, .. }
            | R2ILOp::PtrAdd { dst, .. }
            | R2ILOp::PtrSub { dst, .. }
            | R2ILOp::SegmentOp { dst, .. }
            | R2ILOp::New { dst, .. }
            | R2ILOp::Cast { dst, .. }
            | R2ILOp::Extract { dst, .. }
            | R2ILOp::Insert { dst, .. } => Some(dst),
            R2ILOp::CallOther { output, .. } => output.as_ref(),
            _ => None,
        }
    }
}

/// A sequence of r2il operations for a single instruction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct R2ILBlock {
    /// The address of the instruction
    pub addr: u64,
    /// The size of the instruction in bytes
    pub size: u32,
    /// The operations for this instruction
    pub ops: Vec<R2ILOp>,
}

impl R2ILBlock {
    /// Create a new empty block.
    pub fn new(addr: u64, size: u32) -> Self {
        Self {
            addr,
            size,
            ops: Vec::new(),
        }
    }

    /// Add an operation to this block.
    pub fn push(&mut self, op: R2ILOp) {
        self.ops.push(op);
    }
}
