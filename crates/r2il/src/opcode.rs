//! r2il opcode definitions.
//!
//! These opcodes are based on Ghidra's P-code operations, providing a strongly-typed
//! intermediate representation for processor instruction semantics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::memory::MemoryOrdering;
use crate::metadata::{InstructionRuns, OpMetadata};
use crate::space::SpaceId;
use crate::varnode::Varnode;

/// What an operation does with a number it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueUse {
    /// Moves the number, or a slice or extension of it, somewhere else unchanged.
    Carries,
    /// Computes a different number from it.
    Derives,
    /// Compares or tests it, yielding a flag or a count rather than a number built on it.
    Tests,
    /// Uses it as it stands: an address, a stored value, a target, an argument.
    Consumes,
}

/// What a block operation does with each element it reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlockTransferKind {
    /// Each element is read from `source` and written at `destination`.
    Move,
    /// Every element is the value `source` holds.
    Fill,
    /// Each element at `destination` is compared with the value `source` holds.
    Scan(BlockStop),
    /// Each element at `source` is compared with the element at `destination`.
    Compare(BlockStop),
}

/// Which comparison ends a scan or a compare early, after the element it compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlockStop {
    /// The operation stops after a pair that is equal.
    Equal,
    /// The operation stops after a pair that differs.
    Unequal,
}

impl BlockTransferKind {
    /// Whether the operation reads memory, at `destination` or at `source`.
    pub const fn reads_memory(self) -> bool {
        !matches!(self, Self::Fill)
    }

    /// Whether the operation writes the elements at `destination`.
    pub const fn writes_memory(self) -> bool {
        matches!(self, Self::Move | Self::Fill)
    }

    /// Whether `source` is an address the operation reads through, rather than a value.
    pub const fn source_is_address(self) -> bool {
        matches!(self, Self::Move | Self::Compare(_))
    }

    /// The comparison that ends the operation early, where it has one.
    pub const fn stop(self) -> Option<BlockStop> {
        match self {
            Self::Scan(stop) | Self::Compare(stop) => Some(stop),
            Self::Move | Self::Fill => None,
        }
    }
}

/// One repeated string operation over up to `count` elements, ascending when `direction` is zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransfer {
    pub space: SpaceId,
    pub kind: BlockTransferKind,
    pub destination: Varnode,
    pub source: Varnode,
    pub count: Varnode,
    pub direction: Varnode,
    pub element_size: u32,
    /// A scan's or a compare's count reached, then the destination's and any source's last element (zero where none).
    pub answer: Option<Varnode>,
}

/// What an indivisible read-modify-write computes from the value it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AtomicFetchOp {
    Add,
    /// `old - operand`.
    Sub,
    And,
    Or,
    Xor,
    /// The operand itself, whatever was read.
    Swap,
    SignedMax,
    SignedMin,
    UnsignedMax,
    UnsignedMin,
}

/// What an indivisible access writes back over the value it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomicUpdate {
    /// `old op operand`, always written.
    Fetch { op: AtomicFetchOp, operand: Varnode },
    /// `replacement`, written only where the value read equals `expected`.
    CompareExchange {
        expected: Varnode,
        replacement: Varnode,
    },
}

/// One indivisible read-modify-write of `dst.size` bytes at `addr`; `dst` is the value read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicAccess {
    pub dst: Varnode,
    pub space: SpaceId,
    pub addr: Varnode,
    pub update: AtomicUpdate,
    pub ordering: MemoryOrdering,
}

impl AtomicAccess {
    /// The operands after the address: the fetch's operand, or the expected value and the replacement.
    pub fn operands(&self) -> Vec<&Varnode> {
        match &self.update {
            AtomicUpdate::Fetch { operand, .. } => vec![operand],
            AtomicUpdate::CompareExchange {
                expected,
                replacement,
            } => vec![expected, replacement],
        }
    }

    pub fn operands_mut(&mut self) -> Vec<&mut Varnode> {
        match &mut self.update {
            AtomicUpdate::Fetch { operand, .. } => vec![operand],
            AtomicUpdate::CompareExchange {
                expected,
                replacement,
            } => vec![expected, replacement],
        }
    }
}

/// The operand one operation sends control to, and how it sends it there.
///
/// R2IL's statement of which operand of a branch or a call says where control
/// goes, which the lift's memory canonicalization, the listing's claims and
/// the body's data references read rather than matching the operations
/// themselves. Where control goes is executed, not read as data, so no
/// consumer may look for a constant, a string or an object there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlTransfer<'a> {
    /// Where control goes: the destination itself where `direct`, else the value that holds it.
    pub target: &'a Varnode,
    /// Whether the operation encodes its destination, as a direct branch or call does, rather than computing it at run time.
    pub direct: bool,
    /// Whether control comes back after it, as it does from a call.
    pub call: bool,
}

/// One access an operation makes to memory, as [`R2ILOp::memory_accesses`] states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess<'a> {
    pub kind: crate::eval::AccessKind,
    pub space: SpaceId,
    /// The address operand: the first element's where `repeated`.
    pub addr: &'a Varnode,
    /// Bytes per access, or per element where `repeated`.
    pub size: u32,
    /// A block transfer's: its count and direction decide the extent, so it may reach anywhere in `space`.
    pub repeated: bool,
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum R2ILOp {
    // ========== Data Movement ==========
    /// Copy src to dst: dst = src
    Copy { dst: Varnode, src: Varnode },

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

    /// One repeated string operation, held out of line so it does not widen every operation.
    BlockTransfer(Box<BlockTransfer>),

    /// Memory fence/barrier with ordering semantics.
    Fence { ordering: MemoryOrdering },

    /// Clears the exclusive monitor a linked load set, so the next conditional store fails.
    ClearExclusive,

    /// Linked load from memory: dst = LL(*[space]addr).
    LoadLinked {
        dst: Varnode,
        space: SpaceId,
        addr: Varnode,
        ordering: MemoryOrdering,
    },

    /// Conditional store to memory; optional result receives success status.
    StoreConditional {
        result: Option<Varnode>,
        space: SpaceId,
        addr: Varnode,
        val: Varnode,
        ordering: MemoryOrdering,
    },

    /// One indivisible read-modify-write: a fetch operation or a compare-and-exchange.
    Atomic(Box<AtomicAccess>),

    /// The instruction's memory accesses are one indivisible access the lift has no typed
    /// statement of; eval runs them as written, and nothing may render them as plain accesses.
    IndivisibleAccess,

    /// Guarded load from memory: if guard then load.
    LoadGuarded {
        dst: Varnode,
        space: SpaceId,
        addr: Varnode,
        guard: Varnode,
        ordering: MemoryOrdering,
    },

    /// Guarded store to memory: if guard then store.
    StoreGuarded {
        space: SpaceId,
        addr: Varnode,
        val: Varnode,
        guard: Varnode,
        ordering: MemoryOrdering,
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
    IntNegate { dst: Varnode, src: Varnode },

    /// Unsigned carry: dst = whether a + b overflows their width
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
    IntNot { dst: Varnode, src: Varnode },

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
    IntZExt { dst: Varnode, src: Varnode },

    /// Sign extension: dst = sext(src)
    IntSExt { dst: Varnode, src: Varnode },

    // ========== Boolean Operations ==========
    /// Boolean NOT: dst = !src
    BoolNot { dst: Varnode, src: Varnode },

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
    PopCount { dst: Varnode, src: Varnode },

    /// Count leading zeros: dst = clz(src)
    Lzcount { dst: Varnode, src: Varnode },

    // ========== Control Flow ==========
    /// Unconditional branch to target
    Branch { target: Varnode },

    /// Conditional branch: if (cond) goto target
    CBranch { target: Varnode, cond: Varnode },

    /// Indirect branch: goto *target
    BranchInd { target: Varnode },

    /// Call a subroutine
    Call { target: Varnode },

    /// Indirect call: call *target
    CallInd { target: Varnode },

    /// Return from subroutine
    Return { target: Varnode },

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
    FloatNeg { dst: Varnode, src: Varnode },

    /// Float absolute value: dst = |src|
    FloatAbs { dst: Varnode, src: Varnode },

    /// Float square root: dst = sqrt(src)
    FloatSqrt { dst: Varnode, src: Varnode },

    /// Float ceiling: dst = ceil(src)
    FloatCeil { dst: Varnode, src: Varnode },

    /// Float floor: dst = floor(src)
    FloatFloor { dst: Varnode, src: Varnode },

    /// Float round: dst = round(src)
    FloatRound { dst: Varnode, src: Varnode },

    /// Float is NaN: dst = isnan(src)
    FloatNaN { dst: Varnode, src: Varnode },

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
    Int2Float { dst: Varnode, src: Varnode },

    /// Convert float to int: dst = (int)src
    Float2Int { dst: Varnode, src: Varnode },

    /// Convert float to different size float: dst = (float_new_size)src
    FloatFloat { dst: Varnode, src: Varnode },

    /// Truncate float to int: dst = trunc(src)
    Trunc { dst: Varnode, src: Varnode },

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
    CpuId { dst: Varnode },

    /// Insert a breakpoint
    Breakpoint,

    /// Multiequal (SSA phi function, used in analysis)
    Multiequal { dst: Varnode, inputs: Vec<Varnode> },

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
    New { dst: Varnode, src: Varnode },

    /// Cast (type cast, used in high-level analysis)
    Cast { dst: Varnode, src: Varnode },

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

    /// Conditional value merge produced when instruction-local P-code control
    /// flow is normalized into the linear r2il value graph.
    Select {
        dst: Varnode,
        cond: Varnode,
        if_true: Varnode,
        if_false: Varnode,
    },
}

/// The operations that compute a value from their operands alone. With the memory, control and
/// state classes below it names every operation once, so a list by class is exhaustive (D41).
macro_rules! value_operation {
    () => {
        R2ILOp::Copy { .. }
            | R2ILOp::IntAdd { .. }
            | R2ILOp::IntSub { .. }
            | R2ILOp::IntMult { .. }
            | R2ILOp::IntDiv { .. }
            | R2ILOp::IntSDiv { .. }
            | R2ILOp::IntRem { .. }
            | R2ILOp::IntSRem { .. }
            | R2ILOp::IntNegate { .. }
            | R2ILOp::IntCarry { .. }
            | R2ILOp::IntSCarry { .. }
            | R2ILOp::IntSBorrow { .. }
            | R2ILOp::IntAnd { .. }
            | R2ILOp::IntOr { .. }
            | R2ILOp::IntXor { .. }
            | R2ILOp::IntNot { .. }
            | R2ILOp::IntLeft { .. }
            | R2ILOp::IntRight { .. }
            | R2ILOp::IntSRight { .. }
            | R2ILOp::IntEqual { .. }
            | R2ILOp::IntNotEqual { .. }
            | R2ILOp::IntLess { .. }
            | R2ILOp::IntSLess { .. }
            | R2ILOp::IntLessEqual { .. }
            | R2ILOp::IntSLessEqual { .. }
            | R2ILOp::IntZExt { .. }
            | R2ILOp::IntSExt { .. }
            | R2ILOp::BoolNot { .. }
            | R2ILOp::BoolAnd { .. }
            | R2ILOp::BoolOr { .. }
            | R2ILOp::BoolXor { .. }
            | R2ILOp::Piece { .. }
            | R2ILOp::Subpiece { .. }
            | R2ILOp::PopCount { .. }
            | R2ILOp::Lzcount { .. }
            | R2ILOp::FloatAdd { .. }
            | R2ILOp::FloatSub { .. }
            | R2ILOp::FloatMult { .. }
            | R2ILOp::FloatDiv { .. }
            | R2ILOp::FloatNeg { .. }
            | R2ILOp::FloatAbs { .. }
            | R2ILOp::FloatSqrt { .. }
            | R2ILOp::FloatCeil { .. }
            | R2ILOp::FloatFloor { .. }
            | R2ILOp::FloatRound { .. }
            | R2ILOp::FloatNaN { .. }
            | R2ILOp::FloatEqual { .. }
            | R2ILOp::FloatNotEqual { .. }
            | R2ILOp::FloatLess { .. }
            | R2ILOp::FloatLessEqual { .. }
            | R2ILOp::Int2Float { .. }
            | R2ILOp::Float2Int { .. }
            | R2ILOp::FloatFloat { .. }
            | R2ILOp::Trunc { .. }
            | R2ILOp::Multiequal { .. }
            | R2ILOp::Indirect { .. }
            | R2ILOp::PtrAdd { .. }
            | R2ILOp::PtrSub { .. }
            | R2ILOp::SegmentOp { .. }
            | R2ILOp::Cast { .. }
            | R2ILOp::Extract { .. }
            | R2ILOp::Insert { .. }
            | R2ILOp::Select { .. }
    };
}

/// The operations that read or write memory, or order its accesses.
macro_rules! memory_operation {
    () => {
        R2ILOp::Load { .. }
            | R2ILOp::Store { .. }
            | R2ILOp::BlockTransfer(_)
            | R2ILOp::Fence { .. }
            | R2ILOp::ClearExclusive
            | R2ILOp::IndivisibleAccess
            | R2ILOp::LoadLinked { .. }
            | R2ILOp::StoreConditional { .. }
            | R2ILOp::Atomic(_)
            | R2ILOp::LoadGuarded { .. }
            | R2ILOp::StoreGuarded { .. }
    };
}

/// The operations that decide where control goes.
macro_rules! control_operation {
    () => {
        R2ILOp::Branch { .. }
            | R2ILOp::CBranch { .. }
            | R2ILOp::BranchInd { .. }
            | R2ILOp::Call { .. }
            | R2ILOp::CallInd { .. }
            | R2ILOp::Return { .. }
            | R2ILOp::Breakpoint
    };
}

/// The rest: machine state, allocation, user operations, and no operation.
macro_rules! state_operation {
    () => {
        R2ILOp::CallOther { .. }
            | R2ILOp::Nop
            | R2ILOp::Unimplemented
            | R2ILOp::CpuId { .. }
            | R2ILOp::New { .. }
    };
}

/// Every operation's output, named once for [`R2ILOp::output`] and [`R2ILOp::output_mut`]: an
/// operation added without an arm fails to compile, so phi placement never misses a definition.
macro_rules! output_of {
    ($op:expr, $as:ident) => {
        match $op {
            R2ILOp::Copy { dst, .. }
            | R2ILOp::Load { dst, .. }
            | R2ILOp::LoadLinked { dst, .. }
            | R2ILOp::LoadGuarded { dst, .. }
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
            | R2ILOp::Insert { dst, .. }
            | R2ILOp::Select { dst, .. } => Some(dst),
            R2ILOp::StoreConditional { result, .. } => result.$as(),
            R2ILOp::CallOther { output, .. } => output.$as(),
            R2ILOp::BlockTransfer(transfer) => transfer.answer.$as(),
            R2ILOp::Atomic(access) => match access.$as() {
                AtomicAccess { dst, .. } => Some(dst),
            },
            R2ILOp::Store { .. }
            | R2ILOp::StoreGuarded { .. }
            | R2ILOp::Fence { .. }
            | R2ILOp::ClearExclusive
            | R2ILOp::IndivisibleAccess
            | R2ILOp::Branch { .. }
            | R2ILOp::CBranch { .. }
            | R2ILOp::BranchInd { .. }
            | R2ILOp::Call { .. }
            | R2ILOp::CallInd { .. }
            | R2ILOp::Return { .. }
            | R2ILOp::Nop
            | R2ILOp::Unimplemented
            | R2ILOp::Breakpoint => None,
        }
    };
}

impl R2ILOp {
    /// What this operation does with the numbers it reads.
    pub fn value_use(&self) -> ValueUse {
        match self {
            R2ILOp::Copy { .. }
            | R2ILOp::IntZExt { .. }
            | R2ILOp::IntSExt { .. }
            | R2ILOp::Subpiece { .. }
            | R2ILOp::Multiequal { .. }
            | R2ILOp::Indirect { .. }
            | R2ILOp::Cast { .. }
            // A selection moves whichever arm it chose, as the SSA operation it becomes says.
            | R2ILOp::Select { .. } => ValueUse::Carries,
            R2ILOp::IntAdd { .. }
            | R2ILOp::IntSub { .. }
            | R2ILOp::IntMult { .. }
            | R2ILOp::IntDiv { .. }
            | R2ILOp::IntSDiv { .. }
            | R2ILOp::IntRem { .. }
            | R2ILOp::IntSRem { .. }
            | R2ILOp::IntNegate { .. }
            | R2ILOp::IntAnd { .. }
            | R2ILOp::IntOr { .. }
            | R2ILOp::IntXor { .. }
            | R2ILOp::IntNot { .. }
            | R2ILOp::IntLeft { .. }
            | R2ILOp::IntRight { .. }
            | R2ILOp::IntSRight { .. }
            | R2ILOp::Piece { .. }
            | R2ILOp::PtrAdd { .. }
            | R2ILOp::PtrSub { .. }
            | R2ILOp::SegmentOp { .. }
            | R2ILOp::Extract { .. }
            | R2ILOp::Insert { .. } => ValueUse::Derives,
            R2ILOp::IntEqual { .. }
            | R2ILOp::IntNotEqual { .. }
            | R2ILOp::IntLess { .. }
            | R2ILOp::IntSLess { .. }
            | R2ILOp::IntLessEqual { .. }
            | R2ILOp::IntSLessEqual { .. }
            | R2ILOp::IntCarry { .. }
            | R2ILOp::IntSCarry { .. }
            | R2ILOp::IntSBorrow { .. }
            | R2ILOp::BoolNot { .. }
            | R2ILOp::BoolAnd { .. }
            | R2ILOp::BoolOr { .. }
            | R2ILOp::BoolXor { .. }
            | R2ILOp::PopCount { .. }
            | R2ILOp::Lzcount { .. } => ValueUse::Tests,
            R2ILOp::FloatAdd { .. }
            | R2ILOp::FloatSub { .. }
            | R2ILOp::FloatMult { .. }
            | R2ILOp::FloatDiv { .. }
            | R2ILOp::FloatNeg { .. }
            | R2ILOp::FloatAbs { .. }
            | R2ILOp::FloatSqrt { .. }
            | R2ILOp::FloatCeil { .. }
            | R2ILOp::FloatFloor { .. }
            | R2ILOp::FloatRound { .. }
            | R2ILOp::FloatNaN { .. }
            | R2ILOp::FloatEqual { .. }
            | R2ILOp::FloatNotEqual { .. }
            | R2ILOp::FloatLess { .. }
            | R2ILOp::FloatLessEqual { .. }
            | R2ILOp::Int2Float { .. }
            | R2ILOp::Float2Int { .. }
            | R2ILOp::FloatFloat { .. }
            | R2ILOp::Trunc { .. }
            | memory_operation!()
            | control_operation!()
            | state_operation!() => ValueUse::Consumes,
        }
    }

    /// Returns true if this operation is a control flow operation.
    pub fn is_control_flow(&self) -> bool {
        // A trap goes to the exception handler and not back: a block ends at one, naming no successor.
        match self {
            control_operation!() => true,
            memory_operation!() | state_operation!() | value_operation!() => false,
        }
    }

    /// Where this operation sends control, where it names a place to send it.
    ///
    /// A return is none: it goes back to wherever its caller was, which is no
    /// address the operation names, and a trap goes to a handler it does not
    /// name either.
    pub fn transfer(&self) -> Option<ControlTransfer<'_>> {
        let (target, direct, call) = match self {
            R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => (target, true, false),
            R2ILOp::Call { target } => (target, true, true),
            R2ILOp::BranchInd { target } => (target, false, false),
            R2ILOp::CallInd { target } => (target, false, true),
            R2ILOp::Return { .. }
            | R2ILOp::Breakpoint
            | memory_operation!()
            | state_operation!()
            | value_operation!() => return None,
        };
        Some(ControlTransfer {
            target,
            direct,
            call,
        })
    }

    /// Whether control comes back after this operation's transfer, as it does from a call.
    pub fn is_call(&self) -> bool {
        self.transfer().is_some_and(|transfer| transfer.call)
    }

    /// A branch to an operation of the same instruction: Sleigh states its target in the constant space.
    pub fn is_local_branch(&self) -> bool {
        self.transfer().is_some_and(|transfer| {
            transfer.direct && !transfer.call && transfer.target.space == SpaceId::Const
        })
    }

    /// How many operations from this one a local branch names, as Sleigh's signed label at the
    /// target's width; `None` for any other operation.
    pub fn local_offset(&self) -> Option<i64> {
        let (R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. }) = self else {
            return None;
        };
        target.signed_label()
    }

    /// Name the operation `offset` operations from this local branch, wrapped to the target's width.
    pub fn set_local_offset(&mut self, offset: i64) {
        if self.local_offset().is_none() {
            return;
        }
        let (R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. }) = self else {
            return;
        };
        target.offset = (offset as u64) & (u64::MAX >> (64 - 8 * target.size));
    }

    /// The inputs through which this operation can name data: every one but
    /// the operand that says where control goes.
    ///
    /// A branch's, a call's or a return's destination is code the transfer
    /// executes, so no constant, string or object is looked for there, whether
    /// the operand is that destination or holds it; only a conditional
    /// branch's condition is data among a transfer's operands.
    ///
    /// This is not the set of storages the operation reads: an indirect
    /// transfer or a return still reads the register holding its destination,
    /// so no def-use or liveness question is answered from it. It also takes
    /// the canonical form the lift gives: a memory slot an indirect transfer
    /// reads its destination from is data, and the lift loads it explicitly
    /// first, so the operand here is never that slot.
    pub fn data_inputs(&self) -> Vec<&Varnode> {
        match self {
            R2ILOp::CBranch { cond, .. } => vec![cond],
            R2ILOp::Return { .. } => Vec::new(),
            _ if self.transfer().is_some() => Vec::new(),
            _ => self.inputs(),
        }
    }

    /// Every access this operation makes to memory, in the order it makes them; a conditional or
    /// linked access names the address it would use as surely as a plain one does.
    pub fn memory_accesses(&self) -> impl Iterator<Item = MemoryAccess<'_>> {
        use crate::eval::AccessKind::{Read, Write};
        let one = |kind, space: &SpaceId, addr, size| MemoryAccess {
            kind,
            space: *space,
            addr,
            size,
            repeated: false,
        };
        let accesses: [Option<MemoryAccess<'_>>; 3] = match self {
            R2ILOp::Load { dst, space, addr }
            | R2ILOp::LoadLinked {
                dst, space, addr, ..
            }
            | R2ILOp::LoadGuarded {
                dst, space, addr, ..
            } => [Some(one(Read, space, addr, dst.size)), None, None],
            R2ILOp::Store { space, addr, val }
            | R2ILOp::StoreConditional {
                space, addr, val, ..
            }
            | R2ILOp::StoreGuarded {
                space, addr, val, ..
            } => [Some(one(Write, space, addr, val.size)), None, None],
            R2ILOp::Atomic(access) => {
                let AtomicAccess {
                    dst, space, addr, ..
                } = access.as_ref();
                [
                    Some(one(Read, space, addr, dst.size)),
                    Some(one(Write, space, addr, dst.size)),
                    None,
                ]
            }
            R2ILOp::BlockTransfer(transfer) => {
                let kind = transfer.kind;
                let element = |kind, addr| MemoryAccess {
                    kind,
                    space: transfer.space,
                    addr,
                    size: transfer.element_size,
                    repeated: true,
                };
                [
                    kind.source_is_address()
                        .then(|| element(Read, &transfer.source)),
                    kind.stop().map(|_| element(Read, &transfer.destination)),
                    kind.writes_memory()
                        .then(|| element(Write, &transfer.destination)),
                ]
            }
            R2ILOp::Fence { .. }
            | R2ILOp::ClearExclusive
            | R2ILOp::IndivisibleAccess
            | control_operation!()
            | state_operation!()
            | value_operation!() => [None, None, None],
        };
        accesses.into_iter().flatten()
    }

    /// Returns true if this operation reads from memory.
    pub fn is_memory_read(&self) -> bool {
        self.memory_accesses()
            .any(|access| access.kind == crate::eval::AccessKind::Read)
    }

    /// Returns true if this operation writes to memory.
    pub fn is_memory_write(&self) -> bool {
        self.memory_accesses()
            .any(|access| access.kind == crate::eval::AccessKind::Write)
    }

    /// Returns true when this value operation may be evaluated speculatively.
    ///
    /// This is intentionally narrower than "has an output": reads, writes,
    /// allocation, CPU state queries, calls, and control flow may be observable
    /// even when their result is later discarded, and a division is undefined
    /// where the test it was guarded by would have skipped it (audit W22).
    pub fn is_speculatable_value(&self) -> bool {
        self.output().is_some()
            && !self.is_control_flow()
            && !self.is_memory_read()
            && !self.is_memory_write()
            && !self.is_integer_division()
            && !matches!(
                self,
                R2ILOp::CallOther { .. } | R2ILOp::CpuId { .. } | R2ILOp::New { .. }
            )
    }

    /// An integer quotient or remainder, undefined at a zero divisor.
    pub fn is_integer_division(&self) -> bool {
        matches!(
            self,
            R2ILOp::IntDiv { .. }
                | R2ILOp::IntSDiv { .. }
                | R2ILOp::IntRem { .. }
                | R2ILOp::IntSRem { .. }
        )
    }

    /// The output varnode, if any: the one list renaming and phi placement both read.
    pub fn output(&self) -> Option<&Varnode> {
        output_of!(self, as_ref)
    }

    /// The output varnode mutably, from the same list as [`Self::output`].
    pub fn output_mut(&mut self) -> Option<&mut Varnode> {
        output_of!(self, as_mut)
    }

    /// Returns the input varnodes for this operation.
    ///
    /// This is the symmetric counterpart to `output()`, enabling consumers
    /// to iterate over all inputs without pattern matching on every variant.
    pub fn inputs(&self) -> Vec<&Varnode> {
        match self {
            // Data movement
            R2ILOp::Copy { src, .. } => vec![src],
            R2ILOp::Load { addr, .. } => vec![addr],
            R2ILOp::Store { addr, val, .. } => vec![addr, val],
            R2ILOp::BlockTransfer(transfer) => vec![
                &transfer.destination,
                &transfer.source,
                &transfer.count,
                &transfer.direction,
            ],
            R2ILOp::Fence { .. } | R2ILOp::ClearExclusive | R2ILOp::IndivisibleAccess => vec![],
            R2ILOp::LoadLinked { addr, .. } => vec![addr],
            R2ILOp::StoreConditional { addr, val, .. } => vec![addr, val],
            R2ILOp::Atomic(access) => std::iter::once(&access.addr)
                .chain(access.operands())
                .collect(),
            R2ILOp::LoadGuarded { addr, guard, .. } => vec![addr, guard],
            R2ILOp::StoreGuarded {
                addr, val, guard, ..
            } => vec![addr, val, guard],

            // Binary integer operations
            R2ILOp::IntAdd { a, b, .. }
            | R2ILOp::IntSub { a, b, .. }
            | R2ILOp::IntMult { a, b, .. }
            | R2ILOp::IntDiv { a, b, .. }
            | R2ILOp::IntSDiv { a, b, .. }
            | R2ILOp::IntRem { a, b, .. }
            | R2ILOp::IntSRem { a, b, .. }
            | R2ILOp::IntCarry { a, b, .. }
            | R2ILOp::IntSCarry { a, b, .. }
            | R2ILOp::IntSBorrow { a, b, .. }
            | R2ILOp::IntAnd { a, b, .. }
            | R2ILOp::IntOr { a, b, .. }
            | R2ILOp::IntXor { a, b, .. }
            | R2ILOp::IntLeft { a, b, .. }
            | R2ILOp::IntRight { a, b, .. }
            | R2ILOp::IntSRight { a, b, .. }
            | R2ILOp::IntEqual { a, b, .. }
            | R2ILOp::IntNotEqual { a, b, .. }
            | R2ILOp::IntLess { a, b, .. }
            | R2ILOp::IntSLess { a, b, .. }
            | R2ILOp::IntLessEqual { a, b, .. }
            | R2ILOp::IntSLessEqual { a, b, .. } => vec![a, b],

            // Unary integer operations
            R2ILOp::IntNegate { src, .. }
            | R2ILOp::IntNot { src, .. }
            | R2ILOp::IntZExt { src, .. }
            | R2ILOp::IntSExt { src, .. } => vec![src],

            // Boolean operations
            R2ILOp::BoolNot { src, .. } => vec![src],
            R2ILOp::BoolAnd { a, b, .. }
            | R2ILOp::BoolOr { a, b, .. }
            | R2ILOp::BoolXor { a, b, .. } => vec![a, b],

            // Bit manipulation
            R2ILOp::Piece { hi, lo, .. } => vec![hi, lo],
            R2ILOp::Subpiece { src, .. } => vec![src],
            R2ILOp::PopCount { src, .. } | R2ILOp::Lzcount { src, .. } => vec![src],

            // Control flow
            R2ILOp::Branch { target } => vec![target],
            R2ILOp::CBranch { target, cond } => vec![target, cond],
            R2ILOp::BranchInd { target } => vec![target],
            R2ILOp::Call { target } => vec![target],
            R2ILOp::CallInd { target } => vec![target],
            R2ILOp::Return { target } => vec![target],

            // Binary float operations
            R2ILOp::FloatAdd { a, b, .. }
            | R2ILOp::FloatSub { a, b, .. }
            | R2ILOp::FloatMult { a, b, .. }
            | R2ILOp::FloatDiv { a, b, .. }
            | R2ILOp::FloatEqual { a, b, .. }
            | R2ILOp::FloatNotEqual { a, b, .. }
            | R2ILOp::FloatLess { a, b, .. }
            | R2ILOp::FloatLessEqual { a, b, .. } => vec![a, b],

            // Unary float operations
            R2ILOp::FloatNeg { src, .. }
            | R2ILOp::FloatAbs { src, .. }
            | R2ILOp::FloatSqrt { src, .. }
            | R2ILOp::FloatCeil { src, .. }
            | R2ILOp::FloatFloor { src, .. }
            | R2ILOp::FloatRound { src, .. }
            | R2ILOp::FloatNaN { src, .. }
            | R2ILOp::Int2Float { src, .. }
            | R2ILOp::Float2Int { src, .. }
            | R2ILOp::FloatFloat { src, .. }
            | R2ILOp::Trunc { src, .. } => vec![src],

            // Special operations
            R2ILOp::CallOther { inputs, .. } => inputs.iter().collect(),
            R2ILOp::Nop | R2ILOp::Unimplemented | R2ILOp::Breakpoint => vec![],
            R2ILOp::CpuId { .. } => vec![],
            R2ILOp::Multiequal { inputs, .. } => inputs.iter().collect(),
            R2ILOp::Indirect { src, indirect, .. } => vec![src, indirect],
            R2ILOp::PtrAdd { base, index, .. } | R2ILOp::PtrSub { base, index, .. } => {
                vec![base, index]
            }
            R2ILOp::SegmentOp {
                segment, offset, ..
            } => vec![segment, offset],
            R2ILOp::New { src, .. } | R2ILOp::Cast { src, .. } => vec![src],
            R2ILOp::Extract { src, position, .. } => vec![src, position],
            R2ILOp::Insert {
                src,
                value,
                position,
                ..
            } => vec![src, value, position],
            R2ILOp::Select {
                cond,
                if_true,
                if_false,
                ..
            } => vec![cond, if_true, if_false],
        }
    }

    /// Returns mutable references to the input varnodes for this operation.
    ///
    /// This enables transformation passes to modify operands in-place.
    pub fn inputs_mut(&mut self) -> Vec<&mut Varnode> {
        match self {
            // Data movement
            R2ILOp::Copy { src, .. } => vec![src],
            R2ILOp::Load { addr, .. } => vec![addr],
            R2ILOp::Store { addr, val, .. } => vec![addr, val],
            R2ILOp::BlockTransfer(transfer) => {
                let BlockTransfer {
                    destination,
                    source,
                    count,
                    direction,
                    ..
                } = transfer.as_mut();
                vec![destination, source, count, direction]
            }
            R2ILOp::Fence { .. } | R2ILOp::ClearExclusive | R2ILOp::IndivisibleAccess => vec![],
            R2ILOp::LoadLinked { addr, .. } => vec![addr],
            R2ILOp::StoreConditional { addr, val, .. } => vec![addr, val],
            R2ILOp::Atomic(access) => {
                let AtomicAccess { addr, update, .. } = access.as_mut();
                match update {
                    AtomicUpdate::Fetch { operand, .. } => vec![addr, operand],
                    AtomicUpdate::CompareExchange {
                        expected,
                        replacement,
                    } => vec![addr, expected, replacement],
                }
            }
            R2ILOp::LoadGuarded { addr, guard, .. } => vec![addr, guard],
            R2ILOp::StoreGuarded {
                addr, val, guard, ..
            } => vec![addr, val, guard],

            // Binary integer operations
            R2ILOp::IntAdd { a, b, .. }
            | R2ILOp::IntSub { a, b, .. }
            | R2ILOp::IntMult { a, b, .. }
            | R2ILOp::IntDiv { a, b, .. }
            | R2ILOp::IntSDiv { a, b, .. }
            | R2ILOp::IntRem { a, b, .. }
            | R2ILOp::IntSRem { a, b, .. }
            | R2ILOp::IntCarry { a, b, .. }
            | R2ILOp::IntSCarry { a, b, .. }
            | R2ILOp::IntSBorrow { a, b, .. }
            | R2ILOp::IntAnd { a, b, .. }
            | R2ILOp::IntOr { a, b, .. }
            | R2ILOp::IntXor { a, b, .. }
            | R2ILOp::IntLeft { a, b, .. }
            | R2ILOp::IntRight { a, b, .. }
            | R2ILOp::IntSRight { a, b, .. }
            | R2ILOp::IntEqual { a, b, .. }
            | R2ILOp::IntNotEqual { a, b, .. }
            | R2ILOp::IntLess { a, b, .. }
            | R2ILOp::IntSLess { a, b, .. }
            | R2ILOp::IntLessEqual { a, b, .. }
            | R2ILOp::IntSLessEqual { a, b, .. } => vec![a, b],

            // Unary integer operations
            R2ILOp::IntNegate { src, .. }
            | R2ILOp::IntNot { src, .. }
            | R2ILOp::IntZExt { src, .. }
            | R2ILOp::IntSExt { src, .. } => vec![src],

            // Boolean operations
            R2ILOp::BoolNot { src, .. } => vec![src],
            R2ILOp::BoolAnd { a, b, .. }
            | R2ILOp::BoolOr { a, b, .. }
            | R2ILOp::BoolXor { a, b, .. } => vec![a, b],

            // Bit manipulation
            R2ILOp::Piece { hi, lo, .. } => vec![hi, lo],
            R2ILOp::Subpiece { src, .. } => vec![src],
            R2ILOp::PopCount { src, .. } | R2ILOp::Lzcount { src, .. } => vec![src],

            // Control flow
            R2ILOp::Branch { target } => vec![target],
            R2ILOp::CBranch { target, cond } => vec![target, cond],
            R2ILOp::BranchInd { target } => vec![target],
            R2ILOp::Call { target } => vec![target],
            R2ILOp::CallInd { target } => vec![target],
            R2ILOp::Return { target } => vec![target],

            // Binary float operations
            R2ILOp::FloatAdd { a, b, .. }
            | R2ILOp::FloatSub { a, b, .. }
            | R2ILOp::FloatMult { a, b, .. }
            | R2ILOp::FloatDiv { a, b, .. }
            | R2ILOp::FloatEqual { a, b, .. }
            | R2ILOp::FloatNotEqual { a, b, .. }
            | R2ILOp::FloatLess { a, b, .. }
            | R2ILOp::FloatLessEqual { a, b, .. } => vec![a, b],

            // Unary float operations
            R2ILOp::FloatNeg { src, .. }
            | R2ILOp::FloatAbs { src, .. }
            | R2ILOp::FloatSqrt { src, .. }
            | R2ILOp::FloatCeil { src, .. }
            | R2ILOp::FloatFloor { src, .. }
            | R2ILOp::FloatRound { src, .. }
            | R2ILOp::FloatNaN { src, .. }
            | R2ILOp::Int2Float { src, .. }
            | R2ILOp::Float2Int { src, .. }
            | R2ILOp::FloatFloat { src, .. }
            | R2ILOp::Trunc { src, .. } => vec![src],

            // Special operations
            R2ILOp::CallOther { inputs, .. } => inputs.iter_mut().collect(),
            R2ILOp::Nop | R2ILOp::Unimplemented | R2ILOp::Breakpoint => vec![],
            R2ILOp::CpuId { .. } => vec![],
            R2ILOp::Multiequal { inputs, .. } => inputs.iter_mut().collect(),
            R2ILOp::Indirect { src, indirect, .. } => vec![src, indirect],
            R2ILOp::PtrAdd { base, index, .. } | R2ILOp::PtrSub { base, index, .. } => {
                vec![base, index]
            }
            R2ILOp::SegmentOp {
                segment, offset, ..
            } => vec![segment, offset],
            R2ILOp::New { src, .. } | R2ILOp::Cast { src, .. } => vec![src],
            R2ILOp::Extract { src, position, .. } => vec![src, position],
            R2ILOp::Insert {
                src,
                value,
                position,
                ..
            } => vec![src, value, position],
            R2ILOp::Select {
                cond,
                if_true,
                if_false,
                ..
            } => vec![cond, if_true, if_false],
        }
    }
}

impl std::fmt::Display for R2ILOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Data movement
            R2ILOp::Copy { dst, src } => write!(f, "{} = COPY {}", dst, src),
            R2ILOp::BlockTransfer(transfer) => {
                let BlockTransfer {
                    space,
                    kind,
                    destination,
                    source,
                    count,
                    direction,
                    element_size,
                    answer,
                } = transfer.as_ref();
                if let Some(answer) = answer {
                    write!(f, "{answer} = ")?;
                }
                let (name, stop) = match kind {
                    BlockTransferKind::Move => ("MOVE", ""),
                    BlockTransferKind::Fill => ("FILL", ""),
                    BlockTransferKind::Scan(BlockStop::Equal) => ("SCAN", " until equal"),
                    BlockTransferKind::Scan(BlockStop::Unequal) => ("SCAN", " until unequal"),
                    BlockTransferKind::Compare(BlockStop::Equal) => ("COMPARE", " until equal"),
                    BlockTransferKind::Compare(BlockStop::Unequal) => ("COMPARE", " until unequal"),
                };
                write!(
                    f,
                    "BLOCK{name} [{space}]{destination} <- {source} x {count}{stop} ({element_size} bytes each, direction {direction})"
                )
            }
            R2ILOp::Load { dst, space, addr } => {
                write!(f, "{} = LOAD [{}]{}", dst, space, addr)
            }
            R2ILOp::Store { space, addr, val } => {
                write!(f, "STORE [{}]{} = {}", space, addr, val)
            }
            R2ILOp::Fence { ordering } => write!(f, "FENCE({ordering:?})"),
            R2ILOp::ClearExclusive => write!(f, "CLEAR_EXCLUSIVE"),
            R2ILOp::LoadLinked {
                dst,
                space,
                addr,
                ordering,
            } => {
                write!(
                    f,
                    "{} = LOAD_LINKED [{}]{} ({ordering:?})",
                    dst, space, addr
                )
            }
            R2ILOp::StoreConditional {
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
                    "STORE_CONDITIONAL [{}]{} = {} ({ordering:?})",
                    space, addr, val
                )
            }
            R2ILOp::Atomic(access) => {
                let AtomicAccess {
                    dst,
                    space,
                    addr,
                    update,
                    ordering,
                } = access.as_ref();
                match update {
                    AtomicUpdate::Fetch { op, operand } => write!(
                        f,
                        "{dst} = ATOMIC_{op:?} [{space}]{addr}, {operand} ({ordering:?})"
                    ),
                    AtomicUpdate::CompareExchange {
                        expected,
                        replacement,
                    } => write!(
                        f,
                        "{dst} = ATOMIC_CAS [{space}]{addr}, {expected}, {replacement} ({ordering:?})"
                    ),
                }
            }
            R2ILOp::IndivisibleAccess => write!(f, "INDIVISIBLE_ACCESS"),
            R2ILOp::LoadGuarded {
                dst,
                space,
                addr,
                guard,
                ordering,
            } => {
                write!(
                    f,
                    "{} = LOAD_GUARDED [{}]{}, {} ({ordering:?})",
                    dst, space, addr, guard
                )
            }
            R2ILOp::StoreGuarded {
                space,
                addr,
                val,
                guard,
                ordering,
            } => {
                write!(
                    f,
                    "STORE_GUARDED [{}]{} = {} if {} ({ordering:?})",
                    space, addr, val, guard
                )
            }

            // Integer arithmetic
            R2ILOp::IntAdd { dst, a, b } => write!(f, "{} = {} + {}", dst, a, b),
            R2ILOp::IntSub { dst, a, b } => write!(f, "{} = {} - {}", dst, a, b),
            R2ILOp::IntMult { dst, a, b } => write!(f, "{} = {} * {}", dst, a, b),
            R2ILOp::IntDiv { dst, a, b } => write!(f, "{} = {} / {}", dst, a, b),
            R2ILOp::IntSDiv { dst, a, b } => write!(f, "{} = {} s/ {}", dst, a, b),
            R2ILOp::IntRem { dst, a, b } => write!(f, "{} = {} % {}", dst, a, b),
            R2ILOp::IntSRem { dst, a, b } => write!(f, "{} = {} s% {}", dst, a, b),
            R2ILOp::IntNegate { dst, src } => write!(f, "{} = -{}", dst, src),
            R2ILOp::IntCarry { dst, a, b } => write!(f, "{} = CARRY({}, {})", dst, a, b),
            R2ILOp::IntSCarry { dst, a, b } => write!(f, "{} = SCARRY({}, {})", dst, a, b),
            R2ILOp::IntSBorrow { dst, a, b } => write!(f, "{} = SBORROW({}, {})", dst, a, b),

            // Logical operations
            R2ILOp::IntAnd { dst, a, b } => write!(f, "{} = {} & {}", dst, a, b),
            R2ILOp::IntOr { dst, a, b } => write!(f, "{} = {} | {}", dst, a, b),
            R2ILOp::IntXor { dst, a, b } => write!(f, "{} = {} ^ {}", dst, a, b),
            R2ILOp::IntNot { dst, src } => write!(f, "{} = ~{}", dst, src),

            // Shift operations
            R2ILOp::IntLeft { dst, a, b } => write!(f, "{} = {} << {}", dst, a, b),
            R2ILOp::IntRight { dst, a, b } => write!(f, "{} = {} >> {}", dst, a, b),
            R2ILOp::IntSRight { dst, a, b } => write!(f, "{} = {} s>> {}", dst, a, b),

            // Comparison operations
            R2ILOp::IntEqual { dst, a, b } => write!(f, "{} = {} == {}", dst, a, b),
            R2ILOp::IntNotEqual { dst, a, b } => write!(f, "{} = {} != {}", dst, a, b),
            R2ILOp::IntLess { dst, a, b } => write!(f, "{} = {} < {}", dst, a, b),
            R2ILOp::IntSLess { dst, a, b } => write!(f, "{} = {} s< {}", dst, a, b),
            R2ILOp::IntLessEqual { dst, a, b } => write!(f, "{} = {} <= {}", dst, a, b),
            R2ILOp::IntSLessEqual { dst, a, b } => write!(f, "{} = {} s<= {}", dst, a, b),

            // Extension operations
            R2ILOp::IntZExt { dst, src } => write!(f, "{} = ZEXT({})", dst, src),
            R2ILOp::IntSExt { dst, src } => write!(f, "{} = SEXT({})", dst, src),

            // Boolean operations
            R2ILOp::BoolNot { dst, src } => write!(f, "{} = !{}", dst, src),
            R2ILOp::BoolAnd { dst, a, b } => write!(f, "{} = {} && {}", dst, a, b),
            R2ILOp::BoolOr { dst, a, b } => write!(f, "{} = {} || {}", dst, a, b),
            R2ILOp::BoolXor { dst, a, b } => write!(f, "{} = {} ^^ {}", dst, a, b),

            // Bit manipulation
            R2ILOp::Piece { dst, hi, lo } => write!(f, "{} = PIECE({}, {})", dst, hi, lo),
            R2ILOp::Subpiece { dst, src, offset } => {
                write!(f, "{} = SUBPIECE({}, {})", dst, src, offset)
            }
            R2ILOp::PopCount { dst, src } => write!(f, "{} = POPCOUNT({})", dst, src),
            R2ILOp::Lzcount { dst, src } => write!(f, "{} = LZCOUNT({})", dst, src),

            // Control flow
            R2ILOp::Branch { target } => write!(f, "BRANCH {}", target),
            R2ILOp::CBranch { target, cond } => write!(f, "CBRANCH {} if {}", target, cond),
            R2ILOp::BranchInd { target } => write!(f, "BRANCHIND {}", target),
            R2ILOp::Call { target } => write!(f, "CALL {}", target),
            R2ILOp::CallInd { target } => write!(f, "CALLIND {}", target),
            R2ILOp::Return { target } => write!(f, "RETURN {}", target),

            // Floating point operations
            R2ILOp::FloatAdd { dst, a, b } => write!(f, "{} = {} f+ {}", dst, a, b),
            R2ILOp::FloatSub { dst, a, b } => write!(f, "{} = {} f- {}", dst, a, b),
            R2ILOp::FloatMult { dst, a, b } => write!(f, "{} = {} f* {}", dst, a, b),
            R2ILOp::FloatDiv { dst, a, b } => write!(f, "{} = {} f/ {}", dst, a, b),
            R2ILOp::FloatNeg { dst, src } => write!(f, "{} = f-{}", dst, src),
            R2ILOp::FloatAbs { dst, src } => write!(f, "{} = FABS({})", dst, src),
            R2ILOp::FloatSqrt { dst, src } => write!(f, "{} = FSQRT({})", dst, src),
            R2ILOp::FloatCeil { dst, src } => write!(f, "{} = FCEIL({})", dst, src),
            R2ILOp::FloatFloor { dst, src } => write!(f, "{} = FFLOOR({})", dst, src),
            R2ILOp::FloatRound { dst, src } => write!(f, "{} = FROUND({})", dst, src),
            R2ILOp::FloatNaN { dst, src } => write!(f, "{} = FNAN({})", dst, src),
            R2ILOp::FloatEqual { dst, a, b } => write!(f, "{} = {} f== {}", dst, a, b),
            R2ILOp::FloatNotEqual { dst, a, b } => write!(f, "{} = {} f!= {}", dst, a, b),
            R2ILOp::FloatLess { dst, a, b } => write!(f, "{} = {} f< {}", dst, a, b),
            R2ILOp::FloatLessEqual { dst, a, b } => write!(f, "{} = {} f<= {}", dst, a, b),
            R2ILOp::Int2Float { dst, src } => write!(f, "{} = INT2FLOAT({})", dst, src),
            R2ILOp::Float2Int { dst, src } => write!(f, "{} = FLOAT2INT({})", dst, src),
            R2ILOp::FloatFloat { dst, src } => write!(f, "{} = FLOAT2FLOAT({})", dst, src),
            R2ILOp::Trunc { dst, src } => write!(f, "{} = TRUNC({})", dst, src),

            // Special operations
            R2ILOp::CallOther {
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
            R2ILOp::Nop => write!(f, "NOP"),
            R2ILOp::Unimplemented => write!(f, "UNIMPLEMENTED"),
            R2ILOp::CpuId { dst } => write!(f, "{} = CPUID", dst),
            R2ILOp::Breakpoint => write!(f, "BREAKPOINT"),
            R2ILOp::Multiequal { dst, inputs } => {
                write!(f, "{} = PHI(", dst)?;
                for (i, inp) in inputs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", inp)?;
                }
                write!(f, ")")
            }
            R2ILOp::Indirect { dst, src, indirect } => {
                write!(f, "{} = INDIRECT({}, {})", dst, src, indirect)
            }
            R2ILOp::PtrAdd {
                dst,
                base,
                index,
                element_size,
            } => {
                write!(f, "{} = PTRADD({}, {}, {})", dst, base, index, element_size)
            }
            R2ILOp::PtrSub {
                dst,
                base,
                index,
                element_size,
            } => {
                write!(f, "{} = PTRSUB({}, {}, {})", dst, base, index, element_size)
            }
            R2ILOp::SegmentOp {
                dst,
                segment,
                offset,
            } => {
                write!(f, "{} = SEGMENT({}, {})", dst, segment, offset)
            }
            R2ILOp::New { dst, src } => write!(f, "{} = NEW({})", dst, src),
            R2ILOp::Cast { dst, src } => write!(f, "{} = CAST({})", dst, src),
            R2ILOp::Extract { dst, src, position } => {
                write!(f, "{} = EXTRACT({}, {})", dst, src, position)
            }
            R2ILOp::Insert {
                dst,
                src,
                value,
                position,
            } => {
                write!(f, "{} = INSERT({}, {}, {})", dst, src, value, position)
            }
            R2ILOp::Select {
                dst,
                cond,
                if_true,
                if_false,
            } => write!(f, "{} = SELECT({}, {}, {})", dst, cond, if_true, if_false),
        }
    }
}

/// Information about a switch case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCase {
    /// The case value.
    pub value: u64,
    /// The target address for this case.
    pub target: u64,
}

/// The table a dispatch goes through, as the engine derived it.
///
/// One owner: `r2sleigh-lift` builds this from the selector's own value range
/// and the table the engine read, and nothing imports it from another tool.
/// The case values bound themselves, so no range is carried beside them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchInfo {
    /// Address of the switch instruction.
    pub switch_addr: u64,
    /// Default case target (if any).
    pub default_target: Option<u64>,
    /// All switch cases.
    pub cases: Vec<SwitchCase>,
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
    /// Switch table information (if this block contains a switch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_info: Option<SwitchInfo>,
    /// Optional metadata for ops, keyed by operation index.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub op_metadata: BTreeMap<usize, OpMetadata>,
    /// The instruction each operation was lifted from, where a join or a stamp said.
    #[serde(default, skip_serializing_if = "InstructionRuns::is_empty")]
    pub instructions: InstructionRuns,
}

/// Whether these operations leave the return address in `link`.
///
/// A machine with no indirect call instruction spells one by writing the
/// address after the transfer into the link register and then branching:
/// ARM's `mov lr, pc; sub pc, r3, 0x3f` is a call to whatever `r3 - 0x3f`
/// names, returning to the instruction after it. Sleigh lifts the branch as a
/// branch, because that is what the opcode is; what makes it a call is the
/// register the convention names for the return address holding the address
/// control comes back to.
///
/// Only the constants the lift itself produces are folded -- a copy, and an
/// addition or subtraction of two constants, which is how a program counter
/// read becomes a literal. Anything else is not recognised here.
pub fn returns_to(ops: &[R2ILOp], next: u64, link: &Varnode) -> bool {
    return_addresses(ops, link).any(|address| address == next)
}

/// Every constant these operations leave in `link`, folded as [`returns_to`] folds them.
pub fn return_addresses<'a>(
    ops: &'a [R2ILOp],
    link: &'a Varnode,
) -> impl Iterator<Item = u64> + 'a {
    let same =
        |a: &Varnode, b: &Varnode| a.space == b.space && a.offset == b.offset && a.size == b.size;
    let literal = |vn: &Varnode| (vn.space == SpaceId::Const).then_some(vn.offset);
    ops.iter().filter_map(move |op| match op {
        R2ILOp::Copy { dst, src } if same(dst, link) => literal(src),
        R2ILOp::IntAdd { dst, a, b } if same(dst, link) => {
            Some(literal(a)?.wrapping_add(literal(b)?))
        }
        R2ILOp::IntSub { dst, a, b } if same(dst, link) => {
            Some(literal(a)?.wrapping_sub(literal(b)?))
        }
        _ => None,
    })
}

/// The transfer an instruction performs only when its predicate holds.
///
/// `ops` are the operations a predicate skips over. A transfer among them is
/// the instruction's own -- ARM's `bxeq lr` returns, `beq` branches -- and it
/// runs on one arm of the predicate only.
///
/// A call is not one. A predicated call reaches the next instruction either
/// way, so its predicate guards an effect rather than an edge, and nothing
/// downstream renders that guard yet.
pub fn guarded_transfer(ops: &[R2ILOp]) -> Option<&R2ILOp> {
    ops.iter().find(|op| {
        matches!(
            op,
            R2ILOp::Return { .. } | R2ILOp::Branch { .. } | R2ILOp::BranchInd { .. }
        )
    })
}

/// The transfer these block operations perform only when a predicate holds.
///
/// A predicated instruction is lifted as a conditional branch over the
/// instruction's own operations, targeting the instruction after it. That skip
/// is one of the block's two machine edges and the transfer it guards is the
/// other, so every derivation of where the block goes has to read the same
/// pair. They ask here.
pub fn predicated_transfer(ops: &[R2ILOp], next: u64) -> Option<&R2ILOp> {
    guarded_transfer(predicated(ops, next)?)
}

/// Whether these operations call only when a predicate holds, so control reaches `next` whatever the callee does.
pub fn predicated_call(ops: &[R2ILOp], next: u64) -> bool {
    predicated(ops, next).is_some_and(|guarded| guarded.iter().any(R2ILOp::is_call))
}

/// The operations a predicate skips by branching to `next`.
fn predicated(ops: &[R2ILOp], next: u64) -> Option<&[R2ILOp]> {
    let skip = ops.iter().position(|op| match op {
        R2ILOp::CBranch { target, .. } => {
            matches!(target.space, SpaceId::Const | SpaceId::Ram) && target.offset == next
        }
        _ => false,
    })?;
    Some(&ops[skip + 1..])
}

impl R2ILBlock {
    /// Create a new empty block.
    pub fn new(addr: u64, size: u32) -> Self {
        Self {
            addr,
            size,
            ops: Vec::new(),
            switch_info: None,
            op_metadata: BTreeMap::new(),
            instructions: InstructionRuns::default(),
        }
    }

    /// Add an operation to this block.
    pub fn push(&mut self, op: R2ILOp) {
        self.ops.push(op);
    }

    /// Add an operation and optional metadata to this block.
    pub fn push_with_metadata(&mut self, op: R2ILOp, meta: Option<OpMetadata>) {
        let idx = self.ops.len();
        self.ops.push(op);
        if let Some(meta) = meta {
            self.op_metadata.insert(idx, meta);
        }
    }

    /// Add an operation lifted from the instruction at `instruction`.
    pub fn push_from(&mut self, op: R2ILOp, instruction: u64) {
        self.instructions.stamp(self.ops.len(), instruction);
        self.ops.push(op);
    }

    /// Record the native instruction the operation at `op_index` was lifted from.
    pub fn stamp_instruction(&mut self, op_index: usize, instruction_addr: u64) {
        self.instructions.stamp(op_index, instruction_addr);
    }

    /// The native instruction the operation at `op_index` was lifted from.
    pub fn instruction_of(&self, op_index: usize) -> Option<u64> {
        self.instructions.of(op_index)
    }

    /// Set metadata for an operation index.
    pub fn set_op_metadata(&mut self, op_index: usize, meta: OpMetadata) {
        self.op_metadata.insert(op_index, meta);
    }

    /// Get metadata for an operation index.
    pub fn op_metadata(&self, op_index: usize) -> Option<&OpMetadata> {
        self.op_metadata.get(&op_index)
    }

    /// Set the switch info for this block.
    pub fn set_switch_info(&mut self, info: SwitchInfo) {
        self.switch_info = Some(info);
    }

    /// One block from the instructions it runs, in order.
    ///
    /// Each part is a single instruction's lift and keeps its own address on
    /// every operation it contributed, which is what lets a consumer say which
    /// instruction an operation came from after the parts are one sequence.
    pub fn join(addr: u64, size: u32, parts: impl IntoIterator<Item = Self>) -> Self {
        let mut joined = Self::new(addr, size);
        for part in parts {
            let base = joined.ops.len();
            joined.instructions.push(base, part.ops.len(), part.addr);
            joined.ops.extend(part.ops);
            for (index, meta) in part.op_metadata {
                joined.set_op_metadata(base + index, meta);
            }
        }
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block transfer reads and writes where its kind says, at the first element of each pointer.
    #[test]
    fn a_block_transfer_accesses_memory_as_its_kind_states() {
        use crate::eval::AccessKind::{Read, Write};
        let pointer = |offset| Varnode::register(offset, 8);
        for (kind, expected) in [
            (BlockTransferKind::Move, vec![(Read, 8), (Write, 0)]),
            (BlockTransferKind::Fill, vec![(Write, 0)]),
            (BlockTransferKind::Scan(BlockStop::Equal), vec![(Read, 0)]),
            (
                BlockTransferKind::Compare(BlockStop::Unequal),
                vec![(Read, 8), (Read, 0)],
            ),
        ] {
            let op = R2ILOp::BlockTransfer(Box::new(BlockTransfer {
                space: SpaceId::Ram,
                kind,
                destination: pointer(0),
                source: pointer(8),
                count: pointer(16),
                direction: Varnode::constant(0, 1),
                element_size: 4,
                answer: None,
            }));
            let accesses = op.memory_accesses().collect::<Vec<_>>();
            let got = (accesses.iter())
                .map(|access| (access.kind, access.addr.offset))
                .collect::<Vec<_>>();
            assert_eq!(got, expected, "{kind:?}");
            assert!(
                accesses
                    .iter()
                    .all(|access| access.repeated && access.size == 4)
            );
            assert_eq!(op.is_memory_read(), kind.reads_memory(), "{kind:?}");
            assert_eq!(op.is_memory_write(), kind.writes_memory(), "{kind:?}");
        }
    }

    /// A division can be undefined where its guard would have skipped it, so it is never hoisted.
    #[test]
    fn integer_division_is_not_speculatable() {
        let (dst, a, b) = (
            Varnode::register(0, 8),
            Varnode::register(8, 8),
            Varnode::register(16, 8),
        );
        let divisions = [
            R2ILOp::IntDiv {
                dst: dst.clone(),
                a: a.clone(),
                b: b.clone(),
            },
            R2ILOp::IntSDiv {
                dst: dst.clone(),
                a: a.clone(),
                b: b.clone(),
            },
            R2ILOp::IntRem {
                dst: dst.clone(),
                a: a.clone(),
                b: b.clone(),
            },
            R2ILOp::IntSRem {
                dst: dst.clone(),
                a: a.clone(),
                b: b.clone(),
            },
        ];
        for op in divisions {
            assert!(!op.is_speculatable_value(), "{op:?}");
        }
        assert!(R2ILOp::IntMult { dst, a, b }.is_speculatable_value());
    }

    /// Every transfer the lift spells, and one data operation beside them.
    fn ops() -> Vec<R2ILOp> {
        let (to, held, cond) = (
            Varnode::ram(0x1000, 8),
            Varnode::register(0, 8),
            Varnode::register(0x200, 1),
        );
        vec![
            R2ILOp::Branch { target: to.clone() },
            R2ILOp::CBranch {
                target: to.clone(),
                cond,
            },
            R2ILOp::Call { target: to.clone() },
            R2ILOp::BranchInd {
                target: held.clone(),
            },
            R2ILOp::CallInd {
                target: held.clone(),
            },
            R2ILOp::Return {
                target: held.clone(),
            },
            R2ILOp::Load {
                dst: held,
                space: SpaceId::Ram,
                addr: to,
            },
        ]
    }

    #[test]
    fn a_transfer_names_where_control_goes_and_every_other_input_is_data() {
        let said = ops()
            .iter()
            .map(|op| {
                let transfer = op
                    .transfer()
                    .map(|one| (one.target.offset, one.direct, one.call));
                let data = op.data_inputs().iter().map(|input| input.offset).collect();
                (transfer, data)
            })
            .collect::<Vec<(_, Vec<u64>)>>();
        assert_eq!(
            said,
            [
                (Some((0x1000, true, false)), vec![]),
                // The condition decides whether it goes; it is read, not executed.
                (Some((0x1000, true, false)), vec![0x200]),
                (Some((0x1000, true, true)), vec![]),
                (Some((0, false, false)), vec![]),
                (Some((0, false, true)), vec![]),
                // A return names no place of its own, and what it goes back to is still not data.
                (None, vec![]),
                (None, vec![0x1000]),
            ]
        );
    }

    /// A local label is signed at the target's width, and a branch names no label of another kind.
    #[test]
    fn a_local_label_is_signed_at_its_targets_width() {
        for (size, offset) in [(1, -3), (4, -1), (4, 7), (8, -2), (2, 100)] {
            let mut branch = R2ILOp::CBranch {
                target: Varnode::constant(0, size),
                cond: Varnode::register(0, 1),
            };
            branch.set_local_offset(offset);
            assert_eq!(branch.local_offset(), Some(offset), "{size}");
        }
        let wrapped = R2ILOp::Branch {
            target: Varnode::constant(0xff, 1),
        };
        assert_eq!(wrapped.local_offset(), Some(-1));
        for other in [
            R2ILOp::Branch {
                target: Varnode::ram(0x1000, 8),
            },
            R2ILOp::Call {
                target: Varnode::constant(1, 4),
            },
            R2ILOp::Nop,
        ] {
            let mut same = other.clone();
            same.set_local_offset(5);
            assert_eq!((other.local_offset(), same), (None, other));
        }
    }
}
