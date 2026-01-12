//! SSA operation definitions.
//!
//! These mirror r2il::R2ILOp but use SSAVar instead of Varnode,
//! providing versioned variables for dataflow analysis.

use serde::{Deserialize, Serialize};

use crate::var::SSAVar;

/// An SSA operation representing a single semantic action with versioned variables.
///
/// Each operation uses SSAVar which includes version numbers, enabling
/// precise tracking of definitions and uses for dataflow analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SSAOp {
    // ========== SSA-specific Operations ==========
    /// Phi function: merges values from different control flow paths.
    /// dst = phi(sources[0], sources[1], ...)
    Phi {
        dst: SSAVar,
        sources: Vec<SSAVar>,
    },

    // ========== Data Movement ==========
    /// Copy src to dst: dst = src
    Copy {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Load from memory: dst = *[space]addr
    Load {
        dst: SSAVar,
        space: String,
        addr: SSAVar,
    },

    /// Store to memory: *[space]addr = val
    Store {
        space: String,
        addr: SSAVar,
        val: SSAVar,
    },

    // ========== Integer Arithmetic ==========
    /// Integer addition: dst = a + b
    IntAdd {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Integer subtraction: dst = a - b
    IntSub {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Integer multiplication: dst = a * b
    IntMult {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Unsigned integer division: dst = a / b
    IntDiv {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed integer division: dst = a / b (signed)
    IntSDiv {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Unsigned integer remainder: dst = a % b
    IntRem {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed integer remainder: dst = a % b (signed)
    IntSRem {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Two's complement negation: dst = -src
    IntNegate {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Addition with carry: dst = a + b + carry
    IntCarry {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed carry (overflow): dst = overflow(a + b)
    IntSCarry {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed borrow: dst = borrow(a - b)
    IntSBorrow {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    // ========== Logical Operations ==========
    /// Bitwise AND: dst = a & b
    IntAnd {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Bitwise OR: dst = a | b
    IntOr {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Bitwise XOR: dst = a ^ b
    IntXor {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Bitwise NOT: dst = ~src
    IntNot {
        dst: SSAVar,
        src: SSAVar,
    },

    // ========== Shift Operations ==========
    /// Left shift: dst = a << b
    IntLeft {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Logical right shift: dst = a >> b (unsigned)
    IntRight {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Arithmetic right shift: dst = a >> b (signed)
    IntSRight {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    // ========== Comparison Operations ==========
    /// Equality: dst = (a == b) ? 1 : 0
    IntEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Inequality: dst = (a != b) ? 1 : 0
    IntNotEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Unsigned less than: dst = (a < b) ? 1 : 0
    IntLess {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed less than: dst = (a < b) ? 1 : 0 (signed)
    IntSLess {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Unsigned less or equal: dst = (a <= b) ? 1 : 0
    IntLessEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Signed less or equal: dst = (a <= b) ? 1 : 0 (signed)
    IntSLessEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    // ========== Extension Operations ==========
    /// Zero extension: dst = zext(src)
    IntZExt {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Sign extension: dst = sext(src)
    IntSExt {
        dst: SSAVar,
        src: SSAVar,
    },

    // ========== Boolean Operations ==========
    /// Boolean NOT: dst = !src
    BoolNot {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Boolean AND: dst = a && b
    BoolAnd {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Boolean OR: dst = a || b
    BoolOr {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Boolean XOR: dst = a ^^ b
    BoolXor {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    // ========== Bit Manipulation ==========
    /// Concatenate two values: dst = (hi << lo.size*8) | lo
    Piece {
        dst: SSAVar,
        hi: SSAVar,
        lo: SSAVar,
    },

    /// Extract a portion of a value: dst = src[offset:size]
    Subpiece {
        dst: SSAVar,
        src: SSAVar,
        offset: u32,
    },

    /// Population count (number of 1 bits): dst = popcount(src)
    PopCount {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Count leading zeros: dst = clz(src)
    Lzcount {
        dst: SSAVar,
        src: SSAVar,
    },

    // ========== Control Flow ==========
    /// Unconditional branch to target
    Branch {
        target: SSAVar,
    },

    /// Conditional branch: if (cond) goto target
    CBranch {
        target: SSAVar,
        cond: SSAVar,
    },

    /// Indirect branch: goto *target
    BranchInd {
        target: SSAVar,
    },

    /// Call a subroutine
    Call {
        target: SSAVar,
    },

    /// Indirect call: call *target
    CallInd {
        target: SSAVar,
    },

    /// Return from subroutine
    Return {
        target: SSAVar,
    },

    // ========== Floating Point ==========
    /// Float addition: dst = a + b
    FloatAdd {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float subtraction: dst = a - b
    FloatSub {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float multiplication: dst = a * b
    FloatMult {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float division: dst = a / b
    FloatDiv {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float negation: dst = -src
    FloatNeg {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float absolute value: dst = |src|
    FloatAbs {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float square root: dst = sqrt(src)
    FloatSqrt {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float ceiling: dst = ceil(src)
    FloatCeil {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float floor: dst = floor(src)
    FloatFloor {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float round: dst = round(src)
    FloatRound {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float is NaN: dst = isnan(src)
    FloatNaN {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Float equality: dst = (a == b) ? 1 : 0
    FloatEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float not equal: dst = (a != b) ? 1 : 0
    FloatNotEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float less than: dst = (a < b) ? 1 : 0
    FloatLess {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Float less or equal: dst = (a <= b) ? 1 : 0
    FloatLessEqual {
        dst: SSAVar,
        a: SSAVar,
        b: SSAVar,
    },

    /// Convert int to float: dst = (float)src
    Int2Float {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Convert float to int: dst = (int)src
    Float2Int {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Convert float to different size float: dst = (float_new_size)src
    FloatFloat {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Truncate float to int: dst = trunc(src)
    Trunc {
        dst: SSAVar,
        src: SSAVar,
    },

    // ========== Special Operations ==========
    /// Call a user-defined operation (CALLOTHER in P-code)
    CallOther {
        /// Optional output varnode
        output: Option<SSAVar>,
        /// User-defined operation index
        userop: u32,
        /// Input arguments
        inputs: Vec<SSAVar>,
    },

    /// No operation (placeholder)
    Nop,

    /// Unimplemented instruction
    Unimplemented,

    /// CPU identification (CPUID-like)
    CpuId {
        dst: SSAVar,
    },

    /// Insert a breakpoint
    Breakpoint,

    /// Pointer addition: dst = base + (index * element_size)
    PtrAdd {
        dst: SSAVar,
        base: SSAVar,
        index: SSAVar,
        element_size: u32,
    },

    /// Pointer subtraction: dst = base - (index * element_size)
    PtrSub {
        dst: SSAVar,
        base: SSAVar,
        index: SSAVar,
        element_size: u32,
    },

    /// Segment calculation: dst = segment:offset
    SegmentOp {
        dst: SSAVar,
        segment: SSAVar,
        offset: SSAVar,
    },

    /// New (allocation, used in high-level analysis)
    New {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Cast (type cast, used in high-level analysis)
    Cast {
        dst: SSAVar,
        src: SSAVar,
    },

    /// Extract (bit field extraction)
    Extract {
        dst: SSAVar,
        src: SSAVar,
        position: SSAVar,
    },

    /// Insert (bit field insertion)
    Insert {
        dst: SSAVar,
        src: SSAVar,
        value: SSAVar,
        position: SSAVar,
    },
}

impl SSAOp {
    /// Get the destination variable if this operation has one.
    pub fn dst(&self) -> Option<&SSAVar> {
        use SSAOp::*;
        match self {
            Phi { dst, .. }
            | Copy { dst, .. }
            | Load { dst, .. }
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
            | Insert { dst, .. } => Some(dst),

            CallOther { output, .. } => output.as_ref(),

            Store { .. }
            | Branch { .. }
            | CBranch { .. }
            | BranchInd { .. }
            | Call { .. }
            | CallInd { .. }
            | Return { .. }
            | Nop
            | Unimplemented
            | Breakpoint => None,
        }
    }

    /// Get all source variables used by this operation.
    pub fn sources(&self) -> Vec<&SSAVar> {
        use SSAOp::*;
        match self {
            Phi { sources, .. } => sources.iter().collect(),

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
            | Cast { src, .. } => vec![src],

            Load { addr, .. } => vec![addr],

            Store { addr, val, .. } => vec![addr, val],

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
            | FloatLessEqual { a, b, .. } => vec![a, b],

            Piece { hi, lo, .. } => vec![hi, lo],

            Extract { src, position, .. } => vec![src, position],

            Insert {
                src,
                value,
                position,
                ..
            } => vec![src, value, position],

            PtrAdd { base, index, .. } | PtrSub { base, index, .. } => vec![base, index],

            SegmentOp {
                segment, offset, ..
            } => vec![segment, offset],

            Branch { target } | BranchInd { target } | Call { target } | CallInd { target } | Return { target } => {
                vec![target]
            }

            CBranch { target, cond } => vec![target, cond],

            CallOther { inputs, .. } => inputs.iter().collect(),

            Nop | Unimplemented | Breakpoint | CpuId { .. } => vec![],
        }
    }

    /// Returns true if this operation is a control flow operation.
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            SSAOp::Branch { .. }
                | SSAOp::CBranch { .. }
                | SSAOp::BranchInd { .. }
                | SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::Return { .. }
        )
    }

    /// Returns true if this operation reads from memory.
    pub fn is_memory_read(&self) -> bool {
        matches!(self, SSAOp::Load { .. })
    }

    /// Returns true if this operation writes to memory.
    pub fn is_memory_write(&self) -> bool {
        matches!(self, SSAOp::Store { .. })
    }

    /// Returns true if this is a phi node.
    pub fn is_phi(&self) -> bool {
        matches!(self, SSAOp::Phi { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dst_extraction() {
        let dst = SSAVar::new("RAX", 1, 8);
        let src = SSAVar::new("RBX", 0, 8);

        let op = SSAOp::Copy {
            dst: dst.clone(),
            src,
        };
        assert_eq!(op.dst(), Some(&dst));

        let op = SSAOp::Nop;
        assert_eq!(op.dst(), None);
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
}
