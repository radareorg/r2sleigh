//! Lowering of the operations that take part in a carrier wider than any C
//! integer.
//!
//! Such a carrier is a `struct r2sleigh_bits_N`, which `crate::bitvector`
//! defines and gives no operators. It is assigned and chosen whole like any
//! struct, and every other operation on one -- taking a field out, putting one
//! in, composing two pieces, zero-extending into one -- is a call to the helper
//! that performs it. An operation none of those spells is refused here rather
//! than written as a C operator on a struct, which would not compile.

use super::*;
use crate::bitvector::{BitVectorHelper, is_wide};

/// Whether a value this many bytes wide is a carrier with no C integer.
fn wide_bytes(size: u32) -> bool {
    is_wide(size.saturating_mul(8))
}

/// Whether an operation would spell a C operator on a wide carrier.
///
/// Assigning and choosing a carrier whole needs no operator, and taking one
/// apart, composing one and zero-extending into one each have a helper;
/// every other value operation reading or writing one has no C spelling.
pub(super) fn applies_an_operator_to_a_carrier(op: &SSAOp) -> bool {
    use r2il::eval::Operation;
    let Some(operation) = op.operation() else {
        return false;
    };
    !matches!(
        operation,
        Operation::Copy
            | Operation::Select
            | Operation::Subpiece { .. }
            | Operation::Piece
            | Operation::ZExt
    ) && (op.dst().is_some_and(|var| wide_bytes(var.size)) || {
        let mut reads_a_carrier = false;
        op.for_each_source(|var| reads_a_carrier |= wide_bytes(var.size));
        reads_a_carrier
    })
}

/// Whether a width change involves a wide carrier, and so is spelled by
/// [`FoldingContext::wide_width_change_stmt`].
pub(super) fn width_change_is_wide(dst: &SSAVar, src: &SSAVar) -> bool {
    wide_bytes(dst.size) || wide_bytes(src.size)
}

impl FoldingContext<'_> {
    /// `dst = hi:lo` into a wide carrier: the low piece zero-extended to the
    /// whole, and the high one inserted above it.
    pub(super) fn wide_piece_stmt(
        &self,
        frame: &LowerFrame,
        dst: &SSAVar,
        hi: &SSAVar,
        lo: &SSAVar,
    ) -> OpLoweringResult<Option<CStmt>> {
        let width = dst.size.saturating_mul(8);
        let low_width = lo.size.saturating_mul(8);
        let zero_extend = BitVectorHelper::zero_extend(low_width, width)
            .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        let insert = BitVectorHelper::insert(width, hi.size.saturating_mul(8))
            .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        let lhs = self.assignment_lhs_expr(dst)?;
        let hi = self.required_input(frame, 0, hi, Some(&uint_type_from_size(hi.size)))?;
        let lo = self.required_input(frame, 1, lo, Some(&uint_type_from_size(lo.size)))?;
        let rhs = insert.call(vec![
            zero_extend.call(vec![lo]),
            hi,
            CExpr::UIntLit(u64::from(low_width)),
        ]);
        Ok(self.assign_stmt(lhs, rhs))
    }

    /// `dst = src[offset..]` out of a wide carrier.
    pub(super) fn wide_subpiece_stmt(
        &self,
        frame: &LowerFrame,
        dst: &SSAVar,
        src: &SSAVar,
        offset: u32,
    ) -> OpLoweringResult<Option<CStmt>> {
        let extract =
            BitVectorHelper::extract(src.size.saturating_mul(8), dst.size.saturating_mul(8))
                .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        let lhs = self.assignment_lhs_expr(dst)?;
        let src_expr = self.required_input(frame, 0, src, Some(&uint_type_from_size(src.size)))?;
        let rhs = extract.call(vec![src_expr, CExpr::UIntLit(u64::from(offset) * 8)]);
        Ok(self.assign_stmt(lhs, rhs))
    }

    /// A width change into or out of a wide carrier. Only a zero extension
    /// into one has a spelling; no cast converts to or from a struct.
    pub(super) fn wide_width_change_stmt(
        &self,
        frame: &LowerFrame,
        op: &SSAOp,
        dst: &SSAVar,
        src: &SSAVar,
    ) -> OpLoweringResult<Option<CStmt>> {
        let zero_extend = matches!(op, SSAOp::IntZExt { .. })
            .then(|| {
                BitVectorHelper::zero_extend(src.size.saturating_mul(8), dst.size.saturating_mul(8))
            })
            .flatten()
            .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        let lhs = self.assignment_lhs_expr(dst)?;
        let operand = self.required_input(frame, 0, src, Some(&uint_type_from_size(src.size)))?;
        Ok(self.assign_stmt(lhs, zero_extend.call(vec![operand])))
    }

    /// `lhs = root` with the lane in place, into a wide root. `operands` are
    /// the insertion's three, rendered in order: the root, the lane, and the
    /// position as the shift count.
    ///
    /// A bit vector has no literal, so a zero root is spelled as the zero
    /// extension of a zero lane -- or, for a lane that is itself a vector, of
    /// a zero word; at position zero that extension is the whole write.
    pub(super) fn wide_insert_stmt(
        &self,
        insert: &r2ssa::InsertOp,
        lsb_bits: u64,
        lhs: CExpr,
        operands: [CExpr; 3],
    ) -> OpLoweringResult<Option<CStmt>> {
        let [root, lane, shift] = operands;
        let root_width = insert.dst.size.saturating_mul(8);
        let lane_width = insert.value.size.saturating_mul(8);
        let insert_lane = BitVectorHelper::insert(root_width, lane_width)
            .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        let zero_extend = BitVectorHelper::zero_extend(lane_width, root_width)
            .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?;
        if insert.src.constant_bits() != Some(0) {
            return Ok(self.assign_stmt(lhs, insert_lane.call(vec![root, lane, shift])));
        }
        if lsb_bits == 0 {
            return Ok(self.assign_stmt(lhs, zero_extend.call(vec![lane])));
        }
        let zero = if is_wide(lane_width) {
            BitVectorHelper::zero_extend(64, root_width)
                .ok_or_else(OpLoweringRefusal::unrepresentable_operation)?
                .call(vec![CExpr::UIntLit(0)])
        } else {
            zero_extend.call(vec![CExpr::cast(
                uint_type_from_size(insert.value.size),
                CExpr::UIntLit(0),
            )])
        };
        Ok(self.assign_stmt(lhs, insert_lane.call(vec![zero, lane, shift])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No operation on a carrier wider than any C integer is spelled unless a
    /// helper performs it: an operator, a sign extension, a cast either way,
    /// and a zero extension from a width no helper takes are each refused
    /// before anything is written, and none reaches C as an operator on a
    /// struct. The same operator on C integers is left to the ordinary
    /// lowering.
    #[test]
    fn a_wide_operation_without_a_helper_is_refused() {
        let ctx = FoldingContext::new(64);
        let frame = LowerFrame::for_expr();
        let wide = |version| SSAVar::new("YMM0", version, 32);
        let xmm = SSAVar::new("XMM0", 0, 16);

        let narrow = SSAOp::IntXor {
            dst: SSAVar::new("RAX", 1, 8),
            a: SSAVar::new("RAX", 0, 8),
            b: SSAVar::new("RDX", 0, 8),
        };
        assert!(!applies_an_operator_to_a_carrier(&narrow));

        let refused = [
            (
                SSAOp::IntXor {
                    dst: wide(3),
                    a: wide(1),
                    b: wide(2),
                },
                "an exclusive or of two carriers",
            ),
            (
                SSAOp::IntEqual {
                    dst: SSAVar::new("ZF", 1, 1),
                    a: wide(1),
                    b: wide(2),
                },
                "a comparison that only reads carriers",
            ),
            (
                SSAOp::IntSExt {
                    dst: wide(1),
                    src: xmm.clone(),
                },
                "a sign extension into a carrier",
            ),
            (
                SSAOp::Cast {
                    dst: wide(1),
                    src: xmm.clone(),
                },
                "a cast into a carrier",
            ),
            (
                SSAOp::Cast {
                    dst: xmm,
                    src: wide(1),
                },
                "a cast out of a carrier",
            ),
            (
                SSAOp::IntZExt {
                    dst: wide(1),
                    src: SSAVar::new("tmp", 0, 3),
                },
                "a zero extension from a width no helper takes",
            ),
        ];
        for (op, why) in refused {
            assert_eq!(
                ctx.op_to_stmt_impl(&op, &frame),
                Err(OpLoweringRefusal::unrepresentable_operation()),
                "{why}"
            );
        }
    }
}
