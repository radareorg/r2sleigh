//! P-code as text, with register names resolved.

use crate::disasm::Disassembler;
use r2il::R2ILOp;

/// Format an R2ILOp with resolved register names.
///
/// This function provides human-readable formatting of r2il operations
/// with register names resolved from the Sleigh specification.
pub fn format_op(disasm: &Disassembler, op: &R2ILOp) -> String {
    use r2il::R2ILOp::*;

    // Helper closure for formatting varnodes
    let vn = |v: &r2il::Varnode| disasm.format_varnode(v);

    match op {
        // Data movement
        Copy { dst, src } => format!("Copy {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        Load { dst, space, addr } => {
            format!(
                "Load {{ dst: {}, space: {:?}, addr: {} }}",
                vn(dst),
                space,
                vn(addr)
            )
        }
        BlockTransfer(transfer) => format!(
            "BlockTransfer {{ kind: {:?}, destination: {}, source: {}, count: {}, element_size: {}, answer: {} }}",
            transfer.kind,
            vn(&transfer.destination),
            vn(&transfer.source),
            vn(&transfer.count),
            transfer.element_size,
            transfer.answer.as_ref().map_or_else(|| "-".to_string(), vn)
        ),
        Store { space, addr, val } => {
            format!(
                "Store {{ space: {:?}, addr: {}, val: {} }}",
                space,
                vn(addr),
                vn(val)
            )
        }
        Fence { ordering } => format!("Fence {{ ordering: {:?} }}", ordering),
        LoadLinked {
            dst,
            space,
            addr,
            ordering,
        } => {
            format!(
                "LoadLinked {{ dst: {}, space: {:?}, addr: {}, ordering: {:?} }}",
                vn(dst),
                space,
                vn(addr),
                ordering
            )
        }
        StoreConditional {
            result,
            space,
            addr,
            val,
            ordering,
        } => {
            let result_str = result
                .as_ref()
                .map(&vn)
                .unwrap_or_else(|| "none".to_string());
            format!(
                "StoreConditional {{ result: {}, space: {:?}, addr: {}, val: {}, ordering: {:?} }}",
                result_str,
                space,
                vn(addr),
                vn(val),
                ordering
            )
        }
        AtomicCAS {
            dst,
            space,
            addr,
            expected,
            replacement,
            ordering,
        } => {
            format!(
                "AtomicCAS {{ dst: {}, space: {:?}, addr: {}, expected: {}, replacement: {}, ordering: {:?} }}",
                vn(dst),
                space,
                vn(addr),
                vn(expected),
                vn(replacement),
                ordering
            )
        }
        LoadGuarded {
            dst,
            space,
            addr,
            guard,
            ordering,
        } => {
            format!(
                "LoadGuarded {{ dst: {}, space: {:?}, addr: {}, guard: {}, ordering: {:?} }}",
                vn(dst),
                space,
                vn(addr),
                vn(guard),
                ordering
            )
        }
        StoreGuarded {
            space,
            addr,
            val,
            guard,
            ordering,
        } => {
            format!(
                "StoreGuarded {{ space: {:?}, addr: {}, val: {}, guard: {}, ordering: {:?} }}",
                space,
                vn(addr),
                vn(val),
                vn(guard),
                ordering
            )
        }

        // Integer arithmetic
        IntAdd { dst, a, b } => {
            format!("IntAdd {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntSub { dst, a, b } => {
            format!("IntSub {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntMult { dst, a, b } => {
            format!("IntMult {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntDiv { dst, a, b } => {
            format!("IntDiv {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntSDiv { dst, a, b } => {
            format!("IntSDiv {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntRem { dst, a, b } => {
            format!("IntRem {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntSRem { dst, a, b } => {
            format!("IntSRem {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntNegate { dst, src } => format!("IntNegate {{ dst: {}, src: {} }}", vn(dst), vn(src)),

        // Bitwise operations
        IntAnd { dst, a, b } => {
            format!("IntAnd {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntOr { dst, a, b } => format!("IntOr {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b)),
        IntXor { dst, a, b } => {
            format!("IntXor {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntNot { dst, src } => format!("IntNot {{ dst: {}, src: {} }}", vn(dst), vn(src)),

        // Shift operations
        IntLeft { dst, a, b } => {
            format!("IntLeft {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntRight { dst, a, b } => format!(
            "IntRight {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntSRight { dst, a, b } => format!(
            "IntSRight {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),

        // Comparison operations
        IntEqual { dst, a, b } => format!(
            "IntEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntNotEqual { dst, a, b } => format!(
            "IntNotEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntLess { dst, a, b } => {
            format!("IntLess {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        IntSLess { dst, a, b } => format!(
            "IntSLess {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntLessEqual { dst, a, b } => format!(
            "IntLessEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntSLessEqual { dst, a, b } => format!(
            "IntSLessEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),

        // Carry/borrow
        IntCarry { dst, a, b } => format!(
            "IntCarry {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntSCarry { dst, a, b } => format!(
            "IntSCarry {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        IntSBorrow { dst, a, b } => format!(
            "IntSBorrow {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),

        // Extension
        IntZExt { dst, src } => format!("IntZExt {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        IntSExt { dst, src } => format!("IntSExt {{ dst: {}, src: {} }}", vn(dst), vn(src)),

        // Boolean operations
        BoolNot { dst, src } => format!("BoolNot {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        BoolAnd { dst, a, b } => {
            format!("BoolAnd {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        BoolOr { dst, a, b } => {
            format!("BoolOr {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }
        BoolXor { dst, a, b } => {
            format!("BoolXor {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b))
        }

        // Bit manipulation
        Piece { dst, hi, lo } => format!(
            "Piece {{ dst: {}, hi: {}, lo: {} }}",
            vn(dst),
            vn(hi),
            vn(lo)
        ),
        Subpiece { dst, src, offset } => format!(
            "Subpiece {{ dst: {}, src: {}, offset: {} }}",
            vn(dst),
            vn(src),
            offset
        ),
        PopCount { dst, src } => format!("PopCount {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        Lzcount { dst, src } => format!("Lzcount {{ dst: {}, src: {} }}", vn(dst), vn(src)),

        // Control flow
        Branch { target } => format!("Branch {{ target: {} }}", vn(target)),
        CBranch { target, cond } => {
            format!("CBranch {{ target: {}, cond: {} }}", vn(target), vn(cond))
        }
        BranchInd { target } => format!("BranchInd {{ target: {} }}", vn(target)),
        Call { target } => format!("Call {{ target: {} }}", vn(target)),
        CallInd { target } => format!("CallInd {{ target: {} }}", vn(target)),
        Return { target } => format!("Return {{ target: {} }}", vn(target)),
        CallOther {
            output,
            userop,
            inputs,
        } => {
            let out_str = output
                .as_ref()
                .map(&vn)
                .unwrap_or_else(|| "none".to_string());
            let in_str: Vec<String> = inputs.iter().map(&vn).collect();
            format!(
                "CallOther {{ output: {}, userop: {}, inputs: [{}] }}",
                out_str,
                userop,
                in_str.join(", ")
            )
        }

        // Floating point
        FloatAdd { dst, a, b } => format!(
            "FloatAdd {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatSub { dst, a, b } => format!(
            "FloatSub {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatMult { dst, a, b } => format!(
            "FloatMult {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatDiv { dst, a, b } => format!(
            "FloatDiv {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatNeg { dst, src } => format!("FloatNeg {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatAbs { dst, src } => format!("FloatAbs {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatSqrt { dst, src } => format!("FloatSqrt {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatCeil { dst, src } => format!("FloatCeil {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatFloor { dst, src } => format!("FloatFloor {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatRound { dst, src } => format!("FloatRound {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatNaN { dst, src } => format!("FloatNaN {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatEqual { dst, a, b } => format!(
            "FloatEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatNotEqual { dst, a, b } => format!(
            "FloatNotEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatLess { dst, a, b } => format!(
            "FloatLess {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        FloatLessEqual { dst, a, b } => format!(
            "FloatLessEqual {{ dst: {}, a: {}, b: {} }}",
            vn(dst),
            vn(a),
            vn(b)
        ),
        Int2Float { dst, src } => format!("Int2Float {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        Float2Int { dst, src } => format!("Float2Int {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        FloatFloat { dst, src } => format!("FloatFloat {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        Trunc { dst, src } => format!("Trunc {{ dst: {}, src: {} }}", vn(dst), vn(src)),

        // Analysis operations
        Multiequal { dst, inputs } => {
            let in_str: Vec<String> = inputs.iter().map(&vn).collect();
            format!(
                "Multiequal {{ dst: {}, inputs: [{}] }}",
                vn(dst),
                in_str.join(", ")
            )
        }
        Indirect { dst, src, indirect } => {
            format!(
                "Indirect {{ dst: {}, src: {}, indirect: {} }}",
                vn(dst),
                vn(src),
                vn(indirect)
            )
        }
        Cast { dst, src } => format!("Cast {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        New { dst, src } => format!("New {{ dst: {}, src: {} }}", vn(dst), vn(src)),
        CpuId { dst } => format!("CpuId {{ dst: {} }}", vn(dst)),

        // Pointer operations
        PtrAdd {
            dst,
            base,
            index,
            element_size,
        } => {
            format!(
                "PtrAdd {{ dst: {}, base: {}, index: {}, element_size: {} }}",
                vn(dst),
                vn(base),
                vn(index),
                element_size
            )
        }
        PtrSub {
            dst,
            base,
            index,
            element_size,
        } => {
            format!(
                "PtrSub {{ dst: {}, base: {}, index: {}, element_size: {} }}",
                vn(dst),
                vn(base),
                vn(index),
                element_size
            )
        }
        SegmentOp {
            dst,
            segment,
            offset,
        } => {
            format!(
                "SegmentOp {{ dst: {}, segment: {}, offset: {} }}",
                vn(dst),
                vn(segment),
                vn(offset)
            )
        }

        // Bit manipulation
        Insert {
            dst,
            src,
            value,
            position,
        } => {
            format!(
                "Insert {{ dst: {}, src: {}, value: {}, position: {} }}",
                vn(dst),
                vn(src),
                vn(value),
                vn(position)
            )
        }
        Extract { dst, src, position } => {
            format!(
                "Extract {{ dst: {}, src: {}, position: {} }}",
                vn(dst),
                vn(src),
                vn(position)
            )
        }
        Select {
            dst,
            cond,
            if_true,
            if_false,
        } => format!(
            "Select {{ dst: {}, cond: {}, if_true: {}, if_false: {} }}",
            vn(dst),
            vn(cond),
            vn(if_true),
            vn(if_false)
        ),

        // Special
        Nop => "Nop".to_string(),
        Unimplemented => "Unimplemented".to_string(),
        Breakpoint => "Breakpoint".to_string(),
    }
}
