//! ESIL formatting helpers shared by the CLI and plugin.

use crate::disasm::Disassembler;
use r2il::R2ILOp;

/// Format an R2ILOp with resolved register names.
pub fn format_op(disasm: &Disassembler, op: &R2ILOp) -> String {
    use r2il::R2ILOp::*;

    match op {
        Copy { dst, src } => format!(
            "Copy {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        Load { dst, space, addr } => format!(
            "Load {{ dst: {}, space: {:?}, addr: {} }}",
            disasm.format_varnode(dst),
            space,
            disasm.format_varnode(addr)
        ),
        Store { space, addr, val } => format!(
            "Store {{ space: {:?}, addr: {}, val: {} }}",
            space,
            disasm.format_varnode(addr),
            disasm.format_varnode(val)
        ),
        IntAdd { dst, a, b } => format!(
            "IntAdd {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSub { dst, a, b } => format!(
            "IntSub {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntAnd { dst, a, b } => format!(
            "IntAnd {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntOr { dst, a, b } => format!(
            "IntOr {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntXor { dst, a, b } => format!(
            "IntXor {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntEqual { dst, a, b } => format!(
            "IntEqual {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSLess { dst, a, b } => format!(
            "IntSLess {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntCarry { dst, a, b } => format!(
            "IntCarry {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSCarry { dst, a, b } => format!(
            "IntSCarry {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntZExt { dst, src } => format!(
            "IntZExt {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        PopCount { dst, src } => format!(
            "PopCount {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        Branch { target } => format!("Branch {{ target: {} }}", disasm.format_varnode(target)),
        CBranch { cond, target } => format!(
            "CBranch {{ cond: {}, target: {} }}",
            disasm.format_varnode(cond),
            disasm.format_varnode(target)
        ),
        Call { target } => format!("Call {{ target: {} }}", disasm.format_varnode(target)),
        Return { target } => format!("Return {{ target: {} }}", disasm.format_varnode(target)),
        _ => format!("{:?}", op),
    }
}

/// Convert an R2ILOp into an ESIL string.
///
/// ESIL (Evaluable Strings Intermediate Language) uses reverse Polish notation:
/// - `a,b,+` = a + b
/// - `a,b,=` = b = a (assignment)
/// - `a,[N]` = read N bytes from address a
/// - `a,b,=[N]` = write N bytes of b to address a
pub fn op_to_esil(disasm: &Disassembler, op: &R2ILOp) -> String {
    use r2il::R2ILOp::*;

    // Helper to format varnode as lowercase ESIL operand
    let vn = |v: &r2il::Varnode| disasm.format_varnode(v).to_lowercase();

    // Helper to get size suffix for memory operations
    let size_suffix = |size: u32| -> String {
        match size {
            1 => "[1]".to_string(),
            2 => "[2]".to_string(),
            4 => "[4]".to_string(),
            8 => "[8]".to_string(),
            _ => format!("[{}]", size),
        }
    };

    match op {
        // ========== Data Movement ==========
        Copy { dst, src } => format!("{},{},=", vn(src), vn(dst)),

        Load { dst, addr, .. } => {
            let sz = size_suffix(dst.size);
            format!("{},{},{},=", vn(addr), sz, vn(dst))
        }

        Store { addr, val, .. } => {
            let sz = size_suffix(val.size);
            format!("{},{},={}", vn(val), vn(addr), sz)
        }

        // ========== Integer Arithmetic ==========
        IntAdd { dst, a, b } => format!("{},{},+,{},=", vn(a), vn(b), vn(dst)),
        IntSub { dst, a, b } => format!("{},{},-,{},=", vn(a), vn(b), vn(dst)),
        IntMult { dst, a, b } => format!("{},{},*,{},=", vn(a), vn(b), vn(dst)),
        IntDiv { dst, a, b } => format!("{},{},/,{},=", vn(a), vn(b), vn(dst)),
        IntSDiv { dst, a, b } => format!("{},{},~/,{},=", vn(a), vn(b), vn(dst)),
        IntRem { dst, a, b } => format!("{},{},%,{},=", vn(a), vn(b), vn(dst)),
        IntSRem { dst, a, b } => format!("{},{},~%,{},=", vn(a), vn(b), vn(dst)),
        IntNegate { dst, src } => format!("{},0,-,{},=", vn(src), vn(dst)),

        // Carry/borrow operations (set flags)
        IntCarry { dst, a, b } => format!("{},{},+,$c,{},=", vn(a), vn(b), vn(dst)),
        IntSCarry { dst, a, b } => format!("{},{},+,$o,{},=", vn(a), vn(b), vn(dst)),
        IntSBorrow { dst, a, b } => format!("{},{},-,$b,{},=", vn(a), vn(b), vn(dst)),

        // ========== Logical Operations ==========
        IntAnd { dst, a, b } => format!("{},{},&,{},=", vn(a), vn(b), vn(dst)),
        IntOr { dst, a, b } => format!("{},{},|,{},=", vn(a), vn(b), vn(dst)),
        IntXor { dst, a, b } => format!("{},{},^,{},=", vn(a), vn(b), vn(dst)),
        IntNot { dst, src } => format!("{},~,{},=", vn(src), vn(dst)),

        // ========== Shift Operations ==========
        IntLeft { dst, a, b } => format!("{},{},<<,{},=", vn(a), vn(b), vn(dst)),
        IntRight { dst, a, b } => format!("{},{},>>,{},=", vn(a), vn(b), vn(dst)),
        IntSRight { dst, a, b } => format!("{},{},>>>,{},=", vn(a), vn(b), vn(dst)),

        // ========== Comparison Operations ==========
        IntEqual { dst, a, b } => format!("{},{},==,{},=", vn(a), vn(b), vn(dst)),
        IntNotEqual { dst, a, b } => format!("{},{},==,!,{},=", vn(a), vn(b), vn(dst)),
        IntLess { dst, a, b } => format!("{},{},<,{},=", vn(a), vn(b), vn(dst)),
        IntSLess { dst, a, b } => format!("{},{},<$,{},=", vn(a), vn(b), vn(dst)),
        IntLessEqual { dst, a, b } => format!("{},{},<=,{},=", vn(a), vn(b), vn(dst)),
        IntSLessEqual { dst, a, b } => format!("{},{},<=$,{},=", vn(a), vn(b), vn(dst)),

        // ========== Extension Operations ==========
        // Zero/sign extension - in ESIL, size is implicit in destination
        IntZExt { dst, src } => format!("{},{},=", vn(src), vn(dst)),
        IntSExt { dst, src } => {
            // Sign extension: use ~~ operator (value,bits,~~)
            let src_bits = src.size * 8;
            format!("{},{},~~,{},=", vn(src), src_bits, vn(dst))
        }

        // ========== Boolean Operations ==========
        BoolNot { dst, src } => format!("{},!,{},=", vn(src), vn(dst)),
        BoolAnd { dst, a, b } => format!("{},{},&&,{},=", vn(a), vn(b), vn(dst)),
        BoolOr { dst, a, b } => format!("{},{},||,{},=", vn(a), vn(b), vn(dst)),
        BoolXor { dst, a, b } => format!("{},{},^^,{},=", vn(a), vn(b), vn(dst)),

        // ========== Bit Manipulation ==========
        Piece { dst, hi, lo } => {
            // Concatenate: dst = (hi << lo.size*8) | lo
            let shift = lo.size * 8;
            format!("{},{},<<,{},|,{},=", vn(hi), shift, vn(lo), vn(dst))
        }

        Subpiece { dst, src, offset } => {
            // Extract: dst = (src >> offset*8) & mask
            let shift = offset * 8;
            if shift > 0 {
                format!("{},{},>>,{},=", vn(src), shift, vn(dst))
            } else {
                format!("{},{},=", vn(src), vn(dst))
            }
        }

        PopCount { dst, src } => format!("{},POPCOUNT,{},=", vn(src), vn(dst)),
        Lzcount { dst, src } => format!("{},CLZ,{},=", vn(src), vn(dst)),

        // ========== Control Flow ==========
        Branch { target } => format!("{},pc,=", vn(target)),

        CBranch { target, cond } => {
            // Conditional branch: if cond then goto target
            format!("{},?{{,{},pc,=,}}", vn(cond), vn(target))
        }

        BranchInd { target } => format!("{},pc,=", vn(target)),

        Call { target } => {
            // Call: push return address, jump to target
            format!("pc,8,rsp,-=,rsp,=[8],{},pc,=", vn(target))
        }

        CallInd { target } => {
            format!("pc,8,rsp,-=,rsp,=[8],{},pc,=", vn(target))
        }

        Return { target: _ } => {
            // Return: pop return address, jump
            "rsp,[8],pc,=,8,rsp,+=".to_string()
        }

        // ========== Floating Point ==========
        FloatAdd { dst, a, b } => format!("{},{},F+,{},=", vn(a), vn(b), vn(dst)),
        FloatSub { dst, a, b } => format!("{},{},F-,{},=", vn(a), vn(b), vn(dst)),
        FloatMult { dst, a, b } => format!("{},{},F*,{},=", vn(a), vn(b), vn(dst)),
        FloatDiv { dst, a, b } => format!("{},{},F/,{},=", vn(a), vn(b), vn(dst)),
        FloatNeg { dst, src } => format!("0,{},F-,{},=", vn(src), vn(dst)),
        FloatAbs { dst, src } => format!("{},FABS,{},=", vn(src), vn(dst)),
        FloatSqrt { dst, src } => format!("{},FSQRT,{},=", vn(src), vn(dst)),
        FloatCeil { dst, src } => format!("{},FCEIL,{},=", vn(src), vn(dst)),
        FloatFloor { dst, src } => format!("{},FFLOOR,{},=", vn(src), vn(dst)),
        FloatRound { dst, src } => format!("{},FROUND,{},=", vn(src), vn(dst)),
        FloatNaN { dst, src } => format!("{},FISNAN,{},=", vn(src), vn(dst)),
        FloatEqual { dst, a, b } => format!("{},{},F==,{},=", vn(a), vn(b), vn(dst)),
        FloatNotEqual { dst, a, b } => format!("{},{},F==,!,{},=", vn(a), vn(b), vn(dst)),
        FloatLess { dst, a, b } => format!("{},{},F<,{},=", vn(a), vn(b), vn(dst)),
        FloatLessEqual { dst, a, b } => format!("{},{},F<=,{},=", vn(a), vn(b), vn(dst)),
        Int2Float { dst, src } => format!("{},I2F,{},=", vn(src), vn(dst)),
        Float2Int { dst, src } => format!("{},F2I,{},=", vn(src), vn(dst)),
        FloatFloat { dst, src } => format!("{},F2F,{},=", vn(src), vn(dst)),
        Trunc { dst, src } => format!("{},FTRUNC,{},=", vn(src), vn(dst)),

        // ========== Special Operations ==========
        CallOther { output, userop, inputs } => {
            let args: Vec<String> = inputs.iter().map(|v| vn(v)).collect();
            let args_str = args.join(",");
            match output {
                Some(dst) => format!("{},CALLOTHER({}),{},=", args_str, userop, vn(dst)),
                None => format!("{},CALLOTHER({})", args_str, userop),
            }
        }

        Nop => String::new(),
        Unimplemented => "UNIMPL".to_string(),
        CpuId { dst } => format!("CPUID,{},=", vn(dst)),
        Breakpoint => "BREAK".to_string(),

        // Analysis operations (typically not in raw P-code from disassembly)
        Multiequal { dst, inputs } => {
            let args: Vec<String> = inputs.iter().map(|v| vn(v)).collect();
            format!("{},PHI,{},=", args.join(","), vn(dst))
        }

        Indirect { dst, src, .. } => format!("{},{},=", vn(src), vn(dst)),

        PtrAdd { dst, base, index, element_size } => {
            format!("{},{},{},*,+,{},=", vn(base), vn(index), element_size, vn(dst))
        }

        PtrSub { dst, base, index, element_size } => {
            format!("{},{},{},*,-,{},=", vn(base), vn(index), element_size, vn(dst))
        }

        SegmentOp { dst, segment, offset } => {
            // Segment:offset calculation (x86 real mode style)
            format!("{},4,<<,{},+,{},=", vn(segment), vn(offset), vn(dst))
        }

        New { dst, src } => format!("{},NEW,{},=", vn(src), vn(dst)),
        Cast { dst, src } => format!("{},{},=", vn(src), vn(dst)),

        Extract { dst, src, position } => {
            format!("{},{},>>,{},=", vn(src), vn(position), vn(dst))
        }

        Insert { dst, src, value, position } => {
            // Insert value into src at position
            format!("{},{},<<,{},|,{},=", vn(value), vn(position), vn(src), vn(dst))
        }
    }
}
