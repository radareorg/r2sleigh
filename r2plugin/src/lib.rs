//! r2sleigh radare2 plugin
//!
//! This module exposes a C-ABI for radare2 integration. It can load r2il
//! specs from disk, or build Sleigh-based disassemblers and lift instruction
//! bytes into r2il blocks with ESIL rendering.

use r2il::{serialize, ArchSpec, R2ILBlock, R2ILOp};
use r2sleigh_lift::{build_arch_spec, op_to_esil, Disassembler};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::slice;

/// Opaque context handle for C API.
pub struct R2ILContext {
    arch: Option<ArchSpec>,
    arch_name_cstr: Option<CString>,
    disasm: Option<Disassembler>,
    error: Option<CString>,
}

impl R2ILContext {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            disasm: None,
            error: None,
        }
    }

    fn with_arch(arch: ArchSpec) -> Self {
        let name = CString::new(arch.name.clone()).ok();
        Self {
            arch: Some(arch),
            arch_name_cstr: name,
            disasm: None,
            error: None,
        }
    }

    fn with_arch_and_disasm(arch: ArchSpec, disasm: Disassembler) -> Self {
        let name = CString::new(arch.name.clone()).ok();
        Self {
            arch: Some(arch),
            arch_name_cstr: name,
            disasm: Some(disasm),
            error: None,
        }
    }

    fn with_error(msg: &str) -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            disasm: None,
            error: CString::new(msg).ok(),
        }
    }
}

/// Load an r2il file and return a context handle.
///
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_load(path: *const c_char) -> *mut R2ILContext {
    if path.is_null() {
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    match serialize::load(Path::new(path_str)) {
        Ok(arch) => Box::into_raw(Box::new(R2ILContext::with_arch(arch))),
        Err(e) => Box::into_raw(Box::new(R2ILContext::with_error(&e.to_string()))),
    }
}

/// Initialize a context from a built-in architecture (Sleigh via sleigh-config).
///
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_arch_init(arch: *const c_char) -> *mut R2ILContext {
    if arch.is_null() {
        return ptr::null_mut();
    }

    let arch_str = unsafe {
        match CStr::from_ptr(arch).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    match create_disassembler_for_arch(arch_str) {
        Ok((spec, dis)) => Box::into_raw(Box::new(R2ILContext::with_arch_and_disasm(spec, dis))),
        Err(e) => Box::into_raw(Box::new(R2ILContext::with_error(&e))),
    }
}

/// Free a context handle.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_free(ctx: *mut R2ILContext) {
    if !ctx.is_null() {
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Check if the context has a loaded architecture.
///
/// Returns 1 if loaded, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_is_loaded(ctx: *const R2ILContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        if (*ctx).arch.is_some() {
            1
        } else {
            0
        }
    }
}

/// Get the architecture name.
///
/// Returns NULL if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_arch_name(ctx: *const R2ILContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }

    unsafe {
        match &(*ctx).arch_name_cstr {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Get the last error message.
///
/// Returns NULL if no error.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_error(ctx: *const R2ILContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }

    unsafe {
        match &(*ctx).error {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Get the address size in bytes.
///
/// Returns 0 if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_addr_size(ctx: *const R2ILContext) -> u32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => arch.addr_size,
            None => 0,
        }
    }
}

/// Check if the architecture is big-endian.
///
/// Returns 1 for big-endian, 0 for little-endian or if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_is_big_endian(ctx: *const R2ILContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => {
                if arch.big_endian {
                    1
                } else {
                    0
                }
            }
            None => 0,
        }
    }
}

/// Get the number of registers.
///
/// Returns 0 if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_register_count(ctx: *const R2ILContext) -> usize {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => arch.registers.len(),
            None => 0,
        }
    }
}

/// Lift instruction bytes into an r2il block.
///
/// Returns NULL on failure or if the context lacks a disassembler.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_lift(
    ctx: *mut R2ILContext,
    bytes: *const u8,
    len: usize,
    addr: u64,
) -> *mut R2ILBlock {
    if ctx.is_null() || bytes.is_null() || len == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &mut *ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let slice = unsafe { slice::from_raw_parts(bytes, len) };
    match disasm.lift(slice, addr) {
        Ok(block) => Box::into_raw(Box::new(block)),
        Err(e) => {
            ctx_ref.error = CString::new(e.to_string()).ok();
            ptr::null_mut()
        }
    }
}

/// Free a lifted block.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_free(block: *mut R2ILBlock) {
    if !block.is_null() {
        unsafe { drop(Box::from_raw(block)) }
    }
}

/// Get the number of operations in a block.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_op_count(block: *const R2ILBlock) -> usize {
    if block.is_null() {
        return 0;
    }
    unsafe { (*block).ops.len() }
}

/// Get the ESIL string for a block (one line per op, joined with ';').
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_to_esil(ctx: *const R2ILContext, block: *const R2ILBlock) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let blk = unsafe { &*block };
    let parts: Vec<String> = blk.ops.iter().map(|op| op_to_esil(disasm, op)).collect();
    CString::new(parts.join(";")).map_or(ptr::null_mut(), |s| s.into_raw())
}

/// Get a JSON representation of an operation in a block.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_op_json(block: *const R2ILBlock, index: usize) -> *mut c_char {
    if block.is_null() {
        return ptr::null_mut();
    }

    let blk = unsafe { &*block };
    if index >= blk.ops.len() {
        return ptr::null_mut();
    }

    match serde_json::to_string(&blk.ops[index]) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the instruction size in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_size(block: *const R2ILBlock) -> u32 {
    if block.is_null() {
        return 0;
    }
    unsafe { (*block).size }
}

/// Get the block address.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_addr(block: *const R2ILBlock) -> u64 {
    if block.is_null() {
        return 0;
    }
    unsafe { (*block).addr }
}

/// Get the disassembly mnemonic for the instruction.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_mnemonic(
    ctx: *const R2ILContext,
    bytes: *const u8,
    len: usize,
    addr: u64,
) -> *mut c_char {
    if ctx.is_null() || bytes.is_null() || len == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let slice = unsafe { slice::from_raw_parts(bytes, len) };
    match disasm.disasm_native(slice, addr) {
        Ok((mnemonic, _size)) => {
            CString::new(mnemonic).map_or(ptr::null_mut(), |c| c.into_raw())
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Radare2 operation type constants (subset).
/// These match R_ANAL_OP_TYPE_* from radare2.
#[repr(C)]
pub struct R2AnalOpType;

impl R2AnalOpType {
    pub const NULL: u32 = 0;
    pub const JMP: u32 = 1;
    pub const UJMP: u32 = 2;
    pub const CJMP: u32 = 0x80000001; // JMP | COND
    pub const CALL: u32 = 3;
    pub const UCALL: u32 = 4;
    pub const RET: u32 = 5;
    pub const ILL: u32 = 6;
    pub const UNK: u32 = 7;
    pub const NOP: u32 = 8;
    pub const MOV: u32 = 9;
    pub const TRAP: u32 = 10;
    pub const SWI: u32 = 11;
    pub const PUSH: u32 = 13;
    pub const POP: u32 = 14;
    pub const CMP: u32 = 15;
    pub const ADD: u32 = 17;
    pub const SUB: u32 = 18;
    pub const MUL: u32 = 20;
    pub const DIV: u32 = 21;
    pub const SHR: u32 = 22;
    pub const SHL: u32 = 23;
    pub const SAR: u32 = 25;
    pub const OR: u32 = 26;
    pub const AND: u32 = 27;
    pub const XOR: u32 = 28;
    pub const NOT: u32 = 30;
    pub const STORE: u32 = 31;
    pub const LOAD: u32 = 32;
}

/// Infer the R_ANAL_OP_TYPE from the r2il operations in a block.
/// Returns R_ANAL_OP_TYPE_* constant.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_type(block: *const R2ILBlock) -> u32 {
    if block.is_null() {
        return R2AnalOpType::NULL;
    }

    let blk = unsafe { &*block };

    // Scan operations to determine instruction type
    // Priority: control flow > memory > arithmetic
    for op in &blk.ops {
        match op {
            R2ILOp::Return { .. } => return R2AnalOpType::RET,
            R2ILOp::Call { .. } => return R2AnalOpType::CALL,
            R2ILOp::CallInd { .. } => return R2AnalOpType::UCALL,
            R2ILOp::Branch { .. } => return R2AnalOpType::JMP,
            R2ILOp::BranchInd { .. } => return R2AnalOpType::UJMP,
            R2ILOp::CBranch { .. } => return R2AnalOpType::CJMP,
            _ => {}
        }
    }

    // Second pass: memory operations
    for op in &blk.ops {
        match op {
            R2ILOp::Store { .. } => return R2AnalOpType::STORE,
            R2ILOp::Load { .. } => return R2AnalOpType::LOAD,
            _ => {}
        }
    }

    // Third pass: arithmetic/logic
    for op in &blk.ops {
        match op {
            R2ILOp::IntAdd { .. } => return R2AnalOpType::ADD,
            R2ILOp::IntSub { .. } => return R2AnalOpType::SUB,
            R2ILOp::IntMult { .. } => return R2AnalOpType::MUL,
            R2ILOp::IntDiv { .. } | R2ILOp::IntSDiv { .. } => return R2AnalOpType::DIV,
            R2ILOp::IntAnd { .. } => return R2AnalOpType::AND,
            R2ILOp::IntOr { .. } => return R2AnalOpType::OR,
            R2ILOp::IntXor { .. } => return R2AnalOpType::XOR,
            R2ILOp::IntNot { .. } => return R2AnalOpType::NOT,
            R2ILOp::IntLeft { .. } => return R2AnalOpType::SHL,
            R2ILOp::IntRight { .. } => return R2AnalOpType::SHR,
            R2ILOp::IntSRight { .. } => return R2AnalOpType::SAR,
            R2ILOp::IntEqual { .. } | R2ILOp::IntNotEqual { .. } |
            R2ILOp::IntLess { .. } | R2ILOp::IntSLess { .. } |
            R2ILOp::IntLessEqual { .. } | R2ILOp::IntSLessEqual { .. } => return R2AnalOpType::CMP,
            R2ILOp::Copy { .. } => return R2AnalOpType::MOV,
            _ => {}
        }
    }

    // Default: unknown
    if blk.ops.is_empty() {
        R2AnalOpType::NOP
    } else {
        R2AnalOpType::UNK
    }
}

/// Get the jump target address from a block (for JMP/CALL instructions).
/// Returns 0 if no jump target is found or if indirect.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_jump(block: *const R2ILBlock) -> u64 {
    if block.is_null() {
        return 0;
    }

    let blk = unsafe { &*block };

    for op in &blk.ops {
        match op {
            R2ILOp::Branch { target } |
            R2ILOp::Call { target } |
            R2ILOp::CBranch { target, .. } => {
                // Only return if target is a constant (direct jump)
                if target.space == r2il::SpaceId::Const || target.space == r2il::SpaceId::Ram {
                    return target.offset;
                }
            }
            _ => {}
        }
    }

    0
}

/// Get the fall-through address (for conditional jumps).
/// Returns addr + size for conditional branches, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_fail(block: *const R2ILBlock) -> u64 {
    if block.is_null() {
        return 0;
    }

    let blk = unsafe { &*block };

    // Check if this is a conditional branch
    for op in &blk.ops {
        if matches!(op, R2ILOp::CBranch { .. }) {
            return blk.addr + blk.size as u64;
        }
    }

    0
}

/// Free a string returned by r2il functions.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

// ========== Typed Analysis FFI ==========

use std::collections::HashSet;
use r2il::Varnode;

/// Helper: extract all register varnodes that are read by an operation.
fn op_regs_read(op: &R2ILOp) -> Vec<&Varnode> {
    let mut regs = Vec::new();
    
    match op {
        // Data movement - src is read
        R2ILOp::Copy { src, .. } => {
            if src.is_register() { regs.push(src); }
        }
        R2ILOp::Load { addr, .. } => {
            if addr.is_register() { regs.push(addr); }
        }
        R2ILOp::Store { addr, val, .. } => {
            if addr.is_register() { regs.push(addr); }
            if val.is_register() { regs.push(val); }
        }
        
        // Binary ops - a and b are read
        R2ILOp::IntAdd { a, b, .. } |
        R2ILOp::IntSub { a, b, .. } |
        R2ILOp::IntMult { a, b, .. } |
        R2ILOp::IntDiv { a, b, .. } |
        R2ILOp::IntSDiv { a, b, .. } |
        R2ILOp::IntRem { a, b, .. } |
        R2ILOp::IntSRem { a, b, .. } |
        R2ILOp::IntAnd { a, b, .. } |
        R2ILOp::IntOr { a, b, .. } |
        R2ILOp::IntXor { a, b, .. } |
        R2ILOp::IntLeft { a, b, .. } |
        R2ILOp::IntRight { a, b, .. } |
        R2ILOp::IntSRight { a, b, .. } |
        R2ILOp::IntEqual { a, b, .. } |
        R2ILOp::IntNotEqual { a, b, .. } |
        R2ILOp::IntLess { a, b, .. } |
        R2ILOp::IntSLess { a, b, .. } |
        R2ILOp::IntLessEqual { a, b, .. } |
        R2ILOp::IntSLessEqual { a, b, .. } |
        R2ILOp::IntCarry { a, b, .. } |
        R2ILOp::IntSCarry { a, b, .. } |
        R2ILOp::IntSBorrow { a, b, .. } |
        R2ILOp::BoolAnd { a, b, .. } |
        R2ILOp::BoolOr { a, b, .. } |
        R2ILOp::BoolXor { a, b, .. } |
        R2ILOp::Piece { hi: a, lo: b, .. } |
        R2ILOp::FloatAdd { a, b, .. } |
        R2ILOp::FloatSub { a, b, .. } |
        R2ILOp::FloatMult { a, b, .. } |
        R2ILOp::FloatDiv { a, b, .. } |
        R2ILOp::FloatEqual { a, b, .. } |
        R2ILOp::FloatNotEqual { a, b, .. } |
        R2ILOp::FloatLess { a, b, .. } |
        R2ILOp::FloatLessEqual { a, b, .. } => {
            if a.is_register() { regs.push(a); }
            if b.is_register() { regs.push(b); }
        }
        
        // Unary ops - src is read
        R2ILOp::IntNegate { src, .. } |
        R2ILOp::IntNot { src, .. } |
        R2ILOp::IntZExt { src, .. } |
        R2ILOp::IntSExt { src, .. } |
        R2ILOp::BoolNot { src, .. } |
        R2ILOp::PopCount { src, .. } |
        R2ILOp::Lzcount { src, .. } |
        R2ILOp::Subpiece { src, .. } |
        R2ILOp::FloatNeg { src, .. } |
        R2ILOp::FloatAbs { src, .. } |
        R2ILOp::FloatSqrt { src, .. } |
        R2ILOp::FloatNaN { src, .. } |
        R2ILOp::Int2Float { src, .. } |
        R2ILOp::FloatFloat { src, .. } |
        R2ILOp::Trunc { src, .. } |
        R2ILOp::FloatCeil { src, .. } |
        R2ILOp::FloatFloor { src, .. } |
        R2ILOp::FloatRound { src, .. } => {
            if src.is_register() { regs.push(src); }
        }
        
        // Control flow - target/cond are read
        R2ILOp::Branch { target } |
        R2ILOp::BranchInd { target } |
        R2ILOp::Call { target } |
        R2ILOp::CallInd { target } |
        R2ILOp::Return { target } => {
            if target.is_register() { regs.push(target); }
        }
        R2ILOp::CBranch { cond, target } => {
            if cond.is_register() { regs.push(cond); }
            if target.is_register() { regs.push(target); }
        }
        
        // CallOther - inputs are read
        R2ILOp::CallOther { inputs, .. } => {
            for inp in inputs {
                if inp.is_register() { regs.push(inp); }
            }
        }
        
        // Float2Int - src is read
        R2ILOp::Float2Int { src, .. } |
        R2ILOp::New { src, .. } |
        R2ILOp::Cast { src, .. } => {
            if src.is_register() { regs.push(src); }
        }
        
        // Extract - src and position are read
        R2ILOp::Extract { src, position, .. } => {
            if src.is_register() { regs.push(src); }
            if position.is_register() { regs.push(position); }
        }
        
        // Insert - src, value, position are read
        R2ILOp::Insert { src, value, position, .. } => {
            if src.is_register() { regs.push(src); }
            if value.is_register() { regs.push(value); }
            if position.is_register() { regs.push(position); }
        }
        
        // SegmentOp - segment and offset are read
        R2ILOp::SegmentOp { segment, offset, .. } => {
            if segment.is_register() { regs.push(segment); }
            if offset.is_register() { regs.push(offset); }
        }
        
        // PtrAdd/PtrSub - base and index are read
        R2ILOp::PtrAdd { base, index, .. } |
        R2ILOp::PtrSub { base, index, .. } => {
            if base.is_register() { regs.push(base); }
            if index.is_register() { regs.push(index); }
        }
        
        // Multiequal - inputs are read
        R2ILOp::Multiequal { inputs, .. } => {
            for inp in inputs {
                if inp.is_register() { regs.push(inp); }
            }
        }
        
        // Indirect - src and indirect are read
        R2ILOp::Indirect { src, indirect, .. } => {
            if src.is_register() { regs.push(src); }
            if indirect.is_register() { regs.push(indirect); }
        }
        
        // Ops with no register reads
        R2ILOp::Nop |
        R2ILOp::Unimplemented |
        R2ILOp::Breakpoint |
        R2ILOp::CpuId { .. } => {}
    }
    
    regs
}

/// Helper: extract all register varnodes that are written by an operation.
fn op_regs_write(op: &R2ILOp) -> Vec<&Varnode> {
    let mut regs = Vec::new();
    
    match op {
        // All ops with dst field write to dst
        R2ILOp::Copy { dst, .. } |
        R2ILOp::Load { dst, .. } |
        R2ILOp::IntAdd { dst, .. } |
        R2ILOp::IntSub { dst, .. } |
        R2ILOp::IntMult { dst, .. } |
        R2ILOp::IntDiv { dst, .. } |
        R2ILOp::IntSDiv { dst, .. } |
        R2ILOp::IntRem { dst, .. } |
        R2ILOp::IntSRem { dst, .. } |
        R2ILOp::IntNegate { dst, .. } |
        R2ILOp::IntAnd { dst, .. } |
        R2ILOp::IntOr { dst, .. } |
        R2ILOp::IntXor { dst, .. } |
        R2ILOp::IntNot { dst, .. } |
        R2ILOp::IntLeft { dst, .. } |
        R2ILOp::IntRight { dst, .. } |
        R2ILOp::IntSRight { dst, .. } |
        R2ILOp::IntEqual { dst, .. } |
        R2ILOp::IntNotEqual { dst, .. } |
        R2ILOp::IntLess { dst, .. } |
        R2ILOp::IntSLess { dst, .. } |
        R2ILOp::IntLessEqual { dst, .. } |
        R2ILOp::IntSLessEqual { dst, .. } |
        R2ILOp::IntZExt { dst, .. } |
        R2ILOp::IntSExt { dst, .. } |
        R2ILOp::IntCarry { dst, .. } |
        R2ILOp::IntSCarry { dst, .. } |
        R2ILOp::IntSBorrow { dst, .. } |
        R2ILOp::BoolAnd { dst, .. } |
        R2ILOp::BoolOr { dst, .. } |
        R2ILOp::BoolXor { dst, .. } |
        R2ILOp::BoolNot { dst, .. } |
        R2ILOp::PopCount { dst, .. } |
        R2ILOp::Lzcount { dst, .. } |
        R2ILOp::Piece { dst, .. } |
        R2ILOp::Subpiece { dst, .. } |
        R2ILOp::FloatAdd { dst, .. } |
        R2ILOp::FloatSub { dst, .. } |
        R2ILOp::FloatMult { dst, .. } |
        R2ILOp::FloatDiv { dst, .. } |
        R2ILOp::FloatNeg { dst, .. } |
        R2ILOp::FloatAbs { dst, .. } |
        R2ILOp::FloatSqrt { dst, .. } |
        R2ILOp::FloatEqual { dst, .. } |
        R2ILOp::FloatNotEqual { dst, .. } |
        R2ILOp::FloatLess { dst, .. } |
        R2ILOp::FloatLessEqual { dst, .. } |
        R2ILOp::FloatNaN { dst, .. } |
        R2ILOp::Int2Float { dst, .. } |
        R2ILOp::FloatFloat { dst, .. } |
        R2ILOp::Trunc { dst, .. } |
        R2ILOp::FloatCeil { dst, .. } |
        R2ILOp::FloatFloor { dst, .. } |
        R2ILOp::FloatRound { dst, .. } => {
            if dst.is_register() { regs.push(dst); }
        }
        
        // Store doesn't have a register dst
        R2ILOp::Store { .. } => {}
        
        // Control flow ops don't write registers directly
        R2ILOp::Branch { .. } |
        R2ILOp::BranchInd { .. } |
        R2ILOp::CBranch { .. } |
        R2ILOp::Call { .. } |
        R2ILOp::CallInd { .. } |
        R2ILOp::Return { .. } => {}
        
        // CallOther may have output
        R2ILOp::CallOther { output, .. } => {
            if let Some(out) = output {
                if out.is_register() { regs.push(out); }
            }
        }
        
        // Ops with dst field that write
        R2ILOp::Float2Int { dst, .. } |
        R2ILOp::CpuId { dst, .. } |
        R2ILOp::SegmentOp { dst, .. } |
        R2ILOp::New { dst, .. } |
        R2ILOp::Cast { dst, .. } |
        R2ILOp::Extract { dst, .. } |
        R2ILOp::Insert { dst, .. } |
        R2ILOp::Multiequal { dst, .. } |
        R2ILOp::Indirect { dst, .. } |
        R2ILOp::PtrAdd { dst, .. } |
        R2ILOp::PtrSub { dst, .. } => {
            if dst.is_register() { regs.push(dst); }
        }
        
        // Ops with no register writes
        R2ILOp::Nop |
        R2ILOp::Unimplemented |
        R2ILOp::Breakpoint => {}
    }
    
    regs
}

/// Get registers read by the block as JSON array of names.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_regs_read(
    ctx: *const R2ILContext,
    block: *const R2ILBlock,
) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }
    
    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    
    let blk = unsafe { &*block };
    let mut seen: HashSet<(u64, u32)> = HashSet::new();
    let mut names: Vec<String> = Vec::new();
    
    for op in &blk.ops {
        for vn in op_regs_read(op) {
            let key = (vn.offset, vn.size);
            if !seen.contains(&key) {
                seen.insert(key);
                let name = disasm.register_name(vn)
                    .unwrap_or_else(|| format!("reg:0x{:x}:{}", vn.offset, vn.size));
                names.push(name);
            }
        }
    }
    
    match serde_json::to_string(&names) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Get registers written by the block as JSON array of names.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_regs_write(
    ctx: *const R2ILContext,
    block: *const R2ILBlock,
) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }
    
    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    
    let blk = unsafe { &*block };
    let mut seen: HashSet<(u64, u32)> = HashSet::new();
    let mut names: Vec<String> = Vec::new();
    
    for op in &blk.ops {
        for vn in op_regs_write(op) {
            let key = (vn.offset, vn.size);
            if !seen.contains(&key) {
                seen.insert(key);
                let name = disasm.register_name(vn)
                    .unwrap_or_else(|| format!("reg:0x{:x}:{}", vn.offset, vn.size));
                names.push(name);
            }
        }
    }
    
    match serde_json::to_string(&names) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

use serde::Serialize;

/// Memory access info for JSON output.
#[derive(Serialize)]
struct MemAccess {
    addr: String,
    size: u32,
    write: bool,
}

/// Get memory accesses (loads/stores) as JSON array.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_mem_access(
    ctx: *const R2ILContext,
    block: *const R2ILBlock,
) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }
    
    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    
    let blk = unsafe { &*block };
    let mut accesses: Vec<MemAccess> = Vec::new();
    
    for op in &blk.ops {
        match op {
            R2ILOp::Load { dst, addr, .. } => {
                let addr_str = disasm.format_varnode(addr);
                accesses.push(MemAccess {
                    addr: addr_str,
                    size: dst.size,
                    write: false,
                });
            }
            R2ILOp::Store { addr, val, .. } => {
                let addr_str = disasm.format_varnode(addr);
                accesses.push(MemAccess {
                    addr: addr_str,
                    size: val.size,
                    write: true,
                });
            }
            _ => {}
        }
    }
    
    match serde_json::to_string(&accesses) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Varnode info for JSON output.
#[derive(Serialize)]
struct VarnodeInfo {
    name: String,
    space: String,
    offset: u64,
    size: u32,
}

/// Helper: collect all varnodes from an operation.
fn op_all_varnodes(op: &R2ILOp) -> Vec<&Varnode> {
    let mut vns = Vec::new();
    
    // Combine read and write varnodes
    vns.extend(op_regs_read(op));
    vns.extend(op_regs_write(op));
    
    // Also get non-register varnodes
    match op {
        R2ILOp::Copy { dst, src } => {
            if !dst.is_register() { vns.push(dst); }
            if !src.is_register() { vns.push(src); }
        }
        R2ILOp::Load { dst, addr, .. } => {
            if !dst.is_register() { vns.push(dst); }
            if !addr.is_register() { vns.push(addr); }
        }
        R2ILOp::Store { addr, val, .. } => {
            if !addr.is_register() { vns.push(addr); }
            if !val.is_register() { vns.push(val); }
        }
        // For binary ops, get non-register operands
        R2ILOp::IntAdd { dst, a, b } |
        R2ILOp::IntSub { dst, a, b } |
        R2ILOp::IntAnd { dst, a, b } |
        R2ILOp::IntOr { dst, a, b } |
        R2ILOp::IntXor { dst, a, b } => {
            if !dst.is_register() { vns.push(dst); }
            if !a.is_register() { vns.push(a); }
            if !b.is_register() { vns.push(b); }
        }
        _ => {} // Other ops handled by op_regs_read/write
    }
    
    vns
}

/// Get all varnodes used in the block as JSON array.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_varnodes(
    ctx: *const R2ILContext,
    block: *const R2ILBlock,
) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }
    
    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    
    let blk = unsafe { &*block };
    let mut seen: HashSet<(u8, u64, u32)> = HashSet::new(); // (space_id, offset, size)
    let mut varnodes: Vec<VarnodeInfo> = Vec::new();
    
    for op in &blk.ops {
        for vn in op_all_varnodes(op) {
            let space_id = match vn.space {
                r2il::SpaceId::Const => 0,
                r2il::SpaceId::Register => 1,
                r2il::SpaceId::Ram => 2,
                r2il::SpaceId::Unique => 3,
                r2il::SpaceId::Custom(n) => 4 + (n as u8),
            };
            let key = (space_id, vn.offset, vn.size);
            
            if !seen.contains(&key) {
                seen.insert(key);
                
                let (name, space_str) = match vn.space {
                    r2il::SpaceId::Const => (format!("0x{:x}", vn.offset), "const".to_string()),
                    r2il::SpaceId::Register => {
                        let name = disasm.register_name(vn)
                            .unwrap_or_else(|| format!("reg:0x{:x}", vn.offset));
                        (name, "register".to_string())
                    }
                    r2il::SpaceId::Ram => (format!("[0x{:x}]", vn.offset), "ram".to_string()),
                    r2il::SpaceId::Unique => (format!("tmp:0x{:x}", vn.offset), "unique".to_string()),
                    r2il::SpaceId::Custom(n) => (format!("space{}:0x{:x}", n, vn.offset), format!("custom:{}", n)),
                };
                
                varnodes.push(VarnodeInfo {
                    name,
                    space: space_str,
                    offset: vn.offset,
                    size: vn.size,
                });
            }
        }
    }
    
    match serde_json::to_string(&varnodes) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Helper: build a disassembler and ArchSpec for a given arch string.
fn create_disassembler_for_arch(arch: &str) -> Result<(ArchSpec, Disassembler), String> {
    match arch.to_lowercase().as_str() {
        #[cfg(feature = "x86")]
        "x86-64" | "x86_64" | "x64" | "amd64" => {
            let spec = build_arch_spec(
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64",
            )
            .map_err(|e| e.to_string())?;
            Ok((spec, dis))
        }
        #[cfg(feature = "x86")]
        "x86" | "x86-32" | "i386" | "i686" => {
            let spec = build_arch_spec(
                sleigh_config::processor_x86::SLA_X86,
                sleigh_config::processor_x86::PSPEC_X86,
                "x86",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_x86::SLA_X86,
                sleigh_config::processor_x86::PSPEC_X86,
                "x86",
            )
            .map_err(|e| e.to_string())?;
            Ok((spec, dis))
        }
        #[cfg(feature = "arm")]
        "arm" | "arm32" | "arm-le" => {
            let spec = build_arch_spec(
                sleigh_config::processor_arm::SLA_ARM8_LE,
                sleigh_config::processor_arm::PSPEC_ARM8_LE,
                "ARM",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_arm::SLA_ARM8_LE,
                sleigh_config::processor_arm::PSPEC_ARM8_LE,
                "ARM",
            )
            .map_err(|e| e.to_string())?;
            Ok((spec, dis))
        }
        _ => {
            let mut supported = vec![];
            #[cfg(feature = "x86")]
            supported.extend(["x86-64", "x86"]);
            #[cfg(feature = "arm")]
            supported.push("arm");

            if supported.is_empty() {
                Err("No architectures enabled; build with feature x86 or arm".to_string())
            } else {
                Err(format!("Unknown architecture '{}'. Supported: {}", arch, supported.join(", ")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_context_lifecycle_from_file() {
        let spec = r2sleigh_lift::create_x86_64_spec();
        let temp_path = "/tmp/test_r2il_plugin.r2il";
        serialize::save(&spec, Path::new(temp_path)).unwrap();

        let path_cstr = CString::new(temp_path).unwrap();
        let ctx = r2il_load(path_cstr.as_ptr());
        assert!(!ctx.is_null());
        assert_eq!(r2il_is_loaded(ctx), 1);

        let name_ptr = r2il_arch_name(ctx);
        assert!(!name_ptr.is_null());
        let name = unsafe { CStr::from_ptr(name_ptr) };
        assert_eq!(name.to_str().unwrap(), "x86-64");

        r2il_free(ctx);
        std::fs::remove_file(temp_path).ok();
    }

    #[test]
    #[cfg(feature = "x86")]
    fn test_lift_and_esil() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        // xor eax, eax (0x31 0xC0) padded to 16 bytes for libsla
        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);

        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());
        assert!(r2il_block_op_count(block) > 0);

        let esil_ptr = r2il_block_to_esil(ctx, block);
        assert!(!esil_ptr.is_null());
        let esil = unsafe { CStr::from_ptr(esil_ptr) }.to_string_lossy().into_owned();
        assert!(esil.contains("eax"));

        unsafe { drop(CString::from_raw(esil_ptr as *mut c_char)) };
        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    fn test_null_handling() {
        assert!(r2il_load(ptr::null()).is_null());
        assert_eq!(r2il_is_loaded(ptr::null()), 0);
        assert!(r2il_arch_name(ptr::null()).is_null());
        r2il_free(ptr::null_mut());
        r2il_block_free(ptr::null_mut());
    }
}
