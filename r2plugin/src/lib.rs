//! r2sleigh radare2 plugin
//!
//! This module exposes a C-ABI for radare2 integration. It can load r2il
//! specs from disk, or build Sleigh-based disassemblers and lift instruction
//! bytes into r2il blocks with ESIL rendering.

use r2il::{serialize, ArchSpec, R2ILBlock, R2ILOp};
use r2ssa::TaintPolicy;
use r2sleigh_lift::{build_arch_spec, op_to_esil, Disassembler};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

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

/// Get the register profile string for radare2.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_get_reg_profile(ctx: *const R2ILContext) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let arch = match &ctx_ref.arch {
        Some(a) => a,
        None => return ptr::null_mut(),
    };

    let mut profile = String::new();
    let mut pc = None;
    let mut sp = None;
    let mut bp = None;
    let mut a0 = None;
    let mut a1 = None;
    let mut a2 = None;
    let mut a3 = None;
    let mut r0 = None;

    // Heuristics for roles
    for reg in &arch.registers {
        // Role detection (case-insensitive)
        let name_lower = reg.name.to_lowercase();
        
        // PC candidates
        if name_lower == "pc" || name_lower == "rip" || name_lower == "eip" || name_lower == "ip" {
           if pc.is_none() { pc = Some(&reg.name); }
        } 
        // SP candidates
        else if name_lower == "sp" || name_lower == "rsp" || name_lower == "esp" {
           if sp.is_none() { sp = Some(&reg.name); }
        } 
        // BP candidates
        else if name_lower == "bp" || name_lower == "rbp" || name_lower == "ebp" || name_lower == "fp" {
           if bp.is_none() { bp = Some(&reg.name); }
        } 
        // Return value candidates
        else if name_lower == "r0" || name_lower == "rax" || name_lower == "eax" || name_lower == "v0" {
           if r0.is_none() { r0 = Some(&reg.name); }
        } 
        // Arg 0
        else if name_lower == "rdi" || name_lower == "a0" {
           if a0.is_none() { a0 = Some(&reg.name); }
        } 
        // Arg 1
        else if name_lower == "rsi" || name_lower == "a1" {
           if a1.is_none() { a1 = Some(&reg.name); }
        } 
        // Arg 2
        else if name_lower == "rdx" || name_lower == "a2" {
           if a2.is_none() { a2 = Some(&reg.name); }
        } 
        // Arg 3
        else if name_lower == "rcx" || name_lower == "a3" {
           if a3.is_none() { a3 = Some(&reg.name); }
        }

        profile.push_str(&format!("gpr\t{}\t.{}\t{}\t0\n", reg.name, reg.size * 8, reg.offset));
    }

    // Add roles
    if let Some(n) = pc { profile.push_str(&format!("=PC\t{}\n", n)); }
    if let Some(n) = sp { profile.push_str(&format!("=SP\t{}\n", n)); }
    if let Some(n) = bp { profile.push_str(&format!("=BP\t{}\n", n)); }
    if let Some(n) = a0 { profile.push_str(&format!("=A0\t{}\n", n)); }
    if let Some(n) = a1 { profile.push_str(&format!("=A1\t{}\n", n)); }
    if let Some(n) = a2 { profile.push_str(&format!("=A2\t{}\n", n)); }
    if let Some(n) = a3 { profile.push_str(&format!("=A3\t{}\n", n)); }
    if let Some(n) = r0 { profile.push_str(&format!("=R0\t{}\n", n)); }

    CString::new(profile).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Lift a single instruction into an r2il block.
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

/// Lift an entire basic block (multiple instructions) into an r2il block.
///
/// # Arguments
///
/// * `ctx` - The r2il context
/// * `bytes` - Instruction bytes for the block
/// * `len` - Length of the byte buffer
/// * `addr` - Starting address of the block
/// * `block_size` - Size of the basic block in bytes (from radare2)
///
/// Returns NULL on failure or if the context lacks a disassembler.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_lift_block(
    ctx: *mut R2ILContext,
    bytes: *const u8,
    len: usize,
    addr: u64,
    block_size: u32,
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
    let size = (block_size as usize).min(len);

    match disasm.lift_block(slice, addr, size) {
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

use serde::{Deserialize, Serialize};

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

// ============================================================================
// SSA Functions
// ============================================================================

/// SSA operation info for JSON output.
#[derive(Serialize)]
struct SSAOpInfo {
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<String>,
}

/// Convert SSAOp to JSON-serializable info.
fn ssa_op_to_info(op: &r2ssa::SSAOp) -> SSAOpInfo {
    use r2ssa::SSAOp::*;

    let op_name = match op {
        Phi { .. } => "Phi",
        Copy { .. } => "Copy",
        Load { .. } => "Load",
        Store { .. } => "Store",
        IntAdd { .. } => "IntAdd",
        IntSub { .. } => "IntSub",
        IntMult { .. } => "IntMult",
        IntDiv { .. } => "IntDiv",
        IntSDiv { .. } => "IntSDiv",
        IntRem { .. } => "IntRem",
        IntSRem { .. } => "IntSRem",
        IntNegate { .. } => "IntNegate",
        IntCarry { .. } => "IntCarry",
        IntSCarry { .. } => "IntSCarry",
        IntSBorrow { .. } => "IntSBorrow",
        IntAnd { .. } => "IntAnd",
        IntOr { .. } => "IntOr",
        IntXor { .. } => "IntXor",
        IntNot { .. } => "IntNot",
        IntLeft { .. } => "IntLeft",
        IntRight { .. } => "IntRight",
        IntSRight { .. } => "IntSRight",
        IntEqual { .. } => "IntEqual",
        IntNotEqual { .. } => "IntNotEqual",
        IntLess { .. } => "IntLess",
        IntSLess { .. } => "IntSLess",
        IntLessEqual { .. } => "IntLessEqual",
        IntSLessEqual { .. } => "IntSLessEqual",
        IntZExt { .. } => "IntZExt",
        IntSExt { .. } => "IntSExt",
        BoolNot { .. } => "BoolNot",
        BoolAnd { .. } => "BoolAnd",
        BoolOr { .. } => "BoolOr",
        BoolXor { .. } => "BoolXor",
        Piece { .. } => "Piece",
        Subpiece { .. } => "Subpiece",
        PopCount { .. } => "PopCount",
        Lzcount { .. } => "Lzcount",
        Branch { .. } => "Branch",
        CBranch { .. } => "CBranch",
        BranchInd { .. } => "BranchInd",
        Call { .. } => "Call",
        CallInd { .. } => "CallInd",
        Return { .. } => "Return",
        FloatAdd { .. } => "FloatAdd",
        FloatSub { .. } => "FloatSub",
        FloatMult { .. } => "FloatMult",
        FloatDiv { .. } => "FloatDiv",
        FloatNeg { .. } => "FloatNeg",
        FloatAbs { .. } => "FloatAbs",
        FloatSqrt { .. } => "FloatSqrt",
        FloatCeil { .. } => "FloatCeil",
        FloatFloor { .. } => "FloatFloor",
        FloatRound { .. } => "FloatRound",
        FloatNaN { .. } => "FloatNaN",
        FloatEqual { .. } => "FloatEqual",
        FloatNotEqual { .. } => "FloatNotEqual",
        FloatLess { .. } => "FloatLess",
        FloatLessEqual { .. } => "FloatLessEqual",
        Int2Float { .. } => "Int2Float",
        Float2Int { .. } => "Float2Int",
        FloatFloat { .. } => "FloatFloat",
        Trunc { .. } => "Trunc",
        CallOther { .. } => "CallOther",
        Nop => "Nop",
        Unimplemented => "Unimplemented",
        CpuId { .. } => "CpuId",
        Breakpoint => "Breakpoint",
        PtrAdd { .. } => "PtrAdd",
        PtrSub { .. } => "PtrSub",
        SegmentOp { .. } => "SegmentOp",
        New { .. } => "New",
        Cast { .. } => "Cast",
        Extract { .. } => "Extract",
        Insert { .. } => "Insert",
    };

    SSAOpInfo {
        op: op_name.to_string(),
        dst: op.dst().map(|v| v.display_name()),
        sources: op.sources().iter().map(|v| v.display_name()).collect(),
    }
}

// ============================================================================
// Taint Analysis Functions
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct TaintConfig {
    sources: Vec<String>,
    sink_calls: bool,
    sink_stores: bool,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            sink_calls: true,
            sink_stores: true,
        }
    }
}

fn taint_config() -> &'static Mutex<TaintConfig> {
    static CONFIG: OnceLock<Mutex<TaintConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| Mutex::new(TaintConfig::default()))
}

/// Configure taint sources/sinks via JSON.
/// If `json` is NULL or empty, returns the current configuration.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_sources_sinks_json(json: *const c_char) -> *mut c_char {
    if !json.is_null() {
        let json_str = unsafe {
            match CStr::from_ptr(json).to_str() {
                Ok(s) => s.trim(),
                Err(_) => return ptr::null_mut(),
            }
        };

        if !json_str.is_empty() {
            match serde_json::from_str::<TaintConfig>(json_str) {
                Ok(new_cfg) => {
                    if let Ok(mut cfg) = taint_config().lock() {
                        *cfg = new_cfg;
                    }
                }
                Err(_) => return ptr::null_mut(),
            }
        }
    }

    let cfg = match taint_config().lock() {
        Ok(cfg) => cfg.clone(),
        Err(_) => return ptr::null_mut(),
    };

    match serde_json::to_string_pretty(&cfg) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

#[derive(Serialize)]
struct TaintSourceJson {
    var: String,
    labels: Vec<String>,
    block: u64,
    block_hex: String,
}

#[derive(Serialize)]
struct TaintSinkJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
    op: SSAOpInfo,
}

#[derive(Serialize)]
struct TaintedVarJson {
    var: String,
    labels: Vec<String>,
}

#[derive(Serialize)]
struct SinkHitJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
    op: SSAOpInfo,
    tainted_vars: Vec<TaintedVarJson>,
}

#[derive(Serialize)]
struct TaintReportJson {
    sources: Vec<TaintSourceJson>,
    sinks: Vec<TaintSinkJson>,
    sink_hits: Vec<SinkHitJson>,
    tainted_vars: Vec<TaintedVarJson>,
}

fn labels_to_strings(labels: &r2ssa::taint::TaintSet) -> Vec<String> {
    let mut out: Vec<String> = labels.iter().map(|l| l.id.clone()).collect();
    out.sort();
    out
}

/// Run taint analysis and return results as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_function_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }
    let ctx = unsafe { &*ctx };


    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx.arch.as_ref()) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let cfg = match taint_config().lock() {
        Ok(cfg) => cfg.clone(),
        Err(_) => return ptr::null_mut(),
    };

    let mut policy = if cfg.sources.is_empty() {
        r2ssa::DefaultTaintPolicy::all_inputs()
    } else {
        r2ssa::DefaultTaintPolicy::new()
    };
    policy = policy
        .with_sink_calls(cfg.sink_calls)
        .with_sink_stores(cfg.sink_stores);
    for src in &cfg.sources {
        policy = policy.with_source(src.clone());
    }

    let analysis = r2ssa::TaintAnalysis::new(&ssa_func, policy.clone());
    let result = analysis.analyze();

    // Collect sources
    let mut source_map: std::collections::HashMap<String, TaintSourceJson> = std::collections::HashMap::new();
    for block in ssa_func.blocks() {
        for phi in &block.phis {
            for (_, src) in &phi.sources {
                if let Some(labels) = policy.is_source(src, block.addr) {
                    let entry = source_map.entry(src.display_name()).or_insert(TaintSourceJson {
                        var: src.display_name(),
                        labels: Vec::new(),
                        block: block.addr,
                        block_hex: format!("0x{:x}", block.addr),
                    });
                    for label in labels {
                        entry.labels.push(label.id);
                    }
                    entry.labels.sort();
                    entry.labels.dedup();
                }
            }
        }

        for op in &block.ops {
            for src in op.sources() {
                if let Some(labels) = policy.is_source(src, block.addr) {
                    let entry = source_map.entry(src.display_name()).or_insert(TaintSourceJson {
                        var: src.display_name(),
                        labels: Vec::new(),
                        block: block.addr,
                        block_hex: format!("0x{:x}", block.addr),
                    });
                    for label in labels {
                        entry.labels.push(label.id);
                    }
                    entry.labels.sort();
                    entry.labels.dedup();
                }
            }
        }
    }

    let mut sources: Vec<TaintSourceJson> = source_map.into_values().collect();
    sources.sort_by(|a, b| a.var.cmp(&b.var));

    // Collect sinks
    let mut sinks = Vec::new();
    for block in ssa_func.blocks() {
        for (op_idx, op) in block.ops.iter().enumerate() {
            if policy.is_sink(op, block.addr) {
                sinks.push(TaintSinkJson {
                    block: block.addr,
                    block_hex: format!("0x{:x}", block.addr),
                    op_idx,
                    op: ssa_op_to_info(op),
                });
            }
        }
    }

    // Collect tainted vars
    let mut tainted_vars = Vec::new();
    for (name, labels) in result.var_taints.iter() {
        if labels.is_empty() {
            continue;
        }
        tainted_vars.push(TaintedVarJson {
            var: name.clone(),
            labels: labels_to_strings(labels),
        });
    }
    tainted_vars.sort_by(|a, b| a.var.cmp(&b.var));

    // Collect sink hits
    let sink_hits = result
        .sink_hits
        .iter()
        .map(|hit| SinkHitJson {
            block: hit.block_addr,
            block_hex: format!("0x{:x}", hit.block_addr),
            op_idx: hit.op_idx,
            op: ssa_op_to_info(&hit.op),
            tainted_vars: hit
                .tainted_vars
                .iter()
                .map(|(var, labels)| TaintedVarJson {
                    var: var.display_name(),
                    labels: labels_to_strings(labels),
                })
                .collect(),
        })
        .collect::<Vec<_>>();

    let report = TaintReportJson {
        sources,
        sinks,
        sink_hits,
        tainted_vars,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Convert block to SSA and return JSON representation.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_to_ssa_json(
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

    // Convert to SSA
    let ssa_block = r2ssa::block::to_ssa(blk, disasm);

    // Convert ops to JSON-serializable format
    let ops_info: Vec<SSAOpInfo> = ssa_block.ops.iter().map(ssa_op_to_info).collect();

    match serde_json::to_string_pretty(&ops_info) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Def-use analysis info for JSON output.
#[derive(Serialize)]
struct DefUseInfoJson {
    inputs: Vec<String>,
    outputs: Vec<String>,
    live: Vec<String>,
}

/// Get def-use analysis for block as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_defuse_json(
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

    // Convert to SSA
    let ssa_block = r2ssa::block::to_ssa(blk, disasm);

    // Compute def-use chains
    let info = r2ssa::def_use(&ssa_block);

    let json_info = DefUseInfoJson {
        inputs: info.inputs.iter().cloned().collect(),
        outputs: info.outputs.iter().cloned().collect(),
        live: info.live.iter().cloned().collect(),
    };

    match serde_json::to_string_pretty(&json_info) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// Function-Level SSA Functions
// ============================================================================

/// Phi node info for JSON output.
#[derive(Serialize)]
struct PhiNodeJson {
    dst: String,
    sources: Vec<(String, String)>, // (predecessor_addr_hex, var_name)
}

/// SSA block info for JSON output.
#[derive(Serialize)]
struct SSABlockJson {
    addr: u64,
    addr_hex: String,
    size: u32,
    phis: Vec<PhiNodeJson>,
    ops: Vec<SSAOpInfo>,
}

/// Function SSA info for JSON output.
#[derive(Serialize)]
struct SSAFunctionJson {
    name: Option<String>,
    entry: u64,
    entry_hex: String,
    num_blocks: usize,
    blocks: Vec<SSABlockJson>,
}

fn build_ssa_function_json(ssa_func: &r2ssa::SSAFunction) -> SSAFunctionJson {
    let mut json_blocks = Vec::new();
    for &addr in ssa_func.block_addrs() {
        if let Some(block) = ssa_func.get_block(addr) {
            let phis: Vec<PhiNodeJson> = block
                .phis
                .iter()
                .map(|phi| PhiNodeJson {
                    dst: phi.dst.display_name(),
                    sources: phi
                        .sources
                        .iter()
                        .map(|(pred, var)| (format!("0x{:x}", pred), var.display_name()))
                        .collect(),
                })
                .collect();

            let ops: Vec<SSAOpInfo> = block.ops.iter().map(ssa_op_to_info).collect();

            json_blocks.push(SSABlockJson {
                addr,
                addr_hex: format!("0x{:x}", addr),
                size: block.size,
                phis,
                ops,
            });
        }
    }

    SSAFunctionJson {
        name: ssa_func.name.clone(),
        entry: ssa_func.entry,
        entry_hex: format!("0x{:x}", ssa_func.entry),
        num_blocks: ssa_func.num_blocks(),
        blocks: json_blocks,
    }
}

fn ssa_function_json_string(ssa_func: &r2ssa::SSAFunction) -> Option<String> {
    let json = build_ssa_function_json(ssa_func);
    serde_json::to_string_pretty(&json).ok()
}

/// Get function-level SSA as JSON (includes phi nodes).
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2ssa_function_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe { (*ctx).arch.as_ref() }) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let Some(json) = ssa_function_json_string(&ssa_func) else {
        return ptr::null_mut();
    };

    CString::new(json).map_or(ptr::null_mut(), |c| c.into_raw())
}

#[derive(Serialize)]
struct SSAOptStatsJson {
    iterations: usize,
    constants_propagated: usize,
    ops_simplified: usize,
    copies_propagated: usize,
    phis_simplified: usize,
    cse_replacements: usize,
    dce_removed_ops: usize,
    dce_removed_phis: usize,
}

#[derive(Serialize)]
struct SSAFunctionOptJson {
    optimized: bool,
    stats: SSAOptStatsJson,
    function: SSAFunctionJson,
}

/// Get optimized function-level SSA as JSON (includes phi nodes).
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2ssa_function_opt_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    let mut ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(
        &r2il_blocks,
        unsafe { (*ctx).arch.as_ref() },
    ) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let stats = ssa_func.optimize(&r2ssa::OptimizationConfig::default());
    let function = build_ssa_function_json(&ssa_func);

    let report = SSAFunctionOptJson {
        optimized: true,
        stats: SSAOptStatsJson {
            iterations: stats.iterations,
            constants_propagated: stats.constants_propagated,
            ops_simplified: stats.ops_simplified,
            copies_propagated: stats.copies_propagated,
            phis_simplified: stats.phis_simplified,
            cse_replacements: stats.cse_replacements,
            dce_removed_ops: stats.dce_removed_ops,
            dce_removed_phis: stats.dce_removed_phis,
        },
        function,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Definition location for JSON output.
#[derive(Serialize)]
struct DefLocationJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
}

/// Use location for JSON output.
#[derive(Serialize)]
struct UseLocationJson {
    block: u64,
    block_hex: String,
    op_idx: usize,
}

/// Function-wide def-use info for JSON output.
#[derive(Serialize)]
struct FunctionDefUseJson {
    definitions: std::collections::HashMap<String, DefLocationJson>,
    uses: std::collections::HashMap<String, Vec<UseLocationJson>>,
    live_in: std::collections::HashMap<String, Vec<String>>,  // block_hex -> vars
    live_out: std::collections::HashMap<String, Vec<String>>, // block_hex -> vars
}

/// Get function-wide def-use analysis as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2ssa_defuse_function_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe { (*ctx).arch.as_ref() }) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    // Collect definitions and uses across all blocks
    let mut definitions = std::collections::HashMap::new();
    let mut uses: std::collections::HashMap<String, Vec<UseLocationJson>> = std::collections::HashMap::new();
    let mut live_in = std::collections::HashMap::new();
    let mut live_out = std::collections::HashMap::new();

    for &addr in ssa_func.block_addrs() {
        if let Some(block) = ssa_func.get_block(addr) {
            let block_hex = format!("0x{:x}", addr);
            let mut block_inputs = Vec::new();
            let mut block_outputs = Vec::new();
            let mut defined_in_block = std::collections::HashSet::new();

            // Process phi nodes
            for phi in &block.phis {
                let dst_name = phi.dst.display_name();
                definitions.insert(dst_name.clone(), DefLocationJson {
                    block: addr,
                    block_hex: block_hex.clone(),
                    op_idx: 0, // Phi nodes are at the start
                });
                defined_in_block.insert(dst_name.clone());
                block_outputs.push(dst_name);

                // Sources are uses
                for (_pred, src) in &phi.sources {
                    let src_name = src.display_name();
                    uses.entry(src_name.clone()).or_default().push(UseLocationJson {
                        block: addr,
                        block_hex: block_hex.clone(),
                        op_idx: 0,
                    });
                }
            }

            // Process ops
            for (op_idx, op) in block.ops.iter().enumerate() {
                // Record definition
                if let Some(dst) = op.dst() {
                    let dst_name = dst.display_name();
                    definitions.insert(dst_name.clone(), DefLocationJson {
                        block: addr,
                        block_hex: block_hex.clone(),
                        op_idx: op_idx + 1, // +1 because phi nodes are at 0
                    });
                    defined_in_block.insert(dst_name.clone());
                    block_outputs.push(dst_name);
                }

                // Record uses
                for src in op.sources() {
                    let src_name = src.display_name();
                    uses.entry(src_name.clone()).or_default().push(UseLocationJson {
                        block: addr,
                        block_hex: block_hex.clone(),
                        op_idx: op_idx + 1,
                    });

                    // If used before defined in this block, it's a live-in
                    if !defined_in_block.contains(&src_name) && !block_inputs.contains(&src_name) {
                        block_inputs.push(src_name);
                    }
                }
            }

            live_in.insert(block_hex.clone(), block_inputs);
            live_out.insert(block_hex, block_outputs);
        }
    }

    let json = FunctionDefUseJson {
        definitions,
        uses,
        live_in,
        live_out,
    };

    match serde_json::to_string_pretty(&json) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Dominator tree info for JSON output.
#[derive(Serialize)]
struct DomTreeJson {
    entry: u64,
    entry_hex: String,
    idom: std::collections::HashMap<String, String>,  // block_hex -> idom_hex
    children: std::collections::HashMap<String, Vec<String>>,  // block_hex -> children_hex
    dominance_frontier: std::collections::HashMap<String, Vec<String>>,  // block_hex -> frontier_hex
    depth: std::collections::HashMap<String, usize>,  // block_hex -> depth
}

/// Get dominator tree as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2ssa_domtree_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function to get dominator tree
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe { (*ctx).arch.as_ref() }) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let domtree = ssa_func.domtree();

    // Build JSON representation
    let mut idom_map = std::collections::HashMap::new();
    let mut children_map = std::collections::HashMap::new();
    let mut frontier_map = std::collections::HashMap::new();
    let mut depth_map = std::collections::HashMap::new();

    for &addr in ssa_func.block_addrs() {
        let block_hex = format!("0x{:x}", addr);

        // Immediate dominator
        if let Some(idom) = domtree.idom(addr) {
            idom_map.insert(block_hex.clone(), format!("0x{:x}", idom));
        }

        // Children
        let children: Vec<String> = domtree.children(addr)
            .iter()
            .map(|c| format!("0x{:x}", c))
            .collect();
        children_map.insert(block_hex.clone(), children);

        // Dominance frontier
        let frontier: Vec<String> = domtree.frontier(addr)
            .map(|f| format!("0x{:x}", f))
            .collect();
        frontier_map.insert(block_hex.clone(), frontier);

        // Depth
        depth_map.insert(block_hex, domtree.depth(addr));
    }

    let json = DomTreeJson {
        entry: ssa_func.entry,
        entry_hex: format!("0x{:x}", ssa_func.entry),
        idom: idom_map,
        children: children_map,
        dominance_frontier: frontier_map,
        depth: depth_map,
    };

    match serde_json::to_string_pretty(&json) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Backward slice info for JSON output.
#[derive(Serialize)]
struct BackwardSliceJson {
    sink_var: String,
    ops: Vec<SliceOpJson>,
    blocks: Vec<String>,
}

#[derive(Serialize)]
struct SliceOpJson {
    #[serde(rename = "type")]
    op_type: String,
    block: String,
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    op_str: Option<String>,
}

/// Compute backward slice from a variable name at a given block.
/// var_name should be in format "name_version" (e.g. "rax_3").
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2ssa_backward_slice_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    var_name: *const c_char,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 || var_name.is_null() {
        return ptr::null_mut();
    }

    let var_name_str = match unsafe { CStr::from_ptr(var_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe { (*ctx).arch.as_ref() }) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    // Find the actual SSAVar with matching display_name (which handles reg: prefix and case)
    let target_display_name = var_name_str.to_string();
    let sink_var = {
        let mut found: Option<r2ssa::SSAVar> = None;
        'outer: for &addr in ssa_func.block_addrs() {
            if let Some(block) = ssa_func.get_block(addr) {
                // Check phi destinations
                for phi in &block.phis {
                    if phi.dst.display_name() == target_display_name {
                        found = Some(phi.dst.clone());
                        break 'outer;
                    }
                }
                // Check op destinations
                for op in &block.ops {
                    if let Some(dst) = op.dst() {
                        if dst.display_name() == target_display_name {
                            found = Some(dst.clone());
                            break 'outer;
                        }
                    }
                }
            }
        }
        match found {
            Some(v) => v,
            None => {
                // Variable not found - return error JSON
                let error_json = format!(
                    r#"{{"error": "Variable '{}' not found"}}"#,
                    var_name_str
                );
                return CString::new(error_json).map_or(ptr::null_mut(), |c| c.into_raw());
            }
        }
    };

    // Compute backward slice
    let slice = r2ssa::backward_slice_from_var(&ssa_func, &sink_var);

    // Convert to JSON
    let mut ops_json = Vec::new();
    for op_ref in &slice.ops {
        match op_ref {
            r2ssa::SliceOpRef::Phi { block_addr, phi_idx } => {
                let mut op_str = None;
                if let Some(block) = ssa_func.get_block(*block_addr) {
                    if let Some(phi) = block.phis.get(*phi_idx) {
                        op_str = Some(format!("{} = phi(...)", phi.dst.display_name()));
                    }
                }
                ops_json.push(SliceOpJson {
                    op_type: "phi".to_string(),
                    block: format!("0x{:x}", block_addr),
                    index: *phi_idx,
                    op_str,
                });
            }
            r2ssa::SliceOpRef::Op { block_addr, op_idx } => {
                let mut op_str = None;
                if let Some(block) = ssa_func.get_block(*block_addr) {
                    if let Some(op) = block.ops.get(*op_idx) {
                        op_str = Some(format!("{:?}", op));
                    }
                }
                ops_json.push(SliceOpJson {
                    op_type: "op".to_string(),
                    block: format!("0x{:x}", block_addr),
                    index: *op_idx,
                    op_str,
                });
            }
        }
    }

    let blocks_hex: Vec<String> = slice.blocks.iter().map(|b| format!("0x{:x}", b)).collect();

    let json = BackwardSliceJson {
        sink_var: var_name_str.to_string(),
        ops: ops_json,
        blocks: blocks_hex,
    };

    match serde_json::to_string_pretty(&json) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// Architecture Helpers
// ============================================================================

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

// ============================================================================
// Symbolic Execution Functions
// ============================================================================

use z3::{Config, Context};

static MERGE_STATES: AtomicBool = AtomicBool::new(false);

fn merge_states_enabled() -> bool {
    MERGE_STATES.load(Ordering::Relaxed)
}

fn seed_symbolic_state<'ctx>(
    state: &mut r2sym::SymState<'ctx>,
    func: &r2ssa::SSAFunction,
    arch: Option<&ArchSpec>,
) {
    let Some(arch) = arch else {
        return;
    };

    let arch_name = arch.name.to_ascii_lowercase();
    let (arg_regs, stack_regs, stack_value) = if arch_name == "x86-64"
        || arch_name == "x86_64"
        || (arch_name == "x86" && arch.addr_size == 8)
    {
        (
            [
                "RDI", "RSI", "RDX", "RCX", "R8", "R9", "EDI", "ESI", "EDX", "ECX", "R8D", "R9D",
            ]
            .as_slice(),
            ["RSP", "RBP"].as_slice(),
            0x7fff_ffff_0000u64,
        )
    } else if arch_name == "x86" {
        (
            ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI"].as_slice(),
            ["ESP", "EBP"].as_slice(),
            0x7fff_0000u64,
        )
    } else {
        return;
    };

    let mut seen = HashSet::new();
    let mut maybe_seed = |var: &r2ssa::SSAVar| {
        if !var.is_register() || var.version != 0 {
            return;
        }

        let base_name = var.name.strip_prefix("reg:").unwrap_or(&var.name);
        let base = base_name.to_ascii_uppercase();
        let reg_name = var.display_name();
        if !seen.insert(reg_name.clone()) {
            return;
        }

        let bits = var.size * 8;
        if stack_regs.contains(&base.as_str()) {
            state.set_concrete(&reg_name, stack_value, bits);
            return;
        }

        if arg_regs.contains(&base.as_str()) {
            let sym_name = base_name.to_ascii_lowercase();
            state.make_symbolic_named(&reg_name, &sym_name, bits);
        }
    };

    for block in func.blocks() {
        for phi in &block.phis {
            maybe_seed(&phi.dst);
            for (_, src) in &phi.sources {
                maybe_seed(src);
            }
        }

        for op in &block.ops {
            if let Some(dst) = op.dst() {
                maybe_seed(dst);
            }
            for src in op.sources() {
                maybe_seed(src);
            }
        }
    }
}

/// Opaque symbolic state handle for C API.
/// Each context owns its own Z3 context for thread safety.
pub struct R2SymContext {
    _config: Config,
    // _context: Context, // Removed in z3 0.19
    entry_pc: u64,
    error: Option<CString>,
}

/// Initialize the symbolic execution engine.
/// Returns 1 on success, 0 on failure.
/// Note: This is a no-op as contexts are created per-state.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_init() -> i32 {
    1
}

/// Clean up the symbolic execution engine.
/// Note: This is a no-op as contexts are cleaned up with their states.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_fini() {
    // No-op
}

/// Create a new symbolic state starting at the given address.
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_state_new(entry_pc: u64) -> *mut R2SymContext {
    let config = Config::new();
    // Context is thread-local in 0.19

    Box::into_raw(Box::new(R2SymContext {
        _config: config,
        entry_pc,
        error: None,
    }))
}

/// Free a symbolic state.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_state_free(state: *mut R2SymContext) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state)) }
    }
}

/// Get the last error from symbolic execution.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_error(state: *const R2SymContext) -> *const c_char {
    if state.is_null() {
        return ptr::null();
    }

    unsafe {
        match &(*state).error {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Get the current PC from the symbolic state.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_get_pc(state: *const R2SymContext) -> u64 {
    if state.is_null() {
        return 0;
    }
    unsafe { (*state).entry_pc }
}

/// Check if the symbolic execution engine is available.
/// Returns 1 if available, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_available() -> i32 {
    1
}

/// Get whether state merging is enabled for symbolic execution.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_merge_is_enabled() -> i32 {
    if merge_states_enabled() {
        1
    } else {
        0
    }
}

/// Enable or disable state merging for symbolic execution.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_merge_set_enabled(enabled: i32) {
    MERGE_STATES.store(enabled != 0, Ordering::Relaxed);
}

/// Symbolic execution summary for JSON output.
#[derive(Serialize)]
struct SymExecSummary {
    paths_explored: usize,
    paths_feasible: usize,
    paths_pruned: usize,
    max_depth: usize,
    states_explored: usize,
    time_ms: u64,
}

/// Symbolically analyze a function and return path summary as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_function(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    entry_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let _disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    // Create Z3 context and run symbolic execution
    // Note: z3 0.19 uses thread-local context
    let z3_ctx = Context::thread_local();

    // Wrap exploration in catch_unwind to handle z3 context issues gracefully
    let explore_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut initial_state = r2sym::SymState::new(&z3_ctx, entry_addr);
        seed_symbolic_state(&mut initial_state, &ssa_func, ctx_ref.arch.as_ref());
        let config = r2sym::ExploreConfig {
            max_states: 100,
            max_depth: 200,
            merge_states: merge_states_enabled(),
            timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        };

        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, config);
        let results = explorer.explore(&ssa_func, initial_state);
        let stats = explorer.stats().clone();
        (results, stats)
    }));

    let (results, stats) = match explore_result {
        Ok(r) => r,
        Err(_) => {
            let error_msg = r#"{"error": "symbolic execution failed (z3 context error)"}"#;
            return CString::new(error_msg).map_or(ptr::null_mut(), |c| c.into_raw());
        }
    };

    // Build summary
    let feasible_count = results.iter().filter(|r| r.feasible).count();

    let summary = SymExecSummary {
        paths_explored: stats.paths_completed,
        paths_feasible: feasible_count,
        paths_pruned: stats.paths_pruned,
        max_depth: stats.max_depth_reached,
        states_explored: stats.states_explored,
        time_ms: stats.total_time.as_millis() as u64,
    };

    match serde_json::to_string_pretty(&summary) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Symbolic state info for JSON output.
#[derive(Serialize)]
struct SymStateInfo {
    pc: u64,
    depth: usize,
    num_constraints: usize,
    registers: std::collections::HashMap<String, String>,
}

/// Get symbolic state as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_state_json(state: *const R2SymContext) -> *mut c_char {
    if state.is_null() {
        return ptr::null_mut();
    }

    let state_ref = unsafe { &*state };

    // Build state info
    let info = SymStateInfo {
        pc: state_ref.entry_pc,
        depth: 0,
        num_constraints: 0,
        registers: std::collections::HashMap::new(),
    };

    match serde_json::to_string_pretty(&info) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Path info for JSON output.
#[derive(Serialize)]
struct PathInfo {
    path_id: usize,
    feasible: bool,
    depth: usize,
    exit_status: String,
    final_pc: String,
    num_constraints: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<PathSolution>,
}

/// Concrete solution for a path.
#[derive(Serialize)]
struct PathSolution {
    /// Concrete input values that satisfy path constraints.
    inputs: std::collections::HashMap<String, String>,
    /// Register values at path end.
    registers: std::collections::HashMap<String, String>,
}

/// Explore paths in a function and return detailed results as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_paths(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    entry_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let _disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    // Create Z3 context and run symbolic execution
    // Note: z3 0.19 uses thread-local context
    let z3_ctx = Context::thread_local();

    // Wrap exploration in catch_unwind to handle z3 context issues gracefully
    let explore_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut initial_state = r2sym::SymState::new(&z3_ctx, entry_addr);
        seed_symbolic_state(&mut initial_state, &ssa_func, ctx_ref.arch.as_ref());
        let config = r2sym::ExploreConfig {
            max_states: 100,
            max_depth: 200,
            merge_states: merge_states_enabled(),
            timeout: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        };

        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, config);
        let results = explorer.explore(&ssa_func, initial_state);
        (results, explorer)
    }));

    let (results, explorer) = match explore_result {
        Ok(r) => r,
        Err(_) => {
            let error_msg = r#"[{"error": "symbolic execution failed (z3 context error)"}]"#;
            return CString::new(error_msg).map_or(ptr::null_mut(), |c| c.into_raw());
        }
    };

    // Build path info with solutions
    let paths: Vec<PathInfo> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            // Try to solve the path and get concrete values
            let solution = if r.feasible {
                explorer.solve_path(r).map(|solved| PathSolution {
                    inputs: solved
                        .inputs
                        .into_iter()
                        .map(|(k, v)| (k, format!("0x{:x}", v)))
                        .collect(),
                    registers: solved
                        .registers
                        .into_iter()
                        .filter(|(name, _)| {
                            // Filter to show only interesting registers (not temporaries)
                            !name.starts_with("tmp:") && !name.contains("_0")
                        })
                        .map(|(k, v)| (k, format!("0x{:x}", v)))
                        .collect(),
                })
            } else {
                None
            };

            PathInfo {
                path_id: i,
                feasible: r.feasible,
                depth: r.depth,
                exit_status: format!("{:?}", r.exit_status),
                final_pc: format!("0x{:x}", r.final_pc()),
                num_constraints: r.num_constraints(),
                solution,
            }
        })
        .collect();

    match serde_json::to_string_pretty(&paths) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// CFG Functions
// ============================================================================

/// Generate ASCII CFG for a function.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2cfg_function_ascii(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build CFG
    let cfg = match r2ssa::CFG::from_blocks(&r2il_blocks) {
        Some(c) => c,
        None => return ptr::null_mut(),
    };

    // Render ASCII
    let output = render_cfg_ascii(&cfg, disasm);

    CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Render a CFG as ASCII art.
fn render_cfg_ascii(cfg: &r2ssa::CFG, disasm: &r2sleigh_lift::Disassembler) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    // Get blocks in order (reverse postorder for better visualization)
    let block_addrs = cfg.reverse_postorder();

    if block_addrs.is_empty() {
        return "Empty CFG\n".to_string();
    }

    // Render each block
    for addr in &block_addrs {
        if let Some(block) = cfg.get_block(*addr) {
            // Block header
            let is_entry = cfg.entry == *addr;
            let entry_marker = if is_entry { " [entry]" } else { "" };
            let _ = writeln!(output, "┌─────────────────────────────────────────────────┐");
            let _ = writeln!(output, "│ 0x{:x}{:<30} │", addr, entry_marker);
            let _ = writeln!(output, "├─────────────────────────────────────────────────┤");

            // Show a few representative operations
            let ops_to_show = std::cmp::min(5, block.ops.len());
            for op in block.ops.iter().take(ops_to_show) {
                let op_str = format_r2il_op_short(op, disasm);
                let truncated = if op_str.len() > 45 {
                    format!("{}...", &op_str[..42])
                } else {
                    op_str
                };
                let _ = writeln!(output, "│ {:<47} │", truncated);
            }
            if block.ops.len() > ops_to_show {
                let _ = writeln!(output, "│ ... ({} more ops)                               │", block.ops.len() - ops_to_show);
            }

            // Block terminator
            let term_str = match &block.terminator {
                r2ssa::cfg::BlockTerminator::Fallthrough { next } => format!("→ 0x{:x}", next),
                r2ssa::cfg::BlockTerminator::Branch { target } => format!("jmp 0x{:x}", target),
                r2ssa::cfg::BlockTerminator::ConditionalBranch { true_target, false_target } => {
                    format!("jcc t:0x{:x} f:0x{:x}", true_target, false_target)
                }
                r2ssa::cfg::BlockTerminator::Return => "ret".to_string(),
                r2ssa::cfg::BlockTerminator::Call { target, .. } => format!("call 0x{:x}", target),
                r2ssa::cfg::BlockTerminator::IndirectBranch => "jmp [reg]".to_string(),
                r2ssa::cfg::BlockTerminator::IndirectCall { .. } => "call [reg]".to_string(),
                r2ssa::cfg::BlockTerminator::None => "???".to_string(),
            };
            let _ = writeln!(output, "│ {:<47} │", term_str);
            let _ = writeln!(output, "└─────────────────────────────────────────────────┘");

            // Draw edges
            match &block.terminator {
                r2ssa::cfg::BlockTerminator::ConditionalBranch { true_target, false_target } => {
                    let _ = writeln!(output, "        │ t         f │");
                    let _ = writeln!(output, "        ├─────┐ ┌─────┤");
                    let _ = writeln!(output, "        v     │ │     v");
                    let _ = writeln!(output, "   [0x{:x}]    [0x{:x}]", true_target, false_target);
                }
                r2ssa::cfg::BlockTerminator::Branch { target } => {
                    let _ = writeln!(output, "        │");
                    let _ = writeln!(output, "        v");
                    let _ = writeln!(output, "   [0x{:x}]", target);
                }
                r2ssa::cfg::BlockTerminator::Fallthrough { next } => {
                    let _ = writeln!(output, "        │");
                    let _ = writeln!(output, "        v");
                    let _ = writeln!(output, "   [0x{:x}]", next);
                }
                _ => {}
            }
            let _ = writeln!(output);
        }
    }

    output
}

/// Format an R2ILOp in a short form for display.
fn format_r2il_op_short(op: &R2ILOp, disasm: &r2sleigh_lift::Disassembler) -> String {
    match op {
        R2ILOp::Copy { dst, src } => {
            format!("{} = {}", disasm.format_varnode(dst), disasm.format_varnode(src))
        }
        R2ILOp::Load { dst, addr, .. } => {
            format!("{} = [{}]", disasm.format_varnode(dst), disasm.format_varnode(addr))
        }
        R2ILOp::Store { addr, val, .. } => {
            format!("[{}] = {}", disasm.format_varnode(addr), disasm.format_varnode(val))
        }
        R2ILOp::IntAdd { dst, a, b } => {
            format!("{} = {} + {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntSub { dst, a, b } => {
            format!("{} = {} - {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntAnd { dst, a, b } => {
            format!("{} = {} & {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntOr { dst, a, b } => {
            format!("{} = {} | {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntXor { dst, a, b } => {
            format!("{} = {} ^ {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntEqual { dst, a, b } => {
            format!("{} = {} == {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::IntLess { dst, a, b } => {
            format!("{} = {} < {}", disasm.format_varnode(dst), disasm.format_varnode(a), disasm.format_varnode(b))
        }
        R2ILOp::Branch { target } => {
            format!("jmp {}", disasm.format_varnode(target))
        }
        R2ILOp::CBranch { cond, target } => {
            format!("if {} jmp {}", disasm.format_varnode(cond), disasm.format_varnode(target))
        }
        R2ILOp::Call { target } => {
            format!("call {}", disasm.format_varnode(target))
        }
        R2ILOp::Return { .. } => "ret".to_string(),
        R2ILOp::Nop => "nop".to_string(),
        _ => format!("{:?}", op).chars().take(40).collect(),
    }
}

/// CFG JSON representation.
#[derive(Serialize)]
struct CFGJson {
    entry: u64,
    num_blocks: usize,
    blocks: Vec<CFGBlockJson>,
    edges: Vec<CFGEdgeJson>,
}

#[derive(Serialize)]
struct CFGBlockJson {
    addr: u64,
    size: u32,
    num_ops: usize,
    terminator: String,
    successors: Vec<u64>,
}

#[derive(Serialize)]
struct CFGEdgeJson {
    from: u64,
    to: u64,
    edge_type: String,
}

/// Get CFG as JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2cfg_function_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build CFG
    let cfg = match r2ssa::CFG::from_blocks(&r2il_blocks) {
        Some(c) => c,
        None => return ptr::null_mut(),
    };

    // Build JSON representation
    let mut json_blocks = Vec::new();
    let mut json_edges = Vec::new();

    for addr in cfg.block_addrs() {
        if let Some(block) = cfg.get_block(addr) {
            let term_str = match &block.terminator {
                r2ssa::cfg::BlockTerminator::Fallthrough { .. } => "fallthrough",
                r2ssa::cfg::BlockTerminator::Branch { .. } => "branch",
                r2ssa::cfg::BlockTerminator::ConditionalBranch { .. } => "conditional",
                r2ssa::cfg::BlockTerminator::Return => "return",
                r2ssa::cfg::BlockTerminator::Call { .. } => "call",
                r2ssa::cfg::BlockTerminator::IndirectBranch => "indirect_branch",
                r2ssa::cfg::BlockTerminator::IndirectCall { .. } => "indirect_call",
                r2ssa::cfg::BlockTerminator::None => "none",
            };

            json_blocks.push(CFGBlockJson {
                addr,
                size: block.size,
                num_ops: block.ops.len(),
                terminator: term_str.to_string(),
                successors: cfg.successors(addr),
            });

            // Add edges
            for succ in cfg.successors(addr) {
                let edge_type = cfg.edge_type(addr, succ)
                    .map(|e| format!("{:?}", e))
                    .unwrap_or_else(|| "unknown".to_string());
                json_edges.push(CFGEdgeJson {
                    from: addr,
                    to: succ,
                    edge_type,
                });
            }
        }
    }

    let cfg_json = CFGJson {
        entry: cfg.entry,
        num_blocks: cfg.num_blocks(),
        blocks: json_blocks,
        edges: json_edges,
    };

    match serde_json::to_string_pretty(&cfg_json) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// Decompiler Functions
// ============================================================================

/// Decompile a function given its SSA representation.
/// Returns C code as a string. Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2dec_function(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    func_name: *const c_char,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let _disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let func_name_str = if func_name.is_null() {
        "func".to_string()
    } else {
        unsafe {
            CStr::from_ptr(func_name)
                .to_str()
                .unwrap_or("func")
                .to_string()
        }
    };

    // Collect R2IL blocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
        Some(f) => f.with_name(&func_name_str),
        None => return ptr::null_mut(),
    };

    // Create decompiler with default config
    let config = r2dec::DecompilerConfig::default();
    let decompiler = r2dec::Decompiler::new(config);

    // Decompile to C code
    let output = decompiler.decompile(&ssa_func);

    CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Decompile a single basic block to C code.
/// Returns C code as a string. Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2dec_block(
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

    // Convert to SSA
    let ssa_block = r2ssa::block::to_ssa(blk, disasm);

    // Build statements from SSA ops
    let expr_builder = r2dec::ExpressionBuilder::new(64); // Assume 64-bit
    let mut stmts = Vec::new();

    for op in &ssa_block.ops {
        if let Some(stmt) = expr_builder.op_to_stmt(op) {
            stmts.push(stmt);
        }
    }

    // Generate C code for statements
    let mut codegen = r2dec::CodeGenerator::new(r2dec::CodeGenConfig::default());
    let mut output = String::new();
    for stmt in &stmts {
        output.push_str(&codegen.generate_stmt(stmt));
        output.push('\n');
    }

    CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Get the C AST for a block as JSON.
/// Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2dec_block_ast_json(
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

    // Convert to SSA
    let ssa_block = r2ssa::block::to_ssa(blk, disasm);

    // Build statements from SSA ops
    let expr_builder = r2dec::ExpressionBuilder::new(64);
    let mut stmts: Vec<r2dec::CStmt> = Vec::new();

    for op in &ssa_block.ops {
        if let Some(stmt) = expr_builder.op_to_stmt(op) {
            stmts.push(stmt);
        }
    }

    match serde_json::to_string_pretty(&stmts) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
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

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_init_x86_64() {
        let arch_cstr = CString::new("x86-64").unwrap();
        let ctx_ptr = r2il_arch_init(arch_cstr.as_ptr());
        if ctx_ptr.is_null() {
             panic!("r2il_arch_initreturnedNULL");
        }
        let ctx = unsafe { &*ctx_ptr };
        
        if let Some(err) = &ctx.error {
             // panic!("Contexthaserror:{:?}",err);
             // It might error if sleigh-config data is bad, but we want to see it
             println!("Contextwarn/error:{:?}",err);
        }
        // If we have an error, we might still have a partial context or it failed completely
        // r2il_arch_init returns context with error set if loading failed
        
        if ctx.arch.is_none() {
            panic!("ArchisNone(loadingfailed)");
        }
        
        let profile_ptr = r2il_get_reg_profile(ctx_ptr);
        assert!(!profile_ptr.is_null());
        let profile = unsafe { CStr::from_ptr(profile_ptr).to_str().unwrap() };
        println!("Profile: {}", profile);
        assert!(profile.contains("=PC\tRIP"));
        std::fs::write("/tmp/sleigh_profile.dr", profile).expect("Unable to write profile");
        
        r2il_string_free(profile_ptr);
        r2il_free(ctx_ptr);
    }
}
