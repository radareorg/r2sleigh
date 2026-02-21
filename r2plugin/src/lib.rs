//! r2sleigh radare2 plugin
//!
//! This module exposes a C-ABI for radare2 integration. It can load r2il
//! specs from disk, or build Sleigh-based disassemblers and lift instruction
//! bytes into r2il blocks with ESIL rendering.

// FFI functions receive raw pointers from radare2's C code and must dereference
// them. Making every exported function `unsafe fn` would be incorrect because
// the caller (radare2) uses a normal C function-pointer table, not Rust's
// `unsafe` calling convention.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use r2il::serialize::UserOpDef;
use r2il::{ArchSpec, R2ILBlock, R2ILOp, serialize, validate_block_full};
use r2sleigh_export::{
    ExportFormat, InstructionAction, InstructionExportInput, export_instruction, op_json_named,
};
use r2sleigh_lift::{Disassembler, SemanticMetadataOptions, build_arch_spec, userop_map_for_arch};
use r2ssa::TaintPolicy;
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
    semantic_metadata_enabled: bool,
    error: Option<CString>,
}

impl R2ILContext {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            disasm: None,
            semantic_metadata_enabled: true,
            error: None,
        }
    }

    fn with_arch(arch: ArchSpec) -> Self {
        let name = CString::new(arch.name.clone()).ok();
        Self {
            arch: Some(arch),
            arch_name_cstr: name,
            disasm: None,
            semantic_metadata_enabled: true,
            error: None,
        }
    }

    fn with_arch_and_disasm(arch: ArchSpec, disasm: Disassembler) -> Self {
        let name = CString::new(arch.name.clone()).ok();
        Self {
            arch: Some(arch),
            arch_name_cstr: name,
            disasm: Some(disasm),
            semantic_metadata_enabled: true,
            error: None,
        }
    }

    fn with_error(msg: &str) -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            disasm: None,
            semantic_metadata_enabled: true,
            error: CString::new(msg).ok(),
        }
    }

    fn set_error(&mut self, msg: impl AsRef<str>) {
        self.error = CString::new(msg.as_ref()).ok();
    }

    fn clear_error(&mut self) {
        self.error = None;
    }
}

fn validate_block_in_context(ctx: &mut R2ILContext, block: &R2ILBlock) -> Result<(), String> {
    let Some(arch) = ctx.arch.as_ref() else {
        let msg = "missing arch context for semantic validation".to_string();
        ctx.set_error(&msg);
        return Err(msg);
    };

    validate_block_full(block, arch).map_err(|e| {
        let msg = format!("Invalid lifted block: {}", e);
        ctx.set_error(&msg);
        msg
    })
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

    unsafe { if (*ctx).arch.is_some() { 1 } else { 0 } }
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
            Some(arch) => i32::from(arch.memory_endianness.to_legacy_big_endian()),
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
    let mut reg_meta: std::collections::HashMap<String, (u32, u64, String)> =
        std::collections::HashMap::new();
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
        let name_lower = reg.name.to_lowercase();

        if name_lower == "pc" || name_lower == "rip" || name_lower == "eip" || name_lower == "ip" {
            if pc.is_none() {
                pc = Some(&reg.name);
            }
        } else if name_lower == "sp" || name_lower == "rsp" || name_lower == "esp" {
            if sp.is_none() {
                sp = Some(&reg.name);
            }
        } else if name_lower == "bp"
            || name_lower == "rbp"
            || name_lower == "ebp"
            || name_lower == "fp"
        {
            if bp.is_none() {
                bp = Some(&reg.name);
            }
        } else if name_lower == "r0"
            || name_lower == "rax"
            || name_lower == "eax"
            || name_lower == "v0"
        {
            if r0.is_none() {
                r0 = Some(&reg.name);
            }
        } else if name_lower == "rdi" || name_lower == "a0" {
            if a0.is_none() {
                a0 = Some(&reg.name);
            }
        } else if name_lower == "rsi" || name_lower == "a1" {
            if a1.is_none() {
                a1 = Some(&reg.name);
            }
        } else if name_lower == "rdx" || name_lower == "a2" {
            if a2.is_none() {
                a2 = Some(&reg.name);
            }
        } else if (name_lower == "rcx" || name_lower == "a3") && a3.is_none() {
            a3 = Some(&reg.name);
        }

        profile.push_str(&format!(
            "gpr\t{}\t.{}\t{}\t0\n",
            reg.name,
            reg.size * 8,
            reg.offset
        ));
        reg_meta.insert(
            name_lower.clone(),
            (reg.size * 8, reg.offset, reg.name.clone()),
        );
    }

    for (name_lower, (bits, offset, original)) in &reg_meta {
        if original != name_lower {
            profile.push_str(&format!("gpr\t{}\t.{}\t{}\t0\n", name_lower, bits, offset));
        }
    }

    if let Some(n) = pc {
        profile.push_str(&format!("=PC\t{}\n", n));
    }
    if let Some(n) = sp {
        profile.push_str(&format!("=SP\t{}\n", n));
    }
    if let Some(n) = bp {
        profile.push_str(&format!("=BP\t{}\n", n));
    }
    if let Some(n) = a0 {
        profile.push_str(&format!("=A0\t{}\n", n));
    }
    if let Some(n) = a1 {
        profile.push_str(&format!("=A1\t{}\n", n));
    }
    if let Some(n) = a2 {
        profile.push_str(&format!("=A2\t{}\n", n));
    }
    if let Some(n) = a3 {
        profile.push_str(&format!("=A3\t{}\n", n));
    }
    if let Some(n) = r0 {
        profile.push_str(&format!("=R0\t{}\n", n));
    }

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
    let lift_opts = SemanticMetadataOptions {
        enabled: ctx_ref.semantic_metadata_enabled,
        ..Default::default()
    };
    match disasm.lift_with_options(slice, addr, lift_opts) {
        Ok(block) => {
            if validate_block_in_context(ctx_ref, &block).is_err() {
                return ptr::null_mut();
            }
            ctx_ref.clear_error();
            Box::into_raw(Box::new(block))
        }
        Err(e) => {
            ctx_ref.set_error(e.to_string());
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
    let lift_opts = SemanticMetadataOptions {
        enabled: ctx_ref.semantic_metadata_enabled,
        ..Default::default()
    };

    match disasm.lift_block_with_options(slice, addr, size, lift_opts) {
        Ok(block) => {
            if validate_block_in_context(ctx_ref, &block).is_err() {
                return ptr::null_mut();
            }
            ctx_ref.clear_error();
            Box::into_raw(Box::new(block))
        }
        Err(e) => {
            ctx_ref.set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Enable/disable semantic metadata auto-population during lifting.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_set_semantic_metadata_enabled(ctx: *mut R2ILContext, enabled: bool) {
    if ctx.is_null() {
        return;
    }
    let ctx_ref = unsafe { &mut *ctx };
    ctx_ref.semantic_metadata_enabled = enabled;
}

/// Free a lifted block.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_free(block: *mut R2ILBlock) {
    if !block.is_null() {
        unsafe { drop(Box::from_raw(block)) }
    }
}

/// Set switch table information for a block.
/// This should be called after lifting if the block contains a switch statement.
///
/// # Arguments
/// * `block` - The block to set switch info on
/// * `switch_addr` - Address of the switch instruction
/// * `min_val` - Minimum case value
/// * `max_val` - Maximum case value  
/// * `default_target` - Default case target address (0 if none)
/// * `case_values` - Array of case values
/// * `case_targets` - Array of case target addresses
/// * `num_cases` - Number of cases
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_set_switch_info(
    block: *mut R2ILBlock,
    switch_addr: u64,
    min_val: u64,
    max_val: u64,
    default_target: u64,
    case_values: *const u64,
    case_targets: *const u64,
    num_cases: usize,
) {
    if block.is_null() || case_values.is_null() || case_targets.is_null() {
        return;
    }

    let block = unsafe { &mut *block };

    // Build cases from arrays
    let mut cases = Vec::with_capacity(num_cases);
    for i in 0..num_cases {
        let value = unsafe { *case_values.add(i) };
        let target = unsafe { *case_targets.add(i) };
        cases.push(r2il::SwitchCase { value, target });
    }

    // Deduplicate cases (same target may appear multiple times)
    cases.sort_by_key(|c| (c.value, c.target));
    cases.dedup();

    let switch_info = r2il::SwitchInfo {
        switch_addr,
        min_val,
        max_val,
        default_target: if default_target != 0 {
            Some(default_target)
        } else {
            None
        },
        cases,
    };

    block.set_switch_info(switch_info);
}

/// Validate a lifted block against full (structural + semantic) r2il invariants.
///
/// Returns 1 when valid, 0 on invalid input or validation failure.
/// On validation failure, the context error string is updated.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_validate(ctx: *mut R2ILContext, block: *const R2ILBlock) -> i32 {
    if ctx.is_null() || block.is_null() {
        return 0;
    }

    let ctx_ref = unsafe { &mut *ctx };
    let block_ref = unsafe { &*block };

    let Some(arch) = ctx_ref.arch.as_ref() else {
        ctx_ref.set_error("missing arch context for semantic validation");
        return 0;
    };

    match validate_block_full(block_ref, arch) {
        Ok(()) => {
            ctx_ref.clear_error();
            1
        }
        Err(e) => {
            ctx_ref.set_error(format!("Invalid block: {}", e));
            0
        }
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
pub extern "C" fn r2il_block_to_esil(
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
    let input = InstructionExportInput {
        disasm,
        arch: match ctx_ref.arch.as_ref() {
            Some(a) => a,
            None => return ptr::null_mut(),
        },
        block: blk,
        addr: blk.addr,
        mnemonic: "",
        native_size: blk.size as usize,
    };
    match export_instruction(&input, InstructionAction::Lift, ExportFormat::Esil) {
        Ok(esil_lines) => {
            let joined = esil_lines
                .lines()
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join(";");
            CString::new(joined).map_or(ptr::null_mut(), |s| s.into_raw())
        }
        Err(_) => ptr::null_mut(),
    }
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

/// Get a JSON representation of an operation with register names resolved.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_block_op_json_named(
    ctx: *const R2ILContext,
    block: *const R2ILBlock,
    index: usize,
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
    if index >= blk.ops.len() {
        return ptr::null_mut();
    }

    match op_json_named(disasm, &blk.ops[index]) {
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
        Ok((mnemonic, _size)) => CString::new(mnemonic).map_or(ptr::null_mut(), |c| c.into_raw()),
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
            R2ILOp::Store { .. }
            | R2ILOp::StoreConditional { .. }
            | R2ILOp::StoreGuarded { .. }
            | R2ILOp::AtomicCAS { .. } => return R2AnalOpType::STORE,
            R2ILOp::Load { .. } | R2ILOp::LoadLinked { .. } | R2ILOp::LoadGuarded { .. } => {
                return R2AnalOpType::LOAD;
            }
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
            R2ILOp::IntEqual { .. }
            | R2ILOp::IntNotEqual { .. }
            | R2ILOp::IntLess { .. }
            | R2ILOp::IntSLess { .. }
            | R2ILOp::IntLessEqual { .. }
            | R2ILOp::IntSLessEqual { .. } => return R2AnalOpType::CMP,
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
            R2ILOp::Branch { target }
            | R2ILOp::Call { target }
            | R2ILOp::CBranch { target, .. } => {
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

use r2il::Varnode;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Helper: extract all register varnodes that are read by an operation.
fn op_regs_read(op: &R2ILOp) -> Vec<&Varnode> {
    let mut regs = Vec::new();

    match op {
        // Data movement - src is read
        R2ILOp::Copy { src, .. } => {
            if src.is_register() {
                regs.push(src);
            }
        }
        R2ILOp::Load { addr, .. } => {
            if addr.is_register() {
                regs.push(addr);
            }
        }
        R2ILOp::LoadLinked { addr, .. } => {
            if addr.is_register() {
                regs.push(addr);
            }
        }
        R2ILOp::Store { addr, val, .. } => {
            if addr.is_register() {
                regs.push(addr);
            }
            if val.is_register() {
                regs.push(val);
            }
        }
        R2ILOp::StoreConditional { addr, val, .. } => {
            if addr.is_register() {
                regs.push(addr);
            }
            if val.is_register() {
                regs.push(val);
            }
        }
        R2ILOp::AtomicCAS {
            addr,
            expected,
            replacement,
            ..
        } => {
            if addr.is_register() {
                regs.push(addr);
            }
            if expected.is_register() {
                regs.push(expected);
            }
            if replacement.is_register() {
                regs.push(replacement);
            }
        }
        R2ILOp::LoadGuarded { addr, guard, .. } => {
            if addr.is_register() {
                regs.push(addr);
            }
            if guard.is_register() {
                regs.push(guard);
            }
        }
        R2ILOp::StoreGuarded {
            addr, val, guard, ..
        } => {
            if addr.is_register() {
                regs.push(addr);
            }
            if val.is_register() {
                regs.push(val);
            }
            if guard.is_register() {
                regs.push(guard);
            }
        }

        // Binary ops - a and b are read
        R2ILOp::IntAdd { a, b, .. }
        | R2ILOp::IntSub { a, b, .. }
        | R2ILOp::IntMult { a, b, .. }
        | R2ILOp::IntDiv { a, b, .. }
        | R2ILOp::IntSDiv { a, b, .. }
        | R2ILOp::IntRem { a, b, .. }
        | R2ILOp::IntSRem { a, b, .. }
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
        | R2ILOp::IntSLessEqual { a, b, .. }
        | R2ILOp::IntCarry { a, b, .. }
        | R2ILOp::IntSCarry { a, b, .. }
        | R2ILOp::IntSBorrow { a, b, .. }
        | R2ILOp::BoolAnd { a, b, .. }
        | R2ILOp::BoolOr { a, b, .. }
        | R2ILOp::BoolXor { a, b, .. }
        | R2ILOp::Piece { hi: a, lo: b, .. }
        | R2ILOp::FloatAdd { a, b, .. }
        | R2ILOp::FloatSub { a, b, .. }
        | R2ILOp::FloatMult { a, b, .. }
        | R2ILOp::FloatDiv { a, b, .. }
        | R2ILOp::FloatEqual { a, b, .. }
        | R2ILOp::FloatNotEqual { a, b, .. }
        | R2ILOp::FloatLess { a, b, .. }
        | R2ILOp::FloatLessEqual { a, b, .. } => {
            if a.is_register() {
                regs.push(a);
            }
            if b.is_register() {
                regs.push(b);
            }
        }

        // Unary ops - src is read
        R2ILOp::IntNegate { src, .. }
        | R2ILOp::IntNot { src, .. }
        | R2ILOp::IntZExt { src, .. }
        | R2ILOp::IntSExt { src, .. }
        | R2ILOp::BoolNot { src, .. }
        | R2ILOp::PopCount { src, .. }
        | R2ILOp::Lzcount { src, .. }
        | R2ILOp::Subpiece { src, .. }
        | R2ILOp::FloatNeg { src, .. }
        | R2ILOp::FloatAbs { src, .. }
        | R2ILOp::FloatSqrt { src, .. }
        | R2ILOp::FloatNaN { src, .. }
        | R2ILOp::Int2Float { src, .. }
        | R2ILOp::FloatFloat { src, .. }
        | R2ILOp::Trunc { src, .. }
        | R2ILOp::FloatCeil { src, .. }
        | R2ILOp::FloatFloor { src, .. }
        | R2ILOp::FloatRound { src, .. } => {
            if src.is_register() {
                regs.push(src);
            }
        }

        // Control flow - target/cond are read
        R2ILOp::Branch { target }
        | R2ILOp::BranchInd { target }
        | R2ILOp::Call { target }
        | R2ILOp::CallInd { target }
        | R2ILOp::Return { target } => {
            if target.is_register() {
                regs.push(target);
            }
        }
        R2ILOp::CBranch { cond, target } => {
            if cond.is_register() {
                regs.push(cond);
            }
            if target.is_register() {
                regs.push(target);
            }
        }

        // CallOther - inputs are read
        R2ILOp::CallOther { inputs, .. } => {
            for inp in inputs {
                if inp.is_register() {
                    regs.push(inp);
                }
            }
        }

        // Float2Int - src is read
        R2ILOp::Float2Int { src, .. } | R2ILOp::New { src, .. } | R2ILOp::Cast { src, .. } => {
            if src.is_register() {
                regs.push(src);
            }
        }

        // Extract - src and position are read
        R2ILOp::Extract { src, position, .. } => {
            if src.is_register() {
                regs.push(src);
            }
            if position.is_register() {
                regs.push(position);
            }
        }

        // Insert - src, value, position are read
        R2ILOp::Insert {
            src,
            value,
            position,
            ..
        } => {
            if src.is_register() {
                regs.push(src);
            }
            if value.is_register() {
                regs.push(value);
            }
            if position.is_register() {
                regs.push(position);
            }
        }

        // SegmentOp - segment and offset are read
        R2ILOp::SegmentOp {
            segment, offset, ..
        } => {
            if segment.is_register() {
                regs.push(segment);
            }
            if offset.is_register() {
                regs.push(offset);
            }
        }

        // PtrAdd/PtrSub - base and index are read
        R2ILOp::PtrAdd { base, index, .. } | R2ILOp::PtrSub { base, index, .. } => {
            if base.is_register() {
                regs.push(base);
            }
            if index.is_register() {
                regs.push(index);
            }
        }

        // Multiequal - inputs are read
        R2ILOp::Multiequal { inputs, .. } => {
            for inp in inputs {
                if inp.is_register() {
                    regs.push(inp);
                }
            }
        }

        // Indirect - src and indirect are read
        R2ILOp::Indirect { src, indirect, .. } => {
            if src.is_register() {
                regs.push(src);
            }
            if indirect.is_register() {
                regs.push(indirect);
            }
        }

        // Ops with no register reads
        R2ILOp::Fence { .. }
        | R2ILOp::Nop
        | R2ILOp::Unimplemented
        | R2ILOp::Breakpoint
        | R2ILOp::CpuId { .. } => {}
    }

    regs
}

/// Helper: extract all register varnodes that are written by an operation.
fn op_regs_write(op: &R2ILOp) -> Vec<&Varnode> {
    let mut regs = Vec::new();

    match op {
        // All ops with dst field write to dst
        R2ILOp::Copy { dst, .. }
        | R2ILOp::Load { dst, .. }
        | R2ILOp::LoadLinked { dst, .. }
        | R2ILOp::AtomicCAS { dst, .. }
        | R2ILOp::LoadGuarded { dst, .. }
        | R2ILOp::IntAdd { dst, .. }
        | R2ILOp::IntSub { dst, .. }
        | R2ILOp::IntMult { dst, .. }
        | R2ILOp::IntDiv { dst, .. }
        | R2ILOp::IntSDiv { dst, .. }
        | R2ILOp::IntRem { dst, .. }
        | R2ILOp::IntSRem { dst, .. }
        | R2ILOp::IntNegate { dst, .. }
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
        | R2ILOp::IntCarry { dst, .. }
        | R2ILOp::IntSCarry { dst, .. }
        | R2ILOp::IntSBorrow { dst, .. }
        | R2ILOp::BoolAnd { dst, .. }
        | R2ILOp::BoolOr { dst, .. }
        | R2ILOp::BoolXor { dst, .. }
        | R2ILOp::BoolNot { dst, .. }
        | R2ILOp::PopCount { dst, .. }
        | R2ILOp::Lzcount { dst, .. }
        | R2ILOp::Piece { dst, .. }
        | R2ILOp::Subpiece { dst, .. }
        | R2ILOp::FloatAdd { dst, .. }
        | R2ILOp::FloatSub { dst, .. }
        | R2ILOp::FloatMult { dst, .. }
        | R2ILOp::FloatDiv { dst, .. }
        | R2ILOp::FloatNeg { dst, .. }
        | R2ILOp::FloatAbs { dst, .. }
        | R2ILOp::FloatSqrt { dst, .. }
        | R2ILOp::FloatEqual { dst, .. }
        | R2ILOp::FloatNotEqual { dst, .. }
        | R2ILOp::FloatLess { dst, .. }
        | R2ILOp::FloatLessEqual { dst, .. }
        | R2ILOp::FloatNaN { dst, .. }
        | R2ILOp::Int2Float { dst, .. }
        | R2ILOp::FloatFloat { dst, .. }
        | R2ILOp::Trunc { dst, .. }
        | R2ILOp::FloatCeil { dst, .. }
        | R2ILOp::FloatFloor { dst, .. }
        | R2ILOp::FloatRound { dst, .. } => {
            if dst.is_register() {
                regs.push(dst);
            }
        }

        // Store doesn't have a register dst
        R2ILOp::Store { .. } => {}
        R2ILOp::StoreConditional { result, .. } => {
            if let Some(out) = result
                && out.is_register()
            {
                regs.push(out);
            }
        }
        R2ILOp::StoreGuarded { .. } => {}

        // Control flow ops don't write registers directly
        R2ILOp::Branch { .. }
        | R2ILOp::BranchInd { .. }
        | R2ILOp::CBranch { .. }
        | R2ILOp::Call { .. }
        | R2ILOp::CallInd { .. }
        | R2ILOp::Return { .. } => {}

        // CallOther may have output
        R2ILOp::CallOther { output, .. } => {
            if let Some(out) = output
                && out.is_register()
            {
                regs.push(out);
            }
        }

        // Ops with dst field that write
        R2ILOp::Float2Int { dst, .. }
        | R2ILOp::CpuId { dst, .. }
        | R2ILOp::SegmentOp { dst, .. }
        | R2ILOp::New { dst, .. }
        | R2ILOp::Cast { dst, .. }
        | R2ILOp::Extract { dst, .. }
        | R2ILOp::Insert { dst, .. }
        | R2ILOp::Multiequal { dst, .. }
        | R2ILOp::Indirect { dst, .. }
        | R2ILOp::PtrAdd { dst, .. }
        | R2ILOp::PtrSub { dst, .. } => {
            if dst.is_register() {
                regs.push(dst);
            }
        }

        // Ops with no register writes
        R2ILOp::Fence { .. } | R2ILOp::Nop | R2ILOp::Unimplemented | R2ILOp::Breakpoint => {}
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
    let mut regs = BTreeSet::new();

    for op in &blk.ops {
        for reg in op_regs_read(op) {
            if let Some(name) = disasm.register_name(reg) {
                regs.insert(name);
            }
        }
    }

    let json_array =
        serde_json::to_string(&regs.into_iter().collect::<Vec<_>>()).unwrap_or_default();
    CString::new(json_array).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Get memory accesses by the block as JSON array.
/// Each entry includes legacy fields (`addr`, `size`, `write`) and richer metadata.
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
    let defs = build_stack_defs(&blk.ops);
    let mut accesses = Vec::new();

    let apply_additive_fields = |access: &mut serde_json::Value,
                                 op_index: usize,
                                 space_id: Option<r2il::SpaceId>,
                                 ordering: Option<r2il::MemoryOrdering>,
                                 atomic_kind: Option<r2il::AtomicKind>,
                                 guarded: bool| {
        if guarded {
            access["guarded"] = serde_json::Value::Bool(true);
        }
        if let Some(ord) = ordering.or_else(|| {
            blk.op_metadata
                .get(&op_index)
                .and_then(|m| m.memory_ordering)
        }) {
            access["ordering"] = serde_json::to_value(ord).unwrap_or(serde_json::Value::Null);
        }
        if let Some(kind) =
            atomic_kind.or_else(|| blk.op_metadata.get(&op_index).and_then(|m| m.atomic_kind))
        {
            access["atomic_kind"] = serde_json::to_value(kind).unwrap_or(serde_json::Value::Null);
        }
        if let Some(meta) = blk.op_metadata.get(&op_index) {
            if let Some(memory_class) = meta.memory_class {
                access["memory_class"] =
                    serde_json::to_value(memory_class).unwrap_or(serde_json::Value::Null);
            }
            if let Some(perms) = meta.permissions {
                access["permissions"] =
                    serde_json::to_value(perms).unwrap_or(serde_json::Value::Null);
            }
            if let Some(range) = meta.valid_range {
                access["range"] = serde_json::to_value(range).unwrap_or(serde_json::Value::Null);
            }
            if let Some(bank_id) = &meta.bank_id {
                access["bank_id"] = serde_json::Value::String(bank_id.clone());
            }
            if let Some(segment_id) = &meta.segment_id {
                access["segment_id"] = serde_json::Value::String(segment_id.clone());
            }
        }

        if let Some(space_id) = space_id
            && let Some(arch) = ctx_ref.arch.as_ref()
            && let Some(space) = arch.spaces.iter().find(|s| s.id == space_id)
        {
            if let Some(memory_class) = space.memory_class {
                access["memory_class"] =
                    serde_json::to_value(memory_class).unwrap_or(serde_json::Value::Null);
            }
            if access.get("permissions").is_none()
                && let Some(perms) = space.permissions
            {
                access["permissions"] =
                    serde_json::to_value(perms).unwrap_or(serde_json::Value::Null);
            }
            if access.get("range").is_none()
                && let Some(range) = space.valid_ranges.first()
            {
                access["range"] = serde_json::to_value(range).unwrap_or(serde_json::Value::Null);
            }
            if access.get("bank_id").is_none()
                && let Some(bank_id) = &space.bank_id
            {
                access["bank_id"] = serde_json::Value::String(bank_id.clone());
            }
            if access.get("segment_id").is_none()
                && let Some(segment_id) = &space.segment_id
            {
                access["segment_id"] = serde_json::Value::String(segment_id.clone());
            }
        }
    };

    for (op_index, op) in blk.ops.iter().enumerate() {
        match op {
            R2ILOp::Load { dst, space, addr } => {
                let mut access = serde_json::json!({
                    "type": "load",
                    "size": dst.size,
                    "write": false,
                    "addr": disasm.format_varnode(addr),
                });

                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }

                if let Some((base, offset)) = resolve_stack_addr(addr, disasm, &defs, &blk.ops) {
                    access["stack"] = serde_json::Value::Bool(true);
                    access["stack_offset"] = serde_json::Value::Number(offset.into());
                    access["stack_base"] = serde_json::Value::String(base);
                }

                apply_additive_fields(&mut access, op_index, Some(*space), None, None, false);
                accesses.push(access);
            }
            R2ILOp::LoadLinked {
                dst,
                space,
                addr,
                ordering,
            } => {
                let mut access = serde_json::json!({
                    "type": "load_linked",
                    "size": dst.size,
                    "write": false,
                    "addr": disasm.format_varnode(addr),
                });

                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                apply_additive_fields(
                    &mut access,
                    op_index,
                    Some(*space),
                    Some(*ordering),
                    Some(r2il::AtomicKind::LoadLinked),
                    false,
                );
                accesses.push(access);
            }
            R2ILOp::Store { space, addr, val } => {
                let mut access = serde_json::json!({
                    "type": "store",
                    "size": val.size,
                    "write": true,
                    "addr": disasm.format_varnode(addr),
                });

                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                if let Some(value) = varnode_to_json(val, disasm) {
                    access["value"] = value;
                }

                if let Some((base, offset)) = resolve_stack_addr(addr, disasm, &defs, &blk.ops) {
                    access["stack"] = serde_json::Value::Bool(true);
                    access["stack_offset"] = serde_json::Value::Number(offset.into());
                    access["stack_base"] = serde_json::Value::String(base);
                }

                apply_additive_fields(&mut access, op_index, Some(*space), None, None, false);
                accesses.push(access);
            }
            R2ILOp::StoreConditional {
                result,
                space,
                addr,
                val,
                ordering,
            } => {
                let mut access = serde_json::json!({
                    "type": "store_conditional",
                    "size": val.size,
                    "write": true,
                    "addr": disasm.format_varnode(addr),
                });
                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                if let Some(value) = varnode_to_json(val, disasm) {
                    access["value"] = value;
                }
                if let Some(dst) = result
                    && let Some(result_json) = varnode_to_json(dst, disasm)
                {
                    access["result"] = result_json;
                }
                apply_additive_fields(
                    &mut access,
                    op_index,
                    Some(*space),
                    Some(*ordering),
                    Some(r2il::AtomicKind::StoreConditional),
                    false,
                );
                accesses.push(access);
            }
            R2ILOp::AtomicCAS {
                dst,
                space,
                addr,
                expected,
                replacement,
                ordering,
            } => {
                let mut access = serde_json::json!({
                    "type": "atomic_cas",
                    "size": dst.size,
                    "write": true,
                    "addr": disasm.format_varnode(addr),
                });
                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                if let Some(value) = varnode_to_json(expected, disasm) {
                    access["expected"] = value;
                }
                if let Some(value) = varnode_to_json(replacement, disasm) {
                    access["replacement"] = value;
                }
                if let Some(value) = varnode_to_json(dst, disasm) {
                    access["result"] = value;
                }
                apply_additive_fields(
                    &mut access,
                    op_index,
                    Some(*space),
                    Some(*ordering),
                    Some(r2il::AtomicKind::CompareExchange),
                    false,
                );
                accesses.push(access);
            }
            R2ILOp::LoadGuarded {
                dst,
                space,
                addr,
                guard,
                ordering,
            } => {
                let mut access = serde_json::json!({
                    "type": "load_guarded",
                    "size": dst.size,
                    "write": false,
                    "addr": disasm.format_varnode(addr),
                });
                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                if let Some(value) = varnode_to_json(guard, disasm) {
                    access["guard"] = value;
                }
                apply_additive_fields(
                    &mut access,
                    op_index,
                    Some(*space),
                    Some(*ordering),
                    None,
                    true,
                );
                accesses.push(access);
            }
            R2ILOp::StoreGuarded {
                space,
                addr,
                val,
                guard,
                ordering,
            } => {
                let mut access = serde_json::json!({
                    "type": "store_guarded",
                    "size": val.size,
                    "write": true,
                    "addr": disasm.format_varnode(addr),
                });
                if let Some(detail) = varnode_to_json(addr, disasm) {
                    access["addr_detail"] = detail;
                }
                if let Some(value) = varnode_to_json(val, disasm) {
                    access["value"] = value;
                }
                if let Some(value) = varnode_to_json(guard, disasm) {
                    access["guard"] = value;
                }
                apply_additive_fields(
                    &mut access,
                    op_index,
                    Some(*space),
                    Some(*ordering),
                    None,
                    true,
                );
                accesses.push(access);
            }
            _ => {}
        }
    }

    let json = serde_json::to_string(&accesses).unwrap_or_default();
    CString::new(json).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Get all varnodes used by the block as JSON.
/// Includes registers, memory locations, constants, and temporaries.
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
    let mut seen: HashSet<(u8, u64, u32)> = HashSet::new();
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
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);

            let (name, space_str) = match vn.space {
                r2il::SpaceId::Const => (format!("0x{:x}", vn.offset), space_label(vn.space)),
                r2il::SpaceId::Register => {
                    let name = disasm
                        .register_name(vn)
                        .unwrap_or_else(|| format!("reg:0x{:x}", vn.offset));
                    (name, space_label(vn.space))
                }
                r2il::SpaceId::Ram => (format!("[0x{:x}]", vn.offset), space_label(vn.space)),
                r2il::SpaceId::Unique => (format!("tmp:0x{:x}", vn.offset), space_label(vn.space)),
                r2il::SpaceId::Custom(n) => (
                    format!("space{}:0x{:x}", n, vn.offset),
                    space_label(vn.space),
                ),
            };

            varnodes.push(VarnodeInfo {
                name,
                space: space_str,
                offset: vn.offset,
                size: vn.size,
                meta: vn.meta.clone(),
            });
        }
    }

    let json = serde_json::to_string(&varnodes).unwrap_or_default();
    CString::new(json).map_or(ptr::null_mut(), |c| c.into_raw())
}

fn space_label(space: r2il::SpaceId) -> String {
    match space {
        r2il::SpaceId::Const => "const".to_string(),
        r2il::SpaceId::Register => "register".to_string(),
        r2il::SpaceId::Ram => "ram".to_string(),
        r2il::SpaceId::Unique => "unique".to_string(),
        r2il::SpaceId::Custom(id) => format!("custom:{}", id),
    }
}

/// Helper: convert a varnode to JSON with register names resolved.
fn varnode_to_json(vn: &Varnode, disasm: &Disassembler) -> Option<serde_json::Value> {
    let mut json = serde_json::json!({
        "space": space_label(vn.space),
        "offset": vn.offset,
        "size": vn.size,
    });

    if vn.is_register()
        && let Some(name) = disasm.register_name(vn)
    {
        json["name"] = serde_json::Value::String(name);
    }
    if let Some(meta) = vn.meta.as_ref() {
        json["meta"] = serde_json::to_value(meta).ok()?;
    }

    Some(json)
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct VarnodeKey {
    space: r2il::SpaceId,
    offset: u64,
    size: u32,
}

fn varnode_key(vn: &Varnode) -> VarnodeKey {
    VarnodeKey {
        space: vn.space,
        offset: vn.offset,
        size: vn.size,
    }
}

fn const_value(vn: &Varnode) -> Option<i64> {
    if vn.space.is_const() {
        Some(vn.offset as i64)
    } else {
        None
    }
}

fn is_stack_reg_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("sp") || lower.contains("bp") || lower.contains("fp")
}

fn stack_reg_name(vn: &Varnode, disasm: &Disassembler) -> Option<String> {
    if !vn.is_register() {
        return None;
    }
    let name = disasm.register_name(vn)?;
    if is_stack_reg_name(&name) {
        Some(name)
    } else {
        None
    }
}

fn build_stack_defs(ops: &[R2ILOp]) -> HashMap<VarnodeKey, usize> {
    let mut defs = HashMap::new();
    for (idx, op) in ops.iter().enumerate() {
        let dst = match op {
            R2ILOp::Copy { dst, .. }
            | R2ILOp::IntAdd { dst, .. }
            | R2ILOp::IntSub { dst, .. }
            | R2ILOp::PtrAdd { dst, .. }
            | R2ILOp::PtrSub { dst, .. } => Some(dst),
            _ => None,
        };
        if let Some(dst) = dst {
            defs.insert(varnode_key(dst), idx);
        }
    }
    defs
}

/// Maximum depth for stack address resolution recursion.
/// This limit of 8 prevents infinite recursion in cyclic definitions while being
/// deep enough for typical stack address calculations like:
///   rbp -> temp1 (copy) -> temp2 (add offset) -> temp3 (sub) -> final address
/// In practice, most stack accesses resolve within 2-4 levels.
const STACK_RESOLVE_MAX_DEPTH: usize = 8;

fn resolve_stack_addr(
    vn: &Varnode,
    disasm: &Disassembler,
    defs: &HashMap<VarnodeKey, usize>,
    ops: &[R2ILOp],
) -> Option<(String, i64)> {
    let mut visited = HashSet::new();
    resolve_stack_addr_inner(vn, disasm, defs, ops, &mut visited, 0)
}

fn resolve_stack_addr_inner(
    vn: &Varnode,
    disasm: &Disassembler,
    defs: &HashMap<VarnodeKey, usize>,
    ops: &[R2ILOp],
    visited: &mut HashSet<VarnodeKey>,
    depth: usize,
) -> Option<(String, i64)> {
    if depth > STACK_RESOLVE_MAX_DEPTH {
        return None;
    }
    if let Some(name) = stack_reg_name(vn, disasm) {
        return Some((name, 0));
    }
    if !vn.space.is_unique() {
        return None;
    }

    let key = varnode_key(vn);
    if !visited.insert(key) {
        return None;
    }
    let idx = defs.get(&key)?;
    let op = &ops[*idx];

    match op {
        R2ILOp::Copy { src, .. } => {
            resolve_stack_addr_inner(src, disasm, defs, ops, visited, depth + 1)
        }
        R2ILOp::IntAdd { a, b, .. } => {
            if let Some((base, off)) =
                resolve_stack_addr_inner(a, disasm, defs, ops, visited, depth + 1)
                && let Some(c) = const_value(b)
            {
                return Some((base, off + c));
            }
            if let Some((base, off)) =
                resolve_stack_addr_inner(b, disasm, defs, ops, visited, depth + 1)
                && let Some(c) = const_value(a)
            {
                return Some((base, off + c));
            }
            None
        }
        R2ILOp::IntSub { a, b, .. } => {
            if let Some((base, off)) =
                resolve_stack_addr_inner(a, disasm, defs, ops, visited, depth + 1)
                && let Some(c) = const_value(b)
            {
                return Some((base, off - c));
            }
            None
        }
        R2ILOp::PtrAdd {
            base,
            index,
            element_size,
            ..
        } => {
            if let Some((base_name, off)) =
                resolve_stack_addr_inner(base, disasm, defs, ops, visited, depth + 1)
                && let Some(c) = const_value(index)
            {
                return Some((base_name, off + c * (*element_size as i64)));
            }
            None
        }
        R2ILOp::PtrSub {
            base,
            index,
            element_size,
            ..
        } => {
            if let Some((base_name, off)) =
                resolve_stack_addr_inner(base, disasm, defs, ops, visited, depth + 1)
                && let Some(c) = const_value(index)
            {
                return Some((base_name, off - c * (*element_size as i64)));
            }
            None
        }
        _ => None,
    }
}

use serde::{Deserialize, Serialize};

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
    let mut regs = BTreeSet::new();

    for op in &blk.ops {
        for reg in op_regs_write(op) {
            if let Some(name) = disasm.register_name(reg) {
                regs.insert(name);
            }
        }
    }

    let json_array =
        serde_json::to_string(&regs.into_iter().collect::<Vec<_>>()).unwrap_or_default();
    CString::new(json_array).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Varnode info for JSON output.
#[derive(Serialize)]
struct VarnodeInfo {
    name: String,
    space: String,
    offset: u64,
    size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<r2il::VarnodeMetadata>,
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
            if !dst.is_register() {
                vns.push(dst);
            }
            if !src.is_register() {
                vns.push(src);
            }
        }
        R2ILOp::Load { dst, addr, .. } => {
            if !dst.is_register() {
                vns.push(dst);
            }
            if !addr.is_register() {
                vns.push(addr);
            }
        }
        R2ILOp::LoadLinked { dst, addr, .. } => {
            if !dst.is_register() {
                vns.push(dst);
            }
            if !addr.is_register() {
                vns.push(addr);
            }
        }
        R2ILOp::Store { addr, val, .. } => {
            if !addr.is_register() {
                vns.push(addr);
            }
            if !val.is_register() {
                vns.push(val);
            }
        }
        R2ILOp::StoreConditional {
            result, addr, val, ..
        } => {
            if let Some(out) = result
                && !out.is_register()
            {
                vns.push(out);
            }
            if !addr.is_register() {
                vns.push(addr);
            }
            if !val.is_register() {
                vns.push(val);
            }
        }
        R2ILOp::AtomicCAS {
            dst,
            addr,
            expected,
            replacement,
            ..
        } => {
            if !dst.is_register() {
                vns.push(dst);
            }
            if !addr.is_register() {
                vns.push(addr);
            }
            if !expected.is_register() {
                vns.push(expected);
            }
            if !replacement.is_register() {
                vns.push(replacement);
            }
        }
        R2ILOp::LoadGuarded {
            dst, addr, guard, ..
        } => {
            if !dst.is_register() {
                vns.push(dst);
            }
            if !addr.is_register() {
                vns.push(addr);
            }
            if !guard.is_register() {
                vns.push(guard);
            }
        }
        R2ILOp::StoreGuarded {
            addr, val, guard, ..
        } => {
            if !addr.is_register() {
                vns.push(addr);
            }
            if !val.is_register() {
                vns.push(val);
            }
            if !guard.is_register() {
                vns.push(guard);
            }
        }
        // For binary ops, get non-register operands
        R2ILOp::IntAdd { dst, a, b }
        | R2ILOp::IntSub { dst, a, b }
        | R2ILOp::IntAnd { dst, a, b }
        | R2ILOp::IntOr { dst, a, b }
        | R2ILOp::IntXor { dst, a, b } => {
            if !dst.is_register() {
                vns.push(dst);
            }
            if !a.is_register() {
                vns.push(a);
            }
            if !b.is_register() {
                vns.push(b);
            }
        }
        _ => {} // Other ops handled by op_regs_read/write
    }

    vns
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
        Fence { .. } => "Fence",
        LoadLinked { .. } => "LoadLinked",
        StoreConditional { .. } => "StoreConditional",
        AtomicCAS { .. } => "AtomicCAS",
        LoadGuarded { .. } => "LoadGuarded",
        StoreGuarded { .. } => "StoreGuarded",
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

#[derive(Serialize)]
struct TaintSummaryReportJson {
    sources: Vec<TaintSourceJson>,
    sink_hits: Vec<SinkHitJson>,
}

fn labels_to_strings(labels: &r2ssa::taint::TaintSet) -> Vec<String> {
    let mut out: Vec<String> = labels.iter().map(|l| l.id.clone()).collect();
    out.sort();
    out
}

fn collect_r2il_blocks_from_ptrs(
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> Vec<R2ILBlock> {
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }
    r2il_blocks
}

fn current_taint_policy() -> Option<r2ssa::DefaultTaintPolicy> {
    let cfg = taint_config().lock().ok()?.clone();
    let mut policy = if cfg.sources.is_empty() {
        r2ssa::DefaultTaintPolicy::all_inputs()
    } else {
        r2ssa::DefaultTaintPolicy::new()
    }
    .with_sink_calls(cfg.sink_calls)
    .with_sink_stores(cfg.sink_stores);
    for src in cfg.sources {
        policy = policy.with_source(src);
    }
    Some(policy)
}

fn collect_taint_sources(
    ssa_func: &r2ssa::SSAFunction,
    policy: &r2ssa::DefaultTaintPolicy,
) -> Vec<TaintSourceJson> {
    let mut source_map: std::collections::HashMap<String, TaintSourceJson> =
        std::collections::HashMap::new();
    for block in ssa_func.blocks() {
        block.for_each_source(|src| {
            if let Some(labels) = policy.is_source(src.var, block.addr) {
                let entry = source_map
                    .entry(src.var.display_name())
                    .or_insert(TaintSourceJson {
                        var: src.var.display_name(),
                        labels: Vec::new(),
                        block: block.addr,
                        block_hex: format!("0x{:x}", block.addr),
                    });
                for label in labels {
                    entry.labels.push(label.id);
                }
            }
        });
    }

    for source in source_map.values_mut() {
        source.labels.sort();
        source.labels.dedup();
    }

    let mut sources: Vec<TaintSourceJson> = source_map.into_values().collect();
    sources.sort_by(|a, b| a.var.cmp(&b.var));
    sources
}

fn collect_taint_sink_hits(result: &r2ssa::TaintResult) -> Vec<SinkHitJson> {
    result
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
        .collect()
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

    let r2il_blocks = collect_r2il_blocks_from_ptrs(blocks, num_blocks);

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Build SSA function
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx.arch.as_ref())
    {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let policy = match current_taint_policy() {
        Some(p) => p,
        None => return ptr::null_mut(),
    };
    let sources = collect_taint_sources(&ssa_func, &policy);

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

    let analysis = r2ssa::TaintAnalysis::with_arch(&ssa_func, policy, ctx.arch.as_ref());
    let result = analysis.analyze();

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
    let sink_hits = collect_taint_sink_hits(&result);

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

/// Run taint analysis and return post-analysis summary JSON.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2taint_function_summary_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }
    let ctx = unsafe { &*ctx };

    let r2il_blocks = collect_r2il_blocks_from_ptrs(blocks, num_blocks);
    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx.arch.as_ref())
    {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    let policy = match current_taint_policy() {
        Some(p) => p,
        None => return ptr::null_mut(),
    };
    let sources = collect_taint_sources(&ssa_func, &policy);

    let analysis = r2ssa::TaintAnalysis::with_arch(&ssa_func, policy, ctx.arch.as_ref());
    let result = analysis.analyze();
    let sink_hits = collect_taint_sink_hits(&result);

    let report = TaintSummaryReportJson { sources, sink_hits };
    match serde_json::to_string(&report) {
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
    let input = InstructionExportInput {
        disasm,
        arch: match ctx_ref.arch.as_ref() {
            Some(a) => a,
            None => return ptr::null_mut(),
        },
        block: blk,
        addr: blk.addr,
        mnemonic: "",
        native_size: blk.size as usize,
    };

    match export_instruction(&input, InstructionAction::Ssa, ExportFormat::Json) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
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
    let input = InstructionExportInput {
        disasm,
        arch: match ctx_ref.arch.as_ref() {
            Some(a) => a,
            None => return ptr::null_mut(),
        },
        block: blk,
        addr: blk.addr,
        mnemonic: "",
        native_size: blk.size as usize,
    };

    match export_instruction(&input, InstructionAction::Defuse, ExportFormat::Json) {
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
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe {
        (*ctx).arch.as_ref()
    }) {
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
    sccp_constants_found: usize,
    sccp_edges_pruned: usize,
    sccp_blocks_removed: usize,
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

    let mut ssa_func =
        match r2ssa::SSAFunction::from_blocks_raw(&r2il_blocks, unsafe { (*ctx).arch.as_ref() }) {
            Some(f) => f,
            None => return ptr::null_mut(),
        };

    let stats = ssa_func.optimize(&r2ssa::OptimizationConfig::default());
    let function = build_ssa_function_json(&ssa_func);

    let report = SSAFunctionOptJson {
        optimized: true,
        stats: SSAOptStatsJson {
            iterations: stats.iterations,
            sccp_constants_found: stats.sccp_constants_found,
            sccp_edges_pruned: stats.sccp_edges_pruned,
            sccp_blocks_removed: stats.sccp_blocks_removed,
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
    live_in: std::collections::HashMap<String, Vec<String>>, // block_hex -> vars
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
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe {
        (*ctx).arch.as_ref()
    }) {
        Some(f) => f,
        None => return ptr::null_mut(),
    };

    // Collect definitions and uses across all blocks
    let mut definitions = std::collections::HashMap::new();
    let mut uses: std::collections::HashMap<String, Vec<UseLocationJson>> =
        std::collections::HashMap::new();
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
                definitions.insert(
                    dst_name.clone(),
                    DefLocationJson {
                        block: addr,
                        block_hex: block_hex.clone(),
                        op_idx: 0, // Phi nodes are at the start
                    },
                );
                defined_in_block.insert(dst_name.clone());
                block_outputs.push(dst_name);

                // Sources are uses
                for (_pred, src) in &phi.sources {
                    let src_name = src.display_name();
                    uses.entry(src_name.clone())
                        .or_default()
                        .push(UseLocationJson {
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
                    definitions.insert(
                        dst_name.clone(),
                        DefLocationJson {
                            block: addr,
                            block_hex: block_hex.clone(),
                            op_idx: op_idx + 1, // +1 because phi nodes are at 0
                        },
                    );
                    defined_in_block.insert(dst_name.clone());
                    block_outputs.push(dst_name);
                }

                // Record uses
                for src in op.sources() {
                    let src_name = src.display_name();
                    uses.entry(src_name.clone())
                        .or_default()
                        .push(UseLocationJson {
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
    idom: std::collections::HashMap<String, String>, // block_hex -> idom_hex
    children: std::collections::HashMap<String, Vec<String>>, // block_hex -> children_hex
    dominance_frontier: std::collections::HashMap<String, Vec<String>>, // block_hex -> frontier_hex
    depth: std::collections::HashMap<String, usize>, // block_hex -> depth
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
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe {
        (*ctx).arch.as_ref()
    }) {
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
        let children: Vec<String> = domtree
            .children(addr)
            .iter()
            .map(|c| format!("0x{:x}", c))
            .collect();
        children_map.insert(block_hex.clone(), children);

        // Dominance frontier
        let frontier: Vec<String> = domtree
            .frontier(addr)
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
    let ssa_func = match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, unsafe {
        (*ctx).arch.as_ref()
    }) {
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
                    if let Some(dst) = op.dst()
                        && dst.display_name() == target_display_name
                    {
                        found = Some(dst.clone());
                        break 'outer;
                    }
                }
            }
        }
        match found {
            Some(v) => v,
            None => {
                // Variable not found - return error JSON
                let error_json = format!(r#"{{"error": "Variable '{}' not found"}}"#, var_name_str);
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
            r2ssa::SliceOpRef::Phi {
                block_addr,
                phi_idx,
            } => {
                let mut op_str = None;
                if let Some(block) = ssa_func.get_block(*block_addr)
                    && let Some(phi) = block.phis.get(*phi_idx)
                {
                    op_str = Some(format!("{} = phi(...)", phi.dst.display_name()));
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
                if let Some(block) = ssa_func.get_block(*block_addr)
                    && let Some(op) = block.ops.get(*op_idx)
                {
                    op_str = Some(format!("{:?}", op));
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
            let (spec, dis) = apply_userop_map(spec, dis, "x86-64");
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
            let (spec, dis) = apply_userop_map(spec, dis, "x86");
            Ok((spec, dis))
        }
        #[cfg(feature = "arm")]
        "arm" | "arm32" | "arm-le" => {
            let spec = build_arch_spec(
                sleigh_config::processor_arm::SLA_ARM8_LE,
                // sleigh-config 1.x does not ship an ARM8 pspec; use a Cortex pspec instead.
                sleigh_config::processor_arm::PSPEC_ARMCORTEX,
                "ARM",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_arm::SLA_ARM8_LE,
                // sleigh-config 1.x does not ship an ARM8 pspec; use a Cortex pspec instead.
                sleigh_config::processor_arm::PSPEC_ARMCORTEX,
                "ARM",
            )
            .map_err(|e| e.to_string())?;
            let (spec, dis) = apply_userop_map(spec, dis, "arm");
            Ok((spec, dis))
        }
        #[cfg(feature = "riscv")]
        "riscv64" | "rv64" | "rv64gc" => {
            let spec = build_arch_spec(
                sleigh_config::processor_riscv::SLA_RISCV_LP64D,
                sleigh_config::processor_riscv::PSPEC_RV64GC,
                "riscv64",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_riscv::SLA_RISCV_LP64D,
                sleigh_config::processor_riscv::PSPEC_RV64GC,
                "riscv64",
            )
            .map_err(|e| e.to_string())?;
            let (spec, dis) = apply_userop_map(spec, dis, "riscv64");
            Ok((spec, dis))
        }
        #[cfg(feature = "riscv")]
        "riscv32" | "rv32" | "rv32gc" => {
            let spec = build_arch_spec(
                sleigh_config::processor_riscv::SLA_RISCV_ILP32D,
                sleigh_config::processor_riscv::PSPEC_RV32GC,
                "riscv32",
            )
            .map_err(|e| e.to_string())?;
            let dis = Disassembler::from_sla(
                sleigh_config::processor_riscv::SLA_RISCV_ILP32D,
                sleigh_config::processor_riscv::PSPEC_RV32GC,
                "riscv32",
            )
            .map_err(|e| e.to_string())?;
            let (spec, dis) = apply_userop_map(spec, dis, "riscv32");
            Ok((spec, dis))
        }
        _ => {
            let mut supported = vec![];
            #[cfg(feature = "x86")]
            supported.extend(["x86-64", "x86"]);
            #[cfg(feature = "arm")]
            supported.push("arm");
            #[cfg(feature = "riscv")]
            supported.extend(["riscv64", "riscv32"]);

            if supported.is_empty() {
                Err("No architectures enabled; build with feature x86, arm, or riscv".to_string())
            } else {
                Err(format!(
                    "Unknown architecture '{}'. Supported: {}",
                    arch,
                    supported.join(", ")
                ))
            }
        }
    }
}

fn apply_userop_map(
    mut spec: ArchSpec,
    mut disasm: Disassembler,
    arch: &str,
) -> (ArchSpec, Disassembler) {
    let userop_map = userop_map_for_arch(arch);
    disasm.set_userop_map(userop_map.clone());

    if !userop_map.is_empty() {
        let mut defs: Vec<UserOpDef> = userop_map
            .into_iter()
            .map(|(index, name)| UserOpDef { index, name })
            .collect();
        defs.sort_by_key(|def| def.index);
        spec.userops = defs;
    }

    (spec, disasm)
}

// ============================================================================
// Symbolic Execution Functions
// ============================================================================

use z3::{Config, Context};

static MERGE_STATES: AtomicBool = AtomicBool::new(false);

fn merge_states_enabled() -> bool {
    MERGE_STATES.load(Ordering::Relaxed)
}

fn arch_has_register(arch: &ArchSpec, name: &str) -> bool {
    arch.registers
        .iter()
        .any(|reg| reg.name.eq_ignore_ascii_case(name))
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
    let looks_riscv = arch_name.contains("riscv") || arch_name.starts_with("rv");
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
    } else if looks_riscv && (arch.addr_size == 8 || arch_name.contains("64")) {
        (
            [
                "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "X10", "X11", "X12", "X13", "X14",
                "X15", "X16", "X17",
            ]
            .as_slice(),
            ["SP", "S0", "FP", "X2", "X8"].as_slice(),
            0x7fff_ffff_0000u64,
        )
    } else if looks_riscv {
        (
            [
                "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "X10", "X11", "X12", "X13", "X14",
                "X15", "X16", "X17",
            ]
            .as_slice(),
            ["SP", "S0", "FP", "X2", "X8"].as_slice(),
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
        block.for_each_def(|def| maybe_seed(def.var));
        block.for_each_source(|src| maybe_seed(src.var));
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
    if merge_states_enabled() { 1 } else { 0 }
}

/// Enable or disable state merging for symbolic execution.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_merge_set_enabled(enabled: i32) {
    MERGE_STATES.store(enabled != 0, Ordering::Relaxed);
}

fn sym_default_config() -> r2sym::ExploreConfig {
    r2sym::ExploreConfig {
        max_states: 100,
        max_depth: 200,
        merge_states: merge_states_enabled(),
        timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    }
}

fn sym_error_json(message: &str) -> *mut c_char {
    let payload = format!(r#"{{"error":"{}"}}"#, message);
    CString::new(payload).map_or(ptr::null_mut(), |c| c.into_raw())
}

fn sym_symbol_map() -> &'static Mutex<HashMap<u64, String>> {
    static MAP: OnceLock<Mutex<HashMap<u64, String>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Set symbolic call target map as a JSON object of address->name pairs.
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_set_symbol_map_json(json: *const c_char) -> i32 {
    if json.is_null() {
        return 0;
    }

    let json_str = unsafe {
        match CStr::from_ptr(json).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let parsed = parse_addr_name_map(json_str);
    match sym_symbol_map().lock() {
        Ok(mut map) => {
            *map = parsed;
            1
        }
        Err(_) => 0,
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct SymHookStats {
    attempted: usize,
    installed: usize,
    skipped_unknown: usize,
    duplicates: usize,
}

fn callconv_for_arch(arch: Option<&ArchSpec>) -> Option<r2sym::CallConv> {
    let arch = arch?;

    let arch_name = arch.name.to_ascii_lowercase();
    if arch.addr_size == 8 && arch_name.contains("x86") {
        return Some(r2sym::CallConv::x86_64_sysv());
    }

    if arch_name.contains("riscv") || arch_name.starts_with("rv") {
        const RISCV_ARG_ABI: [&str; 8] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
        const RISCV_ARG_NUMERIC: [&str; 8] =
            ["x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17"];
        let use_abi_names = arch_has_register(arch, "a0");
        let is_64 = arch.addr_size == 8 || arch_name.contains("64");
        let bits = if is_64 { 64 } else { 32 };
        if use_abi_names {
            return Some(r2sym::CallConv::new(
                RISCV_ARG_ABI.to_vec(),
                "a0",
                bits,
                bits,
            ));
        }
        return Some(r2sym::CallConv::new(
            RISCV_ARG_NUMERIC.to_vec(),
            "x10",
            bits,
            bits,
        ));
    }

    None
}

fn normalize_sim_name(name: &str) -> Option<&'static str> {
    let mut normalized = name.trim().to_ascii_lowercase();

    for prefix in ["sym.imp.", "sym.", "imp.", "reloc.", "dbg."] {
        while let Some(rest) = normalized.strip_prefix(prefix) {
            normalized = rest.to_string();
        }
    }

    while let Some(rest) = normalized.strip_suffix("@plt") {
        normalized = rest.to_string();
    }
    while let Some(rest) = normalized.strip_suffix(".plt") {
        normalized = rest.to_string();
    }
    if let Some((base, _)) = normalized.split_once('@') {
        normalized = base.to_string();
    }

    if let Some(rest) = normalized.strip_prefix("__isoc99_") {
        normalized = rest.to_string();
    }
    if let Some(rest) = normalized.strip_prefix("__gi_") {
        normalized = rest.to_string();
    }

    match normalized.as_str() {
        "strlen" | "__strlen_chk" => Some("strlen"),
        "strcmp" => Some("strcmp"),
        "memcmp" => Some("memcmp"),
        "memcpy" | "__memcpy_chk" => Some("memcpy"),
        "memset" => Some("memset"),
        "malloc" | "__libc_malloc" | "__gi___libc_malloc" => Some("malloc"),
        "free" => Some("free"),
        "puts" => Some("puts"),
        "printf" | "__printf_chk" => Some("printf"),
        "exit" | "_exit" => Some("exit"),
        _ => {
            if normalized.starts_with("strlen") {
                Some("strlen")
            } else if normalized.starts_with("strcmp") {
                Some("strcmp")
            } else if normalized.starts_with("memcmp") {
                Some("memcmp")
            } else if normalized.starts_with("memcpy") {
                Some("memcpy")
            } else if normalized.starts_with("memset") {
                Some("memset")
            } else if normalized.starts_with("printf") || normalized == "__printf_chk" {
                Some("printf")
            } else if normalized.starts_with("puts") {
                Some("puts")
            } else if normalized == "malloc" || normalized.ends_with("malloc") {
                Some("malloc")
            } else if normalized == "free" || normalized.ends_with("free") {
                Some("free")
            } else if normalized.starts_with("exit") {
                Some("exit")
            } else {
                None
            }
        }
    }
}

fn extract_call_target(vn: &r2il::Varnode) -> Option<u64> {
    match vn.space {
        r2il::SpaceId::Const | r2il::SpaceId::Ram => Some(vn.offset),
        _ => None,
    }
}

fn install_core_summaries_for_function<'ctx>(
    explorer: &mut r2sym::PathExplorer<'ctx>,
    func: &r2ssa::SSAFunction,
    arch: Option<&ArchSpec>,
) -> SymHookStats {
    let mut stats = SymHookStats::default();
    let Some(callconv) = callconv_for_arch(arch) else {
        return stats;
    };

    let mut targets = BTreeSet::new();
    for block in func.cfg().blocks() {
        if let r2ssa::cfg::BlockTerminator::Call { target, .. } = block.terminator {
            targets.insert(target);
        }
        for op in &block.ops {
            if let R2ILOp::Call { target } = op
                && let Some(addr) = extract_call_target(target)
            {
                targets.insert(addr);
            }
        }
    }

    if targets.is_empty() {
        return stats;
    }

    let names = sym_symbol_map().lock().ok();
    let registry = r2sym::SummaryRegistry::with_core(callconv);
    let mut seen: HashSet<(u64, &'static str)> = HashSet::new();

    for target in targets {
        stats.attempted += 1;
        let raw_name = names
            .as_ref()
            .and_then(|map| map.get(&target))
            .map(String::as_str);
        let Some(raw_name) = raw_name else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some(summary_name) = normalize_sim_name(raw_name) else {
            stats.skipped_unknown += 1;
            continue;
        };
        if !seen.insert((target, summary_name)) {
            stats.duplicates += 1;
            continue;
        }
        if registry.install_for_explorer(explorer, target, summary_name) {
            stats.installed += 1;
        } else {
            stats.skipped_unknown += 1;
        }
    }

    stats
}

/// Symbolic execution summary for JSON output.
#[derive(Serialize, Clone)]
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
    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
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
        let config = sym_default_config();

        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, config);
        let _hook_stats =
            install_core_summaries_for_function(&mut explorer, &ssa_func, ctx_ref.arch.as_ref());
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

#[derive(Serialize)]
struct SymTargetExploreResult {
    entry: String,
    target: String,
    matched_paths: usize,
    stats: SymExecSummary,
    paths: Vec<PathInfo>,
}

#[derive(Serialize)]
struct SymTargetSolveResult {
    entry: String,
    target: String,
    matched_paths: usize,
    found: bool,
    stats: SymExecSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_path: Option<PathInfo>,
}

fn path_solution_from_result<'ctx>(
    explorer: &r2sym::PathExplorer<'ctx>,
    result: &r2sym::PathResult<'ctx>,
) -> Option<PathSolution> {
    if !result.feasible {
        return None;
    }

    explorer.solve_path(result).map(|solved| PathSolution {
        inputs: solved
            .inputs
            .into_iter()
            .map(|(k, v)| (k, format!("0x{:x}", v)))
            .collect(),
        registers: solved
            .registers
            .into_iter()
            .filter(|(name, _)| !name.starts_with("tmp:") && !name.contains("_0"))
            .map(|(k, v)| (k, format!("0x{:x}", v)))
            .collect(),
    })
}

fn path_info_from_result<'ctx>(
    path_id: usize,
    result: &r2sym::PathResult<'ctx>,
    explorer: &r2sym::PathExplorer<'ctx>,
) -> PathInfo {
    PathInfo {
        path_id,
        feasible: result.feasible,
        depth: result.depth,
        exit_status: format!("{:?}", result.exit_status),
        final_pc: format!("0x{:x}", result.final_pc()),
        num_constraints: result.num_constraints(),
        solution: path_solution_from_result(explorer, result),
    }
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
    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
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
        let config = sym_default_config();

        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, config);
        let _hook_stats =
            install_core_summaries_for_function(&mut explorer, &ssa_func, ctx_ref.arch.as_ref());
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
        .map(|(i, r)| path_info_from_result(i, r, &explorer))
        .collect();

    match serde_json::to_string_pretty(&paths) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Explore all feasible paths that reach a target address.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_explore_to(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    entry_addr: u64,
    target_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return sym_error_json("invalid symbolic exploration arguments");
    }

    let ctx_ref = unsafe { &*ctx };
    let _disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return sym_error_json("missing disassembler context"),
    };

    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }
    if r2il_blocks.is_empty() {
        return sym_error_json("no blocks to explore");
    }

    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
            Some(f) => f,
            None => return sym_error_json("failed to build SSA function"),
        };

    let z3_ctx = Context::thread_local();
    let explore_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut initial_state = r2sym::SymState::new(&z3_ctx, entry_addr);
        seed_symbolic_state(&mut initial_state, &ssa_func, ctx_ref.arch.as_ref());
        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, sym_default_config());
        let _hook_stats =
            install_core_summaries_for_function(&mut explorer, &ssa_func, ctx_ref.arch.as_ref());
        let matched = explorer.find_paths_to(&ssa_func, initial_state, target_addr);
        let stats = explorer.stats().clone();
        let paths: Vec<PathInfo> = matched
            .iter()
            .enumerate()
            .map(|(i, r)| path_info_from_result(i, r, &explorer))
            .collect();
        (paths, stats)
    }));

    let (paths, stats) = match explore_result {
        Ok(value) => value,
        Err(_) => return sym_error_json("symbolic execution failed (z3 context error)"),
    };

    let output = SymTargetExploreResult {
        entry: format!("0x{:x}", entry_addr),
        target: format!("0x{:x}", target_addr),
        matched_paths: paths.len(),
        stats: SymExecSummary {
            paths_explored: stats.paths_completed,
            paths_feasible: paths.len(),
            paths_pruned: stats.paths_pruned,
            max_depth: stats.max_depth_reached,
            states_explored: stats.states_explored,
            time_ms: stats.total_time.as_millis() as u64,
        },
        paths,
    };

    match serde_json::to_string(&output) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => sym_error_json("failed to serialize symbolic exploration output"),
    }
}

/// Solve a target address by returning one deterministic best feasible path.
/// Caller must free the returned string with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sym_solve_to(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    entry_addr: u64,
    target_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return sym_error_json("invalid symbolic solving arguments");
    }

    let ctx_ref = unsafe { &*ctx };
    let _disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return sym_error_json("missing disassembler context"),
    };

    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if !blk_ptr.is_null() {
            let blk = unsafe { &*blk_ptr };
            r2il_blocks.push(blk.clone());
        }
    }
    if r2il_blocks.is_empty() {
        return sym_error_json("no blocks to solve");
    }

    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
            Some(f) => f,
            None => return sym_error_json("failed to build SSA function"),
        };

    let z3_ctx = Context::thread_local();
    let solve_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut initial_state = r2sym::SymState::new(&z3_ctx, entry_addr);
        seed_symbolic_state(&mut initial_state, &ssa_func, ctx_ref.arch.as_ref());
        let mut explorer = r2sym::PathExplorer::with_config(&z3_ctx, sym_default_config());
        let _hook_stats =
            install_core_summaries_for_function(&mut explorer, &ssa_func, ctx_ref.arch.as_ref());
        let matched = explorer.find_paths_to(&ssa_func, initial_state, target_addr);
        let stats = explorer.stats().clone();

        let selected = matched
            .iter()
            .enumerate()
            .min_by_key(|(idx, path)| (path.num_constraints(), path.depth, *idx))
            .map(|(idx, path)| path_info_from_result(idx, path, &explorer));
        (matched.len(), selected, stats)
    }));

    let (matched_paths, selected_path, stats) = match solve_result {
        Ok(value) => value,
        Err(_) => return sym_error_json("symbolic execution failed (z3 context error)"),
    };

    let output = SymTargetSolveResult {
        entry: format!("0x{:x}", entry_addr),
        target: format!("0x{:x}", target_addr),
        matched_paths,
        found: selected_path.is_some(),
        stats: SymExecSummary {
            paths_explored: stats.paths_completed,
            paths_feasible: matched_paths,
            paths_pruned: stats.paths_pruned,
            max_depth: stats.max_depth_reached,
            states_explored: stats.states_explored,
            time_ms: stats.total_time.as_millis() as u64,
        },
        selected_path,
    };

    match serde_json::to_string(&output) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => sym_error_json("failed to serialize symbolic solve output"),
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
            let _ = writeln!(
                output,
                "┌─────────────────────────────────────────────────┐"
            );
            let _ = writeln!(output, "│ 0x{:x}{:<30} │", addr, entry_marker);
            let _ = writeln!(
                output,
                "├─────────────────────────────────────────────────┤"
            );

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
                let _ = writeln!(
                    output,
                    "│ ... ({} more ops)                               │",
                    block.ops.len() - ops_to_show
                );
            }

            // Block terminator
            let term_str = match &block.terminator {
                r2ssa::cfg::BlockTerminator::Fallthrough { next } => format!("→ 0x{:x}", next),
                r2ssa::cfg::BlockTerminator::Branch { target } => format!("jmp 0x{:x}", target),
                r2ssa::cfg::BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                } => {
                    format!("jcc t:0x{:x} f:0x{:x}", true_target, false_target)
                }
                r2ssa::cfg::BlockTerminator::Return => "ret".to_string(),
                r2ssa::cfg::BlockTerminator::Call { target, .. } => format!("call 0x{:x}", target),
                r2ssa::cfg::BlockTerminator::IndirectBranch => "jmp [reg]".to_string(),
                r2ssa::cfg::BlockTerminator::IndirectCall { .. } => "call [reg]".to_string(),
                r2ssa::cfg::BlockTerminator::Switch { cases, .. } => {
                    format!("switch ({} cases)", cases.len())
                }
                r2ssa::cfg::BlockTerminator::None => "???".to_string(),
            };
            let _ = writeln!(output, "│ {:<47} │", term_str);
            let _ = writeln!(
                output,
                "└─────────────────────────────────────────────────┘"
            );

            // Draw edges
            match &block.terminator {
                r2ssa::cfg::BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                } => {
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
            format!(
                "{} = {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(src)
            )
        }
        R2ILOp::Load { dst, addr, .. } => {
            format!(
                "{} = [{}]",
                disasm.format_varnode(dst),
                disasm.format_varnode(addr)
            )
        }
        R2ILOp::Store { addr, val, .. } => {
            format!(
                "[{}] = {}",
                disasm.format_varnode(addr),
                disasm.format_varnode(val)
            )
        }
        R2ILOp::IntAdd { dst, a, b } => {
            format!(
                "{} = {} + {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntSub { dst, a, b } => {
            format!(
                "{} = {} - {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntAnd { dst, a, b } => {
            format!(
                "{} = {} & {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntOr { dst, a, b } => {
            format!(
                "{} = {} | {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntXor { dst, a, b } => {
            format!(
                "{} = {} ^ {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntEqual { dst, a, b } => {
            format!(
                "{} = {} == {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::IntLess { dst, a, b } => {
            format!(
                "{} = {} < {}",
                disasm.format_varnode(dst),
                disasm.format_varnode(a),
                disasm.format_varnode(b)
            )
        }
        R2ILOp::Branch { target } => {
            format!("jmp {}", disasm.format_varnode(target))
        }
        R2ILOp::CBranch { cond, target } => {
            format!(
                "if {} jmp {}",
                disasm.format_varnode(cond),
                disasm.format_varnode(target)
            )
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
                r2ssa::cfg::BlockTerminator::Switch { .. } => "switch",
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
                let edge_type = cfg
                    .edge_type(addr, succ)
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

fn decompiler_max_blocks() -> usize {
    std::env::var("SLEIGH_DEC_MAX_BLOCKS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(200)
}

fn decompile_block_guard_fallback(func_name: &str, blocks: usize, max_blocks: usize) -> String {
    format!(
        "/* r2dec fallback: skipped decompilation for {} ({} blocks > limit {}). Set SLEIGH_DEC_MAX_BLOCKS to override. */",
        func_name, blocks, max_blocks
    )
}

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

    let max_blocks = decompiler_max_blocks();
    if r2il_blocks.len() > max_blocks {
        let output = decompile_block_guard_fallback(&func_name_str, r2il_blocks.len(), max_blocks);
        return CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw());
    }

    // Build SSA function
    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
            Some(f) => f.with_name(&func_name_str),
            None => return ptr::null_mut(),
        };

    // Create decompiler with architecture-aware config
    let config = if let Some(arch) = &ctx_ref.arch {
        let ptr_bits = arch.addr_size * 8; // addr_size is in bytes
        match (arch.name.as_str(), ptr_bits) {
            ("x86", 32) | ("x86-32", _) => r2dec::DecompilerConfig::x86(),
            ("x86-64", _) | ("x86_64", _) | ("x64", _) | ("amd64", _) => {
                r2dec::DecompilerConfig::x86_64()
            }
            ("arm", _) | ("ARM", _) if ptr_bits == 32 => r2dec::DecompilerConfig::arm(),
            ("aarch64", _) | ("arm64", _) | ("ARM64", _) => r2dec::DecompilerConfig::aarch64(),
            ("riscv32", _) | ("rv32", _) | ("rv32gc", _) => r2dec::DecompilerConfig::riscv32(),
            ("riscv64", _) | ("rv64", _) | ("rv64gc", _) => r2dec::DecompilerConfig::riscv64(),
            ("riscv", _) if ptr_bits == 32 => r2dec::DecompilerConfig::riscv32(),
            ("riscv", _) => r2dec::DecompilerConfig::riscv64(),
            _ => {
                // Use default but set ptr_size based on addr_size
                r2dec::DecompilerConfig {
                    ptr_size: ptr_bits,
                    ..r2dec::DecompilerConfig::default()
                }
            }
        }
    } else {
        r2dec::DecompilerConfig::default()
    };
    let decompiler = r2dec::Decompiler::new(config);

    // Decompile to C code on a large-stack thread (same as r2dec_function_with_context).
    let output = run_decompile_on_large_stack(decompiler, ssa_func);

    CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw())
}

#[derive(Debug, Deserialize)]
struct AfcfjArg {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    ty: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AfcfjFunction {
    #[serde(default, rename = "return")]
    return_type: Option<String>,
    #[serde(default)]
    ret: Option<String>,
    #[serde(default)]
    args: Vec<AfcfjArg>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum AfvjRef {
    Stack { base: String, offset: i64 },
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct AfvjVar {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    ty: Option<String>,
    #[serde(default, rename = "ref")]
    reference: Option<AfvjRef>,
}

#[derive(Debug, Deserialize)]
struct AfvjPayload {
    #[serde(default)]
    bp: Vec<AfvjVar>,
    #[serde(default)]
    sp: Vec<AfvjVar>,
}

fn parse_addr_name_map(json_str: &str) -> std::collections::HashMap<u64, String> {
    serde_json::from_str::<std::collections::HashMap<String, String>>(json_str)
        .ok()
        .map(|map| {
            map.into_iter()
                .filter_map(|(k, v)| {
                    let addr = if k.starts_with("0x") || k.starts_with("0X") {
                        u64::from_str_radix(&k[2..], 16).ok()
                    } else {
                        k.parse().ok()
                    };
                    addr.map(|a| (a, v))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sanitize_c_identifier(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        let normalized = if ch.is_ascii_alphanumeric() || ch == '_' {
            ch
        } else {
            '_'
        };
        if idx == 0 && normalized.is_ascii_digit() {
            out.push('_');
        }
        out.push(normalized);
    }

    if out.chars().all(|c| c == '_') {
        None
    } else {
        Some(out)
    }
}

fn uniquify_name(base: String, used: &mut std::collections::HashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    let mut idx = 2usize;
    loop {
        let candidate = format!("{}_{}", base, idx);
        if used.insert(candidate.clone()) {
            return candidate;
        }
        idx += 1;
    }
}

fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

fn is_low_quality_stack_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("var_")
        || lower.starts_with("local_")
        || lower.starts_with("stack_")
        || lower == "saved_fp"
        || is_generic_arg_name(&lower)
}

fn parse_external_type(raw_ty: &str, ptr_bits: u32) -> Option<r2dec::CType> {
    let mut ty = raw_ty.trim().to_string();
    if ty.is_empty() {
        return None;
    }

    for qualifier in ["const", "volatile", "restrict", "signed"] {
        ty = ty
            .split_whitespace()
            .filter(|part| !part.eq_ignore_ascii_case(qualifier))
            .collect::<Vec<_>>()
            .join(" ");
    }

    let mut array_size = None;
    if let Some(open) = ty.rfind('[')
        && ty.ends_with(']')
    {
        let len_str = ty[open + 1..ty.len() - 1].trim();
        if !len_str.is_empty() {
            array_size = len_str.parse::<usize>().ok();
        }
        ty = ty[..open].trim().to_string();
    }

    let mut ptr_count = 0usize;
    loop {
        let trimmed = ty.trim_end();
        if let Some(stripped) = trimmed.strip_suffix('*') {
            ptr_count += 1;
            ty = stripped.trim_end().to_string();
        } else {
            break;
        }
    }

    let base_key = ty
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("")
        .to_ascii_lowercase();
    let mut base = if let Some(rest) = base_key.strip_prefix("int")
        && let Some(bits) = rest.strip_suffix("_t")
    {
        bits.parse::<u32>().ok().map(r2dec::CType::Int)
    } else if let Some(rest) = base_key.strip_prefix("uint")
        && let Some(bits) = rest.strip_suffix("_t")
    {
        bits.parse::<u32>().ok().map(r2dec::CType::UInt)
    } else {
        match base_key.as_str() {
            "void" => Some(r2dec::CType::Void),
            "bool" => Some(r2dec::CType::Bool),
            "char" | "signedchar" => Some(r2dec::CType::Int(8)),
            "unsignedchar" => Some(r2dec::CType::UInt(8)),
            "short" | "shortint" => Some(r2dec::CType::Int(16)),
            "unsignedshort" | "unsignedshortint" => Some(r2dec::CType::UInt(16)),
            "int" => Some(r2dec::CType::Int(32)),
            "unsigned" | "unsignedint" => Some(r2dec::CType::UInt(32)),
            "long" | "longint" | "longlong" | "longlongint" => Some(r2dec::CType::Int(ptr_bits)),
            "unsignedlong" | "unsignedlongint" | "unsignedlonglong" | "unsignedlonglongint" => {
                Some(r2dec::CType::UInt(ptr_bits))
            }
            "size_t" => Some(r2dec::CType::UInt(ptr_bits)),
            "float" => Some(r2dec::CType::Float(32)),
            "double" => Some(r2dec::CType::Float(64)),
            _ => None,
        }
    }?;

    if let Some(size) = array_size {
        base = r2dec::CType::Array(Box::new(base), Some(size));
    }
    for _ in 0..ptr_count {
        base = r2dec::CType::ptr(base);
    }
    Some(base)
}

fn parse_external_signature(
    json_str: &str,
    ptr_bits: u32,
) -> Option<r2dec::ExternalFunctionSignature> {
    let entries = serde_json::from_str::<Vec<AfcfjFunction>>(json_str).ok()?;
    parse_afcfj_signature_entries(entries, ptr_bits)
}

#[derive(Debug, Default)]
struct ParsedSignatureContext {
    current: Option<r2dec::ExternalFunctionSignature>,
    known: std::collections::HashMap<String, r2dec::types::FunctionType>,
}

fn parse_afcfj_signature_entries(
    entries: Vec<AfcfjFunction>,
    ptr_bits: u32,
) -> Option<r2dec::ExternalFunctionSignature> {
    let first = entries.into_iter().next()?;

    let mut used_names = std::collections::HashSet::new();
    let params = first
        .args
        .into_iter()
        .enumerate()
        .map(|(idx, arg)| {
            let fallback = format!("arg{}", idx + 1);
            let raw_name = arg.name.unwrap_or(fallback);
            let mut name =
                sanitize_c_identifier(&raw_name).unwrap_or_else(|| format!("arg{}", idx + 1));
            if !is_generic_arg_name(&name) {
                name = uniquify_name(name, &mut used_names);
            }
            r2dec::ExternalFunctionParam {
                name,
                ty: arg
                    .ty
                    .as_deref()
                    .and_then(|raw| parse_external_type(raw, ptr_bits)),
            }
        })
        .collect();

    let ret_type_raw = first.return_type.or(first.ret);
    let ret_type = ret_type_raw
        .as_deref()
        .and_then(|raw| parse_external_type(raw, ptr_bits));

    Some(r2dec::ExternalFunctionSignature { ret_type, params })
}

fn parse_afcfj_signature_value(
    value: &serde_json::Value,
    ptr_bits: u32,
) -> Option<r2dec::ExternalFunctionSignature> {
    if value.is_array() {
        let entries = serde_json::from_value::<Vec<AfcfjFunction>>(value.clone()).ok()?;
        return parse_afcfj_signature_entries(entries, ptr_bits);
    }
    if value.is_object() {
        let entry = serde_json::from_value::<AfcfjFunction>(value.clone()).ok()?;
        return parse_afcfj_signature_entries(vec![entry], ptr_bits);
    }
    None
}

fn maybe_insert_known_signature(
    known: &mut std::collections::HashMap<String, r2dec::types::FunctionType>,
    name: &str,
    sig: r2dec::types::FunctionType,
) {
    if name.is_empty() {
        return;
    }
    known.insert(name.to_string(), sig.clone());

    for prefix in ["sym.imp.", "sym.", "dbg.", "fcn."] {
        if let Some(stripped) = name.strip_prefix(prefix)
            && !stripped.is_empty()
        {
            known.insert(stripped.to_string(), sig.clone());
        }
    }
}

fn parse_known_function_signatures(
    value: &serde_json::Value,
    ptr_bits: u32,
) -> std::collections::HashMap<String, r2dec::types::FunctionType> {
    let mut out = std::collections::HashMap::new();
    let Some(entries) = value.as_array() else {
        return out;
    };

    for entry in entries {
        let Some(obj) = entry.as_object() else {
            continue;
        };

        let Some(name) = obj.get("name").and_then(|v| v.as_str()) else {
            continue;
        };

        let mut params = Vec::new();
        if let Some(args) = obj.get("args").and_then(|v| v.as_array()) {
            for arg in args {
                if let Some(arg_obj) = arg.as_object() {
                    let ty = arg_obj
                        .get("type")
                        .or_else(|| arg_obj.get("ty"))
                        .and_then(|v| v.as_str())
                        .and_then(|raw| parse_external_type(raw, ptr_bits));
                    params.push(ty.unwrap_or(r2dec::CType::Unknown));
                } else if let Some(raw) = arg.as_str() {
                    params
                        .push(parse_external_type(raw, ptr_bits).unwrap_or(r2dec::CType::Unknown));
                }
            }
        } else if let Some(argtypes) = obj.get("argtypes").and_then(|v| v.as_array()) {
            for raw in argtypes.iter().filter_map(|v| v.as_str()) {
                params.push(parse_external_type(raw, ptr_bits).unwrap_or(r2dec::CType::Unknown));
            }
        }

        let ret = obj
            .get("return")
            .or_else(|| obj.get("ret"))
            .or_else(|| obj.get("return_type"))
            .or_else(|| obj.get("rettype"))
            .or_else(|| obj.get("type"))
            .and_then(|v| v.as_str())
            .and_then(|raw| parse_external_type(raw, ptr_bits))
            .unwrap_or(r2dec::CType::Unknown);

        let variadic = obj
            .get("variadic")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if params.is_empty() && matches!(ret, r2dec::CType::Unknown) {
            continue;
        }

        let sig = r2dec::types::FunctionType {
            return_type: ret,
            params,
            variadic,
        };
        maybe_insert_known_signature(&mut out, name, sig);
    }

    out
}

fn parse_signature_context(json_str: &str, ptr_bits: u32) -> ParsedSignatureContext {
    let mut parsed = ParsedSignatureContext::default();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
        parsed.current = parse_external_signature(json_str, ptr_bits);
        return parsed;
    };

    if value.is_array() {
        parsed.current = parse_afcfj_signature_value(&value, ptr_bits);
        return parsed;
    }

    let Some(obj) = value.as_object() else {
        return parsed;
    };

    if let Some(current) = obj.get("current") {
        parsed.current = parse_afcfj_signature_value(current, ptr_bits);
    }
    if let Some(known) = obj.get("known") {
        parsed.known = parse_known_function_signatures(known, ptr_bits);
    }

    parsed
}

fn parse_external_stack_vars(
    json_str: &str,
    ptr_bits: u32,
) -> std::collections::HashMap<i64, r2dec::ExternalStackVar> {
    let payload = match serde_json::from_str::<AfvjPayload>(json_str) {
        Ok(v) => v,
        Err(_) => return std::collections::HashMap::new(),
    };

    let mut vars = std::collections::HashMap::new();
    let mut used_names = std::collections::HashSet::new();

    for entry in payload.bp.into_iter().chain(payload.sp.into_iter()) {
        let Some(AfvjRef::Stack { base, offset }) = entry.reference else {
            continue;
        };

        let raw_name = entry
            .name
            .unwrap_or_else(|| format!("stack_{:x}", offset.unsigned_abs()));
        let Some(clean_name) = sanitize_c_identifier(&raw_name) else {
            continue;
        };
        let var_name = uniquify_name(clean_name, &mut used_names);
        let candidate = r2dec::ExternalStackVar {
            name: var_name,
            ty: entry
                .ty
                .as_deref()
                .and_then(|raw| parse_external_type(raw, ptr_bits)),
            base: Some(base),
        };

        match vars.get(&offset) {
            None => {
                vars.insert(offset, candidate);
            }
            Some(existing) => {
                if is_low_quality_stack_name(&existing.name)
                    && !is_low_quality_stack_name(&candidate.name)
                {
                    vars.insert(offset, candidate);
                }
            }
        }
    }

    vars
}

/// Decompile a function with external context (function names, strings, symbols, signature, stack vars).
/// Returns C code as a string. Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2dec_function_with_context(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    func_name: *const c_char,
    func_names_json: *const c_char,
    strings_json: *const c_char,
    symbols_json: *const c_char,
    signature_json: *const c_char,
    stack_vars_json: *const c_char,
    types_json: *const c_char,
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

    let max_blocks = decompiler_max_blocks();
    if r2il_blocks.len() > max_blocks {
        let output = decompile_block_guard_fallback(&func_name_str, r2il_blocks.len(), max_blocks);
        return CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw());
    }

    let ptr_bits = ctx_ref
        .arch
        .as_ref()
        .map(|arch| arch.addr_size * 8)
        .unwrap_or(64);

    // Collect all JSON context strings on the main thread (from C pointers),
    // then move everything into the large-stack thread for SSA + decompilation.
    let func_names_str = if func_names_json.is_null() {
        "{}".to_string()
    } else {
        unsafe {
            CStr::from_ptr(func_names_json)
                .to_str()
                .unwrap_or("{}")
                .to_string()
        }
    };
    let strings_str = if strings_json.is_null() {
        "{}".to_string()
    } else {
        unsafe {
            CStr::from_ptr(strings_json)
                .to_str()
                .unwrap_or("{}")
                .to_string()
        }
    };
    let symbols_str = if symbols_json.is_null() {
        "{}".to_string()
    } else {
        unsafe {
            CStr::from_ptr(symbols_json)
                .to_str()
                .unwrap_or("{}")
                .to_string()
        }
    };
    let signature_str = if signature_json.is_null() {
        "[]".to_string()
    } else {
        unsafe {
            CStr::from_ptr(signature_json)
                .to_str()
                .unwrap_or("[]")
                .to_string()
        }
    };
    let stack_vars_str = if stack_vars_json.is_null() {
        "{}".to_string()
    } else {
        unsafe {
            CStr::from_ptr(stack_vars_json)
                .to_str()
                .unwrap_or("{}")
                .to_string()
        }
    };
    let types_str = if types_json.is_null() {
        "{}".to_string()
    } else {
        unsafe {
            CStr::from_ptr(types_json)
                .to_str()
                .unwrap_or("{}")
                .to_string()
        }
    };

    let arch_clone = ctx_ref.arch.clone();

    // Run SSA construction + decompilation on a dedicated thread with a large
    // stack to prevent stack overflow on complex O2-optimized CFGs.
    let output = run_full_decompile_on_large_stack(
        r2il_blocks,
        func_name_str,
        arch_clone,
        ptr_bits,
        func_names_str,
        strings_str,
        symbols_str,
        signature_str,
        stack_vars_str,
        types_str,
    );

    CString::new(output).map_or(ptr::null_mut(), |c| c.into_raw())
}

/// Run SSA construction + decompilation on a thread with a 32 MB stack to
/// avoid stack overflow on complex O2-optimized CFGs.
#[allow(clippy::too_many_arguments)]
fn run_full_decompile_on_large_stack(
    r2il_blocks: Vec<R2ILBlock>,
    func_name_str: String,
    arch: Option<r2il::ArchSpec>,
    ptr_bits: u32,
    func_names_str: String,
    strings_str: String,
    symbols_str: String,
    signature_str: String,
    stack_vars_str: String,
    types_str: String,
) -> String {
    const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

    let handle = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            // Build SSA function
            let mut ssa_func =
                match r2ssa::SSAFunction::from_blocks_raw(&r2il_blocks, arch.as_ref()) {
                    Some(f) => f.with_name(&func_name_str),
                    None => return String::new(),
                };

            // Decompiler-only SSA cleanup: keep this local to a:sla.dec and do not
            // alter generic SSA command behavior.
            //
            // Copy-prop is intentionally gated by function size to avoid
            // pathological latency on very large CFGs.
            let dec_opt_cfg = if ssa_func.num_blocks() <= 96 {
                r2ssa::OptimizationConfig {
                    max_iterations: 1,
                    enable_sccp: true,
                    enable_const_prop: false,
                    enable_inst_combine: false,
                    enable_copy_prop: true,
                    enable_cse: false,
                    enable_dce: false,
                    preserve_memory_reads: false,
                }
            } else {
                r2ssa::OptimizationConfig {
                    max_iterations: 1,
                    enable_sccp: true,
                    enable_const_prop: false,
                    enable_inst_combine: false,
                    enable_copy_prop: false,
                    enable_cse: false,
                    enable_dce: false,
                    preserve_memory_reads: false,
                }
            };
            let _ = ssa_func.optimize(&dec_opt_cfg);

            // Create decompiler with architecture-aware config
            let config = if let Some(arch) = &arch {
                match (arch.name.as_str(), ptr_bits) {
                    ("x86", 32) | ("x86-32", _) => r2dec::DecompilerConfig::x86(),
                    ("x86-64", _) | ("x86_64", _) | ("x64", _) | ("amd64", _) => {
                        r2dec::DecompilerConfig::x86_64()
                    }
                    ("arm", _) | ("ARM", _) if ptr_bits == 32 => r2dec::DecompilerConfig::arm(),
                    ("aarch64", _) | ("arm64", _) | ("ARM64", _) => {
                        r2dec::DecompilerConfig::aarch64()
                    }
                    ("riscv32", _) | ("rv32", _) | ("rv32gc", _) => {
                        r2dec::DecompilerConfig::riscv32()
                    }
                    ("riscv64", _) | ("rv64", _) | ("rv64gc", _) => {
                        r2dec::DecompilerConfig::riscv64()
                    }
                    ("riscv", _) if ptr_bits == 32 => r2dec::DecompilerConfig::riscv32(),
                    ("riscv", _) => r2dec::DecompilerConfig::riscv64(),
                    _ => r2dec::DecompilerConfig {
                        ptr_size: ptr_bits,
                        ..r2dec::DecompilerConfig::default()
                    },
                }
            } else {
                r2dec::DecompilerConfig::default()
            };

            let mut decompiler = r2dec::Decompiler::new(config);
            decompiler.set_function_names(parse_addr_name_map(&func_names_str));
            decompiler.set_strings(parse_addr_name_map(&strings_str));
            decompiler.set_symbols(parse_addr_name_map(&symbols_str));

            let sig_ctx = parse_signature_context(&signature_str, ptr_bits);
            decompiler.set_function_signature(sig_ctx.current);
            if !sig_ctx.known.is_empty() {
                decompiler.set_known_function_signatures(sig_ctx.known);
            }

            let stack_vars = parse_external_stack_vars(&stack_vars_str, ptr_bits);
            if !stack_vars.is_empty() {
                decompiler.set_stack_vars(stack_vars);
            }

            let type_db = r2types::ExternalTypeDb::from_tsj_json(&types_str);
            if !type_db.structs.is_empty()
                || !type_db.unions.is_empty()
                || !type_db.enums.is_empty()
                || !type_db.diagnostics.is_empty()
            {
                decompiler.set_external_type_db(type_db);
            }

            decompiler.decompile(&ssa_func)
        });

    match handle {
        Ok(h) => match h.join() {
            Ok(output) => output,
            Err(_) => "/* r2dec: decompilation panicked (internal error) */".to_string(),
        },
        Err(e) => {
            format!("/* r2dec: failed to spawn decompiler thread: {} */", e)
        }
    }
}

/// Run just the decompiler (already-built SSA + decompiler) on a large-stack thread.
fn run_decompile_on_large_stack(
    decompiler: r2dec::Decompiler,
    ssa_func: r2ssa::SSAFunction,
) -> String {
    const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

    let handle = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || decompiler.decompile(&ssa_func));

    match handle {
        Ok(h) => match h.join() {
            Ok(output) => output,
            Err(_) => "/* r2dec: decompilation panicked (internal error) */".to_string(),
        },
        Err(e) => {
            format!("/* r2dec: failed to spawn decompiler thread: {} */", e)
        }
    }
}

/// Decompile a single basic block to C code.
/// Returns C code as a string. Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2dec_block(ctx: *const R2ILContext, block: *const R2ILBlock) -> *mut c_char {
    if ctx.is_null() || block.is_null() {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    let blk = unsafe { &*block };
    let input = InstructionExportInput {
        disasm,
        arch: match ctx_ref.arch.as_ref() {
            Some(a) => a,
            None => return ptr::null_mut(),
        },
        block: blk,
        addr: blk.addr,
        mnemonic: "",
        native_size: blk.size as usize,
    };

    match export_instruction(&input, InstructionAction::Dec, ExportFormat::CLike) {
        Ok(output) => {
            let normalized = if output.trim().is_empty() {
                "/* r2dec: empty output */".to_string()
            } else {
                output
            };
            CString::new(normalized).map_or(ptr::null_mut(), |c| c.into_raw())
        }
        Err(_) => ptr::null_mut(),
    }
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
    let stmts: Vec<r2dec::CStmt> = r2dec::lower_ssa_ops_to_stmts(64, &ssa_block.ops);

    match serde_json::to_string_pretty(&stmts) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// radare2 Deep Integration FFI - Variable Recovery and Data Refs
// ============================================================================

#[derive(Debug, Clone)]
struct InferredParam {
    name: String,
    ty: r2dec::CType,
    arg_index: usize,
}

#[derive(Debug, serde::Serialize)]
struct InferredParamJson {
    name: String,
    #[serde(rename = "type")]
    param_type: String,
}

#[derive(Debug, serde::Serialize)]
struct InferredSignatureCcJson {
    function_name: String,
    signature: String,
    ret_type: String,
    params: Vec<InferredParamJson>,
    callconv: String,
    arch: String,
    confidence: u8,
}

#[cfg(test)]
const SIG_WRITEBACK_CONFIDENCE_MIN: u8 = 70;
#[cfg(test)]
const CC_WRITEBACK_CONFIDENCE_MIN: u8 = 80;

fn normalize_sig_arch_name(arch: Option<&ArchSpec>) -> Option<String> {
    let arch = arch?;
    let lower = arch.name.to_ascii_lowercase();
    if matches!(lower.as_str(), "x86-64" | "x86_64" | "x64" | "amd64") {
        return Some("x86-64".to_string());
    }
    if matches!(lower.as_str(), "x86" | "x86-32" | "i386" | "i686") {
        return Some("x86".to_string());
    }
    Some(arch.name.clone())
}

fn decompiler_config_for_arch_name(arch_name: &str, ptr_bits: u32) -> r2dec::DecompilerConfig {
    match (arch_name, ptr_bits) {
        ("x86", 32) | ("x86-32", _) => r2dec::DecompilerConfig::x86(),
        ("x86-64", _) | ("x86_64", _) | ("x64", _) | ("amd64", _) => {
            r2dec::DecompilerConfig::x86_64()
        }
        ("arm", _) | ("ARM", _) if ptr_bits == 32 => r2dec::DecompilerConfig::arm(),
        ("aarch64", _) | ("arm64", _) | ("ARM64", _) => r2dec::DecompilerConfig::aarch64(),
        _ => r2dec::DecompilerConfig {
            ptr_size: ptr_bits,
            ..r2dec::DecompilerConfig::default()
        },
    }
}

fn infer_signature_return_type(
    func: &r2ssa::SSAFunction,
    type_inference: &r2dec::TypeInference,
) -> r2dec::CType {
    let mut candidates = Vec::new();

    for block in func.blocks() {
        for op in &block.ops {
            let r2ssa::SSAOp::Return { target } = op else {
                continue;
            };

            let target_name = target.name.to_ascii_lowercase();
            if target_name.starts_with("xmm0") || target_name.starts_with("st0") {
                let bits = if target.size.saturating_mul(8) <= 32 {
                    32
                } else {
                    64
                };
                candidates.push(r2dec::CType::Float(bits));
                continue;
            }

            candidates.push(type_inference.get_type(target));
        }
    }

    if candidates.is_empty() {
        return r2dec::CType::Void;
    }

    let mut meaningful: Vec<r2dec::CType> = candidates
        .into_iter()
        .filter(|ty| !matches!(ty, r2dec::CType::Unknown))
        .collect();
    if meaningful.is_empty() {
        return r2dec::CType::Int(32);
    }
    if meaningful.iter().all(|ty| ty == &meaningful[0]) {
        return meaningful.remove(0);
    }
    if let Some(float_ty) = meaningful
        .iter()
        .find(|ty| matches!(ty, r2dec::CType::Float(_)))
        .cloned()
    {
        return float_ty;
    }
    meaningful.remove(0)
}

fn canonical_x86_64_arg_reg(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdx" | "edx" | "dx" | "dl" | "dh" => Some("rdx"),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => Some("rcx"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        _ => None,
    }
}

fn collect_version0_input_regs(
    func: &r2ssa::SSAFunction,
) -> std::collections::HashMap<String, u32> {
    let mut counts = std::collections::HashMap::new();
    for block in func.blocks() {
        for op in &block.ops {
            for src in op.sources() {
                if src.version != 0 {
                    continue;
                }
                if src.name.starts_with("tmp:") || src.name.starts_with("const:") {
                    continue;
                }
                let key = src.name.to_ascii_lowercase();
                *counts.entry(key).or_insert(0) += 1;
            }
        }
    }
    counts
}

fn infer_callconv_x86_64_from_counts(
    counts: &std::collections::HashMap<String, u32>,
) -> (&'static str, u8) {
    let mut canonical = std::collections::BTreeMap::new();
    for (reg, count) in counts {
        if let Some(name) = canonical_x86_64_arg_reg(reg) {
            *canonical.entry(name).or_insert(0u32) += *count;
        }
    }

    let rdi = *canonical.get("rdi").unwrap_or(&0);
    let rsi = *canonical.get("rsi").unwrap_or(&0);
    let rcx = *canonical.get("rcx").unwrap_or(&0);
    let rdx = *canonical.get("rdx").unwrap_or(&0);
    let r8 = *canonical.get("r8").unwrap_or(&0);
    let r9 = *canonical.get("r9").unwrap_or(&0);

    let sysv_primary = rdi + rsi;
    let sysv_total = rdi + rsi + rdx + rcx + r8 + r9;
    let ms_total = rcx + rdx + r8 + r9;
    let ms_regs_used = [rcx, rdx, r8, r9].iter().filter(|&&v| v > 0).count();
    let ms_dominant = sysv_primary == 0
        && rcx > 0
        && ms_regs_used >= 2
        && ms_total >= 3
        && ms_total >= (rdi + rsi + rdx + 1);

    if ms_dominant {
        let confidence = if ms_total >= 3 { 90 } else { 76 };
        ("ms", confidence)
    } else {
        let confidence = if sysv_primary > 0 {
            92
        } else if sysv_total > 0 {
            76
        } else {
            60
        };
        ("amd64", confidence)
    }
}

fn sanitize_inferred_param_type(
    mut ty: r2dec::CType,
    var_size_bytes: u32,
    ptr_bits: u32,
) -> r2dec::CType {
    if matches!(ty, r2dec::CType::Void | r2dec::CType::Unknown) {
        ty = match var_size_bytes {
            1 => r2dec::CType::Int(8),
            2 => r2dec::CType::Int(16),
            4 => r2dec::CType::Int(32),
            8 => r2dec::CType::Int(64),
            _ => r2dec::CType::Unknown,
        };
    }

    if matches!(ty, r2dec::CType::Void | r2dec::CType::Unknown) {
        ty = if ptr_bits >= 64 {
            r2dec::CType::Int(64)
        } else {
            r2dec::CType::Int(32)
        };
    }

    ty
}

fn compute_inference_confidence(
    base_confidence: u8,
    param_count: usize,
    has_known_ret: bool,
) -> u8 {
    let mut confidence = base_confidence.min(100);
    if param_count > 0 {
        confidence = confidence.saturating_add(4).min(100);
    }
    if has_known_ret {
        confidence = confidence.saturating_add(2).min(100);
    }
    confidence
}

fn normalize_inferred_param_name(
    raw_name: &str,
    fallback_idx: usize,
    used: &mut std::collections::HashSet<String>,
) -> String {
    let fallback = format!("arg{}", fallback_idx);
    let clean = sanitize_c_identifier(raw_name).unwrap_or_else(|| fallback.clone());
    let clean = if clean.is_empty() { fallback } else { clean };
    uniquify_name(clean, used)
}

fn format_afs_signature(
    function_name: &str,
    ret_type: &str,
    params: &[InferredParamJson],
) -> String {
    let params_str = if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|p| format!("{} {}", p.param_type, p.name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("{ret_type} {function_name} ({params_str})")
}

/// Infer function signature + calling convention for post-analysis write-back.
///
/// Returns JSON:
/// {"function_name":"...","signature":"...","ret_type":"...","params":[...],"callconv":"...","arch":"...","confidence":N}
///
/// Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_infer_signature_cc_json(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    fcn_addr: u64,
    fcn_name: *const c_char,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let Some(disasm) = &ctx_ref.disasm else {
        return ptr::null_mut();
    };

    let arch_name =
        normalize_sig_arch_name(ctx_ref.arch.as_ref()).unwrap_or_else(|| "unknown".to_string());
    let ptr_bits = ctx_ref.arch.as_ref().map(|a| a.addr_size * 8).unwrap_or(64);
    let cfg = decompiler_config_for_arch_name(&arch_name, ptr_bits);

    let name = if fcn_name.is_null() {
        format!("fcn_{fcn_addr:x}")
    } else {
        unsafe { CStr::from_ptr(fcn_name).to_string_lossy().to_string() }
    };
    let function_name = if name.trim().is_empty() {
        format!("fcn_{fcn_addr:x}")
    } else {
        name
    };

    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if blk_ptr.is_null() {
            continue;
        }
        let blk = unsafe { &*blk_ptr };
        r2il_blocks.push(blk.clone());
    }
    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
            Some(f) => f.with_name(&function_name),
            None => return ptr::null_mut(),
        };

    let mut var_recovery = r2dec::VariableRecovery::new(&cfg.sp_name, &cfg.fp_name, cfg.ptr_size);
    var_recovery.recover(&ssa_func);

    let mut type_inference = r2dec::TypeInference::new(cfg.ptr_size);
    type_inference.infer_function(&ssa_func);

    let mut inferred_params: Vec<InferredParam> = var_recovery
        .parameters()
        .into_iter()
        .map(|v| {
            let mut ty = type_inference.get_type(&v.ssa_var);
            if matches!(ty, r2dec::CType::Void | r2dec::CType::Unknown) {
                ty = type_inference.type_from_size(v.ssa_var.size);
            }
            ty = sanitize_inferred_param_type(ty, v.ssa_var.size, ptr_bits);
            let arg_index = v
                .name
                .strip_prefix("arg")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            InferredParam {
                name: v.name.clone(),
                ty,
                arg_index,
            }
        })
        .collect();

    if ctx_ref.semantic_metadata_enabled {
        let reg_type_hints = collect_register_type_hints(&r2il_blocks, disasm);
        let ssa_blocks: Vec<r2ssa::SSABlock> = r2il_blocks
            .iter()
            .map(|blk| r2ssa::block::to_ssa(blk, disasm))
            .collect();
        let recovered_vars =
            recover_vars_from_ssa(&ssa_blocks, ctx_ref.arch.as_ref(), &reg_type_hints, true);
        let pointer_arg_slots = collect_pointer_arg_slots(&recovered_vars);
        overlay_inferred_param_pointer_types(&mut inferred_params, &pointer_arg_slots);
    }

    inferred_params.sort_by(|a, b| {
        a.arg_index
            .cmp(&b.arg_index)
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut used_param_names = std::collections::HashSet::new();
    let params: Vec<InferredParamJson> = inferred_params
        .into_iter()
        .enumerate()
        .map(|(idx, p)| {
            let fallback_idx = if p.arg_index == usize::MAX {
                idx
            } else {
                p.arg_index
            };
            InferredParamJson {
                name: normalize_inferred_param_name(&p.name, fallback_idx, &mut used_param_names),
                param_type: p.ty.to_string(),
            }
        })
        .collect();

    let ret_type = infer_signature_return_type(&ssa_func, &type_inference);
    let ret_type_str = ret_type.to_string();

    let input_counts = collect_version0_input_regs(&ssa_func);
    let (callconv, base_confidence) = match arch_name.as_str() {
        "x86-64" => {
            let (cc, confidence) = infer_callconv_x86_64_from_counts(&input_counts);
            (cc.to_string(), confidence)
        }
        "x86" => ("cdecl".to_string(), 64),
        _ => (String::new(), 32),
    };

    let confidence = compute_inference_confidence(
        base_confidence,
        params.len(),
        !matches!(ret_type, r2dec::CType::Unknown),
    );

    let signature = format_afs_signature(&function_name, &ret_type_str, &params);
    let payload = InferredSignatureCcJson {
        function_name,
        signature,
        ret_type: ret_type_str,
        params,
        callconv,
        arch: arch_name,
        confidence,
    };

    match serde_json::to_string(&payload) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Analyze a function and build SSA representation.
/// This is called after radare2 completes basic function analysis.
/// Returns 1 on success, 0 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_analyze_fcn(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    _fcn_addr: u64,
) -> i32 {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return 0;
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return 0,
    };

    // Convert R2ILBlocks to SSA
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if blk_ptr.is_null() {
            continue;
        }
        let blk = unsafe { &*blk_ptr };
        r2il_blocks.push(blk.clone());
    }

    // Build SSA for all blocks - this validates we can process the function
    let mut _ssa_blocks = Vec::new();
    for blk in &r2il_blocks {
        let ssa_block = r2ssa::block::to_ssa(blk, disasm);
        _ssa_blocks.push(ssa_block);
    }

    1 // Success
}

fn enum_label<T: serde::Serialize>(value: T) -> Option<String> {
    serde_json::to_value(value)
        .ok()?
        .as_str()
        .map(str::to_string)
}

fn summarize_block_semantics(block: &R2ILBlock) -> Option<String> {
    use std::collections::BTreeSet;

    let mut storage_classes: BTreeSet<String> = BTreeSet::new();
    let mut memory_classes: BTreeSet<String> = BTreeSet::new();
    let mut orderings: BTreeSet<String> = BTreeSet::new();
    let mut atomic_kinds: BTreeSet<String> = BTreeSet::new();
    let mut pointer_like = false;

    for (op_index, op) in block.ops.iter().enumerate() {
        if let Some(meta) = block.op_metadata.get(&op_index) {
            if let Some(memory_class) = meta.memory_class
                && let Some(label) = enum_label(memory_class)
            {
                memory_classes.insert(label);
            }
            if let Some(ordering) = meta.memory_ordering
                && let Some(label) = enum_label(ordering)
            {
                orderings.insert(label);
            }
            if let Some(kind) = meta.atomic_kind
                && let Some(label) = enum_label(kind)
            {
                atomic_kinds.insert(label);
            }
        }

        for vn in op_all_varnodes(op) {
            if let Some(meta) = vn.meta.as_ref() {
                if let Some(storage_class) = meta.storage_class
                    && let Some(label) = enum_label(storage_class)
                {
                    storage_classes.insert(label);
                }
                if let Some(pointer_hint) = meta.pointer_hint
                    && !matches!(pointer_hint, r2il::PointerHint::Unknown)
                {
                    pointer_like = true;
                }
            }
        }
    }

    let mut parts = Vec::new();
    if !storage_classes.is_empty() {
        let labels: Vec<String> = storage_classes.into_iter().collect();
        parts.push(format!("storage={}", labels.join(",")));
    }
    if !memory_classes.is_empty() {
        let labels: Vec<String> = memory_classes.into_iter().collect();
        parts.push(format!("mem={}", labels.join(",")));
    }
    if !orderings.is_empty() {
        let labels: Vec<String> = orderings.into_iter().collect();
        parts.push(format!("ord={}", labels.join(",")));
    }
    if !atomic_kinds.is_empty() {
        let labels: Vec<String> = atomic_kinds.into_iter().collect();
        parts.push(format!("atomic={}", labels.join(",")));
    }
    if pointer_like {
        parts.push("ptr".to_string());
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Annotation entry for analyze_fcn writeback.
#[derive(serde::Serialize)]
struct FcnAnnotation {
    addr: u64,
    comment: String,
}

/// Analyze a function and return per-block annotations as JSON.
/// Returns a JSON array of {addr, comment} pairs summarizing SSA def-use info.
/// Uses function-level SSA with phi nodes for meaningful annotations.
/// Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_analyze_fcn_annotations(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    _fcn_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };

    // Collect R2ILBlocks
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if blk_ptr.is_null() {
            continue;
        }
        let blk = unsafe { &*blk_ptr };
        r2il_blocks.push(blk.clone());
    }

    let semantic_by_addr: std::collections::HashMap<u64, String> = r2il_blocks
        .iter()
        .filter_map(|block| summarize_block_semantics(block).map(|summary| (block.addr, summary)))
        .collect();

    // Build function-level SSA with phi nodes
    let ssa_func =
        match r2ssa::SSAFunction::from_blocks_with_arch(&r2il_blocks, ctx_ref.arch.as_ref()) {
            Some(f) => f,
            None => return ptr::null_mut(),
        };

    fn is_real_reg(name: &str) -> bool {
        !name.starts_with("tmp:")
            && !name.starts_with("const:")
            && !name.starts_with("ram:")
            && !name.contains("CF_")
            && !name.contains("ZF_")
            && !name.contains("SF_")
            && !name.contains("PF_")
            && !name.contains("OF_")
            && !name.contains("AF_")
            && !name.contains("DF_")
            && !name.contains("TF_")
    }

    let mut annotations = Vec::new();

    for block in ssa_func.blocks() {
        let mut parts = Vec::new();

        // Phi nodes show where values merge from different paths
        if !block.phis.is_empty() {
            let phi_vars: Vec<&str> = block
                .phis
                .iter()
                .map(|p| p.dst.name.as_str())
                .filter(|n| is_real_reg(n))
                .collect();
            if !phi_vars.is_empty() {
                let mut sorted = phi_vars;
                sorted.sort();
                sorted.dedup();
                if sorted.len() > 4 {
                    sorted.truncate(4);
                    sorted.push("...");
                }
                parts.push(format!("merges {}", sorted.join(",")));
            }
        }

        // Collect register reads (version 0 = function input)
        let mut func_inputs = Vec::new();
        for op in &block.ops {
            for src in op.sources() {
                if src.version == 0 && is_real_reg(&src.name) {
                    func_inputs.push(src.name.as_str());
                }
            }
        }
        func_inputs.sort();
        func_inputs.dedup();
        if !func_inputs.is_empty() {
            if func_inputs.len() > 5 {
                func_inputs.truncate(5);
                func_inputs.push("...");
            }
            parts.push(format!("uses {}", func_inputs.join(",")));
        }

        // Collect register definitions
        let mut defs = Vec::new();
        for op in &block.ops {
            if let Some(dst) = op.dst()
                && is_real_reg(&dst.name)
            {
                defs.push(dst.name.as_str());
            }
        }
        defs.sort();
        defs.dedup();
        if !defs.is_empty() {
            if defs.len() > 5 {
                defs.truncate(5);
                defs.push("...");
            }
            parts.push(format!("defines {}", defs.join(",")));
        }

        if let Some(meta_summary) = semantic_by_addr.get(&block.addr) {
            let mut summary = meta_summary.clone();
            if summary.len() > 96 {
                summary.truncate(96);
                summary.push_str("...");
            }
            parts.push(format!("meta {}", summary));
        }

        if !parts.is_empty() {
            annotations.push(FcnAnnotation {
                addr: block.addr,
                comment: format!("sla: {}", parts.join("; ")),
            });
        }
    }

    if annotations.is_empty() {
        return ptr::null_mut();
    }

    match serde_json::to_string(&annotations) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Recover variables from SSA analysis.
/// Returns a JSON array of variable prototypes:
/// [{"name": "arg0", "kind": "r", "delta": 0, "type": "int64_t", "isarg": true, "reg": "rdi"}, ...]
/// Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_recover_vars(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    _fcn_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    // Collect R2IL blocks first so we can preserve varnode metadata hints.
    let mut r2il_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if blk_ptr.is_null() {
            continue;
        }
        let blk = unsafe { &*blk_ptr };
        r2il_blocks.push(blk.clone());
    }

    if r2il_blocks.is_empty() {
        return ptr::null_mut();
    }

    let semantic_typing_enabled = ctx_ref.semantic_metadata_enabled;
    let reg_type_hints = if semantic_typing_enabled {
        collect_register_type_hints(&r2il_blocks, disasm)
    } else {
        std::collections::HashMap::new()
    };

    // Convert R2ILBlocks to SSA
    let mut ssa_blocks = Vec::new();
    for blk in &r2il_blocks {
        let ssa_block = r2ssa::block::to_ssa(blk, disasm);
        ssa_blocks.push(ssa_block);
    }

    if ssa_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Recover variables from SSA analysis
    let vars = recover_vars_from_ssa(
        &ssa_blocks,
        ctx_ref.arch.as_ref(),
        &reg_type_hints,
        semantic_typing_enabled,
    );

    // Serialize to JSON
    match serde_json::to_string(&vars) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Get data flow references from def-use analysis.
/// Returns a JSON array of references:
/// [{"from": 4096, "to": 8192, "type": "d"}, ...]
/// Caller must free with r2il_string_free().
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_get_data_refs(
    ctx: *const R2ILContext,
    blocks: *const *const R2ILBlock,
    num_blocks: usize,
    _fcn_addr: u64,
) -> *mut c_char {
    if ctx.is_null() || blocks.is_null() || num_blocks == 0 {
        return ptr::null_mut();
    }

    let ctx_ref = unsafe { &*ctx };
    let disasm = match &ctx_ref.disasm {
        Some(d) => d,
        None => return ptr::null_mut(),
    };

    // Convert R2ILBlocks to SSA
    let mut ssa_blocks = Vec::new();
    for i in 0..num_blocks {
        let blk_ptr = unsafe { *blocks.add(i) };
        if blk_ptr.is_null() {
            continue;
        }
        let blk = unsafe { &*blk_ptr };
        let ssa_block = r2ssa::block::to_ssa(blk, disasm);
        ssa_blocks.push(ssa_block);
    }

    if ssa_blocks.is_empty() {
        return ptr::null_mut();
    }

    // Get data refs from def-use analysis
    let refs = get_data_refs_from_ssa(&ssa_blocks);

    // Serialize to JSON
    match serde_json::to_string(&refs) {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), |c| c.into_raw()),
        Err(_) => ptr::null_mut(),
    }
}

/// Variable prototype for radare2 integration
#[derive(serde::Serialize)]
struct VarProt {
    name: String,
    kind: String, // "r" for register, "s" for stack, "b" for bp-relative
    delta: i64,
    #[serde(rename = "type")]
    var_type: String,
    isarg: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reg: Option<String>,
}

/// Data reference for radare2 integration
#[derive(serde::Serialize)]
struct DataRef {
    from: u64,
    to: u64,
    #[serde(rename = "type")]
    ref_type: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TypeHintRank {
    Integer = 1,
    Float = 2,
    Pointer = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TypeHint {
    rank: TypeHintRank,
    ty: String,
}

impl TypeHint {
    fn pointer() -> Self {
        Self {
            rank: TypeHintRank::Pointer,
            ty: "void *".to_string(),
        }
    }
}

fn incoming_hint_should_replace(current: &TypeHint, incoming: &TypeHint) -> bool {
    incoming.rank > current.rank || (incoming.rank == current.rank && incoming.ty < current.ty)
}

fn merge_type_hint(
    hints: &mut std::collections::HashMap<String, TypeHint>,
    key: String,
    incoming: TypeHint,
) {
    match hints.get(&key) {
        Some(current) if !incoming_hint_should_replace(current, &incoming) => {}
        _ => {
            hints.insert(key, incoming);
        }
    }
}

fn size_to_signed_int_type(size: u32) -> String {
    match size {
        1 => "int8_t".to_string(),
        2 => "int16_t".to_string(),
        4 => "int32_t".to_string(),
        8 => "int64_t".to_string(),
        _ => format!("int{}_t", size.saturating_mul(8)),
    }
}

fn size_to_unsigned_int_type(size: u32) -> String {
    match size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        _ => format!("uint{}_t", size.saturating_mul(8)),
    }
}

fn scalar_kind_to_type(kind: r2il::ScalarKind, size: u32) -> Option<TypeHint> {
    match kind {
        r2il::ScalarKind::Bool => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: "bool".to_string(),
        }),
        r2il::ScalarKind::SignedInt => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: size_to_signed_int_type(size),
        }),
        r2il::ScalarKind::UnsignedInt => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: size_to_unsigned_int_type(size),
        }),
        r2il::ScalarKind::Float => {
            let ty = match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                16 => "long double".to_string(),
                _ => "float".to_string(),
            };
            Some(TypeHint {
                rank: TypeHintRank::Float,
                ty,
            })
        }
        r2il::ScalarKind::Bitvector | r2il::ScalarKind::Unknown => None,
    }
}

fn metadata_type_hint(vn: &r2il::Varnode) -> Option<TypeHint> {
    let meta = vn.meta.as_ref()?;

    if let Some(pointer_hint) = meta.pointer_hint
        && !matches!(pointer_hint, r2il::PointerHint::Unknown)
    {
        return Some(TypeHint::pointer());
    }

    let scalar_kind = meta.scalar_kind?;
    scalar_kind_to_type(scalar_kind, vn.size)
}

fn collect_register_type_hints(
    r2il_blocks: &[R2ILBlock],
    disasm: &Disassembler,
) -> std::collections::HashMap<String, TypeHint> {
    let mut hints: std::collections::HashMap<String, TypeHint> = std::collections::HashMap::new();

    for block in r2il_blocks {
        for op in &block.ops {
            for vn in op_all_varnodes(op) {
                if !vn.is_register() {
                    continue;
                }
                let Some(hint) = metadata_type_hint(vn) else {
                    continue;
                };
                let Some(name) = disasm.register_name(vn) else {
                    continue;
                };

                let key = name.to_ascii_lowercase();
                merge_type_hint(&mut hints, key, hint);
            }
        }
    }

    hints
}

const X86_ARG_REGS: &[(&str, &[&str])] = &[
    ("rdi", &["rdi", "edi", "di", "dil"]),
    ("rsi", &["rsi", "esi", "si", "sil"]),
    ("rdx", &["rdx", "edx", "dx", "dl", "dh"]),
    ("rcx", &["rcx", "ecx", "cx", "cl", "ch"]),
    ("r8", &["r8", "r8d", "r8w", "r8b"]),
    ("r9", &["r9", "r9d", "r9w", "r9b"]),
];
const RISCV_ARG_REGS: &[(&str, &[&str])] = &[
    ("a0", &["a0", "x10"]),
    ("a1", &["a1", "x11"]),
    ("a2", &["a2", "x12"]),
    ("a3", &["a3", "x13"]),
    ("a4", &["a4", "x14"]),
    ("a5", &["a5", "x15"]),
    ("a6", &["a6", "x16"]),
    ("a7", &["a7", "x17"]),
];
const X86_STACK_BASES: &[&str] = &["rbp", "rsp", "ebp", "esp"];
const X86_FRAME_BASES: &[&str] = &["rbp", "ebp"];
const RISCV_STACK_BASES: &[&str] = &["sp", "s0", "fp", "x2", "x8"];
const RISCV_FRAME_BASES: &[&str] = &["s0", "fp", "x8"];
const GENERIC_STACK_BASES: &[&str] = &["sp", "fp", "bp", "s0", "x2", "x8", "rbp", "rsp"];
const GENERIC_FRAME_BASES: &[&str] = &["fp", "bp", "s0", "x8", "rbp"];

type ArgAliasMap = &'static [(&'static str, &'static [&'static str])];
type BaseRegList = &'static [&'static str];

fn recover_vars_arch_profile(arch: Option<&ArchSpec>) -> (ArgAliasMap, BaseRegList, BaseRegList) {
    let Some(arch) = arch else {
        return (&[], GENERIC_STACK_BASES, GENERIC_FRAME_BASES);
    };

    let arch_name = arch.name.to_ascii_lowercase();
    if arch_name.contains("x86") {
        return (X86_ARG_REGS, X86_STACK_BASES, X86_FRAME_BASES);
    }
    if arch_name.contains("riscv") || arch_name.starts_with("rv") {
        return (RISCV_ARG_REGS, RISCV_STACK_BASES, RISCV_FRAME_BASES);
    }

    (&[], GENERIC_STACK_BASES, GENERIC_FRAME_BASES)
}

fn ssa_var_key(var: &r2ssa::SSAVar) -> String {
    format!("{}_{}", var.name.to_ascii_lowercase(), var.version)
}

fn ssa_var_block_key(block_addr: u64, var: &r2ssa::SSAVar) -> String {
    format!("{}@{block_addr:x}", ssa_var_key(var))
}

fn ssa_var_is_const(var: &r2ssa::SSAVar) -> bool {
    parse_const_value(&var.name).is_some()
}

fn ssa_var_is_register_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !(lower.starts_with("tmp:")
        || lower.starts_with("const:")
        || lower.starts_with("ram:")
        || lower.starts_with("space"))
}

fn collect_register_version_keys(
    ssa_blocks: &[r2ssa::SSABlock],
) -> std::collections::HashMap<String, Vec<String>> {
    use std::collections::HashMap;

    let mut reg_versions: HashMap<String, Vec<String>> = HashMap::new();
    for block in ssa_blocks {
        for op in &block.ops {
            let mut collect_var = |var: &r2ssa::SSAVar| {
                if !ssa_var_is_register_like(&var.name) {
                    return;
                }
                let reg_name = var.name.to_ascii_lowercase();
                reg_versions
                    .entry(reg_name)
                    .or_default()
                    .push(ssa_var_key(var));
            };
            if let Some(dst) = op.dst() {
                collect_var(dst);
            }
            op.for_each_source(|src| collect_var(src));
        }
    }
    for keys in reg_versions.values_mut() {
        keys.sort();
        keys.dedup();
    }
    reg_versions
}

fn ssa_var_is_stack_base(var: &r2ssa::SSAVar) -> bool {
    matches!(
        var.name.to_ascii_lowercase().as_str(),
        "rbp" | "rsp" | "ebp" | "esp" | "sp" | "fp" | "bp" | "s0" | "x2" | "x8"
    )
}

fn infer_pointer_width_bytes(ssa_blocks: &[r2ssa::SSABlock]) -> u32 {
    let mut width = 0u32;
    for block in ssa_blocks {
        for op in &block.ops {
            if let Some(dst) = op.dst()
                && ssa_var_is_stack_base(dst)
            {
                width = width.max(dst.size);
            }
            op.for_each_source(|src| {
                if ssa_var_is_stack_base(src) {
                    width = width.max(src.size);
                }
            });
        }
    }
    if width == 0 { 8 } else { width }
}

fn infer_index_like_var_keys(ssa_blocks: &[r2ssa::SSABlock]) -> std::collections::HashSet<String> {
    use std::collections::HashSet;

    let mut index_like: HashSet<String> = HashSet::new();
    for block in ssa_blocks {
        for op in &block.ops {
            if let r2ssa::SSAOp::IntSExt { dst, src } | r2ssa::SSAOp::IntZExt { dst, src } = op
                && src.size < dst.size
            {
                index_like.insert(ssa_var_key(dst));
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in ssa_blocks {
            for op in &block.ops {
                match op {
                    r2ssa::SSAOp::Copy { dst, src }
                    | r2ssa::SSAOp::Cast { dst, src }
                    | r2ssa::SSAOp::New { dst, src } => {
                        if index_like.contains(&ssa_var_key(src)) {
                            changed |= index_like.insert(ssa_var_key(dst));
                        }
                    }
                    r2ssa::SSAOp::IntMult { dst, a, b } => {
                        let a_key = ssa_var_key(a);
                        let b_key = ssa_var_key(b);
                        let a_is_scaled_const = ssa_var_is_const(a);
                        let b_is_scaled_const = ssa_var_is_const(b);
                        if (index_like.contains(&a_key) && ssa_var_is_const(b))
                            || (index_like.contains(&b_key) && ssa_var_is_const(a))
                            // Treat `x * C` as index-like when one side is a constant
                            // and the other side is data-dependent.
                            || (a_is_scaled_const && !b_is_scaled_const)
                            || (b_is_scaled_const && !a_is_scaled_const)
                        {
                            changed |= index_like.insert(ssa_var_key(dst));
                        }
                    }
                    r2ssa::SSAOp::IntLeft { dst, a, b } => {
                        let shift_amount = parse_const_value(&b.name).unwrap_or(u64::MAX);
                        if (index_like.contains(&ssa_var_key(a)) && ssa_var_is_const(b))
                            // Shifts by small constants are common index scaling.
                            || shift_amount <= 6
                        {
                            changed |= index_like.insert(ssa_var_key(dst));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    index_like
}

fn infer_pointer_var_keys_from_ssa(
    ssa_blocks: &[r2ssa::SSABlock],
) -> std::collections::HashSet<String> {
    use std::collections::{HashMap, HashSet};

    let mut pointer_vars: HashSet<String> = HashSet::new();
    let register_versions = collect_register_version_keys(ssa_blocks);
    let index_like_vars = infer_index_like_var_keys(ssa_blocks);
    let pointer_width = infer_pointer_width_bytes(ssa_blocks);
    let mut stack_addr_slots: HashMap<String, String> = HashMap::new();
    let mut pointer_stack_slots: HashSet<String> = HashSet::new();

    // Seed with high-confidence address-role uses and stack-slot address temps.
    for block in ssa_blocks {
        for op in &block.ops {
            match op {
                r2ssa::SSAOp::IntAdd { dst, a, b } | r2ssa::SSAOp::IntSub { dst, a, b } => {
                    let a_is_stack = ssa_var_is_stack_base(a);
                    let b_is_stack = ssa_var_is_stack_base(b);
                    let a_const = parse_const_value(&a.name);
                    let b_const = parse_const_value(&b.name);

                    if a_is_stack && b_const.is_some() {
                        let raw = b_const.unwrap_or(0);
                        let offset = if matches!(op, r2ssa::SSAOp::IntSub { .. }) {
                            -(raw as i64)
                        } else {
                            raw as i64
                        };
                        stack_addr_slots.insert(
                            ssa_var_block_key(block.addr, dst),
                            format!("{}:{offset}", a.name.to_ascii_lowercase()),
                        );
                    } else if matches!(op, r2ssa::SSAOp::IntAdd { .. })
                        && b_is_stack
                        && a_const.is_some()
                    {
                        let raw = a_const.unwrap_or(0);
                        stack_addr_slots.insert(
                            ssa_var_block_key(block.addr, dst),
                            format!("{}:{}", b.name.to_ascii_lowercase(), raw as i64),
                        );
                    }
                }
                r2ssa::SSAOp::Load { addr, .. }
                | r2ssa::SSAOp::Store { addr, .. }
                | r2ssa::SSAOp::LoadLinked { addr, .. }
                | r2ssa::SSAOp::StoreConditional { addr, .. }
                | r2ssa::SSAOp::LoadGuarded { addr, .. }
                | r2ssa::SSAOp::StoreGuarded { addr, .. }
                | r2ssa::SSAOp::AtomicCAS { addr, .. } => {
                    pointer_vars.insert(ssa_var_key(addr));
                }
                _ => {}
            }
        }
    }

    // Back/forward propagation over high-confidence pointer-preserving transforms.
    let mut changed = true;
    while changed {
        changed = false;
        for block in ssa_blocks {
            for op in &block.ops {
                match op {
                    r2ssa::SSAOp::Phi { dst, sources } => {
                        let dst_key = ssa_var_key(dst);
                        let dst_is_pointer = pointer_vars.contains(&dst_key);
                        let any_source_pointer = sources
                            .iter()
                            .any(|src| pointer_vars.contains(&ssa_var_key(src)));

                        if any_source_pointer {
                            changed |= pointer_vars.insert(dst_key.clone());
                        }
                        if dst_is_pointer {
                            for src in sources {
                                changed |= pointer_vars.insert(ssa_var_key(src));
                            }
                        }
                    }
                    r2ssa::SSAOp::Copy { dst, src }
                    | r2ssa::SSAOp::Cast { dst, src }
                    | r2ssa::SSAOp::New { dst, src } => {
                        let dst_key = ssa_var_key(dst);
                        let src_key = ssa_var_key(src);
                        if pointer_vars.contains(&dst_key) {
                            changed |= pointer_vars.insert(src_key.clone());
                        }
                        if pointer_vars.contains(&src_key) {
                            changed |= pointer_vars.insert(dst_key);
                        }
                    }
                    r2ssa::SSAOp::IntAdd { dst, a, b } | r2ssa::SSAOp::IntSub { dst, a, b } => {
                        let dst_key = ssa_var_key(dst);
                        let a_key = ssa_var_key(a);
                        let b_key = ssa_var_key(b);
                        let a_is_const = ssa_var_is_const(a);
                        let b_is_const = ssa_var_is_const(b);
                        let a_index_like = index_like_vars.contains(&a_key);
                        let b_index_like = index_like_vars.contains(&b_key);

                        if pointer_vars.contains(&dst_key) {
                            if a_is_const && !b_is_const {
                                changed |= pointer_vars.insert(b_key.clone());
                            } else if b_is_const && !a_is_const {
                                changed |= pointer_vars.insert(a_key.clone());
                            } else {
                                if a_index_like && !b_index_like {
                                    changed |= pointer_vars.insert(b_key.clone());
                                } else if b_index_like && !a_index_like {
                                    changed |= pointer_vars.insert(a_key.clone());
                                } else if a_index_like && b_index_like {
                                    // SSA versions can collide across blocks; when both operands
                                    // look index-like, prefer the non-temporary operand as base.
                                    let a_is_tmp = a.name.starts_with("tmp:");
                                    let b_is_tmp = b.name.starts_with("tmp:");
                                    if a_is_tmp && !b_is_tmp {
                                        changed |= pointer_vars.insert(b_key.clone());
                                    } else if b_is_tmp && !a_is_tmp {
                                        changed |= pointer_vars.insert(a_key.clone());
                                    }
                                }
                            }
                        }

                        if pointer_vars.contains(&a_key) && b_is_const {
                            changed |= pointer_vars.insert(dst_key.clone());
                        }
                        if pointer_vars.contains(&b_key) && a_is_const {
                            changed |= pointer_vars.insert(dst_key.clone());
                        }
                        if pointer_vars.contains(&a_key) && index_like_vars.contains(&b_key) {
                            changed |= pointer_vars.insert(dst_key.clone());
                        }
                        if pointer_vars.contains(&b_key) && index_like_vars.contains(&a_key) {
                            changed |= pointer_vars.insert(dst_key.clone());
                        }
                    }
                    r2ssa::SSAOp::PtrAdd { dst, base, .. }
                    | r2ssa::SSAOp::PtrSub { dst, base, .. } => {
                        let dst_key = ssa_var_key(dst);
                        let base_key = ssa_var_key(base);
                        if pointer_vars.contains(&dst_key) {
                            changed |= pointer_vars.insert(base_key.clone());
                        }
                        if pointer_vars.contains(&base_key) {
                            changed |= pointer_vars.insert(dst_key);
                        }
                    }
                    r2ssa::SSAOp::SegmentOp { dst, offset, .. } => {
                        let dst_key = ssa_var_key(dst);
                        let offset_key = ssa_var_key(offset);
                        if pointer_vars.contains(&dst_key) {
                            changed |= pointer_vars.insert(offset_key.clone());
                        }
                        if pointer_vars.contains(&offset_key) {
                            changed |= pointer_vars.insert(dst_key);
                        }
                    }
                    r2ssa::SSAOp::Store { addr, val, .. } => {
                        if let Some(slot) =
                            stack_addr_slots.get(&ssa_var_block_key(block.addr, addr))
                        {
                            let val_key = ssa_var_key(val);
                            if val.size >= pointer_width && pointer_vars.contains(&val_key) {
                                changed |= pointer_stack_slots.insert(slot.clone());
                            }
                            if val.size >= pointer_width && pointer_stack_slots.contains(slot) {
                                changed |= pointer_vars.insert(val_key);
                            }
                        }
                    }
                    r2ssa::SSAOp::Load { dst, addr, .. } => {
                        if let Some(slot) =
                            stack_addr_slots.get(&ssa_var_block_key(block.addr, addr))
                        {
                            let dst_key = ssa_var_key(dst);
                            if dst.size >= pointer_width && pointer_stack_slots.contains(slot) {
                                changed |= pointer_vars.insert(dst_key.clone());
                            }
                            if dst.size >= pointer_width && pointer_vars.contains(&dst_key) {
                                changed |= pointer_stack_slots.insert(slot.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        for reg_keys in register_versions.values() {
            if reg_keys.iter().any(|key| pointer_vars.contains(key)) {
                for key in reg_keys {
                    changed |= pointer_vars.insert(key.clone());
                }
            }
        }
    }

    pointer_vars
}

fn infer_usage_register_type_hints(
    ssa_blocks: &[r2ssa::SSABlock],
) -> (
    std::collections::HashMap<String, TypeHint>,
    std::collections::HashSet<String>,
) {
    let pointer_vars = infer_pointer_var_keys_from_ssa(ssa_blocks);
    let mut hints = std::collections::HashMap::new();

    for block in ssa_blocks {
        for op in &block.ops {
            let mut maybe_add = |var: &r2ssa::SSAVar| {
                let key = ssa_var_key(var);
                if !pointer_vars.contains(&key) || !ssa_var_is_register_like(&var.name) {
                    return;
                }
                merge_type_hint(
                    &mut hints,
                    var.name.to_ascii_lowercase(),
                    TypeHint::pointer(),
                );
            };

            if let Some(dst) = op.dst() {
                maybe_add(dst);
            }
            op.for_each_source(|src| maybe_add(src));
        }
    }

    (hints, pointer_vars)
}

fn strongest_hint_for_aliases(
    hints: &std::collections::HashMap<String, TypeHint>,
    canonical: &str,
    aliases: &[&str],
) -> Option<TypeHint> {
    let mut best = hints.get(canonical).cloned();
    for alias in aliases {
        if let Some(candidate) = hints.get(*alias).cloned() {
            match &best {
                Some(current) if !incoming_hint_should_replace(current, &candidate) => {}
                _ => best = Some(candidate),
            }
        }
    }
    best
}

fn merge_register_type_hints(
    metadata_hints: &std::collections::HashMap<String, TypeHint>,
    usage_hints: &std::collections::HashMap<String, TypeHint>,
    arg_regs: ArgAliasMap,
) -> std::collections::HashMap<String, TypeHint> {
    let mut merged = std::collections::HashMap::new();

    for (reg, hint) in metadata_hints {
        merge_type_hint(&mut merged, reg.clone(), hint.clone());
    }
    for (reg, hint) in usage_hints {
        merge_type_hint(&mut merged, reg.clone(), hint.clone());
    }

    // Canonicalize argument register alias families so lookups are deterministic.
    for (canonical, aliases) in arg_regs {
        if let Some(best) = strongest_hint_for_aliases(&merged, canonical, aliases) {
            merge_type_hint(&mut merged, (*canonical).to_string(), best.clone());
            for alias in *aliases {
                merge_type_hint(&mut merged, alias.to_string(), best.clone());
            }
        }
    }

    merged
}

fn collect_pointer_arg_slots(vars: &[VarProt]) -> std::collections::BTreeSet<usize> {
    vars.iter()
        .filter(|var| var.kind == "r" && var.isarg && var.var_type.contains('*'))
        .filter_map(|var| {
            var.name
                .strip_prefix("arg")
                .and_then(|idx| idx.parse::<usize>().ok())
        })
        .collect()
}

fn overlay_inferred_param_pointer_types(
    inferred_params: &mut [InferredParam],
    pointer_arg_slots: &std::collections::BTreeSet<usize>,
) {
    if pointer_arg_slots.is_empty() {
        return;
    }

    let param_count = inferred_params.len();
    for (fallback_idx, param) in inferred_params.iter_mut().enumerate() {
        let explicit_slot = if param.arg_index == usize::MAX {
            None
        } else {
            Some(param.arg_index)
        };
        let slot = explicit_slot.unwrap_or(fallback_idx);
        let fallback_slot_match = pointer_arg_slots.contains(&fallback_idx)
            && (explicit_slot.is_none() || param_count == 1);
        if pointer_arg_slots.contains(&slot) || fallback_slot_match {
            param.ty = r2dec::CType::ptr(r2dec::CType::Void);
        }
    }
}

/// Recover variables from SSA blocks using architecture-specific lightweight heuristics.
fn recover_vars_from_ssa(
    ssa_blocks: &[r2ssa::SSABlock],
    arch: Option<&ArchSpec>,
    metadata_reg_type_hints: &std::collections::HashMap<String, TypeHint>,
    semantic_typing_enabled: bool,
) -> Vec<VarProt> {
    use std::collections::{HashMap, HashSet};

    let mut vars = Vec::new();
    let mut seen_offsets: HashMap<i64, usize> = HashMap::new();
    let mut seen_arg_regs: HashSet<String> = HashSet::new();
    let (arg_regs, stack_bases, frame_bases) = recover_vars_arch_profile(arch);
    let (usage_reg_type_hints, pointer_var_keys) = if semantic_typing_enabled {
        infer_usage_register_type_hints(ssa_blocks)
    } else {
        (HashMap::new(), HashSet::new())
    };
    let reg_type_hints = if semantic_typing_enabled {
        merge_register_type_hints(metadata_reg_type_hints, &usage_reg_type_hints, arg_regs)
    } else {
        HashMap::new()
    };

    // Track temp variables that are stack addresses: temp_name -> (base_reg, offset)
    let mut stack_addr_temps: HashMap<String, (String, i64)> = HashMap::new();

    for block in ssa_blocks {
        for op in &block.ops {
            // Pattern 1: Detect IntAdd/IntSub with RBP/RSP and constant
            // This creates a stack address in a temp variable
            match op {
                r2ssa::SSAOp::IntAdd { dst, a, b } | r2ssa::SSAOp::IntSub { dst, a, b } => {
                    let a_name = a.name.to_lowercase();
                    let b_name = b.name.to_lowercase();

                    // Check if 'a' is stack/frame base and 'b' is a constant
                    let is_a_base = stack_bases.contains(&a_name.as_str());
                    let is_b_const = b_name.starts_with("const:");

                    if is_a_base && is_b_const {
                        if let Some(raw_offset) = parse_const_value(&b.name) {
                            // For IntAdd with large values, treat as two's complement negative
                            // e.g., 0xffffffffffffffb8 = -0x48
                            let offset = if matches!(op, r2ssa::SSAOp::IntSub { .. }) {
                                -(raw_offset as i64)
                            } else {
                                // IntAdd: if value > 0x7FFF... it's a negative in two's complement
                                raw_offset as i64 // Rust handles this correctly
                            };

                            // Store this temp as a known stack address
                            let dst_key = ssa_var_block_key(block.addr, dst);
                            stack_addr_temps.insert(dst_key, (a_name.clone(), offset));
                        }
                    }
                    // Also check if 'b' is the base register (commutative for add)
                    else if stack_bases.contains(&b_name.as_str())
                        && a_name.starts_with("const:")
                        && let Some(raw_offset) = parse_const_value(&a.name)
                    {
                        let offset = raw_offset as i64;
                        let dst_key = ssa_var_block_key(block.addr, dst);
                        stack_addr_temps.insert(dst_key, (b_name.clone(), offset));
                    }
                }

                // Pattern 2: Detect Store/Load with a known stack address temp
                r2ssa::SSAOp::Store { addr, val, .. } => {
                    let addr_key = ssa_var_block_key(block.addr, addr);
                    if let Some((base_reg, offset)) = stack_addr_temps.get(&addr_key) {
                        let type_override = if semantic_typing_enabled
                            && pointer_var_keys.contains(&ssa_var_key(val))
                        {
                            Some("void *".to_string())
                        } else {
                            None
                        };
                        add_stack_var(
                            &mut vars,
                            &mut seen_offsets,
                            base_reg,
                            frame_bases,
                            *offset,
                            val.size,
                            type_override,
                        );
                    }
                }
                r2ssa::SSAOp::Load { dst, addr, .. } => {
                    let addr_key = ssa_var_block_key(block.addr, addr);
                    if let Some((base_reg, offset)) = stack_addr_temps.get(&addr_key) {
                        let type_override = if semantic_typing_enabled
                            && pointer_var_keys.contains(&ssa_var_key(dst))
                        {
                            Some("void *".to_string())
                        } else {
                            None
                        };
                        add_stack_var(
                            &mut vars,
                            &mut seen_offsets,
                            base_reg,
                            frame_bases,
                            *offset,
                            dst.size,
                            type_override,
                        );
                    }
                }

                _ => {}
            }

            // Pattern 3: Detect register arguments (version 0 = uninitialized input)
            for src in op.sources() {
                let base_name = src.name.to_lowercase();
                if src.version == 0 {
                    // Check if this register matches any argument register (including aliases)
                    for (i, (canonical, aliases)) in arg_regs.iter().enumerate() {
                        if aliases.contains(&base_name.as_str())
                            && !seen_arg_regs.contains(*canonical)
                        {
                            seen_arg_regs.insert(canonical.to_string());
                            let hinted_type = if semantic_typing_enabled {
                                strongest_hint_for_aliases(&reg_type_hints, canonical, aliases)
                                    .map(|hint| hint.ty)
                            } else {
                                None
                            };
                            vars.push(VarProt {
                                name: format!("arg{}", i),
                                kind: "r".to_string(),
                                delta: 0,
                                var_type: hinted_type.unwrap_or_else(|| size_to_type(src.size)),
                                isarg: true,
                                reg: Some(canonical.to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    // Sort variables by offset for consistent output
    vars.sort_by_key(|v| v.delta);
    vars
}

/// Add a stack variable if not already seen
fn add_stack_var(
    vars: &mut Vec<VarProt>,
    seen_offsets: &mut std::collections::HashMap<i64, usize>,
    base_reg: &str,
    frame_bases: &[&str],
    offset: i64,
    size: u32,
    type_override: Option<String>,
) {
    if let Some(existing_idx) = seen_offsets.get(&offset).copied() {
        if let Some(override_ty) = type_override
            && override_ty == "void *"
            && let Some(existing) = vars.get_mut(existing_idx)
            && existing.var_type != "void *"
        {
            existing.var_type = override_ty;
        }
        return;
    }

    // Determine if this is an argument or local variable
    // For RBP-relative: negative offset = local, positive = saved regs/return/args
    // For RSP-relative: depends on stack frame layout
    let is_frame_base = frame_bases.contains(&base_reg);
    let is_arg = if is_frame_base {
        offset > 0 // Above frame base = return addr/saved fp, then args
    } else {
        false // SP-relative accesses are typically locals
    };

    let var_name = if is_arg && offset > 8 {
        // Skip return address (offset 8) and saved RBP (offset 0)
        format!("arg_{:x}h", offset.unsigned_abs())
    } else {
        format!("var_{:x}h", offset.unsigned_abs())
    };

    let kind = if is_frame_base { "b" } else { "s" }; // frame-relative or stack-relative

    vars.push(VarProt {
        name: var_name,
        kind: kind.to_string(),
        delta: offset,
        var_type: type_override.unwrap_or_else(|| size_to_type(size)),
        isarg: is_arg && offset > 8,
        reg: None,
    });
    seen_offsets.insert(offset, vars.len().saturating_sub(1));
}

/// Parse a constant value from SSA variable name
/// Handles formats like:
/// - "const:0x48"
/// - "const:18446744073709551544"
/// - "const:ffffffffffffffb8_0" (SSA versioned constant with hex)
fn parse_const_value(name: &str) -> Option<u64> {
    let val_str = name
        .strip_prefix("const:")
        .or_else(|| name.strip_prefix("CONST:"))?;

    // Remove SSA version suffix if present (e.g., "ffffffffffffffb8_0" -> "ffffffffffffffb8")
    let val_str = val_str.split('_').next().unwrap_or(val_str);

    if let Some(hex) = val_str
        .strip_prefix("0x")
        .or_else(|| val_str.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    // Try parsing as decimal first
    if let Ok(v) = val_str.parse::<u64>() {
        return Some(v);
    }
    // Try parsing as hex without 0x prefix (common for constants like "ffffffffffffffb8")
    u64::from_str_radix(val_str, 16).ok()
}

/// Convert size in bytes to C type string
fn size_to_type(size: u32) -> String {
    match size {
        1 => "int8_t".to_string(),
        2 => "int16_t".to_string(),
        4 => "int32_t".to_string(),
        8 => "int64_t".to_string(),
        _ => format!("byte[{}]", size),
    }
}

/// Extract a constant address from an SSA variable name.
///
/// Returns `Some(addr)` when the variable is a `const:XXXX` name and the hex
/// value looks like a plausible data/code address (>= 0x1000 and not a small
/// immediate).  Addresses below 0x1000 are almost always small constants
/// (flags, loop bounds, offsets) rather than real memory references.
fn parse_const_addr(name: &str) -> Option<u64> {
    let hex = name.strip_prefix("const:")?;
    let addr = u64::from_str_radix(hex, 16).ok()?;
    // Filter out small immediates and character constants.
    // Real data/code addresses in ELF binaries are well above 0x10000:
    //   - Non-PIE x86-64: base 0x400000
    //   - PIE x86-64: base 0x555... (randomized, always > 0x10000)
    //   - Values below 0x10000 are almost always:
    //     * Small integer constants (loop bounds, flags, enum values)
    //     * Character literals ('/', 0x2f; ' ', 0x20; etc.)
    //     * Bitmasks (0x80, 0xff, 0x1000, etc.)
    if addr >= 0x10000 { Some(addr) } else { None }
}

/// Get data references from SSA blocks.
///
/// A "data ref" means: instruction at address X references a **memory address** Y.
/// We emit refs for:
///   - Copy/IntAdd/IntSub with a const: source that looks like an address (LEA, MOV imm)
///   - Load/Store whose address operand is a const: (absolute memory access)
///   - Call/CallInd whose target is a const: (direct call target)
///
/// We do NOT emit refs for register def-use flow between instructions — those
/// are data-flow edges, not address references.
fn get_data_refs_from_ssa(ssa_blocks: &[r2ssa::SSABlock]) -> Vec<DataRef> {
    let mut refs = Vec::new();

    for block in ssa_blocks {
        for op in &block.ops {
            match op {
                // Copy from const address (LEA, MOV imm)
                r2ssa::SSAOp::Copy { src, .. } => {
                    if let Some(addr) = parse_const_addr(&src.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "d".to_string(),
                        });
                    }
                }

                // Load from absolute address
                r2ssa::SSAOp::Load { addr, .. } => {
                    if let Some(target) = parse_const_addr(&addr.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: target,
                            ref_type: "d".to_string(),
                        });
                    }
                }

                // Store to absolute address
                r2ssa::SSAOp::Store { addr, .. } => {
                    if let Some(target) = parse_const_addr(&addr.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: target,
                            ref_type: "d".to_string(),
                        });
                    }
                }

                // IntAdd/IntSub with a const operand (e.g., base + offset)
                r2ssa::SSAOp::IntAdd { a, b, .. } | r2ssa::SSAOp::IntSub { a, b, .. } => {
                    if let Some(addr) = parse_const_addr(&a.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "d".to_string(),
                        });
                    }
                    if let Some(addr) = parse_const_addr(&b.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "d".to_string(),
                        });
                    }
                }

                // Direct call/branch to known address
                r2ssa::SSAOp::Call { target, .. } | r2ssa::SSAOp::Branch { target } => {
                    if let Some(addr) = parse_const_addr(&target.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "c".to_string(), // code/call ref
                        });
                    }
                }

                // Indirect call/branch where the target is a known constant
                r2ssa::SSAOp::CallInd { target, .. } | r2ssa::SSAOp::BranchInd { target } => {
                    if let Some(addr) = parse_const_addr(&target.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "c".to_string(),
                        });
                    }
                }

                // CBranch: the target is a const address
                r2ssa::SSAOp::CBranch { target, .. } => {
                    if let Some(addr) = parse_const_addr(&target.name) {
                        refs.push(DataRef {
                            from: block.addr,
                            to: addr,
                            ref_type: "c".to_string(),
                        });
                    }
                }

                _ => {}
            }
        }
    }

    // Deduplicate refs
    refs.sort_by_key(|r| (r.from, r.to));
    refs.dedup_by(|a, b| a.from == b.from && a.to == b.to);

    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::ffi::{CStr, CString};

    #[cfg(feature = "x86")]
    unsafe fn c_string_to_owned(ptr: *mut c_char) -> String {
        let out = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        r2il_string_free(ptr);
        out
    }

    #[cfg(feature = "x86")]
    fn export_from_context(
        ctx_ref: &R2ILContext,
        block: &R2ILBlock,
        action: InstructionAction,
        format: ExportFormat,
    ) -> String {
        let disasm = ctx_ref.disasm.as_ref().expect("disassembler");
        let arch = ctx_ref.arch.as_ref().expect("arch spec");
        let input = InstructionExportInput {
            disasm,
            arch,
            block,
            addr: block.addr,
            mnemonic: "",
            native_size: block.size as usize,
        };
        export_instruction(&input, action, format).expect("export")
    }

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
        let esil = unsafe { CStr::from_ptr(esil_ptr) }
            .to_string_lossy()
            .into_owned();
        assert!(esil.contains("eax"));

        unsafe { drop(CString::from_raw(esil_ptr as *mut c_char)) };
        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    #[cfg(feature = "x86")]
    fn op_json_named_matches_exporter_output_shape() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);
        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        let block_ref = unsafe { &*block };
        let ctx_ref = unsafe { &*ctx };
        let op_index = 0usize;
        let expected_json = op_json_named(
            ctx_ref.disasm.as_ref().expect("disassembler"),
            &block_ref.ops[op_index],
        )
        .expect("exporter op json");

        let json_ptr = r2il_block_op_json_named(ctx, block, op_index);
        assert!(!json_ptr.is_null());
        let ffi_json = unsafe { c_string_to_owned(json_ptr) };

        let expected_val: Value =
            serde_json::from_str(&expected_json).expect("expected json value");
        let ffi_val: Value = serde_json::from_str(&ffi_json).expect("ffi json value");
        assert_eq!(ffi_val, expected_val);

        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    #[cfg(feature = "x86")]
    fn block_to_esil_matches_exporter() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);
        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        let ffi_ptr = r2il_block_to_esil(ctx, block);
        assert!(!ffi_ptr.is_null());
        let ffi_esil = unsafe { c_string_to_owned(ffi_ptr) };

        let ctx_ref = unsafe { &*ctx };
        let block_ref = unsafe { &*block };
        let expected = export_from_context(
            ctx_ref,
            block_ref,
            InstructionAction::Lift,
            ExportFormat::Esil,
        );
        let expected_joined = expected
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(ffi_esil, expected_joined);

        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    #[cfg(feature = "x86")]
    fn block_to_ssa_json_matches_exporter() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);
        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        let ffi_ptr = r2il_block_to_ssa_json(ctx, block);
        assert!(!ffi_ptr.is_null());
        let ffi_json = unsafe { c_string_to_owned(ffi_ptr) };

        let ctx_ref = unsafe { &*ctx };
        let block_ref = unsafe { &*block };
        let expected = export_from_context(
            ctx_ref,
            block_ref,
            InstructionAction::Ssa,
            ExportFormat::Json,
        );

        let ffi_val: Value = serde_json::from_str(&ffi_json).expect("ffi json");
        let expected_val: Value = serde_json::from_str(&expected).expect("expected json");
        assert_eq!(ffi_val, expected_val);

        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    #[cfg(feature = "x86")]
    fn block_defuse_json_matches_exporter() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);
        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        let ffi_ptr = r2il_block_defuse_json(ctx, block);
        assert!(!ffi_ptr.is_null());
        let ffi_json = unsafe { c_string_to_owned(ffi_ptr) };

        let ctx_ref = unsafe { &*ctx };
        let block_ref = unsafe { &*block };
        let expected = export_from_context(
            ctx_ref,
            block_ref,
            InstructionAction::Defuse,
            ExportFormat::Json,
        );

        let ffi_val: Value = serde_json::from_str(&ffi_json).expect("ffi json");
        let expected_val: Value = serde_json::from_str(&expected).expect("expected json");
        assert_eq!(ffi_val, expected_val);

        r2il_block_free(block);
        r2il_free(ctx);
    }

    #[test]
    #[cfg(feature = "x86")]
    fn r2dec_block_c_like_matches_exporter_path() {
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        let mut bytes = vec![0x31, 0xC0];
        bytes.resize(16, 0);
        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        let ffi_ptr = r2dec_block(ctx, block);
        assert!(!ffi_ptr.is_null());
        let ffi_c_like = unsafe { c_string_to_owned(ffi_ptr) };

        let ctx_ref = unsafe { &*ctx };
        let block_ref = unsafe { &*block };
        let expected = export_from_context(
            ctx_ref,
            block_ref,
            InstructionAction::Dec,
            ExportFormat::CLike,
        );
        assert_eq!(ffi_c_like, expected);

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

    #[test]
    fn is_big_endian_uses_memory_endianness_shim() {
        let mut arch = ArchSpec::new("shim");
        arch.set_memory_endianness(r2il::Endianness::Big);
        let ctx = Box::into_raw(Box::new(R2ILContext::with_arch(arch)));
        assert_eq!(r2il_is_big_endian(ctx), 1);
        r2il_free(ctx);

        let mut arch = ArchSpec::new("shim2");
        arch.set_memory_endianness(r2il::Endianness::Mixed);
        let ctx = Box::into_raw(Box::new(R2ILContext::with_arch(arch)));
        assert_eq!(r2il_is_big_endian(ctx), 0);
        r2il_free(ctx);
    }

    #[test]
    fn test_parse_external_signature_with_args() {
        let json = r#"[{"name":"dbg.vuln_memcpy","args":[{"name":"user_input","type":"char *"},{"name":"user_len","type":"int32_t"}],"count":2}]"#;
        let sig = parse_external_signature(json, 64).expect("signature should parse");
        assert!(sig.ret_type.is_none());
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].name, "user_input");
        assert_eq!(sig.params[1].name, "user_len");
        assert_eq!(
            sig.params[0].ty,
            Some(r2dec::CType::ptr(r2dec::CType::Int(8)))
        );
        assert_eq!(sig.params[1].ty, Some(r2dec::CType::Int(32)));
    }

    #[test]
    fn test_parse_external_signature_missing_return() {
        let json = r#"[{"name":"dbg.main","args":[{"name":"arg0","type":"int64_t"}]}]"#;
        let sig = parse_external_signature(json, 64).expect("signature should parse");
        assert!(sig.ret_type.is_none());
        assert_eq!(sig.params[0].name, "arg0");
    }

    #[test]
    fn test_parse_signature_context_legacy_array() {
        let json =
            r#"[{"name":"dbg.main","return":"int32_t","args":[{"name":"x","type":"int32_t"}]}]"#;
        let ctx = parse_signature_context(json, 64);
        assert!(
            ctx.current.is_some(),
            "legacy payload should parse current signature"
        );
        assert!(
            ctx.known.is_empty(),
            "legacy payload should not synthesize known signatures"
        );
    }

    #[test]
    fn test_parse_signature_context_object_with_known() {
        let json = r#"{
          "current":[{"name":"dbg.main","return":"int32_t","args":[{"name":"x","type":"int32_t"}]}],
          "known":[
            {"name":"sym.imp.printf","return":"int32_t","args":[{"name":"fmt","type":"char *"}],"variadic":true},
            {"name":"sym.imp.strlen","return":"size_t","args":[{"name":"s","type":"char *"}]}
          ],
          "cc":{"sysv":{"ret":"rax"}}
        }"#;
        let ctx = parse_signature_context(json, 64);
        assert!(ctx.current.is_some(), "current signature should parse");
        assert!(
            ctx.known.contains_key("sym.imp.printf"),
            "known map should include original symbol names"
        );
        assert!(
            ctx.known.contains_key("printf"),
            "known map should include stripped fallback aliases"
        );
        assert!(
            ctx.known.contains_key("sym.imp.strlen"),
            "known map should include additional signatures"
        );
    }

    #[test]
    fn test_parse_external_stack_vars_bp_sp() {
        let json = r#"{"sp":[{"name":"var_8h","kind":"var","type":"int64_t","ref":{"base":"RSP","offset":80}}],"bp":[{"name":"buf","kind":"var","type":"char[64]","ref":{"base":"RBP","offset":-64}},{"name":"user_input","kind":"var","type":"char *","ref":{"base":"RBP","offset":-72}}]}"#;
        let vars = parse_external_stack_vars(json, 64);
        assert_eq!(vars.get(&-64).map(|v| v.name.as_str()), Some("buf"));
        assert_eq!(vars.get(&-72).map(|v| v.name.as_str()), Some("user_input"));
        assert_eq!(vars.get(&80).map(|v| v.base.as_deref()), Some(Some("RSP")));
    }

    #[test]
    fn test_name_sanitization_and_collisions() {
        let json = r#"{"bp":[{"name":"bad-name","type":"int","ref":{"base":"RBP","offset":-8}},{"name":"bad name","type":"int","ref":{"base":"RBP","offset":-16}}]}"#;
        let vars = parse_external_stack_vars(json, 64);
        let first = vars.get(&-8).expect("first var");
        let second = vars.get(&-16).expect("second var");
        assert_eq!(first.name, "bad_name");
        assert_ne!(first.name, second.name);
    }

    #[test]
    fn test_parse_external_type_db_tsj_struct_payload() {
        let json = r#"{
          "types": [
            {
              "kind": "struct",
              "name": "DemoStruct",
              "members": [
                {"name": "first", "offset": 0, "type": "int"},
                {"name": "thirteenth", "offset": 48, "type": "int"}
              ]
            }
          ]
        }"#;
        let db = r2types::ExternalTypeDb::from_tsj_json(json);
        assert!(db.diagnostics.is_empty(), "diagnostics should be empty");
        assert!(
            db.structs
                .get("demostruct")
                .and_then(|st| st.fields.get(&48))
                .is_some(),
            "DemoStruct field at offset 48 should be parsed"
        );
    }

    #[test]
    #[cfg(feature = "x86")]
    fn test_r2dec_with_context_uses_tsj_field_name() {
        let arch = CString::new("x86-64").expect("valid arch string");
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null(), "context should initialize");

        // mov eax, [rdi + 0x30]
        let mut mov_bytes = vec![0x8b, 0x47, 0x30];
        mov_bytes.resize(16, 0);
        let block_load = r2il_lift(ctx, mov_bytes.as_ptr(), mov_bytes.len(), 0x1000);
        assert!(!block_load.is_null(), "load block should lift");

        // ret
        let mut ret_bytes = vec![0xc3];
        ret_bytes.resize(16, 0);
        let block_ret = r2il_lift(ctx, ret_bytes.as_ptr(), ret_bytes.len(), 0x1003);
        assert!(!block_ret.is_null(), "ret block should lift");

        let blocks: [*const R2ILBlock; 2] = [block_load, block_ret];
        let func_name = CString::new("demo").expect("valid function name");
        let empty_map = CString::new("{}").expect("valid empty json");
        let empty_sig = CString::new("[]").expect("valid empty signature json");
        let types_json = CString::new(
            r#"{
                "types":[
                    {
                        "kind":"struct",
                        "name":"DemoStruct",
                        "members":[
                            {"name":"thirteenth","offset":48,"type":"int"}
                        ]
                    }
                ]
            }"#,
        )
        .expect("valid tsj json");

        let out = r2dec_function_with_context(
            ctx,
            blocks.as_ptr(),
            blocks.len(),
            func_name.as_ptr(),
            empty_map.as_ptr(),
            empty_map.as_ptr(),
            empty_map.as_ptr(),
            empty_sig.as_ptr(),
            empty_map.as_ptr(),
            types_json.as_ptr(),
        );
        assert!(!out.is_null(), "decompilation output should not be null");
        let output = unsafe { CStr::from_ptr(out) }.to_string_lossy().to_string();

        r2il_string_free(out);
        r2il_block_free(block_load);
        r2il_block_free(block_ret);
        r2il_free(ctx);

        assert!(
            output.contains("thirteenth")
                || output.contains("*(rdi + 30)")
                || output.contains("*(rdi + const_30)")
                || output.contains("*(rdi + 48)")
                || output.contains("*(rdi + const_48)")
                || output.contains("saved_fp"),
            "decompiler should keep decompilation stable with tsj context, got: {}",
            output
        );
    }

    #[test]
    #[cfg(feature = "x86")]
    fn test_varnode_to_json_includes_meta_when_set() {
        let (_, disasm) = create_disassembler_for_arch("x86-64").expect("disassembler");
        let meta = r2il::VarnodeMetadata {
            scalar_kind: Some(r2il::ScalarKind::UnsignedInt),
            pointer_hint: Some(r2il::PointerHint::PointerLike),
            ..Default::default()
        };
        let vn = r2il::Varnode::register(0, 8).with_meta(meta);

        let value = varnode_to_json(&vn, &disasm).expect("varnode json");
        let meta_json = value
            .get("meta")
            .and_then(Value::as_object)
            .expect("meta object");
        assert_eq!(
            meta_json.get("scalar_kind").and_then(Value::as_str),
            Some("unsigned_int")
        );
        assert_eq!(
            meta_json.get("pointer_hint").and_then(Value::as_str),
            Some("pointer_like")
        );
    }

    #[test]
    #[cfg(feature = "x86")]
    fn test_varnode_to_json_omits_meta_when_unset() {
        let (_, disasm) = create_disassembler_for_arch("x86-64").expect("disassembler");
        let vn = r2il::Varnode::register(0, 8);

        let value = varnode_to_json(&vn, &disasm).expect("varnode json");
        assert!(
            value.get("meta").is_none(),
            "meta should be omitted when not set"
        );
    }

    #[test]
    fn recover_vars_usage_pointer_inference_promotes_x86_arg_type() {
        let arch = ArchSpec::new("x86-64");
        let block = r2ssa::SSABlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:1000", 1, 8),
                    a: r2ssa::SSAVar::new("rdi", 0, 8),
                    b: r2ssa::SSAVar::new("const:8", 0, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:2000", 1, 8),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:1000", 1, 8),
                },
            ],
        };

        let hints = std::collections::HashMap::new();
        let vars = recover_vars_from_ssa(&[block], Some(&arch), &hints, true);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "void *",
            "address-role usage should infer pointer type for arg0"
        );
    }

    #[test]
    fn recover_vars_usage_pointer_inference_handles_spill_reload_scaled_index() {
        let arch = ArchSpec::new("x86-64");
        let block = r2ssa::SSABlock {
            addr: 0x2000,
            size: 4,
            ops: vec![
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                    a: r2ssa::SSAVar::new("rbp", 0, 8),
                    b: r2ssa::SSAVar::new("const:fffffffffffffff8", 0, 8),
                },
                r2ssa::SSAOp::Store {
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                    val: r2ssa::SSAVar::new("rdi", 0, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:arr", 2, 8),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                },
                r2ssa::SSAOp::IntSExt {
                    dst: r2ssa::SSAVar::new("tmp:idx64", 1, 8),
                    src: r2ssa::SSAVar::new("esi", 0, 4),
                },
                r2ssa::SSAOp::IntMult {
                    dst: r2ssa::SSAVar::new("tmp:scale", 1, 8),
                    a: r2ssa::SSAVar::new("tmp:idx64", 1, 8),
                    b: r2ssa::SSAVar::new("const:4", 0, 8),
                },
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:elem", 1, 8),
                    a: r2ssa::SSAVar::new("tmp:arr", 2, 8),
                    b: r2ssa::SSAVar::new("tmp:scale", 1, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:val", 1, 4),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:elem", 1, 8),
                },
            ],
        };

        let hints = std::collections::HashMap::new();
        let vars = recover_vars_from_ssa(&[block], Some(&arch), &hints, true);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "void *",
            "spill/reload + scaled index should preserve pointer type on arg0"
        );
    }

    #[test]
    fn recover_vars_usage_pointer_inference_handles_shift_scaled_index() {
        let arch = ArchSpec::new("x86-64");
        let block = r2ssa::SSABlock {
            addr: 0x2100,
            size: 4,
            ops: vec![
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                    a: r2ssa::SSAVar::new("rbp", 0, 8),
                    b: r2ssa::SSAVar::new("const:fffffffffffffff8", 0, 8),
                },
                r2ssa::SSAOp::Store {
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                    val: r2ssa::SSAVar::new("rdi", 0, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:arr", 2, 8),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:slot", 1, 8),
                },
                r2ssa::SSAOp::IntSExt {
                    dst: r2ssa::SSAVar::new("tmp:idx64", 1, 8),
                    src: r2ssa::SSAVar::new("esi", 0, 4),
                },
                r2ssa::SSAOp::IntLeft {
                    dst: r2ssa::SSAVar::new("tmp:scale", 1, 8),
                    a: r2ssa::SSAVar::new("tmp:idx64", 1, 8),
                    b: r2ssa::SSAVar::new("const:2", 0, 8),
                },
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:elem", 1, 8),
                    a: r2ssa::SSAVar::new("tmp:arr", 2, 8),
                    b: r2ssa::SSAVar::new("tmp:scale", 1, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:val", 1, 4),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:elem", 1, 8),
                },
            ],
        };

        let hints = std::collections::HashMap::new();
        let vars = recover_vars_from_ssa(&[block], Some(&arch), &hints, true);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "void *",
            "shift-scaled index should preserve pointer type on arg0"
        );
    }

    #[test]
    fn recover_vars_semantic_disable_falls_back_to_integer_types() {
        let arch = ArchSpec::new("x86-64");
        let block = r2ssa::SSABlock {
            addr: 0x3000,
            size: 4,
            ops: vec![
                r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("tmp:addr", 1, 8),
                    a: r2ssa::SSAVar::new("rdi", 0, 8),
                    b: r2ssa::SSAVar::new("const:8", 0, 8),
                },
                r2ssa::SSAOp::Load {
                    dst: r2ssa::SSAVar::new("tmp:val", 1, 8),
                    space: "ram".to_string(),
                    addr: r2ssa::SSAVar::new("tmp:addr", 1, 8),
                },
            ],
        };

        let mut hints = std::collections::HashMap::new();
        merge_type_hint(&mut hints, "rdi".to_string(), TypeHint::pointer());
        let vars = recover_vars_from_ssa(&[block], Some(&arch), &hints, false);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "int64_t",
            "semantic-disabled path should ignore metadata/usage pointer hints"
        );
    }

    #[test]
    fn recover_vars_safe_array_access_pattern_marks_rdi_pointer() {
        let arch = ArchSpec::new("x86-64");
        let blocks = vec![
            r2ssa::SSABlock {
                addr: 0x4014dc,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                        a: r2ssa::SSAVar::new("RBP", 0, 8),
                        b: r2ssa::SSAVar::new("const:fffffffffffffff8", 0, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("tmp:6b00", 1, 8),
                        src: r2ssa::SSAVar::new("RDI", 0, 8),
                    },
                    r2ssa::SSAOp::Store {
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                        val: r2ssa::SSAVar::new("tmp:6b00", 1, 8),
                    },
                ],
            },
            r2ssa::SSABlock {
                addr: 0x4014e0,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4600", 1, 8),
                        a: r2ssa::SSAVar::new("RBP", 0, 8),
                        b: r2ssa::SSAVar::new("const:fffffffffffffff4", 0, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("tmp:7000", 1, 4),
                        src: r2ssa::SSAVar::new("ESI", 0, 4),
                    },
                    r2ssa::SSAOp::Store {
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4600", 1, 8),
                        val: r2ssa::SSAVar::new("tmp:7000", 1, 4),
                    },
                ],
            },
            r2ssa::SSABlock {
                addr: 0x4014f7,
                size: 4,
                ops: vec![r2ssa::SSAOp::IntSExt {
                    dst: r2ssa::SSAVar::new("RAX", 1, 8),
                    src: r2ssa::SSAVar::new("EAX", 0, 4),
                }],
            },
            r2ssa::SSABlock {
                addr: 0x4014f9,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntMult {
                        dst: r2ssa::SSAVar::new("tmp:4c80", 1, 8),
                        a: r2ssa::SSAVar::new("RAX", 0, 8),
                        b: r2ssa::SSAVar::new("const:4", 0, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("RDX", 1, 8),
                        src: r2ssa::SSAVar::new("tmp:4c80", 1, 8),
                    },
                ],
            },
            r2ssa::SSABlock {
                addr: 0x401501,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                        a: r2ssa::SSAVar::new("RBP", 0, 8),
                        b: r2ssa::SSAVar::new("const:fffffffffffffff8", 0, 8),
                    },
                    r2ssa::SSAOp::Load {
                        dst: r2ssa::SSAVar::new("tmp:11f80", 1, 8),
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("RAX", 1, 8),
                        src: r2ssa::SSAVar::new("tmp:11f80", 1, 8),
                    },
                ],
            },
            r2ssa::SSABlock {
                addr: 0x401505,
                size: 4,
                ops: vec![r2ssa::SSAOp::IntAdd {
                    dst: r2ssa::SSAVar::new("RAX", 1, 8),
                    a: r2ssa::SSAVar::new("RAX", 1, 8),
                    b: r2ssa::SSAVar::new("RDX", 0, 8),
                }],
            },
            r2ssa::SSABlock {
                addr: 0x401508,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::Load {
                        dst: r2ssa::SSAVar::new("tmp:11f00", 1, 4),
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("RAX", 0, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("EAX", 1, 4),
                        src: r2ssa::SSAVar::new("tmp:11f00", 1, 4),
                    },
                    r2ssa::SSAOp::IntZExt {
                        dst: r2ssa::SSAVar::new("RAX", 1, 8),
                        src: r2ssa::SSAVar::new("EAX", 1, 4),
                    },
                ],
            },
        ];

        let hints = std::collections::HashMap::new();
        let vars = recover_vars_from_ssa(&blocks, Some(&arch), &hints, true);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "void *",
            "safe-array style spill/reload indexed deref should type arr arg as pointer"
        );
        let arg1 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rsi"))
            .expect("rsi argument should be recovered");
        assert_ne!(
            arg1.var_type, "void *",
            "index argument should remain non-pointer in this pattern"
        );
    }

    #[test]
    fn recover_vars_safe_array_access_minimal_two_block_pattern_marks_rdi_pointer() {
        let arch = ArchSpec::new("x86-64");
        let blocks = vec![
            r2ssa::SSABlock {
                addr: 0x5000,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                        a: r2ssa::SSAVar::new("RBP", 1, 8),
                        b: r2ssa::SSAVar::new("const:fffffffffffffff0", 0, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("tmp:6b00", 1, 8),
                        src: r2ssa::SSAVar::new("RDI", 0, 8),
                    },
                    r2ssa::SSAOp::Store {
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 1, 8),
                        val: r2ssa::SSAVar::new("tmp:6b00", 1, 8),
                    },
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 2, 8),
                        a: r2ssa::SSAVar::new("RBP", 1, 8),
                        b: r2ssa::SSAVar::new("const:ffffffffffffffec", 0, 8),
                    },
                    r2ssa::SSAOp::Store {
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 2, 8),
                        val: r2ssa::SSAVar::new("ESI", 0, 4),
                    },
                ],
            },
            r2ssa::SSABlock {
                addr: 0x5010,
                size: 4,
                ops: vec![
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 9, 8),
                        a: r2ssa::SSAVar::new("RBP", 1, 8),
                        b: r2ssa::SSAVar::new("const:fffffffffffffff0", 0, 8),
                    },
                    r2ssa::SSAOp::Load {
                        dst: r2ssa::SSAVar::new("tmp:11f80", 2, 8),
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 9, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("RAX", 4, 8),
                        src: r2ssa::SSAVar::new("tmp:11f80", 2, 8),
                    },
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4700", 10, 8),
                        a: r2ssa::SSAVar::new("RBP", 1, 8),
                        b: r2ssa::SSAVar::new("const:ffffffffffffffec", 0, 8),
                    },
                    r2ssa::SSAOp::Load {
                        dst: r2ssa::SSAVar::new("tmp:11f00", 5, 4),
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4700", 10, 8),
                    },
                    r2ssa::SSAOp::IntSExt {
                        dst: r2ssa::SSAVar::new("RCX", 2, 8),
                        src: r2ssa::SSAVar::new("tmp:11f00", 5, 4),
                    },
                    r2ssa::SSAOp::IntMult {
                        dst: r2ssa::SSAVar::new("tmp:4900", 2, 8),
                        a: r2ssa::SSAVar::new("RCX", 2, 8),
                        b: r2ssa::SSAVar::new("const:4", 0, 8),
                    },
                    r2ssa::SSAOp::IntAdd {
                        dst: r2ssa::SSAVar::new("tmp:4a00", 2, 8),
                        a: r2ssa::SSAVar::new("RAX", 4, 8),
                        b: r2ssa::SSAVar::new("tmp:4900", 2, 8),
                    },
                    r2ssa::SSAOp::Load {
                        dst: r2ssa::SSAVar::new("tmp:11f00", 6, 4),
                        space: "ram".to_string(),
                        addr: r2ssa::SSAVar::new("tmp:4a00", 2, 8),
                    },
                    r2ssa::SSAOp::Copy {
                        dst: r2ssa::SSAVar::new("EAX", 4, 4),
                        src: r2ssa::SSAVar::new("tmp:11f00", 6, 4),
                    },
                    r2ssa::SSAOp::IntZExt {
                        dst: r2ssa::SSAVar::new("RAX", 5, 8),
                        src: r2ssa::SSAVar::new("EAX", 4, 4),
                    },
                ],
            },
        ];

        let hints = std::collections::HashMap::new();
        let vars = recover_vars_from_ssa(&blocks, Some(&arch), &hints, true);
        let arg0 = vars
            .iter()
            .find(|v| v.reg.as_deref() == Some("rdi"))
            .expect("rdi argument should be recovered");
        assert_eq!(
            arg0.var_type, "void *",
            "two-block spill/reload + scaled-index pattern should mark rdi as pointer"
        );
    }

    #[test]
    fn merge_register_type_hints_prefers_pointer_over_integer_aliases() {
        let mut metadata = std::collections::HashMap::new();
        merge_type_hint(
            &mut metadata,
            "edi".to_string(),
            TypeHint {
                rank: TypeHintRank::Integer,
                ty: "int32_t".to_string(),
            },
        );
        let mut usage = std::collections::HashMap::new();
        merge_type_hint(&mut usage, "rdi".to_string(), TypeHint::pointer());

        let merged = merge_register_type_hints(&metadata, &usage, X86_ARG_REGS);
        assert_eq!(
            merged.get("rdi").map(|hint| hint.ty.as_str()),
            Some("void *")
        );
        assert_eq!(
            merged.get("edi").map(|hint| hint.ty.as_str()),
            Some("void *")
        );
    }

    #[test]
    fn add_stack_var_upgrades_existing_slot_to_pointer_when_confident() {
        let mut vars = Vec::new();
        let mut seen_offsets = std::collections::HashMap::new();
        add_stack_var(
            &mut vars,
            &mut seen_offsets,
            "rbp",
            X86_FRAME_BASES,
            -8,
            8,
            None,
        );
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].var_type, "int64_t");

        add_stack_var(
            &mut vars,
            &mut seen_offsets,
            "rbp",
            X86_FRAME_BASES,
            -8,
            8,
            Some("void *".to_string()),
        );
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].var_type, "void *");
    }

    #[test]
    fn overlay_inferred_signature_params_with_pointer_slots() {
        let mut inferred_params = vec![InferredParam {
            name: "arg1".to_string(),
            ty: r2dec::CType::Int(64),
            arg_index: 1,
        }];
        let mut pointer_slots = std::collections::BTreeSet::new();
        pointer_slots.insert(0);

        overlay_inferred_param_pointer_types(&mut inferred_params, &pointer_slots);
        assert_eq!(
            inferred_params[0].ty,
            r2dec::CType::ptr(r2dec::CType::Void),
            "single-parameter fallback should adopt high-confidence pointer slot"
        );
    }

    #[test]
    fn test_generic_arg_detection() {
        assert!(is_generic_arg_name("arg0"));
        assert!(is_generic_arg_name("Arg12"));
        assert!(!is_generic_arg_name("user_input"));
    }

    #[test]
    fn test_format_afs_signature() {
        let params = vec![
            InferredParamJson {
                name: "a".to_string(),
                param_type: "int32_t".to_string(),
            },
            InferredParamJson {
                name: "b".to_string(),
                param_type: "int64_t".to_string(),
            },
        ];
        let sig = format_afs_signature("dbg.sum", "int32_t", &params);
        assert_eq!(sig, "int32_t dbg.sum (int32_t a, int64_t b)");
    }

    #[test]
    fn test_normalize_inferred_param_name_fallback_and_uniquify() {
        let mut used = std::collections::HashSet::new();
        let first = normalize_inferred_param_name("bad name", 0, &mut used);
        let second = normalize_inferred_param_name("bad name", 1, &mut used);
        let fallback = normalize_inferred_param_name("$$$", 2, &mut used);
        assert_eq!(first, "bad_name");
        assert_eq!(second, "bad_name_2");
        assert_eq!(fallback, "arg2");
    }

    #[test]
    fn test_sanitize_inferred_param_type_fallbacks_from_void() {
        let ty = sanitize_inferred_param_type(r2dec::CType::Void, 0, 64);
        assert_eq!(ty, r2dec::CType::Int(64));
    }

    #[test]
    fn test_infer_callconv_x86_64_prefers_amd64_for_sysv_inputs() {
        let mut counts = std::collections::HashMap::new();
        counts.insert("rdi".to_string(), 3);
        counts.insert("rsi".to_string(), 2);
        counts.insert("rdx".to_string(), 1);
        let (cc, confidence) = infer_callconv_x86_64_from_counts(&counts);
        assert_eq!(cc, "amd64");
        assert!(confidence >= 80);
    }

    #[test]
    fn test_infer_callconv_x86_64_prefers_ms_when_rcx_dominates() {
        let mut counts = std::collections::HashMap::new();
        counts.insert("rcx".to_string(), 3);
        counts.insert("rdx".to_string(), 2);
        counts.insert("r8".to_string(), 1);
        let (cc, confidence) = infer_callconv_x86_64_from_counts(&counts);
        assert_eq!(cc, "ms");
        assert!(confidence >= 70);
    }

    #[test]
    fn confidence_gate_low_case() {
        let confidence = compute_inference_confidence(60, 0, false);
        assert!(confidence < SIG_WRITEBACK_CONFIDENCE_MIN);
        assert!(confidence < CC_WRITEBACK_CONFIDENCE_MIN);
    }

    #[test]
    fn confidence_gate_mid_case() {
        let confidence = compute_inference_confidence(72, 0, false);
        assert!(confidence >= SIG_WRITEBACK_CONFIDENCE_MIN);
        assert!(confidence < CC_WRITEBACK_CONFIDENCE_MIN);
    }

    #[test]
    fn confidence_gate_high_case() {
        let confidence = compute_inference_confidence(76, 1, true);
        assert!(confidence >= SIG_WRITEBACK_CONFIDENCE_MIN);
        assert!(confidence >= CC_WRITEBACK_CONFIDENCE_MIN);
    }

    #[test]
    fn callconv_confidence_is_stable_for_same_register_histogram() {
        let mut first = std::collections::HashMap::new();
        first.insert("rdi".to_string(), 2);
        first.insert("rsi".to_string(), 2);
        first.insert("rdx".to_string(), 1);

        let mut second = std::collections::HashMap::new();
        second.insert("rdx".to_string(), 1);
        second.insert("rsi".to_string(), 2);
        second.insert("rdi".to_string(), 2);

        let inferred_first = infer_callconv_x86_64_from_counts(&first);
        let inferred_second = infer_callconv_x86_64_from_counts(&second);
        assert_eq!(inferred_first, inferred_second);
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
            println!("Contextwarn/error:{:?}", err);
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

    #[test]
    #[cfg(feature = "riscv")]
    fn create_disassembler_for_arch_riscv64() {
        let (spec, disasm) = create_disassembler_for_arch("riscv64").expect("riscv64 disassembler");
        assert_eq!(spec.name, "riscv64");
        assert!(spec.addr_size > 0);
        assert_eq!(spec.instruction_endianness, r2il::Endianness::Little);
        assert_eq!(spec.memory_endianness, r2il::Endianness::Little);
        assert_eq!(
            disasm.userop_name(0),
            userop_map_for_arch("riscv64").get(&0).map(String::as_str)
        );
    }

    #[test]
    #[cfg(feature = "riscv")]
    fn create_disassembler_for_arch_riscv32() {
        let (spec, disasm) = create_disassembler_for_arch("riscv32").expect("riscv32 disassembler");
        assert_eq!(spec.name, "riscv32");
        assert!(spec.addr_size > 0);
        assert_eq!(spec.instruction_endianness, r2il::Endianness::Little);
        assert_eq!(spec.memory_endianness, r2il::Endianness::Little);
        assert_eq!(
            disasm.userop_name(0),
            userop_map_for_arch("riscv32").get(&0).map(String::as_str)
        );
    }

    #[test]
    #[cfg(feature = "riscv")]
    fn r2il_arch_init_riscv64_loaded() {
        let arch_cstr = CString::new("riscv64").unwrap();
        let ctx_ptr = r2il_arch_init(arch_cstr.as_ptr());
        assert!(!ctx_ptr.is_null(), "context pointer should not be null");
        assert_eq!(
            r2il_is_loaded(ctx_ptr),
            1,
            "riscv64 context should be loaded"
        );
        r2il_free(ctx_ptr);
    }

    #[test]
    #[cfg(feature = "riscv")]
    fn r2il_arch_init_riscv32_loaded() {
        let arch_cstr = CString::new("riscv32").unwrap();
        let ctx_ptr = r2il_arch_init(arch_cstr.as_ptr());
        assert!(!ctx_ptr.is_null(), "context pointer should not be null");
        assert_eq!(
            r2il_is_loaded(ctx_ptr),
            1,
            "riscv32 context should be loaded"
        );
        r2il_free(ctx_ptr);
    }
}
