//! Expression folding for decompilation.
//!
//! This module performs expression folding to combine SSA operations into
//! compound C expressions, eliminating unnecessary temporaries and improving
//! readability.
//!
//! ## Key Transformations
//!
//! 1. **Single-use inlining**: If a variable is only used once, inline its
//!    definition at the use site.
//!    ```text
//!    t1 = a + b;
//!    t2 = t1 * c;
//!    // becomes:
//!    t2 = (a + b) * c;
//!    ```
//!
//! 2. **Dead code elimination**: Remove definitions of variables that are
//!    never used (especially CPU flags).
//!
//! 3. **Constant folding**: Replace `const:xxx` with actual numeric values.

use std::collections::{HashMap, HashSet};

use r2ssa::{FunctionSSABlock, SSAFunction, SSAOp, SSAVar};

use crate::analysis;
use crate::ExternalStackVar;
use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};

// Type alias for clarity
pub(crate) type SSABlock = FunctionSSABlock;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PtrArith {
    pub(crate) base: SSAVar,
    pub(crate) index: SSAVar,
    pub(crate) element_size: u32,
    pub(crate) is_sub: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareContext {
    Eq,
    Ne,
    SignedNegative,
}

#[derive(Debug, Clone, PartialEq)]
struct CompareTuple {
    lhs: CExpr,
    rhs: CExpr,
    context: CompareContext,
}

/// Threshold for detecting 64-bit negative values stored as unsigned.
/// Values above this are likely negative offsets (within ~65536 of u64::MAX).
/// This handles cases like stack offsets: 0xffffffffffffffb8 represents -72.
const LIKELY_NEGATIVE_THRESHOLD: u64 = 0xffffffffffff0000;

/// Tracks use counts and definitions for expression folding.
#[derive(Debug)]
pub struct FoldingContext {
    /// Pointer size in bits (reserved for architecture-aware type sizing).
    ptr_size: u32,
    /// Function address to name mapping for resolving call targets.
    function_names: HashMap<u64, String>,
    /// String literals at addresses.
    strings: HashMap<u64, String>,
    /// Symbol/global variable names at addresses.
    symbols: HashMap<u64, String>,
    /// Whether to hide stack frame boilerplate (prologue/epilogue).
    hide_stack_frame: bool,
    /// Stack/frame pointer register names for detection.
    sp_name: String,
    fp_name: String,
    /// Return register name ("rax" for 64-bit, "eax" for 32-bit).
    ret_reg_name: String,
    /// The function's exit block address (block containing SSAOp::Return).
    exit_block: Option<u64>,
    /// Blocks that branch directly to the exit block (these are "return" points).
    return_blocks: HashSet<u64>,
    /// Current block address being processed (for return detection).
    current_block_addr: Option<u64>,
    /// Optional userop name mappings for CallOther.
    userop_names: HashMap<u32, String>,
    /// Ordered argument registers for the calling convention (e.g., SysV x86-64).
    arg_regs: Vec<String>,
    /// Caller-saved registers that can be eliminated when unused.
    caller_saved_regs: HashSet<String>,
    /// Snapshot of explicit analysis passes.
    analysis_ctx: analysis::AnalysisContext,
    /// Stack variables recovered from external analysis metadata.
    external_stack_vars: HashMap<i64, ExternalStackVar>,
}

impl FoldingContext {
    fn use_info(&self) -> &analysis::UseInfo {
        &self.analysis_ctx.use_info
    }

    fn flag_info(&self) -> &analysis::FlagInfo {
        &self.analysis_ctx.flag_info
    }

    fn stack_info(&self) -> &analysis::StackInfo {
        &self.analysis_ctx.stack_info
    }

    pub(crate) fn use_counts_map(&self) -> &HashMap<String, usize> {
        &self.use_info().use_counts
    }
    pub(crate) fn definitions_map(&self) -> &HashMap<String, CExpr> {
        &self.use_info().definitions
    }
    pub(crate) fn formatted_defs_map(&self) -> &HashMap<String, CExpr> {
        &self.use_info().formatted_defs
    }
    pub(crate) fn copy_sources_map(&self) -> &HashMap<String, String> {
        &self.use_info().copy_sources
    }
    pub(crate) fn ptr_arith_map(&self) -> &HashMap<String, PtrArith> {
        &self.use_info().ptr_arith
    }
    pub(crate) fn condition_vars_set(&self) -> &HashSet<String> {
        &self.use_info().condition_vars
    }
    pub(crate) fn pinned_set(&self) -> &HashSet<String> {
        &self.use_info().pinned
    }
    pub(crate) fn call_args_map(&self) -> &HashMap<(u64, usize), Vec<CExpr>> {
        &self.use_info().call_args
    }
    pub(crate) fn consumed_by_call_set(&self) -> &HashSet<String> {
        &self.use_info().consumed_by_call
    }
    pub(crate) fn var_aliases_map(&self) -> &HashMap<String, String> {
        &self.use_info().var_aliases
    }
    pub(crate) fn type_hints_map(&self) -> &HashMap<String, CType> {
        &self.use_info().type_hints
    }
    pub(crate) fn flag_origins_map(&self) -> &HashMap<String, (String, String)> {
        &self.flag_info().flag_origins
    }
    pub(crate) fn flag_only_values_set(&self) -> &HashSet<String> {
        &self.flag_info().flag_only_values
    }
    pub(crate) fn stack_vars_map(&self) -> &HashMap<i64, String> {
        &self.stack_info().stack_vars
    }
    pub(crate) fn to_pass_env(&self) -> analysis::PassEnv {
        analysis::PassEnv {
            ptr_size: self.ptr_size,
            sp_name: self.sp_name.clone(),
            fp_name: self.fp_name.clone(),
            ret_reg_name: self.ret_reg_name.clone(),
            function_names: self.function_names.clone(),
            strings: self.strings.clone(),
            symbols: self.symbols.clone(),
            arg_regs: self.arg_regs.clone(),
            caller_saved_regs: self.caller_saved_regs.clone(),
            type_hints: self.use_info().type_hints.clone(),
        }
    }

    /// Create a new folding context.
    pub fn new(ptr_size: u32) -> Self {
        let sp_name = if ptr_size == 64 {
            "rsp".to_string()
        } else {
            "esp".to_string()
        };
        let fp_name = if ptr_size == 64 {
            "rbp".to_string()
        } else {
            "ebp".to_string()
        };
        let ret_reg_name = if ptr_size == 64 {
            "rax".to_string()
        } else {
            "eax".to_string()
        };
        let arg_regs = if ptr_size == 64 {
            vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ]
        } else {
            vec![]
        };
        let caller_saved_regs = {
            let mut s = HashSet::new();
            if ptr_size == 64 {
                for r in &["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"] {
                    s.insert(r.to_string());
                }
            } else {
                for r in &["eax", "ecx", "edx"] {
                    s.insert(r.to_string());
                }
            }
            s
        };

        Self {
            ptr_size,
            function_names: HashMap::new(),
            strings: HashMap::new(),
            symbols: HashMap::new(),
            hide_stack_frame: true, // Default to hiding stack frame
            // NOTE: Stack register names are currently x86-only.
            // For ARM/MIPS support, these would need to be configurable:
            // - ARM: sp, fp (or r13, r11)
            // - MIPS: $sp, $fp ($29, $30)
            // Use set_stack_regs() to override for other architectures.
            sp_name,
            fp_name,
            ret_reg_name,
            exit_block: None,
            return_blocks: HashSet::new(),
            current_block_addr: None,
            userop_names: HashMap::new(),
            arg_regs,
            caller_saved_regs,
            analysis_ctx: analysis::AnalysisContext {
                use_info: analysis::UseInfo::default(),
                flag_info: analysis::FlagInfo::default(),
                stack_info: analysis::StackInfo::default(),
            },
            external_stack_vars: HashMap::new(),
        }
    }

    /// Set whether to hide stack frame boilerplate.
    pub fn set_hide_stack_frame(&mut self, hide: bool) {
        self.hide_stack_frame = hide;
    }

    /// Set stack/frame pointer names for stack frame detection.
    pub fn set_stack_regs(&mut self, sp_name: &str, fp_name: &str) {
        self.sp_name = sp_name.to_string();
        self.fp_name = fp_name.to_string();
    }

    /// Set the function name mapping for resolving call targets.
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.function_names = names;
    }

    /// Set the string literals mapping.
    pub fn set_strings(&mut self, strings: HashMap<u64, String>) {
        self.strings = strings;
    }

    /// Set calling convention argument registers (ordered).
    pub fn set_arg_regs(&mut self, regs: Vec<String>) {
        self.arg_regs = regs;
    }

    /// Collect the set of variable names that survive folding (not inlined, not dead,
    /// not consumed by call args). Used to filter local variable declarations.
    pub fn emitted_var_names(&self, blocks: &[SSABlock]) -> HashSet<String> {
        let mut names = HashSet::new();
        for block in blocks {
            for (op_idx, op) in block.ops.iter().enumerate() {
                if self.is_stack_frame_op(op) {
                    continue;
                }
                if let Some(dst) = op.dst() {
                    if self.is_dead(dst) {
                        continue;
                    }
                    let key = dst.display_name();
                    if self.should_inline(&key) {
                        continue;
                    }
                    if self.consumed_by_call_set().contains(&key) {
                        continue;
                    }
                }
                // For Call/CallInd, check if op_to_stmt_with_args would emit it
                let is_call = matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. });
                if is_call {
                    // Calls don't produce named variables, skip
                    continue;
                }
                // This op would be emitted - collect any variable name it defines
                if let Some(dst) = op.dst() {
                    let var_name = self.var_name(dst);
                    names.insert(var_name);
                }
                // Also collect variable names used in the right-hand side
                // (These appear as Var references in the output)
                for src in op.sources() {
                    if src.is_const() || src.name.starts_with("ram:") {
                        continue;
                    }
                    let _ = op_idx; // suppress unused warning
                    let var_name = self.var_name(src);
                    names.insert(var_name);
                }
            }
        }
        names
    }

    /// Set the symbol/global variable names mapping.
    pub fn set_symbols(&mut self, symbols: HashMap<u64, String>) {
        self.symbols = symbols;
    }

    /// Set CallOther userop name mappings.
    pub fn set_userop_names(&mut self, names: HashMap<u32, String>) {
        self.userop_names = names;
    }

    /// Set inferred type hints keyed by rendered variable name.
    pub fn set_type_hints(&mut self, hints: HashMap<String, CType>) {
        self.analysis_ctx.use_info.type_hints = hints;
    }

    /// Set externally recovered stack variables keyed by signed stack offset.
    pub fn set_external_stack_vars(&mut self, stack_vars: HashMap<i64, ExternalStackVar>) {
        self.external_stack_vars = stack_vars;
    }

    /// Analyze function structure to detect return patterns.
    /// This finds the exit block and blocks that branch to it.
    pub fn analyze_function_structure(&mut self, func: &SSAFunction) {
        // Find exit block (the block containing SSAOp::Return)
        for block in func.blocks() {
            for op in &block.ops {
                if matches!(op, SSAOp::Return { .. }) {
                    self.exit_block = Some(block.addr);
                    break;
                }
            }
            if self.exit_block.is_some() {
                break;
            }
        }

        // Find blocks that branch directly to the exit block
        if let Some(exit_addr) = self.exit_block {
            // Treat the exit block itself as a return context.
            self.return_blocks.insert(exit_addr);

            for block in func.blocks() {
                // Skip the exit block itself
                if block.addr == exit_addr {
                    continue;
                }

                for op in &block.ops {
                    if let SSAOp::Branch { target } = op {
                        // Extract address from the target variable (e.g., "ram:401256_0")
                        if let Some(addr) = self.extract_branch_target_address(target) {
                            if addr == exit_addr {
                                self.return_blocks.insert(block.addr);
                            }
                        }
                    }
                }
            }

            // Also mark blocks that fall through to exit (no explicit branch at end)
            // These are typically the else branch in if-return patterns
            // Check if this block is a predecessor of exit block by looking at phi nodes
            if let Some(exit_blk) = func.get_block(exit_addr) {
                for phi in &exit_blk.phis {
                    for (src_addr, _) in &phi.sources {
                        // src_addr is already u64
                        if *src_addr != exit_addr {
                            self.return_blocks.insert(*src_addr);
                        }
                    }
                }
            }
        }
    }

    /// Extract address from a branch target variable.
    fn extract_branch_target_address(&self, target: &SSAVar) -> Option<u64> {
        // Target is usually "ram:401256_0" format
        let name = &target.name;
        if let Some(rest) = name.strip_prefix("ram:") {
            // Parse hex address
            u64::from_str_radix(rest, 16).ok()
        } else if let Some(rest) = name.strip_prefix("const:") {
            u64::from_str_radix(rest, 16).ok()
        } else {
            None
        }
    }

    /// Set the current block address being processed.
    pub fn set_current_block(&mut self, addr: u64) {
        self.current_block_addr = Some(addr);
    }

    /// Check if the current block is a return block.
    fn is_current_return_block(&self) -> bool {
        if let Some(addr) = self.current_block_addr {
            return self.return_blocks.contains(&addr);
        }
        false
    }

    /// Return true when `name` identifies an architecture return register.
    /// `name` is expected to be lowercase and without SSA suffix.
    fn is_return_register_name(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        let base = name.split('_').next().unwrap_or(&name);

        if base == self.ret_reg_name {
            return true;
        }

        match self.ptr_size {
            8 => matches!(base, "rax" | "eax" | "ax" | "al"),
            _ => matches!(base, "eax" | "ax" | "al"),
        }
    }

    /// Look up a function name by address.
    fn lookup_function(&self, addr: u64) -> Option<&String> {
        self.function_names.get(&addr)
    }

    /// Look up a string literal by address.
    fn lookup_string(&self, addr: u64) -> Option<&String> {
        self.strings.get(&addr)
    }

    /// Look up a symbol by address.
    fn lookup_symbol(&self, addr: u64) -> Option<&String> {
        self.symbols.get(&addr)
    }

    /// Look up a userop name for CallOther.
    fn lookup_userop_name(&self, userop: u32) -> String {
        self.userop_names
            .get(&userop)
            .cloned()
            .unwrap_or_else(|| format!("userop_{}", userop))
    }

    /// Analyze a block to collect use counts and definitions.
    pub fn analyze_block(&mut self, block: &SSABlock) {
        self.analyze_blocks(std::slice::from_ref(block));
    }

    /// Analyze multiple blocks (for function-level folding).
    pub fn analyze_blocks(&mut self, blocks: &[SSABlock]) {
        // Explicit pass order:
        // 1) UseInfo
        // 2) FlagInfo + StackInfo
        // 3) Predicate simplification/statement emit consume analysis state
        let env = self.to_pass_env();
        let mut use_info = analysis::UseInfo::analyze(blocks, &env);
        let flag_info = analysis::FlagInfo::analyze(blocks, &use_info, &env);
        let mut stack_info = analysis::StackInfo::analyze(blocks, &use_info, &env);

        for (offset, ext_var) in &self.external_stack_vars {
            if ext_var.name.is_empty() {
                continue;
            }
            let should_replace = match stack_info.stack_vars.get(offset) {
                None => true,
                Some(existing) => {
                    existing.starts_with("local_")
                        || existing.starts_with("stack_")
                        || existing.starts_with("arg_")
                        || existing == "saved_fp"
                        || is_generic_arg_name(existing)
                }
            };
            if should_replace {
                stack_info.stack_vars.insert(*offset, ext_var.name.clone());
            }
        }

        // Deterministically merge stack-derived alias refinements.
        for (key, expr) in &stack_info.definition_overrides {
            if self.is_stack_alias_expr(expr) {
                use_info.definitions.insert(key.clone(), expr.clone());
                use_info.formatted_defs.insert(
                    analysis::utils::format_traced_name(key, &use_info.var_aliases),
                    expr.clone(),
                );
            }
        }
        self.analysis_ctx = analysis::AnalysisContext {
            use_info,
            flag_info,
            stack_info,
        };
    }

    fn is_stack_alias_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lowered = name.to_lowercase();
                lowered.starts_with("arg")
                    || lowered.starts_with("local_")
                    || lowered.starts_with("&arg")
                    || lowered.starts_with("&local_")
            }
            _ => false,
        }
    }

    /// Try to extract a stack offset from a variable name or its definition.
    pub(crate) fn extract_stack_offset_from_var(&self, var: &SSAVar) -> Option<i64> {
        let name_lower = var.name.to_lowercase();

        // Direct fp/sp reference
        if name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name) {
            return Some(0);
        }

        // Check if this variable was defined as fp/sp + offset
        let key = var.display_name();
        if let Some(expr) = self.definitions_map().get(&key) {
            return self.extract_offset_from_expr(expr);
        }

        None
    }

    /// Extract stack offset from an expression like (rbp + -0x48).
    fn extract_offset_from_expr(&self, expr: &CExpr) -> Option<i64> {
        self.extract_offset_from_expr_with_depth(expr, 0)
    }

    fn extract_offset_from_expr_with_depth(&self, expr: &CExpr, depth: u32) -> Option<i64> {
        if depth > 8 {
            return None;
        }

        match expr {
            CExpr::Paren(inner) => self.extract_offset_from_expr_with_depth(inner, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.extract_offset_from_expr_with_depth(inner, depth + 1)
            }
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => {
                if self.is_stack_base_expr(left) {
                    return self.expr_to_offset(right);
                }
                if self.is_stack_base_expr(right) {
                    return self.expr_to_offset(left);
                }
                None
            }
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => {
                if self.is_stack_base_expr(left) {
                    return self.expr_to_offset(right).map(|off| -off);
                }
                None
            }
            CExpr::Var(name) => {
                let name_lower = name.to_lowercase();
                if name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name) {
                    return Some(0);
                }
                self.lookup_definition(name)
                    .and_then(|inner| self.extract_offset_from_expr_with_depth(&inner, depth + 1))
            }
            _ => None,
        }
    }

    fn is_stack_base_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let name_lower = name.to_lowercase();
                name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name)
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => self.is_stack_base_expr(inner),
            _ => false,
        }
    }

    /// Convert an expression to an offset value.
    fn expr_to_offset(&self, expr: &CExpr) -> Option<i64> {
        match expr {
            CExpr::IntLit(v) => Some(*v),
            CExpr::UIntLit(v) => {
                // Handle negative offsets stored as unsigned
                if *v > LIKELY_NEGATIVE_THRESHOLD {
                    let neg = (!*v).wrapping_add(1);
                    Some(-(neg as i64))
                } else {
                    Some(*v as i64)
                }
            }
            _ => None,
        }
    }

    fn arg_alias_for_register_name(&self, reg_name: &str) -> Option<String> {
        let reg = reg_name.to_lowercase();
        if reg.contains("rdi") || reg.contains("edi") {
            return Some("arg1".to_string());
        }
        if reg.contains("rsi") || reg.contains("esi") {
            return Some("arg2".to_string());
        }
        if reg.contains("rdx") || reg.contains("edx") {
            return Some("arg3".to_string());
        }
        if reg.contains("rcx") || reg.contains("ecx") {
            return Some("arg4".to_string());
        }
        if reg.contains("r8") {
            return Some("arg5".to_string());
        }
        if reg.contains("r9") {
            return Some("arg6".to_string());
        }
        None
    }

    fn arg_alias_for_rendered_name(&self, name: &str) -> Option<String> {
        let lower = name.to_lowercase();
        if let Some((base, version)) = lower.rsplit_once('_') {
            if version != "0" {
                return None;
            }
            return self.arg_alias_for_register_name(base);
        }
        self.arg_alias_for_register_name(&lower)
    }

    /// Check if an address expression is a stack access and return the variable name.
    pub fn simplify_stack_access(&self, addr_expr: &CExpr) -> Option<String> {
        match addr_expr {
            CExpr::Paren(inner) => return self.simplify_stack_access(inner),
            CExpr::Cast { expr: inner, .. } => return self.simplify_stack_access(inner),
            CExpr::Var(name) => {
                if let Some(stripped) = name.strip_prefix('&') {
                    return Some(stripped.to_string());
                }
            }
            _ => {}
        }

        if let Some(offset) = self.extract_offset_from_expr(addr_expr) {
            return self.resolve_stack_var(offset);
        }
        None
    }

    fn resolve_stack_alias_from_addr_expr(&self, expr: &CExpr, depth: u32) -> Option<String> {
        if depth > 8 {
            return None;
        }

        if let Some(alias) = self.simplify_stack_access(expr) {
            return Some(alias);
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(stripped) = name.strip_prefix('&') {
                    return Some(stripped.to_string());
                }
                self.lookup_definition(name)
                    .and_then(|inner| self.resolve_stack_alias_from_addr_expr(&inner, depth + 1))
            }
            CExpr::Paren(inner) => self.resolve_stack_alias_from_addr_expr(inner, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.resolve_stack_alias_from_addr_expr(inner, depth + 1)
            }
            CExpr::Deref(inner) => self.resolve_stack_alias_from_addr_expr(inner, depth + 1),
            _ => None,
        }
    }
    pub(crate) fn stack_var_for_addr_var(&self, addr: &SSAVar) -> Option<String> {
        let addr_key = addr.display_name();
        if let Some(alias) =
            self.resolve_stack_alias_from_addr_expr(&CExpr::Var(addr_key.clone()), 0)
        {
            return Some(alias);
        }
        if let Some(alias) =
            self.resolve_stack_alias_from_addr_expr(&CExpr::Var(self.var_name(addr)), 0)
        {
            return Some(alias);
        }
        self.extract_stack_offset_from_var(addr)
            .and_then(|offset| self.resolve_stack_var(offset))
    }

    /// Resolve a stack variable name by signed stack offset.
    pub fn resolve_stack_var(&self, offset: i64) -> Option<String> {
        self.stack_vars_map().get(&offset).cloned()
    }

    fn rewrite_stack_expr(&self, expr: CExpr) -> CExpr {
        let rewritten = match expr {
            CExpr::Unary { op, operand } => CExpr::Unary {
                op,
                operand: Box::new(self.rewrite_stack_expr(*operand)),
            },
            CExpr::Binary { op, left, right } => CExpr::Binary {
                op,
                left: Box::new(self.rewrite_stack_expr(*left)),
                right: Box::new(self.rewrite_stack_expr(*right)),
            },
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => CExpr::Ternary {
                cond: Box::new(self.rewrite_stack_expr(*cond)),
                then_expr: Box::new(self.rewrite_stack_expr(*then_expr)),
                else_expr: Box::new(self.rewrite_stack_expr(*else_expr)),
            },
            CExpr::Call { func, args } => CExpr::Call {
                func: Box::new(self.rewrite_stack_expr(*func)),
                args: args
                    .into_iter()
                    .map(|arg| self.rewrite_stack_expr(arg))
                    .collect(),
            },
            CExpr::Cast { ty, expr } => CExpr::Cast {
                ty,
                expr: Box::new(self.rewrite_stack_expr(*expr)),
            },
            CExpr::Paren(inner) => CExpr::Paren(Box::new(self.rewrite_stack_expr(*inner))),
            CExpr::Deref(inner) => CExpr::Deref(Box::new(self.rewrite_stack_expr(*inner))),
            CExpr::AddrOf(inner) => CExpr::AddrOf(Box::new(self.rewrite_stack_expr(*inner))),
            CExpr::Subscript { base, index } => CExpr::Subscript {
                base: Box::new(self.rewrite_stack_expr(*base)),
                index: Box::new(self.rewrite_stack_expr(*index)),
            },
            CExpr::Member { base, member } => CExpr::Member {
                base: Box::new(self.rewrite_stack_expr(*base)),
                member,
            },
            CExpr::PtrMember { base, member } => CExpr::PtrMember {
                base: Box::new(self.rewrite_stack_expr(*base)),
                member,
            },
            CExpr::Sizeof(inner) => CExpr::Sizeof(Box::new(self.rewrite_stack_expr(*inner))),
            CExpr::Comma(items) => {
                CExpr::Comma(items.into_iter().map(|item| self.rewrite_stack_expr(item)).collect())
            }
            other => other,
        };

        if matches!(
            rewritten,
            CExpr::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                ..
            } | CExpr::Paren(_) | CExpr::Cast { .. }
        ) && let Some(alias) = self.resolve_stack_alias_from_addr_expr(&rewritten, 0)
        {
            return CExpr::Var(alias);
        }

        match rewritten {
            CExpr::Deref(inner) => {
                if let Some(alias) = self.resolve_stack_alias_from_addr_expr(&inner, 0) {
                    return CExpr::Var(alias);
                }
                if let Some(var_name) = self.extract_known_stack_var_name(&inner) {
                    return CExpr::Var(var_name);
                }
                CExpr::Deref(inner)
            }
            other => other,
        }
    }

    fn extract_known_stack_var_name(&self, expr: &CExpr) -> Option<String> {
        match expr {
            CExpr::Var(name) => {
                if self.stack_vars_map().values().any(|candidate| candidate == name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.extract_known_stack_var_name(inner)
            }
            _ => None,
        }
    }

    /// Check if a variable should be inlined.
    fn should_inline(&self, var_name: &str) -> bool {
        let use_count = self.use_counts_map().get(var_name).copied().unwrap_or(0);
        if use_count == 0 || use_count > 3 {
            return false;
        }

        if self.pinned_set().contains(var_name) {
            return false;
        }

        if self.condition_vars_set().contains(var_name)
            && !self.is_condition_inline_candidate(var_name)
        {
            return false;
        }

        // Values that only feed flag computation should always disappear.
        if self.flag_only_values_set().contains(var_name) {
            return true;
        }

        // Multi-use inlining is only allowed for very small expressions.
        if use_count > 1 && !self.is_simple_inline_candidate(var_name) {
            return false;
        }

        // Always inline temporaries and constants.
        if var_name.starts_with("tmp:") || var_name.starts_with("const:") {
            return true;
        }

        // Inline single-use register copies:
        // If a named register variable is used exactly once and has a simple
        // definition (Copy from const/string/var), inline it at the use site.
        // This eliminates `rdi_2 = "hello"; foo(rdi_2)` -> `foo("hello")`.
        if let Some((base, _version)) = var_name.rsplit_once('_') {
            let base_lower = base.to_lowercase();
            // Don't inline return register assignments in return blocks
            if base_lower == self.ret_reg_name && self.is_current_return_block() {
                return false;
            }
            // Don't inline stack/frame pointer versions - they're structural
            if base_lower == self.sp_name || base_lower == self.fp_name {
                return false;
            }
            // Inline calling-convention argument registers (consumed by call args)
            if self.caller_saved_regs.contains(&base_lower) {
                return true;
            }
            // Inline any register with a definition when it is single-use
            // or the definition is trivially small.
            if use_count == 1 || self.is_simple_inline_candidate(var_name) {
                return true;
            }
        }

        false
    }

    fn is_condition_inline_candidate(&self, var_name: &str) -> bool {
        if self.flag_only_values_set().contains(var_name) {
            return true;
        }

        if is_cpu_flag(&var_name.to_lowercase()) {
            return true;
        }

        self.is_simple_inline_candidate(var_name)
    }

    fn is_simple_inline_candidate(&self, var_name: &str) -> bool {
        self.definitions_map()
            .get(var_name)
            .map(|expr| self.is_simple_expr(expr, 0))
            .unwrap_or(false)
    }

    fn is_simple_expr(&self, expr: &CExpr, depth: u32) -> bool {
        if depth > 2 {
            return false;
        }

        match expr {
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_) => true,
            CExpr::Var(name) => {
                if is_cpu_flag(&name.to_lowercase()) {
                    return true;
                }
                self.definitions_map()
                    .get(name)
                    .map(|inner| self.is_simple_expr(inner, depth + 1))
                    .unwrap_or(true)
            }
            CExpr::Cast { expr, .. } | CExpr::Paren(expr) => self.is_simple_expr(expr, depth + 1),
            CExpr::Unary { operand, .. } => self.is_simple_expr(operand, depth + 1),
            CExpr::Binary { op, left, right } => {
                matches!(
                    op,
                    BinaryOp::Add
                        | BinaryOp::Sub
                        | BinaryOp::Eq
                        | BinaryOp::Ne
                        | BinaryOp::BitAnd
                        | BinaryOp::BitOr
                        | BinaryOp::BitXor
                        | BinaryOp::And
                        | BinaryOp::Or
                ) && self.is_simple_expr(left, depth + 1)
                    && self.is_simple_expr(right, depth + 1)
            }
            _ => false,
        }
    }

    /// Check if a variable is dead (never used).
    pub fn is_dead(&self, var: &SSAVar) -> bool {
        let key = var.display_name();
        let use_count = self.use_counts_map().get(&key).copied().unwrap_or(0);
        let lower = var.name.to_lowercase();

        // Flag registers are rendering artifacts; keep them out of emitted code.
        if is_cpu_flag(&lower) {
            return true;
        }

        // Helpers used only to feed flags are also dead in final output.
        if self.flag_only_values_set().contains(&key) {
            return true;
        }

        if use_count > 0 {
            return false;
        }

        // Temporaries and reg: prefixed vars are always dead if unused
        if var.name.starts_with("tmp:")
            || var.name.starts_with("const:")
            || var.name.starts_with("reg:")
        {
            return true;
        }

        // Caller-saved / calling-convention registers are dead if unused
        // (their values don't survive across calls anyway)
        if self.caller_saved_regs.contains(&lower) {
            return true;
        }

        // Variables consumed by call argument collection are dead
        if self.consumed_by_call_set().contains(&key) {
            return true;
        }

        // Stack/frame pointer intermediate versions are dead if unused
        if lower == self.sp_name || lower == self.fp_name {
            return true;
        }

        // Eliminate explicit zeroing idioms when the value is never used
        // beyond setup/flag chains (e.g., eax = eax ^ eax).
        if let Some(expr) = self.definitions_map().get(&key) {
            if self.is_zeroing_expr(expr) {
                return true;
            }
        }

        // Keep other named registers alive (e.g., callee-saved like rbx, r12-r15)
        // as they might be meaningful outputs
        false
    }

    fn is_zeroing_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Binary {
                op: BinaryOp::BitXor | BinaryOp::Sub,
                left,
                right,
            } => left == right,
            _ => false,
        }
    }

    /// Check if an operation is part of stack frame setup/teardown (prologue/epilogue).
    pub fn is_stack_frame_op(&self, op: &SSAOp) -> bool {
        if !self.hide_stack_frame {
            return false;
        }

        match op {
            // push rbp: Store to (rsp - 8) where value is rbp
            SSAOp::Store { addr, val, .. } => {
                let addr_name = addr.name.to_lowercase();
                let val_name = val.name.to_lowercase();
                // Store of fp to stack (push fp)
                if val_name.contains(&self.fp_name)
                    && (addr_name.contains(&self.sp_name) || addr_name.contains("tmp:"))
                {
                    return true;
                }
                // Store return address to stack
                if val_name.contains("rip") || val_name.contains("eip") {
                    return true;
                }
                // Store constant to RSP-derived address (pre-call return address push)
                if val.is_const()
                    && (addr_name.contains(&self.sp_name) || addr_name.contains("tmp:"))
                {
                    // Check if this constant was consumed by call-arg analysis
                    let val_key = val.display_name();
                    if self.consumed_by_call_set().contains(&val_key) {
                        return true;
                    }
                }
                // Store callee-saved register to stack (prologue push)
                // The P-code often uses temps: Copy tmp:X = RBX; Store [RSP], tmp:X
                // So we need to check both direct and indirect through temps.
                if (addr_name.contains(&self.sp_name) || addr_name.contains("tmp:"))
                    && !val.is_const()
                {
                    // Direct: val is a callee-saved register
                    if val_name.contains("rbx")
                        || val_name.contains("r12")
                        || val_name.contains("r13")
                        || val_name.contains("r14")
                        || val_name.contains("r15")
                    {
                        return true;
                    }
                    // Indirect: val is a temp, trace it back via copy_sources
                    if val.name.starts_with("tmp:") {
                        let val_key = val.display_name();
                        if let Some(src_key) = self.copy_sources_map().get(&val_key) {
                            let src_lower = src_key.to_lowercase();
                            if src_lower.contains("rbx")
                                || src_lower.contains("r12")
                                || src_lower.contains("r13")
                                || src_lower.contains("r14")
                                || src_lower.contains("r15")
                                || src_lower.contains(&self.fp_name)
                            {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            // mov rbp, rsp: Copy from sp to fp
            SSAOp::Copy { dst, src } => {
                let dst_name = dst.name.to_lowercase();
                let src_name = src.name.to_lowercase();
                // mov fp, sp (frame pointer setup)
                if dst_name.contains(&self.fp_name) && src_name.contains(&self.sp_name) {
                    return true;
                }
                // mov sp, fp (frame pointer teardown)
                if dst_name.contains(&self.sp_name) && src_name.contains(&self.fp_name) {
                    return true;
                }
                false
            }
            // sub rsp, N: Stack allocation
            SSAOp::IntSub { dst, a, b } => {
                let dst_name = dst.name.to_lowercase();
                let a_name = a.name.to_lowercase();
                // sp = sp - const (stack allocation)
                if dst_name.contains(&self.sp_name)
                    && a_name.contains(&self.sp_name)
                    && b.is_const()
                {
                    return true;
                }
                false
            }
            // add rsp, N: Stack deallocation
            SSAOp::IntAdd { dst, a, b } => {
                let dst_name = dst.name.to_lowercase();
                let a_name = a.name.to_lowercase();
                // sp = sp + const (stack deallocation)
                if dst_name.contains(&self.sp_name)
                    && a_name.contains(&self.sp_name)
                    && b.is_const()
                {
                    return true;
                }
                // sp = fp + const (leave instruction equivalent)
                if dst_name.contains(&self.sp_name)
                    && a_name.contains(&self.fp_name)
                    && b.is_const()
                {
                    return true;
                }
                false
            }
            // pop rbp: Load from stack to fp
            SSAOp::Load { dst, addr, .. } => {
                let dst_name = dst.name.to_lowercase();
                let addr_name = addr.name.to_lowercase();
                // Load fp from stack (pop fp)
                if dst_name.contains(&self.fp_name)
                    && (addr_name.contains(&self.sp_name) || addr_name.contains("tmp:"))
                {
                    return true;
                }
                // Load return address (ret)
                if dst_name.contains("rip") || dst_name.contains("eip") {
                    return true;
                }
                // Load callee-saved register from stack (epilogue pop)
                if (addr_name.contains(&self.sp_name) || addr_name.contains("tmp:"))
                    && (dst_name.contains("rbx")
                        || dst_name.contains("r12")
                        || dst_name.contains("r13")
                        || dst_name.contains("r14")
                        || dst_name.contains("r15"))
                {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Get the expression for a variable, potentially inlining its definition.
    pub fn get_expr(&self, var: &SSAVar) -> CExpr {
        let key = var.display_name();

        // Always inline constants
        if var.is_const() {
            return self.const_to_expr(var);
        }

        // Resolve ram:address references to known names
        if var.name.starts_with("ram:") {
            if let Some(addr) = extract_call_address(&var.name) {
                if let Some(name) = self.lookup_function(addr) {
                    return CExpr::Var(name.clone());
                }
                if let Some(s) = self.lookup_string(addr) {
                    return CExpr::StringLit(s.clone());
                }
                if let Some(s) = self.lookup_symbol(addr) {
                    return CExpr::Var(s.clone());
                }
            }
        }

        // Try to inline if appropriate
        if self.should_inline(&key) {
            if let Some(expr) = self.definitions_map().get(&key) {
                return expr.clone();
            }
        }

        // Otherwise return a variable reference
        CExpr::Var(self.var_name(var))
    }

    fn should_inline_in_return(&self, var_name: &str, depth: u32) -> bool {
        if depth > 8 {
            return false;
        }

        let lower = var_name.to_lowercase();
        if lower.starts_with("const:") || lower.starts_with("tmp:") {
            return true;
        }
        if self.is_return_register_name(&lower) {
            return true;
        }

        let is_pinned = self.pinned_set().contains(var_name)
            || self.pinned_set().contains(&lower)
            || var_name
                .rsplit_once('_')
                .map(|(base, ver)| {
                    self.pinned_set()
                        .contains(&format!("{}_{}", base.to_lowercase(), ver))
                        || self
                            .pinned_set()
                            .contains(&format!("{}_{}", base.to_uppercase(), ver))
                })
                .unwrap_or(false);
        if is_pinned {
            return false;
        }

        let use_count = self
            .use_counts_map()
            .get(var_name)
            .copied()
            .or_else(|| self.use_counts_map().get(&lower).copied())
            .or_else(|| {
                var_name.rsplit_once('_').and_then(|(base, ver)| {
                    self.use_counts_map()
                        .get(&format!("{}_{}", base.to_lowercase(), ver))
                        .copied()
                        .or_else(|| {
                            self.use_counts_map()
                                .get(&format!("{}_{}", base.to_uppercase(), ver))
                                .copied()
                        })
                })
            })
            .unwrap_or(0);
        if use_count == 0 || use_count > 3 {
            return false;
        }

        self.lookup_definition(var_name)
            .map(|expr| self.is_return_inline_candidate(&expr, 0))
            .unwrap_or(false)
    }

    fn is_return_inline_candidate(&self, expr: &CExpr, depth: u32) -> bool {
        if depth > 5 {
            return false;
        }

        match expr {
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_) => true,
            CExpr::Var(_) => true,
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.is_return_inline_candidate(inner, depth + 1)
            }
            CExpr::Unary { operand, .. } => self.is_return_inline_candidate(operand, depth + 1),
            CExpr::Binary { op, left, right } => {
                matches!(
                    op,
                    BinaryOp::Add
                        | BinaryOp::Sub
                        | BinaryOp::Mul
                        | BinaryOp::Div
                        | BinaryOp::Mod
                        | BinaryOp::Shl
                        | BinaryOp::Shr
                        | BinaryOp::BitAnd
                        | BinaryOp::BitOr
                        | BinaryOp::BitXor
                        | BinaryOp::And
                        | BinaryOp::Or
                        | BinaryOp::Eq
                        | BinaryOp::Ne
                        | BinaryOp::Lt
                        | BinaryOp::Le
                        | BinaryOp::Gt
                        | BinaryOp::Ge
                ) && self.is_return_inline_candidate(left, depth + 1)
                    && self.is_return_inline_candidate(right, depth + 1)
            }
            CExpr::Deref(inner) => self.resolve_stack_alias_from_addr_expr(inner, 0).is_some(),
            _ => false,
        }
    }

    fn stack_alias_from_deref_expr(&self, expr: &CExpr) -> Option<String> {
        match expr {
            CExpr::Deref(inner) => self.resolve_stack_alias_from_addr_expr(inner, 0),
            CExpr::Paren(inner) => self.stack_alias_from_deref_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.stack_alias_from_deref_expr(inner),
            _ => None,
        }
    }

    fn expand_return_expr(&self, expr: &CExpr, depth: u32, visited: &mut HashSet<String>) -> CExpr {
        if depth > 8 {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(val) = parse_const_value(name) {
                    return if val > 0x7fffffff {
                        CExpr::UIntLit(val)
                    } else {
                        CExpr::IntLit(val as i64)
                    };
                }
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if let Some(inner) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                {
                    if let CExpr::Var(inner_name) = inner {
                        if inner_name.starts_with("arg") {
                            return CExpr::Var(inner_name);
                        }
                        if let Some(alias) = self.arg_alias_for_rendered_name(&inner_name) {
                            return CExpr::Var(alias);
                        }
                    }
                }

                if !self.should_inline_in_return(name, depth) || !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| self.expand_return_expr(&inner, depth + 1, visited))
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                if self.is_predicate_like_expr(&resolved) {
                    self.simplify_condition_expr(resolved)
                } else {
                    resolved
                }
            }
            CExpr::Deref(inner) => {
                if let Some(stack_var) = self.resolve_stack_alias_from_addr_expr(inner, 0) {
                    CExpr::Var(stack_var)
                } else {
                    let expanded_inner = self.expand_return_expr(inner, depth + 1, visited);
                    if let Some(sub) = self.try_subscript_from_addr_expr(&expanded_inner) {
                        sub
                    } else if let Some(member) =
                        self.try_member_access_from_addr_expr(&expanded_inner)
                    {
                        member
                    } else {
                        CExpr::Deref(Box::new(expanded_inner))
                    }
                }
            }
            CExpr::Unary { op, operand } => {
                CExpr::unary(*op, self.expand_return_expr(operand, depth + 1, visited))
            }
            CExpr::Binary { op, left, right } => {
                let rebuilt = CExpr::binary(
                    *op,
                    self.expand_return_expr(left, depth + 1, visited),
                    self.expand_return_expr(right, depth + 1, visited),
                );
                if self.is_predicate_like_expr(&rebuilt) {
                    self.simplify_condition_expr(rebuilt)
                } else {
                    rebuilt
                }
            }
            CExpr::Paren(inner) => {
                CExpr::Paren(Box::new(self.expand_return_expr(inner, depth + 1, visited)))
            }
            CExpr::Cast { ty, expr: inner } => {
                let expanded_inner = self.expand_return_expr(inner, depth + 1, visited);
                let simplified_inner = if self.is_predicate_like_expr(&expanded_inner) {
                    self.simplify_condition_expr(expanded_inner)
                } else {
                    expanded_inner
                };
                CExpr::Cast {
                    ty: ty.clone(),
                    expr: Box::new(simplified_inner),
                }
            }
            _ => expr.clone(),
        }
    }

    fn get_return_expr(&self, var: &SSAVar) -> CExpr {
        if var.is_const() {
            return self.const_to_expr(var);
        }

        let mut visited = HashSet::new();
        let root_name = var.display_name();
        let root = self
            .lookup_definition(&root_name)
            .unwrap_or_else(|| CExpr::Var(root_name));
        let raw = self.expand_return_expr(&root, 0, &mut visited);
        if self.is_predicate_like_expr(&raw) {
            self.simplify_condition_expr(raw)
        } else {
            raw
        }
    }

    /// Convert an SSA variable to a C variable name.
    pub fn var_name(&self, var: &SSAVar) -> String {
        if var.is_const() {
            // Return the constant value directly
            let val = parse_const_value(&var.name).unwrap_or(0);
            if val > 0xffff {
                return format!("0x{:x}", val);
            } else {
                return format!("{}", val);
            }
        }

        if let Some(addr) = extract_call_address(&var.name) {
            if let Some(sym) = self.lookup_symbol(addr) {
                return sym.clone();
            }
            if let Some(name) = self.lookup_function(addr) {
                return name.clone();
            }
        }

        // Check if coalescing mapped this SSA name to a merged name
        let display = var.display_name();
        if let Some(alias) = self.var_aliases_map().get(&display) {
            return alias.clone();
        }

        let base = if var.name.starts_with("reg:") {
            let reg = var.name.trim_start_matches("reg:");
            if is_hex_name(reg) {
                format!("r{}", reg)
            } else {
                reg.to_string()
            }
        } else if var.name.starts_with("tmp:") {
            format!("t{}", var.version)
        } else {
            var.name.to_lowercase()
        };

        if var.version > 0 {
            format!("{}_{}", base, var.version)
        } else {
            base
        }
    }

    /// Convert a constant variable to a C expression.
    fn const_to_expr(&self, var: &SSAVar) -> CExpr {
        let val = parse_const_value(&var.name).unwrap_or(0);

        // Only resolve addresses that are plausibly code/data (not small literals)
        if val > 0xff {
            // Check if this is a function address (e.g., for lea rdi, [main])
            if let Some(name) = self.lookup_function(val) {
                return CExpr::Var(name.clone());
            }

            // Check if this is a string address
            if let Some(s) = self.lookup_string(val) {
                return CExpr::StringLit(s.clone());
            }

            // Check if this is a symbol address
            if let Some(s) = self.lookup_symbol(val) {
                return CExpr::Var(s.clone());
            }
        }

        if val > 0x7fffffff {
            CExpr::UIntLit(val)
        } else {
            CExpr::IntLit(val as i64)
        }
    }

    /// Convert an SSA operation to a C expression.
    pub(crate) fn op_to_expr(&self, op: &SSAOp) -> CExpr {
        match op {
            SSAOp::Copy { src, .. } => self.get_expr(src),
            SSAOp::Load { addr, .. } => {
                // Try to resolve ram: address to a global symbol directly
                if addr.name.starts_with("ram:") {
                    if let Some(address) = extract_call_address(&addr.name) {
                        if let Some(sym) = self.lookup_symbol(address) {
                            return CExpr::Var(sym.clone());
                        }
                        if let Some(name) = self.lookup_function(address) {
                            return CExpr::Var(name.clone());
                        }
                        if let Some(s) = self.lookup_string(address) {
                            return CExpr::StringLit(s.clone());
                        }
                    }
                }
                if let Some(stack_var) = self.stack_var_for_addr_var(addr) {
                    return CExpr::Var(stack_var);
                }
                let addr_expr = self.get_expr(addr);
                if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                    CExpr::Var(stack_var)
                } else if let Some(ptr) = self.ptr_arith_map().get(&addr.display_name()) {
                    self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
                } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                    sub
                } else if let Some(member) = self.try_member_access_from_expr(addr, &addr_expr) {
                    member
                } else {
                    CExpr::Deref(Box::new(addr_expr))
                }
            }
            SSAOp::IntAdd { a, b, .. } => self.binary_expr(BinaryOp::Add, a, b),
            SSAOp::IntSub { a, b, .. } => self.binary_expr(BinaryOp::Sub, a, b),
            SSAOp::IntMult { a, b, .. } => self.binary_expr(BinaryOp::Mul, a, b),
            SSAOp::IntDiv { a, b, .. } | SSAOp::IntSDiv { a, b, .. } => {
                self.binary_expr(BinaryOp::Div, a, b)
            }
            SSAOp::IntRem { a, b, .. } | SSAOp::IntSRem { a, b, .. } => {
                self.binary_expr(BinaryOp::Mod, a, b)
            }
            SSAOp::IntAnd { a, b, .. } => self.binary_expr(BinaryOp::BitAnd, a, b),
            SSAOp::IntOr { a, b, .. } => self.binary_expr(BinaryOp::BitOr, a, b),
            SSAOp::IntXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::IntLeft { a, b, .. } => self.binary_expr(BinaryOp::Shl, a, b),
            SSAOp::IntRight { a, b, .. } | SSAOp::IntSRight { a, b, .. } => {
                self.binary_expr(BinaryOp::Shr, a, b)
            }
            SSAOp::IntLess { a, b, .. } | SSAOp::IntSLess { a, b, .. } => {
                self.binary_expr(BinaryOp::Lt, a, b)
            }
            SSAOp::IntLessEqual { a, b, .. } | SSAOp::IntSLessEqual { a, b, .. } => {
                self.binary_expr(BinaryOp::Le, a, b)
            }
            SSAOp::IntEqual { a, b, .. } => self.binary_expr(BinaryOp::Eq, a, b),
            SSAOp::IntNotEqual { a, b, .. } => self.binary_expr(BinaryOp::Ne, a, b),
            SSAOp::IntNegate { src, .. } => CExpr::unary(UnaryOp::Neg, self.get_expr(src)),
            SSAOp::IntNot { src, .. } => CExpr::unary(UnaryOp::BitNot, self.get_expr(src)),
            SSAOp::BoolAnd { a, b, .. } => {
                self.simplify_condition_expr(self.binary_expr(BinaryOp::And, a, b))
            }
            SSAOp::BoolOr { a, b, .. } => {
                self.simplify_condition_expr(self.binary_expr(BinaryOp::Or, a, b))
            }
            SSAOp::BoolXor { a, b, .. } => {
                self.simplify_condition_expr(self.binary_expr(BinaryOp::BitXor, a, b))
            }
            SSAOp::BoolNot { src, .. } => {
                self.simplify_condition_expr(CExpr::unary(UnaryOp::Not, self.get_expr(src)))
            }
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Trunc { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Piece { dst, hi, lo } => {
                let shift_bits = lo.size.saturating_mul(8);
                let dst_ty = uint_type_from_size(dst.size);
                let hi_cast = CExpr::cast(dst_ty.clone(), self.get_expr(hi));
                let lo_cast = CExpr::cast(dst_ty.clone(), self.get_expr(lo));
                let shifted = if shift_bits == 0 {
                    hi_cast
                } else {
                    CExpr::binary(BinaryOp::Shl, hi_cast, CExpr::IntLit(shift_bits as i64))
                };
                CExpr::binary(BinaryOp::BitOr, shifted, lo_cast)
            }
            SSAOp::Subpiece { dst, src, offset } => {
                if *offset == 0 && dst.size == src.size {
                    self.get_expr(src)
                } else if *offset == 0 {
                    CExpr::cast(uint_type_from_size(dst.size), self.get_expr(src))
                } else {
                    let shift_bits = offset.saturating_mul(8);
                    let src_cast = CExpr::cast(uint_type_from_size(src.size), self.get_expr(src));
                    let shifted =
                        CExpr::binary(BinaryOp::Shr, src_cast, CExpr::IntLit(shift_bits as i64));
                    CExpr::cast(uint_type_from_size(dst.size), shifted)
                }
            }
            SSAOp::FloatAdd { a, b, .. } => self.binary_expr(BinaryOp::Add, a, b),
            SSAOp::FloatSub { a, b, .. } => self.binary_expr(BinaryOp::Sub, a, b),
            SSAOp::FloatMult { a, b, .. } => self.binary_expr(BinaryOp::Mul, a, b),
            SSAOp::FloatDiv { a, b, .. } => self.binary_expr(BinaryOp::Div, a, b),
            SSAOp::FloatNeg { src, .. } => CExpr::unary(UnaryOp::Neg, self.get_expr(src)),
            SSAOp::FloatLess { a, b, .. } => self.binary_expr(BinaryOp::Lt, a, b),
            SSAOp::FloatLessEqual { a, b, .. } => self.binary_expr(BinaryOp::Le, a, b),
            SSAOp::FloatEqual { a, b, .. } => self.binary_expr(BinaryOp::Eq, a, b),
            SSAOp::FloatNotEqual { a, b, .. } => self.binary_expr(BinaryOp::Ne, a, b),
            SSAOp::Int2Float { dst, src } => {
                let ty = CType::Float(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Float2Int { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Cast { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Call { target } => {
                let func_expr = self.resolve_call_target(target);
                CExpr::call(func_expr, vec![])
            }
            SSAOp::CallInd { target } => {
                let target_expr = self.get_expr(target);
                CExpr::call(CExpr::Deref(Box::new(target_expr)), vec![])
            }
            SSAOp::CallOther {
                output: _,
                userop,
                inputs,
            } => {
                let mut args = Vec::with_capacity(inputs.len() + 1);
                args.push(CExpr::StringLit(self.lookup_userop_name(*userop)));
                for input in inputs {
                    args.push(self.get_expr(input));
                }
                CExpr::call(CExpr::Var("callother".to_string()), args)
            }
            SSAOp::CpuId { .. } => {
                let args = vec![CExpr::StringLit("cpuid".to_string())];
                CExpr::call(CExpr::Var("callother".to_string()), args)
            }
            SSAOp::PtrAdd {
                base,
                index,
                element_size,
                ..
            } => self.ptr_arith_expr(base, index, *element_size, false),
            SSAOp::PtrSub {
                base,
                index,
                element_size,
                ..
            } => self.ptr_arith_expr(base, index, *element_size, true),
            // For other ops, generate a placeholder indicating unhandled operation.
            // This helps identify operations that need explicit handling.
            _ => {
                if let Some(dst) = op.dst() {
                    CExpr::Var(self.var_name(dst))
                } else {
                    // No destination - return a comment-like placeholder
                    CExpr::Var("__unhandled_op__".to_string())
                }
            }
        }
    }

    /// Create a binary expression.
    fn binary_expr(&self, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> CExpr {
        let width_bytes = if a.size > 0 && a.size == b.size {
            Some(a.size)
        } else {
            None
        };
        self.identity_simplify_binary(op, self.get_expr(a), self.get_expr(b), width_bytes)
    }

    fn is_literal_zero_expr(&self, expr: &CExpr) -> bool {
        matches!(expr, CExpr::IntLit(0) | CExpr::UIntLit(0))
    }

    fn is_one_expr(&self, expr: &CExpr) -> bool {
        matches!(expr, CExpr::IntLit(1) | CExpr::UIntLit(1))
    }

    fn is_all_ones_mask_expr(&self, expr: &CExpr, width_bytes: u32) -> bool {
        if width_bytes == 0 || width_bytes > 8 {
            return false;
        }
        let bits = width_bytes.saturating_mul(8);
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };

        match expr {
            CExpr::UIntLit(v) => *v == mask,
            CExpr::IntLit(v) => *v == -1 || u64::try_from(*v).map(|n| n == mask).unwrap_or(false),
            CExpr::Paren(inner) => self.is_all_ones_mask_expr(inner, width_bytes),
            CExpr::Cast { expr: inner, .. } => self.is_all_ones_mask_expr(inner, width_bytes),
            _ => false,
        }
    }

    fn identity_simplify_binary(
        &self,
        op: BinaryOp,
        left: CExpr,
        right: CExpr,
        width_bytes: Option<u32>,
    ) -> CExpr {
        match op {
            BinaryOp::Sub if self.is_literal_zero_expr(&right) => left,
            BinaryOp::Add => {
                if self.is_literal_zero_expr(&right) {
                    left
                } else if self.is_literal_zero_expr(&left) {
                    right
                } else {
                    CExpr::binary(op, left, right)
                }
            }
            BinaryOp::BitOr | BinaryOp::BitXor => {
                if self.is_literal_zero_expr(&right) {
                    left
                } else if self.is_literal_zero_expr(&left) {
                    right
                } else {
                    CExpr::binary(op, left, right)
                }
            }
            BinaryOp::Mul => {
                if self.is_one_expr(&right) {
                    left
                } else if self.is_one_expr(&left) {
                    right
                } else {
                    CExpr::binary(op, left, right)
                }
            }
            BinaryOp::Div => {
                if self.is_one_expr(&right) {
                    left
                } else {
                    CExpr::binary(op, left, right)
                }
            }
            BinaryOp::BitAnd => {
                if let Some(width) = width_bytes {
                    if self.is_all_ones_mask_expr(&right, width) {
                        return left;
                    }
                    if self.is_all_ones_mask_expr(&left, width) {
                        return right;
                    }
                }
                CExpr::binary(op, left, right)
            }
            _ => CExpr::binary(op, left, right),
        }
    }

    fn identity_simplify_expr(&self, expr: CExpr) -> CExpr {
        match expr {
            CExpr::Binary { op, left, right } => {
                self.identity_simplify_binary(op, *left, *right, None)
            }
            other => other,
        }
    }

    fn assign_stmt(&self, lhs: CExpr, rhs: CExpr) -> Option<CStmt> {
        let lhs = self.rewrite_stack_expr(lhs);
        let rhs = self.rewrite_stack_expr(self.identity_simplify_expr(rhs));
        if lhs == rhs {
            return None;
        }
        Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
    }

    fn ptr_arith_expr(
        &self,
        base: &SSAVar,
        index: &SSAVar,
        element_size: u32,
        is_sub: bool,
    ) -> CExpr {
        let base_expr = self.get_expr(base);
        let index_expr = self.get_expr(index);
        let scaled = if element_size <= 1 {
            index_expr
        } else {
            CExpr::binary(
                BinaryOp::Mul,
                index_expr,
                CExpr::IntLit(element_size as i64),
            )
        };
        let op = if is_sub { BinaryOp::Sub } else { BinaryOp::Add };
        CExpr::binary(op, base_expr, scaled)
    }

    fn ptr_subscript_expr(
        &self,
        base: &SSAVar,
        index: &SSAVar,
        element_size: u32,
        is_sub: bool,
    ) -> CExpr {
        let elem_ty = uint_type_from_size(element_size);
        let base_expr = CExpr::cast(CType::ptr(elem_ty), self.get_expr(base));
        let index_expr = if is_sub {
            CExpr::unary(UnaryOp::Neg, self.get_expr(index))
        } else {
            self.get_expr(index)
        };
        CExpr::Subscript {
            base: Box::new(base_expr),
            index: Box::new(index_expr),
        }
    }

    fn try_subscript_from_expr(&self, addr: &SSAVar, addr_expr: &CExpr) -> Option<CExpr> {
        let expr = self
            .definitions_map()
            .get(&addr.display_name())
            .cloned()
            .unwrap_or_else(|| addr_expr.clone());
        self.try_subscript_from_addr_expr(&expr)
    }

    fn try_subscript_from_addr_expr(&self, expr: &CExpr) -> Option<CExpr> {
        let (base_expr, index_expr, elem_size, is_sub) = self.extract_base_index_scale(expr)?;

        if elem_size == 0 {
            return None;
        }

        let elem_ty = uint_type_from_size(elem_size);
        let base_cast = CExpr::cast(CType::ptr(elem_ty), base_expr);
        let index_final = if is_sub {
            CExpr::unary(UnaryOp::Neg, index_expr)
        } else {
            index_expr
        };

        Some(CExpr::Subscript {
            base: Box::new(base_cast),
            index: Box::new(index_final),
        })
    }

    fn try_member_access_from_expr(&self, addr: &SSAVar, addr_expr: &CExpr) -> Option<CExpr> {
        let expr = self
            .definitions_map()
            .get(&addr.display_name())
            .cloned()
            .unwrap_or_else(|| addr_expr.clone());
        self.try_member_access_from_addr_expr(&expr)
    }

    fn try_member_access_from_addr_expr(&self, expr: &CExpr) -> Option<CExpr> {
        let (base_expr, offset) = self.extract_base_const_offset(expr)?;
        if offset == 0 || self.is_stackish_expr(&base_expr) || !self.looks_like_pointer(&base_expr)
        {
            return None;
        }

        let member = if offset < 0 {
            format!("field_neg_{:x}", (-offset) as u64)
        } else {
            format!("field_{:x}", offset as u64)
        };

        Some(CExpr::PtrMember {
            base: Box::new(base_expr),
            member,
        })
    }

    fn extract_base_const_offset(&self, expr: &CExpr) -> Option<(CExpr, i64)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => {
                if let Some(off) = self.literal_to_i64(right) {
                    return Some((left.as_ref().clone(), off));
                }
                if let Some(off) = self.literal_to_i64(left) {
                    return Some((right.as_ref().clone(), off));
                }
                None
            }
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => self
                .literal_to_i64(right)
                .map(|off| (left.as_ref().clone(), -off)),
            CExpr::Cast { expr: inner, .. } | CExpr::Paren(inner) => {
                self.extract_base_const_offset(inner)
            }
            CExpr::Var(name) => self
                .lookup_definition(name)
                .and_then(|def| self.extract_base_const_offset(&def)),
            _ => None,
        }
    }

    fn looks_like_pointer(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Cast { ty, .. } => matches!(ty, CType::Pointer(_)),
            CExpr::Deref(_) => true,
            CExpr::Var(name) => {
                if name.starts_with("arg") || name.contains("ptr") {
                    return true;
                }
                if let Some(ty) = self.lookup_type_hint(name) {
                    return matches!(ty, CType::Pointer(_) | CType::Struct(_));
                }
                false
            }
            CExpr::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                left,
                right,
            } => self.looks_like_pointer(left) || self.looks_like_pointer(right),
            _ => false,
        }
    }

    fn is_stackish_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                lower.contains(&self.sp_name) || lower.contains(&self.fp_name)
            }
            CExpr::Binary { left, right, .. } => {
                self.is_stackish_expr(left) || self.is_stackish_expr(right)
            }
            CExpr::Cast { expr, .. } | CExpr::Paren(expr) | CExpr::Unary { operand: expr, .. } => {
                self.is_stackish_expr(expr)
            }
            // Dereferencing a stack slot often yields a pointer value stored on
            // the stack (e.g., local pointer variable), so don't reject it.
            CExpr::Deref(_) => false,
            _ => false,
        }
    }

    fn lookup_type_hint(&self, name: &str) -> Option<&CType> {
        if let Some(ty) = self.type_hints_map().get(name) {
            return Some(ty);
        }
        let lower = name.to_lowercase();
        self.type_hints_map().get(&lower)
    }

    fn type_hint_for_var(&self, var: &SSAVar) -> Option<CType> {
        let display = var.display_name();
        if let Some(ty) = self.lookup_type_hint(&display) {
            return Some(ty.clone());
        }

        let rendered = self.var_name(var);
        self.lookup_type_hint(&rendered).cloned()
    }

    fn extract_base_index_scale(&self, expr: &CExpr) -> Option<(CExpr, CExpr, u32, bool)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => self
                .extract_base_index_from_add(left, right)
                .map(|(b, i, s)| (b, i, s, false)),
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => self
                .extract_base_index_from_add(left, right)
                .map(|(b, i, s)| (b, i, s, true)),
            CExpr::Var(name) => {
                if let Some(def) = self.definitions_map().get(name) {
                    self.extract_base_index_scale(def)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn extract_base_index_from_add(
        &self,
        left: &CExpr,
        right: &CExpr,
    ) -> Option<(CExpr, CExpr, u32)> {
        if let Some((index, scale)) = self.extract_mul_const(right, 0) {
            return self
                .scale_to_elem_size(scale)
                .map(|s| (left.clone(), index, s));
        }
        if let Some((index, scale)) = self.extract_mul_const(left, 0) {
            return self
                .scale_to_elem_size(scale)
                .map(|s| (right.clone(), index, s));
        }
        // Fallback: base + index (scale = 1)
        let right_resolved = self.resolve_once(right).unwrap_or_else(|| right.clone());
        if matches!(
            right_resolved,
            CExpr::Var(_) | CExpr::Cast { .. } | CExpr::Binary { .. }
        ) {
            return Some((left.clone(), right_resolved, 1));
        }
        None
    }

    fn resolve_once(&self, expr: &CExpr) -> Option<CExpr> {
        if let CExpr::Var(name) = expr {
            self.lookup_definition(name)
        } else {
            None
        }
    }

    fn extract_mul_const(&self, expr: &CExpr, depth: u32) -> Option<(CExpr, i64)> {
        if depth > 2 {
            return None;
        }

        match expr {
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } => {
                if let Some(c) = self.literal_to_i64(right) {
                    return Some((left.as_ref().clone(), c));
                }
                if let Some(c) = self.literal_to_i64(left) {
                    return Some((right.as_ref().clone(), c));
                }
                None
            }
            CExpr::Cast { expr: inner, .. } => self.extract_mul_const(inner, depth + 1),
            CExpr::Var(name) => {
                if let Some(def) = self.lookup_definition(name) {
                    return self.extract_mul_const(&def, depth + 1);
                }
                None
            }
            _ => None,
        }
    }

    fn literal_to_i64(&self, expr: &CExpr) -> Option<i64> {
        match expr {
            CExpr::IntLit(v) => Some(*v),
            CExpr::UIntLit(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    fn expr_mentions_stack_or_ip(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                lower.contains("rsp")
                    || lower.contains("esp")
                    || lower.contains("sp_")
                    || lower.contains("rip")
                    || lower.contains("eip")
            }
            CExpr::Unary { operand, .. } => self.expr_mentions_stack_or_ip(operand),
            CExpr::Binary { left, right, .. } => {
                self.expr_mentions_stack_or_ip(left) || self.expr_mentions_stack_or_ip(right)
            }
            CExpr::Paren(inner) => self.expr_mentions_stack_or_ip(inner),
            CExpr::Cast { expr: inner, .. } => self.expr_mentions_stack_or_ip(inner),
            CExpr::Deref(inner) => self.expr_mentions_stack_or_ip(inner),
            _ => false,
        }
    }

    fn is_low_level_return_artifact(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Deref(inner) => self.expr_mentions_stack_or_ip(inner),
            CExpr::Var(_) => self.expr_mentions_stack_or_ip(expr),
            CExpr::Paren(inner) => self.is_low_level_return_artifact(inner),
            CExpr::Cast { expr: inner, .. } => self.is_low_level_return_artifact(inner),
            _ => false,
        }
    }

    fn lookup_definition(&self, name: &str) -> Option<CExpr> {
        if let Some(expr) = self.definitions_map().get(name) {
            return Some(expr.clone());
        }
        let lower = name.to_lowercase();
        if let Some(expr) = self.definitions_map().get(&lower) {
            return Some(expr.clone());
        }
        if let Some((base, version)) = name.rsplit_once('_') {
            let lower = format!("{}_{}", base.to_lowercase(), version);
            if let Some(expr) = self.definitions_map().get(&lower) {
                return Some(expr.clone());
            }
            let upper = format!("{}_{}", base.to_uppercase(), version);
            if let Some(expr) = self.definitions_map().get(&upper) {
                return Some(expr.clone());
            }
        }
        None
    }

    fn scale_to_elem_size(&self, scale: i64) -> Option<u32> {
        let abs = scale.checked_abs()? as u64;
        if abs == 0 {
            return None;
        }
        u32::try_from(abs).ok()
    }

    /// Convert a block to folded C statements.
    pub fn fold_block(&self, block: &SSABlock) -> Vec<CStmt> {
        let mut stmts = Vec::new();
        let mut last_ret_value: Option<CExpr> = None;

        for (op_idx, op) in block.ops.iter().enumerate() {
            // Skip stack frame setup/teardown if enabled
            if self.is_stack_frame_op(op) {
                continue;
            }

            if self.is_current_return_block() {
                match op {
                    SSAOp::Copy { dst, src }
                        if self.is_return_register_name(&dst.name.to_lowercase()) =>
                    {
                        last_ret_value = Some(self.get_return_expr(src));
                    }
                    SSAOp::IntZExt { dst, src }
                    | SSAOp::IntSExt { dst, src }
                    | SSAOp::Trunc { dst, src }
                    | SSAOp::Cast { dst, src }
                        if self.is_return_register_name(&dst.name.to_lowercase()) =>
                    {
                        let ty = type_from_size(dst.size);
                        last_ret_value = Some(CExpr::cast(ty, self.get_return_expr(src)));
                    }
                    _ => {
                        if let Some(dst) = op.dst() {
                            if self.is_return_register_name(&dst.name.to_lowercase()) {
                                let mut visited = HashSet::new();
                                let raw = self.op_to_expr(op);
                                let expanded = self.expand_return_expr(&raw, 0, &mut visited);
                                let final_expr = if self.is_predicate_like_expr(&expanded) {
                                    self.simplify_condition_expr(expanded)
                                } else {
                                    expanded
                                };
                                last_ret_value = Some(final_expr);
                            }
                        }
                    }
                }
            }

            if let SSAOp::Return { target } = op {
                if self.is_current_return_block() {
                    let target_expr = self.get_expr(target);
                    let expr = match last_ret_value.clone() {
                        Some(last) if self.is_predicate_like_expr(&last) => last,
                        Some(last) if self.is_low_level_return_artifact(&target_expr) => last,
                        _ => target_expr,
                    };
                    stmts.push(CStmt::Return(Some(self.rewrite_stack_expr(expr))));
                    break;
                }
                if let Some(stmt) = self.op_to_stmt_with_args(op, block.addr, op_idx) {
                    stmts.push(stmt);
                }
                break;
            }

            // In return-context blocks, keep return-register writes as tracking-only.
            // Emit a single high-level return at the SSA Return terminator.
            if self.is_current_return_block() {
                if let Some(dst) = op.dst() {
                    if self.is_return_register_name(&dst.name.to_lowercase()) {
                        continue;
                    }
                }
            }

            // Skip operations that produce dead values
            if let Some(dst) = op.dst() {
                if self.is_dead(dst) {
                    continue;
                }

                // Skip if this will be inlined
                let key = dst.display_name();
                if self.should_inline(&key) {
                    continue;
                }

                // Skip if this op's destination was consumed by call argument collection
                if self.consumed_by_call_set().contains(&key) {
                    continue;
                }
            }

            if let Some(stmt) = self.op_to_stmt_with_args(op, block.addr, op_idx) {
                let is_return = matches!(stmt, CStmt::Return(_));
                stmts.push(stmt);
                if is_return {
                    break;
                }
            }
        }

        self.prune_dead_temp_assignments(stmts)
    }

    fn assignment_target_and_rhs(stmt: &CStmt) -> Option<(&str, &CExpr)> {
        let CStmt::Expr(CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        }) = stmt
        else {
            return None;
        };

        let CExpr::Var(name) = left.as_ref() else {
            return None;
        };

        Some((name.as_str(), right.as_ref()))
    }

    fn expr_is_pure(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::Var(_) => true,
            CExpr::Unary { operand, .. }
            | CExpr::Paren(operand)
            | CExpr::Deref(operand)
            | CExpr::AddrOf(operand)
            | CExpr::Sizeof(operand) => self.expr_is_pure(operand),
            CExpr::Binary { op, left, right } => {
                !matches!(
                    op,
                    BinaryOp::Assign
                        | BinaryOp::AddAssign
                        | BinaryOp::SubAssign
                        | BinaryOp::MulAssign
                        | BinaryOp::DivAssign
                        | BinaryOp::ModAssign
                        | BinaryOp::BitAndAssign
                        | BinaryOp::BitOrAssign
                        | BinaryOp::BitXorAssign
                        | BinaryOp::ShlAssign
                        | BinaryOp::ShrAssign
                ) && self.expr_is_pure(left)
                    && self.expr_is_pure(right)
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.expr_is_pure(cond)
                    && self.expr_is_pure(then_expr)
                    && self.expr_is_pure(else_expr)
            }
            CExpr::Cast { expr, .. } => self.expr_is_pure(expr),
            CExpr::Call { .. } => false,
            CExpr::Subscript { base, index } => self.expr_is_pure(base) && self.expr_is_pure(index),
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => self.expr_is_pure(base),
            CExpr::SizeofType(_) => true,
            CExpr::Comma(items) => items.iter().all(|item| self.expr_is_pure(item)),
        }
    }

    fn collect_expr_reads(&self, expr: &CExpr, out: &mut HashSet<String>) {
        match expr {
            CExpr::Var(name) => {
                out.insert(name.clone());
            }
            CExpr::Unary { operand, .. }
            | CExpr::Paren(operand)
            | CExpr::Deref(operand)
            | CExpr::AddrOf(operand)
            | CExpr::Sizeof(operand) => self.collect_expr_reads(operand, out),
            CExpr::Binary { left, right, .. } => {
                self.collect_expr_reads(left, out);
                self.collect_expr_reads(right, out);
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_expr_reads(cond, out);
                self.collect_expr_reads(then_expr, out);
                self.collect_expr_reads(else_expr, out);
            }
            CExpr::Cast { expr, .. } => self.collect_expr_reads(expr, out),
            CExpr::Call { func, args } => {
                self.collect_expr_reads(func, out);
                for arg in args {
                    self.collect_expr_reads(arg, out);
                }
            }
            CExpr::Subscript { base, index } => {
                self.collect_expr_reads(base, out);
                self.collect_expr_reads(index, out);
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                self.collect_expr_reads(base, out);
            }
            CExpr::Comma(items) => {
                for item in items {
                    self.collect_expr_reads(item, out);
                }
            }
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::SizeofType(_) => {}
        }
    }

    fn stmt_reads_and_def(&self, stmt: &CStmt) -> (HashSet<String>, Option<String>) {
        let mut reads = HashSet::new();
        let mut def = None;

        match stmt {
            CStmt::Expr(CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                right,
            }) => {
                if let CExpr::Var(name) = left.as_ref() {
                    def = Some(name.clone());
                } else {
                    self.collect_expr_reads(left, &mut reads);
                }
                self.collect_expr_reads(right, &mut reads);
            }
            CStmt::Expr(expr) => self.collect_expr_reads(expr, &mut reads),
            CStmt::Decl { init, .. } => {
                if let Some(expr) = init {
                    self.collect_expr_reads(expr, &mut reads);
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.collect_expr_reads(cond, &mut reads);
                let (then_reads, _) = self.stmt_reads_and_def(then_body);
                reads.extend(then_reads);
                if let Some(else_stmt) = else_body {
                    let (else_reads, _) = self.stmt_reads_and_def(else_stmt);
                    reads.extend(else_reads);
                }
            }
            CStmt::While { cond, body } | CStmt::DoWhile { cond, body } => {
                self.collect_expr_reads(cond, &mut reads);
                let (body_reads, _) = self.stmt_reads_and_def(body);
                reads.extend(body_reads);
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init_stmt) = init {
                    let (init_reads, _) = self.stmt_reads_and_def(init_stmt);
                    reads.extend(init_reads);
                }
                if let Some(cond_expr) = cond {
                    self.collect_expr_reads(cond_expr, &mut reads);
                }
                if let Some(update_expr) = update {
                    self.collect_expr_reads(update_expr, &mut reads);
                }
                let (body_reads, _) = self.stmt_reads_and_def(body);
                reads.extend(body_reads);
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                self.collect_expr_reads(expr, &mut reads);
                for case in cases {
                    for stmt in &case.body {
                        let (case_reads, _) = self.stmt_reads_and_def(stmt);
                        reads.extend(case_reads);
                    }
                }
                if let Some(default_stmts) = default {
                    for stmt in default_stmts {
                        let (default_reads, _) = self.stmt_reads_and_def(stmt);
                        reads.extend(default_reads);
                    }
                }
            }
            CStmt::Return(Some(expr)) => self.collect_expr_reads(expr, &mut reads),
            CStmt::Block(stmts) => {
                for stmt in stmts {
                    let (stmt_reads, _) = self.stmt_reads_and_def(stmt);
                    reads.extend(stmt_reads);
                }
            }
            CStmt::Label(_)
            | CStmt::Goto(_)
            | CStmt::Break
            | CStmt::Continue
            | CStmt::Return(None)
            | CStmt::Comment(_)
            | CStmt::Empty => {}
        }

        (reads, def)
    }

    fn prune_dead_temp_assignments(&self, stmts: Vec<CStmt>) -> Vec<CStmt> {
        let mut live = HashSet::new();
        let mut kept_rev = Vec::with_capacity(stmts.len());

        for stmt in stmts.into_iter().rev() {
            let (reads, def) = self.stmt_reads_and_def(&stmt);

            let drop_stmt = if let Some((target, rhs)) = Self::assignment_target_and_rhs(&stmt) {
                self.is_opaque_temp_name(target) && !live.contains(target) && self.expr_is_pure(rhs)
            } else {
                false
            };

            if drop_stmt {
                continue;
            }

            if let Some(def_name) = def {
                live.remove(&def_name);
            }
            live.extend(reads);
            kept_rev.push(stmt);
        }

        kept_rev.reverse();
        kept_rev
    }

    /// Convert an SSA operation to a C statement, with call argument context.
    fn op_to_stmt_with_args(&self, op: &SSAOp, block_addr: u64, op_idx: usize) -> Option<CStmt> {
        match op {
            SSAOp::Call { target } => {
                let func_expr = self.resolve_call_target(target);
                let args = self
                    .call_args_map()
                    .get(&(block_addr, op_idx))
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|arg| self.rewrite_stack_expr(arg))
                    .collect();
                let call = CExpr::call(func_expr, args);
                Some(CStmt::Expr(call))
            }
            SSAOp::CallInd { target } => {
                let target_expr = self.get_expr(target);
                let func_expr = CExpr::Deref(Box::new(target_expr));
                let args = self
                    .call_args_map()
                    .get(&(block_addr, op_idx))
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|arg| self.rewrite_stack_expr(arg))
                    .collect();
                let call = CExpr::call(func_expr, args);
                Some(CStmt::Expr(call))
            }
            _ => self.op_to_stmt(op),
        }
    }

    /// Resolve a call target to a function name expression.
    fn resolve_call_target(&self, target: &SSAVar) -> CExpr {
        if let Some(addr) = extract_call_address(&target.name) {
            if let Some(name) = self.lookup_function(addr) {
                return CExpr::Var(name.clone());
            }
            if let Some(name) = self.lookup_symbol(addr) {
                return CExpr::Var(name.clone());
            }
        } else if target.is_const() {
            if let Some(addr) = parse_const_value(&target.name) {
                if let Some(name) = self.lookup_function(addr) {
                    return CExpr::Var(name.clone());
                }
                if let Some(name) = self.lookup_symbol(addr) {
                    return CExpr::Var(name.clone());
                }
            }
        }
        self.get_expr(target)
    }

    /// Convert an SSA operation to a C statement.
    fn op_to_stmt(&self, op: &SSAOp) -> Option<CStmt> {
        match op {
            SSAOp::Copy { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs_base = self.get_expr(src);
                let mut rhs = self.resolve_predicate_rhs_for_var(src, rhs_base);
                if let Some(dst_ty) = self.type_hint_for_var(dst) {
                    if matches!(dst_ty, CType::Pointer(_)) && !self.looks_like_pointer(&rhs) {
                        rhs = CExpr::cast(dst_ty, rhs);
                    }
                }
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Load { dst, addr, .. } => {
                let lhs = CExpr::Var(self.var_name(dst));
                // Try to resolve ram: address to a global symbol name directly
                let rhs = if addr.name.starts_with("ram:") {
                    if let Some(address) = extract_call_address(&addr.name) {
                        if let Some(sym) = self.lookup_symbol(address) {
                            CExpr::Var(sym.clone())
                        } else if let Some(name) = self.lookup_function(address) {
                            CExpr::Var(name.clone())
                        } else if let Some(s) = self.lookup_string(address) {
                            CExpr::StringLit(s.clone())
                        } else {
                            let addr_expr = self.get_expr(addr);
                            CExpr::Deref(Box::new(addr_expr))
                        }
                    } else {
                        let addr_expr = self.get_expr(addr);
                        CExpr::Deref(Box::new(addr_expr))
                    }
                } else {
                    if let Some(stack_var) = self.stack_var_for_addr_var(addr) {
                        CExpr::Var(stack_var)
                    } else {
                        // Try to use stack variable name if this is a stack access
                        let addr_expr = self.get_expr(addr);
                        let addr_key = addr.display_name();
                        if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                            CExpr::Var(stack_var)
                        } else if let Some(ptr) = self.ptr_arith_map().get(&addr_key) {
                            self.ptr_subscript_expr(
                                &ptr.base,
                                &ptr.index,
                                ptr.element_size,
                                ptr.is_sub,
                            )
                        } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                            sub
                        } else if let Some(member) =
                            self.try_member_access_from_expr(addr, &addr_expr)
                        {
                            member
                        } else {
                            CExpr::Deref(Box::new(addr_expr))
                        }
                    }
                };
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Store { addr, val, .. } => {
                // Try to resolve ram: address to a global symbol name directly
                let lhs = if addr.name.starts_with("ram:") {
                    if let Some(address) = extract_call_address(&addr.name) {
                        if let Some(sym) = self.lookup_symbol(address) {
                            CExpr::Var(sym.clone())
                        } else {
                            let addr_expr = self.get_expr(addr);
                            CExpr::Deref(Box::new(addr_expr))
                        }
                    } else {
                        let addr_expr = self.get_expr(addr);
                        CExpr::Deref(Box::new(addr_expr))
                    }
                } else {
                    if let Some(stack_var) = self.stack_var_for_addr_var(addr) {
                        CExpr::Var(stack_var)
                    } else {
                        // Try to use stack variable name if this is a stack access
                        let addr_expr = self.get_expr(addr);
                        let addr_key = addr.display_name();
                        if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                            CExpr::Var(stack_var)
                        } else if let Some(ptr) = self.ptr_arith_map().get(&addr_key) {
                            self.ptr_subscript_expr(
                                &ptr.base,
                                &ptr.index,
                                ptr.element_size,
                                ptr.is_sub,
                            )
                        } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                            sub
                        } else if let Some(member) =
                            self.try_member_access_from_expr(addr, &addr_expr)
                        {
                            member
                        } else {
                            CExpr::Deref(Box::new(addr_expr))
                        }
                    }
                };
                let mut rhs = self.get_expr(val);
                if let Some(val_ty) = self.type_hint_for_var(val) {
                    if matches!(val_ty, CType::Pointer(_)) && !self.looks_like_pointer(&rhs) {
                        rhs = CExpr::cast(val_ty, rhs);
                    }
                }
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::IntAdd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Add),
            SSAOp::IntSub { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Sub),
            SSAOp::IntMult { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Mul),
            SSAOp::IntDiv { dst, a, b } | SSAOp::IntSDiv { dst, a, b } => {
                self.binary_stmt(dst, a, b, BinaryOp::Div)
            }
            SSAOp::IntRem { dst, a, b } | SSAOp::IntSRem { dst, a, b } => {
                self.binary_stmt(dst, a, b, BinaryOp::Mod)
            }
            SSAOp::IntAnd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitAnd),
            SSAOp::IntOr { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitOr),
            SSAOp::IntXor { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitXor),
            SSAOp::IntLeft { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Shl),
            SSAOp::IntRight { dst, a, b } | SSAOp::IntSRight { dst, a, b } => {
                self.binary_stmt(dst, a, b, BinaryOp::Shr)
            }
            SSAOp::IntLess { dst, a, b } | SSAOp::IntSLess { dst, a, b } => {
                self.binary_stmt(dst, a, b, BinaryOp::Lt)
            }
            SSAOp::IntLessEqual { dst, a, b } | SSAOp::IntSLessEqual { dst, a, b } => {
                self.binary_stmt(dst, a, b, BinaryOp::Le)
            }
            SSAOp::IntEqual { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Eq),
            SSAOp::IntNotEqual { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Ne),
            SSAOp::IntNegate { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::unary(UnaryOp::Neg, self.get_expr(src));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::IntNot { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::unary(UnaryOp::BitNot, self.get_expr(src));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::BoolAnd { dst, a, b } => self.boolean_stmt(dst, BinaryOp::And, a, b),
            SSAOp::BoolOr { dst, a, b } => self.boolean_stmt(dst, BinaryOp::Or, a, b),
            SSAOp::BoolXor { dst, a, b } => self.boolean_stmt(dst, BinaryOp::BitXor, a, b),
            SSAOp::BoolNot { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs =
                    self.simplify_condition_expr(CExpr::unary(UnaryOp::Not, self.get_expr(src)));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs =
                    self.normalize_assignment_predicate_rhs(CExpr::cast(ty, self.get_expr(src)));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Trunc { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs =
                    self.normalize_assignment_predicate_rhs(CExpr::cast(ty, self.get_expr(src)));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Piece { dst, hi, lo } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let shift_bits = lo.size.saturating_mul(8);
                let dst_ty = uint_type_from_size(dst.size);
                let hi_cast = CExpr::cast(dst_ty.clone(), self.get_expr(hi));
                let lo_cast = CExpr::cast(dst_ty.clone(), self.get_expr(lo));
                let shifted = if shift_bits == 0 {
                    hi_cast
                } else {
                    CExpr::binary(BinaryOp::Shl, hi_cast, CExpr::IntLit(shift_bits as i64))
                };
                let rhs = CExpr::binary(BinaryOp::BitOr, shifted, lo_cast);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Subpiece { dst, src, offset } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = if *offset == 0 && dst.size == src.size {
                    self.get_expr(src)
                } else if *offset == 0 {
                    CExpr::cast(uint_type_from_size(dst.size), self.get_expr(src))
                } else {
                    let shift_bits = offset.saturating_mul(8);
                    let src_cast = CExpr::cast(uint_type_from_size(src.size), self.get_expr(src));
                    let shifted =
                        CExpr::binary(BinaryOp::Shr, src_cast, CExpr::IntLit(shift_bits as i64));
                    CExpr::cast(uint_type_from_size(dst.size), shifted)
                };
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Call { target } => {
                // Note: Call arguments are handled by op_to_stmt_with_args().
                // This fallback emits the call without args when called directly.
                let func_expr = self.resolve_call_target(target);
                let call = CExpr::call(func_expr, vec![]);
                Some(CStmt::Expr(call))
            }
            SSAOp::CallInd { target } => {
                // Note: Call arguments are handled by op_to_stmt_with_args().
                let target_expr = self.get_expr(target);
                let func_expr = CExpr::Deref(Box::new(target_expr));
                let call = CExpr::call(func_expr, vec![]);
                Some(CStmt::Expr(call))
            }
            SSAOp::CallOther {
                output,
                userop,
                inputs,
            } => {
                let mut args = Vec::with_capacity(inputs.len() + 1);
                args.push(CExpr::StringLit(self.lookup_userop_name(*userop)));
                for input in inputs {
                    args.push(self.get_expr(input));
                }
                let call = CExpr::call(CExpr::Var("callother".to_string()), args);
                if let Some(dst) = output {
                    let lhs = CExpr::Var(self.var_name(dst));
                    Some(CStmt::Expr(CExpr::assign(lhs, call)))
                } else {
                    Some(CStmt::Expr(call))
                }
            }
            SSAOp::CpuId { dst } => {
                let call = CExpr::call(
                    CExpr::Var("callother".to_string()),
                    vec![CExpr::StringLit("cpuid".to_string())],
                );
                let lhs = CExpr::Var(self.var_name(dst));
                Some(CStmt::Expr(CExpr::assign(lhs, call)))
            }
            SSAOp::PtrAdd {
                dst,
                base,
                index,
                element_size,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = self.ptr_arith_expr(base, index, *element_size, false);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::PtrSub {
                dst,
                base,
                index,
                element_size,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = self.ptr_arith_expr(base, index, *element_size, true);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Cast { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = self.normalize_assignment_predicate_rhs(CExpr::cast(
                    type_from_size(dst.size),
                    self.get_expr(src),
                ));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Return { target } => {
                Some(CStmt::Return(Some(self.rewrite_stack_expr(self.get_expr(target)))))
            }
            SSAOp::Branch { .. } | SSAOp::CBranch { .. } => {
                // Handled by control flow structuring
                None
            }
            SSAOp::Phi { .. } => {
                // Phi nodes handled separately
                None
            }
            SSAOp::Nop => None,
            SSAOp::Unimplemented => Some(CStmt::comment("Unimplemented operation")),
            _ => None,
        }
    }

    /// Create a binary operation statement.
    fn binary_stmt(&self, dst: &SSAVar, a: &SSAVar, b: &SSAVar, op: BinaryOp) -> Option<CStmt> {
        let lhs = CExpr::Var(self.var_name(dst));
        let rhs_raw = self.identity_simplify_binary(
            op,
            self.get_expr(a),
            self.get_expr(b),
            (dst.size > 0).then_some(dst.size),
        );
        let rhs = if matches!(
            op,
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
        ) {
            self.normalize_assignment_predicate_rhs(rhs_raw)
        } else {
            rhs_raw
        };
        self.assign_stmt(lhs, rhs)
    }

    fn boolean_stmt(&self, dst: &SSAVar, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> Option<CStmt> {
        let lhs = CExpr::Var(self.var_name(dst));
        let rhs = self.normalize_assignment_predicate_rhs(CExpr::binary(
            op,
            self.get_expr(a),
            self.get_expr(b),
        ));
        self.assign_stmt(lhs, rhs)
    }

    fn normalize_assignment_predicate_rhs(&self, rhs: CExpr) -> CExpr {
        if self.is_assignment_predicate_expr(&rhs) {
            self.simplify_condition_expr(rhs)
        } else {
            rhs
        }
    }

    fn predicate_candidate_for_var(&self, var: &SSAVar) -> Option<CExpr> {
        let key = var.display_name();
        self.lookup_definition(&key)
            .or_else(|| self.formatted_defs_map().get(&key).cloned())
            .or_else(|| {
                let rendered = self.var_name(var);
                self.formatted_defs_map().get(&rendered).cloned()
            })
    }

    fn resolve_predicate_rhs_for_var(&self, src: &SSAVar, fallback: CExpr) -> CExpr {
        let fallback_simplified = self.normalize_assignment_predicate_rhs(fallback);
        if self.is_assignment_predicate_expr(&fallback_simplified) {
            return fallback_simplified;
        }

        if let Some(candidate) = self.predicate_candidate_for_var(src)
            && self.is_assignment_predicate_expr(&candidate)
        {
            return self.simplify_condition_expr(candidate);
        }

        fallback_simplified
    }

    fn is_assignment_predicate_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                is_cpu_flag(&name.to_lowercase())
                    || self.flag_only_values_set().contains(name)
                    || self.condition_vars_set().contains(name)
            }
            CExpr::Unary {
                op: UnaryOp::Not, ..
            } => true,
            CExpr::Binary { op, .. } => matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::BitAnd
                    | BinaryOp::BitXor
            ),
            CExpr::Paren(inner) => self.is_assignment_predicate_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.is_assignment_predicate_expr(inner),
            _ => false,
        }
    }

    /// Extract a condition expression from a branch operation.
    pub fn extract_condition(&self, op: &SSAOp) -> Option<CExpr> {
        match op {
            SSAOp::CBranch { cond, .. } => Some(self.get_condition_expr(cond)),
            _ => None,
        }
    }

    /// Get the expression for a condition variable, always inlining its definition.
    /// Unlike get_expr(), this bypasses the should_inline() check because we always
    /// want to see the actual condition expression, not a temp variable name.
    fn get_condition_expr(&self, var: &SSAVar) -> CExpr {
        // Always inline constants
        if var.is_const() {
            return self.const_to_expr(var);
        }

        let key = var.display_name();
        let expr = self
            .definitions_map()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| CExpr::Var(self.var_name(var)));
        self.simplify_condition_expr(expr)
    }

    fn simplify_condition_expr(&self, expr: CExpr) -> CExpr {
        analysis::PredicateSimplifier::new(self).simplify_condition_expr(expr)
    }

    pub(crate) fn simplify_predicate_expr(&self, expr: CExpr) -> CExpr {
        self.simplify_predicate_expr_inner(expr, 0)
    }

    fn simplify_predicate_expr_inner(&self, expr: CExpr, depth: u32) -> CExpr {
        if depth > 6 {
            return expr;
        }

        let normalized = match expr {
            CExpr::Unary { op, operand } => CExpr::Unary {
                op,
                operand: Box::new(self.simplify_predicate_expr_inner(*operand, depth + 1)),
            },
            CExpr::Binary { op, left, right } => CExpr::Binary {
                op,
                left: Box::new(self.simplify_predicate_expr_inner(*left, depth + 1)),
                right: Box::new(self.simplify_predicate_expr_inner(*right, depth + 1)),
            },
            CExpr::Paren(inner) => CExpr::Paren(Box::new(
                self.simplify_predicate_expr_inner(*inner, depth + 1),
            )),
            CExpr::Cast { ty, expr } => CExpr::Cast {
                ty,
                expr: Box::new(self.simplify_predicate_expr_inner(*expr, depth + 1)),
            },
            other => other,
        };

        let rewritten = self.rewrite_predicate_once(normalized.clone());
        if rewritten != normalized {
            return self.simplify_predicate_expr_inner(rewritten, depth + 1);
        }
        rewritten
    }

    fn rewrite_predicate_once(&self, expr: CExpr) -> CExpr {
        match expr {
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                if let Some(gt) = self.rewrite_signed_positive_and(left.as_ref(), right.as_ref()) {
                    gt
                } else {
                    CExpr::binary(BinaryOp::And, *left, *right)
                }
            }
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => match *operand {
                CExpr::Binary {
                    op: BinaryOp::Eq,
                    left,
                    right,
                } => CExpr::binary(BinaryOp::Ne, *left, *right),
                CExpr::Binary {
                    op: BinaryOp::Ne,
                    left,
                    right,
                } => CExpr::binary(BinaryOp::Eq, *left, *right),
                other => CExpr::unary(UnaryOp::Not, other),
            },
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if self.is_zero_expr(right.as_ref()) => *left,
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => self.rewrite_zero_comparison(BinaryOp::Eq, *left, *right),
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => self.rewrite_zero_comparison(BinaryOp::Ne, *left, *right),
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } => {
                if self.is_zero_expr(right.as_ref()) {
                    if let Some(base) = self.strip_sub_zero(left.as_ref()) {
                        return CExpr::binary(BinaryOp::Lt, base, CExpr::IntLit(0));
                    }
                }
                CExpr::binary(BinaryOp::Lt, *left, *right)
            }
            CExpr::Var(name) => {
                if let Some(val) = parse_const_value(&name) {
                    if val > 0x7fffffff {
                        CExpr::UIntLit(val)
                    } else {
                        CExpr::IntLit(val as i64)
                    }
                } else {
                    CExpr::Var(name)
                }
            }
            other => other,
        }
    }

    fn rewrite_signed_positive_and(&self, left: &CExpr, right: &CExpr) -> Option<CExpr> {
        let left_ne = self.extract_cmp_zero_operand(left, BinaryOp::Ne);
        let right_ge = self.extract_cmp_zero_operand(right, BinaryOp::Ge);
        if let (Some(a), Some(b)) = (left_ne.clone(), right_ge.clone())
            && a == b
        {
            return Some(CExpr::binary(BinaryOp::Gt, a, CExpr::IntLit(0)));
        }

        let left_ge = self.extract_cmp_zero_operand(left, BinaryOp::Ge);
        let right_ne = self.extract_cmp_zero_operand(right, BinaryOp::Ne);
        if let (Some(a), Some(b)) = (left_ge, right_ne)
            && a == b
        {
            return Some(CExpr::binary(BinaryOp::Gt, a, CExpr::IntLit(0)));
        }

        None
    }

    fn extract_cmp_zero_operand(&self, expr: &CExpr, op: BinaryOp) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: expr_op,
                left,
                right,
            } if *expr_op == op => {
                if self.is_zero_expr(right.as_ref()) {
                    return Some(left.as_ref().clone());
                }
                if self.is_zero_expr(left.as_ref()) {
                    return Some(right.as_ref().clone());
                }
                None
            }
            CExpr::Paren(inner) => self.extract_cmp_zero_operand(inner, op),
            CExpr::Cast { expr: inner, .. } => self.extract_cmp_zero_operand(inner, op),
            _ => None,
        }
    }

    fn rewrite_zero_comparison(&self, cmp_op: BinaryOp, left: CExpr, right: CExpr) -> CExpr {
        if self.is_zero_expr(&right) {
            if let Some(base) = self.strip_test_self(&left) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
            if let Some(base) = self.strip_sub_zero(&left) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
        }

        if self.is_zero_expr(&left) {
            if let Some(base) = self.strip_test_self(&right) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
            if let Some(base) = self.strip_sub_zero(&right) {
                return CExpr::binary(cmp_op, base, CExpr::IntLit(0));
            }
        }

        CExpr::binary(cmp_op, left, right)
    }

    fn strip_sub_zero(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } if self.is_zero_expr(right.as_ref()) => Some(left.as_ref().clone()),
            CExpr::Paren(inner) => self.strip_sub_zero(inner),
            CExpr::Cast { expr: inner, .. } => self.strip_sub_zero(inner),
            CExpr::Var(name) => self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                .and_then(|inner| self.strip_sub_zero(&inner)),
            _ => None,
        }
    }

    fn strip_test_self(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                left,
                right,
            } if left == right => Some(left.as_ref().clone()),
            CExpr::Paren(inner) => self.strip_test_self(inner),
            CExpr::Cast { expr: inner, .. } => self.strip_test_self(inner),
            CExpr::Var(name) => self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
                .and_then(|inner| self.strip_test_self(&inner)),
            _ => None,
        }
    }

    fn is_zero_expr(&self, expr: &CExpr) -> bool {
        matches!(expr, CExpr::IntLit(0) | CExpr::UIntLit(0))
            || matches!(expr, CExpr::Var(name) if name == "0" || name == "elf_header")
    }

    fn is_predicate_like_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                is_cpu_flag(&name.to_lowercase())
                    || self.flag_only_values_set().contains(name)
                    || self.condition_vars_set().contains(name)
            }
            CExpr::Unary {
                op: UnaryOp::Not, ..
            } => true,
            CExpr::Binary { op, .. } => matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::BitAnd
                    | BinaryOp::BitXor
                    | BinaryOp::Sub
            ),
            CExpr::Paren(inner) => self.is_predicate_like_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.is_predicate_like_expr(inner),
            CExpr::IntLit(_) | CExpr::UIntLit(_) => true,
            _ => false,
        }
    }

    fn should_expand_predicate_var(&self, name: &str) -> bool {
        if is_cpu_flag(&name.to_lowercase())
            || self.condition_vars_set().contains(name)
            || self.flag_only_values_set().contains(name)
        {
            return true;
        }

        self.lookup_definition(name)
            .or_else(|| self.formatted_defs_map().get(name).cloned())
            .map(|expr| self.is_predicate_like_expr(&expr))
            .unwrap_or(false)
    }

    pub(crate) fn expand_predicate_vars(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > 6 {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if let Some(inner) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                {
                    if let CExpr::Var(inner_name) = inner {
                        if inner_name.starts_with("arg") {
                            return CExpr::Var(inner_name);
                        }
                        if let Some(alias) = self.arg_alias_for_rendered_name(&inner_name) {
                            return CExpr::Var(alias);
                        }
                    }
                }
                if !self.should_expand_predicate_var(name) || !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let expanded = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .filter(|inner| self.is_predicate_like_expr(inner))
                    .map(|inner| self.expand_predicate_vars(&inner, depth + 1, visited))
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                expanded
            }
            CExpr::Unary { op, operand } => {
                CExpr::unary(*op, self.expand_predicate_vars(operand, depth + 1, visited))
            }
            CExpr::Binary { op, left, right } => CExpr::binary(
                *op,
                self.expand_predicate_vars(left, depth + 1, visited),
                self.expand_predicate_vars(right, depth + 1, visited),
            ),
            CExpr::Paren(inner) => CExpr::Paren(Box::new(self.expand_predicate_vars(
                inner,
                depth + 1,
                visited,
            ))),
            CExpr::Cast { ty, expr: inner } => CExpr::Cast {
                ty: ty.clone(),
                expr: Box::new(self.expand_predicate_vars(inner, depth + 1, visited)),
            },
            _ => expr.clone(),
        }
    }

    /// Try to reconstruct a high-level comparison from x86 flag patterns.
    /// Handles patterns like:
    /// - BoolNot(ZF) -> a != b
    /// - ZF -> a == b  
    /// - !ZF && (OF == SF) -> a > b (signed, JG)
    /// - OF == SF -> a >= b (signed, JGE)
    /// - OF != SF -> a < b (signed, JL)
    /// - ZF || (OF != SF) -> a <= b (signed, JLE)
    /// - !CF && !ZF -> a > b (unsigned, JA)
    /// - !CF -> a >= b (unsigned, JAE)
    /// - CF -> a < b (unsigned, JB)
    /// - CF || ZF -> a <= b (unsigned, JBE)
    pub(crate) fn try_reconstruct_condition(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            // Pattern: Binary AND - check for signed greater than: !ZF && (OF == SF)
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_gt_from_and(left, right) {
                    return Some(rel);
                }
                if let Some(rel) = self.reconstruct_signed_gt_from_and(right, left) {
                    return Some(rel);
                }

                // Try !ZF && (OF == SF) -> a > b (signed)
                if let (Some(zf_name), true) = (self.extract_not_zf(left), self.is_of_eq_sf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed: (OF == SF) && !ZF
                if let (Some(zf_name), true) = (self.extract_not_zf(right), self.is_of_eq_sf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                // Try !CF && !ZF -> a > b (unsigned, JA)
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_not_cf(left), self.extract_not_zf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_not_cf(right), self.extract_not_zf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                None
            }

            // Pattern: Binary OR - check for unsigned less-equal: CF || ZF
            CExpr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_le_from_or(left, right) {
                    return Some(rel);
                }
                if let Some(rel) = self.reconstruct_signed_le_from_or(right, left) {
                    return Some(rel);
                }

                // Try CF || ZF -> a <= b (unsigned, JBE)
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_cf(left), self.extract_zf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(cf_name), Some(zf_name)) =
                    (self.extract_cf(right), self.extract_zf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                // Try ZF || (OF != SF) -> a <= b (signed, JLE)
                if let (Some(zf_name), true) = (self.extract_zf(left), self.is_of_ne_sf(right)) {
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(zf_name), true) = (self.extract_zf(right), self.is_of_ne_sf(left)) {
                    if let Some((a, b)) = self.lookup_flag_origin(&zf_name) {
                        return Some(CExpr::binary(BinaryOp::Le, CExpr::Var(a), CExpr::Var(b)));
                    }
                }

                None
            }

            // Pattern: Binary Eq - check for OF == SF (signed >=)
            // AND temp == 0 patterns (TEST/CMP reconstruction)
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_ge_from_eq(expr) {
                    return Some(rel);
                }

                // OF == SF -> a >= b (signed, JGE)
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(left), self.extract_sf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(right), self.extract_sf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Ge, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Fallback: temp == 0 where temp is from TEST/CMP
                if let Some(result) = self.try_reconstruct_cmp_zero(left, right, BinaryOp::Eq) {
                    return Some(result);
                }
                // Also try reversed (0 == temp)
                if let Some(result) = self.try_reconstruct_cmp_zero(right, left, BinaryOp::Eq) {
                    return Some(result);
                }
                None
            }

            // Pattern: Binary Ne - check for OF != SF (signed <)
            // AND temp != 0 patterns (TEST/CMP reconstruction)
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => {
                if let Some(rel) = self.reconstruct_signed_lt_from_ne(expr) {
                    return Some(rel);
                }

                // OF != SF -> a < b (signed, JL)
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(left), self.extract_sf(right))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Try reversed
                if let (Some(of_name), Some(sf_name)) =
                    (self.extract_of(right), self.extract_sf(left))
                {
                    if let Some((a, b)) = self.lookup_flag_origin(&of_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                    if let Some((a, b)) = self.lookup_flag_origin(&sf_name) {
                        return Some(CExpr::binary(BinaryOp::Lt, CExpr::Var(a), CExpr::Var(b)));
                    }
                }
                // Fallback: temp != 0 where temp is from TEST/CMP
                if let Some(result) = self.try_reconstruct_cmp_zero(left, right, BinaryOp::Ne) {
                    return Some(result);
                }
                if let Some(result) = self.try_reconstruct_cmp_zero(right, left, BinaryOp::Ne) {
                    return Some(result);
                }
                None
            }

            CExpr::Paren(inner) => self.try_reconstruct_condition(inner),

            CExpr::Cast { ty, expr: inner } => {
                self.try_reconstruct_condition(inner)
                    .map(|reconstructed| CExpr::Cast {
                        ty: ty.clone(),
                        expr: Box::new(reconstructed),
                    })
            }

            // Pattern: !ZF (BoolNot of ZF) means "not equal"
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => {
                if let CExpr::Var(flag_name) = operand.as_ref() {
                    let flag_lower = flag_name.to_lowercase();
                    if flag_lower.contains("zf") {
                        // !ZF means a != b
                        if let Some((left, right)) = self.lookup_flag_origin(flag_name) {
                            return Some(CExpr::binary(
                                BinaryOp::Ne,
                                CExpr::Var(left),
                                CExpr::Var(right),
                            ));
                        }
                    }
                    // !CF means a >= b (unsigned, JAE)
                    if flag_lower.contains("cf") {
                        if let Some((left, right)) = self.lookup_flag_origin(flag_name) {
                            return Some(CExpr::binary(
                                BinaryOp::Ge,
                                CExpr::Var(left),
                                CExpr::Var(right),
                            ));
                        }
                    }
                }

                // Try !(CF || ZF) -> a > b (unsigned, JA) - negation of JBE
                if let CExpr::Binary {
                    op: BinaryOp::Or,
                    left: or_left,
                    right: or_right,
                } = operand.as_ref()
                {
                    if let (Some(cf_name), Some(_zf_name)) =
                        (self.extract_cf(or_left), self.extract_zf(or_right))
                    {
                        if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                            return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                        }
                    }
                    // Try reversed
                    if let (Some(cf_name), Some(_zf_name)) =
                        (self.extract_cf(or_right), self.extract_zf(or_left))
                    {
                        if let Some((a, b)) = self.lookup_flag_origin(&cf_name) {
                            return Some(CExpr::binary(BinaryOp::Gt, CExpr::Var(a), CExpr::Var(b)));
                        }
                    }
                }

                // Try to recurse into the operand and negate the result
                if let Some(inner) = self.try_reconstruct_condition(operand) {
                    // Negate comparison operators directly instead of wrapping in !()
                    return Some(match inner {
                        CExpr::Binary {
                            op: BinaryOp::Eq,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Ne,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Ne,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Eq,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Lt,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Ge,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Ge,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Lt,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Gt,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Le,
                            left,
                            right,
                        },
                        CExpr::Binary {
                            op: BinaryOp::Le,
                            left,
                            right,
                        } => CExpr::Binary {
                            op: BinaryOp::Gt,
                            left,
                            right,
                        },
                        other => CExpr::unary(UnaryOp::Not, other),
                    });
                }
                None
            }

            // Pattern: ZF directly means "equal"
            CExpr::Var(flag_name) => {
                let flag_lower = flag_name.to_lowercase();
                if flag_lower.contains("zf") {
                    if let Some((left, right)) = self.lookup_flag_origin(flag_name) {
                        return Some(CExpr::binary(
                            BinaryOp::Eq,
                            CExpr::Var(left),
                            CExpr::Var(right),
                        ));
                    }
                }
                // CF directly means a < b (unsigned, JB)
                if flag_lower.contains("cf") {
                    if let Some((left, right)) = self.lookup_flag_origin(flag_name) {
                        return Some(CExpr::binary(
                            BinaryOp::Lt,
                            CExpr::Var(left),
                            CExpr::Var(right),
                        ));
                    }
                }
                None
            }

            _ => None,
        }
    }

    /// Try to reconstruct a comparison from `temp == 0` or `temp != 0` patterns.
    ///
    /// For `TEST reg, reg; JZ/JNZ`:
    ///   - `t1 = IntAnd(RBX, RBX)` -> `ZF = (t1 == 0)` -> CBranch(ZF)
    ///   - When we see `Var(t1) == IntLit(0)`, trace t1's definition:
    ///     - If `BitAnd(a, b)` where a == b (TEST): produce `a == 0` / `a != 0`
    ///     - If `Sub(a, b)` (CMP): produce `a == b` / `a != b`
    fn try_reconstruct_cmp_zero(
        &self,
        var_side: &CExpr,
        zero_side: &CExpr,
        cmp_op: BinaryOp,
    ) -> Option<CExpr> {
        // zero_side must be 0
        let is_zero = match zero_side {
            CExpr::IntLit(0) => true,
            CExpr::Var(name) if name == "elf_header" || name == "0" => true,
            _ => false,
        };
        if !is_zero {
            return None;
        }

        // var_side must be a variable reference
        let var_name = match var_side {
            CExpr::Var(name) => name,
            _ => return None,
        };

        // Look up the definition of this variable (try SSA key first, then formatted name)
        let def = self
            .definitions_map()
            .get(var_name)
            .or_else(|| self.formatted_defs_map().get(var_name))?;

        match def {
            // TEST reg, reg pattern: IntAnd(a, b) where a == b
            CExpr::Binary {
                op: BinaryOp::BitAnd,
                left,
                right,
            } => {
                if left == right {
                    // TEST reg, reg -> reg == 0 / reg != 0
                    return Some(CExpr::binary(cmp_op, *left.clone(), CExpr::IntLit(0)));
                }
                // TEST a, b (different operands) -> (a & b) == 0 / != 0
                Some(CExpr::binary(
                    cmp_op,
                    CExpr::binary(BinaryOp::BitAnd, *left.clone(), *right.clone()),
                    CExpr::IntLit(0),
                ))
            }
            // CMP a, b pattern: Sub(a, b) where the sub is a CMP (result only used for flags)
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => {
                // CMP a, b; JE/JNE -> a == b / a != b
                Some(CExpr::binary(cmp_op, *left.clone(), *right.clone()))
            }
            _ => None,
        }
    }

    // ========== Helper functions for flag pattern detection ==========

    fn extract_flag_name(&self, expr: &CExpr, flag: &str) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if name.to_lowercase().contains(flag) {
                return Some(name.clone());
            }

            if let Some(CExpr::Var(inner)) = self
                .lookup_definition(name)
                .or_else(|| self.formatted_defs_map().get(name).cloned())
            {
                if inner.to_lowercase().contains(flag) {
                    return Some(inner);
                }
            }
        }
        None
    }

    /// Extract ZF variable name from an expression (if it's a ZF flag reference).
    fn extract_zf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "zf")
    }

    /// Extract CF variable name from an expression (if it's a CF flag reference).
    fn extract_cf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "cf")
    }

    /// Extract SF variable name from an expression (if it's a SF flag reference).
    fn extract_sf(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "sf")
    }

    /// Extract OF variable name from an expression (if it's an OF flag reference).
    fn extract_of(&self, expr: &CExpr) -> Option<String> {
        self.extract_flag_name(expr, "of")
    }

    /// Extract ZF variable name from a !ZF expression.
    fn extract_not_zf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.extract_zf(operand);
        }
        None
    }

    /// Extract CF variable name from a !CF expression.
    fn extract_not_cf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.extract_cf(operand);
        }
        None
    }

    /// Check if expression is OF == SF.
    fn is_of_eq_sf(&self, expr: &CExpr) -> bool {
        if let CExpr::Binary {
            op: BinaryOp::Eq,
            left,
            right,
        } = expr
        {
            let has_of_sf = self.extract_of(left).is_some() && self.is_sf_like_expr(right);
            let has_sf_of = self.is_sf_like_expr(left) && self.extract_of(right).is_some();
            return has_of_sf || has_sf_of;
        }
        false
    }

    /// Check if expression is OF != SF.
    fn is_of_ne_sf(&self, expr: &CExpr) -> bool {
        if let CExpr::Binary {
            op: BinaryOp::Ne,
            left,
            right,
        } = expr
        {
            let has_of_sf = self.extract_of(left).is_some() && self.is_sf_like_expr(right);
            let has_sf_of = self.is_sf_like_expr(left) && self.extract_of(right).is_some();
            return has_of_sf || has_sf_of;
        }
        // Also check for !(OF == SF)
        if let CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } = expr
        {
            return self.is_of_eq_sf(operand);
        }
        false
    }

    fn reconstruct_signed_gt_from_and(
        &self,
        cmp_expr: &CExpr,
        of_sf_expr: &CExpr,
    ) -> Option<CExpr> {
        let cmp = self.canonical_compare_tuple(cmp_expr)?;
        if cmp.context != CompareContext::Ne {
            return None;
        }

        let (of_name, sf_expr) = self.extract_of_sf_pair(of_sf_expr, false)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        if !self.compare_tuple_operands_match(&cmp, &sf_cmp) {
            return None;
        }
        if !self.compare_tuple_matches_flag_origin(&cmp, &of_name) {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Gt, cmp.lhs, cmp.rhs))
    }

    fn reconstruct_signed_le_from_or(&self, cmp_expr: &CExpr, of_sf_expr: &CExpr) -> Option<CExpr> {
        let cmp = self.canonical_compare_tuple(cmp_expr)?;
        if cmp.context != CompareContext::Eq {
            return None;
        }

        let (of_name, sf_expr) = self.extract_of_sf_pair(of_sf_expr, true)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        if !self.compare_tuple_operands_match(&cmp, &sf_cmp) {
            return None;
        }
        if !self.compare_tuple_matches_flag_origin(&cmp, &of_name) {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Le, cmp.lhs, cmp.rhs))
    }

    fn reconstruct_signed_ge_from_eq(&self, expr: &CExpr) -> Option<CExpr> {
        let (_of_name, sf_expr) = self.extract_of_sf_pair(expr, false)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Ge, sf_cmp.lhs, sf_cmp.rhs))
    }

    fn reconstruct_signed_lt_from_ne(&self, expr: &CExpr) -> Option<CExpr> {
        let (_of_name, sf_expr) = self.extract_of_sf_pair(expr, true)?;
        let sf_cmp = self.canonical_compare_tuple(sf_expr)?;
        if sf_cmp.context != CompareContext::SignedNegative {
            return None;
        }

        Some(CExpr::binary(BinaryOp::Lt, sf_cmp.lhs, sf_cmp.rhs))
    }

    fn extract_of_sf_pair<'a>(
        &self,
        expr: &'a CExpr,
        want_ne: bool,
    ) -> Option<(String, &'a CExpr)> {
        let op_match = if want_ne { BinaryOp::Ne } else { BinaryOp::Eq };
        if let CExpr::Binary { op, left, right } = expr {
            if *op != op_match {
                return None;
            }
            if let Some(of_name) = self.extract_of(left) {
                return Some((of_name, right));
            }
            if let Some(of_name) = self.extract_of(right) {
                return Some((of_name, left));
            }
        }
        None
    }

    fn canonical_compare_tuple(&self, expr: &CExpr) -> Option<CompareTuple> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Eq,
                left,
                right,
            } => Some(self.normalize_compare_tuple(CompareTuple {
                lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                rhs: self.resolve_predicate_operand(right, 0, &mut HashSet::new()),
                context: CompareContext::Eq,
            })),
            CExpr::Binary {
                op: BinaryOp::Ne,
                left,
                right,
            } => Some(self.normalize_compare_tuple(CompareTuple {
                lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                rhs: self.resolve_predicate_operand(right, 0, &mut HashSet::new()),
                context: CompareContext::Ne,
            })),
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } if self.is_zero_expr(right) => {
                if let Some((sub_lhs, sub_rhs)) = self.extract_sub_operands(left) {
                    return Some(self.normalize_compare_tuple(CompareTuple {
                        lhs: self.resolve_predicate_operand(&sub_lhs, 0, &mut HashSet::new()),
                        rhs: self.resolve_predicate_operand(&sub_rhs, 0, &mut HashSet::new()),
                        context: CompareContext::SignedNegative,
                    }));
                }
                Some(self.normalize_compare_tuple(CompareTuple {
                    lhs: self.resolve_predicate_operand(left, 0, &mut HashSet::new()),
                    rhs: CExpr::IntLit(0),
                    context: CompareContext::SignedNegative,
                }))
            }
            CExpr::Paren(inner) => self.canonical_compare_tuple(inner),
            CExpr::Cast { expr: inner, .. } => self.canonical_compare_tuple(inner),
            _ => None,
        }
    }

    fn extract_sub_operands(&self, expr: &CExpr) -> Option<(CExpr, CExpr)> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => Some((left.as_ref().clone(), right.as_ref().clone())),
            CExpr::Paren(inner) => self.extract_sub_operands(inner),
            CExpr::Cast { expr: inner, .. } => self.extract_sub_operands(inner),
            CExpr::Var(name) => {
                if let Some(def) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                {
                    return self.extract_sub_operands(&def);
                }
                None
            }
            _ => None,
        }
    }

    fn normalize_compare_tuple(&self, mut tuple: CompareTuple) -> CompareTuple {
        if matches!(tuple.context, CompareContext::Eq | CompareContext::Ne)
            && self.is_literal_expr(&tuple.lhs)
            && !self.is_literal_expr(&tuple.rhs)
        {
            std::mem::swap(&mut tuple.lhs, &mut tuple.rhs);
        }
        tuple
    }

    fn compare_tuple_operands_match(&self, a: &CompareTuple, b: &CompareTuple) -> bool {
        a.lhs == b.lhs && a.rhs == b.rhs
    }

    fn compare_tuple_matches_flag_origin(&self, tuple: &CompareTuple, of_name: &str) -> bool {
        let Some(origin) = self.compare_tuple_from_flag_origin(of_name) else {
            return true;
        };

        // If either side still contains opaque temporaries, treat origin matching as
        // advisory only. Local tuple consistency (cmp vs SF-surrogate) remains mandatory.
        if self.expr_contains_opaque_temp(&tuple.lhs)
            || self.expr_contains_opaque_temp(&tuple.rhs)
            || self.expr_contains_opaque_temp(&origin.lhs)
            || self.expr_contains_opaque_temp(&origin.rhs)
            || self.expr_contains_unresolved_memory(&tuple.lhs)
            || self.expr_contains_unresolved_memory(&tuple.rhs)
            || self.expr_contains_unresolved_memory(&origin.lhs)
            || self.expr_contains_unresolved_memory(&origin.rhs)
        {
            return true;
        }

        tuple.lhs == origin.lhs && tuple.rhs == origin.rhs
    }

    fn compare_tuple_from_flag_origin(&self, flag_name: &str) -> Option<CompareTuple> {
        let (lhs_name, rhs_name) = self.lookup_flag_origin(flag_name)?;
        let lhs = self.resolve_predicate_operand(
            &self.origin_name_to_expr(&lhs_name),
            0,
            &mut HashSet::new(),
        );
        let rhs = self.resolve_predicate_operand(
            &self.origin_name_to_expr(&rhs_name),
            0,
            &mut HashSet::new(),
        );

        Some(self.normalize_compare_tuple(CompareTuple {
            lhs,
            rhs,
            context: CompareContext::SignedNegative,
        }))
    }

    fn origin_name_to_expr(&self, name: &str) -> CExpr {
        if let Some(parsed) = self.parse_expr_from_name(name) {
            return parsed;
        }
        CExpr::Var(name.to_string())
    }

    fn parse_expr_from_name(&self, name: &str) -> Option<CExpr> {
        if let Some(val) = parse_const_value(name) {
            return Some(if val > 0x7fffffff {
                CExpr::UIntLit(val)
            } else {
                CExpr::IntLit(val as i64)
            });
        }

        if let Some(hex) = name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
            if let Ok(val) = u64::from_str_radix(hex, 16) {
                return Some(if val > 0x7fffffff {
                    CExpr::UIntLit(val)
                } else {
                    CExpr::IntLit(val as i64)
                });
            }
        }

        if let Ok(dec) = name.parse::<i64>() {
            return Some(CExpr::IntLit(dec));
        }

        None
    }

    fn resolve_predicate_operand(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > 6 {
            return expr.clone();
        }

        match expr {
            CExpr::Paren(inner) => self.resolve_predicate_operand(inner, depth + 1, visited),
            CExpr::Cast { expr: inner, .. } => {
                self.resolve_predicate_operand(inner, depth + 1, visited)
            }
            CExpr::Deref(inner) => {
                if let Some(stack_var) = self.simplify_stack_access(inner) {
                    CExpr::Var(stack_var)
                } else {
                    expr.clone()
                }
            }
            CExpr::Var(name) => {
                if let Some(parsed) = self.parse_expr_from_name(name) {
                    return parsed;
                }
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| {
                        if let Some(stack_var) = self.stack_alias_from_deref_expr(&inner) {
                            CExpr::Var(stack_var)
                        } else if matches!(
                            inner,
                            CExpr::Var(_) | CExpr::Paren(_) | CExpr::Cast { .. }
                        ) {
                            self.resolve_predicate_operand(&inner, depth + 1, visited)
                        } else {
                            CExpr::Var(name.clone())
                        }
                    })
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                resolved
            }
            _ => expr.clone(),
        }
    }

    fn is_literal_expr(&self, expr: &CExpr) -> bool {
        matches!(
            expr,
            CExpr::IntLit(_) | CExpr::UIntLit(_) | CExpr::FloatLit(_) | CExpr::CharLit(_)
        )
    }

    fn is_opaque_temp_name(&self, name: &str) -> bool {
        if name.starts_with("var_") {
            return true;
        }
        if let Some(rest) = name.strip_prefix('t') {
            return rest
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);
        }
        false
    }

    fn expr_contains_opaque_temp(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => self.is_opaque_temp_name(name),
            CExpr::Unary { operand, .. } => self.expr_contains_opaque_temp(operand),
            CExpr::Binary { left, right, .. } => {
                self.expr_contains_opaque_temp(left) || self.expr_contains_opaque_temp(right)
            }
            CExpr::Paren(inner) => self.expr_contains_opaque_temp(inner),
            CExpr::Cast { expr: inner, .. } => self.expr_contains_opaque_temp(inner),
            CExpr::Deref(inner) => self.expr_contains_opaque_temp(inner),
            CExpr::AddrOf(inner) => self.expr_contains_opaque_temp(inner),
            CExpr::Subscript { base, index } => {
                self.expr_contains_opaque_temp(base) || self.expr_contains_opaque_temp(index)
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                self.expr_contains_opaque_temp(base)
            }
            CExpr::Call { func, args } => {
                self.expr_contains_opaque_temp(func)
                    || args.iter().any(|arg| self.expr_contains_opaque_temp(arg))
            }
            _ => false,
        }
    }

    fn expr_contains_unresolved_memory(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Deref(_) => true,
            CExpr::Unary { operand, .. } => self.expr_contains_unresolved_memory(operand),
            CExpr::Binary { left, right, .. } => {
                self.expr_contains_unresolved_memory(left)
                    || self.expr_contains_unresolved_memory(right)
            }
            CExpr::Paren(inner) => self.expr_contains_unresolved_memory(inner),
            CExpr::Cast { expr: inner, .. } => self.expr_contains_unresolved_memory(inner),
            CExpr::AddrOf(inner) => self.expr_contains_unresolved_memory(inner),
            CExpr::Subscript { base, index } => {
                self.expr_contains_unresolved_memory(base)
                    || self.expr_contains_unresolved_memory(index)
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                self.expr_contains_unresolved_memory(base)
            }
            CExpr::Call { func, args } => {
                self.expr_contains_unresolved_memory(func)
                    || args
                        .iter()
                        .any(|arg| self.expr_contains_unresolved_memory(arg))
            }
            _ => false,
        }
    }

    fn is_sf_like_expr(&self, expr: &CExpr) -> bool {
        self.extract_sf(expr).is_some() || self.is_sf_surrogate(expr)
    }

    fn is_sf_surrogate(&self, expr: &CExpr) -> bool {
        let mut visited = HashSet::new();
        self.is_sf_surrogate_inner(expr, &mut visited, 0)
    }

    fn is_sf_surrogate_inner(
        &self,
        expr: &CExpr,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        // Guard against deeply nested/cyclic definitions from large CFGs.
        if depth > 128 {
            return false;
        }
        match expr {
            CExpr::Binary {
                op: BinaryOp::Lt,
                left,
                right,
            } if self.is_zero_expr(right) => self.is_sub_like_expr_inner(left, visited, depth + 1),
            CExpr::Paren(inner) => self.is_sf_surrogate_inner(inner, visited, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.is_sf_surrogate_inner(inner, visited, depth + 1)
            }
            CExpr::Var(name) => {
                if !visited.insert(name.clone()) {
                    return false;
                }
                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| self.is_sf_surrogate_inner(&inner, visited, depth + 1))
                    .unwrap_or(false);
                visited.remove(name);
                resolved
            }
            _ => false,
        }
    }

    fn is_sub_like_expr_inner(
        &self,
        expr: &CExpr,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if depth > 128 {
            return false;
        }
        match expr {
            CExpr::Binary {
                op: BinaryOp::Sub, ..
            } => true,
            CExpr::Paren(inner) => self.is_sub_like_expr_inner(inner, visited, depth + 1),
            CExpr::Cast { expr: inner, .. } => {
                self.is_sub_like_expr_inner(inner, visited, depth + 1)
            }
            CExpr::Var(name) => {
                if !visited.insert(name.clone()) {
                    return false;
                }
                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    .map(|inner| self.is_sub_like_expr_inner(&inner, visited, depth + 1))
                    .unwrap_or(false);
                visited.remove(name);
                resolved
            }
            _ => false,
        }
    }

    /// Extract switch expression from an operation (for switch statement detection).
    pub fn extract_switch_expr(&self, op: &SSAOp) -> Option<CExpr> {
        // Look for indirect branch (BranchInd) which typically holds the switch variable
        if let SSAOp::BranchInd { target } = op {
            return Some(self.get_expr(target));
        }
        None
    }

    /// Look up the original comparison operands for a flag variable.
    fn lookup_flag_origin(&self, flag_name: &str) -> Option<(String, String)> {
        let flag_lower = flag_name.to_lowercase();

        // Try exact match first (case-insensitive)
        for (key, origin) in self.flag_origins_map() {
            if key.to_lowercase() == flag_lower {
                return Some(origin.clone());
            }
        }

        // Try matching by base name (without version suffix)
        // e.g., "zf_1" should match "ZF_1", "zf" should match "zf_1"
        for (key, origin) in self.flag_origins_map() {
            let key_lower = key.to_lowercase();
            // Check if they share the same base (e.g., "zf" part)
            let flag_base = flag_lower.split('_').next().unwrap_or(&flag_lower);
            let key_base = key_lower.split('_').next().unwrap_or(&key_lower);
            if flag_base == key_base {
                return Some(origin.clone());
            }
        }

        None
    }
}

/// Check if a name is a CPU flag that should be eliminated when unused.
pub(crate) fn is_cpu_flag(name: &str) -> bool {
    // Match exact flag names
    if matches!(
        name,
        "cf" | "pf"
            | "af"
            | "zf"
            | "sf"
            | "of"
            | "df"
            | "tf"
            | "if"
            | "iopl"
            | "nt"
            | "rf"
            | "vm"
            | "ac"
            | "vif"
            | "vip"
            | "id"
    ) {
        return true;
    }

    // Also match versioned flags (e.g., cf_1, zf_2)
    name.starts_with("cf_")
        || name.starts_with("pf_")
        || name.starts_with("af_")
        || name.starts_with("zf_")
        || name.starts_with("sf_")
        || name.starts_with("of_")
}

/// Parse a constant value from a name like "const:0x42" or "const:42".
pub(crate) fn parse_const_value(name: &str) -> Option<u64> {
    let val_str = name.strip_prefix("const:")?;
    // Remove any SSA version suffix (e.g., "const:42_0" -> "42")
    let val_str = val_str.split('_').next().unwrap_or(val_str);

    if let Some(hex) = val_str
        .strip_prefix("0x")
        .or_else(|| val_str.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if val_str.chars().all(|c| c.is_ascii_hexdigit()) {
        // All hex digits - could be hex without 0x prefix
        // Try hex first if it contains a-f, otherwise try decimal
        if val_str.chars().any(|c| c.is_ascii_alphabetic()) {
            // Contains letters, must be hex
            u64::from_str_radix(val_str, 16).ok()
        } else {
            // All digits - could be decimal or hex
            // If it's a long number (> 4 digits), treat as hex
            if val_str.len() > 4 {
                u64::from_str_radix(val_str, 16).ok()
            } else {
                // Short number - parse as decimal
                val_str.parse().ok()
            }
        }
    } else {
        val_str.parse().ok()
    }
}

fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

/// Extract address from a call target name like "ram:401110_0" or "const:401110".
fn extract_call_address(name: &str) -> Option<u64> {
    // Try ram:address_version format (e.g., "ram:401110_0")
    if let Some(rest) = name.strip_prefix("ram:") {
        let addr_str = rest.split('_').next().unwrap_or(rest);
        return u64::from_str_radix(addr_str, 16).ok();
    }

    // Try const:address format
    if let Some(rest) = name.strip_prefix("const:") {
        let addr_str = rest.split('_').next().unwrap_or(rest);
        if let Some(hex) = addr_str
            .strip_prefix("0x")
            .or_else(|| addr_str.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).ok();
        }
        // Try as plain hex
        return u64::from_str_radix(addr_str, 16).ok();
    }

    None
}

/// Check if a string looks like a hex number.
fn is_hex_name(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Get a C type from a bit size.
fn type_from_size(size: u32) -> CType {
    match size {
        0 => CType::Unknown,
        1 => CType::Int(8),
        2 => CType::Int(16),
        4 => CType::Int(32),
        8 => CType::Int(64),
        _ => CType::Int(size.saturating_mul(8)),
    }
}

fn uint_type_from_size(size: u32) -> CType {
    match size {
        0 => CType::Unknown,
        1 => CType::UInt(8),
        2 => CType::UInt(16),
        4 => CType::UInt(32),
        8 => CType::UInt(64),
        _ => CType::UInt(size.saturating_mul(8)),
    }
}

/// Fold expressions in a block, returning simplified C statements.
pub fn fold_block(block: &SSABlock) -> Vec<CStmt> {
    let mut ctx = FoldingContext::new(64);
    ctx.analyze_block(block);
    ctx.fold_block(block)
}

/// Fold expressions across multiple blocks.
pub fn fold_blocks(blocks: &[SSABlock]) -> Vec<(u64, Vec<CStmt>)> {
    let mut ctx = FoldingContext::new(64);
    ctx.analyze_blocks(blocks);

    blocks.iter().map(|b| (b.addr, ctx.fold_block(b))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExternalStackVar;
    use r2il::{R2ILBlock, R2ILOp, Varnode};

    fn make_var(name: &str, version: u32, size: u32) -> SSAVar {
        SSAVar::new(name, version, size)
    }

    fn make_block(ops: Vec<SSAOp>) -> SSABlock {
        SSABlock {
            addr: 0x1000,
            size: 4,
            ops,
            phis: Vec::new(),
        }
    }

    fn expr_contains_binary_op(expr: &CExpr, target: BinaryOp) -> bool {
        match expr {
            CExpr::Binary { op, left, right } => {
                *op == target
                    || expr_contains_binary_op(left, target)
                    || expr_contains_binary_op(right, target)
            }
            CExpr::Unary { operand, .. } => expr_contains_binary_op(operand, target),
            CExpr::Paren(inner) => expr_contains_binary_op(inner, target),
            CExpr::Cast { expr: inner, .. } => expr_contains_binary_op(inner, target),
            _ => false,
        }
    }

    fn expr_contains_flag_artifact(expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                lower.starts_with("of_")
                    || lower.starts_with("zf_")
                    || lower.starts_with("sf_")
                    || lower.starts_with("cf_")
            }
            CExpr::Binary { left, right, .. } => {
                expr_contains_flag_artifact(left) || expr_contains_flag_artifact(right)
            }
            CExpr::Unary { operand, .. } => expr_contains_flag_artifact(operand),
            CExpr::Paren(inner) => expr_contains_flag_artifact(inner),
            CExpr::Cast { expr: inner, .. } => expr_contains_flag_artifact(inner),
            CExpr::Deref(inner) => expr_contains_flag_artifact(inner),
            CExpr::Subscript { base, index } => {
                expr_contains_flag_artifact(base) || expr_contains_flag_artifact(index)
            }
            CExpr::Member { base, .. } => expr_contains_flag_artifact(base),
            CExpr::PtrMember { base, .. } => expr_contains_flag_artifact(base),
            CExpr::Call { func, args } => {
                expr_contains_flag_artifact(func) || args.iter().any(expr_contains_flag_artifact)
            }
            _ => false,
        }
    }

    fn expr_contains_sub_zero_cmp_scaffold(expr: &CExpr) -> bool {
        fn is_zero(expr: &CExpr) -> bool {
            matches!(expr, CExpr::IntLit(0) | CExpr::UIntLit(0))
        }

        fn is_sub_zero(expr: &CExpr) -> bool {
            matches!(
                expr,
                CExpr::Binary {
                    op: BinaryOp::Sub,
                    right,
                    ..
                } if is_zero(right)
            )
        }

        match expr {
            CExpr::Binary { op, left, right } => {
                ((*op == BinaryOp::Eq || *op == BinaryOp::Ne)
                    && ((is_sub_zero(left) && is_zero(right))
                        || (is_sub_zero(right) && is_zero(left))))
                    || expr_contains_sub_zero_cmp_scaffold(left)
                    || expr_contains_sub_zero_cmp_scaffold(right)
            }
            CExpr::Unary { operand, .. } => expr_contains_sub_zero_cmp_scaffold(operand),
            CExpr::Paren(inner) => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Cast { expr: inner, .. } => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Deref(inner) => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Subscript { base, index } => {
                expr_contains_sub_zero_cmp_scaffold(base)
                    || expr_contains_sub_zero_cmp_scaffold(index)
            }
            CExpr::Member { base, .. } => expr_contains_sub_zero_cmp_scaffold(base),
            CExpr::PtrMember { base, .. } => expr_contains_sub_zero_cmp_scaffold(base),
            CExpr::Call { func, args } => {
                expr_contains_sub_zero_cmp_scaffold(func)
                    || args.iter().any(expr_contains_sub_zero_cmp_scaffold)
            }
            _ => false,
        }
    }

    #[test]
    fn test_constant_parsing() {
        assert_eq!(parse_const_value("const:0x42"), Some(0x42));
        assert_eq!(parse_const_value("const:42"), Some(42));
        assert_eq!(parse_const_value("const:fffffffc"), Some(0xfffffffc));
        assert_eq!(parse_const_value("const:0x42_0"), Some(0x42));
    }

    #[test]
    fn test_is_cpu_flag() {
        assert!(is_cpu_flag("cf"));
        assert!(is_cpu_flag("zf"));
        assert!(is_cpu_flag("sf"));
        assert!(is_cpu_flag("cf_1"));
        assert!(!is_cpu_flag("rax"));
        assert!(!is_cpu_flag("rbp"));
    }

    #[test]
    fn test_dead_flag_elimination() {
        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let zf_1 = make_var("ZF", 1, 1);
        let const_1 = make_var("const:1", 0, 8);

        let block = make_block(vec![
            // RAX_1 = RAX_0 + 1 (used)
            SSAOp::IntAdd {
                dst: rax_1.clone(),
                a: rax_0.clone(),
                b: const_1.clone(),
            },
            // ZF_1 = RAX_1 == 0 (not used - should be eliminated)
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: rax_1.clone(),
                b: make_var("const:0", 0, 8),
            },
            // Store RAX_1 (uses RAX_1)
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:0x1000", 0, 8),
                val: rax_1,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // ZF_1 should be dead (flag, not used)
        assert!(ctx.is_dead(&zf_1));
    }

    #[test]
    fn test_single_use_inlining() {
        let rax_0 = make_var("RAX", 0, 8);
        let rbx_0 = make_var("RBX", 0, 8);
        let t0 = make_var("tmp:100", 0, 8);
        let t1 = make_var("tmp:100", 1, 8);

        let block = make_block(vec![
            // t0 = rax_0 + rbx_0 (single use)
            SSAOp::IntAdd {
                dst: t0.clone(),
                a: rax_0.clone(),
                b: rbx_0.clone(),
            },
            // t1 = t0 * 2
            SSAOp::IntMult {
                dst: t1.clone(),
                a: t0.clone(),
                b: make_var("const:2", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // t0 should be inlined (single use, temp)
        assert!(ctx.should_inline(&t0.display_name()));
    }

    #[test]
    fn test_multi_use_simple_temp_inlining() {
        let rax_0 = make_var("RAX", 0, 8);
        let t0 = make_var("tmp:200", 1, 8);
        let t1 = make_var("tmp:201", 1, 8);
        let t2 = make_var("tmp:202", 1, 8);

        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: t0.clone(),
                a: rax_0,
                b: make_var("const:1", 0, 8),
            },
            SSAOp::IntAdd {
                dst: t1.clone(),
                a: t0.clone(),
                b: t0.clone(),
            },
            SSAOp::IntAdd {
                dst: t2,
                a: t1,
                b: t0.clone(),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // t0 has 3 uses but remains simple enough to inline.
        assert!(ctx.should_inline(&t0.display_name()));
    }

    #[test]
    fn test_fold_block() {
        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let zf_1 = make_var("ZF", 1, 1);
        let const_1 = make_var("const:1", 0, 8);

        let block = make_block(vec![
            // RAX_1 = RAX_0 + 1
            SSAOp::IntAdd {
                dst: rax_1.clone(),
                a: rax_0.clone(),
                b: const_1.clone(),
            },
            // ZF_1 = RAX_1 == 0 (unused flag)
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: rax_1.clone(),
                b: make_var("const:0", 0, 8),
            },
        ]);

        let stmts = fold_block(&block);

        // RAX_1 is used only once (in the dead ZF_1 expression), so with stronger
        // inlining it gets inlined into the dead expression, which is then eliminated.
        // Both statements should be eliminated.
        assert_eq!(stmts.len(), 0);
    }

    #[test]
    fn test_comparison_reconstruction() {
        // Test that CMP instruction pattern is reconstructed:
        // IntSub tmp = a - 0xdead
        // IntEqual ZF = tmp == 0
        // BoolNot cond = !ZF
        // CBranch cond  -> should become "if (a != 0xdead)"

        let edi_0 = make_var("EDI", 0, 4);
        let tmp_sub = make_var("tmp:1000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:2000", 1, 1);
        let const_dead = make_var("const:dead", 0, 4);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            // tmp_sub = edi_0 - 0xdead (the CMP)
            SSAOp::IntSub {
                dst: tmp_sub.clone(),
                a: edi_0.clone(),
                b: const_dead.clone(),
            },
            // ZF = tmp_sub == 0
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp_sub.clone(),
                b: const_0.clone(),
            },
            // cond = !ZF
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1.clone(),
            },
            // CBranch cond
            SSAOp::CBranch {
                cond: cond.clone(),
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // Check that flag_origins was populated
        assert!(
            ctx.flag_origins_map().contains_key("ZF_1"),
            "ZF_1 should be in flag_origins"
        );

        // Check the origin values
        let (left, right) = ctx.flag_origins_map().get("ZF_1").unwrap();
        assert_eq!(left, "edi", "Left operand should be edi");
        assert_eq!(right, "0xdead", "Right operand should be 0xdead");
    }

    #[test]
    fn test_flag_only_transitive_marking() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:3000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:3001", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        assert!(ctx.flag_only_values_set().contains(&tmp.display_name()));
        assert!(ctx.is_dead(&tmp));
    }

    #[test]
    fn test_flag_only_preserved_for_non_flag_consumer() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:4000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:4001", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0.clone(),
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:0x2000", 0, 8),
                val: tmp.clone(),
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        assert!(!ctx.flag_only_values_set().contains(&tmp.display_name()));
        assert!(!ctx.is_dead(&tmp));
    }

    #[test]
    fn test_simplify_predicate_rewrites_cmp_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::unary(
            UnaryOp::Not,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
                CExpr::IntLit(0),
            ),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_simplify_predicate_rewrites_ne_ge_zero_to_gt_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(BinaryOp::Ge, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("x".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_identity_sub_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Sub,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_add_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Add,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_or_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitOr,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_xor_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitXor,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_mul_one() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Mul,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_div_one() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Div,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_and_all_ones_with_explicit_width() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitAnd,
            CExpr::Var("x".to_string()),
            CExpr::UIntLit(0xffff_ffff),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_negative_cases_preserved() {
        let ctx = FoldingContext::new(64);
        let sub = ctx.identity_simplify_binary(
            BinaryOp::Sub,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(
            sub,
            CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(1))
        );

        let add = ctx.identity_simplify_binary(
            BinaryOp::Add,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(2),
            Some(4),
        );
        assert_eq!(
            add,
            CExpr::binary(BinaryOp::Add, CExpr::Var("x".to_string()), CExpr::IntLit(2))
        );

        let or = ctx.identity_simplify_binary(
            BinaryOp::BitOr,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(
            or,
            CExpr::binary(
                BinaryOp::BitOr,
                CExpr::Var("x".to_string()),
                CExpr::IntLit(1)
            )
        );
    }

    #[test]
    fn test_noop_assignment_is_suppressed() {
        let ctx = FoldingContext::new(64);
        let lhs = CExpr::Var("x".to_string());
        let rhs = CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0));
        let stmt = ctx.assign_stmt(lhs, rhs);
        assert!(stmt.is_none(), "x = x - 0 should be suppressed as a no-op");
    }

    #[test]
    fn test_rewrite_stack_deref_to_external_name() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: Some(CType::Array(Box::new(CType::Int(8)), Some(64))),
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::Deref(Box::new(CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x40),
        )));

        assert_eq!(ctx.rewrite_stack_expr(expr), CExpr::Var("buf".to_string()));
    }

    #[test]
    fn test_rewrite_stack_address_expr_for_call_arg() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x40),
        );
        assert_eq!(ctx.rewrite_stack_expr(expr), CExpr::Var("buf".to_string()));
    }

    #[test]
    fn test_rewrite_stack_cast_paren_expr() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -72,
            ExternalStackVar {
                name: "user_input".to_string(),
                ty: Some(CType::ptr(CType::Int(8))),
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::Deref(Box::new(CExpr::Cast {
            ty: CType::ptr(CType::Int(8)),
            expr: Box::new(CExpr::Paren(Box::new(CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("rbp_1".to_string()),
                CExpr::IntLit(-0x48),
            )))),
        }));

        assert_eq!(
            ctx.rewrite_stack_expr(expr),
            CExpr::Var("user_input".to_string())
        );
    }

    #[test]
    fn test_rewrite_stack_unknown_offset_preserved() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x20),
        );
        assert_eq!(ctx.rewrite_stack_expr(expr.clone()), expr);
    }

    #[test]
    fn test_sf_surrogate_cycle_is_guarded() {
        let mut ctx = FoldingContext::new(64);
        ctx.analysis_ctx
            .use_info
            .definitions
            .insert("sf_1".to_string(), CExpr::Var("sf_2".to_string()));
        ctx.analysis_ctx
            .use_info
            .definitions
            .insert("sf_2".to_string(), CExpr::Var("sf_1".to_string()));

        assert!(
            !ctx.is_sf_surrogate(&CExpr::Var("sf_1".to_string())),
            "Cyclic surrogate definitions must short-circuit without recursion overflow"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_removes_unused_pure_copy() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t1_1".to_string()),
                CExpr::Var("arg1".to_string()),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t2_2".to_string()),
                CExpr::Var("arg2".to_string()),
            )),
            CStmt::Return(Some(CExpr::Var("t2_2".to_string()))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(pruned.len(), 2, "Unused pure temp copy should be removed");
        assert!(
            !matches!(
                pruned.first(),
                Some(CStmt::Expr(CExpr::Binary {
                    op: BinaryOp::Assign,
                    left,
                    right: _,
                })) if left.as_ref() == &CExpr::Var("t1_1".to_string())
            ),
            "t1_1 copy should be pruned"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_keeps_side_effecting_rhs() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t1_1".to_string()),
                CExpr::call(CExpr::Var("foo".to_string()), vec![]),
            )),
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(
            pruned.len(),
            2,
            "Dead temp assignment must be kept when RHS has side effects"
        );
    }

    #[test]
    fn test_copy_predicate_assignment_uses_simplified_rhs() {
        let edi_0 = make_var("EDI", 0, 4);
        let sub = make_var("tmp:9100", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:9101", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: sub.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: sub,
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let rhs = ctx.resolve_predicate_rhs_for_var(&cond, ctx.get_expr(&cond));

        assert!(
            expr_contains_binary_op(&rhs, BinaryOp::Ne),
            "Predicate copy helper should preserve high-level comparison form"
        );
        assert!(
            !expr_contains_flag_artifact(&rhs),
            "Predicate copy helper output should not contain raw flag temporaries"
        );
        assert!(
            !expr_contains_sub_zero_cmp_scaffold(&rhs),
            "Predicate copy helper output should not contain cmp-to-zero subtraction scaffold"
        );
    }

    #[test]
    fn test_simplify_signed_gt_from_ne_and_of_eq_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.analysis_ctx.flag_info.flag_origins.insert(
            "OF_1".to_string(),
            ("a".to_string(), "const:0_0".to_string()),
        );

        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("of_1".to_string()),
                CExpr::binary(BinaryOp::Lt, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("a".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_simplify_signed_ge_from_of_eq_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_2".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::Eq,
            CExpr::Var("of_2".to_string()),
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::binary(
                    BinaryOp::Sub,
                    CExpr::Var("a".to_string()),
                    CExpr::Var("b".to_string()),
                ),
                CExpr::IntLit(0),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Ge,
                CExpr::Var("a".to_string()),
                CExpr::Var("b".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_signed_lt_from_of_ne_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_3".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::Ne,
            CExpr::Var("of_3".to_string()),
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::binary(
                    BinaryOp::Sub,
                    CExpr::Var("a".to_string()),
                    CExpr::Var("b".to_string()),
                ),
                CExpr::IntLit(0),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::Var("a".to_string()),
                CExpr::Var("b".to_string())
            )
        );
    }

    #[test]
    fn test_signed_canonicalization_mismatch_does_not_collapse() {
        let mut ctx = FoldingContext::new(64);
        ctx.analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_4".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("of_4".to_string()),
                CExpr::binary(BinaryOp::Lt, CExpr::Var("y".to_string()), CExpr::IntLit(0)),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr.clone());
        assert_eq!(simplified, expr);
    }

    #[test]
    fn test_stack_prologue_arg_alias_recovery() {
        let rbp_1 = make_var("RBP", 1, 8);
        let edi_0 = make_var("EDI", 0, 4);
        let addr = make_var("tmp:7000", 1, 8);
        let arg_copy = make_var("tmp:7001", 1, 4);
        let loaded = make_var("tmp:7002", 1, 4);
        let cond = make_var("tmp:7003", 1, 1);
        let const_neg4 = make_var("const:fffffffffffffffc", 0, 8);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: rbp_1.clone(),
                b: const_neg4,
            },
            SSAOp::Copy {
                dst: arg_copy.clone(),
                src: edi_0,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: addr.clone(),
                val: arg_copy,
            },
            SSAOp::Load {
                dst: loaded.clone(),
                space: "ram".to_string(),
                addr: addr,
            },
            SSAOp::IntNotEqual {
                dst: cond.clone(),
                a: loaded.clone(),
                b: const_0,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_blocks(std::slice::from_ref(&block));

        assert_eq!(ctx.stack_vars_map().get(&-4), Some(&"arg1".to_string()));

        let mut visited = HashSet::new();
        let resolved =
            ctx.resolve_predicate_operand(&CExpr::Var(loaded.display_name()), 0, &mut visited);
        assert_eq!(resolved, CExpr::Var("arg1".to_string()));
    }

    #[test]
    fn test_use_info_deterministic() {
        let eax_0 = make_var("EAX", 0, 4);
        let tmp = make_var("tmp:8200", 1, 4);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: tmp.clone(),
                a: eax_0,
                b: make_var("const:1", 0, 4),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:1000", 0, 8),
                val: tmp,
            },
        ]);

        let ctx_a = FoldingContext::new(64);
        let ctx_b = FoldingContext::new(64);
        let blocks = vec![block];

        let cfg_a = ctx_a.to_pass_env();
        let cfg_b = ctx_b.to_pass_env();
        let info_a = analysis::UseInfo::analyze(&blocks, &cfg_a);
        let info_b = analysis::UseInfo::analyze(&blocks, &cfg_b);
        assert_eq!(info_a, info_b, "UseInfo analysis should be deterministic");
    }

    #[test]
    fn test_flag_info_transitive_marking_and_guard() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:8300", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:8301", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let flag_only_block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0.clone(),
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0.clone(),
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![flag_only_block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let flag_info = analysis::FlagInfo::analyze(&blocks, &use_info, &cfg);
        assert!(flag_info.flag_only_values.contains(&tmp.display_name()));

        let tmp2 = make_var("tmp:8400", 1, 4);
        let zf_2 = make_var("ZF", 2, 1);
        let cond2 = make_var("tmp:8401", 1, 1);
        let guarded_block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp2.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_2,
                a: tmp2.clone(),
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond2.clone(),
                src: make_var("ZF", 2, 1),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:2000", 0, 8),
                val: tmp2.clone(),
            },
            SSAOp::CBranch {
                cond: cond2,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![guarded_block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let flag_info = analysis::FlagInfo::analyze(&blocks, &use_info, &cfg);
        assert!(!flag_info.flag_only_values.contains(&tmp2.display_name()));
    }

    #[test]
    fn test_stack_info_arg_alias_requires_version_zero() {
        let rbp_1 = make_var("RBP", 1, 8);
        let eax_1 = make_var("EAX", 1, 4);
        let addr = make_var("tmp:8500", 1, 8);
        let const_neg4 = make_var("const:fffffffffffffffc", 0, 8);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: rbp_1,
                b: const_neg4,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr,
                val: eax_1,
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let stack_info = analysis::StackInfo::analyze(&blocks, &use_info, &cfg);

        assert!(
            !stack_info.stack_arg_aliases.values().any(|v| v == "arg1"),
            "Non-argument registers must not be treated as prologue arg aliases"
        );
    }

    #[test]
    fn test_analyze_function_structure_marks_exit_as_return_context() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let func = SSAFunction::from_blocks(&[block]).expect("SSA function should build");

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_function_structure(&func);

        assert!(ctx.return_blocks.contains(&0x1000));
    }

    #[test]
    fn test_return_expr_inlines_simple_xor_chain_and_stops_after_return() {
        let eax_1 = make_var("EAX", 1, 4);
        let edi_0 = make_var("EDI", 0, 4);
        let esi_0 = make_var("ESI", 0, 4);
        let t1 = make_var("tmp:8000", 1, 1);
        let t2 = make_var("tmp:8001", 1, 1);
        let t3 = make_var("tmp:8002", 1, 1);
        let rip_1 = make_var("RIP", 1, 8);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntNotEqual {
                dst: t1.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntNotEqual {
                dst: t2.clone(),
                a: esi_0,
                b: const_0,
            },
            SSAOp::IntXor {
                dst: t3.clone(),
                a: t1,
                b: t2,
            },
            SSAOp::Copy {
                dst: eax_1,
                src: t3,
            },
            SSAOp::Return { target: rip_1 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        ctx.return_blocks.insert(block.addr);
        ctx.set_current_block(block.addr);

        let stmts = ctx.fold_block(&block);
        assert_eq!(
            stmts.len(),
            1,
            "Should stop emitting after high-level return"
        );

        match &stmts[0] {
            CStmt::Return(Some(expr)) => {
                assert!(
                    expr_contains_binary_op(expr, BinaryOp::BitXor),
                    "Return expression should inline XOR chain"
                );
                assert!(
                    expr_contains_binary_op(expr, BinaryOp::Ne),
                    "Return expression should include inlined predicate comparisons"
                );
            }
            other => panic!("Expected return statement, got {:?}", other),
        }
    }

    #[test]
    fn test_no_duplicate_low_level_return_after_high_level_return() {
        let eax_1 = make_var("EAX", 1, 4);
        let tmp = make_var("tmp:8100", 1, 4);
        let rip_1 = make_var("RIP", 1, 8);

        let block = make_block(vec![
            SSAOp::Copy {
                dst: tmp.clone(),
                src: make_var("const:1", 0, 4),
            },
            SSAOp::Copy {
                dst: eax_1,
                src: tmp,
            },
            SSAOp::Return { target: rip_1 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        ctx.return_blocks.insert(block.addr);
        ctx.set_current_block(block.addr);

        let stmts = ctx.fold_block(&block);
        let return_count = stmts
            .iter()
            .filter(|stmt| matches!(stmt, CStmt::Return(_)))
            .count();
        assert_eq!(return_count, 1, "Should emit a single high-level return");
    }
}
