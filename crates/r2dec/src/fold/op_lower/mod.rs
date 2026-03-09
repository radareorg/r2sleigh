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

use r2ssa::{SSAFunction, SSAOp, SSAVar};
use r2types::TypeArena;
#[cfg(test)]
use r2types::TypeOracle;

use crate::analysis;
use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};
use crate::types::FunctionType;

use super::context::{FoldingContext, PtrArith, SSABlock};
use super::flags::is_cpu_flag;
use super::{
    MAX_ALIAS_REWRITE_DEPTH, MAX_MUL_CONST_DEPTH, MAX_PREDICATE_OPERAND_DEPTH,
    MAX_RETURN_EXPR_DEPTH, MAX_RETURN_INLINE_CANDIDATE_DEPTH, MAX_RETURN_INLINE_DEPTH,
    MAX_SIMPLE_EXPR_DEPTH,
};

mod aliases;
mod calls;
mod lowering;
mod returns;

#[derive(Debug, Clone, PartialEq)]
enum LoweredOp {
    Assign { lhs: CExpr, rhs: CExpr },
    Expr(CExpr),
    Return(Option<CExpr>),
    None,
    Comment(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowerMode {
    Expr,
    Stmt,
}

#[derive(Debug, Clone, Copy)]
struct LowerFrame {
    mode: LowerMode,
    block_addr: u64,
    op_idx: usize,
    with_call_args: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct VisibleExprQuality {
    semantic_shapes: i32,
    semantic_names: i32,
    stable_pointer_shapes: i32,
    generic_stack_penalty: i32,
    transient_reg_penalty: i32,
    temp_penalty: i32,
    zero_offset_penalty: i32,
    node_penalty: i32,
}

impl LowerFrame {
    fn for_expr() -> Self {
        Self {
            mode: LowerMode::Expr,
            block_addr: 0,
            op_idx: 0,
            with_call_args: false,
        }
    }

    fn for_stmt(block_addr: u64, op_idx: usize, with_call_args: bool) -> Self {
        Self {
            mode: LowerMode::Stmt,
            block_addr,
            op_idx,
            with_call_args,
        }
    }
}

impl<'a> FoldingContext<'a> {
    fn use_info(&self) -> &analysis::UseInfo {
        &self.state.analysis_ctx.use_info
    }

    fn flag_info(&self) -> &analysis::FlagInfo {
        &self.state.analysis_ctx.flag_info
    }

    fn stack_info(&self) -> &analysis::StackInfo {
        &self.state.analysis_ctx.stack_info
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
    pub(crate) fn ptr_members_map(&self) -> &HashMap<String, (SSAVar, i64)> {
        &self.use_info().ptr_members
    }
    pub(crate) fn stack_slots_map(&self) -> &HashMap<String, analysis::StackSlotProvenance> {
        &self.use_info().stack_slots
    }
    pub(crate) fn forwarded_values_map(&self) -> &HashMap<String, analysis::ValueProvenance> {
        &self.use_info().forwarded_values
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
    pub(crate) fn to_pass_env(&self) -> analysis::PassEnv<'_> {
        analysis::PassEnv {
            ptr_size: self.inputs.arch.ptr_size,
            sp_name: &self.inputs.arch.sp_name,
            fp_name: &self.inputs.arch.fp_name,
            ret_reg_name: &self.inputs.arch.ret_reg_name,
            function_names: self.inputs.function_names,
            strings: self.inputs.strings,
            symbols: self.inputs.symbols,
            arg_regs: &self.inputs.arch.arg_regs,
            param_register_aliases: self.inputs.param_register_aliases,
            caller_saved_regs: &self.inputs.arch.caller_saved_regs,
            type_hints: &self.use_info().type_hints,
            type_oracle: self.inputs.type_oracle,
        }
    }

    /// Set whether to hide stack frame boilerplate.
    pub fn set_hide_stack_frame(&mut self, hide: bool) {
        self.hide_stack_frame = hide;
    }

    #[cfg(test)]
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.inputs.function_names = Box::leak(Box::new(names));
    }

    #[cfg(test)]
    pub fn set_known_function_signatures(&mut self, signatures: HashMap<String, FunctionType>) {
        let normalized = signatures
            .into_iter()
            .map(|(name, sig)| (normalize_callee_name(&name), sig))
            .collect::<HashMap<_, _>>();
        self.inputs.known_function_signatures = Box::leak(Box::new(normalized));
    }

    #[cfg(test)]
    pub fn set_type_hints(&mut self, hints: HashMap<String, CType>) {
        self.inputs.type_hints = Box::leak(Box::new(hints.clone()));
        self.state.analysis_ctx.use_info.type_hints = hints;
    }

    #[cfg(test)]
    pub fn set_external_stack_vars(&mut self, stack_vars: HashMap<i64, crate::ExternalStackVar>) {
        self.inputs.external_stack_vars = Box::leak(Box::new(stack_vars));
    }

    #[cfg(test)]
    pub fn set_type_oracle(&mut self, type_oracle: Option<&'a dyn TypeOracle>) {
        self.inputs.type_oracle = type_oracle;
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

    /// Set CallOther userop name mappings.
    pub fn set_userop_names(&mut self, names: HashMap<u32, String>) {
        self.userop_names = names;
    }

    /// Analyze function structure to detect return patterns.
    /// This finds the exit block and blocks that branch to it.
    pub fn analyze_function_structure(&mut self, func: &SSAFunction) {
        // Find exit block (the block containing SSAOp::Return)
        for block in func.blocks() {
            for op in &block.ops {
                if matches!(op, SSAOp::Return { .. }) {
                    self.state.exit_block = Some(block.addr);
                    break;
                }
            }
            if self.state.exit_block.is_some() {
                break;
            }
        }

        // Find blocks that branch directly to the exit block
        if let Some(exit_addr) = self.state.exit_block {
            // Treat the exit block itself as a return context.
            self.state.return_blocks.insert(exit_addr);

            // Any CFG predecessor of the exit block is a return context,
            // including fallthrough paths that no longer carry phi metadata.
            for pred in func.predecessors(exit_addr) {
                if pred != exit_addr {
                    self.state.return_blocks.insert(pred);
                }
            }

            for block in func.blocks() {
                // Skip the exit block itself
                if block.addr == exit_addr {
                    continue;
                }

                for op in &block.ops {
                    if let SSAOp::Branch { target } = op {
                        // Extract address from the target variable (e.g., "ram:401256_0")
                        if let Some(addr) = self.extract_branch_target_address(target)
                            && addr == exit_addr
                        {
                            self.state.return_blocks.insert(block.addr);
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
                            self.state.return_blocks.insert(*src_addr);
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

    /// Check if the current block is a return block.
    fn is_current_return_block(&self) -> bool {
        if let Some(addr) = self.current_block_addr.get() {
            return self.state.return_blocks.contains(&addr);
        }
        false
    }

    /// Look up a function name by address.
    fn lookup_function(&self, addr: u64) -> Option<&String> {
        self.inputs.function_names.get(&addr)
    }

    /// Look up a string literal by address.
    fn lookup_string(&self, addr: u64) -> Option<&String> {
        self.inputs.strings.get(&addr)
    }

    /// Look up a symbol by address.
    fn lookup_symbol(&self, addr: u64) -> Option<&String> {
        self.inputs.symbols.get(&addr)
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
        self.state.analysis_ctx.use_info.type_hints = self.inputs.type_hints.clone();
        let env = self.to_pass_env();
        let mut use_info = analysis::UseInfo::analyze(blocks, &env);
        let mut stack_info = analysis::StackInfo::analyze(blocks, &use_info, &env);
        let initial_stack_info = stack_info.clone();

        for (offset, ext_var) in self.inputs.external_stack_vars {
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

        if !stack_info.definition_overrides.is_empty() {
            use_info = analysis::UseInfo::analyze_with_definition_overrides(
                blocks,
                &env,
                &stack_info.definition_overrides,
            );
            stack_info = analysis::StackInfo::analyze(blocks, &use_info, &env);
            for (offset, alias) in &initial_stack_info.stack_arg_aliases {
                stack_info.stack_arg_aliases.insert(*offset, alias.clone());
                let should_replace = match stack_info.stack_vars.get(offset) {
                    None => true,
                    Some(existing) => should_replace_preserved_stack_alias(existing),
                };
                if should_replace {
                    stack_info.stack_vars.insert(*offset, alias.clone());
                }
            }
            for (key, expr) in &initial_stack_info.definition_overrides {
                let should_replace = match stack_info.definition_overrides.get(key) {
                    None => true,
                    Some(existing) => should_replace_preserved_stack_expr(existing, expr),
                };
                if should_replace {
                    stack_info
                        .definition_overrides
                        .insert(key.clone(), expr.clone());
                }
            }
            normalize_stack_definition_overrides(&mut stack_info);
            for (offset, ext_var) in self.inputs.external_stack_vars {
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
            use_info = analysis::UseInfo::analyze_with_definition_overrides(
                blocks,
                &env,
                &stack_info.definition_overrides,
            );
        }
        let flag_info = analysis::FlagInfo::analyze(blocks, &use_info, &env);
        self.state.analysis_ctx = analysis::AnalysisContext {
            use_info,
            flag_info,
            stack_info,
        };
    }

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
            if self.inputs.arch.is_return_register_name(&base_lower)
                && self.is_current_return_block()
            {
                return false;
            }
            // Don't inline stack/frame pointer versions - they're structural
            if self.inputs.arch.is_stack_base_name(&base_lower) {
                return false;
            }
            // Inline calling-convention argument registers (consumed by call args)
            if self.inputs.arch.is_caller_saved_name(&base_lower) {
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
        if depth > MAX_SIMPLE_EXPR_DEPTH {
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
        if self.inputs.arch.is_caller_saved_name(&lower) {
            return true;
        }

        // Variables consumed by call argument collection are dead
        if self.consumed_by_call_set().contains(&key) {
            return true;
        }

        // Stack/frame pointer intermediate versions are dead if unused
        if self.inputs.arch.is_stack_base_name(&lower) {
            return true;
        }

        // Eliminate explicit zeroing idioms when the value is never used
        // beyond setup/flag chains (e.g., eax = eax ^ eax).
        if let Some(expr) = self.definitions_map().get(&key)
            && self.is_zeroing_expr(expr)
        {
            return true;
        }

        // Keep other named registers alive (e.g., callee-saved like rbx, r12-r15)
        // as they might be meaningful outputs
        false
    }

    /// Get the expression for a variable, potentially inlining its definition.
    pub fn get_expr(&self, var: &SSAVar) -> CExpr {
        let key = var.display_name();

        // Always inline constants
        if var.is_const() {
            return self.const_to_expr(var);
        }

        // Resolve ram:address references to known names
        if var.name.starts_with("ram:")
            && let Some(addr) = extract_call_address(&var.name)
        {
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

        // Try to inline if appropriate
        if self.should_inline(&key)
            && let Some(expr) = self.definitions_map().get(&key)
        {
            return expr.clone();
        }

        // Otherwise return a variable reference
        CExpr::Var(self.var_name(var))
    }

    fn op_to_expr_impl(&self, op: &SSAOp) -> CExpr {
        if let SSAOp::Copy { src, .. } = op {
            return self.get_expr(src);
        }

        if let Some(stmt) = self.op_to_stmt_impl(op) {
            return match Self::lowered_from_stmt(stmt) {
                LoweredOp::Assign { rhs, .. } => rhs,
                LoweredOp::Expr(expr) => expr,
                LoweredOp::Return(Some(expr)) => expr,
                LoweredOp::Return(None) => CExpr::Var("return".to_string()),
                LoweredOp::Comment(_) | LoweredOp::None => {
                    if let Some(dst) = op.dst() {
                        CExpr::Var(self.var_name(dst))
                    } else {
                        CExpr::Var("__unhandled_op__".to_string())
                    }
                }
            };
        }

        match op {
            // These ops do not lower to statements but still need expression form.
            SSAOp::CBranch { cond, .. } => self.get_condition_expr(cond),
            SSAOp::Return { target } => self.get_return_expr(target),
            _ => {
                if let Some(dst) = op.dst() {
                    CExpr::Var(self.var_name(dst))
                } else {
                    CExpr::Var("__unhandled_op__".to_string())
                }
            }
        }
    }

    /// Create a binary expression.
    #[allow(dead_code)]
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
                if op == BinaryOp::BitXor && left == right {
                    CExpr::IntLit(0)
                } else if self.is_literal_zero_expr(&right) {
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
        if let CExpr::Var(lhs_name) = &lhs
            && is_generic_arg_name(lhs_name)
            && let Some(rhs_alias) = self.arg_alias_for_expr(&rhs)
            && lhs_name.eq_ignore_ascii_case(&rhs_alias)
        {
            return None;
        }
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
    ) -> Option<CExpr> {
        let elem_ty = self.infer_subscript_elem_type(base, element_size);
        let base_expr = self.normalize_pointer_base_expr(&self.expr_for_provenance(base), 0);
        let index_expr = self.normalize_index_expr(&self.expr_for_provenance(index), 0)?;
        self.build_subscript_expr(base_expr, index_expr, elem_ty, is_sub)
    }

    fn try_subscript_from_expr(&self, addr: &SSAVar, addr_expr: &CExpr) -> Option<CExpr> {
        if let Some(ptr) = self.ptr_arith_map().get(&addr.display_name())
            && let Some(sub) =
                self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
        {
            return Some(sub);
        }
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
        let base_expr = self.normalize_pointer_base_expr(&base_expr, 0);
        let index_expr = self.normalize_index_expr(&index_expr, 0)?;
        self.build_subscript_expr(base_expr, index_expr, elem_ty, is_sub)
    }

    fn infer_subscript_elem_type(&self, base: &SSAVar, element_size: u32) -> CType {
        if let Some(oracle) = self.inputs.type_oracle {
            let base_ty = oracle.type_of(base);
            if (oracle.is_array(base_ty) || oracle.is_pointer(base_ty))
                && let Some(hint) = self.type_hint_for_var(base)
            {
                match hint {
                    CType::Pointer(inner) | CType::Array(inner, _) => return *inner,
                    _ => {}
                }
            }
        }
        uint_type_from_size(element_size)
    }

    fn try_member_access_from_expr(&self, addr: &SSAVar, addr_expr: &CExpr) -> Option<CExpr> {
        if let Some((base, offset)) = self.ptr_members_map().get(&addr.display_name()) {
            return self.provenanced_member_expr(addr, base, *offset);
        }
        let expr = self
            .definitions_map()
            .get(&addr.display_name())
            .cloned()
            .unwrap_or_else(|| addr_expr.clone());
        self.try_member_access_from_addr_expr(Some(addr), &expr)
    }

    fn try_member_access_from_addr_expr(
        &self,
        addr: Option<&SSAVar>,
        expr: &CExpr,
    ) -> Option<CExpr> {
        let (base_expr, offset) = self.extract_base_const_offset(expr)?;
        if offset == 0 || self.is_stackish_expr(&base_expr) {
            return None;
        }
        let oracle_member = self.oracle_member_name(addr, &base_expr, offset);
        if oracle_member.is_none() || !self.is_semantic_member_base(&base_expr) {
            return None;
        }

        Some(self.member_access_expr(base_expr, oracle_member?))
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

    fn oracle_member_name(
        &self,
        addr: Option<&SSAVar>,
        base_expr: &CExpr,
        offset: i64,
    ) -> Option<String> {
        if offset < 0 {
            return None;
        }
        let oracle = self.inputs.type_oracle?;
        let offset = offset as u64;

        // Best-effort: prefer base pointer identities captured during analysis.
        if let Some(addr) = addr
            && let Some((base, mapped_offset)) = self.ptr_members_map().get(&addr.display_name())
            && *mapped_offset == offset as i64
        {
            let base_ty = oracle.type_of(base);
            if let Some(name) = oracle.field_name(base_ty, offset) {
                return Some(name.to_string());
            }
        }

        if let CExpr::Var(base_name) = base_expr {
            for (base, mapped_offset) in self.ptr_members_map().values() {
                if *mapped_offset != offset as i64 {
                    continue;
                }
                if self.var_name(base) != *base_name {
                    continue;
                }
                let base_ty = oracle.type_of(base);
                if let Some(name) = oracle.field_name(base_ty, offset) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    fn looks_like_pointer(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Cast { ty, .. } => matches!(ty, CType::Pointer(_)),
            CExpr::Deref(_) => true,
            CExpr::Subscript { .. } | CExpr::Member { .. } | CExpr::PtrMember { .. } => true,
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

    fn build_subscript_expr(
        &self,
        base_expr: CExpr,
        index_expr: CExpr,
        elem_ty: CType,
        is_sub: bool,
    ) -> Option<CExpr> {
        if !self.looks_like_pointer(&base_expr)
            || self.is_non_index_pointer_expr(&index_expr)
            || !self.is_semantic_index_expr(&index_expr)
            || base_expr == index_expr
        {
            return None;
        }

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

    fn normalize_pointer_base_expr(&self, expr: &CExpr, depth: u32) -> CExpr {
        if depth > 4 {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => self
                .lookup_definition(name)
                .map(|inner| self.normalize_pointer_base_expr(&inner, depth + 1))
                .filter(|inner| self.looks_like_pointer(inner))
                .unwrap_or_else(|| expr.clone()),
            CExpr::Paren(inner) => {
                CExpr::Paren(Box::new(self.normalize_pointer_base_expr(inner, depth + 1)))
            }
            CExpr::Cast { ty, expr: inner } => CExpr::Cast {
                ty: ty.clone(),
                expr: Box::new(self.normalize_pointer_base_expr(inner, depth + 1)),
            },
            _ => expr.clone(),
        }
    }

    fn normalize_index_expr(&self, expr: &CExpr, depth: u32) -> Option<CExpr> {
        if depth > 4 {
            return self.is_semantic_index_expr(expr).then_some(expr.clone());
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(inner) = self.lookup_definition(name) {
                    let normalized = self.normalize_index_expr(&inner, depth + 1)?;
                    if !self.is_non_index_pointer_expr(&normalized) {
                        return Some(normalized);
                    }
                }
                if self.is_non_index_pointer_expr(expr) {
                    None
                } else {
                    self.is_semantic_index_expr(expr).then_some(expr.clone())
                }
            }
            CExpr::Paren(inner) => self
                .normalize_index_expr(inner, depth + 1)
                .map(|normalized| CExpr::Paren(Box::new(normalized))),
            CExpr::Cast { ty, expr: inner } => self
                .normalize_index_expr(inner, depth + 1)
                .map(|normalized| CExpr::cast(ty.clone(), normalized)),
            CExpr::Unary { op, operand } => self
                .normalize_index_expr(operand, depth + 1)
                .map(|normalized| CExpr::unary(*op, normalized)),
            _ => self.is_semantic_index_expr(expr).then_some(expr.clone()),
        }
    }

    fn is_semantic_index_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => self
                .lookup_definition(name)
                .map(|inner| self.is_semantic_index_expr(&inner))
                .unwrap_or_else(|| {
                    !name.starts_with("const:")
                        && !name.starts_with("ram:")
                        && self.stack_slots_map().get(name).is_none()
                }),
            CExpr::Unary { operand, .. } => self.is_semantic_index_expr(operand),
            CExpr::Binary { left, right, .. } => {
                self.is_semantic_index_expr(left) || self.is_semantic_index_expr(right)
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.is_semantic_index_expr(inner)
            }
            _ => false,
        }
    }

    fn is_non_index_pointer_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Cast { ty, .. } => matches!(ty, CType::Pointer(_)),
            CExpr::Deref(_) | CExpr::Subscript { .. } | CExpr::PtrMember { .. } => true,
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                lower.contains("ptr")
                    || lower.contains("addr")
                    || self.stack_slots_map().get(name).is_some()
                    || self
                        .lookup_type_hint(name)
                        .map(|ty| matches!(ty, CType::Pointer(_) | CType::Struct(_)))
                        .unwrap_or(false)
            }
            CExpr::Paren(inner) => self.is_non_index_pointer_expr(inner),
            CExpr::Unary { operand, .. } => self.is_non_index_pointer_expr(operand),
            _ => false,
        }
    }

    fn is_semantic_member_base(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                !self.inputs.arch.is_stack_base_name(&lower)
                    && !lower.starts_with('r')
                    && !lower.starts_with('e')
                    && !lower.starts_with("tmp:")
            }
            CExpr::Subscript { .. } | CExpr::Member { .. } => true,
            CExpr::Cast { expr, .. } | CExpr::Paren(expr) => self.is_semantic_member_base(expr),
            _ => self.looks_like_pointer(expr),
        }
    }

    fn member_access_expr(&self, base_expr: CExpr, member: String) -> CExpr {
        match base_expr {
            CExpr::Subscript { .. } | CExpr::Member { .. } => CExpr::Member {
                base: Box::new(base_expr),
                member,
            },
            _ => CExpr::PtrMember {
                base: Box::new(base_expr),
                member,
            },
        }
    }

    fn provenanced_member_expr(&self, addr: &SSAVar, base: &SSAVar, offset: i64) -> Option<CExpr> {
        if offset == 0 {
            return None;
        }

        let member =
            self.oracle_member_name(Some(addr), &self.expr_for_provenance(base), offset)?;
        let base_expr = if let Some(ptr) = self.ptr_arith_map().get(&base.display_name()) {
            if let Some(sub) =
                self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
            {
                sub
            } else {
                self.normalize_pointer_base_expr(&self.expr_for_provenance(base), 0)
            }
        } else if let Some(def) = self.lookup_definition(&base.display_name()) {
            if let Some(sub) = self.try_subscript_from_addr_expr(&def) {
                sub
            } else {
                self.normalize_pointer_base_expr(&def, 0)
            }
        } else {
            self.normalize_pointer_base_expr(&self.expr_for_provenance(base), 0)
        };

        self.is_semantic_member_base(&base_expr)
            .then(|| self.member_access_expr(base_expr, member))
    }

    fn expr_for_provenance(&self, var: &SSAVar) -> CExpr {
        self.lookup_definition(&var.display_name())
            .unwrap_or_else(|| self.get_expr(var))
    }

    fn is_stackish_expr(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                self.inputs.arch.is_stack_base_name(&lower)
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

    pub(super) fn prefers_visible_expr(&self, current: &CExpr, candidate: &CExpr) -> bool {
        self.visible_expr_quality(candidate) > self.visible_expr_quality(current)
    }

    pub(super) fn choose_preferred_visible_expr(
        &self,
        current: Option<CExpr>,
        candidate: Option<CExpr>,
    ) -> Option<CExpr> {
        match (current, candidate) {
            (None, other) => other,
            (some @ Some(_), None) => some,
            (Some(current_expr), Some(candidate_expr)) => {
                if self.prefers_visible_expr(&current_expr, &candidate_expr) {
                    Some(candidate_expr)
                } else {
                    Some(current_expr)
                }
            }
        }
    }

    pub(super) fn best_visible_definition(&self, name: &str) -> Option<CExpr> {
        self.choose_preferred_visible_expr(
            self.lookup_definition(name),
            self.formatted_defs_map().get(name).cloned(),
        )
    }

    fn visible_expr_quality(&self, expr: &CExpr) -> VisibleExprQuality {
        let mut quality = VisibleExprQuality::default();
        self.accumulate_visible_expr_quality(expr, &mut quality, 0);
        quality
    }

    fn accumulate_visible_expr_quality(
        &self,
        expr: &CExpr,
        quality: &mut VisibleExprQuality,
        depth: u32,
    ) {
        if depth > MAX_SIMPLE_EXPR_DEPTH {
            return;
        }

        quality.node_penalty -= 1;
        match expr {
            CExpr::Var(name) => {
                if should_replace_preserved_stack_alias(name) {
                    quality.generic_stack_penalty -= 8;
                } else if self.is_transient_visible_name(name) {
                    quality.transient_reg_penalty -= 6;
                } else if self.is_low_signal_visible_name(name) {
                    quality.temp_penalty -= 4;
                } else {
                    quality.semantic_names += 3;
                }
            }
            CExpr::Subscript { base, index } => {
                quality.semantic_shapes += 6;
                quality.stable_pointer_shapes += 2;
                self.accumulate_visible_expr_quality(base, quality, depth + 1);
                self.accumulate_visible_expr_quality(index, quality, depth + 1);
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                quality.semantic_shapes += 7;
                quality.stable_pointer_shapes += 2;
                self.accumulate_visible_expr_quality(base, quality, depth + 1);
            }
            CExpr::Deref(inner) | CExpr::AddrOf(inner) => {
                quality.stable_pointer_shapes += 1;
                self.accumulate_visible_expr_quality(inner, quality, depth + 1);
            }
            CExpr::Cast { expr: inner, .. }
            | CExpr::Paren(inner)
            | CExpr::Unary { operand: inner, .. } => {
                self.accumulate_visible_expr_quality(inner, quality, depth + 1);
            }
            CExpr::Binary { op, left, right } => {
                if matches!(op, BinaryOp::Add | BinaryOp::Sub)
                    && (self.literal_to_i64(left).is_some_and(|lit| lit == 0)
                        || self.literal_to_i64(right).is_some_and(|lit| lit == 0))
                {
                    quality.zero_offset_penalty -= 4;
                }
                self.accumulate_visible_expr_quality(left, quality, depth + 1);
                self.accumulate_visible_expr_quality(right, quality, depth + 1);
            }
            CExpr::Call { func, args } => {
                self.accumulate_visible_expr_quality(func, quality, depth + 1);
                for arg in args {
                    self.accumulate_visible_expr_quality(arg, quality, depth + 1);
                }
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.accumulate_visible_expr_quality(cond, quality, depth + 1);
                self.accumulate_visible_expr_quality(then_expr, quality, depth + 1);
                self.accumulate_visible_expr_quality(else_expr, quality, depth + 1);
            }
            CExpr::Comma(exprs) => {
                for inner in exprs {
                    self.accumulate_visible_expr_quality(inner, quality, depth + 1);
                }
            }
            CExpr::Sizeof(inner) => self.accumulate_visible_expr_quality(inner, quality, depth + 1),
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::SizeofType(_) => {}
        }
    }

    fn is_low_signal_visible_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with("tmp:")
            || lower.starts_with("const:")
            || lower.starts_with("ram:")
            || lower.starts_with("t")
                && lower
                    .trim_start_matches('t')
                    .chars()
                    .all(|ch| ch.is_ascii_digit())
    }

    fn is_transient_visible_name(&self, name: &str) -> bool {
        if self.is_low_signal_visible_name(name) {
            return false;
        }

        let lower = name.to_ascii_lowercase();
        if is_cpu_flag(&lower) {
            return true;
        }

        let base = lower.split('_').next().unwrap_or(lower.as_str());
        self.inputs.arch.is_register_like_base_name(base)
            && !Self::is_semantic_binding_name(base)
            && self.arg_alias_for_rendered_name(name).is_none()
    }

    fn expr_type_hint(&self, expr: &CExpr) -> Option<CType> {
        match expr {
            CExpr::Var(name) => self.lookup_type_hint(name).cloned(),
            CExpr::Cast { ty, .. } => Some(ty.clone()),
            CExpr::Paren(inner) => self.expr_type_hint(inner),
            _ => None,
        }
    }

    fn typed_deref_expr(&self, addr: &SSAVar, addr_expr: CExpr, elem_ty: CType) -> CExpr {
        let ptr_ty = CType::ptr(elem_ty);
        let casted = self.cast_addr_expr_to_ptr_if_needed(addr, addr_expr, &ptr_ty);
        CExpr::Deref(Box::new(casted))
    }

    fn cast_addr_expr_to_ptr_if_needed(
        &self,
        addr: &SSAVar,
        addr_expr: CExpr,
        target_ptr_ty: &CType,
    ) -> CExpr {
        if let CExpr::Cast { ty, .. } = &addr_expr
            && ty == target_ptr_ty
        {
            return addr_expr;
        }

        let source_ty = self
            .expr_type_hint(&addr_expr)
            .or_else(|| self.type_hint_for_var(addr));
        if let Some(source_ty) = source_ty.as_ref() {
            return self.cast_expr_if_needed(addr_expr, target_ptr_ty.clone(), Some(source_ty));
        }

        if self.looks_like_pointer(&addr_expr) {
            return addr_expr;
        }

        CExpr::cast(target_ptr_ty.clone(), addr_expr)
    }

    fn int_meta(&self, ty: &CType) -> Option<(bool, u32)> {
        match ty {
            CType::Int(bits) => Some((true, *bits)),
            CType::UInt(bits) => Some((false, *bits)),
            CType::Bool => Some((false, 1)),
            _ => None,
        }
    }

    fn cast_needed(&self, target: &CType, source: Option<&CType>) -> bool {
        let Some(source) = source else {
            return false;
        };

        if target == source {
            return false;
        }

        if let (Some((dst_signed, dst_bits)), Some((src_signed, src_bits))) =
            (self.int_meta(target), self.int_meta(source))
        {
            return dst_signed != src_signed || dst_bits != src_bits;
        }

        matches!(
            (target, source),
            (
                CType::Pointer(_),
                CType::Int(_) | CType::UInt(_) | CType::Bool
            ) | (CType::Int(_) | CType::UInt(_), CType::Pointer(_))
        )
    }

    fn cast_expr_if_needed(&self, expr: CExpr, target: CType, source: Option<&CType>) -> CExpr {
        if let CExpr::Cast { ty, .. } = &expr
            && *ty == target
        {
            return expr;
        }
        if self.cast_needed(&target, source) {
            CExpr::cast(target, expr)
        } else {
            expr
        }
    }

    fn assignment_rhs_with_type_policy(
        &self,
        dst: &SSAVar,
        src: Option<&SSAVar>,
        rhs: CExpr,
    ) -> CExpr {
        let Some(dst_ty) = self.type_hint_for_var(dst) else {
            return rhs;
        };

        let src_ty = src.and_then(|var| self.type_hint_for_var(var));
        self.cast_expr_if_needed(rhs, dst_ty, src_ty.as_ref())
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
        None
    }

    fn extract_mul_const(&self, expr: &CExpr, depth: u32) -> Option<(CExpr, i64)> {
        if depth > MAX_MUL_CONST_DEPTH {
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
            CExpr::Binary {
                op: BinaryOp::Shl,
                left,
                right,
            } => {
                let shift = self.literal_to_i64(right)?;
                if !(0..=62).contains(&shift) {
                    return None;
                }
                let scale = 1_i64.checked_shl(shift as u32)?;
                self.extract_mul_const(left, depth + 1)
                    .and_then(|(inner, inner_scale)| {
                        inner_scale
                            .checked_mul(scale)
                            .map(|combined| (inner, combined))
                    })
                    .or_else(|| {
                        let index = left.as_ref().clone();
                        self.is_semantic_index_expr(&index)
                            .then_some((index, scale))
                    })
            }
            CExpr::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                left,
                right,
            } => {
                let (left_expr, left_scale) = self.extract_mul_const(left, depth + 1)?;
                let (right_expr, right_scale) = self.extract_mul_const(right, depth + 1)?;
                let left_norm = self.normalize_index_expr(&left_expr, 0)?;
                let right_norm = self.normalize_index_expr(&right_expr, 0)?;
                if left_norm != right_norm {
                    return None;
                }
                let combined = match expr {
                    CExpr::Binary {
                        op: BinaryOp::Add, ..
                    } => left_scale.checked_add(right_scale)?,
                    CExpr::Binary {
                        op: BinaryOp::Sub, ..
                    } => left_scale.checked_sub(right_scale)?,
                    _ => unreachable!(),
                };
                (combined != 0).then_some((left_norm, combined))
            }
            CExpr::Cast { expr: inner, .. } => self.extract_mul_const(inner, depth + 1),
            CExpr::Var(name) => {
                if let Some(def) = self.lookup_definition(name) {
                    return self.extract_mul_const(&def, depth + 1);
                }
                if !self.is_non_index_pointer_expr(expr) && self.is_semantic_index_expr(expr) {
                    Some((expr.clone(), 1))
                } else {
                    None
                }
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
                self.inputs.arch.is_stack_pointer_name(&lower)
                    || self.inputs.arch.is_frame_pointer_name(&lower)
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

    /// Check if `expr` is a version-0 return register (e.g. `RAX_0`, `EAX_0`,
    /// `XMM0_0`).  These appear in exit blocks when phi nodes merge uninitialized
    /// entry values and should be replaced by the last meaningful computed value.
    fn is_uninitialized_return_reg(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                lower.ends_with("_0")
                    && self
                        .inputs
                        .arch
                        .is_return_register_name(lower.trim_end_matches("_0"))
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.is_uninitialized_return_reg(inner)
            }
            _ => false,
        }
    }

    fn resolve_return_expr_from_defs(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > MAX_PREDICATE_OPERAND_DEPTH {
            return None;
        }

        match expr {
            CExpr::Paren(inner) => self.resolve_return_expr_from_defs(inner, depth + 1, visited),
            CExpr::Cast { ty, expr: inner } => self
                .resolve_return_expr_from_defs(inner, depth + 1, visited)
                .map(|resolved| CExpr::cast(ty.clone(), resolved)),
            CExpr::Var(name) => {
                if !visited.insert(name.clone()) {
                    return None;
                }

                let resolved = self.best_visible_definition(name).and_then(|def| {
                    if def == CExpr::Var(name.clone()) {
                        return None;
                    }
                    self.resolve_return_expr_from_defs(&def, depth + 1, visited)
                        .or(Some(def))
                });

                visited.remove(name);
                resolved
            }
            _ => None,
        }
    }

    fn resolve_return_target_expr(
        &self,
        target_expr: CExpr,
        last_ret_value: Option<CExpr>,
    ) -> CExpr {
        let mut best = Some(target_expr.clone());
        let mut visited = HashSet::new();
        if let Some(resolved) = self.resolve_return_expr_from_defs(&target_expr, 0, &mut visited)
            && resolved != target_expr
        {
            best = self.choose_preferred_visible_expr(best, Some(resolved));
        }

        if let Some(last) = last_ret_value
            && (self.is_predicate_like_expr(&last)
                || self.is_low_level_return_artifact(&target_expr)
                || self.is_uninitialized_return_reg(&target_expr)
                || best
                    .as_ref()
                    .is_some_and(|current| self.prefers_visible_expr(current, &last)))
        {
            best = self.choose_preferred_visible_expr(best, Some(last));
        }

        best.unwrap_or(target_expr)
    }

    pub(super) fn lookup_definition(&self, name: &str) -> Option<CExpr> {
        self.lookup_definition_with_depth(name, 0, &mut HashSet::new())
    }

    fn lookup_definition_with_depth(
        &self,
        name: &str,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > MAX_SIMPLE_EXPR_DEPTH || !visited.insert(name.to_string()) {
            return None;
        }

        let mut best = self.lookup_definition_raw(name);

        if let Some(prov) = self.forwarded_values_map().get(name) {
            let resolved = self
                .lookup_definition_with_depth(&prov.source, depth + 1, visited)
                .or_else(|| Some(self.expr_for_ssa_fallback_name(&prov.source)));
            best = self.choose_preferred_visible_expr(best, resolved);
        }

        let rendered = self
            .find_ssa_name_for_rendered_alias(name)
            .and_then(|ssa_name| self.lookup_definition_with_depth(&ssa_name, depth + 1, visited));
        best = self.choose_preferred_visible_expr(best, rendered);
        visited.remove(name);
        best
    }

    fn lookup_definition_raw(&self, name: &str) -> Option<CExpr> {
        let mut best = None;
        if let Some(expr) = self.definitions_map().get(name) {
            best = self.choose_preferred_visible_expr(best, Some(expr.clone()));
        }
        let lower = name.to_lowercase();
        if let Some(expr) = self.definitions_map().get(&lower) {
            best = self.choose_preferred_visible_expr(best, Some(expr.clone()));
        }
        if let Some((base, version)) = name.rsplit_once('_') {
            let lower = format!("{}_{}", base.to_lowercase(), version);
            if let Some(expr) = self.definitions_map().get(&lower) {
                best = self.choose_preferred_visible_expr(best, Some(expr.clone()));
            }
            let upper = format!("{}_{}", base.to_uppercase(), version);
            if let Some(expr) = self.definitions_map().get(&upper) {
                best = self.choose_preferred_visible_expr(best, Some(expr.clone()));
            }
        }
        best
    }

    fn find_ssa_name_for_rendered_alias(&self, name: &str) -> Option<String> {
        self.var_aliases_map()
            .iter()
            .find(|(_, alias)| alias.eq_ignore_ascii_case(name))
            .map(|(ssa_name, _)| ssa_name.clone())
    }

    fn expr_for_ssa_fallback_name(&self, ssa_name: &str) -> CExpr {
        if parse_const_value(ssa_name).is_some() {
            return CExpr::Var(ssa_name.to_string());
        }
        if let Some(alias) = self.var_aliases_map().get(ssa_name) {
            return CExpr::Var(alias.clone());
        }
        CExpr::Var(ssa_name.to_string())
    }

    fn scale_to_elem_size(&self, scale: i64) -> Option<u32> {
        let abs = scale.checked_abs()? as u64;
        if abs == 0 {
            return None;
        }
        u32::try_from(abs).ok()
    }

    /// Convert a block to folded C statements.
    pub fn fold_block(&self, block: &SSABlock, current_block_addr: u64) -> Vec<CStmt> {
        self.current_block_addr.set(Some(current_block_addr));
        let mut stmts = Vec::new();
        let mut last_ret_value: Option<CExpr> = None;

        for (op_idx, op) in block.ops.iter().enumerate() {
            // Skip stack frame setup/teardown if enabled
            if self.is_stack_frame_op(op) {
                continue;
            }

            match op {
                SSAOp::Copy { dst, src }
                    if self
                        .inputs
                        .arch
                        .is_return_register_name(&dst.name.to_lowercase()) =>
                {
                    last_ret_value = Some(self.get_return_expr(src));
                }
                SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src }
                | SSAOp::Trunc { dst, src }
                | SSAOp::Cast { dst, src }
                    if self
                        .inputs
                        .arch
                        .is_return_register_name(&dst.name.to_lowercase()) =>
                {
                    let ty = type_from_size(dst.size);
                    last_ret_value = Some(CExpr::cast(ty, self.get_return_expr(src)));
                }
                _ => {
                    if let Some(dst) = op.dst()
                        && self
                            .inputs
                            .arch
                            .is_return_register_name(&dst.name.to_lowercase())
                    {
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

            if let SSAOp::Return { target } = op {
                let unresolved = self.get_expr(target);
                let target_expr = self
                    .choose_preferred_visible_expr(
                        Some(unresolved.clone()),
                        self.best_visible_definition(&target.display_name()),
                    )
                    .unwrap_or(unresolved);
                let expr = self.resolve_return_target_expr(target_expr, last_ret_value.clone());
                let rewritten = self.rewrite_stack_expr(expr.clone());
                let final_expr = self.sanitize_final_return_expr(rewritten, expr);
                stmts.push(CStmt::Return(Some(final_expr)));
                break;
            }

            // In return-context blocks, keep return-register writes as tracking-only.
            // Emit a single high-level return at the SSA Return terminator.
            if self.is_current_return_block()
                && let Some(dst) = op.dst()
                && self
                    .inputs
                    .arch
                    .is_return_register_name(&dst.name.to_lowercase())
            {
                continue;
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

        if self.is_current_return_block()
            && !stmts.iter().any(|stmt| matches!(stmt, CStmt::Return(_)))
            && let Some(expr) = last_ret_value
        {
            let rewritten = self.rewrite_stack_expr(expr.clone());
            let final_expr = self.sanitize_final_return_expr(rewritten, expr);
            stmts.push(CStmt::Return(Some(final_expr)));
        }

        let stmts = self.propagate_ephemeral_copies(stmts);
        let out = self.prune_dead_temp_assignments(stmts);
        self.current_block_addr.set(None);
        out
    }

    fn op_to_stmt_impl(&self, op: &SSAOp) -> Option<CStmt> {
        match op {
            SSAOp::Copy { dst, src } => {
                if self.is_entry_arg_alias_copy(dst, src) {
                    return None;
                }
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs_base = self.get_expr(src);
                let rhs = self.resolve_predicate_rhs_for_var(src, rhs_base);
                let rhs = self.assignment_rhs_with_type_policy(dst, Some(src), rhs);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Load { dst, addr, .. } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let elem_ty = self
                    .type_hint_for_var(dst)
                    .unwrap_or_else(|| type_from_size(dst.size));
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
                            self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                        }
                    } else {
                        let addr_expr = self.get_expr(addr);
                        self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                    }
                } else if let Some(stack_var) = self.stack_var_for_addr_var(addr) {
                    CExpr::Var(stack_var)
                } else {
                    // Try to use stack variable name if this is a stack access
                    let addr_expr = self.get_expr(addr);
                    if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                        CExpr::Var(stack_var)
                    } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                        sub
                    } else if let Some(member) = self.try_member_access_from_expr(addr, &addr_expr)
                    {
                        member
                    } else {
                        self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                    }
                };
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Store { addr, val, .. } => {
                let elem_ty = self
                    .type_hint_for_var(val)
                    .unwrap_or_else(|| type_from_size(val.size));
                // Try to resolve ram: address to a global symbol name directly
                let lhs = if addr.name.starts_with("ram:") {
                    if let Some(address) = extract_call_address(&addr.name) {
                        if let Some(sym) = self.lookup_symbol(address) {
                            CExpr::Var(sym.clone())
                        } else {
                            let addr_expr = self.get_expr(addr);
                            self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                        }
                    } else {
                        let addr_expr = self.get_expr(addr);
                        self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                    }
                } else if let Some(stack_var) = self.stack_var_for_addr_var(addr) {
                    CExpr::Var(stack_var)
                } else {
                    // Try to use stack variable name if this is a stack access
                    let addr_expr = self.get_expr(addr);
                    if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                        CExpr::Var(stack_var)
                    } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                        sub
                    } else if let Some(member) = self.try_member_access_from_expr(addr, &addr_expr)
                    {
                        member
                    } else {
                        self.typed_deref_expr(addr, addr_expr, elem_ty.clone())
                    }
                };
                let mut rhs = self.get_expr(val);
                if let Some(val_ty) = self.type_hint_for_var(val)
                    && matches!(val_ty, CType::Pointer(_))
                    && !self.looks_like_pointer(&rhs)
                {
                    rhs = CExpr::cast(val_ty, rhs);
                }
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Fence { ordering } => Some(CStmt::Expr(CExpr::call(
                CExpr::Var("memory_fence".to_string()),
                vec![CExpr::StringLit(memory_ordering_name(ordering).to_string())],
            ))),
            SSAOp::LoadLinked {
                dst,
                space,
                addr,
                ordering,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let call = CExpr::call(
                    CExpr::Var("load_linked".to_string()),
                    vec![
                        CExpr::StringLit(space.clone()),
                        self.get_expr(addr),
                        CExpr::StringLit(memory_ordering_name(ordering).to_string()),
                    ],
                );
                Some(CStmt::Expr(CExpr::assign(lhs, call)))
            }
            SSAOp::StoreConditional {
                result,
                space,
                addr,
                val,
                ordering,
            } => {
                let call = CExpr::call(
                    CExpr::Var("store_conditional".to_string()),
                    vec![
                        CExpr::StringLit(space.clone()),
                        self.get_expr(addr),
                        self.get_expr(val),
                        CExpr::StringLit(memory_ordering_name(ordering).to_string()),
                    ],
                );
                if let Some(dst) = result {
                    let lhs = CExpr::Var(self.var_name(dst));
                    Some(CStmt::Expr(CExpr::assign(lhs, call)))
                } else {
                    Some(CStmt::Expr(call))
                }
            }
            SSAOp::AtomicCAS {
                dst,
                space,
                addr,
                expected,
                replacement,
                ordering,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let call = CExpr::call(
                    CExpr::Var("atomic_cas".to_string()),
                    vec![
                        CExpr::StringLit(space.clone()),
                        self.get_expr(addr),
                        self.get_expr(expected),
                        self.get_expr(replacement),
                        CExpr::StringLit(memory_ordering_name(ordering).to_string()),
                    ],
                );
                Some(CStmt::Expr(CExpr::assign(lhs, call)))
            }
            SSAOp::LoadGuarded {
                dst,
                space,
                addr,
                guard,
                ordering,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let call = CExpr::call(
                    CExpr::Var("load_guarded".to_string()),
                    vec![
                        CExpr::StringLit(space.clone()),
                        self.get_expr(addr),
                        self.get_expr(guard),
                        CExpr::StringLit(memory_ordering_name(ordering).to_string()),
                    ],
                );
                Some(CStmt::Expr(CExpr::assign(lhs, call)))
            }
            SSAOp::StoreGuarded {
                space,
                addr,
                val,
                guard,
                ordering,
            } => Some(CStmt::Expr(CExpr::call(
                CExpr::Var("store_guarded".to_string()),
                vec![
                    CExpr::StringLit(space.clone()),
                    self.get_expr(addr),
                    self.get_expr(val),
                    self.get_expr(guard),
                    CExpr::StringLit(memory_ordering_name(ordering).to_string()),
                ],
            ))),
            SSAOp::IntAdd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Add),
            SSAOp::IntSub { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Sub),
            SSAOp::IntMult { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Mul),
            SSAOp::IntDiv { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Div,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSDiv { dst, a, b } => {
                self.binary_stmt_typed(dst, a, b, BinaryOp::Div, Some(type_from_size(dst.size)))
            }
            SSAOp::IntRem { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Mod,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSRem { dst, a, b } => {
                self.binary_stmt_typed(dst, a, b, BinaryOp::Mod, Some(type_from_size(dst.size)))
            }
            SSAOp::IntAnd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitAnd),
            SSAOp::IntOr { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitOr),
            SSAOp::IntXor { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitXor),
            SSAOp::IntLeft { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Shl),
            SSAOp::IntRight { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Shr,
                Some(uint_type_from_size(dst.size)),
            ),
            SSAOp::IntSRight { dst, a, b } => {
                self.binary_stmt_typed(dst, a, b, BinaryOp::Shr, Some(type_from_size(dst.size)))
            }
            SSAOp::IntLess { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Lt,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLess { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Lt,
                Some(type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntLessEqual { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Le,
                Some(uint_type_from_size(a.size.max(b.size))),
            ),
            SSAOp::IntSLessEqual { dst, a, b } => self.binary_stmt_typed(
                dst,
                a,
                b,
                BinaryOp::Le,
                Some(type_from_size(a.size.max(b.size))),
            ),
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
                let rhs = self.resolve_predicate_rhs_for_var(
                    dst,
                    CExpr::unary(UnaryOp::Not, self.get_expr(src)),
                );
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs =
                    self.resolve_predicate_rhs_for_var(dst, CExpr::cast(ty, self.get_expr(src)));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Trunc { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs =
                    self.resolve_predicate_rhs_for_var(dst, CExpr::cast(ty, self.get_expr(src)));
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
            SSAOp::FloatAdd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Add),
            SSAOp::FloatSub { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Sub),
            SSAOp::FloatMult { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Mul),
            SSAOp::FloatDiv { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Div),
            SSAOp::FloatNeg { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::unary(UnaryOp::Neg, self.get_expr(src));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatAbs { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("fabs".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatSqrt { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("sqrt".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatCeil { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("ceil".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatFloor { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("floor".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatRound { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("round".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatNaN { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::call(CExpr::Var("isnan".to_string()), vec![self.get_expr(src)]);
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatLess { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Lt),
            SSAOp::FloatLessEqual { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Le),
            SSAOp::FloatEqual { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Eq),
            SSAOp::FloatNotEqual { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Ne),
            SSAOp::Int2Float { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::cast(CType::Float(dst.size), self.get_expr(src));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Float2Int { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::cast(type_from_size(dst.size), self.get_expr(src));
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::FloatFloat { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::cast(CType::Float(dst.size), self.get_expr(src));
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
                let rhs = self.resolve_predicate_rhs_for_var(
                    dst,
                    CExpr::cast(type_from_size(dst.size), self.get_expr(src)),
                );
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Return { target } => Some(CStmt::Return(Some(
                self.rewrite_stack_expr(self.get_expr(target)),
            ))),
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
        self.binary_stmt_typed(dst, a, b, op, None)
    }

    fn binary_stmt_typed(
        &self,
        dst: &SSAVar,
        a: &SSAVar,
        b: &SSAVar,
        op: BinaryOp,
        operand_ty: Option<CType>,
    ) -> Option<CStmt> {
        let lhs = CExpr::Var(self.var_name(dst));
        let mut lhs_expr = self.get_expr(a);
        let mut rhs_expr = self.get_expr(b);
        if let Some(ty) = operand_ty {
            let a_hint = self.type_hint_for_var(a);
            let b_hint = self.type_hint_for_var(b);
            lhs_expr = self.cast_expr_if_needed(lhs_expr, ty.clone(), a_hint.as_ref());
            rhs_expr = self.cast_expr_if_needed(rhs_expr, ty, b_hint.as_ref());
        }
        let rhs_raw = self.identity_simplify_binary(
            op,
            lhs_expr,
            rhs_expr,
            (dst.size > 0).then_some(dst.size),
        );
        let rhs = if matches!(
            op,
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
        ) {
            self.resolve_predicate_rhs_for_var(dst, rhs_raw)
        } else {
            rhs_raw
        };
        let rhs = self.assignment_rhs_with_type_policy(dst, None, rhs);
        self.assign_stmt(lhs, rhs)
    }

    fn boolean_stmt(&self, dst: &SSAVar, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> Option<CStmt> {
        let lhs = CExpr::Var(self.var_name(dst));
        let rhs = self.resolve_predicate_rhs_for_var(
            dst,
            CExpr::binary(op, self.get_expr(a), self.get_expr(b)),
        );
        self.assign_stmt(lhs, rhs)
    }
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
        return u64::from_str_radix(hex, 16).ok();
    }

    if val_str.chars().all(|c| c.is_ascii_hexdigit()) {
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

pub(super) fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

pub(crate) fn should_replace_preserved_stack_alias(existing: &str) -> bool {
    existing == "stack"
        || existing.starts_with("local_")
        || existing.starts_with("stack_")
        || existing == "saved_fp"
}

fn should_replace_preserved_stack_expr(existing: &CExpr, preserved: &CExpr) -> bool {
    match (existing, preserved) {
        (CExpr::Var(existing_name), CExpr::Var(preserved_name)) => {
            should_replace_preserved_stack_alias(existing_name)
                && !should_replace_preserved_stack_alias(preserved_name)
        }
        _ => false,
    }
}

fn normalize_stack_definition_overrides(stack_info: &mut analysis::StackInfo) {
    let replacements: Vec<(String, CExpr)> = stack_info
        .definition_overrides
        .iter()
        .filter_map(|(key, expr)| {
            let CExpr::Var(name) = expr else {
                return None;
            };
            let offset = if let Some(rest) = name.strip_prefix("local_") {
                i64::from_str_radix(rest, 16).ok().map(|v| -v)
            } else if let Some(rest) = name.strip_prefix("stack_") {
                i64::from_str_radix(rest, 16).ok()
            } else {
                None
            }?;
            let preferred = stack_info.stack_vars.get(&offset)?;
            if should_replace_preserved_stack_alias(name)
                && !should_replace_preserved_stack_alias(preferred)
            {
                Some((key.clone(), CExpr::Var(preferred.clone())))
            } else {
                None
            }
        })
        .collect();
    for (key, expr) in replacements {
        stack_info.definition_overrides.insert(key, expr);
    }
}

fn normalize_callee_name(name: &str) -> String {
    let mut normalized = name.trim().to_ascii_lowercase();

    for prefix in ["sym.imp.", "sym.", "imp.", "dbg.", "fcn."] {
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
    if let Some((base, suffix)) = normalized.rsplit_once('_')
        && !base.is_empty()
        && !suffix.is_empty()
        && suffix.chars().all(|ch| ch.is_ascii_digit())
    {
        normalized = base.to_string();
    }

    normalized
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
        if let Some(dec) = addr_str
            .strip_prefix("0d")
            .or_else(|| addr_str.strip_prefix("0D"))
        {
            return dec.parse().ok();
        }
        if let Some(hex) = addr_str
            .strip_prefix("0x")
            .or_else(|| addr_str.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).ok();
        }
        // Plain const payloads are interpreted as addresses in hex form.
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

fn memory_ordering_name(ordering: &r2il::MemoryOrdering) -> &'static str {
    match ordering {
        r2il::MemoryOrdering::Relaxed => "relaxed",
        r2il::MemoryOrdering::Acquire => "acquire",
        r2il::MemoryOrdering::Release => "release",
        r2il::MemoryOrdering::AcqRel => "acq_rel",
        r2il::MemoryOrdering::SeqCst => "seq_cst",
        r2il::MemoryOrdering::Unknown => "unknown",
    }
}

#[cfg(test)]
#[path = "../tests/lowering.rs"]
mod lowering_tests;

include!("../tests/pipeline.rs");
