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
    MAX_ALIAS_REWRITE_DEPTH, MAX_PREDICATE_OPERAND_DEPTH, MAX_RETURN_EXPR_DEPTH,
    MAX_RETURN_INLINE_CANDIDATE_DEPTH, MAX_RETURN_INLINE_DEPTH, MAX_SIMPLE_EXPR_DEPTH,
};

mod aliases;
mod calls;
mod lowering;
mod memory_renderer;
mod return_resolver;

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
    const MAX_SEMANTIC_RENDER_DEPTH: u32 = 8;

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
    pub(crate) fn semantic_values_map(&self) -> &HashMap<String, analysis::SemanticValue> {
        &self.use_info().semantic_values
    }
    pub(crate) fn frame_slot_merges_map(
        &self,
    ) -> &HashMap<String, analysis::FrameSlotMergeSummary> {
        &self.use_info().frame_slot_merges
    }
    pub(crate) fn formatted_defs_map(&self) -> &HashMap<String, CExpr> {
        &self.use_info().formatted_defs
    }
    pub(crate) fn copy_sources_map(&self) -> &HashMap<String, String> {
        &self.use_info().copy_sources
    }
    #[allow(dead_code)]
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
        self.state.return_stack_slots.clear();
        self.state.analysis_ctx.use_info.frame_slot_merges.clear();
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

            self.detect_return_stack_slots(func, exit_addr);
        }
        let type_hints = self.state.analysis_ctx.use_info.type_hints.clone();
        let env = analysis::PassEnv {
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
            type_hints: &type_hints,
            type_oracle: self.inputs.type_oracle,
        };
        analysis::use_info::populate_frame_slot_merges(
            &mut self.state.analysis_ctx.use_info,
            func,
            &env,
        );
    }

    fn detect_return_stack_slots(&mut self, func: &SSAFunction, exit_addr: u64) {
        let Some(exit_block) = func.get_block(exit_addr) else {
            return;
        };
        let pure_control_exit = exit_block.ops.iter().all(
            |op| matches!(op, SSAOp::Return { target } if self.is_control_return_target(target)),
        );
        let exit_loaded_slot = if pure_control_exit {
            None
        } else {
            self.return_stack_slot_loaded_before_control_return(exit_block)
        };
        if !pure_control_exit && exit_loaded_slot.is_none() {
            return;
        }

        let preds = func.predecessors(exit_addr);
        if preds.is_empty() {
            return;
        }

        let mut common_slot: Option<i64> = None;
        for pred_addr in preds {
            let Some(pred_block) = func.get_block(pred_addr) else {
                return;
            };
            let Some(slot) = self.return_stack_slot_written_before_exit(pred_block, exit_addr)
            else {
                return;
            };
            match common_slot {
                Some(existing) if existing != slot => return,
                None => common_slot = Some(slot),
                Some(_) => {}
            }
        }

        if let Some(exit_slot) = exit_loaded_slot
            && common_slot != Some(exit_slot)
        {
            return;
        }

        if let Some(slot) = common_slot.or(exit_loaded_slot) {
            self.state.return_stack_slots.insert(slot);
        }
    }

    fn return_stack_slot_written_before_exit(
        &self,
        block: &SSABlock,
        exit_addr: u64,
    ) -> Option<i64> {
        let mut branches_to_exit = false;
        for op in block.ops.iter().rev() {
            match op {
                SSAOp::Branch { target } => {
                    if self.extract_branch_target_address(target) == Some(exit_addr) {
                        branches_to_exit = true;
                    }
                }
                SSAOp::CBranch { target, .. } => {
                    if self.extract_branch_target_address(target) == Some(exit_addr) {
                        branches_to_exit = true;
                    }
                }
                SSAOp::Store { addr, .. } => {
                    if branches_to_exit || self.is_current_return_context_candidate(block.addr) {
                        let offset = self.stack_slot_offset_for_var(addr);
                        if offset.is_some() {
                            return offset;
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn return_stack_slot_loaded_before_control_return(&self, block: &SSABlock) -> Option<i64> {
        let mut loaded_slots = HashSet::new();
        let mut saw_control_return = false;

        for op in &block.ops {
            match op {
                SSAOp::Load { addr, .. } => {
                    if let Some(offset) = self.stack_slot_offset_for_var(addr) {
                        loaded_slots.insert(offset);
                    }
                }
                SSAOp::Return { target } => {
                    if !self.is_control_return_target(target) {
                        return None;
                    }
                    saw_control_return = true;
                }
                SSAOp::Copy { .. }
                | SSAOp::IntZExt { .. }
                | SSAOp::IntSExt { .. }
                | SSAOp::Trunc { .. }
                | SSAOp::Cast { .. }
                | SSAOp::IntAdd { .. }
                | SSAOp::IntCarry { .. }
                | SSAOp::IntSCarry { .. }
                | SSAOp::IntSLess { .. }
                | SSAOp::IntEqual { .. } => {}
                _ => return None,
            }
        }

        if !saw_control_return || loaded_slots.len() != 1 {
            return None;
        }

        loaded_slots.into_iter().next()
    }

    fn stack_slot_offset_for_var(&self, var: &SSAVar) -> Option<i64> {
        self.stack_slots_map()
            .get(&var.display_name())
            .map(|slot| slot.offset)
            .or_else(|| {
                analysis::utils::extract_stack_offset_from_var(
                    var,
                    self.definitions_map(),
                    &self.inputs.arch.fp_name,
                    &self.inputs.arch.sp_name,
                )
            })
    }

    fn is_current_return_context_candidate(&self, addr: u64) -> bool {
        self.state.return_blocks.contains(&addr)
    }

    /// Extract address from a branch target variable.
    fn extract_branch_target_address(&self, target: &SSAVar) -> Option<u64> {
        crate::address::parse_address_from_var_name(&target.name)
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

        let fallback = CExpr::Var(self.var_name(var));
        let mut semantic_visited = HashSet::new();
        if let Some(semantic) = self.render_semantic_value_by_name(&key, 0, &mut semantic_visited)
            && self.prefers_visible_expr(&fallback, &semantic)
        {
            return semantic;
        }

        // Try to inline if appropriate
        if self.should_inline(&key)
            && let Some(expr) = self.definitions_map().get(&key)
        {
            return expr.clone();
        }

        // Otherwise return a variable reference
        fallback
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
        let rhs = self.identity_simplify_expr(rhs);
        let mut semantic_visited = HashSet::new();
        let rhs = self.semanticize_visible_expr(&rhs, 0, &mut semantic_visited);
        let rhs = self.rewrite_stack_expr(rhs);
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

    fn lookup_semantic_value(&self, name: &str) -> Option<&analysis::SemanticValue> {
        self.semantic_values_map()
            .get(name)
            .or_else(|| self.semantic_values_map().get(&name.to_ascii_lowercase()))
            .or_else(|| {
                name.rsplit_once('_').and_then(|(base, version)| {
                    self.semantic_values_map()
                        .get(&format!("{}_{}", base.to_lowercase(), version))
                        .or_else(|| {
                            self.semantic_values_map().get(&format!(
                                "{}_{}",
                                base.to_uppercase(),
                                version
                            ))
                        })
                })
            })
    }

    fn render_semantic_value_by_name(
        &self,
        name: &str,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH || !visited.insert(format!("sem:{name}")) {
            return None;
        }
        let rendered = self
            .lookup_semantic_value(name)
            .and_then(|value| self.render_semantic_value(value, depth + 1, visited));
        visited.remove(&format!("sem:{name}"));
        rendered
    }

    pub(crate) fn render_semantic_value(
        &self,
        value: &analysis::SemanticValue,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        match value {
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Expr(expr)) => {
                Some(expr.clone())
            }
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(value)) => {
                self.render_value_ref(value, depth, visited)
            }
            analysis::SemanticValue::Address(shape) => {
                self.render_address_expr_from_addr(shape, depth, visited)
            }
            analysis::SemanticValue::Load { addr, size } => {
                self.render_load_from_addr(addr, *size, depth, visited)
            }
            analysis::SemanticValue::Unknown => None,
        }
    }

    fn render_value_ref(
        &self,
        value: &analysis::ValueRef,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }
        let name = value.display_name();
        let visit_key = format!("val:{name}");
        if !visited.insert(visit_key.clone()) {
            return None;
        }

        let forwarded = self.forwarded_source_var(&name).and_then(|source| {
            self.render_value_ref(&analysis::ValueRef::from(source), depth + 1, visited)
        });
        let fallback = if value.var.is_const() {
            Some(self.const_to_expr(&value.var))
        } else {
            let rendered = self.var_name(&value.var);
            Some(
                self.arg_alias_for_rendered_name(&rendered)
                    .map(CExpr::Var)
                    .unwrap_or_else(|| CExpr::Var(rendered)),
            )
        };
        let rendered = match self.lookup_semantic_value(&name) {
            Some(analysis::SemanticValue::Scalar(analysis::ScalarValue::Expr(expr))) => {
                self.render_scalar_value_ref(value, expr.clone(), fallback.clone())
            }
            Some(analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(root))) => {
                self.render_value_ref(root, depth + 1, visited)
            }
            Some(analysis::SemanticValue::Address(shape)) => {
                self.render_address_expr_from_addr(shape, depth + 1, visited)
            }
            Some(analysis::SemanticValue::Load { addr, size }) => {
                self.render_load_from_addr(addr, *size, depth + 1, visited)
            }
            Some(analysis::SemanticValue::Unknown) | None => self
                .lookup_definition(&name)
                .and_then(|expr| {
                    self.render_semantic_load_from_definition_expr(&expr, depth + 1, visited)
                })
                .or_else(|| {
                    self.definitions_map().get(&name).and_then(|expr| {
                        self.render_semantic_load_from_definition_expr(expr, depth + 1, visited)
                    })
                }),
        }
        .or(fallback);
        let rendered = self.choose_preferred_visible_expr(rendered, forwarded);

        visited.remove(&visit_key);
        rendered
    }

    fn render_semantic_load_from_definition_expr(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }
        match expr {
            CExpr::Deref(inner) => {
                let addr = self.normalized_addr_from_visible_expr(inner, depth + 1)?;
                self.render_load_from_addr(&addr, 0, depth + 1, visited)
            }
            CExpr::Cast { expr: inner, .. } | CExpr::Paren(inner) => {
                self.render_semantic_load_from_definition_expr(inner, depth + 1, visited)
            }
            _ => None,
        }
    }

    fn forwarded_source_var(&self, name: &str) -> Option<SSAVar> {
        let direct = || self.forwarded_values_map().get(name);
        let lower = || self.forwarded_values_map().get(&name.to_ascii_lowercase());
        let normalized = || {
            name.rsplit_once('_').and_then(|(base, version)| {
                self.forwarded_values_map()
                    .get(&format!("{}_{}", base.to_ascii_lowercase(), version))
                    .or_else(|| {
                        self.forwarded_values_map().get(&format!(
                            "{}_{}",
                            base.to_ascii_uppercase(),
                            version
                        ))
                    })
            })
        };
        direct()
            .or_else(lower)
            .or_else(normalized)
            .and_then(|prov| prov.source_var.clone())
            .filter(|src| src.display_name() != name)
    }

    fn render_base_ref_expr(
        &self,
        base: &analysis::BaseRef,
        as_address: bool,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        match base {
            analysis::BaseRef::Value(value) => self.render_value_ref(value, depth + 1, visited),
            analysis::BaseRef::StackSlot(offset) => {
                self.resolve_stack_var(*offset).map(CExpr::Var).map(|expr| {
                    if as_address {
                        CExpr::AddrOf(Box::new(expr))
                    } else {
                        expr
                    }
                })
            }
            analysis::BaseRef::Raw(expr) => Some(expr.clone()),
        }
    }

    fn render_scalar_value_ref(
        &self,
        value: &analysis::ValueRef,
        semantic: CExpr,
        fallback: Option<CExpr>,
    ) -> Option<CExpr> {
        if !value.var.is_const()
            && (matches!(semantic, CExpr::IntLit(0) | CExpr::UIntLit(0))
                || self.expr_contains_synthetic_stack_placeholder(&semantic)
                || self.is_uninitialized_return_reg(&semantic))
        {
            fallback
        } else {
            Some(semantic)
        }
    }

    fn expr_contains_synthetic_stack_placeholder(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_ascii_lowercase();
                lower == "stack" || lower == "saved_fp" || lower.starts_with("stack_")
            }
            CExpr::Paren(inner) | CExpr::AddrOf(inner) | CExpr::Deref(inner) => {
                self.expr_contains_synthetic_stack_placeholder(inner)
            }
            CExpr::Cast { expr: inner, .. } | CExpr::Unary { operand: inner, .. } => {
                self.expr_contains_synthetic_stack_placeholder(inner)
            }
            CExpr::Binary { left, right, .. } => {
                self.expr_contains_synthetic_stack_placeholder(left)
                    || self.expr_contains_synthetic_stack_placeholder(right)
            }
            CExpr::Subscript { base, index } => {
                self.expr_contains_synthetic_stack_placeholder(base)
                    || self.expr_contains_synthetic_stack_placeholder(index)
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                self.expr_contains_synthetic_stack_placeholder(base)
            }
            CExpr::Call { func, args } => {
                self.expr_contains_synthetic_stack_placeholder(func)
                    || args
                        .iter()
                        .any(|arg| self.expr_contains_synthetic_stack_placeholder(arg))
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                self.expr_contains_synthetic_stack_placeholder(cond)
                    || self.expr_contains_synthetic_stack_placeholder(then_expr)
                    || self.expr_contains_synthetic_stack_placeholder(else_expr)
            }
            CExpr::Comma(exprs) => exprs
                .iter()
                .any(|inner| self.expr_contains_synthetic_stack_placeholder(inner)),
            CExpr::Sizeof(inner) => self.expr_contains_synthetic_stack_placeholder(inner),
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::SizeofType(_) => false,
        }
    }

    fn render_address_expr_from_addr(
        &self,
        addr: &analysis::NormalizedAddr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }

        let mut expr = self.render_base_ref_expr(&addr.base, true, depth + 1, visited)?;
        if let Some(index) = &addr.index {
            let index_expr = self.render_value_ref(index, depth + 1, visited)?;
            let scaled = if addr.scale_bytes.unsigned_abs() <= 1 {
                index_expr
            } else {
                CExpr::binary(
                    BinaryOp::Mul,
                    index_expr,
                    CExpr::IntLit(addr.scale_bytes.unsigned_abs() as i64),
                )
            };
            expr = CExpr::binary(
                if addr.scale_bytes < 0 {
                    BinaryOp::Sub
                } else {
                    BinaryOp::Add
                },
                expr,
                scaled,
            );
        }
        if addr.offset_bytes != 0 {
            expr = CExpr::binary(
                if addr.offset_bytes < 0 {
                    BinaryOp::Sub
                } else {
                    BinaryOp::Add
                },
                expr,
                CExpr::IntLit(addr.offset_bytes.unsigned_abs() as i64),
            );
        }
        Some(expr)
    }

    fn oracle_field_name_for_addr(&self, addr: &analysis::NormalizedAddr) -> Option<String> {
        if addr.offset_bytes < 0 {
            return None;
        }
        let analysis::BaseRef::Value(base_ref) = &addr.base else {
            return None;
        };
        let offset = addr.offset_bytes as u64;

        if let Some(oracle) = self.inputs.type_oracle
            && let Some(field) = oracle
                .field_name(oracle.type_of(&base_ref.var), offset)
                .map(|field| field.to_string())
        {
            return Some(field);
        }

        let mut visited = HashSet::new();
        if let Some(root) = self.semantic_root_var(&base_ref.var, 0, &mut visited) {
            if let Some(oracle) = self.inputs.type_oracle
                && let Some(field) = oracle
                    .field_name(oracle.type_of(&root), offset)
                    .map(|field| field.to_string())
            {
                return Some(field);
            }
            if let Some(field) = self
                .field_name_from_type_hint_for_var(&root, offset)
                .or_else(|| self.field_name_from_type_hint_for_var(&base_ref.var, offset))
            {
                return Some(field);
            }
        }

        if let Some(field) = self.field_name_from_type_hint_for_var(&base_ref.var, offset) {
            return Some(field);
        }

        None
    }

    fn field_name_from_type_hint_for_var(&self, var: &SSAVar, offset: u64) -> Option<String> {
        let hint = self.type_hint_for_var(var)?;
        self.field_name_from_type_hint(&hint, offset)
    }

    fn field_name_from_type_hint(&self, ty: &CType, offset: u64) -> Option<String> {
        match ty {
            CType::Pointer(inner) | CType::Array(inner, _) => {
                self.field_name_from_type_hint(inner, offset)
            }
            CType::Struct(name) => self.lookup_external_field_name(name, offset),
            CType::Union(name) => self.lookup_external_field_name(name, offset),
            _ => None,
        }
    }

    fn lookup_external_field_name(&self, type_name: &str, offset: u64) -> Option<String> {
        let key = type_name.trim().to_ascii_lowercase();
        if let Some(st) = self.inputs.external_type_db.structs.get(&key)
            && let Some(field) = st.fields.get(&offset)
        {
            return Some(field.name.clone());
        }
        if let Some(un) = self.inputs.external_type_db.unions.get(&key)
            && let Some(field) = un.fields.get(&offset)
        {
            return Some(field.name.clone());
        }
        None
    }

    fn semantic_root_var(
        &self,
        var: &SSAVar,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<SSAVar> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }
        let name = var.display_name();
        if !visited.insert(name.clone()) {
            return None;
        }

        let resolved = self
            .forwarded_source_var(&name)
            .and_then(|source| {
                self.semantic_root_var(&source, depth + 1, visited)
                    .or(Some(source))
            })
            .or_else(|| match self.lookup_semantic_value(&name) {
                Some(analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(root))) => self
                    .semantic_root_var(&root.var, depth + 1, visited)
                    .or_else(|| Some(root.var.clone())),
                Some(analysis::SemanticValue::Address(analysis::NormalizedAddr {
                    base: analysis::BaseRef::Value(root),
                    ..
                })) => self
                    .semantic_root_var(&root.var, depth + 1, visited)
                    .or_else(|| Some(root.var.clone())),
                _ => None,
            });

        visited.remove(&name);
        resolved
    }

    fn render_access_expr_from_addr(
        &self,
        addr: &analysis::NormalizedAddr,
        elem_size: u32,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        let raw_base_expr = self.render_base_ref_expr(&addr.base, false, depth + 1, visited)?;
        let effective_addr = if addr.index.is_none() {
            self.normalized_addr_from_visible_expr(&raw_base_expr, depth + 1)
                .and_then(|mut normalized| {
                    normalized.offset_bytes =
                        normalized.offset_bytes.checked_add(addr.offset_bytes)?;
                    Some(normalized)
                })
                .filter(|normalized| {
                    normalized.index.is_some()
                        || self.oracle_field_name_for_addr(normalized).is_some()
                })
                .unwrap_or_else(|| addr.clone())
        } else {
            addr.clone()
        };
        let base_expr = if effective_addr != *addr {
            self.render_base_ref_expr(&effective_addr.base, false, depth + 1, visited)
                .unwrap_or_else(|| raw_base_expr.clone())
        } else {
            raw_base_expr
        };
        let field_name = self
            .oracle_field_name_for_addr(&effective_addr)
            .or_else(|| {
                let mut normalized =
                    self.normalized_addr_from_visible_expr(&base_expr, depth + 1)?;
                normalized.offset_bytes = normalized
                    .offset_bytes
                    .checked_add(effective_addr.offset_bytes)?;
                self.oracle_field_name_for_addr(&normalized)
            })
            .or_else(|| self.oracle_member_name(None, &base_expr, effective_addr.offset_bytes));

        if let Some(index) = &effective_addr.index {
            let scale = effective_addr.scale_bytes.unsigned_abs() as u32;
            let index_expr = self.render_value_ref(index, depth + 1, visited)?;
            let index_expr = self
                .normalize_index_expr(&index_expr, 0)
                .unwrap_or(index_expr);
            let elem_ty =
                self.infer_elem_type_from_base_ref(&effective_addr.base, scale.max(elem_size));
            let normalized_base = self.normalize_pointer_base_expr(&base_expr, 0);
            let base_source_ty = self.expr_type_hint(&normalized_base);
            let base_cast = self.cast_expr_if_needed(
                normalized_base,
                CType::ptr(elem_ty),
                base_source_ty.as_ref(),
            );
            let index_final = if effective_addr.scale_bytes < 0 {
                CExpr::unary(UnaryOp::Neg, index_expr)
            } else {
                index_expr
            };
            let indexed = CExpr::Subscript {
                base: Box::new(base_cast),
                index: Box::new(index_final),
            };
            if let Some(field) = field_name {
                return Some(self.member_access_expr(indexed, field));
            }
            if effective_addr.offset_bytes == 0 {
                return Some(indexed);
            }
        }

        if let Some(field) = field_name {
            return Some(self.member_access_expr(base_expr, field));
        }

        if matches!(effective_addr.base, analysis::BaseRef::StackSlot(_))
            && effective_addr.index.is_none()
            && effective_addr.offset_bytes == 0
        {
            return Some(base_expr);
        }

        None
    }

    fn render_load_from_addr(
        &self,
        addr: &analysis::NormalizedAddr,
        elem_size: u32,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        self.render_access_expr_from_addr(addr, elem_size, depth, visited)
            .or_else(|| {
                self.render_address_expr_from_addr(addr, depth + 1, visited)
                    .map(|expr| CExpr::Deref(Box::new(expr)))
            })
    }

    fn value_ref_from_visible_expr(&self, expr: &CExpr) -> Option<analysis::ValueRef> {
        match expr {
            CExpr::Var(name) => {
                if self.stack_offset_for_visible_storage_name(name).is_some() {
                    return None;
                }
                self.ssa_var_for_visible_name(name)
                    .map(analysis::ValueRef::from)
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.value_ref_from_visible_expr(inner)
            }
            _ => None,
        }
    }

    fn extract_visible_scaled_index(
        &self,
        expr: &CExpr,
        depth: u32,
    ) -> Option<(analysis::ValueRef, i64)> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }

        match expr {
            CExpr::Binary {
                op: BinaryOp::Mul,
                left,
                right,
            } => {
                if let Some(scale) = self.literal_to_i64(right) {
                    return self
                        .value_ref_from_visible_expr(left)
                        .map(|index| (index, scale));
                }
                if let Some(scale) = self.literal_to_i64(left) {
                    return self
                        .value_ref_from_visible_expr(right)
                        .map(|index| (index, scale));
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
                self.value_ref_from_visible_expr(left)
                    .map(|index| (index, 1i64 << shift))
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.extract_visible_scaled_index(inner, depth + 1)
            }
            _ => self
                .value_ref_from_visible_expr(expr)
                .map(|index| (index, 1)),
        }
    }

    fn extract_visible_scaled_index_with_offset(
        &self,
        expr: &CExpr,
        depth: u32,
    ) -> Option<(analysis::ValueRef, i64, i64)> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }

        match expr {
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => {
                if let Some(delta) = self.literal_to_i64(right)
                    && let Some((index, scale, offset)) =
                        self.extract_visible_scaled_index_with_offset(left, depth + 1)
                {
                    return offset
                        .checked_add(delta)
                        .map(|combined| (index, scale, combined));
                }
                if let Some(delta) = self.literal_to_i64(left)
                    && let Some((index, scale, offset)) =
                        self.extract_visible_scaled_index_with_offset(right, depth + 1)
                {
                    return offset
                        .checked_add(delta)
                        .map(|combined| (index, scale, combined));
                }
                self.extract_visible_scaled_index(expr, depth + 1)
                    .map(|(index, scale)| (index, scale, 0))
            }
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => {
                if let Some(delta) = self.literal_to_i64(right)
                    && let Some((index, scale, offset)) =
                        self.extract_visible_scaled_index_with_offset(left, depth + 1)
                {
                    return offset
                        .checked_sub(delta)
                        .map(|combined| (index, scale, combined));
                }
                self.extract_visible_scaled_index(expr, depth + 1)
                    .map(|(index, scale)| (index, scale, 0))
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.extract_visible_scaled_index_with_offset(inner, depth + 1)
            }
            _ => self
                .extract_visible_scaled_index(expr, depth + 1)
                .map(|(index, scale)| (index, scale, 0)),
        }
    }

    fn normalized_addr_from_visible_expr(
        &self,
        expr: &CExpr,
        depth: u32,
    ) -> Option<analysis::NormalizedAddr> {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return None;
        }

        match expr {
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.normalized_addr_from_visible_expr(inner, depth + 1)
            }
            CExpr::Var(name) => {
                let mut semantic_visited = HashSet::new();
                if let Some(semantic) =
                    self.render_semantic_value_by_name(name, depth + 1, &mut semantic_visited)
                    && !matches!(&semantic, CExpr::Var(inner) if inner == name)
                    && let Some(addr) = self.normalized_addr_from_visible_expr(&semantic, depth + 1)
                {
                    return Some(addr);
                }
                if let Some(def) = self
                    .lookup_definition(name)
                    .or_else(|| self.definitions_map().get(name).cloned())
                    && !matches!(&def, CExpr::Var(inner) if inner == name)
                    && let Some(addr) = self.normalized_addr_from_visible_expr(&def, depth + 1)
                {
                    return Some(addr);
                }
                if let Some(offset) = self.stack_offset_for_visible_storage_name(name) {
                    return Some(analysis::NormalizedAddr {
                        base: analysis::BaseRef::StackSlot(offset),
                        index: None,
                        scale_bytes: 0,
                        offset_bytes: 0,
                    });
                }
                if let Some(var) = self.ssa_var_for_visible_name(name) {
                    return Some(analysis::NormalizedAddr {
                        base: analysis::BaseRef::Value(analysis::ValueRef::from(var)),
                        index: None,
                        scale_bytes: 0,
                        offset_bytes: 0,
                    });
                }
                None
            }
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => {
                if let Some(delta) = self.literal_to_i64(right)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                {
                    addr.offset_bytes = addr.offset_bytes.saturating_add(delta);
                    return Some(addr);
                }
                if let Some(delta) = self.literal_to_i64(left)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(right, depth + 1)
                {
                    addr.offset_bytes = addr.offset_bytes.saturating_add(delta);
                    return Some(addr);
                }
                if let Some((index, scale)) = self.extract_visible_scaled_index(right, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale;
                    return Some(addr);
                }
                if let Some((index, scale, offset)) =
                    self.extract_visible_scaled_index_with_offset(right, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale;
                    addr.offset_bytes = addr.offset_bytes.saturating_add(offset);
                    return Some(addr);
                }
                if let Some((index, scale)) = self.extract_visible_scaled_index(left, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(right, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale;
                    return Some(addr);
                }
                if let Some((index, scale, offset)) =
                    self.extract_visible_scaled_index_with_offset(left, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(right, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale;
                    addr.offset_bytes = addr.offset_bytes.saturating_add(offset);
                    return Some(addr);
                }
                None
            }
            CExpr::Binary {
                op: BinaryOp::Sub,
                left,
                right,
            } => {
                if let Some(delta) = self.literal_to_i64(right)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                {
                    addr.offset_bytes = addr.offset_bytes.saturating_sub(delta);
                    return Some(addr);
                }
                if let Some((index, scale)) = self.extract_visible_scaled_index(right, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale.saturating_neg();
                    return Some(addr);
                }
                if let Some((index, scale, offset)) =
                    self.extract_visible_scaled_index_with_offset(right, depth + 1)
                    && let Some(mut addr) = self.normalized_addr_from_visible_expr(left, depth + 1)
                    && addr.index.is_none()
                {
                    addr.index = Some(index);
                    addr.scale_bytes = scale.saturating_neg();
                    addr.offset_bytes = addr.offset_bytes.saturating_sub(offset);
                    return Some(addr);
                }
                None
            }
            _ => None,
        }
    }

    fn render_memory_access_by_name(
        &self,
        name: &str,
        elem_size: u32,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        let value = self.lookup_semantic_value(name)?;
        match value {
            analysis::SemanticValue::Load { addr, size } => {
                self.render_load_from_addr(addr, *size, depth, visited)
            }
            analysis::SemanticValue::Address(shape) => {
                self.render_load_from_addr(shape, elem_size, depth, visited)
            }
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Expr(expr)) => {
                Some(expr.clone())
            }
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(value_ref)) => {
                self.render_value_ref(value_ref, depth, visited)
            }
            analysis::SemanticValue::Unknown => None,
        }
    }

    fn infer_elem_type_from_base_ref(&self, base: &analysis::BaseRef, element_size: u32) -> CType {
        match base {
            analysis::BaseRef::Value(base_ref) => {
                if let Some(CType::Pointer(inner) | CType::Array(inner, _)) =
                    self.type_hint_for_var(&base_ref.var)
                {
                    return *inner;
                }
                if let Some(oracle) = self.inputs.type_oracle {
                    let mut visited = HashSet::new();
                    if let Some(root) = self.semantic_root_var(&base_ref.var, 0, &mut visited) {
                        if let Some(CType::Pointer(inner) | CType::Array(inner, _)) =
                            self.type_hint_for_var(&root)
                        {
                            return *inner;
                        }
                        let ty = oracle.type_of(&root);
                        if (oracle.is_array(ty) || oracle.is_pointer(ty))
                            && let Some(CType::Pointer(inner) | CType::Array(inner, _)) =
                                self.type_hint_for_var(&root)
                        {
                            return *inner;
                        }
                    }
                }
                self.infer_subscript_elem_type(&base_ref.var, element_size)
            }
            analysis::BaseRef::StackSlot(_) | analysis::BaseRef::Raw(_) => {
                uint_type_from_size(element_size)
            }
        }
    }

    fn guess_ssa_var_from_name(&self, name: &str) -> Option<SSAVar> {
        if self.stack_offset_for_visible_storage_name(name).is_some() {
            return None;
        }
        let (base, version) = name.rsplit_once('_')?;
        let version = version.parse::<u32>().ok()?;
        let base = base.to_ascii_lowercase();
        let size = self
            .lookup_type_hint(name)
            .and_then(|ty| ty.bits())
            .map(|bits| bits.div_ceil(8))
            .filter(|bytes| *bytes > 0)
            .unwrap_or(self.inputs.arch.ptr_size);
        Some(SSAVar::new(base, version, size))
    }

    fn ssa_var_for_visible_name(&self, name: &str) -> Option<SSAVar> {
        if self.stack_offset_for_visible_storage_name(name).is_some() {
            return None;
        }

        let infer_reg_size = |reg_name: &str| -> u32 {
            let lower = reg_name.to_ascii_lowercase();
            if let Some(ty) = self.lookup_type_hint(name)
                && let Some(bits) = ty.bits()
            {
                return bits.div_ceil(8).max(1);
            }
            if matches!(
                lower.as_str(),
                "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" | "eip"
            ) || (lower.starts_with('w') && lower[1..].chars().all(|ch| ch.is_ascii_digit()))
            {
                return 4;
            }
            self.inputs.arch.ptr_size
        };

        let semantic_var = |value: &analysis::SemanticValue| match value {
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(root)) => {
                Some(root.var.clone())
            }
            analysis::SemanticValue::Address(analysis::NormalizedAddr {
                base: analysis::BaseRef::Value(root),
                index: None,
                scale_bytes,
                offset_bytes,
            }) if *scale_bytes == 0 && *offset_bytes == 0 => Some(root.var.clone()),
            analysis::SemanticValue::Load { addr, .. } => match &addr.base {
                analysis::BaseRef::Value(root) => Some(root.var.clone()),
                _ => None,
            },
            _ => None,
        };

        if let Some(ssa_name) = self.find_ssa_name_for_rendered_alias(name) {
            if let Some(value) = self.lookup_semantic_value(&ssa_name)
                && let Some(var) = semantic_var(value)
            {
                return Some(var);
            }
            if let Some(prov) = self.forwarded_values_map().get(&ssa_name)
                && let Some(var) = &prov.source_var
            {
                return Some(var.clone());
            }
            if let Some(var) = self.guess_ssa_var_from_name(&ssa_name) {
                return Some(var);
            }
        }

        if let Some(value) = self.lookup_semantic_value(name)
            && let Some(var) = semantic_var(value)
        {
            return Some(var);
        }

        for (reg_name, alias) in self.inputs.param_register_aliases {
            if alias.eq_ignore_ascii_case(name) {
                return Some(SSAVar::new(reg_name, 0, infer_reg_size(reg_name)));
            }
        }

        if let Some(rest) = name.strip_prefix("arg")
            && let Ok(idx) = rest.parse::<usize>()
            && idx > 0
            && let Some(reg_name) = self.inputs.arch.arg_regs.get(idx - 1)
        {
            return Some(SSAVar::new(reg_name, 0, infer_reg_size(reg_name)));
        }

        if let Some(prov) = self.forwarded_values_map().get(name)
            && let Some(var) = &prov.source_var
        {
            return Some(var.clone());
        }
        self.guess_ssa_var_from_name(name)
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

    fn oracle_member_name(
        &self,
        addr: Option<&SSAVar>,
        base_expr: &CExpr,
        offset: i64,
    ) -> Option<String> {
        if offset < 0 {
            return None;
        }
        let offset = offset as u64;

        // Best-effort: prefer base pointer identities captured during analysis.
        if let Some(addr) = addr
            && let Some((base, mapped_offset)) = self.ptr_members_map().get(&addr.display_name())
            && *mapped_offset == offset as i64
        {
            if let Some(oracle) = self.inputs.type_oracle {
                let base_ty = oracle.type_of(base);
                if let Some(name) = oracle.field_name(base_ty, offset) {
                    return Some(name.to_string());
                }
            }
            if let Some(name) = self.field_name_from_type_hint_for_var(base, offset) {
                return Some(name);
            }
        }

        if let Some(addr) = addr
            && offset == 0
            && let Some(name) = self
                .inputs
                .type_oracle
                .and_then(|oracle| oracle.field_name(oracle.type_of(addr), offset))
        {
            return Some(name.to_string());
        }

        if let CExpr::Var(base_name) = base_expr
            && self
                .stack_offset_for_visible_storage_name(base_name)
                .is_none()
            && let Some(base_var) = self.ssa_var_for_visible_name(base_name)
        {
            if let Some(name) = self
                .inputs
                .type_oracle
                .and_then(|oracle| oracle.field_name(oracle.type_of(&base_var), offset))
            {
                return Some(name.to_string());
            }
            if let Some(name) = self.field_name_from_type_hint_for_var(&base_var, offset) {
                return Some(name);
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
                if let Some(oracle) = self.inputs.type_oracle {
                    let base_ty = oracle.type_of(base);
                    if let Some(name) = oracle.field_name(base_ty, offset) {
                        return Some(name.to_string());
                    }
                }
                if let Some(name) = self.field_name_from_type_hint_for_var(base, offset) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn stack_offset_for_visible_storage_name(&self, name: &str) -> Option<i64> {
        let lower = name.to_ascii_lowercase();
        if lower == "stack" {
            return Some(0);
        }
        if lower == "saved_fp" {
            return Some(0);
        }
        if let Some(rest) = lower.strip_prefix("stack_")
            && let Ok(offset) = i64::from_str_radix(rest, 16)
        {
            return Some(offset);
        }
        if let Some(rest) = lower.strip_prefix("local_")
            && let Ok(offset) = i64::from_str_radix(rest, 16)
        {
            return Some(offset);
        }
        if let Some(rest) = lower.strip_prefix("arg_")
            && let Ok(offset) = i64::from_str_radix(rest, 16)
        {
            return Some(-offset);
        }
        if let Some((offset, _)) = self
            .stack_vars_map()
            .iter()
            .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
        {
            return Some(*offset);
        }
        self.inputs
            .external_stack_vars
            .iter()
            .find(|(_, var)| var.name.eq_ignore_ascii_case(name))
            .map(|(offset, _)| *offset)
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
                if !self.is_low_signal_visible_name(name)
                    && !self.is_transient_visible_name(name)
                    && !self.is_non_index_pointer_expr(expr)
                    && self.is_semantic_index_expr(expr)
                {
                    return Some(expr.clone());
                }
                if let Some(inner) = self.lookup_definition(name)
                    && let Some(normalized) = self.normalize_index_expr(&inner, depth + 1)
                    && !self.is_non_index_pointer_expr(&normalized)
                {
                    return Some(normalized);
                }
                if self.lookup_definition(name).is_some() {
                    return None;
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
                    let lower = name.to_ascii_lowercase();
                    let stack_placeholder =
                        lower == "stack" || lower == "saved_fp" || lower.starts_with("stack_");
                    !name.starts_with("const:")
                        && !name.starts_with("ram:")
                        && (!stack_placeholder
                            && (self.stack_slots_map().get(name).is_none()
                                || lower.starts_with("local_")
                                || lower.starts_with("arg")))
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

        if let Some(alias) = self
            .inputs
            .param_register_aliases
            .get(&var.name.to_ascii_lowercase())
            && let Some(ty) = self.lookup_type_hint(alias)
        {
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
                if self.is_non_index_pointer_expr(index) {
                    quality.transient_reg_penalty -= 10;
                }
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
                    quality.zero_offset_penalty -= 10;
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
        let is_temp_family = |prefix: char| {
            lower
                .strip_prefix(prefix)
                .and_then(|rest| {
                    let (head, tail) = rest.split_once('_').unwrap_or((rest, ""));
                    head.chars().all(|ch| ch.is_ascii_digit()).then_some(tail)
                })
                .is_some_and(|tail| tail.is_empty() || tail.chars().all(|ch| ch.is_ascii_digit()))
        };
        lower.starts_with("tmp:")
            || lower.starts_with("const:")
            || lower.starts_with("ram:")
            || is_temp_family('t')
            || is_temp_family('v')
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
        let elem_size = elem_ty.bits().map(|bits| bits.div_ceil(8)).unwrap_or(0);
        if let Some(shape) = self.normalized_addr_from_visible_expr(&addr_expr, 0) {
            let mut visited = HashSet::new();
            if let Some(access) =
                self.render_access_expr_from_addr(&shape, elem_size, 0, &mut visited)
            {
                return access;
            }
        }
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
                    || lower == "pc"
                    || lower.starts_with("pc_")
                    || lower == "lr"
                    || lower.starts_with("lr_")
                    || lower == "ra"
                    || lower.starts_with("ra_")
                    || lower == "x30"
                    || lower.starts_with("x30_")
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
            && {
                let last = self.resolve_return_candidate(&last);
                self.is_predicate_like_expr(&last)
                    || self.is_low_level_return_artifact(&target_expr)
                    || self.is_uninitialized_return_reg(&target_expr)
                    || best
                        .as_ref()
                        .is_some_and(|current| self.prefers_visible_expr(current, &last))
            }
        {
            let last = self.resolve_return_candidate(&last);
            best = self.choose_preferred_visible_expr(best, Some(last));
        }

        best.unwrap_or(target_expr)
    }

    fn is_control_return_target(&self, target: &SSAVar) -> bool {
        let lower = target.name.to_ascii_lowercase();
        lower == "pc"
            || lower == "lr"
            || lower == "ra"
            || lower == "x30"
            || lower.starts_with("pc_")
            || lower.starts_with("lr_")
            || lower.starts_with("ra_")
            || lower.starts_with("x30_")
            || lower == "rip"
            || lower == "eip"
            || lower.starts_with("rip_")
            || lower.starts_with("eip_")
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

        let semantic = self.render_semantic_value_by_name(name, depth, visited);
        if semantic.is_some() {
            visited.remove(name);
            return semantic;
        }

        let mut best = self.lookup_definition_raw(name).map(|expr| {
            let semanticized = self.semanticize_visible_expr(&expr, depth + 1, visited);
            if self.prefers_visible_expr(&expr, &semanticized) {
                semanticized
            } else {
                expr
            }
        });

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

    fn semanticize_visible_expr(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > Self::MAX_SEMANTIC_RENDER_DEPTH {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(semantic) = self.render_semantic_value_by_name(name, depth + 1, visited)
                    && self.prefers_visible_expr(expr, &semantic)
                {
                    return semantic;
                }
                expr.clone()
            }
            CExpr::Deref(inner) => {
                if let CExpr::Var(name) = inner.as_ref()
                    && let Some(candidate) = self.semantic_deref_candidate_for_name(name)
                {
                    return candidate;
                }

                let semantic_inner = self.semanticize_visible_expr(inner, depth + 1, visited);
                if let Some(access) = self.render_memory_access_from_visible_expr(
                    &semantic_inner,
                    0,
                    depth + 1,
                    visited,
                ) {
                    return access;
                }
                CExpr::Deref(Box::new(semantic_inner))
            }
            CExpr::Cast { ty, expr: inner } => CExpr::cast(
                ty.clone(),
                self.semanticize_visible_expr(inner, depth + 1, visited),
            ),
            CExpr::Paren(inner) => CExpr::Paren(Box::new(self.semanticize_visible_expr(
                inner,
                depth + 1,
                visited,
            ))),
            CExpr::Unary { op, operand } => CExpr::unary(
                *op,
                self.semanticize_visible_expr(operand, depth + 1, visited),
            ),
            CExpr::Binary { op, left, right } => CExpr::binary(
                *op,
                self.semanticize_visible_expr(left, depth + 1, visited),
                self.semanticize_visible_expr(right, depth + 1, visited),
            ),
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => CExpr::Ternary {
                cond: Box::new(self.semanticize_visible_expr(cond, depth + 1, visited)),
                then_expr: Box::new(self.semanticize_visible_expr(then_expr, depth + 1, visited)),
                else_expr: Box::new(self.semanticize_visible_expr(else_expr, depth + 1, visited)),
            },
            CExpr::Call { func, args } => CExpr::Call {
                func: Box::new(self.semanticize_visible_expr(func, depth + 1, visited)),
                args: args
                    .iter()
                    .map(|arg| self.semanticize_visible_expr(arg, depth + 1, visited))
                    .collect(),
            },
            CExpr::Subscript { base, index } => CExpr::Subscript {
                base: Box::new(self.semanticize_visible_expr(base, depth + 1, visited)),
                index: Box::new(self.semanticize_visible_expr(index, depth + 1, visited)),
            },
            CExpr::Member { base, member } => CExpr::Member {
                base: Box::new(self.semanticize_visible_expr(base, depth + 1, visited)),
                member: member.clone(),
            },
            CExpr::PtrMember { base, member } => CExpr::PtrMember {
                base: Box::new(self.semanticize_visible_expr(base, depth + 1, visited)),
                member: member.clone(),
            },
            CExpr::Sizeof(inner) => CExpr::Sizeof(Box::new(self.semanticize_visible_expr(
                inner,
                depth + 1,
                visited,
            ))),
            CExpr::AddrOf(inner) => CExpr::AddrOf(Box::new(self.semanticize_visible_expr(
                inner,
                depth + 1,
                visited,
            ))),
            CExpr::Comma(items) => CExpr::Comma(
                items
                    .iter()
                    .map(|item| self.semanticize_visible_expr(item, depth + 1, visited))
                    .collect(),
            ),
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::SizeofType(_) => expr.clone(),
        }
    }

    /// Convert a block to folded C statements.
    pub fn fold_block(&self, block: &SSABlock, current_block_addr: u64) -> Vec<CStmt> {
        self.current_block_addr.set(Some(current_block_addr));
        if block.addr == self.state.exit_block.unwrap_or(0)
            && !self.state.return_stack_slots.is_empty()
        {
            self.current_block_addr.set(None);
            return Vec::new();
        }
        let mut stmts = Vec::new();
        let mut last_ret_value: Option<CExpr> = None;

        for (op_idx, op) in block.ops.iter().enumerate() {
            // Skip stack frame setup/teardown if enabled
            if self.is_stack_frame_op(op) {
                continue;
            }

            if let SSAOp::Store { addr, val, .. } = op
                && self.is_current_return_block()
                && let Some(offset) = self.stack_slot_offset_for_var(addr)
                && self.state.return_stack_slots.contains(&offset)
            {
                last_ret_value = self.preferred_return_candidate(
                    self.merged_return_candidate_for_block_slot(block.addr, offset),
                    Some(self.get_return_expr(val)),
                );
                continue;
            }

            if let SSAOp::Load { addr, .. } = op
                && block.addr == self.state.exit_block.unwrap_or(0)
                && self.is_current_return_block()
                && let Some(offset) = self.stack_slot_offset_for_var(addr)
                && self.state.return_stack_slots.contains(&offset)
            {
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
                        let mut semantic_visited = HashSet::new();
                        let semanticized =
                            self.semanticize_visible_expr(&expanded, 0, &mut semantic_visited);
                        let final_expr = if self.is_predicate_like_expr(&semanticized) {
                            self.simplify_condition_expr(semanticized)
                        } else {
                            semanticized
                        };
                        last_ret_value = Some(final_expr);
                    }
                }
            }

            if let SSAOp::Return { target } = op {
                if block.addr == self.state.exit_block.unwrap_or(0)
                    && self.is_control_return_target(target)
                    && !self.state.return_stack_slots.is_empty()
                {
                    break;
                }
                let unresolved = self.get_expr(target);
                let mut visited = HashSet::new();
                let target_expr = self
                    .choose_preferred_visible_expr(
                        self.render_semantic_value_by_name(&target.display_name(), 0, &mut visited),
                        Some(unresolved.clone()),
                    )
                    .and_then(|expr| {
                        self.choose_preferred_visible_expr(
                            Some(expr),
                            self.best_visible_definition(&target.display_name()),
                        )
                    })
                    .unwrap_or(unresolved);
                let expr = if self.is_control_return_target(target)
                    && let Some(last) = last_ret_value.clone()
                {
                    self.resolve_return_target_expr(last, None)
                } else {
                    self.resolve_return_target_expr(target_expr, last_ret_value.clone())
                };
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
                let rhs = self.render_canonical_load_expr(dst, addr, elem_ty.clone());
                self.assign_stmt(lhs, rhs)
            }
            SSAOp::Store { addr, val, .. } => {
                let elem_ty = self
                    .type_hint_for_var(val)
                    .unwrap_or_else(|| type_from_size(val.size));
                let lhs = self.render_canonical_store_target_expr(addr, val.size, elem_ty.clone());
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
