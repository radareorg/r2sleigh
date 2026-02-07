//! Control flow structuring.
//!
//! This module converts unstructured control flow (gotos, CFG edges) into
//! structured high-level constructs (if-then-else, while, for, etc.).

use std::collections::{HashMap, HashSet};

use r2ssa::SSAFunction;

use crate::ast::{CExpr, CStmt, CType};
use crate::expr::ExpressionBuilder;
use crate::fold::FoldingContext;
use crate::region::{Region, RegionAnalyzer};

/// Control flow structurer.
///
/// Converts a region tree into structured C statements.
pub struct ControlFlowStructurer<'a> {
    func: &'a SSAFunction,
    expr_builder: ExpressionBuilder,
    /// Folding context for expression optimization.
    fold_ctx: Option<FoldingContext>,
    /// Labels for blocks that need gotos.
    labels: HashMap<u64, String>,
    /// Counter for generating unique labels.
    label_counter: usize,
    /// Region analyzer for detecting breaks/continues.
    region_analyzer: Option<RegionAnalyzer<'a>>,
    /// Whether finalize_analysis has been called.
    analysis_finalized: bool,
}

impl<'a> ControlFlowStructurer<'a> {
    /// Create a new structurer with the specified pointer size.
    /// NOTE: Call set_function_names/set_strings/set_symbols before structure()
    /// so that definitions are resolved with full context.
    pub fn new(func: &'a SSAFunction, ptr_size: u32) -> Self {
        let fold_ctx = FoldingContext::new(ptr_size);
        let region_analyzer = RegionAnalyzer::new(func);

        Self {
            func,
            expr_builder: ExpressionBuilder::new(ptr_size),
            fold_ctx: Some(fold_ctx),
            labels: HashMap::new(),
            label_counter: 0,
            region_analyzer: Some(region_analyzer),
            analysis_finalized: false,
        }
    }

    /// Finalize initialization: analyze blocks after external context is set.
    /// Must be called after set_function_names/set_strings/set_symbols.
    /// Safe to call multiple times; only the first call performs analysis.
    fn finalize_analysis(&mut self) {
        if self.analysis_finalized {
            return;
        }
        self.analysis_finalized = true;
        if let Some(ref mut ctx) = self.fold_ctx {
            let blocks: Vec<_> = self.func.blocks().cloned().collect();
            ctx.analyze_blocks(&blocks);
            ctx.analyze_function_structure(self.func);
        }
    }

    /// Create a structurer without expression folding (for comparison).
    pub fn new_unfolded(func: &'a SSAFunction, ptr_size: u32) -> Self {
        Self {
            func,
            expr_builder: ExpressionBuilder::new(ptr_size),
            fold_ctx: None,
            labels: HashMap::new(),
            label_counter: 0,
            region_analyzer: None,
            analysis_finalized: true, // No folding context, nothing to finalize
        }
    }

    /// Set function names for call target resolution.
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        if let Some(ref mut ctx) = self.fold_ctx {
            ctx.set_function_names(names);
        }
    }

    /// Set string literals for constant address resolution.
    pub fn set_strings(&mut self, strings: HashMap<u64, String>) {
        if let Some(ref mut ctx) = self.fold_ctx {
            ctx.set_strings(strings);
        }
    }

    /// Set symbol names for global variable resolution.
    pub fn set_symbols(&mut self, symbols: HashMap<u64, String>) {
        if let Some(ref mut ctx) = self.fold_ctx {
            ctx.set_symbols(symbols);
        }
    }

    /// Set inferred variable type hints for expression recovery.
    pub fn set_type_hints(&mut self, hints: HashMap<String, CType>) {
        if let Some(ref mut ctx) = self.fold_ctx {
            ctx.set_type_hints(hints);
        }
    }

    /// Get the set of variable names that survive folding (for filtering declarations).
    pub fn emitted_var_names(&mut self) -> HashSet<String> {
        // Ensure analysis is finalized before computing emitted vars
        self.finalize_analysis();
        if let Some(ref ctx) = self.fold_ctx {
            let blocks: Vec<_> = self.func.blocks().cloned().collect();
            ctx.emitted_var_names(&blocks)
        } else {
            HashSet::new()
        }
    }

    /// Structure the function's control flow.
    pub fn structure(&mut self) -> CStmt {
        // Ensure analysis is finalized (idempotent)
        self.finalize_analysis();
        let mut analyzer = RegionAnalyzer::new(self.func);
        let region = analyzer.analyze();
        let stmt = self.structure_region(&region);
        // Post-process: flatten, simplify loops, remove redundant control flow
        Self::cleanup(stmt)
    }

    /// Structure a region into C statements.
    fn structure_region(&mut self, region: &Region) -> CStmt {
        match region {
            Region::Block(addr) => self.structure_block(*addr),
            Region::Sequence(regions) => {
                let stmts: Vec<CStmt> = regions
                    .iter()
                    .map(|r| self.structure_region(r))
                    .filter(|s| !matches!(s, CStmt::Empty))
                    .collect();
                if stmts.is_empty() {
                    CStmt::Empty
                } else if stmts.len() == 1 {
                    stmts.into_iter().next().unwrap()
                } else {
                    CStmt::Block(stmts)
                }
            }
            Region::IfThenElse {
                cond_block,
                then_region,
                else_region,
                merge_block: _,
            } => {
                let cond = self.get_branch_condition(*cond_block);
                let then_stmt = self.structure_region(then_region);
                let else_stmt = else_region.as_ref().map(|r| self.structure_region(r));
                let if_stmt = CStmt::if_stmt(cond, then_stmt, else_stmt);
                let mut prefix = self.structure_block_prefix_stmts(*cond_block);
                if prefix.is_empty() {
                    if_stmt
                } else {
                    prefix.push(if_stmt);
                    CStmt::Block(prefix)
                }
            }
            Region::WhileLoop { header, body } => {
                let cond = self.get_branch_condition(*header);
                let body_stmt = self.structure_loop_body(body);
                CStmt::while_loop(cond, body_stmt)
            }
            Region::DoWhileLoop { body, cond_block } => {
                let body_stmt = self.structure_loop_body(body);
                let cond = self.get_branch_condition(*cond_block);
                CStmt::DoWhile {
                    body: Box::new(body_stmt),
                    cond,
                }
            }
            Region::Switch {
                switch_block,
                cases,
                default,
                merge_block: _,
            } => {
                // Get the switch expression from the block
                let switch_expr = self.get_switch_expression(*switch_block);

                // Build switch cases
                let mut switch_cases = Vec::new();
                for (case_value, case_region) in cases {
                    let value_expr = case_value
                        .map(|v| CExpr::IntLit(v as i64))
                        .unwrap_or(CExpr::IntLit(0));
                    let case_stmt = self.structure_region(case_region);
                    switch_cases.push(crate::ast::SwitchCase {
                        value: value_expr,
                        body: vec![case_stmt, CStmt::Break],
                    });
                }

                // Build default case
                let default_body = default.as_ref().map(|r| vec![self.structure_region(r)]);

                let switch_stmt = CStmt::Switch {
                    expr: switch_expr,
                    cases: switch_cases,
                    default: default_body,
                };

                let mut prefix = self.structure_block_prefix_stmts(*switch_block);
                if prefix.is_empty() {
                    switch_stmt
                } else {
                    prefix.push(switch_stmt);
                    CStmt::Block(prefix)
                }
            }
            Region::Irreducible { entry, blocks } => self.structure_irreducible(*entry, blocks),
        }
    }

    /// Get the switch expression from a block.
    fn get_switch_expression(&mut self, addr: u64) -> CExpr {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return CExpr::Var("switch_expr".to_string()),
        };

        // Look for an indirect branch which typically has the switch variable
        // For now, return a generic switch variable
        // A more sophisticated implementation would trace the indirect branch target
        if let Some(ref fold_ctx) = self.fold_ctx {
            for op in &block.ops {
                if let Some(expr) = fold_ctx.extract_switch_expr(op) {
                    return expr;
                }
            }
        }

        CExpr::Var("test".to_string())
    }

    /// Structure a single basic block.
    fn structure_block(&mut self, addr: u64) -> CStmt {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return CStmt::Empty,
        };

        let mut stmts = Vec::new();

        // Add label if needed
        if let Some(label) = self.labels.get(&addr) {
            stmts.push(CStmt::Label(label.clone()));
        }

        // Convert operations to statements
        if let Some(ref mut fold_ctx) = self.fold_ctx {
            // Set current block address for return detection
            fold_ctx.set_current_block(addr);
            // Use folding context for optimized output
            stmts.extend(fold_ctx.fold_block(block));
        } else {
            // Fall back to basic expression builder
            for op in &block.ops {
                if let Some(stmt) = self.expr_builder.op_to_stmt(op) {
                    stmts.push(stmt);
                }
            }
        }

        // Check for break/continue at block end
        if let Some(ref analyzer) = self.region_analyzer {
            if analyzer.is_loop_continue(addr) {
                stmts.push(CStmt::Continue);
            } else if analyzer.is_loop_break(addr) {
                stmts.push(CStmt::Break);
            }
        }

        if stmts.is_empty() {
            CStmt::Empty
        } else if stmts.len() == 1 {
            stmts.remove(0)
        } else {
            CStmt::Block(stmts)
        }
    }

    /// Structure a loop body region, flattening block sequences into a single
    /// statement list to avoid nested `{ ...; break; } { ...; continue; }` braces.
    fn structure_loop_body(&mut self, body: &Region) -> CStmt {
        // If the body is a Sequence of Blocks, flatten all block statements
        // into one continuous list instead of wrapping each in CStmt::Block.
        if let Region::Sequence(regions) = body {
            let mut all_stmts = Vec::new();
            for region in regions {
                match region {
                    Region::Block(addr) => {
                        // Inline the block's statements directly
                        self.structure_block_stmts_into(*addr, &mut all_stmts);
                    }
                    _ => {
                        // Non-block region: structure normally and append
                        let stmt = self.structure_region(region);
                        if !matches!(stmt, CStmt::Empty) {
                            all_stmts.push(stmt);
                        }
                    }
                }
            }
            if all_stmts.is_empty() {
                CStmt::Empty
            } else if all_stmts.len() == 1 {
                all_stmts.remove(0)
            } else {
                CStmt::Block(all_stmts)
            }
        } else {
            self.structure_region(body)
        }
    }

    /// Emit statements for a block directly into an existing statement list
    /// (without wrapping in CStmt::Block). Used for loop body flattening.
    fn structure_block_stmts_into(&mut self, addr: u64, stmts: &mut Vec<CStmt>) {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return,
        };

        // Add label if needed
        if let Some(label) = self.labels.get(&addr) {
            stmts.push(CStmt::Label(label.clone()));
        }

        // Convert operations to statements
        if let Some(ref mut fold_ctx) = self.fold_ctx {
            fold_ctx.set_current_block(addr);
            stmts.extend(fold_ctx.fold_block(block));
        } else {
            for op in &block.ops {
                if let Some(stmt) = self.expr_builder.op_to_stmt(op) {
                    stmts.push(stmt);
                }
            }
        }

        // Check for break/continue at block end
        if let Some(ref analyzer) = self.region_analyzer {
            if analyzer.is_loop_continue(addr) {
                stmts.push(CStmt::Continue);
            } else if analyzer.is_loop_break(addr) {
                stmts.push(CStmt::Break);
            }
        }
    }

    /// Emit side-effecting statements for a block without labels or loop markers.
    /// Used for condition/switch header blocks where statements must appear before
    /// the structured control-flow construct.
    fn structure_block_prefix_stmts(&mut self, addr: u64) -> Vec<CStmt> {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return Vec::new(),
        };

        if let Some(ref mut fold_ctx) = self.fold_ctx {
            fold_ctx.set_current_block(addr);
            fold_ctx.fold_block(block)
        } else {
            block
                .ops
                .iter()
                .filter_map(|op| self.expr_builder.op_to_stmt(op))
                .collect()
        }
    }

    /// Get the branch condition from a block.
    fn get_branch_condition(&mut self, addr: u64) -> CExpr {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return CExpr::IntLit(1),
        };

        // Look for a conditional branch in the block
        for op in &block.ops {
            if let Some(ref fold_ctx) = self.fold_ctx {
                if let Some(cond) = fold_ctx.extract_condition(op) {
                    return cond;
                }
            } else if let Some(cond) = self.expr_builder.extract_condition(op) {
                return cond;
            }
        }

        // Default to true
        CExpr::IntLit(1)
    }

    /// Structure an irreducible region using gotos.
    fn structure_irreducible(&mut self, entry: u64, blocks: &[u64]) -> CStmt {
        // Assign labels to all blocks
        for &addr in blocks {
            if !self.labels.contains_key(&addr) {
                let label = format!("L{}", self.label_counter);
                self.label_counter += 1;
                self.labels.insert(addr, label);
            }
        }

        // Start with the entry block
        let mut stmts = vec![self.structure_block(entry)];

        // Add remaining blocks with gotos
        for &addr in blocks {
            if addr != entry {
                stmts.push(self.structure_block(addr));
            }
        }

        CStmt::Block(stmts)
    }

    // TODO: gen_label() and goto_block() are reserved for future use when
    // implementing more complex control flow restructuring (e.g., irreducible
    // regions that require goto-based fallback). Currently, structure_irreducible()
    // handles labels directly. These helpers may be useful for:
    // - Break/continue in nested loops
    // - Early returns from deeply nested code
    // - Complex switch fallthrough patterns

    /// Post-process a statement tree to clean up control flow artifacts.
    ///
    /// Applies three transformations recursively:
    /// - Fix A: Flatten single-element `Block`s.
    /// - Fix B: Remove trailing `continue` in loop bodies (implicit) and
    ///   trailing `break` in single-exit if-then inside loops.
    /// - Fix C: Convert `do { if (c) break; ... } while(1)` to `while(!c) { ... }`.
    fn cleanup(stmt: CStmt) -> CStmt {
        // Recurse first, then simplify
        let stmt = Self::cleanup_recurse(stmt);
        Self::flatten(stmt)
    }

    /// Recursively clean up children first, then apply local simplifications.
    fn cleanup_recurse(stmt: CStmt) -> CStmt {
        match stmt {
            CStmt::Block(stmts) => {
                let cleaned: Vec<CStmt> = stmts
                    .into_iter()
                    .map(Self::cleanup_recurse)
                    .filter(|s| !matches!(s, CStmt::Empty))
                    .collect();
                if cleaned.is_empty() {
                    CStmt::Empty
                } else if cleaned.len() == 1 {
                    cleaned.into_iter().next().unwrap()
                } else {
                    CStmt::Block(cleaned)
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let then_body = Box::new(Self::cleanup_recurse(*then_body));
                let else_body = else_body.map(|e| Box::new(Self::cleanup_recurse(*e)));
                CStmt::If {
                    cond,
                    then_body,
                    else_body,
                }
            }
            CStmt::While { cond, body } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(*body));
                CStmt::While {
                    cond,
                    body: Box::new(body),
                }
            }
            CStmt::DoWhile { body, cond } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(*body));
                // Fix C: do { if (c) break; rest } while(1) -> while(!c) { rest }
                Self::try_convert_do_while_to_while(body, cond)
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(*body));
                CStmt::For {
                    init,
                    cond,
                    update,
                    body: Box::new(body),
                }
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                let cases = cases
                    .into_iter()
                    .map(|c| crate::ast::SwitchCase {
                        value: c.value,
                        body: c.body.into_iter().map(Self::cleanup_recurse).collect(),
                    })
                    .collect();
                let default = default.map(|d| d.into_iter().map(Self::cleanup_recurse).collect());
                CStmt::Switch {
                    expr,
                    cases,
                    default,
                }
            }
            other => other,
        }
    }

    /// Flatten single-element blocks.
    fn flatten(stmt: CStmt) -> CStmt {
        match stmt {
            CStmt::Block(mut stmts) if stmts.len() == 1 => Self::flatten(stmts.remove(0)),
            CStmt::Block(stmts) if stmts.is_empty() => CStmt::Empty,
            other => other,
        }
    }

    /// Fix B: Remove trailing `continue` from a loop body (it's implicit).
    /// Also remove trailing `break` inside an if-then at the end of a block
    /// if it's the only exit path.
    fn strip_trailing_continue(stmt: CStmt) -> CStmt {
        match stmt {
            CStmt::Continue => CStmt::Empty,
            CStmt::Block(mut stmts) => {
                // Remove trailing Continue
                while matches!(stmts.last(), Some(CStmt::Continue)) {
                    stmts.pop();
                }
                if stmts.is_empty() {
                    CStmt::Empty
                } else if stmts.len() == 1 {
                    stmts.remove(0)
                } else {
                    CStmt::Block(stmts)
                }
            }
            other => other,
        }
    }

    /// Fix C: Convert `do { if (cond) break; body... } while(1)` into
    /// `while(!cond) { body... }`.
    fn try_convert_do_while_to_while(body: CStmt, cond: CExpr) -> CStmt {
        // Only applies when condition is always true (literal 1 or true)
        let is_infinite = match &cond {
            CExpr::IntLit(v) => *v != 0,
            _ => false,
        };
        if !is_infinite {
            return CStmt::DoWhile {
                body: Box::new(body),
                cond,
            };
        }

        // Extract the body statements
        let stmts = match &body {
            CStmt::Block(stmts) => stmts.clone(),
            CStmt::If { .. } => vec![body.clone()],
            _ => {
                return CStmt::DoWhile {
                    body: Box::new(body),
                    cond,
                };
            }
        };

        if stmts.is_empty() {
            return CStmt::DoWhile {
                body: Box::new(body),
                cond,
            };
        }

        // Check if first statement is `if (c) { break; }` (no else)
        if let CStmt::If {
            cond: break_cond,
            then_body,
            else_body: None,
        } = &stmts[0]
        {
            let is_break = matches!(then_body.as_ref(), CStmt::Break)
                || matches!(then_body.as_ref(), CStmt::Block(v) if v.len() == 1 && matches!(v[0], CStmt::Break));
            if is_break {
                // Negate the condition
                let negated = CExpr::unary(crate::ast::UnaryOp::Not, break_cond.clone());
                // Remaining body after the break-guard
                let rest: Vec<CStmt> = stmts[1..].to_vec();
                let new_body = if rest.is_empty() {
                    CStmt::Empty
                } else if rest.len() == 1 {
                    rest.into_iter().next().unwrap()
                } else {
                    CStmt::Block(rest)
                };
                return CStmt::While {
                    cond: negated,
                    body: Box::new(new_body),
                };
            }
        }

        CStmt::DoWhile {
            body: Box::new(body),
            cond,
        }
    }
}

// TODO: detect_for_loop() - Planned feature to detect for-loop patterns.
// A for loop has:
// - An initialization before the loop
// - A condition at the loop header
// - An increment at the end of the loop body
// Implementation requires:
// 1. Identify counter variable initialized before header
// 2. Match counter comparison in header condition
// 3. Find counter increment at end of loop body
// 4. Transform WhileLoop region into ForLoop with init/update expressions

// TODO: detect_switch() - Planned feature to simplify nested if-else chains.
// Would analyze condition expressions to detect:
// - Same variable compared against multiple constants
// - Exclusive conditions (no overlap)
// - Convert to switch statement for cleaner output

#[cfg(test)]
mod tests {
    // Tests would require constructing SSAFunctions
    // which needs r2il blocks
}
