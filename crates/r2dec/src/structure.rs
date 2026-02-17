//! Control flow structuring.
//!
//! This module converts unstructured control flow (gotos, CFG edges) into
//! structured high-level constructs (if-then-else, while, for, etc.).

use std::collections::{HashMap, HashSet};

use r2ssa::SSAFunction;

use crate::ast::{BinaryOp, CExpr, CStmt, UnaryOp};
use crate::fold::FoldingContext;
use crate::region::{Region, RegionAnalyzer};

/// Control flow structurer.
///
/// Converts a region tree into structured C statements.
pub struct ControlFlowStructurer<'a, 'o> {
    func: &'a SSAFunction,
    /// Folding context for expression optimization.
    fold_ctx: &'o FoldingContext<'o>,
    /// Labels for blocks that need gotos.
    labels: HashMap<u64, String>,
    /// Counter for generating unique labels.
    label_counter: usize,
    /// Region analyzer for detecting breaks/continues.
    region_analyzer: Option<RegionAnalyzer<'a>>,
    /// Safety budget for recursive region structuring.
    safety_budget_remaining: usize,
    safety_budget_max: usize,
    safety_reason: Option<String>,
}

impl<'a, 'o> ControlFlowStructurer<'a, 'o> {
    /// Create a new structurer using a pre-analyzed folding context.
    pub fn new(func: &'a SSAFunction, fold_ctx: &'o FoldingContext<'o>) -> Self {
        let region_analyzer = RegionAnalyzer::new(func);
        let safety_budget_max = Self::compute_safety_budget(func.num_blocks());

        Self {
            func,
            fold_ctx,
            labels: HashMap::new(),
            label_counter: 0,
            region_analyzer: Some(region_analyzer),
            safety_budget_remaining: safety_budget_max,
            safety_budget_max,
            safety_reason: None,
        }
    }

    /// Create a structurer without expression folding (for comparison).
    pub fn new_unfolded(func: &'a SSAFunction, fold_ctx: &'o FoldingContext<'o>) -> Self {
        let safety_budget_max = Self::compute_safety_budget(func.num_blocks());
        Self {
            func,
            fold_ctx,
            labels: HashMap::new(),
            label_counter: 0,
            region_analyzer: Some(RegionAnalyzer::new(func)),
            safety_budget_remaining: safety_budget_max,
            safety_budget_max,
            safety_reason: None,
        }
    }

    fn compute_safety_budget(num_blocks: usize) -> usize {
        num_blocks.saturating_mul(128).max(256)
    }

    fn reset_safety_budget(&mut self) {
        self.safety_budget_remaining = self.safety_budget_max;
        self.safety_reason = None;
    }

    fn consume_safety_budget(&mut self, units: usize) -> bool {
        if self.safety_budget_remaining >= units {
            self.safety_budget_remaining -= units;
            true
        } else {
            if self.safety_reason.is_none() {
                self.safety_reason = Some(format!(
                    "structuring budget exceeded (limit: {})",
                    self.safety_budget_max
                ));
            }
            false
        }
    }

    /// Returns the reason why structuring short-circuited, if any.
    pub fn safety_reason(&self) -> Option<&str> {
        self.safety_reason.as_deref()
    }

    /// Get the set of variable names that survive folding (for filtering declarations).
    pub fn emitted_var_names(&self) -> HashSet<String> {
        let blocks: Vec<_> = self.func.blocks().cloned().collect();
        self.fold_ctx.emitted_var_names(&blocks)
    }

    /// Structure the function's control flow.
    pub fn structure(&mut self) -> CStmt {
        self.reset_safety_budget();
        if self.region_analyzer.is_none() {
            self.region_analyzer = Some(RegionAnalyzer::new(self.func));
        }
        let region = if let Some(analyzer) = self.region_analyzer.as_mut() {
            let region = analyzer.analyze();
            if let Some(reason) = analyzer.analysis_reason() {
                self.safety_reason = Some(reason.to_string());
            }
            region
        } else {
            self.safety_reason = Some("missing region analyzer".to_string());
            Region::Irreducible {
                entry: self.func.entry,
                blocks: self.func.block_addrs().to_vec(),
            }
        };
        let stmt = self.structure_region(&region);
        if self.safety_reason.is_some() {
            return CStmt::Empty;
        }
        // Post-process: flatten, simplify loops, remove redundant control flow
        Self::cleanup(stmt)
    }

    /// Structure a region into C statements.
    fn structure_region(&mut self, region: &Region) -> CStmt {
        if !self.consume_safety_budget(1) {
            return CStmt::Empty;
        }
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
        for op in &block.ops {
            if let Some(expr) = self.fold_ctx.extract_switch_expr(op) {
                return expr;
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
        // Use folding context for optimized output
        stmts.extend(self.fold_ctx.fold_block(block, addr));

        // Check for break/continue at block end
        if let Some(ref analyzer) = self.region_analyzer {
            if analyzer.is_loop_continue(addr) {
                stmts.push(CStmt::Continue);
            } else if analyzer.is_loop_break(addr) {
                stmts.push(CStmt::Break);
            } else if analyzer.is_loop_goto(addr)
                && let Some(target) = analyzer.get_loop_goto_target(addr)
            {
                let label = self.ensure_label(target);
                stmts.push(CStmt::Goto(label));
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
        stmts.extend(self.fold_ctx.fold_block(block, addr));

        // Check for break/continue at block end
        if let Some(ref analyzer) = self.region_analyzer {
            if analyzer.is_loop_continue(addr) {
                stmts.push(CStmt::Continue);
            } else if analyzer.is_loop_break(addr) {
                stmts.push(CStmt::Break);
            } else if analyzer.is_loop_goto(addr)
                && let Some(target) = analyzer.get_loop_goto_target(addr)
            {
                let label = self.ensure_label(target);
                stmts.push(CStmt::Goto(label));
            }
        }
    }

    fn ensure_label(&mut self, addr: u64) -> String {
        if let Some(label) = self.labels.get(&addr) {
            return label.clone();
        }
        let label = format!("L{}", self.label_counter);
        self.label_counter += 1;
        self.labels.insert(addr, label.clone());
        label
    }

    /// Emit side-effecting statements for a block without labels or loop markers.
    /// Used for condition/switch header blocks where statements must appear before
    /// the structured control-flow construct.
    fn structure_block_prefix_stmts(&mut self, addr: u64) -> Vec<CStmt> {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return Vec::new(),
        };

        self.fold_ctx.fold_block(block, addr)
    }

    /// Get the branch condition from a block.
    fn get_branch_condition(&mut self, addr: u64) -> CExpr {
        let block = match self.func.get_block(addr) {
            Some(b) => b,
            None => return CExpr::IntLit(1),
        };

        // Look for a conditional branch in the block
        for op in &block.ops {
            if let Some(cond) = self.fold_ctx.extract_condition(op) {
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
                let cleaned = stmts
                    .into_iter()
                    .map(Self::cleanup_recurse)
                    .filter(|s| !matches!(s, CStmt::Empty))
                    .collect();
                let rewritten = Self::rewrite_block_loops_to_for(cleaned);
                if rewritten.is_empty() {
                    CStmt::Empty
                } else if rewritten.len() == 1 {
                    rewritten.into_iter().next().unwrap()
                } else {
                    CStmt::Block(rewritten)
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let cond = Self::normalize_condition_addr_artifacts(cond);
                let then_body = Box::new(Self::cleanup_recurse(*then_body));
                let else_body = else_body
                    .map(|e| Box::new(Self::cleanup_recurse(*e)))
                    .and_then(|e| (!matches!(*e, CStmt::Empty)).then_some(e));
                let stmt = CStmt::If {
                    cond,
                    then_body,
                    else_body,
                };
                let stmt = Self::rewrite_if_short_circuit(stmt);
                Self::rewrite_if_condition_inversion(stmt)
            }
            CStmt::While { cond, body } => {
                let cond = Self::normalize_condition_addr_artifacts(cond);
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(*body));
                CStmt::While {
                    cond,
                    body: Box::new(body),
                }
            }
            CStmt::DoWhile { body, cond } => {
                let body = Self::strip_trailing_continue(Self::cleanup_recurse(*body));
                let cond = Self::normalize_condition_addr_artifacts(cond);
                // Fix C: do { if (c) break; rest } while(1) -> while(!c) { rest }
                Self::try_convert_do_while_to_while(body, cond)
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let cond = cond.map(Self::normalize_condition_addr_artifacts);
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

    fn rewrite_if_short_circuit(stmt: CStmt) -> CStmt {
        let CStmt::If {
            cond,
            then_body,
            else_body,
        } = stmt
        else {
            return stmt;
        };

        let then_stmt = (*then_body).clone();
        let else_stmt = else_body.as_ref().map(|b| (**b).clone());

        // if (a) { if (b) { T } } -> if (a && b) { T }
        if else_body.is_none()
            && let CStmt::If {
                cond: inner_cond,
                then_body: inner_then,
                else_body: None,
            } = &then_stmt
        {
            return CStmt::If {
                cond: CExpr::binary(BinaryOp::And, cond, inner_cond.clone()),
                then_body: inner_then.clone(),
                else_body: None,
            };
        }

        // if (a) { T } else if (b) { T } -> if (a || b) { T }
        if let Some(CStmt::If {
            cond: right_cond,
            then_body: right_then,
            else_body: None,
        }) = else_stmt.as_ref()
            && then_stmt == **right_then
        {
            return CStmt::If {
                cond: CExpr::binary(BinaryOp::Or, cond, right_cond.clone()),
                then_body: Box::new(then_stmt),
                else_body: None,
            };
        }

        // if (a) { if (b) { T } else { E } } else { E } -> if (a && b) { T } else { E }
        if let CStmt::If {
            cond: inner_cond,
            then_body: inner_then,
            else_body: Some(inner_else),
        } = &then_stmt
            && let Some(outer_else) = else_stmt.as_ref()
            && *outer_else == **inner_else
        {
            return CStmt::If {
                cond: CExpr::binary(BinaryOp::And, cond, inner_cond.clone()),
                then_body: inner_then.clone(),
                else_body: Some(inner_else.clone()),
            };
        }

        CStmt::If {
            cond,
            then_body,
            else_body,
        }
    }

    fn rewrite_if_condition_inversion(stmt: CStmt) -> CStmt {
        let CStmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } = stmt
        else {
            return stmt;
        };

        let Some(terminator) = Self::single_terminator_stmt(else_body.as_ref()) else {
            return CStmt::If {
                cond,
                then_body,
                else_body: Some(else_body),
            };
        };

        CStmt::Block(vec![
            CStmt::If {
                cond: Self::negate_condition(cond),
                then_body: Box::new(terminator),
                else_body: None,
            },
            *then_body,
        ])
    }

    fn single_terminator_stmt(stmt: &CStmt) -> Option<CStmt> {
        if Self::stmt_is_unconditional_terminator(stmt) {
            return Some(stmt.clone());
        }

        if let CStmt::Block(stmts) = stmt
            && stmts.len() == 1
            && Self::stmt_is_unconditional_terminator(&stmts[0])
        {
            return Some(stmts[0].clone());
        }

        None
    }

    fn negate_condition(cond: CExpr) -> CExpr {
        match cond {
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => *operand,
            CExpr::Binary { op, left, right } => {
                let negated = match op {
                    BinaryOp::Eq => Some(BinaryOp::Ne),
                    BinaryOp::Ne => Some(BinaryOp::Eq),
                    BinaryOp::Lt => Some(BinaryOp::Ge),
                    BinaryOp::Le => Some(BinaryOp::Gt),
                    BinaryOp::Gt => Some(BinaryOp::Le),
                    BinaryOp::Ge => Some(BinaryOp::Lt),
                    _ => None,
                };

                if let Some(op) = negated {
                    CExpr::Binary { op, left, right }
                } else {
                    CExpr::unary(UnaryOp::Not, CExpr::Binary { op, left, right })
                }
            }
            other => CExpr::unary(UnaryOp::Not, other),
        }
    }

    /// Rewrite adjacent `init; while (...) { ...; update; }` into `for (...)`.
    fn rewrite_block_loops_to_for(stmts: Vec<CStmt>) -> Vec<CStmt> {
        let mut rewritten = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            if i + 1 < stmts.len()
                && let Some(mut for_stmts) = Self::try_rewrite_while_with_preheader_init(
                    stmts[i].clone(),
                    stmts[i + 1].clone(),
                )
            {
                rewritten.append(&mut for_stmts);
                i += 2;
                continue;
            }
            rewritten.push(stmts[i].clone());
            i += 1;
        }
        rewritten
    }

    fn try_rewrite_while_with_preheader_init(
        preheader_stmt: CStmt,
        while_stmt: CStmt,
    ) -> Option<Vec<CStmt>> {
        let (prefix_stmts, init_stmt, induction_var) = Self::split_preheader_init(preheader_stmt)?;
        let CStmt::While { cond, body } = while_stmt else {
            return None;
        };

        let (loop_cond, loop_body) = match cond {
            CExpr::IntLit(v) if v != 0 => {
                let (exit_cond, stripped_body) = Self::extract_guard_break_cond(*body)?;
                (CExpr::unary(UnaryOp::Not, exit_cond), stripped_body)
            }
            _ => (cond, *body),
        };

        let cond_vars = Self::collect_expr_vars(&loop_cond);
        let cond_reads_induction = Self::set_contains_loop_var(&cond_vars, &induction_var);
        let (update, body_without_update, update_links_cond) =
            Self::extract_loop_update(&induction_var, &cond_vars, loop_body)?;

        if !cond_reads_induction && !update_links_cond {
            return None;
        }

        let mut rewritten = prefix_stmts;
        rewritten.push(CStmt::For {
            init: Some(Box::new(init_stmt)),
            cond: Some(loop_cond),
            update: Some(update),
            body: Box::new(body_without_update),
        });
        Some(rewritten)
    }

    fn extract_induction_var_from_init(init_stmt: &CStmt) -> Option<String> {
        match init_stmt {
            CStmt::Expr(CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                ..
            }) => match left.as_ref() {
                CExpr::Var(name) => Some(name.clone()),
                _ => None,
            },
            CStmt::Decl {
                name,
                init: Some(_),
                ..
            } => Some(name.clone()),
            _ => None,
        }
    }

    fn split_preheader_init(preheader_stmt: CStmt) -> Option<(Vec<CStmt>, CStmt, String)> {
        if let Some(var) = Self::extract_induction_var_from_init(&preheader_stmt) {
            return Some((Vec::new(), preheader_stmt, var));
        }

        let CStmt::Block(mut prefix) = preheader_stmt else {
            return None;
        };
        while matches!(prefix.last(), Some(CStmt::Empty)) {
            prefix.pop();
        }
        let init_stmt = prefix.pop()?;
        let var = Self::extract_induction_var_from_init(&init_stmt)?;
        Some((prefix, init_stmt, var))
    }

    fn extract_loop_update(
        var: &str,
        cond_vars: &HashSet<String>,
        body: CStmt,
    ) -> Option<(CExpr, CStmt, bool)> {
        let stmts = Self::stmt_into_vec(body);
        if stmts.is_empty() {
            return None;
        }

        // Trim unreachable statements after the first unconditional transfer.
        let mut effective = Vec::new();
        for stmt in stmts {
            let is_terminator = Self::stmt_is_unconditional_terminator(&stmt);
            effective.push(stmt);
            if is_terminator {
                break;
            }
        }

        while matches!(effective.last(), Some(CStmt::Empty | CStmt::Continue)) {
            effective.pop();
        }
        if effective.is_empty() {
            return None;
        }

        let prev_stmts = if effective.len() >= 2 {
            &effective[..effective.len() - 1]
        } else {
            &[]
        };
        let (update, update_links_cond) =
            Self::update_expr_from_stmt(var, cond_vars, prev_stmts, effective.last().unwrap())?;
        effective.pop();
        Some((update, Self::stmt_from_vec(effective), update_links_cond))
    }

    fn extract_guard_break_cond(body: CStmt) -> Option<(CExpr, CStmt)> {
        let mut stmts = Self::stmt_into_vec(body);
        let first = stmts.first()?;
        let break_cond = Self::is_if_break_without_else(first)?;
        stmts.remove(0);
        Some((break_cond, Self::stmt_from_vec(stmts)))
    }

    fn update_expr_from_stmt(
        var: &str,
        cond_vars: &HashSet<String>,
        prev_stmts: &[CStmt],
        stmt: &CStmt,
    ) -> Option<(CExpr, bool)> {
        let CStmt::Expr(expr) = stmt else {
            return None;
        };
        match expr {
            CExpr::Unary { op, operand }
                if matches!(
                    op,
                    UnaryOp::PreInc | UnaryOp::PostInc | UnaryOp::PreDec | UnaryOp::PostDec
                ) && matches!(operand.as_ref(), CExpr::Var(_)) =>
            {
                Some((expr.clone(), false))
            }
            CExpr::Binary { op, left, right } if matches!(left.as_ref(), CExpr::Var(_)) => {
                if *op == BinaryOp::Assign {
                    let rhs_vars = Self::collect_expr_vars(right);
                    let links_cond_direct = Self::sets_overlap_loop_vars(&rhs_vars, cond_vars);
                    let reads_induction = Self::set_contains_loop_var(&rhs_vars, var);
                    let links_cond_via_alias =
                        Self::rhs_links_cond_via_alias(prev_stmts, &rhs_vars, cond_vars);
                    if reads_induction || links_cond_direct || links_cond_via_alias {
                        return Some((expr.clone(), links_cond_direct || links_cond_via_alias));
                    }
                }
                if Self::is_compound_assign_op(*op) {
                    return Some((expr.clone(), false));
                }
                None
            }
            _ => None,
        }
    }

    fn is_if_break_without_else(stmt: &CStmt) -> Option<CExpr> {
        let CStmt::If {
            cond,
            then_body,
            else_body: None,
        } = stmt
        else {
            return None;
        };
        if matches!(then_body.as_ref(), CStmt::Break)
            || matches!(then_body.as_ref(), CStmt::Block(v) if v.len() == 1 && matches!(v[0], CStmt::Break))
        {
            return Some(cond.clone());
        }
        None
    }

    fn is_compound_assign_op(op: BinaryOp) -> bool {
        matches!(
            op,
            BinaryOp::AddAssign
                | BinaryOp::SubAssign
                | BinaryOp::MulAssign
                | BinaryOp::DivAssign
                | BinaryOp::ModAssign
                | BinaryOp::BitAndAssign
                | BinaryOp::BitOrAssign
                | BinaryOp::BitXorAssign
                | BinaryOp::ShlAssign
                | BinaryOp::ShrAssign
        )
    }

    fn stmt_is_unconditional_terminator(stmt: &CStmt) -> bool {
        matches!(
            stmt,
            CStmt::Break | CStmt::Continue | CStmt::Return(_) | CStmt::Goto(_)
        )
    }

    fn stmt_into_vec(stmt: CStmt) -> Vec<CStmt> {
        match stmt {
            CStmt::Block(stmts) => stmts,
            CStmt::Empty => Vec::new(),
            other => vec![other],
        }
    }

    fn stmt_from_vec(stmts: Vec<CStmt>) -> CStmt {
        match stmts.len() {
            0 => CStmt::Empty,
            1 => stmts.into_iter().next().unwrap(),
            _ => CStmt::Block(stmts),
        }
    }

    fn rhs_links_cond_via_alias(
        prev_stmts: &[CStmt],
        rhs_vars: &HashSet<String>,
        cond_vars: &HashSet<String>,
    ) -> bool {
        let mut tracked = rhs_vars.clone();
        for stmt in prev_stmts.iter().rev().take(2) {
            let Some((def, prev_reads)) = Self::stmt_def_and_reads(stmt) else {
                continue;
            };
            if !Self::set_contains_loop_var(&tracked, &def) {
                continue;
            }
            if Self::sets_overlap_loop_vars(&prev_reads, cond_vars) {
                return true;
            }
            Self::set_remove_loop_var_aliases(&mut tracked, &def);
            tracked.extend(prev_reads);
        }
        false
    }

    fn stmt_def_and_reads(stmt: &CStmt) -> Option<(String, HashSet<String>)> {
        let CStmt::Expr(CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        }) = stmt
        else {
            return None;
        };
        let CExpr::Var(def) = left.as_ref() else {
            return None;
        };
        Some((def.clone(), Self::collect_expr_vars(right)))
    }

    fn collect_expr_vars(expr: &CExpr) -> HashSet<String> {
        let mut vars = HashSet::new();
        Self::collect_expr_vars_into(expr, &mut vars);
        vars
    }

    fn normalize_loop_expr_refs(expr: &CExpr) -> &CExpr {
        match expr {
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                Self::normalize_loop_expr_refs(inner)
            }
            CExpr::AddrOf(inner) => match inner.as_ref() {
                CExpr::Deref(inner2) => Self::normalize_loop_expr_refs(inner2),
                _ => expr,
            },
            CExpr::Deref(inner) => match inner.as_ref() {
                CExpr::AddrOf(inner2) => Self::normalize_loop_expr_refs(inner2),
                _ => expr,
            },
            _ => expr,
        }
    }

    fn normalize_condition_addr_artifacts(expr: CExpr) -> CExpr {
        match expr {
            CExpr::Var(name) if name.starts_with('&') && name.len() > 1 => {
                CExpr::Var(name.trim_start_matches('&').to_string())
            }
            CExpr::Unary { op, operand } => CExpr::Unary {
                op,
                operand: Box::new(Self::normalize_condition_addr_artifacts(*operand)),
            },
            CExpr::Binary { op, left, right } => CExpr::Binary {
                op,
                left: Box::new(Self::normalize_condition_addr_artifacts(*left)),
                right: Box::new(Self::normalize_condition_addr_artifacts(*right)),
            },
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => CExpr::Ternary {
                cond: Box::new(Self::normalize_condition_addr_artifacts(*cond)),
                then_expr: Box::new(Self::normalize_condition_addr_artifacts(*then_expr)),
                else_expr: Box::new(Self::normalize_condition_addr_artifacts(*else_expr)),
            },
            CExpr::Cast { ty, expr } => CExpr::Cast {
                ty,
                expr: Box::new(Self::normalize_condition_addr_artifacts(*expr)),
            },
            CExpr::Call { func, args } => CExpr::Call {
                func: Box::new(Self::normalize_condition_addr_artifacts(*func)),
                args: args
                    .into_iter()
                    .map(Self::normalize_condition_addr_artifacts)
                    .collect(),
            },
            CExpr::Subscript { base, index } => CExpr::Subscript {
                base: Box::new(Self::normalize_condition_addr_artifacts(*base)),
                index: Box::new(Self::normalize_condition_addr_artifacts(*index)),
            },
            CExpr::Member { base, member } => CExpr::Member {
                base: Box::new(Self::normalize_condition_addr_artifacts(*base)),
                member,
            },
            CExpr::PtrMember { base, member } => CExpr::PtrMember {
                base: Box::new(Self::normalize_condition_addr_artifacts(*base)),
                member,
            },
            CExpr::Sizeof(inner) => {
                CExpr::Sizeof(Box::new(Self::normalize_condition_addr_artifacts(*inner)))
            }
            CExpr::AddrOf(inner) => {
                let normalized = Self::normalize_condition_addr_artifacts(*inner);
                match normalized {
                    CExpr::Deref(inner2) => *inner2,
                    CExpr::Var(name) => CExpr::Var(name),
                    other => CExpr::AddrOf(Box::new(other)),
                }
            }
            CExpr::Deref(inner) => {
                let normalized = Self::normalize_condition_addr_artifacts(*inner);
                match normalized {
                    CExpr::AddrOf(inner2) => *inner2,
                    other => CExpr::Deref(Box::new(other)),
                }
            }
            CExpr::Comma(values) => CExpr::Comma(
                values
                    .into_iter()
                    .map(Self::normalize_condition_addr_artifacts)
                    .collect(),
            ),
            CExpr::Paren(inner) => {
                CExpr::Paren(Box::new(Self::normalize_condition_addr_artifacts(*inner)))
            }
            other => other,
        }
    }

    fn collect_expr_vars_into(expr: &CExpr, out: &mut HashSet<String>) {
        match Self::normalize_loop_expr_refs(expr) {
            CExpr::Var(name) => {
                out.insert(name.trim_start_matches('&').to_string());
            }
            CExpr::AddrOf(inner) | CExpr::Deref(inner) => {
                if let CExpr::Var(name) = Self::normalize_loop_expr_refs(inner) {
                    out.insert(name.trim_start_matches('&').to_string());
                }
                Self::collect_expr_vars_into(inner, out);
            }
            CExpr::Unary { operand, .. } => Self::collect_expr_vars_into(operand, out),
            CExpr::Binary { left, right, .. } => {
                Self::collect_expr_vars_into(left, out);
                Self::collect_expr_vars_into(right, out);
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::collect_expr_vars_into(cond, out);
                Self::collect_expr_vars_into(then_expr, out);
                Self::collect_expr_vars_into(else_expr, out);
            }
            CExpr::Cast { expr, .. } | CExpr::Paren(expr) | CExpr::Sizeof(expr) => {
                Self::collect_expr_vars_into(expr, out)
            }
            CExpr::Call { func, args } => {
                Self::collect_expr_vars_into(func, out);
                for arg in args {
                    Self::collect_expr_vars_into(arg, out);
                }
            }
            CExpr::Subscript { base, index } => {
                Self::collect_expr_vars_into(base, out);
                Self::collect_expr_vars_into(index, out);
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                Self::collect_expr_vars_into(base, out);
            }
            CExpr::Comma(values) => {
                for value in values {
                    Self::collect_expr_vars_into(value, out);
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

    fn loop_var_base(name: &str) -> &str {
        let name = name.trim_start_matches('&');
        if let Some((base, suffix)) = name.rsplit_once('_')
            && !base.is_empty()
            && suffix.chars().all(|ch| ch.is_ascii_digit())
        {
            return base;
        }
        name
    }

    fn loop_var_equiv(a: &str, b: &str) -> bool {
        if a.eq_ignore_ascii_case(b) {
            return true;
        }
        Self::loop_var_base(a).eq_ignore_ascii_case(Self::loop_var_base(b))
    }

    fn set_contains_loop_var(vars: &HashSet<String>, target: &str) -> bool {
        vars.iter().any(|name| Self::loop_var_equiv(name, target))
    }

    fn sets_overlap_loop_vars(a: &HashSet<String>, b: &HashSet<String>) -> bool {
        a.iter()
            .any(|name| b.iter().any(|other| Self::loop_var_equiv(name, other)))
    }

    fn set_remove_loop_var_aliases(vars: &mut HashSet<String>, target: &str) {
        let to_remove: Vec<String> = vars
            .iter()
            .filter(|name| Self::loop_var_equiv(name, target))
            .cloned()
            .collect();
        for name in to_remove {
            vars.remove(&name);
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
    use super::ControlFlowStructurer;
    use crate::ast::{BinaryOp, CExpr, CStmt, UnaryOp};

    fn v(name: &str) -> CExpr {
        CExpr::Var(name.to_string())
    }

    fn expr_stmt(expr: CExpr) -> CStmt {
        CStmt::Expr(expr)
    }

    fn assign(lhs: &str, rhs: CExpr) -> CStmt {
        expr_stmt(CExpr::assign(v(lhs), rhs))
    }

    #[test]
    fn rewrites_canonical_while_to_for() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, v("i"), CExpr::IntLit(10)),
                CStmt::Block(vec![
                    assign("sum", CExpr::binary(BinaryOp::Add, v("sum"), v("i"))),
                    assign("i", CExpr::binary(BinaryOp::Add, v("i"), CExpr::IntLit(1))),
                ]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::For {
            init,
            cond,
            update,
            body,
        } = cleaned
        else {
            panic!("Expected canonical loop rewrite to produce CStmt::For");
        };
        assert!(init.is_some(), "for-loop should keep init statement");
        assert!(cond.is_some(), "for-loop should keep loop condition");
        assert!(
            update.is_some(),
            "for-loop should extract update expression"
        );
        assert!(
            !matches!(*body, CStmt::Empty),
            "for-loop body should retain side-effect statements"
        );
    }

    #[test]
    fn rewrites_guard_break_while1_to_for() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::IntLit(1),
                CStmt::Block(vec![
                    CStmt::if_stmt(
                        CExpr::binary(BinaryOp::Ge, v("i"), v("n")),
                        CStmt::Break,
                        None,
                    ),
                    assign("sum", CExpr::binary(BinaryOp::Add, v("sum"), v("i"))),
                    expr_stmt(CExpr::Unary {
                        op: UnaryOp::PostInc,
                        operand: Box::new(v("i")),
                    }),
                ]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::For {
            cond: Some(cond),
            update: Some(update),
            ..
        } = cleaned
        else {
            panic!("Expected guarded while(1) rewrite to produce CStmt::For");
        };
        assert!(
            matches!(
                cond,
                CExpr::Unary {
                    op: UnaryOp::Not,
                    ..
                }
            ),
            "guard-break form should negate break condition for for-loop cond"
        );
        assert!(
            matches!(
                update,
                CExpr::Unary {
                    op: UnaryOp::PostInc,
                    ..
                }
            ),
            "guard-break form should preserve update expression"
        );
    }

    #[test]
    fn does_not_rewrite_without_tail_update() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, v("i"), CExpr::IntLit(10)),
                CStmt::Block(vec![assign(
                    "sum",
                    CExpr::binary(BinaryOp::Add, v("sum"), CExpr::IntLit(1)),
                )]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::Block(stmts) = cleaned else {
            panic!("Expected unmatched loop to remain a block");
        };
        assert!(
            matches!(stmts.get(1), Some(CStmt::While { .. })),
            "loop without a recognized update should remain while-loop"
        );
    }

    #[test]
    fn does_not_rewrite_when_cond_var_mismatch() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, v("j"), CExpr::IntLit(10)),
                CStmt::Block(vec![assign(
                    "i",
                    CExpr::binary(BinaryOp::Add, v("i"), CExpr::IntLit(1)),
                )]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::Block(stmts) = cleaned else {
            panic!("Expected unmatched condition var to remain a block");
        };
        assert!(
            matches!(stmts.get(1), Some(CStmt::While { .. })),
            "condition must reference same induction variable as init/update"
        );
    }

    #[test]
    fn accepts_self_assign_update_forms() {
        let updates = vec![
            CExpr::binary(
                BinaryOp::Assign,
                v("i"),
                CExpr::binary(BinaryOp::Add, v("i"), CExpr::IntLit(2)),
            ),
            CExpr::binary(BinaryOp::AddAssign, v("i"), CExpr::IntLit(2)),
            CExpr::binary(
                BinaryOp::Assign,
                v("i"),
                CExpr::call(v("next_i"), vec![v("i"), v("x")]),
            ),
        ];

        for update_expr in updates {
            let input = CStmt::Block(vec![
                assign("i", CExpr::IntLit(0)),
                CStmt::while_loop(
                    CExpr::binary(BinaryOp::Lt, v("i"), v("n")),
                    CStmt::Block(vec![
                        assign("sum", CExpr::binary(BinaryOp::Add, v("sum"), v("i"))),
                        expr_stmt(update_expr.clone()),
                    ]),
                ),
            ]);

            let cleaned = ControlFlowStructurer::cleanup(input);
            let CStmt::For {
                update: Some(update),
                ..
            } = cleaned
            else {
                panic!("Expected loop rewrite for accepted self-assign update form");
            };
            assert_eq!(update, update_expr);
        }
    }

    #[test]
    fn rewrites_nested_if_without_else_to_short_circuit_and() {
        let input = CStmt::if_stmt(
            v("a"),
            CStmt::if_stmt(v("b"), CStmt::ret(Some(CExpr::IntLit(1))), None),
            None,
        );

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert_eq!(
            cleaned,
            CStmt::if_stmt(
                CExpr::binary(BinaryOp::And, v("a"), v("b")),
                CStmt::ret(Some(CExpr::IntLit(1))),
                None
            )
        );
    }

    #[test]
    fn rewrites_if_else_if_same_body_to_short_circuit_or() {
        let body = assign("x", CExpr::IntLit(1));
        let input = CStmt::if_stmt(
            v("a"),
            body.clone(),
            Some(CStmt::if_stmt(v("b"), body.clone(), None)),
        );

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert_eq!(
            cleaned,
            CStmt::if_stmt(CExpr::binary(BinaryOp::Or, v("a"), v("b")), body, None)
        );
    }

    #[test]
    fn rewrites_shared_else_nested_if_to_short_circuit_and() {
        let then_stmt = assign("x", CExpr::IntLit(1));
        let else_stmt = assign("x", CExpr::IntLit(2));
        let input = CStmt::if_stmt(
            v("a"),
            CStmt::if_stmt(v("b"), then_stmt.clone(), Some(else_stmt.clone())),
            Some(else_stmt.clone()),
        );

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert_eq!(
            cleaned,
            CStmt::if_stmt(
                CExpr::binary(BinaryOp::And, v("a"), v("b")),
                then_stmt,
                Some(else_stmt)
            )
        );
    }

    #[test]
    fn inverts_if_when_else_is_single_terminator() {
        let input = CStmt::if_stmt(
            CExpr::binary(BinaryOp::Lt, v("x"), v("limit")),
            assign("sum", CExpr::binary(BinaryOp::Add, v("sum"), v("x"))),
            Some(CStmt::ret(Some(CExpr::IntLit(0)))),
        );

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::Block(stmts) = cleaned else {
            panic!("Expected condition inversion to emit block sequence");
        };
        assert_eq!(
            stmts.len(),
            2,
            "Inversion should emit guard + then statement"
        );
        assert_eq!(
            stmts[0],
            CStmt::if_stmt(
                CExpr::binary(BinaryOp::Ge, v("x"), v("limit")),
                CStmt::ret(Some(CExpr::IntLit(0))),
                None
            )
        );
    }

    #[test]
    fn does_not_invert_if_when_else_is_not_terminator() {
        let input = CStmt::if_stmt(
            v("a"),
            assign("x", CExpr::IntLit(1)),
            Some(assign("x", v("b"))),
        );
        let cleaned = ControlFlowStructurer::cleanup(input.clone());
        assert_eq!(cleaned, input);
    }

    #[test]
    fn removes_empty_else_branch() {
        let input = CStmt::if_stmt(v("a"), assign("x", CExpr::IntLit(1)), Some(CStmt::Empty));
        let cleaned = ControlFlowStructurer::cleanup(input);
        assert_eq!(
            cleaned,
            CStmt::if_stmt(v("a"), assign("x", CExpr::IntLit(1)), None)
        );
    }

    #[test]
    fn rewrites_while_to_for_when_condition_uses_addrof_induction_var() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, CExpr::AddrOf(Box::new(v("i"))), v("n")),
                CStmt::Block(vec![
                    assign("sum", CExpr::binary(BinaryOp::Add, v("sum"), v("i"))),
                    assign("i", CExpr::binary(BinaryOp::Add, v("i"), CExpr::IntLit(1))),
                ]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert!(
            matches!(cleaned, CStmt::For { .. }),
            "Address-wrapped induction variable should still allow for-loop rewrite"
        );
    }

    #[test]
    fn normalizes_addrof_var_artifact_in_while_condition_without_rewrite() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, CExpr::AddrOf(Box::new(v("local"))), v("n")),
                CStmt::Block(vec![assign(
                    "sum",
                    CExpr::binary(BinaryOp::Add, v("sum"), CExpr::IntLit(1)),
                )]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::Block(stmts) = cleaned else {
            panic!("Expected unmatched loop to remain a block");
        };
        let Some(CStmt::While { cond, .. }) = stmts.get(1) else {
            panic!("Expected second statement to remain a while-loop");
        };
        match cond {
            CExpr::Binary { left, .. } => {
                assert!(
                    matches!(left.as_ref(), CExpr::Var(name) if name == "local"),
                    "Address-of local artifact should normalize to plain variable in condition"
                );
            }
            other => panic!(
                "Unexpected condition shape after normalization: {:?}",
                other
            ),
        }
    }

    #[test]
    fn rewrites_while_to_for_with_two_step_alias_update_chain() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, v("i"), v("n")),
                CStmt::Block(vec![
                    assign("tmp1", v("i")),
                    assign("tmp2", v("tmp1")),
                    assign(
                        "i",
                        CExpr::binary(BinaryOp::Add, v("tmp2"), CExpr::IntLit(1)),
                    ),
                ]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert!(
            matches!(cleaned, CStmt::For { .. }),
            "Two-step alias chain should be enough to connect update with loop condition"
        );
    }

    #[test]
    fn does_not_rewrite_while_to_for_when_alias_chain_is_too_long() {
        let input = CStmt::Block(vec![
            assign("i", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, v("i"), v("n")),
                CStmt::Block(vec![
                    assign("tmp1", v("i")),
                    assign("tmp2", v("tmp1")),
                    assign("tmp3", v("tmp2")),
                    assign(
                        "i",
                        CExpr::binary(BinaryOp::Add, v("tmp3"), CExpr::IntLit(1)),
                    ),
                ]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        let CStmt::Block(stmts) = cleaned else {
            panic!("Expected long alias-chain loop to remain a block");
        };
        assert!(
            matches!(stmts.get(1), Some(CStmt::While { .. })),
            "Alias chain beyond bounded lookback should not rewrite to for-loop"
        );
    }

    #[test]
    fn rewrites_while_to_for_when_condition_uses_suffix_equivalent_var_name() {
        let input = CStmt::Block(vec![
            assign("local_4", CExpr::IntLit(0)),
            CStmt::while_loop(
                CExpr::binary(BinaryOp::Lt, CExpr::AddrOf(Box::new(v("local"))), v("n")),
                CStmt::Block(vec![assign(
                    "local_4",
                    CExpr::binary(BinaryOp::Add, v("local_4"), CExpr::IntLit(1)),
                )]),
            ),
        ]);

        let cleaned = ControlFlowStructurer::cleanup(input);
        assert!(
            matches!(cleaned, CStmt::For { .. }),
            "Suffix-equivalent loop vars (local/local_4) should be treated as matching"
        );
    }
}
