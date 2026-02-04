//! Control flow structuring.
//!
//! This module converts unstructured control flow (gotos, CFG edges) into
//! structured high-level constructs (if-then-else, while, for, etc.).

use std::collections::HashMap;

use r2ssa::SSAFunction;

use crate::ast::{CExpr, CStmt};
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
}

impl<'a> ControlFlowStructurer<'a> {
    /// Create a new structurer with the specified pointer size.
    pub fn new(func: &'a SSAFunction, ptr_size: u32) -> Self {
        // Pre-analyze all blocks for expression folding
        let mut fold_ctx = FoldingContext::new(ptr_size);
        let blocks: Vec<_> = func.blocks().cloned().collect();
        fold_ctx.analyze_blocks(&blocks);

        Self {
            func,
            expr_builder: ExpressionBuilder::new(ptr_size),
            fold_ctx: Some(fold_ctx),
            labels: HashMap::new(),
            label_counter: 0,
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

    /// Structure the function's control flow.
    pub fn structure(&mut self) -> CStmt {
        let mut analyzer = RegionAnalyzer::new(self.func);
        let region = analyzer.analyze();
        self.structure_region(&region)
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

                CStmt::if_stmt(cond, then_stmt, else_stmt)
            }
            Region::WhileLoop { header, body } => {
                let cond = self.get_branch_condition(*header);
                let body_stmt = self.structure_region(body);
                CStmt::while_loop(cond, body_stmt)
            }
            Region::DoWhileLoop { body, cond_block } => {
                let body_stmt = self.structure_region(body);
                let cond = self.get_branch_condition(*cond_block);
                CStmt::DoWhile {
                    body: Box::new(body_stmt),
                    cond,
                }
            }
            Region::Irreducible { entry, blocks } => self.structure_irreducible(*entry, blocks),
        }
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
        if let Some(ref fold_ctx) = self.fold_ctx {
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

        if stmts.is_empty() {
            CStmt::Empty
        } else if stmts.len() == 1 {
            stmts.remove(0)
        } else {
            CStmt::Block(stmts)
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

    /// Generate a unique label.
    #[allow(dead_code)]
    fn gen_label(&mut self) -> String {
        let label = format!("L{}", self.label_counter);
        self.label_counter += 1;
        label
    }

    /// Add a goto for a block.
    #[allow(dead_code)]
    fn goto_block(&mut self, addr: u64) -> CStmt {
        let label = self.labels.entry(addr).or_insert_with(|| {
            let l = format!("L{}", self.label_counter);
            self.label_counter += 1;
            l
        });
        CStmt::Goto(label.clone())
    }
}

/// Try to detect for-loop patterns.
///
/// A for loop has:
/// - An initialization before the loop
/// - A condition at the loop header
/// - An increment at the end of the loop body
#[allow(dead_code)]
pub fn detect_for_loop(
    func: &SSAFunction,
    header: u64,
    _body: &[u64],
) -> Option<(CStmt, CExpr, CExpr)> {
    let _header_block = func.get_block(header)?;

    // Look for common patterns:
    // 1. Counter variable initialized before header
    // 2. Counter compared in header
    // 3. Counter incremented in body

    // This is a simplified heuristic - real detection needs more analysis
    None
}

/// Simplify nested if-else chains into switch statements.
#[allow(dead_code)]
pub fn detect_switch(region: &Region) -> Option<(CExpr, Vec<(u64, Region)>)> {
    match region {
        Region::IfThenElse { .. } => {
            // Check if this is part of a switch chain
            // Would need to analyze the condition expressions
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    // Tests would require constructing SSAFunctions
    // which needs r2il blocks
}
