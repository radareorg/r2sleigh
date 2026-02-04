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

use r2ssa::{FunctionSSABlock, SSAOp, SSAVar};

use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};

// Type alias for clarity
type SSABlock = FunctionSSABlock;

/// Tracks use counts and definitions for expression folding.
#[derive(Debug)]
pub struct FoldingContext {
    /// Maps SSA variable name to its defining expression.
    definitions: HashMap<String, CExpr>,
    /// Maps SSA variable name to its use count.
    use_counts: HashMap<String, usize>,
    /// Variables that should not be inlined (e.g., multiple uses, side effects).
    pinned: HashSet<String>,
    /// Variables that are used in control flow conditions.
    condition_vars: HashSet<String>,
    /// Pointer size in bits.
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
    /// Stack variable names by offset.
    stack_vars: HashMap<i64, String>,
    /// Counter for unique stack variable names.
    stack_var_counter: usize,
}

impl FoldingContext {
    /// Create a new folding context.
    pub fn new(ptr_size: u32) -> Self {
        Self {
            definitions: HashMap::new(),
            use_counts: HashMap::new(),
            pinned: HashSet::new(),
            condition_vars: HashSet::new(),
            ptr_size,
            function_names: HashMap::new(),
            strings: HashMap::new(),
            symbols: HashMap::new(),
            hide_stack_frame: true, // Default to hiding stack frame
            sp_name: if ptr_size == 64 {
                "rsp".to_string()
            } else {
                "esp".to_string()
            },
            fp_name: if ptr_size == 64 {
                "rbp".to_string()
            } else {
                "ebp".to_string()
            },
            stack_vars: HashMap::new(),
            stack_var_counter: 0,
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

    /// Set the symbol/global variable names mapping.
    pub fn set_symbols(&mut self, symbols: HashMap<u64, String>) {
        self.symbols = symbols;
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

    /// Analyze a block to collect use counts and definitions.
    pub fn analyze_block(&mut self, block: &SSABlock) {
        // First pass: count uses of each variable
        for op in &block.ops {
            for src in op.sources() {
                let key = src.display_name();
                *self.use_counts.entry(key).or_insert(0) += 1;
            }

            // Mark condition variables as pinned (we want them named for readability)
            if let SSAOp::CBranch { cond, .. } = op {
                self.condition_vars.insert(cond.display_name());
            }
        }

        // Second pass: build definitions
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                let key = dst.display_name();
                let expr = self.op_to_expr(op);
                self.definitions.insert(key, expr);
            }
        }
    }

    /// Analyze multiple blocks (for function-level folding).
    pub fn analyze_blocks(&mut self, blocks: &[SSABlock]) {
        for block in blocks {
            self.analyze_block(block);
        }
        // Analyze stack variable patterns
        self.analyze_stack_vars(blocks);
    }

    /// Analyze stack variable access patterns and assign names.
    fn analyze_stack_vars(&mut self, blocks: &[SSABlock]) {
        for block in blocks {
            for op in &block.ops {
                match op {
                    SSAOp::Load { addr, .. } | SSAOp::Store { addr, .. } => {
                        // Check if address is a stack offset expression
                        if let Some(offset) = self.extract_stack_offset_from_var(addr) {
                            self.get_or_create_stack_var(offset);
                        }
                    }
                    // Also check IntAdd operations that compute stack addresses
                    SSAOp::IntAdd { dst, a, b } => {
                        let a_lower = a.name.to_lowercase();
                        if a_lower.contains(&self.fp_name) || a_lower.contains(&self.sp_name) {
                            if let Some(offset) = self.parse_const_offset(b) {
                                // Create stack var name first to avoid borrow issues
                                let stack_var_name = self.get_or_create_stack_var(offset);
                                // Record that dst is a stack address
                                let key = dst.display_name();
                                self.definitions
                                    .insert(key, CExpr::Var(format!("&{}", stack_var_name)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Try to extract a stack offset from a variable name or its definition.
    fn extract_stack_offset_from_var(&self, var: &SSAVar) -> Option<i64> {
        let name_lower = var.name.to_lowercase();

        // Direct fp/sp reference
        if name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name) {
            return Some(0);
        }

        // Check if this variable was defined as fp/sp + offset
        let key = var.display_name();
        if let Some(expr) = self.definitions.get(&key) {
            return self.extract_offset_from_expr(expr);
        }

        None
    }

    /// Extract stack offset from an expression like (rbp + -0x48).
    fn extract_offset_from_expr(&self, expr: &CExpr) -> Option<i64> {
        match expr {
            CExpr::Binary {
                op: BinaryOp::Add,
                left,
                right,
            } => {
                // Check if left is fp/sp
                if let CExpr::Var(name) = left.as_ref() {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name) {
                        // Get offset from right
                        return self.expr_to_offset(right);
                    }
                }
                None
            }
            CExpr::Var(name) => {
                let name_lower = name.to_lowercase();
                if name_lower.contains(&self.fp_name) || name_lower.contains(&self.sp_name) {
                    return Some(0);
                }
                None
            }
            _ => None,
        }
    }

    /// Convert an expression to an offset value.
    fn expr_to_offset(&self, expr: &CExpr) -> Option<i64> {
        match expr {
            CExpr::IntLit(v) => Some(*v),
            CExpr::UIntLit(v) => {
                // Handle negative offsets stored as unsigned
                if *v > 0xffffffffffff0000 {
                    let neg = (!*v).wrapping_add(1);
                    Some(-(neg as i64))
                } else {
                    Some(*v as i64)
                }
            }
            _ => None,
        }
    }

    /// Parse a constant offset from an SSA variable.
    fn parse_const_offset(&self, var: &SSAVar) -> Option<i64> {
        if var.is_const() {
            if let Some(val) = parse_const_value(&var.name) {
                // Handle negative offsets stored as unsigned
                if val > 0xffffffffffff0000 {
                    let neg = (!val).wrapping_add(1);
                    return Some(-(neg as i64));
                }
                return Some(val as i64);
            }
        }
        None
    }

    /// Get or create a name for a stack variable at the given offset.
    fn get_or_create_stack_var(&mut self, offset: i64) -> String {
        if let Some(name) = self.stack_vars.get(&offset) {
            return name.clone();
        }

        // Generate a name based on offset
        let name = if offset < 0 {
            // Negative offset from fp = local variable
            format!("local_{:x}", (-offset) as u64)
        } else if offset == 0 {
            "saved_fp".to_string()
        } else {
            // Positive offset from fp = stack argument or saved value
            format!("stack_{:x}", offset as u64)
        };

        self.stack_vars.insert(offset, name.clone());
        name
    }

    /// Check if an address expression is a stack access and return the variable name.
    pub fn simplify_stack_access(&self, addr_expr: &CExpr) -> Option<String> {
        if let Some(offset) = self.extract_offset_from_expr(addr_expr) {
            return self.stack_vars.get(&offset).cloned();
        }
        None
    }

    /// Check if a variable should be inlined.
    fn should_inline(&self, var_name: &str) -> bool {
        // Don't inline if:
        // 1. It has multiple uses
        // 2. It's explicitly pinned
        // 3. It's a register output (we want to see what gets written to regs)
        // 4. It's used in a condition

        let use_count = self.use_counts.get(var_name).copied().unwrap_or(0);

        if use_count != 1 {
            return false;
        }

        if self.pinned.contains(var_name) {
            return false;
        }

        if self.condition_vars.contains(var_name) {
            return false;
        }

        // Always inline temporaries and constants
        if var_name.starts_with("tmp:") || var_name.starts_with("const:") {
            return true;
        }

        // Don't inline named registers by default - user wants to see them
        // But do inline temp versions (t1_1, etc.)
        if var_name.contains("_") {
            let base = var_name.split('_').next().unwrap_or(var_name);
            // Inline if it's a temp-like name
            base.starts_with("t") && base.len() <= 3
        } else {
            false
        }
    }

    /// Check if a variable is dead (never used).
    pub fn is_dead(&self, var: &SSAVar) -> bool {
        let key = var.display_name();
        let use_count = self.use_counts.get(&key).copied().unwrap_or(0);

        if use_count > 0 {
            return false;
        }

        // Don't mark as dead if it's a named register (could be output)
        let is_named_reg = !var.name.starts_with("tmp:")
            && !var.name.starts_with("const:")
            && !var.name.starts_with("reg:");

        // Keep named register outputs, kill flags and temps
        if is_named_reg {
            // But do mark CPU flags as dead
            let lower = var.name.to_lowercase();
            is_cpu_flag(&lower)
        } else {
            true
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

        // Try to inline if appropriate
        if self.should_inline(&key) {
            if let Some(expr) = self.definitions.get(&key) {
                return expr.clone();
            }
        }

        // Otherwise return a variable reference
        CExpr::Var(self.var_name(var))
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

        // Check if this is a string address
        if let Some(s) = self.lookup_string(val) {
            return CExpr::StringLit(s.clone());
        }

        // Check if this is a symbol address
        if let Some(s) = self.lookup_symbol(val) {
            return CExpr::Var(s.clone());
        }

        if val > 0x7fffffff {
            CExpr::UIntLit(val)
        } else {
            CExpr::IntLit(val as i64)
        }
    }

    /// Convert an SSA operation to a C expression.
    fn op_to_expr(&self, op: &SSAOp) -> CExpr {
        match op {
            SSAOp::Copy { src, .. } => self.get_expr(src),
            SSAOp::Load { addr, .. } => CExpr::Deref(Box::new(self.get_expr(addr))),
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
            SSAOp::BoolAnd { a, b, .. } => self.binary_expr(BinaryOp::And, a, b),
            SSAOp::BoolOr { a, b, .. } => self.binary_expr(BinaryOp::Or, a, b),
            SSAOp::BoolNot { src, .. } => CExpr::unary(UnaryOp::Not, self.get_expr(src)),
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
            }
            SSAOp::Trunc { dst, src } => {
                let ty = type_from_size(dst.size);
                CExpr::cast(ty, self.get_expr(src))
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
            SSAOp::Call { target } => {
                // Try to resolve function name from address
                let func_expr = if let Some(addr) = extract_call_address(&target.name) {
                    if let Some(name) = self.lookup_function(addr) {
                        CExpr::Var(name.clone())
                    } else {
                        self.get_expr(target)
                    }
                } else if target.is_const() {
                    if let Some(addr) = parse_const_value(&target.name) {
                        if let Some(name) = self.lookup_function(addr) {
                            CExpr::Var(name.clone())
                        } else {
                            self.get_expr(target)
                        }
                    } else {
                        self.get_expr(target)
                    }
                } else {
                    self.get_expr(target)
                };
                CExpr::call(func_expr, vec![])
            }
            // For other ops, just return a variable reference
            _ => {
                if let Some(dst) = op.dst() {
                    CExpr::Var(self.var_name(dst))
                } else {
                    CExpr::IntLit(0)
                }
            }
        }
    }

    /// Create a binary expression.
    fn binary_expr(&self, op: BinaryOp, a: &SSAVar, b: &SSAVar) -> CExpr {
        CExpr::binary(op, self.get_expr(a), self.get_expr(b))
    }

    /// Convert a block to folded C statements.
    pub fn fold_block(&self, block: &SSABlock) -> Vec<CStmt> {
        let mut stmts = Vec::new();

        for op in &block.ops {
            // Skip stack frame setup/teardown if enabled
            if self.is_stack_frame_op(op) {
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
            }

            if let Some(stmt) = self.op_to_stmt(op) {
                stmts.push(stmt);
            }
        }

        stmts
    }

    /// Convert an SSA operation to a C statement.
    fn op_to_stmt(&self, op: &SSAOp) -> Option<CStmt> {
        match op {
            SSAOp::Copy { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = self.get_expr(src);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Load { dst, addr, .. } => {
                let lhs = CExpr::Var(self.var_name(dst));
                // Try to use stack variable name if this is a stack access
                let addr_expr = self.get_expr(addr);
                let rhs = if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                    CExpr::Var(stack_var)
                } else {
                    CExpr::Deref(Box::new(addr_expr))
                };
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Store { addr, val, .. } => {
                // Try to use stack variable name if this is a stack access
                let addr_expr = self.get_expr(addr);
                let lhs = if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                    CExpr::Var(stack_var)
                } else {
                    CExpr::Deref(Box::new(addr_expr))
                };
                let rhs = self.get_expr(val);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
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
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::IntNot { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::unary(UnaryOp::BitNot, self.get_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::BoolAnd { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::And),
            SSAOp::BoolOr { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Or),
            SSAOp::BoolNot { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::unary(UnaryOp::Not, self.get_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs = CExpr::cast(ty, self.get_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Trunc { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let ty = type_from_size(dst.size);
                let rhs = CExpr::cast(ty, self.get_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Call { target } => {
                // Try to resolve function name from address
                let func_expr = if let Some(addr) = extract_call_address(&target.name) {
                    if let Some(name) = self.lookup_function(addr) {
                        CExpr::Var(name.clone())
                    } else {
                        self.get_expr(target)
                    }
                } else if target.is_const() {
                    if let Some(addr) = parse_const_value(&target.name) {
                        if let Some(name) = self.lookup_function(addr) {
                            CExpr::Var(name.clone())
                        } else {
                            self.get_expr(target)
                        }
                    } else {
                        self.get_expr(target)
                    }
                } else {
                    self.get_expr(target)
                };
                let call = CExpr::call(func_expr, vec![]);
                Some(CStmt::Expr(call))
            }
            SSAOp::Return { target } => Some(CStmt::Return(Some(self.get_expr(target)))),
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
        let rhs = CExpr::binary(op, self.get_expr(a), self.get_expr(b));
        Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
    }

    /// Extract a condition expression from a branch operation.
    pub fn extract_condition(&self, op: &SSAOp) -> Option<CExpr> {
        match op {
            SSAOp::CBranch { cond, .. } => Some(self.get_expr(cond)),
            _ => None,
        }
    }
}

/// Check if a name is a CPU flag that should be eliminated when unused.
fn is_cpu_flag(name: &str) -> bool {
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
fn parse_const_value(name: &str) -> Option<u64> {
    let val_str = name.strip_prefix("const:")?;
    // Remove any SSA version suffix (e.g., "const:42_0" -> "42")
    let val_str = val_str.split('_').next().unwrap_or(val_str);

    if let Some(hex) = val_str
        .strip_prefix("0x")
        .or_else(|| val_str.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if val_str.chars().all(|c| c.is_ascii_hexdigit()) && val_str.len() > 4 {
        // Likely a hex value without 0x prefix
        u64::from_str_radix(val_str, 16).ok()
    } else {
        val_str.parse().ok()
    }
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
fn type_from_size(bits: u32) -> CType {
    match bits {
        1 => CType::Bool,
        8 => CType::Int(8),
        16 => CType::Int(16),
        32 => CType::Int(32),
        64 => CType::Int(64),
        _ => CType::Int(bits),
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

        // Should only have one statement (RAX_1 assignment)
        // ZF_1 should be eliminated as dead
        assert_eq!(stmts.len(), 1);
    }
}
