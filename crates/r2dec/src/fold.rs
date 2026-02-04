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

use crate::ast::{BinaryOp, CExpr, CStmt, CType, UnaryOp};

// Type alias for clarity
type SSABlock = FunctionSSABlock;

/// Threshold for detecting 64-bit negative values stored as unsigned.
/// Values above this are likely negative offsets (within ~65536 of u64::MAX).
/// This handles cases like stack offsets: 0xffffffffffffffb8 represents -72.
const LIKELY_NEGATIVE_THRESHOLD: u64 = 0xffffffffffff0000;

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
    /// Pointer size in bits (reserved for architecture-aware type sizing).
    #[allow(dead_code)]
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
    /// Counter for unique stack variable names (reserved for stack var naming).
    #[allow(dead_code)]
    stack_var_counter: usize,
    /// Maps flag variable names (like ZF) to original comparison operands.
    /// Used to reconstruct high-level comparisons from x86 cmp/test patterns.
    flag_origins: HashMap<String, (String, String)>,
    /// Maps subtraction result names to their operands (for CMP reconstruction).
    sub_results: HashMap<String, (String, String)>,
    /// Maps SSA variable keys to their copy sources (for tracing through copies).
    /// Key is display_name, value is display_name of source.
    copy_sources: HashMap<String, String>,
    /// Maps memory addresses (display_name of address var) to stored values (display_name).
    /// Used to trace through Store→Load pairs.
    memory_stores: HashMap<String, String>,
    /// Return register name ("rax" for 64-bit, "eax" for 32-bit).
    ret_reg_name: String,
    /// The function's exit block address (block containing SSAOp::Return).
    exit_block: Option<u64>,
    /// Blocks that branch directly to the exit block (these are "return" points).
    return_blocks: HashSet<u64>,
    /// Current block address being processed (for return detection).
    current_block_addr: Option<u64>,
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
            // NOTE: Stack register names are currently x86-only.
            // For ARM/MIPS support, these would need to be configurable:
            // - ARM: sp, fp (or r13, r11)
            // - MIPS: $sp, $fp ($29, $30)
            // Use set_stack_regs() to override for other architectures.
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
            flag_origins: HashMap::new(),
            sub_results: HashMap::new(),
            copy_sources: HashMap::new(),
            memory_stores: HashMap::new(),
            ret_reg_name: if ptr_size == 64 {
                "rax".to_string()
            } else {
                "eax".to_string()
            },
            exit_block: None,
            return_blocks: HashSet::new(),
            current_block_addr: None,
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

        // Second pass: build definitions and track copies/stores/loads
        for op in &block.ops {
            // Track Copy operations for tracing through to original sources
            if let SSAOp::Copy { dst, src } = op {
                self.copy_sources
                    .insert(dst.display_name(), src.display_name());
            }

            // Track Store operations: memory[addr] = val
            if let SSAOp::Store { addr, val, .. } = op {
                // Normalize the address to a canonical form for matching
                let addr_key = self.normalize_stack_address(addr);
                self.memory_stores.insert(addr_key, val.display_name());
            }

            // Track Load operations: dst = memory[addr]
            // If we previously stored to this address, link to the stored value
            if let SSAOp::Load { dst, addr, .. } = op {
                let addr_key = self.normalize_stack_address(addr);
                if let Some(stored_val) = self.memory_stores.get(&addr_key).cloned() {
                    // Link load result to the stored value
                    self.copy_sources.insert(dst.display_name(), stored_val);
                } else {
                    // Fallback: mark as memory load
                    self.copy_sources
                        .insert(dst.display_name(), format!("*{}", addr.display_name()));
                }
            }

            if let Some(dst) = op.dst() {
                let key = dst.display_name();
                let expr = self.op_to_expr(op);
                self.definitions.insert(key, expr);
            }
        }

        // Third pass: track comparison patterns (after definitions are built)
        // This allows us to trace through temporaries for comparison reconstruction
        for op in &block.ops {
            // Track IntSub results for CMP reconstruction
            // x86 CMP instruction is encoded as SUB that only sets flags
            if let SSAOp::IntSub { dst, a, b } = op {
                let dst_key = dst.display_name();
                // Trace through copies to find the original source variable
                let a_name = self.trace_ssa_var_to_source(a);
                let b_name = if b.is_const() {
                    // Format constant nicely
                    if let Some(val) = parse_const_value(&b.name) {
                        // Use hex for values that look like they were written as hex
                        // (> 255 and not a round decimal number)
                        if val > 255 && val % 10 != 0 {
                            format!("0x{:x}", val)
                        } else if val > 0xffff {
                            format!("0x{:x}", val)
                        } else {
                            format!("{}", val)
                        }
                    } else {
                        self.var_name(b)
                    }
                } else {
                    self.trace_ssa_var_to_source(b)
                };
                self.sub_results.insert(dst_key, (a_name, b_name));
            }

            // Track ZF origins: ZF = (sub_result == 0) means the original comparison
            // When ZF=1, it means a == b (from the subtraction a - b)
            if let SSAOp::IntEqual { dst, a, b } = op {
                let dst_name = dst.name.to_lowercase();
                // Check if this sets ZF and compares to zero
                if dst_name.contains("zf") {
                    if b.is_const() && parse_const_value(&b.name) == Some(0) {
                        // This is ZF = (sub_result == 0)
                        let a_key = a.display_name();
                        if let Some((orig_a, orig_b)) = self.sub_results.get(&a_key).cloned() {
                            // ZF=1 when orig_a == orig_b
                            self.flag_origins
                                .insert(dst.display_name(), (orig_a, orig_b));
                        }
                    }
                }
            }
        }
    }

    /// Trace an SSA variable back to its original source by following Copy operations.
    /// This is used for comparison reconstruction to find the actual argument name.
    fn trace_ssa_var_to_source(&self, var: &SSAVar) -> String {
        let mut current_key = var.display_name();
        let mut visited = HashSet::new();

        // Trace through up to 20 copies to find the source
        for _ in 0..20 {
            if visited.contains(&current_key) {
                break; // Cycle detected
            }
            visited.insert(current_key.clone());

            // Use copy_sources map to trace through copies
            if let Some(src_key) = self.copy_sources.get(&current_key) {
                // Check if this is a memory dereference marker
                if src_key.starts_with("*") {
                    // This was loaded from memory - can't trace further easily
                    // But check if the value stored there came from a register
                    // For now, just return a placeholder
                    return format!("var_{}", current_key.split('_').last().unwrap_or("0"));
                }
                current_key = src_key.clone();
                continue;
            }

            // No more copies - check what we have
            break;
        }

        // Format the final result nicely
        self.format_traced_name(&current_key)
    }

    /// Normalize a stack address for matching Store→Load pairs.
    /// Addresses like tmp:4700_1 and tmp:4700_2 at the same offset should match.
    fn normalize_stack_address(&self, addr: &SSAVar) -> String {
        // The address variable name contains the unique address (e.g., "tmp:4700")
        // Different versions (tmp:4700_1, tmp:4700_2) compute the same address
        // So we just use the base name without version
        let addr_key = addr.display_name();

        // Strip version number to get canonical address
        // "tmp:4700_1" -> "tmp:4700"
        if let Some((base, _)) = addr_key.rsplit_once('_') {
            return base.to_string();
        }

        addr_key
    }

    /// Format a traced SSA variable name for display.
    fn format_traced_name(&self, key: &str) -> String {
        // Check if it's a named register (not tmp: or const:)
        if !key.starts_with("tmp:") && !key.starts_with("const:") && !key.starts_with("ram:") {
            // It's a register name like "EDI_0" or "RAX_1"
            // Split into base and version
            if let Some((base, version)) = key.rsplit_once('_') {
                if version == "0" {
                    // Version 0 = function input/parameter
                    return base.to_lowercase();
                }
                // Other versions - show the name with version
                return format!("{}_{}", base.to_lowercase(), version);
            }
            return key.to_lowercase();
        }

        // For temporaries, generate a simple name
        if key.starts_with("tmp:") {
            // Extract version for unique naming
            if let Some(version) = key.rsplit_once('_').map(|(_, v)| v) {
                return format!("t{}", version);
            }
        }

        key.to_string()
    }

    /// Convert an expression to a simple name string (for comparison reconstruction).
    fn expr_to_simple_name(&self, expr: &CExpr) -> String {
        match expr {
            CExpr::Var(name) => {
                // Try to trace through to get the actual source
                self.trace_to_source(name)
            }
            CExpr::IntLit(val) => {
                if *val < 0 {
                    format!("{}", val)
                } else if *val > 0xffff {
                    format!("0x{:x}", val)
                } else {
                    format!("{}", val)
                }
            }
            CExpr::UIntLit(val) => {
                if *val > 0xffff {
                    format!("0x{:x}", val)
                } else {
                    format!("{}", val)
                }
            }
            // For complex expressions, just use a placeholder
            _ => format!("{:?}", expr),
        }
    }

    /// Trace through copies to find the original source variable.
    /// This is used for comparison reconstruction to get the actual argument name.
    /// Unlike get_expr, this traces through ALL copies regardless of use count.
    fn trace_to_source(&self, name: &str) -> String {
        let mut current = name.to_string();
        let mut visited = HashSet::new();

        // Trace through up to 20 copies to find the source
        for _ in 0..20 {
            if visited.contains(&current) {
                break; // Cycle detected
            }
            visited.insert(current.clone());

            // Look up the definition
            if let Some(expr) = self.definitions.get(&current) {
                match expr {
                    // If it's a simple variable reference, continue tracing
                    CExpr::Var(next_name) => {
                        // Check if this looks like a temp name (t1_1 style)
                        // If so, we haven't traced far enough - try to find its definition
                        if next_name.starts_with("t") && next_name.contains("_") {
                            // This is a temp var that wasn't inlined due to use count
                            // Try to find the original by looking for the tmp: definition
                            // We need to find the display name for this temp
                            // The temp name "t1_1" corresponds to "tmp:xxx_1"
                            // We can't easily reverse this, so just return what we have
                            current = next_name.clone();
                            continue;
                        }
                        // It's a register name or similar - could be the source
                        current = next_name.clone();
                        continue;
                    }
                    // If it's a cast, trace through
                    CExpr::Cast { expr: inner, .. } => {
                        if let CExpr::Var(next_name) = inner.as_ref() {
                            current = next_name.clone();
                            continue;
                        }
                    }
                    // For any other expression, we've found the definition
                    _ => {}
                }
            }
            break;
        }

        // Clean up the name - prefer readable format
        // If it's a version 0 register, it's likely a function parameter
        if current.ends_with("_0") && !current.starts_with("t") {
            // This is a register at version 0 - likely a parameter
            let base = current.strip_suffix("_0").unwrap_or(&current);
            // Make it more readable (e.g., "edi_0" -> "edi")
            return base.to_string();
        }

        current
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

    /// Parse a constant offset from an SSA variable.
    fn parse_const_offset(&self, var: &SSAVar) -> Option<i64> {
        if var.is_const() {
            if let Some(val) = parse_const_value(&var.name) {
                // Handle negative offsets stored as unsigned
                if val > LIKELY_NEGATIVE_THRESHOLD {
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
                let dst_name = dst.name.to_lowercase();
                // Check if this is a return value assignment in a return block
                if (dst_name == self.ret_reg_name || dst_name == "rax" || dst_name == "eax")
                    && self.is_current_return_block()
                {
                    // Emit return statement instead of assignment
                    return Some(CStmt::Return(Some(self.get_expr(src))));
                }
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
            SSAOp::CBranch { cond, .. } => Some(self.get_condition_expr(cond)),
            _ => None,
        }
    }

    /// Get the expression for a condition variable, always inlining its definition.
    /// Unlike get_expr(), this bypasses the should_inline() check because we always
    /// want to see the actual condition expression, not a temp variable name.
    fn get_condition_expr(&self, var: &SSAVar) -> CExpr {
        let key = var.display_name();

        // Always inline constants
        if var.is_const() {
            return self.const_to_expr(var);
        }

        // Try to inline the condition's definition
        if let Some(expr) = self.definitions.get(&key) {
            // Try to reconstruct comparison from flag patterns
            if let Some(reconstructed) = self.try_reconstruct_condition(expr) {
                return reconstructed;
            }
            return expr.clone();
        }

        // Fallback to variable reference
        CExpr::Var(self.var_name(var))
    }

    /// Try to reconstruct a high-level comparison from x86 flag patterns.
    /// Handles patterns like: BoolNot(ZF) -> a != b, ZF -> a == b
    fn try_reconstruct_condition(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
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
                }
                // Try to recurse into the operand
                if let Some(inner) = self.try_reconstruct_condition(operand) {
                    return Some(CExpr::unary(UnaryOp::Not, inner));
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
                None
            }
            // Pattern: SF (sign flag) could be a < 0 comparison
            // TODO: Handle more flag patterns (SF, CF, OF)
            _ => None,
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
        for (key, origin) in &self.flag_origins {
            if key.to_lowercase() == flag_lower {
                return Some(origin.clone());
            }
        }

        // Try matching by base name (without version suffix)
        // e.g., "zf_1" should match "ZF_1", "zf" should match "zf_1"
        for (key, origin) in &self.flag_origins {
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
            ctx.flag_origins.contains_key("ZF_1"),
            "ZF_1 should be in flag_origins"
        );

        // Check the origin values
        let (left, right) = ctx.flag_origins.get("ZF_1").unwrap();
        assert_eq!(left, "edi", "Left operand should be edi");
        assert_eq!(right, "0xdead", "Right operand should be 0xdead");
    }
}
