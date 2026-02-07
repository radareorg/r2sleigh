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

#[derive(Debug, Clone)]
struct PtrArith {
    base: SSAVar,
    index: SSAVar,
    element_size: u32,
    is_sub: bool,
}

/// Threshold for detecting 64-bit negative values stored as unsigned.
/// Values above this are likely negative offsets (within ~65536 of u64::MAX).
/// This handles cases like stack offsets: 0xffffffffffffffb8 represents -72.
const LIKELY_NEGATIVE_THRESHOLD: u64 = 0xffffffffffff0000;

/// Tracks use counts and definitions for expression folding.
#[derive(Debug)]
pub struct FoldingContext {
    /// Maps SSA variable name to its defining expression.
    definitions: HashMap<String, CExpr>,
    /// Reverse map: formatted display name -> SSA definition CExpr.
    /// Populated after analyze_blocks to allow condition reconstruction
    /// to look up definitions by their rendered C variable names.
    formatted_defs: HashMap<String, CExpr>,
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
    /// Tracks pointer arithmetic results for subscript reconstruction.
    ptr_arith: HashMap<String, PtrArith>,
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
    /// Collected call arguments: maps (block_addr, op_index) -> ordered arg expressions.
    call_args: HashMap<(u64, usize), Vec<CExpr>>,
    /// SSA variable names whose definitions are consumed by call argument collection.
    consumed_by_call: HashSet<String>,
    /// Out-of-SSA variable aliases: maps SSA display_name -> merged C name.
    var_aliases: HashMap<String, String>,
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
            ptr_arith: HashMap::new(),
            ret_reg_name: if ptr_size == 64 {
                "rax".to_string()
            } else {
                "eax".to_string()
            },
            exit_block: None,
            return_blocks: HashSet::new(),
            current_block_addr: None,
            userop_names: HashMap::new(),
            arg_regs: if ptr_size == 64 {
                vec![
                    "rdi".to_string(),
                    "rsi".to_string(),
                    "rdx".to_string(),
                    "rcx".to_string(),
                    "r8".to_string(),
                    "r9".to_string(),
                ]
            } else {
                // cdecl / x86-32: arguments are on the stack, no register args
                vec![]
            },
            caller_saved_regs: {
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
            },
            call_args: HashMap::new(),
            consumed_by_call: HashSet::new(),
            var_aliases: HashMap::new(),
            formatted_defs: HashMap::new(),
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
                    if self.consumed_by_call.contains(&key) {
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

    /// Look up a userop name for CallOther.
    fn lookup_userop_name(&self, userop: u32) -> String {
        self.userop_names
            .get(&userop)
            .cloned()
            .unwrap_or_else(|| format!("userop_{}", userop))
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

            if let SSAOp::PtrAdd {
                dst,
                base,
                index,
                element_size,
            } = op
            {
                self.ptr_arith.insert(
                    dst.display_name(),
                    PtrArith {
                        base: base.clone(),
                        index: index.clone(),
                        element_size: *element_size,
                        is_sub: false,
                    },
                );
            }

            if let SSAOp::PtrSub {
                dst,
                base,
                index,
                element_size,
            } = op
            {
                self.ptr_arith.insert(
                    dst.display_name(),
                    PtrArith {
                        base: base.clone(),
                        index: index.clone(),
                        element_size: *element_size,
                        is_sub: true,
                    },
                );
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

            // Track SF origins: SF = (sub_result < 0) - sign of the subtraction result
            // SF is set when the result is negative (high bit set)
            if let SSAOp::IntSLess { dst, a, b } = op {
                let dst_name = dst.name.to_lowercase();
                if dst_name.contains("sf") {
                    // SF = (sub_result < 0)
                    if b.is_const() && parse_const_value(&b.name) == Some(0) {
                        let a_key = a.display_name();
                        if let Some((orig_a, orig_b)) = self.sub_results.get(&a_key).cloned() {
                            self.flag_origins
                                .insert(dst.display_name(), (orig_a, orig_b));
                        }
                    }
                }
            }

            // Track OF origins: OF = IntSBorrow(a, b) - signed overflow from subtraction
            if let SSAOp::IntSBorrow { dst, a, b } = op {
                let dst_name = dst.name.to_lowercase();
                if dst_name.contains("of") {
                    // Trace operands like we do for IntSub
                    let a_name = self.trace_ssa_var_to_source(a);
                    let b_name = if b.is_const() {
                        if let Some(val) = parse_const_value(&b.name) {
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
                    self.flag_origins
                        .insert(dst.display_name(), (a_name, b_name));
                }
            }

            // Track CF origins: CF = IntLess(a, b) - unsigned carry/borrow from subtraction
            if let SSAOp::IntLess { dst, a, b } = op {
                let dst_name = dst.name.to_lowercase();
                if dst_name.contains("cf") {
                    // Trace operands
                    let a_name = self.trace_ssa_var_to_source(a);
                    let b_name = if b.is_const() {
                        if let Some(val) = parse_const_value(&b.name) {
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
                    self.flag_origins
                        .insert(dst.display_name(), (a_name, b_name));
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
    /// Different SSA versions of the same temp can compute different addresses
    /// (e.g., tmp:4700_1 = rbp-100, tmp:4700_2 = rbp-112).
    /// We need to look at the definition to get the actual offset.
    fn normalize_stack_address(&self, addr: &SSAVar) -> String {
        let addr_key = addr.display_name();

        // Check if we have a definition for this address variable
        if let Some(expr) = self.definitions.get(&addr_key) {
            // Try to extract the offset from the definition
            if let Some(offset) = self.extract_offset_from_expr(expr) {
                // Use the offset as the canonical key
                return format!("stack:{}", offset);
            }
        }

        // Fallback: use the full address key (including version) since
        // different versions can compute different addresses
        addr_key
    }

    /// Format a traced SSA variable name for display.
    fn format_traced_name(&self, key: &str) -> String {
        // Check coalesced alias first
        if let Some(alias) = self.var_aliases.get(key) {
            return alias.clone();
        }

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

        // For temporaries, generate a name matching var_name() output:
        // var_name: base="t{version}", then if version > 0: "{base}_{version}"
        if key.starts_with("tmp:") {
            if let Some(version_str) = key.rsplit_once('_').map(|(_, v)| v) {
                if let Ok(ver) = version_str.parse::<u32>() {
                    return if ver > 0 {
                        format!("t{}_{}", ver, ver)
                    } else {
                        "t0".to_string()
                    };
                }
                return format!("t{}", version_str);
            }
        }

        key.to_string()
    }

    /// Analyze multiple blocks (for function-level folding).
    pub fn analyze_blocks(&mut self, blocks: &[SSABlock]) {
        for block in blocks {
            self.analyze_block(block);
        }
        // Analyze stack variable patterns
        self.analyze_stack_vars(blocks);
        // Collect call arguments from pre-call register writes
        self.analyze_call_args(blocks);
        // Coalesce SSA versions into single variable names
        self.coalesce_variables(blocks);
        // Build reverse map: formatted name -> definition
        // This allows condition reconstruction to look up definitions by rendered names
        self.build_formatted_defs();
    }

    /// Build the reverse definitions map (formatted name -> CExpr).
    /// Must be called after coalesce_variables() since it depends on var_aliases.
    fn build_formatted_defs(&mut self) {
        self.formatted_defs.clear();
        for (ssa_key, expr) in &self.definitions {
            let formatted = self.format_traced_name(ssa_key);
            self.formatted_defs.insert(formatted, expr.clone());
        }
    }

    /// Coalesce SSA variable versions into single names where possible.
    ///
    /// Uses a union-find structure over phi node edges to group SSA versions
    /// that represent the same logical variable. Within each group, if no two
    /// versions appear in the same block, they all share the base register name.
    fn coalesce_variables(&mut self, blocks: &[SSABlock]) {
        // Step 1: Collect all named register SSA vars and build base-register map
        let mut reg_versions: HashMap<String, Vec<(String, u32)>> = HashMap::new();

        for block in blocks {
            for op in &block.ops {
                if let Some(dst) = op.dst() {
                    if dst.name.starts_with("tmp:") || dst.name.starts_with("const:")
                        || dst.name.starts_with("ram:") || dst.name.starts_with("reg:")
                    {
                        continue;
                    }
                    let base = dst.name.to_lowercase();
                    reg_versions.entry(base).or_default()
                        .push((dst.display_name(), dst.version));
                }
                for src in op.sources() {
                    if src.name.starts_with("tmp:") || src.name.starts_with("const:")
                        || src.name.starts_with("ram:") || src.name.starts_with("reg:")
                    {
                        continue;
                    }
                    let base = src.name.to_lowercase();
                    reg_versions.entry(base).or_default()
                        .push((src.display_name(), src.version));
                }
            }
            for phi in &block.phis {
                if !phi.dst.name.starts_with("tmp:") && !phi.dst.name.starts_with("const:")
                    && !phi.dst.name.starts_with("ram:") && !phi.dst.name.starts_with("reg:")
                {
                    let base = phi.dst.name.to_lowercase();
                    reg_versions.entry(base).or_default()
                        .push((phi.dst.display_name(), phi.dst.version));
                }
                for (_, src) in &phi.sources {
                    if !src.name.starts_with("tmp:") && !src.name.starts_with("const:")
                        && !src.name.starts_with("ram:") && !src.name.starts_with("reg:")
                    {
                        let base = src.name.to_lowercase();
                        reg_versions.entry(base).or_default()
                            .push((src.display_name(), src.version));
                    }
                }
            }
        }

        // Step 2: Build union-find and merge phi-connected versions
        let mut uf_parent: HashMap<String, String> = HashMap::new();

        // Initialize each SSA name as its own parent
        for versions in reg_versions.values() {
            for (name, _) in versions {
                uf_parent.entry(name.clone()).or_insert_with(|| name.clone());
            }
        }

        // Union phi-connected versions
        for block in blocks {
            for phi in &block.phis {
                if phi.dst.name.starts_with("tmp:") || phi.dst.name.starts_with("const:")
                    || phi.dst.name.starts_with("ram:") || phi.dst.name.starts_with("reg:")
                {
                    continue;
                }
                let dst_key = phi.dst.display_name();
                for (_, src) in &phi.sources {
                    let src_key = src.display_name();
                    // Union dst and src
                    let root_a = uf_find(&mut uf_parent, &dst_key);
                    let root_b = uf_find(&mut uf_parent, &src_key);
                    if root_a != root_b {
                        uf_parent.insert(root_a, root_b);
                    }
                }
            }
        }

        // Step 3: Build block -> set of SSA names
        let mut block_vars: HashMap<u64, HashSet<String>> = HashMap::new();
        for block in blocks {
            let vars = block_vars.entry(block.addr).or_default();
            for op in &block.ops {
                if let Some(dst) = op.dst() {
                    vars.insert(dst.display_name());
                }
                for src in op.sources() {
                    vars.insert(src.display_name());
                }
            }
            for phi in &block.phis {
                vars.insert(phi.dst.display_name());
                for (_, src) in &phi.sources {
                    vars.insert(src.display_name());
                }
            }
        }

        // Step 4: For each base register, group by union-find root and assign names
        for (base, versions) in &reg_versions {
            if *base == self.sp_name || *base == self.fp_name {
                continue;
            }
            // Deduplicate
            let mut unique: Vec<(String, u32)> = versions.clone();
            unique.sort_by_key(|(_, v)| *v);
            unique.dedup_by_key(|(k, _)| k.clone());
            if unique.len() <= 1 {
                continue;
            }

            // Group by union-find root
            let mut groups: HashMap<String, Vec<String>> = HashMap::new();
            for (ssa_name, _) in &unique {
                let root = uf_find(&mut uf_parent, ssa_name);
                groups.entry(root).or_default().push(ssa_name.clone());
            }

            // For each group, check if members conflict (appear in the same block)
            let mut group_idx = 0usize;
            for (_root, members) in &groups {
                let has_conflict = block_vars.values().any(|vars| {
                    let mut count = 0;
                    for m in members {
                        if vars.contains(m) {
                            count += 1;
                        }
                    }
                    count > 1
                });

                if !has_conflict {
                    // All members share the base name
                    let alias = if group_idx == 0 {
                        base.clone()
                    } else {
                        format!("{}_{}", base, group_idx + 1)
                    };
                    for m in members {
                        self.var_aliases.insert(m.clone(), alias.clone());
                    }
                    group_idx += 1;
                } else {
                    // Members conflict -- assign base name to the group representative
                    // and leave others with their versioned names
                    let alias = if group_idx == 0 {
                        base.clone()
                    } else {
                        format!("{}_{}", base, group_idx + 1)
                    };
                    // Only alias version 0 if present
                    for m in members {
                        // Check if this is version 0
                        if let Some((_, v)) = unique.iter().find(|(n, _)| n == m) {
                            if *v == 0 {
                                self.var_aliases.insert(m.clone(), alias.clone());
                            }
                        }
                    }
                    group_idx += 1;
                }
            }

            // If there are ungrouped singletons, also try to alias them
            // (versions not in any phi chain but still non-conflicting)
            let grouped: HashSet<&str> = groups.values()
                .flat_map(|v| v.iter().map(|s| s.as_str()))
                .collect();
            let ungrouped: Vec<&(String, u32)> = unique.iter()
                .filter(|(n, _)| !grouped.contains(n.as_str()) && !self.var_aliases.contains_key(n))
                .collect();
            if !ungrouped.is_empty() {
                // Check if all ungrouped can share a name
                let ug_names: Vec<&str> = ungrouped.iter().map(|(n, _)| n.as_str()).collect();
                let has_conflict = block_vars.values().any(|vars| {
                    let mut count = 0;
                    for n in &ug_names {
                        if vars.contains(*n) {
                            count += 1;
                        }
                    }
                    count > 1
                });
                if !has_conflict {
                    let alias = if group_idx == 0 { base.clone() } else { format!("{}_{}", base, group_idx + 1) };
                    for (n, _) in &ungrouped {
                        self.var_aliases.insert(n.clone(), alias.clone());
                    }
                }
            }
        }
    }

    /// Analyze blocks to collect call arguments from register writes preceding calls.
    ///
    /// For each Call/CallInd, scan backwards to find Copy ops that write to
    /// calling-convention argument registers (RDI, RSI, RDX, RCX, R8, R9).
    /// Also handles IntZExt targeting those registers (common for 32-bit args).
    fn analyze_call_args(&mut self, blocks: &[SSABlock]) {
        if self.arg_regs.is_empty() {
            return;
        }

        for block in blocks {
            let ops = &block.ops;
            for (call_idx, op) in ops.iter().enumerate() {
                let is_call = matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. });
                if !is_call {
                    continue;
                }

                // Scan backwards from this call to collect arg register writes
                let mut found_regs: HashMap<String, (CExpr, String)> = HashMap::new();
                let mut i = call_idx;
                while i > 0 {
                    i -= 1;
                    let prev_op = &ops[i];

                    // Stop at another call (barrier)
                    if matches!(prev_op, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                        break;
                    }

                    // Check Copy and IntZExt ops that write to arg registers
                    let (dst_var, src_var) = match prev_op {
                        SSAOp::Copy { dst, src } => (dst, Some(src)),
                        SSAOp::IntZExt { dst, src } => (dst, Some(src)),
                        SSAOp::IntSExt { dst, src } => (dst, Some(src)),
                        _ => continue,
                    };

                    let dst_base = dst_var.name.to_lowercase();
                    // Check if this writes to an arg register
                    if let Some(_pos) = self.arg_regs.iter().position(|r| *r == dst_base) {
                        if !found_regs.contains_key(&dst_base) {
                            if let Some(src) = src_var {
                                let expr = self.get_expr(src);
                                let dst_key = dst_var.display_name();
                                found_regs.insert(dst_base.clone(), (expr, dst_key));
                            }
                        }
                    }
                }

                // Build ordered argument list based on calling convention order
                let mut args = Vec::new();
                let mut consumed_keys = Vec::new();
                for reg in &self.arg_regs {
                    if let Some((expr, dst_key)) = found_regs.remove(reg) {
                        args.push(expr);
                        consumed_keys.push(dst_key);
                    } else {
                        // Gap in arguments - stop collecting
                        // (e.g., if RDI and RDX are set but not RSI, only take RDI)
                        break;
                    }
                }

                if !args.is_empty() {
                    self.call_args.insert((block.addr, call_idx), args);
                    for key in consumed_keys {
                        self.consumed_by_call.insert(key);
                    }
                }

                // Also detect pre-call return address push pattern:
                //   IntSub { dst: RSP_N, a: RSP_M, b: const:8 }
                //   Store  { addr: RSP_N, val: const:RETADDR }
                // Mark both as consumed.
                let mut j = call_idx;
                while j > 0 {
                    j -= 1;
                    let prev = &ops[j];
                    // Stop at another call
                    if matches!(prev, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
                        break;
                    }
                    // Look for Store of a constant to an RSP-derived address
                    if let SSAOp::Store { addr, val, .. } = prev {
                        let addr_lower = addr.name.to_lowercase();
                        if addr_lower.contains(&self.sp_name) && val.is_const() {
                            // This is likely push of return address
                            let store_val_key = val.display_name();
                            self.consumed_by_call.insert(store_val_key);
                            let addr_key = addr.display_name();
                            self.consumed_by_call.insert(addr_key);
                            // Also find the preceding IntSub that adjusted RSP
                            if j > 0 {
                                let prev2 = &ops[j - 1];
                                if let SSAOp::IntSub { dst, b, .. } = prev2 {
                                    let dst_lower = dst.name.to_lowercase();
                                    if dst_lower.contains(&self.sp_name) && b.is_const() {
                                        let sub_key = dst.display_name();
                                        self.consumed_by_call.insert(sub_key);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
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
        // Don't inline if it has multiple uses
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
            // Inline any single-use register with a simple definition
            if self.definitions.contains_key(var_name) {
                return true;
            }
        }

        false
    }

    /// Check if a variable is dead (never used).
    pub fn is_dead(&self, var: &SSAVar) -> bool {
        let key = var.display_name();
        let use_count = self.use_counts.get(&key).copied().unwrap_or(0);

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

        // CPU flags are always dead if unused
        let lower = var.name.to_lowercase();
        if is_cpu_flag(&lower) {
            return true;
        }

        // Caller-saved / calling-convention registers are dead if unused
        // (their values don't survive across calls anyway)
        if self.caller_saved_regs.contains(&lower) {
            return true;
        }

        // Variables consumed by call argument collection are dead
        if self.consumed_by_call.contains(&key) {
            return true;
        }

        // Stack/frame pointer intermediate versions are dead if unused
        if lower == self.sp_name || lower == self.fp_name {
            return true;
        }

        // Keep other named registers alive (e.g., callee-saved like rbx, r12-r15)
        // as they might be meaningful outputs
        false
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
                    if self.consumed_by_call.contains(&val_key) {
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
                    if val_name.contains("rbx") || val_name.contains("r12")
                        || val_name.contains("r13") || val_name.contains("r14")
                        || val_name.contains("r15")
                    {
                        return true;
                    }
                    // Indirect: val is a temp, trace it back via copy_sources
                    if val.name.starts_with("tmp:") {
                        let val_key = val.display_name();
                        if let Some(src_key) = self.copy_sources.get(&val_key) {
                            let src_lower = src_key.to_lowercase();
                            if src_lower.contains("rbx") || src_lower.contains("r12")
                                || src_lower.contains("r13") || src_lower.contains("r14")
                                || src_lower.contains("r15") || src_lower.contains(&self.fp_name)
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
                    && (dst_name.contains("rbx") || dst_name.contains("r12")
                        || dst_name.contains("r13") || dst_name.contains("r14")
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

        // Check if coalescing mapped this SSA name to a merged name
        let display = var.display_name();
        if let Some(alias) = self.var_aliases.get(&display) {
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
    fn op_to_expr(&self, op: &SSAOp) -> CExpr {
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
                let addr_expr = self.get_expr(addr);
                if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                    CExpr::Var(stack_var)
                } else if let Some(ptr) = self.ptr_arith.get(&addr.display_name()) {
                    self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
                } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                    sub
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
            SSAOp::BoolAnd { a, b, .. } => self.binary_expr(BinaryOp::And, a, b),
            SSAOp::BoolOr { a, b, .. } => self.binary_expr(BinaryOp::Or, a, b),
            SSAOp::BoolXor { a, b, .. } => self.binary_expr(BinaryOp::BitXor, a, b),
            SSAOp::BoolNot { src, .. } => CExpr::unary(UnaryOp::Not, self.get_expr(src)),
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
        CExpr::binary(op, self.get_expr(a), self.get_expr(b))
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
            .definitions
            .get(&addr.display_name())
            .cloned()
            .unwrap_or_else(|| addr_expr.clone());

        let (base_expr, index_expr, elem_size, is_sub) = self.extract_base_index_scale(&expr)?;

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
                if let Some(def) = self.definitions.get(name) {
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

    fn lookup_definition(&self, name: &str) -> Option<CExpr> {
        if let Some(expr) = self.definitions.get(name) {
            return Some(expr.clone());
        }
        if let Some((base, version)) = name.rsplit_once('_') {
            let upper = format!("{}_{}", base.to_uppercase(), version);
            if let Some(expr) = self.definitions.get(&upper) {
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

        for (op_idx, op) in block.ops.iter().enumerate() {
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

                // Skip if this op's destination was consumed by call argument collection
                if self.consumed_by_call.contains(&key) {
                    continue;
                }
            }

            if let Some(stmt) = self.op_to_stmt_with_args(op, block.addr, op_idx) {
                stmts.push(stmt);
            }
        }

        stmts
    }

    /// Convert an SSA operation to a C statement, with call argument context.
    fn op_to_stmt_with_args(&self, op: &SSAOp, block_addr: u64, op_idx: usize) -> Option<CStmt> {
        match op {
            SSAOp::Call { target } => {
                let func_expr = self.resolve_call_target(target);
                let args = self
                    .call_args
                    .get(&(block_addr, op_idx))
                    .cloned()
                    .unwrap_or_default();
                let call = CExpr::call(func_expr, args);
                Some(CStmt::Expr(call))
            }
            SSAOp::CallInd { target } => {
                let target_expr = self.get_expr(target);
                let func_expr = CExpr::Deref(Box::new(target_expr));
                let args = self
                    .call_args
                    .get(&(block_addr, op_idx))
                    .cloned()
                    .unwrap_or_default();
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
        } else if target.is_const() {
            if let Some(addr) = parse_const_value(&target.name) {
                if let Some(name) = self.lookup_function(addr) {
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
                    // Try to use stack variable name if this is a stack access
                    let addr_expr = self.get_expr(addr);
                    let addr_key = addr.display_name();
                    if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                        CExpr::Var(stack_var)
                    } else if let Some(ptr) = self.ptr_arith.get(&addr_key) {
                        self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
                    } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                        sub
                    } else {
                        CExpr::Deref(Box::new(addr_expr))
                    }
                };
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
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
                    // Try to use stack variable name if this is a stack access
                    let addr_expr = self.get_expr(addr);
                    let addr_key = addr.display_name();
                    if let Some(stack_var) = self.simplify_stack_access(&addr_expr) {
                        CExpr::Var(stack_var)
                    } else if let Some(ptr) = self.ptr_arith.get(&addr_key) {
                        self.ptr_subscript_expr(&ptr.base, &ptr.index, ptr.element_size, ptr.is_sub)
                    } else if let Some(sub) = self.try_subscript_from_expr(addr, &addr_expr) {
                        sub
                    } else {
                        CExpr::Deref(Box::new(addr_expr))
                    }
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
            SSAOp::BoolXor { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::BitXor),
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
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
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
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
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
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::PtrSub {
                dst,
                base,
                index,
                element_size,
            } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = self.ptr_arith_expr(base, index, *element_size, true);
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
            }
            SSAOp::Cast { dst, src } => {
                let lhs = CExpr::Var(self.var_name(dst));
                let rhs = CExpr::cast(type_from_size(dst.size), self.get_expr(src));
                Some(CStmt::Expr(CExpr::assign(lhs, rhs)))
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

        // If the variable is a flag (ZF, CF, etc.), try direct flag reconstruction first
        let var_lower = var.name.to_lowercase();
        if var_lower.contains("zf") || var_lower.contains("cf")
            || var_lower.contains("sf") || var_lower.contains("of")
        {
            let var_cname = self.var_name(var);
            if let Some(reconstructed) =
                self.try_reconstruct_condition(&CExpr::Var(var_cname))
            {
                return reconstructed;
            }
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
    fn try_reconstruct_condition(&self, expr: &CExpr) -> Option<CExpr> {
        match expr {
            // Pattern: Binary AND - check for signed greater than: !ZF && (OF == SF)
            CExpr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => {
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
        let def = self.definitions.get(var_name)
            .or_else(|| self.formatted_defs.get(var_name))?;

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

    /// Extract ZF variable name from an expression (if it's a ZF flag reference).
    fn extract_zf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if name.to_lowercase().contains("zf") {
                return Some(name.clone());
            }
        }
        None
    }

    /// Extract CF variable name from an expression (if it's a CF flag reference).
    fn extract_cf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if name.to_lowercase().contains("cf") {
                return Some(name.clone());
            }
        }
        None
    }

    /// Extract SF variable name from an expression (if it's a SF flag reference).
    fn extract_sf(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if name.to_lowercase().contains("sf") {
                return Some(name.clone());
            }
        }
        None
    }

    /// Extract OF variable name from an expression (if it's an OF flag reference).
    fn extract_of(&self, expr: &CExpr) -> Option<String> {
        if let CExpr::Var(name) = expr {
            if name.to_lowercase().contains("of") {
                return Some(name.clone());
            }
        }
        None
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
            let has_of_sf = self.extract_of(left).is_some() && self.extract_sf(right).is_some();
            let has_sf_of = self.extract_sf(left).is_some() && self.extract_of(right).is_some();
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
            let has_of_sf = self.extract_of(left).is_some() && self.extract_sf(right).is_some();
            let has_sf_of = self.extract_sf(left).is_some() && self.extract_of(right).is_some();
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
/// Union-find: find the root representative with path compression.
fn uf_find(parent: &mut HashMap<String, String>, x: &str) -> String {
    let p = parent.get(x).cloned().unwrap_or_else(|| x.to_string());
    if p == x {
        return x.to_string();
    }
    let root = uf_find(parent, &p);
    parent.insert(x.to_string(), root.clone());
    root
}

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
            ctx.flag_origins.contains_key("ZF_1"),
            "ZF_1 should be in flag_origins"
        );

        // Check the origin values
        let (left, right) = ctx.flag_origins.get("ZF_1").unwrap();
        assert_eq!(left, "edi", "Left operand should be edi");
        assert_eq!(right, "0xdead", "Right operand should be 0xdead");
    }
}
