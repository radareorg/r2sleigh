//! r2dec - Decompiler for r2sleigh.
//!
//! This crate provides decompilation capabilities for the r2sleigh project,
//! converting SSA form to readable C code.
//!
//! ## Overview
//!
//! The decompilation pipeline consists of:
//!
//! 1. **AST** (`ast`): C Abstract Syntax Tree representation
//! 2. **Expression Building** (`expr`): Convert SSA operations to C expressions
//! 3. **Region Identification** (`region`): Identify control flow regions
//! 4. **Control Flow Structuring** (`structure`): Convert CFG to structured code
//! 5. **Type Inference** (`types`): Infer C types from operations
//! 6. **Variable Recovery** (`variable`): Recover variable names and types
//! 7. **Code Generation** (`codegen`): Generate readable C source code
//!
//! ## Usage
//!
//! ```ignore
//! use r2dec::{Decompiler, DecompilerConfig};
//! use r2ssa::SSAFunction;
//!
//! let func: SSAFunction = /* ... */;
//! let config = DecompilerConfig::default();
//! let decompiler = Decompiler::new(config);
//! let c_code = decompiler.decompile(&func);
//! println!("{}", c_code);
//! ```

pub(crate) mod address;
pub(crate) mod analysis;
pub mod ast;
pub mod codegen;
pub mod fold;
pub(crate) mod normalize;
pub(crate) mod post_rename;
pub mod region;
pub mod structure;
pub mod types;
pub mod variable;

pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::{CodeGenConfig, CodeGenerator, generate};
pub use fold::lower_ssa_ops_to_stmts;
pub use region::{Region, RegionAnalyzer};
pub use structure::ControlFlowStructurer;
pub use types::TypeInference;
pub use variable::VariableRecovery;

use crate::fold::FoldingContext;
use crate::fold::context::{FoldArchConfig, FoldInputs};
use r2ssa::SSAFunction;
use r2ssa::SSAOp;
use r2types::ExternalTypeDb;
use r2types::TypeOracle;
use std::collections::HashSet;
use types::FunctionType;

fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

fn normalize_callee_name(name: &str) -> String {
    let mut out = name.trim().to_ascii_lowercase();
    for prefix in ["sym.imp.", "sym.", "fcn."] {
        if let Some(rest) = out.strip_prefix(prefix) {
            out = rest.to_string();
            break;
        }
    }
    if let Some((base, ver)) = out.rsplit_once('_')
        && !base.is_empty()
        && ver.chars().all(|c| c.is_ascii_digit())
    {
        return base.to_string();
    }
    out
}

fn merge_params_with_external_signature(
    recovered_params: Vec<ast::CParam>,
    signature: Option<&ExternalFunctionSignature>,
) -> Vec<ast::CParam> {
    let Some(signature) = signature else {
        return recovered_params;
    };

    if signature.params.is_empty() {
        return recovered_params;
    }

    let target_len = recovered_params.len().max(signature.params.len());
    (0..target_len)
        .map(|idx| {
            let fallback_name = format!("arg{}", idx + 1);
            let mut param = recovered_params.get(idx).cloned().unwrap_or(ast::CParam {
                ty: CType::Int(32),
                name: fallback_name,
            });

            if let Some(ext) = signature.params.get(idx) {
                if !is_generic_arg_name(&ext.name) {
                    param.name = ext.name.clone();
                }
                if let Some(ext_ty) = &ext.ty {
                    param.ty = ext_ty.clone();
                }
            }

            param
        })
        .collect()
}

fn register_alias_names(reg_name: &str) -> Vec<String> {
    let lower = reg_name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Vec::new();
    }

    match lower.as_str() {
        "rdi" | "edi" | "di" | "dil" => {
            return vec!["rdi", "edi", "di", "dil"]
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        "rsi" | "esi" | "si" | "sil" => {
            return vec!["rsi", "esi", "si", "sil"]
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        "rdx" | "edx" | "dx" | "dl" => {
            return vec!["rdx", "edx", "dx", "dl"]
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        "rcx" | "ecx" | "cx" | "cl" => {
            return vec!["rcx", "ecx", "cx", "cl"]
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        _ => {}
    }

    for base in ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"] {
        if lower == base
            || lower == format!("{base}d")
            || lower == format!("{base}w")
            || lower == format!("{base}b")
        {
            return vec![
                base.to_string(),
                format!("{base}d"),
                format!("{base}w"),
                format!("{base}b"),
            ];
        }
    }

    if let Some(rest) = lower.strip_prefix('x')
        && rest.chars().all(|c| c.is_ascii_digit())
    {
        return vec![lower.clone(), format!("w{rest}")];
    }
    if let Some(rest) = lower.strip_prefix('w')
        && rest.chars().all(|c| c.is_ascii_digit())
    {
        return vec![format!("x{rest}"), lower];
    }

    vec![lower]
}

fn build_param_register_aliases(
    params: &[ast::CParam],
    recovered_params: &[(r2ssa::SSAVar, ast::CParam)],
    register_params: &[ExternalRegisterParam],
) -> std::collections::HashMap<String, String> {
    let mut aliases = std::collections::HashMap::new();

    for (idx, (ssa_var, _)) in recovered_params.iter().enumerate() {
        if let Some(param) = params.get(idx) {
            aliases.insert(ssa_var.name.to_ascii_lowercase(), param.name.clone());
        }
    }

    for (idx, reg_param) in register_params.iter().enumerate() {
        let Some(param) = params.get(idx) else {
            continue;
        };
        for alias in register_alias_names(&reg_param.reg) {
            aliases.insert(alias, param.name.clone());
        }
    }

    aliases
}

/// Decompiler configuration.
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// Code generation configuration.
    pub codegen: CodeGenConfig,
    /// Pointer size in bits.
    pub ptr_size: u32,
    /// Stack pointer register name.
    pub sp_name: String,
    /// Frame pointer register name.
    pub fp_name: String,
    /// Ordered argument registers for the active ABI.
    pub arg_regs: Vec<String>,
    /// Return-value registers for the active ABI.
    pub ret_regs: Vec<String>,
    /// Caller-saved registers for the active ABI.
    pub caller_saved_regs: HashSet<String>,
    /// Soft cap for function blocks before forcing fallback.
    pub max_blocks: usize,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            codegen: CodeGenConfig::default(),
            ptr_size: 64,
            sp_name: "rsp".to_string(),
            fp_name: "rbp".to_string(),
            arg_regs: vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ],
            ret_regs: vec![
                "rax".to_string(),
                "eax".to_string(),
                "xmm0".to_string(),
                "xmm0_qa".to_string(),
                "xmm0_qb".to_string(),
                "st0".to_string(),
            ],
            caller_saved_regs: ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            max_blocks: 200,
        }
    }
}

impl DecompilerConfig {
    /// Create a configuration for 32-bit x86.
    pub fn x86() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "esp".to_string(),
            fp_name: "ebp".to_string(),
            arg_regs: vec![],
            ret_regs: vec!["eax".to_string(), "xmm0".to_string(), "st0".to_string()],
            caller_saved_regs: ["eax", "ecx", "edx"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for 64-bit x86.
    pub fn x86_64() -> Self {
        Self::default()
    }

    /// Create a configuration for ARM.
    pub fn arm() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "sp".to_string(),
            fp_name: "fp".to_string(),
            arg_regs: ["r0", "r1", "r2", "r3"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["r0".to_string()],
            caller_saved_regs: ["r0", "r1", "r2", "r3", "r12", "lr", "ip"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for AArch64.
    pub fn aarch64() -> Self {
        Self {
            ptr_size: 64,
            sp_name: "sp".to_string(),
            fp_name: "fp".to_string(),
            arg_regs: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["x0".to_string(), "w0".to_string()],
            caller_saved_regs: [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for RISC-V RV32.
    pub fn riscv32() -> Self {
        Self {
            ptr_size: 32,
            sp_name: "sp".to_string(),
            fp_name: "s0".to_string(),
            arg_regs: ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["a0".to_string()],
            caller_saved_regs: [
                "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }

    /// Create a configuration for RISC-V RV64.
    pub fn riscv64() -> Self {
        Self {
            ptr_size: 64,
            sp_name: "sp".to_string(),
            fp_name: "s0".to_string(),
            arg_regs: ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ret_regs: vec!["a0".to_string()],
            caller_saved_regs: [
                "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            ..Default::default()
        }
    }
}

/// External information for decompilation (function names, strings, symbols).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFunctionParam {
    /// Parameter name recovered from external metadata.
    pub name: String,
    /// Optional type recovered from external metadata.
    pub ty: Option<CType>,
}

/// External register-backed parameter metadata recovered from host analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRegisterParam {
    /// Parameter name recovered from external metadata.
    pub name: String,
    /// Optional type recovered from external metadata.
    pub ty: Option<CType>,
    /// Register reference reported by host analysis.
    pub reg: String,
}

/// External function signature recovered from host analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalFunctionSignature {
    /// Optional return type.
    pub ret_type: Option<CType>,
    /// Ordered parameters.
    pub params: Vec<ExternalFunctionParam>,
}

/// External stack variable metadata recovered from host analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalStackVar {
    /// Variable name.
    pub name: String,
    /// Optional variable type.
    pub ty: Option<CType>,
    /// Base register used by the analysis backend (e.g. RBP/RSP).
    pub base: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DecompilerContext {
    /// Function address to name mapping.
    pub function_names: std::collections::HashMap<u64, String>,
    /// String literal addresses.
    pub strings: std::collections::HashMap<u64, String>,
    /// Symbol/global variable names.
    pub symbols: std::collections::HashMap<u64, String>,
    /// Optional external function signature.
    pub function_signature: Option<ExternalFunctionSignature>,
    /// Register-backed parameter metadata from host analysis.
    pub register_params: Vec<ExternalRegisterParam>,
    /// Optional known function signatures from host analysis.
    pub known_function_signatures: std::collections::HashMap<String, FunctionType>,
    /// Stack variables keyed by signed stack offset.
    pub stack_vars: std::collections::HashMap<i64, ExternalStackVar>,
    /// Optional external host type database (e.g. tsj payload).
    pub external_type_db: ExternalTypeDb,
}

/// The main decompiler.
pub struct Decompiler {
    config: DecompilerConfig,
    context: DecompilerContext,
}

impl Decompiler {
    /// Create a new decompiler with the given configuration.
    pub fn new(config: DecompilerConfig) -> Self {
        Self {
            config,
            context: DecompilerContext::default(),
        }
    }

    /// Set external context (function names, strings, symbols).
    pub fn with_context(mut self, context: DecompilerContext) -> Self {
        self.context = context;
        self
    }

    /// Set function names for call target resolution.
    pub fn set_function_names(&mut self, names: std::collections::HashMap<u64, String>) {
        self.context.function_names = names;
    }

    /// Set string literals for address resolution.
    pub fn set_strings(&mut self, strings: std::collections::HashMap<u64, String>) {
        self.context.strings = strings;
    }

    /// Set symbol names for global variable resolution.
    pub fn set_symbols(&mut self, symbols: std::collections::HashMap<u64, String>) {
        self.context.symbols = symbols;
    }

    /// Set an externally recovered function signature.
    pub fn set_function_signature(&mut self, signature: Option<ExternalFunctionSignature>) {
        self.context.function_signature = signature;
    }

    /// Set externally recovered register-backed parameters.
    pub fn set_register_params(&mut self, register_params: Vec<ExternalRegisterParam>) {
        self.context.register_params = register_params;
    }

    /// Set externally recovered known function signatures keyed by name.
    pub fn set_known_function_signatures(
        &mut self,
        signatures: std::collections::HashMap<String, FunctionType>,
    ) {
        self.context.known_function_signatures = signatures;
    }

    /// Set externally recovered stack variables keyed by signed stack offset.
    pub fn set_stack_vars(&mut self, stack_vars: std::collections::HashMap<i64, ExternalStackVar>) {
        self.context.stack_vars = stack_vars;
    }

    /// Set externally recovered host type database.
    pub fn set_external_type_db(&mut self, external_type_db: ExternalTypeDb) {
        self.context.external_type_db = external_type_db;
    }

    /// Decompile an SSA function to C code.
    pub fn decompile(&self, func: &SSAFunction) -> String {
        // Build the C function
        let c_func = self.build_function(func);

        // Generate code
        let mut codegen = CodeGenerator::new(self.config.codegen.clone());
        codegen.generate_function(&c_func)
    }

    fn stmt_has_content(stmt: &CStmt) -> bool {
        match stmt {
            CStmt::Empty => false,
            CStmt::Block(stmts) => !stmts.is_empty(),
            _ => true,
        }
    }

    fn prepend_comment(stmt: CStmt, text: String) -> CStmt {
        let comment = CStmt::comment(text);
        match stmt {
            CStmt::Empty => CStmt::Block(vec![comment]),
            CStmt::Block(mut stmts) => {
                stmts.insert(0, comment);
                CStmt::Block(stmts)
            }
            other => CStmt::Block(vec![comment, other]),
        }
    }

    fn linearize_function_body(
        &self,
        func: &SSAFunction,
        fold_ctx: &FoldingContext<'_>,
    ) -> Vec<CStmt> {
        let blocks: Vec<_> = func.blocks().cloned().collect();
        let mut stmts = Vec::new();

        for block in &blocks {
            for stmt in fold_ctx.fold_block(block, block.addr) {
                if !matches!(stmt, CStmt::Empty) {
                    stmts.push(stmt);
                }
            }
        }

        stmts
    }

    /// Build a C function from an SSA function.
    pub fn build_function(&self, func: &SSAFunction) -> CFunction {
        // Materialize phis on non-critical edges to reduce SSA artifacts in output.
        let normalized_func = normalize::materialize_phis(func);
        let func = &normalized_func;

        // Recover variables
        let mut var_recovery = VariableRecovery::new_with_abi(
            &self.config.sp_name,
            &self.config.fp_name,
            self.config.ptr_size,
            self.config.arg_regs.clone(),
            self.config.ret_regs.clone(),
        );
        if let Some(signature) = &self.context.function_signature {
            var_recovery.set_external_signature(signature.clone());
        }
        if !self.context.stack_vars.is_empty() {
            var_recovery.set_external_stack_vars(self.context.stack_vars.clone());
        }
        var_recovery.recover(func);

        // Infer types
        let mut type_inference = TypeInference::new_with_abi(
            self.config.ptr_size,
            self.config.arg_regs.clone(),
            self.config.ret_regs.clone(),
        );
        if !self.context.function_names.is_empty() {
            type_inference.set_function_names(self.context.function_names.clone());
        }
        if self.context.function_signature.is_some() {
            type_inference.set_external_signature(self.context.function_signature.clone());
        }
        for (name, signature) in &self.context.known_function_signatures {
            type_inference.add_function_type(name, signature.clone());
        }
        if !self.context.stack_vars.is_empty() {
            type_inference.set_external_stack_vars(self.context.stack_vars.clone());
        }
        if !self.context.external_type_db.structs.is_empty()
            || !self.context.external_type_db.unions.is_empty()
            || !self.context.external_type_db.enums.is_empty()
        {
            type_inference.set_external_type_db(self.context.external_type_db.clone());
        }
        type_inference.infer_function(func);
        let type_hints = type_inference.var_type_hints();
        let type_oracle = type_inference
            .solved_types()
            .map(|solved| solved as &dyn TypeOracle);

        let known_function_signatures = self
            .context
            .known_function_signatures
            .iter()
            .map(|(name, ty)| (normalize_callee_name(name), ty.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let mut recovered_param_infos: Vec<_> = var_recovery
            .parameters()
            .iter()
            .map(|v| {
                (
                    v.ssa_var.clone(),
                    ast::CParam {
                        ty: type_inference.get_type(&v.ssa_var),
                        name: v.name.clone(),
                    },
                )
            })
            .collect();
        recovered_param_infos.sort_by(|a, b| {
            let ai =
                a.1.name
                    .strip_prefix("arg")
                    .and_then(|n| n.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
            let bi =
                b.1.name
                    .strip_prefix("arg")
                    .and_then(|n| n.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
            ai.cmp(&bi).then_with(|| a.1.name.cmp(&b.1.name))
        });
        let params = merge_params_with_external_signature(
            recovered_param_infos
                .iter()
                .map(|(_, param)| param.clone())
                .collect(),
            self.context.function_signature.as_ref(),
        );
        let param_register_aliases = build_param_register_aliases(
            &params,
            &recovered_param_infos,
            &self.context.register_params,
        );

        let fold_arch = FoldArchConfig {
            ptr_size: self.config.ptr_size,
            sp_name: self.config.sp_name.clone(),
            fp_name: self.config.fp_name.clone(),
            ret_reg_name: self
                .config
                .ret_regs
                .first()
                .cloned()
                .unwrap_or_else(|| "rax".to_string()),
            arg_regs: self.config.arg_regs.clone(),
            caller_saved_regs: self.config.caller_saved_regs.clone(),
        };
        let fold_inputs = FoldInputs {
            arch: &fold_arch,
            function_names: &self.context.function_names,
            strings: &self.context.strings,
            symbols: &self.context.symbols,
            known_function_signatures: &known_function_signatures,
            external_stack_vars: &self.context.stack_vars,
            param_register_aliases: &param_register_aliases,
            type_hints: &type_hints,
            type_oracle,
        };
        let mut fold_ctx = FoldingContext::from_inputs(fold_inputs);
        let fold_blocks: Vec<_> = func.blocks().cloned().collect();
        fold_ctx.analyze_blocks(&fold_blocks);
        fold_ctx.analyze_function_structure(func);

        // Structure control flow (primary path: folded)
        let mut structurer = ControlFlowStructurer::new(func, &fold_ctx);

        // Get set of variables that survive folding before structuring.
        let emitted_vars = structurer.emitted_var_names();
        let mut use_conservative_locals = false;
        let mut is_linear_fallback = false;

        let folded_stmt = structurer.structure();
        let mut body_stmt = folded_stmt;

        if !Self::stmt_has_content(&body_stmt) {
            let folded_reason = structurer
                .safety_reason()
                .map(str::to_string)
                .unwrap_or_else(|| "folded structuring produced empty output".to_string());

            // Fallback 1: unfolded structuring
            let mut unfolded = ControlFlowStructurer::new_unfolded(func, &fold_ctx);
            let unfolded_stmt = unfolded.structure();

            if Self::stmt_has_content(&unfolded_stmt) {
                use_conservative_locals = true;
                body_stmt = Self::prepend_comment(
                    unfolded_stmt,
                    format!("r2dec fallback: {}", folded_reason),
                );
            } else {
                let unfolded_reason = unfolded
                    .safety_reason()
                    .map(str::to_string)
                    .unwrap_or_else(|| "unfolded structuring produced empty output".to_string());

                // Fallback 2: linear block emission
                let mut linear_stmts = self.linearize_function_body(func, &fold_ctx);
                let fallback_reason = format!("{}; {}", folded_reason, unfolded_reason);

                use_conservative_locals = true;
                is_linear_fallback = true;
                if linear_stmts.is_empty() {
                    body_stmt = CStmt::Block(vec![CStmt::comment(format!(
                        "r2dec fallback: {} -> no statements recovered",
                        fallback_reason
                    ))]);
                } else {
                    linear_stmts.insert(
                        0,
                        CStmt::comment(format!(
                            "r2dec fallback: {} -> linear block emission",
                            fallback_reason
                        )),
                    );
                    body_stmt = CStmt::Block(linear_stmts);
                }
            }
        }

        // Build the C function
        let func_name = func
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", func.entry));

        // Collect locals -- on fallback keep locals conservatively.
        let locals: Vec<ast::CLocal> = if use_conservative_locals {
            var_recovery
                .locals()
                .iter()
                .map(|v| ast::CLocal {
                    ty: type_inference.get_type(&v.ssa_var),
                    name: v.name.clone(),
                    stack_offset: v.stack_offset,
                })
                .collect()
        } else {
            var_recovery
                .locals()
                .iter()
                .filter(|v| emitted_vars.contains(&v.name))
                .map(|v| ast::CLocal {
                    ty: type_inference.get_type(&v.ssa_var),
                    name: v.name.clone(),
                    stack_offset: v.stack_offset,
                })
                .collect()
        };

        // Convert body to statements
        let body = self.stmt_to_vec(body_stmt);
        let inferred_ret_type = self.infer_return_type(func, &type_inference);

        let mut c_function = CFunction {
            name: func_name,
            ret_type: self
                .context
                .function_signature
                .as_ref()
                .and_then(|sig| sig.ret_type.clone())
                .unwrap_or(inferred_ret_type),
            params,
            locals,
            body,
        };

        // Apply post-structuring suffix cleanup for folded/unfolded paths.
        // Linear fallback intentionally keeps its raw expression-builder output.
        if !is_linear_fallback {
            let mut known_function_names = HashSet::new();
            for name in self.context.function_names.values() {
                known_function_names.insert(name.to_ascii_lowercase());
            }
            for name in self.context.known_function_signatures.keys() {
                known_function_names.insert(name.to_ascii_lowercase());
            }
            post_rename::rewrite_function_identifiers(&mut c_function, &known_function_names);
        }

        c_function
    }

    /// Convert a CStmt to a Vec<CStmt>.
    fn stmt_to_vec(&self, stmt: CStmt) -> Vec<CStmt> {
        match stmt {
            CStmt::Block(stmts) => stmts,
            CStmt::Empty => vec![],
            other => vec![other],
        }
    }

    fn infer_return_type(&self, func: &SSAFunction, type_inference: &TypeInference) -> CType {
        let mut candidates = Vec::new();

        for block in func.blocks() {
            for op in &block.ops {
                let SSAOp::Return { target } = op else {
                    continue;
                };

                let target_name = target.name.to_ascii_lowercase();
                if target_name.starts_with("xmm0") || target_name.starts_with("st0") {
                    let bits = if target.size.saturating_mul(8) <= 32 {
                        32
                    } else {
                        64
                    };
                    candidates.push(CType::Float(bits));
                    continue;
                }

                candidates.push(type_inference.get_type(target));
            }
        }

        if candidates.is_empty() {
            return CType::Void;
        }

        let mut meaningful: Vec<CType> = candidates
            .into_iter()
            .filter(|ty| !matches!(ty, CType::Unknown))
            .collect();
        if meaningful.is_empty() {
            return CType::Int(32);
        }
        if meaningful.iter().all(|ty| ty == &meaningful[0]) {
            return meaningful.remove(0);
        }
        if let Some(float_ty) = meaningful
            .iter()
            .find(|ty| matches!(ty, CType::Float(_)))
            .cloned()
        {
            return float_ty;
        }
        meaningful.remove(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompiler_config_default() {
        let config = DecompilerConfig::default();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "rsp");
        assert_eq!(config.fp_name, "rbp");
    }

    #[test]
    fn test_decompiler_config_x86() {
        let config = DecompilerConfig::x86();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "esp");
        assert_eq!(config.fp_name, "ebp");
    }

    #[test]
    fn test_decompiler_config_arm() {
        let config = DecompilerConfig::arm();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "fp");
    }

    #[test]
    fn test_decompiler_config_aarch64() {
        let config = DecompilerConfig::aarch64();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "fp");
        assert_eq!(config.arg_regs[0], "x0");
        assert_eq!(config.ret_regs[0], "x0");
        assert!(config.caller_saved_regs.contains("x17"));
    }

    #[test]
    fn test_decompiler_config_riscv32() {
        let config = DecompilerConfig::riscv32();
        assert_eq!(config.ptr_size, 32);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "s0");
    }

    #[test]
    fn test_decompiler_config_riscv64() {
        let config = DecompilerConfig::riscv64();
        assert_eq!(config.ptr_size, 64);
        assert_eq!(config.sp_name, "sp");
        assert_eq!(config.fp_name, "s0");
    }

    #[test]
    fn external_signature_does_not_shrink_richer_recovered_header_params() {
        let recovered = vec![
            ast::CParam {
                ty: CType::Int(32),
                name: "arg1".to_string(),
            },
            ast::CParam {
                ty: CType::Int(32),
                name: "arg2".to_string(),
            },
            ast::CParam {
                ty: CType::Int(32),
                name: "arg3".to_string(),
            },
        ];
        let signature = ExternalFunctionSignature {
            ret_type: Some(CType::Pointer(Box::new(CType::Int(8)))),
            params: vec![
                ExternalFunctionParam {
                    name: "src".to_string(),
                    ty: Some(CType::Pointer(Box::new(CType::Int(8)))),
                },
                ExternalFunctionParam {
                    name: "len".to_string(),
                    ty: Some(CType::UInt(64)),
                },
            ],
        };

        let params = merge_params_with_external_signature(recovered, Some(&signature));
        assert_eq!(
            params.len(),
            3,
            "external signature should not shrink a richer recovered header"
        );
        assert_eq!(params[0].name, "src");
        assert_eq!(params[1].name, "len");
        assert_eq!(params[2].name, "arg3");
        assert!(matches!(params[1].ty, CType::UInt(64)));
    }

    #[test]
    fn external_signature_can_extend_empty_recovered_header_params() {
        let signature = ExternalFunctionSignature {
            ret_type: None,
            params: vec![
                ExternalFunctionParam {
                    name: "buf".to_string(),
                    ty: Some(CType::Pointer(Box::new(CType::Int(8)))),
                },
                ExternalFunctionParam {
                    name: "count".to_string(),
                    ty: Some(CType::UInt(64)),
                },
            ],
        };

        let params = merge_params_with_external_signature(Vec::new(), Some(&signature));
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "buf");
        assert_eq!(params[1].name, "count");
    }
}
