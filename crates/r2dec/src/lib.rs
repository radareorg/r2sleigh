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
pub mod expr;
pub mod fold;
pub(crate) mod normalize;
pub(crate) mod post_rename;
pub mod region;
pub mod structure;
pub mod types;
pub mod variable;

pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::{CodeGenConfig, CodeGenerator, generate};
pub use expr::ExpressionBuilder;
pub use fold::{FoldingContext, fold_block, fold_blocks};
pub use region::{Region, RegionAnalyzer};
pub use structure::ControlFlowStructurer;
pub use types::TypeInference;
pub use variable::VariableRecovery;

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
            ..Default::default()
        }
    }

    /// Create a configuration for AArch64.
    pub fn aarch64() -> Self {
        Self {
            ptr_size: 64,
            sp_name: "sp".to_string(),
            fp_name: "fp".to_string(),
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

    fn configure_structurer<'o>(
        &self,
        structurer: &mut ControlFlowStructurer<'_, 'o>,
        type_hints: &std::collections::HashMap<String, CType>,
        type_oracle: Option<&'o dyn TypeOracle>,
    ) {
        if !self.context.function_names.is_empty() {
            structurer.set_function_names(self.context.function_names.clone());
        }
        if !self.context.strings.is_empty() {
            structurer.set_strings(self.context.strings.clone());
        }
        if !self.context.symbols.is_empty() {
            structurer.set_symbols(self.context.symbols.clone());
        }
        if !self.context.stack_vars.is_empty() {
            structurer.set_external_stack_vars(self.context.stack_vars.clone());
        }
        if !type_hints.is_empty() {
            structurer.set_type_hints(type_hints.clone());
        }
        structurer.set_type_oracle(type_oracle);
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
        type_hints: &std::collections::HashMap<String, CType>,
        type_oracle: Option<&dyn TypeOracle>,
    ) -> Vec<CStmt> {
        let mut fold_ctx = FoldingContext::new(self.config.ptr_size);
        if !self.context.function_names.is_empty() {
            fold_ctx.set_function_names(self.context.function_names.clone());
        }
        if !self.context.strings.is_empty() {
            fold_ctx.set_strings(self.context.strings.clone());
        }
        if !self.context.symbols.is_empty() {
            fold_ctx.set_symbols(self.context.symbols.clone());
        }
        if !self.context.stack_vars.is_empty() {
            fold_ctx.set_external_stack_vars(self.context.stack_vars.clone());
        }
        if !type_hints.is_empty() {
            fold_ctx.set_type_hints(type_hints.clone());
        }
        fold_ctx.set_type_oracle(type_oracle);

        let blocks: Vec<_> = func.blocks().cloned().collect();
        fold_ctx.analyze_blocks(&blocks);
        fold_ctx.analyze_function_structure(func);
        let mut stmts = Vec::new();

        for block in &blocks {
            fold_ctx.set_current_block(block.addr);
            for stmt in fold_ctx.fold_block(block) {
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
        let mut var_recovery = VariableRecovery::new(
            &self.config.sp_name,
            &self.config.fp_name,
            self.config.ptr_size,
        );
        if let Some(signature) = &self.context.function_signature {
            var_recovery.set_external_signature(signature.clone());
        }
        if !self.context.stack_vars.is_empty() {
            var_recovery.set_external_stack_vars(self.context.stack_vars.clone());
        }
        var_recovery.recover(func);

        // Infer types
        let mut type_inference = TypeInference::new(self.config.ptr_size);
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

        // Structure control flow (primary path: folded)
        let mut structurer = ControlFlowStructurer::new(func, self.config.ptr_size);
        self.configure_structurer(&mut structurer, &type_hints, type_oracle);

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
            let mut unfolded = ControlFlowStructurer::new_unfolded(func, self.config.ptr_size);
            self.configure_structurer(&mut unfolded, &type_hints, type_oracle);
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
                let mut linear_stmts = self.linearize_function_body(func, &type_hints, type_oracle);
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

        // Collect parameters -- always include in signature even if inlined in body
        let mut recovered_params: Vec<ast::CParam> = var_recovery
            .parameters()
            .iter()
            .map(|v| ast::CParam {
                ty: type_inference.get_type(&v.ssa_var),
                name: v.name.clone(),
            })
            .collect();
        // Sort by arg number when available, then by name.
        recovered_params.sort_by(|a, b| {
            let ai = a
                .name
                .strip_prefix("arg")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            let bi = b
                .name
                .strip_prefix("arg")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            ai.cmp(&bi).then_with(|| a.name.cmp(&b.name))
        });

        let params: Vec<ast::CParam> = if let Some(signature) = &self.context.function_signature {
            if signature.params.is_empty() {
                recovered_params
            } else {
                let total = recovered_params.len().max(signature.params.len());
                (0..total)
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
        } else {
            recovered_params
        };

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
}
