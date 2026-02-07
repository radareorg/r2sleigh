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

pub mod ast;
pub mod codegen;
pub mod expr;
pub mod fold;
pub mod region;
pub mod structure;
pub mod types;
pub mod variable;

pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::{generate, CodeGenConfig, CodeGenerator};
pub use expr::ExpressionBuilder;
pub use fold::{fold_block, fold_blocks, FoldingContext};
pub use region::{Region, RegionAnalyzer};
pub use structure::ControlFlowStructurer;
pub use types::TypeInference;
pub use variable::VariableRecovery;

use r2ssa::SSAFunction;

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
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            codegen: CodeGenConfig::default(),
            ptr_size: 64,
            sp_name: "rsp".to_string(),
            fp_name: "rbp".to_string(),
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
#[derive(Debug, Clone, Default)]
pub struct DecompilerContext {
    /// Function address to name mapping.
    pub function_names: std::collections::HashMap<u64, String>,
    /// String literal addresses.
    pub strings: std::collections::HashMap<u64, String>,
    /// Symbol/global variable names.
    pub symbols: std::collections::HashMap<u64, String>,
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

    /// Decompile an SSA function to C code.
    pub fn decompile(&self, func: &SSAFunction) -> String {
        // Build the C function
        let c_func = self.build_function(func);

        // Generate code
        let mut codegen = CodeGenerator::new(self.config.codegen.clone());
        codegen.generate_function(&c_func)
    }

    /// Build a C function from an SSA function.
    pub fn build_function(&self, func: &SSAFunction) -> CFunction {
        // Recover variables
        let mut var_recovery =
            VariableRecovery::new(&self.config.sp_name, &self.config.fp_name, self.config.ptr_size);
        var_recovery.recover(func);

        // Infer types
        let mut type_inference = TypeInference::new(self.config.ptr_size);
        type_inference.infer_function(func);

        // Structure control flow
        let mut structurer = ControlFlowStructurer::new(func, self.config.ptr_size);
        
        // Pass external context to structurer
        if !self.context.function_names.is_empty() {
            structurer.set_function_names(self.context.function_names.clone());
        }
        if !self.context.strings.is_empty() {
            structurer.set_strings(self.context.strings.clone());
        }
        if !self.context.symbols.is_empty() {
            structurer.set_symbols(self.context.symbols.clone());
        }
        
        // Get set of variables that survive folding before structuring
        let emitted_vars = structurer.emitted_var_names();

        let body_stmt = structurer.structure();

        // Build the C function
        let func_name = func.name.clone().unwrap_or_else(|| {
            format!("sub_{:x}", func.entry)
        });

        // Collect parameters -- always include in signature even if inlined in body
        let mut params: Vec<ast::CParam> = var_recovery
            .parameters()
            .iter()
            .map(|v| ast::CParam {
                ty: type_inference.get_type(&v.ssa_var),
                name: v.name.clone(),
            })
            .collect();
        // Sort by arg number for stable ordering (arg1, arg2, ...)
        params.sort_by(|a, b| a.name.cmp(&b.name));

        // Collect locals -- keep only those whose names appear in emitted output
        let locals: Vec<ast::CLocal> = var_recovery
            .locals()
            .iter()
            .filter(|v| emitted_vars.contains(&v.name))
            .map(|v| ast::CLocal {
                ty: type_inference.get_type(&v.ssa_var),
                name: v.name.clone(),
                stack_offset: v.stack_offset,
            })
            .collect();

        // Convert body to statements
        let body = self.stmt_to_vec(body_stmt);

        CFunction {
            name: func_name,
            ret_type: CType::Int(32), // Default to int
            params,
            locals,
            body,
        }
    }

    /// Convert a CStmt to a Vec<CStmt>.
    fn stmt_to_vec(&self, stmt: CStmt) -> Vec<CStmt> {
        match stmt {
            CStmt::Block(stmts) => stmts,
            CStmt::Empty => vec![],
            other => vec![other],
        }
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
