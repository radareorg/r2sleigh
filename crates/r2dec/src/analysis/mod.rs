use std::collections::{HashMap, HashSet};

use r2types::TypeOracle;

use crate::ast::{CExpr, CType};
use crate::fold::{PtrArith, SSABlock};

// Pass dependency invariant:
// UseInfo -> (FlagInfo, StackInfo) -> PredicateSimplifier -> statement emit.
pub(crate) mod flag_info;
pub(crate) mod lower;
pub(crate) mod predicate;
pub(crate) mod stack_info;
pub(crate) mod use_info;
pub(crate) mod utils;

pub(crate) use predicate::PredicateSimplifier;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct AnalysisContext {
    pub(crate) use_info: UseInfo,
    pub(crate) flag_info: FlagInfo,
    pub(crate) stack_info: StackInfo,
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct PassEnv<'a> {
    pub(crate) ptr_size: u32,
    pub(crate) sp_name: String,
    pub(crate) fp_name: String,
    pub(crate) ret_reg_name: String,
    pub(crate) function_names: HashMap<u64, String>,
    pub(crate) strings: HashMap<u64, String>,
    pub(crate) symbols: HashMap<u64, String>,
    pub(crate) arg_regs: Vec<String>,
    pub(crate) caller_saved_regs: HashSet<String>,
    pub(crate) type_hints: HashMap<String, CType>,
    pub(crate) type_oracle: Option<&'a dyn TypeOracle>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct UseInfo {
    pub(crate) use_counts: HashMap<String, usize>,
    pub(crate) definitions: HashMap<String, CExpr>,
    pub(crate) formatted_defs: HashMap<String, CExpr>,
    pub(crate) copy_sources: HashMap<String, String>,
    pub(crate) memory_stores: HashMap<String, String>,
    pub(crate) ptr_arith: HashMap<String, PtrArith>,
    pub(crate) ptr_members: HashMap<String, (r2ssa::SSAVar, i64)>,
    pub(crate) condition_vars: HashSet<String>,
    pub(crate) pinned: HashSet<String>,
    pub(crate) call_args: HashMap<(u64, usize), Vec<CExpr>>,
    pub(crate) consumed_by_call: HashSet<String>,
    pub(crate) var_aliases: HashMap<String, String>,
    pub(crate) type_hints: HashMap<String, CType>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct FlagInfo {
    pub(crate) flag_origins: HashMap<String, (String, String)>,
    pub(crate) sub_results: HashMap<String, (String, String)>,
    pub(crate) flag_only_values: HashSet<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct StackInfo {
    pub(crate) stack_vars: HashMap<i64, String>,
    pub(crate) stack_arg_aliases: HashMap<i64, String>,
    pub(crate) definition_overrides: HashMap<String, CExpr>,
}

impl UseInfo {
    pub(crate) fn analyze(blocks: &[SSABlock], env: &PassEnv<'_>) -> Self {
        use_info::analyze(blocks, env)
    }
}

impl FlagInfo {
    pub(crate) fn analyze(blocks: &[SSABlock], use_info: &UseInfo, env: &PassEnv<'_>) -> Self {
        flag_info::analyze(blocks, use_info, env)
    }
}

impl StackInfo {
    pub(crate) fn analyze(blocks: &[SSABlock], use_info: &UseInfo, env: &PassEnv<'_>) -> Self {
        stack_info::analyze(blocks, use_info, env)
    }
}
