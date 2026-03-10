use std::collections::{BTreeMap, HashMap, HashSet};

use r2ssa::SSAVar;
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
#[derive(Debug, Clone, Default)]
pub(crate) struct AnalysisContext {
    pub(crate) use_info: UseInfo,
    pub(crate) flag_info: FlagInfo,
    pub(crate) stack_info: StackInfo,
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct PassEnv<'a> {
    pub(crate) ptr_size: u32,
    pub(crate) sp_name: &'a str,
    pub(crate) fp_name: &'a str,
    pub(crate) ret_reg_name: &'a str,
    pub(crate) function_names: &'a HashMap<u64, String>,
    pub(crate) strings: &'a HashMap<u64, String>,
    pub(crate) symbols: &'a HashMap<u64, String>,
    pub(crate) arg_regs: &'a [String],
    pub(crate) param_register_aliases: &'a HashMap<String, String>,
    pub(crate) caller_saved_regs: &'a HashSet<String>,
    pub(crate) type_hints: &'a HashMap<String, CType>,
    pub(crate) type_oracle: Option<&'a dyn TypeOracle>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct UseInfo {
    pub(crate) use_counts: HashMap<String, usize>,
    pub(crate) definitions: HashMap<String, CExpr>,
    pub(crate) semantic_values: HashMap<String, SemanticValue>,
    pub(crate) frame_slot_merges: HashMap<String, FrameSlotMergeSummary>,
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
    pub(crate) stack_slots: HashMap<String, StackSlotProvenance>,
    pub(crate) forwarded_values: HashMap<String, ValueProvenance>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueRef {
    pub(crate) var: SSAVar,
}

impl ValueRef {
    pub(crate) fn new(var: SSAVar) -> Self {
        Self { var }
    }

    pub(crate) fn display_name(&self) -> String {
        self.var.display_name()
    }
}

impl From<SSAVar> for ValueRef {
    fn from(var: SSAVar) -> Self {
        Self::new(var)
    }
}

impl From<&SSAVar> for ValueRef {
    fn from(var: &SSAVar) -> Self {
        Self::new(var.clone())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BaseRef {
    Value(ValueRef),
    StackSlot(i64),
    Raw(CExpr),
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NormalizedAddr {
    pub(crate) base: BaseRef,
    pub(crate) index: Option<ValueRef>,
    pub(crate) scale_bytes: i64,
    pub(crate) offset_bytes: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ScalarValue {
    Root(ValueRef),
    Expr(CExpr),
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SemanticValue {
    Scalar(ScalarValue),
    Address(NormalizedAddr),
    Load { addr: NormalizedAddr, size: u32 },
    Unknown,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FrameSlotMergeSummary {
    pub(crate) slot_offset: i64,
    pub(crate) merge_block_addr: u64,
    pub(crate) load_name: String,
    pub(crate) incoming: BTreeMap<u64, SemanticValue>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct FlagInfo {
    pub(crate) flag_origins: HashMap<String, (String, String)>,
    pub(crate) compare_provenance: HashMap<String, FlagCompareProvenance>,
    pub(crate) sub_results: HashMap<String, (String, String)>,
    pub(crate) flag_only_values: HashSet<String>,
    pub(crate) predicate_exprs: HashMap<String, CExpr>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagCompareKind {
    Equality,
    UnsignedLess,
    SignedNegative,
    Overflow,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlagCompareProvenance {
    pub(crate) lhs: String,
    pub(crate) rhs: String,
    pub(crate) kind: FlagCompareKind,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct StackInfo {
    pub(crate) stack_vars: HashMap<i64, String>,
    pub(crate) stack_arg_aliases: HashMap<i64, String>,
    pub(crate) definition_overrides: HashMap<String, CExpr>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackSlotProvenance {
    pub(crate) offset: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueProvenance {
    pub(crate) source: String,
    pub(crate) source_var: Option<SSAVar>,
    pub(crate) stack_slot: Option<i64>,
}

impl UseInfo {
    pub(crate) fn analyze(blocks: &[SSABlock], env: &PassEnv<'_>) -> Self {
        use_info::analyze(blocks, env)
    }

    pub(crate) fn analyze_with_definition_overrides(
        blocks: &[SSABlock],
        env: &PassEnv<'_>,
        definition_overrides: &HashMap<String, CExpr>,
    ) -> Self {
        use_info::analyze_with_definition_overrides(blocks, env, definition_overrides)
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
