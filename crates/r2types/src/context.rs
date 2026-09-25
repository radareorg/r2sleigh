use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::convert::CTypeLike;
use crate::external::ExternalTypeDb;
use crate::facts::{
    CalleeFact, CalleeLinkage, FunctionParamSpec, FunctionSignatureSpec, FunctionType,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalRegisterParamSpec {
    pub name: String,
    pub ty: Option<CTypeLike>,
    pub reg: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalStackSlotSpec {
    pub name: String,
    pub ty: Option<CTypeLike>,
    pub role: ExternalStackSlotRole,
    pub param_index: Option<usize>,
    pub param_name: Option<String>,
    pub source_reg: Option<String>,
}

pub type ExternalStackVarSpec = ExternalStackSlotSpec;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedExternalContext {
    pub context_schema_version: Option<u64>,
    pub context_dirty_epoch: Option<u64>,
    pub type_dirty_epoch: Option<u64>,
    pub context_hash: Option<u64>,
    pub current_signature: Option<FunctionSignatureSpec>,
    pub merged_signature: Option<FunctionSignatureSpec>,
    pub known_function_signatures: HashMap<String, FunctionType>,
    pub register_params: Vec<ExternalRegisterParamSpec>,
    pub stack_slots: BTreeMap<StackSlotKey, ExternalStackSlotSpec>,
    pub external_type_db: ExternalTypeDb,
    pub program_data_objects: crate::ProgramDataObjectTypeFacts,
    /// Where the program's loaded sections lie, which is where a constant can name one of its objects.
    pub program_extents: ProgramExtents,
    pub callee_facts: BTreeMap<u64, CalleeFact>,
    pub assumptions: r2ssa::AssumptionSet,
    pub diagnostics: Vec<String>,
    pub callconv: Option<String>,
    pub noreturn: bool,
}

/// The address ranges a program's loaded sections hold.
///
/// A number that is not proven to move with the program names one of its
/// objects only where a section it loads holds it; how large the number is
/// says nothing, since a program linked low keeps its data at small addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramExtents {
    /// Half-open, sorted by start, and merged wherever two touch.
    ranges: Vec<(u64, u64)>,
}

impl ProgramExtents {
    /// A program that declares no loaded section, so no number names anything in it.
    pub const fn none() -> Self {
        Self { ranges: Vec::new() }
    }

    /// The extents of these half-open ranges; an empty one holds nothing.
    pub fn new(ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut sorted = ranges
            .into_iter()
            .filter(|(start, end)| start < end)
            .collect::<Vec<_>>();
        sorted.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
        for (start, end) in sorted {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Self { ranges: merged }
    }

    /// Whether a loaded section holds this address.
    pub fn holds(&self, address: u64) -> bool {
        let after = self.ranges.partition_point(|(start, _)| *start <= address);
        after
            .checked_sub(1)
            .is_some_and(|index| address < self.ranges[index].1)
    }
}

pub use r2ssa::StackAddressBase as ExternalStackBase;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExternalStackSlotRole {
    Local,
    StackArg,
    ParamHome,
    SavedReg,
    SavedFp,
    #[default]
    Unknown,
}

pub type StackSlotKey = r2ssa::StackAddressRoot;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCalleeLinkageJson {
    #[default]
    Unknown,
    Internal,
    Imported,
}

impl From<ExternalCalleeLinkageJson> for CalleeLinkage {
    fn from(value: ExternalCalleeLinkageJson) -> Self {
        match value {
            ExternalCalleeLinkageJson::Unknown => Self::Unknown,
            ExternalCalleeLinkageJson::Internal => Self::Internal,
            ExternalCalleeLinkageJson::Imported => Self::Imported,
        }
    }
}

fn normalize_function_basename(name: &str) -> String {
    let mut lower = name.trim().to_ascii_lowercase();
    for prefix in ["sym.imp.", "sym.", "dbg.", "fcn.", "imp."] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            lower = rest.to_string();
            break;
        }
    }
    if let Some(rest) = lower.strip_prefix('_')
        && rest == "main"
    {
        return "main".to_string();
    }
    lower
}

fn is_c_main_function(name: &str) -> bool {
    normalize_function_basename(name) == "main"
}

pub fn canonical_main_signature_spec() -> FunctionSignatureSpec {
    let char_ptr = CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 8,
        signedness: crate::Signedness::Signed,
    }));
    let char_pp = CTypeLike::Pointer(Box::new(char_ptr));
    FunctionSignatureSpec {
        ret_type: Some(CTypeLike::typedef("int")),
        params: vec![
            FunctionParamSpec {
                name: "argc".to_string(),
                ty: Some(CTypeLike::typedef("int")),
            },
            FunctionParamSpec {
                name: "argv".to_string(),
                ty: Some(char_pp.clone()),
            },
            FunctionParamSpec {
                name: "envp".to_string(),
                ty: Some(char_pp),
            },
        ],
    }
}

fn normalize_signature_param_name(name: &str) -> String {
    name.trim()
        .trim_start_matches('_')
        .to_ascii_lowercase()
        .replace('-', "_")
}

fn signature_spec_has_main_abi_evidence(signature: &FunctionSignatureSpec) -> bool {
    let mut names = signature
        .params
        .iter()
        .map(|param| normalize_signature_param_name(&param.name))
        .collect::<Vec<_>>();
    names.retain(|name| !name.is_empty());
    let has_argc = names.iter().any(|name| name == "argc");
    let has_argv = names.iter().any(|name| name == "argv");
    let has_envp = names.iter().any(|name| name == "envp" || name == "env");
    has_argc && (has_argv || has_envp)
}

pub fn apply_main_signature_override(
    function_name: &str,
    merged_signature: &mut Option<FunctionSignatureSpec>,
) -> bool {
    if !is_c_main_function(function_name) {
        return false;
    }
    let Some(signature) = merged_signature.as_ref() else {
        return false;
    };
    if !signature_spec_has_main_abi_evidence(signature) {
        return false;
    }
    let canonical = canonical_main_signature_spec();
    if merged_signature.as_ref() == Some(&canonical) {
        return false;
    }
    *merged_signature = Some(canonical);
    true
}

/// The C identifier a source name renders as, or `None` when nothing of the
/// name survives.
///
/// Every rendered identifier passes through here: parameter and variable
/// names, the names the analysis declares, and the rendered function's own
/// name. A source name is arbitrary bytes -- a radare2 flag, a DWARF string --
/// and a name that is not a C identifier makes the whole rendering invalid C,
/// so the one place that answers "what does this name spell" is this function.
///
/// A leading or trailing underscore is part of the name and is kept: `_init`
/// is a real symbol, and trimming it renamed the function to something the
/// binary does not contain.
pub fn sanitize_c_identifier(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        let normalized = if ch.is_ascii_alphanumeric() || ch == '_' {
            ch
        } else {
            '_'
        };
        if idx == 0 && normalized.is_ascii_digit() {
            out.push('_');
        }
        out.push(normalized);
    }

    if out.chars().all(|c| c == '_') {
        None
    } else {
        Some(out)
    }
}

pub fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_main_signature_override_refuses_name_only_main() {
        let mut merged = None;
        assert!(!apply_main_signature_override("dbg.main", &mut merged));
        assert!(merged.is_none());
    }

    #[test]
    fn apply_main_signature_override_canonicalizes_main_shaped_signature() {
        let mut merged = Some(FunctionSignatureSpec {
            ret_type: Some(CTypeLike::typedef("int")),
            params: vec![
                FunctionParamSpec {
                    name: "argc".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                        bits: 8,
                        signedness: crate::Signedness::Signed,
                    }))),
                },
                FunctionParamSpec {
                    name: "argv".to_string(),
                    ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Pointer(Box::new(
                        CTypeLike::Int {
                            bits: 8,
                            signedness: crate::Signedness::Signed,
                        },
                    ))))),
                },
            ],
        });
        assert!(apply_main_signature_override("dbg.main", &mut merged));
        let merged = merged.expect("main signature");
        assert_eq!(merged.params.len(), 3);
        assert_eq!(merged.params[0].name, "argc");
        assert_eq!(merged.params[0].ty, Some(CTypeLike::typedef("int")));
        assert_eq!(merged.params[1].name, "argv");
        assert_eq!(merged.params[2].name, "envp");
    }
}
