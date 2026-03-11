use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::convert::CTypeLike;
use crate::external::{
    ExternalEnum, ExternalField, ExternalStruct, ExternalTypeDb, ExternalUnion,
    normalize_external_type_name,
};
use crate::facts::{FunctionParamSpec, FunctionSignatureSpec, FunctionType, parse_type_like_spec};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalRegisterParamSpec {
    pub name: String,
    pub ty: Option<CTypeLike>,
    pub reg: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalStackVarSpec {
    pub name: String,
    pub ty: Option<CTypeLike>,
    pub base: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedExternalContext {
    pub current_signature: Option<FunctionSignatureSpec>,
    pub merged_signature: Option<FunctionSignatureSpec>,
    pub known_function_signatures: HashMap<String, FunctionType>,
    pub register_params: Vec<ExternalRegisterParamSpec>,
    pub external_stack_vars: HashMap<i64, ExternalStackVarSpec>,
    pub external_type_db: ExternalTypeDb,
    pub diagnostics: Vec<String>,
    pub callconv: Option<String>,
    pub noreturn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalStackBase {
    FramePointer,
    StackPointer,
    Named(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalVarKind {
    Register,
    #[default]
    Stack,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignatureParamJson {
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
    #[serde(default)]
    pub cc_reg: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignatureJson {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "ret")]
    pub ret_type: Option<String>,
    #[serde(default)]
    pub callconv: Option<String>,
    #[serde(default)]
    pub noreturn: bool,
    #[serde(default)]
    pub params: Vec<ExternalSignatureParamJson>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalVarJson {
    pub kind: ExternalVarKind,
    pub name: String,
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
    #[serde(default)]
    pub is_arg: bool,
    #[serde(default)]
    pub reg: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBaseTypeMemberJson {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub offset: u64,
    #[serde(default)]
    pub size_bits: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalEnumVariantJson {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalBaseTypeKind {
    #[default]
    Struct,
    Union,
    Enum,
    Typedef,
    Atomic,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBaseTypeJson {
    pub kind: ExternalBaseTypeKind,
    pub name: String,
    #[serde(default)]
    pub members: Vec<ExternalBaseTypeMemberJson>,
    #[serde(default)]
    pub variants: Vec<ExternalEnumVariantJson>,
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
    #[serde(default)]
    pub size_bits: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownSignatureJson {
    pub name: String,
    #[serde(default, rename = "ret")]
    pub ret_type: Option<String>,
    #[serde(default)]
    pub args: Vec<ExternalSignatureParamJson>,
    #[serde(default)]
    pub variadic: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalContextJson {
    #[serde(default)]
    pub signature: Option<ExternalSignatureJson>,
    #[serde(default)]
    pub vars: Vec<ExternalVarJson>,
    #[serde(default)]
    pub base_types: Vec<ExternalBaseTypeJson>,
    #[serde(default)]
    pub known_signatures: Vec<KnownSignatureJson>,
}

pub fn normalize_function_basename(name: &str) -> String {
    let mut lower = name.trim().to_ascii_lowercase();
    for prefix in ["sym.imp.", "sym.", "dbg.", "fcn."] {
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

pub fn is_c_main_function(name: &str) -> bool {
    normalize_function_basename(name) == "main"
}

pub fn canonical_main_signature_spec() -> FunctionSignatureSpec {
    let char_ptr = CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 8,
        signedness: crate::Signedness::Signed,
    }));
    let char_pp = CTypeLike::Pointer(Box::new(char_ptr));
    FunctionSignatureSpec {
        ret_type: Some(CTypeLike::Int {
            bits: 32,
            signedness: crate::Signedness::Signed,
        }),
        params: vec![
            FunctionParamSpec {
                name: "argc".to_string(),
                ty: Some(CTypeLike::Int {
                    bits: 32,
                    signedness: crate::Signedness::Signed,
                }),
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

pub fn merge_signature_with_register_params(
    signature: Option<FunctionSignatureSpec>,
    register_params: &[ExternalRegisterParamSpec],
) -> Option<FunctionSignatureSpec> {
    if register_params.is_empty() {
        return signature;
    }

    let mut signature = signature.unwrap_or_default();
    if signature.params.is_empty() {
        signature.params = register_params
            .iter()
            .map(|param| FunctionParamSpec {
                name: param.name.clone(),
                ty: param.ty.clone(),
            })
            .collect();
        return Some(signature);
    }

    for (idx, reg_param) in register_params.iter().enumerate() {
        if let Some(existing) = signature.params.get_mut(idx) {
            if is_generic_signature_type(existing.ty.as_ref())
                && !is_generic_signature_type(reg_param.ty.as_ref())
            {
                existing.ty = reg_param.ty.clone();
            }
            if is_generic_arg_name(&existing.name) && !is_generic_arg_name(&reg_param.name) {
                existing.name = reg_param.name.clone();
            }
        } else {
            signature.params.push(FunctionParamSpec {
                name: reg_param.name.clone(),
                ty: reg_param.ty.clone(),
            });
        }
    }

    Some(signature)
}

pub fn apply_main_signature_override(
    function_name: &str,
    merged_signature: &mut Option<FunctionSignatureSpec>,
) {
    if is_c_main_function(function_name) {
        *merged_signature = Some(canonical_main_signature_spec());
    }
}

pub fn parse_external_context_json(json_str: &str, ptr_bits: u32) -> ParsedExternalContext {
    let trimmed = json_str.trim();
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "[]" {
        return ParsedExternalContext::default();
    }

    let mut parsed = ParsedExternalContext::default();
    let Ok(raw) = serde_json::from_str::<ExternalContextJson>(trimmed) else {
        parsed
            .diagnostics
            .push("failed to parse external context json".to_string());
        return parsed;
    };

    if let Some(signature) = raw.signature.as_ref() {
        parsed.current_signature = parse_signature_json(signature, ptr_bits);
        parsed.callconv = signature.callconv.clone();
        parsed.noreturn = signature.noreturn;
    }

    let (register_params, external_stack_vars) = parse_external_vars(&raw.vars, ptr_bits);
    parsed.register_params = register_params;
    parsed.external_stack_vars = external_stack_vars;
    parsed.external_type_db = external_type_db_from_base_types(&raw.base_types);
    parsed.known_function_signatures = parse_known_signatures(&raw.known_signatures, ptr_bits);
    parsed.merged_signature = merge_signature_with_register_params(
        parsed.current_signature.clone(),
        &parsed.register_params,
    );

    parsed
}

fn parse_signature_json(
    signature: &ExternalSignatureJson,
    ptr_bits: u32,
) -> Option<FunctionSignatureSpec> {
    let mut used_names = HashSet::new();
    let mut params: Vec<_> = signature
        .params
        .iter()
        .enumerate()
        .map(|(idx, arg)| {
            let fallback = format!("arg{}", idx + 1);
            let raw_name = arg.name.clone().unwrap_or(fallback);
            let mut name =
                sanitize_c_identifier(&raw_name).unwrap_or_else(|| format!("arg{}", idx + 1));
            if !is_generic_arg_name(&name) {
                name = uniquify_name(name, &mut used_names);
            }
            FunctionParamSpec {
                name,
                ty: arg
                    .ty
                    .as_deref()
                    .and_then(|raw| parse_type_like_spec(raw, ptr_bits)),
            }
        })
        .collect();

    if params.len() == 1
        && params[0].ty == Some(CTypeLike::Void)
        && is_generic_arg_name(&params[0].name)
    {
        params.clear();
    }

    let ret_type = signature
        .ret_type
        .as_deref()
        .and_then(|raw| parse_type_like_spec(raw, ptr_bits));

    if params.is_empty() && ret_type.is_none() {
        return None;
    }

    Some(FunctionSignatureSpec { ret_type, params })
}

fn parse_external_vars(
    vars: &[ExternalVarJson],
    ptr_bits: u32,
) -> (
    Vec<ExternalRegisterParamSpec>,
    HashMap<i64, ExternalStackVarSpec>,
) {
    let mut register_params = Vec::new();
    let mut stack_vars = HashMap::new();
    let mut used_names = HashSet::new();

    for (idx, var) in vars.iter().enumerate() {
        let sanitized_name =
            sanitize_c_identifier(&var.name).unwrap_or_else(|| format!("arg{}", idx + 1));
        let name = if is_generic_arg_name(&sanitized_name) {
            sanitized_name
        } else {
            uniquify_name(sanitized_name, &mut used_names)
        };
        let ty = var
            .ty
            .as_deref()
            .and_then(|raw| parse_type_like_spec(raw, ptr_bits));

        match var.kind {
            ExternalVarKind::Register => {
                register_params.push(ExternalRegisterParamSpec {
                    name,
                    ty,
                    reg: var.reg.clone().unwrap_or_default(),
                });
            }
            ExternalVarKind::Stack => {
                let Some(offset) = var.offset else {
                    continue;
                };
                stack_vars.insert(
                    offset,
                    ExternalStackVarSpec {
                        name,
                        ty,
                        base: var.base.clone(),
                    },
                );
            }
        }
    }

    (register_params, stack_vars)
}

fn parse_known_signatures(
    entries: &[KnownSignatureJson],
    ptr_bits: u32,
) -> HashMap<String, FunctionType> {
    let mut out = HashMap::new();

    for entry in entries {
        if entry.name.trim().is_empty() {
            continue;
        }

        let params = entry
            .args
            .iter()
            .map(|arg| {
                arg.ty
                    .as_deref()
                    .and_then(|raw| parse_type_like_spec(raw, ptr_bits))
                    .unwrap_or(CTypeLike::Unknown)
            })
            .collect::<Vec<_>>();
        let return_type = entry
            .ret_type
            .as_deref()
            .and_then(|raw| parse_type_like_spec(raw, ptr_bits))
            .unwrap_or(CTypeLike::Unknown);
        let sig = FunctionType {
            return_type,
            params,
            variadic: entry.variadic,
        };
        maybe_insert_known_signature(&mut out, &entry.name, sig);
    }

    out
}

fn maybe_insert_known_signature(
    known: &mut HashMap<String, FunctionType>,
    name: &str,
    sig: FunctionType,
) {
    if name.is_empty() {
        return;
    }
    known.insert(name.to_string(), sig.clone());

    for prefix in ["sym.imp.", "sym.", "dbg.", "fcn."] {
        if let Some(stripped) = name.strip_prefix(prefix)
            && !stripped.is_empty()
        {
            known.insert(stripped.to_string(), sig.clone());
        }
    }
}

fn external_type_db_from_base_types(base_types: &[ExternalBaseTypeJson]) -> ExternalTypeDb {
    let mut out = ExternalTypeDb::default();

    for base_type in base_types {
        match base_type.kind {
            ExternalBaseTypeKind::Struct => {
                let name = normalize_aggregate_name(&base_type.name, "struct");
                if name.is_empty() {
                    continue;
                }
                let mut fields = BTreeMap::new();
                for member in &base_type.members {
                    fields.insert(
                        member.offset,
                        ExternalField {
                            name: member.name.clone(),
                            offset: member.offset,
                            ty: Some(normalize_external_type_name(&member.ty)),
                        },
                    );
                }
                out.structs
                    .insert(name.to_ascii_lowercase(), ExternalStruct { name, fields });
            }
            ExternalBaseTypeKind::Union => {
                let name = normalize_aggregate_name(&base_type.name, "union");
                if name.is_empty() {
                    continue;
                }
                let mut fields = BTreeMap::new();
                for member in &base_type.members {
                    fields.insert(
                        member.offset,
                        ExternalField {
                            name: member.name.clone(),
                            offset: member.offset,
                            ty: Some(normalize_external_type_name(&member.ty)),
                        },
                    );
                }
                out.unions
                    .insert(name.to_ascii_lowercase(), ExternalUnion { name, fields });
            }
            ExternalBaseTypeKind::Enum => {
                let name = normalize_aggregate_name(&base_type.name, "enum");
                if name.is_empty() {
                    continue;
                }
                let mut variants = BTreeMap::new();
                for variant in &base_type.variants {
                    variants.insert(variant.value, variant.name.clone());
                }
                out.enums
                    .insert(name.to_ascii_lowercase(), ExternalEnum { name, variants });
            }
            ExternalBaseTypeKind::Typedef | ExternalBaseTypeKind::Atomic => {}
        }
    }

    out
}

fn normalize_aggregate_name(name: &str, prefix: &str) -> String {
    let normalized = normalize_external_type_name(name);
    normalized
        .strip_prefix(&format!("{prefix} "))
        .unwrap_or(name)
        .trim()
        .to_string()
}

fn sanitize_c_identifier(name: &str) -> Option<String> {
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

fn uniquify_name(base: String, used: &mut HashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    let mut idx = 2usize;
    loop {
        let candidate = format!("{base}_{idx}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        idx += 1;
    }
}

pub fn is_generic_arg_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_prefix("arg")
        .map(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

fn is_generic_signature_type(ty: Option<&CTypeLike>) -> bool {
    match ty {
        None => true,
        Some(CTypeLike::Unknown | CTypeLike::Void) => true,
        Some(CTypeLike::Pointer(inner)) => {
            matches!(inner.as_ref(), CTypeLike::Unknown | CTypeLike::Void)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_external_context_merges_register_params() {
        let ctx = parse_external_context_json(
            r#"{
                "signature":{"ret":"int32_t","params":[{"name":"arg1","type":"void *"}]},
                "vars":[
                    {"kind":"register","name":"count","type":"int32_t","reg":"rdi"},
                    {"kind":"stack","name":"local_10h","type":"int32_t","base":"rbp","offset":-16}
                ]
            }"#,
            64,
        );

        let merged = ctx.merged_signature.expect("merged signature");
        assert_eq!(merged.params[0].name, "count");
        assert_eq!(
            merged.params[0].ty,
            Some(CTypeLike::Int {
                bits: 32,
                signedness: crate::Signedness::Signed,
            })
        );
        assert_eq!(
            ctx.external_stack_vars
                .get(&-16)
                .map(|var| var.name.as_str()),
            Some("local_10h")
        );
    }

    #[test]
    fn apply_main_signature_override_uses_canonical_signature() {
        let mut merged = None;
        apply_main_signature_override("dbg.main", &mut merged);
        let merged = merged.expect("main signature");
        assert_eq!(merged.params.len(), 3);
        assert_eq!(merged.params[0].name, "argc");
        assert_eq!(merged.params[1].name, "argv");
        assert_eq!(merged.params[2].name, "envp");
    }
}
