use std::collections::HashMap;

use r2ssa::{SSAFunction, SSAVar};
use r2types::{
    CTypeLike, CombinedTypeOracle, ExternalStackVarSpec, ExternalTypeDb, FunctionSignatureSpec,
    FunctionType as R2FunctionType, Signedness, TypeInference as InnerTypeInference,
};

use crate::ast::CType;
use crate::{ExternalFunctionSignature, ExternalStackVar};

#[derive(Debug, Clone)]
pub struct FunctionType {
    pub return_type: CType,
    pub params: Vec<CType>,
    pub variadic: bool,
}

impl From<FunctionType> for R2FunctionType {
    fn from(value: FunctionType) -> Self {
        Self {
            return_type: ctype_to_type_like(&value.return_type),
            params: value.params.iter().map(ctype_to_type_like).collect(),
            variadic: value.variadic,
        }
    }
}

impl From<&FunctionType> for R2FunctionType {
    fn from(value: &FunctionType) -> Self {
        Self {
            return_type: ctype_to_type_like(&value.return_type),
            params: value.params.iter().map(ctype_to_type_like).collect(),
            variadic: value.variadic,
        }
    }
}

fn ctype_to_type_like(ty: &CType) -> CTypeLike {
    match ty {
        CType::Void => CTypeLike::Void,
        CType::Bool => CTypeLike::Bool,
        CType::Int(bits) => CTypeLike::Int {
            bits: *bits,
            signedness: Signedness::Signed,
        },
        CType::UInt(bits) => CTypeLike::Int {
            bits: *bits,
            signedness: Signedness::Unsigned,
        },
        CType::Float(bits) => CTypeLike::Float(*bits),
        CType::Pointer(inner) => CTypeLike::Pointer(Box::new(ctype_to_type_like(inner))),
        CType::Array(inner, len) => CTypeLike::Array(Box::new(ctype_to_type_like(inner)), *len),
        CType::Struct(name) => CTypeLike::Struct(name.clone()),
        CType::Union(name) => CTypeLike::Union(name.clone()),
        CType::Enum(name) => CTypeLike::Enum(name.clone()),
        CType::Function { .. } | CType::Typedef(_) | CType::Unknown => CTypeLike::Unknown,
    }
}

fn type_like_to_ctype(ty: &CTypeLike) -> CType {
    match ty {
        CTypeLike::Void => CType::Void,
        CTypeLike::Bool => CType::Bool,
        CTypeLike::Int { bits, signedness } => match signedness {
            Signedness::Unsigned => CType::UInt(*bits),
            Signedness::Signed | Signedness::Unknown => CType::Int(*bits),
        },
        CTypeLike::Float(bits) => CType::Float(*bits),
        CTypeLike::Pointer(inner) => CType::Pointer(Box::new(type_like_to_ctype(inner))),
        CTypeLike::Array(inner, len) => CType::Array(Box::new(type_like_to_ctype(inner)), *len),
        CTypeLike::Struct(name) => CType::Struct(name.clone()),
        CTypeLike::Union(name) => CType::Union(name.clone()),
        CTypeLike::Enum(name) => CType::Enum(name.clone()),
        CTypeLike::Function | CTypeLike::Unknown => CType::Unknown,
    }
}

fn external_signature_to_spec(
    signature: Option<ExternalFunctionSignature>,
) -> Option<FunctionSignatureSpec> {
    signature.map(|signature| FunctionSignatureSpec {
        ret_type: signature.ret_type.as_ref().map(ctype_to_type_like),
        params: signature
            .params
            .iter()
            .map(|param| r2types::FunctionParamSpec {
                name: param.name.clone(),
                ty: param.ty.as_ref().map(ctype_to_type_like),
            })
            .collect(),
    })
}

fn external_stack_vars_to_specs(
    stack_vars: HashMap<i64, ExternalStackVar>,
) -> HashMap<i64, ExternalStackVarSpec> {
    stack_vars
        .into_iter()
        .map(|(offset, stack_var)| {
            (
                offset,
                ExternalStackVarSpec {
                    name: stack_var.name,
                    ty: stack_var.ty.as_ref().map(ctype_to_type_like),
                    base: stack_var.base,
                },
            )
        })
        .collect()
}

/// Thin decompiler-facing wrapper over the type inference engine owned by `r2types`.
pub struct TypeInference {
    inner: InnerTypeInference,
}

impl TypeInference {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(ptr_size: u32) -> Self {
        Self {
            inner: InnerTypeInference::new(ptr_size),
        }
    }

    pub fn new_with_abi(ptr_size: u32, arg_regs: Vec<String>, ret_regs: Vec<String>) -> Self {
        Self {
            inner: InnerTypeInference::new_with_abi(ptr_size, arg_regs, ret_regs),
        }
    }

    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.inner.set_function_names(names);
    }

    pub fn set_external_signature(&mut self, signature: Option<ExternalFunctionSignature>) {
        self.inner
            .set_external_signature(external_signature_to_spec(signature));
    }

    pub fn set_external_stack_vars(&mut self, stack_vars: HashMap<i64, ExternalStackVar>) {
        self.inner
            .set_external_stack_vars(external_stack_vars_to_specs(stack_vars));
    }

    pub fn set_external_type_db(&mut self, db: ExternalTypeDb) {
        self.inner.set_external_type_db(db);
    }

    pub fn infer_function(&mut self, func: &SSAFunction) {
        self.inner.infer_function(func);
    }

    pub fn get_type(&self, var: &SSAVar) -> CType {
        type_like_to_ctype(&self.inner.get_type(var))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn type_from_size(&self, size: u32) -> CType {
        type_like_to_ctype(&self.inner.type_from_size(size))
    }

    pub fn var_type_hints(&self) -> HashMap<String, CType> {
        self.inner
            .var_type_hints()
            .into_iter()
            .map(|(name, ty)| (name, type_like_to_ctype(&ty)))
            .collect()
    }

    pub fn add_function_type<T: Into<R2FunctionType>>(&mut self, name: &str, func_type: T) {
        self.inner.add_function_type(name, func_type);
    }

    #[allow(dead_code)]
    pub fn solved_types(&self) -> Option<&r2types::SolvedTypes> {
        self.inner.solved_types()
    }

    pub(crate) fn combined_type_oracle(&self) -> Option<CombinedTypeOracle<'_>> {
        self.inner.combined_type_oracle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_from_size_converts_back_to_ctype() {
        let ti = TypeInference::new(64);

        assert_eq!(ti.type_from_size(1), CType::Int(8));
        assert_eq!(ti.type_from_size(2), CType::Int(16));
        assert_eq!(ti.type_from_size(4), CType::Int(32));
        assert_eq!(ti.type_from_size(8), CType::Int(64));
    }

    #[test]
    fn function_type_converts_to_r2types_contract() {
        let ty = FunctionType {
            return_type: CType::Int(32),
            params: vec![CType::ptr(CType::Int(8)), CType::UInt(64)],
            variadic: false,
        };

        let converted: R2FunctionType = (&ty).into();
        assert_eq!(
            converted.return_type,
            CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            }
        );
        assert_eq!(converted.params.len(), 2);
    }
}
