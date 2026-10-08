use std::collections::{BTreeMap, HashMap};

use r2ssa::SSAVar;

use crate::analysis::RecoveredVariable;
use crate::signature_infer::RecoveredSignatureParam;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeHintRank {
    Integer = 1,
    Float = 2,
    Pointer = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeHint {
    pub rank: TypeHintRank,
    pub ty: String,
}

impl TypeHint {
    pub fn pointer() -> Self {
        Self {
            rank: TypeHintRank::Pointer,
            ty: "void *".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataScalarKind {
    Bool,
    SignedInt,
    UnsignedInt,
    Float,
    Bitvector,
    Unknown,
}

pub fn size_to_signed_int_type(size: u32) -> String {
    match size {
        1 => "int8_t".to_string(),
        2 => "int16_t".to_string(),
        4 => "int32_t".to_string(),
        8 => "int64_t".to_string(),
        _ => format!("int{}_t", size.saturating_mul(8)),
    }
}

pub fn size_to_unsigned_int_type(size: u32) -> String {
    match size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        _ => format!("uint{}_t", size.saturating_mul(8)),
    }
}

pub fn scalar_metadata_type_hint(kind: MetadataScalarKind, size: u32) -> Option<TypeHint> {
    match kind {
        MetadataScalarKind::Bool => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: "bool".to_string(),
        }),
        MetadataScalarKind::SignedInt => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: size_to_signed_int_type(size),
        }),
        MetadataScalarKind::UnsignedInt => Some(TypeHint {
            rank: TypeHintRank::Integer,
            ty: size_to_unsigned_int_type(size),
        }),
        MetadataScalarKind::Float => {
            let ty = match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                16 => "long double".to_string(),
                _ => "float".to_string(),
            };
            Some(TypeHint {
                rank: TypeHintRank::Float,
                ty,
            })
        }
        MetadataScalarKind::Bitvector | MetadataScalarKind::Unknown => None,
    }
}

pub fn type_hint_from_value_metadata(
    pointer_like: bool,
    scalar_kind: Option<MetadataScalarKind>,
    size: u32,
) -> Option<TypeHint> {
    if pointer_like {
        return Some(TypeHint::pointer());
    }

    scalar_metadata_type_hint(scalar_kind?, size)
}

/// A key that identifies one SSA variable across its width views.
///
/// This deliberately does *not* include `size`. The maps it keys pool the
/// register's width views on purpose -- arm64 evidence has to flow between
/// `x0` and `w0`, and the x86 low-carrier tests fail immediately if it cannot.
///
/// It does now include `rename_disambiguator`, which it dropped before. That
/// field exists, by its own documentation, to separate "two exact source
/// storages that project to the same display name and width", so leaving it out
/// made the key collide on precisely the case it had been added to prevent, and
/// `DefUseInfo` carried the resulting ambiguity at runtime as an
/// `Option<usize>` meaning "the key collided". Width views of one register
/// share a disambiguator, so pooling still works.
pub fn ssa_var_key(var: &SSAVar) -> String {
    format!(
        "{}_{}_{}",
        var.name().to_ascii_lowercase(),
        var.version,
        var.rename_disambiguator()
    )
}

pub fn ssa_var_block_key(block_addr: u64, var: &SSAVar) -> String {
    format!("{}@{block_addr:x}", ssa_var_key(var))
}

pub fn merge_type_hint(hints: &mut HashMap<String, TypeHint>, key: String, incoming: TypeHint) {
    match hints.get(&key) {
        Some(current) if !incoming_hint_should_replace(current, &incoming) => {}
        _ => {
            hints.insert(key, incoming);
        }
    }
}

/// The variable each formal enters in.
///
/// This is the inverse of the identity relation, not a second copy of it: the
/// forward map answers which formal a value is, and once it holds every value
/// that is a formal it can no longer name the one variable a signature
/// parameter is declared from. The boundary facts state that directly.
fn prepared_formal_parameters(prepared: &r2ssa::SsaArtifact) -> BTreeMap<usize, SSAVar> {
    prepared
        .facts()
        .boundaries
        .parameters
        .iter()
        .filter(|(index, fact)| fact.index == **index)
        .filter_map(|(index, fact)| {
            Some((*index as usize, prepared.value_var(fact.value)?.clone()))
        })
        .collect()
}

pub(crate) fn recover_signature_params_from_prepared_ssa(
    prepared: &r2ssa::SsaArtifact,
    ptr_bits: u32,
) -> Vec<RecoveredSignatureParam> {
    prepared_formal_parameters(prepared)
        .into_iter()
        .map(|(index, var)| {
            let initial_ty = if source_parameter_is_logical_pointer(prepared, index, ptr_bits)
                || source_parameter_has_certified_memory_use(prepared, index)
            {
                crate::CTypeLike::Pointer(Box::new(crate::CTypeLike::Void))
            } else {
                size_to_neutral_int_type_like(var.size)
            };
            RecoveredSignatureParam {
                name: format!("arg{index}"),
                arg_index: index,
                ssa_var: var,
                initial_ty: if matches!(initial_ty, crate::CTypeLike::Unknown) && ptr_bits > 0 {
                    crate::CTypeLike::Int {
                        bits: ptr_bits,
                        signedness: crate::Signedness::Unknown,
                    }
                } else {
                    initial_ty
                },
            }
        })
        .collect()
}

fn source_parameter_is_logical_pointer(
    prepared: &r2ssa::SsaArtifact,
    index: usize,
    ptr_bits: u32,
) -> bool {
    let context = prepared.machine_context();
    if !context.abi_model().is_available() {
        return false;
    }
    let Some(interface) = context.function_interface() else {
        return false;
    };
    let Some(graph) = interface
        .type_graph()
        .filter(|graph| graph.validates_pointer_width(ptr_bits))
    else {
        return false;
    };
    let Some(parameter) = prepared
        .facts()
        .boundaries
        .parameters
        .get(&u32::try_from(index).unwrap_or(u32::MAX))
    else {
        return false;
    };
    if parameter.index as usize != index {
        return false;
    }
    let Some(logical_value) = parameter.logical_value else {
        return false;
    };
    graph
        .types()
        .get(logical_value.type_id() as usize)
        .is_some_and(|source_type| {
            matches!(source_type.kind(), r2ssa::SourceTypeKind::Pointer { .. })
        })
}

fn source_parameter_has_certified_memory_use(prepared: &r2ssa::SsaArtifact, index: usize) -> bool {
    prepared
        .certificates()
        .memory_accesses
        .values()
        .filter(|access| access.space == r2il::SpaceId::Ram)
        .any(|access| {
            prepared
                .addresses()
                .parameter_expression(access.address)
                .is_some_and(|address| address.parameter == index)
        })
}

/// The lifted machine's identity, where the lift was made under one.
pub(crate) fn prepared_arch_display_name(prepared: &r2ssa::SsaArtifact) -> Option<&str> {
    Some(prepared.machine_context().architecture()).filter(|name| !name.is_empty())
}

fn prepared_register_name(prepared: &r2ssa::SsaArtifact, index: usize) -> Option<String> {
    let slot = prepared
        .machine_context()
        .abi_model()
        .argument_registers()
        .iter()
        .find(|slot| slot.index() as usize == index)?;
    prepared
        .machine_context()
        .register_storages_by_name()
        .iter()
        .filter(|(_, storage)| **storage == slot.storage())
        .map(|(name, _)| name)
        .min_by_key(|name| (name.len(), *name))
        .cloned()
}

pub(crate) fn recover_vars_from_prepared_ssa(
    prepared: &r2ssa::SsaArtifact,
    ptr_bits: u32,
) -> Vec<RecoveredVariable> {
    let mut vars = recover_signature_params_from_prepared_ssa(prepared, ptr_bits)
        .into_iter()
        .map(|parameter| RecoveredVariable {
            name: parameter.name,
            kind: "r".to_string(),
            delta: 0,
            var_type: match parameter.initial_ty {
                crate::CTypeLike::Pointer(_) => "void *".to_string(),
                _ => crate::analysis::storage_type_spelling(
                    parameter.ssa_var.size,
                    crate::Signedness::Signed,
                )
                .unwrap_or_default(),
            },
            isarg: true,
            reg: prepared_register_name(prepared, parameter.arg_index),
        })
        .collect::<Vec<_>>();

    let mut stack_slots = prepared
        .certificates()
        .stack_slots
        .values()
        .map(|slot| {
            // The certified extent alone; a slot nothing sizes has none (doc/adr-frame-model.md, one extent rule).
            let size = slot.size.unwrap_or(0);
            RecoveredVariable {
                name: if slot.offset < 0 {
                    format!("var_{:x}", slot.offset.unsigned_abs())
                } else {
                    format!("var_{}", slot.offset)
                },
                kind: "v".to_string(),
                delta: slot.offset,
                // A slot nothing reads or writes a width of has no type.
                var_type: crate::analysis::storage_type_spelling(size, crate::Signedness::Signed)
                    .unwrap_or_default(),
                isarg: false,
                reg: None,
            }
        })
        .collect::<Vec<_>>();
    vars.append(&mut stack_slots);
    vars.sort_by(|left, right| {
        left.isarg
            .cmp(&right.isarg)
            .reverse()
            .then_with(|| left.delta.cmp(&right.delta))
            .then_with(|| left.name.cmp(&right.name))
    });
    vars.dedup_by(|left, right| {
        left.isarg == right.isarg
            && left.delta == right.delta
            && left.reg == right.reg
            && left.name == right.name
    });
    vars
}

fn size_to_neutral_int_type_like(size: u32) -> crate::CTypeLike {
    let bits = match size {
        1 => 8,
        2 => 16,
        4 => 32,
        8 => 64,
        _ => return crate::CTypeLike::Unknown,
    };
    crate::CTypeLike::Int {
        bits,
        signedness: crate::Signedness::Unknown,
    }
}

fn incoming_hint_should_replace(current: &TypeHint, incoming: &TypeHint) -> bool {
    incoming.rank > current.rank || (incoming.rank == current.rank && incoming.ty < current.ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared_aarch64_parameter(
        ops: Vec<r2il::R2ILOp>,
        declared_pointer: bool,
    ) -> r2ssa::SsaArtifact {
        let mut arch = r2il::ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.add_register(r2il::RegisterDef::new("x0", 0, 8));
        arch.add_register(r2il::RegisterDef::new("sp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("lr", 24, 8));
        let storage = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = if declared_pointer {
            let graph = r2ssa::SourceTypeGraph::new(
                [
                    r2ssa::SourceType::new(0, r2ssa::SourceTypeKind::UnsignedInteger, 8, 8),
                    r2ssa::SourceType::new(
                        1,
                        r2ssa::SourceTypeKind::Pointer { target_type_id: 0 },
                        64,
                        64,
                    ),
                ],
                [],
            )
            .expect("pointer type graph");
            r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
                b"prepare-source-pointer".to_vec(),
                "aarch64",
                [r2ssa::SourceAbiParameterSpec::new(0, storage(0))],
                r2ssa::SourceFunctionReturn::Void,
                [],
                [Some(r2ssa::SourceLogicalValue::new(
                    1,
                    r2ssa::SourceCarrierProjection::new(r2ssa::SourceCarrierKind::Full, 0, 64),
                ))],
                None,
                Some(graph),
            )
        } else {
            r2ssa::SourceFunctionInterface::new_exact(
                b"prepare-source-scalar".to_vec(),
                "aarch64",
                [r2ssa::SourceAbiParameterSpec::new(0, storage(0))],
                r2ssa::SourceFunctionReturn::Void,
                [],
            )
        }
        .and_then(|interface| interface.with_return_address_storage(storage(24)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(16)))
        .expect("exact AArch64 interface");
        let block = r2il::R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops,
            switch_info: None,
            op_metadata: Default::default(),
        };
        r2ssa::SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("prepared AArch64 parameter")
    }

    #[test]
    fn prepared_parameter_pointer_requires_use_or_exact_source_type() {
        let scalar = prepared_aarch64_parameter(
            vec![r2il::R2ILOp::IntLess {
                dst: r2il::Varnode::unique(0x10, 1),
                a: r2il::Varnode::register(0, 8),
                b: r2il::Varnode::constant(10, 8),
            }],
            false,
        );
        let dereferenced = prepared_aarch64_parameter(
            vec![r2il::R2ILOp::Load {
                dst: r2il::Varnode::unique(0x20, 1),
                space: r2il::SpaceId::Ram,
                addr: r2il::Varnode::register(0, 8),
            }],
            false,
        );
        let declared = prepared_aarch64_parameter(
            vec![r2il::R2ILOp::Copy {
                dst: r2il::Varnode::unique(0x30, 8),
                src: r2il::Varnode::register(0, 8),
            }],
            true,
        );

        let initial_type = |prepared: &r2ssa::SsaArtifact| {
            recover_signature_params_from_prepared_ssa(prepared, 64)
                .into_iter()
                .find(|parameter| parameter.arg_index == 0)
                .expect("first parameter")
                .initial_ty
        };
        assert!(matches!(
            initial_type(&scalar),
            crate::CTypeLike::Int { .. }
        ));
        assert!(matches!(
            initial_type(&dereferenced),
            crate::CTypeLike::Pointer(_)
        ));
        assert!(matches!(
            initial_type(&declared),
            crate::CTypeLike::Pointer(_)
        ));
    }

    #[test]
    fn metadata_scalar_type_hints_are_width_aware() {
        assert_eq!(
            scalar_metadata_type_hint(MetadataScalarKind::Bool, 1).map(|hint| hint.ty),
            Some("bool".to_string())
        );
        assert_eq!(
            scalar_metadata_type_hint(MetadataScalarKind::SignedInt, 4).map(|hint| hint.ty),
            Some("int32_t".to_string())
        );
        assert_eq!(
            scalar_metadata_type_hint(MetadataScalarKind::UnsignedInt, 8).map(|hint| hint.ty),
            Some("uint64_t".to_string())
        );
        assert_eq!(
            scalar_metadata_type_hint(MetadataScalarKind::Float, 8).map(|hint| hint.ty),
            Some("double".to_string())
        );
        assert!(scalar_metadata_type_hint(MetadataScalarKind::Unknown, 8).is_none());
    }

    #[test]
    fn value_metadata_pointer_hint_overrides_scalar_hint() {
        let hint = type_hint_from_value_metadata(true, Some(MetadataScalarKind::UnsignedInt), 8)
            .expect("pointer hint");

        assert_eq!(hint.rank, TypeHintRank::Pointer);
        assert_eq!(hint.ty, "void *");
    }
}
