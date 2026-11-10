use std::collections::HashMap;

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

pub fn merge_type_hint(hints: &mut HashMap<String, TypeHint>, key: String, incoming: TypeHint) {
    match hints.get(&key) {
        Some(current) if !incoming_hint_should_replace(current, &incoming) => {}
        _ => {
            hints.insert(key, incoming);
        }
    }
}

/// Each formal parameter of the boundary facts, in slot order: register and stack alike.
pub(crate) fn recover_signature_params_from_prepared_ssa(
    prepared: &r2ssa::SsaArtifact,
    ptr_bits: u32,
) -> Vec<RecoveredSignatureParam> {
    prepared
        .facts()
        .boundaries
        .parameters
        .iter()
        .filter(|(index, fact)| fact.index == **index)
        .map(|(index, fact)| {
            let index = *index as usize;
            let initial_ty = if source_parameter_is_logical_pointer(prepared, index, ptr_bits)
                || source_parameter_has_certified_memory_use(prepared, index)
            {
                crate::CTypeLike::Pointer(Box::new(crate::CTypeLike::Void))
            } else {
                size_to_neutral_int_type_like(fact.bytes())
            };
            RecoveredSignatureParam {
                name: r2source::positional_parameter_name(index),
                arg_index: index,
                value: fact.value(),
                size_bytes: fact.bytes(),
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
                        r2ssa::SourceTypeKind::Pointer {
                            target_type_id: 0,
                            const_target: false,
                        },
                        64,
                        64,
                    ),
                ],
                [],
            )
            .expect("pointer type graph");
            r2ssa::SourceFunctionInterface::new_exact_with_logical_types(
                b"prepare-source-pointer".to_vec(),
                r2source::ConventionId::Aapcs64,
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
                r2source::ConventionId::Aapcs64,
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
            ..Default::default()
        };
        r2ssa::SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
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
}
