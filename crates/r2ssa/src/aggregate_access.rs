//! Exact source-layout projections for scalar aggregate member accesses.
//!
//! This pass only joins facts already owned by r2ssa: a revision-bound source
//! type graph, canonical parameter-relative address provenance, and one exact
//! structured RAM access.  Failure to prove every part leaves the access
//! unprojected.

use std::collections::BTreeMap;

use r2il::SpaceId;
use serde::Serialize;

use crate::{
    AddressProvenanceFacts, InstId, InstPayload, SSAOp, SourceMachineContext, SourceTypeKind,
    SsaGraph, StructuredAccessId, StructuredMemoryAccessFact, ValueId,
};

pub const AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION: u32 = 4;

/// Exact scalar value carried by one projected memory effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AggregateAccessBinding {
    Read { result: ValueId },
    Write { value: ValueId },
}

/// Exact source-layout array index retained by one aggregate access.
///
/// The coefficient is not caller policy: it is admitted only when it equals
/// the byte size of the revision-bound aggregate layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AggregateElementIndexProjection {
    pub value: ValueId,
    pub stride_bytes: u64,
}

/// One exact access to a scalar member in a source-owned aggregate layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggregateAccessProjection {
    pub schema_version: u32,
    pub source_revision_identity: Box<[u8]>,
    pub source_parameter_index: u32,
    pub pointer_type_id: u32,
    pub struct_type_id: u32,
    pub aggregate_id: u32,
    /// Member ids from the outermost aggregate to the scalar leaf the access reads (D346).
    pub path: Box<[u32]>,
    /// The path's member names joined by `.` (`top_left.x`), so a consumer needs no graph.
    pub member_name: Box<str>,
    /// The leaf's type.
    pub member_type_id: u32,
    pub element_index: Option<AggregateElementIndexProjection>,
    pub byte_offset: u64,
    pub byte_width: u32,
    pub space: SpaceId,
    pub access: StructuredAccessId,
    pub producer: InstId,
    pub binding: AggregateAccessBinding,
}

/// Revision-sealed aggregate access projections keyed by canonical access ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggregateAccessProjectionFacts {
    schema_version: u32,
    source_revision_identity: Option<Box<[u8]>>,
    projections: BTreeMap<StructuredAccessId, AggregateAccessProjection>,
}

impl Default for AggregateAccessProjectionFacts {
    fn default() -> Self {
        Self {
            schema_version: AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION,
            source_revision_identity: None,
            projections: BTreeMap::new(),
        }
    }
}

impl AggregateAccessProjectionFacts {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn source_revision_identity(&self) -> Option<&[u8]> {
        self.source_revision_identity.as_deref()
    }

    pub fn projection(
        &self,
        source_revision_identity: &[u8],
        access: StructuredAccessId,
    ) -> Option<&AggregateAccessProjection> {
        (self.source_revision_identity.as_deref() == Some(source_revision_identity))
            .then(|| self.projections.get(&access))
            .flatten()
    }

    pub fn projections_for_revision(
        &self,
        source_revision_identity: &[u8],
    ) -> Option<&BTreeMap<StructuredAccessId, AggregateAccessProjection>> {
        (self.source_revision_identity.as_deref() == Some(source_revision_identity))
            .then_some(&self.projections)
    }

    pub fn len(&self) -> usize {
        self.projections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.projections.is_empty()
    }
}

fn graph_type(graph: &crate::SourceTypeGraph, type_id: u32) -> Option<&crate::SourceType> {
    usize::try_from(type_id)
        .ok()
        .and_then(|index| graph.types().get(index))
        .filter(|source_type| source_type.id() == type_id)
}

fn exact_access_binding(
    graph: &SsaGraph,
    access: &StructuredMemoryAccessFact,
    expected_space: SpaceId,
) -> Option<AggregateAccessBinding> {
    if access.id.ordinal != 0 {
        return None;
    }
    let instruction = graph.inst(access.id.inst)?;
    if instruction.id != access.id.inst {
        return None;
    }
    match (&instruction.payload, access.is_write) {
        (InstPayload::Op(SSAOp::Load { dst, space, addr }), false) => (*space == expected_space
            && *addr == access.address
            && access.value == Some(*dst)
            && instruction.output == Some(*dst)
            && graph.var(*dst).size == access.width)
            .then_some(AggregateAccessBinding::Read { result: *dst }),
        (InstPayload::Op(SSAOp::Store { space, addr, val }), true) => (*space == expected_space
            && *addr == access.address
            && access.value == Some(*val)
            && instruction.output.is_none()
            && graph.var(*val).size == access.width)
            .then_some(AggregateAccessBinding::Write { value: *val }),
        _ => None,
    }
}

/// The scalar member an access of `size_bits` at `offset_bits` reads, by member path.
struct ScalarLeaf {
    path: Vec<u32>,
    name: String,
    type_id: u32,
}

/// Descends by-value struct members to the one scalar member the access covers exactly.
/// A union, an array, a bit-field or two containing members refuse. The graph refuses
/// self-containment, so the descent ends within `aggregates().len()` levels; each level is O(m).
fn scalar_leaf(
    graph: &crate::SourceTypeGraph,
    aggregate: &crate::SourceAggregateLayout,
    offset_bits: u64,
    size_bits: u64,
) -> Option<ScalarLeaf> {
    let mut leaf = ScalarLeaf {
        path: Vec::new(),
        name: String::new(),
        type_id: 0,
    };
    let (mut aggregate, mut offset_bits) = (aggregate, offset_bits);
    for _ in 0..=graph.aggregates().len() {
        let mut containing = aggregate.members().iter().filter(|member| {
            member.offset_bits() <= offset_bits
                && offset_bits - member.offset_bits() < member.size_bits()
        });
        let member = containing.next()?;
        if containing.next().is_some() || member.is_bit_field() {
            return None;
        }
        let member_type = graph_type(graph, member.type_id())?;
        leaf.path.push(member.member_id());
        // An anonymous struct member adds no name: C spells its members as the outer's.
        if !member.name().is_empty() {
            if !leaf.name.is_empty() {
                leaf.name.push('.');
            }
            leaf.name.push_str(member.name());
        }
        let inner = offset_bits - member.offset_bits();
        match member_type.kind() {
            SourceTypeKind::Struct { aggregate_id } => {
                aggregate = usize::try_from(aggregate_id)
                    .ok()
                    .and_then(|index| graph.aggregates().get(index))
                    .filter(|nested| nested.id() == aggregate_id)?;
                offset_bits = inner;
            }
            SourceTypeKind::Union { .. } | SourceTypeKind::Array { .. } => return None,
            // Where an access lands and how wide it is decide the member, not its kind:
            // a store to `s->next` projects onto the pointer.
            _ => {
                return (inner == 0
                    && !member.name().is_empty()
                    && member.size_bits() == size_bits
                    && member_type.size_bits() == size_bits)
                    .then(|| ScalarLeaf {
                        type_id: member.type_id(),
                        ..leaf
                    });
            }
        }
    }
    None
}

pub(crate) fn collect_aggregate_access_projections(
    graph: &SsaGraph,
    addresses: &AddressProvenanceFacts,
    accesses: &BTreeMap<StructuredAccessId, StructuredMemoryAccessFact>,
    machine_context: &SourceMachineContext,
) -> AggregateAccessProjectionFacts {
    let Some(interface) = machine_context.function_interface() else {
        return AggregateAccessProjectionFacts::default();
    };
    let Some(type_graph) = interface.type_graph() else {
        return AggregateAccessProjectionFacts::default();
    };
    let revision = interface.revision_identity().to_vec().into_boxed_slice();
    let mut projections = BTreeMap::new();
    for (access_id, access) in accesses {
        let space = access.space;
        if *access_id != access.id || !access.provenance_complete || space != SpaceId::Ram {
            continue;
        }
        let Some(binding) = exact_access_binding(graph, access, space) else {
            continue;
        };
        let Some(expression) = addresses.parameter_expression(access.address) else {
            continue;
        };
        if expression.offset < 0 {
            continue;
        }
        let Ok(parameter_index) = u32::try_from(expression.parameter) else {
            continue;
        };
        let Some(parameter) = interface.parameters().get(expression.parameter) else {
            continue;
        };
        let Some(logical_value) = interface.parameter_logical_value(expression.parameter) else {
            continue;
        };
        if parameter.index() != parameter_index {
            continue;
        }
        if expression.parameter_storage != parameter.register_storage() {
            continue;
        }
        let pointer_type_id = logical_value.type_id();
        let Some(pointer_type) = graph_type(type_graph, pointer_type_id) else {
            continue;
        };
        let SourceTypeKind::Pointer {
            target_type_id: struct_type_id,
            ..
        } = pointer_type.kind()
        else {
            continue;
        };
        let Some(struct_type) = graph_type(type_graph, struct_type_id) else {
            continue;
        };
        let SourceTypeKind::Struct { aggregate_id } = struct_type.kind() else {
            continue;
        };
        let Some(aggregate) = usize::try_from(aggregate_id)
            .ok()
            .and_then(|index| type_graph.aggregates().get(index))
            .filter(|aggregate| {
                aggregate.id() == aggregate_id && aggregate.type_id() == struct_type_id
            })
        else {
            continue;
        };
        if aggregate.size_bits() == 0 || !aggregate.size_bits().is_multiple_of(8) {
            continue;
        }
        let aggregate_size_bytes = aggregate.size_bits() / 8;
        let element_index = match expression.terms.as_slice() {
            [] => None,
            [term]
                if term.coefficient > 0
                    && u64::try_from(term.coefficient) == Ok(aggregate_size_bytes)
                    && graph.value(term.value).is_some() =>
            {
                Some(AggregateElementIndexProjection {
                    value: term.value,
                    stride_bytes: aggregate_size_bytes,
                })
            }
            _ => continue,
        };
        let Ok(byte_offset) = u64::try_from(expression.offset) else {
            continue;
        };
        let Some(offset_bits) = byte_offset.checked_mul(8) else {
            continue;
        };
        let size_bits = u64::from(access.width) * 8;
        let Some(leaf) = scalar_leaf(type_graph, aggregate, offset_bits, size_bits) else {
            continue;
        };
        let projection = AggregateAccessProjection {
            schema_version: AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION,
            source_revision_identity: revision.clone(),
            source_parameter_index: parameter_index,
            pointer_type_id,
            struct_type_id,
            aggregate_id,
            path: leaf.path.into_boxed_slice(),
            member_name: leaf.name.into_boxed_str(),
            member_type_id: leaf.type_id,
            element_index,
            byte_offset,
            byte_width: access.width,
            space,
            access: access.id,
            producer: access.id.inst,
            binding,
        };
        if projections.insert(access.id, projection).is_some() {
            projections.remove(&access.id);
        }
    }
    AggregateAccessProjectionFacts {
        schema_version: AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION,
        source_revision_identity: Some(revision),
        projections,
    }
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    use super::*;
    use crate::{
        CanonicalStorageId, CanonicalStorageSpace, SourceAbiParameterSpec, SourceAggregateLayout,
        SourceAggregateMember, SourceCarrierKind, SourceCarrierProjection, SourceFunctionInterface,
        SourceFunctionReturn, SourceLogicalValue, SourceType, SourceTypeGraph,
    };

    const REVISION: &[u8] = b"demo-struct-layout-revision";

    fn register_storage(offset: u64) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        }
    }

    fn aarch64_arch() -> crate::Arch {
        crate::Arch::new(aarch64_arch_spec())
    }

    fn aarch64_arch_spec() -> ArchSpec {
        let mut arch = ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.alignment = 4;
        arch.add_register(RegisterDef::new("x0", 0, 8));
        arch.add_register(RegisterDef::new("w0", 0, 4));
        arch.add_register(RegisterDef::new("x1", 8, 8));
        arch.add_register(RegisterDef::new("w1", 8, 4));
        arch.add_register(RegisterDef::new("x2", 16, 8));
        arch.add_register(RegisterDef::new("w2", 16, 4));
        arch.add_register(RegisterDef::new("x3", 24, 8));
        arch
    }

    fn demo_struct_graph() -> SourceTypeGraph {
        let members = (0..14).map(|index| {
            SourceAggregateMember::new(
                index,
                1,
                u64::from(index) * 32,
                32,
                format!("member_{index}"),
            )
        });
        SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::Struct { aggregate_id: 0 }, 56 * 8, 32),
                SourceType::new(1, SourceTypeKind::SignedInteger, 32, 32),
                SourceType::new(
                    2,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
            ],
            [SourceAggregateLayout::new(
                0,
                0,
                56 * 8,
                32,
                "DemoStruct",
                members,
            )],
        )
        .expect("valid DemoStruct graph")
    }

    /// `struct R { struct P tl; struct P br; union U u; }`, `struct P { int x; int y; }`,
    /// `union U { int a; int b; }`; type 2 is `struct R *`.
    fn nested_struct_graph() -> SourceTypeGraph {
        let point = |id| {
            SourceAggregateLayout::new(
                id,
                3,
                64,
                32,
                "P",
                [
                    SourceAggregateMember::new(0, 1, 0, 32, "x"),
                    SourceAggregateMember::new(1, 1, 32, 32, "y"),
                ],
            )
        };
        SourceTypeGraph::new(
            [
                SourceType::new(0, SourceTypeKind::Struct { aggregate_id: 0 }, 160, 32),
                SourceType::new(1, SourceTypeKind::SignedInteger, 32, 32),
                SourceType::new(
                    2,
                    SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
                SourceType::new(3, SourceTypeKind::Struct { aggregate_id: 1 }, 64, 32),
                SourceType::new(4, SourceTypeKind::Union { aggregate_id: 2 }, 32, 32),
            ],
            [
                SourceAggregateLayout::new(
                    0,
                    0,
                    160,
                    32,
                    "R",
                    [
                        SourceAggregateMember::new(0, 3, 0, 64, "tl"),
                        SourceAggregateMember::new(1, 3, 64, 64, "br"),
                        SourceAggregateMember::new(2, 4, 128, 32, "u"),
                    ],
                ),
                point(1),
                SourceAggregateLayout::new(
                    2,
                    4,
                    32,
                    32,
                    "U",
                    [
                        SourceAggregateMember::new(0, 1, 0, 32, "a"),
                        SourceAggregateMember::new(1, 1, 0, 32, "b"),
                    ],
                ),
            ],
        )
        .expect("valid nested graph")
    }

    fn interface_with_graph(graph: SourceTypeGraph) -> SourceFunctionInterface {
        let scalar_carrier = SourceCarrierProjection::new(SourceCarrierKind::LowBits, 0, 32);
        SourceFunctionInterface::new_with_logical_types(
            REVISION.to_vec(),
            r2source::ConventionId::Aapcs64,
            [
                SourceAbiParameterSpec::new(0, register_storage(0)),
                SourceAbiParameterSpec::new(1, register_storage(8)),
            ],
            SourceFunctionReturn::Void,
            [],
            [
                Some(SourceLogicalValue::new(
                    2,
                    SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 64),
                )),
                Some(SourceLogicalValue::new(1, scalar_carrier)),
            ],
            None,
            Some(graph),
        )
        .expect("valid nested source interface")
    }

    /// D346: a read inside a by-value member names the scalar leaf; a union member refuses.
    #[test]
    fn a_read_inside_a_nested_struct_member_projects_its_member_path() {
        let projected = |offset| {
            let blocks = single_load_blocks(Varnode::register(0, 8), offset, 4, SpaceId::Ram);
            let artifact =
                artifact_with_interface(&blocks, interface_with_graph(nested_struct_graph()));
            let facts = artifact.aggregate_accesses();
            (facts.projections_for_revision(REVISION).into_iter())
                .flat_map(|projections| projections.values())
                .map(|projection| (projection.path.to_vec(), projection.member_name.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(projected(8), [(vec![1, 0], "br.x".to_string())]);
        assert_eq!(projected(4), [(vec![0, 1], "tl.y".to_string())]);
        assert!(
            projected(16).is_empty(),
            "a union member names no single leaf"
        );
    }

    /// Nine single-member levels around one `int`: the leaf's path names every level.
    #[test]
    fn a_scalar_nested_at_any_depth_is_named_by_its_whole_path() {
        const LEVELS: u32 = 9;
        let mut types = vec![SourceType::new(0, SourceTypeKind::SignedInteger, 32, 32)];
        let mut aggregates = Vec::new();
        for level in 0..LEVELS {
            let kind = SourceTypeKind::Struct {
                aggregate_id: level,
            };
            types.push(SourceType::new(level + 1, kind, 32, 32));
            let (member, name) = match level + 1 == LEVELS {
                true => (0, "leaf"),
                false => (level + 2, "inner"),
            };
            let members = [SourceAggregateMember::new(0, member, 0, 32, name)];
            aggregates.push(SourceAggregateLayout::new(
                level,
                level + 1,
                32,
                32,
                format!("level{level}"),
                members,
            ));
        }
        let graph = SourceTypeGraph::new(types, aggregates).expect("nested graph");
        let leaf = scalar_leaf(&graph, &graph.aggregates()[0], 0, 32).expect("a leaf");
        assert_eq!(
            leaf.name,
            format!("{}leaf", "inner.".repeat(LEVELS as usize - 1))
        );
        assert_eq!(leaf.path.len(), LEVELS as usize);
    }

    fn source_interface(exact_graph: bool) -> SourceFunctionInterface {
        source_interface_with_pointer_storage(exact_graph, 0)
    }

    fn source_interface_with_pointer_storage(
        exact_graph: bool,
        pointer_offset: u64,
    ) -> SourceFunctionInterface {
        let parameters = [
            SourceAbiParameterSpec::new(0, register_storage(pointer_offset)),
            SourceAbiParameterSpec::new(1, register_storage(8)),
            SourceAbiParameterSpec::new(2, register_storage(16)),
        ];
        if !exact_graph {
            return SourceFunctionInterface::new(
                REVISION.to_vec(),
                r2source::ConventionId::Aapcs64,
                parameters,
                SourceFunctionReturn::Void,
                [],
            )
            .expect("valid untyped source interface");
        }
        let scalar_carrier = SourceCarrierProjection::new(SourceCarrierKind::LowBits, 0, 32);
        SourceFunctionInterface::new_with_logical_types(
            REVISION.to_vec(),
            r2source::ConventionId::Aapcs64,
            parameters,
            SourceFunctionReturn::Void,
            [],
            [
                Some(SourceLogicalValue::new(
                    2,
                    SourceCarrierProjection::new(SourceCarrierKind::Full, 0, 64),
                )),
                Some(SourceLogicalValue::new(1, scalar_carrier)),
                Some(SourceLogicalValue::new(1, scalar_carrier)),
            ],
            None,
            Some(demo_struct_graph()),
        )
        .expect("valid exact source interface")
    }

    fn exact_member_blocks() -> Vec<R2ILBlock> {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(52, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x30, 8),
            val: Varnode::register(16, 4),
        });
        vec![block]
    }

    fn single_load_blocks(
        base: Varnode,
        offset: u64,
        width: u32,
        space: SpaceId,
    ) -> Vec<R2ILBlock> {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 8),
            a: base,
            b: Varnode::constant(offset, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, width),
            space,
            addr: Varnode::unique(0x10, 8),
        });
        vec![block]
    }

    fn artifact(blocks: &[R2ILBlock], exact_graph: bool) -> crate::SsaArtifact {
        artifact_with_interface(blocks, source_interface(exact_graph))
    }

    /// The first operation of the block that `matches`; lane and formal
    /// projections put operations before the lifted ones, so an index is not
    /// a stable name for one.
    fn first_op(
        artifact: &crate::SsaArtifact,
        block_addr: u64,
        matches: impl Fn(&crate::SSAOp) -> bool,
    ) -> crate::InstId {
        let block = artifact.named_block(block_addr).expect("block");
        let (id, _) = block
            .sited()
            .find(|(_, op)| matches(op))
            .expect("an operation of the requested kind");
        artifact
            .graph()
            .inst_for_op(id)
            .expect("instruction for the operation")
    }

    fn artifact_with_interface(
        blocks: &[R2ILBlock],
        interface: SourceFunctionInterface,
    ) -> crate::SsaArtifact {
        crate::SsaArtifact::for_decompile_with_interface(blocks, Some(&aarch64_arch()), interface)
            .expect("prepared source-backed SSA")
    }

    #[test]
    fn exact_demo_struct_load_and_store_project_stable_member_facts() {
        let artifact = artifact(&exact_member_blocks(), true);
        let facts = artifact.aggregate_accesses();
        let projections = facts
            .projections_for_revision(REVISION)
            .expect("matching source revision");
        assert_eq!(
            facts.schema_version(),
            AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION
        );
        assert_eq!(projections.len(), 2);

        let load_inst = first_op(&artifact, 0x1000, |op| {
            matches!(op, crate::SSAOp::Load { .. })
        });
        let load_access = StructuredAccessId {
            inst: load_inst,
            ordinal: 0,
        };
        let load = facts
            .projection(REVISION, load_access)
            .expect("third-member load projection");
        assert_eq!(load.source_revision_identity.as_ref(), REVISION);
        assert_eq!(load.source_parameter_index, 0);
        assert_eq!(load.pointer_type_id, 2);
        assert_eq!(load.struct_type_id, 0);
        assert_eq!(load.aggregate_id, 0);
        assert_eq!(load.path.as_ref(), [2]);
        assert_eq!(load.member_name.as_ref(), "member_2");
        assert_eq!(load.member_type_id, 1);
        assert_eq!(load.element_index, None);
        assert_eq!((load.byte_offset, load.byte_width), (8, 4));
        assert_eq!(load.space, SpaceId::Ram);
        assert_eq!(load.access, load_access);
        assert_eq!(load.producer, load_inst);
        let AggregateAccessBinding::Read { result } = load.binding else {
            panic!("load projection must retain its exact result value");
        };
        assert_eq!(artifact.graph().def_inst(result), Some(load_inst));

        let store_inst = first_op(&artifact, 0x1000, |op| {
            matches!(op, crate::SSAOp::Store { .. })
        });
        let store_access = StructuredAccessId {
            inst: store_inst,
            ordinal: 0,
        };
        let store = facts
            .projection(REVISION, store_access)
            .expect("fourteenth-member store projection");
        assert_eq!(store.path.as_ref(), [13]);
        assert_eq!((store.byte_offset, store.byte_width), (52, 4));
        assert_eq!(store.producer, store_inst);
        let AggregateAccessBinding::Write { value } = store.binding else {
            panic!("store projection must retain its exact stored value");
        };
        assert_eq!(
            artifact.structured().memory_accesses[&store_access].value,
            Some(value)
        );

        assert!(facts.projections_for_revision(b"other-revision").is_none());
        assert!(facts.projection(b"other-revision", load_access).is_none());
    }

    #[test]
    fn aggregate_projection_rejects_missing_or_mutated_authority() {
        let exact_blocks = exact_member_blocks();
        assert!(
            artifact(&exact_blocks, false)
                .aggregate_accesses()
                .is_empty()
        );

        let wrong_base = single_load_blocks(Varnode::register(8, 8), 8, 4, SpaceId::Ram);
        assert!(artifact(&wrong_base, true).aggregate_accesses().is_empty());

        let declared_other_base = single_load_blocks(Varnode::register(0, 8), 8, 4, SpaceId::Ram);
        assert!(
            artifact_with_interface(
                &declared_other_base,
                source_interface_with_pointer_storage(true, 24),
            )
            .aggregate_accesses()
            .is_empty()
        );

        let wrong_offset = single_load_blocks(Varnode::register(0, 8), 10, 4, SpaceId::Ram);
        assert!(
            artifact(&wrong_offset, true)
                .aggregate_accesses()
                .is_empty()
        );

        let wrong_width = single_load_blocks(Varnode::register(0, 8), 8, 8, SpaceId::Ram);
        assert!(artifact(&wrong_width, true).aggregate_accesses().is_empty());

        let wrong_space = single_load_blocks(Varnode::register(0, 8), 8, 4, SpaceId::Custom(7));
        assert!(artifact(&wrong_space, true).aggregate_accesses().is_empty());

        let nonzero_index = single_load_blocks(Varnode::register(0, 8), 64, 4, SpaceId::Ram);
        assert!(
            artifact(&nonzero_index, true)
                .aggregate_accesses()
                .is_empty()
        );

        let mut dynamic = R2ILBlock::new(0x1000, 4);
        dynamic.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(8, 8),
            b: Varnode::constant(56, 8),
        });
        dynamic.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x10, 8),
        });
        dynamic.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::constant(8, 8),
        });
        dynamic.push(R2ILOp::Load {
            dst: Varnode::unique(0x40, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x30, 8),
        });
        let indexed = artifact(&[dynamic], true);
        let indexed_access = StructuredAccessId {
            inst: first_op(&indexed, 0x1000, |op| {
                matches!(op, crate::SSAOp::Load { .. })
            }),
            ordinal: 0,
        };
        let indexed_projection = indexed
            .aggregate_accesses()
            .projection(REVISION, indexed_access)
            .expect("exact aggregate-stride index projection");
        let index = indexed_projection
            .element_index
            .expect("indexed projection must retain its exact SSA index");
        assert_eq!(index.stride_bytes, 56);
        assert_eq!(
            indexed
                .addresses()
                .parameter_expression(indexed.structured().memory_accesses[&indexed_access].address)
                .and_then(|expression| expression.terms.first())
                .map(|term| term.value),
            Some(index.value)
        );

        let mut wrong_stride = R2ILBlock::new(0x1000, 4);
        wrong_stride.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(8, 8),
            b: Varnode::constant(48, 8),
        });
        wrong_stride.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x10, 8),
        });
        wrong_stride.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::constant(8, 8),
        });
        wrong_stride.push(R2ILOp::Load {
            dst: Varnode::unique(0x40, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x30, 8),
        });
        assert!(
            artifact(&[wrong_stride], true)
                .aggregate_accesses()
                .is_empty()
        );

        let mut aliased = R2ILBlock::new(0x1000, 4);
        aliased.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        });
        aliased.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        assert!(artifact(&[aliased], true).aggregate_accesses().is_empty());

        let positive = artifact(&exact_blocks, true);
        let load_id = StructuredAccessId {
            inst: first_op(&positive, 0x1000, |op| {
                matches!(op, crate::SSAOp::Load { .. })
            }),
            ordinal: 0,
        };
        let mut ambiguous_accesses = positive.structured().memory_accesses.clone();
        ambiguous_accesses
            .get_mut(&load_id)
            .expect("load access")
            .provenance_complete = false;
        let recollected = collect_aggregate_access_projections(
            positive.graph(),
            positive.addresses(),
            &ambiguous_accesses,
            positive.machine_context(),
        );
        assert!(recollected.projection(REVISION, load_id).is_none());

        let mut mismatched_graph = positive.graph().clone();
        let instruction = mismatched_graph
            .insts
            .get_mut(load_id.inst.0 as usize)
            .expect("load instruction");
        let InstPayload::Op(SSAOp::Load { space, .. }) = &mut instruction.payload else {
            panic!("expected source load");
        };
        *space = SpaceId::Custom(7);
        let recollected = collect_aggregate_access_projections(
            &mismatched_graph,
            positive.addresses(),
            &positive.structured().memory_accesses,
            positive.machine_context(),
        );
        assert!(
            recollected.projection(REVISION, load_id).is_none(),
            "a Custom source op must not reuse a Ram machine-context projection"
        );
    }
}
