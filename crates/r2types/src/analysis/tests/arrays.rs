//! What the analysis proves about arrays and their elements.

use super::super::*;

#[test]
fn prepared_parameter_indexed_accesses_keep_semantic_index_identity() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("RAX", 0x00, 8));
    arch.add_register(r2il::RegisterDef::sub("EAX", 0x00, 4, "RAX"));
    arch.add_register(r2il::RegisterDef::new("RDI", 0x10, 8));
    arch.add_register(r2il::RegisterDef::new("RSI", 0x18, 8));
    arch.add_register(r2il::RegisterDef::sub("ESI", 0x18, 4, "RSI"));
    let mut block = r2il::R2ILBlock::new(0x401000, 4);
    block.push(r2il::R2ILOp::IntZExt {
        dst: r2il::Varnode::unique(1, 8),
        src: r2il::Varnode::register(0x18, 4),
    });
    block.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(2, 8),
        a: r2il::Varnode::register(0x10, 8),
        b: r2il::Varnode::unique(1, 8),
    });
    block.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::register(0x00, 1),
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(2, 8),
    });
    block.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(3, 1),
        space: r2il::SpaceId::Custom(7),
        addr: r2il::Varnode::unique(2, 8),
    });
    let register_storage = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"prepared-indexed-access-fixture".to_vec(),
        "sysv64",
        [
            r2ssa::SourceAbiParameterSpec::new(0, register_storage(0x10)),
            r2ssa::SourceAbiParameterSpec::new(1, register_storage(0x18)),
        ],
        r2ssa::SourceFunctionReturn::Void,
        [],
    )
    .expect("exact indexed-access interface");
    let prepared = r2ssa::SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&r2ssa::Arch::from(arch.clone())),
        interface,
    )
    .expect("prepared indexed load");
    let graph = prepared.graph();
    let load_inst = (graph
        .op_insts(graph.block_id_for_addr(0x401000).expect("block"))
        .iter())
    .copied()
    .find(|inst| matches!(graph.op(*inst), Some(r2ssa::SSAOp::Load { .. })))
    .expect("indexed load instruction");
    let address = prepared
        .memory_certificate_for_inst(load_inst, false)
        .expect("memory certificate");
    let parameter_address = prepared
        .addresses()
        .parameter_expression(address.address)
        .expect("parameter-relative address");
    let index_value = parameter_address.terms[0].value;
    let custom_load = (graph.op_insts(graph.block_id_for_addr(0x401000).expect("block")).iter())
        .copied()
        .find(|inst| {
            matches!(graph.op(*inst), Some(r2ssa::SSAOp::Load { space, .. }) if *space == r2il::SpaceId::Custom(7))
        })
        .expect("custom-space load");
    assert!(
        prepared
            .memory_certificate_for_inst(custom_load, false)
            .is_some(),
        "the Custom-space access must exist before type filtering"
    );

    let candidates = prepared_parameter_indexed_accesses(&prepared);

    assert_eq!(
        candidates,
        vec![ScalarArrayRenderCandidate {
            slot: 0,
            op: graph.op_for_inst(load_inst).expect("indexed load"),
            is_write: false,
            field_offset: 0,
            element_stride: 1,
            access_width: 1,
            index_value: Some(index_value),
        }]
    );
}
