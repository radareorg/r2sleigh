//! What the analysis proves about the frame and its slots.

use super::super::*;
use super::*;

/// A slot's widths and signedness are what the graph's RAM accesses through it show.
#[test]
fn stack_accesses_read_the_graph_s_ram_accesses() {
    let mut arch = r2il::ArchSpec::new("x86-64");
    arch.add_register(r2il::RegisterDef::new("rdi", 0, 8));
    arch.add_register(r2il::RegisterDef::new("rsp", 8, 8));
    arch.add_register(r2il::RegisterDef::new("rip", 16, 8));
    let register = |offset| r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = r2ssa::SourceFunctionInterface::new_exact(
        b"stack-accesses".to_vec(),
        "sysv64",
        [],
        r2ssa::SourceFunctionReturn::Void,
        [r2ssa::SourceStackSlotSpec::new_local(
            r2ssa::StackAddressBase::StackPointer,
            register(8),
            -15,
            1,
        )],
    )
    .and_then(|interface| interface.with_stack_pointer_storage(register(8)))
    .and_then(|interface| interface.with_return_address_storage(register(16)))
    .expect("exact source interface");
    let mut block = r2il::R2ILBlock::new(0x1000, 4);
    block.push(r2il::R2ILOp::IntAdd {
        dst: r2il::Varnode::unique(0x100, 8),
        a: r2il::Varnode::register(8, 8),
        b: r2il::Varnode::constant((-15i64) as u64, 8),
    });
    block.push(r2il::R2ILOp::Load {
        dst: r2il::Varnode::unique(0x200, 1),
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::unique(0x100, 8),
    });
    block.push(r2il::R2ILOp::IntZExt {
        dst: r2il::Varnode::unique(0x300, 4),
        src: r2il::Varnode::unique(0x200, 1),
    });
    block.push(r2il::R2ILOp::Store {
        space: r2il::SpaceId::Ram,
        addr: r2il::Varnode::constant(0x5000, 8),
        val: r2il::Varnode::unique(0x300, 4),
    });
    block.push(r2il::R2ILOp::Return {
        target: r2il::Varnode::register(16, 8),
    });
    let source = SsaArtifact::for_decompile_with_interface(
        &[block],
        Some(&r2ssa::Arch::from(arch)),
        interface,
    )
    .expect("prepared source");

    let signedness = crate::signedness::scalar_signedness_of(&source, false, std::iter::empty());
    let stack = StackAccesses::of(&source, &signedness);
    let slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -15,
    };
    assert_eq!(stack.widths, BTreeMap::from([(slot, BTreeSet::from([1]))]));
    assert_eq!(
        stack.signedness,
        BTreeMap::from([(slot, BTreeSet::from([ScalarSignednessEvidence::Unsigned]))])
    );
}

#[test]
fn canonical_stack_access_width_overrides_generic_host_integer_width() {
    let slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -16,
    };
    let stack = StackAccesses {
        widths: BTreeMap::from([(slot, BTreeSet::from([4]))]),
        signedness: BTreeMap::new(),
    };
    let vars = [RecoveredVariable {
        name: "var_10h".to_string(),
        kind: "s".to_string(),
        delta: -16,
        var_type: "int32_t".to_string(),
        isarg: false,
        reg: None,
    }];

    let analysis = build_type_analysis_with_stack_accesses(
        TypeAnalysisInput {
            function_name: "sym._sum_array",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym._sum_array".to_string(),
                signature: "void sym._sum_array ()".to_string(),
                ret_type: "void".to_string(),
                params: Vec::new(),
                callconv: String::new(),
                arch: "aarch64".to_string(),
            },
            recovered_vars: &vars,
            parsed_context: ParsedExternalContext::default(),
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &stack,
    );

    let int32 = Some(CTypeLike::Int {
        bits: 32,
        signedness: Signedness::Signed,
    });
    assert!(analysis.type_facts.visible_bindings.iter().any(|binding| {
        binding.name == "var_10h"
            && binding.ty == int32
            && binding.stack_slot.as_ref()
                == Some(&StackSlotKey {
                    base: ExternalStackBase::StackPointer,
                    offset: -16,
                })
    }));
}

#[test]
fn canonical_stack_zero_extension_recovers_unsigned_local() {
    let slot = StackSlotKey {
        base: ExternalStackBase::StackPointer,
        offset: -15,
    };
    let stack = StackAccesses {
        widths: BTreeMap::from([(slot, BTreeSet::from([1]))]),
        signedness: BTreeMap::from([(slot, BTreeSet::from([ScalarSignednessEvidence::Unsigned]))]),
    };
    let vars = [RecoveredVariable {
        name: "var_fh".to_string(),
        kind: "s".to_string(),
        delta: -15,
        var_type: "int8_t".to_string(),
        isarg: false,
        reg: None,
    }];

    let analysis = build_type_analysis_with_stack_accesses(
        TypeAnalysisInput {
            function_name: "sym._fnv_fold",
            ptr_bits: 64,
            inferred_signature: InferredSignature {
                function_name: "sym._fnv_fold".to_string(),
                signature: "void sym._fnv_fold ()".to_string(),
                ret_type: "void".to_string(),
                params: Vec::new(),
                callconv: String::new(),
                arch: "aarch64".to_string(),
            },
            recovered_vars: &vars,
            parsed_context: ParsedExternalContext::default(),
            local_structs: LocalStructArtifacts::default(),
            interproc_summary_set: None,
            diagnostics: TypeAnalysisDiagnostics::default(),
        },
        &stack,
    );

    // A byte loaded only to be zero-extended is unsigned, whatever radare2 named its type.
    let uint8 = Some(CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Unsigned,
    });
    let binding = (analysis.type_facts.visible_bindings.iter())
        .find(|binding| binding.name == "var_fh")
        .expect("var_fh is bound");
    assert_eq!(binding.ty, uint8, "{binding:?}");
}

#[test]
fn interproc_summary_name_does_not_prune_generated_surplus_slots() {
    let analysis = build_type_analysis(TypeAnalysisInput {
        function_name: "dbg.or",
        ptr_bits: 64,
        inferred_signature: InferredSignature {
            function_name: "dbg.or".to_string(),
            signature: "bool dbg.or(void *arg1, struct sla_struct_deadbeef *arg2)".to_string(),
            ret_type: "bool".to_string(),
            params: vec![
                InferredSignatureParam {
                    name: "arg1".to_string(),
                    param_type: "void *".to_string(),
                },
                InferredSignatureParam {
                    name: "arg2".to_string(),
                    param_type: "struct sla_struct_deadbeef *".to_string(),
                },
            ],
            callconv: "amd64".to_string(),
            arch: "x86-64".to_string(),
        },
        recovered_vars: &[],
        parsed_context: ParsedExternalContext::default(),
        local_structs: LocalStructArtifacts {
            slot_type_overrides: HashMap::from([(
                5usize,
                "struct sla_struct_0e18b2bc34030602 *".to_string(),
            )]),
            ..Default::default()
        },
        interproc_summary_set: Some(semantic_role_summary_set("dbg.or", Some(2))),
        diagnostics: TypeAnalysisDiagnostics::default(),
    });

    assert_eq!(spelled_signature(&analysis).ret_type, "bool");
    assert_eq!(spelled_signature(&analysis).params.len(), 2);
}
