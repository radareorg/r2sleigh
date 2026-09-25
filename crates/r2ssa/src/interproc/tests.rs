use super::*;
use crate::SsaArtifact;
use r2il::{MemoryOrdering, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

fn x86_64_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rip", 16, 8));
    arch.add_register(RegisterDef::new("rsp", 24, 8));
    arch
}

fn windows_x64_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rcx", 8, 8));
    arch.add_register(RegisterDef::new("rdx", 16, 8));
    arch.add_register(RegisterDef::new("r8", 24, 8));
    arch.add_register(RegisterDef::new("r9", 32, 8));
    arch.add_register(RegisterDef::new("rip", 40, 8));
    arch.add_register(RegisterDef::new("rsp", 48, 8));
    arch
}

fn x86_64_sysv_arg_arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rsi", 16, 8));
    arch.add_register(RegisterDef::new("rdx", 24, 8));
    arch.add_register(RegisterDef::new("rcx", 32, 8));
    arch.add_register(RegisterDef::new("r8", 40, 8));
    arch.add_register(RegisterDef::new("r9", 48, 8));
    arch
}

fn empty_local_summary(direct_callees: BTreeSet<u64>) -> LocalSummaryFacts {
    LocalSummaryFacts {
        arg_count_hint: None,
        direct_callees,
        callsite_count: 0,
        has_unknown_calls: false,
        arg_effects: BTreeMap::new(),
        memory_effects: BTreeSet::new(),
        transfer_effects: BTreeSet::new(),
        allocation_effects: BTreeSet::new(),
        lifetime_effects: BTreeSet::new(),
        sync_effects: BTreeSet::new(),
        atomic_effects: BTreeSet::new(),
        return_observations: Vec::new(),
        call_observations: BTreeMap::new(),
        call_carriers_converged: true,
        dereferenced_args: BTreeSet::new(),
        unplaced_reach: 0,
    }
}

#[test]
fn summary_sccs_handle_deep_chains_and_cycles_deterministically() {
    const FUNCTION_COUNT: u64 = 8_192;

    let mut locals = BTreeMap::new();
    for node in 0..FUNCTION_COUNT {
        let direct_callees = (node + 1 < FUNCTION_COUNT)
            .then_some(node + 1)
            .into_iter()
            .collect();
        locals.insert(
            InterprocFunctionId(node),
            (None, empty_local_summary(direct_callees)),
        );
    }

    let chain_sccs = compute_summary_sccs(&locals);
    let chain_order = chain_sccs
        .iter()
        .map(|component| {
            assert_eq!(component.len(), 1);
            component[0].0
        })
        .collect::<Vec<_>>();
    assert_eq!(chain_order, (0..FUNCTION_COUNT).rev().collect::<Vec<_>>());

    locals
        .get_mut(&InterprocFunctionId(FUNCTION_COUNT - 1))
        .expect("last function")
        .1
        .direct_callees
        .insert(0);
    let cycle_sccs = compute_summary_sccs(&locals);
    assert_eq!(cycle_sccs.len(), 1);
    assert_eq!(
        cycle_sccs[0],
        (0..FUNCTION_COUNT)
            .map(InterprocFunctionId)
            .collect::<Vec<_>>()
    );
}

#[test]
fn sleigh_aarch64_arch_name_uses_arm64_abi_profile() {
    let mut arch = ArchSpec::new("AARCH64:LE:64:v8A");
    arch.addr_size = 8;
    let profile = AbiProfile::from_arch(Some(&arch));

    assert_eq!(profile.argument_index("x0"), Some(0));
    assert_eq!(profile.argument_index("w1"), Some(1));
}

#[test]
fn sleigh_x86_64_arch_name_uses_amd64_abi_profile_without_addr_size() {
    let arch = ArchSpec::new("x86:LE:64:default");
    let profile = AbiProfile::from_arch(Some(&arch));

    assert_eq!(profile.argument_index("rdi"), Some(0));
    assert!(profile.is_return_register("rax"));
}

#[test]
fn x86_64_arch_name_uses_amd64_abi_profile_without_addr_size() {
    let arch = ArchSpec::new("x86-64");
    let profile = AbiProfile::from_arch(Some(&arch));

    assert_eq!(profile.argument_index("rdi"), Some(0));
    assert_eq!(profile.argument_index("rsi"), Some(1));
    assert!(profile.is_return_register("rax"));
}

#[test]
fn exact_return_boundary_ignores_misleading_carrier_names() {
    let mut arch = x86_64_arch();
    for register in &mut arch.registers {
        let renamed = match register.offset {
            0 => Some("rdi"),
            8 => Some("rax"),
            16 => Some("not_the_ip"),
            24 => Some("not_the_sp"),
            _ => None,
        };
        if let Some(renamed) = renamed {
            register.name = renamed.to_string();
        }
    }
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = crate::SourceFunctionInterface::new_exact(
        b"misleading-return-names".to_vec(),
        "sysv64",
        [],
        crate::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
    .expect("exact function interface");
    let prepared = SsaArtifact::for_decompile_with_interface(
        &[block(
            0x4100,
            vec![
                R2ILOp::Copy {
                    dst: reg(0, 8),
                    src: c(7, 8),
                },
                R2ILOp::Return { target: reg(16, 8) },
            ],
        )],
        Some(&arch),
        interface,
    )
    .expect("exact return artifact");
    let abi =
        AbiProfile::from_machine_context(prepared.machine_context()).expect("source-owned ABI");

    let local = collect_local_summary_facts(&prepared, &abi);

    assert_eq!(
        local.return_observations,
        vec![SummaryValueObservation::Const(7)]
    );
}

fn reg(offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Register,
        offset,
        size,
        meta: None,
    }
}

fn tmp(name: u64, size: u32) -> Varnode {
    Varnode::unique(name, size)
}

fn c(value: u64, size: u32) -> Varnode {
    Varnode::constant(value, size)
}

fn ram(offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId::Ram,
        offset,
        size,
        meta: None,
    }
}

/// A test block whose transfers are lifted from instruction
/// `addr + op_index`, so a call site identity can name them.
fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
    let mut block = R2ILBlock {
        addr,
        size: 4,
        ops,
        switch_info: None,
        op_metadata: Default::default(),
    };
    for op_index in 0..block.ops.len() {
        if matches!(
            block.ops[op_index],
            R2ILOp::Call { .. } | R2ILOp::CallInd { .. } | R2ILOp::Branch { .. }
        ) {
            block.stamp_instruction(op_index, addr + op_index as u64);
        }
    }
    block
}

fn register_storage(offset: u64) -> crate::CanonicalStorageId {
    crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    }
}

/// Build an untyped fixture whose ABI and call carriers still come from
/// exact source-owned storage identities. Interproc tests must not recover
/// those facts from register or calling-convention names.
fn exact_untyped_artifact(
    blocks: &[R2ILBlock],
    arch: &ArchSpec,
    revision: &[u8],
    calling_convention: &str,
    parameter_offsets: &[u64],
    return_address_offset: u64,
    stack_pointer_offset: u64,
) -> SsaArtifact {
    let parameters = parameter_offsets
        .iter()
        .copied()
        .enumerate()
        .map(|(index, offset)| {
            crate::SourceAbiParameterSpec::new(index as u32, register_storage(offset))
        })
        .collect::<Vec<_>>();
    let function_interface = crate::SourceFunctionInterface::new_exact(
        revision.to_vec(),
        calling_convention,
        parameters,
        crate::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| {
        interface.with_return_address_storage(register_storage(return_address_offset))
    })
    .and_then(|interface| {
        interface.with_stack_pointer_storage(register_storage(stack_pointer_offset))
    })
    .expect("exact untyped function interface");
    let call_arguments = || {
        parameter_offsets
            .iter()
            .copied()
            .enumerate()
            .map(|(index, offset)| {
                crate::SourceCallArgumentSpec::new(index as u32, register_storage(offset))
            })
            .collect::<Vec<_>>()
    };
    let call_site_interfaces = blocks
        .iter()
        .flat_map(|block| {
            block
                .ops
                .iter()
                .enumerate()
                .filter_map(move |(op_index, op)| match op {
                    R2ILOp::Call { target } | R2ILOp::CallInd { target } => Some(
                        crate::SourceCallSiteInterface::new(
                            revision.to_vec(),
                            crate::SourceCallSiteIdentity::new(
                                block
                                    .op_metadata(op_index)
                                    .and_then(|metadata| metadata.instruction_addr)
                                    .expect("test transfers are lifted from an instruction"),
                                crate::CanonicalStorageId::from_varnode(target),
                            ),
                            true,
                            calling_convention,
                            call_arguments(),
                            false,
                            false,
                            crate::SourceCallResult::Void,
                        )
                        .expect("exact untyped callsite interface"),
                    ),
                    _ => None,
                })
        })
        .collect();

    crate::testing::prepared(
        blocks,
        arch,
        Some(function_interface),
        call_site_interfaces,
        [
            register_storage(return_address_offset),
            register_storage(stack_pointer_offset),
        ],
    )
    .expect("exact untyped SSA artifact")
}

fn prepared_owner(addr: u64, arch: &ArchSpec) -> Arc<SsaArtifact> {
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = crate::SourceFunctionInterface::new_exact(
        b"prepared-interproc-owner".to_vec(),
        "sysv64",
        [crate::SourceAbiParameterSpec::new(0, storage(8))],
        crate::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
    .expect("exact prepared interproc interface");
    Arc::new(
        SsaArtifact::for_decompile_with_interface(
            &[block(
                addr,
                vec![R2ILOp::Return {
                    target: Varnode::constant(0, 8),
                }],
            )],
            Some(arch),
            interface,
        )
        .expect("prepared root"),
    )
}

#[test]
fn prepared_summary_set_retains_exact_root_owner() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let weak = Arc::downgrade(&root);
    let independent = prepared_owner(0x4000, &arch);
    let prepared = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("root".to_string()),
            prepared: &root,
        }],
    )
    .expect("source-owned summary");

    assert!(prepared.matches_root(&root));
    assert!(!prepared.matches_root(&independent));
    assert!(Arc::ptr_eq(prepared.root(), &root));
    assert_eq!(prepared.owners().len(), 1);
    assert!(
        prepared
            .owner(InterprocFunctionId(0x4000))
            .is_some_and(|owner| Arc::ptr_eq(owner, &root))
    );
    assert_eq!(prepared.report().root, Some(InterprocFunctionId(0x4000)));
    drop(root);
    assert!(
        weak.upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, prepared.root()))
    );
    drop(prepared);
    assert!(weak.upgrade().is_none());
}

#[test]
fn prepared_summary_set_invalidates_incomplete_source_boundary() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4100, &arch);
    assert!(root.obligations().obligations().values().any(|obligation| {
        obligation.id.kind == crate::SemanticObligationKind::VolatileOrUnknownEffect
    }));

    let prepared = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4100),
            name: None,
            prepared: &root,
        }],
    )
    .expect("source-owned summary remains conservatively representable");
    let summary = prepared
        .report()
        .summaries
        .get(&InterprocFunctionId(0x4100))
        .expect("root summary");

    assert!(summary.has_unknown_calls);
    assert!(summary.touches_unknown_memory);
    assert_eq!(summary.return_relation, SummaryReturnRelation::Unknown);
    for kind in [
        SummaryMemoryEffectKind::Read,
        SummaryMemoryEffectKind::Write,
        SummaryMemoryEffectKind::Escape,
    ] {
        assert!(summary.memory_effects.contains(&SummaryMemoryEffect {
            kind,
            location: unknown_location(),
        }));
    }
}

#[test]
fn interproc_report_schema_round_trips_and_validates_nested_stamps() {
    let id = InterprocFunctionId(0x4100);
    let report = InterprocSummarySet {
        schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
        root: Some(id),
        summaries: BTreeMap::from([(id, FunctionSemanticSummary::unknown(id, None))]),
        diagnostics: InterprocSummaryDiagnostics::default(),
    };
    assert!(report.has_current_schema());

    let encoded = serde_json::to_value(&report).expect("serialize interproc report");
    assert_eq!(
        encoded
            .get("schema_version")
            .and_then(|value| value.as_u64()),
        Some(u64::from(INTERPROC_SUMMARY_SCHEMA_VERSION))
    );
    let nested = encoded
        .get("summaries")
        .and_then(|value| value.as_object())
        .and_then(|summaries| summaries.values().next())
        .expect("serialized function summary");
    assert_eq!(
        nested
            .get("schema_version")
            .and_then(|value| value.as_u64()),
        Some(u64::from(INTERPROC_SUMMARY_SCHEMA_VERSION))
    );
    let decoded: InterprocSummarySet =
        serde_json::from_value(encoded.clone()).expect("deserialize current report");
    assert_eq!(decoded, report);
    assert!(decoded.has_current_schema());

    for required_field in [
        "linkage",
        "arg_count_hint",
        "memory_effects",
        "transfer_effects",
        "allocation_effects",
        "lifetime_effects",
        "sync_effects",
        "atomic_effects",
    ] {
        let mut missing_field = encoded.clone();
        missing_field
            .get_mut("summaries")
            .and_then(|value| value.as_object_mut())
            .and_then(|summaries| summaries.values_mut().next())
            .and_then(|summary| summary.as_object_mut())
            .expect("serialized function summary object")
            .remove(required_field)
            .unwrap_or_else(|| panic!("serialized summary must contain {required_field}"));
        assert!(
            serde_json::from_value::<InterprocSummarySet>(missing_field).is_err(),
            "current schema must require {required_field}"
        );
    }

    let mut stale_report = encoded.clone();
    stale_report["schema_version"] = serde_json::json!(1);
    let stale_report: InterprocSummarySet =
        serde_json::from_value(stale_report).expect("deserialize explicit old report schema");
    assert!(!stale_report.has_current_schema());

    let mut stale_summary = encoded.clone();
    *stale_summary
        .get_mut("summaries")
        .and_then(|value| value.as_object_mut())
        .and_then(|summaries| summaries.values_mut().next())
        .and_then(|summary| summary.get_mut("schema_version"))
        .expect("nested schema stamp") = serde_json::json!(1);
    let stale_summary: InterprocSummarySet =
        serde_json::from_value(stale_summary).expect("deserialize explicit old nested schema");
    assert!(!stale_summary.has_current_schema());

    let mut unversioned = encoded;
    unversioned
        .as_object_mut()
        .expect("serialized report object")
        .remove("schema_version");
    assert!(serde_json::from_value::<InterprocSummarySet>(unversioned).is_err());
}

#[test]
fn report_only_solver_rejects_stale_or_mislabeled_seeds() {
    let id = InterprocFunctionId(0x4200);
    let mut stale = FunctionSemanticSummary::unknown(id, None);
    stale.schema_version = 1;
    assert_eq!(
        solve_interproc_summary_set(&[], None, None, &BTreeMap::from([(id, stale)]),),
        Err(InterprocSummarySchemaError::FunctionSchemaVersion { id, found: 1 })
    );

    let foreign_id = InterprocFunctionId(0x4300);
    let mislabeled = FunctionSemanticSummary::unknown(foreign_id, None);
    assert_eq!(
        solve_interproc_summary_set(&[], None, None, &BTreeMap::from([(id, mislabeled)]),),
        Err(InterprocSummarySchemaError::FunctionIdentityMismatch {
            key: id,
            summary_id: foreign_id,
        })
    );
}

#[test]
fn prepared_summary_set_ignores_detached_name_advice() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let solve = |name| {
        solve_prepared_interproc_summary_set(
            Arc::clone(&root),
            &[PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name,
                prepared: &root,
            }],
        )
        .expect("source-owned summary")
    };

    let first = solve(Some("sym.imp.malloc".to_string()));
    let second = solve(Some("renamed_advisory".to_string()));

    assert_eq!(first.report(), second.report());
    assert_eq!(
        first
            .report()
            .summaries
            .get(&InterprocFunctionId(0x4000))
            .expect("root summary")
            .name,
        None
    );
}

#[test]
fn prepared_summary_set_models_missing_direct_callee_as_unknown() {
    let arch = x86_64_arch();
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let revision = b"prepared-interproc-missing-direct-callee";
    let function_interface = crate::SourceFunctionInterface::new_exact(
        revision.to_vec(),
        "sysv64",
        [crate::SourceAbiParameterSpec::new(0, storage(8))],
        crate::SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
    .expect("exact function interface");
    let target = c(0x5000, 8);
    let call_interface = crate::SourceCallSiteInterface::new(
        revision.to_vec(),
        crate::SourceCallSiteIdentity::new(
            0x4000,
            crate::CanonicalStorageId::from_varnode(&target),
        ),
        true,
        "sysv64",
        [crate::SourceCallArgumentSpec::new(0, storage(8))],
        false,
        false,
        crate::SourceCallResult::Register {
            storage: storage(0),
        },
    )
    .expect("exact external callsite interface");
    let root = Arc::new(
        crate::testing::prepared(
            &[block(
                0x4000,
                vec![
                    R2ILOp::Call { target },
                    R2ILOp::Return { target: reg(0, 8) },
                ],
            )],
            &arch,
            Some(function_interface),
            vec![call_interface],
            [storage(16), storage(24)],
        )
        .expect("prepared external-call root"),
    );

    let prepared = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: None,
            prepared: &root,
        }],
    )
    .expect("source-owned summary");
    let summary = prepared
        .report()
        .summaries
        .get(&InterprocFunctionId(0x4000))
        .expect("root summary");

    assert_eq!(summary.direct_callees, BTreeSet::from([0x5000]));
    assert!(summary.has_unknown_calls);
    assert!(summary.touches_unknown_memory);
    assert_eq!(summary.return_relation, SummaryReturnRelation::Unknown);
    assert_eq!(
        summary.arg_effects.get(&0),
        Some(&SummaryArgEffect {
            read: true,
            write: true,
            escape: true,
            free: false,
        })
    );
    for kind in [
        SummaryMemoryEffectKind::Read,
        SummaryMemoryEffectKind::Write,
    ] {
        assert!(summary.memory_effects.contains(&SummaryMemoryEffect {
            kind,
            location: unknown_location(),
        }));
    }
    for kind in [
        SummaryMemoryEffectKind::Read,
        SummaryMemoryEffectKind::Write,
        SummaryMemoryEffectKind::Escape,
    ] {
        assert!(summary.memory_effects.contains(&SummaryMemoryEffect {
            kind,
            location: arg_location(0, None, None),
        }));
    }
}

#[test]
fn prepared_summary_set_refuses_foreign_independently_rebuilt_root() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let foreign = prepared_owner(0x4000, &arch);
    let error = solve_prepared_interproc_summary_set(
        root,
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("foreign".to_string()),
            prepared: &foreign,
        }],
    )
    .expect_err("foreign root must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::ForeignRoot);
}

#[test]
fn prepared_summary_set_refuses_missing_root() {
    let arch = x86_64_arch();
    let error = solve_prepared_interproc_summary_set(prepared_owner(0x4000, &arch), &[])
        .expect_err("missing root must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::MissingRoot);
}

#[test]
fn prepared_summary_set_refuses_duplicate_root() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root-a".to_string()),
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root-b".to_string()),
                prepared: &root,
            },
        ],
    )
    .expect_err("duplicate root must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::DuplicateRoot);
}

#[test]
fn prepared_summary_set_refuses_mislabeled_root() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x5000),
            name: Some("wrong-id".to_string()),
            prepared: &root,
        }],
    )
    .expect_err("mislabeled root must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::MislabeledRoot);
}

#[test]
fn prepared_summary_set_refuses_mislabeled_helper() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let helper = prepared_owner(0x5000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root".to_string()),
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x6000),
                name: Some("wrong-helper-id".to_string()),
                prepared: &helper,
            },
        ],
    )
    .expect_err("mislabeled helper must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::MislabeledFunction);
}

#[test]
fn prepared_summary_set_refuses_duplicate_helper_id() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let helper_a = prepared_owner(0x5000, &arch);
    let helper_b = prepared_owner(0x5000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root".to_string()),
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x5000),
                name: Some("helper-a".to_string()),
                prepared: &helper_a,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x5000),
                name: Some("helper-b".to_string()),
                prepared: &helper_b,
            },
        ],
    )
    .expect_err("duplicate helper id must refuse");

    assert_eq!(error, PreparedInterprocSummaryError::DuplicateFunction);
}

#[test]
fn prepared_summary_set_refuses_manual_helper_owner() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let helper = prepared_owner(0x5000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root".to_string()),
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x5000),
                name: Some("manual-helper".to_string()),
                prepared: &helper,
            },
        ],
    )
    .expect_err("manual helper must not become prepared evidence");

    assert_eq!(error, PreparedInterprocSummaryError::ManualFunction);
}

#[test]
fn prepared_summary_set_refuses_overlapping_function_ranges() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let helper = prepared_owner(0x4002, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: None,
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4002),
                name: None,
                prepared: &helper,
            },
        ],
    )
    .expect_err("cross-function block overlap must refuse authoritative evidence");

    assert_eq!(
        error,
        PreparedInterprocSummaryError::OverlappingFunctionBlockRanges
    );
}

#[test]
fn prepared_summary_set_refuses_function_range_overflow() {
    let error =
        validate_interproc_block_ranges([(InterprocFunctionId(u64::MAX - 1), u64::MAX - 1, 4)])
            .expect_err("overflowing block range must fail preflight");

    assert_eq!(
        error,
        PreparedInterprocSummaryError::FunctionBlockRangeOverflow
    );
}

#[test]
fn prepared_summary_set_requires_trusted_root_for_helper_scope() {
    assert_eq!(
        require_trusted_root_for_helper_scope(crate::SsaArtifactProvenanceKind::Manual, 2,),
        Err(PreparedInterprocSummaryError::ManualRootWithHelpers)
    );
    assert_eq!(
        require_trusted_root_for_helper_scope(crate::SsaArtifactProvenanceKind::TrustedSource, 2,),
        Ok(())
    );
}

#[test]
fn prepared_summary_set_does_not_promote_report_only_seeds() {
    let arch = x86_64_arch();
    let root = prepared_owner(0x4000, &arch);
    let root_input = InterprocFunctionInput {
        id: InterprocFunctionId(0x4000),
        name: Some("root".to_string()),
        prepared: root.as_ref(),
    };
    let seed_id = InterprocFunctionId(0x7000);
    let seed = FunctionSemanticSummary::unknown(seed_id, Some("external-seed".to_string()));
    let raw = solve_interproc_summary_set(
        std::slice::from_ref(&root_input),
        Some(&arch),
        Some(InterprocFunctionId(0x4000)),
        &BTreeMap::from([(seed_id, seed)]),
    )
    .expect("current report-only seed schema");
    let prepared = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("root".to_string()),
            prepared: &root,
        }],
    )
    .expect("seedless prepared summary");

    assert!(raw.summaries.contains_key(&seed_id));
    assert!(!prepared.report().summaries.contains_key(&seed_id));
}

#[test]
fn prepared_summary_set_refuses_unknown_source_architecture() {
    let mut arch = x86_64_arch();
    arch.name = "unknown-64-bit-family".to_string();
    let root = prepared_owner(0x4000, &arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("root".to_string()),
            prepared: &root,
        }],
    )
    .expect_err("unknown family must refuse authoritative summary");

    assert_eq!(
        error,
        PreparedInterprocSummaryError::UnknownOrIncoherentMachineContext
    );
}

#[test]
fn prepared_summary_set_refuses_cross_family_helper() {
    let root_arch = x86_64_arch();
    let mut helper_arch = x86_64_arch();
    helper_arch.name = "aarch64".to_string();
    let root = prepared_owner(0x4000, &root_arch);
    let helper = prepared_owner(0x5000, &helper_arch);
    let error = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x4000),
                name: Some("root".to_string()),
                prepared: &root,
            },
            PreparedInterprocFunctionInput {
                id: InterprocFunctionId(0x5000),
                name: Some("helper".to_string()),
                prepared: &helper,
            },
        ],
    )
    .expect_err("cross-family helper must refuse authoritative summary");

    assert_eq!(error, PreparedInterprocSummaryError::ArchitectureMismatch);
}

#[test]
fn prepared_summary_set_refuses_nonconverged_report() {
    let report = InterprocSummarySet {
        diagnostics: InterprocSummaryDiagnostics {
            converged: false,
            ..InterprocSummaryDiagnostics::default()
        },
        ..InterprocSummarySet::default()
    };

    assert_eq!(
        require_converged_summary_report(&report),
        Err(PreparedInterprocSummaryError::NonConverged),
        "partial fixed points must not be sealed"
    );
}

#[test]
fn prepared_summary_uses_exact_abi_carrier_not_callconv_label() {
    let mut arch = x86_64_arch();
    arch.add_register(RegisterDef::new("rcx", 32, 8));
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = crate::SourceFunctionInterface::new_exact(
        b"prepared-interproc-exact-abi".to_vec(),
        "misleading-sysv-label",
        [crate::SourceAbiParameterSpec::new(0, storage(32))],
        crate::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(16)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
    .expect("exact prepared ABI interface");
    let root = Arc::new(
        SsaArtifact::for_decompile_with_interface(
            &[block(
                0x4000,
                vec![
                    R2ILOp::IntAdd {
                        dst: tmp(0x10, 8),
                        a: reg(32, 8),
                        b: Varnode::constant(4, 8),
                    },
                    R2ILOp::Store {
                        space: SpaceId::Ram,
                        addr: tmp(0x10, 8),
                        val: Varnode::constant(0, 1),
                    },
                    R2ILOp::Return {
                        target: Varnode::constant(0, 8),
                    },
                ],
            )],
            Some(&arch),
            interface,
        )
        .expect("prepared exact ABI root"),
    );
    let prepared = solve_prepared_interproc_summary_set(
        Arc::clone(&root),
        &[PreparedInterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("root".to_string()),
            prepared: &root,
        }],
    )
    .expect("source-owned summary");
    let summary = prepared
        .report()
        .summaries
        .get(&InterprocFunctionId(0x4000))
        .expect("root summary");

    assert!(summary.memory_effects.iter().any(|effect| {
        effect.kind == SummaryMemoryEffectKind::Write
            && effect.location.region == (SummaryMemoryRegion::Arg { index: 0 })
            && effect.location.range.is_some_and(|range| {
                range.offset_lo == 4 && range.offset_hi == 4 && range.width == Some(1)
            })
    }));
    assert!(
        !summary
            .memory_effects
            .iter()
            .any(|effect| { effect.location.region == (SummaryMemoryRegion::Arg { index: 3 }) })
    );
}

#[test]
fn seed_summary_models_the_fortified_snprintf_by_its_length_argument() {
    let seed =
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(9), "sym.imp.__snprintf_chk")
            .expect("snprintf_chk seed");
    assert_eq!(seed.transfer_effects.len(), 1);
    assert_eq!(
        seed.transfer_effects[0].len,
        SummaryTransferLength::Arg(1),
        "the fortified layout bounds the write by maxlen"
    );
    assert_eq!(
        seed.transfer_effects[0].dst.region,
        SummaryMemoryRegion::Arg { index: 0 }
    );
    let plain = FunctionSemanticSummary::seed_for_name(InterprocFunctionId(10), "sym.imp.snprintf")
        .expect("snprintf seed");
    assert_eq!(plain.transfer_effects[0].len, SummaryTransferLength::Arg(1));
}

#[test]
fn seed_summary_models_malloc_and_memcpy() {
    let malloc = FunctionSemanticSummary::seed_for_name(InterprocFunctionId(1), "sym.imp.malloc")
        .expect("malloc seed");
    assert_eq!(malloc.return_relation, SummaryReturnRelation::HeapAlloc);
    assert_eq!(
        malloc.allocation_effects,
        vec![SummaryAllocationEffect {
            size_arg: Some(0),
            zeroed: false,
        }]
    );
    let memcpy = FunctionSemanticSummary::seed_for_name(InterprocFunctionId(2), "sym.imp.memcpy")
        .expect("memcpy seed");
    assert_eq!(memcpy.return_relation, SummaryReturnRelation::Arg(0));
    assert!(memcpy.arg_effects.get(&0).expect("dst").write);
    assert!(memcpy.arg_effects.get(&1).expect("src").read);
    assert_eq!(
        memcpy.transfer_effects,
        vec![SummaryTransferEffect {
            dst: arg_location(0, None, None),
            src: arg_location(1, None, None),
            len: SummaryTransferLength::Arg(2),
        }]
    );
}

#[test]
fn seed_summary_requires_external_marker() {
    for name in [
        "malloc",
        "memcpy",
        "sym.malloc",
        "dbg.memcpy",
        "sym._copyin",
    ] {
        assert!(
            FunctionSemanticSummary::seed_for_name(InterprocFunctionId(0xdead), name).is_none(),
            "test seed must not accept local/name-only semantic owner for {name}"
        );
    }
}

#[test]
fn seed_summary_models_kernel_helpers_as_canonical_effects() {
    let copyin = FunctionSemanticSummary::seed_for_name(InterprocFunctionId(3), "sym.imp.copyin")
        .expect("copyin seed");
    assert_eq!(
        copyin.transfer_effects,
        vec![SummaryTransferEffect {
            dst: arg_location(1, None, None),
            src: arg_location(0, None, None),
            len: SummaryTransferLength::Arg(2),
        }]
    );
    assert!(copyin.arg_effects.get(&0).expect("src").read);
    assert!(copyin.arg_effects.get(&1).expect("dst").write);

    let retain =
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(4), "sym.imp.os_ref_retain")
            .expect("retain seed");
    assert_eq!(retain.return_relation, SummaryReturnRelation::Arg(0));
    assert_eq!(
        retain.lifetime_effects,
        vec![SummaryLifetimeEffect {
            arg: 0,
            op: SummaryLifetimeOp::Retain,
        }]
    );

    let lock =
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(5), "sym.imp.lck_mtx_lock")
            .expect("lock seed");
    assert_eq!(
        lock.sync_effects,
        vec![SummarySyncEffect {
            arg: 0,
            op: SummarySyncOp::Lock,
        }]
    );
}

#[test]
fn report_only_summary_does_not_promote_unbound_call_returns() {
    let arch = x86_64_arch();
    let alloc_block = block(
        0x1000,
        vec![
            R2ILOp::Call {
                target: c(0x2000, 8),
            },
            R2ILOp::Return { target: reg(0, 8) },
        ],
    );
    let wrapper_block = block(
        0x3000,
        vec![
            R2ILOp::Call {
                target: c(0x1000, 8),
            },
            R2ILOp::Return { target: reg(0, 8) },
        ],
    );

    let alloc = crate::testing::prepared(
        &[alloc_block],
        &arch,
        None,
        Vec::new(),
        [register_storage(16), register_storage(24)],
    )
    .expect("alloc ssa")
    .with_name("alloc_wrapper");
    let wrapper = crate::testing::prepared(
        &[wrapper_block],
        &arch,
        None,
        Vec::new(),
        [register_storage(16), register_storage(24)],
    )
    .expect("wrapper ssa")
    .with_name("wrapper");

    let mut seeds = BTreeMap::new();
    seeds.insert(
        InterprocFunctionId(0x2000),
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(0x2000), "sym.imp.malloc")
            .expect("malloc"),
    );

    let set = solve_interproc_summary_set(
        &[
            InterprocFunctionInput {
                id: InterprocFunctionId(0x1000),
                name: Some("alloc_wrapper".to_string()),
                prepared: &alloc,
            },
            InterprocFunctionInput {
                id: InterprocFunctionId(0x3000),
                name: Some("wrapper".to_string()),
                prepared: &wrapper,
            },
        ],
        Some(&arch),
        Some(InterprocFunctionId(0x3000)),
        &seeds,
    )
    .expect("current report-only seed schema");

    assert_eq!(
        set.summaries
            .get(&InterprocFunctionId(0x1000))
            .expect("alloc summary")
            .return_relation,
        SummaryReturnRelation::Unknown
    );
    assert_eq!(
        set.summaries
            .get(&InterprocFunctionId(0x3000))
            .expect("wrapper summary")
            .return_relation,
        SummaryReturnRelation::Unknown
    );
}

#[test]
fn report_only_ip_return_requires_exact_call_result_carrier() {
    let arch = x86_64_arch();
    let alloc_block = block(
        0x1000,
        vec![
            R2ILOp::Call {
                target: c(0x2000, 8),
            },
            R2ILOp::Return { target: reg(16, 8) },
        ],
    );

    let alloc = crate::testing::prepared(
        &[alloc_block],
        &arch,
        None,
        Vec::new(),
        [register_storage(16), register_storage(24)],
    )
    .expect("alloc ssa")
    .with_name("alloc_wrapper");

    let mut seeds = BTreeMap::new();
    seeds.insert(
        InterprocFunctionId(0x2000),
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(0x2000), "sym.imp.malloc")
            .expect("malloc"),
    );

    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x1000),
            name: Some("alloc_wrapper".to_string()),
            prepared: &alloc,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x1000)),
        &seeds,
    )
    .expect("current report-only seed schema");

    assert_eq!(
        set.summaries
            .get(&InterprocFunctionId(0x1000))
            .expect("alloc summary")
            .return_relation,
        SummaryReturnRelation::Unknown
    );
}

#[test]
fn opaque_single_call_wrapper_does_not_promote_unbound_return() {
    let mut arch = ArchSpec::new("x86:LE:64:default");
    arch.addr_size = 8;
    let wrapper_block = block(
        0x401000,
        vec![
            R2ILOp::Call {
                target: c(0x2000, 8),
            },
            R2ILOp::Return { target: reg(0, 8) },
        ],
    );
    let wrapper = SsaArtifact::for_symbolic(&[wrapper_block], Some(&arch)).expect("wrapper ssa");
    let mut seeds = BTreeMap::new();
    seeds.insert(
        InterprocFunctionId(0x2000),
        FunctionSemanticSummary::seed_for_name(InterprocFunctionId(0x2000), "sym.imp.malloc")
            .expect("malloc"),
    );

    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x401000),
            name: Some("sym.alloc_wrapper".to_string()),
            prepared: &wrapper,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x401000)),
        &seeds,
    )
    .expect("current report-only seed schema");

    assert_eq!(
        set.summaries
            .get(&InterprocFunctionId(0x401000))
            .expect("wrapper summary")
            .return_relation,
        SummaryReturnRelation::Unknown
    );
}

#[test]
fn branchind_trampoline_without_return_stays_unknown() {
    let arch = x86_64_arch();
    let trampoline = SsaArtifact::for_decompile(
        &[block(
            0x3500,
            vec![R2ILOp::BranchInd {
                target: ram(0x406050, 8),
            }],
        )],
        Some(&arch),
    )
    .expect("trampoline ssa")
    .with_name("sym.imp.setlocale");

    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x3500),
            name: Some("sym.imp.setlocale".to_string()),
            prepared: &trampoline,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x3500)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");

    assert_eq!(
        set.summaries
            .get(&InterprocFunctionId(0x3500))
            .expect("trampoline summary")
            .return_relation,
        SummaryReturnRelation::Unknown
    );
}

#[test]
fn direct_pointer_load_marks_argument_read() {
    let arch = x86_64_arch();
    let blk = block(
        0x4000,
        vec![
            R2ILOp::Load {
                dst: tmp(1, 4),
                space: SpaceId::Ram,
                addr: reg(8, 8),
            },
            R2ILOp::Return { target: c(0, 4) },
        ],
    );
    let prepared = exact_untyped_artifact(
        &[blk],
        &arch,
        b"direct-pointer-load",
        "sysv64",
        &[8],
        16,
        24,
    );
    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x4000),
            name: Some("read_arg".to_string()),
            prepared: &prepared,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x4000)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");
    assert!(
        set.summaries
            .get(&InterprocFunctionId(0x4000))
            .and_then(|summary| summary.arg_effects.get(&0))
            .is_some_and(|effect| effect.read)
    );
}

#[test]
fn overwritten_abi_register_is_not_a_formal_argument_read() {
    let arch = x86_64_sysv_arg_arch();
    let blk = block(
        0x4050,
        vec![
            R2ILOp::Copy {
                dst: reg(24, 8),
                src: c(0x5000, 8),
            },
            R2ILOp::Load {
                dst: tmp(1, 1),
                space: SpaceId::Ram,
                addr: reg(24, 8),
            },
            R2ILOp::Return { target: c(0, 4) },
        ],
    );
    let prepared = SsaArtifact::for_decompile(&[blk], Some(&arch)).expect("ssa");
    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x4050),
            name: Some("scratch_load".to_string()),
            prepared: &prepared,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x4050)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");
    let summary = set
        .summaries
        .get(&InterprocFunctionId(0x4050))
        .expect("summary");

    assert!(
        !summary.arg_effects.contains_key(&2),
        "rdx was overwritten before the load, so it is not caller arg2: {summary:?}"
    );
    assert_eq!(summary.arg_count_hint, Some(0));
    assert!(summary.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Global { address: 0x5000 },
                    ..
                }
            }
        )
    }));
}

#[test]
fn unused_entry_abi_register_source_does_not_inflate_arg_count_hint() {
    let arch = x86_64_sysv_arg_arch();
    let blk = block(
        0x4060,
        vec![
            R2ILOp::IntAdd {
                dst: tmp(1, 8),
                a: reg(24, 8),
                b: c(1, 8),
            },
            R2ILOp::Return { target: c(0, 4) },
        ],
    );
    let prepared = SsaArtifact::for_decompile(&[blk], Some(&arch)).expect("ssa");
    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x4060),
            name: Some("scratch_arg_reg".to_string()),
            prepared: &prepared,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x4060)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");
    let summary = set
        .summaries
        .get(&InterprocFunctionId(0x4060))
        .expect("summary");

    assert_eq!(
        summary.arg_count_hint,
        Some(0),
        "arg count must be derived from summary effects, not raw SSA register reads"
    );
    assert!(summary.arg_effects.is_empty());
}

#[test]
fn store_conditional_marks_argument_read_and_write() {
    let arch = x86_64_arch();
    let blk = block(
        0x4100,
        vec![
            R2ILOp::StoreConditional {
                result: Some(tmp(1, 1)),
                space: SpaceId::Ram,
                addr: reg(8, 8),
                val: c(0x41, 1),
                ordering: MemoryOrdering::SeqCst,
            },
            R2ILOp::Return { target: reg(16, 8) },
        ],
    );
    let prepared =
        exact_untyped_artifact(&[blk], &arch, b"store-conditional", "sysv64", &[8], 16, 24);
    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x4100),
            name: Some("store_conditional".to_string()),
            prepared: &prepared,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x4100)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");
    let summary = set
        .summaries
        .get(&InterprocFunctionId(0x4100))
        .expect("summary");
    let arg0 = summary.arg_effects.get(&0).expect("arg effect");
    assert!(arg0.read);
    assert!(arg0.write);
    assert_eq!(
        summary.atomic_effects,
        vec![SummaryAtomicEffect {
            op: SummaryAtomicOp::StoreConditional,
            location: arg_location(0, Some(0), Some(1)),
            ordering: SummaryAtomicOrdering::SeqCst,
        }]
    );
    assert!(summary.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Arg { index: 0 },
                    ..
                }
            }
        )
    }));
    assert!(summary.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Arg { index: 0 },
                    ..
                }
            }
        )
    }));
}

#[test]
fn atomic_cas_marks_argument_read_and_write() {
    let arch = x86_64_arch();
    let blk = block(
        0x4200,
        vec![
            R2ILOp::AtomicCAS {
                dst: reg(0, 8),
                space: SpaceId::Ram,
                addr: reg(8, 8),
                expected: c(1, 8),
                replacement: c(2, 8),
                ordering: MemoryOrdering::SeqCst,
            },
            R2ILOp::Return { target: reg(16, 8) },
        ],
    );
    let prepared = exact_untyped_artifact(&[blk], &arch, b"atomic-cas", "sysv64", &[8], 16, 24);
    let set = solve_interproc_summary_set(
        &[InterprocFunctionInput {
            id: InterprocFunctionId(0x4200),
            name: Some("atomic_cas".to_string()),
            prepared: &prepared,
        }],
        Some(&arch),
        Some(InterprocFunctionId(0x4200)),
        &BTreeMap::new(),
    )
    .expect("current report-only seed schema");
    let summary = set
        .summaries
        .get(&InterprocFunctionId(0x4200))
        .expect("summary");
    let arg0 = summary.arg_effects.get(&0).expect("arg effect");
    assert!(arg0.read);
    assert!(arg0.write);
    assert_eq!(
        summary.atomic_effects,
        vec![SummaryAtomicEffect {
            op: SummaryAtomicOp::CompareExchange,
            location: arg_location(0, Some(0), Some(8)),
            ordering: SummaryAtomicOrdering::SeqCst,
        }]
    );
    assert!(summary.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Arg { index: 0 },
                    ..
                }
            }
        )
    }));
    assert!(summary.memory_effects.iter().any(|effect| {
        matches!(
            effect,
            SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Arg { index: 0 },
                    ..
                }
            }
        )
    }));
}

#[test]
fn symbolic_store_plus_constant_preserves_arg_offset_range() {
    let arch = x86_64_arch();
    let blocks = [block(
        0x4300,
        vec![
            R2ILOp::IntAdd {
                dst: reg(0x80, 8),
                a: reg(8, 8),
                b: c(2, 8),
            },
            R2ILOp::Store {
                addr: reg(0x80, 8),
                val: reg(16, 2),
                space: SpaceId::Ram,
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"symbolic-store-plus",
        "sysv64",
        &[8],
        16,
        24,
    );
    let abi = prepared.abi().expect("exact ABI");
    let block = prepared.function().get_block(0x4300).expect("block");
    let Some(SSAOp::Store { addr, val, .. }) = block
        .ops
        .iter()
        .find(|op| matches!(op, SSAOp::Store { .. }))
    else {
        panic!("expected store");
    };
    let addr_id = prepared
        .graph()
        .value_id_for_var(addr)
        .expect("store addr value id");
    let def_inst = prepared.graph().def_inst(addr_id).expect("store addr def");
    let inst = prepared.graph().inst(def_inst).expect("store addr inst");
    let [left_id, right_id] = match inst.inputs.as_slice() {
        [left, right] => [*left, *right],
        _ => panic!("expected additive store addr inputs"),
    };
    assert_eq!(summary_const_value(&prepared, right_id), Some(2));
    assert_eq!(
        classify_memory_access_location_value(&prepared, &abi, left_id, SpaceId::Ram, val.size),
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(0, val.size),
        }
    );
    assert_eq!(
        classify_memory_access_location_value(&prepared, &abi, addr_id, SpaceId::Ram, val.size),
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(2, val.size),
        }
    );
    let location = classify_memory_access_location(&prepared, &abi, addr, SpaceId::Ram, val.size);
    assert_eq!(
        location,
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(2, val.size),
        },
        "store address should resolve to arg0+2, got {location:?}; addr={addr:?}; ops={:?}",
        block.ops
    );
}

#[test]
fn symbolic_store_minus_constant_preserves_arg_offset_range() {
    let arch = x86_64_arch();
    let blocks = [block(
        0x4310,
        vec![
            R2ILOp::IntSub {
                dst: reg(0x80, 8),
                a: reg(8, 8),
                b: c(1, 8),
            },
            R2ILOp::Store {
                addr: reg(0x80, 8),
                val: reg(16, 1),
                space: SpaceId::Ram,
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"symbolic-store-minus",
        "sysv64",
        &[8],
        16,
        24,
    );
    let abi = prepared.abi().expect("exact ABI");
    let block = prepared.function().get_block(0x4310).expect("block");
    let Some(SSAOp::Store { addr, val, .. }) = block
        .ops
        .iter()
        .find(|op| matches!(op, SSAOp::Store { .. }))
    else {
        panic!("expected store");
    };
    let addr_id = prepared
        .graph()
        .value_id_for_var(addr)
        .expect("store addr value id");
    let def_inst = prepared.graph().def_inst(addr_id).expect("store addr def");
    let inst = prepared.graph().inst(def_inst).expect("store addr inst");
    let [left_id, right_id] = match inst.inputs.as_slice() {
        [left, right] => [*left, *right],
        _ => panic!("expected additive store addr inputs"),
    };
    assert_eq!(summary_const_value(&prepared, right_id), Some(1));
    assert_eq!(
        classify_memory_access_location_value(&prepared, &abi, left_id, SpaceId::Ram, val.size),
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(0, val.size),
        }
    );
    assert_eq!(
        classify_memory_access_location_value(&prepared, &abi, addr_id, SpaceId::Ram, val.size),
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(-1, val.size),
        }
    );
    let location = classify_memory_access_location(&prepared, &abi, addr, SpaceId::Ram, val.size);
    assert_eq!(
        location,
        SummaryMemoryLocation {
            region: SummaryMemoryRegion::Arg { index: 0 },
            range: exact_range(-1, val.size),
        },
        "store address should resolve to arg0-1, got {location:?}; addr={addr:?}; ops={:?}",
        block.ops
    );
}

#[test]
fn windows_x64_call_arg_observer_tracks_registration_handler_constant() {
    let arch = windows_x64_arch();
    let blocks = [block(
        0x5000,
        vec![
            R2ILOp::Copy {
                dst: reg(8, 8),
                src: c(1, 8),
            },
            R2ILOp::Copy {
                dst: reg(16, 8),
                src: c(0x1400_3d0f, 8),
            },
            R2ILOp::Call {
                target: c(0x1800_1000, 8),
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"windows-handler-call",
        "windows-x64",
        &[8, 16, 24, 32],
        40,
        48,
    );

    let observations =
        observe_call_arguments(&prepared, &prepared.abi().expect("exact Windows ABI"));
    let call_id = prepared
        .call_sites()
        .by_id
        .keys()
        .next()
        .copied()
        .expect("callsite");
    let args = observations.get(&call_id).expect("call args");
    assert_eq!(args.first(), Some(&CallArgObservation::Const(1)));
    assert_eq!(args.get(1), Some(&CallArgObservation::Const(0x1400_3d0f)));
}

#[test]
fn call_arg_observer_does_not_reuse_pre_call_carriers_after_call() {
    let arch = windows_x64_arch();
    let blocks = [block(
        0x6000,
        vec![
            R2ILOp::Copy {
                dst: reg(8, 8),
                src: c(7, 8),
            },
            R2ILOp::Call {
                target: c(0x7000, 8),
            },
            R2ILOp::Call {
                target: c(0x8000, 8),
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"windows-two-call-carriers",
        "windows-x64",
        &[8, 16, 24, 32],
        40,
        48,
    );

    let observations =
        observe_call_arguments(&prepared, &prepared.abi().expect("exact Windows ABI"));
    let mut calls = prepared
        .call_sites()
        .by_id
        .iter()
        .map(|(id, call)| (call.at, *id))
        .collect::<Vec<_>>();
    calls.sort_by_key(|(at, _)| *at);
    let first = observations.get(&calls[0].1).expect("first call args");
    let second = observations.get(&calls[1].1).expect("second call args");

    assert_eq!(first.first(), Some(&CallArgObservation::Const(7)));
    assert_eq!(second.first(), Some(&CallArgObservation::Unknown));
}

#[test]
fn volatile_or_unknown_effects_clobber_call_carriers_and_observable_state() {
    let arch = windows_x64_arch();
    let cases = [
        (
            "callother",
            R2ILOp::CallOther {
                output: None,
                userop: 7,
                inputs: Vec::new(),
            },
        ),
        ("unimplemented", R2ILOp::Unimplemented),
        ("cpuid", R2ILOp::CpuId { dst: tmp(0x90, 8) }),
        (
            "new",
            R2ILOp::New {
                dst: tmp(0x98, 8),
                src: c(8, 8),
            },
        ),
    ];

    for (label, unknown_op) in cases {
        let prepared = SsaArtifact::for_symbolic(
            &[block(
                0x6800,
                vec![
                    R2ILOp::Copy {
                        dst: reg(8, 8),
                        src: c(7, 8),
                    },
                    unknown_op,
                    R2ILOp::Call {
                        target: c(0x7000, 8),
                    },
                    R2ILOp::Return { target: c(0, 8) },
                ],
            )],
            Some(&arch),
        )
        .unwrap_or_else(|| panic!("{label} SSA"));
        let abi = AbiProfile::windows_x64();
        let observations = observe_call_arguments(&prepared, &abi);
        let call_id = prepared
            .call_sites()
            .by_id
            .keys()
            .next()
            .copied()
            .unwrap_or_else(|| panic!("{label} callsite"));
        let args = observations
            .get(&call_id)
            .unwrap_or_else(|| panic!("{label} args"));
        let local = collect_local_summary_facts(&prepared, &abi);

        assert_eq!(
            args.first(),
            Some(&CallArgObservation::Unknown),
            "{label} must not preserve the pre-effect carrier"
        );
        assert!(local.has_unknown_calls, "{label} must remain observable");
        for kind in [
            SummaryMemoryEffectKind::Read,
            SummaryMemoryEffectKind::Write,
        ] {
            assert!(
                local.memory_effects.contains(&SummaryMemoryEffect {
                    kind,
                    location: unknown_location(),
                }),
                "{label} must carry unknown {kind:?} memory"
            );
        }
    }
}

#[test]
fn volatile_or_unknown_effects_invalidate_pre_effect_return_relations() {
    let arch = windows_x64_arch();
    for (label, return_seed) in [("constant", c(1, 8)), ("entry argument", reg(8, 8))] {
        let prepared = SsaArtifact::for_symbolic(
            &[block(
                0x6900,
                vec![
                    R2ILOp::Copy {
                        dst: reg(0, 8),
                        src: return_seed,
                    },
                    R2ILOp::CallOther {
                        output: None,
                        userop: 9,
                        inputs: Vec::new(),
                    },
                    R2ILOp::Return { target: reg(0, 8) },
                ],
            )],
            Some(&arch),
        )
        .unwrap_or_else(|| panic!("{label} return SSA"));
        let local = collect_local_summary_facts(&prepared, &AbiProfile::windows_x64());
        let summary = initial_summary(InterprocFunctionId(0x6900), None, &local);

        assert_eq!(
            local.return_observations,
            vec![SummaryValueObservation::Unknown],
            "{label} continuity must be erased"
        );
        assert_eq!(summary.return_relation, SummaryReturnRelation::Unknown);
    }
}

#[test]
fn callother_maps_explicit_argument_and_unknown_escape() {
    let arch = x86_64_arch();
    let blocks = [block(
        0x69a0,
        vec![
            R2ILOp::CallOther {
                output: None,
                userop: 11,
                inputs: vec![reg(8, 8)],
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"callother-explicit-argument",
        "sysv64",
        &[8],
        16,
        24,
    );
    let local = collect_local_summary_facts(&prepared, &prepared.abi().expect("exact SysV ABI"));

    assert_eq!(
        local.arg_effects.get(&0),
        Some(&SummaryArgEffect {
            read: true,
            write: true,
            escape: true,
            free: false,
        })
    );
    assert!(local.memory_effects.contains(&SummaryMemoryEffect {
        kind: SummaryMemoryEffectKind::Escape,
        location: unknown_location(),
    }));
}

#[test]
fn resolved_summary_propagates_transitive_unknown_calls() {
    let mut local = empty_local_summary(BTreeSet::from([0x7100]));
    local.call_observations.insert(
        CallSiteId(0),
        CallObservation {
            target: 0x7100,
            args: Vec::new(),
            result_storage: None,
        },
    );
    let mut callee = FunctionSemanticSummary::unknown(InterprocFunctionId(0x7100), None);
    callee.has_unknown_calls = true;
    let summary = resolve_summary(
        InterprocFunctionId(0x7000),
        None,
        &local,
        &BTreeMap::from([(callee.id, callee)]),
    );

    assert!(summary.has_unknown_calls);
}

#[test]
fn call_return_relation_requires_complete_nonvoid_result_carrier() {
    let arch = x86_64_arch();
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let revision = b"interproc-exact-call-result";
    let target = c(0x7100, 8);
    let function_interface = || {
        crate::SourceFunctionInterface::new_exact(
            revision.to_vec(),
            "sysv64",
            [],
            crate::SourceFunctionReturn::Register {
                storage: storage(0),
            },
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(storage(16)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
        .expect("exact function interface")
    };
    for (label, complete, result, expected) in [
        (
            "exact",
            true,
            crate::SourceCallResult::Register {
                storage: storage(0),
            },
            SummaryReturnRelation::Const(7),
        ),
        (
            "void",
            true,
            crate::SourceCallResult::Void,
            SummaryReturnRelation::Unknown,
        ),
        (
            "incomplete",
            false,
            crate::SourceCallResult::Register {
                storage: storage(0),
            },
            SummaryReturnRelation::Unknown,
        ),
        (
            "foreign-carrier",
            true,
            crate::SourceCallResult::Register {
                storage: storage(8),
            },
            SummaryReturnRelation::Unknown,
        ),
    ] {
        let call_interface = crate::SourceCallSiteInterface::new(
            revision.to_vec(),
            crate::SourceCallSiteIdentity::new(
                0x7000,
                crate::CanonicalStorageId::from_varnode(&target),
            ),
            complete,
            "sysv64",
            [],
            false,
            false,
            result,
        )
        .expect("callsite interface");
        let prepared = crate::testing::prepared(
            &[block(
                0x7000,
                vec![
                    R2ILOp::Call {
                        target: target.clone(),
                    },
                    R2ILOp::Return { target: reg(16, 8) },
                ],
            )],
            &arch,
            Some(function_interface()),
            vec![call_interface],
            [storage(16), storage(24)],
        )
        .unwrap_or_else(|| panic!("{label} prepared SSA"));
        let abi = AbiProfile::from_machine_context(prepared.machine_context())
            .unwrap_or_else(|| panic!("{label} ABI"));
        let local = collect_local_summary_facts(&prepared, &abi);
        let mut callee = FunctionSemanticSummary::unknown(InterprocFunctionId(0x7100), None);
        callee.return_relation = SummaryReturnRelation::Const(7);
        let summary = resolve_summary(
            InterprocFunctionId(0x7000),
            None,
            &local,
            &BTreeMap::from([(callee.id, callee)]),
        );

        assert_eq!(
            summary.return_relation, expected,
            "{label} call-result authority must control the return relation"
        );
    }
}

#[test]
fn call_carrier_nonconvergence_degrades_all_observations() {
    let arch = x86_64_arch();
    let prepared = SsaArtifact::for_symbolic(
        &[
            block(
                0x1000,
                vec![R2ILOp::Branch {
                    target: c(0x1010, 8),
                }],
            ),
            block(
                0x1010,
                vec![
                    R2ILOp::Call {
                        target: c(0x8000, 8),
                    },
                    R2ILOp::Return { target: c(0, 8) },
                ],
            ),
        ],
        Some(&arch),
    )
    .expect("advisory SSA");
    let state = collect_call_arg_state_with_iteration_limit(
        &prepared,
        &AbiProfile::from_arch(Some(&arch)),
        1,
    );

    assert!(!state.converged);
    assert!(
        state
            .by_call
            .values()
            .flatten()
            .all(|arg| *arg == SummaryOperand::Unknown)
    );

    let mut local = empty_local_summary(BTreeSet::new());
    local.call_carriers_converged = state.converged;
    assert_eq!(
        require_converged_call_carriers(&local),
        Err(PreparedInterprocSummaryError::NonConverged),
        "authoritative sealing must refuse the degraded state"
    );
}

#[test]
fn call_arg_observer_preserves_ambiguous_join_as_unknown() {
    let arch = windows_x64_arch();
    let prepared = SsaArtifact::for_symbolic(
        &[
            block(
                0x6000,
                vec![R2ILOp::CBranch {
                    target: c(0x6008, 8),
                    cond: c(1, 1),
                }],
            ),
            block(
                0x6004,
                vec![
                    R2ILOp::Copy {
                        dst: reg(8, 8),
                        src: c(1, 8),
                    },
                    R2ILOp::Branch {
                        target: c(0x600c, 8),
                    },
                ],
            ),
            block(
                0x6008,
                vec![
                    R2ILOp::Copy {
                        dst: reg(8, 8),
                        src: c(2, 8),
                    },
                    R2ILOp::Branch {
                        target: c(0x600c, 8),
                    },
                ],
            ),
            block(
                0x600c,
                vec![
                    R2ILOp::Call {
                        target: c(0x7000, 8),
                    },
                    R2ILOp::Return { target: c(0, 8) },
                ],
            ),
        ],
        Some(&arch),
    )
    .expect("ssa");

    let observations = observe_call_arguments(&prepared, &AbiProfile::windows_x64());
    let call_id = prepared
        .call_sites()
        .by_id
        .keys()
        .next()
        .copied()
        .expect("callsite");
    let args = observations.get(&call_id).expect("call args");

    assert_eq!(args.first(), Some(&CallArgObservation::Unknown));
}

#[test]
fn source_owned_call_observer_requires_exact_complete_call_carriers() {
    let mut arch = x86_64_arch();
    arch.add_register(RegisterDef::new("rcx", 32, 8));
    let storage = |offset| crate::CanonicalStorageId {
        space: crate::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let revision = b"interproc-exact-call-carriers";
    let function_interface = || {
        crate::SourceFunctionInterface::new_exact(
            revision.to_vec(),
            "sysv64",
            [crate::SourceAbiParameterSpec::new(0, storage(8))],
            crate::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(storage(16)))
        .and_then(|interface| interface.with_stack_pointer_storage(storage(24)))
        .expect("exact function interface")
    };
    let target = c(0x7000, 8);
    let blocks = [block(
        0x6000,
        vec![
            R2ILOp::Copy {
                dst: reg(32, 8),
                src: c(9, 8),
            },
            R2ILOp::Call {
                target: target.clone(),
            },
            R2ILOp::Return { target: c(0, 8) },
        ],
    )];
    let call_interface = |complete| {
        crate::SourceCallSiteInterface::new(
            revision.to_vec(),
            crate::SourceCallSiteIdentity::new(
                0x6001,
                crate::CanonicalStorageId::from_varnode(&target),
            ),
            complete,
            "win64",
            [crate::SourceCallArgumentSpec::new(0, storage(32))],
            false,
            false,
            crate::SourceCallResult::Void,
        )
        .expect("callsite interface")
    };
    let complete = crate::testing::prepared(
        &blocks,
        &arch,
        Some(function_interface()),
        vec![call_interface(true)],
        [register_storage(16), register_storage(24)],
    )
    .expect("complete call carrier artifact");
    let incomplete = crate::testing::prepared(
        &blocks,
        &arch,
        Some(function_interface()),
        vec![call_interface(false)],
        [register_storage(16), register_storage(24)],
    )
    .expect("incomplete call carrier artifact");
    let complete_abi =
        AbiProfile::from_machine_context(complete.machine_context()).expect("source-owned ABI");
    let incomplete_abi =
        AbiProfile::from_machine_context(incomplete.machine_context()).expect("source-owned ABI");
    let complete_args = observe_call_arguments(&complete, &complete_abi)
        .into_values()
        .next()
        .expect("complete call args");
    let incomplete_args = observe_call_arguments(&incomplete, &incomplete_abi)
        .into_values()
        .next()
        .expect("incomplete call args");

    assert_eq!(complete_args.first(), Some(&CallArgObservation::Const(9)));
    assert_eq!(incomplete_args.first(), Some(&CallArgObservation::Unknown));
}

/// x86-64 with two argument registers: rdi at 8 and rsi at 32.
fn two_argument_arch() -> ArchSpec {
    let mut arch = x86_64_arch();
    arch.add_register(RegisterDef::new("rsi", 32, 8));
    arch
}

/// What a callee's summary says it reaches through each argument.
fn touch_reach(prepared: &SsaArtifact) -> BTreeMap<usize, SummaryArgumentReach> {
    let abi = prepared.abi().expect("exact ABI");
    PreparedCalleeSummary {
        id: InterprocFunctionId(prepared.function().entry),
        architecture_family: prepared.machine_context().architecture_family(),
        blocks: Vec::new(),
        local: collect_source_owned_summary_facts(prepared, &abi),
        callee_names: BTreeMap::new(),
    }
    .argument_touch_reach()
}

/// `avg` at -O2 starts its walk at `v` or at `v + 8`, depending on the
/// parity of `n`: the read through the merged pointer has no place a summary
/// can state, but its address is computed from `v`. Reading the stated
/// `*v` alone as the whole reach made the caller's array two objects.
#[test]
fn an_access_at_no_stated_place_leaves_the_formal_its_address_depends_on_unbounded() {
    let arch = two_argument_arch();
    let blocks = [
        block(
            0x4400,
            vec![
                R2ILOp::Load {
                    dst: tmp(1, 8),
                    space: SpaceId::Ram,
                    addr: reg(8, 8),
                },
                R2ILOp::Copy {
                    dst: reg(0, 8),
                    src: reg(8, 8),
                },
                R2ILOp::CBranch {
                    target: c(0x4408, 8),
                    cond: reg(32, 1),
                },
            ],
        ),
        block(
            0x4404,
            vec![R2ILOp::IntAdd {
                dst: reg(0, 8),
                a: reg(8, 8),
                b: c(8, 8),
            }],
        ),
        block(
            0x4408,
            vec![
                R2ILOp::Load {
                    dst: tmp(2, 8),
                    space: SpaceId::Ram,
                    addr: reg(0, 8),
                },
                R2ILOp::Return { target: reg(16, 8) },
            ],
        ),
    ];
    let prepared =
        exact_untyped_artifact(&blocks, &arch, b"merged-walk", "sysv64", &[8, 32], 16, 24);
    let reach = touch_reach(&prepared);
    assert!(
        !reach.contains_key(&0),
        "a read through v or v + 8 reaches past v's first word: {reach:?}"
    );
}

/// `table[i]` with `table` a constant address: the index is scaled, which no
/// pointer is, so the read is inside the global and touches no argument's
/// object.
#[test]
fn a_constant_address_read_at_a_scaled_index_is_the_global() {
    let arch = two_argument_arch();
    let blocks = [block(
        0x4600,
        vec![
            R2ILOp::IntMult {
                dst: tmp(1, 8),
                a: reg(8, 8),
                b: c(4, 8),
            },
            R2ILOp::IntAdd {
                dst: tmp(2, 8),
                a: c(0x2020, 8),
                b: tmp(1, 8),
            },
            R2ILOp::Load {
                dst: tmp(3, 4),
                space: SpaceId::Ram,
                addr: tmp(2, 8),
            },
            R2ILOp::Load {
                dst: tmp(4, 4),
                space: SpaceId::Ram,
                addr: reg(32, 8),
            },
            R2ILOp::Return { target: reg(16, 8) },
        ],
    )];
    let prepared = exact_untyped_artifact(
        &blocks,
        &arch,
        b"constant-table",
        "sysv64",
        &[8, 32],
        16,
        24,
    );
    let abi = prepared.abi().expect("exact ABI");
    let local = collect_source_owned_summary_facts(&prepared, &abi);
    let regions = local
        .memory_effects
        .iter()
        .map(|effect| effect.location.region)
        .collect::<Vec<_>>();
    assert!(
        regions.contains(&SummaryMemoryRegion::Global { address: 0x2020 }),
        "{regions:?}"
    );
    assert!(
        !regions.contains(&SummaryMemoryRegion::Unknown),
        "{regions:?}"
    );
    assert_eq!(
        touch_reach(&prepared).get(&1),
        Some(&SummaryArgumentReach::Bytes(4))
    );
}
