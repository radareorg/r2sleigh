use std::sync::Arc;

use r2il::{
    AddressSpace, ArchSpec, R2ILBlock, R2ILOp, RegisterBitSlice, RegisterDef, RegisterProjection,
    RegisterProjectionDisposition, RegisterStorage, SpaceId, Varnode,
};
use r2ssa::{
    CanonicalStorageId, CanonicalStorageSpace, SourceAbiParameterSpec, SourceFunctionInterface,
    SourceFunctionReturn, SsaArtifact,
};

use super::*;
use crate::ast::{CLocal, CType};
use crate::binding_plan::{BindingId, BindingNameResolution, ValueDisposition, ValueRefusal};
use crate::structured_region::{
    StructuredRegionKind, StructuredRegionMarker, seal_structured_body,
};
use crate::symbol::{ExternalKind, SymbolRole};

/// radare2 spells the same struct parameter with and without the keyword,
/// and C has separate namespaces for tags and typedef names, so the bare
/// one named nothing. The rendering's own other spellings say which it is.
#[test]
fn a_bare_name_this_rendering_spells_as_a_tag_is_that_tag() {
    let tags = std::collections::BTreeMap::from([
        ("parsedb_state".to_string(), false),
        ("anon".to_string(), true),
    ]);

    let mut bare = CType::ptr(CType::typedef("parsedb_state"));
    resolve_tag_spelling(&mut bare, &tags);
    assert_eq!(bare, CType::ptr(CType::Struct("parsedb_state".to_string())));

    let mut union_name = CType::ptr(CType::typedef("anon"));
    resolve_tag_spelling(&mut union_name, &tags);
    assert_eq!(union_name, CType::ptr(CType::Union("anon".to_string())));

    // A name no spelling here calls a tag is left alone, so a real typedef
    // is never turned into a struct.
    let mut typedef = CType::ptr(CType::typedef("size_t"));
    resolve_tag_spelling(&mut typedef, &tags);
    assert_eq!(typedef, CType::ptr(CType::typedef("size_t")));

    // A name that already carries what it stands for is already answered.
    let named = CType::named(
        "parsedb_state",
        CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        },
    );
    let mut carried = named.clone();
    resolve_tag_spelling(&mut carried, &tags);
    assert_eq!(carried, named);
}

/// Storage C has no scalar for gets a tag this decompiler invents, and
/// nothing outside the rendering can define it.
#[test]
fn a_synthesised_tag_is_defined_by_the_rendering() {
    let mut tags = std::collections::BTreeMap::new();
    collect_tag_spellings(&CType::ptr(CType::Struct("s".to_string())), &mut tags);
    assert_eq!(tags.get("s"), Some(&false));
    collect_tag_spellings(
        &CType::named("u", CType::Union("u_tag".to_string())),
        &mut tags,
    );
    assert_eq!(tags.get("u_tag"), Some(&true));
}

#[test]
fn exact_zero_occurrence_answer_precedes_refusal_per_use() {
    let elided = UseSite {
        inst: InstId(7),
        input_idx: 0,
    };
    let still_refused = UseSite {
        inst: InstId(7),
        input_idx: 1,
    };
    let mut refused = vec![elided, still_refused];
    let elisions = BTreeMap::from([(elided, crate::ledger::ElisionReason::StackFrame)]);

    retain_only_unanswered_refusals(&mut refused, &elisions);

    assert_eq!(refused, vec![still_refused]);
}

fn source_owned() -> SourceOwnedFunctionFacts {
    let mut block = R2ILBlock::new(0x1000, 4);
    // These tests are about what the journal records for a bound value, so
    // the fixture has to contain one, and that has taken three corrections.
    // A value with a single reader is folded into that reader, so the
    // first sum is read twice. A value that reads nothing but literals is
    // spelled at every reader however many there are, so the chain starts
    // from a register rather than from a constant. And a copy is forwarded
    // to its readers and is then read by nothing, so the bound value has
    // to be computed rather than copied.
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x20, 8),
        a: Varnode::register(0, 8),
        b: Varnode::constant(2, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x30, 8),
        a: Varnode::unique(0x20, 8),
        b: Varnode::register(0, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::unique(0x40, 8),
        a: Varnode::unique(0x30, 8),
        b: Varnode::unique(0x20, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::unique(0x40, 8),
    });
    source_owned_from_blocks(&[block])
}

fn source_owned_from_blocks(blocks: &[R2ILBlock]) -> SourceOwnedFunctionFacts {
    source_owned_from_blocks_with_parameter(blocks, false)
}

fn source_owned_from_blocks_with_preserved_calls(blocks: &[R2ILBlock]) -> SourceOwnedFunctionFacts {
    source_owned_from_blocks_with_interface(blocks, false, true)
}

fn source_owned_from_blocks_with_parameter(
    blocks: &[R2ILBlock],
    with_parameter: bool,
) -> SourceOwnedFunctionFacts {
    source_owned_from_blocks_with_interface(blocks, with_parameter, false)
}

fn source_owned_from_blocks_with_interface(
    blocks: &[R2ILBlock],
    with_parameter: bool,
    preserved_calls: bool,
) -> SourceOwnedFunctionFacts {
    let mut arch = ArchSpec::new("x86-64");
    arch.add_space(AddressSpace::ram(8));
    arch.add_register(RegisterDef::new("RAX", 0, 8));
    arch.add_register(RegisterDef::new("RSP", 0x28, 8));
    arch.add_register(RegisterDef::new("RIP", 0x30, 8));
    arch.add_register(RegisterDef::new("RDI", 0x38, 8));
    arch.add_register(RegisterDef::new("CF", 0x40, 1));
    arch.register_projections = [(0, 8), (0x28, 8), (0x30, 8), (0x38, 8), (0x40, 1)]
        .into_iter()
        .map(|(offset, size)| RegisterProjection {
            written: RegisterStorage { offset, size },
            disposition: RegisterProjectionDisposition::Bound {
                carrier: RegisterStorage { offset, size },
                slice: RegisterBitSlice {
                    lsb_bit_offset: 0,
                    size_bits: u64::from(size) * 8,
                },
            },
        })
        .collect();
    let storage = |offset| CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    };
    let interface = SourceFunctionInterface::new_exact(
        b"observation-journal-test".to_vec(),
        "sysv64",
        with_parameter.then_some(SourceAbiParameterSpec::new(0, storage(0x38))),
        SourceFunctionReturn::Register {
            storage: storage(0),
        },
        std::iter::empty(),
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x30)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x28)))
    .expect("exact test source interface");
    // A call preserves the return address, and the stack pointer where the fixture says so.
    let preserved = if preserved_calls {
        vec![storage(0x30), storage(0x28)]
    } else {
        vec![storage(0x30)]
    };
    let call_effect = r2ssa::SourceCallEffect::new([], preserved).expect("a call effect");
    let source = Arc::new(
        SsaArtifact::for_decompile_with(
            blocks,
            r2ssa::DecompileInputs {
                arch: Some(&arch),
                function_interface: Some(interface),
                call_effect: Some(call_effect),
                ..Default::default()
            },
        )
        .expect("test SSA artifact"),
    );
    let request = r2types::TypeAnalysisRequest::new(
        Arc::clone(&source),
        r2types::ParsedExternalContext::default(),
    )
    .expect("source-owned request");
    r2types::build_source_owned_type_analysis(request)
        .expect("source-owned analysis")
        .finalize_for_decompile(r2types::DecompileFinalization {
            kind: r2types::DecompileRouteKind::Standard,
            reason: "observation journal test".to_string(),
            fallback_comment: None,
        })
        .expect("source-owned finalization")
}

fn journal_fixture() -> (
    SourceOwnedFunctionFacts,
    BindingPlan,
    CFunction,
    LegacyObservationJournal,
) {
    journal_fixture_for_source(source_owned())
}

fn test_binding_names(
    source: &SourceOwnedFunctionFacts,
    plan: Rc<BindingPlan>,
    symbols: Rc<RefCell<SymbolTable>>,
) -> Rc<BindingNameResolution> {
    Rc::new(
        BindingNameResolution::build(source, plan, symbols)
            .expect("authority-bound test binding names"),
    )
}

fn journal_fixture_for_source(
    source: SourceOwnedFunctionFacts,
) -> (
    SourceOwnedFunctionFacts,
    BindingPlan,
    CFunction,
    LegacyObservationJournal,
) {
    let plan = BindingPlan::build_shadow(&source).expect("sealed binding plan");
    let function = CFunction::new("journal", CType::Void);
    let function_source = source.source().function();
    let normalized =
        r2ssa::RewrittenFunction::new(function_source, function_source.blocks().to_vec());
    let origins = NormalizationOrigins::for_unchanged(function_source, source.source());
    let names = test_binding_names(&source, Rc::new(plan.clone()), Rc::clone(&function.symbols));
    let journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        names,
        Rc::clone(&function.symbols),
    )
    .expect("authority-bound journal");
    (source, plan, function, journal)
}

#[test]
fn a_dead_restore_of_the_stack_carrier_is_stack_geometry() {
    let rsp = Varnode::register(0x28, 8);
    let ops = vec![
        R2ILOp::IntSub {
            dst: rsp.clone(),
            a: rsp.clone(),
            b: Varnode::constant(8, 8),
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: rsp,
            val: Varnode::constant(0x1005, 8),
        },
        R2ILOp::Call {
            target: Varnode::constant(0x2000, 8),
        },
    ];
    let op_metadata = (0..ops.len())
        .map(|index| {
            (
                index,
                r2il::OpMetadata {
                    instruction_addr: Some(0x1000),
                    ..Default::default()
                },
            )
        })
        .collect();
    let block = R2ILBlock {
        addr: 0x1000,
        size: 5,
        ops,
        switch_info: None,
        op_metadata,
    };
    let source = source_owned_from_blocks_with_preserved_calls(std::slice::from_ref(&block));
    let graph = source.source().graph();
    let (restore, output) = graph
        .insts
        .iter()
        .find_map(|inst| match &inst.payload {
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallRestore { .. }) => {
                Some((inst.id, inst.output?))
            }
            _ => None,
        })
        .expect("the preserved call restores its stack carrier");
    assert!(graph.use_sites(output).is_empty(), "restore output is dead");

    // The restore is the copy the convention states, so the geometry
    // certificate owns both its sides; the journal adds nothing of its own.
    let (_source, plan, _function, journal) = journal_fixture_for_source(source);
    assert!(matches!(
        plan.disposition(output),
        Some(ValueDisposition::Elided {
            reason: crate::ledger::ElisionReason::DeadStackBase,
            ..
        })
    ));
    let use_site = UseSite {
        inst: restore,
        input_idx: 0,
    };
    assert_eq!(
        journal.uses[restore.0 as usize][0],
        Some(LegacyUseObservation::Elided(
            crate::ledger::ElisionReason::DeadStackBase
        ))
    );
    assert!(!journal.coalesced_carrier_uses.contains(&use_site));

    // Without the convention's word no restore is minted at all: matching
    // storage cannot replace the absent certificate.
    let uncertified = source_owned_from_blocks(&[block]);
    assert!(uncertified.source().graph().insts.iter().all(|inst| {
        !matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallRestore { .. })
        )
    }));
}

#[test]
fn preplacement_dead_definition_closes_value_use_write_and_producer_effect() {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::IntCarry {
        dst: Varnode::register(0x40, 1),
        a: Varnode::register(0x38, 8),
        b: Varnode::constant(1, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks_with_parameter(&[block], true);
    let graph = source.source().graph();
    let dead = graph
        .values
        .iter()
        .find(|value| {
            value.canonical_storage.is_some_and(|storage| {
                storage.space == CanonicalStorageSpace::Register
                    && storage.offset == 0x40
                    && storage.size == 1
            }) && graph.def_inst(value.id).is_some()
        })
        .expect("defined CF value")
        .id;
    let definition = graph.def_inst(dead).expect("CF definition");
    let dead_literal = graph
        .values
        .iter()
        .find(|value| {
            value.var.constant_bits() == Some(1)
                && !graph.use_sites(value.id).is_empty()
                && graph
                    .use_sites(value.id)
                    .iter()
                    .all(|site| site.inst == definition)
        })
        .expect("constant read only by the dead CF definition")
        .id;
    let (source, plan, _function, journal) = journal_fixture_for_source(source);

    assert!(
        matches!(
            plan.disposition(dead),
            Some(ValueDisposition::Elided {
                reason: crate::ledger::ElisionReason::DeadUnusedTemporary,
                ..
            })
        ),
        "unexpected dead disposition: {:?}",
        plan.disposition(dead)
    );
    assert_eq!(
        journal.values[dead.0 as usize],
        Some(LegacyValueObservation::Elided(
            crate::ledger::ElisionReason::DeadUnusedTemporary
        ))
    );
    assert_eq!(
        journal.writes[definition.0 as usize],
        Some(LegacyWriteObservation::Elided(
            crate::ledger::ElisionReason::DeadUnusedTemporary
        ))
    );
    assert!(
        matches!(
            plan.disposition(dead_literal),
            Some(ValueDisposition::Inline { .. })
        ),
        "unexpected literal disposition: {:?}",
        plan.disposition(dead_literal)
    );
    assert_eq!(
        journal.values[dead_literal.0 as usize],
        Some(LegacyValueObservation::Elided(
            crate::ledger::ElisionReason::DeadUnusedTemporary
        ))
    );
    let input_count = source
        .source()
        .graph()
        .inst(definition)
        .expect("exact dead definition")
        .inputs
        .len();
    for input_idx in 0..input_count {
        assert_eq!(
            journal.uses[definition.0 as usize][input_idx],
            Some(LegacyUseObservation::Elided(
                crate::ledger::ElisionReason::DeadUnusedTemporary
            ))
        );
    }
    let producer_effects = source
        .source()
        .obligations()
        .obligations_for_inst(definition)
        .filter(|obligation| obligation.id.kind == r2ssa::SemanticObligationKind::LiveValueProducer)
        .map(|obligation| obligation.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(journal.dead_unused_value_effects, producer_effects);
    assert!(
        producer_effects
            .iter()
            .all(|effect| journal.effect_occurrences.get(effect) == Some(&0))
    );
}

#[test]
fn mixed_use_return_control_elides_only_the_exact_return_use() {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Copy {
        dst: Varnode::unique(0x80, 8),
        src: Varnode::register(0x30, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[block]);
    let graph = source.source().graph();
    let control_sites = crate::binding_plan::certified_return_control_sites(source.source());
    let control_site = *control_sites.iter().next().expect("certified return use");
    assert_eq!(control_sites.len(), 1);
    let return_control = graph
        .inst(control_site.inst)
        .and_then(|inst| inst.inputs.get(control_site.input_idx))
        .copied()
        .expect("return control value");
    assert_eq!(graph.use_sites(return_control).len(), 2);
    assert!(
        !crate::binding_plan::certified_return_control_values(source.source())
            .contains(&return_control)
    );

    let plan = BindingPlan::build_shadow(&source).expect("mixed-use binding plan");
    assert!(matches!(
        plan.disposition(return_control),
        Some(ValueDisposition::Bound { .. })
    ));
    let function_source = source.source().function();
    let normalized =
        r2ssa::RewrittenFunction::new(function_source, function_source.blocks().to_vec());
    let origins = NormalizationOrigins::for_unchanged(function_source, source.source());
    let function = CFunction::new("mixed_return_control", CType::Void);
    let names = test_binding_names(&source, Rc::new(plan), Rc::clone(&function.symbols));
    let journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        names,
        Rc::clone(&function.symbols),
    )
    .expect("mixed-use journal");

    assert_eq!(
        journal.uses[control_site.inst.0 as usize][control_site.input_idx],
        Some(LegacyUseObservation::Elided(
            crate::ledger::ElisionReason::ReturnControl
        ))
    );
    let ordinary_site = graph
        .use_sites(return_control)
        .iter()
        .copied()
        .find(|site| *site != control_site)
        .expect("ordinary non-control use");
    assert_ne!(
        journal.uses[ordinary_site.inst.0 as usize][ordinary_site.input_idx],
        Some(LegacyUseObservation::Elided(
            crate::ledger::ElisionReason::ReturnControl
        ))
    );
}

#[test]
fn certified_value_read_rejects_forged_expression_at_allocation_and_seal() {
    let mut block = R2ILBlock::new(0x1000, 4);
    // A computed value with a second reader is what keeps the returned
    // object one of its own: a literal is spelled at every reader, and a
    // value only the return reads is spelled by its expression.
    block.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 8),
        a: Varnode::register(0x40, 8),
        b: Varnode::register(0x48, 8),
    });
    block.push(R2ILOp::IntAdd {
        dst: Varnode::register(0x10, 8),
        a: Varnode::register(0, 8),
        b: Varnode::register(0, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[block]);
    let certificate = source
        .source()
        .certificates()
        .returns
        .first()
        .cloned()
        .expect("exact source return-value certificate");
    let plan = Rc::new(BindingPlan::build_shadow(&source).expect("return binding plan"));
    let mut function = CFunction::new(
        "certified_read",
        CType::Int {
            bits: 64,
            signedness: r2types::Signedness::Signed,
        },
    );
    let names = Rc::new(
        BindingNameResolution::build(&source, Rc::clone(&plan), Rc::clone(&function.symbols))
            .expect("sealed return names"),
    );
    let symbol = names
        .symbol_for_value(certificate.value)
        .expect("certified return has one planned symbol");
    let binding = match plan.disposition(certificate.value) {
        Some(ValueDisposition::Bound { binding }) => *binding,
        other => panic!("certified return must be bound, got {other:?}"),
    };
    let function_source = source.source().function();
    let normalized =
        r2ssa::RewrittenFunction::new(function_source, function_source.blocks().to_vec());
    let origins = NormalizationOrigins::for_unchanged(function_source, source.source());
    let mut journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        Rc::clone(&names),
        Rc::clone(&function.symbols),
    )
    .expect("return observation journal");

    for forged in [
        CExpr::IntLit(7),
        CExpr::External {
            name: "forged_return".to_string(),
            kind: ExternalKind::Global,
        },
    ] {
        assert_eq!(
            journal.observe_certified_value_read_expr(
                certificate.value,
                certificate.at,
                symbol,
                forged,
            ),
            Err(LegacyObservationJournalError::RenderedValueRequired {
                value: certificate.value,
                cause: RenderedValueRequirementCause::CertifiedReadExpressionMissingSymbol,
                disposition: plan.disposition(certificate.value).cloned(),
            })
        );
    }

    let marked = journal
        .observe_certified_value_read_expr(
            certificate.value,
            certificate.at,
            symbol,
            CExpr::Var(symbol),
        )
        .expect("valid exact certified read marker");
    let id = *marked
        .observation_ids()
        .first()
        .expect("journal returns an observed expression");
    let forged_after_allocation = CExpr::observe_one(id, CExpr::IntLit(7));
    let sealed = seal_structured_body(
        CStmt::structured_region(
            StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
            CStmt::structured_region(
                StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::Block),
                CStmt::Return(Some(forged_after_allocation)),
            ),
        ),
        source.source().authority(),
    )
    .expect("sealed marked return");
    let (statement, regions) = sealed.into_marked_parts();
    function.body = vec![statement];

    assert_eq!(
        crate::placement::collect_final_placement_occurrences(
            &function,
            &regions,
            source.source(),
            &names,
            journal.placement_target_count(),
            |id| journal.placement_target(id),
        ),
        Err(crate::placement::PlacementAnalysisError::UnobservedBindingRead { binding })
    );
}

#[test]
fn a_refused_placement_leaves_the_emitted_function_exactly_as_it_was() {
    // `finish_enforcing` records a placement refusal and then goes on to
    // inspect the same function, so a half-applied tree would reach the
    // emitter on the refusal path. Nothing else covers it: the corpus
    // passes `placement_audit` on all fifty-four cells, so no cell takes
    // this path, and the guarantee is only visible as a snapshot restore
    // in one error arm. This is the test that fails if that restore is
    // ever simplified away.
    let (source, plan, mut function, _journal) = journal_fixture();
    let plan = Rc::new(plan);
    let names = test_binding_names(&source, Rc::clone(&plan), Rc::clone(&function.symbols));

    // A region artifact that is well formed but describes a body this
    // function does not have, so the declarations cannot be inserted and
    // the application refuses at its last step -- after every mutation the
    // decision loop makes.
    let sealed = seal_structured_body(
        CStmt::structured_region(
            StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
            CStmt::structured_region(
                StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::Block),
                CStmt::Return(None),
            ),
        ),
        source.source().authority(),
    )
    .expect("sealed region artifact");
    let (_statement, regions) = sealed.into_marked_parts();

    // One binding that owns a declared local and is named by the body, so
    // the lexical-declaration arm removes its local -- the mutation this
    // test is looking for -- and the transitive-deadness pass leaves it
    // alone.
    let (binding, symbol) = plan
        .bindings()
        .find_map(|(binding, _)| {
            names
                .symbol_for_binding(binding)
                .map(|symbol| (binding, symbol))
        })
        .expect("a planned binding with a name");
    function.locals.push(CLocal {
        ty: CType::Int {
            bits: 64,
            signedness: r2types::Signedness::Unsigned,
        },
        name: symbol,
        stack_offset: None,
    });
    function.body = vec![CStmt::Return(Some(CExpr::Var(symbol)))];

    let mut decisions = vec![None; plan.binding_count()];
    decisions[binding.index()] = Some(crate::placement::PlacementDecision::LexicalDeclaration {
        region: regions.source_root(),
    });
    let decisions = crate::placement::PlacementDecisions::from_decisions_for_test(decisions);

    let before = function.clone();
    let refusal = crate::placement::apply_placement_decisions(
        &mut function,
        &regions,
        &names,
        &decisions,
        &[],
        &std::collections::BTreeMap::new(),
    );

    assert!(
        refusal.is_err(),
        "the region is absent from this body, so applying the decisions must refuse"
    );
    // The whole tree, not a symptom: any surviving mutation fails this,
    // including the removed local the lexical-declaration arm takes out
    // before the refusal is reached.
    assert_eq!(
        function, before,
        "a refused placement must leave the emitted function untouched"
    );
}

#[test]
fn effect_observations_count_only_final_ast_occurrences() {
    let (source, _plan, mut function, mut journal) = journal_fixture();
    let obligation = *source
        .source()
        .obligations()
        .obligations()
        .keys()
        .next()
        .expect("fixture has source obligations");
    let obligations = BTreeSet::from([obligation]);

    let surviving = journal
        .observe_effect_stmt(&obligations, CStmt::Return(None))
        .expect("source-owned effect marker");
    let deleted = journal
        .observe_effect_stmt(&obligations, CStmt::Empty)
        .expect("empty statement cannot claim an effect occurrence");
    function.body.push(surviving);
    drop(deleted);

    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let effects = journal
        .seal_effects_only(&source, &mut ready)
        .expect("final effect occurrences seal independently of V/U/W");
    assert_eq!(effects.occurrence_count(obligation), Some(1));
    assert_eq!(effects.surviving().collect::<Vec<_>>(), [(obligation, 1)]);
}

#[test]
fn conflicting_use_elision_reasons_refuse_instead_of_picking_one() {
    let mut slot = None;
    record_same(
        &mut slot,
        LegacyUseObservation::Elided(crate::ledger::ElisionReason::CoalescedCopy),
    )
    .expect("the first proof owns the empty use cell");
    assert_eq!(
        record_same(
            &mut slot,
            LegacyUseObservation::Elided(crate::ledger::ElisionReason::RedundantPhiEdge),
        ),
        Err(()),
        "a second, different elision proof may not replace the first"
    );
}

#[test]
fn placement_effect_elision_is_considered_only_at_zero_occurrences() {
    let (source, _plan, mut function, mut journal) = journal_fixture();
    let obligation = source
        .source()
        .obligations()
        .obligations()
        .keys()
        .copied()
        .find(|id| matches!(id.instruction.site, r2ssa::CanonicalInstructionSite::Op(_)))
        .expect("fixture has an operation-backed obligation");
    let removed = journal
        .allocate_many(vec![ObservationTarget::Effect(obligation)])
        .expect("one removed effect observation")[0];
    journal.placement_elided_observations.insert(removed);
    journal.account_removed_occurrences();

    let obligations = BTreeSet::from([obligation]);
    function.body.push(
        journal
            .observe_effect_stmt(&obligations, CStmt::Return(None))
            .expect("one surviving effect occurrence"),
    );
    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let effects = journal
        .seal_effects_only(&source, &mut ready)
        .expect("effect observations seal independently of V/U/W");
    assert!(effects.placement_removed_effect(obligation));
    assert_eq!(effects.occurrence_count(obligation), Some(1));

    let origins = NormalizationOrigins::for_unchanged(source.source().function(), source.source());
    let ledger = crate::effect_ledger::build_obligation_ledger(source.source(), &origins, &effects);
    assert!(matches!(
        ledger.outcome(&obligation),
        crate::ledger::Outcome::Rendered { .. }
    ));
}

#[test]
fn residual_memory_effect_is_unaccounted_not_a_rendered_occurrence() {
    let mut block = R2ILBlock::new(0x1000, 4);
    block.push(R2ILOp::Store {
        space: r2il::SpaceId::Ram,
        addr: Varnode::register(0x28, 8),
        val: Varnode::constant(7, 8),
    });
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[block]);
    let (source, _plan, mut function, mut journal) = journal_fixture_for_source(source);
    let obligation = source
        .source()
        .obligations()
        .obligations()
        .keys()
        .copied()
        .find(|id| id.kind == r2ssa::SemanticObligationKind::ObservableMemoryWrite)
        .expect("fixture has an observable memory-write obligation");
    let obligations = BTreeSet::from([obligation]);
    let residual = journal
        .observe_effect_stmt(
            &obligations,
            CStmt::Comment("unsupported exact memory store".to_string()),
        )
        .expect("residual is accepted without claiming the effect");
    let empty = journal
        .observe_effect_stmt(&obligations, CStmt::Empty)
        .expect("empty statement is accepted without claiming the effect");
    assert!(matches!(residual, CStmt::Comment(_)));
    assert_eq!(empty, CStmt::Empty);
    function.body = vec![residual, empty];

    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let effects = journal
        .seal_effects_only(&source, &mut ready)
        .expect("effect observations seal independently of V/U/W");
    assert_eq!(effects.occurrence_count(obligation), Some(0));

    let origins = NormalizationOrigins::for_unchanged(source.source().function(), source.source());
    let ledger = crate::effect_ledger::build_obligation_ledger(source.source(), &origins, &effects);
    assert_eq!(
        ledger.outcome(&obligation),
        crate::ledger::Outcome::Unattributed
    );
    assert!(ledger.unattributed().any(|id| *id == obligation));
}

#[test]
fn duplicate_surviving_effect_occurrence_is_a_conflict() {
    let (source, _plan, mut function, mut journal) = journal_fixture();
    let obligation = *source
        .source()
        .obligations()
        .obligations()
        .keys()
        .next()
        .expect("fixture has source obligations");
    let obligations = BTreeSet::from([obligation]);
    function.body = vec![
        journal
            .observe_effect_stmt(&obligations, CStmt::Return(None))
            .expect("first concrete effect occurrence"),
        journal
            .observe_effect_stmt(&obligations, CStmt::Return(None))
            .expect("second concrete effect occurrence"),
    ];

    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let effects = journal
        .seal_effects_only(&source, &mut ready)
        .expect("final effect occurrences seal independently of V/U/W");
    assert_eq!(effects.occurrence_count(obligation), Some(2));

    let origins = NormalizationOrigins::for_unchanged(source.source().function(), source.source());
    let ledger = crate::effect_ledger::build_obligation_ledger(source.source(), &origins, &effects);
    assert!(matches!(
        ledger.outcome(&obligation),
        crate::ledger::Outcome::Rendered { .. }
    ));
    assert_eq!(
        ledger.conflicts().collect::<Vec<_>>(),
        vec![(&obligation, 1)]
    );
}

#[test]
fn effect_observations_reject_cells_outside_source_inventory() {
    let (source, _plan, _function, mut journal) = journal_fixture();
    let mut obligation = *source
        .source()
        .obligations()
        .obligations()
        .keys()
        .next()
        .expect("fixture has source obligations");
    obligation.instruction.block_addr ^= 1;
    let obligations = BTreeSet::from([obligation]);

    let (value, _binding, _site, _input_idx) = first_bound_rendered_input(&_plan, &source);
    assert_eq!(
        journal.observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                CExpr::UIntLit(0),
                value,
                Vec::new(),
                obligations,
            )
        ),
        Err(LegacyObservationJournalError::InvalidEffectObligation(
            obligation
        ))
    );
}

fn first_bound(plan: &BindingPlan, source: &SourceOwnedFunctionFacts) -> (ValueId, BindingId) {
    source
        .source()
        .graph()
        .values
        .iter()
        .find_map(|value| match plan.disposition(value.id) {
            Some(ValueDisposition::Bound { binding }) => Some((value.id, *binding)),
            _ => None,
        })
        .expect("fixture has a bound value")
}

#[test]
fn source_certified_dead_phi_accounts_for_value_edges_and_write() {
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(R2ILOp::CBranch {
        cond: Varnode::constant(1, 1),
        target: Varnode::constant(0x1008, 8),
    });
    let mut left = R2ILBlock::new(0x1004, 4);
    left.push(R2ILOp::Copy {
        dst: Varnode::unique(0x90, 8),
        src: Varnode::constant(11, 8),
    });
    left.push(R2ILOp::Branch {
        target: Varnode::constant(0x100c, 8),
    });
    let mut right = R2ILBlock::new(0x1008, 4);
    right.push(R2ILOp::Copy {
        dst: Varnode::unique(0x90, 8),
        src: Varnode::constant(12, 8),
    });
    right.push(R2ILOp::Branch {
        target: Varnode::constant(0x100c, 8),
    });
    let mut join = R2ILBlock::new(0x100c, 4);
    join.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::constant(0, 8),
    });
    join.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[entry, left, right, join]);
    let dead = source
        .source()
        .unobserved_merges()
        .iter()
        .find(|value| {
            source.source().graph().value(*value).is_some_and(|value| {
                value.canonical_storage.is_some_and(|storage| {
                    storage.space == CanonicalStorageSpace::Unique
                        && storage.offset == 0x90
                        && storage.size == 8
                })
            })
        })
        .expect("unused unique-space merge");
    let definition = source
        .source()
        .graph()
        .def_inst(dead)
        .expect("dead merge definition");
    let input_count = source
        .source()
        .graph()
        .inst(definition)
        .expect("dead merge instruction")
        .inputs
        .len();
    let support_values = source
        .source()
        .graph()
        .inst(definition)
        .expect("dead merge instruction")
        .inputs
        .clone();
    let plan = Rc::new(BindingPlan::build_shadow(&source).expect("dead-merge-aware plan"));
    let function = CFunction::new("dead_phi", CType::Void);
    let function_source = source.source().function();
    let normalized =
        r2ssa::RewrittenFunction::new(function_source, function_source.blocks().to_vec());
    let origins = NormalizationOrigins::for_unchanged(function_source, source.source());
    let names = test_binding_names(&source, plan, Rc::clone(&function.symbols));
    let journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        names,
        Rc::clone(&function.symbols),
    )
    .expect("journal seeds exact dead-phi cells");
    assert_eq!(
        journal.values[dead.0 as usize],
        Some(LegacyValueObservation::Elided(
            crate::ledger::ElisionReason::UnobservedMerge
        ))
    );
    for support in support_values {
        assert_eq!(
            journal.values[support.0 as usize],
            Some(LegacyValueObservation::Elided(
                crate::ledger::ElisionReason::UnobservedValue
            )),
            "a pure value used only by the dead merge is certified non-rendered"
        );
    }
    for input_idx in 0..input_count {
        assert_eq!(
            journal.uses[definition.0 as usize][input_idx],
            Some(LegacyUseObservation::Elided(
                crate::ledger::ElisionReason::UnobservedMerge
            ))
        );
    }
    assert_eq!(
        journal.writes[definition.0 as usize],
        Some(LegacyWriteObservation::Elided(
            crate::ledger::ElisionReason::UnobservedMerge
        ))
    );
    let coverage = journal.final_coverage();
    assert!(coverage.equations_hold());
    assert!(coverage.values.justified_elision >= 1);
    assert!(coverage.uses.justified_elision >= input_count);
    assert!(coverage.writes.justified_elision >= 1);
}

#[test]
fn immutable_phi_coalesced_by_one_binding_accounts_for_edges_and_definition() {
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(R2ILOp::CBranch {
        cond: Varnode::constant(1, 1),
        target: Varnode::constant(0x1008, 8),
    });
    // Each edge computes from a register the function entered holding,
    // not a constant and not a copy. A fixture built from constants stops
    // having a subject every time the plan gets better at spelling one:
    // every value in it folds into its reader, and a test about a *bound*
    // merge input then asserts about values the plan no longer binds. A
    // fixture built from copies lost its subject when copies were
    // forwarded: the merge then read two entry values, which are both live
    // at entry and so cannot be one object. This is the fourth time that
    // has been corrected here, so the reason is written down rather than
    // the shape merely repaired.
    let mut left = R2ILBlock::new(0x1004, 4);
    left.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 8),
        a: Varnode::register(0x38, 8),
        b: Varnode::constant(1, 8),
    });
    left.push(R2ILOp::Branch {
        target: Varnode::constant(0x100c, 8),
    });
    let mut right = R2ILBlock::new(0x1008, 4);
    right.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 8),
        a: Varnode::register(0x38, 8),
        b: Varnode::constant(2, 8),
    });
    right.push(R2ILOp::Branch {
        target: Varnode::constant(0x100c, 8),
    });
    let mut join = R2ILBlock::new(0x100c, 4);
    join.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[entry, left, right, join]);
    let graph = source.source().graph();
    let definition = graph
        .insts
        .iter()
        .find(|inst| {
            matches!(inst.payload, r2ssa::InstPayload::Phi { .. })
                && inst.output.is_some_and(|output| {
                    !source.source().unobserved_merges().contains(output)
                        && graph.value(output).is_some_and(|value| {
                            value.canonical_storage.is_some_and(|storage| {
                                storage.space == CanonicalStorageSpace::Register
                                    && storage.offset == 0
                            })
                        })
                })
        })
        .expect("live immutable return merge");
    let output = definition.output.expect("phi output");
    let plan = Rc::new(BindingPlan::build_shadow(&source).expect("coalesced phi plan"));
    let output_binding = match plan.disposition(output) {
        Some(ValueDisposition::Bound { binding }) => *binding,
        other => panic!("live merge output must be bound: {other:?}"),
    };
    assert!(definition.inputs.iter().all(|input| matches!(
        plan.disposition(*input),
        Some(ValueDisposition::Bound { binding }) if *binding == output_binding
    )));

    let function = CFunction::new(
        "coalesced_phi",
        CType::Int {
            bits: 64,
            signedness: r2types::Signedness::Signed,
        },
    );
    let function_source = source.source().function();
    let normalized =
        r2ssa::RewrittenFunction::new(function_source, function_source.blocks().to_vec());
    let origins = NormalizationOrigins::for_unchanged(function_source, source.source());
    let names = test_binding_names(&source, plan, Rc::clone(&function.symbols));
    let journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        names,
        Rc::clone(&function.symbols),
    )
    .expect("journal certifies immutable coalesced phi");

    assert_eq!(journal.values[output.0 as usize], None);
    for input_idx in 0..definition.inputs.len() {
        assert_eq!(
            journal.uses[definition.id.0 as usize][input_idx],
            Some(LegacyUseObservation::Elided(
                crate::ledger::ElisionReason::CoalescedImmutablePhi
            ))
        );
    }
    assert_eq!(
        journal.writes[definition.id.0 as usize],
        Some(LegacyWriteObservation::Elided(
            crate::ledger::ElisionReason::CoalescedImmutablePhi
        ))
    );
}

#[test]
fn normalized_identity_phi_edge_is_a_precise_elision_not_an_absence() {
    // The carrier enters holding a register rather than a constant, for
    // the reason given in the immutable-phi fixture above: a constant
    // initialiser folds into its readers, the entry edge is then not a
    // copy between two bound values, and the coalescing this test is
    // about has nothing to coalesce.
    let mut entry = R2ILBlock::new(0x2000, 4);
    entry.push(R2ILOp::Copy {
        dst: Varnode::register(0, 8),
        src: Varnode::register(0x38, 8),
    });
    entry.push(R2ILOp::Branch {
        target: Varnode::constant(0x2004, 8),
    });
    let mut header = R2ILBlock::new(0x2004, 4);
    header.push(R2ILOp::CBranch {
        cond: Varnode::constant(1, 1),
        target: Varnode::constant(0x2014, 8),
    });
    let mut choose_latch = R2ILBlock::new(0x2008, 4);
    choose_latch.push(R2ILOp::CBranch {
        cond: Varnode::constant(1, 1),
        target: Varnode::constant(0x2010, 8),
    });
    let mut identity_latch = R2ILBlock::new(0x200c, 4);
    identity_latch.push(R2ILOp::Branch {
        target: Varnode::constant(0x2004, 8),
    });
    let mut update_latch = R2ILBlock::new(0x2010, 4);
    update_latch.push(R2ILOp::IntAdd {
        dst: Varnode::register(0, 8),
        a: Varnode::register(0, 8),
        b: Varnode::constant(1, 8),
    });
    update_latch.push(R2ILOp::Branch {
        target: Varnode::constant(0x2004, 8),
    });
    let mut exit = R2ILBlock::new(0x2014, 4);
    exit.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    let source = source_owned_from_blocks(&[
        entry,
        header,
        choose_latch,
        identity_latch,
        update_latch,
        exit,
    ]);
    let render = source.report().render().expect("render facts");
    let (normalized, origins) = crate::normalize::materialize_certified_loop_carriers(
        source.source().function(),
        source.source(),
        render,
    )
    .expect("certified carrier normalization");
    let noop_sites = origins.noop_sites().collect::<Vec<_>>();
    assert_eq!(noop_sites.len(), 1, "self-carried edge is the sole no-op");

    let plan = Rc::new(BindingPlan::build_shadow(&source).expect("sealed plan"));
    let function = CFunction::new("identity_phi", CType::Void);
    let names = test_binding_names(&source, plan, Rc::clone(&function.symbols));
    let journal = LegacyObservationJournal::new(
        &source,
        &normalized,
        &origins,
        names,
        Rc::clone(&function.symbols),
    )
    .expect("normalization-backed journal");
    assert_eq!(
        journal.uses[noop_sites[0].inst.0 as usize][noop_sites[0].input_idx],
        Some(LegacyUseObservation::Elided(
            crate::ledger::ElisionReason::RedundantPhiEdge
        ))
    );
    assert!(
        !journal.coalesced_carrier_copy_sites.is_empty(),
        "the non-entry carrier update must derive one coalesced edge disposition"
    );
    for site in journal.coalesced_carrier_copy_sites.iter().copied() {
        for source_use in journal
            .normalized_projection(site)
            .expect("sealed carrier projection")
            .inputs
            .iter()
            .flat_map(|input| input.uses.iter().copied())
        {
            assert_eq!(
                journal.uses[source_use.inst.0 as usize][source_use.input_idx],
                Some(LegacyUseObservation::Elided(
                    crate::ledger::ElisionReason::CoalescedCopy
                ))
            );
        }
    }
    assert!(
        !journal.coalesced_carrier_phi_writes.is_empty(),
        "all certified carrier edges in the fixture are identities after coalescing"
    );
    for inst in journal.coalesced_carrier_phi_writes.iter().copied() {
        assert_eq!(
            journal.writes[inst.0 as usize],
            Some(LegacyWriteObservation::Elided(
                crate::ledger::ElisionReason::CoalescedIdentityPhi
            ))
        );
    }
    let coverage = journal.final_coverage();
    assert!(coverage.equations_hold());
    assert!(coverage.uses.justified_elision >= 1);
}

fn first_bound_rendered_input(
    plan: &BindingPlan,
    source: &SourceOwnedFunctionFacts,
) -> (ValueId, BindingId, NormalizedOpSite, usize) {
    let graph = source.source().graph();
    graph
        .insts
        .iter()
        .find_map(|inst| {
            let (block_addr, op_idx) = source.source().inst_op_site(inst.id)?;
            let block = graph.block_id_for_addr(block_addr)?;
            inst.inputs
                .iter()
                .copied()
                .enumerate()
                .find_map(|(input_idx, value)| {
                    let ValueDisposition::Bound { binding } = plan.disposition(value)? else {
                        return None;
                    };
                    matches!(
                        plan.use_disposition(UseSite {
                            inst: inst.id,
                            input_idx,
                        }),
                        Some(
                            MachineUseDisposition::Exact(_)
                                | MachineUseDisposition::MemoryAddress(_)
                        )
                    )
                    .then_some((
                        value,
                        *binding,
                        NormalizedOpSite { block, op_idx },
                        input_idx,
                    ))
                })
        })
        .expect("fixture has an exactly projected bound input")
}

fn first_bound_rendered_output(
    plan: &BindingPlan,
    source: &SourceOwnedFunctionFacts,
) -> (ValueId, BindingId, InstId, NormalizedOpSite) {
    let graph = source.source().graph();
    graph
        .insts
        .iter()
        .find_map(|inst| {
            let value = inst.output?;
            let ValueDisposition::Bound { binding } = plan.disposition(value)? else {
                return None;
            };
            if !matches!(
                plan.write_disposition(inst.id),
                Some(MachineWriteDisposition::Exact(_))
            ) {
                return None;
            }
            let (block_addr, op_idx) = source.source().inst_op_site(inst.id)?;
            let block = graph.block_id_for_addr(block_addr)?;
            Some((value, *binding, inst.id, NormalizedOpSite { block, op_idx }))
        })
        .expect("fixture has an exactly projected bound output")
}

fn declare_legacy_symbol(
    function: &CFunction,
    plan: &BindingPlan,
    binding: BindingId,
    name: &str,
) -> SymbolId {
    function.symbols.borrow_mut().declare(
        name,
        plan.binding(binding)
            .expect("dense binding")
            .declaration_type()
            .clone(),
        SymbolRole::Carrier,
    )
}

fn declare_legacy_local(
    function: &mut CFunction,
    plan: &BindingPlan,
    binding: BindingId,
    name: &str,
) -> SymbolId {
    let symbol = declare_legacy_symbol(function, plan, binding, name);
    function.locals.push(CLocal {
        ty: plan
            .binding(binding)
            .expect("dense binding")
            .declaration_type()
            .clone(),
        name: symbol,
        stack_offset: None,
    });
    symbol
}

#[test]
fn every_private_journal_error_has_a_stable_public_seal_cause() {
    let function = CFunction::new("seal_cause", CType::Void);
    let symbol = function.symbols.borrow_mut().declare(
        "unowned",
        CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        },
        SymbolRole::Carrier,
    );
    let site = UseSite {
        inst: InstId(17),
        input_idx: 3,
    };
    let normalized_site = NormalizedOpSite {
        block: r2ssa::BlockId(5),
        op_idx: 7,
    };
    let marker = test_render_observation_id(11);
    let inline_expr = {
        let source = source_owned();
        let plan = BindingPlan::build_shadow(&source).expect("sealed binding plan");
        source
            .source()
            .graph()
            .values
            .iter()
            .find_map(|value| match plan.disposition(value.id) {
                Some(ValueDisposition::Inline { term, .. }) => Some(*term),
                _ => None,
            })
            .expect("fixture inline expression")
    };
    let cases = [
        (
            LegacyObservationJournalError::SourceAuthority,
            BindingObservationJournalFailure::SourceAuthority,
        ),
        (
            LegacyObservationJournalError::BindingPlan(BindingPlanSourceMismatch::Authority),
            BindingObservationJournalFailure::BindingPlanAuthority,
        ),
        (
            LegacyObservationJournalError::Normalization(NormalizationOriginError::BlockTopology),
            BindingObservationJournalFailure::NormalizationBlockTopology,
        ),
        (
            LegacyObservationJournalError::TooManyObservations,
            BindingObservationJournalFailure::TooManyObservations,
        ),
        (
            LegacyObservationJournalError::InvalidValue(ValueId(13)),
            BindingObservationJournalFailure::InvalidValue { value: ValueId(13) },
        ),
        (
            LegacyObservationJournalError::InvalidCertifiedValueRead {
                value: ValueId(14),
                at: InstId(15),
            },
            BindingObservationJournalFailure::InvalidCertifiedValueRead {
                value: ValueId(14),
                at: InstId(15),
            },
        ),
        (
            LegacyObservationJournalError::InvalidUse(site),
            BindingObservationJournalFailure::InvalidUse { site },
        ),
        (
            LegacyObservationJournalError::InvalidWrite(InstId(19)),
            BindingObservationJournalFailure::InvalidWrite { inst: InstId(19) },
        ),
        (
            LegacyObservationJournalError::OutputlessWrite(InstId(23)),
            BindingObservationJournalFailure::OutputlessWrite { inst: InstId(23) },
        ),
        (
            LegacyObservationJournalError::InvalidNormalizedSite(normalized_site),
            BindingObservationJournalFailure::InvalidNormalizedSite {
                block: r2ssa::BlockId(5),
                op_idx: 7,
            },
        ),
        (
            LegacyObservationJournalError::MissingNormalizedBlock(0x1234),
            BindingObservationJournalFailure::MissingNormalizedBlock { address: 0x1234 },
        ),
        (
            LegacyObservationJournalError::MissingNormalizedSiteContext,
            BindingObservationJournalFailure::MissingNormalizedSiteContext,
        ),
        (
            LegacyObservationJournalError::InvalidNormalizedInput {
                site: normalized_site,
                input_idx: 9,
            },
            BindingObservationJournalFailure::InvalidNormalizedInput {
                block: r2ssa::BlockId(5),
                op_idx: 7,
                input_idx: 9,
            },
        ),
        (
            LegacyObservationJournalError::MissingNormalizedOutput(normalized_site),
            BindingObservationJournalFailure::MissingNormalizedOutput {
                block: r2ssa::BlockId(5),
                op_idx: 7,
            },
        ),
        (
            LegacyObservationJournalError::RefusedRenderedUse(site),
            BindingObservationJournalFailure::RefusedRenderedUse { site },
        ),
        (
            LegacyObservationJournalError::RefusedRenderedWrite(InstId(29)),
            BindingObservationJournalFailure::RefusedRenderedWrite { inst: InstId(29) },
        ),
        (
            LegacyObservationJournalError::RenderedValueRequired {
                value: ValueId(31),
                cause: RenderedValueRequirementCause::UnobservedValueCellAtSeal,
                disposition: None,
            },
            BindingObservationJournalFailure::RenderedValueRequired { value: ValueId(31) },
        ),
        (
            LegacyObservationJournalError::PlannedElidedValueRendered {
                value: ValueId(32),
                reason: crate::ledger::ElisionReason::DeadUnusedTemporary,
            },
            BindingObservationJournalFailure::PlannedElidedValueRendered { value: ValueId(32) },
        ),
        (
            LegacyObservationJournalError::PlannedRefusedValueRendered {
                value: ValueId(33),
                reason: ValueRefusal::MissingBindingCertificate { value: ValueId(33) },
            },
            BindingObservationJournalFailure::PlannedRefusedValueRendered { value: ValueId(33) },
        ),
        (
            LegacyObservationJournalError::MissingPlannedValue(ValueId(34)),
            BindingObservationJournalFailure::MissingPlannedValue { value: ValueId(34) },
        ),
        (
            LegacyObservationJournalError::InvalidPlannedInline {
                value: ValueId(35),
                term: inline_expr,
            },
            BindingObservationJournalFailure::InvalidPlannedInline {
                value: ValueId(35),
                term_index: inline_expr.index(),
            },
        ),
        (
            LegacyObservationJournalError::ExactUseRequiresRenderedOccurrence(site),
            BindingObservationJournalFailure::ExactUseRequiresRenderedOccurrence { site },
        ),
        (
            LegacyObservationJournalError::ExactWriteRequiresRenderedOccurrence(InstId(37)),
            BindingObservationJournalFailure::ExactWriteRequiresRenderedOccurrence {
                inst: InstId(37),
            },
        ),
        (
            LegacyObservationJournalError::SymbolTableMismatch,
            BindingObservationJournalFailure::SymbolTableMismatch,
        ),
        (
            LegacyObservationJournalError::UnownedBindingSymbol {
                value: ValueId(40),
                symbol,
            },
            BindingObservationJournalFailure::UnownedBindingSymbol {
                value: ValueId(40),
                symbol_index: symbol.index(),
            },
        ),
        (
            LegacyObservationJournalError::ConflictingValue(ValueId(41)),
            BindingObservationJournalFailure::ConflictingValue { value: ValueId(41) },
        ),
        (
            LegacyObservationJournalError::ConflictingUse(site),
            BindingObservationJournalFailure::ConflictingUse { site },
        ),
        (
            LegacyObservationJournalError::ConflictingWrite(InstId(43)),
            BindingObservationJournalFailure::ConflictingWrite { inst: InstId(43) },
        ),
        (
            LegacyObservationJournalError::Markers(RenderObservationStripError::DomainTooLarge {
                expected_count: 47,
            }),
            BindingObservationJournalFailure::ObservationDomainTooLarge { expected_count: 47 },
        ),
        (
            LegacyObservationJournalError::Markers(
                RenderObservationStripError::CapacityUnavailable { expected_count: 53 },
            ),
            BindingObservationJournalFailure::ObservationCapacityUnavailable { expected_count: 53 },
        ),
        (
            LegacyObservationJournalError::Markers(RenderObservationStripError::OutOfRange {
                id: marker,
                expected_count: 59,
            }),
            BindingObservationJournalFailure::ObservationOutOfRange {
                observation_id: 11,
                expected_count: 59,
            },
        ),
        (
            LegacyObservationJournalError::Markers(RenderObservationStripError::Duplicate {
                id: marker,
            }),
            BindingObservationJournalFailure::DuplicateObservation { observation_id: 11 },
        ),
    ];

    for (private, public) in cases {
        assert_eq!(BindingObservationJournalFailure::from(&private), public);
        assert!(!public.kind().is_empty());
    }
}

#[test]
fn rendered_value_cannot_be_recorded_as_nonrendered() {
    let (source, plan, _function, mut journal) = journal_fixture();
    let (value, _) = first_bound(&plan, &source);
    assert_eq!(
        journal.record_nonrendered_value(value),
        Err(LegacyObservationJournalError::RenderedValueRequired {
            value,
            cause: RenderedValueRequirementCause::NonrenderedValueDisposition,
            disposition: plan.disposition(value).cloned(),
        })
    );
}

#[test]
fn conflicting_output_expression_decisions_are_transactional() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (value, binding, _inst, site) = first_bound_rendered_output(&plan, &source);
    let symbol = declare_legacy_local(&mut function, &plan, binding, "conflicting_output");
    let bound = journal
        .observe_normalized_output_expr(site, CExpr::Var(symbol))
        .expect("bound output expression");
    let inline = journal
        .observe_normalized_output_expr(site, CExpr::IntLit(7))
        .expect("inline output expression");
    function.body = vec![CStmt::Expr(bound), CStmt::Expr(inline)];

    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let unchanged = ready.function_for_marker_test().clone();
    assert_eq!(
        journal.seal(&source, &mut ready),
        Err(LegacyObservationJournalError::ConflictingValue(value))
    );
    assert_eq!(ready.function_for_marker_test(), &unchanged);
}

#[test]
fn production_binding_classification_failure_refuses_the_native_product() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (value, binding, _inst, site) = first_bound_rendered_output(&plan, &source);
    let symbol = declare_legacy_local(&mut function, &plan, binding, "conflicting_output");
    let bound = journal
        .observe_normalized_output_expr(site, CExpr::Var(symbol))
        .expect("bound output expression");
    let inline = journal
        .observe_normalized_output_expr(site, CExpr::IntLit(7))
        .expect("inline output expression");
    let obligation = *source
        .source()
        .obligations()
        .obligations()
        .keys()
        .next()
        .expect("fixture has a source effect");
    let effect = journal
        .observe_effect_stmt(&BTreeSet::from([obligation]), CStmt::Return(None))
        .expect("independent effect occurrence");
    function.body = vec![CStmt::Expr(bound), CStmt::Expr(inline), effect];

    let result = MarkedNativeDraft::new(function, journal).finish_enforcing(&source, None);
    if let Err(error) = &result {
        eprintln!("production audit failure: {error:?}");
    }
    assert!(matches!(
        result,
        Err(BindingShadowAuditFailure::JournalSeal(
            BindingObservationJournalFailure::ConflictingValue { value: actual },
        )) if actual == value
    ));
}

#[test]
fn invalid_or_duplicate_markers_leave_ast_unchanged() {
    let (source, plan, mut duplicate_function, mut duplicate_journal) = journal_fixture();
    let (_value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&duplicate_function, &plan, binding, "duplicate_value");
    let marked = duplicate_journal
        .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
        .expect("value marker");
    duplicate_function.body = vec![CStmt::Expr(marked.clone()), CStmt::Expr(marked)];
    let mut duplicate_ready = crate::codegen::prepare_function_for_emission(duplicate_function);
    let unchanged = duplicate_ready.function_for_marker_test().clone();
    assert!(matches!(
        duplicate_journal.seal(&source, &mut duplicate_ready),
        Err(LegacyObservationJournalError::Markers(
            RenderObservationStripError::Duplicate { .. }
        ))
    ));
    assert_eq!(duplicate_ready.function_for_marker_test(), &unchanged);

    let (source, plan, mut range_function, mut range_journal) = journal_fixture();
    let (_value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&range_function, &plan, binding, "range_value");
    let marked = range_journal
        .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
        .expect("value marker");
    let ids = marked.observation_ids();
    let (_outermost, inner) = ids.split_first().expect("marked expression");
    let marked = CExpr::observe_all(
        std::iter::once(test_render_observation_id(2)).chain(inner.iter().copied()),
        marked.unobserved().clone(),
    );
    range_function.body = vec![CStmt::Expr(marked)];
    let mut range_ready = crate::codegen::prepare_function_for_emission(range_function);
    let unchanged = range_ready.function_for_marker_test().clone();
    assert!(matches!(
        range_journal.seal(&source, &mut range_ready),
        Err(LegacyObservationJournalError::Markers(
            RenderObservationStripError::OutOfRange { .. }
        ))
    ));
    assert_eq!(range_ready.function_for_marker_test(), &unchanged);
}

#[test]
fn production_audit_failure_refuses_the_native_product() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (_value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&function, &plan, binding, "duplicate_native_value");
    let marked = journal
        .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
        .expect("value marker");
    let duplicate_id = marked
        .observation_ids()
        .first()
        .expect("rendered input must carry an observation")
        .index();
    function.body = vec![CStmt::Expr(marked.clone()), CStmt::Expr(marked)];

    let result = MarkedNativeDraft::new(function, journal).finish_enforcing(&source, None);
    assert!(matches!(
        result,
        Err(BindingShadowAuditFailure::JournalSeal(
            BindingObservationJournalFailure::DuplicateObservation {
                observation_id: actual,
            },
        )) if actual == duplicate_id
    ));
}

#[test]
fn production_recording_failure_refuses_with_its_exact_cause() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (_value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&function, &plan, binding, "recording_value");
    let marked = journal
        .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
        .expect("value marker");
    let obligation = *source
        .source()
        .obligations()
        .obligations()
        .keys()
        .next()
        .expect("fixture has a source effect");
    let marked = journal
        .observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                marked,
                _value,
                Vec::new(),
                BTreeSet::from([obligation]),
            ),
        )
        .expect("independent effect marker");
    function.body = vec![CStmt::Expr(marked)];

    let result = MarkedNativeDraft::new(function, journal).finish_enforcing(
        &source,
        Some(LegacyObservationJournalError::MissingNormalizedSiteContext),
    );
    assert!(matches!(
        result,
        Err(BindingShadowAuditFailure::JournalRecording(
            BindingObservationJournalFailure::MissingNormalizedSiteContext,
        ))
    ));
}

#[test]
fn journal_construction_does_not_allocate_candidate_symbols() {
    let (source, plan, function, _journal) = journal_fixture();
    let (_, binding) = first_bound(&plan, &source);
    // A name nothing else in the fixture asks for. The binding's own
    // presentation hint is not one: name resolution allocates it when the
    // fixture builds, so requesting it here would come back deduplicated
    // and the test would be measuring that instead of what it is about,
    // which is whether constructing the journal took the name first.
    let requested = "candidate_name";
    let symbol = declare_legacy_symbol(&function, &plan, binding, requested);
    assert_eq!(function.symbols.borrow().name(symbol), requested);
}

#[test]
fn a_bound_value_read_through_a_cast_is_the_same_binding_as_read_bare() {
    // Converting a value does not change which object was named. Before
    // this, the bare read classified as `Bound` and the converted read as
    // an inline expression, so one value collected two classifications and
    // the seal refused -- which is what happens the moment a redundant
    // cast is removed from one of two reads of the same binding.
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&function, &plan, binding, "bound_value");
    let bare = journal
        .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
        .expect("bare value marker");
    let converted = journal
        .observe_normalized_input_expr(
            site,
            input_idx,
            CExpr::cast(crate::ast::CType::machine_bits(64), CExpr::Var(symbol)),
        )
        .expect("converted value marker");
    // The classification is also the check that a rendered name owns a
    // declaration, so the fixture has to declare it.
    function.body = vec![
        CStmt::Decl {
            ty: crate::ast::CType::machine_bits(64),
            name: symbol,
            init: None,
        },
        CStmt::Expr(bare),
        CStmt::Expr(converted),
    ];
    let mut ready = crate::codegen::prepare_function_for_emission(function);
    // The property is that the two reads agree, not that this minimal
    // fixture seals: the seal also requires every other value of the
    // function to have a cell, and this one marks two. Before the fix the
    // bare read classified as the binding and the converted read as an
    // inline expression, and the seal reported exactly this conflict.
    assert_ne!(
        journal.seal(&source, &mut ready).err(),
        Some(LegacyObservationJournalError::ConflictingValue(value)),
        "reading {value:?} bare and through a cast must be one classification"
    );
}

#[test]
fn bound_marker_rejects_a_symbol_without_a_surviving_declaration() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let (value, binding, site, input_idx) = first_bound_rendered_input(&plan, &source);
    let symbol = declare_legacy_symbol(&function, &plan, binding, "undeclared_value");
    function.body = vec![CStmt::Expr(
        journal
            .observe_normalized_input_expr(site, input_idx, CExpr::Var(symbol))
            .expect("value marker"),
    )];
    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let unchanged = ready.function_for_marker_test().clone();
    assert_eq!(
        journal.seal(&source, &mut ready),
        Err(LegacyObservationJournalError::UnownedBindingSymbol { value, symbol })
    );
    assert_eq!(ready.function_for_marker_test(), &unchanged);
}

#[test]
fn discharging_two_instructions_marks_owned_cells_and_each_effect_once() {
    let (source, plan, mut function, mut journal) = journal_fixture();
    let graph = source.source().graph();
    // The fixture folds `u20 = u10 + 2` into its one reader,
    // `u30 = u20 + u10`. Rendering the reader's value as one expression
    // then stands for both instructions.
    let (folded, folded_definition) = graph
        .values
        .iter()
        .find_map(|value| {
            if !matches!(
                plan.disposition(value.id),
                Some(ValueDisposition::Inline { .. })
            ) {
                return None;
            }
            // A constant is inline too and has no defining instruction;
            // this test is about the operation whose statement vanished.
            Some((value.id, graph.def_inst(value.id)?))
        })
        .expect("fixture folds one computed value into its reader");
    let [use_site] = graph.use_sites(folded) else {
        panic!("a folded value has exactly one reader");
    };
    let reader = use_site.inst;
    let value = graph
        .inst(reader)
        .and_then(|inst| inst.output)
        .expect("the reader defines a value");
    let obligations = [reader, folded_definition]
        .iter()
        .flat_map(|inst| {
            source
                .source()
                .obligations()
                .instruction_for_inst(*inst)
                .expect("discharged instruction has a disposition")
                .obligations
                .iter()
                .copied()
        })
        .collect::<BTreeSet<_>>();
    let before = journal.targets.len();
    let marked = journal
        .observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                CExpr::binary(BinaryOp::Add, CExpr::IntLit(1), CExpr::IntLit(2)),
                value,
                vec![reader, folded_definition],
                obligations.clone(),
            ),
        )
        .expect("a two-instruction discharge");

    // Every cell the replacement owns, on the one occurrence: the value
    // rendered, then for each instruction in canonical order its write,
    // the value it produced, every operand use, and only definitionless
    // inline operand values. Bound operand values stay on exact symbol
    // occurrences instead of this parent expression.
    let mut expected = vec![ObservationTarget::Value(value)];
    let mut represented_values = BTreeSet::from([value]);
    let mut order = [reader, folded_definition];
    order.sort_unstable();
    let produced = order
        .iter()
        .filter_map(|inst| graph.inst(*inst)?.output)
        .collect::<BTreeSet<_>>();
    for inst_id in order {
        let inst = graph.inst(inst_id).expect("discharged instruction");
        let block = source
            .source()
            .inst_op_site(inst_id)
            .map(|(block, _)| block)
            .expect("discharged instruction has a site");
        let write = match plan.write_disposition(inst_id) {
            Some(MachineWriteDisposition::Exact(write)) => LegacyWriteObservation::Exact(*write),
            other => panic!("discharged write must be exact, got {other:?}"),
        };
        expected.push(ObservationTarget::Write {
            inst: inst_id,
            observation: write,
            block,
        });
        let output = inst.output.expect("pure definition has an output");
        if represented_values.insert(output) {
            expected.push(ObservationTarget::Value(output));
        }
        for input_idx in 0..inst.inputs.len() {
            let site = UseSite {
                inst: inst_id,
                input_idx,
            };
            let observation = match plan.use_disposition(site) {
                Some(MachineUseDisposition::Exact(slice)) => LegacyUseObservation::Exact(slice),
                Some(MachineUseDisposition::MemoryAddress(_)) => {
                    LegacyUseObservation::MemoryAddress
                }
                other => panic!("discharged use must be exact, got {other:?}"),
            };
            expected.push(ObservationTarget::Use {
                site,
                observation,
                block,
            });
            let input = inst.inputs[input_idx];
            if !produced.contains(&input)
                && !matches!(
                    plan.disposition(input),
                    Some(ValueDisposition::Bound { .. })
                )
                && represented_values.insert(input)
            {
                expected.push(ObservationTarget::Value(input));
            }
        }
    }
    expected.extend(obligations.iter().copied().map(ObservationTarget::Effect));
    assert_eq!(&journal.targets[before..], expected.as_slice());
    assert_eq!(
        journal
            .targets
            .iter()
            .filter(|target| matches!(target, ObservationTarget::Write { .. }))
            .count(),
        2,
        "both discharged instructions have their write cell marked"
    );
    assert_eq!(
        journal
            .targets
            .iter()
            .filter(|target| matches!(target, ObservationTarget::Value(_)))
            .count(),
        represented_values.len(),
        "replacement-owned values each have one target"
    );

    // The effects the two instructions answered for move with the
    // expression, and each is rendered exactly once.
    assert!(
        !obligations.is_empty(),
        "a pure definition carries a live-value obligation"
    );
    function.body = vec![CStmt::Expr(marked)];
    let mut ready = crate::codegen::prepare_function_for_emission(function);
    let effects = journal
        .seal_effects_only(&source, &mut ready)
        .expect("effect-only seal");
    for obligation in &obligations {
        assert_eq!(
            effects.occurrence_count(*obligation),
            Some(1),
            "obligation {obligation:?} is rendered once by the discharge"
        );
    }
}

#[test]
fn nested_replacement_reuses_inline_child_and_does_not_claim_bound_operand() {
    let (source, plan, _function, mut journal) = journal_fixture();
    let graph = source.source().graph();
    let (folded, folded_definition) = graph
        .values
        .iter()
        .find_map(|value| {
            if !matches!(
                plan.disposition(value.id),
                Some(ValueDisposition::Inline { .. })
            ) {
                return None;
            }
            Some((value.id, graph.def_inst(value.id)?))
        })
        .expect("fixture folds one computed value into its reader");
    let [use_site] = graph.use_sites(folded) else {
        panic!("a folded value has exactly one reader");
    };
    let reader = use_site.inst;
    let rendered = graph
        .inst(reader)
        .and_then(|inst| inst.output)
        .expect("the reader defines a value");
    let bound = graph
        .inst(reader)
        .expect("folded value reader")
        .inputs
        .iter()
        .copied()
        .find(|value| {
            matches!(
                plan.disposition(*value),
                Some(ValueDisposition::Bound { .. })
            )
        })
        .expect("the folded reader also consumes a bound value");

    assert!(
        matches!(
            journal.observe_rendered_replacement_expr(
                crate::fold::op_lower::RenderedReplacementContract::for_test(
                    CExpr::IntLit(3),
                    rendered,
                    vec![reader],
                    BTreeSet::new(),
                ),
            ),
            Err(LegacyObservationJournalError::RenderedValueRequired {
                value,
                cause: RenderedValueRequirementCause::NonrenderedValueDisposition,
                ..
            }) if value == folded
        ),
        "an outer replacement cannot silently claim a defined inline operand"
    );

    let inner = journal
        .observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                CExpr::binary(BinaryOp::Add, CExpr::IntLit(1), CExpr::IntLit(2)),
                folded,
                vec![folded_definition],
                BTreeSet::new(),
            ),
        )
        .expect("the inner replacement owns the folded value occurrence");
    let before_outer = journal.targets.len();
    journal
        .observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                CExpr::binary(BinaryOp::Add, inner, CExpr::IntLit(4)),
                rendered,
                vec![reader],
                BTreeSet::new(),
            ),
        )
        .expect("the outer replacement composes the finalized inner expression");

    assert!(
        !journal.targets[before_outer..].contains(&ObservationTarget::Value(folded)),
        "the outer replacement must not become a second answerer for the inner value"
    );
    assert_eq!(
        journal
            .targets
            .iter()
            .filter(|target| **target == ObservationTarget::Value(folded))
            .count(),
        1,
        "the nested expression carries exactly one folded-value occurrence"
    );
    assert!(
        !journal.targets[before_outer..].contains(&ObservationTarget::Value(bound)),
        "the outer replacement must not claim a bound value its child already names"
    );
    assert_eq!(
        journal
            .targets
            .iter()
            .filter(|target| **target == ObservationTarget::Value(bound))
            .count(),
        0,
        "a bound value cell remains for an exact occurrence of its own symbol"
    );
}

#[test]
fn replacement_claims_bound_operand_only_when_its_exact_symbol_survives() {
    let (source, plan, _function, mut journal) = journal_fixture();
    let graph = source.source().graph();
    let (rendered, definition, bound, binding) = graph
        .values
        .iter()
        .find_map(|value| {
            if !matches!(
                plan.disposition(value.id),
                Some(ValueDisposition::Inline { .. })
            ) {
                return None;
            }
            let definition = graph.def_inst(value.id)?;
            let (bound, binding) = graph.inst(definition)?.inputs.iter().find_map(|input| {
                match plan.disposition(*input) {
                    Some(ValueDisposition::Bound { binding }) => Some((*input, *binding)),
                    _ => None,
                }
            })?;
            Some((value.id, definition, bound, binding))
        })
        .expect("fixture has an inline definition with a bound operand");
    let symbol = journal
        .names
        .symbol_for_binding(binding)
        .expect("the bound operand has its planned symbol");
    let before = journal.targets.len();

    journal
        .observe_rendered_replacement_expr(
            crate::fold::op_lower::RenderedReplacementContract::for_test(
                CExpr::binary(BinaryOp::Add, CExpr::Var(symbol), CExpr::IntLit(2)),
                rendered,
                vec![definition],
                BTreeSet::new(),
            ),
        )
        .expect("the exact bound symbol remains in the replacement");

    assert!(
        journal.targets[before..].contains(&ObservationTarget::Value(bound)),
        "the surviving exact symbol owns its bound value cell"
    );
}

#[test]
fn replacement_rejects_a_bound_intermediate_producer() {
    let (source, plan, _function, mut journal) = journal_fixture();
    let graph = source.source().graph();
    let rendered = graph
        .values
        .iter()
        .find(|value| {
            matches!(
                plan.disposition(value.id),
                Some(ValueDisposition::Inline { .. })
            )
        })
        .map(|value| value.id)
        .expect("fixture has an inline value");
    let (bound, definition) = graph
        .values
        .iter()
        .find_map(|value| {
            if !matches!(
                plan.disposition(value.id),
                Some(ValueDisposition::Bound { .. })
            ) {
                return None;
            }
            Some((value.id, graph.def_inst(value.id)?))
        })
        .expect("fixture has a bound computed value");

    assert!(
        matches!(
            journal.observe_rendered_replacement_expr(
                crate::fold::op_lower::RenderedReplacementContract::for_test(
                    CExpr::IntLit(1),
                    rendered,
                    vec![definition],
                    BTreeSet::new(),
                ),
            ),
            Err(LegacyObservationJournalError::RenderedValueRequired {
                value,
                cause: RenderedValueRequirementCause::NonrenderedValueDisposition,
                ..
            }) if value == bound
        ),
        "a replacement cannot absorb a producer the plan still renders separately"
    );
}

/// How many `Observed` layers stand on top of one another from `stmt` down,
/// counted without recursing so that counting a deep chain cannot overflow.
fn stacked_observation_layers(stmt: &CStmt) -> usize {
    let mut layers = 0;
    let mut cursor = stmt;
    while let CStmt::Observed { stmt, .. } = cursor {
        layers += 1;
        cursor = stmt;
    }
    layers
}

/// A function of `pairs` sums of a register, each stored: a few thousand
/// cells, all of them the gap's to claim.
fn stored_sums(pairs: u64) -> SourceOwnedFunctionFacts {
    let mut block = R2ILBlock::new(0x1000, 4);
    for pair in 0..pairs {
        let sum = Varnode::unique(0x100 + 8 * pair, 8);
        block.push(R2ILOp::IntAdd {
            dst: sum.clone(),
            a: Varnode::register(0, 8),
            b: Varnode::constant(pair + 1, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0x38, 8),
            val: sum,
        });
    }
    block.push(R2ILOp::Return {
        target: Varnode::register(0x30, 8),
    });
    source_owned_from_blocks_with_parameter(&[block], true)
}

/// Every cell a fresh journal has not answered, which is every cell a gap
/// over the whole function can claim.
fn unanswered_cells(journal: &LegacyObservationJournal) -> Vec<GapCell> {
    let values = journal.values.iter().enumerate();
    let mut cells = values
        .filter(|(_, slot)| slot.is_none())
        .map(|(value, _)| GapCell::Value(ValueId(value as u32)))
        .collect::<Vec<_>>();
    let uses = journal.uses.iter().enumerate().flat_map(|(inst, inputs)| {
        let unanswered = inputs.iter().enumerate().filter(|(_, slot)| slot.is_none());
        unanswered.map(move |(input_idx, _)| GapCell::Use {
            site: UseSite {
                inst: InstId(inst as u32),
                input_idx,
            },
            block: 0x1000,
        })
    });
    cells.extend(uses);
    let writes = journal.writes.iter().zip(journal.write_has_output.iter());
    cells.extend(
        writes
            .enumerate()
            .filter(|(_, (slot, has_output))| slot.is_none() && **has_output)
            .map(|(inst, _)| GapCell::Write(InstId(inst as u32))),
    );
    cells.extend(
        journal
            .effect_occurrences
            .keys()
            .copied()
            .map(GapCell::Effect),
    );
    cells
}

/// One statement as the whole of a function's one block, with sealed regions.
fn the_whole_body(
    stmt: CStmt,
    source: &SourceOwnedFunctionFacts,
) -> (
    CStmt,
    crate::structured_region::SealedStructuredRegionArtifact,
) {
    seal_structured_body(
        CStmt::structured_region(
            StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
            CStmt::structured_region(
                StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::Block),
                stmt,
            ),
        ),
        source.source().authority(),
    )
    .expect("sealed body")
    .into_marked_parts()
}

/// One gap statement carries every cell it claims as one observation set.
///
/// A gap claims the whole closure of a refusal, and in `fcn.1000414cc` of
/// macOS `ssh` that was 38,726 cells. They were attached one wrapper per cell,
/// so the tree under the gap was as deep as the cell count and every recursive
/// pass over it -- sealing, placement, stripping, cloning, dropping --
/// recursed once per cell and overflowed the stack. The fixture is a few
/// thousand generated instructions whose every cell the gap claims; the
/// passes then run on a thread with 128 KiB of stack.
#[test]
fn a_gap_carries_every_cell_it_claims_on_one_node() {
    let source = stored_sums(1_500);
    let checked = std::thread::Builder::new()
        .name("128 KiB stack".to_owned())
        .stack_size(128 << 10)
        .spawn(move || {
            let (source, plan, mut function, mut journal) = journal_fixture_for_source(source);
            let names = test_binding_names(&source, Rc::new(plan), Rc::clone(&function.symbols));
            let cells = unanswered_cells(&journal);
            let anchor = GapAnchor {
                block_addr: 0x1000,
                op_idx: 0,
            };
            let marker = crate::ast::GapMarker {
                kind: "test".to_string(),
                origin: "a_gap_carries_every_cell_it_claims_on_one_node".to_string(),
                block_addr: 0x1000,
                op_idx: 0,
                ops: 3_001,
            };
            let gap = journal
                .gap_stmt(anchor, marker, &cells)
                .expect("the gap claims every unanswered cell");

            // The depth does not grow with the cell count. Counted before
            // anything recursive touches the tree; a chain is leaked rather
            // than dropped, because dropping it recurses once per layer.
            let layers = stacked_observation_layers(&gap);
            if layers != 1 {
                std::mem::forget(gap);
                panic!("{layers} observation layers stand over one gap statement");
            }

            let (statement, regions) = the_whole_body(gap, &source);
            function.body = vec![statement];
            let count = journal.placement_target_count();

            // Every id is the gap's, outermost first: the last one allocated
            // stands outermost, as it did when each id was its own wrapper.
            let mut visited = Vec::new();
            crate::ast::inspect_render_observations(&function, count, |id, node| {
                let on_the_gap =
                    matches!(node, crate::ast::RenderObservationNode::Stmt(CStmt::Gap(_)));
                visited.push((on_the_gap, id.index()));
                Ok::<(), ()>(())
            })
            .expect("one valid observation set");
            assert!(visited.iter().all(|(on_the_gap, _)| *on_the_gap));
            assert!(visited.iter().map(|(_, id)| *id).rev().eq(0..count as u32));

            crate::placement::collect_final_placement_occurrences(
                &function,
                &regions,
                source.source(),
                &names,
                count,
                |id| journal.placement_target(id),
            )
            .expect("a gap reads and writes no binding placement orders");

            let mut stripped = function.clone();
            let reachable = crate::ast::strip_render_observations(&mut stripped, count)
                .expect("every id is in the journal's domain");
            assert_eq!(reachable.ids().count(), count);

            let mut ready = crate::codegen::prepare_function_for_emission(function);
            let coverage = journal
                .seal(&source, &mut ready)
                .expect("the gap seals")
                .coverage();
            assert!(coverage.equations_hold(), "{coverage:?}");
            (cells, coverage)
        })
        .expect("spawn the small-stack thread")
        .join();
    let (cells, coverage) = checked.expect("sealing, placement and stripping fit in 128 KiB");
    assert!(cells.len() > 5_000, "{} cells", cells.len());
    // Each claimed cell sealed exactly once, as the gap's.
    let claimed = cells
        .iter()
        .filter(|cell| !matches!(cell, GapCell::Effect(_)))
        .count();
    let gapped = coverage.values.gapped + coverage.uses.gapped + coverage.writes.gapped;
    assert_eq!(gapped, claimed, "{coverage:?}");
}
