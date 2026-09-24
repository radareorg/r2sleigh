use super::*;
use crate::structured_region::{
    StructuredRegionKind, StructuredRegionMarker,
    seal_structured_body_for_test as seal_structured_body,
};
use crate::symbol::{SymbolRole, SymbolTable};

fn observation(index: u32) -> RenderObservationId {
    crate::observation_journal::test_render_observation_id(index)
}

#[test]
fn dense_binding_sets_refuse_mismatched_domains_without_partial_mutation() {
    let binding = BindingId::from_dense_index(0).expect("binding");
    let mut one_binding = DenseBindingSet::empty(1);
    one_binding.insert(binding).expect("in-domain binding");
    let two_bindings = DenseBindingSet::all(2);
    let original = one_binding.clone();
    let mismatch = DenseBindingDomainMismatch;

    assert_eq!(one_binding.intersect_with(&two_bindings), Err(mismatch));
    assert_eq!(one_binding, original);
    assert_eq!(one_binding.union_with(&two_bindings), Err(mismatch));
    assert_eq!(one_binding, original);
    assert_eq!(
        one_binding.insert(BindingId::from_dense_index(1).expect("binding")),
        Err(mismatch)
    );
    assert_eq!(one_binding, original);
}

#[test]
fn invalid_dense_domain_refuses_every_placement_binding() {
    let decisions = refuse_unprovable_binding_domain(2, DenseBindingDomainMismatch);
    for index in 0..2 {
        let binding = BindingId::from_dense_index(index).expect("binding");
        assert_eq!(
            decisions.decision(binding),
            Some(PlacementDecision::Refused(
                PlacementRefusal::UnprovableExecutionOrder { binding },
            ))
        );
    }
}

#[derive(Debug)]
struct TestCfg {
    entry: u64,
    successors: BTreeMap<u64, Vec<u64>>,
    predecessors: BTreeMap<u64, Vec<u64>>,
    dominators: BTreeMap<u64, BTreeSet<u64>>,
}

impl TestCfg {
    fn new(entry: u64, edges: &[(u64, u64)]) -> Self {
        let mut blocks = BTreeSet::from([entry]);
        let mut successors = BTreeMap::<u64, Vec<u64>>::new();
        let mut predecessors = BTreeMap::<u64, Vec<u64>>::new();
        for &(from, to) in edges {
            blocks.extend([from, to]);
            successors.entry(from).or_default().push(to);
            predecessors.entry(to).or_default().push(from);
        }
        for block in &blocks {
            successors.entry(*block).or_default().sort_unstable();
            predecessors.entry(*block).or_default().sort_unstable();
        }

        let mut dominators = blocks
            .iter()
            .map(|block| {
                let set = if *block == entry {
                    BTreeSet::from([entry])
                } else {
                    blocks.clone()
                };
                (*block, set)
            })
            .collect::<BTreeMap<_, _>>();
        loop {
            let mut changed = false;
            for block in blocks.iter().copied().filter(|block| *block != entry) {
                let preds = &predecessors[&block];
                let mut next = if let Some(first) = preds.first() {
                    dominators[first].clone()
                } else {
                    BTreeSet::new()
                };
                for predecessor in preds.iter().skip(1) {
                    next = next
                        .intersection(&dominators[predecessor])
                        .copied()
                        .collect();
                }
                next.insert(block);
                if next != dominators[&block] {
                    dominators.insert(block, next);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Self {
            entry,
            successors,
            predecessors,
            dominators,
        }
    }
}

impl PlacementControlFlow for TestCfg {
    fn entry(&self) -> u64 {
        self.entry
    }

    fn block_addrs(&self) -> Vec<u64> {
        self.successors.keys().copied().collect()
    }

    fn predecessors(&self, block: u64) -> Vec<u64> {
        self.predecessors[&block].clone()
    }

    fn successors(&self, block: u64) -> Vec<u64> {
        self.successors[&block].clone()
    }

    fn dominates(&self, dominator: u64, block: u64) -> bool {
        self.dominators[&block].contains(&dominator)
    }
}

#[test]
fn a_for_initializer_belongs_to_the_region_the_loop_sits_in() {
    // `for (i = 0; ...)` writes the initializer inside the loop because C
    // spells it there, and it runs once, at the predecessor that enters the
    // loop. Giving the occurrence the loop's own region asks the loop
    // header to dominate a block before it, which it never does.
    let init_marker = crate::ast::RenderObservationId::from_index(0);
    let body_marker = crate::ast::RenderObservationId::from_index(1);
    let loop_body = CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1010, StructuredRegionKind::Loop),
        CStmt::For {
            init: Some(Box::new(CStmt::observe_one(init_marker, CStmt::Empty))),
            cond: None,
            update: None,
            body: Box::new(CStmt::observe_one(body_marker, CStmt::Empty)),
        },
    );
    let (marked, regions) =
        crate::structured_region::seal_structured_body_for_test(CStmt::structured_region(
            StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
            CStmt::Block(vec![block_region(0x1000), loop_body]),
        ))
        .expect("marker tree")
        .into_marked_parts();
    let mut scoped = FinalObservationScopes {
        first: vec![None; 2],
        repeats: BTreeMap::new(),
    };
    let mut conditionals = 0;
    collect_stmt_observation_regions(&marked, None, &regions, &mut conditionals, &mut scoped);
    let init_region = scoped
        .scope(RenderObservationId::from_dense_index(0))
        .and_then(|scope| scope.region)
        .expect("the initializer was scoped");
    let body_region = scoped
        .scope(RenderObservationId::from_dense_index(1))
        .and_then(|scope| scope.region)
        .expect("the body was scoped");
    assert_ne!(
        init_region, body_region,
        "the initializer runs before the loop and the body runs inside it"
    );
    assert_eq!(
        regions.node(body_region).map(|node| node.kind()),
        Some(StructuredRegionKind::Loop)
    );
    assert_eq!(
        regions.node(body_region).and_then(|node| node.parent()),
        Some(init_region),
        "the initializer takes the region the loop sits in"
    );
}

/// A marker tree sealed the way the structurer seals its own.
fn regions_from(entry: u64, body: Vec<CStmt>) -> SealedStructuredRegionArtifact {
    crate::structured_region::seal_structured_body_for_test(CStmt::structured_region(
        StructuredRegionMarker::unsealed(entry, StructuredRegionKind::FunctionBody),
        CStmt::Block(body),
    ))
    .expect("marker tree")
    .into_marked_parts()
    .1
}

fn block_region(entry: u64) -> CStmt {
    CStmt::structured_region(
        StructuredRegionMarker::unsealed(entry, StructuredRegionKind::Block),
        CStmt::Empty,
    )
}

fn if_region(cond: u64, then_body: CStmt, else_body: CStmt) -> CStmt {
    CStmt::structured_region(
        StructuredRegionMarker::unsealed(cond, StructuredRegionKind::IfThenElse),
        CStmt::if_stmt(CExpr::IntLit(1), then_body, Some(else_body)),
    )
}

fn diamond_regions() -> SealedStructuredRegionArtifact {
    regions_from(
        0x1000,
        vec![
            if_region(0x1000, block_region(0x1010), block_region(0x1020)),
            block_region(0x1030),
        ],
    )
}

fn region_with_entry(
    regions: &SealedStructuredRegionArtifact,
    entry: u64,
    kind: StructuredRegionKind,
) -> RegionId {
    let index = regions
        .nodes()
        .iter()
        .position(|node| node.entry() == entry && node.kind() == kind)
        .expect("region entry");
    regions
        .node_for_anchor(
            regions.authority(),
            regions.nodes()[index].emission_anchor(),
        )
        .expect("dense region")
        .0
}

fn diamond_cfg() -> TestCfg {
    TestCfg::new(
        0x1000,
        &[
            (0x1000, 0x1010),
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            (0x1020, 0x1030),
        ],
    )
}

#[test]
fn diamond_with_both_arms_assigned_places_one_lexical_declaration() {
    let regions = diamond_regions();
    let cfg = diamond_cfg();
    let binding = BindingId::from_dense_index(0).expect("binding");
    let then_region = region_with_entry(&regions, 0x1010, StructuredRegionKind::Block);
    let else_region = region_with_entry(&regions, 0x1020, StructuredRegionKind::Block);
    let merge_region = region_with_entry(&regions, 0x1030, StructuredRegionKind::Block);
    let writes = [
        FinalBindingWrite {
            statement: 0,
            defines: None,
            effectful: false,
            binding,
            inst: InstId(1),
            region: then_region,
            block: 0x1010,
            order: FinalOccurrenceOrder(1),
            observation: observation(1),
            inline_eligible: true,
        },
        FinalBindingWrite {
            statement: 0,
            defines: None,
            effectful: false,
            binding,
            inst: InstId(2),
            region: else_region,
            block: 0x1020,
            order: FinalOccurrenceOrder(2),
            observation: observation(2),
            inline_eligible: true,
        },
    ];
    let reads = [FinalBindingRead {
        statement: 0,
        value: None,
        binding,
        source: PlacementRead::Use(UseSite {
            inst: InstId(3),
            input_idx: 0,
        }),
        region: merge_region,
        block: 0x1030,
        order: FinalOccurrenceOrder(3),
        spelled: true,
    }];

    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &reads,
        &writes,
    )
    .expect("placement");
    // The arms and the merge meet at the function body itself.
    let body = regions.root();
    assert_eq!(
        decisions.decision(binding),
        Some(PlacementDecision::LexicalDeclaration { region: body })
    );
}

#[test]
fn diamond_with_one_arm_unassigned_refuses_merge_read() {
    let regions = diamond_regions();
    let cfg = diamond_cfg();
    let binding = BindingId::from_dense_index(0).expect("binding");
    let then_region = region_with_entry(&regions, 0x1010, StructuredRegionKind::Block);
    let merge_region = region_with_entry(&regions, 0x1030, StructuredRegionKind::Block);
    let site = UseSite {
        inst: InstId(3),
        input_idx: 0,
    };
    let writes = [FinalBindingWrite {
        statement: 0,
        defines: None,
        effectful: false,
        binding,
        inst: InstId(1),
        region: then_region,
        block: 0x1010,
        order: FinalOccurrenceOrder(1),
        observation: observation(1),
        inline_eligible: true,
    }];
    let reads = [FinalBindingRead {
        statement: 0,
        value: None,
        binding,
        source: PlacementRead::Use(site),
        region: merge_region,
        block: 0x1030,
        order: FinalOccurrenceOrder(2),
        spelled: true,
    }];

    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &reads,
        &writes,
    )
    .expect("placement");
    assert_eq!(
        decisions.decision(binding),
        Some(PlacementDecision::Refused(
            PlacementRefusal::ReadBeforeAssignment {
                binding,
                read: PlacementRead::Use(site),
            }
        ))
    );
}

#[test]
fn duplicated_merge_reads_in_exclusive_arms_use_the_cfg_assignment_proof() {
    let regions = regions_from(
        0x1000,
        vec![if_region(
            0x1000,
            CStmt::Block(vec![block_region(0x1010), block_region(0x1030)]),
            CStmt::Block(vec![block_region(0x1020), block_region(0x1030)]),
        )],
    );
    let cfg = diamond_cfg();
    let binding = BindingId::from_dense_index(0).expect("binding");
    let then_region = region_with_entry(&regions, 0x1010, StructuredRegionKind::Block);
    let else_region = region_with_entry(&regions, 0x1020, StructuredRegionKind::Block);
    let merge_regions = regions
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.entry() == 0x1030 && node.kind() == StructuredRegionKind::Block)
        .filter_map(|(_, node)| {
            regions
                .node_for_anchor(regions.authority(), node.emission_anchor())
                .map(|(region, _)| region)
        })
        .collect::<Vec<_>>();
    assert_eq!(merge_regions.len(), 2);
    assert!(regions.regions_are_exclusive(merge_regions[0], merge_regions[1]));
    let writes = [
        FinalBindingWrite {
            defines: None,
            statement: 0x1010,
            effectful: false,
            binding,
            inst: InstId(1),
            region: then_region,
            block: 0x1010,
            order: FinalOccurrenceOrder(1),
            observation: observation(1),
            inline_eligible: true,
        },
        FinalBindingWrite {
            defines: None,
            statement: 0x1020,
            effectful: false,
            binding,
            inst: InstId(2),
            region: else_region,
            block: 0x1020,
            order: FinalOccurrenceOrder(3),
            observation: observation(2),
            inline_eligible: true,
        },
    ];
    let reads = [
        FinalBindingRead {
            value: None,
            statement: 0x1030,
            binding,
            source: PlacementRead::Use(UseSite {
                inst: InstId(3),
                input_idx: 0,
            }),
            region: merge_regions[0],
            block: 0x1030,
            order: FinalOccurrenceOrder(2),
            spelled: true,
        },
        FinalBindingRead {
            value: None,
            statement: 0x1030,
            binding,
            source: PlacementRead::Use(UseSite {
                inst: InstId(3),
                input_idx: 0,
            }),
            region: merge_regions[1],
            block: 0x1030,
            order: FinalOccurrenceOrder(4),
            spelled: true,
        },
    ];

    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &reads,
        &writes,
    )
    .expect("placement");
    assert!(matches!(
        decisions.decision(binding),
        Some(PlacementDecision::LexicalDeclaration { .. })
    ));
}

#[test]
fn one_dominating_write_is_inlined_at_its_exact_assignment() {
    let regions = regions_from(0x1000, vec![block_region(0x1000), block_region(0x1010)]);
    let cfg = TestCfg::new(0x1000, &[(0x1000, 0x1010)]);
    let binding = BindingId::from_dense_index(0).expect("binding");
    let write_region = region_with_entry(&regions, 0x1000, StructuredRegionKind::Block);
    let read_region = region_with_entry(&regions, 0x1010, StructuredRegionKind::Block);
    let write = InstId(1);
    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &[FinalBindingRead {
            statement: 0,
            value: None,
            binding,
            source: PlacementRead::Use(UseSite {
                inst: InstId(2),
                input_idx: 0,
            }),
            region: read_region,
            block: 0x1010,
            order: FinalOccurrenceOrder(2),
            spelled: true,
        }],
        &[FinalBindingWrite {
            statement: 0,
            defines: None,
            effectful: false,
            binding,
            inst: write,
            region: write_region,
            block: 0x1000,
            order: FinalOccurrenceOrder(1),
            observation: observation(1),
            inline_eligible: true,
        }],
    )
    .expect("placement");

    assert_eq!(
        decisions.decision(binding),
        Some(PlacementDecision::Inline {
            write,
            // The fallback the inline carries if the emitted tree turns out
            // to put its declaration out of scope: the lowest region that
            // dominates both the write and the read.
            region: lowest_common_ancestor(&regions, write_region, read_region)
                .expect("common ancestor"),
        })
    );
}

#[test]
fn certified_parameter_read_uses_entry_assignment_without_a_local() {
    let regions = regions_from(0x1000, vec![block_region(0x1000)]);
    let cfg = TestCfg::new(0x1000, &[]);
    let binding = BindingId::from_dense_index(0).expect("binding");
    let block_region = region_with_entry(&regions, 0x1000, StructuredRegionKind::Block);
    let reads = [FinalBindingRead {
        statement: 0,
        value: None,
        binding,
        source: PlacementRead::Use(UseSite {
            inst: InstId(0),
            input_idx: 0,
        }),
        region: block_region,
        block: 0x1000,
        order: FinalOccurrenceOrder(0),
        spelled: true,
    }];

    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::from([binding]),
        &BTreeSet::new(),
        &reads,
        &[],
    )
    .expect("parameter placement");
    assert_eq!(
        decisions.decision(binding),
        Some(PlacementDecision::ExternallyDeclared)
    );

    let uncertified = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &reads,
        &[],
    )
    .expect("uncertified placement");
    assert_eq!(
        uncertified.decision(binding),
        Some(PlacementDecision::Refused(
            PlacementRefusal::MissingDefinition { binding }
        ))
    );
}

#[test]
fn escaped_frame_object_address_uses_its_declaration_as_definition() {
    let regions = regions_from(0x1000, vec![block_region(0x1000)]);
    let cfg = TestCfg::new(0x1000, &[]);
    let binding = BindingId::from_dense_index(0).expect("binding");
    let block_region = region_with_entry(&regions, 0x1000, StructuredRegionKind::Block);
    let value = r2ssa::ValueId(3);
    let reads = [FinalBindingRead {
        statement: 0,
        value: Some(value),
        binding,
        source: PlacementRead::ObjectAddress { value },
        region: block_region,
        block: 0x1000,
        order: FinalOccurrenceOrder(0),
        spelled: true,
    }];

    let decisions = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::from([binding]),
        &reads,
        &[],
    )
    .expect("address-taken frame-object placement");
    assert_eq!(
        decisions.decision(binding),
        Some(PlacementDecision::LexicalDeclaration {
            region: block_region,
        })
    );

    let unescaped = derive_with_cfg(
        &regions,
        &cfg,
        1,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &reads,
        &[],
    )
    .expect("unescaped frame-object placement");
    assert_eq!(
        unescaped.decision(binding),
        Some(PlacementDecision::Refused(
            PlacementRefusal::MissingDefinition { binding }
        ))
    );
}

#[test]
fn exact_region_insertion_uses_the_sealed_anchor_not_the_block_address() {
    let repeated_entry = CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Block(vec![
            CStmt::structured_region(
                StructuredRegionMarker::unsealed(0x1010, StructuredRegionKind::Block),
                CStmt::comment("first"),
            ),
            CStmt::structured_region(
                StructuredRegionMarker::unsealed(0x1010, StructuredRegionKind::Block),
                CStmt::comment("second"),
            ),
        ]),
    );
    let sealed = seal_structured_body(repeated_entry).expect("sealed occurrences");
    let target = sealed
        .regions()
        .node_for_anchor(
            sealed.regions().authority(),
            sealed.regions().nodes()[2].emission_anchor(),
        )
        .expect("second occurrence")
        .0;
    let (statement, regions) = sealed.into_marked_parts();
    let mut statements = vec![statement];
    let declaration = CStmt::comment("declaration");

    assert_eq!(
        insert_region_declarations(&mut statements, &regions, target, &[declaration]),
        1
    );
    let CStmt::StructuredRegion { stmt: root, .. } = &statements[0] else {
        panic!("function marker")
    };
    let CStmt::Block(children) = root.as_ref() else {
        panic!("function body")
    };
    let CStmt::StructuredRegion { stmt: first, .. } = &children[0] else {
        panic!("first marker")
    };
    let CStmt::StructuredRegion { stmt: second, .. } = &children[1] else {
        panic!("second marker")
    };
    assert!(!format!("{first:?}").contains("declaration"));
    assert!(format!("{second:?}").contains("declaration"));
}

#[test]
fn inline_replaces_only_the_exact_marked_assignment() {
    let symbols = std::rc::Rc::new(std::cell::RefCell::new(SymbolTable::new()));
    let symbol = symbols.borrow_mut().declare(
        "value",
        crate::ast::CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Unsigned,
        },
        SymbolRole::Carrier,
    );
    let marker = observation(7);
    let assignment = CStmt::observe_one(
        marker,
        CStmt::expr(CExpr::assign(CExpr::Var(symbol), CExpr::UIntLit(9))),
    );
    let mut statements = vec![assignment, CStmt::comment("untouched")];

    let mentions = SymbolMentions::of_body(&statements);
    assert_eq!(
        inline_marked_write(
            &mentions,
            &mut statements,
            marker,
            symbol,
            &crate::ast::CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Unsigned
            },
        ),
        1
    );
    assert!(matches!(
        statements[0].unobserved(),
        CStmt::Decl {
            name,
            init: Some(CExpr::UIntLit(9)),
            ..
        } if *name == symbol
    ));
}

#[test]
fn final_scope_order_matches_do_while_execution() {
    let body_id = observation(0);
    let condition_id = observation(1);
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::DoWhile {
            body: Box::new(CStmt::observe_one(body_id, CStmt::Empty)),
            cond: CExpr::observe_one(condition_id, CExpr::UIntLit(1)),
        },
    ))
    .expect("sealed do-while");
    let (statement, regions) = sealed.into_marked_parts();
    let targets = vec![Some(PlacementObservationTarget::Other); 2];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);
    let order_of = |index| match scopes[index] {
        Some(FinalObservationScope::Exact { order, .. }) => order,
        other => panic!("expected exact scope, got {other:?}"),
    };
    assert!(order_of(0) < order_of(1));
}

#[test]
fn final_scope_order_matches_for_execution_phases() {
    let init_id = observation(0);
    let condition_id = observation(1);
    let body_id = observation(2);
    let update_id = observation(3);
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::For {
            init: Some(Box::new(CStmt::observe_one(init_id, CStmt::Empty))),
            cond: Some(CExpr::observe_one(condition_id, CExpr::UIntLit(1))),
            update: Some(CExpr::observe_one(update_id, CExpr::UIntLit(0))),
            body: Box::new(CStmt::observe_one(body_id, CStmt::Empty)),
        },
    ))
    .expect("sealed for");
    let (statement, regions) = sealed.into_marked_parts();
    let targets = vec![Some(PlacementObservationTarget::Other); 4];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);
    let order_of = |index| match scopes[index] {
        Some(FinalObservationScope::Exact { order, .. }) => order,
        other => panic!("expected exact scope, got {other:?}"),
    };
    assert!(order_of(0) < order_of(1));
    assert!(order_of(1) < order_of(2));
    assert!(order_of(2) < order_of(3));
}

#[test]
fn final_scope_sequences_comma_reads_output_write_and_later_read() {
    let operand_read = observation(0);
    let output_write = observation(1);
    let later_read = observation(2);
    let expression = CExpr::Comma(vec![
        CExpr::observe_one(
            output_write,
            CExpr::observe_one(operand_read, CExpr::UIntLit(1)),
        ),
        CExpr::observe_one(later_read, CExpr::UIntLit(2)),
    ]);
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Expr(expression),
    ))
    .expect("sealed comma expression");
    let (statement, regions) = sealed.into_marked_parts();
    let targets = [
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(0),
                input_idx: 0,
            },
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Write {
            inst: InstId(1),
            projection: r2ssa::MachineWriteProjection::Full,
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(2),
                input_idx: 0,
            },
            block: 0x1000,
        }),
    ];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);
    let order_of = |index| match scopes[index] {
        Some(FinalObservationScope::Exact { order, .. }) => order,
        other => panic!("expected exact scope, got {other:?}"),
    };

    assert!(order_of(0) < order_of(1));
    assert!(order_of(1) < order_of(2));
}

#[test]
fn final_scope_refuses_alternative_write_phase() {
    let branch_write = observation(0);
    let competing_read = observation(1);
    let expression = CExpr::Ternary {
        cond: Box::new(CExpr::UIntLit(1)),
        then_expr: Box::new(CExpr::observe_one(branch_write, CExpr::UIntLit(2))),
        else_expr: Box::new(CExpr::observe_one(competing_read, CExpr::UIntLit(3))),
    };
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Expr(expression),
    ))
    .expect("sealed alternative expression");
    let (statement, regions) = sealed.into_marked_parts();
    let targets = [
        Some(PlacementObservationTarget::Write {
            inst: InstId(0),
            projection: r2ssa::MachineWriteProjection::Full,
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(1),
                input_idx: 0,
            },
            block: 0x1000,
        }),
    ];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);

    assert_eq!(scopes[0], Some(FinalObservationScope::Ambiguous));
    assert_eq!(scopes[1], Some(FinalObservationScope::Ambiguous));
}

#[test]
fn final_scope_refuses_unsequenced_write_phase() {
    let operand_write = observation(0);
    let competing_read = observation(1);
    let expression = CExpr::binary(
        BinaryOp::Add,
        CExpr::observe_one(operand_write, CExpr::UIntLit(1)),
        CExpr::observe_one(competing_read, CExpr::UIntLit(2)),
    );
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Expr(expression),
    ))
    .expect("sealed unsequenced expression");
    let (statement, regions) = sealed.into_marked_parts();
    let targets = [
        Some(PlacementObservationTarget::Write {
            inst: InstId(0),
            projection: r2ssa::MachineWriteProjection::Full,
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(1),
                input_idx: 0,
            },
            block: 0x1000,
        }),
    ];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);

    assert_eq!(scopes[0], Some(FinalObservationScope::Ambiguous));
    assert_eq!(scopes[1], Some(FinalObservationScope::Ambiguous));
}

#[test]
fn final_scope_sequences_direct_stack_assignment_after_its_value() {
    let stack_write = observation(0);
    let elided_address_use = observation(1);
    let value_read = observation(2);
    let symbols = std::rc::Rc::new(std::cell::RefCell::new(SymbolTable::new()));
    let symbol = symbols.borrow_mut().declare(
        "stack_m16",
        crate::ast::CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Unsigned,
        },
        SymbolRole::StackLocal(-16),
    );
    let expression = CExpr::assign(
        CExpr::observe_one(
            elided_address_use,
            CExpr::observe_one(stack_write, CExpr::Var(symbol)),
        ),
        CExpr::observe_one(value_read, CExpr::UIntLit(7)),
    );
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Expr(expression),
    ))
    .expect("sealed stack assignment");
    let (statement, regions) = sealed.into_marked_parts();
    let binding = BindingId::from_dense_index(0).expect("binding");
    let targets = [
        Some(PlacementObservationTarget::StackAccess {
            access: r2ssa::StructuredAccessId {
                inst: InstId(0),
                ordinal: 0,
            },
            object: r2ssa::ObjectId(0),
            binding,
            symbol,
            is_write: true,
            rendered_block: None,
        }),
        Some(PlacementObservationTarget::Other),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(0),
                input_idx: 0,
            },
            block: 0x1000,
        }),
    ];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);
    let order_of = |index| match scopes[index] {
        Some(FinalObservationScope::Exact { order, .. }) => order,
        other => panic!("expected exact scope, got {other:?}"),
    };

    assert!(order_of(2) < order_of(0));
    assert_eq!(scopes[1], None);
}

#[test]
fn final_scope_sequences_direct_stack_array_assignment_after_its_index_and_value() {
    let stack_write = observation(0);
    let address_use = observation(1);
    let index_read = observation(2);
    let value_read = observation(3);
    let symbols = std::rc::Rc::new(std::cell::RefCell::new(SymbolTable::new()));
    let symbol = symbols.borrow_mut().declare(
        "stack_m64",
        crate::ast::CType::Array(Box::new(crate::ast::CType::u8()), Some(64)),
        SymbolRole::StackLocal(-64),
    );
    let index = symbols
        .borrow_mut()
        .declare("i", crate::ast::CType::u64(), SymbolRole::Carrier);
    let expression = CExpr::assign(
        CExpr::observe_one(
            address_use,
            CExpr::observe_one(
                stack_write,
                CExpr::Subscript {
                    base: Box::new(CExpr::cast(
                        crate::ast::CType::ptr(crate::ast::CType::i8()),
                        CExpr::Var(symbol),
                    )),
                    index: Box::new(CExpr::observe_one(index_read, CExpr::Var(index))),
                },
            ),
        ),
        CExpr::observe_one(value_read, CExpr::UIntLit(7)),
    );
    let sealed = seal_structured_body(CStmt::structured_region(
        StructuredRegionMarker::unsealed(0x1000, StructuredRegionKind::FunctionBody),
        CStmt::Expr(expression),
    ))
    .expect("sealed stack array assignment");
    let (statement, regions) = sealed.into_marked_parts();
    let binding = BindingId::from_dense_index(0).expect("binding");
    let targets = [
        Some(PlacementObservationTarget::StackAccess {
            access: r2ssa::StructuredAccessId {
                inst: InstId(0),
                ordinal: 0,
            },
            object: r2ssa::ObjectId(0),
            binding,
            symbol,
            is_write: true,
            rendered_block: None,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(0),
                input_idx: 0,
            },
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(0),
                input_idx: 1,
            },
            block: 0x1000,
        }),
        Some(PlacementObservationTarget::Use {
            site: UseSite {
                inst: InstId(0),
                input_idx: 2,
            },
            block: 0x1000,
        }),
    ];
    let scopes = collect_final_observation_scopes(&[statement], &regions, &targets);
    let order_of = |index| match scopes[index] {
        Some(FinalObservationScope::Exact { order, .. }) => order,
        other => panic!("expected exact scope, got {other:?}"),
    };

    assert!(order_of(3) < order_of(1));
    assert_eq!(order_of(1), order_of(2));
    assert!(order_of(2) < order_of(0));
}
