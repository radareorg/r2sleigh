//! Building an SSA function from lifted blocks.

use super::*;

impl SSAFunction {
    #[cfg(test)]
    pub(crate) fn from_exact_test_blocks(blocks: &[SSABlock], cfg: CFG) -> Self {
        let entry = cfg.entered_at();
        let domtree = DomTree::compute(&cfg);
        let block_order = cfg.reverse_postorder();
        // The entry-edge block is the graph's own, not one of the program's:
        // a test that writes the program's blocks gets it from the graph.
        let ordered = block_order
            .iter()
            .filter_map(|addr| {
                blocks
                    .iter()
                    .find(|block| block.addr == *addr)
                    .cloned()
                    .or_else(|| {
                        (*addr == crate::cfg::ENTRY_EDGE)
                            .then(|| SSABlock::new(crate::cfg::ENTRY_EDGE, 0))
                    })
            })
            .collect::<Vec<SSABlock>>();
        let mut values = crate::value_table::ValueTable::default();
        let ordered = ordered
            .iter()
            .map(|block| block.map_operands(&mut |var| values.intern(var)))
            .collect::<Vec<_>>();
        Self {
            call_preserved_carriers: None,
            supervisor_calls: BTreeSet::new(),
            promoted_slots: crate::dense::IdSet::default(),
            compiler_inserted: crate::dense::IdSet::default(),
            compiler_inserted_blocks: BTreeSet::new(),
            premises: BTreeSet::new(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            natural_loops: std::sync::OnceLock::new(),
            block_index: block_index_of(&ordered),
            blocks: Blocks::adopting(ordered),
            values,
            block_order,
            formal_projections: crate::dense::IdMap::default(),
            formal_roots: crate::dense::IdMap::default(),
            entry_lanes: crate::dense::IdMap::default(),
            written: crate::lanes::Written::default(),
        }
    }

    /// Build an SSA function from a sequence of r2il blocks.
    pub fn from_blocks(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_with_arch(blocks, None)
    }

    /// Build an SSA function from blocks with constructor-time SCCP enabled.
    pub fn from_blocks_with_arch(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        let func = Self::from_blocks_raw(blocks, arch)?;
        // Constructor path applies SCCP by default while keeping legacy SSA consumers stable.
        let cfg = crate::optimize::OptimizationConfig {
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: false,
        };
        Lifted::new(func)
            .optimize_and_validate(&cfg, &UncheckedSsaWorkControl)
            .ok()
            .map(Prepared::into_function)
    }

    /// Build SSA prepared for decompilation.
    ///
    /// Unlike the generic constructor path, this preserves copy/cast and
    /// address-provenance roots by default and only applies explicitly
    /// configured decompiler-safe cleanup.
    pub fn from_blocks_for_decompile(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
    ) -> Option<Self> {
        Self::from_blocks_for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build decompiler-prepared SSA while polling expensive worklists.
    ///
    /// The function is constructed locally and returned only after every
    /// preparation and canonicalization phase completes.
    pub fn from_blocks_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::none(),
            &SourceMachineContext::from_blocks(blocks, arch),
            &CalleeBoundaries::default(),
            None,
            control,
        )
        .map(Prepared::into_function)
    }

    /// Decompile-prepared SSA under a machine context the test built.
    #[cfg(test)]
    pub(crate) fn for_decompile_under(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        machine_context: &SourceMachineContext,
    ) -> Option<Self> {
        Self::from_blocks_for_decompile_with_interface_and_control(
            blocks,
            arch,
            InterfaceQuestions::none(),
            machine_context,
            &CalleeBoundaries::default(),
            None,
            &UncheckedSsaWorkControl,
        )
        .ok()
        .map(Prepared::into_function)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_blocks_for_decompile_with_interface_and_control<
        C: SsaWorkControl + ?Sized,
    >(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        questions: InterfaceQuestions<'_>,
        machine_context: &SourceMachineContext,
        callees: &CalleeBoundaries,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        control: &C,
    ) -> Result<Prepared, SsaPrepareError> {
        let call_preserved_carriers = machine_context.call_preserved_carriers();
        let stack_pointer_carrier = machine_context.stack_pointer_carrier();
        // The lifted text as it arrived, for a reader tracing a defect that
        // the SSA may already have folded away; the SSA dump is r2dec's.
        if dump_il() {
            for block in blocks {
                eprintln!("R2IL block {:#x} ({} ops)", block.addr, block.ops.len());
                for (index, op) in block.ops.iter().enumerate() {
                    eprintln!("  {index}: {op:?}");
                }
            }
        }
        control.poll()?;
        // The convention says the callee leaves this carrier where it found
        // it, and the machine's own p-code moved it to transfer control. Both
        // halves have to be in hand before SSA construction, because it is
        // construction that decides which value each later read of the carrier
        // sees.
        let stack_pointer_restored_by_callee = stack_pointer_carrier
            .filter(|_| call_preserved_carriers.is_some_and(|carriers| carriers.stack_pointer()));
        // The carriers the convention names at this function's own boundary:
        // every caller reads the result register and writes the argument
        // registers, so the whole of each is used even where the body's own
        // operations name only a lane of one.
        let abi_carriers = questions.construction_carriers();

        let cfg = lifted_cfg(blocks, declared_successors)?;
        // The same phase report the semantic collector gives, for the half of
        // a decompile's bytes that are already held before the collector runs.
        // Construction is three passes over the same body and they do not cost
        // alike; without this the whole of it is one number.
        let started = std::time::Instant::now();
        let held = std::cell::Cell::new(r2il::allocation::live_bytes());
        let phase = |name: &str, size: usize| {
            let live = r2il::allocation::live_bytes();
            let grew = live.saturating_sub(held.get());
            held.set(live);
            r2il::refusal_evidence!(
                "collect-phase",
                "build@{:#x}/{} {name} {} ms size {size} bytes {grew}",
                blocks.first().map_or(0, |block| block.addr),
                blocks.len(),
                started.elapsed().as_millis()
            );
        };
        let mut func = Self::from_blocks_raw_for_decompile_with_carriers_and_control(
            blocks,
            cfg,
            arch,
            machine_context,
            stack_pointer_restored_by_callee,
            callees,
            &abi_carriers,
            control,
        )?;
        phase("raw", func.num_blocks());
        func.call_preserved_carriers = call_preserved_carriers;
        func.stack_pointer_carrier = stack_pointer_carrier;
        // Before preparation, so the arithmetic above the constant folds with it.
        func.forward_proven_call_return_addresses(callees);
        let promoted = crate::slot_promotion::promote(
            &mut func,
            machine_context,
            stack_pointer_restored_by_callee.is_some(),
        );
        func.record_promoted_slots(promoted);
        // Before preparation, so the comparison a decided check leaves unread folds away.
        crate::stack_protector::decide(&mut func, machine_context);
        // Preparation reads the interface for the return projection only;
        // the prep facts, collected when the function is sealed, read it for
        // the declared stack bases.
        let prepared = Lifted::new(func).prepare(
            &crate::optimize::DecompilePrepConfig::default(),
            questions.return_carrier(),
            control,
        )?;
        phase("prepared", prepared.num_blocks());
        control.poll()?;
        Ok(prepared)
    }

    /// Build SSA prepared for pattern/type inference.
    ///
    /// This keeps memory reads and address arithmetic intact while still
    /// applying limited whole-function SCCP so layout-sensitive patterns
    /// collapse to a canonical indexed+offset form for downstream consumers.
    pub fn from_blocks_for_patterns(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::from_blocks_for_patterns_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build pattern/type-inference SSA while polling expensive worklists.
    pub fn from_blocks_for_patterns_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        let func = Self::from_blocks_raw_with_policy_and_control(
            lifted_cfg(blocks, None)?,
            arch,
            None,
            &[],
            control,
        )?;
        let cfg = crate::optimize::OptimizationConfig {
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: true,
        };
        let prepared = Lifted::new(func).optimize_and_validate(&cfg, control)?;
        control.poll()?;
        Ok(prepared.into_function())
    }

    /// Build an SSA function from blocks without running optimization passes.
    ///
    /// This performs raw SSA construction:
    /// 1. Build CFG from blocks
    /// 2. Compute dominator tree
    /// 3. Place phi nodes
    /// 4. Rename variables
    pub fn from_blocks_raw(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        Self::from_blocks_raw_with_control(blocks, arch, &UncheckedSsaWorkControl).ok()
    }

    /// Build raw SSA while polling the caller's cancellation and deadline.
    ///
    /// Renaming a whole function is not work a caller can abandon once it has
    /// started, so a preflight that builds raw SSA only to inspect it needs
    /// this seam: without it the poll-free builder runs to completion past a
    /// deadline the request has already missed.
    pub fn from_blocks_raw_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_raw_with_policy_and_control(
            lifted_cfg(blocks, None)?,
            arch,
            None,
            &[],
            control,
        )
    }

    /// Build raw SSA prepared with decompiler-safe call boundaries.
    pub fn from_blocks_raw_for_decompile(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
    ) -> Option<Self> {
        Self::from_blocks_raw_for_decompile_with_control(blocks, arch, &UncheckedSsaWorkControl)
            .ok()
    }

    /// Build raw decompiler SSA while polling construction worklists.
    pub fn from_blocks_raw_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        Self::from_blocks_raw_for_decompile_with_carriers_and_control(
            blocks,
            lifted_cfg(blocks, None)?,
            arch,
            &SourceMachineContext::from_blocks(blocks, arch),
            None,
            &CalleeBoundaries::default(),
            &[],
            control,
        )
    }

    /// The same, told which carrier the convention says a callee restores.
    #[allow(clippy::too_many_arguments)]
    fn from_blocks_raw_for_decompile_with_carriers_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        cfg: CFG,
        arch: Option<&ArchSpec>,
        machine_context: &SourceMachineContext,
        stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
        callees: &CalleeBoundaries,
        abi_carriers: &[CanonicalStorageId],
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let policy = decompile_call_boundary_config(
            blocks,
            arch,
            machine_context,
            stack_pointer_restored_by_callee,
            callees.clone(),
        )?;
        Self::from_blocks_raw_with_policy_and_control(
            cfg,
            arch,
            policy.as_ref(),
            abi_carriers,
            control,
        )
    }

    /// Construct SSA over the graph `lifted_cfg` built from the lifted blocks.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "keyed by name where there is no value table: renaming builds the names the table interns, the table's own interning index, or a one-instruction block"
        )
    )]
    fn from_blocks_raw_with_policy_and_control<C: SsaWorkControl + ?Sized>(
        cfg: CFG,
        arch: Option<&ArchSpec>,
        call_boundaries: Option<&CallBoundaryConfig>,
        abi_carriers: &[CanonicalStorageId],
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        // The function is named by the address it is entered at; the graph
        // may be rooted in front of it (`cfg::ENTRY_EDGE`).
        let entry = cfg.entered_at();

        // Compute dominator tree
        let domtree = DomTree::compute_with_control(&cfg, control)?;

        let reg_names = arch.map(cached_register_name_map);
        let reg_names_ref = reg_names.as_deref();
        // One identity per register family: a lane is renamed as a projection
        // of its root (doc/adr-register-identity.md).
        // One identity per register family, rooted at what this function
        // touches of it rather than at the widest name the architecture has.
        let families = arch.map(cached_register_family_info).map(|families| {
            let mut used = Vec::new();
            for block in cfg.blocks() {
                for op in &block.ops {
                    for varnode in op.inputs().into_iter().chain(op.output()) {
                        if matches!(varnode.space, r2il::SpaceId::Register) {
                            used.push((varnode.offset, varnode.size));
                        }
                    }
                }
            }
            // The carriers the convention names at this function's boundary.
            for carrier in abi_carriers {
                if carrier.space == CanonicalStorageSpace::Register {
                    used.push((carrier.offset, carrier.size));
                }
            }
            // A call's clobbers widen a root; a body that never calls has none.
            for storage in call_boundaries
                .into_iter()
                .flat_map(|config| &config.clobbered)
            {
                used.push((storage.offset, storage.size));
            }
            Arc::new(families.with_program_roots(used))
        });
        let families_ref = families.as_deref();

        // Collect variable definitions and sizes
        let (mut defs, mut storage_by_identity) =
            collect_defs_from_cfg_with_names_storage_and_control(
                &cfg,
                reg_names_ref,
                families_ref,
                control,
            )?;

        // Place phi nodes: at the iterated dominance frontier of each
        // identity's definitions, and, where the convention says what calls
        // and returns read, only where the identity is live on entry to the
        // merge (pruned SSA, Choi et al.). A merge nothing reads names no
        // program state: a Sleigh temporary never outlives its instruction,
        // so none of its merges is live. A call defines its convention's
        // registers, and renaming writes those definitions after placement,
        // so their sites are added to the definitions first.
        let phi_placement = if let Some(call_boundaries) = call_boundaries {
            crate::phi::add_call_boundary_def_sites(
                &cfg,
                call_boundaries,
                reg_names_ref,
                families_ref,
                &mut defs,
                &mut storage_by_identity,
            );
            let live_in = crate::phi::live_in_by_block(
                &cfg,
                call_boundaries,
                crate::phi::IdentityNaming {
                    reg_names: reg_names_ref,
                    families: families_ref,
                },
                &defs,
            );
            PhiPlacement::compute_with_storage_and_control(
                &cfg,
                &domtree,
                &defs,
                &storage_by_identity,
                control,
            )?
            .retain_live(&live_in)
        } else {
            // Without a convention nothing says what a return observes, so
            // every merge a definition reaches is kept.
            PhiPlacement::compute_with_storage_and_control(
                &cfg,
                &domtree,
                &defs,
                &storage_by_identity,
                control,
            )?
        };

        // Rename variables
        let renamed = rename_function(
            crate::rename::RenameInputs {
                cfg: &cfg,
                domtree: &domtree,
                phi_placement: &phi_placement,
                reg_names: reg_names_ref,
                call_boundaries,
            },
            &defs,
            families.clone(),
            control,
        )?;

        // Build SSA blocks. The renamed ops move across rather than being
        // cloned: holding both copies doubled every operation of the function,
        // and each operation owns up to four named variables.
        let mut renamed_blocks = renamed.blocks;
        let mut renamed_origins = renamed.origins;
        let renamed_block_order = renamed.block_order;
        let renamed_storage = renamed.canonical_storage_by_var;
        let mut shaped = Vec::with_capacity(renamed_block_order.len());
        for &addr in &renamed_block_order {
            control.poll()?;
            let cfg_block = cfg.get_block(addr).ok_or_else(malformed_ssa_input)?;
            let ops = renamed_blocks.remove(&addr).unwrap_or_default();
            let origins = renamed_origins.remove(&addr).unwrap_or_default();
            // Renaming keeps the two in step; an operation without its origin
            // beside it is malformed input, not an operation of no origin.
            if origins.len() != ops.len() {
                return Err(malformed_ssa_input());
            }

            // Separate phi nodes from other ops; the origins travel with them.
            let (phi_ops, other_ops): (Vec<_>, Vec<_>) = ops
                .into_iter()
                .zip(origins)
                .partition(|(op, _)| matches!(op, SSAOp::Phi { .. }));

            // Convert phi ops to PhiNode structs
            let preds = cfg.predecessors(addr);
            let mut phis = Vec::with_capacity(phi_ops.len());
            for (phi_idx, (op, _)) in phi_ops.into_iter().enumerate() {
                let SSAOp::Phi { dst, sources } = op else {
                    unreachable!("phi partition contains only phi operations");
                };
                if sources.len() != preds.len() {
                    return Err(malformed_ssa_input());
                }
                let phi_sources = sources
                    .into_iter()
                    .zip(preds.iter().copied())
                    .map(|(var, pred)| (pred, var))
                    .collect();
                let canonical_storage = phi_placement
                    .get_phis(addr)
                    .get(phi_idx)
                    .and_then(|phi| phi.storage);
                phis.push(PhiNode {
                    dst,
                    sources: phi_sources,
                    canonical_storage,
                });
            }
            shaped.push(ShapedBlock {
                addr,
                size: cfg_block.size,
                phis,
                ops: other_ops,
            });
        }
        let (arena, named_blocks) = mint_renamed_blocks(shaped);
        // The operations enter the function here, so this is where each
        // variable they name gets its id.
        let mut values = crate::value_table::ValueTable::default();
        let ssa_blocks = named_blocks
            .iter()
            .map(|block| block.map_operands(&mut |var| values.intern(var)))
            .collect::<Vec<_>>();
        // What the renamer learned of each variable's lifted storage joins
        // its row, including variables no operation names any more.
        for (var, storage) in renamed_storage {
            values.intern_with_storage(&var, storage);
        }
        let mut cfg = cfg;
        cfg.release_operations();
        let mut function = Self {
            call_preserved_carriers: None,
            supervisor_calls: arch
                .map(|arch| arch.supervisor_calls.iter().copied().collect())
                .unwrap_or_default(),
            promoted_slots: crate::dense::IdSet::default(),
            compiler_inserted: crate::dense::IdSet::default(),
            compiler_inserted_blocks: BTreeSet::new(),
            premises: BTreeSet::new(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            natural_loops: std::sync::OnceLock::new(),
            block_index: block_index_of(&ssa_blocks),
            block_order: renamed_block_order,
            blocks: Blocks::new(ssa_blocks, arena),
            values,
            formal_projections: crate::dense::IdMap::default(),
            formal_roots: crate::dense::IdMap::default(),
            entry_lanes: crate::dense::IdMap::default(),
            written: crate::lanes::Written::default(),
        };
        function.zero_scratch_insert_roots(abi_carriers);
        // The validator answers with a typed integrity error naming the block
        // and the edge it disagreed about; discarding it left the reader with
        // "malformed SSA source input" and nothing to look at.
        validate_ssa_function(&function).map_err(|error| {
            if r2il::refusal_evidence::tracing() {
                let mut addrs = function.block_order.clone();
                addrs.sort_unstable();
                eprintln!("ssa block domain ({}): {addrs:x?}", addrs.len());
            }
            r2il::refusal_evidence!("ssa-integrity", "{error:?}");
            malformed_ssa_input()
        })?;
        control.poll()?;
        Ok(function)
    }

    /// Build raw SSA without architecture metadata.
    pub fn from_blocks_raw_no_arch(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_raw(blocks, None)
    }
}

impl DecompilePrepFacts {
    /// Install the canonical source-boundary parameter projection. This
    /// deliberately accepts `ValueId` facts, then resolves the graph value
    /// back to its `SSAVar`; no register spelling participates in slot
    /// identity.
    pub(super) fn install_exact_formal_parameters(
        &mut self,
        graph: &SsaGraph,
        parameters: &BTreeMap<u32, crate::semantic::SourceFormalParameterFact>,
    ) {
        let prep = self;
        prep.formal_parameters = crate::dense::IdMap::new(graph.values.len());
        prep.formal_parameter_bases = crate::dense::IdMap::new(graph.values.len());
        for (slot, parameter) in parameters {
            let Ok(index) = usize::try_from(*slot) else {
                continue;
            };
            let Some(value) = graph.value(parameter.value) else {
                continue;
            };
            let entry_value = graph.def_inst(parameter.value).is_none()
                && value.var.version == 0
                && value.var.size == parameter.graph_storage.size
                && value.canonical_storage == Some(parameter.graph_storage);
            let projection =
                graph.formal_projection_storage(parameter.value) == Some(parameter.graph_storage);
            if parameter.index != *slot || !(entry_value || projection) {
                continue;
            }
            prep.formal_parameters.insert(parameter.value, index);
            if parameter.graph_storage == parameter.abi_storage {
                prep.formal_parameter_bases.insert(parameter.value, index);
            }
        }
    }
}

/// The graph of the lifted blocks, rooted where control enters
/// (`cfg::ENTRY_EDGE`). Built once per construction: promotion asks it whether
/// the entry block runs once, and construction renames over it.
fn lifted_cfg(
    blocks: &[R2ILBlock],
    declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
) -> Result<CFG, SsaPrepareError> {
    CFG::from_blocks_with_declared_successors(blocks, declared_successors)
        .ok_or_else(malformed_ssa_input)
}

/// One renamed block before its operations have ids: its address, size,
/// phis, and each operation with where renaming says it came from.
struct ShapedBlock {
    addr: u64,
    size: u32,
    phis: Vec<PhiNode>,
    ops: Vec<(SSAOp, crate::rename::RenamedOrigin)>,
}

/// Mint every operation of a freshly renamed function its id.
///
/// The lifted operations first, blocks in reverse postorder and each block's
/// in lift order, so that ids `0..n` are the lift's own operations in R2IL
/// order; then each block's phis and the operations renaming added, in the
/// order they stand. Both walks are over vectors, so the numbering is a
/// function of the IR alone.
fn mint_renamed_blocks(shaped: Vec<ShapedBlock>) -> (OpArena, Vec<SSABlock>) {
    use crate::arena::OpOrigin;
    use crate::rename::RenamedOrigin;
    let mut arena = OpArena::default();
    let lifted = shaped
        .iter()
        .map(|ShapedBlock { addr, ops, .. }| {
            ops.iter()
                .filter_map(|(_, origin)| match *origin {
                    RenamedOrigin::Lifted { index, instruction } => Some((
                        index,
                        arena.mint(OpOrigin::Lifted {
                            block: *addr,
                            index,
                            instruction,
                        }),
                    )),
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let blocks = shaped
        .into_iter()
        .zip(lifted)
        .map(
            |(
                ShapedBlock {
                    addr,
                    size,
                    phis,
                    ops,
                },
                lifted,
            )| {
                let phis = phis
                    .into_iter()
                    .map(|phi| {
                        let id = arena.mint(OpOrigin::Derived {
                            from: None,
                            pass: Pass::PhiPlacement,
                        });
                        (id, phi)
                    })
                    .collect();
                let ops = ops
                    .into_iter()
                    .map(|(op, origin)| {
                        let id = match origin {
                            RenamedOrigin::Lifted { index, .. } => lifted[&index],
                            RenamedOrigin::Derived { index } => arena.mint(OpOrigin::Derived {
                                from: lifted.get(&index).copied(),
                                pass: Pass::Rename,
                            }),
                            RenamedOrigin::Phi => arena.mint(OpOrigin::Derived {
                                from: None,
                                pass: Pass::PhiPlacement,
                            }),
                        };
                        (id, op)
                    })
                    .collect();
                SSABlock::from_sited(addr, size, ops, phis)
            },
        )
        .collect();
    (arena, blocks)
}
