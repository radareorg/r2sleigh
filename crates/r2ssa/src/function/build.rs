//! Building an SSA function from lifted blocks.

use super::*;

impl SSAFunction {
    #[cfg(test)]
    pub(crate) fn from_exact_test_blocks(blocks: &[SSABlock], cfg: CFG) -> Self {
        let entry = cfg
            .entry_block()
            .map(|block| block.addr)
            .unwrap_or_default();
        let domtree = DomTree::compute(&cfg);
        let block_order = cfg.reverse_postorder();
        let ordered = block_order
            .iter()
            .filter_map(|addr| blocks.iter().find(|block| block.addr == *addr).cloned())
            .collect::<Vec<_>>();
        Self {
            call_preserved_carriers: None,
            promoted_slot_sites: BTreeSet::new(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            block_index: block_index_of(&ordered),
            blocks: ordered,
            block_order,
            op_instruction_addrs: BTreeMap::new(),
            canonical_storage_by_var: BTreeMap::new(),
            formal_projections: BTreeMap::new(),
            decompile_prep_facts: None,
            query_index: RwLock::new(None),
        }
    }

    /// Build an SSA function from a sequence of r2il blocks.
    pub fn from_blocks(blocks: &[R2ILBlock]) -> Option<Self> {
        Self::from_blocks_with_arch(blocks, None)
    }

    /// Build an SSA function from blocks with constructor-time SCCP enabled.
    pub fn from_blocks_with_arch(blocks: &[R2ILBlock], arch: Option<&ArchSpec>) -> Option<Self> {
        let mut func = Self::from_blocks_raw(blocks, arch)?;
        // Constructor path applies SCCP by default while keeping legacy SSA consumers stable.
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: false,
        };
        func.optimize(&cfg);
        validate_ssa_function(&func).ok()?;
        Some(func)
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
            None,
            None,
            &CalleeBoundaries::default(),
            None,
            control,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_blocks_for_decompile_with_interface_and_control<
        C: SsaWorkControl + ?Sized,
    >(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        questions: InterfaceQuestions<'_>,
        call_preserved_carriers: Option<SourceCallPreservedCarriers>,
        stack_pointer_carrier: Option<CanonicalStorageId>,
        callees: &CalleeBoundaries,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
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
        let stack_pointer_restored_by_callee = stack_pointer_carrier.filter(|_| {
            stack_pointer_restored_across_calls(
                call_preserved_carriers,
                questions.for_machine_carriers(),
            )
        });
        // The carriers the convention names at this function's own boundary:
        // every caller reads the result register and writes the argument
        // registers, so the whole of each is used even where the body's own
        // operations name only a lane of one.
        let abi_carriers = questions
            .for_argument_placement()
            .into_iter()
            .flat_map(|interface| {
                interface
                    .parameters()
                    .iter()
                    .filter_map(crate::SourceAbiParameterSpec::register_storage)
            })
            .chain(questions.for_return_boundary().and_then(|interface| {
                match interface.return_kind() {
                    crate::SourceFunctionReturn::Register { storage } => Some(storage),
                    crate::SourceFunctionReturn::Void | crate::SourceFunctionReturn::Unproven => {
                        None
                    }
                }
            }))
            .collect::<Vec<_>>();

        // Which frame slots behave like variables. Asked of the lifted text,
        // before construction, because construction is what decides which
        // value each read of a variable sees.
        let promoted = crate::promote::promote_private_stack_slots(
            blocks,
            stack_pointer_carrier,
            questions.interface,
            &abi_carriers,
            stack_pointer_restored_by_callee.is_some(),
        )
        .unwrap_or_default();
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
            arch,
            stack_pointer_restored_by_callee,
            callees,
            declared_successors,
            &abi_carriers,
            &promoted,
            control,
        )?;
        phase("raw", func.num_blocks());
        func.call_preserved_carriers = call_preserved_carriers;
        func.stack_pointer_carrier = stack_pointer_carrier;
        // Before preparation, so the arithmetic above the constant folds with it.
        func.forward_proven_call_return_addresses(callees);
        // Preparation reads the interface for the return projection only.
        func.prepare_for_decompile_with_interface_and_control(
            &crate::optimize::DecompilePrepConfig::default(),
            questions.for_return_boundary(),
            control,
        )?;
        phase("prepared", func.num_blocks());
        // The prep facts read it for the declared stack bases.
        func.refresh_decompile_prep_facts_with_interface_and_control(
            questions.for_frame_geometry(),
            control,
        )?;
        phase("prep_facts", func.num_blocks());
        validate_ssa_function(&func).map_err(|error| {
            r2il::refusal_evidence!("ssa-integrity", "{error:?}");
            malformed_ssa_input()
        })?;
        phase("validated", 0);
        control.poll()?;
        Ok(func)
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
        let mut func = Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            None,
            None,
            &[],
            &Default::default(),
            control,
        )?;
        let cfg = crate::optimize::OptimizationConfig {
            max_iterations: 1,
            enable_sccp: true,
            enable_inst_combine: false,
            preserve_memory_reads: true,
        };
        func.decompile_prep_facts = None;
        func.invalidate_query_index();
        crate::optimize::optimize_function_with_control(&mut func, &cfg, control)?;
        validate_ssa_function(&func).map_err(|_| malformed_ssa_input())?;
        func.refresh_decompile_prep_facts_with_control(control)?;
        control.poll()?;
        Ok(func)
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
            blocks,
            arch,
            None,
            None,
            &[],
            &Default::default(),
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
            arch,
            None,
            &CalleeBoundaries::default(),
            None,
            &[],
            &Default::default(),
            control,
        )
    }

    /// The same, told which carrier the convention says a callee restores.
    #[allow(clippy::too_many_arguments)]
    fn from_blocks_raw_for_decompile_with_carriers_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        stack_pointer_restored_by_callee: Option<CanonicalStorageId>,
        callees: &CalleeBoundaries,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
        promoted: &crate::phi::PromotedStackSlots,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        let policy =
            decompile_call_boundary_config(arch, stack_pointer_restored_by_callee, callees.clone());
        Self::from_blocks_raw_with_policy_and_control(
            blocks,
            arch,
            policy.as_ref(),
            declared_successors,
            abi_carriers,
            promoted,
            control,
        )
    }

    fn from_blocks_raw_with_policy_and_control<C: SsaWorkControl + ?Sized>(
        blocks: &[R2ILBlock],
        arch: Option<&ArchSpec>,
        call_boundaries: Option<&CallBoundaryConfig>,
        declared_successors: Option<&crate::cfg::DeclaredSuccessors>,
        abi_carriers: &[CanonicalStorageId],
        promoted: &crate::phi::PromotedStackSlots,
        control: &C,
    ) -> Result<Self, SsaPrepareError> {
        control.poll()?;
        if blocks.is_empty() {
            return Err(malformed_ssa_input());
        }

        // Build CFG
        let cfg = CFG::from_blocks_with_declared_successors(blocks, declared_successors)
            .ok_or_else(malformed_ssa_input)?;
        control.poll()?;
        let entry = cfg.entry;

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
            // A convention's clobber list describes what a call does, so it
            // widens a root only in a function that makes one.
            let calls = cfg.blocks().any(|block| {
                block
                    .ops
                    .iter()
                    .any(|op| matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }))
            });
            if let Some(call_boundaries) = call_boundaries.filter(|_| calls) {
                for reg in &call_boundaries.defined_regs {
                    if let Some(slot) = families.slot_for_name(&reg.name) {
                        used.push((slot.offset, reg.size.max(slot.width)));
                    }
                }
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
                promoted,
                control,
            )?;

        // Place phi nodes
        let mut phi_placement = PhiPlacement::compute_with_storage_and_control(
            &cfg,
            &domtree,
            &defs,
            &storage_by_identity,
            control,
        )?;
        // A call defines its convention's registers, and renaming writes those
        // definitions after placement has run, so the merges they need are
        // added here -- pruned, because an unread merge only invents a live-in.
        if let Some(call_boundaries) = call_boundaries {
            crate::phi::add_call_boundary_def_sites(
                &cfg,
                call_boundaries,
                reg_names_ref,
                families_ref,
                &mut defs,
                &mut storage_by_identity,
            );
            let complete = PhiPlacement::compute_with_storage_and_control(
                &cfg,
                &domtree,
                &defs,
                &storage_by_identity,
                control,
            )?;
            let live_in = crate::phi::live_in_by_block(
                &cfg,
                call_boundaries,
                reg_names_ref,
                families_ref,
                &defs,
            );
            phi_placement.merge_live_additions(complete, &live_in);
        }

        // Rename variables
        let renamed = rename_function(
            crate::rename::RenameInputs {
                cfg: &cfg,
                domtree: &domtree,
                phi_placement: &phi_placement,
                reg_names: reg_names_ref,
                call_boundaries,
                promoted,
            },
            &defs,
            families.clone(),
            control,
        )?;

        // Build SSA blocks. The renamed ops move across rather than being
        // cloned: holding both copies doubled every operation of the function,
        // and each operation owns up to four named variables.
        let mut renamed_blocks = renamed.blocks;
        let mut renamed_addrs = renamed.instruction_addrs;
        let renamed_block_order = renamed.block_order;
        let renamed_storage = renamed.canonical_storage_by_var;
        let mut ssa_blocks = Vec::with_capacity(renamed_block_order.len());
        let mut op_instruction_addrs = BTreeMap::new();
        for &addr in &renamed_block_order {
            control.poll()?;
            let cfg_block = cfg.get_block(addr).ok_or_else(malformed_ssa_input)?;
            let ops = renamed_blocks.remove(&addr).unwrap_or_default();
            let mut instruction_addrs = renamed_addrs.remove(&addr).unwrap_or_default();
            // Renaming keeps the two in step; an operation with no address
            // beside it would silently take the next operation's, so the
            // shorter vector is padded rather than trusted.
            instruction_addrs.resize(ops.len(), None);

            // Separate phi nodes from other ops. The addresses travel with
            // them: a phi is dropped and every other operation keeps the
            // instruction it was emitted for, at its new index.
            let (phi_ops, other_ops): (Vec<_>, Vec<_>) = ops
                .into_iter()
                .zip(instruction_addrs)
                .partition(|(op, _)| matches!(op, SSAOp::Phi { .. }));
            let phi_ops = phi_ops.into_iter().map(|(op, _)| op).collect::<Vec<_>>();
            op_instruction_addrs.extend(
                other_ops
                    .iter()
                    .enumerate()
                    .filter_map(|(op_idx, (_, from))| Some(((addr, op_idx), (*from)?))),
            );
            let other_ops = other_ops.into_iter().map(|(op, _)| op).collect::<Vec<_>>();

            // Convert phi ops to PhiNode structs
            let preds = cfg.predecessors(addr);
            let mut phis = Vec::with_capacity(phi_ops.len());
            for (phi_idx, op) in phi_ops.into_iter().enumerate() {
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

            let ssa_block = SSABlock {
                addr,
                size: cfg_block.size,
                ops: other_ops,
                phis,
            };
            ssa_blocks.push(ssa_block);
        }

        let mut cfg = cfg;
        cfg.release_operations();
        let mut function = Self {
            call_preserved_carriers: None,
            promoted_slot_sites: promoted.keys().copied().collect(),
            stack_pointer_carrier: None,
            name: None,
            entry,
            cfg,
            domtree,
            block_index: block_index_of(&ssa_blocks),
            block_order: renamed_block_order,
            blocks: ssa_blocks,
            op_instruction_addrs,
            canonical_storage_by_var: renamed_storage,
            formal_projections: BTreeMap::new(),
            decompile_prep_facts: None,
            query_index: RwLock::new(None),
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

    pub fn refresh_after_cfg_mutation(&mut self) {
        self.blocks
            .retain(|block| self.cfg.get_block(block.addr).is_some());
        self.block_order = self.cfg.reverse_postorder();
        self.reorder_blocks();
        self.domtree = DomTree::compute(&self.cfg);
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
    }

    /// Prepare SSA for decompilation using provenance-preserving defaults.
    pub fn prepare_for_decompile(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
    ) -> crate::optimize::OptimizationStats {
        self.prepare_for_decompile_with_control(config, &UncheckedSsaWorkControl)
            .expect("unchecked decompiler preparation cannot stop")
    }

    fn prepare_for_decompile_with_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
        control: &C,
    ) -> Result<crate::optimize::OptimizationStats, SsaExecutionStopReason> {
        self.prepare_for_decompile_with_interface_and_control(config, None, control)
    }

    fn prepare_for_decompile_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        config: &crate::optimize::DecompilePrepConfig,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<crate::optimize::OptimizationStats, SsaExecutionStopReason> {
        control.poll()?;
        self.decompile_prep_facts = None;
        self.invalidate_query_index();
        let cfg: crate::optimize::OptimizationConfig = config.into();
        crate::optimize::optimize_function_with_interface_and_control(
            self,
            &cfg,
            function_interface,
            control,
        )
    }

    pub(crate) fn install_exact_formal_parameters(
        &mut self,
        graph: &SsaGraph,
        parameters: &BTreeMap<u32, crate::semantic::SourceFormalParameterFact>,
    ) {
        let Some(prep) = self.decompile_prep_facts.as_mut() else {
            return;
        };
        prep.formal_parameters.clear();
        prep.formal_parameter_bases.clear();
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
            prep.formal_parameters.insert(value.var.clone(), index);
            if parameter.graph_storage == parameter.abi_storage {
                prep.formal_parameter_bases.insert(value.var.clone(), index);
            }
        }
    }

    /// Record every value that is a formal parameter, and which one.
    ///
    /// A formal reaches its uses through more than the storage it entered in:
    /// a copy, a widening, a lane projection and the reload of the slot the
    /// prologue spilled it to all deliver the same value. Four call sites each
    /// answered that question with their own partial walk, and none of them
    /// reached the reload. The address facts already answer it exactly -- they
    /// seed from the ABI storages and propagate through those steps, across
    /// the frame included -- so a value is the formal when its parameter
    /// expression names one with nothing added to it. What
    /// `install_exact_formal_parameters` proved is authoritative and is not
    /// overwritten here.
    pub(crate) fn install_formal_parameter_identity(
        &mut self,
        graph: &SsaGraph,
        addresses: &crate::AddressProvenanceFacts,
    ) {
        let Some(prep) = self.decompile_prep_facts.as_mut() else {
            return;
        };
        let exact = prep.formal_parameters.len();
        for (value, expression) in &addresses.parameter_expressions {
            if !expression.terms.is_empty() || expression.offset != 0 {
                continue;
            }
            let Some(var) = graph.value(*value).map(|value| value.var.clone()) else {
                continue;
            };
            prep.formal_parameters
                .entry(var)
                .or_insert(expression.parameter);
        }
        r2il::refusal_evidence!(
            "formal-identity",
            "{} values are a formal, {exact} of them proved at entry, from {} parameter expressions",
            prep.formal_parameters.len(),
            addresses.parameter_expressions.len()
        );
    }

    /// Refresh the cached decompiler-prep facts for the current SSA state.
    pub fn refresh_decompile_prep_facts(&mut self) {
        self.refresh_decompile_prep_facts_with_interface_and_control(
            None,
            &UncheckedSsaWorkControl,
        )
        .expect("unchecked decompiler fact collection cannot stop");
    }

    fn refresh_decompile_prep_facts_with_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        self.refresh_decompile_prep_facts_with_interface_and_control(None, control)
    }

    fn refresh_decompile_prep_facts_with_interface_and_control<C: SsaWorkControl + ?Sized>(
        &mut self,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        let facts = self.collect_decompile_prep_facts_with_control(function_interface, control)?;
        control.poll()?;
        self.decompile_prep_facts = Some(facts);
        Ok(())
    }
}
