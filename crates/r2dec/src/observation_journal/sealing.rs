//! What closes the journal, and what the closure accounts for.

use super::*;

impl LegacyObservationJournal {
    pub(crate) fn placement_target_count(&self) -> usize {
        self.targets.len()
    }

    pub(crate) fn placement_target(
        &self,
        id: RenderObservationId,
    ) -> Option<crate::placement::PlacementObservationTarget> {
        match self.targets.get(id.index() as usize)? {
            ObservationTarget::CertifiedValueRead {
                value,
                source,
                binding,
                symbol,
            } => Some(
                crate::placement::PlacementObservationTarget::CertifiedValueRead {
                    value: *value,
                    source: *source,
                    binding: *binding,
                    symbol: *symbol,
                },
            ),
            ObservationTarget::CertifiedArrayIndexRead {
                access,
                value,
                binding,
                symbol,
            } => Some(
                crate::placement::PlacementObservationTarget::CertifiedArrayIndexRead {
                    access: *access,
                    value: *value,
                    binding: *binding,
                    symbol: *symbol,
                },
            ),
            // An elided use is not an occurrence: nothing spells the value
            // there, so placement has no read to place.
            ObservationTarget::Use {
                observation: LegacyUseObservation::Elided(_),
                ..
            } => Some(crate::placement::PlacementObservationTarget::Other),
            ObservationTarget::Use { site, block, .. } => Some(
                self.source
                    .graph()
                    .inst(site.inst)
                    .and_then(|inst| inst.inputs.get(site.input_idx))
                    .and_then(|value| self.plan.disposition(*value))
                    .and_then(|disposition| {
                        matches!(disposition, ValueDisposition::Bound { .. }).then_some(
                            crate::placement::PlacementObservationTarget::Use {
                                site: *site,
                                block: *block,
                            },
                        )
                    })
                    .unwrap_or(crate::placement::PlacementObservationTarget::Other),
            ),
            ObservationTarget::Write {
                inst,
                observation,
                block,
            } => Some(
                self.source
                    .graph()
                    .inst(*inst)
                    .and_then(|inst| inst.output)
                    .and_then(|value| self.plan.disposition(value))
                    .and_then(|disposition| {
                        matches!(disposition, ValueDisposition::Bound { .. }).then(|| {
                            match observation {
                                LegacyWriteObservation::Exact(projection) => {
                                    crate::placement::PlacementObservationTarget::Write {
                                        inst: *inst,
                                        projection: *projection,
                                        block: *block,
                                    }
                                }
                                _ => crate::placement::PlacementObservationTarget::Other,
                            }
                        })
                    })
                    .unwrap_or(crate::placement::PlacementObservationTarget::Other),
            ),
            ObservationTarget::StackAccess {
                access,
                object,
                binding,
                symbol,
                is_write,
                rendered_block,
            } => Some(crate::placement::PlacementObservationTarget::StackAccess {
                access: *access,
                object: *object,
                binding: *binding,
                symbol: *symbol,
                is_write: *is_write,
                rendered_block: *rendered_block,
            }),
            ObservationTarget::ObjectAddress {
                value,
                object,
                binding,
                symbol,
                block,
            } => Some(
                crate::placement::PlacementObservationTarget::ObjectAddress {
                    value: *value,
                    object: *object,
                    binding: *binding,
                    symbol: *symbol,
                    block: *block,
                },
            ),
            // A gapped read of a value defined outside the gap is still a
            // read; one of a value the gap owns names nothing the output has.
            ObservationTarget::Gapped {
                cell: GapCell::Use { site, block },
                ..
            } => Some(
                self.source
                    .graph()
                    .inst(site.inst)
                    .and_then(|inst| inst.inputs.get(site.input_idx))
                    .filter(|value| !self.gapped_values.contains(value))
                    .and_then(|value| self.plan.disposition(*value))
                    .and_then(|disposition| {
                        matches!(disposition, ValueDisposition::Bound { .. }).then_some(
                            crate::placement::PlacementObservationTarget::Use {
                                site: *site,
                                block: *block,
                            },
                        )
                    })
                    .unwrap_or(crate::placement::PlacementObservationTarget::Other),
            ),
            ObservationTarget::Gapped { .. }
            | ObservationTarget::Value(_)
            | ObservationTarget::Effect(_) => {
                Some(crate::placement::PlacementObservationTarget::Other)
            }
        }
    }

    /// The cells each discharged instruction still owes, in canonical order:
    /// its write, the value it produced, and every operand it read.
    ///
    /// `rendered` is the value the caller has already marked, and `expr` is the
    /// expression standing in for the vanished statements. Both are absent when
    /// a *statement* discharges the instructions, and that absence is what
    /// distinguishes the two cases rather than a second copy of this walk. With
    /// an expression there is no statement left to answer for a definitionless
    /// inline operand, so its value cell is filled here unless a child marker
    /// already owns it. Bound operands are claimed only when the expression
    /// still names their exact planned symbol; otherwise attaching them to the
    /// parent would infer identity from unrelated C syntax. With a statement,
    /// its own markers already answer for operands, and filling them again
    /// would put two answers on one cell.
    pub(crate) fn discharged_instruction_targets(
        &mut self,
        rendered: Option<ValueId>,
        discharged: &[InstId],
        expr: Option<&CExpr>,
    ) -> Result<Vec<ObservationTarget>, LegacyObservationJournalError> {
        let rendered = rendered.into_iter().collect::<Vec<_>>();
        self.discharged_instruction_targets_with(&rendered, discharged, expr)
    }

    /// The discharge walk with every value the expression already stands for.
    pub(crate) fn discharged_instruction_targets_with(
        &mut self,
        rendered: &[ValueId],
        discharged: &[InstId],
        expr: Option<&CExpr>,
    ) -> Result<Vec<ObservationTarget>, LegacyObservationJournalError> {
        let mut targets = Vec::new();
        let mut represented_values: BTreeSet<ValueId> = rendered.iter().copied().collect();
        if let Some(expr) = expr {
            represented_values.extend(self.expr_value_observations(expr));
        }
        let rendered_symbols = expr.map_or_else(BTreeSet::new, Self::expr_symbols);
        let mut order = discharged.to_vec();
        order.sort_unstable();
        order.dedup();
        let produced = order
            .iter()
            .filter_map(|definition| self.source.graph().inst(*definition)?.output)
            .collect::<BTreeSet<_>>();
        for definition in order {
            let block = self
                .source
                .inst_op_site(definition)
                .map(|(block, _)| block)
                .unwrap_or_default();
            let inst = self
                .source
                .graph()
                .inst(definition)
                .ok_or(LegacyObservationJournalError::InvalidWrite(definition))?;
            // Stack geometry the rewriter folded into an object's address is
            // still the certificate's: none of its cells is an occurrence.
            if inst
                .output
                .is_some_and(|output| self.stack_geometry_elides(output))
            {
                continue;
            }
            // The write the vanished statement performed. Its result is part
            // of the expression now standing in the reader's place.
            if let Some(output) = inst.output {
                if expr.is_some()
                    && !rendered.contains(&output)
                    && !matches!(
                        self.plan.disposition(output),
                        Some(ValueDisposition::Inline { .. })
                    )
                {
                    return Err(LegacyObservationJournalError::rendered_value_required(
                        output,
                        RenderedValueRequirementCause::NonrenderedValueDisposition,
                        self.plan.disposition(output),
                    ));
                }
                let observation = self.rendered_write_observation(definition)?;
                targets.push(ObservationTarget::Write {
                    inst: definition,
                    observation,
                    block,
                });
                if represented_values.insert(output) {
                    self.value_slot(output)?;
                    targets.push(ObservationTarget::Value(output));
                }
            }
            // Every operand the vanished statement read. One a certificate
            // already answered -- the stack base an address was computed
            // from -- is spelled nowhere in what stands here, and stays its.
            for input_idx in 0..inst.inputs.len() {
                let site = UseSite {
                    inst: definition,
                    input_idx,
                };
                if matches!(
                    self.uses
                        .get(definition.0 as usize)
                        .and_then(|row| row.get(input_idx)),
                    Some(Some(LegacyUseObservation::Elided(_)))
                ) {
                    continue;
                }
                let input = inst.inputs[input_idx];
                let bound_symbol_spelled =
                    |journal: &Self, binding: crate::binding_plan::BindingId| {
                        journal
                            .names
                            .symbol_for_binding(binding)
                            .is_some_and(|symbol| rendered_symbols.contains(&symbol))
                    };
                // The base a stack address was computed from is absorbed by
                // the object's name: `&slot` spells the slot, never the stack
                // pointer it was measured from. That read is not an
                // occurrence, and saying it was rendered would leave the
                // pointer's value cell owed to nothing.
                if expr.is_some() && self.stack_base_absorbed_by(input, &rendered_symbols) {
                    targets.push(ObservationTarget::Use {
                        site,
                        observation: LegacyUseObservation::Elided(
                            crate::ledger::ElisionReason::DeadStackBase,
                        ),
                        block,
                    });
                    continue;
                }
                // A stack address the plan never renders -- the frame pointer
                // an address was measured from -- is absorbed the same way:
                // the object's name stands for every step from the frame to it.
                if expr.is_some()
                    && !matches!(
                        self.plan.disposition(input),
                        Some(ValueDisposition::Bound { .. })
                    )
                    && self
                        .source
                        .objects()
                        .object_for_value(input, r2il::SpaceId::Ram)
                        .is_some()
                {
                    targets.push(ObservationTarget::Use {
                        site,
                        observation: LegacyUseObservation::Elided(
                            crate::ledger::ElisionReason::DeadStackBase,
                        ),
                        block,
                    });
                    continue;
                }
                let observation = self.rendered_use_observation(site)?;
                r2il::refusal_evidence!(
                    "discharged-operand",
                    "{site:?} accounted as {observation:?} by the expression standing for {rendered:?}"
                );
                targets.push(ObservationTarget::Use {
                    site,
                    observation,
                    block,
                });
                let Some(_expr) = expr else {
                    continue;
                };
                if !produced.contains(&input) && !represented_values.contains(&input) {
                    let needs_value_target = match self.plan.disposition(input) {
                        // A discharge owns this exact use, but it can claim the
                        // bound value only when the surviving expression still
                        // names that binding's exact symbol. Canonical
                        // rewriting may absorb the operand entirely; attaching
                        // its value cell to whatever unrelated syntax survived
                        // would then fabricate a second identity answer.
                        Some(ValueDisposition::Bound { binding }) => {
                            bound_symbol_spelled(self, *binding)
                        }
                        Some(ValueDisposition::Inline { .. })
                            if self.source.graph().def_inst(input).is_none() =>
                        {
                            true
                        }
                        Some(ValueDisposition::Inline { .. })
                        | Some(ValueDisposition::Elided { .. })
                        | Some(ValueDisposition::Refused { .. })
                        | None => {
                            // Which statement folded this operand in is what a
                            // repair needs; the value alone says only that one
                            // did.
                            r2il::refusal_evidence!(
                                "folded-operand",
                                "{input:?} is operand {input_idx} of {definition:?} at {block:#x}, \
                                 folded into a rendered expression"
                            );
                            return Err(LegacyObservationJournalError::rendered_value_required(
                                input,
                                RenderedValueRequirementCause::NonrenderedValueDisposition,
                                self.plan.disposition(input),
                            ));
                        }
                    };
                    if needs_value_target && represented_values.insert(input) {
                        self.value_slot(input)?;
                        targets.push(ObservationTarget::Value(input));
                    }
                }
            }
        }
        Ok(targets)
    }

    /// Account the merge a normalization removed by materializing its edges.
    ///
    /// The copies on those edges are what write the merge, so the phi itself
    /// has no occurrence of its own. This fills only slots the renderer left
    /// empty: where the phi does still render, that observation already stands
    /// and is not replaced, which is why this cannot be declared up front.
    /// Fill the value cell of a merge that performs nothing, from the binding
    /// that carries it.
    ///
    /// A merge whose every edge is an identity has no statement: the edge
    /// copies are suppressed, so `observe_normalized_output_stmt` never runs
    /// and never marks the value. Where the binding has a declaration, the
    /// value is rendered under that binding's name by whatever wrote it. A
    /// carrier whose complete use domain is independently elided has no C
    /// occurrence instead, just as the coalesced copy case below does not.
    ///
    /// This is the sibling of `observe_rendered_replacement_expr`, which accepts that a
    /// discharged instruction's cells are filled at the site rendering its
    /// replacement. The two cannot share a path, and the difference is worth
    /// stating: that function has an expression to hang markers on, because
    /// something is rendered where the discharged statement used to be. An
    /// identity merge has no site at all -- its statement is gone and nothing
    /// stands in its place -- so its cell is closed here, at the seal, in the
    /// same way `account_materialized_phi_occurrences` closes the cells of
    /// definitions placement dropped.
    ///
    pub(crate) fn account_values_rendered_by_binding(
        &mut self,
        symbol_bindings: &BTreeMap<SymbolId, LegacyBindingId>,
    ) -> Result<(), LegacyObservationJournalError> {
        let graph = self.source.graph();
        let rendered_by_binding = self
            .plan
            .identity_merges(graph)
            .into_iter()
            .collect::<BTreeSet<_>>();
        for value in rendered_by_binding {
            let Some(slot) = self.values.get(value.0 as usize) else {
                continue;
            };
            if slot.is_some() {
                continue;
            }
            let Some(ValueDisposition::Bound { binding }) = self.plan.disposition(value) else {
                continue;
            };
            if let Some(legacy) = self
                .names
                .symbol_for_binding(*binding)
                .and_then(|symbol| symbol_bindings.get(&symbol).copied())
            {
                self.values[value.0 as usize] =
                    Some(LegacyValueObservation::Bound { binding: legacy });
                continue;
            }
            // A read a gap owns is accounted as surely as an elided one.
            let every_use_is_accounted = graph.use_sites(value).iter().all(|site| {
                matches!(
                    self.uses
                        .get(site.inst.0 as usize)
                        .and_then(|row| row.get(site.input_idx)),
                    Some(Some(
                        LegacyUseObservation::Elided(_) | LegacyUseObservation::Gap(_)
                    ))
                )
            });
            if every_use_is_accounted {
                self.values[value.0 as usize] = Some(LegacyValueObservation::Elided(
                    crate::ledger::ElisionReason::CoalescedImmutablePhi,
                ));
            }
        }
        Ok(())
    }

    /// Account a value whose defining program copy was elided as an identity.
    ///
    /// The copy itself has no occurrence. Usually its binding is declared
    /// elsewhere, and that declaration answers for the value -- exactly as
    /// for a merge coalesced to one binding. A carrier used only by certified
    /// machine plumbing is the other case: no C object is declared, and every
    /// use has its own justified elision, so the copy's coalescing proof also
    /// answers that its output has no rendered occurrence.
    ///
    /// These are the only two answers. An undeclared binding with any use that
    /// is not already proved elided still refuses; otherwise this would turn a
    /// missing occurrence into an accounting exemption.
    pub(crate) fn account_coalesced_copy_outputs(
        &mut self,
        symbol_bindings: &BTreeMap<SymbolId, LegacyBindingId>,
    ) -> Result<(), LegacyObservationJournalError> {
        let graph = self.source.graph();
        for value in self.coalesced_copy_outputs.iter().copied() {
            let slot = value.0 as usize;
            if self.values.get(slot).is_none_or(Option::is_some) {
                continue;
            }
            let Some(symbol) = self.names.symbol_for_value(value) else {
                continue;
            };
            if let Some(binding) = symbol_bindings.get(&symbol).copied() {
                self.values[slot] = Some(LegacyValueObservation::Bound { binding });
                continue;
            }
            let every_use_is_elided = graph.use_sites(value).iter().all(|site| {
                matches!(
                    self.uses
                        .get(site.inst.0 as usize)
                        .and_then(|row| row.get(site.input_idx)),
                    Some(Some(LegacyUseObservation::Elided(_)))
                )
            });
            if every_use_is_elided {
                self.values[slot] = Some(LegacyValueObservation::Elided(
                    crate::ledger::ElisionReason::CoalescedCopy,
                ));
                continue;
            }
            r2il::refusal_evidence!(
                "unowned-binding-symbol",
                "value {value:?} named {symbol:?} has no binding; live uses {:?} of {}",
                graph
                    .use_sites(value)
                    .iter()
                    .filter(|site| {
                        !matches!(
                            self.uses
                                .get(site.inst.0 as usize)
                                .and_then(|row| row.get(site.input_idx)),
                            Some(Some(LegacyUseObservation::Elided(_)))
                        )
                    })
                    .map(|site| {
                        (
                            site.inst,
                            site.input_idx,
                            graph
                                .inst(site.inst)
                                .map(|inst| format!("{:?}", inst.payload)),
                            self.uses
                                .get(site.inst.0 as usize)
                                .and_then(|row| row.get(site.input_idx))
                                .map(|observation| format!("{observation:?}")),
                        )
                    })
                    .collect::<Vec<_>>(),
                graph.use_sites(value).len()
            );
            return Err(LegacyObservationJournalError::UnownedBindingSymbol { value, symbol });
        }
        Ok(())
    }

    pub(crate) fn account_removed_occurrences(&mut self) {
        let graph = self.source.graph();
        for inst in self.materialized_removed_phis.clone() {
            let reason = crate::ledger::ElisionReason::MaterializedPhiEdges;
            if let Some(slot) = self.writes.get_mut(inst.0 as usize) {
                Self::record_removed_write(slot, reason);
            }
            let inputs = graph.inst(inst).map_or(0, |inst| inst.inputs.len());
            for input_idx in 0..inputs {
                if let Some(row) = self.uses.get_mut(inst.0 as usize)
                    && let Some(slot) = row.get_mut(input_idx)
                {
                    Self::record_removed_use(slot, reason);
                }
            }
        }

        // Definitions placement dropped because nothing reads what they
        // produce. What they did besides producing that value is answered by
        // the effect ledger, which is why removing the statement does not lose
        // an obligation; here only the value, use and write cells they carried
        // are closed out.
        let reason = crate::ledger::ElisionReason::DeadUnusedTemporary;
        for inst in self.placement_elided_writes.clone() {
            if let Some(slot) = self.writes.get_mut(inst.0 as usize) {
                Self::record_removed_write(slot, reason);
            }
            let Some(instruction) = graph.inst(inst) else {
                continue;
            };
            if let Some(output) = instruction.output
                && let Some(slot) = self.values.get_mut(output.0 as usize)
            {
                Self::record_removed_value(slot, reason);
            }
            for input_idx in 0..instruction.inputs.len() {
                if let Some(row) = self.uses.get_mut(inst.0 as usize)
                    && let Some(slot) = row.get_mut(input_idx)
                {
                    Self::record_removed_use(slot, reason);
                }
            }
        }

        // Every cell the discarded statements carried. Walking the writes
        // reaches only what a defining instruction produced, and a
        // caller-supplied value is version zero with no defining instruction at
        // all -- the stack pointer is exactly that -- so its cell is reachable
        // only through the observation that named it.
        //
        // These are the observations placement reported removing, not the cells
        // that happen to be empty. Filling in whatever is empty would satisfy
        // the seal by silencing it, and the seal is the only thing that catches
        // a value the renderer was supposed to emit and did not.
        let reason = crate::ledger::ElisionReason::DeadUnreadBinding;
        for id in self.placement_elided_observations.clone() {
            let Some(target) = self.targets.get(id.index() as usize).copied() else {
                continue;
            };
            match target {
                ObservationTarget::Value(value) => {
                    if let Some(slot) = self.values.get_mut(value.0 as usize) {
                        Self::record_removed_value(slot, reason);
                    }
                }
                ObservationTarget::Use { site, .. } => {
                    if let Some(row) = self.uses.get_mut(site.inst.0 as usize)
                        && let Some(slot) = row.get_mut(site.input_idx)
                    {
                        Self::record_removed_use(slot, reason);
                    }
                }
                ObservationTarget::Write { inst, .. } => {
                    if let Some(slot) = self.writes.get_mut(inst.0 as usize) {
                        Self::record_removed_write(slot, reason);
                    }
                }
                // A stack access answers through the object it addresses, and a
                // certified read through the value it reads; an effect answers
                // to the effect ledger. None of the three owns a cell here.
                // An effect answers to the effect ledger, and the ledger has
                // to be told. Placement removed the statement that carried
                // this obligation's only occurrence because nothing reads the
                // object it wrote, which is the same fact the three cells
                // above are filled with; the obligation is dead with the
                // statement.
                ObservationTarget::Effect(obligation) => {
                    self.placement_elided_effects.insert(obligation);
                }
                // A gapped cell is already accounted by the gap. Placement
                // removing the marker changes nothing about that: the cell was
                // never going to be rendered, and the elision rule above would
                // claim it had been proven unnecessary.
                ObservationTarget::Gapped { .. }
                | ObservationTarget::StackAccess { .. }
                | ObservationTarget::CertifiedValueRead { .. }
                | ObservationTarget::CertifiedArrayIndexRead { .. }
                | ObservationTarget::ObjectAddress { .. } => {}
            }
        }

        // A value supplied from outside has no statement to render, so its only
        // possible occurrence is a read; where every read elided, none exists.
        for index in 0..self.values.len() {
            let value = ValueId(index as u32);
            // A call clobber is supplied from outside this function too, by the
            // callee rather than the caller, and the plan is what says so.
            let supplied_from_outside = if graph.caller_supplied(value) {
                crate::ledger::ElisionReason::CallerSuppliedEntryValue
            } else if self.plan.value_is_call_clobber(value) {
                crate::ledger::ElisionReason::UnclaimedCallClobber
            } else {
                continue;
            };
            if self.values.get(index).is_none_or(|slot| slot.is_some())
                || !matches!(
                    self.plan.disposition(value),
                    Some(ValueDisposition::Bound { .. })
                )
            {
                continue;
            }
            let reason = supplied_from_outside;
            let unobserved = graph.use_sites(value).iter().all(|site| {
                matches!(
                    self.uses
                        .get(site.inst.0 as usize)
                        .and_then(|row| row.get(site.input_idx)),
                    Some(Some(LegacyUseObservation::Elided(_)))
                )
            });
            if unobserved && let Some(slot) = self.values.get_mut(index) {
                Self::record_removed_value(slot, reason);
            }
        }
    }

    /// Seal only the source-effect occurrence stream.
    ///
    /// Binding shadow recording is diagnostic and may already have failed by
    /// this point. Effect markers have an independent source domain, so that
    /// failure must not erase the exact effect occurrences that reached the
    /// final emission tree.
    #[cfg(test)]
    pub(crate) fn seal_effects_only(
        self,
        source: &SourceOwnedFunctionFacts,
        ready: &mut EmissionReadyFunction,
    ) -> Result<SurvivingEffectObservations, LegacyObservationJournalError> {
        if self.authority != *source.source().authority() {
            return Err(LegacyObservationJournalError::SourceAuthority);
        }
        let mut seal_authority = ObservationSealAuthority::new();
        let function = ready.function_mut_for_observation_seal(&mut seal_authority);
        let rewrite_elided = self.rewrite_elided_effects();
        let mut effect_occurrences = self.effect_occurrences;
        let targets = self.targets;
        // Without a region tree there is nothing to prove two occurrences of
        // one cell exclude each other, so the first marker met twice refuses.
        let mut met = vec![false; targets.len()];
        inspect_and_strip_render_observations(
            function,
            targets.len(),
            |id, _node| -> Result<(), LegacyObservationJournalError> {
                if let Some(seen) = met.get_mut(id.index() as usize) {
                    if *seen {
                        return Err(LegacyObservationJournalError::Markers(
                            RenderObservationStripError::Duplicate { id },
                        ));
                    }
                    *seen = true;
                }
                let target = targets.get(id.index() as usize).copied().ok_or({
                    LegacyObservationJournalError::Markers(
                        RenderObservationStripError::OutOfRange {
                            id,
                            expected_count: targets.len(),
                        },
                    )
                })?;
                if let ObservationTarget::Effect(id) = target {
                    let occurrences = effect_occurrences
                        .get_mut(&id)
                        .ok_or(LegacyObservationJournalError::InvalidEffectObligation(id))?;
                    *occurrences = occurrences
                        .checked_add(1)
                        .ok_or(LegacyObservationJournalError::TooManyObservations)?;
                }
                Ok(())
            },
        )
        .map_err(|error| match error {
            RenderObservationInspectError::Markers(error) => {
                LegacyObservationJournalError::Markers(error)
            }
            RenderObservationInspectError::Observer(error) => error,
        })?;
        Ok(SurvivingEffectObservations {
            rewrite_elided,
            // This path has no region tree to prove exclusion with, so it
            // claims none.
            occurrences: effect_occurrences
                .into_iter()
                .map(|(id, count)| {
                    (
                        id,
                        EffectOccurrences {
                            count,
                            exclusive: false,
                            // Nor a plan to ask which values are literals.
                            repeated_literal: false,
                            named_object_address: false,
                        },
                    )
                })
                .collect(),
            gapped: self.gapped_effects,
            coalesced_carriers: Box::new(CoalescedCarrierEffectElisions {
                coalesced_store_sites: self.coalesced_store_sites,
                coalesced_carrier_uses: self.coalesced_carrier_uses,
                coalesced_carrier_phis: self.coalesced_carrier_phi_writes,
                coalesced_copies: self.coalesced_copy_writes,
                placement_elided_effects: self.placement_elided_effects,
                dead_unused_value_effects: self.dead_unused_value_effects,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn seal(
        self,
        source: &SourceOwnedFunctionFacts,
        ready: &mut EmissionReadyFunction,
    ) -> Result<SealedLegacyObservations, LegacyObservationJournalError> {
        match self.seal_preserving_effects(source, ready, None)? {
            LegacyObservationSeal::Complete(observations) => Ok(observations),
            LegacyObservationSeal::BindingFailure(error) => Err(error),
        }
    }

    /// Inspect the final marker tree once while retaining the first legacy
    /// binding-classification failure. Effect occurrences are sealed only with
    /// a fully classified product; a binding failure leaves the tree unchanged
    /// and exposes neither executable C nor a partial effect stream.
    pub(crate) fn seal_preserving_effects(
        mut self,
        source: &SourceOwnedFunctionFacts,
        ready: &mut EmissionReadyFunction,
        regions: Option<&crate::structured_region::SealedStructuredRegionArtifact>,
    ) -> Result<LegacyObservationSeal, LegacyObservationJournalError> {
        if self.authority != *source.source().authority() {
            return Err(LegacyObservationJournalError::SourceAuthority);
        }
        let mut seal_authority = ObservationSealAuthority::new();
        let function = ready.function_mut_for_observation_seal(&mut seal_authority);
        if !Rc::ptr_eq(&self.symbols, &function.symbols) {
            return Err(LegacyObservationJournalError::SymbolTableMismatch);
        }

        // A marker written more than once discharges its cell more than once,
        // which is a duplicate unless the writings exclude one another. Without
        // a region tree there is no structure to prove that with, so a repeat
        // refuses here and the tree is left as it was found.
        if regions.is_none()
            && let Some(id) = crate::placement::repeated_observations(&function.body)
                .into_iter()
                .next()
        {
            return Err(LegacyObservationJournalError::Markers(
                RenderObservationStripError::Duplicate { id },
            ));
        }
        // Where each observation ended up in the structured tree. Read before
        // the walk, from the same final tree the walk counts, so the two cannot
        // disagree about which occurrence sat where.
        let observation_regions = regions.map(|regions| {
            crate::placement::final_observation_regions(&function.body, regions, self.targets.len())
        });

        let mut values = std::mem::take(&mut self.values);
        let mut uses = std::mem::take(&mut self.uses);
        let mut writes = std::mem::take(&mut self.writes);
        let mut effect_occurrences = std::mem::take(&mut self.effect_occurrences);
        let mut effect_occurrence_regions = std::mem::take(&mut self.effect_occurrence_regions);
        let mut gapped_effects = std::mem::take(&mut self.gapped_effects);
        // Cells a control rewrite took out of the text. They are answered here,
        // before the walk, because the walk counts what the tree carries and
        // these are exactly what it no longer carries. The rewrite stated the
        // reason; nothing is inferred from the absence.
        for (id, reason) in self.rewrite_elisions.cells.clone() {
            match self.targets.get(id.index() as usize) {
                Some(ObservationTarget::Value(value)) => {
                    if let Some(slot) = values.get_mut(value.0 as usize) {
                        let _ = record_same(slot, LegacyValueObservation::Elided(reason));
                    }
                }
                Some(ObservationTarget::Use { site, .. }) => {
                    if let Some(slot) = uses
                        .get_mut(site.inst.0 as usize)
                        .and_then(|inputs| inputs.get_mut(site.input_idx))
                    {
                        let _ = record_same(slot, LegacyUseObservation::Elided(reason));
                    }
                }
                Some(ObservationTarget::Write { inst, .. }) => {
                    if let Some(slot) = writes.get_mut(inst.0 as usize) {
                        let _ = record_same(slot, LegacyWriteObservation::Elided(reason));
                    }
                }
                _ => {}
            }
        }
        let targets = &self.targets;
        let value_is_literal = &self.value_is_literal;
        let plan = &self.plan;
        let names = &self.names;
        let symbol_bindings = declared_legacy_bindings(function);
        let mut binding_failure = None;
        // How many times the walk has met each marker, so a repeat's scope is
        // the place that writing sits in rather than the first one's.
        let mut seen_markers = BTreeMap::<RenderObservationId, usize>::new();
        // Which allocated observations the final tree actually carries. One it
        // does not is a cell that was accounted for by an expression nothing
        // emitted, and the slot it answered for stays owed to nobody.
        let mut placed = vec![false; self.targets.len()];
        inspect_render_observations(
            function,
            targets.len(),
            |id, node| -> Result<(), LegacyObservationJournalError> {
                if let Some(seen) = placed.get_mut(id.index() as usize) {
                    *seen = true;
                }
                let target = targets.get(id.index() as usize).copied().ok_or({
                    LegacyObservationJournalError::Markers(
                        RenderObservationStripError::OutOfRange {
                            id,
                            expected_count: targets.len(),
                        },
                    )
                })?;
                if binding_failure.is_some() && !matches!(target, ObservationTarget::Effect(_)) {
                    return Ok(());
                }
                let result = match target {
                    // Sealing has nothing to record: the read carries no
                    // value or use slot of its own, and the placement audit is
                    // what it exists to answer.
                    ObservationTarget::CertifiedValueRead { .. } => Ok(()),
                    ObservationTarget::CertifiedArrayIndexRead { .. } => Ok(()),
                    ObservationTarget::Value(value) => {
                        match plan.disposition(value) {
                            // The one elision that renders: nothing reads the
                            // value, and its instruction still performs the
                            // read. The statement spells the read, not the
                            // value, so there is no name to disagree about.
                            Some(ValueDisposition::Elided {
                                reason: crate::ledger::ElisionReason::UnreadEffectfulValue,
                                ..
                            }) => {}
                            Some(ValueDisposition::Elided { reason, .. }) => {
                                // Which value, and why the plan elided it, is
                                // what separates a wrong plan from a wrong
                                // rendering.
                                r2il::refusal_evidence!(
                                    "planned-elided-value-rendered",
                                    "{value:?} was elided as {reason:?} and a statement still names it"
                                );
                                binding_failure = Some(
                                    LegacyObservationJournalError::PlannedElidedValueRendered {
                                        value,
                                        reason: *reason,
                                    },
                                );
                                return Ok(());
                            }
                            Some(ValueDisposition::Refused { reason }) => {
                                binding_failure = Some(
                                    LegacyObservationJournalError::PlannedRefusedValueRendered {
                                        value,
                                        reason: *reason,
                                    },
                                );
                                return Ok(());
                            }
                            Some(
                                ValueDisposition::Bound { .. } | ValueDisposition::Inline { .. },
                            )
                            | None => {}
                        }
                        classify_value_node(
                            value,
                            node,
                            plan.disposition(value),
                            value_is_literal,
                            &symbol_bindings,
                            names.symbol_for_value(value),
                        )
                        .and_then(|observation| {
                            let slot = &mut values[value.0 as usize];
                            if record_same(slot, observation).is_err() {
                                if r2il::refusal_evidence::tracing() {
                                    eprintln!(
                                        "conflicting value {value:?}: recorded {slot:?}, rendered \
                                         {observation:?}, disposition={:?}, node={}",
                                        plan.disposition(value),
                                        format!("{node:?}")
                                            .chars()
                                            .take(180)
                                            .collect::<String>()
                                    );
                                }
                                Err(LegacyObservationJournalError::ConflictingValue(value))
                            } else {
                                Ok(())
                            }
                        })
                    }
                    ObservationTarget::Use {
                        site, observation, ..
                    } => {
                        let slot = &mut uses[site.inst.0 as usize][site.input_idx];
                        if record_same(slot, observation).is_err() {
                            if r2il::refusal_evidence::tracing() {
                                eprintln!(
                                    "conflicting use {site:?}: recorded {slot:?}, rendered {observation:?} operands={:?} payload={:?}",
                                    // Which operand this is, by storage: a
                                    // stack base and a computed index are the
                                    // two halves of one address and only the
                                    // base is stack geometry.
                                    self.source.graph().inst(site.inst).map(|inst| inst
                                        .inputs
                                        .iter()
                                        .map(|value| (
                                            *value,
                                            self.source
                                                .graph()
                                                .value(*value)
                                                .and_then(|value| value.canonical_storage)
                                                .map(|storage| (storage.space, storage.offset))
                                        ))
                                        .collect::<Vec<_>>()),
                                    self.source.graph().inst(site.inst).map(|inst| format!(
                                        "{:?}",
                                        inst.payload
                                    )
                                    .chars()
                                    .take(120)
                                    .collect::<String>())
                                );
                            }
                            Err(conflicting_use(site))
                        } else {
                            Ok(())
                        }
                    }
                    ObservationTarget::Write {
                        inst, observation, ..
                    } => record_same(&mut writes[inst.0 as usize], observation)
                        .map_err(|()| LegacyObservationJournalError::ConflictingWrite(inst)),
                    // The gap's own cells. Recorded with the same
                    // `record_same` the rendered cells use, so a cell claimed
                    // by both a gap and a rendering is a conflict rather than
                    // a silent overwrite.
                    ObservationTarget::Gapped { anchor, cell } => match cell {
                        GapCell::Value(value) => {
                            let slot = &mut values[value.0 as usize];
                            record_same(slot, LegacyValueObservation::Gap(anchor))
                                .map_err(|()| LegacyObservationJournalError::ConflictingValue(value))
                        }
                        GapCell::Use { site, .. } => {
                            let slot = &mut uses[site.inst.0 as usize][site.input_idx];
                            record_same(slot, LegacyUseObservation::Gap(anchor)).map_err(|()| {
                                if r2il::refusal_evidence::tracing() {
                                    eprintln!(
                                        "gapped use {site:?} at {anchor:?}: already recorded {slot:?}"
                                    );
                                }
                                LegacyObservationJournalError::ConflictingUse(site)
                            })
                        }
                        GapCell::Write(inst) => {
                            record_same(&mut writes[inst.0 as usize], LegacyWriteObservation::Gap(anchor))
                                .map_err(|()| LegacyObservationJournalError::ConflictingWrite(inst))
                        }
                        // Never an occurrence: an obligation the gap covers was
                        // not performed by the output, and counting it as one
                        // would let a cloned shared tail report it twice.
                        GapCell::Effect(effect) => {
                            gapped_effects.insert(effect);
                            Ok(())
                        }
                    },
                    ObservationTarget::StackAccess { .. }
                    | ObservationTarget::ObjectAddress { .. } => Ok(()),
                    ObservationTarget::Effect(effect) => {
                        let occurrences = effect_occurrences.get_mut(&effect).ok_or(
                            LegacyObservationJournalError::InvalidEffectObligation(effect),
                        )?;
                        *occurrences = occurrences
                            .checked_add(1)
                            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
                        if r2il::refusal_evidence::tracing() {
                            r2il::refusal_evidence!(
                                "effect-occurrence",
                                "{effect:?} occurrence {} by marker {id:?} from {:?} on {}",
                                *occurrences,
                                self.target_origins.get(id.index() as usize).map(ToString::to_string),
                                format!("{node:?}").chars().take(160).collect::<String>()
                            );
                        }
                        let nth = seen_markers.entry(id).or_insert(0);
                        let at = *nth;
                        *nth += 1;
                        if let Some(scope) = observation_regions
                            .as_ref()
                            .and_then(|scoped| scoped.scope_at(id, at))
                        {
                            effect_occurrence_regions
                                .entry(effect)
                                .or_default()
                                .push(scope.clone());
                        }
                        return Ok(());
                    }
                };
                if let Err(error) = result {
                    binding_failure = Some(error);
                }
                Ok(())
            },
        )
        .map_err(|error| match error {
            RenderObservationInspectError::Markers(error) => {
                LegacyObservationJournalError::Markers(error)
            }
            RenderObservationInspectError::Observer(error) => error,
        })?;

        if r2il::refusal_evidence::tracing() {
            for (index, seen) in placed.iter().enumerate() {
                if *seen {
                    continue;
                }
                r2il::refusal_evidence!(
                    "observation-not-placed",
                    "{:?} was allocated by {} and the emitted tree does not carry it",
                    self.targets.get(index),
                    self.target_origins
                        .get(index)
                        .map_or_else(|| "an untraced site".to_string(), ToString::to_string)
                );
            }
        }

        if let Some(error) = binding_failure {
            if r2il::refusal_evidence::tracing() {
                eprintln!("observation binding failure: {error:?}");
            }
            return Ok(LegacyObservationSeal::BindingFailure(error));
        }

        self.values = values;
        self.uses = uses;
        self.writes = writes;
        self.effect_occurrences = effect_occurrences;
        self.effect_occurrence_regions = effect_occurrence_regions;
        self.gapped_effects = gapped_effects;
        // Placement has the final word on which statements survive. Apply its
        // exact removals before deciding whether a coalesced output has any
        // rendered consumer; doing this in the opposite order mistakes a
        // consumer placement removed for an undeclared C object.
        if let Err(error) = self.apply_absent_occurrence_contracts(&symbol_bindings) {
            return Ok(LegacyObservationSeal::BindingFailure(error));
        }
        if let Some(error) = self.first_unaccounted_render_observation() {
            return Ok(LegacyObservationSeal::BindingFailure(error));
        }
        // An obligation rendered more than once is a duplicate unless the
        // region tree proves the copies exclude one another. Deciding it here,
        // where the tree that produced the occurrences is still in hand, keeps
        // the ledger's question a lookup rather than a second analysis.
        if let Some(regions) = regions {
            self.exclusive_duplicate_effects = self
                .effect_occurrence_regions
                .iter()
                .filter(|(effect, occupied)| {
                    self.effect_occurrences
                        .get(*effect)
                        .is_some_and(|count| *count > 1)
                        && occupied.len() == self.effect_occurrences[*effect]
                        && occupied.iter().enumerate().all(|(at, left)| {
                            occupied
                                .iter()
                                .skip(at + 1)
                                .all(|right| left.excludes(right, regions))
                        })
                })
                .map(|(effect, _)| *effect)
                .collect();
        }
        if let (Some(scopes), Some(regions)) = (observation_regions.as_ref(), regions) {
            for (id, written) in scopes.repeated() {
                let exclusive = written.iter().enumerate().all(|(at, left)| {
                    written
                        .iter()
                        .skip(at + 1)
                        .all(|right| left.excludes(right, regions))
                });
                if !exclusive {
                    r2il::refusal_evidence!(
                        "repeated-observation",
                        "{id:?} written {} times on paths that do not exclude one another",
                        written.len()
                    );
                    return Err(LegacyObservationJournalError::Markers(
                        RenderObservationStripError::Duplicate { id },
                    ));
                }
            }
        }
        // Seal the proof markers only after every classification and coverage
        // check succeeds. A binding failure leaves the marked draft intact.
        // A sealed marker stays on the tree as where its statement came from,
        // and the emitter reads it through the table this builds.
        let locations = self.observation_locations();
        let mut seal_authority = ObservationSealAuthority::new();
        ready.seal_observation_markers(&mut seal_authority, locations);
        Ok(LegacyObservationSeal::Complete(
            self.into_sealed_observations(source),
        ))
    }

    pub(crate) fn final_coverage(&self) -> LegacyObservationCoverage {
        let value_total = self.values.len();
        let value_rendered = self
            .values
            .iter()
            .filter(|cell| {
                matches!(
                    cell,
                    Some(
                        LegacyValueObservation::Bound { .. }
                            | LegacyValueObservation::InlineConstant
                            | LegacyValueObservation::InlineNonLiteral
                    )
                )
            })
            .count();
        let value_justified_elision = self
            .values
            .iter()
            .filter(|cell| matches!(cell, Some(LegacyValueObservation::Elided(_))))
            .count();
        let value_refused = self
            .values
            .iter()
            .filter(|cell| matches!(cell, Some(LegacyValueObservation::Refused(_))))
            .count();
        let value_gapped = self
            .values
            .iter()
            .filter(|cell| matches!(cell, Some(LegacyValueObservation::Gap(_))))
            .count();
        let value_unaccounted = self.values.iter().filter(|cell| cell.is_none()).count();

        let use_total = self.uses.iter().map(|row| row.len()).sum();
        let use_rendered = self
            .uses
            .iter()
            .flat_map(|row| row.iter())
            .filter(|cell| {
                matches!(
                    cell,
                    Some(LegacyUseObservation::Exact(_) | LegacyUseObservation::MemoryAddress)
                )
            })
            .count();
        let use_refused = self
            .uses
            .iter()
            .flat_map(|row| row.iter())
            .filter(|cell| matches!(cell, Some(LegacyUseObservation::Refused(_))))
            .count();
        let use_justified_elision = self
            .uses
            .iter()
            .flat_map(|row| row.iter())
            .filter(|cell| matches!(cell, Some(LegacyUseObservation::Elided(_))))
            .count();
        let use_gapped = self
            .uses
            .iter()
            .flat_map(|row| row.iter())
            .filter(|cell| matches!(cell, Some(LegacyUseObservation::Gap(_))))
            .count();
        let use_unaccounted = self
            .uses
            .iter()
            .flat_map(|row| row.iter())
            .filter(|cell| cell.is_none())
            .count();

        let write_total = self
            .write_has_output
            .iter()
            .filter(|has_output| **has_output)
            .count();
        let write_rendered = self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .filter(|(cell, has_output)| {
                **has_output && matches!(cell, Some(LegacyWriteObservation::Exact(_)))
            })
            .count();
        let write_refused = self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .filter(|(cell, has_output)| {
                **has_output && matches!(cell, Some(LegacyWriteObservation::Refused(_)))
            })
            .count();
        let write_justified_elision = self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .filter(|(cell, has_output)| {
                **has_output && matches!(cell, Some(LegacyWriteObservation::Elided(_)))
            })
            .count();
        let write_gapped = self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .filter(|(cell, has_output)| {
                **has_output && matches!(cell, Some(LegacyWriteObservation::Gap(_)))
            })
            .count();
        let write_unaccounted = self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .filter(|(cell, has_output)| **has_output && cell.is_none())
            .count();

        LegacyObservationCoverage {
            values: LegacyObservationDomainCoverage::from_counts(
                value_total,
                value_rendered,
                value_justified_elision,
                value_refused,
                value_gapped,
                value_unaccounted,
            ),
            uses: LegacyObservationDomainCoverage::from_counts(
                use_total,
                use_rendered,
                use_justified_elision,
                use_refused,
                use_gapped,
                use_unaccounted,
            ),
            writes: LegacyObservationDomainCoverage::from_counts(
                write_total,
                write_rendered,
                write_justified_elision,
                write_refused,
                write_gapped,
                write_unaccounted,
            ),
        }
    }
}
