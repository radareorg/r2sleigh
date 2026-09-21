//! What goes into the journal: every value and effect the emission produced.

use super::*;

impl LegacyObservationJournal {
    /// Consume placement's complete removal report as one cell contract.
    ///
    /// The removed binding identifies every defining instruction whose
    /// statement disappeared. The exact removed markers identify the value,
    /// use, write, and effect cells those statements carried. Keeping the
    /// report opaque until this method consumes both halves prevents a caller
    /// from forwarding only the cell family it happened to remember.
    pub(crate) fn record_placement_removals(
        &mut self,
        removals: crate::placement::PlacementRemovals,
        writes: &[crate::placement::FinalBindingWrite],
    ) {
        let (bindings, observations) = removals.into_contract();
        for binding in bindings {
            self.placement_elided_writes.extend(
                writes
                    .iter()
                    .filter(|write| write.binding == binding)
                    .map(|write| write.inst),
            );
        }
        self.placement_elided_observations.extend(observations);
    }

    /// The block whose text one observed statement was emitted in, for the
    /// control certificate; read-side targets say nothing about placement.
    /// Record cells a control rewrite removed, with the reason it removed them.
    pub(crate) fn record_rewrite_elisions(&mut self, elisions: &RewriteElisions) {
        self.rewrite_elisions
            .cells
            .extend(elisions.cells.iter().copied());
    }

    /// Seed only decisions whose upstream disposition proves that no rendered
    /// occurrence may exist. Bound, inline, and exact machine cells remain
    /// absent until a marker actually survives final emission.
    pub(crate) fn record_upstream_nonrendered_dispositions(
        &mut self,
        source: &SourceOwnedFunctionFacts,
        origins: &NormalizationOrigins,
    ) -> Result<(), LegacyObservationJournalError> {
        let graph = source.source().graph();
        let nonrendered_values = (0..self.values.len())
            .filter_map(|index| {
                let value = ValueId(index as u32);
                matches!(
                    self.plan.disposition(value),
                    Some(ValueDisposition::Elided { .. } | ValueDisposition::Refused { .. })
                )
                .then_some(value)
            })
            .collect::<Vec<_>>();
        // The cells the certificates elide are one statement, shared with the
        // binding plan: `binding_plan::certificate_elided_cells`. What follows
        // are the cells only this journal can answer for -- the
        // normalization's own phi-edge copies, the carriers the plan
        // coalesced, the merges the plan made immutable, and the dispositions
        // the plan refused.
        let crate::binding_plan::CertificateElidedCells {
            uses: mut elided_uses,
            writes: mut elided_writes,
            ..
        } = crate::binding_plan::certificate_elided_cells(
            source.source(),
            self.plan.machine_projection(),
        )?;
        // A redundant phi edge carries no read: the edge's value is the phi's
        // own, so nothing about it is an operand of a surviving operation. A
        // certificate that answered the same cell was answering for an operand
        // that is not there, and the two do not disagree about the disposition
        // -- both say the cell renders nothing. Normalization owns it, because
        // its claim is about the SSA form rather than about what an operation
        // does with an operand it no longer has.
        for site in origins.noop_sites() {
            if let Some(existing) =
                elided_uses.insert(site, crate::ledger::ElisionReason::RedundantPhiEdge)
                && existing != crate::ledger::ElisionReason::RedundantPhiEdge
            {
                r2il::refusal_evidence!(
                    "redundant-phi-edge-subsumes",
                    "{site:?} was answered {existing:?} by a certificate; the edge carries no read"
                );
            }
        }
        let coalesced_carrier_uses = self
            .coalesced_carrier_uses
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for site in coalesced_carrier_uses {
            // A cell a certificate already answered for keeps that answer. Two
            // tables saying one read renders nothing do not disagree, and the
            // certificate is the one with the authority; what the seal is for
            // is a cell two tables render *differently*.
            if elided_uses.contains_key(&site) {
                continue;
            }
            match elided_uses.insert(site, crate::ledger::ElisionReason::CoalescedCopy) {
                Some(crate::ledger::ElisionReason::CoalescedCopy) | None => {}
                Some(existing) => {
                    if r2il::refusal_evidence::tracing() {
                        eprintln!(
                            "conflicting use {site:?}: certificate reason {existing:?}, normalization reason CoalescedCopy"
                        );
                    }
                    return Err(conflicting_use(site));
                }
            }
        }
        for inst in self.coalesced_carrier_phi_writes.iter().copied() {
            match elided_writes.insert(inst, crate::ledger::ElisionReason::CoalescedIdentityPhi) {
                Some(crate::ledger::ElisionReason::CoalescedIdentityPhi) | None => {}
                Some(_) => return Err(conflicting_write(inst)),
            }
        }
        // A program copy that says nothing owes no write either. The object
        // it would have written was written by the statement that produced
        // the value it copies, which is the same fact that let the statement
        // go.
        for inst in self.coalesced_copy_writes.iter().copied() {
            match elided_writes.insert(inst, crate::ledger::ElisionReason::CoalescedCopy) {
                Some(crate::ledger::ElisionReason::CoalescedCopy) | None => {}
                Some(_) => return Err(conflicting_write(inst)),
            }
        }
        let removed_phis = origins
            .removed_phis()
            .iter()
            .map(|origin| origin.definition.inst)
            .collect::<BTreeSet<_>>();
        // A merge normalization left in place whose every input is its own
        // binding performs nothing. Which merges those are is the plan's
        // statement, `identity_merges`, and the seal fills their value cells
        // from the same statement; asking it twice in two spellings is how
        // the value cell and the write cell came to disagree about one merge.
        let identity_merges = self.plan.identity_merges(graph);
        for inst in &graph.insts {
            if removed_phis.contains(&inst.id)
                || !matches!(inst.payload, r2ssa::InstPayload::Phi { .. })
            {
                continue;
            }
            let Some(output) = inst.output else {
                return Err(LegacyObservationJournalError::InvalidWrite(inst.id));
            };
            if !identity_merges.contains(&output) {
                continue;
            }
            for input_idx in 0..inst.inputs.len() {
                let site = UseSite {
                    inst: inst.id,
                    input_idx,
                };
                match elided_uses.insert(site, crate::ledger::ElisionReason::CoalescedImmutablePhi)
                {
                    Some(crate::ledger::ElisionReason::CoalescedImmutablePhi) | None => {}
                    Some(existing) => {
                        if r2il::refusal_evidence::tracing() {
                            eprintln!(
                                "conflicting use {site:?}: certificate reason {existing:?}, normalization reason CoalescedImmutablePhi"
                            );
                        }
                        return Err(conflicting_use(site));
                    }
                }
            }
            match elided_writes.insert(inst.id, crate::ledger::ElisionReason::CoalescedImmutablePhi)
            {
                Some(crate::ledger::ElisionReason::CoalescedImmutablePhi) | None => {}
                Some(_) => {
                    return Err(conflicting_write(inst.id));
                }
            }
        }
        let mut refused_uses = self
            .plan
            .machine_projection()
            .uses()
            .filter(|(_, disposition)| matches!(disposition, MachineUseDisposition::Refused(_)))
            .map(|(site, _)| site)
            .collect::<Vec<_>>();
        let mut refused_writes = self
            .plan
            .machine_projection()
            .write_dispositions()
            .iter()
            .enumerate()
            .filter_map(|(inst, disposition)| {
                matches!(disposition, Some(MachineWriteDisposition::Refused(_)))
                    .then_some(InstId(inst as u32))
            })
            .collect::<Vec<_>>();

        // Definitions whose values the plan proves nobody reads have no
        // statement to carry their cells. An unused call clobber is structural
        // and owns no operands or semantic obligation. A restored carrier is
        // structural too, but it has one operand: the exact pre-call carrier.
        // Construction mints a restore only for the carrier the convention
        // brings back, so the restore is an identity by its existence, and
        // its operand read disappears with a dead restore output for the same
        // reason it disappears when both ends are one live binding.
        //
        // A pre-placement dead computation also loses the operand reads and
        // the LiveValueProducer obligation its statement would have carried.
        // Only that dependency obligation is authorized here: any observable
        // effect on the same instruction remains at zero occurrences and the
        // effect ledger refuses it instead of relabelling it dead.
        //
        // This is deliberately not done for every elided value. Most elisions
        // mean some other rendering answers for the value, and claiming its
        // definition renders nothing would take the cells away from whatever
        // does.
        for value in &nonrendered_values {
            let Some(ValueDisposition::Elided { reason, .. }) = self.plan.disposition(*value)
            else {
                continue;
            };
            if !matches!(
                reason,
                crate::ledger::ElisionReason::UnusedStructuralValue
                    | crate::ledger::ElisionReason::DeadUnusedTemporary
            ) {
                continue;
            }
            let Some(inst) = graph.def_inst(*value) else {
                continue;
            };
            let Some(instruction) = graph.inst(inst).filter(|inst| inst.output == Some(*value))
            else {
                continue;
            };
            elided_writes.entry(inst).or_insert(*reason);
            for input_idx in 0..instruction.inputs.len() {
                let site = UseSite { inst, input_idx };
                let input_reason = *reason;
                match elided_uses.insert(site, input_reason) {
                    Some(existing) if existing != input_reason => {
                        return Err(conflicting_use(site));
                    }
                    _ => {}
                }
            }
            if *reason == crate::ledger::ElisionReason::DeadUnusedTemporary {
                self.dead_unused_value_effects.extend(
                    source
                        .source()
                        .obligations()
                        .obligations_for_inst(inst)
                        .filter(|obligation| {
                            obligation.id.kind == r2ssa::SemanticObligationKind::LiveValueProducer
                        })
                        .map(|obligation| obligation.id),
                );
            }
        }

        // An inline value is normally accounted where its expression is
        // inserted. A dead definition is never built, so an inline source
        // whose every reader is one of those definitions has zero rendered
        // occurrences and no marker that could close its value cell. Literal
        // constants are the common case: once a dead flag definition is
        // removed, the constant it read must not force the journal to refuse
        // merely because there is nowhere left to spell it.
        //
        // This is deliberately narrower than "all currently empty values".
        // Every graph read must already have an exact elision reason, and a
        // certified boundary read disqualifies the value because that read is
        // absent from the graph. This includes a dead definition directly and
        // a source-certified merge that was already absent from the normalized
        // program. Defined inline expressions still owe their own write, input
        // and effect cells independently; this closes only the value occurrence
        // proved to be absent.
        let certified_boundary_values = graph
            .insts
            .iter()
            .flat_map(|inst| {
                crate::binding_plan::certified_boundary_read_values(source.source(), inst.id)
            })
            .collect::<BTreeSet<_>>();
        // Deadness propagates. A dead inline value's defining instruction
        // renders nothing, so its own operand reads have no occurrence either.
        let mut dead_inline_values = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let found = graph
                .values
                .iter()
                .filter(|value| !seen.contains(&value.id))
                .filter(|value| {
                    matches!(
                        self.plan.disposition(value.id),
                        Some(ValueDisposition::Inline { .. })
                    )
                })
                .filter(|value| !certified_boundary_values.contains(&value.id))
                .filter(|value| {
                    graph
                        .use_sites(value.id)
                        .iter()
                        .all(|site| elided_uses.contains_key(site))
                })
                .map(|value| value.id)
                .collect::<Vec<_>>();
            if found.is_empty() {
                break;
            }
            for value in found {
                seen.insert(value);
                dead_inline_values.push(value);
                // Only a definition whose sole output is this value renders
                // nothing once it is dead; anything else still owes its cells.
                let Some(definition) = graph.def_inst(value) else {
                    continue;
                };
                let Some(instruction) = graph.inst(definition) else {
                    continue;
                };
                if instruction.output != Some(value) {
                    continue;
                }
                for input_idx in 0..instruction.inputs.len() {
                    elided_uses
                        .entry(UseSite {
                            inst: definition,
                            input_idx,
                        })
                        .or_insert(crate::ledger::ElisionReason::DeadUnusedTemporary);
                }
                elided_writes
                    .entry(definition)
                    .or_insert(crate::ledger::ElisionReason::DeadUnusedTemporary);
                // The statement renders nothing, so the value it owed the
                // ledger is closed the same way a plan-elided one is.
                self.dead_unused_value_effects.extend(
                    source
                        .source()
                        .obligations()
                        .obligations_for_inst(definition)
                        .filter(|obligation| {
                            obligation.id.kind == r2ssa::SemanticObligationKind::LiveValueProducer
                        })
                        .map(|obligation| obligation.id),
                );
            }
        }
        for value in dead_inline_values {
            let slot = self.value_slot_mut(value)?;
            record_same(
                slot,
                LegacyValueObservation::Elided(crate::ledger::ElisionReason::DeadUnusedTemporary),
            )
            .map_err(|()| LegacyObservationJournalError::ConflictingValue(value))?;
        }
        // A refusal says that a use or write cannot be rendered. It is not a
        // second answer for a cell a source certificate has already proved has
        // no occurrence. Stack-frame setup is the concrete overlap: its memory
        // operand has no standalone memory context, but the whole instruction
        // disappears under the exact frame round-trip certificate, so there is
        // nothing left for that missing context to refuse.
        //
        // Filter per cell, after every certificate and normalization elision
        // has been assembled. Filtering by instruction kind would suppress live
        // uses beside an elided one; filtering values would let an elision hide
        // a different rendered occurrence. The maps are the zero-occurrence
        // proof domain and therefore the only admissible precedence rule.
        retain_only_unanswered_refusals(&mut refused_uses, &elided_uses);
        retain_only_unanswered_refusals(&mut refused_writes, &elided_writes);
        for value in nonrendered_values {
            self.record_nonrendered_value(value)?;
        }
        for (site, reason) in elided_uses {
            let slot = self.use_slot_mut(site)?;
            if record_same(slot, LegacyUseObservation::Elided(reason)).is_err() {
                if r2il::refusal_evidence::tracing() {
                    eprintln!(
                        "conflicting use {site:?}: recorded {slot:?}, elision reason {reason:?}"
                    );
                }
                return Err(conflicting_use(site));
            }
        }
        for (inst, reason) in elided_writes {
            let slot = self.write_slot_mut(inst)?;
            record_same(slot, LegacyWriteObservation::Elided(reason))
                .map_err(|()| LegacyObservationJournalError::ConflictingWrite(inst))?;
        }
        for site in refused_uses {
            self.record_refused_use(site)?;
        }
        for inst in refused_writes {
            self.record_refused_write(inst)?;
        }
        Ok(())
    }

    fn allocate_pair(
        &mut self,
        first: ObservationTarget,
        second: ObservationTarget,
    ) -> Result<(RenderObservationId, RenderObservationId), LegacyObservationJournalError> {
        let first_index = u32::try_from(self.targets.len())
            .map_err(|_| LegacyObservationJournalError::TooManyObservations)?;
        let second_index = first_index
            .checked_add(1)
            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        self.targets.push(first);
        self.targets.push(second);
        Ok((
            RenderObservationId(first_index),
            RenderObservationId(second_index),
        ))
    }

    #[track_caller]
    pub(crate) fn allocate_many(
        &mut self,
        targets: Vec<ObservationTarget>,
    ) -> Result<Vec<RenderObservationId>, LegacyObservationJournalError> {
        let first = u32::try_from(self.targets.len())
            .map_err(|_| LegacyObservationJournalError::TooManyObservations)?;
        let count = u32::try_from(targets.len())
            .map_err(|_| LegacyObservationJournalError::TooManyObservations)?;
        if count > 0 {
            first
                .checked_add(count - 1)
                .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        }
        let ids = (0..count)
            .map(|offset| RenderObservationId(first + offset))
            .collect();
        if r2il::refusal_evidence::tracing() {
            let origin = std::panic::Location::caller();
            self.target_origins
                .resize(self.targets.len() + targets.len(), origin);
            for slot in &mut self.target_origins[self.targets.len()..] {
                *slot = origin;
            }
        }
        self.targets.extend(targets);
        Ok(ids)
    }

    fn allocate_normalized_output_targets(
        &mut self,
        site: NormalizedOpSite,
    ) -> Result<(RenderObservationId, RenderObservationId), LegacyObservationJournalError> {
        let projection = self.normalized_projection(site)?;
        let block = projection.block;
        let output = projection
            .output
            .ok_or(LegacyObservationJournalError::MissingNormalizedOutput(site))?;
        self.value_slot(output.value)?;
        let write = self.rendered_write_observation(output.inst)?;
        self.allocate_pair(
            ObservationTarget::Value(output.value),
            ObservationTarget::Write {
                inst: output.inst,
                observation: write,
                block,
            },
        )
    }

    /// Mark one value occurrence and every original use represented by the
    /// exact normalized operand that produced it.
    ///
    /// Callers cannot supply a `ValueId`, `UseSite`, or machine disposition:
    /// all three come from the authority-checked normalization projection and
    /// binding plan retained by this journal.
    #[cfg(test)]
    pub(crate) fn observe_normalized_input_expr(
        &mut self,
        site: NormalizedOpSite,
        input_idx: usize,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        let marked = self.observe_normalized_input_value_expr(site, input_idx, expr)?;
        self.observe_normalized_input_uses_expr(site, input_idx, marked)
    }

    /// Mark the base SSA value before any per-use machine projection is
    /// applied. This keeps one value disposition independent from the several
    /// exact widths or slices at which that value may be consumed.
    #[cfg(test)]
    pub(crate) fn observe_normalized_input_value_expr(
        &mut self,
        site: NormalizedOpSite,
        input_idx: usize,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        let input = self
            .normalized_projection(site)?
            .inputs
            .get(input_idx)
            .cloned()
            .ok_or(LegacyObservationJournalError::InvalidNormalizedInput { site, input_idx })?;
        let value = input.value;
        self.value_slot(value)?;
        let id = self
            .allocate_many(vec![ObservationTarget::Value(value)])?
            .into_iter()
            .next()
            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        Ok(CExpr::observed(id, expr))
    }

    /// Mark one exact semantic value read that has no graph [`UseSite`].
    ///
    /// Return values are certified at the return instruction by the source
    /// boundary contract, while the lifted `Return` operand itself is the
    /// control target. This marker carries that exact `(ValueId, InstId)` into
    /// final declaration placement without inventing an operand index.
    /// Derive every cell one rendered replacement owns.
    ///
    /// The opaque input says what the replacement rendered and carries the
    /// complete set of definitions and effects derived by operation lowering.
    /// No other production module can construct it. This owner derives the
    /// value, use, write, and literal targets from the source graph, validates
    /// the effect targets against the source inventory, and attaches every
    /// target to the same concrete occurrence.
    ///
    /// A replaced producer must be inline in the sealed plan. Duplicability is
    /// not a rendering disposition: accepting a bound output here would mark
    /// its write both on its own assignment and on the replacement. Refusing
    /// the contract at this boundary prevents that second answerer.
    ///
    /// Values without definitions need explicit derivation. A folded literal
    /// can never occur in `replaced`, but it is still an operand of one of
    /// those instructions and has no other occurrence after replacement. Its
    /// value cell is therefore part of this same contract, deduplicated with
    /// the root, produced values, and exact child markers already carried by
    /// the expression.
    #[track_caller]
    pub(crate) fn observe_rendered_replacement_expr(
        &mut self,
        contract: crate::fold::op_lower::RenderedReplacementContract,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        let (expr, value, replaced, obligations) = contract.into_parts();
        self.value_slot(value)?;
        // A stack address the geometry certificate elided has no occurrence;
        // the spelling that stands in its place names the cell, not the value.
        let mut targets = if self.stack_geometry_elides(value) {
            Vec::new()
        } else {
            vec![ObservationTarget::Value(value)]
        };
        targets.extend(self.discharged_instruction_targets(Some(value), &replaced, Some(&expr))?);

        for obligation in obligations {
            if !self.effect_occurrences.contains_key(&obligation) {
                return Err(LegacyObservationJournalError::InvalidEffectObligation(
                    obligation,
                ));
            }
            targets.push(ObservationTarget::Effect(obligation));
        }

        let mut marked = expr;
        for id in self.allocate_many(targets)? {
            marked = CExpr::observed(id, marked);
        }
        Ok(marked)
    }

    /// The cells a bound value's assignment owes when its right-hand side is
    /// the rewriter's canonical term rather than the operation's own lowering.
    ///
    /// Two of them, and neither is answered by the statement's own markers.
    ///
    /// The producers the term absorbed are the same contract the inline path
    /// makes: their writes, their outputs and their operands vanish into this
    /// expression. It is the expression form of the walk rather than the
    /// statement form, because the statement here answers for the operands of
    /// *its* operation and not for theirs.
    ///
    /// The definition's own operands are the second, and they are why this is
    /// not simply the discharge walk with one more instruction in the list.
    /// The statement owns its write and its value, so the definition must not
    /// be walked as a discharge; but a rewrite absorbs operands as readily as
    /// it absorbs producers, and an operand with no definition of its own --
    /// a folded literal, `x | 0x811c9dc5` proven to be the constant -- then
    /// has no occurrence anywhere in the function. Everything else the rewrite
    /// drops still has one: a bound operand has its own statement, and an
    /// inline operand with a definition is in the absorbed list above.
    pub(crate) fn observe_canonical_assignment_stmt(
        &mut self,
        value: ValueId,
        definition: InstId,
        absorbed: &[InstId],
        stmt: CStmt,
    ) -> Result<CStmt, LegacyObservationJournalError> {
        let rhs = assignment_rhs(&stmt).ok_or_else(|| {
            LegacyObservationJournalError::rendered_value_required(
                value,
                RenderedValueRequirementCause::NonrenderedValueDisposition,
                self.plan.disposition(value),
            )
        })?;
        let mut represented = self.expr_value_observations(rhs);
        let mut targets = self.discharged_instruction_targets(Some(value), absorbed, Some(rhs))?;
        represented.extend(targets.iter().filter_map(|target| match target {
            ObservationTarget::Value(value) => Some(*value),
            _ => None,
        }));
        represented.insert(value);
        let inputs = self
            .source
            .graph()
            .inst(definition)
            .ok_or(LegacyObservationJournalError::InvalidWrite(definition))?
            .inputs
            .clone();
        for input in inputs.iter().copied() {
            if !represented.insert(input)
                || !matches!(
                    self.plan.disposition(input),
                    Some(ValueDisposition::Inline { .. })
                )
                || self.source.graph().def_inst(input).is_some()
            {
                continue;
            }
            self.value_slot(input)?;
            targets.push(ObservationTarget::Value(input));
        }
        let mut marked = stmt;
        for id in self.allocate_many(targets)? {
            marked = CStmt::observed(id, marked);
        }
        Ok(marked)
    }

    pub(crate) fn observe_certified_value_read_expr(
        &mut self,
        value: ValueId,
        at: InstId,
        symbol: SymbolId,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.observe_certified_read_expr(
            value,
            crate::binding_plan::CertifiedValueReadSource::Boundary(at),
            symbol,
            expr,
        )
    }

    /// Mark one spelled frame-object address inside the rendering of `value`.
    ///
    /// The plan's canonical term for `value` names the object's address, the
    /// object is bound, and the expression is that binding's address spelling.
    pub(crate) fn observe_object_address_expr(
        &mut self,
        value: ValueId,
        object: r2ssa::ObjectId,
        expr: CExpr,
        block: u64,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.value_slot(value)?;
        if !crate::placement::value_names_object_address(&self.plan, value, object) {
            // Which of the two it is decides where to look: a value with no
            // planned spelling at all, or one whose spelling is not this
            // object's address.
            r2il::refusal_evidence!(
                "object-address",
                "{value:?} does not name {object:?}: disposition {:?}",
                self.plan.disposition(value)
            );
            return Err(LegacyObservationJournalError::MissingPlannedValue(value));
        }
        let Some(StackObjectDisposition::Bound { binding }) =
            self.plan.stack_object_disposition(object)
        else {
            r2il::refusal_evidence!(
                "object-address",
                "{object:?} is not bound: {:?}",
                self.plan.stack_object_disposition(object)
            );
            return Err(LegacyObservationJournalError::MissingPlannedValue(value));
        };
        let Some(symbol) = self.names.symbol_for_binding(binding) else {
            r2il::refusal_evidence!("object-address", "{binding:?} has no symbol");
            return Err(LegacyObservationJournalError::MissingPlannedValue(value));
        };
        let is_array = self
            .plan
            .binding(binding)
            .is_some_and(|binding| binding.declaration_type().is_array());
        if !crate::placement::frame_object_address_expr_matches(&expr, symbol, is_array) {
            r2il::refusal_evidence!(
                "object-address",
                "{value:?} spells {object:?} bound to {binding:?} as {expr:?}, not its address"
            );
            return Err(LegacyObservationJournalError::MissingPlannedValue(value));
        }
        let id = self
            .allocate_many(vec![ObservationTarget::ObjectAddress {
                value,
                object,
                binding,
                symbol,
                block,
            }])?
            .into_iter()
            .next()
            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        Ok(CExpr::observed(id, expr))
    }

    pub(crate) fn observe_certified_address_read_expr(
        &mut self,
        value: ValueId,
        access: r2ssa::StructuredAccessId,
        symbol: SymbolId,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.observe_certified_read_expr(
            value,
            crate::binding_plan::CertifiedValueReadSource::Address(access),
            symbol,
            expr,
        )
    }

    pub(crate) fn observe_certified_lane_read_expr(
        &mut self,
        value: ValueId,
        access: r2ssa::StructuredAccessId,
        symbol: SymbolId,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.observe_certified_read_expr(
            value,
            crate::binding_plan::CertifiedValueReadSource::Lane(access),
            symbol,
            expr,
        )
    }

    fn observe_certified_read_expr(
        &mut self,
        value: ValueId,
        source: crate::binding_plan::CertifiedValueReadSource,
        symbol: SymbolId,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.value_slot(value)?;
        // The same boundary record the final placement audit will consult.
        // Two tables answering for one read is how a marker survives here and
        // is refused there, so they ask one question.
        if !crate::binding_plan::certified_value_read(&self.source, value, source) {
            return Err(LegacyObservationJournalError::InvalidCertifiedValueRead {
                value,
                at: source.inst(),
            });
        }
        let Some(ValueDisposition::Bound { binding }) = self.plan.disposition(value) else {
            return Err(LegacyObservationJournalError::rendered_value_required(
                value,
                RenderedValueRequirementCause::CertifiedReadDispositionNotBound,
                self.plan.disposition(value),
            ));
        };
        if !crate::placement::expr_reads_symbol(&expr, symbol) {
            // Which spelling was written instead: the read is certified and the
            // binding is known, so the disagreement is about the expression.
            r2il::refusal_evidence!(
                "certified-read",
                "{value:?} bound to {binding:?} renders as {expr:?} which does not read \
                 symbol {symbol:?}"
            );
            return Err(LegacyObservationJournalError::rendered_value_required(
                value,
                RenderedValueRequirementCause::CertifiedReadExpressionMissingSymbol,
                self.plan.disposition(value),
            ));
        }
        // A value its own statement defines is answered by that definition, and
        // a read of it is not a second answer. Only a value nothing defines --
        // one the caller supplied -- has its cell answered where it is read.
        let defined = self.source.graph().def_inst(value).is_some();
        let mut targets = Vec::with_capacity(2);
        if !defined {
            targets.push(ObservationTarget::Value(value));
        }
        targets.push(ObservationTarget::CertifiedValueRead {
            value,
            source,
            binding: *binding,
            symbol,
        });
        let mut ids = self.allocate_many(targets)?.into_iter();
        let value_id = if defined { None } else { ids.next() };
        if !defined && value_id.is_none() {
            return Err(LegacyObservationJournalError::TooManyObservations);
        }
        let read_id = ids
            .next()
            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        let marked = match value_id {
            Some(value_id) => CExpr::observed(value_id, expr),
            None => expr,
        };
        Ok(CExpr::observed(read_id, marked))
    }

    /// Mark the exact value a certified stack-array subscript uses as its
    /// element index.
    ///
    /// The machine store reads the completed address, not this earlier SSA
    /// value directly. Replacing that address with `array[index]` introduces a
    /// C read of the index binding, so the array element certificate is the
    /// authority for that replacement occurrence. The ordinary value marker
    /// installed while the term is rendered still fills the value cell; this
    /// target supplies the placement read.
    pub(crate) fn observe_certified_array_index_expr(
        &mut self,
        access: r2ssa::StructuredAccessId,
        value: ValueId,
        symbol: SymbolId,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        self.value_slot(value)?;
        let Some(ValueDisposition::Bound { binding }) = self.plan.disposition(value) else {
            return Err(LegacyObservationJournalError::rendered_value_required(
                value,
                RenderedValueRequirementCause::CertifiedReadDispositionNotBound,
                self.plan.disposition(value),
            ));
        };
        if !crate::placement::certified_array_index_read_matches(
            &self.source,
            &self.names,
            access,
            value,
            *binding,
            symbol,
        ) {
            return Err(LegacyObservationJournalError::InvalidCertifiedValueRead {
                value,
                at: access.inst,
            });
        }
        if !crate::placement::expr_reads_symbol(&expr, symbol) {
            // Which spelling was written instead: the read is certified and the
            // binding is known, so the disagreement is about the expression.
            r2il::refusal_evidence!(
                "certified-read",
                "{value:?} bound to {binding:?} at an address access renders as {expr:?} \
                 which does not read symbol {symbol:?}"
            );
            return Err(LegacyObservationJournalError::rendered_value_required(
                value,
                RenderedValueRequirementCause::CertifiedReadExpressionMissingSymbol,
                self.plan.disposition(value),
            ));
        }
        let read_id = self
            .allocate_many(vec![ObservationTarget::CertifiedArrayIndexRead {
                access,
                value,
                binding: *binding,
                symbol,
            }])?
            .into_iter()
            .next()
            .ok_or(LegacyObservationJournalError::TooManyObservations)?;
        Ok(CExpr::observed(read_id, expr))
    }

    /// Mark one exact rendered access to a source-owned stack-object binding.
    ///
    /// The structured access owns the object, the binding plan owns the
    /// object-to-binding projection, and name resolution owns the symbol. A
    /// non-stack memory access returns unchanged; no address spelling or stack
    /// offset is consulted here.
    pub(crate) fn observe_stack_access_expr(
        &mut self,
        access: r2ssa::StructuredAccessId,
        is_write: bool,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        // Four checks share one error, and which of them refused is the
        // whole trace when it does.
        let invalid = |why: &str| {
            r2il::refusal_evidence!(
                "stack-access-observe",
                "{access:?} is_write={is_write}: {why}"
            );
            LegacyObservationJournalError::InvalidUse(UseSite {
                inst: access.inst,
                input_idx: 0,
            })
        };
        let fact = self
            .source
            .structured()
            .memory_accesses
            .get(&access)
            .filter(|fact| {
                fact.id == access && fact.is_write == is_write && fact.provenance_complete
            })
            .ok_or_else(|| invalid("no complete access fact of this direction"))?
            .clone();
        let fact = &fact;
        let Some(disposition) = self.plan.stack_object_disposition(fact.object) else {
            return Ok(expr);
        };
        let StackObjectDisposition::Bound { binding } = disposition else {
            return Err(invalid(&format!(
                "object {:?} is not bound: {disposition:?}",
                fact.object
            )));
        };
        let symbol = self
            .names
            .symbol_for_binding(binding)
            .ok_or_else(|| invalid("the binding has no symbol"))?;
        if !crate::placement::stack_access_expr_mentions_slot(
            &self.source,
            &self.names,
            access,
            &expr,
            symbol,
        ) {
            return Err(invalid(&format!(
                "the expression {expr:?} does not read {symbol:?}"
            )));
        }
        // The address the machine computed has no separate spelling here: the
        // rendered lvalue names the object it addressed, so the statements that
        // computed the address vanished into it and it answers for their cells.
        // A producer the expression's own replacement already stands for --
        // the rewriter's subscript marks every value it absorbed -- is not
        // discharged a second time here.
        let already_represented = self.expr_value_observations(&expr);
        let mut discharged = self.inlined_address_producers(fact.address);
        discharged.retain(|inst| {
            self.source
                .graph()
                .inst(*inst)
                .and_then(|inst| inst.output)
                .is_none_or(|output| !already_represented.contains(&output))
        });
        let mut targets = vec![ObservationTarget::StackAccess {
            access,
            object: fact.object,
            binding,
            symbol,
            is_write,
            rendered_block: None,
        }];
        // An operand of the address that is the object's own address is
        // spelled by the object's name: `buf + i` reads `buf` by naming it,
        // whatever else the base register was read for.
        let graph = self.source.graph();
        let objects = self.source.objects();
        let spelled_by_the_object = discharged
            .iter()
            .filter_map(|inst| graph.inst(*inst))
            .flat_map(|inst| inst.inputs.iter().copied())
            .filter(|input| {
                objects.object_for_value(*input, r2il::SpaceId::Ram) == Some(fact.object)
            })
            .collect::<Vec<_>>();
        // One whose producer this access discharges has no occurrence of its
        // own anywhere: the object's name stands for it, so its cell is
        // elided once, the way the geometry elides a frame address. One spelled
        // somewhere else keeps the cell its own spelling owns.
        let elided_bases = spelled_by_the_object
            .iter()
            .copied()
            .filter(|value| {
                matches!(
                    self.plan.disposition(*value),
                    Some(ValueDisposition::Inline { .. })
                ) && graph
                    .def_inst(*value)
                    .is_some_and(|definition| discharged.contains(&definition))
            })
            .collect::<Vec<_>>();
        for value in elided_bases {
            let slot = self.value_slot_mut(value)?;
            Self::record_removed_value(slot, crate::ledger::ElisionReason::DeadStackBase);
        }
        targets.extend(self.discharged_instruction_targets_with(
            &spelled_by_the_object,
            &discharged,
            Some(&expr),
        )?);
        // The statements went here, and so did the obligations they owed: a
        // frame address computation carries a live-value producer, and its
        // occurrence is this access.
        for inst in &discharged {
            for obligation in self.source.obligations().obligations_for_inst(*inst) {
                if self.effect_occurrences.contains_key(&obligation.id) {
                    targets.push(ObservationTarget::Effect(obligation.id));
                }
            }
        }
        let mut marked = expr;
        for id in self.allocate_many(targets)? {
            marked = CExpr::observed(id, marked);
        }
        Ok(marked)
    }

    pub(crate) fn record_removed_value(
        slot: &mut Option<LegacyValueObservation>,
        reason: crate::ledger::ElisionReason,
    ) {
        if slot.is_none() {
            *slot = Some(LegacyValueObservation::Elided(reason));
        }
    }

    pub(crate) fn record_removed_use(
        slot: &mut Option<LegacyUseObservation>,
        reason: crate::ledger::ElisionReason,
    ) {
        if slot.is_none() {
            *slot = Some(LegacyUseObservation::Elided(reason));
        }
    }

    pub(crate) fn record_removed_write(
        slot: &mut Option<LegacyWriteObservation>,
        reason: crate::ledger::ElisionReason,
    ) {
        if slot.is_none() {
            *slot = Some(LegacyWriteObservation::Elided(reason));
        }
    }

    /// Mark every exact original use outside the already-projected expression.
    pub(crate) fn observe_normalized_input_uses_expr(
        &mut self,
        site: NormalizedOpSite,
        input_idx: usize,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        let projection = self.normalized_projection(site)?;
        let block = projection.block;
        let input = projection
            .inputs
            .get(input_idx)
            .cloned()
            .ok_or(LegacyObservationJournalError::InvalidNormalizedInput { site, input_idx })?;
        let rendered_symbols = Self::expr_symbols(&expr);
        let mut targets = Vec::with_capacity(input.uses.len());
        for use_site in input.uses {
            // A spelling that names the object rather than the stack pointer
            // absorbs the base, whether the object is being accessed or its
            // address computed. What decides it is whether this rendering
            // spells the base, never what kind of operand it is: the rewriter
            // turns `esp + 4` into the object's address exactly as it turns
            // `[esp + 4]` into the object, and the base is read nowhere in
            // either.
            let observation = if self.stack_base_absorbed_by(input.value, &rendered_symbols) {
                LegacyUseObservation::Elided(crate::ledger::ElisionReason::DeadStackBase)
            } else {
                self.rendered_use_observation(use_site)?
            };
            targets.push(ObservationTarget::Use {
                site: use_site,
                observation,
                block,
            });
        }
        let mut marked = expr;
        for id in self.allocate_many(targets)? {
            marked = CExpr::observed(id, marked);
        }
        Ok(marked)
    }

    /// Mark one rendered definition and its source write using the exact
    /// normalized output projection.
    pub(crate) fn observe_normalized_output_stmt(
        &mut self,
        site: NormalizedOpSite,
        stmt: CStmt,
    ) -> Result<CStmt, LegacyObservationJournalError> {
        let (value_id, write_id) = self.allocate_normalized_output_targets(site)?;
        Ok(CStmt::observed(write_id, CStmt::observed(value_id, stmt)))
    }

    /// Mark one rendered definition that survives inside an expression.
    ///
    /// This is the expression twin of [`Self::observe_normalized_output_stmt`].
    /// Both value and write identity come exclusively from the authority-bound
    /// normalized output projection retained by this journal.
    #[cfg(test)]
    pub(crate) fn observe_normalized_output_expr(
        &mut self,
        site: NormalizedOpSite,
        expr: CExpr,
    ) -> Result<CExpr, LegacyObservationJournalError> {
        let (value_id, write_id) = self.allocate_normalized_output_targets(site)?;
        Ok(CExpr::observed(write_id, CExpr::observed(value_id, expr)))
    }

    fn allocate_effect_targets(
        &mut self,
        obligation_ids: &BTreeSet<SemanticObligationId>,
    ) -> Result<Vec<RenderObservationId>, LegacyObservationJournalError> {
        for id in obligation_ids {
            if !self.effect_occurrences.contains_key(id) {
                return Err(LegacyObservationJournalError::InvalidEffectObligation(*id));
            }
        }
        self.allocate_many(
            obligation_ids
                .iter()
                .copied()
                .map(ObservationTarget::Effect)
                .collect(),
        )
    }

    /// Attach exact source-obligation cells to one concrete statement.
    ///
    /// Call this only after the upstream render certificate has selected the
    /// exact obligation IDs discharged by the construct. The IDs are checked
    /// against this journal's source-owned inventory, allocated in canonical
    /// order, and counted only if this statement occurrence reaches sealing.
    pub(crate) fn observe_effect_stmt(
        &mut self,
        obligation_ids: &BTreeSet<SemanticObligationId>,
        stmt: CStmt,
    ) -> Result<CStmt, LegacyObservationJournalError> {
        if matches!(stmt.unobserved(), CStmt::Comment(_) | CStmt::Empty) {
            return Ok(stmt);
        }
        let mut marked = stmt;
        for id in self.allocate_effect_targets(obligation_ids)? {
            marked = CStmt::observed(id, marked);
        }
        Ok(marked)
    }

    /// Mark one gap statement with every cell it accounts for.
    ///
    /// The cells come from the caller's closure of the refusal, and each one
    /// is attached to this single occurrence. A cell already answered by a
    /// rendered occurrence is a conflict at the seal rather than a silent
    /// second answer, which is what keeps a gap from covering for a statement
    /// that in fact rendered.
    pub(crate) fn gap_stmt(
        &mut self,
        anchor: GapAnchor,
        marker: crate::ast::GapMarker,
        cells: &[GapCell],
    ) -> Result<CStmt, LegacyObservationJournalError> {
        // Three answers a cell can already hold, and the gap treats each
        // differently.
        //
        // An upstream refusal is what the gap exists to make visible: the
        // machine projection could give the operation no semantics, and until
        // now the output said nothing about that. The gap takes that cell
        // over, so a reader sees a marker where there was silence.
        //
        // An elision is a proof that the cell needs no output, which is a
        // stronger statement than the gap's and stays: the gap simply does
        // not claim it.
        //
        // Anything else is a rendered claim, and a gap that overwrote one
        // would be covering for output that exists.
        let mut claimed = Vec::with_capacity(cells.len());
        for cell in cells {
            match *cell {
                GapCell::Value(value) => {
                    let slot = self.value_slot_mut(value)?;
                    match slot {
                        None => {}
                        Some(LegacyValueObservation::Refused(_)) => *slot = None,
                        Some(LegacyValueObservation::Elided(_)) => continue,
                        Some(_) => {
                            return Err(LegacyObservationJournalError::ConflictingValue(value));
                        }
                    }
                }
                GapCell::Use { site, .. } => {
                    let slot = self
                        .uses
                        .get_mut(site.inst.0 as usize)
                        .and_then(|row| row.get_mut(site.input_idx))
                        .ok_or(LegacyObservationJournalError::InvalidUse(site))?;
                    match slot {
                        None => {}
                        Some(LegacyUseObservation::Refused(_)) => *slot = None,
                        Some(LegacyUseObservation::Elided(_)) => continue,
                        Some(_) => {
                            return Err(conflicting_use(site));
                        }
                    }
                }
                GapCell::Write(inst) => {
                    if !self
                        .write_has_output
                        .get(inst.0 as usize)
                        .copied()
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let slot = self
                        .writes
                        .get_mut(inst.0 as usize)
                        .ok_or(LegacyObservationJournalError::InvalidWrite(inst))?;
                    match slot {
                        None => {}
                        Some(LegacyWriteObservation::Refused(_)) => *slot = None,
                        Some(LegacyWriteObservation::Elided(_)) => continue,
                        Some(existing) => {
                            if r2il::refusal_evidence::tracing() {
                                eprintln!("gapped write {inst:?}: already recorded {existing:?}");
                            }
                            return Err(conflicting_write(inst));
                        }
                    }
                }
                GapCell::Effect(obligation) => {
                    if !self.effect_occurrences.contains_key(&obligation) {
                        return Err(LegacyObservationJournalError::InvalidEffectObligation(
                            obligation,
                        ));
                    }
                }
            }
            if let GapCell::Value(value) = *cell {
                self.gapped_values.insert(value);
            }
            claimed.push(*cell);
        }
        let targets = claimed
            .iter()
            .map(|cell| ObservationTarget::Gapped {
                anchor,
                cell: *cell,
            })
            .collect();
        let mut marked = CStmt::Gap(marker);
        for id in self.allocate_many(targets)? {
            marked = CStmt::observed(id, marked);
        }
        Ok(marked)
    }

    /// Record a value only when the sealed plan proves that no rendered AST
    /// occurrence is allowed for it.
    pub(crate) fn record_nonrendered_value(
        &mut self,
        value: ValueId,
    ) -> Result<(), LegacyObservationJournalError> {
        let observation = match self.plan.disposition(value) {
            Some(ValueDisposition::Elided { reason, .. }) => {
                LegacyValueObservation::Elided(*reason)
            }
            Some(ValueDisposition::Refused { reason }) => LegacyValueObservation::Refused(*reason),
            Some(ValueDisposition::Bound { .. } | ValueDisposition::Inline { .. }) | None => {
                return Err(LegacyObservationJournalError::rendered_value_required(
                    value,
                    RenderedValueRequirementCause::NonrenderedValueDisposition,
                    self.plan.disposition(value),
                ));
            }
        };
        let slot = self.value_slot_mut(value)?;
        record_same(slot, observation)
            .map_err(|()| LegacyObservationJournalError::ConflictingValue(value))
    }

    /// Record an upstream refusal for a use that therefore has no AST node.
    pub(crate) fn record_refused_use(
        &mut self,
        site: UseSite,
    ) -> Result<(), LegacyObservationJournalError> {
        let observation = match self.plan.use_disposition(site) {
            Some(MachineUseDisposition::Refused(reason)) => LegacyUseObservation::Refused(reason),
            Some(MachineUseDisposition::Exact(_) | MachineUseDisposition::MemoryAddress(_))
            | None => {
                return Err(
                    LegacyObservationJournalError::ExactUseRequiresRenderedOccurrence(site),
                );
            }
        };
        let slot = self.use_slot_mut(site)?;
        if record_same(slot, observation).is_err() {
            if r2il::refusal_evidence::tracing() {
                eprintln!("conflicting use {site:?}: recorded {slot:?}, refusal {observation:?}");
            }
            Err(conflicting_use(site))
        } else {
            Ok(())
        }
    }

    /// Record an upstream refusal for a write that therefore has no AST node.
    pub(crate) fn record_refused_write(
        &mut self,
        inst: InstId,
    ) -> Result<(), LegacyObservationJournalError> {
        let observation = match self.plan.write_disposition(inst) {
            Some(MachineWriteDisposition::Refused(reason)) => {
                LegacyWriteObservation::Refused(*reason)
            }
            Some(MachineWriteDisposition::Exact(_)) | None => {
                return Err(
                    LegacyObservationJournalError::ExactWriteRequiresRenderedOccurrence(inst),
                );
            }
        };
        let slot = self.write_slot_mut(inst)?;
        record_same(slot, observation)
            .map_err(|()| LegacyObservationJournalError::ConflictingWrite(inst))
    }
}
