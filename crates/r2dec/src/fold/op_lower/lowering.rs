use super::calls::CertifiedCallArgs;
use super::memory_renderer::CertifiedMemoryAccessExpr;
use super::projection::project_machine_write;
use super::*;
use r2rewrite::CValue;

/// Every definition the sealed inline plan would have nested under `value`.
///
/// Ordinary inline lowering records these through nested replacement
/// expressions. A frame-object address replaces the whole expression with one
/// program-object spelling, so it has no nested AST on which to carry those
/// contracts and must collect the same closure up front.
fn operation_requires_final_write_projection(op: &SSAOp) -> bool {
    op.dst().is_some()
}

/// One bound value's assignment, spelled from the rewriter's canonical term.
///
/// The cells it owes travel with it because they are not the cells the
/// operation arms' statement would have owed; see
/// [`FoldingContext::canonical_bound_assignment`].
struct CanonicalBoundAssignment {
    stmt: CStmt,
    value: ValueId,
    definition: r2ssa::InstId,
    /// The producers the term expanded and then stopped reading.
    absorbed: Vec<r2ssa::InstId>,
}

impl<'a> FoldingContext<'a> {
    /// Turn one opaque rendering result into the complete source-cell set it
    /// replaces. This is the only extractor for [`PendingReplacementExpr`].
    ///
    /// A plain value read replaces no instruction. An inlined value replaces
    /// its definition when one exists. Canonical memory rewrites replace
    /// exactly the instructions recorded by the authority-bound access term.
    /// Callers cannot pass any of those instruction lists.
    #[track_caller]
    pub(super) fn finish_replacement_expr(&self, pending: PendingReplacementExpr) -> CExpr {
        let PendingReplacementExpr {
            expr,
            value,
            source,
        } = pending;
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let invalid = || {
            crate::observation_journal::LegacyObservationJournalError::MissingPlannedValue(value)
        };
        let Some(prepared) = self.inputs.prepared_ssa else {
            self.retain_first_observation_error(invalid());
            return expr;
        };
        let replaced = match source {
            ReplacementSource::RenderedValue => Vec::new(),
            ReplacementSource::PlannedInline => {
                let Some(names) = self.inputs.binding_names else {
                    self.retain_first_observation_error(invalid());
                    return expr;
                };
                let Some(rewrite) = names.plan().canonical().value(value) else {
                    self.retain_first_observation_error(invalid());
                    return expr;
                };
                let mut replaced = prepared
                    .graph()
                    .def_inst(value)
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                for id in &rewrite.discharges {
                    let Some(inst) = (match id.site {
                        r2ssa::CanonicalInstructionSite::Op(ordinal) => {
                            usize::try_from(ordinal).ok().and_then(|op_idx| {
                                prepared.graph().inst_id_for_op_site(id.block_addr, op_idx)
                            })
                        }
                        r2ssa::CanonicalInstructionSite::Phi(_)
                        | r2ssa::CanonicalInstructionSite::NativeSpan { .. } => None,
                    }) else {
                        self.retain_first_observation_error(invalid());
                        return expr;
                    };
                    replaced.insert(inst);
                }
                replaced.into_iter().collect()
            }
            ReplacementSource::CanonicalAccess(access) => {
                let Some(names) = self.inputs.binding_names else {
                    self.retain_first_observation_error(invalid());
                    return expr;
                };
                let Some(rewrite) = names.plan().canonical().access(access) else {
                    self.retain_first_observation_error(invalid());
                    return expr;
                };
                let replaced = rewrite
                    .discharges
                    .iter()
                    .filter_map(|id| match id.site {
                        r2ssa::CanonicalInstructionSite::Op(ordinal) => {
                            usize::try_from(ordinal).ok().and_then(|op_idx| {
                                prepared.graph().inst_id_for_op_site(id.block_addr, op_idx)
                            })
                        }
                        r2ssa::CanonicalInstructionSite::Phi(_)
                        | r2ssa::CanonicalInstructionSite::NativeSpan { .. } => None,
                    })
                    .collect::<Vec<_>>();
                if replaced.len() != rewrite.discharges.len() {
                    self.retain_first_observation_error(invalid());
                    return expr;
                }
                replaced
            }
        };
        let obligations = replaced
            .iter()
            .flat_map(|definition| {
                let output = prepared
                    .graph()
                    .inst(*definition)
                    .and_then(|inst| inst.output);
                self.exact_effect_obligations_for_source_inst(
                    EffectOccurrenceKind::Expression,
                    *definition,
                    output,
                )
            })
            .collect::<BTreeSet<_>>();
        r2il::refusal_evidence!(
            "replacement-discharges",
            "{value:?} from {source:?} discharges {replaced:?} as {expr:?}"
        );
        let fallback = expr.clone();
        let contract = RenderedReplacementContract::new(expr, value, replaced, obligations);
        match journal
            .borrow_mut()
            .observe_rendered_replacement_expr(contract)
        {
            Ok(marked) => marked,
            Err(error) => {
                self.retain_first_observation_error(error);
                fallback
            }
        }
    }

    fn observation_lowering_refusal(
        error: &crate::observation_journal::LegacyObservationJournalError,
    ) -> OpLoweringRefusal {
        use crate::observation_journal::LegacyObservationJournalError as Error;
        match error {
            Error::RenderedValueRequired { .. }
            | Error::InvalidPlannedInline { .. }
            | Error::PlannedElidedValueRendered { .. }
            | Error::PlannedRefusedValueRendered { .. }
            | Error::MissingPlannedValue(_) => {
                if r2il::refusal_evidence::tracing() {
                    eprintln!("refusal from journal error {error:?}");
                }
                OpLoweringRefusal::missing_program_variable()
            }
            other => {
                if r2il::refusal_evidence::tracing() {
                    eprintln!("refusal from journal error {other:?}");
                }
                OpLoweringRefusal::missing_machine_projection()
            }
        }
    }

    fn exact_normalized_op_effects(
        &self,
        op: &SSAOp,
        block_addr: u64,
        op_idx: usize,
    ) -> std::collections::BTreeSet<r2ssa::SemanticObligationId> {
        // A call has no `dst`. One statement implements two instructions --
        // the call supplies the effect, the `CallDefine` owns the write -- so
        // the value the occurrence names has to come from the site's certified
        // result rather than from the operation's own output, which does not
        // exist. Without it the call-result obligation matched no occurrence
        // and every function that called anything was refused for a result its
        // rendering did assign.
        let rendered_value = match op {
            SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                self.certified_call_result_value((block_addr, op_idx))
            }
            _ => op.dst().and_then(|dst| self.value_id_for_rendered_op(dst)),
        };
        let mut obligations = self.exact_effect_obligations_for_normalized_value(
            EffectOccurrenceKind::Expression,
            block_addr,
            op_idx,
            rendered_value,
        );
        // The other half of the same statement. `x = f()` renders the call and
        // the definition of its result at once, so the `CallDefine`'s own
        // obligations are answered here; the `CallDefine` itself lowers to no
        // statement precisely because this one already assigned it, and left
        // alone its producer obligation had nothing to name.
        if matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
            && let Some((define_block, define_idx)) =
                self.certified_call_result_definition_site((block_addr, op_idx))
        {
            obligations.extend(self.exact_effect_obligations_for_normalized_value(
                EffectOccurrenceKind::Expression,
                define_block,
                define_idx,
                rendered_value,
            ));
        }
        // Memory-effect ownership comes from the exact source operation and its
        // certified access, not from the finalized C shape. A stack-object
        // assignment is still the same source Store even though its AST no
        // longer contains a pointer dereference.
        // A decomposed wide store is one write per member, and each member's
        // access carries its own obligation.
        if let SSAOp::Store { .. } = op
            && let Some(run) = self
                .prepared_ssa()
                .and_then(|prepared| prepared.graph().inst_id_for_op_site(block_addr, op_idx))
                .and_then(|inst| {
                    self.prepared_ssa()?
                        .structured()
                        .member_run_stores
                        .get(&inst)
                })
        {
            for member in &run.members {
                obligations.extend(self.exact_effect_obligations_for_member_access(
                    run.inst,
                    member.access,
                    run.address,
                    match member.source {
                        r2ssa::MemberRunSource::Constant(_) => None,
                        r2ssa::MemberRunSource::Lane(value) => Some(value),
                    },
                ));
            }
            return obligations;
        }
        if matches!(op, SSAOp::BlockTransfer { .. }) {
            obligations.extend(self.block_transfer_effect_obligations(block_addr, op_idx));
            return obligations;
        }
        let memory = match op {
            SSAOp::Load { .. } => self
                .certified_memory_access_for_current_op(false)
                .map(|cert| (EffectOccurrenceKind::MemoryRead, cert)),
            SSAOp::Store { .. } => self
                .certified_memory_access_for_current_op(true)
                .map(|cert| (EffectOccurrenceKind::MemoryWrite, cert)),
            _ => None,
        };
        if let Some((kind, cert)) = memory {
            obligations.extend(self.exact_effect_obligations_for_normalized_memory(
                kind,
                block_addr,
                op_idx,
                cert.space,
                Some(cert.address),
                cert.value,
            ));
        }
        obligations
    }

    pub(super) fn normalized_output_projection(
        &self,
        site: crate::normalize::NormalizedOpSite,
    ) -> Result<
        crate::normalize::NormalizedOutputProjection,
        crate::observation_journal::LegacyObservationJournalError,
    > {
        let prepared = self.inputs.prepared_ssa.ok_or(
            crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
        )?;
        self.inputs
            .normalization_origins
            .ok_or(
                crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
            )?
            .projection(site, prepared)
            .map_err(crate::observation_journal::LegacyObservationJournalError::Normalization)?
            .ok_or(
                crate::observation_journal::LegacyObservationJournalError::InvalidNormalizedSite(
                    site,
                ),
            )?
            .output
            .ok_or(
                crate::observation_journal::LegacyObservationJournalError::MissingNormalizedOutput(
                    site,
                ),
            )
    }

    fn project_planned_assignment(
        &self,
        site: Option<crate::normalize::NormalizedOpSite>,
        lhs: CExpr,
        rhs: CExpr,
    ) -> Result<(CExpr, CExpr), crate::observation_journal::LegacyObservationJournalError> {
        let Some(site) = site else {
            return Ok((lhs, rhs));
        };
        let output = self.normalized_output_projection(site)?;
        let Some(names) = self.inputs.binding_names else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::MissingPlannedValue(
                    output.value,
                ),
            );
        };
        match names.require_write(output.inst) {
            Ok(r2ssa::MachineWriteDisposition::Exact(projection)) => {
                // What the right-hand side has: stated by the lowering that
                // built it, or, where it built the assignment directly, by
                // the typed boundaries of the operation's root.
                let rhs_type = self.pending_assignment_type.take().or_else(|| {
                    let root = names
                        .plan()
                        .machine_projection()
                        .entity_for_output(output.value)?
                        .root();
                    names.plan().typed_boundaries().produced(root).cloned()
                });
                // The projection says how the machine writes the carrier --
                // a lane, or a zero-extension into the full register -- and
                // spells that from what the right-hand side has. What the
                // object is declared as is the last word, and the conversion
                // to it is made once, outside the projection, from the type
                // the projection produced.
                // A right-hand side already as wide as the carrier spells the
                // zero extension itself: its root is the extension, and the
                // projection describing the same write must not say it twice.
                r2il::refusal_evidence!(
                    "write-projection",
                    "{:?} {:?} rhs_type={:?} rhs={:?}",
                    output.value,
                    projection,
                    rhs_type,
                    rhs
                );
                let projection = match *projection {
                    r2ssa::MachineWriteProjection::ZeroExtend { to_width_bits, .. }
                        if rhs_type.as_ref().and_then(CValue::as_type).and_then(|ty| {
                            r2types::declaration_type_width_bits(ty, self.pointer_bits())
                        }) == Some(to_width_bits) =>
                    {
                        r2ssa::MachineWriteProjection::Full
                    }
                    projection => projection,
                };
                let (lhs, rhs, projected_type) = project_machine_write(
                    lhs,
                    rhs,
                    rhs_type.as_ref(),
                    projection,
                    self.pointer_bits(),
                )
                .map_err(|_| {
                    crate::observation_journal::LegacyObservationJournalError::RefusedRenderedWrite(
                        output.inst,
                    )
                })?;
                let rhs = match self.value_declaration_type(output.value) {
                    Some(declared) => self.convert_from(rhs, projected_type.as_ref(), &declared),
                    None => rhs,
                };
                Ok((lhs, rhs))
            }
            Ok(r2ssa::MachineWriteDisposition::Refused(_)) => {
                unreachable!("require_write cannot return a refused disposition")
            }
            Err(crate::binding_plan::RenderedIdentityRefusal::MachineWrite { .. }) => Err(
                crate::observation_journal::LegacyObservationJournalError::RefusedRenderedWrite(
                    output.inst,
                ),
            ),
            Err(_) => Err(
                crate::observation_journal::LegacyObservationJournalError::InvalidWrite(
                    output.inst,
                ),
            ),
        }
    }

    /// Apply a source write only when the finalized statement targets the
    /// exact plan-owned output binding. A different target has no typed
    /// synthetic-origin certificate, so it cannot waive the `InstId` write
    /// projection.
    fn project_finalized_assignment_stmt(
        &self,
        site: Option<crate::normalize::NormalizedOpSite>,
        stmt: CStmt,
    ) -> OpLoweringResult<CStmt> {
        let Some(site) = site else {
            return Ok(stmt);
        };
        let output = match self.normalized_output_projection(site) {
            Ok(output) => output,
            Err(error) => {
                self.retain_first_observation_error(error);
                return Err(OpLoweringRefusal::missing_machine_projection());
            }
        };
        let Some(names) = self.inputs.binding_names else {
            return Err(OpLoweringRefusal::missing_program_variable());
        };
        let symbol = match names.require_value(output.value) {
            Ok(crate::binding_plan::PlannedValueSymbol::Bound(symbol)) => symbol,
            Ok(
                crate::binding_plan::PlannedValueSymbol::Inline(_)
                | crate::binding_plan::PlannedValueSymbol::Elided(_),
            ) => return Ok(stmt),
            Ok(
                crate::binding_plan::PlannedValueSymbol::Refused(_)
                | crate::binding_plan::PlannedValueSymbol::Absent,
            ) => unreachable!("require_value cannot return an absent or refused disposition"),
            Err(_) => return Err(OpLoweringRefusal::missing_program_variable()),
        };
        let CStmt::Expr(CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        }) = stmt
        else {
            return Ok(stmt);
        };
        let lhs = *left;
        let rhs = *right;
        let planned_lhs = CExpr::Var(symbol);
        if !lhs.transparently_eq(&planned_lhs) {
            // The statement assigns something other than the object the plan
            // says this write defines, and which two disagree is the repair.
            r2il::refusal_evidence!(
                "planned-assignment-target",
                "{:?} writes {lhs:?}, but the plan names {planned_lhs:?} for {:?}",
                site,
                output.value
            );
            return Err(OpLoweringRefusal::missing_program_variable());
        }
        match self.project_planned_assignment(Some(site), lhs, rhs) {
            Ok((lhs, rhs)) => Ok(CStmt::Expr(CExpr::assign(lhs, rhs))),
            Err(error) => {
                let refusal = Self::observation_lowering_refusal(&error);
                self.retain_first_observation_error(error);
                Err(refusal)
            }
        }
    }

    /// The type the plan declares for a value, if it declares one.
    pub(super) fn value_declaration_type(&self, value: ValueId) -> Option<CType> {
        let names = self.inputs.binding_names?;
        // An inlined value that spells one object is read at that object's
        // declared type: the expression is the object, so the boundary that
        // converts from a bound value has the same conversion to make here.
        let binding = match names.disposition_for_value(value)? {
            crate::binding_plan::ValueDisposition::Bound { binding } => *binding,
            crate::binding_plan::ValueDisposition::Inline { term, .. } => {
                crate::binding_plan::term_spells_binding(names.plan(), *term)?
            }
            _ => return None,
        };
        Some(names.plan().binding(binding)?.declaration_type().clone())
    }

    fn materialize_machine_expr(
        &self,
        names: &crate::binding_plan::BindingNameResolution,
        value: ValueId,
        term: r2rewrite::TermId,
        expr: r2ssa::MachineExprId,
        depth: u32,
    ) -> Result<CExpr, crate::observation_journal::LegacyObservationJournalError> {
        use r2ssa::MachineExprKind as Kind;
        let invalid =
            || crate::observation_journal::LegacyObservationJournalError::InvalidPlannedInline {
                value,
                term,
            };
        if depth as usize > names.plan().machine_projection().arena().len() {
            return Err(invalid());
        }
        let Some(machine_expr) = names.plan().machine_projection().expr(expr) else {
            return Err(invalid());
        };
        // Every operand crosses the boundary its operator states for it,
        // from the type the operand's own rendering has; both come from the
        // typed boundaries, keyed by this node and the operand's position.
        let typed = names.plan().typed_boundaries();
        let child = |index: usize,
                     id: r2ssa::MachineExprId|
         -> Result<
            CExpr,
            crate::observation_journal::LegacyObservationJournalError,
        > {
            let rendered = self.materialize_machine_expr(names, value, term, id, depth + 1)?;
            // An operand that exists has a requirement: every kind with
            // children states one. `None` here is not "no conversion needed",
            // it is "nobody decided", and rendering the operand at whatever
            // type it happened to have is how a byte offset reached a typed
            // pointer. Refuse instead.
            let Some(required) = typed.required(expr, index) else {
                r2il::refusal_evidence!(
                    "operand-requirement",
                    "machine {expr:?} operand {index} has no stated requirement"
                );
                return Err(invalid());
            };
            // The same statement of a machine operand's two types as the term
            // closure below makes, so a cast that converts nothing can be
            // traced to whichever of the two layers spelled it.
            if r2il::refusal_evidence::tracing() {
                r2il::refusal_evidence!(
                    "machine-operand-conversion",
                    "machine={expr:?} index={index} produced={:?} required={required:?} rendered={:?}",
                    typed.produced(id),
                    rendered.unobserved()
                );
            }
            Ok(self.convert_from(rendered, typed.produced(id), required))
        };
        Ok(match machine_expr.kind() {
            Kind::Constant {
                binding,
                value: literal,
            } => {
                let rendered = if machine_expr.ty().is_float() {
                    super::float_literal(literal.bits(), literal.width_bits())
                        .ok_or_else(invalid)?
                } else {
                    wide_aware_literal(literal.bits(), literal.width_bits())
                };
                // Every value owes a cell, and a constant reached as a leaf of
                // a moved expression is rendered here rather than as an operand
                // of an emitted statement, so this is where it is marked.
                let constant = binding.value();
                if constant == value {
                    rendered
                } else {
                    self.finish_replacement_expr(PendingReplacementExpr::planned_inline(
                        constant, rendered,
                    ))
                }
            }
            Kind::Source { binding, .. } => {
                let source = binding.value();
                if source == value {
                    return Err(invalid());
                }
                self.planned_value_expr(source)?
            }
            Kind::Copy { input } => child(0, *input)?,
            Kind::Arithmetic {
                op, left, right, ..
            } => CExpr::binary(
                match op {
                    r2ssa::MachineArithmeticOp::Add => BinaryOp::Add,
                    r2ssa::MachineArithmeticOp::Subtract => BinaryOp::Sub,
                    r2ssa::MachineArithmeticOp::Multiply => BinaryOp::Mul,
                },
                child(0, *left)?,
                child(1, *right)?,
            ),
            Kind::Bitwise { op, left, right } => CExpr::binary(
                match op {
                    r2ssa::MachineBitwiseOp::And => BinaryOp::BitAnd,
                    r2ssa::MachineBitwiseOp::Or => BinaryOp::BitOr,
                    r2ssa::MachineBitwiseOp::Xor => BinaryOp::BitXor,
                },
                child(0, *left)?,
                child(1, *right)?,
            ),
            Kind::Boolean { op, left, right } => CExpr::binary(
                match op {
                    r2ssa::MachineBooleanOp::And => BinaryOp::And,
                    r2ssa::MachineBooleanOp::Or => BinaryOp::Or,
                    // C has no boolean exclusive-or; on values the machine
                    // already reduced to zero or one, inequality is it.
                    r2ssa::MachineBooleanOp::Xor => BinaryOp::Ne,
                },
                child(0, *left)?,
                child(1, *right)?,
            ),
            // The signedness of the comparison is the node's interpretation,
            // and the typed boundaries state it as the operands' requirement.
            Kind::Compare {
                op, left, right, ..
            } => CExpr::binary(
                match op {
                    r2ssa::MachineComparisonOp::Equal => BinaryOp::Eq,
                    r2ssa::MachineComparisonOp::NotEqual => BinaryOp::Ne,
                    r2ssa::MachineComparisonOp::LessThan => BinaryOp::Lt,
                    r2ssa::MachineComparisonOp::LessThanOrEqual => BinaryOp::Le,
                },
                child(0, *left)?,
                child(1, *right)?,
            ),
            // An arithmetic right shift is `>>` on a signed operand and
            // nothing else; the boundary requires the signed operand.
            Kind::Shift {
                kind,
                value: shifted,
                count,
                ..
            } => CExpr::binary(
                match kind {
                    r2ssa::MachineShiftKind::Left => BinaryOp::Shl,
                    r2ssa::MachineShiftKind::LogicalRight
                    | r2ssa::MachineShiftKind::ArithmeticRight => BinaryOp::Shr,
                },
                child(0, *shifted)?,
                child(1, *count)?,
            ),
            Kind::BitwiseNot { input } => CExpr::unary(UnaryOp::BitNot, child(0, *input)?),
            Kind::BooleanNot { input } => CExpr::unary(UnaryOp::Not, child(0, *input)?),
            Kind::FloatArithmetic { op, left, right } => {
                CExpr::binary(float_binary_op(*op), child(0, *left)?, child(1, *right)?)
            }
            Kind::FloatUnary { op, input } => {
                let width = names
                    .plan()
                    .machine_projection()
                    .expr(*input)
                    .map(|expr| expr.ty().width_bits())
                    .ok_or_else(invalid)?;
                float_unary(*op, width, child(0, *input)?)
            }
            Kind::FloatCompare { op, left, right } => {
                CExpr::binary(comparison_op(*op), child(0, *left)?, child(1, *right)?)
            }
            Kind::Negate { input, .. } => CExpr::unary(UnaryOp::Neg, child(0, *input)?),
            Kind::Select {
                condition,
                if_true,
                if_false,
            } => CExpr::Ternary {
                cond: Box::new(child(0, *condition)?),
                then_expr: Box::new(child(1, *if_true)?),
                else_expr: Box::new(child(2, *if_false)?),
            },
            // Everything else -- a memory read, a merge, a division that traps,
            // a flag or a width change whose C form depends on a type this does
            // not carry -- keeps its own statement.
            _ => return Err(invalid()),
        })
    }

    /// Render the rewriter's canonical term for one planned inline value.
    ///
    /// This is deliberately paired with `expression_renders_inline`: every
    /// admitted modeled machine kind imports to one of these arms. A leaf is
    /// the only escape back to the machine arena, where the existing value path
    /// accounts for the exact source value it names.
    /// The type a term is declared with, when the term spells one object.
    ///
    /// The arena's width for a leaf is the machine carrier's; what the page
    /// says is the binding's declaration. A conversion between the two is the
    /// identity in the rendered program and has to be recognised as one.
    fn term_declaration_type(
        &self,
        names: &crate::binding_plan::BindingNameResolution,
        term: r2rewrite::TermId,
    ) -> Option<CType> {
        let binding = crate::binding_plan::term_spells_binding(names.plan(), term)?;
        Some(names.plan().binding(binding)?.declaration_type().clone())
    }

    fn materialize_term(
        &self,
        names: &crate::binding_plan::BindingNameResolution,
        value: ValueId,
        term: r2rewrite::TermId,
        depth: u32,
    ) -> Result<CExpr, crate::observation_journal::LegacyObservationJournalError> {
        use r2rewrite::TermKind as Kind;
        let invalid =
            || crate::observation_journal::LegacyObservationJournalError::InvalidPlannedInline {
                value,
                term,
            };
        let canonical = names.plan().canonical();
        let arena = canonical.arena();
        if depth as usize > arena.len() {
            return Err(invalid());
        }
        let node = arena.term(term);
        let typed = names.plan().typed_boundaries();
        let child = |index: usize,
                     id: r2rewrite::TermId|
         -> Result<
            CExpr,
            crate::observation_journal::LegacyObservationJournalError,
        > {
            let rendered = self.materialize_term(names, value, id, depth + 1)?;
            let Some(required) = typed.term_required(term, index) else {
                r2il::refusal_evidence!(
                    "operand-requirement",
                    "term {term:?} operand {index} has no stated requirement"
                );
                return Err(invalid());
            };
            // What each operand of a term was produced as and what its parent
            // asked for. A cast in the output that converts nothing is always
            // a disagreement between these two, and this is where it is
            // stated.
            if r2il::refusal_evidence::tracing() {
                r2il::refusal_evidence!(
                    "term-operand-conversion",
                    "term={term:?} index={index} kind={:?} produced={:?} required={required:?} rendered={:?}",
                    arena.term(id).kind,
                    typed.term_produced(id),
                    rendered.unobserved()
                );
            }
            Ok(self.convert_from(rendered, typed.term_produced(id), required))
        };
        let literal =
            |bits: r2ssa::MachineBitVector| wide_aware_literal(bits.bits(), bits.width_bits());
        Ok(match node.kind {
            Kind::Leaf(read) => {
                self.materialize_machine_expr(names, value, term, read.expr, depth + 1)?
            }
            Kind::Literal(bits) => {
                if node.ty.is_float() {
                    super::float_literal(bits.bits(), bits.width_bits()).ok_or_else(invalid)?
                } else {
                    literal(bits)
                }
            }
            Kind::FloatArithmetic { op, left, right } => {
                CExpr::binary(float_binary_op(op), child(0, left)?, child(1, right)?)
            }
            Kind::FloatUnary { op, input } => {
                let width = arena.term(input).width_bits();
                float_unary(op, width, child(0, input)?)
            }
            Kind::FloatCompare { op, left, right } => {
                CExpr::binary(comparison_op(op), child(0, left)?, child(1, right)?)
            }
            // The conversion the machine states, spelled as the C cast to the
            // type it produces; the operand arrives at the type it reads.
            Kind::FloatCast { input, .. } => {
                let rendered = child(0, input)?;
                let Some(produced) = typed
                    .term_produced(term)
                    .and_then(r2rewrite::CValue::as_type)
                else {
                    return Err(invalid());
                };
                CExpr::cast(produced.clone(), rendered)
            }
            Kind::Arithmetic { op, left, right } => CExpr::binary(
                match op {
                    r2ssa::MachineArithmeticOp::Add => BinaryOp::Add,
                    r2ssa::MachineArithmeticOp::Subtract => BinaryOp::Sub,
                    r2ssa::MachineArithmeticOp::Multiply => BinaryOp::Mul,
                },
                child(0, left)?,
                child(1, right)?,
            ),
            Kind::Negate(input) => CExpr::unary(UnaryOp::Neg, child(0, input)?),
            Kind::Bitwise { op, left, right } => CExpr::binary(
                match op {
                    r2ssa::MachineBitwiseOp::And => BinaryOp::BitAnd,
                    r2ssa::MachineBitwiseOp::Or => BinaryOp::BitOr,
                    r2ssa::MachineBitwiseOp::Xor => BinaryOp::BitXor,
                },
                child(0, left)?,
                child(1, right)?,
            ),
            Kind::BitwiseNot(input) => CExpr::unary(UnaryOp::BitNot, child(0, input)?),
            Kind::Boolean { op, left, right } => CExpr::binary(
                match op {
                    r2ssa::MachineBooleanOp::And => BinaryOp::And,
                    r2ssa::MachineBooleanOp::Or => BinaryOp::Or,
                    r2ssa::MachineBooleanOp::Xor => BinaryOp::Ne,
                },
                child(0, left)?,
                child(1, right)?,
            ),
            Kind::BooleanNot(input) => CExpr::unary(UnaryOp::Not, child(0, input)?),
            Kind::Compare {
                op, left, right, ..
            } => CExpr::binary(
                match op {
                    r2ssa::MachineComparisonOp::Equal => BinaryOp::Eq,
                    r2ssa::MachineComparisonOp::NotEqual => BinaryOp::Ne,
                    r2ssa::MachineComparisonOp::LessThan => BinaryOp::Lt,
                    r2ssa::MachineComparisonOp::LessThanOrEqual => BinaryOp::Le,
                },
                child(0, left)?,
                child(1, right)?,
            ),
            Kind::Cast { input, .. } => {
                let Some(produced) = typed
                    .term_produced(term)
                    .and_then(r2rewrite::CValue::as_type)
                else {
                    return Err(invalid());
                };
                // A conversion whose operand already has the type it produces
                // is the identity, whatever the arena calls the carrier in
                // between. Spelling it made the operand travel out to the
                // carrier's width and straight back, and the two conversions
                // collapse into one cast that converts nothing.
                if typed
                    .term_produced(input)
                    .and_then(r2rewrite::CValue::as_type)
                    == Some(produced)
                {
                    self.materialize_term(names, value, input, depth + 1)?
                } else {
                    let rendered = child(0, input)?;
                    let from = typed
                        .term_required(term, 0)
                        .cloned()
                        .map(r2rewrite::CValue::Typed);
                    self.convert_from(rendered, from.as_ref(), produced)
                }
            }
            Kind::Extract { input, lsb_bits } => {
                let Some(produced) = typed
                    .term_produced(term)
                    .and_then(r2rewrite::CValue::as_type)
                else {
                    return Err(invalid());
                };
                // Selecting the low bits of a name that is declared exactly
                // that wide is the name. The arena keeps the register's
                // carrier width while the plan declares the object as wide as
                // the widest read of it, so the two disagree on every narrowed
                // binding and the truncation is spelled over a name that has
                // nothing above the bits it selects.
                if lsb_bits == 0
                    && self.term_declaration_type(names, input).as_ref() == Some(produced)
                {
                    return self.materialize_term(names, value, input, depth + 1);
                }
                let rendered = child(0, input)?;
                // The operand arrives at the type this term requires of it; a
                // shift leaves it at that type promoted. The piece's width is
                // a conversion from there, spelled only where it is not the
                // identity: a 32-bit object read at 32 bits is the object.
                let from = typed.term_required(term, 0).cloned();
                if lsb_bits == 0 {
                    let from = from.map(r2rewrite::CValue::Typed);
                    self.convert_from(rendered, from.as_ref(), produced)
                } else {
                    let shifted =
                        CExpr::binary(BinaryOp::Shr, rendered, CExpr::IntLit(i64::from(lsb_bits)));
                    let from = from
                        .map(|ty| r2rewrite::promoted(&ty))
                        .map(r2rewrite::CValue::Typed);
                    self.convert_from(shifted, from.as_ref(), produced)
                }
            }
            Kind::Concat { high, low } => {
                let low_width = arena.term(low).width_bits();
                // Zeroes above a value spell a widening of it, not a shift-or.
                if r2rewrite::canon::literal_bits(arena, high) == Some(0) {
                    let Some(produced) = typed
                        .term_produced(term)
                        .and_then(r2rewrite::CValue::as_type)
                        .cloned()
                    else {
                        return Err(invalid());
                    };
                    let low_required = typed
                        .term_required(term, 1)
                        .cloned()
                        .map(r2rewrite::CValue::Typed);
                    return Ok(self.convert_from(child(1, low)?, low_required.as_ref(), &produced));
                }
                let Some(produced) = typed
                    .term_produced(term)
                    .and_then(r2rewrite::CValue::as_type)
                    .cloned()
                else {
                    return Err(invalid());
                };
                let high_required = typed
                    .term_required(term, 0)
                    .cloned()
                    .map(r2rewrite::CValue::Typed);
                let low_required = typed
                    .term_required(term, 1)
                    .cloned()
                    .map(r2rewrite::CValue::Typed);
                let high = self.convert_from(child(0, high)?, high_required.as_ref(), &produced);
                let low = self.convert_from(child(1, low)?, low_required.as_ref(), &produced);
                CExpr::binary(
                    BinaryOp::BitOr,
                    CExpr::binary(BinaryOp::Shl, high, CExpr::IntLit(i64::from(low_width))),
                    low,
                )
            }
            Kind::Select {
                condition,
                if_true,
                if_false,
            } => CExpr::Ternary {
                cond: Box::new(child(0, condition)?),
                then_expr: Box::new(child(1, if_true)?),
                else_expr: Box::new(child(2, if_false)?),
            },
            Kind::Shift {
                kind,
                value: shifted,
                count,
                ..
            } => CExpr::binary(
                match kind {
                    r2ssa::MachineShiftKind::Left => BinaryOp::Shl,
                    r2ssa::MachineShiftKind::LogicalRight
                    | r2ssa::MachineShiftKind::ArithmeticRight => BinaryOp::Shr,
                },
                child(0, shifted)?,
                child(1, count)?,
            ),
            Kind::Flag { op, left, right } => {
                let width = arena.term(left).width_bits();
                if arena.term(right).width_bits() != width
                    || !matches!(width, 8 | 16 | 32 | 64 | 128)
                {
                    return Err(invalid());
                }
                let operation = match op {
                    r2ssa::MachineArithmeticFlagOp::UnsignedCarry => "carry",
                    r2ssa::MachineArithmeticFlagOp::SignedCarry => "scarry",
                    r2ssa::MachineArithmeticFlagOp::SignedBorrow => "sborrow",
                };
                CExpr::call(
                    CExpr::External {
                        name: format!("r2sleigh_int_{operation}_{width}"),
                        kind: crate::symbol::ExternalKind::Intrinsic,
                    },
                    vec![child(0, left)?, child(1, right)?],
                )
            }
            // The object's address is a constant of the frame: the array's
            // name, or `&name` for anything else.
            Kind::ObjectAddress(object) => self
                .object_address_expr(value, object)
                .ok_or_else(invalid)?,
            Kind::Opaque(_) | Kind::Variable(_) | Kind::Load { .. } | Kind::Subscript { .. } => {
                return Err(invalid());
            }
        })
    }

    /// The assignment a bound value's canonical term spells, where spelling it
    /// from the term is sound.
    ///
    /// A value the plan inlines is rendered from the rewriter's canonical term.
    /// A value it binds was not: the operation arms rebuilt its right-hand side
    /// from the machine arena, so a rule that fired on the definition computed a
    /// simpler expression and then had it thrown away. `identity.and_self`
    /// proves `RSI_0 & RSI_0` is `RSI_0` and the reader was still shown the
    /// conjunction, on nineteen definitions across fourteen of the corpus's
    /// fifty-four cells. Only the *spelling* moves here; which values are bound
    /// is the binding partition's answer and is untouched.
    ///
    /// Three conditions gate it, and each is a refusal rather than an
    /// adjustment.
    ///
    /// The term must actually have been rewritten. An unchanged term is the
    /// base rendering reached by a second route, and routing it through here
    /// would trade the operation arms' spelling -- predicate resolution, the
    /// certified memory access, the flag intrinsics -- for nothing.
    ///
    /// Every producer the term absorbed must be one the plan inlines. A term
    /// that absorbed a value the plan *binds* computes it twice, once in its
    /// own statement and again inside this expression, and the observation
    /// journal refuses exactly that on the inline path for the same reason.
    ///
    /// And the term must be one `materialize_term` has a form for. A load, a
    /// subscript or a frame-object address renders through the memory and
    /// subscript renderers, which the term materialiser deliberately does not
    /// duplicate, so those keep the operation arms' statement.
    fn canonical_bound_assignment(
        &self,
        site: crate::normalize::NormalizedOpSite,
    ) -> Option<CanonicalBoundAssignment> {
        let names = self.inputs.binding_names?;
        let prepared = self.inputs.prepared_ssa?;
        let output = self.normalized_output_projection(site).ok()?;
        let value = output.value;
        let crate::binding_plan::ValueDisposition::Bound { binding } =
            names.disposition_for_value(value)?
        else {
            return None;
        };
        let symbol = names.symbol_for_binding(*binding)?;
        let canonical = names.plan().canonical();
        let rewrite = canonical.value(value)?;
        if rewrite.canonical == canonical.import().value(value)?.term {
            return None;
        }
        let mut absorbed = Vec::with_capacity(rewrite.discharges.len());
        for id in &rewrite.discharges {
            let r2ssa::CanonicalInstructionSite::Op(ordinal) = id.site else {
                return None;
            };
            let inst = prepared
                .graph()
                .inst_id_for_op_site(id.block_addr, usize::try_from(ordinal).ok()?)?;
            let produced = prepared.graph().inst(inst).and_then(|inst| inst.output)?;
            if !matches!(
                names.disposition_for_value(produced),
                Some(crate::binding_plan::ValueDisposition::Inline { .. })
            ) {
                return None;
            }
            absorbed.push(inst);
        }
        let projection = self
            .inputs
            .normalization_origins?
            .projection(site, prepared)
            .ok()??;
        // The object's declaration is the last word on what the assignment
        // holds. A widening at the root has nowhere to go when the object is
        // declared at its operand's width: rendering it and narrowing back at
        // the declaration produced a cast that converts nothing, which is most
        // of the redundant casts on the assignment side.
        let root = rewrite.canonical;
        let mut rhs = self.materialize_term(names, value, root, 0).ok()?;
        // The operand reads the base path would have marked one at a time,
        // marked on the whole right-hand side instead. The rewrite may have
        // absorbed the operand that carried a read -- `x & x` reads `x` once
        // where the machine read it twice -- and the use cell is owed by the
        // occurrence that now stands for it either way.
        for input_idx in 0..projection.inputs.len() {
            rhs = self.observe_optional_normalized_input_uses_expr(Some(site), input_idx, rhs);
        }
        // What the right-hand side has is now the term's produced type, not the
        // machine root's; the write projection reads this to decide how the
        // carrier is written.
        self.pending_assignment_type
            .set(names.plan().typed_boundaries().term_produced(root).cloned());
        Some(CanonicalBoundAssignment {
            stmt: CStmt::Expr(CExpr::assign(CExpr::Var(symbol), rhs)),
            value,
            definition: output.inst,
            absorbed,
        })
    }

    /// The caller is recorded so an elided value names who asked for it.
    #[track_caller]
    pub(crate) fn planned_value_expr(
        &self,
        value: ValueId,
    ) -> Result<CExpr, crate::observation_journal::LegacyObservationJournalError> {
        let asked_by = std::panic::Location::caller();
        let Some(names) = self.inputs.binding_names else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::rendered_value_required(
                    value,
                    crate::observation_journal::RenderedValueRequirementCause::PlannedValueNamesUnavailable,
                    None,
                ),
            );
        };
        match names.require_value(value) {
            Ok(crate::binding_plan::PlannedValueSymbol::Bound(symbol)) => {
                Ok(self.finish_replacement_expr(PendingReplacementExpr::rendered_value(
                    value,
                    CExpr::Var(symbol),
                )))
            }
            Ok(crate::binding_plan::PlannedValueSymbol::Inline(term)) => {
                let valid = names
                    .plan()
                    .canonical()
                    .value(value)
                    .is_some_and(|canonical| canonical.canonical == term);
                if !valid {
                    return Err(
                        crate::observation_journal::LegacyObservationJournalError::InvalidPlannedInline {
                            value,
                            term,
                        },
                    );
                }
                let rendered = self.materialize_term(names, value, term, 0)?;
                Ok(self.finish_replacement_expr(PendingReplacementExpr::planned_inline(
                    value, rendered,
                )))
            }
            Ok(crate::binding_plan::PlannedValueSymbol::Elided(reason)) => {
                // Which value, and why the plan elided it, is what separates a
                // wrong plan from a rendering that should not have asked.
                r2il::refusal_evidence!(
                    "planned-elided-value-rendered",
                    "{value:?} was elided as {reason:?} and {}:{} asked for it by name",
                    asked_by.file(),
                    asked_by.line()
                );
                Err(
                    crate::observation_journal::LegacyObservationJournalError::PlannedElidedValueRendered {
                        value,
                        reason,
                    },
                )
            }
            Ok(
                crate::binding_plan::PlannedValueSymbol::Refused(_)
                | crate::binding_plan::PlannedValueSymbol::Absent,
            ) => unreachable!("require_value cannot return an absent or refused disposition"),
            Err(crate::binding_plan::RenderedIdentityRefusal::Value { reason, .. }) => Err(
                crate::observation_journal::LegacyObservationJournalError::PlannedRefusedValueRendered {
                    value,
                    reason,
                },
            ),
            Err(_) => Err(
                crate::observation_journal::LegacyObservationJournalError::MissingPlannedValue(
                    value,
                ),
            ),
        }
    }

    fn normalized_input_projection(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
    ) -> Result<
        (
            crate::normalize::NormalizedOpSite,
            crate::normalize::NormalizedInputProjection,
        ),
        crate::observation_journal::LegacyObservationJournalError,
    > {
        let site = frame.normalized_site.ok_or(
            crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
        )?;
        let prepared = self.inputs.prepared_ssa.ok_or(
            crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
        )?;
        let projection = self
            .inputs
            .normalization_origins
            .ok_or(
                crate::observation_journal::LegacyObservationJournalError::MissingNormalizedSiteContext,
            )?
            .projection(site, prepared)
            .map_err(crate::observation_journal::LegacyObservationJournalError::Normalization)?
            .ok_or(
                crate::observation_journal::LegacyObservationJournalError::InvalidNormalizedSite(
                    site,
                ),
            )?;
        let input = projection.inputs.get(input_idx).cloned().ok_or(
            crate::observation_journal::LegacyObservationJournalError::InvalidNormalizedInput {
                site,
                input_idx,
            },
        )?;
        Ok((site, input))
    }

    fn uniform_planned_input_disposition(
        &self,
        site: crate::normalize::NormalizedOpSite,
        input_idx: usize,
        input: &crate::normalize::NormalizedInputProjection,
    ) -> Result<
        Option<(r2ssa::UseSite, r2ssa::MachineUseDisposition)>,
        crate::observation_journal::LegacyObservationJournalError,
    > {
        let Some(first_site) = input.uses.first().copied() else {
            return Ok(None);
        };
        let Some(names) = self.inputs.binding_names else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::rendered_value_required(
                    input.value,
                    crate::observation_journal::RenderedValueRequirementCause::PlannedInputNamesUnavailable,
                    None,
                ),
            );
        };
        let first_disposition = match names.require_use(first_site) {
            Ok(
                disposition @ (r2ssa::MachineUseDisposition::Exact(_)
                | r2ssa::MachineUseDisposition::MemoryAddress(_)),
            ) => disposition,
            Ok(r2ssa::MachineUseDisposition::Refused(_)) => {
                unreachable!("require_use cannot return a refused disposition")
            }
            Err(crate::binding_plan::RenderedIdentityRefusal::MachineUse { .. }) => {
                return Err(
                    crate::observation_journal::LegacyObservationJournalError::RefusedRenderedUse(
                        first_site,
                    ),
                );
            }
            Err(_) => {
                return Err(
                    crate::observation_journal::LegacyObservationJournalError::InvalidUse(
                        first_site,
                    ),
                );
            }
        };
        for use_site in input.uses.iter().copied().skip(1) {
            match names.require_use(use_site) {
                Ok(disposition) if disposition == first_disposition => {}
                Ok(r2ssa::MachineUseDisposition::Refused(_)) => {
                    unreachable!("require_use cannot return a refused disposition")
                }
                Err(crate::binding_plan::RenderedIdentityRefusal::MachineUse { .. }) => {
                    return Err(
                        crate::observation_journal::LegacyObservationJournalError::RefusedRenderedUse(
                            use_site,
                        ),
                    );
                }
                Ok(
                    r2ssa::MachineUseDisposition::Exact(_)
                    | r2ssa::MachineUseDisposition::MemoryAddress(_),
                ) => {
                    // One relocated normalized expression cannot implement two
                    // different source projections. Keep the normalized site
                    // typed and refuse the projection instead of choosing one.
                    return Err(
                        crate::observation_journal::LegacyObservationJournalError::InvalidNormalizedInput {
                            site,
                            input_idx,
                        },
                    );
                }
                Err(_) => {
                    return Err(
                        crate::observation_journal::LegacyObservationJournalError::InvalidUse(
                            use_site,
                        ),
                    );
                }
            }
        }
        Ok(Some((first_site, first_disposition)))
    }

    /// The planned expression for one operand, with the type it has.
    ///
    /// The type is what the read renders as -- the declared type of the
    /// object, or the type of the expression an inlined value stands for --
    /// carried through the use projection, which converts it where a slice
    /// or a conversion is selected and leaves it alone where the whole value
    /// is read. The boundary reading the operand converts from this type.
    fn planned_input_expr(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
    ) -> Result<(CExpr, Option<CValue>), crate::observation_journal::LegacyObservationJournalError>
    {
        let (site, input) = self.normalized_input_projection(frame, input_idx)?;
        let Some((first_site, first_disposition)) =
            self.uniform_planned_input_disposition(site, input_idx, &input)?
        else {
            // Synthetic preservation inputs have no original graph use and
            // therefore no source-owned projection to apply.
            return Ok((
                self.planned_value_expr(input.value)?,
                self.value_type(input.value),
            ));
        };
        match first_disposition {
            r2ssa::MachineUseDisposition::Exact(slice) => {
                let base = self.planned_value_expr(input.value)?;
                // What the base is spelled as, which is its declaration when
                // the expression is an object. Handing the projection the
                // machine type instead made it widen a name to a carrier the
                // name does not hold and narrow it straight back.
                let base_type = self
                    .value_declaration_type(input.value)
                    .map(CValue::Typed)
                    .or_else(|| self.value_type(input.value));
                super::projection::project_machine_use_of(
                    base,
                    base_type.as_ref(),
                    slice,
                    self.pointer_bits(),
                )
                .map(|(projected, ty)| (projected, Some(ty)))
                .map_err(|_| {
                    // The machine use is exact, but the strict C dialect cannot spell
                    // this projection without more type evidence. Refuse the emitted
                    // occurrence instead of inventing an integer or pointer type.
                    crate::observation_journal::LegacyObservationJournalError::RefusedRenderedUse(
                        first_site,
                    )
                })
            }
            // A contextual address cannot be projected from an arbitrary AST.
            // Only `planned_memory_input_expr` accepts the opaque expression
            // minted from the exact structured-access render fact.
            r2ssa::MachineUseDisposition::MemoryAddress(_) => Err(
                crate::observation_journal::LegacyObservationJournalError::RefusedRenderedUse(
                    first_site,
                ),
            ),
            r2ssa::MachineUseDisposition::Refused(_) => {
                unreachable!("the refused source use returned before projection")
            }
        }
    }

    fn planned_memory_input_expr(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
        certified: CertifiedMemoryAccessExpr,
    ) -> Result<CExpr, crate::observation_journal::LegacyObservationJournalError> {
        let (site, input) = self.normalized_input_projection(frame, input_idx)?;
        let Some((first_site, disposition)) =
            self.uniform_planned_input_disposition(site, input_idx, &input)?
        else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::InvalidNormalizedInput {
                    site,
                    input_idx,
                },
            );
        };
        let r2ssa::MachineUseDisposition::MemoryAddress(address) = disposition else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::RefusedRenderedUse(
                    first_site,
                ),
            );
        };
        let Some(access) = address.memory_access() else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::InvalidUse(first_site),
            );
        };
        let source_is_write = match self
            .inputs
            .prepared_ssa
            .and_then(|prepared| prepared.graph().inst(first_site.inst))
            .map(|inst| &inst.payload)
        {
            Some(r2ssa::InstPayload::Op(SSAOp::Load { .. })) => false,
            Some(r2ssa::InstPayload::Op(SSAOp::Store { .. })) => true,
            _ => {
                return Err(
                    crate::observation_journal::LegacyObservationJournalError::InvalidUse(
                        first_site,
                    ),
                );
            }
        };
        if address.binding().value() != input.value
            || certified.address() != input.value
            || certified.access() != access
            || certified.access().inst != first_site.inst
            || certified.is_write() != source_is_write
        {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::InvalidUse(first_site),
            );
        }
        let access = certified.access();
        let is_write = certified.is_write();
        let expr = certified.into_expr();
        let Some(journal) = self.inputs.observation_journal else {
            return Ok(expr);
        };
        journal
            .borrow_mut()
            .observe_stack_access_expr(access, is_write, expr)
    }

    /// One member's own write in a decomposed wide store.
    pub(super) fn observe_member_access_expr(
        &self,
        access: r2ssa::StructuredAccessId,
        expr: CExpr,
    ) -> CExpr {
        let Some(journal) = self.inputs.observation_journal else {
            return expr;
        };
        let fallback = expr.clone();
        match journal
            .borrow_mut()
            .observe_stack_access_expr(access, true, expr)
        {
            Ok(marked) => marked,
            Err(error) => {
                let refusal = Self::observation_lowering_refusal(&error);
                self.retain_first_observation_error(error);
                self.retain_first_lowering_refusal(refusal);
                fallback
            }
        }
    }

    pub(crate) fn planned_input_expr_at(
        &self,
        block_addr: u64,
        op_idx: usize,
        input_idx: usize,
    ) -> OpLoweringResult<CExpr> {
        let frame = LowerFrame::for_observed_expr(self.normalized_site(block_addr, op_idx));
        match self.planned_input_expr(&frame, input_idx) {
            Ok((expr, _)) => Ok(self.observe_optional_normalized_input_uses_expr(
                frame.normalized_site,
                input_idx,
                expr,
            )),
            Err(error) => {
                let refusal = Self::observation_lowering_refusal(&error);
                self.retain_first_observation_error(error);
                Err(refusal)
            }
        }
    }

    pub(super) fn planned_current_output_expr(
        &self,
    ) -> Result<Option<CExpr>, crate::observation_journal::LegacyObservationJournalError> {
        if self.inputs.observation_journal.is_none() {
            return Ok(None);
        }
        let Some(block_addr) = self.current_block_addr.get() else {
            return Ok(None);
        };
        let Some(op_idx) = self.current_op_idx.get() else {
            return Ok(None);
        };
        let site = self.normalized_site(block_addr, op_idx).ok_or(
            crate::observation_journal::LegacyObservationJournalError::MissingNormalizedBlock(
                block_addr,
            ),
        )?;
        let value = self.normalized_output_projection(site)?.value;
        let Some(names) = self.inputs.binding_names else {
            return Err(
                crate::observation_journal::LegacyObservationJournalError::MissingPlannedValue(
                    value,
                ),
            );
        };
        match names.require_value(value) {
            Ok(crate::binding_plan::PlannedValueSymbol::Bound(symbol)) => {
                Ok(Some(CExpr::Var(symbol)))
            }
            Ok(crate::binding_plan::PlannedValueSymbol::Inline(term)) => Err(
                crate::observation_journal::LegacyObservationJournalError::InvalidPlannedInline {
                    value,
                    term,
                },
            ),
            // An attempted lowering is not a rendered occurrence. Keep the
            // legacy candidate long enough for dead-code and structuring
            // rewrites to delete it; the final surviving value marker is the
            // only place allowed to turn either disposition into an error.
            Ok(
                crate::binding_plan::PlannedValueSymbol::Elided(_)
            ) => Ok(None),
            Ok(
                crate::binding_plan::PlannedValueSymbol::Refused(_)
                | crate::binding_plan::PlannedValueSymbol::Absent,
            ) => unreachable!("require_value cannot return an absent or refused disposition"),
            Err(crate::binding_plan::RenderedIdentityRefusal::Value { reason, .. }) => Err(
                crate::observation_journal::LegacyObservationJournalError::PlannedRefusedValueRendered {
                    value,
                    reason,
                },
            ),
            Err(_) => Err(
                crate::observation_journal::LegacyObservationJournalError::MissingPlannedValue(
                    value,
                ),
            ),
        }
    }

    pub(super) fn observed_input(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
        expr: CExpr,
    ) -> CExpr {
        self.observed_input_typed(frame, input_idx, expr, None).0
    }

    /// The operand at `input_idx`, read from `var`, with the type it has.
    ///
    /// Under observation the operand is the planned, projected expression
    /// and its type comes with it; outside observation it is the value's
    /// own rendering, at the type a read of that value has.
    pub(super) fn typed_input(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
        var: &SSAVar,
    ) -> OpLoweringResult<(CExpr, Option<CValue>)> {
        let expr = self.get_expr(var)?;
        let fallback = self
            .prepared_value_id_for_var(var)
            .and_then(|value| self.value_type(value));
        Ok(self.observed_input_typed(frame, input_idx, expr, fallback))
    }

    fn observed_input_typed(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
        expr: CExpr,
        fallback: Option<CValue>,
    ) -> (CExpr, Option<CValue>) {
        if frame.observe_inputs {
            let (expr, ty) = match self.planned_input_expr(frame, input_idx) {
                Ok(planned) => planned,
                Err(error) => {
                    let refusal = Self::observation_lowering_refusal(&error);
                    self.retain_first_observation_error(error);
                    self.retain_first_lowering_refusal(refusal);
                    return (expr, fallback);
                }
            };
            (
                self.observe_optional_normalized_input_uses_expr(
                    frame.normalized_site,
                    input_idx,
                    expr,
                ),
                ty,
            )
        } else {
            (expr, fallback)
        }
    }

    pub(super) fn observed_memory_input(
        &self,
        frame: &LowerFrame,
        input_idx: usize,
        certified: CertifiedMemoryAccessExpr,
    ) -> CExpr {
        let fallback = certified.expr().clone();
        if !frame.observe_inputs {
            return fallback;
        }
        let expr = match self.planned_memory_input_expr(frame, input_idx, certified) {
            Ok(planned) => planned,
            Err(error) => {
                let refusal = Self::observation_lowering_refusal(&error);
                self.retain_first_observation_error(error);
                self.retain_first_lowering_refusal(refusal);
                return fallback;
            }
        };
        self.observe_optional_normalized_input_uses_expr(frame.normalized_site, input_idx, expr)
    }

    pub(super) fn lowered_from_stmt(stmt: CStmt) -> LoweredOp {
        match stmt {
            CStmt::Empty => LoweredOp::None,
            stmt => LoweredOp::FinalizedStmt(stmt),
        }
    }

    pub(super) fn lowered_to_stmt(&self, lowered: LoweredOp) -> Option<CStmt> {
        match lowered {
            LoweredOp::Assign { lhs, rhs } => self.assign_stmt(lhs, rhs),
            LoweredOp::FinalizedStmt(stmt) => Some(stmt),
            LoweredOp::Expr(expr) => Some(CStmt::Expr(expr)),
            LoweredOp::None => None,
        }
    }

    fn lower_certified_statement_call(
        &self,
        block_addr: u64,
        op_idx: usize,
        call: CExpr,
        _certified_args: CertifiedCallArgs,
    ) -> LoweredOp {
        if let Some(owner) =
            self.materializable_call_result_expr_for_call_expr((block_addr, op_idx), &call)
        {
            // The object the result is assigned to decides the conversion,
            // exactly as it does everywhere else: from what the callee is
            // recorded to return, to what the plan declared the object.
            let returned = self
                .known_signature_for_site(block_addr, op_idx)
                .map(|signature| CValue::Typed(signature.return_type));
            let call = match self
                .certified_call_result_value((block_addr, op_idx))
                .and_then(|value| self.value_declaration_type(value))
                .or_else(|| {
                    self.declared_type_of_name(&owner)
                        .and_then(|owner| owner.as_type().cloned())
                }) {
                Some(declared) => self.convert_from(call, returned.as_ref(), &declared),
                None => call,
            };
            return LoweredOp::Assign {
                lhs: owner,
                rhs: call,
            };
        }
        LoweredOp::Expr(call)
    }

    fn certified_call_target_expr(
        &self,
        frame: &LowerFrame,
        target: &SSAVar,
        cert: &r2types::CallsiteArgumentFacts,
        direct: bool,
    ) -> OpLoweringResult<CExpr> {
        if self.prepared_value_id_for_var(target) != Some(cert.target) {
            return Err(OpLoweringRefusal::missing_machine_projection());
        }
        // A direct call spells its callee's name, which the call site's own
        // identity supplies. Asking the plan for the operand's expression
        // would be asking for the object that holds the callee's address, and
        // there is none: the plan elides that value, and the operand's
        // occurrence is elided beside it. Only an indirect call reads a target
        // the program computed, and only there is the planned expression the
        // thing being called.
        if direct {
            let address = cert
                .direct_target
                .ok_or_else(|| OpLoweringRefusal::missing_machine_projection())?;
            return Ok(self.callee_identity_expr(&self.callee_identity_for_direct_target(address)));
        }
        let (planned, _) = self.planned_input_expr(frame, 0).map_err(|error| {
            let refusal = Self::observation_lowering_refusal(&error);
            self.retain_first_observation_error(error);
            refusal
        })?;
        if cert.direct_target.is_some() {
            return Err(OpLoweringRefusal::missing_machine_projection());
        }
        let target = Self::indirect_callable_expr(planned);
        Ok(self.observe_optional_normalized_input_uses_expr(frame.normalized_site, 0, target))
    }

    pub(super) fn lower_op(
        &self,
        op: &SSAOp,
        frame: &mut LowerFrame,
    ) -> OpLoweringResult<LoweredOp> {
        self.pending_lowering_refusal.set(None);
        let lowered = match frame.mode {
            LowerMode::Expr => self
                .op_to_expr_impl(op, frame)?
                .map(LoweredOp::Expr)
                .unwrap_or(LoweredOp::None),
            LowerMode::Stmt => {
                if frame.with_call_args {
                    match op {
                        SSAOp::Call { target, .. } => {
                            let Some((source_block, source_op_idx)) = frame.source_call_site else {
                                return Err(OpLoweringRefusal::missing_machine_projection());
                            };
                            let (cert, _) = self.admitted_callsite(source_block, source_op_idx)?;
                            let func_expr =
                                self.certified_call_target_expr(frame, target, cert, true)?;
                            let certified_args =
                                self.certified_call_args_for_site(source_block, source_op_idx)?;
                            self.record_callee_declaration(
                                &func_expr,
                                source_block,
                                source_op_idx,
                                &certified_args,
                            )?;
                            let call = CExpr::call_at(
                                (source_block, source_op_idx),
                                func_expr,
                                certified_args.args.clone(),
                            );
                            return self.finish_lowering_transaction(
                                self.lower_certified_statement_call(
                                    source_block,
                                    source_op_idx,
                                    call,
                                    certified_args,
                                ),
                            );
                        }
                        SSAOp::CallInd { target, .. } => {
                            let Some((source_block, source_op_idx)) = frame.source_call_site else {
                                return Err(OpLoweringRefusal::missing_machine_projection());
                            };
                            let (cert, _) = self.admitted_callsite(source_block, source_op_idx)?;
                            // Whether the callee is named is the certificate's
                            // to say. A `call [reloc.X]` is indirect in shape
                            // and direct in fact.
                            let direct = cert.direct_target.is_some();
                            let func_expr =
                                self.certified_call_target_expr(frame, target, cert, direct)?;
                            let certified_args =
                                self.certified_call_args_for_site(source_block, source_op_idx)?;
                            if direct {
                                self.record_callee_declaration(
                                    &func_expr,
                                    source_block,
                                    source_op_idx,
                                    &certified_args,
                                )?;
                            }
                            let func_expr = self.callable_target_expr(
                                func_expr,
                                source_block,
                                source_op_idx,
                                &certified_args,
                            )?;
                            let call = CExpr::call_at(
                                (source_block, source_op_idx),
                                func_expr,
                                certified_args.args.clone(),
                            );
                            return self.finish_lowering_transaction(
                                self.lower_certified_statement_call(
                                    source_block,
                                    source_op_idx,
                                    call,
                                    certified_args,
                                ),
                            );
                        }
                        // A tail call is certified through either branch
                        // shape; the thunk `jmp [reloc.X]` is the indirect one.
                        SSAOp::Branch { target, .. } | SSAOp::BranchInd { target, .. }
                            if frame.source_call_site.is_some_and(|(block_addr, op_idx)| {
                                self.certified_call_render_fact_for_op(block_addr, op_idx)
                                    .is_some_and(|fact| fact.disposition.is_terminal_return())
                            }) =>
                        {
                            let Some((source_block, source_op_idx)) = frame.source_call_site else {
                                return Err(OpLoweringRefusal::missing_machine_projection());
                            };
                            let (cert, render_fact) =
                                self.admitted_callsite(source_block, source_op_idx)?;
                            if !render_fact.disposition.is_terminal_return() {
                                return Err(OpLoweringRefusal::missing_machine_projection());
                            }
                            // A tail transfer is direct when the site names the
                            // address it goes to, exactly as an ordinary call
                            // is. `jmp rax` names none: the callee is whatever
                            // the register holds, and the target expression is
                            // the planned value of that register.
                            let direct = cert.direct_target.is_some();
                            let func_expr =
                                self.certified_call_target_expr(frame, target, cert, direct)?;
                            let certified_args =
                                self.certified_call_args_for_site(source_block, source_op_idx)?;
                            self.record_callee_declaration(
                                &func_expr,
                                source_block,
                                source_op_idx,
                                &certified_args,
                            )?;
                            let func_expr = self.callable_target_expr(
                                func_expr,
                                source_block,
                                source_op_idx,
                                &certified_args,
                            )?;
                            let call = CExpr::call_at(
                                (source_block, source_op_idx),
                                func_expr,
                                certified_args.args,
                            );
                            let stmt = if render_fact.disposition
                                == r2types::CallsiteRenderDisposition::TerminalVoidReturn
                            {
                                CStmt::Block(vec![CStmt::Expr(call), CStmt::Return(None)])
                            } else {
                                CStmt::Return(Some(call))
                            };
                            return self
                                .finish_lowering_transaction(LoweredOp::FinalizedStmt(stmt));
                        }
                        _ => {}
                    }
                }

                self.op_to_stmt_impl(op, frame)?
                    .map(Self::lowered_from_stmt)
                    .unwrap_or(LoweredOp::None)
            }
        };
        self.finish_lowering_transaction(lowered)
    }

    fn finish_lowering_transaction(&self, lowered: LoweredOp) -> OpLoweringResult<LoweredOp> {
        match self.pending_lowering_refusal.take() {
            Some(refusal) => {
                if r2il::refusal_evidence::tracing() {
                    eprintln!("refusal {refusal:?} raised by finish_lowering_transaction");
                }
                Err(refusal)
            }
            None => Ok(lowered),
        }
    }

    /// Convert an SSA operation to a C statement, with call argument context.
    pub(super) fn op_to_stmt_with_args(
        &self,
        op: &SSAOp,
        block_addr: u64,
        op_idx: usize,
    ) -> OpLoweringResult<Option<CStmt>> {
        let source_site = self.source_op_site_for_normalized_op(block_addr, op_idx);
        let carries_callsite = matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
            || matches!(op, SSAOp::Branch { .. } | SSAOp::BranchInd { .. })
                && source_site.is_some_and(|(block_addr, op_idx)| {
                    self.certified_call_render_fact_for_op(block_addr, op_idx)
                        .is_some_and(|fact| fact.disposition.is_terminal_return())
                });
        if carries_callsite && source_site.is_none() {
            return Ok(Some(self.certified_residual_comment(format!(
                "synthetic operation cannot carry callsite facts at 0x{block_addr:x}:{op_idx}"
            ))));
        }
        let normalized_site = self.normalized_site(block_addr, op_idx);
        let source_call_site = source_site.or(Some((block_addr, op_idx)));
        let mut frame = LowerFrame::for_stmt(normalized_site, source_call_site, true);
        let (lowered, canonical) =
            match normalized_site.and_then(|site| self.canonical_bound_assignment(site)) {
                Some(CanonicalBoundAssignment {
                    stmt,
                    value,
                    definition,
                    absorbed,
                }) => (
                    LoweredOp::FinalizedStmt(stmt),
                    Some((value, definition, absorbed)),
                ),
                None => (self.lower_op(op, &mut frame)?, None),
            };
        let Some(stmt) = self.lowered_to_stmt(lowered) else {
            return Ok(None);
        };
        // Final write projection belongs only to an operation with a typed SSA
        // output. Calls and stores are source effects with exact input/effect
        // observations but no destination; asking them for a normalized output
        // fabricates an assignment contract they do not have.
        let stmt = if operation_requires_final_write_projection(op) {
            self.project_finalized_assignment_stmt(normalized_site, stmt)?
        } else {
            stmt
        };

        let obligations = self.exact_normalized_op_effects(op, block_addr, op_idx);
        let rendered = !matches!(stmt.unobserved(), CStmt::Comment(_) | CStmt::Empty);
        let stmt = if op.dst().is_some() && rendered {
            let mut stmt = self.observe_normalized_output_stmt(block_addr, op_idx, stmt);
            if let Some((value, definition, absorbed)) = canonical {
                stmt = self.observe_canonical_assignment_stmt(
                    value,
                    definition,
                    &absorbed,
                    &obligations,
                    stmt,
                );
            }
            stmt
        } else if rendered
            && matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
            && self.call_site_assigns_its_own_result((block_addr, op_idx))
            && let Some((definition_block, definition_idx)) =
                self.certified_call_result_definition_site((block_addr, op_idx))
        {
            self.observe_normalized_output_stmt(definition_block, definition_idx, stmt)
        } else {
            stmt
        };
        Ok(Some(self.observe_effect_stmt(&obligations, stmt)))
    }

    /// Render one resolved indirect-call target without letting occurrence
    /// metadata change whether an already-callable variable is dereferenced.
    pub(super) fn indirect_callable_expr(resolved_target: CExpr) -> CExpr {
        match resolved_target.unobserved() {
            CExpr::Var(_) => resolved_target,
            _ => CExpr::Deref(Box::new(resolved_target)),
        }
    }

    /// The call target spelled as something C can call.
    ///
    /// A computed target is a value in a machine-width local, and calling it
    /// as it stands renders `RAX_3(...)`, which no compiler accepts. The type
    /// it is called through is the prototype the call site itself proves, so
    /// the cast asserts nothing the arguments and the result boundary did not
    /// already say. A named callee is left alone: its declaration carries the
    /// same prototype and the name is already callable.
    fn callable_target_expr(
        &self,
        func_expr: CExpr,
        block_addr: u64,
        op_idx: usize,
        args: &CertifiedCallArgs,
    ) -> OpLoweringResult<CExpr> {
        if matches!(func_expr.unobserved(), CExpr::External { .. }) {
            return Ok(func_expr);
        }
        let (ret_type, params, _variadic) =
            self.certified_callee_signature(block_addr, op_idx, args)?;
        // `CType::Function` is already spelled as a pointer to function,
        // `ret(*)(params)`, so wrapping it in `Pointer` would spell a pointer
        // to that and call the wrong thing.
        Ok(CExpr::cast(
            CType::Function {
                ret: Box::new(ret_type),
                params: params.into_boxed_slice(),
            },
            func_expr,
        ))
    }
}

fn float_binary_op(op: r2ssa::MachineFloatOp) -> BinaryOp {
    match op {
        r2ssa::MachineFloatOp::Add => BinaryOp::Add,
        r2ssa::MachineFloatOp::Subtract => BinaryOp::Sub,
        r2ssa::MachineFloatOp::Multiply => BinaryOp::Mul,
        r2ssa::MachineFloatOp::Divide => BinaryOp::Div,
    }
}

fn comparison_op(op: r2ssa::MachineComparisonOp) -> BinaryOp {
    match op {
        r2ssa::MachineComparisonOp::Equal => BinaryOp::Eq,
        r2ssa::MachineComparisonOp::NotEqual => BinaryOp::Ne,
        r2ssa::MachineComparisonOp::LessThan => BinaryOp::Lt,
        r2ssa::MachineComparisonOp::LessThanOrEqual => BinaryOp::Le,
    }
}

/// Negation is the operator; the rest are the intrinsic header's helpers over
/// the compiler builtins, at the operand's width.
fn float_unary(op: r2ssa::MachineFloatUnaryOp, width: u32, operand: CExpr) -> CExpr {
    let name = match op {
        r2ssa::MachineFloatUnaryOp::Negate => return CExpr::unary(UnaryOp::Neg, operand),
        r2ssa::MachineFloatUnaryOp::Absolute => "abs",
        r2ssa::MachineFloatUnaryOp::SquareRoot => "sqrt",
        r2ssa::MachineFloatUnaryOp::Ceiling => "ceil",
        r2ssa::MachineFloatUnaryOp::Floor => "floor",
        r2ssa::MachineFloatUnaryOp::Round => "round",
        r2ssa::MachineFloatUnaryOp::IsNan => "isnan",
    };
    CExpr::call(
        CExpr::External {
            name: format!("r2sleigh_float_{name}_{width}"),
            kind: crate::symbol::ExternalKind::Intrinsic,
        },
        vec![operand],
    )
}

#[cfg(test)]
mod typed_output_contract_tests {
    use super::*;

    #[test]
    fn only_operations_with_typed_outputs_require_final_write_projection() {
        let dst = r2ssa::SSAVar::new("dst", 1, 8);
        let input = r2ssa::SSAVar::new("input", 0, 8);

        assert!(operation_requires_final_write_projection(&SSAOp::Copy {
            dst,
            src: input.clone(),
        }));
        assert!(!operation_requires_final_write_projection(&SSAOp::Store {
            space: r2il::SpaceId::Ram,
            addr: input.clone(),
            val: input.clone(),
        }));
        assert!(!operation_requires_final_write_projection(&SSAOp::Call {
            target: input.clone(),
            instruction: None,
        }));
        assert!(!operation_requires_final_write_projection(
            &SSAOp::CallInd {
                target: input,
                instruction: None
            }
        ));
    }
}
