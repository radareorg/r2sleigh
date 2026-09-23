mod prepared;
mod returns;
#[cfg(test)]
mod tests;

pub use prepared::*;
pub use returns::{ReturnTypeEvidence, ReturnTypeFact, ReturnTypeRefusal};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::callee::{CalleeIdentityContext, CalleeResolutionFacts, CallsiteKey};
use crate::context::{ExternalStackSlotRole, ExternalStackSlotSpec, StackSlotKey};
use crate::facts::{
    CalleeFact, CalleeLinkage, FunctionSignatureProjection, FunctionSignatureSpec,
    FunctionTypeFacts, OutParamCertificateEvidence, OutParamCertificateSource,
    SignatureCertificateSource, SignatureProjectionResult, VisibleBindingKind,
};
use crate::{CTypeLike, normalize_external_type_name, parse_c_type_like};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ParamSlotResolver {
    slots_by_value: BTreeMap<r2ssa::ValueId, usize>,
}

impl ParamSlotResolver {
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.slots_by_value.is_empty()
    }

    fn slot_for_value(&self, value: r2ssa::ValueId) -> Option<usize> {
        self.slots_by_value.get(&value).copied()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionCallsiteFacts {
    pub by_callsite: BTreeMap<CallsiteKey, CallsiteArgumentFacts>,
}

impl FunctionCallsiteFacts {
    pub fn is_empty(&self) -> bool {
        self.by_callsite.is_empty()
    }

    pub fn arguments_for_site(&self, callsite: CallsiteKey) -> Option<&CallsiteArgumentFacts> {
        self.by_callsite.get(&callsite)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionCallResultFacts {
    pub by_value: BTreeMap<r2ssa::ValueId, CallResultFact>,
    pub by_callsite: BTreeMap<CallsiteKey, Vec<r2ssa::ValueId>>,
}

impl FunctionCallResultFacts {
    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty() && self.by_callsite.is_empty()
    }

    pub fn result_for_value(&self, value: r2ssa::ValueId) -> Option<&CallResultFact> {
        self.by_value.get(&value)
    }

    pub fn results_for_site(&self, callsite: CallsiteKey) -> impl Iterator<Item = &CallResultFact> {
        self.by_callsite
            .get(&callsite)
            .into_iter()
            .flatten()
            .filter_map(|value| self.by_value.get(value))
    }

    /// The value the call boundary itself defines.
    ///
    /// A result may acquire a stable stack owner after copies, a store and a
    /// reload. That owner is useful for later reads, but it is not the value
    /// whose definition the call statement renders. The boundary definition is
    /// the earliest identity result carried in a register; propagated identity
    /// results occur later. A tie is ambiguous and therefore remains unowned.
    pub fn definition_for_site(&self, callsite: CallsiteKey) -> Option<&CallResultFact> {
        let is_boundary_definition = |result: &CallResultFact| {
            result.relation.is_identity()
                && matches!(result.carrier, r2ssa::ReturnCarrier::Register { .. })
        };
        let earliest = self
            .results_for_site(callsite)
            .filter(|result| is_boundary_definition(result))
            .map(|result| result.at)
            .min()?;
        let mut definitions = self
            .results_for_site(callsite)
            .filter(|result| is_boundary_definition(result) && result.at == earliest);
        let definition = definitions.next()?;
        definitions.next().is_none().then_some(definition)
    }

    pub fn owner_for_site(&self, callsite: CallsiteKey) -> Option<&r2ssa::ValueOwner> {
        let direct_stack_owner = self.unique_owner_for_site_matching(callsite, |result, owner| {
            result.relation.is_identity()
                && matches!(&result.carrier, r2ssa::ReturnCarrier::Register { .. })
                && matches!(owner, r2ssa::ValueOwner::StackSlot { .. })
        });
        match direct_stack_owner {
            Ok(Some(owner)) => return Some(owner),
            Err(()) => return None,
            Ok(None) => {}
        }

        let carrier_stack_owner = self.unique_owner_for_site_matching(callsite, |result, owner| {
            result.relation.is_identity()
                && matches!(
                (&result.carrier, owner),
                (
                    r2ssa::ReturnCarrier::StackSlot {
                        object: carrier_object,
                        offset: carrier_offset,
                        ..
                    },
                    r2ssa::ValueOwner::StackSlot {
                        object: owner_object,
                        offset: owner_offset,
                    }
                ) if carrier_object == owner_object && carrier_offset == owner_offset
                )
        });
        match carrier_stack_owner {
            Ok(Some(owner)) => return Some(owner),
            Err(()) => return None,
            Ok(None) => {}
        }

        // A result carried in a register and owned by a value. Every branch
        // above requires a stack slot, so a register-carried result never had
        // an owner and the call site was never recorded as assigning it.
        let register_owner = self.unique_owner_for_site_matching(callsite, |result, owner| {
            result.relation.is_identity()
                && matches!(&result.carrier, r2ssa::ReturnCarrier::Register { .. })
                && matches!(owner, r2ssa::ValueOwner::Value(_))
        });
        match register_owner {
            Ok(Some(owner)) => return Some(owner),
            Err(()) => return None,
            Ok(None) => {}
        }

        self.unique_owner_for_site_matching(callsite, |result, owner| {
            result.relation.is_identity() && matches!(owner, r2ssa::ValueOwner::StackSlot { .. })
        })
        .ok()
        .flatten()
    }

    pub fn owner_for_value(&self, value: r2ssa::ValueId) -> Option<&r2ssa::ValueOwner> {
        self.result_for_value(value)
            .and_then(|result| result.owner.as_ref())
    }

    fn unique_owner_for_site_matching(
        &self,
        callsite: CallsiteKey,
        accept: impl Fn(&CallResultFact, &r2ssa::ValueOwner) -> bool,
    ) -> Result<Option<&r2ssa::ValueOwner>, ()> {
        let mut selected = None;
        for result in self.results_for_site(callsite) {
            let Some(owner) = result.owner.as_ref().filter(|owner| accept(result, owner)) else {
                continue;
            };
            if selected.is_some_and(|existing| existing != owner) {
                return Err(());
            }
            selected = Some(owner);
        }
        Ok(selected)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionCallRenderFacts {
    pub by_callsite: BTreeMap<CallsiteKey, CallsiteRenderFact>,
}

impl FunctionCallRenderFacts {
    pub fn is_empty(&self) -> bool {
        self.by_callsite.is_empty()
    }

    pub fn fact_for_site(&self, callsite: CallsiteKey) -> Option<&CallsiteRenderFact> {
        self.by_callsite.get(&callsite)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionControlFacts {
    pub branch_predicates: BTreeMap<u64, BranchPredicateFact>,
    pub block_assumptions: BTreeMap<u64, Vec<ControlBlockAssumptionFact>>,
    pub loops: BTreeMap<r2ssa::LoopId, LoopStructureFact>,
    pub switches: BTreeMap<u64, SwitchSelectorFact>,
    pub control_domains: r2ssa::ControlDomainFacts,
}

impl FunctionControlFacts {
    pub fn is_empty(&self) -> bool {
        self.branch_predicates.is_empty()
            && self.block_assumptions.is_empty()
            && self.loops.is_empty()
            && self.switches.is_empty()
            && self.control_domains.by_block.is_empty()
    }

    pub fn branch_for_block(&self, block_addr: u64) -> Option<&BranchPredicateFact> {
        self.branch_predicates.get(&block_addr)
    }

    pub fn switch_for_block(&self, block_addr: u64) -> Option<&SwitchSelectorFact> {
        self.switches.get(&block_addr)
    }

    pub fn control_domain_for_block(&self, block_addr: u64) -> Option<&r2ssa::ControlDomain> {
        self.control_domains.for_block(block_addr)
    }

    pub fn loops_for_header(&self, header: u64) -> impl Iterator<Item = &LoopStructureFact> + '_ {
        self.loops
            .values()
            .filter(move |fact| fact.header == header)
    }

    pub fn assumptions_for_block(
        &self,
        block_addr: u64,
    ) -> impl Iterator<Item = &ControlBlockAssumptionFact> {
        self.block_assumptions
            .get(&block_addr)
            .into_iter()
            .flatten()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionRenderFacts {
    /// Canonical certified expression graph keyed by stable semantic identity.
    pub certified_exprs: BTreeMap<r2ssa::SemanticId, CertifiedExpr>,
    /// Canonical certified addressable entities keyed by stable semantic identity.
    pub certified_entities: BTreeMap<r2ssa::SemanticId, CertifiedEntity>,
    /// Canonical certified observable-effect graph keyed by stable semantic identity.
    pub certified_effects: BTreeMap<r2ssa::SemanticId, CertifiedEffect>,
    /// Stable return-effect identity for each canonical SSA op site.
    pub return_effects_by_op: BTreeMap<OpSiteKey, r2ssa::SemanticId>,
    /// Stable memory-effect identities for each canonical SSA op site.
    pub memory_effects_by_op: BTreeMap<MemoryOpSiteKey, Vec<r2ssa::SemanticId>>,
    /// Value annotations that supplement, rather than duplicate, certified expressions.
    pub string_literals_by_value: BTreeMap<r2ssa::ValueId, StringLiteralRenderFact>,
    /// Type-owner render projections tied back to canonical memory-effect identities.
    pub member_accesses_by_op: BTreeMap<MemoryOpSiteKey, Vec<MemberAccessRenderFact>>,
    pub array_accesses_by_op: BTreeMap<MemoryOpSiteKey, Vec<ArrayAccessRenderFact>>,
}

impl FunctionRenderFacts {
    /// Project one prepared SSA artifact into the canonical render contract.
    ///
    /// This is the only owner for translating prepared certificates into
    /// certified expressions, entities, effects, and op-site indexes.
    fn from_prepared(prepared: &r2ssa::SsaArtifact) -> Self {
        prepared_render_facts(prepared)
    }

    pub fn is_empty(&self) -> bool {
        self.certified_exprs.is_empty()
            && self.certified_entities.is_empty()
            && self.certified_effects.is_empty()
            && self.return_effects_by_op.is_empty()
            && self.memory_effects_by_op.is_empty()
            && self.string_literals_by_value.is_empty()
            && self.member_accesses_by_op.is_empty()
            && self.array_accesses_by_op.is_empty()
    }

    pub fn expression_for_value(&self, value: r2ssa::ValueId) -> Option<&ExpressionRenderFact> {
        self.certified_exprs
            .get(&r2ssa::SemanticId::expression(value))
            .map(|cert| &cert.fact)
    }

    pub fn certified_expr_for_value(&self, value: r2ssa::ValueId) -> Option<&CertifiedExpr> {
        self.certified_exprs
            .get(&r2ssa::SemanticId::expression(value))
    }

    pub fn guarded_phi_for_value(&self, value: r2ssa::ValueId) -> Option<&GuardedPhiRenderFact> {
        self.certified_expr_for_value(value)?.guarded_phi.as_ref()
    }

    pub fn certified_effect(&self, id: r2ssa::SemanticId) -> Option<&CertifiedEffect> {
        self.certified_effects.get(&id)
    }

    pub fn parameter_values(&self, slot: usize) -> impl Iterator<Item = r2ssa::ValueId> + '_ {
        let entity =
            r2ssa::SemanticId::parameter(slot).and_then(|id| self.certified_entities.get(&id));
        entity
            .into_iter()
            .flat_map(|entity| match entity {
                CertifiedEntity::Parameter { entry_values, .. } => Some(entry_values),
                CertifiedEntity::StackSlot { .. } | CertifiedEntity::LoopCarrier { .. } => None,
            })
            .flatten()
            .copied()
    }

    pub fn has_certified_parameter(&self, slot: usize) -> bool {
        let Some(id) = r2ssa::SemanticId::parameter(slot) else {
            return false;
        };
        matches!(
            self.certified_entities.get(&id),
            Some(CertifiedEntity::Parameter {
                slot: entity_slot,
                ..
            }) if usize::try_from(*entity_slot).ok() == Some(slot)
        )
    }

    /// Resolve a value carrying a direct parameter binding to one ABI slot.
    ///
    /// This deliberately does not walk expression inputs: an expression that
    /// depends on one parameter is not necessarily identical to that parameter.
    pub fn exact_parameter_slot_for_value(&self, value: r2ssa::ValueId) -> Option<usize> {
        let expr = self.certified_expr_for_value(value)?;
        let mut slots = expr.bindings.iter().filter_map(|binding| {
            let r2ssa::SemanticId::Parameter(slot) = binding else {
                return None;
            };
            match self.certified_entities.get(binding) {
                Some(CertifiedEntity::Parameter {
                    slot: entity_slot, ..
                }) if entity_slot == slot => usize::try_from(*slot).ok(),
                _ => None,
            }
        });
        let slot = slots.next()?;
        slots.next().is_none().then_some(slot)
    }

    /// Resolve an expression to one unambiguous ABI parameter dependency.
    ///
    /// The walk follows only the certified expression graph and its stable
    /// `SemanticId::Parameter` bindings. Rendered names and register spellings
    /// are deliberately excluded.
    pub fn unique_parameter_dependency_slot_for_value(
        &self,
        value: r2ssa::ValueId,
    ) -> Option<usize> {
        let mut pending = vec![r2ssa::SemanticId::expression(value)];
        let mut visited = BTreeSet::new();
        let mut slots = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let Some(expr) = self.certified_exprs.get(&id) else {
                continue;
            };
            for binding in &expr.bindings {
                if let r2ssa::SemanticId::Parameter(slot) = binding {
                    slots.insert(usize::try_from(*slot).ok()?);
                }
            }
            pending.extend(expr.inputs.iter().copied());
        }
        let slot = slots.pop_first()?;
        slots.is_empty().then_some(slot)
    }

    pub fn return_effect_id_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
    ) -> Option<r2ssa::SemanticId> {
        self.return_effects_by_op
            .get(&(block_addr, op_index))
            .copied()
    }

    pub fn memory_effect_id_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
        is_write: bool,
        space: r2il::SpaceId,
        address: r2ssa::ValueId,
        value: Option<r2ssa::ValueId>,
    ) -> Option<r2ssa::SemanticId> {
        let mut matching = self
            .memory_effects_by_op
            .get(&(block_addr, op_index, is_write))?
            .iter()
            .filter_map(|id| match self.certified_effects.get(id) {
                Some(CertifiedEffect::Memory { fact, .. })
                    if fact.space == space && fact.address == address && fact.value == value =>
                {
                    Some(*id)
                }
                _ => None,
            });
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    pub fn expression_is_renderable(&self, value: r2ssa::ValueId) -> bool {
        self.expression_for_value(value)
            .is_some_and(|fact| fact.renderable)
    }

    pub fn string_literal_for_value(
        &self,
        value: r2ssa::ValueId,
    ) -> Option<&StringLiteralRenderFact> {
        self.string_literals_by_value.get(&value)
    }

    /// The memory fact for one exact structured access at an op site.
    ///
    /// A decomposed wide store has several accesses at one site, so the access
    /// identity rather than uniqueness is what selects the fact.
    pub fn memory_access_for_access(
        &self,
        block_addr: u64,
        op_index: usize,
        is_write: bool,
        access: r2ssa::StructuredAccessId,
    ) -> Option<&MemoryAccessRenderFact> {
        let mut matching = self
            .memory_effects_by_op
            .get(&(block_addr, op_index, is_write))?
            .iter()
            .filter_map(|id| {
                self.certified_effects
                    .get(id)
                    .and_then(CertifiedEffect::memory_fact)
            })
            .filter(|fact| fact.access == access && fact.width > 0);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    pub fn memory_access_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
        is_write: bool,
        space: r2il::SpaceId,
    ) -> Option<&MemoryAccessRenderFact> {
        let mut matching = self
            .memory_effects_by_op
            .get(&(block_addr, op_index, is_write))?
            .iter()
            .filter_map(|id| {
                self.certified_effects
                    .get(id)
                    .and_then(CertifiedEffect::memory_fact)
            })
            .filter(|fact| fact.space == space && fact.width > 0);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    pub fn memory_access(
        &self,
        access: r2ssa::StructuredAccessId,
    ) -> Option<&MemoryAccessRenderFact> {
        self.certified_effects
            .get(&r2ssa::SemanticId::memory_access(access))
            .and_then(CertifiedEffect::memory_fact)
    }

    pub fn memory_accesses(&self) -> impl Iterator<Item = &MemoryAccessRenderFact> {
        self.certified_effects
            .values()
            .filter_map(CertifiedEffect::memory_fact)
    }

    pub fn member_access(
        &self,
        access: r2ssa::StructuredAccessId,
    ) -> Option<&MemberAccessRenderFact> {
        let memory = self.memory_access(access)?;
        let facts = self.member_accesses_by_op.get(&(
            memory.block_addr,
            memory.op_index,
            memory.is_write,
        ))?;
        let mut matching = facts.iter().filter(|fact| {
            fact.access == memory.access
                && fact.object == memory.object
                && fact.access_width == memory.width
        });
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    pub fn memory_value_type(&self, access: r2ssa::StructuredAccessId) -> Option<&CTypeLike> {
        self.member_access(access)?.field_type.as_ref()
    }

    pub fn return_effects(&self) -> impl Iterator<Item = &ReturnValueRenderFact> {
        self.certified_effects
            .values()
            .filter_map(CertifiedEffect::return_fact)
    }

    pub fn stack_slot(
        &self,
        object: r2ssa::ObjectId,
    ) -> Option<(r2ssa::StackAddressBase, i64, Option<u32>)> {
        match self
            .certified_entities
            .get(&r2ssa::SemanticId::stack_slot(object))?
        {
            CertifiedEntity::StackSlot {
                base, offset, size, ..
            } => Some((*base, *offset, *size)),
            CertifiedEntity::Parameter { .. } | CertifiedEntity::LoopCarrier { .. } => None,
        }
    }

    pub fn stack_slot_offset(&self, object: r2ssa::ObjectId) -> Option<i64> {
        self.stack_slot(object).map(|(_, offset, _)| offset)
    }

    pub fn stack_slots(
        &self,
    ) -> impl Iterator<Item = (r2ssa::ObjectId, r2ssa::StackAddressBase, i64, Option<u32>)> + '_
    {
        self.certified_entities
            .values()
            .filter_map(|entity| match entity {
                CertifiedEntity::StackSlot {
                    object,
                    base,
                    offset,
                    size,
                    ..
                } => Some((*object, *base, *offset, *size)),
                CertifiedEntity::Parameter { .. } | CertifiedEntity::LoopCarrier { .. } => None,
            })
    }

    pub fn loop_carrier_for_value(&self, value: r2ssa::ValueId) -> Option<&CertifiedEntity> {
        let expr = self.certified_expr_for_value(value)?;
        let mut carriers = expr.bindings.iter().filter_map(|binding| {
            let r2ssa::SemanticId::LoopCarrier(_) = binding else {
                return None;
            };
            match self.certified_entities.get(binding) {
                Some(entity @ CertifiedEntity::LoopCarrier { members, .. })
                    if members
                        .binary_search_by_key(&value, |member| member.value)
                        .is_ok() =>
                {
                    Some(entity)
                }
                _ => None,
            }
        });
        let carrier = carriers.next()?;
        carriers.next().is_none().then_some(carrier)
    }

    pub fn loop_carrier_update_for_value_at_latch(
        &self,
        value: r2ssa::ValueId,
        latch: u64,
    ) -> Option<&CertifiedEntity> {
        let expr = self.certified_expr_for_value(value)?;
        let mut carriers = expr.bindings.iter().filter_map(|binding| {
            let r2ssa::SemanticId::LoopCarrier(_) = binding else {
                return None;
            };
            match self.certified_entities.get(binding) {
                Some(entity @ CertifiedEntity::LoopCarrier { updates, .. })
                    if updates.iter().any(|update| {
                        update.predecessor == latch
                            && (update.value == value || update.identity_values.contains(&value))
                    }) =>
                {
                    Some(entity)
                }
                _ => None,
            }
        });
        let carrier = carriers.next()?;
        carriers.next().is_none().then_some(carrier)
    }

    pub fn loop_carrier_update_for_value(&self, value: r2ssa::ValueId) -> Option<&CertifiedEntity> {
        let expr = self.certified_expr_for_value(value)?;
        let mut carriers = expr.bindings.iter().filter_map(|binding| {
            let r2ssa::SemanticId::LoopCarrier(_) = binding else {
                return None;
            };
            match self.certified_entities.get(binding) {
                Some(entity @ CertifiedEntity::LoopCarrier { updates, .. })
                    if updates.iter().any(|update| {
                        update.value == value || update.identity_values.contains(&value)
                    }) =>
                {
                    Some(entity)
                }
                _ => None,
            }
        });
        let carrier = carriers.next()?;
        carriers.next().is_none().then_some(carrier)
    }

    pub fn loop_carriers(&self) -> impl Iterator<Item = &CertifiedEntity> {
        self.certified_entities
            .values()
            .filter(|entity| matches!(entity, CertifiedEntity::LoopCarrier { .. }))
    }

    pub fn return_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
    ) -> Option<&ReturnValueRenderFact> {
        self.return_effect_id_for_op(block_addr, op_index)
            .and_then(|id| self.certified_effects.get(&id))
            .and_then(CertifiedEffect::return_fact)
    }

    pub fn member_access_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
        is_write: bool,
        field_name: &str,
        field_offset: u64,
        access_width: Option<u32>,
    ) -> Option<&MemberAccessRenderFact> {
        self.member_accesses_by_op
            .get(&(block_addr, op_index, is_write))?
            .iter()
            .find(|fact| {
                let Some(memory) = self.memory_access(fact.access) else {
                    return false;
                };
                memory.block_addr == block_addr
                    && memory.op_index == op_index
                    && memory.is_write == is_write
                    && memory.object == fact.object
                    && memory.width == fact.access_width
                    && fact.field_offset == field_offset
                    && fact.field_name.eq_ignore_ascii_case(field_name)
                    && access_width.is_none_or(|width| fact.access_width == width)
            })
    }

    pub fn member_access_for_op_any_direction(
        &self,
        block_addr: u64,
        op_index: usize,
        field_name: &str,
        field_offset: u64,
        access_width: Option<u32>,
    ) -> Option<&MemberAccessRenderFact> {
        self.member_access_for_op(
            block_addr,
            op_index,
            false,
            field_name,
            field_offset,
            access_width,
        )
        .or_else(|| {
            self.member_access_for_op(
                block_addr,
                op_index,
                true,
                field_name,
                field_offset,
                access_width,
            )
        })
    }

    pub fn array_access_for_op(
        &self,
        block_addr: u64,
        op_index: usize,
        is_write: bool,
        field_offset: u64,
        element_stride: u64,
        access_width: Option<u32>,
    ) -> Option<&ArrayAccessRenderFact> {
        self.array_accesses_by_op
            .get(&(block_addr, op_index, is_write))?
            .iter()
            .find(|fact| {
                let Some(memory) = self.memory_access(fact.access) else {
                    return false;
                };
                memory.block_addr == block_addr
                    && memory.op_index == op_index
                    && memory.is_write == is_write
                    && memory.object == fact.object
                    && memory.width == fact.access_width
                    && fact.field_offset == field_offset
                    && fact.element_stride == element_stride
                    && access_width.is_none_or(|width| fact.access_width == width)
            })
    }

    pub fn array_access_for_op_any_direction(
        &self,
        block_addr: u64,
        op_index: usize,
        field_offset: u64,
        element_stride: u64,
        access_width: Option<u32>,
    ) -> Option<&ArrayAccessRenderFact> {
        self.array_access_for_op(
            block_addr,
            op_index,
            false,
            field_offset,
            element_stride,
            access_width,
        )
        .or_else(|| {
            self.array_access_for_op(
                block_addr,
                op_index,
                true,
                field_offset,
                element_stride,
                access_width,
            )
        })
    }

    pub fn has_stack_slot_offset(&self, offset: i64) -> bool {
        self.stack_slots()
            .any(|(_, _, slot_offset, _)| slot_offset == offset)
    }
}

/// The exact storage width a C declaration type describes.
pub fn declaration_type_width_bits(ty: &CTypeLike, ptr_bits: u32) -> Option<u32> {
    match ty {
        CTypeLike::Int {
            bits,
            signedness: crate::Signedness::Signed | crate::Signedness::Unsigned,
        }
        | CTypeLike::Float(bits)
            if *bits <= 128 =>
        {
            Some(*bits)
        }
        // `Function` is this model's spelling for a pointer to function, so it
        // occupies exactly what a pointer does.
        CTypeLike::Pointer(_) | CTypeLike::Function { .. } => Some(ptr_bits),
        CTypeLike::Array(element, Some(count)) => {
            declaration_type_width_bits(element, ptr_bits)?.checked_mul(u32::try_from(*count).ok()?)
        }
        // A bitvector is as wide as it says. The width used to be read only
        // above what C's integers reach, so a ninety-six-bit object -- which
        // is exactly why the spelling exists, C having no such integer -- was
        // declared `BitVector(96)` by the rule that names it and had no width
        // at all to the rule that checks it.
        CTypeLike::BitVector(bits) => Some(*bits),
        // A name is as wide as what it stands for. The target is asked first
        // because it is evidence -- the capture resolved it -- and the name
        // text is only a fallback for a spelling C itself defines.
        CTypeLike::Const(inner) => declaration_type_width_bits(inner, ptr_bits),
        CTypeLike::Typedef { name, ty } => {
            declaration_type_width_bits(ty, ptr_bits).or_else(|| {
                crate::parse_external_type_like_spec(name, ptr_bits)
                    .and_then(|parsed| parsed.bits(ptr_bits))
            })
        }
        _ => None,
    }
}

/// Admit a logical type only where it describes this exact storage width.
pub fn admit_declaration_type(ty: CTypeLike, width_bits: u32, ptr_bits: u32) -> CTypeLike {
    admissible_declaration_type(ty, width_bits, ptr_bits)
        .unwrap_or_else(|| CTypeLike::machine_bits(width_bits))
}

/// A logical type as declared at this storage width, where it describes that width.
pub fn admissible_declaration_type(
    ty: CTypeLike,
    width_bits: u32,
    ptr_bits: u32,
) -> Option<CTypeLike> {
    // Fixed-width C spellings are scalar types, not distinct semantic aliases.
    // Canonicalizing them here gives every downstream type boundary the same
    // structured fact while preserving source-significant aliases such as
    // `size_t`, whose canonical integer spelling differs from its name.
    let ty = crate::signature_infer::resolve_builtin_typedefs(ty, ptr_bits);
    let admissible = match &ty {
        CTypeLike::Pointer(_) | CTypeLike::Function { .. } => width_bits == ptr_bits,
        CTypeLike::Int { bits, .. } | CTypeLike::Float(bits) => *bits == width_bits,
        CTypeLike::Typedef { .. } => declaration_type_width_bits(&ty, ptr_bits) == Some(width_bits),
        // A sized array describes the storage when its own extent is that
        // storage: the element width times the count, which is exactly what
        // `declaration_type_width_bits` computes for it.
        CTypeLike::Array(_, Some(_)) => {
            declaration_type_width_bits(&ty, ptr_bits) == Some(width_bits)
        }
        _ => false,
    };
    admissible.then_some(ty)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecompileRouteKind {
    Standard,
    StructuredWorker,
    SummaryIslands,
    LinearWorker,
    VmSummary,
    FallbackComment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileRouteFacts {
    pub kind: DecompileRouteKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_comment: Option<String>,
    pub use_prepared_semantic_view: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInputQualityFacts {
    pub expected_blocks: usize,
    pub lifted_blocks: usize,
    pub actual_lifted_blocks: usize,
    pub read_failures: usize,
    pub invalid_blocks: usize,
    pub null_lift_failures: usize,
    pub truncated_blocks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

impl FunctionInputQualityFacts {
    pub fn is_complete(&self) -> bool {
        self.refusal_reason.is_none()
            && self.expected_blocks > 0
            && self.lifted_blocks > 0
            && self.expected_blocks == self.lifted_blocks
            && self.lifted_blocks == self.actual_lifted_blocks
            && self.read_failures == 0
            && self.invalid_blocks == 0
            && self.null_lift_failures == 0
            && self.truncated_blocks == 0
    }
}

/// Advisory function-analysis report.
///
/// This detached view is useful for diagnostics and rendering at report
/// boundaries. It may retain opaque semantic or interprocedural evidence
/// owners, but it does not itself require one exact prepared SSA source and
/// cannot be promoted into source-dependent certification.
#[derive(Debug, Clone, Default)]
pub struct FunctionFacts {
    types: FunctionTypeFacts,
    interproc_summary: Option<r2ssa::PreparedInterprocSummarySet>,
    decompile_route: Option<DecompileRouteFacts>,
    input_quality: Option<FunctionInputQualityFacts>,
    callee_resolution: CalleeResolutionFacts,
    /// Spellings radare2 already holds for the addresses this function
    /// touches. Rendering reads them; nothing that decides behaviour does.
    display_names: crate::DisplayNames,
    /// What the architecture calls its user-defined operations, indexed the
    /// way `SSAOp::CallOther` indexes them. Only the lift ever saw the
    /// architecture, and an index means nothing without the table.
    user_operations: Option<std::sync::Arc<[String]>>,
    callsites: FunctionCallsiteFacts,
    call_results: FunctionCallResultFacts,
    call_render: FunctionCallRenderFacts,
    control: FunctionControlFacts,
    render: FunctionRenderFacts,
    assumptions: r2ssa::AssumptionSet,
    summary_view: InterprocSummaryView,
    diagnostics: Vec<String>,
    assumption_usage: r2ssa::AssumptionUsageReport,
    /// What the function returns, decided once where the source enriches this report.
    return_type: Option<ReturnTypeFact>,
}

/// Opaque source-owned function facts.
///
/// The exact prepared SSA allocation is retained alongside its advisory
/// report. There is deliberately no public promotion or parts constructor:
/// authoritative instances are sealed only by source-owned analysis after
/// all semantic, interprocedural, assumption, and machine-context checks pass.
#[derive(Debug, Clone)]
pub struct SourceOwnedFunctionFacts {
    source: Arc<r2ssa::SsaArtifact>,
    report: FunctionFacts,
    evidence_types: crate::EvidenceTypes,
    _callee_signatures: BTreeMap<u64, SourceOwnedCalleeSignature>,
}

/// One C signature derived from the exact retained body that owns it.
///
/// Construction is crate-private: callers may transport this certificate, but
/// cannot pair an arbitrary signature with an SSA body. The retained function
/// interface also lets a caller prove that this is the same physical contract
/// `r2ssa` admitted at its call site before consuming the logical C types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOwnedCalleeSignature {
    address: u64,
    interface: r2ssa::SourceFunctionInterface,
    signature: crate::FunctionType,
}

impl SourceOwnedCalleeSignature {
    /// Derive a callee's C signature certificate from the body that owns it.
    ///
    /// The body is read here and not retained. What proves this signature
    /// belongs to a call site is the interface matching the one the call site
    /// declares, which is a comparison by value; holding the SSA allocation as
    /// well made every certificate keep a whole prepared function alive, which
    /// is what a caller then had to cache to reuse one.
    pub(crate) fn new(
        source: &Arc<r2ssa::SsaArtifact>,
        signature: crate::FunctionType,
    ) -> Option<Self> {
        let interface = source.machine_context().function_interface()?.clone();
        let matches = function_type_matches_source_interface(
            &signature,
            &interface,
            source
                .machine_context()
                .memory_model()
                .default_address_bits(),
        );
        if !matches {
            r2il::refusal_evidence!(
                "callee-signature",
                "{:#x}: the C signature {signature:?} does not match the interface ({} parameters, {:?})",
                source.function().entry,
                interface.parameters().len(),
                interface.return_kind()
            );
        }
        matches.then_some(Self {
            address: source.function().entry,
            interface,
            signature,
        })
    }

    /// A signature the program's own declarations state, for a callee whose
    /// body the program does not carry.
    ///
    /// An import is exactly that: the name reaches the program and the body
    /// does not, so there is no SSA to derive anything from and the
    /// declaration is the only statement of what the call takes. The interface
    /// is the one the call site will carry, and the same match is checked, so
    /// a declaration that contradicts the machine is refused here rather than
    /// travelling as authority.
    pub fn declared(
        address: u64,
        interface: r2ssa::SourceFunctionInterface,
        signature: crate::FunctionType,
        address_bits: u32,
    ) -> Option<Self> {
        if !function_type_matches_source_interface(&signature, &interface, address_bits) {
            r2il::refusal_evidence!(
                "callee-signature",
                "{address:#x}: the declared signature {signature:?} does not match the interface \
                 ({} parameters, {:?})",
                interface.parameters().len(),
                interface.return_kind()
            );
            return None;
        }
        Some(Self {
            address,
            interface,
            signature,
        })
    }

    pub(crate) fn address(&self) -> u64 {
        self.address
    }
}

impl SourceOwnedFunctionFacts {
    #[cfg(test)]
    pub(crate) fn seal(source: Arc<r2ssa::SsaArtifact>, report: FunctionFacts) -> Option<Self> {
        Self::seal_with_callee_signatures(source, report, BTreeMap::new())
    }

    pub(crate) fn seal_with_callee_signatures(
        source: Arc<r2ssa::SsaArtifact>,
        mut report: FunctionFacts,
        callee_signatures: BTreeMap<u64, SourceOwnedCalleeSignature>,
    ) -> Option<Self> {
        // Canonicalization is part of sealing. Runtime consumers must observe
        // this exact report and may not clone then normalize it independently.
        report.canonicalize_type_facts();
        if report.assumptions() != &source.facts().assumptions
            || report
                .prepared_interproc_summary()
                .is_some_and(|summary| !summary.matches_root(&source))
        {
            return None;
        }
        // Source-owned facts are authoritative only when every source-dependent
        // projection is exactly what this retained SSA artifact produces. Both
        // construction and consumers previously read `report`, so a stale
        // detached render/call/control row could validate against itself. Build
        // the projection again from the retained source and the final canonical
        // type payload, then require exact equality before sealing.
        let mut expected = report.clone();
        Self::rebuild_source_owned_decompile_evidence(source.as_ref(), &mut expected);
        expected.apply_source_owned_callee_signatures(source.as_ref(), &callee_signatures);
        if report.types != expected.types
            || report.callee_resolution != expected.callee_resolution
            || report.callsites != expected.callsites
            || report.call_results != expected.call_results
            || report.call_render != expected.call_render
            || report.control != expected.control
            || report.render != expected.render
        {
            return None;
        }
        let ptr_bits = source
            .machine_context()
            .memory_model()
            .default_address_bits();
        let evidence_types =
            crate::solve_evidence_types(source.as_ref(), &report.callsite_signatures(), ptr_bits);
        Some(Self {
            source,
            report,
            evidence_types,
            _callee_signatures: callee_signatures,
        })
    }

    pub fn source(&self) -> &r2ssa::SsaArtifact {
        self.source.as_ref()
    }

    pub fn shared_source(&self) -> Arc<r2ssa::SsaArtifact> {
        Arc::clone(&self.source)
    }

    pub fn shares_source(&self, source: &Arc<r2ssa::SsaArtifact>) -> bool {
        Arc::ptr_eq(&self.source, source)
    }

    pub fn report(&self) -> &FunctionFacts {
        &self.report
    }

    /// Exact ValueId/ObjectId-keyed type solution for the retained source.
    pub fn evidence_types(&self) -> &crate::EvidenceTypes {
        &self.evidence_types
    }

    /// What this function returns, decided once for `afi` and every rendering.
    pub const fn return_type(&self) -> Option<&ReturnTypeFact> {
        self.report.return_type()
    }

    /// The type parameter `slot` is declared with at this width: the signature's where it fits, else the certified entity's.
    pub fn parameter_declaration(&self, slot: usize, width_bits: u32) -> Option<CTypeLike> {
        let ptr_bits = self
            .source
            .machine_context()
            .memory_model()
            .default_address_bits();
        let signed = self
            .report
            .type_facts()
            .render_authorized_signature()
            .and_then(|signature| signature.params.get(slot)?.ty.clone());
        let certified = u32::try_from(slot).ok().and_then(|slot| {
            match self
                .report
                .render()?
                .certified_entities
                .get(&r2ssa::SemanticId::Parameter(slot))?
            {
                CertifiedEntity::Parameter { ty, .. } => ty.clone(),
                _ => None,
            }
        });
        signed
            .into_iter()
            .chain(certified)
            .find_map(|ty| admissible_declaration_type(ty, width_bits, ptr_bits))
    }

    pub(crate) fn stamp_report_decompile_route(
        report: &mut FunctionFacts,
        kind: DecompileRouteKind,
        reason: impl Into<String>,
        fallback_comment: Option<String>,
    ) -> bool {
        let reason = reason.into();
        let reason = if reason.trim().is_empty() {
            "source-owned decompile route".to_string()
        } else {
            reason
        };
        let compatible = true;
        let (kind, reason, fallback_comment) = if compatible {
            (kind, reason, fallback_comment)
        } else {
            let reason = format!(
                "source-owned route refused: {:?} is incompatible with retained report",
                kind
            );
            (
                DecompileRouteKind::FallbackComment,
                reason.clone(),
                Some(format!("/* {reason} */")),
            )
        };
        let use_prepared_semantic_view =
            kind == DecompileRouteKind::Standard && report.render().is_some();
        report.set_decompile_route(Some(DecompileRouteFacts {
            kind,
            reason: Some(reason),
            fallback_comment: (kind == DecompileRouteKind::FallbackComment)
                .then_some(fallback_comment)
                .flatten(),
            use_prepared_semantic_view,
        }));
        compatible
    }

    /// Attach the decompile evidence the source can support.
    ///
    /// Parameter-slot resolution needs a coherent ABI. When the source does not
    /// carry one there are no parameter slots to resolve, so the steps keyed on
    /// them have nothing to do; every other piece of evidence is still valid and
    /// is still attached. Returns which parameter declarations changed and
    /// whether the return declaration changed in the final signature.
    #[cfg(test)]
    pub(crate) fn enrich_report_from_source_for_decompile(
        source: &r2ssa::SsaArtifact,
        report: &mut FunctionFacts,
    ) -> (BTreeSet<usize>, bool) {
        Self::enrich_report_from_source_with_callee_signatures(source, report, &BTreeMap::new())
    }

    /// The parameter slots whose declared type changed, and whether the return
    /// changed, are decided here, on `merged_signature`, and handed on. They
    /// were once counted here and recounted by the plan refresh on the
    /// render-authorized projection, and the two owners disagreeing failed the
    /// function. One fact has one owner.
    pub(crate) fn enrich_report_from_source_with_callee_signatures(
        source: &r2ssa::SsaArtifact,
        report: &mut FunctionFacts,
        callee_signatures: &BTreeMap<u64, SourceOwnedCalleeSignature>,
    ) -> (BTreeSet<usize>, bool) {
        let prior_signature = report.types.merged_signature.clone();
        // The report is taken rather than copied: it is written back whole at
        // the end of this function and nothing reads the original in between,
        // so the copy was the whole fact set duplicated once for the root and
        // once for every callee whose contribution is derived.
        let mut enriched = std::mem::take(report);
        let mut usage = source.facts().assumption_usage.clone();
        usage.extend(enriched.assumption_usage());
        enriched.assumption_usage = usage;
        enriched.display_names.absorb(source.display_names());
        Self::rebuild_source_owned_decompile_evidence(source, &mut enriched);
        enriched.apply_source_owned_callee_signatures(source, callee_signatures);
        let ptr_bits = source
            .machine_context()
            .memory_model()
            .default_address_bits();
        enriched.apply_certified_call_argument_type_constraints(ptr_bits);
        let evidence = enriched.apply_recovered_evidence_types(source, ptr_bits);
        // Exact immutable interface evidence outranks advisory propagation.
        // Apply it after recovered call evidence so the latter cannot rewrite
        // a declared signedness or logical projection through a weak scalar.
        enriched.apply_exact_source_signature(source);
        enriched.apply_return_type_fact(source, &evidence);
        // Type constraints may change advisory member/carrier types. Rebuild
        // once more so the sealed render projection is a pure function of the
        // final type facts and the exact retained source.
        Self::rebuild_source_owned_decompile_evidence(source, &mut enriched);
        enriched.apply_source_owned_callee_signatures(source, callee_signatures);
        let final_signature = enriched.types.merged_signature.as_ref();
        let changed_parameters = final_signature.map_or_else(BTreeSet::new, |signature| {
            signature
                .params
                .iter()
                .enumerate()
                .filter(|(slot, parameter)| {
                    prior_signature
                        .as_ref()
                        .and_then(|signature| signature.params.get(*slot))
                        .and_then(|parameter| parameter.ty.as_ref())
                        != parameter.ty.as_ref()
                })
                .map(|(slot, _)| slot)
                .collect()
        });
        let return_type_changed = prior_signature
            .as_ref()
            .and_then(|signature| signature.ret_type.as_ref())
            != final_signature.and_then(|signature| signature.ret_type.as_ref());
        *report = enriched;
        (changed_parameters, return_type_changed)
    }

    fn rebuild_source_owned_decompile_evidence(
        source: &r2ssa::SsaArtifact,
        report: &mut FunctionFacts,
    ) {
        let param_slots = exact_source_param_slot_resolver(source);
        report.attach_prepared_decompile_evidence(source);
        if let Some(param_slots) = param_slots.as_ref() {
            report.populate_certified_parameter_exprs(source, param_slots);
        }
        report.populate_parameter_home_reloads();
        report.normalize_field_certificates_from_external_layout();
        if let Some(param_slots) = param_slots.as_ref() {
            report.populate_member_access_render_facts_from_field_certificates(source, param_slots);
            // Before the declared-slot pass, which reads an array fact to find
            // the member offset inside an element the index selects.
            report.populate_array_access_render_facts_from_scalar_candidates(source, param_slots);
            report.populate_member_access_render_facts_from_declared_slots(source, param_slots);
        }
        report.populate_certified_loop_carrier_types();
    }
}

fn exact_source_param_slot_resolver(source: &r2ssa::SsaArtifact) -> Option<ParamSlotResolver> {
    let context = source.machine_context();
    let interface = context.function_interface()?;
    let abi = context.abi_model();
    if !abi.is_available() {
        return None;
    }
    let mut resolver = ParamSlotResolver::default();
    for (index, parameter) in &source.facts().boundaries.parameters {
        let slot = usize::try_from(*index).ok()?;
        let source_parameter = interface
            .parameters()
            .iter()
            .find(|candidate| candidate.index() == *index)?;
        let abi_slot = abi
            .argument_registers()
            .iter()
            .find(|candidate| candidate.index() == *index)?;
        let graph_value = source.graph().value(parameter.value)?;
        // The formal's value is the carrier's entry value, or the projection
        // minted for a lane of it (doc/adr-register-identity.md §8, 6).
        let entry_value = graph_value.canonical_storage == Some(parameter.graph_storage)
            && graph_value.var.size == parameter.graph_storage.size
            && graph_value.var.version == 0
            && source.graph().def_inst(parameter.value).is_none();
        let projection = source.graph().formal_projection_storage(parameter.value)
            == Some(parameter.graph_storage)
            && graph_value.var.size == parameter.graph_storage.size;
        if parameter.index != *index
            || Some(parameter.abi_storage) != source_parameter.register_storage()
            || parameter.abi_storage != abi_slot.storage()
            || !(entry_value || projection)
            || resolver
                .slots_by_value
                .insert(parameter.value, slot)
                .is_some()
        {
            return None;
        }
    }
    Some(resolver)
}

impl FunctionFacts {
    pub fn new(types: FunctionTypeFacts) -> Self {
        Self {
            types,
            interproc_summary: None,
            decompile_route: None,
            input_quality: None,
            callee_resolution: CalleeResolutionFacts::default(),
            display_names: crate::DisplayNames::default(),
            user_operations: None,
            callsites: FunctionCallsiteFacts::default(),
            call_results: FunctionCallResultFacts::default(),
            call_render: FunctionCallRenderFacts::default(),
            control: FunctionControlFacts::default(),
            render: FunctionRenderFacts::default(),
            assumptions: r2ssa::AssumptionSet::default(),
            summary_view: InterprocSummaryView::default(),
            diagnostics: Vec::new(),
            assumption_usage: r2ssa::AssumptionUsageReport::default(),
            return_type: None,
        }
    }

    pub fn with_assumptions(mut self, assumptions: r2ssa::AssumptionSet) -> Self {
        self.assumptions = assumptions;
        self
    }

    pub(crate) fn with_summary_view(mut self, summary_view: InterprocSummaryView) -> Self {
        self.interproc_summary = None;
        self.summary_view = summary_view;
        self
    }

    pub(crate) fn with_prepared_interproc_summary(
        mut self,
        summary: r2ssa::PreparedInterprocSummarySet,
    ) -> Self {
        let Ok(summary_view) = InterprocSummaryView::new(Some(summary.report().clone())) else {
            self.summary_view = InterprocSummaryView::default();
            self.interproc_summary = None;
            return self;
        };
        self.summary_view = summary_view;
        self.interproc_summary = Some(summary);
        self
    }

    pub fn with_diagnostics<I>(mut self, diagnostics: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.diagnostics = diagnostics.into_iter().collect();
        self
    }

    pub fn with_assumption_usage(mut self, usage: r2ssa::AssumptionUsageReport) -> Self {
        self.assumption_usage = usage;
        self
    }

    pub fn merge_assumption_usage(&mut self, usage: &r2ssa::AssumptionUsageReport) {
        self.assumption_usage.extend(usage);
    }

    pub fn with_decompile_route(mut self, route: DecompileRouteFacts) -> Self {
        self.decompile_route = Some(route);
        self
    }

    pub fn with_input_quality(mut self, input_quality: FunctionInputQualityFacts) -> Self {
        self.input_quality = Some(input_quality);
        self
    }

    pub fn set_input_quality(&mut self, input_quality: Option<FunctionInputQualityFacts>) {
        self.input_quality = input_quality;
    }

    pub fn input_quality(&self) -> Option<&FunctionInputQualityFacts> {
        self.input_quality.as_ref()
    }

    pub fn with_callee_resolution(mut self, callee_resolution: CalleeResolutionFacts) -> Self {
        self.callee_resolution = callee_resolution;
        self
    }

    pub fn set_callee_resolution(&mut self, callee_resolution: CalleeResolutionFacts) {
        self.callee_resolution = callee_resolution;
    }

    pub fn callee_resolution(&self) -> Option<&CalleeResolutionFacts> {
        (!self.callee_resolution.is_empty()).then_some(&self.callee_resolution)
    }

    pub fn with_callsites(mut self, callsites: FunctionCallsiteFacts) -> Self {
        self.callsites = callsites;
        self
    }

    pub fn set_callsites(&mut self, callsites: FunctionCallsiteFacts) {
        self.callsites = callsites;
    }

    pub fn callsites(&self) -> Option<&FunctionCallsiteFacts> {
        (!self.callsites.is_empty()).then_some(&self.callsites)
    }

    fn apply_source_owned_callee_signatures(
        &mut self,
        source: &r2ssa::SsaArtifact,
        signatures: &BTreeMap<u64, SourceOwnedCalleeSignature>,
    ) {
        for arguments in self.callsites.by_callsite.values_mut() {
            let Some(target) = arguments.direct_target else {
                continue;
            };
            let Some(signature) = signatures.get(&target) else {
                continue;
            };
            let same_interface = source
                .call_site_interface(arguments.call_site_id)
                .and_then(r2ssa::SourceCallSiteInterface::exact_callee_interface)
                .is_some_and(|interface| interface == &signature.interface);
            if same_interface && signature.address() == target {
                let mut logical_signature = signature.signature.clone();
                logical_signature.variadic = arguments.variadic;
                arguments.callee_signature = Some(logical_signature);
                arguments.callee_signature_from_source_types =
                    signature.interface.prototype_from_source_types();
            } else {
                let site = source
                    .call_site_interface(arguments.call_site_id)
                    .and_then(r2ssa::SourceCallSiteInterface::exact_callee_interface);
                r2il::refusal_evidence!(
                    "callee-signature",
                    "call to {target:#x}: same_interface={same_interface} signature_address={:#x} site={:?} signature_interface={:?}",
                    signature.address(),
                    site.map(|i| (
                        i.parameters().len(),
                        i.return_kind(),
                        i.body_proven_format_parameter(),
                        i.revision_identity().len()
                    )),
                    (
                        signature.interface.parameters().len(),
                        signature.interface.return_kind(),
                        signature.interface.body_proven_format_parameter(),
                        signature.interface.revision_identity().len()
                    )
                );
            }
        }
        // A code pointer table names its target outright, so no call site has
        // to agree about an interface before the target's own body says what
        // its prototype is.
        for (_, target) in source.machine_context().code_pointer_entries() {
            let Some(signature) = signatures.get(&target) else {
                continue;
            };
            let name = self.display_names.functions().get(&target).cloned();
            let fact = self
                .types
                .callee_facts
                .entry(target)
                .or_insert_with(|| CalleeFact::named(target, name, CalleeLinkage::Internal));
            fact.signature = Some(signature.signature.clone());
        }
    }

    pub fn with_call_results(mut self, call_results: FunctionCallResultFacts) -> Self {
        self.call_results = call_results;
        self
    }

    pub fn set_call_results(&mut self, call_results: FunctionCallResultFacts) {
        self.call_results = call_results;
    }

    pub fn call_results(&self) -> Option<&FunctionCallResultFacts> {
        (!self.call_results.is_empty()).then_some(&self.call_results)
    }

    pub fn with_call_render(mut self, call_render: FunctionCallRenderFacts) -> Self {
        self.call_render = call_render;
        self
    }

    pub fn set_call_render(&mut self, call_render: FunctionCallRenderFacts) {
        self.call_render = call_render;
    }

    pub fn call_render(&self) -> Option<&FunctionCallRenderFacts> {
        (!self.call_render.is_empty()).then_some(&self.call_render)
    }

    pub fn with_control(mut self, control: FunctionControlFacts) -> Self {
        self.control = control;
        self
    }

    pub fn set_control(&mut self, control: FunctionControlFacts) {
        self.control = control;
    }

    pub fn control(&self) -> Option<&FunctionControlFacts> {
        (!self.control.is_empty()).then_some(&self.control)
    }

    #[cfg(test)]
    fn with_render(mut self, render: FunctionRenderFacts) -> Self {
        self.render = render;
        self
    }

    pub fn render(&self) -> Option<&FunctionRenderFacts> {
        (!self.render.is_empty()).then_some(&self.render)
    }

    pub fn render_facts(&self) -> &FunctionRenderFacts {
        &self.render
    }

    /// Spellings for the addresses this function touches.
    ///
    /// Rendering asks this what to print. Nothing that decides what a call
    /// does, which route to take, or what type something has may consult it:
    /// a name is presentation, and treating it as evidence is how a decompiler
    /// starts inventing semantics from symbol strings.
    pub fn display_names(&self) -> &crate::DisplayNames {
        &self.display_names
    }

    /// Attach the spellings radare2 already holds.
    pub fn set_display_names(&mut self, names: crate::DisplayNames) {
        self.display_names = names;
    }

    /// The name the architecture gives one of its user-defined operations.
    ///
    /// `None` where the artifact was built without an architecture or the
    /// index is outside the table, both of which mean the operation cannot be
    /// identified and must be refused rather than guessed at.
    pub fn user_operation_name(&self, userop: u32) -> Option<&str> {
        self.user_operations
            .as_ref()?
            .get(userop as usize)
            .map(String::as_str)
    }

    pub fn control_facts(&self) -> &FunctionControlFacts {
        &self.control
    }

    pub fn authorized_stack_slot_owner_render(
        &self,
        object: r2ssa::ObjectId,
        offset: i64,
        name: &str,
    ) -> Option<StackSlotOwnerRenderAuthorization> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        let render_offset = self.render.stack_slot_offset(object)?;
        if render_offset != offset || !self.stack_owner_name_is_renderable(offset, name) {
            return None;
        }
        Some(StackSlotOwnerRenderAuthorization {
            object,
            offset,
            name: name.to_string(),
        })
    }

    pub fn authorized_stack_slot_owner_render_by_offset(
        &self,
        offset: i64,
        name: &str,
    ) -> Option<StackSlotOwnerRenderAuthorization> {
        let mut matching_objects = self
            .render
            .stack_slots()
            .filter_map(|(object, _, slot_offset, _)| (slot_offset == offset).then_some(object));
        let object = matching_objects.next()?;
        if matching_objects.next().is_some() {
            return None;
        }
        self.authorized_stack_slot_owner_render(object, offset, name)
    }

    pub fn authorized_stack_param_owner_render(
        &self,
        object: r2ssa::ObjectId,
        offset: i64,
    ) -> Option<StackSlotOwnerRenderAuthorization> {
        let render_offset = self.render.stack_slot_offset(object)?;
        if render_offset != offset {
            return None;
        }
        if let Some(name) = self.stack_param_owner_name_for_offset(offset) {
            return self.authorized_stack_slot_owner_render(object, offset, &name);
        }
        None
    }

    fn stack_param_owner_name_for_offset(&self, offset: i64) -> Option<String> {
        let mut candidate = None;
        for (slot_key, slot) in &self.types.stack_slots {
            if stack_slot_matches_offset(slot_key, offset)
                && matches!(
                    slot.role,
                    ExternalStackSlotRole::StackArg | ExternalStackSlotRole::ParamHome
                )
            {
                if let Some(name) =
                    indexed_param_home_name(self.types.merged_signature.as_ref(), slot)
                {
                    remember_stack_param_owner_name(&mut candidate, name)?;
                    continue;
                }
                if let Some(name) = slot
                    .param_name
                    .as_ref()
                    .filter(|name| !name.trim().is_empty())
                    .filter(|name| {
                        slot.ty.as_ref().is_some_and(stack_owner_type_is_renderable)
                            || (matches!(slot.role, ExternalStackSlotRole::ParamHome)
                                && signature_param_name_type_is_renderable(
                                    self.types.merged_signature.as_ref(),
                                    name,
                                ))
                    })
                {
                    remember_stack_param_owner_name(&mut candidate, name)?;
                    continue;
                }
                if !slot.name.trim().is_empty() {
                    remember_stack_param_owner_name(&mut candidate, &slot.name)?;
                }
            }
        }
        if candidate.is_some() {
            return candidate;
        }

        for binding in &self.types.visible_bindings {
            let Some(slot) = binding.stack_slot.as_ref() else {
                continue;
            };
            if stack_slot_matches_offset(slot, offset)
                && matches!(binding.kind, VisibleBindingKind::Param)
                && binding
                    .ty
                    .as_ref()
                    .is_some_and(stack_owner_type_is_renderable)
                && !binding.name.trim().is_empty()
            {
                remember_stack_param_owner_name(&mut candidate, &binding.name)?;
            }
        }
        candidate
    }

    fn stack_owner_name_is_renderable(&self, offset: i64, name: &str) -> bool {
        self.types.visible_bindings.iter().any(|binding| {
            let Some(slot) = binding.stack_slot.as_ref() else {
                return false;
            };
            binding.name.eq_ignore_ascii_case(name)
                && stack_slot_matches_offset(slot, offset)
                && binding
                    .ty
                    .as_ref()
                    .is_some_and(stack_owner_type_is_renderable)
                && visible_stack_binding_kind_is_renderable(&binding.kind)
        }) || self.types.stack_slots.iter().any(|(slot_key, slot)| {
            if !stack_slot_matches_offset(slot_key, offset) {
                return false;
            }
            if let Some(canonical_name) =
                indexed_param_home_name(self.types.merged_signature.as_ref(), slot)
            {
                return canonical_name.eq_ignore_ascii_case(name);
            }
            (slot.name.eq_ignore_ascii_case(name)
                || (matches!(
                    slot.role,
                    ExternalStackSlotRole::StackArg | ExternalStackSlotRole::ParamHome
                ) && slot
                    .param_name
                    .as_ref()
                    .is_some_and(|param_name| param_name.eq_ignore_ascii_case(name))))
                && (slot.ty.as_ref().is_some_and(stack_owner_type_is_renderable)
                    || (matches!(slot.role, ExternalStackSlotRole::ParamHome)
                        && slot.param_name.as_ref().is_some_and(|param_name| {
                            param_name.eq_ignore_ascii_case(name)
                                && signature_param_name_type_is_renderable(
                                    self.types.merged_signature.as_ref(),
                                    param_name,
                                )
                        })))
                && (external_stack_slot_role_is_renderable(slot.role)
                    || (matches!(slot.role, ExternalStackSlotRole::ParamHome)
                        && slot
                            .param_name
                            .as_ref()
                            .is_some_and(|param_name| param_name.eq_ignore_ascii_case(name))))
        })
    }

    pub fn authorized_recovered_stack_slot_owner_render(
        &self,
        object: r2ssa::ObjectId,
        offset: i64,
        name: &str,
    ) -> Option<StackSlotOwnerRenderAuthorization> {
        let name = name.trim();
        if !recovered_stack_owner_name_is_renderable(name) {
            return None;
        }
        let render_offset = self.render.stack_slot_offset(object)?;
        if render_offset != offset {
            return None;
        }
        Some(StackSlotOwnerRenderAuthorization {
            object,
            offset,
            name: name.to_string(),
        })
    }

    fn set_decompile_route(&mut self, route: Option<DecompileRouteFacts>) {
        self.decompile_route = route;
    }

    pub fn decompile_route(&self) -> Option<&DecompileRouteFacts> {
        self.decompile_route.as_ref()
    }

    pub fn decompile_fallback_comment(&self) -> Option<&str> {
        self.decompile_route
            .as_ref()
            .filter(|route| route.kind == DecompileRouteKind::FallbackComment)
            .and_then(|route| {
                route
                    .fallback_comment
                    .as_deref()
                    .or(route.reason.as_deref())
            })
    }

    pub fn summary_rollup(&self) -> Option<&SummaryEffectRollup> {
        self.summary_view.rollup.as_ref()
    }

    #[cfg(test)]
    pub fn __test_set_summary_rollup(&mut self, rollup: SummaryEffectRollup) {
        self.summary_view.rollup = Some(rollup);
    }

    pub fn canonicalize_type_facts(&mut self) {
        self.types = std::mem::take(&mut self.types).canonicalized();
    }

    pub fn replace_type_facts(&mut self, types: FunctionTypeFacts) {
        self.types = types.canonicalized();
    }

    pub fn normalize_field_certificates_from_external_layout(&mut self) {
        let Some(signature) = self.types.merged_signature.as_ref() else {
            return;
        };
        let type_db = &self.types.external_type_db;
        if type_db.structs.is_empty() {
            return;
        }

        for cert in &mut self.types.field_access_certificates {
            let Some(param) = signature.params.get(cert.slot) else {
                continue;
            };
            let Some(struct_name) = struct_name_from_pointer_type(param.ty.as_ref()) else {
                continue;
            };
            let key = normalize_external_type_name(struct_name).to_ascii_lowercase();
            let Some(field) = type_db
                .structs
                .get(&key)
                .and_then(|structure| structure.fields.get(&cert.field_offset))
            else {
                continue;
            };
            cert.field_name = field.name.clone();
            if cert.field_type.is_none() {
                cert.field_type = field.ty.clone();
            }
        }
    }

    /// A member of an aggregate the source declared in a frame slot.
    ///
    /// The pointer form -- `s->field` through a parameter -- has a producer
    /// already. A struct held in a slot had none, so an access inside one
    /// rendered as address arithmetic carrying the frame displacement, and the
    /// geometry constant in it then had no rendered occurrence.
    fn populate_member_access_render_facts_from_declared_slots(
        &mut self,
        prepared: &r2ssa::SsaArtifact,
        param_slots: &ParamSlotResolver,
    ) {
        let Some(interface) = prepared.machine_context().function_interface() else {
            return;
        };
        let Some(graph) = interface.type_graph() else {
            return;
        };
        let mut member_facts = Vec::new();
        for memory in self.render.memory_accesses() {
            // Offset zero is a member too when the access is narrower than the
            // object: the slot's name would stand for the whole aggregate.
            // An element of an array of aggregates has no constant object
            // offset -- the index is a value -- but the member's offset inside
            // the element is as constant as any other, and the array fact for
            // the same access carries it. Without this the declared type never
            // sees the access and `arr[i].third` is left to the external
            // layout's `f_8`.
            let indexed = self
                .render
                .array_accesses_by_op
                .get(&(memory.block_addr, memory.op_index, memory.is_write))
                .and_then(|facts| {
                    facts.iter().find(|fact| {
                        fact.access == memory.access
                            && fact.object == memory.object
                            && fact.access_width == memory.width
                    })
                });
            let Some(offset_bits) = memory
                .object_offset
                .filter(|offset| *offset >= 0)
                .and_then(|offset| u64::try_from(offset).ok())
                .or_else(|| indexed.map(|fact| fact.field_offset))
                .filter(|_| memory.width > 0)
                .and_then(|bytes| bytes.checked_mul(8))
            else {
                r2il::refusal_evidence!(
                    "member-access-declined",
                    "object={:?} width={} address={:?}: no constant offset inside the object",
                    memory.object,
                    memory.width,
                    memory.address
                );
                continue;
            };
            let declined = |why: &str| {
                r2il::refusal_evidence!(
                    "member-access-declined",
                    "object={:?} offset_bits={offset_bits} width={}: {why}",
                    memory.object,
                    memory.width
                );
            };
            // A declared stack slot, or the aggregate a pointer parameter points at.
            let slot_type = prepared
                .certificates()
                .stack_slots
                .get(&memory.object)
                .and_then(|certificate| certificate.source_slot.as_ref())
                .and_then(|slot| slot.logical_type());
            let pointer_base = slot_type
                .is_none()
                .then(|| {
                    parameter_base_of(prepared, memory.address)
                        .or_else(|| {
                            indexed.and_then(|fact| match fact.base {
                                Some(r2ssa::SemanticId::Parameter(slot)) => {
                                    usize::try_from(slot).ok()
                                }
                                _ => None,
                            })
                        })
                        .or_else(|| {
                            prepared_memory_access_param_slot(prepared, memory, param_slots)
                        })
                })
                .flatten();
            let declared_type =
                slot_type.or_else(|| parameter_pointee_type(interface, pointer_base?));
            let Some(aggregate) =
                declared_type.and_then(|type_id| aggregate_layout_for_type(graph, type_id))
            else {
                declined("neither a declared slot nor a pointer parameter names an aggregate");
                continue;
            };
            // A tag the rendering cannot define names nothing it can spell, and the fact
            // would retype the access to it as well as label it.
            if !aggregate_is_definable(graph, aggregate.name()) {
                declined("the rendering cannot define that aggregate");
                continue;
            }
            let width_bits = u64::from(memory.width).saturating_mul(8);
            // The member has to be the whole of what the access reads, or its
            // name would stand for more or less than the machine touched.
            let Some(member) = aggregate.members().iter().find(|member| {
                member.offset_bits() == offset_bits && member.size_bits() == width_bits
            }) else {
                declined("no member covers exactly that offset and width");
                continue;
            };
            r2il::refusal_evidence!(
                "member-access-named",
                "object={:?} offset_bits={offset_bits} width={} aggregate={} member={}",
                memory.object,
                memory.width,
                aggregate.name(),
                member.name()
            );
            member_facts.push(MemberAccessRenderFact {
                access: memory.access,
                block_addr: memory.block_addr,
                op_index: memory.op_index,
                object: memory.object,
                is_write: memory.is_write,
                field_offset: offset_bits / 8,
                field_name: member.name().to_string(),
                field_type: crate::analysis::source_type_like(
                    graph,
                    member.type_id(),
                    &mut BTreeSet::new(),
                ),
                access_width: memory.width,
                base: pointer_base.and_then(r2ssa::SemanticId::parameter),
                source: MemberAccessSource::DeclaredType,
            });
        }
        for fact in member_facts {
            let key = (fact.block_addr, fact.op_index, fact.is_write);
            let facts = self.render.member_accesses_by_op.entry(key).or_default();
            // The declared name replaces one an external layout guessed: two facts for one
            // access are no fact at all, because the lookup requires exactly one.
            facts.retain(|existing| {
                !(existing.access == fact.access
                    && existing.object == fact.object
                    && existing.access_width == fact.access_width)
            });
            facts.push(fact);
        }
    }

    fn populate_member_access_render_facts_from_field_certificates(
        &mut self,
        prepared: &r2ssa::SsaArtifact,
        param_slots: &ParamSlotResolver,
    ) {
        if self.types.field_access_certificates.is_empty() {
            return;
        }

        let mut member_facts = Vec::new();
        for memory in self.render.memory_accesses() {
            if memory.width == 0 {
                continue;
            }
            let Some(field_offset) = prepared_memory_access_field_offset(prepared, memory) else {
                continue;
            };
            let param_slot = prepared_memory_access_param_slot(prepared, memory, param_slots);
            let ptr_bits = prepared_memory_access_ptr_bits(prepared, memory);
            member_facts.extend(self.member_render_facts_for_memory(
                memory,
                field_offset,
                ptr_bits,
                param_slot,
            ));
        }

        for candidate in self.types.scalar_array_render_candidates.iter().copied() {
            if candidate.access_width == 0
                || !self.scalar_array_render_candidate_has_array_certificate(candidate)
            {
                continue;
            }
            let key = (candidate.block_addr, candidate.op_index, candidate.is_write);
            let Some(effect_ids) = self.render.memory_effects_by_op.get(&key) else {
                continue;
            };
            for effect_id in effect_ids {
                let Some(memory) = self
                    .render
                    .certified_effect(*effect_id)
                    .and_then(CertifiedEffect::memory_fact)
                else {
                    continue;
                };
                if memory.block_addr != candidate.block_addr
                    || memory.op_index != candidate.op_index
                    || memory.is_write != candidate.is_write
                    || memory.width == 0
                    || memory.width != candidate.access_width
                {
                    continue;
                }
                if self
                    .certified_scalar_array_identity(prepared, memory, candidate)
                    .is_none()
                {
                    continue;
                }
                let ptr_bits = prepared_memory_access_ptr_bits(prepared, memory);
                member_facts.extend(self.member_render_facts_for_memory(
                    memory,
                    candidate.field_offset,
                    ptr_bits,
                    Some(candidate.slot),
                ));
            }
        }

        for fact in member_facts {
            let key = (fact.block_addr, fact.op_index, fact.is_write);
            let facts = self.render.member_accesses_by_op.entry(key).or_default();
            if !facts.contains(&fact) {
                facts.push(fact);
            }
        }

        for facts in self.render.member_accesses_by_op.values_mut() {
            facts.sort_by(|a, b| {
                (
                    a.block_addr,
                    a.op_index,
                    a.is_write,
                    a.field_offset,
                    a.access_width,
                    a.field_name.as_str(),
                    a.access,
                )
                    .cmp(&(
                        b.block_addr,
                        b.op_index,
                        b.is_write,
                        b.field_offset,
                        b.access_width,
                        b.field_name.as_str(),
                        b.access,
                    ))
            });
        }
    }

    fn member_render_facts_for_memory(
        &self,
        memory: &MemoryAccessRenderFact,
        field_offset: u64,
        ptr_bits: u32,
        param_slot: Option<usize>,
    ) -> Vec<MemberAccessRenderFact> {
        self.types
            .field_access_certificates
            .iter()
            .filter(|cert| {
                param_slot == Some(cert.slot)
                    && cert.field_offset == field_offset
                    && field_certificate_width_matches(cert, memory.width, ptr_bits)
            })
            .map(|cert| MemberAccessRenderFact {
                access: memory.access,
                block_addr: memory.block_addr,
                op_index: memory.op_index,
                object: memory.object,
                is_write: memory.is_write,
                field_offset,
                field_name: cert.field_name.clone(),
                field_type: cert
                    .field_type
                    .as_deref()
                    .and_then(|ty| parse_c_type_like(ty, ptr_bits)),
                access_width: memory.width,
                base: u32::try_from(cert.slot)
                    .ok()
                    .map(r2ssa::SemanticId::Parameter),
                source: MemberAccessSource::ExternalLayout,
            })
            .collect()
    }

    fn populate_array_access_render_facts_from_scalar_candidates(
        &mut self,
        prepared: &r2ssa::SsaArtifact,
        _param_slots: &ParamSlotResolver,
    ) {
        if self.types.scalar_array_render_candidates.is_empty() {
            return;
        }

        for candidate in self.types.scalar_array_render_candidates.iter().copied() {
            if candidate.element_stride == 0
                || candidate.access_width == 0
                || !self.scalar_array_render_candidate_has_array_certificate(candidate)
            {
                continue;
            }
            let key = (candidate.block_addr, candidate.op_index, candidate.is_write);
            let Some(effect_ids) = self.render.memory_effects_by_op.get(&key) else {
                continue;
            };
            let effect_ids = effect_ids.clone();
            for effect_id in effect_ids {
                let Some(memory) = self
                    .render
                    .certified_effect(effect_id)
                    .and_then(CertifiedEffect::memory_fact)
                else {
                    continue;
                };
                if memory.block_addr != candidate.block_addr
                    || memory.op_index != candidate.op_index
                    || memory.is_write != candidate.is_write
                    || memory.width == 0
                    || memory.width != candidate.access_width
                {
                    continue;
                }
                let Some((base, index)) =
                    self.certified_scalar_array_identity(prepared, memory, candidate)
                else {
                    continue;
                };
                let fact = ArrayAccessRenderFact {
                    access: memory.access,
                    block_addr: memory.block_addr,
                    op_index: memory.op_index,
                    object: memory.object,
                    is_write: memory.is_write,
                    field_offset: candidate.field_offset,
                    element_stride: candidate.element_stride,
                    access_width: memory.width,
                    base: Some(base),
                    index: Some(index),
                };
                let facts = self.render.array_accesses_by_op.entry(key).or_default();
                if !facts.contains(&fact) {
                    facts.push(fact);
                }
            }
        }

        for facts in self.render.array_accesses_by_op.values_mut() {
            facts.sort_by_key(|fact| {
                (
                    fact.block_addr,
                    fact.op_index,
                    fact.is_write,
                    fact.field_offset,
                    fact.element_stride,
                    fact.access_width,
                    fact.access,
                    fact.object,
                    fact.base,
                    fact.index,
                )
            });
        }
    }

    fn scalar_array_render_candidate_has_array_certificate(
        &self,
        candidate: crate::facts::ScalarArrayRenderCandidate,
    ) -> bool {
        self.types.array_index_certificates.iter().any(|cert| {
            cert.slot == candidate.slot
                && cert.field_offset == candidate.field_offset
                && cert.element_stride == candidate.element_stride
                && match &cert.base {
                    Some(crate::facts::ArrayIndexBase::Param { index }) => *index == candidate.slot,
                    Some(crate::facts::ArrayIndexBase::StackSlot { .. }) | None => true,
                }
        })
    }

    fn certified_scalar_array_identity(
        &self,
        prepared: &r2ssa::SsaArtifact,
        memory: &MemoryAccessRenderFact,
        candidate: crate::facts::ScalarArrayRenderCandidate,
    ) -> Option<(r2ssa::SemanticId, r2ssa::SemanticId)> {
        let index = candidate.index_value?;
        let address = prepared.addresses().parameter_expression(memory.address)?;
        let [term] = address.terms.as_slice() else {
            return None;
        };
        if address.parameter != candidate.slot
            || address.offset != i64::try_from(candidate.field_offset).ok()?
            || term.coefficient != i64::try_from(candidate.element_stride).ok()?
            || term.value != index
            || self
                .render
                .parameter_values(candidate.slot)
                .next()
                .is_none()
            || !self
                .render
                .certified_expr_for_value(index)
                .is_some_and(|expr| expr.fact.renderable)
        {
            return None;
        }
        Some((
            r2ssa::SemanticId::parameter(candidate.slot)?,
            r2ssa::SemanticId::expression(index),
        ))
    }

    pub fn type_facts(&self) -> &FunctionTypeFacts {
        &self.types
    }

    #[cfg(test)]
    pub fn __test_type_facts_mut(&mut self) -> &mut FunctionTypeFacts {
        &mut self.types
    }

    #[cfg(test)]
    pub fn __test_render_facts_mut(&mut self) -> &mut FunctionRenderFacts {
        &mut self.render
    }

    pub fn assumptions(&self) -> &r2ssa::AssumptionSet {
        &self.assumptions
    }

    pub fn summary_view(&self) -> &InterprocSummaryView {
        &self.summary_view
    }

    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    pub fn assumption_usage(&self) -> &r2ssa::AssumptionUsageReport {
        &self.assumption_usage
    }

    pub fn apply_signature_projection(
        &mut self,
        function_name: &str,
        projection: FunctionSignatureProjection,
        ptr_bits: u32,
    ) -> SignatureProjectionResult {
        self.types
            .apply_signature_projection(function_name, projection, ptr_bits)
    }

    pub fn apply_decompile_type_override(&mut self, override_facts: FunctionTypeFacts) -> bool {
        let Some(signature) = override_facts.render_authorized_signature().cloned() else {
            return false;
        };
        self.types.merged_signature = Some(signature);
        self.types.signature_certificate = override_facts.signature_certificate;
        true
    }

    fn attach_prepared_decompile_evidence(&mut self, prepared: &r2ssa::SsaArtifact) {
        let prepared_callee_resolution = prepared_callee_resolution_facts(prepared, self);
        let prepared_callsites = prepared_callsite_argument_facts(prepared);
        let prepared_call_results = prepared_call_result_facts(prepared);
        let prepared_call_render = prepared_call_render_facts(prepared);
        let prepared_control = prepared_control_facts(prepared);
        let prepared_render = FunctionRenderFacts::from_prepared(prepared);

        // These fields are projections of one exact prepared artifact, not
        // extension points. Letting detached rows win with `or_insert` gave the
        // report and its validator the same stale answer. Advisory type and
        // presentation inputs are consumed while rebuilding, but the resulting
        // source-owned maps are replaced atomically.
        self.callee_resolution = prepared_callee_resolution;
        self.callsites = prepared_callsites;
        self.call_results = prepared_call_results;
        self.call_render = prepared_call_render;
        self.control = prepared_control;
        self.render = prepared_render;
        self.user_operations = Some(prepared.user_operations());
    }

    /// Bind canonical entry values to ABI parameter-slot semantic identities.
    ///
    /// This is a separate step because the ABI profile is owned by the engine,
    /// while expression identity is owned by prepared SSA. Every entry alias is
    /// retained; downstream consumers can select a width without guessing from
    /// register spelling.
    fn populate_certified_parameter_exprs(
        &mut self,
        prepared: &r2ssa::SsaArtifact,
        param_slots: &ParamSlotResolver,
    ) {
        // Register call arguments are implicit machine reads and therefore do
        // not appear in the graph's ordinary use lists. The callsite
        // certificate is their canonical use table; index it once so a formal
        // handed straight to a callee remains a live parameter binding.
        // A carrier passed to a call is read by that call, whether or not the
        // call certified: an import thunk's tail forwards a variadic tail no
        // count proves, and its fixed parameters are still what it passes.
        let implicit_call_arguments = prepared
            .certificates()
            .callsites
            .values()
            .flat_map(|callsite| callsite.argument_values.iter().copied())
            .chain(
                prepared
                    .facts()
                    .boundaries
                    .calls
                    .values()
                    .flat_map(|boundary| boundary.arguments.iter())
                    .filter_map(|argument| match argument.value {
                        r2ssa::SourceCallArgumentValue::Value(value) => Some(value),
                        r2ssa::SourceCallArgumentValue::PreservedEntry => None,
                    }),
            )
            .collect::<BTreeSet<_>>();
        // The resolver names each formal's one value -- the carrier's entry
        // value or the lane projection minted for it -- and its width is the
        // formal's (doc/adr-register-identity.md).
        let mut entry_value_by_slot = BTreeMap::<u32, (r2ssa::ValueId, u32)>::new();
        let mut resolved = param_slots
            .slots_by_value
            .iter()
            .map(|(value, slot)| (*value, *slot))
            .collect::<Vec<_>>();
        resolved.sort_unstable();
        for (value_id, slot) in resolved {
            let Some(value) = prepared.graph().value(value_id) else {
                continue;
            };
            if !parameter_entry_value_has_live_use(prepared, value.id, &implicit_call_arguments) {
                continue;
            }
            let Some(parameter_id) = r2ssa::SemanticId::parameter(slot) else {
                continue;
            };
            let Some(cert) = self
                .render
                .certified_exprs
                .get_mut(&r2ssa::SemanticId::expression(value.id))
            else {
                continue;
            };
            cert.bindings.insert(parameter_id);
            r2il::refusal_evidence!(
                "parameter-entry",
                "slot {slot} entry value {:?} of {} bytes ({:?})",
                value.id,
                value.var.size,
                value.canonical_storage
            );
            entry_value_by_slot.insert(slot as u32, (value.id, value.var.size));
        }
        let mut parameter_slot_by_value = entry_value_by_slot
            .iter()
            .map(|(slot, (value, _))| (*value, *slot))
            .collect::<BTreeMap<_, _>>();
        for reload in prepared.certificates().stack_reloads.values() {
            let mut slots = [reload.canonical_source, reload.source]
                .into_iter()
                .filter_map(|value| parameter_slot_by_value.get(&value).copied())
                .collect::<BTreeSet<_>>();
            let Some(slot) = slots.pop_first() else {
                continue;
            };
            if !slots.is_empty() {
                continue;
            }
            let Some(expr) = self
                .render
                .certified_exprs
                .get_mut(&r2ssa::SemanticId::expression(reload.value))
            else {
                continue;
            };
            expr.bindings.insert(r2ssa::SemanticId::Parameter(slot));
            parameter_slot_by_value.insert(reload.value, slot);
        }

        // Preserve exact parameter identity through same-width copies. This is
        // an alias relation, unlike the broader expression dependency walk:
        // arithmetic, loads, casts, and phi nodes never inherit the binding.
        let mut changed = true;
        while changed {
            changed = false;
            for value in &prepared.graph().values {
                if parameter_slot_by_value.contains_key(&value.id) {
                    continue;
                }
                let Some(inst) = prepared
                    .graph()
                    .def_inst(value.id)
                    .and_then(|inst| prepared.graph().inst(inst))
                else {
                    continue;
                };
                let r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { dst, src }) = &inst.payload else {
                    continue;
                };
                if dst.size != src.size {
                    continue;
                }
                let Some(source) = prepared.graph().value_id_for_var(src) else {
                    continue;
                };
                let Some(slot) = parameter_slot_by_value.get(&source).copied() else {
                    continue;
                };
                let Some(expr) = self
                    .render
                    .certified_exprs
                    .get_mut(&r2ssa::SemanticId::expression(value.id))
                else {
                    continue;
                };
                expr.bindings.insert(r2ssa::SemanticId::Parameter(slot));
                parameter_slot_by_value.insert(value.id, slot);
                changed = true;
            }
        }
        for (slot, (entry_value, carrier_width)) in entry_value_by_slot {
            let id = r2ssa::SemanticId::Parameter(slot);
            r2il::refusal_evidence!(
                "parameter-entity",
                "slot {slot} carrier {carrier_width} logical {:?}",
                prepared
                    .machine_context()
                    .function_interface()
                    .and_then(|interface| interface
                        .parameter_logical_values()
                        .get(slot as usize)
                        .copied())
            );
            let ty = prepared
                .machine_context()
                .function_interface()
                .filter(|interface| {
                    interface
                        .parameters()
                        .get(slot as usize)
                        .is_some_and(|parameter| parameter.index() == slot)
                })
                .and_then(|interface| {
                    let graph = interface.type_graph()?;
                    let logical = interface.parameter_logical_value(slot as usize)?;
                    let ty = crate::analysis::source_type_like(
                        graph,
                        logical.type_id(),
                        &mut BTreeSet::new(),
                    )?;
                    // The graph has no qualifier; the prototype's own spelling does.
                    let spelled = prepared
                        .source_signature()
                        .and_then(|signature| signature.named_parameters().get(slot as usize))
                        .and_then(r2source::SourceSignatureParameter::type_spelling)
                        .and_then(|spelling| {
                            crate::parse_c_type_like(
                                spelling,
                                prepared
                                    .machine_context()
                                    .memory_model()
                                    .default_address_bits(),
                            )
                        });
                    Some(match spelled {
                        Some(spelled) => crate::analysis::requalify(ty, &spelled),
                        None => ty,
                    })
                });
            self.render.certified_entities.insert(
                id,
                CertifiedEntity::Parameter {
                    id,
                    slot,
                    entry_values: BTreeSet::from([entry_value]),
                    home_reload_values: BTreeSet::new(),
                    carrier_width,
                    ty,
                },
            );
        }
    }

    /// Give each parameter the values its home slot's reloads produced.
    ///
    /// `CertifiedEntity::StackSlot` deliberately declines to coalesce a
    /// parameter home's reloads -- "the parameter entity owns those values and
    /// decides there" -- and until now the parameter entity never claimed them,
    /// so every `-O0` body named one local for the slot and a second for the
    /// register that ferried it back.
    fn populate_parameter_home_reloads(&mut self) {
        let mut by_parameter = BTreeMap::<u32, BTreeSet<r2ssa::ValueId>>::new();
        for entity in self.render.certified_entities.values() {
            let CertifiedEntity::StackSlot {
                source_slot,
                reload_values,
                ..
            } = entity
            else {
                continue;
            };
            let Some(index) = source_slot.and_then(|slot| match slot.role() {
                r2ssa::SourceStackSlotRole::ParameterHome {
                    parameter_index, ..
                }
                | r2ssa::SourceStackSlotRole::Parameter { parameter_index } => {
                    Some(parameter_index)
                }
                _ => None,
            }) else {
                continue;
            };
            by_parameter
                .entry(index)
                .or_default()
                .extend(reload_values.iter().copied());
        }
        for entity in self.render.certified_entities.values_mut() {
            let CertifiedEntity::Parameter {
                slot,
                home_reload_values,
                ..
            } = entity
            else {
                continue;
            };
            if let Some(reloads) = by_parameter.get(slot) {
                home_reload_values.extend(reloads.iter().copied());
            }
        }
    }

    /// Attach one unambiguous certified type to each loop carrier.
    ///
    /// Carrier identity comes from prepared SSA. Types are projected only from
    /// an exact parameter or return binding already authorized by the function
    /// signature, or from an exact typed memory-access certificate. Conflicting
    /// projections leave the carrier untyped.
    fn populate_certified_loop_carrier_types(&mut self) {
        let signature = self.types.render_authorized_signature().cloned();
        let mut memory_value_types = BTreeMap::<r2ssa::ValueId, CTypeLike>::new();
        let mut conflicting_memory_values = BTreeSet::new();
        for memory in self.render.memory_accesses() {
            let Some(value) = memory.value.filter(|_| !memory.is_write) else {
                continue;
            };
            let Some(ty) = self.render.memory_value_type(memory.access).cloned() else {
                continue;
            };
            match memory_value_types.get(&value) {
                None => {
                    memory_value_types.insert(value, ty);
                }
                Some(existing) if *existing == ty => {}
                Some(_) => {
                    conflicting_memory_values.insert(value);
                }
            }
        }
        for value in conflicting_memory_values {
            memory_value_types.remove(&value);
        }
        let return_values = self
            .render
            .return_effects()
            .map(|fact| fact.value)
            .collect::<BTreeSet<_>>();
        let carriers = self
            .render
            .loop_carriers()
            .filter_map(|entity| match entity {
                CertifiedEntity::LoopCarrier { id, members, .. } => Some((*id, members.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        for (id, members) in carriers {
            let mut candidates = Vec::<CTypeLike>::new();
            let carrier_values = members
                .into_iter()
                .map(|member| member.value)
                .collect::<BTreeSet<_>>();
            for value in &carrier_values {
                if let Some(slot) = self.render.exact_parameter_slot_for_value(*value)
                    && let Some(ty) = signature
                        .as_ref()
                        .and_then(|signature| signature.params.get(slot))
                        .and_then(|param| param.ty.clone())
                    && !candidates.contains(&ty)
                {
                    candidates.push(ty);
                }
                if let Some(ty) = memory_value_types.get(value).cloned()
                    && !candidates.contains(&ty)
                {
                    candidates.push(ty);
                }
            }
            if carrier_values
                .iter()
                .any(|value| return_values.contains(value))
                && let Some(ty) = signature
                    .as_ref()
                    .and_then(|signature| signature.ret_type.clone())
                && !candidates.contains(&ty)
            {
                candidates.push(ty);
            }
            let [ty] = candidates.as_slice() else {
                continue;
            };
            if let Some(CertifiedEntity::LoopCarrier {
                ty: carrier_type, ..
            }) = self.render.certified_entities.get_mut(&id)
            {
                *carrier_type = Some(ty.clone());
            }
        }
    }

    /// Project exact callee parameter types back onto caller parameters.
    ///
    /// A constraint is accepted only when the callsite argument has a unique
    /// certified path to one ABI parameter and the callee identity carries a
    /// typed signature. Conflicting callees leave the caller type unchanged.
    pub fn apply_certified_call_argument_type_constraints(&mut self, ptr_bits: u32) -> usize {
        let type_db = &self.types.external_type_db;
        let mut constraints = BTreeMap::<usize, CTypeLike>::new();
        let mut conflicted = BTreeSet::new();
        for (callsite, arguments) in &self.callsites.by_callsite {
            let identity = self.callee_resolution.identity_for_callsite(*callsite);
            let signature = arguments
                .callee_signature
                .as_ref()
                .or_else(|| identity.and_then(crate::CalleeIdentity::known_signature));
            let Some(signature) = signature else {
                continue;
            };
            for argument in &arguments.argument_values {
                let Some(hint) = signature.params.get(argument.index) else {
                    continue;
                };
                let Some(slot) = self
                    .render
                    .unique_parameter_dependency_slot_for_value(argument.value)
                else {
                    continue;
                };
                if conflicted.contains(&slot) {
                    continue;
                }
                match constraints.get(&slot) {
                    None => {
                        constraints.insert(slot, hint.clone());
                    }
                    Some(existing) if existing == hint => {}
                    Some(existing)
                        if crate::signature_hint_can_replace_existing(
                            existing,
                            Some(hint),
                            ptr_bits,
                            type_db,
                        ) =>
                    {
                        constraints.insert(slot, hint.clone());
                    }
                    Some(existing)
                        if crate::signature_hint_can_replace_existing(
                            hint,
                            Some(existing),
                            ptr_bits,
                            type_db,
                        ) => {}
                    Some(_) => {
                        constraints.remove(&slot);
                        conflicted.insert(slot);
                    }
                }
            }
        }

        let protects_existing = self.types.certified_signature().is_some();
        let Some(signature) = self.types.merged_signature.as_mut() else {
            return 0;
        };
        let mut applied = BTreeMap::new();
        for (slot, hint) in constraints {
            let Some(param) = signature.params.get_mut(slot) else {
                continue;
            };
            let replace = match param.ty.as_ref() {
                None => true,
                Some(existing) if existing == &hint => false,
                Some(existing) => {
                    !protects_existing
                        && crate::signature_hint_can_replace_existing(
                            existing,
                            Some(&hint),
                            ptr_bits,
                            type_db,
                        )
                }
            };
            if replace {
                param.ty = Some(hint.clone());
                applied.insert(slot, hint);
            }
        }
        if applied.is_empty() {
            return 0;
        }
        for (slot, hint) in &applied {
            if let Some(param) = self.types.register_params.get_mut(*slot) {
                param.ty = Some(hint.clone());
            }
            for binding in self
                .types
                .visible_bindings
                .iter_mut()
                .filter(|binding| binding.param_index == Some(*slot))
            {
                binding.ty = Some(hint.clone());
            }
        }
        self.types
            .certify_current_signature_with_source(SignatureCertificateSource::CalleeSignature);
        applied.len()
    }

    /// Take the whole signature from the immutable source interface where it
    /// carries a type graph: each parameter's and the return's declared type,
    /// resolved through the graph, which is the same source the binding layer
    /// declares from. The rendered header and the body then agree by
    /// construction. radare2's spelled signature was the header's source before
    /// and stays the fallback: it names typedefs the renderer cannot place and
    /// carries signedness the source never declared, which is how `z_streamp`
    /// rendered as a machine word and a header parameter disagreed with the
    /// typed local it was stored into. Parameter names are kept from the
    /// spelled signature when it has the same arity.
    fn apply_exact_source_signature(&mut self, source: &r2ssa::SsaArtifact) -> bool {
        let context = source.machine_context();
        let Some(interface) = context.function_interface() else {
            return false;
        };
        let Some(graph) = interface.type_graph() else {
            return false;
        };
        let logical = interface.parameter_logical_values();
        if logical.len() != interface.parameters().len() {
            return false;
        }
        let spelled = self.types.merged_signature.clone();
        let names = spelled
            .as_ref()
            .filter(|signature| signature.params.len() == logical.len())
            .map(|signature| {
                signature
                    .params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect::<Vec<_>>()
            });
        // The graph carries no qualifier; the spelling does, and a `const`
        // pointee is part of the declared type.
        let ptr_bits = context.memory_model().default_address_bits();
        let spelled_types = spelled
            .as_ref()
            .filter(|signature| signature.params.len() == logical.len())
            .map(|signature| {
                signature
                    .params
                    .iter()
                    .map(|param| param.ty.clone())
                    .collect::<Vec<_>>()
            })
            .or_else(|| {
                let signature = source.source_signature()?;
                let parameters = signature.named_parameters();
                (parameters.len() == logical.len()).then(|| {
                    parameters
                        .iter()
                        .map(|parameter| {
                            parameter
                                .type_spelling()
                                .and_then(|spelling| crate::parse_c_type_like(spelling, ptr_bits))
                        })
                        .collect::<Vec<_>>()
                })
            });
        r2il::refusal_evidence!(
            "exact-source-signature",
            "{:#x}: spelled={} presentation={} spelled_types={:?}",
            source.function().entry,
            spelled.is_some(),
            source.source_signature().is_some(),
            spelled_types
        );
        let mut params = Vec::with_capacity(logical.len());
        for (index, value) in logical.iter().enumerate() {
            // An exact signature is exact in every parameter. One the capture
            // could not place leaves the signature to radare2's spelling,
            // which is what a function with no graph already falls back to --
            // and the rest of the graph still serves its slots and members.
            let Some(value) = value else {
                r2il::refusal_evidence!(
                    "exact-source-signature",
                    "parameter {index} carries no logical value"
                );
                return false;
            };
            let Some(ty) =
                crate::analysis::source_type_like(graph, value.type_id(), &mut BTreeSet::new())
            else {
                r2il::refusal_evidence!(
                    "exact-source-signature",
                    "parameter {index}'s logical type is not in the graph"
                );
                return false;
            };
            let ty = match spelled_types
                .as_ref()
                .and_then(|types| types.get(index))
                .and_then(Option::as_ref)
            {
                Some(spelled) => crate::analysis::requalify(ty, spelled),
                None => ty,
            };
            let name = names
                .as_ref()
                .and_then(|names| names.get(index).cloned())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("arg{index}"));
            params.push(crate::FunctionParamSpec { name, ty: Some(ty) });
        }
        let ret_type = match interface.return_kind() {
            r2ssa::SourceFunctionReturn::Void => Some(CTypeLike::Void),
            r2ssa::SourceFunctionReturn::Register { .. } => {
                interface.return_logical_value().and_then(|value| {
                    crate::analysis::source_type_like(graph, value.type_id(), &mut BTreeSet::new())
                })
            }
            // Nothing proved a result, so no return type can be spelled.
            r2ssa::SourceFunctionReturn::Unproven => None,
        };
        let Some(ret_type) = ret_type else {
            r2il::refusal_evidence!(
                "exact-source-signature",
                "the return type is not in the graph"
            );
            return false;
        };
        let signature = crate::FunctionSignatureSpec {
            ret_type: Some(ret_type),
            params,
        };
        let Some(certificate) = crate::SignatureCertificate::from_signature(
            &signature,
            [SignatureCertificateSource::SourceInterface],
        ) else {
            r2il::refusal_evidence!(
                "exact-source-signature",
                "the signature carries no certificate: {signature:?}"
            );
            return false;
        };
        self.types.merged_signature = Some(signature);
        self.types.signature_certificate = Some(certificate);
        true
    }

    /// Decide the return type once and make the signature state it, or state none where it is refused.
    fn apply_return_type_fact(
        &mut self,
        source: &r2ssa::SsaArtifact,
        evidence: &crate::EvidenceTypes,
    ) {
        let fact = ReturnTypeFact::decide(source, &self.callsite_signatures(), evidence);
        let exact = matches!(
            fact,
            ReturnTypeFact::Decided {
                by: ReturnTypeEvidence::ExactSource,
                ..
            }
        );
        if let Some(signature) = self.types.merged_signature.as_mut() {
            let previous = signature.clone();
            signature.ret_type = fact.decided().cloned();
            let mut sources = self
                .types
                .signature_certificate
                .as_ref()
                .filter(|certificate| certificate.signature == previous)
                .map(|certificate| certificate.sources.clone());
            if exact {
                sources
                    .get_or_insert_default()
                    .push(SignatureCertificateSource::SourceReturnType);
            }
            // A signature nothing certified before stays uncertified; only its return is restated.
            self.types.signature_certificate = sources.and_then(|sources| {
                crate::SignatureCertificate::from_signature(signature, sources)
            });
        }
        self.return_type = Some(fact);
    }

    /// What the function returns, where the source enriched this report.
    pub const fn return_type(&self) -> Option<&ReturnTypeFact> {
        self.return_type.as_ref()
    }

    /// The prototype each call site reaches, keyed the way the solver needs it.
    pub(crate) fn callsite_signatures(&self) -> BTreeMap<r2ssa::CallSiteId, crate::FunctionType> {
        let mut signatures = BTreeMap::new();
        for (callsite, arguments) in &self.callsites.by_callsite {
            let Some(signature) = arguments.callee_signature.as_ref().or_else(|| {
                self.callee_resolution
                    .identity_for_callsite(*callsite)
                    .and_then(crate::CalleeIdentity::known_signature)
            }) else {
                continue;
            };
            signatures.insert(arguments.call_site_id, signature.clone());
        }
        signatures
    }

    /// Type what the code proves, for a function that carries no declared types.
    ///
    /// The solver is given every callee prototype, every certified access width
    /// and every SSA identity at once and run to a fixpoint; what comes back is
    /// only written where the fact it would replace is storage width rather than
    /// evidence, so a recovered type never overwrites a declared one and a value
    /// the solver did not reach keeps whatever it had.
    pub fn apply_recovered_evidence_types(
        &mut self,
        source: &r2ssa::SsaArtifact,
        ptr_bits: u32,
    ) -> crate::EvidenceTypes {
        let signatures = self.callsite_signatures();
        let recovered = crate::evidence::solve_evidence_types(source, &signatures, ptr_bits);
        if !recovered.is_empty() {
            self.apply_recovered_parameter_types(source, &recovered, ptr_bits);
            self.apply_recovered_stack_slot_types(&recovered, ptr_bits);
        }
        recovered
    }

    /// The type of each exact source parameter value the solver reached.
    ///
    /// Boundary facts own the slot-to-`ValueId` mapping. A missing or
    /// contradictory solution leaves just that parameter unchanged, while a
    /// pointer or operation-proven scalar signedness may replace the weak
    /// machine-width declaration inferred for the same slot.
    fn apply_recovered_parameter_types(
        &mut self,
        source: &r2ssa::SsaArtifact,
        recovered: &crate::EvidenceTypes,
        ptr_bits: u32,
    ) {
        let type_db = &self.types.external_type_db;
        let Some(signature) = self.types.merged_signature.as_mut() else {
            return;
        };
        let mut changed = false;
        for (slot, parameter) in &source.facts().boundaries.parameters {
            if parameter.index != *slot {
                continue;
            }
            let Ok(index) = usize::try_from(*slot) else {
                continue;
            };
            let Some(candidate) = recovered.value_type(parameter.value) else {
                continue;
            };
            let Some(param) = signature.params.get_mut(index) else {
                continue;
            };
            let replace = match param.ty.as_ref() {
                None => true,
                Some(existing) => {
                    recovered_type_outranks(existing, candidate, ptr_bits, type_db)
                        || recovered_scalar_signedness_outranks(existing, candidate, ptr_bits)
                }
            };
            if replace {
                param.ty = Some(candidate.clone());
                changed = true;
            }
        }
        if changed {
            self.types
                .certify_current_signature_with_source(SignatureCertificateSource::LocalInference);
        }
    }

    /// The type of each stack home the solver reached.
    fn apply_recovered_stack_slot_types(
        &mut self,
        recovered: &crate::EvidenceTypes,
        ptr_bits: u32,
    ) {
        let type_db = &self.types.external_type_db;
        let mut retyped: Vec<(String, CTypeLike)> = Vec::new();
        for (key, ty) in recovered.stack_slot_types() {
            let Some(slot) = self.types.stack_slots.get_mut(key) else {
                continue;
            };
            let replace = match slot.ty.as_ref() {
                None => true,
                Some(existing) => {
                    recovered_type_outranks(existing, ty, ptr_bits, type_db)
                        || recovered_scalar_signedness_outranks(existing, ty, ptr_bits)
                }
            };
            if !replace {
                continue;
            }
            slot.ty = Some(ty.clone());
            retyped.push((slot.name.clone(), ty.clone()));
        }
        if retyped.is_empty() {
            return;
        }
        for (name, ty) in retyped {
            for binding in self
                .types
                .visible_bindings
                .iter_mut()
                .filter(|binding| binding.name == name)
            {
                let replace = match binding.ty.as_ref() {
                    None => true,
                    Some(existing) => {
                        recovered_type_outranks(existing, &ty, ptr_bits, type_db)
                            || recovered_scalar_signedness_outranks(existing, &ty, ptr_bits)
                    }
                };
                if replace {
                    binding.ty = Some(ty.clone());
                }
            }
        }
    }

    pub fn interproc_summary_set(&self) -> Option<&r2ssa::InterprocSummarySet> {
        self.interproc_summary
            .as_ref()
            .map(r2ssa::PreparedInterprocSummarySet::report)
    }

    /// Borrow the advisory report used by pure projection and rendering.
    ///
    /// Unlike [`Self::prepared_interproc_summary`], this report does not prove
    /// ownership of the prepared SSA source and must not authorize mutation or
    /// certification.
    pub fn interproc_summary_report(&self) -> Option<&r2ssa::InterprocSummarySet> {
        self.interproc_summary
            .as_ref()
            .map(r2ssa::PreparedInterprocSummarySet::report)
            .or_else(|| self.summary_view.as_set())
    }

    pub fn prepared_interproc_summary(&self) -> Option<&r2ssa::PreparedInterprocSummarySet> {
        self.interproc_summary.as_ref()
    }
}

#[cfg(test)]
mod bitvector_width_tests {
    use super::*;

    #[test]
    fn a_bitvector_is_as_wide_as_it_says() {
        // The width was read only above what C's integers reach, so a
        // ninety-six-bit object -- which is why the spelling exists, C having
        // no such integer -- was named `BitVector(96)` by the rule that
        // declares a stack object and had no width at all to the seal that
        // checks the declaration against the object.
        for bits in [96, 128, 256] {
            assert_eq!(
                declaration_type_width_bits(&CTypeLike::BitVector(bits), 32),
                Some(bits)
            );
        }
    }
}
