//! Authority-bound observations of the legacy renderer's final AST decisions.
//!
//! This module owns the only production allocator for render observation IDs.
//! Callers mark exact occurrences, run every AST rewrite, then seal the dense
//! source V/U/W snapshot from the final wrapped nodes.

mod recording;
mod sealing;
#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use r2ssa::{
    InstId, MachineUseDisposition, MachineWriteDisposition, SemanticObligationId, SsaArtifact,
    SsaArtifactAuthority, UseSite, ValueId,
};
use r2types::SourceOwnedFunctionFacts;

#[cfg(test)]
use crate::ast::inspect_and_strip_render_observations;
use crate::ast::{
    BinaryOp, CExpr, CFunction, CStmt, RenderObservationInspectError, RenderObservationNode,
    RenderObservationStripError, inspect_render_observations,
};
use crate::binding_plan::{
    BindingNameResolution, BindingPlan, BindingPlanSourceMismatch, StackObjectDisposition,
    ValueDisposition,
};
use crate::codegen::{EmissionReadyFunction, prepare_function_for_emission};
use crate::normalize::{
    NormalizationOriginError, NormalizationOrigins, NormalizedOpOrigin, NormalizedOpProjection,
    NormalizedOpSite,
};
use crate::shadow_report::{
    GapAnchor, LegacyAnalysisSnapshot, LegacyBindingId, LegacyUseCell, LegacyUseObservation,
    LegacyValueCell, LegacyValueObservation, LegacyWriteCell, LegacyWriteObservation,
};
use crate::symbol::{SymbolId, SymbolTable};
use crate::{
    BindingMachineProjectionFailure, BindingObservationJournalFailure, BindingShadowAuditFailure,
};

/// Opaque dense identity of one exact marked AST occurrence.
///
/// It is deliberately neither serializable nor deserializable. Production
/// construction is private to [`LegacyObservationJournal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RenderObservationId(u32);

impl RenderObservationId {
    pub(crate) const fn index(self) -> u32 {
        self.0
    }

    pub(crate) fn from_dense_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("validated observation domain fits u32"))
    }

    #[cfg(test)]
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }
}

/// Capability required to expose a marked emission tree for journal sealing.
/// Its constructor is private to this module, so no other lowering or codegen
/// caller can bypass the marked-draft boundary.
pub(crate) struct ObservationSealAuthority(());

impl ObservationSealAuthority {
    fn new() -> Self {
        Self(())
    }
}

#[cfg(test)]
pub(crate) const fn test_render_observation_id(index: u32) -> RenderObservationId {
    RenderObservationId::from_index(index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationTarget {
    Value(ValueId),
    CertifiedValueRead {
        value: ValueId,
        source: crate::binding_plan::CertifiedValueReadSource,
        binding: crate::binding_plan::BindingId,
        symbol: SymbolId,
    },
    CertifiedArrayIndexRead {
        access: r2ssa::StructuredAccessId,
        value: ValueId,
        binding: crate::binding_plan::BindingId,
        symbol: SymbolId,
    },
    Use {
        site: UseSite,
        observation: LegacyUseObservation,
        /// Where the normalized operation consuming this use is emitted.
        block: u64,
    },
    Write {
        inst: InstId,
        observation: LegacyWriteObservation,
        /// Where the normalized definition is emitted, which is not the
        /// original instruction's block when normalization materialized it.
        block: u64,
    },
    StackAccess {
        access: r2ssa::StructuredAccessId,
        object: r2ssa::ObjectId,
        binding: crate::binding_plan::BindingId,
        symbol: SymbolId,
        is_write: bool,
        /// The block the statement spelling this access is emitted in, when
        /// that is not the access instruction's own block. A read spelled at
        /// the operation that uses it lands with that operation, and placement
        /// dominates over where the text is.
        rendered_block: Option<u64>,
    },
    /// One spelled occurrence of a frame object's base address, inside the
    /// rendering of `value`. It tells placement that the object's declaration
    /// must dominate this statement and that its storage is its definition.
    ObjectAddress {
        value: ValueId,
        object: r2ssa::ObjectId,
        binding: crate::binding_plan::BindingId,
        symbol: SymbolId,
        /// Where the statement spelling the address is emitted.
        block: u64,
    },
    /// One cell a marked gap accounts for.
    ///
    /// The gap statement carries one of these per cell in its closure, so a
    /// gapped cell is a typed observation rather than an empty slot. That
    /// distinction is what lets the seal keep refusing a statement that was
    /// silently dropped while admitting one the output says is missing.
    Gapped {
        anchor: GapAnchor,
        cell: GapCell,
    },
    /// One exact cell from the source-owned semantic obligation inventory.
    ///
    /// Unlike the legacy fold-side proof vector, this target belongs to one
    /// concrete AST occurrence. If a later rewrite deletes that occurrence,
    /// the final inspection never visits this target and therefore cannot
    /// count the obligation as rendered.
    Effect(SemanticObligationId),
}

/// One cell covered by a marked gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GapCell {
    Value(ValueId),
    /// `block` is where the operation consuming the use would have been
    /// emitted, which placement needs to keep the definition it reads alive.
    Use {
        site: UseSite,
        block: u64,
    },
    Write(InstId),
    Effect(SemanticObligationId),
}

/// A statement the journal declined to mark, handed back as it came with the
/// reason. The caller keeps the statement without having copied it in case of
/// a refusal; boxed, because a statement is large and a refusal is rare.
pub(crate) type RefusedStmt = Box<(LegacyObservationJournalError, CStmt)>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LegacyObservationJournalError {
    SourceAuthority,
    BindingPlan(BindingPlanSourceMismatch),
    Normalization(NormalizationOriginError),
    TooManyObservations,
    InvalidValue(ValueId),
    InvalidCertifiedValueRead {
        value: ValueId,
        at: InstId,
    },
    InvalidUse(UseSite),
    InvalidWrite(InstId),
    InvalidEffectObligation(SemanticObligationId),
    OutputlessWrite(InstId),
    InvalidNormalizedSite(NormalizedOpSite),
    MissingNormalizedBlock(u64),
    MissingNormalizedSiteContext,
    InvalidNormalizedInput {
        site: NormalizedOpSite,
        input_idx: usize,
    },
    MissingNormalizedOutput(NormalizedOpSite),
    RefusedRenderedUse(UseSite),
    /// A rendered use of a value the specification's user operation `userop`
    /// produces, which the machine projection refused because the lift gave
    /// the operation no semantics.
    UnmodelledUserOperation {
        site: UseSite,
        userop: u32,
    },
    RefusedRenderedWrite(InstId),
    RenderedValueRequired {
        value: ValueId,
        cause: RenderedValueRequirementCause,
        disposition: Option<ValueDisposition>,
    },
    PlannedElidedValueRendered {
        value: ValueId,
        reason: crate::ledger::ElisionReason,
    },
    PlannedRefusedValueRendered {
        value: ValueId,
        reason: crate::binding_plan::ValueRefusal,
    },
    MissingPlannedValue(ValueId),
    InvalidPlannedInline {
        value: ValueId,
        term: r2rewrite::TermId,
    },
    ExactUseRequiresRenderedOccurrence(UseSite),
    ExactWriteRequiresRenderedOccurrence(InstId),
    SymbolTableMismatch,
    UnownedBindingSymbol {
        value: ValueId,
        symbol: SymbolId,
    },
    ConflictingValue(ValueId),
    ConflictingUse(UseSite),
    ConflictingWrite(InstId),
    Markers(RenderObservationStripError),
}

/// Exact precondition behind the historically overloaded
/// `RenderedValueRequired` refusal.
///
/// These sites deliberately remain one public refusal category: they all mean
/// that the native tree cannot account for one planned value.  The internal
/// cause names which producer/consumer contract failed so refusal tracing can
/// lead back to the owner rather than treating the shared label as one bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderedValueRequirementCause {
    CertifiedValueReadMissingSymbol,
    CertifiedAddressReadMissingSymbol,
    CertifiedReadDispositionNotBound,
    CertifiedReadExpressionMissingSymbol,
    UnobservedValueCellAtSeal,
    NonrenderedValueDisposition,
    PlannedValueNamesUnavailable,
    PlannedInputNamesUnavailable,
}

impl LegacyObservationJournalError {
    /// Build one rendered-value refusal and retain the predicate operands on
    /// the standard opt-in evidence channel.
    #[track_caller]
    pub(crate) fn rendered_value_required(
        value: ValueId,
        cause: RenderedValueRequirementCause,
        disposition: Option<&ValueDisposition>,
    ) -> Self {
        let disposition = disposition.cloned();
        let demanded_at = std::panic::Location::caller();
        r2il::refusal_evidence!(
            "rendered-value-required",
            "value={value:?} disposition={disposition:?} cause={cause:?} demanded_at={demanded_at}"
        );
        Self::RenderedValueRequired {
            value,
            cause,
            disposition,
        }
    }

    /// A rendered use the machine projection refused, keeping which user
    /// operation it was when the refusal is that one had no semantics.
    pub(crate) const fn refused_use(site: UseSite, refusal: r2ssa::MachineUseRefusal) -> Self {
        match refusal {
            r2ssa::MachineUseRefusal::UnmodelledUserOperation { userop } => {
                Self::UnmodelledUserOperation { site, userop }
            }
            _ => Self::RefusedRenderedUse(site),
        }
    }
}

impl From<crate::binding_plan::CertificateElidedCellsError> for LegacyObservationJournalError {
    fn from(error: crate::binding_plan::CertificateElidedCellsError) -> Self {
        use crate::binding_plan::CertificateElidedCellsError as Cells;
        match error {
            Cells::InvalidWrite(inst) => Self::InvalidWrite(inst),
            Cells::InvalidValue(value) => Self::InvalidValue(value),
            Cells::ConflictingUse(site) => Self::ConflictingUse(site),
            Cells::ConflictingWrite(inst) => Self::ConflictingWrite(inst),
        }
    }
}

impl From<&r2ssa::MachineBuildError> for BindingMachineProjectionFailure {
    fn from(error: &r2ssa::MachineBuildError) -> Self {
        use r2ssa::MachineBuildError as Error;
        match error {
            Error::UntrustedArtifactProvenance => Self::UntrustedArtifactProvenance,
            Error::IncompleteObligationInventory => Self::IncompleteObligationInventory,
            Error::MissingGraphValue(value) => Self::MissingGraphValue { value: *value },
            Error::MissingGraphBlock(block) => Self::MissingGraphBlock { block: *block },
            Error::DuplicateBlockAddress(address) => {
                Self::DuplicateBlockAddress { address: *address }
            }
            Error::TopologyMismatch => Self::TopologyMismatch,
            Error::MachineContextMismatch => Self::MachineContextMismatch,
            Error::MissingInstruction(inst) => Self::MissingInstruction { inst: *inst },
            Error::MissingInstructionDisposition(inst) => {
                Self::MissingInstructionDisposition { inst: *inst }
            }
            Error::MissingUseDisposition(site) => Self::MissingUseDisposition { site: *site },
            Error::MissingWriteDisposition(inst) => Self::MissingWriteDisposition { inst: *inst },
            Error::MissingOutput(inst) => Self::MissingOutput { inst: *inst },
            Error::InvalidValueWidth { value, size_bytes } => Self::InvalidValueWidth {
                value: *value,
                size_bytes: *size_bytes,
            },
            Error::ConstantTooWide { value, width_bits } => Self::ConstantTooWide {
                value: *value,
                width_bits: *width_bits,
            },
            Error::WrongOperandCount {
                inst,
                expected,
                actual,
            } => Self::WrongOperandCount {
                inst: *inst,
                expected: *expected,
                actual: *actual,
            },
            Error::WidthMismatch {
                inst,
                expected_bits,
                actual_bits,
            } => Self::WidthMismatch {
                inst: *inst,
                expected_bits: *expected_bits,
                actual_bits: *actual_bits,
            },
            Error::InvalidCastWidth {
                inst,
                kind,
                from_bits,
                to_bits,
            } => Self::InvalidCastWidth {
                inst: *inst,
                kind: *kind,
                from_bits: *from_bits,
                to_bits: *to_bits,
            },
            Error::InvalidSubpiece {
                inst,
                source_bits,
                result_bits,
                lsb_bits,
            } => Self::InvalidSubpiece {
                inst: *inst,
                source_bits: *source_bits,
                result_bits: *result_bits,
                lsb_bits: *lsb_bits,
            },
            Error::InvalidChild { expr, child } => Self::InvalidChild {
                expr_index: expr.index(),
                child_index: child.index(),
            },
            Error::InvalidExpressionType { expr } => Self::InvalidExpressionType {
                expr_index: expr.index(),
            },
            Error::DuplicateEntity(value) => Self::DuplicateEntity { value: *value },
            Error::EntityMismatch(inst) => Self::EntityMismatch { inst: *inst },
            Error::ObligationMismatch(inst) => Self::ObligationMismatch { inst: *inst },
            Error::UseDispositionMismatch(site) => Self::UseDispositionMismatch { site: *site },
            Error::WriteDispositionMismatch(inst) => Self::WriteDispositionMismatch { inst: *inst },
            Error::ObligationSourceMismatch(instruction) => Self::ObligationSourceMismatch {
                instruction: *instruction,
            },
            Error::UnsupportedOperation { inst, .. } => Self::UnsupportedOperation { inst: *inst },
        }
    }
}

fn binding_plan_failure(error: &BindingPlanSourceMismatch) -> BindingObservationJournalFailure {
    match error {
        BindingPlanSourceMismatch::Authority => {
            BindingObservationJournalFailure::BindingPlanAuthority
        }
        BindingPlanSourceMismatch::MachineProjection(error) => {
            BindingObservationJournalFailure::BindingPlanMachineProjection(error.into())
        }
        BindingPlanSourceMismatch::ValueTopology { index, value } => {
            BindingObservationJournalFailure::BindingPlanValueTopology {
                index: *index,
                value: *value,
            }
        }
        BindingPlanSourceMismatch::DispositionCount { expected, actual } => {
            BindingObservationJournalFailure::BindingPlanDispositionCount {
                expected: *expected,
                actual: *actual,
            }
        }
        BindingPlanSourceMismatch::BindingCount { expected, actual } => {
            BindingObservationJournalFailure::BindingPlanBindingCount {
                expected: *expected,
                actual: *actual,
            }
        }
        BindingPlanSourceMismatch::InvalidBindingReference { value, binding } => {
            BindingObservationJournalFailure::BindingPlanInvalidBindingReference {
                value: *value,
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::CertificateMembership { binding } => {
            BindingObservationJournalFailure::BindingPlanCertificateMembership {
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::DeclarationWidth { binding } => {
            BindingObservationJournalFailure::BindingPlanDeclarationWidth {
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::InvalidLiteralInline { value } => {
            BindingObservationJournalFailure::BindingPlanInvalidLiteralInline { value: *value }
        }
        BindingPlanSourceMismatch::InvalidElisionProof { value } => {
            BindingObservationJournalFailure::BindingPlanInvalidElisionProof { value: *value }
        }
        BindingPlanSourceMismatch::UnexpectedValueDisposition { value } => {
            BindingObservationJournalFailure::BindingPlanUnexpectedValueDisposition {
                value: *value,
            }
        }
        BindingPlanSourceMismatch::StackObjectCount { expected, actual } => {
            BindingObservationJournalFailure::BindingPlanStackObjectCount {
                expected: *expected,
                actual: *actual,
            }
        }
        BindingPlanSourceMismatch::UnexpectedStackObjectDisposition { object } => {
            BindingObservationJournalFailure::BindingPlanUnexpectedStackObjectDisposition {
                object: *object,
            }
        }
        BindingPlanSourceMismatch::StackObjectCertificate { object, binding } => {
            BindingObservationJournalFailure::BindingPlanStackObjectCertificate {
                object: *object,
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::StackObjectDeclarationWidth { object, binding } => {
            BindingObservationJournalFailure::BindingPlanStackObjectDeclarationWidth {
                object: *object,
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::ParameterCount { expected, actual } => {
            BindingObservationJournalFailure::BindingPlanParameterCount {
                expected: *expected,
                actual: *actual,
            }
        }
        BindingPlanSourceMismatch::UnexpectedParameterDisposition { slot } => {
            BindingObservationJournalFailure::BindingPlanUnexpectedParameterDisposition {
                slot: *slot,
            }
        }
        BindingPlanSourceMismatch::ParameterCertificate { slot, binding } => {
            BindingObservationJournalFailure::BindingPlanParameterCertificate {
                slot: *slot,
                binding_index: binding.index(),
            }
        }
        BindingPlanSourceMismatch::ParameterDeclarationWidth { slot, binding } => {
            BindingObservationJournalFailure::BindingPlanParameterDeclarationWidth {
                slot: *slot,
                binding_index: binding.index(),
            }
        }
    }
}

fn normalization_failure(error: NormalizationOriginError) -> BindingObservationJournalFailure {
    match error {
        NormalizationOriginError::SourceAuthority => {
            BindingObservationJournalFailure::NormalizationSourceAuthority
        }
        NormalizationOriginError::BlockTopology => {
            BindingObservationJournalFailure::NormalizationBlockTopology
        }
        NormalizationOriginError::RowCount { block } => {
            BindingObservationJournalFailure::NormalizationRowCount {
                block_address: block,
            }
        }
        NormalizationOriginError::OriginalInstruction { block, op_idx } => {
            BindingObservationJournalFailure::NormalizationOriginalInstruction {
                block_address: block,
                op_idx,
            }
        }
        NormalizationOriginError::OriginalCoverage => {
            BindingObservationJournalFailure::NormalizationOriginalCoverage
        }
        NormalizationOriginError::PhiEdge { block, op_idx } => {
            BindingObservationJournalFailure::NormalizationPhiEdge {
                block_address: block,
                op_idx,
            }
        }
        NormalizationOriginError::RelocatedInitializer { block, op_idx } => {
            BindingObservationJournalFailure::NormalizationRelocatedInitializer {
                block_address: block,
                op_idx,
            }
        }
        NormalizationOriginError::RemovedPhi => {
            BindingObservationJournalFailure::NormalizationRemovedPhi
        }
        NormalizationOriginError::RemovedPhiEdge => {
            BindingObservationJournalFailure::NormalizationRemovedPhiEdge
        }
        NormalizationOriginError::InvalidCarrierCertificates => {
            BindingObservationJournalFailure::NormalizationInvalidCarrierCertificates
        }
    }
}

impl From<&LegacyObservationJournalError> for BindingObservationJournalFailure {
    fn from(error: &LegacyObservationJournalError) -> Self {
        match error {
            LegacyObservationJournalError::SourceAuthority => Self::SourceAuthority,
            LegacyObservationJournalError::BindingPlan(error) => binding_plan_failure(error),
            LegacyObservationJournalError::Normalization(error) => normalization_failure(*error),
            LegacyObservationJournalError::TooManyObservations => Self::TooManyObservations,
            LegacyObservationJournalError::InvalidValue(value) => {
                Self::InvalidValue { value: *value }
            }
            LegacyObservationJournalError::InvalidCertifiedValueRead { value, at } => {
                Self::InvalidCertifiedValueRead {
                    value: *value,
                    at: *at,
                }
            }
            LegacyObservationJournalError::InvalidUse(site) => Self::InvalidUse { site: *site },
            LegacyObservationJournalError::InvalidWrite(inst) => Self::InvalidWrite { inst: *inst },
            LegacyObservationJournalError::InvalidEffectObligation(obligation) => {
                Self::InvalidEffectObligation {
                    obligation: *obligation,
                }
            }
            LegacyObservationJournalError::OutputlessWrite(inst) => {
                Self::OutputlessWrite { inst: *inst }
            }
            LegacyObservationJournalError::InvalidNormalizedSite(site) => {
                Self::InvalidNormalizedSite {
                    block: site.block,
                    op_idx: site.op_idx,
                }
            }
            LegacyObservationJournalError::MissingNormalizedBlock(address) => {
                Self::MissingNormalizedBlock { address: *address }
            }
            LegacyObservationJournalError::MissingNormalizedSiteContext => {
                Self::MissingNormalizedSiteContext
            }
            LegacyObservationJournalError::InvalidNormalizedInput { site, input_idx } => {
                Self::InvalidNormalizedInput {
                    block: site.block,
                    op_idx: site.op_idx,
                    input_idx: *input_idx,
                }
            }
            LegacyObservationJournalError::MissingNormalizedOutput(site) => {
                Self::MissingNormalizedOutput {
                    block: site.block,
                    op_idx: site.op_idx,
                }
            }
            LegacyObservationJournalError::RefusedRenderedUse(site) => {
                Self::RefusedRenderedUse { site: *site }
            }
            LegacyObservationJournalError::UnmodelledUserOperation { site, userop } => {
                Self::UnmodelledUserOperation {
                    site: *site,
                    userop: *userop,
                }
            }
            LegacyObservationJournalError::RefusedRenderedWrite(inst) => {
                Self::RefusedRenderedWrite { inst: *inst }
            }
            LegacyObservationJournalError::RenderedValueRequired { value, .. } => {
                Self::RenderedValueRequired { value: *value }
            }
            LegacyObservationJournalError::PlannedElidedValueRendered { value, .. } => {
                Self::PlannedElidedValueRendered { value: *value }
            }
            LegacyObservationJournalError::PlannedRefusedValueRendered { value, .. } => {
                Self::PlannedRefusedValueRendered { value: *value }
            }
            LegacyObservationJournalError::MissingPlannedValue(value) => {
                Self::MissingPlannedValue { value: *value }
            }
            LegacyObservationJournalError::InvalidPlannedInline { value, term } => {
                Self::InvalidPlannedInline {
                    value: *value,
                    term_index: term.index(),
                }
            }
            LegacyObservationJournalError::ExactUseRequiresRenderedOccurrence(site) => {
                Self::ExactUseRequiresRenderedOccurrence { site: *site }
            }
            LegacyObservationJournalError::ExactWriteRequiresRenderedOccurrence(inst) => {
                Self::ExactWriteRequiresRenderedOccurrence { inst: *inst }
            }
            LegacyObservationJournalError::SymbolTableMismatch => Self::SymbolTableMismatch,
            LegacyObservationJournalError::UnownedBindingSymbol { value, symbol } => {
                Self::UnownedBindingSymbol {
                    value: *value,
                    symbol_index: symbol.index(),
                }
            }
            LegacyObservationJournalError::ConflictingValue(value) => {
                Self::ConflictingValue { value: *value }
            }
            LegacyObservationJournalError::ConflictingUse(site) => {
                Self::ConflictingUse { site: *site }
            }
            LegacyObservationJournalError::ConflictingWrite(inst) => {
                Self::ConflictingWrite { inst: *inst }
            }
            LegacyObservationJournalError::Markers(
                RenderObservationStripError::DomainTooLarge { expected_count },
            ) => Self::ObservationDomainTooLarge {
                expected_count: *expected_count,
            },
            LegacyObservationJournalError::Markers(
                RenderObservationStripError::CapacityUnavailable { expected_count },
            ) => Self::ObservationCapacityUnavailable {
                expected_count: *expected_count,
            },
            LegacyObservationJournalError::Markers(RenderObservationStripError::OutOfRange {
                id,
                expected_count,
            }) => Self::ObservationOutOfRange {
                observation_id: id.index(),
                expected_count: *expected_count,
            },
            LegacyObservationJournalError::Markers(RenderObservationStripError::Duplicate {
                id,
            }) => Self::DuplicateObservation {
                observation_id: id.index(),
            },
            LegacyObservationJournalError::Markers(
                RenderObservationStripError::NestedObservation { id },
            ) => Self::NestedObservation {
                observation_id: id.index(),
            },
        }
    }
}

/// Final coverage of one dense source domain after marker inspection.
///
/// The four disposition counts are deliberately disjoint. This lets an
/// external gate reconstruct the exact coverage equation instead of treating
/// refusal as a successful kind of "accounted" output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyObservationDomainCoverage {
    pub(crate) total: usize,
    pub(crate) rendered: usize,
    pub(crate) justified_elision: usize,
    pub(crate) refused: usize,
    /// Cells a marked gap accounts for. Disjoint from the other four: the
    /// renderer neither rendered them nor proved them unnecessary, and said
    /// so in the output.
    pub(crate) gapped: usize,
    pub(crate) unaccounted: usize,
}

impl LegacyObservationDomainCoverage {
    fn from_counts(
        total: usize,
        rendered: usize,
        justified_elision: usize,
        refused: usize,
        gapped: usize,
        unaccounted: usize,
    ) -> Self {
        Self {
            total,
            rendered,
            justified_elision,
            refused,
            gapped,
            unaccounted,
        }
    }

    pub(crate) fn equations_hold(self) -> bool {
        self.rendered
            .checked_add(self.justified_elision)
            .and_then(|count| count.checked_add(self.refused))
            .and_then(|count| count.checked_add(self.gapped))
            .and_then(|count| count.checked_add(self.unaccounted))
            == Some(self.total)
    }

    pub(crate) fn is_complete(self) -> bool {
        self.equations_hold() && self.unaccounted == 0
    }

    pub(crate) fn passes_quality(self) -> bool {
        self.is_complete() && self.refused == 0
    }
}

/// Dense V/U/W coverage sealed from the final marker-bearing emission tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyObservationCoverage {
    pub(crate) values: LegacyObservationDomainCoverage,
    pub(crate) uses: LegacyObservationDomainCoverage,
    pub(crate) writes: LegacyObservationDomainCoverage,
}

impl LegacyObservationCoverage {
    #[cfg(test)]
    pub(crate) fn equations_hold(self) -> bool {
        self.values.equations_hold() && self.uses.equations_hold() && self.writes.equations_hold()
    }

    pub(crate) fn is_complete(self) -> bool {
        self.values.is_complete() && self.uses.is_complete() && self.writes.is_complete()
    }

    pub(crate) fn passes_quality(self) -> bool {
        self.values.passes_quality() && self.uses.passes_quality() && self.writes.passes_quality()
    }
}

/// One dense legacy snapshot and the independently visible coverage that
/// produced it. Missing cells remain `LegacyAbsent` in the snapshot while the
/// coverage keeps them distinguishable from explicit final decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedLegacyObservations {
    snapshot: LegacyAnalysisSnapshot,
    coverage: LegacyObservationCoverage,
    effects: SurvivingEffectObservations,
}

impl SealedLegacyObservations {
    pub(crate) const fn snapshot(&self) -> &LegacyAnalysisSnapshot {
        &self.snapshot
    }

    pub(crate) const fn coverage(&self) -> LegacyObservationCoverage {
        self.coverage
    }

    pub(crate) const fn effects(&self) -> &SurvivingEffectObservations {
        &self.effects
    }
}

/// Final occurrence counts for the canonical source obligation domain.
///
/// The map is opened from the source inventory before lowering. A zero count
/// therefore means that no marker for that exact source cell survived the
/// finished AST; it never means that the source cell was omitted from the
/// accounting domain. Counts remain visible so duplicated render occurrences
/// cannot collapse into a misleading boolean "rendered" answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SurvivingEffectObservations {
    occurrences: BTreeMap<SemanticObligationId, EffectOccurrences>,
    coalesced_carriers: Box<CoalescedCarrierEffectElisions>,
    gapped: BTreeSet<SemanticObligationId>,
    rewrite_elided: BTreeSet<SemanticObligationId>,
}

/// How often one source obligation was rendered, and whether the copies stand
/// on paths that exclude one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EffectOccurrences {
    count: usize,
    exclusive: bool,
    /// The obligation belongs to a value the plan spells as a literal at every
    /// reader, so a count above one is one execution spelled several times.
    repeated_literal: bool,
    /// The obligation belongs to an address computation every reader spells by
    /// naming the object it addressed, which performs nothing, so a count above
    /// one is how many accesses named it rather than how many ran.
    named_object_address: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoalescedCarrierEffectElisions {
    coalesced_store_sites: BTreeSet<(u64, usize)>,
    coalesced_carrier_uses: BTreeSet<UseSite>,
    coalesced_carrier_phis: BTreeSet<InstId>,
    coalesced_copies: BTreeSet<InstId>,
    placement_elided_effects: BTreeSet<SemanticObligationId>,
    dead_unused_value_effects: BTreeSet<SemanticObligationId>,
}

impl SurvivingEffectObservations {
    /// Whether a marked gap in the output accounts for this obligation.
    ///
    /// Asked before any zero-occurrence elision rule, because a gapped
    /// obligation has no occurrence for exactly the reason the gap states,
    /// and calling that an elision would claim it was proven unnecessary.
    pub(crate) fn gapped_effect(&self, id: SemanticObligationId) -> bool {
        self.gapped.contains(&id)
    }

    pub(crate) fn occurrence_count(&self, id: SemanticObligationId) -> Option<usize> {
        self.occurrences
            .get(&id)
            .map(|occurrences| occurrences.count)
    }

    /// Whether every rendered occurrence of this obligation excludes every
    /// other, which is what makes more than one of them still one execution.
    pub(crate) fn duplicates_are_exclusive(&self, id: SemanticObligationId) -> bool {
        self.occurrences
            .get(&id)
            .is_some_and(|occurrences| occurrences.exclusive)
    }

    /// Whether the obligation's value is a frame constant the plan spells at
    /// each reader, which is the other way several occurrences are one
    /// execution.
    ///
    /// The machine writes the temporary once. A reader that spells `5` or
    /// `&slot` instead of naming it performs nothing, so three readers are
    /// three spellings of one execution rather than three executions. This
    /// holds only because the value reads nothing: an expression repeated at
    /// three readers would be three evaluations and is not admitted here.
    pub(crate) fn duplicates_are_a_repeated_literal(&self, id: SemanticObligationId) -> bool {
        self.occurrences
            .get(&id)
            .is_some_and(|occurrences| occurrences.repeated_literal)
    }

    pub(crate) fn duplicates_are_a_named_object_address(&self, id: SemanticObligationId) -> bool {
        self.occurrences
            .get(&id)
            .is_some_and(|occurrences| occurrences.named_object_address)
    }

    pub(crate) fn is_coalesced_carrier_use(&self, site: UseSite) -> bool {
        self.coalesced_carriers
            .coalesced_carrier_uses
            .contains(&site)
    }

    pub(crate) fn is_coalesced_carrier_phi(&self, inst: InstId) -> bool {
        self.coalesced_carriers
            .coalesced_carrier_phis
            .contains(&inst)
    }

    /// Whether this instruction is a copy elided for saying nothing.
    pub(crate) fn is_coalesced_copy(&self, inst: InstId) -> bool {
        self.coalesced_carriers.coalesced_copies.contains(&inst)
    }

    /// Whether a store into an object already holding the value owned this obligation.
    pub(crate) fn coalesced_store_effect(&self, id: SemanticObligationId) -> bool {
        matches!(id.instruction.site, r2ssa::CanonicalInstructionSite::Op(op_index)
            if usize::try_from(op_index).is_ok_and(|op_index| self
                .coalesced_carriers
                .coalesced_store_sites
                .contains(&(id.instruction.block_addr, op_index))))
    }

    /// Whether placement removed the statement carrying this obligation.
    pub(crate) fn placement_removed_effect(&self, id: SemanticObligationId) -> bool {
        self.coalesced_carriers
            .placement_elided_effects
            .contains(&id)
    }

    /// Whether a control rewrite took this obligation's statement out of the
    /// text and said why.
    pub(crate) fn rewrite_elided_effect(&self, id: SemanticObligationId) -> bool {
        self.rewrite_elided.contains(&id)
    }

    /// Whether a pre-placement dead definition owned this producer obligation.
    pub(crate) fn dead_unused_value_effect(&self, id: SemanticObligationId) -> bool {
        self.coalesced_carriers
            .dead_unused_value_effects
            .contains(&id)
    }

    #[cfg(test)]
    pub(crate) fn surviving(&self) -> impl Iterator<Item = (SemanticObligationId, usize)> + '_ {
        self.occurrences.iter().filter_map(|(id, occurrences)| {
            (occurrences.count > 0).then_some((*id, occurrences.count))
        })
    }
}

/// Sealed, source-authority-bound recorder for one legacy rendering run.
pub(crate) struct LegacyObservationJournal {
    authority: SsaArtifactAuthority,
    source: std::sync::Arc<SsaArtifact>,
    plan: Rc<BindingPlan>,
    names: Rc<BindingNameResolution>,
    normalized_projections: Vec<Box<[NormalizedOpProjection]>>,
    /// Synthetic carrier copies whose exact incoming use is discharged by
    /// binding coalescing. Lowering queries this same derived answer before it
    /// suppresses the `x = x` operation.
    coalesced_carrier_copy_sites: BTreeSet<NormalizedOpSite>,
    /// Stores into an object that already holds the value, by block address and op index.
    coalesced_store_sites: BTreeSet<(u64, usize)>,
    coalesced_carrier_uses: BTreeSet<UseSite>,
    /// Bindings whose every read is a return or a merge of the binding itself.
    return_only_carriers: BTreeSet<crate::binding_plan::BindingId>,
    /// Phi inputs a relocated initializer supersedes: reads no text spells.
    superseded_phi_edges: BTreeSet<UseSite>,
    /// Removed carrier phis for which every incoming edge is already accounted
    /// by SSA identity or one of `coalesced_carrier_copy_sites`.
    coalesced_carrier_phi_writes: BTreeSet<InstId>,
    /// Program copies this journal elides, by instruction.
    ///
    /// Their write is elided with them, for the same reason: the object was
    /// already written by the statement that produced the value copied.
    coalesced_copy_writes: BTreeSet<InstId>,
    /// Values defined by a program copy this journal elides.
    ///
    /// The copy said nothing because its two sides are one object, so the
    /// object's own rendering answers for the value the copy defined. Kept so
    /// the seal can say that rather than look for an occurrence the elided
    /// statement would have carried.
    coalesced_copy_outputs: BTreeSet<ValueId>,
    /// Merges normalization removed by materializing every incoming edge, so
    /// the copies on those edges are what write them.
    materialized_removed_phis: BTreeSet<InstId>,
    /// Definitions placement dropped because nothing reads what they produce.
    placement_elided_writes: BTreeSet<InstId>,
    /// Observations that went with the statements placement discarded.
    ///
    /// Named exactly, never inferred from what is unaccounted: the seal refuses
    /// a function whose cells are empty, and filling in whatever is empty would
    /// answer that check instead of answering to it.
    placement_elided_observations: BTreeSet<crate::ast::RenderObservationId>,
    /// Obligations whose only occurrence placement removed with the statement
    /// that carried it.
    placement_elided_effects: BTreeSet<SemanticObligationId>,
    /// Producer obligations owned by definitions the binding plan proved had
    /// no graph or certified-boundary reader before lowering began.
    dead_unused_value_effects: BTreeSet<SemanticObligationId>,
    symbols: Rc<RefCell<SymbolTable>>,
    value_is_literal: Box<[bool]>,
    values: Box<[Option<LegacyValueObservation>]>,
    uses: Box<[Box<[Option<LegacyUseObservation>]>]>,
    write_has_output: Box<[bool]>,
    writes: Box<[Option<LegacyWriteObservation>]>,
    effect_occurrences: BTreeMap<SemanticObligationId, usize>,
    /// Where the sealing walk found each effect obligation rendered: one scope
    /// per occurrence, so two occurrences in one place stay two.
    effect_occurrence_regions:
        BTreeMap<SemanticObligationId, Vec<crate::placement::ObservationScope>>,
    /// Obligations whose duplicate occurrences the region tree proved to
    /// exclude one another.
    exclusive_duplicate_effects: BTreeSet<SemanticObligationId>,
    /// Obligations a marked gap accounts for.
    ///
    /// Kept apart from `effect_occurrences` on purpose: a gap is not an
    /// occurrence, so a shared tail cloned onto two paths cannot turn one
    /// gapped obligation into a duplicate rendering.
    gapped_effects: BTreeSet<SemanticObligationId>,
    /// Cells a control rewrite took out of the text, with its stated reason.
    rewrite_elisions: RewriteElisions,
    /// Values a marked gap accounts for, so a read the gap also covers is
    /// known to name an object no statement outside the gap assigns.
    gapped_values: BTreeSet<ValueId>,
    targets: Vec<ObservationTarget>,
    /// Where each target was allocated, under `R2DEC_TRACE_REFUSAL` only.
    target_origins: Vec<&'static std::panic::Location<'static>>,
}

/// Cells a control rewrite removed from the text, with the reason it removed
/// them.
///
/// A rewrite that takes a statement out of the tree owes an answer for the
/// cells that statement carried. Reporting them is that answer, and it is the
/// rewrite's to give: it is the only thing that knows why the statement is
/// gone. The journal records the elision and the ledger reads it, exactly as it
/// reads the certificates' elisions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RewriteElisions {
    pub(crate) cells: Vec<(RenderObservationId, crate::ledger::ElisionReason)>,
}

/// Transaction boundary for render markers allocated by one tentative AST
/// route. The source V/U/W domains are immutable after journal construction;
/// only the dense target tail changes while lowering candidate trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObservationJournalCheckpoint {
    target_len: usize,
}

pub(crate) enum LegacyObservationSeal {
    Complete(SealedLegacyObservations),
    BindingFailure(LegacyObservationJournalError),
}

/// Internal ownership boundary for an AST that may still contain markers.
///
/// There is deliberately no function accessor. A marked tree can become
/// visible to another decompiler module only by sealing it, which first runs
/// emission preparation and then strips every marker transactionally.
pub(crate) struct MarkedNativeDraft {
    function: CFunction,
    journal: LegacyObservationJournal,
    placement: Option<NativePlacementInput>,
}

struct NativePlacementInput {
    regions: crate::structured_region::SealedStructuredRegionArtifact,
    names: Rc<crate::binding_plan::BindingNameResolution>,
}

#[derive(Debug)]
enum NativePlacementFailure {
    MissingStructuredRegionArtifact,
    Analysis(crate::placement::PlacementAnalysisError),
    Application(crate::placement::PlacementApplicationError),
    MissingBindingRole {
        binding: crate::binding_plan::BindingId,
    },
    UndeclaredNames {
        count: usize,
    },
    RegionFinalization(crate::structured_region::StructuredRegionFinalizationError),
}

fn region_marker_refusal(
    error: crate::structured_region::StructuredRegionFinalizationError,
) -> crate::PlacementAuditRefusal {
    use crate::PlacementAuditRefusal as Refusal;
    use crate::structured_region::StructuredRegionFinalizationError as Error;

    match error {
        Error::UnsealedMarker => Refusal::RegionMarkerUnsealed,
        Error::ForeignMarker { anchor } => Refusal::RegionMarkerForeign {
            anchor_index: anchor.index(),
        },
        Error::DuplicateMarker { region } => Refusal::RegionMarkerDuplicate {
            region_index: region.index(),
        },
        Error::MissingMarker { region } => Refusal::RegionMarkerMissing {
            region_index: region.index(),
        },
        Error::ParentMismatch { region } => Refusal::RegionMarkerParentMismatch {
            region_index: region.index(),
        },
        Error::OutOfOrder { region, expected } => Refusal::RegionMarkerOutOfOrder {
            region_index: region.index(),
            expected_region_index: expected.index(),
        },
    }
}

fn observation_marker_refusal(
    error: crate::ast::RenderObservationStripError,
) -> crate::PlacementAuditRefusal {
    use crate::PlacementAuditRefusal as Refusal;
    use crate::ast::RenderObservationStripError as Error;

    match error {
        Error::DomainTooLarge { expected_count } => {
            Refusal::ObservationDomainTooLarge { expected_count }
        }
        Error::CapacityUnavailable { expected_count } => {
            Refusal::ObservationCapacityUnavailable { expected_count }
        }
        Error::OutOfRange { id, expected_count } => Refusal::ObservationOutOfRange {
            observation_id: id.index(),
            expected_count,
        },
        Error::Duplicate { id } => Refusal::DuplicateObservation {
            observation_id: id.index(),
        },
        Error::NestedObservation { id } => Refusal::NestedObservation {
            observation_id: id.index(),
        },
    }
}

fn placement_refusal(
    refusal: crate::binding_plan::PlacementRefusal,
) -> crate::PlacementAuditRefusal {
    use crate::PlacementAuditRefusal as Public;
    use crate::binding_plan::PlacementRefusal as Private;

    match refusal {
        Private::NoDominatingRegion { binding } => Public::NoDominatingRegion {
            binding_index: binding.index(),
        },
        Private::MissingDefinition { binding } => Public::MissingDefinition {
            binding_index: binding.index(),
        },
        Private::ReadBeforeAssignment {
            binding,
            read: crate::binding_plan::PlacementRead::Use(site),
        } => Public::ReadBeforeAssignment {
            binding_index: binding.index(),
            instruction_id: site.inst.0,
            input_index: site.input_idx,
        },
        Private::ReadBeforeAssignment {
            binding,
            read: crate::binding_plan::PlacementRead::CertifiedValue { value, at },
        } => Public::CertifiedValueReadBeforeAssignment {
            binding_index: binding.index(),
            value_id: value.0,
            instruction_id: at.0,
        },
        Private::ReadBeforeAssignment {
            binding,
            read: crate::binding_plan::PlacementRead::ArrayIndex { access, value },
        } => Public::CertifiedValueReadBeforeAssignment {
            binding_index: binding.index(),
            value_id: value.0,
            instruction_id: access.inst.0,
        },
        Private::ReadBeforeAssignment {
            binding,
            read: crate::binding_plan::PlacementRead::ObjectAddress { value },
        } => Public::ObjectAddressReadBeforeAssignment {
            binding_index: binding.index(),
            value_id: value.0,
        },
        Private::ReadBeforeAssignment {
            binding,
            read:
                crate::binding_plan::PlacementRead::StackAccess(access)
                | crate::binding_plan::PlacementRead::IndexedStackAccess(access),
        } => Public::StackAccessReadBeforeAssignment {
            binding_index: binding.index(),
            instruction_id: access.inst.0,
            access_ordinal: access.ordinal,
        },
        Private::UnprovableExecutionOrder { binding } => Public::UnprovableExecutionOrder {
            binding_index: binding.index(),
        },
    }
}

fn placement_analysis_refusal(
    error: crate::placement::PlacementAnalysisError,
) -> crate::PlacementAuditRefusal {
    use crate::PlacementAuditRefusal as Refusal;
    use crate::placement::PlacementAnalysisError as Error;

    match error {
        Error::SourceAuthorityMismatch => Refusal::SourceAuthorityMismatch,
        Error::BindingOutsidePlan { binding } => Refusal::BindingOutsidePlan {
            binding_index: binding.index(),
        },
        Error::RegionOutsideArtifact { region } => Refusal::RegionOutsideArtifact {
            region_index: region.index(),
        },
        Error::BlockOutsideFunction { block } => Refusal::BlockOutsideFunction {
            block_address: block,
        },
        Error::RegionDoesNotDominateOccurrence { region, block } => {
            Refusal::RegionDoesNotDominateOccurrence {
                region_index: region.index(),
                block_address: block,
            }
        }
        Error::ExternalBindingOutsidePlan { binding } => Refusal::ExternalBindingOutsidePlan {
            binding_index: binding.index(),
        },
        Error::RegionMarkers(error) => region_marker_refusal(error),
        Error::ObservationMarkers(error) => observation_marker_refusal(error),
        Error::MissingObservationTarget { observation } => Refusal::MissingObservationTarget {
            observation_id: observation.index(),
        },
        Error::InvalidUse { site } => Refusal::InvalidUse {
            instruction_id: site.inst.0,
            input_index: site.input_idx,
        },
        Error::InvalidWrite { inst } => Refusal::InvalidWrite {
            instruction_id: inst.0,
        },
        Error::InvalidCertifiedValueRead { value, at } => Refusal::InvalidCertifiedValueRead {
            value_id: value.0,
            instruction_id: at.0,
        },
        Error::MissingPlannedValue { value } => Refusal::MissingPlannedValue { value_id: value.0 },
        Error::RefusedPlannedValue { value } => Refusal::RefusedPlannedValue { value_id: value.0 },
        Error::UnscopedObservation { observation } => Refusal::UnscopedObservation {
            observation_id: observation.index(),
        },
        Error::AmbiguousExecutionOrder { observation } => {
            Refusal::AmbiguousObservationExecutionOrder {
                observation_id: observation.index(),
            }
        }
        Error::UnauthorizedProgramVariable { symbol } => Refusal::UnauthorizedProgramVariable {
            symbol_index: symbol.index(),
        },
        Error::UnobservedBindingRead { binding } => Refusal::UnobservedBindingRead {
            binding_index: binding.index(),
        },
        Error::UnobservedBindingWrite { binding } => Refusal::UnobservedBindingWrite {
            binding_index: binding.index(),
        },
    }
}

fn placement_application_refusal(
    error: crate::placement::PlacementApplicationError,
) -> crate::PlacementAuditRefusal {
    use crate::PlacementAuditRefusal as Refusal;
    use crate::placement::PlacementApplicationError as Error;

    match error {
        Error::Refused(refusal) => placement_refusal(refusal),
        Error::MissingBinding { binding } => Refusal::MissingBinding {
            binding_index: binding.index(),
        },
        Error::MissingBindingSymbol { binding } => Refusal::MissingBindingSymbol {
            binding_index: binding.index(),
        },
        Error::ExternalBindingMissingParameter { binding } => {
            Refusal::ExternalBindingMissingParameter {
                binding_index: binding.index(),
            }
        }
        Error::MissingRegion { region } => Refusal::MissingRegion {
            region_index: region.index(),
        },
        Error::DuplicateRegion { region } => Refusal::DuplicateRegion {
            region_index: region.index(),
        },
        Error::MissingInlineWrite { inst } => Refusal::MissingInlineWrite {
            instruction_id: inst.0,
        },
        Error::DuplicateInlineWrite { inst } => Refusal::DuplicateInlineWrite {
            instruction_id: inst.0,
        },
    }
}

impl From<NativePlacementFailure> for crate::PlacementAuditRefusal {
    fn from(failure: NativePlacementFailure) -> Self {
        match failure {
            NativePlacementFailure::MissingStructuredRegionArtifact => {
                Self::MissingStructuredRegionArtifact
            }
            NativePlacementFailure::Analysis(error) => placement_analysis_refusal(error),
            NativePlacementFailure::Application(error) => placement_application_refusal(error),
            NativePlacementFailure::MissingBindingRole { binding } => Self::MissingBindingRole {
                binding_index: binding.index(),
            },
            NativePlacementFailure::UndeclaredNames { count } => Self::UndeclaredNames { count },
            NativePlacementFailure::RegionFinalization(error) => region_marker_refusal(error),
        }
    }
}

impl MarkedNativeDraft {
    #[cfg(test)]
    pub(crate) fn new(function: CFunction, journal: LegacyObservationJournal) -> Self {
        Self {
            function,
            journal,
            placement: None,
        }
    }

    pub(crate) fn new_with_placement(
        function: CFunction,
        journal: LegacyObservationJournal,
        regions: Option<crate::structured_region::SealedStructuredRegionArtifact>,
        names: Rc<crate::binding_plan::BindingNameResolution>,
    ) -> Self {
        Self {
            function,
            journal,
            placement: regions.map(|regions| NativePlacementInput { regions, names }),
        }
    }

    fn derive_and_apply_placement(
        &mut self,
        source: &SourceOwnedFunctionFacts,
    ) -> Result<(), NativePlacementFailure> {
        let Some(placement) = self.placement.as_ref() else {
            return Err(NativePlacementFailure::MissingStructuredRegionArtifact);
        };
        // The tree placement is about to judge, markers and all, for a reader
        // chasing a refusal that names one statement out of it.
        if let Some(path) = crate::debug::dump_ast_path() {
            let _ = std::fs::write(path, format!("{:#?}", self.function));
        }
        let occurrences = crate::placement::collect_final_placement_occurrences(
            &self.function,
            &placement.regions,
            source.source(),
            &placement.names,
            self.journal.placement_target_count(),
            |id| self.journal.placement_target(id),
        )
        .map_err(NativePlacementFailure::Analysis)?;
        let mut externally_declared = BTreeSet::new();
        let mut entry_declared = BTreeSet::new();
        for (binding, _) in placement.names.plan().bindings() {
            match placement.names.binding_is_externally_declared(binding) {
                Some(true) => {
                    externally_declared.insert(binding);
                }
                Some(false) => {}
                None => return Err(NativePlacementFailure::MissingBindingRole { binding }),
            }
            match placement.names.binding_is_entry_declared(binding) {
                Some(true) => {
                    entry_declared.insert(binding);
                }
                Some(false) => {}
                None => return Err(NativePlacementFailure::MissingBindingRole { binding }),
            }
        }
        entry_declared.extend(occurrences.escaped_stack_bindings().iter().copied());
        let decisions = crate::placement::derive_placement_decisions(
            &placement.regions,
            source.source().function(),
            placement.names.plan().binding_count(),
            &externally_declared,
            &entry_declared,
            occurrences.reads(),
            occurrences.writes(),
        )
        .map_err(NativePlacementFailure::Analysis)?;
        // A placement refusal names a binding by number, and the number is
        // never the question: which program object could not be placed, and
        // where it was mentioned, is. Both are in hand exactly here, and
        // nowhere downstream -- the refusal that reaches the reader carries
        // only its category. So the operands travel on the same diagnostic
        // channel every other refusing predicate uses.
        if r2il::refusal_evidence::tracing() {
            for (binding, decision) in decisions.iter() {
                let Some(crate::placement::PlacementDecision::Refused(reason)) = decision else {
                    continue;
                };
                let name = placement
                    .names
                    .symbol_for_binding(binding)
                    .map(|symbol| placement.names.spelling(symbol).to_string())
                    .unwrap_or_default();
                let reads = occurrences
                    .reads()
                    .iter()
                    .filter(|read| read.binding == binding)
                    .map(|read| (read.block, read.statement, read.source))
                    .collect::<Vec<_>>();
                let writes = occurrences
                    .writes()
                    .iter()
                    .filter(|write| write.binding == binding)
                    .map(|write| (write.block, write.statement, write.inst))
                    .collect::<Vec<_>>();
                // A binding with no rendered write is the common refusal, and
                // the question is always what the plan did with the values it
                // holds, which is knowable only here.
                let members = (0..source.source().graph().values.len())
                    .map(|index| r2ssa::ValueId(index as u32))
                    .filter(|value| {
                        matches!(
                            placement.names.plan().disposition(*value),
                            Some(crate::binding_plan::ValueDisposition::Bound {
                                binding: bound
                            }) if *bound == binding
                        )
                    })
                    .map(|value| (value, source.source().graph().def_inst(value)))
                    .collect::<Vec<_>>();
                // What the definitions observed, which tells a never-rendered
                // statement apart from one rendered and then removed.
                let defining_insts = members
                    .iter()
                    .filter_map(|(_, inst)| *inst)
                    .collect::<BTreeSet<_>>();
                let observations = (0..self.journal.placement_target_count())
                    .filter_map(|index| {
                        let id = RenderObservationId::from_dense_index(index);
                        let target = self.journal.placement_target(id)?;
                        let names_definition = crate::placement::placement_target_inst(&target)
                            .is_some_and(|inst| defining_insts.contains(&inst));
                        let names_binding =
                            crate::placement::placement_target_binding(&target) == Some(binding);
                        (names_definition || names_binding).then_some((index, target))
                    })
                    .collect::<Vec<_>>();
                r2il::refusal_evidence!(
                    "placement-decision",
                    "binding={binding:?} name={name} reason={reason:?} \
                     reads={reads:?} writes={writes:?} members={members:?} \
                     definition_observations={observations:?}"
                );
            }
        }
        // Which writes lost their statements is only known once the decisions
        // have been applied: one can be declined because the tree still
        // mentions the symbol, and one binding's removal can take away the last
        // reader of another. Asking afterwards is what keeps the obligations
        // these statements carried closed out against what was actually
        // emitted rather than against what was planned.
        let removals = crate::placement::apply_placement_decisions(
            &mut self.function,
            &placement.regions,
            &placement.names,
            &decisions,
            occurrences.writes(),
            &source.source().certificates().stack_slots,
        )
        .map_err(NativePlacementFailure::Application)?;
        self.journal
            .record_placement_removals(removals, occurrences.writes());
        let undeclared = crate::unrendered::names_mentioned_without_a_declaration(&self.function);
        if !undeclared.is_empty() {
            return Err(NativePlacementFailure::UndeclaredNames {
                count: undeclared.len(),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn seal(
        mut self,
        source: &SourceOwnedFunctionFacts,
    ) -> Result<SealedNativeFunction, LegacyObservationJournalError> {
        let mut ready = prepare_function_for_emission(std::mem::replace(
            &mut self.function,
            CFunction::new(String::new(), crate::ast::CType::Void),
        ));
        let plan = Rc::clone(&self.journal.plan);
        let observations = self.journal.seal(source, &mut ready)?;
        Ok(SealedNativeFunction {
            ready,
            observations: Some(observations),
            fallback_effects: None,
            ledger: None,
            placement_audit: crate::PlacementAudit::NotRun,
            observation_failure: None,
            plan,
        })
    }

    /// Seal the final native tree as a required render proof.
    ///
    /// A missing marker, conflicting observation, or journal failure rejects
    /// the native product. The caller may cross the typed residual boundary,
    /// but it cannot recover the marker-free executable tree from this draft.
    #[expect(
        clippy::result_large_err,
        reason = "the typed refusal retains the complete value/use/write ledger at the final audit boundary"
    )]
    pub(crate) fn finish_enforcing(
        mut self,
        source: &SourceOwnedFunctionFacts,
        recording_failure: Option<LegacyObservationJournalError>,
    ) -> Result<SealedNativeFunction, BindingShadowAuditFailure> {
        let placement_failure = self
            .derive_and_apply_placement(source)
            .err()
            .map(crate::PlacementAuditRefusal::from);
        crate::stage_timing::mark("placement");
        let mut ready = prepare_function_for_emission(std::mem::replace(
            &mut self.function,
            CFunction::new(String::new(), crate::ast::CType::Void),
        ));
        let plan = Rc::clone(&self.journal.plan);
        if let Some(error) = recording_failure {
            return Err(BindingShadowAuditFailure::JournalRecording(
                BindingObservationJournalFailure::from(&error),
            ));
        }
        // A placement that ran and refused is reported before the seal, because
        // it is the cause of the seal failure it produces rather than an
        // independent finding. When placement cannot declare a binding, the
        // seal then observes a rendered name that owns no declaration and
        // refuses with `UnownedBindingSymbol`, naming the symbol instead of the
        // phase that failed to declare it. Sealing first reported that symptom
        // and discarded the cause.
        //
        // A draft carrying no placement input at all is a different case: no
        // placement ran, so nothing links its absence to what the seal finds,
        // and the seal keeps precedence.
        if self.placement.is_some()
            && let Some(refusal) = placement_failure
        {
            return Err(BindingShadowAuditFailure::Placement(refusal));
        }
        let regions = self.placement.as_ref().map(|placement| &placement.regions);
        let observations = match self
            .journal
            .seal_preserving_effects(source, &mut ready, regions)
        {
            Ok(LegacyObservationSeal::Complete(observations)) => observations,
            Ok(LegacyObservationSeal::BindingFailure(error)) | Err(error) => {
                return Err(BindingShadowAuditFailure::JournalSeal(
                    BindingObservationJournalFailure::from(&error),
                ));
            }
        };
        if let Some(refusal) = placement_failure {
            return Err(BindingShadowAuditFailure::Placement(refusal));
        }
        if let Some(placement) = self.placement.as_ref() {
            ready
                .strip_structured_region_markers(&placement.regions)
                .map_err(|error| {
                    BindingShadowAuditFailure::Placement(crate::PlacementAuditRefusal::from(
                        NativePlacementFailure::RegionFinalization(error),
                    ))
                })?;
        }
        let coverage = observations.coverage();
        if !coverage.passes_quality() {
            return Err(BindingShadowAuditFailure::NonQualityObservations {
                observations: coverage.into(),
            });
        }
        Ok(SealedNativeFunction {
            ready,
            observations: Some(observations),
            fallback_effects: None,
            ledger: None,
            placement_audit: crate::PlacementAudit::Applied,
            observation_failure: None,
            plan,
        })
    }
}

/// Marker-free exact emission tree paired with the observations sealed from it.
pub(crate) struct SealedNativeFunction {
    ready: EmissionReadyFunction,
    observations: Option<SealedLegacyObservations>,
    /// Exact effect stream when the independent legacy V/U/W audit failed.
    /// A run owns effects here or inside `observations`, never in both.
    fallback_effects: Option<SurvivingEffectObservations>,
    ledger: Option<crate::ledger::ObligationLedger>,
    placement_audit: crate::PlacementAudit,
    observation_failure: Option<BindingShadowAuditFailure>,
    plan: Rc<BindingPlan>,
}

impl SealedNativeFunction {
    pub(crate) const fn emission(&self) -> &EmissionReadyFunction {
        &self.ready
    }

    #[cfg(test)]
    pub(crate) fn observations(&self) -> &LegacyAnalysisSnapshot {
        self.observations
            .as_ref()
            .map(SealedLegacyObservations::snapshot)
            .expect("strictly sealed native function must retain observations")
    }

    #[expect(
        clippy::result_large_err,
        reason = "audit consumers receive the complete typed failure ledger rather than a lossy summary"
    )]
    pub(crate) fn audit_observations(
        &self,
    ) -> Result<(&LegacyAnalysisSnapshot, LegacyObservationCoverage), BindingShadowAuditFailure>
    {
        self.observations
            .as_ref()
            .map(|observations| (observations.snapshot(), observations.coverage()))
            .ok_or_else(|| {
                self.observation_failure
                    .expect("missing observations retain a typed failure category")
            })
    }

    pub(crate) fn plan(&self) -> &BindingPlan {
        &self.plan
    }

    /// Declare the named types this rendering spells, and unspell the rest.
    ///
    /// A pointer to an undeclared tag is legal C; a pointer to an undeclared
    /// typedef name is not, and five `bzip2` renderings were exactly that --
    /// `UInt16 *`, `UChar *`, `BZFILE *`. A rendering that does not compile
    /// scores nothing at all, so a name it spells has to come with what it
    /// stands for, or stop being spelled.
    ///
    /// Both halves live here on purpose. Compilation destroys the name and the
    /// producer's type database keeps it, so the binding travels with the type
    /// graph: the capture resolved this spelling to this type while building
    /// the graph, which makes the declaration exact rather than inferred. But
    /// the graph is refused whole -- one unrepresentable return type and there
    /// are no bindings at all -- while the spelling reaches the page from
    /// radare2's signature either way. Whichever component decided what may be
    /// declared must therefore also decide what may be spelled, or the two
    /// answers drift and the rendering names something nothing defines.
    pub(crate) fn define_declared_typedefs(&mut self, prepared: &r2ssa::SsaArtifact) {
        self.resolve_names_that_are_tags();
        let graph = prepared
            .machine_context()
            .function_interface()
            .and_then(r2ssa::SourceFunctionInterface::type_graph);
        let mut spelled = Vec::new();
        self.ready
            .function_for_aggregate_definitions()
            .visit_types(&mut |ty| collect_named_types(ty, &mut spelled));
        // A named type carries what it stands for, so the declaration is
        // usually already in hand. The graph is asked only for a name that
        // reached the page carrying nothing -- a spelling radare2 supplied
        // that the parser could make no more of than an identifier.
        let mut targets = std::collections::BTreeMap::new();
        for (name, carried) in spelled {
            // A builtin already means itself: `typedef int8_t char;` is not C.
            if name_is_a_c_builtin_type(&name) {
                continue;
            }
            if targets.contains_key(&name) {
                continue;
            }
            let target = match carried {
                r2types::CTypeLike::Unknown => {
                    graph.and_then(|graph| named_type_target(graph, &name))
                }
                resolved => Some(resolved),
            };
            let Some(target) = target else {
                continue;
            };
            // A name that stands for itself declares nothing: `typedef uint64_t
            // uint64_t;` is the graph saying it knows the name and no more.
            if target.to_string() == name {
                continue;
            }
            // A name the C implementation defines has a spelling of its own,
            // and it is not a fixed-width one. `size_t` is `unsigned long`
            // wherever a long is the address width and `unsigned long long`
            // where it is not, and the two are distinct types however equal
            // their widths: `typedef uint64_t size_t;` made every declaration
            // of a library function taking one incompatible with the compiler's
            // own, and `snprintf` was rejected for it.
            targets.insert(name, target);
        }
        // A name has to stand before any name declared through it, so the
        // order is the dependency order and not the order they were met.
        let mut wanted = Vec::new();
        let mut placed = std::collections::BTreeSet::new();
        let address_bits = prepared
            .machine_context()
            .memory_model()
            .default_address_bits();
        for name in targets.keys() {
            place_typedef(name, &targets, &mut placed, &mut wanted, address_bits);
        }
        if r2il::refusal_evidence::tracing() {
            for entry in &wanted {
                r2il::refusal_evidence!(
                    "named-type",
                    "declare {} = {:?}",
                    entry.name,
                    entry.target
                );
            }
        }
        self.ready.set_typedef_definitions(wanted);
        self.report_names_nothing_declares(&targets);
    }

    /// A bare name this rendering spells as a tag elsewhere is that tag.
    ///
    /// radare2 spells a `struct parsedb_state *` parameter as `parsedb_state *`
    /// in some signatures and `struct parsedb_state *` in others, so one
    /// rendering declared `dbg_parse_warn(parsedb_state*, ...)` beside four
    /// prototypes using the keyword. C has separate namespaces for tags and
    /// typedef names, so the bare one named nothing and the translation unit
    /// contradicted itself.
    ///
    /// The evidence is the rendering's own other spellings, and the repair adds
    /// the keyword rather than removing the name -- nothing the capture knew is
    /// lost. A name no spelling here calls a tag is left alone, so this cannot
    /// turn a typedef into a struct.
    fn resolve_names_that_are_tags(&mut self) {
        let mut tags = std::collections::BTreeMap::new();
        self.ready
            .function_for_aggregate_definitions()
            .visit_types(&mut |ty| collect_tag_spellings(ty, &mut tags));
        if tags.is_empty() {
            return;
        }
        self.ready
            .function_mut_for_type_declarations()
            .visit_types_mut(&mut |ty| resolve_tag_spelling(ty, &tags));
    }

    /// Name every type this rendering spells that it could not declare.
    ///
    /// The invariant is that a name on the page is a name the rendering
    /// declares, and the two halves above establish it from the type's own
    /// target or from the graph's alias table. Where neither answers, the
    /// rendering will not compile and scores nothing, and the cause is
    /// upstream: radare2 knows what `Cell` means and the capture did not carry
    /// it this far.
    ///
    /// This reports rather than repairs, deliberately. An earlier version
    /// rewrote such a name out of the page, which made the translation unit
    /// build by destroying the one thing the function knew -- and the name was
    /// only undeclarable because a `double` in the signature had refused the
    /// whole type graph. Substituting for a missing fact hides the gap that
    /// produced it; naming the gap is what gets it closed.
    fn report_names_nothing_declares(
        &self,
        declared: &std::collections::BTreeMap<String, crate::ast::CType>,
    ) {
        if !r2il::refusal_evidence::tracing() {
            return;
        }
        let mut spelled = Vec::new();
        self.ready
            .function_for_aggregate_definitions()
            .visit_types(&mut |ty| collect_named_types(ty, &mut spelled));
        let mut reported = std::collections::BTreeSet::new();
        for (name, _) in spelled {
            if declared.contains_key(&name) || !reported.insert(name.clone()) {
                continue;
            }
            r2il::refusal_evidence!(
                "named-type",
                "{name} is spelled with nothing to declare it: no target on the type, no alias in the graph, and no tag of that name in this rendering"
            );
        }
    }

    /// Define the aggregates this rendering declares a value of.
    ///
    /// A pointer to an undefined tag is legal C and needs nothing; a value of
    /// one is not, and seventy-five renderings declared exactly that. The
    /// layout comes from the same type graph the declaration's type came from.
    pub(crate) fn define_declared_aggregates(&mut self, prepared: &r2ssa::SsaArtifact) {
        // The graph is what a *source* aggregate's layout comes from. A tag
        // this decompiler synthesised needs none, so its absence is not a
        // reason to skip the pass -- doing that left every `va_list` local
        // declared at a tag nothing defined.
        let graph = prepared
            .machine_context()
            .function_interface()
            .and_then(r2ssa::SourceFunctionInterface::type_graph);
        let function = self.ready.function_for_aggregate_definitions();
        // What the body calls on a wide carrier is defined above it, and each
        // helper names the carriers it takes, which are defined here too.
        let helpers = crate::bitvector::helpers_called(function);
        let mut wanted = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = std::iter::once(&function.ret_type)
            .chain(function.params.iter().map(|param| &param.ty))
            .chain(function.locals.iter().map(|local| &local.ty))
            .cloned()
            .collect::<Vec<_>>();
        // A local is a declaration statement in the body, not an entry in
        // `locals`, which production never fills.
        collect_declared_types(&function.body, &mut pending);
        while let Some(ty) = pending.pop() {
            // Every tag this rendering spells, not only the ones it holds by
            // value. A pointer to an undefined tag is legal C right up to the
            // first `p + n` or `p[i]`, and 82 `z_stream *` and 56
            // `struct gzFile_s *` renderings did exactly that -- the compiler
            // needs the element size and an incomplete type has none. A
            // definition the graph can lay out is more information at the cost
            // of text, and `aggregate_is_definable` already refuses the rest.
            let name = match &ty {
                crate::ast::CType::Struct(name) | crate::ast::CType::Union(name) => name.clone(),
                crate::ast::CType::Array(inner, _) | crate::ast::CType::Pointer(inner) => {
                    pending.push(inner.as_ref().clone());
                    continue;
                }
                // A value declared at a name is a value of what the name
                // stands for, so the tag behind it is one this rendering has
                // to define. The name carries its target, so this does not
                // depend on the declarations having been decided yet.
                crate::ast::CType::Typedef { ty, .. } => {
                    pending.push(ty.as_ref().clone());
                    continue;
                }
                // Storage this decompiler synthesised a tag for, because C has
                // no scalar of that width. Nothing outside the rendering can
                // define it, so the rendering does, as `crate::bitvector`
                // states the carrier: its whole bytes, which is exactly what
                // the tag claims and keeps it distinct from an integer, so no
                // arithmetic is emitted for it.
                crate::ast::CType::BitVector(bits) => {
                    if let Some(definition) = crate::bitvector::carrier_definition(*bits)
                        && seen.insert(definition.name.clone())
                    {
                        wanted.push(definition);
                    }
                    continue;
                }
                _ => continue,
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some((graph, layout)) = graph.and_then(|graph| {
                graph
                    .aggregates()
                    .iter()
                    .find(|aggregate| aggregate.name() == name)
                    .map(|layout| (graph, layout))
            }) else {
                continue;
            };
            let mut members = Vec::new();
            for member in layout.members() {
                let mut visiting = std::collections::BTreeSet::<u32>::new();
                let Some(member_ty) =
                    r2types::source_type_like(graph, member.type_id(), &mut visiting)
                else {
                    members.clear();
                    break;
                };
                // The graph names a member's element type and its extent
                // separately: `UChar b[8]` is an eight-byte member of a
                // one-byte type. Rebuilding the array is what makes the
                // definition the same size the capture measured.
                let width = r2types::declaration_type_width_bits(&member_ty, 64);
                let member_ty = match width {
                    Some(width) if u64::from(width) == member.size_bits() => member_ty,
                    Some(width)
                        if width > 0
                            && member.size_bits() % u64::from(width) == 0
                            && usize::try_from(member.size_bits() / u64::from(width)).is_ok() =>
                    {
                        crate::ast::CType::Array(
                            Box::new(member_ty),
                            usize::try_from(member.size_bits() / u64::from(width)).ok(),
                        )
                    }
                    _ => {
                        members.clear();
                        break;
                    }
                };
                pending.push(member_ty.clone());
                members.push((member_ty, member.name().to_string()));
            }
            if members.len() != layout.members().len() || members.is_empty() {
                continue;
            }
            // A definition whose members do not account for the size the
            // capture measured would recompile to a different object, which is
            // worse than leaving the tag undefined.
            let covered = layout
                .members()
                .iter()
                .map(|member| member.offset_bits() + member.size_bits())
                .max()
                .unwrap_or(0);
            if covered != layout.size_bits() {
                continue;
            }
            wanted.push(crate::ast::CAggregateDef {
                is_union: matches!(ty, crate::ast::CType::Union(_)),
                name,
                members,
            });
        }
        for bits in helpers.iter().flat_map(|helper| helper.carriers()) {
            if let Some(definition) = crate::bitvector::carrier_definition(bits)
                && seen.insert(definition.name.clone())
            {
                wanted.push(definition);
            }
        }
        if r2il::refusal_evidence::tracing() {
            for entry in &wanted {
                r2il::refusal_evidence!("declared-aggregate", "define {}", entry.name);
            }
        }
        self.ready.set_aggregate_definitions(wanted);
        self.ready.set_bitvector_helpers(helpers);
    }

    pub(crate) fn effect_observations(&self) -> &SurvivingEffectObservations {
        self.observations
            .as_ref()
            .map(SealedLegacyObservations::effects)
            .or(self.fallback_effects.as_ref())
            .expect("every native function retains the source effect domain")
    }

    /// Finalize native admission from the exact sealed effect stream.
    ///
    /// The public audit retains the tuple even when admission fails. Refused
    /// output is comment-only: keeping the executable body beside a refusal
    /// would still expose unproven semantics to ordinary decompile callers.
    pub(crate) fn finalize_effect_ledger(
        &mut self,
        ledger: &crate::ledger::ObligationLedger,
        radare2_variadic_format_counts: usize,
        radare2_prototypes: usize,
        radare2_local_names: usize,
        entry_supplied: &std::collections::BTreeMap<
            crate::symbol::SymbolId,
            crate::binding_plan::EntrySupply,
        >,
    ) {
        self.ledger = Some(ledger.clone());
        let audit = self.effect_obligation_audit();
        if !audit.is_admitted() {
            let function_name = self.ready.function().name.clone();
            let reason = format!(
                "r2dec residual: source effect closure refused native C ({} refused, {} unaccounted, {} conflicting)",
                audit.refused, audit.unaccounted, audit.conflicts,
            );
            self.ready = prepare_function_for_emission(
                crate::residual_function_for_render_boundary(&function_name, &reason),
            );
        }
        let mut function = self.ready.function().clone();
        crate::note_unproven_constructs(
            &mut function,
            Some(ledger),
            radare2_variadic_format_counts,
            radare2_prototypes,
            radare2_local_names,
            entry_supplied,
        );
        self.ready = prepare_function_for_emission(function);
    }

    pub(crate) fn effect_obligation_audit(&self) -> crate::EffectObligationAudit {
        self.ledger
            .as_ref()
            .map_or(crate::EffectObligationAudit::NOT_RUN, |ledger| {
                crate::EffectObligationAudit::from_ledger(ledger)
            })
    }

    /// What became of every obligation, for a reader that wants more than counts.
    pub(crate) fn obligation_ledger(&self) -> Option<&crate::ledger::ObligationLedger> {
        self.ledger.as_ref()
    }

    pub(crate) const fn placement_audit(&self) -> crate::PlacementAudit {
        self.placement_audit
    }

    pub(crate) fn into_function(self) -> CFunction {
        self.ready.into_function()
    }
}

impl LegacyObservationJournal {
    fn expr_value_observations(&self, expr: &CExpr) -> BTreeSet<ValueId> {
        let mut values = BTreeSet::new();
        expr.visit_render_observations(&mut |id| {
            if let Some(ObservationTarget::Value(value)) = self.targets.get(id.index() as usize) {
                values.insert(*value);
            }
        });
        values
    }

    fn expr_symbols(expr: &CExpr) -> BTreeSet<SymbolId> {
        let mut symbols = BTreeSet::new();
        expr.visit(&mut |node| {
            if let CExpr::Var(symbol) = node {
                symbols.insert(*symbol);
            }
        });
        symbols
    }

    pub(crate) fn checkpoint(&self) -> ObservationJournalCheckpoint {
        ObservationJournalCheckpoint {
            target_len: self.targets.len(),
        }
    }

    /// Discard markers allocated by a candidate tree that will not be emitted.
    ///
    /// The checkpoint comes from this journal immediately before the candidate
    /// route. Dense observation IDs allocated after it are unreachable once
    /// that tree is dropped, so truncating the tail preserves all earlier IDs.
    pub(crate) fn rollback(&mut self, checkpoint: ObservationJournalCheckpoint) {
        assert!(
            checkpoint.target_len <= self.targets.len(),
            "an observation checkpoint cannot point past its issuing journal"
        );
        self.targets.truncate(checkpoint.target_len);
    }

    /// The effect obligations a control rewrite removed from the text.
    pub(crate) fn rewrite_elided_effects(&self) -> BTreeSet<SemanticObligationId> {
        self.rewrite_elisions
            .cells
            .iter()
            .filter_map(|(id, _)| match self.targets.get(id.index() as usize) {
                Some(ObservationTarget::Effect(effect)) => Some(*effect),
                _ => None,
            })
            .collect()
    }

    /// What this marker stands for, for a diagnostic that has only its id.
    pub(crate) fn observation_description(&self, id: RenderObservationId) -> String {
        match self.targets.get(id.index() as usize) {
            Some(target) => format!("{target:?}").chars().take(200).collect(),
            None => "<none>".to_string(),
        }
    }

    /// Whether the object this symbol names exists only to carry a value to
    /// the function's return.
    ///
    /// Specialising the return into the arms above it removes that object, so
    /// nothing else may read it. `pearson` is why this is asked of the plan and
    /// not of the text: its merge is also a loop carrier, read inside the arm
    /// through an expression written somewhere the rewrite cannot see. A phi
    /// that feeds the same object back is the carrier rather than a reader.
    pub(crate) fn merge_carries_only_to_return(&self, symbol: SymbolId) -> bool {
        self.return_only_carriers
            .iter()
            .any(|binding| self.names.symbol_for_binding(*binding) == Some(symbol))
    }

    /// Whether this marker stands for a write rather than for a value or read.
    ///
    /// A rewrite that merges two arms into one assignment has to know: the
    /// value each arm computed stays inside its arm, while the write they both
    /// performed is the one store the merged assignment makes, and a write
    /// marker inside the right-hand side is an ordering the placement pass
    /// cannot resolve.
    pub(crate) fn observation_is_write(&self, id: RenderObservationId) -> bool {
        matches!(
            self.targets.get(id.index() as usize),
            Some(
                ObservationTarget::Write { .. }
                    | ObservationTarget::StackAccess { is_write: true, .. }
            )
        )
    }

    pub(crate) fn observation_block(&self, id: RenderObservationId) -> Option<u64> {
        let graph = self.source.graph();
        let inst_block = |inst: InstId| {
            graph
                .inst(inst)
                .and_then(|inst| graph.block(inst.block))
                .map(|block| block.addr)
        };
        match self.targets.get(id.index() as usize)? {
            ObservationTarget::Use { block, .. } | ObservationTarget::Write { block, .. } => {
                Some(*block)
            }
            ObservationTarget::StackAccess {
                access,
                rendered_block,
                ..
            } => rendered_block.or_else(|| inst_block(access.inst)),
            ObservationTarget::ObjectAddress { block, .. } => Some(*block),
            ObservationTarget::Gapped { anchor, .. } => Some(anchor.block_addr),
            ObservationTarget::Effect(id) => match id.instruction.site {
                r2ssa::CanonicalInstructionSite::Phi(_) => None,
                _ => Some(id.instruction.block_addr),
            },
            ObservationTarget::Value(_)
            | ObservationTarget::CertifiedValueRead { .. }
            | ObservationTarget::CertifiedArrayIndexRead { .. } => None,
        }
    }

    pub(crate) fn new(
        source: &SourceOwnedFunctionFacts,
        normalized: &r2ssa::RewrittenFunction<'_>,
        origins: &NormalizationOrigins,
        names: Rc<BindingNameResolution>,
        symbols: Rc<RefCell<SymbolTable>>,
    ) -> Result<Self, LegacyObservationJournalError> {
        let plan = Rc::clone(names.plan());
        plan.validate_source(source.source())
            .map_err(LegacyObservationJournalError::BindingPlan)?;
        if !names.owns_symbol_table(&symbols) {
            return Err(LegacyObservationJournalError::SymbolTableMismatch);
        }
        origins
            .validate(normalized, source.source(), source.report().render())
            .map_err(LegacyObservationJournalError::Normalization)?;

        let graph = source.source().graph();
        let mut normalized_projections: Vec<Box<[NormalizedOpProjection]>> =
            vec![Vec::new().into_boxed_slice(); graph.blocks.len()];
        for block_id in graph.block_order.iter().copied() {
            let block = graph
                .block(block_id)
                .and_then(|block| normalized.get_block(block.addr))
                .ok_or(LegacyObservationJournalError::Normalization(
                    NormalizationOriginError::BlockTopology,
                ))?;
            let rows = (0..block.ops.len())
                .map(|op_idx| {
                    let site = NormalizedOpSite {
                        block: block_id,
                        op_idx,
                    };
                    origins
                        .projection(site, source.source())
                        .map_err(LegacyObservationJournalError::Normalization)?
                        .ok_or(LegacyObservationJournalError::InvalidNormalizedSite(site))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice();
            normalized_projections[block_id.0 as usize] = rows;
        }
        crate::stage_timing::mark("journal_projections");
        let value_is_literal = graph
            .values
            .iter()
            .map(|value| value.var.constant_bits().is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        crate::stage_timing::mark("journal_literals");
        let mut coalesced_carrier_copy_sites = BTreeSet::new();
        let mut coalesced_store_sites = BTreeSet::<(u64, usize)>::new();
        let mut coalesced_copy_writes = BTreeSet::new();
        let mut coalesced_copy_outputs = BTreeSet::new();
        for block_id in graph.block_order.iter().copied() {
            let Some(block) = graph
                .block(block_id)
                .and_then(|block| normalized.get_block(block.addr))
            else {
                return Err(LegacyObservationJournalError::Normalization(
                    NormalizationOriginError::BlockTopology,
                ));
            };
            for (op_idx, op) in block.ops.iter().enumerate() {
                let site = NormalizedOpSite {
                    block: block_id,
                    op_idx,
                };
                // Any copy normalization made for a merge: the copy on each
                // materialised edge, and the initializer a certified carrier
                // relocates ahead of its entry edges. What makes the copy say
                // nothing is that both sides resolve to one binding, which is
                // tested below; the loop carrier is where the case was found,
                // not the reason it holds.
                //
                // An entry value among the sources is no exception: a binding
                // holding one is declared as caller-supplied, so its copy
                // into that binding says `x = x` like any other.
                //
                // And the program's own copies. `subs x1, x1, #1` lifts to a
                // subtraction into a temporary and a copy of the temporary
                // into `x1`; once the carrier certificate puts the temporary
                // and the register in one object, that copy is `x = x` for
                // exactly the reason the edge copies are. It keeps its
                // statement only where the copy does something the name does
                // not: a write projection narrower than the object, or a read
                // that converts, is a real operation whatever the two sides
                // are called.
                // And the restore a call boundary makes. It is admitted here
                // for exactly the reason an edge copy is -- both sides resolve
                // to one binding, which is tested below -- and it is licensed
                // by the convention fact it was built from rather than by its
                // operation kind. The interference rule above declines a save
                // and restore around a clobber *for want of proof* that
                // nothing touched the object in between; here the source
                // states that the callee leaves this carrier where it found
                // it, and names the carrier it means, which is that proof. A
                // restore the convention does not speak for is declined
                // exactly as an unproven program copy is.
                // A reload of a slot whose object is the value's own binding
                // says `x = x` for the same reason a copy does: the store
                // that filled the slot already produced this value, and the
                // memory SSA proved nothing wrote it in between.
                if matches!(op, r2ssa::SSAOp::Load { .. })
                    && let Some(output) = normalized_projections
                        .get(block_id.0 as usize)
                        .and_then(|rows| rows.get(op_idx))
                        .and_then(|projection| projection.output)
                        .map(|output| output.value)
                    && let Some(inst) = graph.def_inst(output)
                    && let Some(object) = loaded_stack_object(source.source(), graph, inst)
                    && let Some(ValueDisposition::Bound {
                        binding: value_binding,
                    }) = plan.disposition(output)
                    && plan.stack_object_disposition(object)
                        == Some(StackObjectDisposition::Bound {
                            binding: *value_binding,
                        })
                {
                    r2il::refusal_evidence!(
                        "reload-elision",
                        "{site:?} loads {output:?} from {object:?}, both bound to \
                         {value_binding:?}; the statement is the store's"
                    );
                    coalesced_carrier_copy_sites.insert(site);
                    coalesced_copy_outputs.insert(output);
                    coalesced_copy_writes.insert(inst);
                    continue;
                }
                // A store into an object bound to the value's own binding says `x = x`.
                if let r2ssa::SSAOp::Store { val, .. } = op
                    && let Some(NormalizedOpOrigin::Original(inst)) = origins.origin(site)
                    && let Some(object) = stored_stack_object(source.source(), graph, *inst)
                    && let Some(stored) = graph.value_id_for_var(val)
                    && let Some(value_binding) = match plan.disposition(stored) {
                        Some(ValueDisposition::Bound { binding }) => Some(*binding),
                        // A folded value spells its own term, and a term that is
                        // a binding's value and no more is that binding.
                        // Only where the term stands for nothing but its own
                        // definition: an absorbed producer owes an obligation
                        // that this statement was answering for.
                        Some(ValueDisposition::Inline { term, .. })
                            if plan
                                .canonical()
                                .value(stored)
                                .is_some_and(|value| value.discharges.is_empty()) =>
                        {
                            crate::binding_plan::term_spells_binding(&plan, *term)
                        }
                        _ => None,
                    }
                    && plan.stack_object_disposition(object)
                        == Some(StackObjectDisposition::Bound {
                            binding: value_binding,
                        })
                {
                    r2il::refusal_evidence!(
                        "store-elision",
                        "{site:?} stores {stored:?} into {object:?}, both bound to \
                         {value_binding:?}; the object already holds it"
                    );
                    coalesced_carrier_copy_sites.insert(site);
                    coalesced_store_sites.insert((block.addr, op_idx));
                    // A folded value's occurrence lived in the statement this
                    // removes, so what it owed goes with it.
                    if matches!(
                        plan.disposition(stored),
                        Some(ValueDisposition::Inline { .. })
                    ) {
                        coalesced_copy_outputs.insert(stored);
                        if let Some(definition) = graph.def_inst(stored) {
                            coalesced_copy_writes.insert(definition);
                        }
                    }
                    continue;
                }
                if r2il::refusal_evidence::tracing()
                    && let r2ssa::SSAOp::Store { val, .. } = op
                    && let Some(NormalizedOpOrigin::Original(inst)) = origins.origin(site)
                {
                    r2il::refusal_evidence!(
                        "store-elision",
                        "{site:?} not elided: object={:?} stored={:?} value_disposition={:?}                          object_disposition={:?}",
                        stored_stack_object(source.source(), graph, *inst),
                        graph.value_id_for_var(val),
                        graph
                            .value_id_for_var(val)
                            .and_then(|v| plan.disposition(v)),
                        stored_stack_object(source.source(), graph, *inst)
                            .and_then(|object| plan.stack_object_disposition(object)),
                    );
                }
                // A restore is a copy the convention states: construction
                // mints it only for the carrier the callee brings back, so
                // the operation's existence is the licence an edge copy has
                // to earn below.
                if !matches!(
                    op,
                    r2ssa::SSAOp::Copy { .. } | r2ssa::SSAOp::CallRestore { .. }
                ) {
                    continue;
                }
                let mut program_copy = None;
                let incoming = match origins.origin(site) {
                    Some(NormalizedOpOrigin::PhiEdgeCopy(origin)) => Some(origin.incoming),
                    Some(NormalizedOpOrigin::RelocatedInitializer(_)) => None,
                    // A copy the program itself made says nothing for the same
                    // reason: both sides are one object, and the partition
                    // that made them one was judged by liveness, so nothing
                    // wrote the object between the value and the copy.
                    Some(NormalizedOpOrigin::Original(inst)) => {
                        program_copy = Some(*inst);
                        None
                    }
                    None => {
                        continue;
                    }
                };
                let projection = &normalized_projections[block_id.0 as usize][op_idx];
                let Some(output) = projection.output else {
                    continue;
                };
                let input = match incoming {
                    Some(incoming) => projection
                        .inputs
                        .iter()
                        .find(|input| input.uses.contains(&incoming)),
                    None => projection.inputs.first(),
                };
                let Some(input) = input else {
                    continue;
                };
                let dispositions = (
                    plan.disposition(input.value),
                    plan.disposition(output.value),
                );
                // An inlined source is an expression read where the copy
                // stands, so when that expression spells the destination the
                // copy assigns the object to itself wherever it sits, and the
                // interval question a bound source needs has no subject.
                let inline_spells_the_destination = matches!(
                    (&dispositions.0, &dispositions.1),
                    (
                        Some(ValueDisposition::Inline { term, .. }),
                        Some(ValueDisposition::Bound { binding }),
                    ) if crate::binding_plan::term_spells_binding(&plan, *term) == Some(*binding)
                );
                // A restore states the convention rather than performing a
                // copy the program wrote, so the question this asks of a
                // program copy -- did anything write the object between the
                // value and the copy -- is the one the certificate already
                // answered. The call is the only thing between the two sides,
                // and the certificate is about exactly that call.
                let same_binding = inline_spells_the_destination
                    || matches!(
                        dispositions,
                        (
                            Some(ValueDisposition::Bound { binding: input }),
                            Some(ValueDisposition::Bound { binding: output }),
                        ) if input == output
                    );
                if same_binding {
                    coalesced_carrier_copy_sites.insert(site);
                    if let Some(inst) = program_copy {
                        coalesced_copy_outputs.insert(output.value);
                        coalesced_copy_writes.insert(inst);
                    }
                    // A folded source's occurrence lived in the statement this
                    // removes, so what it owed goes with it.
                    if inline_spells_the_destination {
                        coalesced_copy_outputs.insert(input.value);
                        if let Some(definition) = graph.def_inst(input.value) {
                            coalesced_copy_writes.insert(definition);
                        }
                    }
                }
            }
        }
        let coalesced_carrier_uses = coalesced_carrier_copy_sites
            .iter()
            .filter_map(|site| {
                normalized_projections
                    .get(site.block.0 as usize)
                    .and_then(|rows| rows.get(site.op_idx))
            })
            .flat_map(|projection| {
                projection
                    .inputs
                    .iter()
                    .flat_map(|input| input.uses.iter().copied())
            })
            .collect::<BTreeSet<_>>();
        // Symmetric with the edge uses above. A merge every one of whose
        // edges is an identity or coalesced to its own binding performs
        // nothing, so it owes no standalone write.
        let coalesced_carrier_phi_writes = origins
            .removed_phis()
            .iter()
            .filter(|removed| {
                removed.incoming_sites.iter().all(|site| {
                    removed.noop_sites().contains(site) || coalesced_carrier_uses.contains(site)
                })
            })
            .map(|removed| removed.definition.inst)
            .collect::<BTreeSet<_>>();
        // A binding read only by returns and by merges of itself exists to
        // carry a value out; computed once, over every value, for the cleanup
        // that asks per return.
        let return_only_carriers = {
            let returns = &source.source().certificates().returns_by_inst;
            let owner = |value: ValueId| match names.disposition_for_value(value) {
                Some(ValueDisposition::Bound { binding }) => Some(*binding),
                _ => None,
            };
            // A value reaches only the return when every use is the return
            // itself, the merge that feeds the same object back, or a copy
            // whose own value reaches only the return: a promoted slot is
            // read into the return register before the machine returns it.
            fn reaches_only_return(
                graph: &r2ssa::SsaGraph,
                returns: &BTreeMap<InstId, usize>,
                owner: &dyn Fn(ValueId) -> Option<crate::binding_plan::BindingId>,
                binding: crate::binding_plan::BindingId,
                value: ValueId,
                depth: usize,
            ) -> bool {
                depth < 8
                    && graph.use_sites(value).iter().all(|site| {
                        returns.contains_key(&site.inst)
                            || graph
                                .inst(site.inst)
                                .is_some_and(|inst| match &inst.payload {
                                    r2ssa::InstPayload::Phi { .. } => inst
                                        .output
                                        .is_some_and(|output| owner(output) == Some(binding)),
                                    r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. }) => {
                                        inst.output.is_some_and(|output| {
                                            reaches_only_return(
                                                graph,
                                                returns,
                                                owner,
                                                binding,
                                                output,
                                                depth + 1,
                                            )
                                        })
                                    }
                                    _ => false,
                                })
                    })
            }
            let mut carriers = BTreeMap::<crate::binding_plan::BindingId, bool>::new();
            for index in 0..graph.values.len() {
                let value = ValueId(index as u32);
                let Some(binding) = owner(value) else {
                    continue;
                };
                let only_returns = carriers.entry(binding).or_insert(true);
                if *only_returns && !reaches_only_return(graph, returns, &owner, binding, value, 0)
                {
                    *only_returns = false;
                }
            }
            carriers
                .into_iter()
                .filter_map(|(binding, only_returns)| only_returns.then_some(binding))
                .collect::<BTreeSet<_>>()
        };
        crate::stage_timing::mark("journal_coalesced");
        let values = vec![None; graph.values.len()].into_boxed_slice();
        let uses = graph
            .insts
            .iter()
            .map(|inst| vec![None; inst.inputs.len()].into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let write_has_output = graph
            .insts
            .iter()
            .map(|inst| inst.output.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let writes = vec![None; graph.insts.len()].into_boxed_slice();
        crate::stage_timing::mark("journal_slots");
        let effect_occurrences = source
            .source()
            .obligations()
            .obligations()
            .keys()
            .copied()
            .map(|id| (id, 0))
            .collect();
        let materialized_edges = origins.materialized_phi_edges_by_definition();
        let superseded_phi_edges = origins.superseded_phi_edges(graph);
        r2il::refusal_evidence!(
            "superseded-phi-edges",
            "{} header inputs a relocated initializer stands for: {:?}",
            superseded_phi_edges.len(),
            superseded_phi_edges.iter().take(12).collect::<Vec<_>>()
        );
        let materialized_removed_phis = origins
            .removed_phis()
            .iter()
            .filter(|removed| {
                let materialized = materialized_edges.get(&removed.definition.inst);
                removed.incoming_sites.iter().all(|site| {
                    removed.noop_sites().contains(site)
                        || materialized.is_some_and(|edges| edges.contains(site))
                })
            })
            .map(|removed| removed.definition.inst)
            .collect::<BTreeSet<_>>();
        let mut journal = Self {
            authority: source.source().authority().clone(),
            source: source.shared_source(),
            plan,
            names,
            normalized_projections,
            coalesced_carrier_copy_sites,
            coalesced_store_sites,
            coalesced_carrier_uses,
            return_only_carriers,
            superseded_phi_edges,
            coalesced_carrier_phi_writes,
            coalesced_copy_writes,
            coalesced_copy_outputs,
            materialized_removed_phis,
            target_origins: Vec::new(),
            placement_elided_writes: BTreeSet::new(),
            placement_elided_observations: BTreeSet::new(),
            placement_elided_effects: BTreeSet::new(),
            dead_unused_value_effects: BTreeSet::new(),
            symbols,
            value_is_literal,
            values,
            uses,
            write_has_output,
            writes,
            effect_occurrences,
            effect_occurrence_regions: BTreeMap::new(),
            exclusive_duplicate_effects: BTreeSet::new(),
            gapped_effects: BTreeSet::new(),
            rewrite_elisions: RewriteElisions::default(),
            gapped_values: BTreeSet::new(),
            targets: Vec::new(),
        };
        journal.record_upstream_nonrendered_dispositions(source, origins)?;
        Ok(journal)
    }

    fn duplicate_observation_target(
        &mut self,
        id: RenderObservationId,
    ) -> Result<RenderObservationId, LegacyObservationJournalError> {
        let index = usize::try_from(id.index()).map_err(|_| {
            LegacyObservationJournalError::Markers(RenderObservationStripError::OutOfRange {
                id,
                expected_count: self.targets.len(),
            })
        })?;
        let target = self.targets.get(index).cloned().ok_or({
            LegacyObservationJournalError::Markers(RenderObservationStripError::OutOfRange {
                id,
                expected_count: self.targets.len(),
            })
        })?;
        self.allocate_many(vec![target])?
            .into_iter()
            .next()
            .ok_or(LegacyObservationJournalError::TooManyObservations)
    }

    /// Clone a cached semantic fold while assigning fresh IDs to its concrete
    /// AST occurrence. The new IDs retain the exact authority-bound targets of
    /// the cached template; no use, value, or write identity is reconstructed.
    pub(crate) fn clone_render_occurrence(
        &mut self,
        stmts: &[CStmt],
    ) -> Result<Vec<CStmt>, LegacyObservationJournalError> {
        let mut clone = stmts.to_vec();
        crate::ast::remap_render_observation_ids(&mut clone, &mut |id| {
            self.duplicate_observation_target(id)
        })?;
        Ok(clone)
    }

    /// Whether a read of a value spells nothing except an object's address.
    ///
    /// A memory-address operand renders as the object's name, and a read on an
    /// unobserved merge edge renders nothing at all; neither can be the
    /// occurrence that answers for the value.
    fn use_spells_nothing_but_an_address(&self, site: UseSite) -> bool {
        matches!(
            self.plan.use_disposition(site),
            Some(r2ssa::MachineUseDisposition::MemoryAddress(_))
        ) || self
            .source
            .unobserved_merges()
            .unobserved_uses()
            .contains(&site)
            || self.superseded_phi_edges.contains(&site)
    }

    /// The definitions an inlined address computation is made of.
    ///
    /// Rendering the access spells the object rather than the address, so every
    /// inlined producer behind that address is discharged there. A producer the
    /// plan bound is not: its own statement still renders it.
    fn inlined_address_producers(&self, address: ValueId) -> Vec<InstId> {
        let graph = self.source.graph();
        let mut discharged = Vec::new();
        let mut pending = vec![address];
        let mut seen = BTreeSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if !matches!(
                self.plan.disposition(value),
                Some(ValueDisposition::Inline { .. })
            ) {
                continue;
            }
            if self
                .values
                .get(value.0 as usize)
                .is_none_or(Option::is_some)
            {
                continue;
            }
            let Some(definition) = graph.def_inst(value) else {
                continue;
            };
            let Some(inst) = graph.inst(definition) else {
                continue;
            };
            pending.extend(inst.inputs.iter().copied());
            // Only a value nothing else can render. A producer read somewhere
            // that spells it is answered there, and answering again here
            // reports one effect discharged twice; a read on an unobserved
            // merge edge spells nothing and does not disqualify it.
            // A read by a producer this same walk has already discharged is
            // part of the address being spelled: `x10 + i` reads `x10` on the
            // way to the object's name, not anywhere a reader could see it.
            if !graph.use_sites(value).iter().all(|site| {
                discharged.contains(&site.inst) || self.use_spells_nothing_but_an_address(*site)
            }) {
                r2il::refusal_evidence!(
                    "address-producer-kept",
                    "{value:?} defined by {definition:?} is read where something spells it: {:?}",
                    graph
                        .use_sites(value)
                        .iter()
                        .map(|site| (
                            *site,
                            self.plan.use_disposition(*site),
                            self.source
                                .unobserved_merges()
                                .unobserved_uses()
                                .contains(site),
                            self.uses
                                .get(site.inst.0 as usize)
                                .and_then(|row| row.get(site.input_idx))
                                .cloned()
                                .flatten()
                        ))
                        .collect::<Vec<_>>()
                );
                continue;
            }
            discharged.push(definition);
        }
        discharged
    }

    /// Apply all absent-occurrence answers in their required dependency order.
    ///
    /// Placement's exact removal report must close its cells before an
    /// identity merge or coalesced copy asks whether every consumer vanished.
    /// Keeping that order behind one call prevents sealing from classifying a
    /// removed consumer as an undeclared object.
    fn apply_absent_occurrence_contracts(
        &mut self,
        symbol_bindings: &BTreeMap<SymbolId, LegacyBindingId>,
    ) -> Result<(), LegacyObservationJournalError> {
        self.account_removed_occurrences();
        self.account_values_rendered_by_binding(symbol_bindings)?;
        self.account_coalesced_copy_outputs(symbol_bindings)
    }

    /// Whether a certificate answers for every occurrence of an undefined value.
    fn every_occurrence_certified(
        &self,
        silence: &crate::binding_plan::CertifiedSilence,
        value: ValueId,
    ) -> bool {
        let graph = self.source.graph();
        let uses = graph.use_sites(value);
        graph.def_inst(value).is_none()
            && !uses.is_empty()
            && uses.iter().all(|site| silence.contains(site.inst))
    }

    /// Name every cell and reader of an unaccounted value, under the trace
    /// switch the lowering refusals use.
    fn trace_unaccounted_value(&self, index: usize, value: ValueId) {
        if !r2il::refusal_evidence::tracing() {
            return;
        }
        let graph = self.source.graph();
        let targets = self
            .targets
            .iter()
            .enumerate()
            .filter_map(|(id, target)| {
                matches!(target, ObservationTarget::Value(target) if *target == value).then_some(id)
            })
            .collect::<Vec<_>>();
        eprintln!(
            "unaccounted value {value:?} disposition {:?} def {:?} uses={uses} storage={storage:?} readers={readers:?} targets={targets:?}",
            self.plan.disposition(value),
            graph
                .def_inst(value)
                .and_then(|inst| graph.inst(inst))
                .map(|inst| format!("{:?}", inst.payload)
                    .chars()
                    .take(130)
                    .collect::<String>()),
            uses = graph.use_sites(value).len(),
            readers = graph
                .use_sites(value)
                .iter()
                .filter_map(|site| graph.inst(site.inst))
                .map(|inst| format!("{:?}", inst.payload)
                    .chars()
                    .take(80)
                    .collect::<String>())
                .collect::<Vec<_>>(),
            storage = graph
                .value(value)
                .and_then(|v| v.canonical_storage)
                .map(|s| (s.space, s.offset, s.size))
        );
        for site in graph.use_sites(value) {
            let reader = graph.inst(site.inst);
            let output = reader.and_then(|inst| inst.output);
            eprintln!(
                "   use {site:?} answer={:?} projection={:?} output={output:?} output_disposition={:?} -> {:?}",
                self.uses
                    .get(site.inst.0 as usize)
                    .and_then(|row| row.get(site.input_idx)),
                self.plan.use_disposition(*site),
                output.and_then(|value| self.plan.disposition(value)),
                reader.map(|inst| format!("{:?}", inst.payload)
                    .chars()
                    .take(110)
                    .collect::<String>())
            );
        }
        self.trace_unaccounted_neighbours(index, value);
    }

    /// The rest of the picture: the call results that share this value's
    /// site, every target, every reader, the definition, and what else went
    /// unaccounted beside it.
    fn trace_unaccounted_neighbours(&self, index: usize, value: ValueId) {
        let graph = self.source.graph();
        let targets = self
            .targets
            .iter()
            .enumerate()
            .filter_map(|(id, target)| {
                matches!(target, ObservationTarget::Value(target) if *target == value).then_some(id)
            })
            .collect::<Vec<_>>();
        if let Some(fact) = self.source.facts().certificates.call_results.get(&value) {
            let site = fact.call_site;
            for peer in self
                .source
                .facts()
                .certificates
                .call_results
                .values()
                .filter(|peer| peer.call_site == site)
            {
                eprintln!(
                    "   call result at {site:?}: {:?} at {:?} width {} relation {:?} carrier {:?} owner {:?}",
                    peer.value, peer.at, peer.width, peer.relation, peer.carrier, peer.owner
                );
            }
        }
        for (id, target) in self.targets.iter().enumerate() {
            if matches!(target, ObservationTarget::Value(_)) {
                eprintln!(
                    "   any {id} {target:?} from {:?}",
                    self.target_origins.get(id).map(ToString::to_string)
                );
            }
        }
        for site in graph.use_sites(value) {
            eprintln!(
                "   reader {:?} write={:?} output_obs={:?}",
                site.inst,
                self.writes.get(site.inst.0 as usize),
                graph
                    .inst(site.inst)
                    .and_then(|inst| inst.output)
                    .and_then(|out| self.values.get(out.0 as usize)),
            );
        }
        if let Some(definition) = graph.def_inst(value) {
            eprintln!(
                "   def {definition:?} write={:?} placement_elided_write={} block={:?}",
                self.writes.get(definition.0 as usize),
                self.placement_elided_writes.contains(&definition),
                graph.inst(definition).map(|inst| inst.block),
            );
        }
        self.trace_unaccounted_targets(index, &targets);
    }

    /// Each target the value has, and every other value still without a cell.
    fn trace_unaccounted_targets(&self, index: usize, targets: &[usize]) {
        let graph = self.source.graph();
        for id in targets {
            eprintln!(
                "   target {id} from {:?} = {:?}",
                self.target_origins.get(*id).map(ToString::to_string),
                self.targets
                    .get(*id)
                    .map(|target| format!("{target:?}").chars().take(160).collect::<String>())
            );
        }
        let other_unaccounted = self
            .values
            .iter()
            .enumerate()
            .skip(index + 1)
            .filter(|(_, observation)| observation.is_none())
            .map(|(index, _)| {
                let value = ValueId(index as u32);
                let definition =
                    graph
                        .def_inst(value)
                        .and_then(|inst| graph.inst(inst))
                        .map(|inst| {
                            format!("{:?}", inst.payload)
                                .chars()
                                .take(70)
                                .collect::<String>()
                        });
                (value, self.plan.disposition(value), definition)
            })
            .collect::<Vec<_>>();
        if !other_unaccounted.is_empty() {
            eprintln!("other unaccounted values: {other_unaccounted:?}");
        }
    }

    /// Why this value went unaccounted, with the evidence to find it by.
    fn unaccounted_value(&self, index: usize, value: ValueId) -> LegacyObservationJournalError {
        self.trace_unaccounted_value(index, value);
        LegacyObservationJournalError::rendered_value_required(
            value,
            RenderedValueRequirementCause::UnobservedValueCellAtSeal,
            self.plan.disposition(value),
        )
    }

    fn first_unaccounted_render_observation(&self) -> Option<LegacyObservationJournalError> {
        // Each of the three loops below names the exact cell it found empty
        // under `R2DEC_TRACE_REFUSAL`, the same switch the lowering refusals
        // use. A seal failure otherwise reports only that some value, use or
        // write went unaccounted, and finding which one back from that cost
        // four separate investigations.
        // A value nothing defines is spelled at its occurrences and nowhere
        // else, so where a certificate answers for every one of them it is
        // never spelled and has no cell. `const:8` is shared between a jump
        // table's scale and the stack-pointer restore in each arm; both are
        // certified, and demanding a rendered occurrence of it asked for a
        // statement that would have been wrong to write.
        let silence = std::cell::OnceCell::new();
        let mut unaccounted = self
            .values
            .iter()
            .enumerate()
            .filter(|(_, observation)| observation.is_none())
            .map(|(index, _)| (index, ValueId(index as u32)))
            // Built once, and only if some value is unaccounted at all.
            .filter(|(_, value)| {
                !self.every_occurrence_certified(
                    silence.get_or_init(|| {
                        crate::binding_plan::CertifiedSilence::for_function(&self.source)
                    }),
                    *value,
                )
            });
        if let Some((index, value)) = unaccounted.next() {
            return Some(self.unaccounted_value(index, value));
        }
        for (inst, row) in self.uses.iter().enumerate() {
            for (input_idx, observation) in row.iter().enumerate() {
                if observation.is_none() {
                    if r2il::refusal_evidence::tracing() {
                        let graph = self.source.graph();
                        let site = UseSite {
                            inst: InstId(inst as u32),
                            input_idx,
                        };
                        let targets = self
                            .targets
                            .iter()
                            .enumerate()
                            .filter_map(|(id, target)| {
                                matches!(target, ObservationTarget::Use { site: target, .. } if *target == site)
                                    .then_some(id)
                            })
                            .collect::<Vec<_>>();
                        // Which object this use addresses, and how the plan
                        // typed it. An address use that nothing rendered is
                        // almost always an access the object's declaration has
                        // no spelling for.
                        let addressed = graph
                            .inst(InstId(inst as u32))
                            .and_then(|inst| inst.inputs.get(input_idx).copied())
                            .and_then(|value| {
                                self.source
                                    .objects()
                                    .object_for_value(value, r2il::SpaceId::Ram)
                            });
                        eprintln!(
                            "unaccounted use inst={inst} input={input_idx} disposition={:?} object={addressed:?} kind={:?} accesses={:?} payload={:?} targets={targets:?}",
                            graph
                                .inst(InstId(inst as u32))
                                .and_then(|inst| inst.inputs.get(input_idx).copied())
                                .and_then(|input| self.plan.disposition(input)),
                            addressed
                                .and_then(|object| self.source.objects().object(object))
                                .map(|object| format!("{:?}", object.kind)
                                    .chars()
                                    .take(70)
                                    .collect::<String>()),
                            addressed.map(|object| self
                                .source
                                .certificates()
                                .memory_accesses
                                .values()
                                .filter(|access| access.object == object)
                                .map(|access| (access.width, access.object_offset, access.is_write))
                                .collect::<Vec<_>>()),
                            graph.inst(InstId(inst as u32)).map(|inst| format!(
                                "{:?}",
                                inst.payload
                            )
                            .chars()
                            .take(120)
                            .collect::<String>())
                        );
                    }
                    return Some(
                        LegacyObservationJournalError::ExactUseRequiresRenderedOccurrence(
                            UseSite {
                                inst: InstId(inst as u32),
                                input_idx,
                            },
                        ),
                    );
                }
            }
        }
        for (index, (observation, has_output)) in self
            .writes
            .iter()
            .zip(self.write_has_output.iter())
            .enumerate()
        {
            if *has_output && observation.is_none() {
                if r2il::refusal_evidence::tracing() {
                    let graph = self.source.graph();
                    eprintln!(
                        "unaccounted write inst={index} payload={:?}",
                        graph
                            .inst(InstId(index as u32))
                            .map(|inst| format!("{:?}", inst.payload)
                                .chars()
                                .take(120)
                                .collect::<String>())
                    );
                }
                return Some(
                    LegacyObservationJournalError::ExactWriteRequiresRenderedOccurrence(InstId(
                        index as u32,
                    )),
                );
            }
        }
        None
    }

    /// Whether a rendering that spells `rendered_symbols` absorbs `value`: a
    /// frame address bound to a carrier the rendering never names.
    fn stack_base_absorbed_by(
        &self,
        value: ValueId,
        rendered_symbols: &BTreeSet<SymbolId>,
    ) -> bool {
        let Some(ValueDisposition::Bound { binding }) = self.plan.disposition(value) else {
            return false;
        };
        if self
            .names
            .symbol_for_binding(*binding)
            .is_some_and(|symbol| rendered_symbols.contains(&symbol))
        {
            r2il::refusal_evidence!(
                "stack-base-absorbed",
                "{value:?} bound to {binding:?} is not absorbed: this rendering spells it"
            );
            return false;
        }
        let entry_root = self.source.entry_stack_address_root_for_value(value);
        if entry_root.is_none() {
            r2il::refusal_evidence!(
                "stack-base-absorbed",
                "{value:?} bound to {binding:?} is not absorbed: no entry root; stack_root={:?}",
                self.source.stack_address_root_for_value(value)
            );
        }
        entry_root.is_some()
    }

    fn normalized_projection(
        &self,
        site: NormalizedOpSite,
    ) -> Result<&NormalizedOpProjection, LegacyObservationJournalError> {
        self.normalized_projections
            .get(site.block.0 as usize)
            .and_then(|rows| rows.get(site.op_idx))
            .ok_or(LegacyObservationJournalError::InvalidNormalizedSite(site))
    }

    pub(crate) fn is_coalesced_carrier_copy(&self, site: NormalizedOpSite) -> bool {
        self.coalesced_carrier_copy_sites.contains(&site)
    }

    /// Whether the plan elides `value` as dead stack geometry.
    fn stack_geometry_elides(&self, value: ValueId) -> bool {
        matches!(
            self.plan.disposition(value),
            Some(ValueDisposition::Elided {
                reason: crate::ledger::ElisionReason::DeadStackBase,
                ..
            })
        )
    }

    fn rendered_use_observation(
        &self,
        site: UseSite,
    ) -> Result<LegacyUseObservation, LegacyObservationJournalError> {
        match self.plan.use_disposition(site) {
            Some(MachineUseDisposition::Exact(slice)) => Ok(LegacyUseObservation::Exact(slice)),
            Some(MachineUseDisposition::MemoryAddress(_)) => {
                Ok(LegacyUseObservation::MemoryAddress)
            }
            Some(MachineUseDisposition::Refused(refusal)) => {
                r2il::refusal_evidence!(
                    "refused-rendered-use",
                    "use {site:?} is rendered at the seal and the projection refused it: {refusal:?}"
                );
                Err(LegacyObservationJournalError::refused_use(site, refusal))
            }
            None => Err(LegacyObservationJournalError::InvalidUse(site)),
        }
    }

    fn rendered_write_observation(
        &self,
        inst: InstId,
    ) -> Result<LegacyWriteObservation, LegacyObservationJournalError> {
        match self.plan.write_disposition(inst) {
            Some(MachineWriteDisposition::Exact(write)) => {
                Ok(LegacyWriteObservation::Exact(*write))
            }
            Some(MachineWriteDisposition::Refused(_)) => {
                Err(LegacyObservationJournalError::RefusedRenderedWrite(inst))
            }
            None => Err(LegacyObservationJournalError::InvalidWrite(inst)),
        }
    }

    /// The obligations of every value the plan spells as a frame constant
    /// wherever it is read: a literal, or a frame object's address.
    ///
    /// Asked of the plan's canonical term, which is the same identity the
    /// inline disposition renders, so planning and accounting cannot disagree
    /// about which values are constants.
    fn repeated_literal_effects(&self) -> BTreeSet<SemanticObligationId> {
        let graph = self.source.graph();
        let mut ids = BTreeSet::new();
        for graph_value in &graph.values {
            let Some(ValueDisposition::Inline { term, .. }) = self.plan.disposition(graph_value.id)
            else {
                continue;
            };
            if !matches!(
                self.plan.canonical().arena().term(*term).kind,
                r2rewrite::TermKind::Literal(_) | r2rewrite::TermKind::ObjectAddress(_)
            ) {
                continue;
            }
            let Some(definition) = graph.def_inst(graph_value.id) else {
                continue;
            };
            if let Some(disposition) = self.source.obligations().instruction_for_inst(definition) {
                ids.extend(disposition.obligations.iter().copied());
            }
        }
        ids
    }

    /// The obligations of every address computation the accesses that read it
    /// spell by naming their object.
    ///
    /// The machine computes the address once and each rendered access performs
    /// nothing to obtain it, exactly as a repeated literal does, so several
    /// occurrences are one execution.
    fn named_object_address_effects(&self) -> BTreeSet<SemanticObligationId> {
        let graph = self.source.graph();
        let mut ids = BTreeSet::new();
        for graph_value in &graph.values {
            if !matches!(
                self.plan.disposition(graph_value.id),
                Some(ValueDisposition::Inline { .. })
            ) {
                continue;
            }
            let uses = graph.use_sites(graph_value.id);
            if uses.is_empty()
                || !uses
                    .iter()
                    .all(|site| self.use_spells_nothing_but_an_address(*site))
            {
                continue;
            }
            let Some(definition) = graph.def_inst(graph_value.id) else {
                continue;
            };
            if let Some(disposition) = self.source.obligations().instruction_for_inst(definition) {
                ids.extend(disposition.obligations.iter().copied());
            }
        }
        ids
    }

    fn into_sealed_observations(
        mut self,
        source: &SourceOwnedFunctionFacts,
    ) -> SealedLegacyObservations {
        if r2il::refusal_evidence::tracing() {
            for (id, count) in &self.effect_occurrences {
                if *count != 0 {
                    continue;
                }
                let inst = match id.instruction.site {
                    r2ssa::CanonicalInstructionSite::Op(op) => {
                        usize::try_from(op).ok().and_then(|op| {
                            self.source
                                .graph()
                                .inst_id_for_op_site(id.instruction.block_addr, op)
                        })
                    }
                    _ => None,
                };
                let write =
                    inst.and_then(|inst| self.writes.get(inst.0 as usize).cloned().flatten());
                let value = inst
                    .and_then(|inst| self.source.graph().inst(inst).and_then(|inst| inst.output))
                    .and_then(|value| self.values.get(value.0 as usize).cloned().flatten());
                r2il::refusal_evidence!(
                    "zero-occurrence-cells",
                    "{id:?} inst={inst:?} write={write:?} value={value:?}"
                );
            }
        }
        let coverage = self.final_coverage();
        let rewrite_elided = self.rewrite_elided_effects();
        let exclusive = std::mem::take(&mut self.exclusive_duplicate_effects);
        let repeated_literals = self.repeated_literal_effects();
        let named_object_addresses = self.named_object_address_effects();
        let effects = SurvivingEffectObservations {
            occurrences: std::mem::take(&mut self.effect_occurrences)
                .into_iter()
                .map(|(id, count)| {
                    (
                        id,
                        EffectOccurrences {
                            count,
                            exclusive: exclusive.contains(&id),
                            repeated_literal: repeated_literals.contains(&id),
                            named_object_address: named_object_addresses.contains(&id),
                        },
                    )
                })
                .collect(),
            gapped: std::mem::take(&mut self.gapped_effects),
            rewrite_elided,
            coalesced_carriers: Box::new(CoalescedCarrierEffectElisions {
                coalesced_store_sites: std::mem::take(&mut self.coalesced_store_sites),
                coalesced_carrier_uses: std::mem::take(&mut self.coalesced_carrier_uses),
                coalesced_carrier_phis: std::mem::take(&mut self.coalesced_carrier_phi_writes),
                coalesced_copies: std::mem::take(&mut self.coalesced_copy_writes),
                placement_elided_effects: std::mem::take(&mut self.placement_elided_effects),
                dead_unused_value_effects: std::mem::take(&mut self.dead_unused_value_effects),
            }),
        };
        let snapshot = self.into_snapshot(source);
        SealedLegacyObservations {
            snapshot,
            coverage,
            effects,
        }
    }

    fn into_snapshot(self, source: &SourceOwnedFunctionFacts) -> LegacyAnalysisSnapshot {
        let values = self
            .values
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(index, observation)| LegacyValueCell {
                value: ValueId(index as u32),
                observation: observation.unwrap_or(LegacyValueObservation::LegacyAbsent),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let uses = self
            .uses
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(inst, row)| {
                row.into_vec()
                    .into_iter()
                    .enumerate()
                    .map(|(input_idx, observation)| LegacyUseCell {
                        site: UseSite {
                            inst: InstId(inst as u32),
                            input_idx,
                        },
                        observation: observation.unwrap_or(LegacyUseObservation::LegacyAbsent),
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let writes = self
            .writes
            .into_vec()
            .into_iter()
            .zip(self.write_has_output)
            .enumerate()
            .map(|(index, (observation, has_output))| {
                has_output.then_some(LegacyWriteCell {
                    inst: InstId(index as u32),
                    observation: observation.unwrap_or(LegacyWriteObservation::LegacyAbsent),
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        LegacyAnalysisSnapshot::new(source, values, uses, writes)
    }

    fn value_slot(
        &self,
        value: ValueId,
    ) -> Result<&Option<LegacyValueObservation>, LegacyObservationJournalError> {
        self.values
            .get(value.0 as usize)
            .ok_or(LegacyObservationJournalError::InvalidValue(value))
    }

    fn value_slot_mut(
        &mut self,
        value: ValueId,
    ) -> Result<&mut Option<LegacyValueObservation>, LegacyObservationJournalError> {
        self.values
            .get_mut(value.0 as usize)
            .ok_or(LegacyObservationJournalError::InvalidValue(value))
    }

    fn use_slot_mut(
        &mut self,
        site: UseSite,
    ) -> Result<&mut Option<LegacyUseObservation>, LegacyObservationJournalError> {
        self.uses
            .get_mut(site.inst.0 as usize)
            .and_then(|row| row.get_mut(site.input_idx))
            .ok_or(LegacyObservationJournalError::InvalidUse(site))
    }

    fn write_slot(
        &self,
        inst: InstId,
    ) -> Result<&Option<LegacyWriteObservation>, LegacyObservationJournalError> {
        let has_output = self
            .write_has_output
            .get(inst.0 as usize)
            .copied()
            .ok_or(LegacyObservationJournalError::InvalidWrite(inst))?;
        if !has_output {
            return Err(LegacyObservationJournalError::OutputlessWrite(inst));
        }
        self.writes
            .get(inst.0 as usize)
            .ok_or(LegacyObservationJournalError::InvalidWrite(inst))
    }

    fn write_slot_mut(
        &mut self,
        inst: InstId,
    ) -> Result<&mut Option<LegacyWriteObservation>, LegacyObservationJournalError> {
        self.write_slot(inst)?;
        Ok(&mut self.writes[inst.0 as usize])
    }
}

/// The right-hand side of an assignment statement, markers intact.
///
/// The markers are the point: the operand walk deduplicates against the value
/// cells the expression already carries, so handing it the stripped expression
/// would make it claim cells a child already owns.
fn assignment_rhs(stmt: &CStmt) -> Option<&CExpr> {
    let CStmt::Expr(expr) = stmt.unobserved() else {
        return None;
    };
    match expr.unobserved() {
        CExpr::Binary {
            op: BinaryOp::Assign,
            right,
            ..
        } => Some(right),
        _ => None,
    }
}

/// A use cell answered twice. Which site noticed is what a repair needs;
/// the error itself names only the cell.
#[track_caller]
fn conflicting_use(site: UseSite) -> LegacyObservationJournalError {
    r2il::refusal_evidence!(
        "conflicting-use",
        "{site:?} at {}",
        std::panic::Location::caller()
    );
    LegacyObservationJournalError::ConflictingUse(site)
}

#[track_caller]
fn conflicting_write(inst: InstId) -> LegacyObservationJournalError {
    r2il::refusal_evidence!(
        "conflicting-write",
        "{inst:?} at {}",
        std::panic::Location::caller()
    );
    LegacyObservationJournalError::ConflictingWrite(inst)
}

fn record_same<T: Copy + Eq>(slot: &mut Option<T>, observation: T) -> Result<(), ()> {
    match slot {
        Some(existing) if *existing != observation => Err(()),
        Some(_) => Ok(()),
        None => {
            *slot = Some(observation);
            Ok(())
        }
    }
}

fn retain_only_unanswered_refusals<T: Ord>(
    refused: &mut Vec<T>,
    elided: &BTreeMap<T, crate::ledger::ElisionReason>,
) {
    refused.retain(|cell| !elided.contains_key(cell));
}

fn classify_value_node(
    value: ValueId,
    node: RenderObservationNode<'_>,
    disposition: Option<&ValueDisposition>,
    value_is_literal: &[bool],
    symbol_bindings: &BTreeMap<SymbolId, LegacyBindingId>,
    planned_symbol: Option<SymbolId>,
) -> Result<LegacyValueObservation, LegacyObservationJournalError> {
    // A value the plan renders where it is read is classified by that
    // decision, not by the shape of what it was rendered as. The shape is not
    // evidence: a copy folded into its reader is spelled as the name it
    // copies, and an identity the rewriter collapsed is spelled as its
    // surviving operand, and neither of those is a binding of this value.
    if matches!(disposition, Some(ValueDisposition::Inline { .. })) {
        let source_literal = value_is_literal
            .get(value.0 as usize)
            .copied()
            .ok_or(LegacyObservationJournalError::InvalidValue(value))?;
        return Ok(if source_literal {
            LegacyValueObservation::InlineConstant
        } else {
            LegacyValueObservation::InlineNonLiteral
        });
    }
    // The same principle for the one elision that renders: the statement is the
    // instruction's effect rather than a spelling of the value, so the plan's
    // decision classifies it and the shape is not evidence against that.
    if matches!(
        disposition,
        Some(ValueDisposition::Elided {
            reason: crate::ledger::ElisionReason::UnreadEffectfulValue,
            ..
        })
    ) {
        return Ok(LegacyValueObservation::Elided(
            crate::ledger::ElisionReason::UnreadEffectfulValue,
        ));
    }
    let (expr, statement_level) = match node {
        RenderObservationNode::Expr(expr) => (expr.unobserved(), false),
        RenderObservationNode::Stmt(stmt) => match stmt.unobserved() {
            CStmt::Decl { name, .. } => return classify_symbol(value, *name, symbol_bindings),
            CStmt::Expr(expr) => (expr.unobserved(), true),
            CStmt::Return(Some(expr)) => (expr.unobserved(), false),
            _ => return Ok(LegacyValueObservation::InlineNonLiteral),
        },
    };
    // Through casts and parentheses. Converting a value or bracketing it does
    // not change which object was named, so `x` and `(uint64_t)x` are one
    // binding read twice. Classifying the second by its outermost node called
    // it an inline expression, one value then collected two classifications,
    // and the seal refused with `ConflictingValue` -- which is what a
    // redundant cast disappearing would otherwise cause.
    //
    // The name this occurrence renders the value as, where it renders one.
    let rendered_symbol = named_object_of(expr).or_else(|| match expr {
        CExpr::Binary { op, left, .. }
            if *op == BinaryOp::Assign
                || (statement_level
                    && matches!(
                        op,
                        BinaryOp::AddAssign
                            | BinaryOp::SubAssign
                            | BinaryOp::MulAssign
                            | BinaryOp::DivAssign
                            | BinaryOp::ModAssign
                            | BinaryOp::BitAndAssign
                            | BinaryOp::BitOrAssign
                            | BinaryOp::BitXorAssign
                            | BinaryOp::ShlAssign
                            | BinaryOp::ShrAssign
                    )) =>
        {
            match left.unobserved() {
                CExpr::Var(symbol) => Some(*symbol),
                _ => None,
            }
        }
        _ => None,
    });
    // A rendered name must own a declaration wherever one is rendered. That
    // is a statement about the C a reader gets, it is what
    // `UnownedBindingSymbol` answers, and it is asked of every occurrence
    // that names something.
    let rendered = rendered_symbol
        .map(|symbol| classify_symbol(value, symbol, symbol_bindings))
        .transpose()?;
    // Which value an occurrence *is* is the plan's answer and not the
    // rendering's, for the same reason a value the plan inlines is already
    // exempt above: the shape is not evidence. One value is read at several
    // places and the renderer spells each read as that place requires -- `x`
    // here, `!x` inside a condition the structurer negated -- so recovering
    // the identity from each spelling makes it a function of the C, which is
    // the thing being decided. Two spellings then give one value two
    // identities and the seal refuses with `ConflictingValue`.
    //
    // The occurrence must still *mention* the name the plan gave the value.
    // That is the difference between a marker sitting one node out from the
    // name it marks, which says nothing about identity, and a rendering that
    // contradicts the plan by spelling a bound value as a constant. The
    // second is a defect and stays a conflict.
    if let Some(ValueDisposition::Bound { .. }) = disposition
        && let Some(planned) = planned_symbol
        && expr_mentions_symbol(expr, planned)
    {
        return classify_symbol(value, planned, symbol_bindings);
    }
    if let Some(rendered) = rendered {
        return Ok(rendered);
    }
    let source_literal = value_is_literal
        .get(value.0 as usize)
        .copied()
        .ok_or(LegacyObservationJournalError::InvalidValue(value))?;
    if source_literal
        && matches!(
            expr,
            CExpr::IntLit(_)
                | CExpr::UIntLit(_)
                | CExpr::FloatLit(..)
                | CExpr::StringLit(_)
                | CExpr::CharLit(_)
        )
    {
        Ok(LegacyValueObservation::InlineConstant)
    } else {
        Ok(LegacyValueObservation::InlineNonLiteral)
    }
}

/// Whether this expression reads `symbol` anywhere inside it.
fn expr_mentions_symbol(expr: &CExpr, symbol: SymbolId) -> bool {
    let mut found = false;
    expr.visit(&mut |node| {
        if !found && matches!(node, CExpr::Var(named) if *named == symbol) {
            found = true;
        }
    });
    found
}

/// The object a rendered expression names, seen through conversions that do
/// not change which object that is.
fn named_object_of(expr: &CExpr) -> Option<SymbolId> {
    match expr {
        CExpr::Var(symbol) => Some(*symbol),
        CExpr::Cast { expr, .. } | CExpr::Paren(expr) => named_object_of(expr.unobserved()),
        _ => None,
    }
}

fn classify_symbol(
    value: ValueId,
    symbol: SymbolId,
    symbol_bindings: &BTreeMap<SymbolId, LegacyBindingId>,
) -> Result<LegacyValueObservation, LegacyObservationJournalError> {
    let binding = symbol_bindings
        .get(&symbol)
        .copied()
        .ok_or(LegacyObservationJournalError::UnownedBindingSymbol { value, symbol })?;
    Ok(LegacyValueObservation::Bound { binding })
}

fn declared_legacy_bindings(function: &CFunction) -> BTreeMap<SymbolId, LegacyBindingId> {
    let mut bindings = BTreeMap::new();
    let mut mark = |symbol: SymbolId| {
        if !bindings.contains_key(&symbol) {
            let index = u32::try_from(bindings.len())
                .expect("a SymbolId-indexed table cannot exceed the legacy binding domain");
            bindings.insert(symbol, LegacyBindingId(index));
        }
    };
    for param in &function.params {
        mark(param.name);
    }
    for local in &function.locals {
        mark(local.name);
    }
    for stmt in &function.body {
        visit_stmt_declarations(stmt, &mut mark);
    }
    bindings
}

fn visit_stmt_declarations(stmt: &CStmt, visit: &mut impl FnMut(SymbolId)) {
    match stmt.unobserved() {
        CStmt::Decl { name, .. } => visit(*name),
        CStmt::Block(stmts) => {
            for stmt in stmts {
                visit_stmt_declarations(stmt, visit);
            }
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            visit_stmt_declarations(then_body, visit);
            if let Some(else_body) = else_body {
                visit_stmt_declarations(else_body, visit);
            }
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            visit_stmt_declarations(body, visit);
        }
        CStmt::StructuredRegion { stmt, .. } => visit_stmt_declarations(stmt, visit),
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                visit_stmt_declarations(init, visit);
            }
            visit_stmt_declarations(body, visit);
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                for stmt in &case.body {
                    visit_stmt_declarations(stmt, visit);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    visit_stmt_declarations(stmt, visit);
                }
            }
        }
        CStmt::Observed { .. } => unreachable!("unobserved statement returned a wrapper"),
        CStmt::Expr(_)
        | CStmt::Return(_)
        | CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
    }
}

/// The stack object a load reads, when it reads exactly one.
///
/// A load whose value shares its object's binding says `x = x`, and the object
/// is what says which binding to compare it against.
fn stored_stack_object(
    source: &SsaArtifact,
    graph: &r2ssa::SsaGraph,
    inst: InstId,
) -> Option<r2ssa::ObjectId> {
    accessed_stack_object(source, graph, inst, true)
}

fn loaded_stack_object(
    source: &SsaArtifact,
    graph: &r2ssa::SsaGraph,
    inst: InstId,
) -> Option<r2ssa::ObjectId> {
    accessed_stack_object(source, graph, inst, false)
}

fn accessed_stack_object(
    source: &SsaArtifact,
    graph: &r2ssa::SsaGraph,
    inst: InstId,
    is_write: bool,
) -> Option<r2ssa::ObjectId> {
    // By op site, never by the instruction's ordinal: an ordinal counts the
    // block's phis first, so in a merge block the two differ and this lands on
    // another op's read.
    let (block_addr, op_idx) = graph.op_site_for_inst(inst)?;
    let accesses = source
        .certificates()
        .memory_accesses_by_op
        .get(&(block_addr, op_idx, is_write))?;
    let [access] = accesses.as_slice() else {
        return None;
    };
    let access = source.certificates().memory_accesses.get(access)?;
    // Another space is another object entirely; the caller's binding check
    // then rejects it, but saying so here keeps the question in one place.
    (access.space == r2il::SpaceId::Ram).then_some(access.object)
}

/// Every type a declaration statement in this body introduces.
/// What the type graph says a name stands for, when it says anything.
///
/// A name that resolves to itself stands for nothing: `source_type_like`
/// spells a named aggregate by its tag, so this is the shape where the graph
/// held a name and no structure behind it.
fn named_type_target(graph: &r2ssa::SourceTypeGraph, name: &str) -> Option<r2types::CTypeLike> {
    let alias = graph.aliases().iter().find(|alias| alias.name() == name)?;
    let mut visiting = std::collections::BTreeSet::new();
    // The projection spells this type by its own name, which is the name being
    // declared; the declaration needs what stands behind it.
    match r2types::source_type_like(graph, alias.type_id(), &mut visiting)? {
        r2types::CTypeLike::Typedef { name: other, ty } if other == *name => match ty.as_ref() {
            r2types::CTypeLike::Unknown => None,
            resolved => Some(resolved.clone()),
        },
        target => Some(target),
    }
}

/// Every struct or union tag a spelled type names, at any depth.
///
/// The value says which keyword introduced it, because a tag is spelled with
/// the one the program used and `union` is not interchangeable with `struct`.
fn collect_tag_spellings(
    ty: &crate::ast::CType,
    out: &mut std::collections::BTreeMap<String, bool>,
) {
    match ty {
        r2types::CTypeLike::Struct(name) => {
            out.insert(name.clone(), false);
        }
        r2types::CTypeLike::Union(name) => {
            out.insert(name.clone(), true);
        }
        r2types::CTypeLike::Typedef { ty, .. }
        | r2types::CTypeLike::Pointer(ty)
        | r2types::CTypeLike::Array(ty, _) => collect_tag_spellings(ty, out),
        r2types::CTypeLike::Function { ret, params } => {
            collect_tag_spellings(ret, out);
            params
                .iter()
                .for_each(|param| collect_tag_spellings(param, out));
        }
        _ => {}
    }
}

/// Spell a name that is one of this rendering's tags as that tag.
fn resolve_tag_spelling(
    ty: &mut crate::ast::CType,
    tags: &std::collections::BTreeMap<String, bool>,
) {
    match ty {
        r2types::CTypeLike::Typedef { name, ty: target }
            if matches!(target.as_ref(), r2types::CTypeLike::Unknown) =>
        {
            match tags.get(name.as_str()) {
                Some(true) => *ty = r2types::CTypeLike::Union(name.clone()),
                Some(false) => *ty = r2types::CTypeLike::Struct(name.clone()),
                None => {}
            }
        }
        r2types::CTypeLike::Typedef { ty, .. }
        | r2types::CTypeLike::Pointer(ty)
        | r2types::CTypeLike::Array(ty, _) => resolve_tag_spelling(ty, tags),
        r2types::CTypeLike::Function { ret, params } => {
            resolve_tag_spelling(ret, tags);
            params
                .iter_mut()
                .for_each(|param| resolve_tag_spelling(param, tags));
        }
        _ => {}
    }
}

/// Every typedef name a spelled type mentions, at any depth.
/// Whether this spelling is a type the language already defines.
fn name_is_a_c_builtin_type(name: &str) -> bool {
    matches!(
        name,
        "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "void"
            | "signed"
            | "unsigned"
            | "_Bool"
            | "bool"
    )
}

fn collect_named_types(ty: &crate::ast::CType, out: &mut Vec<(String, crate::ast::CType)>) {
    match ty {
        r2types::CTypeLike::Typedef { name, ty } => {
            out.push((name.clone(), ty.as_ref().clone()));
            collect_named_types(ty, out);
        }
        r2types::CTypeLike::Pointer(inner) | r2types::CTypeLike::Array(inner, _) => {
            collect_named_types(inner, out);
        }
        r2types::CTypeLike::Function { ret, params } => {
            collect_named_types(ret, out);
            params
                .iter()
                .for_each(|param| collect_named_types(param, out));
        }
        _ => {}
    }
}

/// Emit one name after every name it is declared through.
///
/// The graph is acyclic: a name's target comes from the type it was minted
/// over, which was built before it.
/// The words a C implementation defines a standard name with.
///
/// `size_t` is `unsigned long` wherever a long is as wide as an address and
/// `unsigned long long` where it is not, and `ptrdiff_t` is the signed one
/// beside it. Both are distinct types from the fixed-width names however equal
/// their widths, so a declaration of a library function that spells one as
/// `uint64_t` is incompatible with the compiler's own and is rejected. The
/// width the capture carried still has to agree: a 32-bit `size_t` on a 64-bit
/// address model is radare2 describing a different program, and it keeps its
/// own spelling.
fn standard_type_spelling(
    name: &str,
    target: &crate::ast::CType,
    address_bits: u32,
) -> Option<&'static str> {
    let long_is_an_address = address_bits == 64;
    let width = r2types::declaration_type_width_bits(target, address_bits)?;
    if width != address_bits {
        return None;
    }
    Some(match (name, long_is_an_address) {
        ("size_t" | "uintptr_t", true) => "unsigned long",
        ("size_t" | "uintptr_t", false) => "unsigned int",
        ("ssize_t" | "ptrdiff_t" | "intptr_t", true) => "long",
        ("ssize_t" | "ptrdiff_t" | "intptr_t", false) => "int",
        _ => return None,
    })
}

fn place_typedef(
    name: &str,
    targets: &std::collections::BTreeMap<String, crate::ast::CType>,
    placed: &mut std::collections::BTreeSet<String>,
    out: &mut Vec<crate::ast::CTypedefDef>,
    address_bits: u32,
) {
    let Some(target) = targets.get(name) else {
        return;
    };
    if !placed.insert(name.to_string()) {
        return;
    }
    let mut dependencies = Vec::new();
    collect_named_types(target, &mut dependencies);
    for (dependency, _) in dependencies {
        place_typedef(&dependency, targets, placed, out, address_bits);
    }
    out.push(crate::ast::CTypedefDef {
        name: name.to_string(),
        target: target.clone(),
        spelling: standard_type_spelling(name, target, address_bits).map(str::to_string),
    });
}

fn collect_declared_types(body: &[CStmt], out: &mut Vec<crate::ast::CType>) {
    fn walk(stmt: &CStmt, out: &mut Vec<crate::ast::CType>) {
        match stmt {
            CStmt::Decl { ty, .. } => out.push(ty.clone()),
            CStmt::Block(stmts) => stmts.iter().for_each(|child| walk(child, out)),
            CStmt::Observed { stmt, .. } | CStmt::StructuredRegion { stmt, .. } => walk(stmt, out),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                walk(then_body, out);
                if let Some(body) = else_body {
                    walk(body, out);
                }
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => walk(body, out),
            CStmt::For { init, body, .. } => {
                if let Some(init) = init {
                    walk(init, out);
                }
                walk(body, out);
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    case.body.iter().for_each(|child| walk(child, out));
                }
                if let Some(default) = default {
                    default.iter().for_each(|child| walk(child, out));
                }
            }
            _ => {}
        }
    }
    body.iter().for_each(|stmt| walk(stmt, out));
}
