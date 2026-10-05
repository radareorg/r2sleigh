//! SSA (Static Single Assignment) form for r2il.
//!
//! This crate provides SSA transformation for r2il blocks, enabling
//! dataflow analysis and optimizations.
//!
//! ## Modules
//!
//! - [`block`]: Single-block SSA conversion
//! - [`cfg`](mod@cfg): Control flow graph representation
//! - [`defuse`]: Def-use chain analysis
//! - [`domtree`]: Dominator tree computation
//! - [`function`]: Function-level SSA with phi nodes
//! - [`op`]: SSA operation types
//! - [`phi`]: Phi-node placement algorithm
//! - [`rename`]: SSA renaming algorithm
//! - [`var`]: SSA variable representation

// A fact about a function's values, instructions or blocks is an index over
// their dense ids (doc/adr-one-ir.md, ROADMAP D11). The exceptions say why
// at the item that keeps one.
#![cfg_attr(dylint_lib = "r2sleigh_lints", deny(entity_keyed_map))]

pub(crate) mod abi;
pub(crate) mod address;
pub(crate) mod aggregate_access;
pub mod arena;
pub(crate) mod assumption;
pub mod block;
pub(crate) mod bytes;
pub mod cfg;
pub(crate) mod constant;
pub(crate) mod control;
pub(crate) mod deadphi;
pub(crate) mod defuse;
pub(crate) mod demand;
pub mod dense;
pub mod domtree;
pub mod fate;
pub mod fixpoint;
pub mod function;
pub mod graph;
pub mod indirect;
pub(crate) mod integrity;
pub mod interproc;
pub mod lanes;
pub mod liveness;
pub(crate) mod liveout;
pub(crate) mod machine;
pub(crate) mod machine_context;
pub(crate) mod mirror;
pub mod name;
mod naming;
pub mod natural_loops;
pub(crate) mod obligation;
pub(crate) mod op;
pub(crate) mod optimize;
pub mod origin;
pub(crate) mod phi;
pub(crate) mod printf;
pub(crate) mod promote;
pub(crate) mod reaching_rules;
pub mod recover_interface;
pub(crate) mod rename;
pub(crate) mod semantic;
mod slice;
pub mod span;
mod strided;
#[cfg(test)]
pub(crate) mod testing;
pub mod value_table;
mod values;
pub(crate) mod var;
pub mod view;

pub use abi::AbiProfile;
pub use address::{
    AddressProvenanceFacts, AffineAddressTerm, ParameterAddressExpression,
    PointeeAddressExpression, PointeeStep,
};
pub use aggregate_access::{
    AGGREGATE_ACCESS_PROJECTION_SCHEMA_VERSION, AggregateAccessBinding, AggregateAccessProjection,
    AggregateAccessProjectionFacts, AggregateElementIndexProjection,
};
pub use arena::{OpArena, OpId, OpOrigin, OpSlot, Pass};
pub use assumption::{
    AnalysisAssumption, AnalysisAssumptionConflict, AssumptionProvenance, AssumptionScope,
    AssumptionSet, AssumptionSubject, AssumptionUsageReport, AssumptionValue,
};
pub use block::{BlockMut, SSABlock, branch_condition};
pub use cfg::{BasicBlock, BlockTerminator, CFG, CFGEdge, DeclaredSuccessors};
pub use control::{
    SsaCancellationToken, SsaExecutionControl, SsaExecutionStopReason, SsaPrepareError,
    SsaWorkControl, SsaWorkMeter,
};
pub use defuse::{DefUseInfo, def_use};
pub use function::{
    CFGRiskSummary, CalleeEvidence, CalleePreservedCarriers, DecompileInputs, DecompilePrepFacts,
    DefRef, DefSite, GenuineNativeInstructionSpan, Lifted, NamedBlockMut, PhiNode, Prepared,
    RegisterFamilyInfo, RegisterFamilySlot, RegisterIdentityCensus, RewrittenFunction,
    SSABlock as FunctionSSABlock, SSAFunction, Sealed, SourceRef, SourceSite, SsaArtifact,
    SsaArtifactAuthority, SsaArtifactProvenanceKind, StackAddressBase, StackAddressRoot,
    TrustedSsaArtifact, def_use_graph,
};
pub use graph::{
    BlockId, GraphBlock, GraphInst, GraphValue, InstId, InstPayload, SsaGraph, UseSite, ValueId,
};
pub use integrity::{ScalarWidthRule, SsaIntegrityError, SsaValueSite, validate_ssa_function};
pub use interproc::{
    ArgumentReach, CallArgObservation, FunctionSemanticLinkage, FunctionSemanticSummary,
    InterprocFunctionId, InterprocFunctionInput, InterprocSummaryDiagnostics, InterprocSummarySet,
    PreparedCalleeSummary, PreparedInterprocFunctionInput, PreparedInterprocSummaryError,
    PreparedInterprocSummarySet, SummaryAllocationEffect, SummaryArgEffect, SummaryArgumentReach,
    SummaryAtomicEffect, SummaryAtomicOp, SummaryAtomicOrdering, SummaryLifetimeEffect,
    SummaryLifetimeOp, SummaryMemoryEffect, SummaryMemoryEffectKind, SummaryMemoryLocation,
    SummaryMemoryRange, SummaryMemoryRegion, SummaryReturnRelation, SummarySyncEffect,
    SummarySyncOp, SummaryTransferEffect, SummaryTransferLength, observe_call_arguments,
    solve_interproc_summary_set, solve_prepared_interproc_summary_set,
    solve_prepared_interproc_summary_set_from_callee_summaries,
};
pub use machine::{
    MachineAddressProvenance, MachineAddressSpace, MachineArithmeticFlagOp, MachineArithmeticMode,
    MachineArithmeticOp, MachineBitVector, MachineBitwiseOp, MachineBooleanOp, MachineBuildError,
    MachineCastKind, MachineComparisonOp, MachineDirectValueGeometry, MachineEntity, MachineExpr,
    MachineExprArena, MachineExprId, MachineExprKind, MachineFloatOp, MachineFloatUnaryOp,
    MachineFunction, MachineOvershiftBehavior, MachineProjection, MachineProjectionFailure,
    MachineRegisterValueGeometry, MachineShiftKind, MachineSignedness, MachineStackBase,
    MachineType, MachineUseConversion, MachineUseDisposition, MachineUseRefusal, MachineUseSlice,
    MachineValueBinding, MachineValueGeometryDisposition, MachineValueGeometryRefusal,
    MachineValueUse, MachineWriteDisposition, MachineWriteProjection, MachineWriteRefusal,
    MachineZeroDivisorBehavior, float_width_is_supported, machine_address_provenance,
};
pub use machine_context::{
    MACHINE_CONTEXT_SCHEMA_VERSION, MachineAbiModel, MachineAbiRegisterSlot,
    MachineArchitectureFamily, MachineMemoryEndianness, MachineMemoryModel, MachineMemorySpace,
    MachineRegisterGeometryState, SOURCE_CALL_SITE_INTERFACE_SCHEMA_VERSION,
    SOURCE_FUNCTION_INTERFACE_SCHEMA_VERSION, SOURCE_TYPE_GRAPH_SCHEMA_VERSION, SourceAbiClass,
    SourceAbiParameterSpec, SourceAggregateLayout, SourceAggregateMember, SourceBoundaryReads,
    SourceCallArgumentSpec, SourceCallEffect, SourceCallResult, SourceCallSiteIdentity,
    SourceCallSiteInterface, SourceCallSiteInterfaceError, SourceCarrierKind,
    SourceCarrierProjection, SourceCodeSignature, SourceConventionSlots, SourceFormatParameterRule,
    SourceFunctionInterface, SourceFunctionInterfaceError, SourceFunctionReturn,
    SourceLogicalValue, SourceMachineContext, SourceMachineRoles, SourceMachineRolesError,
    SourceOpaqueTag, SourceParameterLocation, SourceStackAllocationContract, SourceStackGrowth,
    SourceStackSlotRole, SourceStackSlotSpec, SourceTagKeyword, SourceType, SourceTypeAlias,
    SourceTypeClosure, SourceTypeGraph, SourceTypeGraphError, SourceTypeGraphParts, SourceTypeKind,
    terminal_indirect_loaded_slot,
};
pub use obligation::{
    CanonicalInstructionId, CanonicalInstructionSite, ObligationInventoryFailure,
    ObligationInventoryFailureKind, SEMANTIC_OBLIGATION_SCHEMA_VERSION,
    SemanticInstructionDisposition, SemanticInstructionState, SemanticMemoryOrdering,
    SemanticObligation, SemanticObligationComponent, SemanticObligationId,
    SemanticObligationInventory, SemanticObligationKind, SemanticSourceSite, SpelledInstruction,
    SpelledObligation,
};
pub use op::{AtomicCasOp, BlockTransferOp, InsertOp, SSAOp, SelectOp};
pub use optimize::{DecompilePrepConfig, OptimizationConfig, OptimizationStats};
pub use promote::promoted_slot_offset;
pub use r2sleigh_lift::{
    GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION, GenuineLiftedFunction, GenuineLiftedFunctionAuthority,
    TrustedLiftedFunction,
};
pub use r2source::OwnedFunctionSnapshot;
pub use semantic::{
    BlockAssumption, CallArgumentCertificate, CallArgumentLocation, CallBoundarySlot,
    CallBoundaryValueFact, CallFrameReach, CallMemoryEffect, CallResultCertificate,
    CallResultValueRelation, CallSiteFact, CallSiteFacts, CallSiteId, CallSiteTransfer,
    CalleeStackAllocationCertificate, CallsiteCertificate, CompareKind, CompareProvenance,
    ControlDomain, ControlDomainFacts, ControlDomainId, ControlGuard, EntryAffineForm,
    ForLoopCertificate, FrameReach, GlobalObjectKey, IfRegionCertificate, InductionFact,
    InductionStep, LoopCarrierEdgeValue, LoopCarrierFact, LoopCarrierMemberFact,
    LoopCarrierMemberRole, LoopCarrierUpdateFact, LoopCertificate, LoopId, LoopTrips,
    MachineReturnControlCertificate, MemberRunPlace, MemberRunSource, MemberRunStoreCertificate,
    MemberRunStoreMember, MemoryAccessCertificate, MemoryDefFact, MemoryLocation, MemoryObjectKey,
    MemoryPhiFact, MemorySSAFacts, MemoryUseFact, MemoryVersion, ObjectFact, ObjectId, ObjectKind,
    ObjectModel, ObjectSpaceId, ParameterObjectKey, PredicateFact, PredicateFacts, PredicateId,
    PreparedAssumptionBinding, PreparedAssumptionBindingKind, PreparedFunctionCertificates,
    PreparedFunctionFacts, PreparedProofFailure, ProofNodeId, RelativeMemoryAddress, ReturnCarrier,
    ReturnValueCertificate, SemanticId, SourceBoundaryFacts, SourceCallArgumentFact,
    SourceCallArgumentValue, SourceCallBoundaryFact, SourceFormalParameterFact,
    SourceReturnAddressFact, SourceReturnBoundaryFact, SourceReturnStackPointerFact,
    StackArrayElementCertificate, StackArrayElementIndex, StackArrayLayoutCertificate,
    StackArrayLayoutDisposition, StackArrayLayoutRefusal, StackFrameRoundTripCertificate,
    StackGeometryCertificate, StackObjectKey, StackSlotCertificate, StructuredAccessId,
    StructuredDataflowFacts, StructuredLoopFact, StructuredLoopKind, StructuredMemoryAccessFact,
    StructuredRecursiveCallFact, SupervisorCall, SwitchCertificate, SwitchGuardCertificate,
    SwitchPredicateFact, TripCount, TripGuard, TripRefusal, TripTest, TwoWaySelectionCertificate,
    ValueOwner, VariadicCallsiteArgumentCountEvidence, VariadicCallsiteArgumentCountRefusal,
    value_reaching,
};
pub use slice::{Slice, SliceError, SliceSeed, backward_slice, resolve_slice_seed};
pub use strided::StridedInterval;
pub use value_table::{ValueTable, VarId};
pub use values::{InstructionBound, ValueRanges, instruction_bound, solve_value_ranges};
pub use var::{CanonicalStorageId, CanonicalStorageSpace, SSAVar, SSAVarNameKind};
pub use view::{Representative, ValueView, ValueViews, ViewExtension, ViewRelation};
