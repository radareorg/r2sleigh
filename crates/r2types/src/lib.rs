pub(crate) mod analysis;
pub(crate) mod callee;
pub(crate) mod constraint;
pub(crate) mod context;
pub(crate) mod convert;
pub(crate) mod evidence;
pub(crate) mod external;
pub(crate) mod facts;
pub mod function_facts;
pub(crate) mod lattice;
pub(crate) mod model;
pub(crate) mod oracle;
pub(crate) mod prepare;
mod register_identity;
pub(crate) mod signature;
pub(crate) mod signature_infer;
mod signedness;
pub(crate) mod solver;

pub fn parse_external_type_like_spec(spec: &str, ptr_bits: u32) -> Option<CTypeLike> {
    convert::parse_c_type_like(spec, ptr_bits)
}

pub(crate) use evidence::solve_evidence_types;
pub(crate) use external::ExternalAggregateKind;
pub(crate) use facts::{
    SIGNATURE_PROJECTION_STRONG_CONFIDENCE, SignatureCertificate, is_generic_signature_type,
    signature_hint_can_replace_existing, signature_param_count_is_authoritative,
    signature_param_name_is_weak, signature_projection_is_exact,
    signature_return_hint_can_replace_existing, signature_strength,
    summary_hint_can_replace_weak_existing,
};

pub use callee::{
    CalleeClass, CalleeIdentity, CalleeIdentityContext, CalleeIdentityKey, CalleeResolutionFacts,
    CalleeTargetIdentityRequest, CalleeTargetResolutionRequest, CallsiteKey, ResolvedCalleeTarget,
    normalize_callee_name,
};
pub use constraint::{Constraint, ConstraintSource, MemoryCapability, SolverNode};
pub(crate) use register_identity::RegisterIdentity;
pub(crate) use signature::SignatureRegistry;
pub(crate) use signature_infer::{
    format_signature_prototype, infer_signature_from_prepared_ssa,
    inferred_signature_from_signature_spec, render_signature_type,
};
pub use solver::{SolvedTypes, SolverConfig, SolverDiagnostics, TypeSolver};

pub use context::{
    ExternalStackBase, ExternalStackSlotRole, ExternalStackSlotSpec, ParsedExternalContext,
    ProgramExtents, StackSlotKey, is_generic_arg_name, parse_external_context_json,
    sanitize_c_identifier,
};
pub use convert::{
    CTypeLike, c_object_declaration, parse_c_type_like, spellable_c_type_like,
    spelling_names_a_type,
};
pub use data_object::{
    DataObjectTypeFact, DataObjectTypeProvenance, DataObjectTypeRefusal, ProgramDataObjectTypeFacts,
};
pub use evidence::EvidenceTypes;
pub use external::{ExternalField, ExternalStruct, ExternalTypeDb, normalize_external_type_name};
pub use facts::{
    CalleeFact, CalleeLinkage, CalleeModelPolicyEvidence, CalleeReturnRelation,
    FieldAccessCertificate, FunctionParamSpec, FunctionSignatureSpec, FunctionType,
    FunctionTypeFacts, SignatureCertificateSource, VisibleBinding, VisibleBindingKind,
};
pub use function_facts::{
    ArrayAccessRenderFact, BranchPredicateFact, CallArgumentValueFact, CallResultFact,
    CallsiteArgumentFacts, CallsiteRenderDisposition, CallsiteRenderFact, CertifiedEntity,
    ControlBlockAssumptionFact, DecompileRouteFacts, DecompileRouteKind, ExpressionRenderFact,
    FunctionCallRenderFacts, FunctionCallResultFacts, FunctionCallsiteFacts, FunctionControlFacts,
    FunctionFacts, FunctionInputQualityFacts, FunctionRenderFacts, InterprocSummaryView,
    MemberAccessRenderFact, MemberAccessSource, MemoryAccessRenderFact, PredicateComparisonFact,
    RegisterCallArgumentLocationFact, ReturnValueRenderFact, SourceOwnedCalleeSignature,
    SourceOwnedFunctionFacts, StackCallArgumentLocationFact, admit_declaration_type,
    aggregate_is_definable, declaration_type_width_bits, exact_source_return_type,
};

pub use model::{Signedness, Type};
pub use oracle::TypeOracle;
pub use prepare::{
    MetadataScalarKind, TypeHint, merge_type_hint, recover_signature_params_from_ssa,
    type_hint_from_value_metadata,
};
pub use r2source::DisplayNames;
pub use r2ssa::AssumptionUsageReport;

pub use analysis::{
    DecompileFinalization, TypeAnalysis, TypeAnalysisError, TypeAnalysisRequest,
    build_source_owned_type_analysis, source_type_like,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_type(bits: u32) -> CTypeLike {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Signed,
        }
    }

    fn unsigned_type(bits: u32) -> CTypeLike {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        }
    }

    fn ptr_type(inner: CTypeLike) -> CTypeLike {
        CTypeLike::Pointer(Box::new(inner))
    }

    #[test]
    fn parse_external_type_like_spec_normalizes_radare2_type_names() {
        assert_eq!(
            parse_external_type_like_spec("type.int", 64),
            Some(signed_type(32))
        );
        assert_eq!(
            parse_external_type_like_spec("type.uint16_t *", 64),
            Some(ptr_type(unsigned_type(16)))
        );
        assert_eq!(
            parse_external_type_like_spec("struct.sla_node *", 64),
            Some(ptr_type(CTypeLike::Struct("sla_node".to_string())))
        );
        assert_eq!(
            parse_external_type_like_spec("type.IOCPU_VTable.setCPUNumber", 64),
            None
        );
        assert_eq!(
            parse_external_type_like_spec("type.intptr_t", 64),
            Some(signed_type(64))
        );
    }
}
mod data_object;
