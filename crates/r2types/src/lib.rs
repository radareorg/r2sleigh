// A fact about a function's values, instructions or blocks is an index over
// their dense ids (doc/adr-one-ir.md, ROADMAP D11). The exceptions say why
// at the item that keeps one.
#![cfg_attr(dylint_lib = "r2sleigh_lints", deny(entity_keyed_map))]
#![cfg_attr(dylint_lib = "r2sleigh_lints", deny(scan_in_loop))]

pub(crate) mod aggregates;
pub(crate) mod analysis;
pub(crate) mod callee;
pub(crate) mod constraint;
pub(crate) mod context;
pub(crate) mod convert;
pub(crate) mod evidence;
pub(crate) mod facts;
pub mod function_facts;
pub(crate) mod lattice;
pub(crate) mod model;
pub(crate) mod prepare;
pub(crate) mod signature_infer;
mod signedness;
pub(crate) mod solver;

pub(crate) use facts::{
    SignatureCertificate, is_generic_signature_type, signature_param_count_is_authoritative,
    signature_param_name_is_weak, signature_projection_is_exact,
};

pub use callee::{
    CalleeClass, CalleeIdentity, CalleeIdentityContext, CalleeIdentityKey, CalleeResolutionFacts,
    CalleeTargetIdentityRequest, CalleeTargetResolutionRequest, ResolvedCalleeTarget,
    normalize_callee_name,
};
pub use constraint::{Constraint, ConstraintSource, SolverNode};
pub(crate) use signature_infer::{infer_signature_from_prepared_ssa, render_signature_type};
pub use solver::{SolvedTypes, solve_constraints};

pub use context::{
    ParsedExternalContext, ProgramExtents, is_generic_arg_name, sanitize_c_identifier,
};
pub use convert::{
    CTypeLike, bit_vector_tag, c_object_declaration, source_type_like, spellable_c_type_like,
    spelling_names_a_type, spells_its_structure,
};
pub use data_object::{
    DataObjectTypeFact, DataObjectTypeProvenance, DataObjectTypeRefusal, ProgramDataObjectTypeFacts,
};
pub use evidence::{DeclaredBound, EvidenceTypes};
pub use facts::{
    CalleeFact, CalleeLinkage, CalleeModelPolicyEvidence, CalleeReturnRelation,
    FieldAccessCertificate, FunctionParamSpec, FunctionSignatureSpec, FunctionType,
    FunctionTypeFacts, ParameterStructure, SignatureCertificateSource,
};
pub(crate) use function_facts::exact_source_return_type;
pub use function_facts::{
    AggregateDefinition, AggregateDefinitions, ArrayAccessRenderFact, BranchPredicateFact,
    CallArgumentValueFact, CallResultFact, CallsiteArgumentFacts, CallsiteRenderDisposition,
    CallsiteRenderFact, CertifiedEntity, ControlBlockAssumptionFact, DecompileRouteFacts,
    DecompileRouteKind, FunctionCallRenderFacts, FunctionCallResultFacts, FunctionCallsiteFacts,
    FunctionControlFacts, FunctionFacts, FunctionInputQualityFacts, FunctionRenderFacts,
    ImportStub, InterprocSummaryView, MemoryAccessRenderFact, PredicateComparisonFact,
    RegisterCallArgumentLocationFact, ReturnTypeEvidence, ReturnTypeFact, ReturnTypeRefusal,
    ReturnValueRenderFact, SourceOwnedCalleeSignature, SourceOwnedFunctionFacts,
    StackCallArgumentLocationFact, UnprovenCause, admissible_declaration_type,
    admit_declaration_type, declaration_type_width_bits, unread_slot,
};
pub use parameter_types::{
    IntegerDecl, ParameterType, ParameterTypes, PointerRefusal, SignFact, SlotType, UNSTATED_WORD,
    is_unstated_word, unstated_word, word_free,
};

pub use model::{Signedness, Type};
pub use r2source::DisplayNames;
pub use r2ssa::AssumptionUsageReport;

pub use analysis::{
    DecompileFinalization, FinalizationRefused, TypeAnalysis, TypeAnalysisError,
    TypeAnalysisRequest, build_source_owned_type_analysis,
};

mod data_object;
mod parameter_types;
