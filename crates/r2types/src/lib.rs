pub mod constraint;
pub mod convert;
pub mod external;
pub mod facts;
pub mod inference;
pub mod lattice;
pub mod model;
pub mod oracle;
pub mod signature;
pub mod solver;

pub use constraint::{Constraint, ConstraintSource, MemoryCapability};
pub use convert::{CTypeLike, to_c_type_like};
pub use external::{
    ExternalEnum, ExternalField, ExternalStruct, ExternalTypeDb, ExternalUnion,
    normalize_external_type_name,
};
pub use facts::{
    FunctionParamSpec, FunctionSignatureSpec, FunctionType, FunctionTypeFactInputs,
    FunctionTypeFacts, FunctionTypeFactsBuilder, LocalFieldAccessFact, ResolvedFieldLayout,
    parse_type_like_spec,
};
pub use inference::{CombinedTypeOracle, ExternalStackVarSpec, TypeInference};
pub use model::{Signedness, StructField, StructShape, Type, TypeArena, TypeId};
pub use oracle::{LayoutOracle, TypeOracle};
pub use signature::{ResolvedSignature, SignatureRegistry};
pub use solver::{SolvedTypes, SolverConfig, SolverDiagnostics, TypeSolver};
