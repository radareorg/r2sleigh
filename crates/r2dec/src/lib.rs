//! r2dec: the C renderer of r2sleigh (doc/adr-decompiler-rewrite.md).
//!
//! `render::render` writes one function from its sealed facts: the control
//! (`structure`), the values and terms (`render`), and the certified emitter
//! (`codegen`); every obligation is answered in a `ledger`.

pub mod ast;
pub mod bitvector;
pub(crate) mod certified;
pub(crate) mod codegen;
pub mod control;
pub(crate) mod debug;
pub mod ledger;
pub mod prelude;
pub mod render;
pub mod report;
pub mod structure;
pub mod symbol;

pub use crate::codegen::RenderedFunction;
pub use crate::codegen::{CRole, CRoles, Emission, ResidualSite, SourceLine};
pub use crate::ledger::{EffectObligationAudit, EffectObligationDisposition};
pub use crate::render::rendered_name_of;
pub use ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
pub use codegen::CodeGenConfig;
pub use control::{DecompileExecutionStop, DecompileWorkControl, DecompileWorkPhase};
