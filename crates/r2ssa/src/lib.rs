//! SSA (Static Single Assignment) form for r2il.
//!
//! This crate provides SSA transformation for r2il blocks, enabling
//! dataflow analysis and optimizations.

pub mod block;
pub mod defuse;
pub mod op;
pub mod var;

pub use block::SSABlock;
pub use defuse::{DefUseInfo, def_use};
pub use op::SSAOp;
pub use var::SSAVar;
