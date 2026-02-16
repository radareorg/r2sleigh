pub(crate) mod arch;
pub(crate) mod context;
pub(crate) mod flags;
pub(crate) mod op_lower;
pub(crate) mod stack;

pub use context::FoldingContext;
pub(crate) use context::{PtrArith, SSABlock};
