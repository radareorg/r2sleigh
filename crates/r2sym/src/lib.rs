//! Symbolic execution engine for r2sleigh.
//!
//! This crate provides symbolic execution capabilities for r2il/r2ssa,
//! using Z3 as the constraint solver backend.
//!
//! ## Architecture
//!
//! - [`value`]: Symbolic values (concrete, symbolic, or unknown)
//! - [`state`]: Symbolic execution state (registers, memory, constraints)
//! - [`memory`]: Symbolic memory model
//! - [`executor`]: Steps through SSA operations symbolically
//! - [`solver`]: Z3 solver wrapper
//! - [`path`]: Path exploration strategies
//!
//! ## Example
//!
//! ```ignore
//! use r2sym::{SymEngine, SymState};
//! use r2ssa::SSAFunction;
//!
//! let func = SSAFunction::from_blocks(&blocks).unwrap();
//! let mut engine = SymEngine::new();
//! engine.make_symbolic("rdi", 64);
//!
//! let results = engine.explore(&func);
//! for path in results {
//!     if let Some(model) = path.solve() {
//!         println!("Found inputs: {:?}", model);
//!     }
//! }
//! ```

pub mod executor;
pub mod memory;
pub mod path;
pub mod solver;
pub mod state;
pub mod value;

pub use executor::SymExecutor;
pub use memory::SymMemory;
pub use path::{ExploreConfig, PathExplorer, PathResult};
pub use solver::{SatResult, SymSolver};
pub use state::SymState;
pub use value::SymValue;

/// Error types for symbolic execution.
#[derive(Debug, thiserror::Error)]
pub enum SymError {
    /// Z3 solver error.
    #[error("Z3 solver error: {0}")]
    SolverError(String),

    /// Unsupported operation.
    #[error("Unsupported operation: {0}")]
    UnsupportedOp(String),

    /// Memory access error.
    #[error("Memory error: {0}")]
    MemoryError(String),

    /// Path explosion (too many states).
    #[error("Path explosion: {0} states")]
    PathExplosion(usize),

    /// Timeout during exploration.
    #[error("Exploration timeout")]
    Timeout,
}

pub type SymResult<T> = Result<T, SymError>;
