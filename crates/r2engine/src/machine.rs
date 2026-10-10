//! A decoder with the architecture tables the analysis reads, built once when a program opens.

use std::ops::Deref;
use std::sync::Arc;

use r2sleigh_lift::EmbeddedMachine;

/// An embedded machine and its architecture's tables, over the one specification both share.
pub struct Machine {
    embedded: EmbeddedMachine,
    tables: r2ssa::Arch,
}

impl Machine {
    pub fn new(embedded: EmbeddedMachine) -> Self {
        let tables = r2ssa::Arch::new(Arc::clone(&embedded.arch));
        Self { embedded, tables }
    }

    /// The architecture with its tables, shared by every function this machine prepares.
    pub fn tables(&self) -> &r2ssa::Arch {
        &self.tables
    }
}

impl Deref for Machine {
    type Target = EmbeddedMachine;

    fn deref(&self) -> &EmbeddedMachine {
        &self.embedded
    }
}
