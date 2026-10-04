//! The one table of a function's variables (doc/adr-one-ir.md, F2.3 stage 3).
//!
//! A function's operations name their operands by [`VarId`], and this table
//! says what each id is spelled as. A variable is interned once, when an
//! operation that names it enters the function; the index from variable to
//! id serves only that interning, so a reader holding an id reads the
//! variable back by indexing and hashes no name.
//!
//! The table only grows: an id stays valid across every rewrite, and a
//! variable no operation names any more is left behind. That is why a
//! `VarId` is not the graph's [`crate::graph::ValueId`]. The graph numbers
//! only what operations name, in the order they name it, and maps each
//! `VarId` to its value densely. The two are distinct types, so a function
//! operand cannot be read as a graph value or the other way round.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::var::SSAVar;

/// A function's number for one of its variables (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VarId(pub u32);

impl crate::dense::DenseId for VarId {
    fn index(self) -> usize {
        self.0 as usize
    }

    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 variables"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ValueTable {
    vars: Vec<SSAVar>,
    index: HashMap<SSAVar, VarId>,
}

impl ValueTable {
    /// The id `var` is held under, interning it first if it is new.
    pub fn intern(&mut self, var: &SSAVar) -> VarId {
        if let Some(id) = self.index.get(var) {
            return *id;
        }
        let id = VarId(u32::try_from(self.vars.len()).expect("fewer than 2^32 variables"));
        self.vars.push(var.clone());
        self.index.insert(var.clone(), id);
        id
    }

    /// The variable an id is spelled as.
    pub fn var(&self, id: VarId) -> &SSAVar {
        &self.vars[id.0 as usize]
    }

    /// The id `var` is held under, where it has been interned.
    pub fn id_of(&self, var: &SSAVar) -> Option<VarId> {
        self.index.get(var).copied()
    }

    pub fn len(&self) -> usize {
        self.vars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Every variable, in id order.
    pub fn vars(&self) -> &[SSAVar] {
        &self.vars
    }
}
