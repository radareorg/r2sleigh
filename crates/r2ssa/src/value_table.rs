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

use crate::CanonicalStorageId;
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
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "keyed by name where there is no value table: renaming builds the names the table interns, the table's own interning index, or a one-instruction block"
    )
)]
pub struct ValueTable {
    vars: Vec<SSAVar>,
    /// The lifted storage each variable was read from or written to, where
    /// the lift stated one: the one owner of that fact, a column beside the
    /// variable rather than a second map keyed by its name.
    storage: Vec<Option<CanonicalStorageId>>,
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
        self.storage.push(None);
        self.index.insert(var.clone(), id);
        id
    }

    /// The lifted storage of `id`, where one was stated.
    pub fn storage(&self, id: VarId) -> Option<CanonicalStorageId> {
        self.storage.get(id.0 as usize).copied().flatten()
    }

    /// The lifted storage of `var`, where it is interned and one was stated.
    pub fn storage_of_var(&self, var: &SSAVar) -> Option<CanonicalStorageId> {
        self.storage(self.id_of(var)?)
    }

    /// State `id`'s lifted storage.
    pub(crate) fn set_storage(&mut self, id: VarId, storage: CanonicalStorageId) {
        self.storage[id.0 as usize] = Some(storage);
    }

    /// Intern `var` and state its storage.
    pub(crate) fn intern_with_storage(
        &mut self,
        var: &SSAVar,
        storage: CanonicalStorageId,
    ) -> VarId {
        let id = self.intern(var);
        self.set_storage(id, storage);
        id
    }

    /// Every variable with a stated storage, ordered by the variable: a
    /// snapshot for the seal's few passes that take the first match among
    /// them, so the match does not depend on interning order. `O(n log n)`,
    /// once per pass.
    pub(crate) fn storage_by_var(&self) -> Vec<(&SSAVar, CanonicalStorageId)> {
        let mut held = self
            .vars
            .iter()
            .zip(&self.storage)
            .filter_map(|(var, storage)| Some((var, (*storage)?)))
            .collect::<Vec<_>>();
        held.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        held
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
}

impl ValueTable {
    /// Append what a plan minted against this table, in the order it minted
    /// them, so that every id the plan wrote names what it meant.
    pub(crate) fn adopt(&mut self, minted: Minted) {
        if minted.vars.is_empty() {
            return;
        }
        assert_eq!(
            self.vars.len(),
            minted.base,
            "a plan's minted variables join the table they were numbered past"
        );
        for var in minted.vars {
            let id = VarId::from_len(self.vars.len());
            self.index.insert(var.clone(), id);
            self.vars.push(var);
            self.storage.push(None);
        }
    }
}

impl VarId {
    fn from_len(len: usize) -> Self {
        Self(u32::try_from(len).expect("fewer than 2^32 variables"))
    }
}

/// The variables a pass names while it plans against a function it only
/// reads: those the table holds keep their ids, and each new one is
/// numbered past the table in the order the pass first names it. The plan
/// carries them as [`Minted`], and they join the table when it applies.
///
/// Interning is `O(1)` expected per variable, as the table's own is.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "keyed by name where there is no value table: renaming builds the names the table interns, the table's own interning index, or a one-instruction block"
    )
)]
pub(crate) struct Minting<'t> {
    table: &'t ValueTable,
    vars: Vec<SSAVar>,
    index: HashMap<SSAVar, VarId>,
}

/// What a [`Minting`] numbered, and the table length it numbered past.
#[derive(Debug, Clone, Default)]
pub(crate) struct Minted {
    base: usize,
    vars: Vec<SSAVar>,
}

impl Minted {
    pub(crate) fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

impl<'t> Minting<'t> {
    pub(crate) fn new(table: &'t ValueTable) -> Self {
        Self {
            table,
            vars: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// The id `var` is held under, numbering it past the table if neither
    /// the table nor this minting holds it yet.
    pub(crate) fn intern(&mut self, var: &SSAVar) -> VarId {
        if let Some(id) = self
            .table
            .id_of(var)
            .or_else(|| self.index.get(var).copied())
        {
            return id;
        }
        let id = VarId::from_len(self.table.len() + self.vars.len());
        self.vars.push(var.clone());
        self.index.insert(var.clone(), id);
        id
    }

    /// The constant `value` at `size` bytes, as a variable id.
    pub(crate) fn constant(&mut self, value: u64, size: u32) -> VarId {
        self.intern(&SSAVar::constant(value, size))
    }

    /// The variable an id is spelled as, whether the table or this minting
    /// numbered it.
    pub(crate) fn var(&self, id: VarId) -> &SSAVar {
        let index = id.0 as usize;
        match index.checked_sub(self.table.len()) {
            Some(minted) => &self.vars[minted],
            None => self.table.var(id),
        }
    }

    /// Everything numbered past the table, for the plan to carry.
    pub(crate) fn finish(self) -> Minted {
        Minted {
            base: self.table.len(),
            vars: self.vars,
        }
    }
}
