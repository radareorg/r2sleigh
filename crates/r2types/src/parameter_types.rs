//! What each parameter's type rests on, one row per convention slot (ROADMAP D261, RULING 1.1).
//! S29 widens the row to the slot's type.

use r2source::Basis;
use r2ssa::body_boundary::SlotId;
use r2ssa::dense::IdVec;

/// Why a width-only slot handed to a declared pointer keeps its width (D262, D71 A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerRefusal {
    /// The value is also handed to a slot a declaration types as no pointer.
    IntegerBound,
    /// The carrier is not as wide as a pointer.
    NotPointerWide,
}

/// One slot's row: the basis its type rests on, and why a declared pointer did not reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterType {
    pub basis: Basis,
    pub refused: Option<PointerRefusal>,
}

impl ParameterType {
    pub const fn stated(basis: Basis) -> Self {
        Self {
            basis,
            refused: None,
        }
    }

    pub const fn refused(basis: Basis, why: PointerRefusal) -> Self {
        Self {
            basis,
            refused: Some(why),
        }
    }
}

/// The rows by slot, and the slot each formal is at. O(1) per lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterTypes {
    rows: IdVec<SlotId, Option<ParameterType>>,
    formals: Vec<SlotId>,
}

impl Default for ParameterTypes {
    fn default() -> Self {
        Self {
            rows: IdVec::filled(0, None),
            formals: Vec::new(),
        }
    }
}

impl ParameterTypes {
    /// The table over `formals`, each formal's slot in order, with no row stated yet.
    pub fn over(formals: Vec<SlotId>) -> Self {
        let len = formals
            .iter()
            .map(|slot| slot.0 as usize + 1)
            .max()
            .unwrap_or(0);
        Self {
            rows: IdVec::filled(len, None),
            formals,
        }
    }

    /// The table over an interface's parameters, at the slot each states; a spec no producer
    /// numbered (a test's) stands at its formal position. O(parameters).
    pub fn of_interface(interface: &r2source::SourceFunctionInterface) -> Self {
        let formals = (interface.parameters().iter().enumerate())
            .map(|(formal, spec)| SlotId(spec.slot().map_or(formal as u32, |slot| slot.id)))
            .collect();
        Self::over(formals)
    }

    /// State formal `formal`'s row; a formal the table is not over states nothing. O(1).
    pub fn set(&mut self, formal: usize, row: ParameterType) {
        if let Some(slot) = self.formals.get(formal) {
            self.rows[*slot] = Some(row);
        }
    }

    /// Formal `formal`'s row, where one is stated.
    pub fn row(&self, formal: usize) -> Option<ParameterType> {
        self.rows.get(*self.formals.get(formal)?).copied().flatten()
    }

    /// The basis formal `formal`'s type rests on, where a row states it.
    pub fn basis(&self, formal: usize) -> Option<Basis> {
        self.row(formal).map(|row| row.basis)
    }

    pub fn is_empty(&self) -> bool {
        self.formals.is_empty()
    }
}
