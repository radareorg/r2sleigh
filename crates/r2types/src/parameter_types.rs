//! Each parameter's type and what it rests on, one row per convention slot (ROADMAP D261, D265,
//! RULING 1.1; doc/adr-call-boundary.md, "S29 as built").

use r2source::Basis;
use r2ssa::body_boundary::SlotId;
use r2ssa::dense::IdVec;

use crate::{CTypeLike, Signedness};

/// Why a width-only slot handed to a declared pointer keeps its width (D262, D71 A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerRefusal {
    /// The value is also handed to a slot a declaration types as no pointer.
    IntegerBound,
    /// The carrier is not as wide as a pointer.
    NotPointerWide,
}

/// What the body states of an integer's sign: every sign-seeding use of the lane agrees, none
/// seeds, or two disagree. Only the first two kinds spell a C sign (D265, RULING 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignFact {
    Signed(Basis),
    Unsigned(Basis),
    Unstated,
    Conflict,
}

impl SignFact {
    /// The sign the lane's seeds state, given which kinds seed it; a body reading is `Decoded`.
    pub fn of(signed: bool, unsigned: bool) -> Self {
        match (signed, unsigned) {
            (true, true) => Self::Conflict,
            (true, false) => Self::Signed(Basis::Decoded),
            (false, true) => Self::Unsigned(Basis::Decoded),
            (false, false) => Self::Unstated,
        }
    }

    /// The C sign stated, where one is.
    pub const fn signedness(self) -> Option<Signedness> {
        match self {
            Self::Signed(_) => Some(Signedness::Signed),
            Self::Unsigned(_) => Some(Signedness::Unsigned),
            Self::Unstated | Self::Conflict => None,
        }
    }
}

/// An integer read at `bits`, its width resting on `width` and its sign on `sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerDecl {
    pub bits: u8,
    pub width: Basis,
    pub sign: SignFact,
}

impl IntegerDecl {
    /// The type C spells: `intN_t` or `uintN_t` where the sign is stated, else the unstated word;
    /// an integer of no standard width (a 128-bit pair) keeps its unsigned spelling.
    pub fn spelled(self) -> CTypeLike {
        let bits = u32::from(self.bits);
        match self.sign.signedness() {
            Some(signedness) => CTypeLike::Int { bits, signedness },
            None if matches!(bits, 8 | 16 | 32 | 64) => unstated_word(bits),
            None => CTypeLike::Int {
                bits,
                signedness: Signedness::Unsigned,
            },
        }
    }
}

/// A slot's type: stated by a declaration, or read from the body (D265, D266).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotType {
    /// Debug information or a library's prototype states it.
    Declared(CTypeLike, Basis),
    Integer(IntegerDecl),
    Float {
        bits: u8,
        basis: Basis,
    },
    Pointer(CTypeLike, Basis),
    /// A width-only type no other row states (a bit vector): the storage it is read as.
    Carrier(CTypeLike, Basis),
}

impl SlotType {
    /// The row a type at `basis` gives: the declaration's own where the basis states a type, else
    /// what the body reads it as, an integer's sign from `sign`.
    pub fn of(ty: &CTypeLike, basis: Basis, sign: SignFact) -> Self {
        if basis.states_type() {
            return Self::Declared(ty.clone(), basis);
        }
        match ty.unaliased() {
            CTypeLike::Pointer(_) => Self::Pointer(ty.clone(), basis),
            CTypeLike::Float(bits) => Self::Float {
                bits: u8::try_from(*bits).unwrap_or(u8::MAX),
                basis,
            },
            CTypeLike::Int { bits, .. } if u8::try_from(*bits).is_ok() => {
                Self::Integer(IntegerDecl {
                    bits: u8::try_from(*bits).unwrap_or(u8::MAX),
                    width: basis,
                    sign,
                })
            }
            _ => Self::Carrier(ty.clone(), basis),
        }
    }

    /// The basis the type rests on: an integer's on its width.
    pub const fn basis(&self) -> Basis {
        match self {
            Self::Declared(_, basis)
            | Self::Pointer(_, basis)
            | Self::Carrier(_, basis)
            | Self::Float { basis, .. } => *basis,
            Self::Integer(integer) => integer.width,
        }
    }

    /// The one C spelling `pdd`, `pddj` and `afi` give the slot.
    pub fn spelled(&self) -> CTypeLike {
        match self {
            Self::Declared(ty, _) | Self::Pointer(ty, _) | Self::Carrier(ty, _) => ty.clone(),
            Self::Integer(integer) => integer.spelled(),
            Self::Float { bits, .. } => CTypeLike::Float(u32::from(*bits)),
        }
    }
}

/// The prelude typedef an integer of no stated sign spells: `r2sleigh_word_uN` over `uintN_t`,
/// which keeps wraparound defined and claims no C sign (D265, as D165's hole typedef).
pub fn unstated_word(bits: u32) -> CTypeLike {
    CTypeLike::Typedef {
        name: format!("{UNSTATED_WORD}{bits}"),
        ty: Box::new(CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        }),
    }
}

/// The unstated word typedef's prefix.
pub const UNSTATED_WORD: &str = "r2sleigh_word_u";

/// `ty`, the unstated word as the integer it is: a merge of evidence reads it as a weak scalar.
pub fn word_free(ty: &CTypeLike) -> &CTypeLike {
    match ty {
        CTypeLike::Typedef { ty: inner, .. } if is_unstated_word(ty) => inner,
        ty => ty,
    }
}

/// Whether `ty` is the unstated word typedef.
pub fn is_unstated_word(ty: &CTypeLike) -> bool {
    matches!(ty, CTypeLike::Typedef { name, .. } if name.starts_with(UNSTATED_WORD))
}

/// One slot's row: its type, and why a declared pointer did not reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterType {
    pub ty: SlotType,
    pub refused: Option<PointerRefusal>,
}

impl ParameterType {
    pub const fn stated(ty: SlotType) -> Self {
        Self { ty, refused: None }
    }

    pub const fn refused(ty: SlotType, why: PointerRefusal) -> Self {
        Self {
            ty,
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
    pub fn row(&self, formal: usize) -> Option<&ParameterType> {
        self.rows.get(*self.formals.get(formal)?)?.as_ref()
    }

    /// The basis formal `formal`'s type rests on, where a row states it.
    pub fn basis(&self, formal: usize) -> Option<Basis> {
        self.row(formal).map(|row| row.ty.basis())
    }

    pub fn is_empty(&self) -> bool {
        self.formals.is_empty()
    }
}
