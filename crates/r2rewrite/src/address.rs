//! Taking an address apart, once, from the facts the arena carries.
//!
//! An address is plain integer arithmetic: the sum says nothing about which
//! operand is the base. The certificates do, and this is the one place that
//! reads them. The subscript rules already worked this way; the renderer did
//! not, and re-derived the same decomposition from the *rendered text* and the
//! symbol table, which is a third copy with a different and weaker notion of
//! what a base is -- the symbol table calls a parameter a pointer whether or
//! not any certificate says the access flows from it.
//!
//! Read-only on purpose. The arena is moved into `CanonicalRoots` before any
//! renderer sees it, so nothing here may intern: the caller spells the sum it
//! is handed.

use std::collections::BTreeMap;

use r2ssa::MachineType;

use crate::canon::collect_affine;
use crate::term::{TermArena, TermId};

/// An address as a base, a scaled index, and a byte displacement.
///
/// Coefficients and the displacement are signed at the address width, so a
/// `base - 16` stays a subtraction rather than becoming
/// `base + 0xffff_ffff_ffff_fff0`: the two agree in bits and only the first is
/// in range of the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressForm {
    /// The one atom the certificates call a base.
    pub base: TermId,
    /// The remaining atoms, each with its signed byte coefficient.
    pub index: Vec<(TermId, i128)>,
    /// The signed byte displacement.
    pub offset: i128,
    /// The width the address itself has.
    pub width_bits: u32,
}

/// The affine form of an address: atoms with coefficients, plus a constant.
///
/// An address the arena types as an address rather than an integer -- a leaf
/// that was never expanded -- is one atom with a unit coefficient.
pub(crate) struct Affine {
    pub(crate) coefficients: BTreeMap<TermId, u64>,
    pub(crate) constant: u64,
    pub(crate) width: u32,
    pub(crate) ty: MachineType,
}

pub(crate) fn affine_of(arena: &TermArena, address: TermId) -> Option<Affine> {
    let term = arena.term(address);
    let width = term.width_bits();
    if width == 0 || width > 64 {
        return None;
    }
    let mut coefficients = BTreeMap::new();
    let mut constant = 0u64;
    match term.ty {
        MachineType::Integer { .. } => {
            let mut atoms = 0usize;
            collect_affine(
                arena,
                address,
                1,
                width,
                &mut coefficients,
                &mut constant,
                &mut atoms,
            );
        }
        MachineType::Address { .. } => {
            coefficients.insert(address, 1);
        }
        MachineType::Bool { .. } | MachineType::Float { .. } => return None,
    }
    coefficients.retain(|_, k| *k != 0);
    Some(Affine {
        coefficients,
        constant,
        width,
        ty: term.ty,
    })
}

/// The one atom with a unit coefficient that `is_base` accepts, if exactly one
/// does.
///
/// Refusing when two qualify is the guarantee: an address with two candidate
/// bases has no spelling this can justify, and picking one would be a guess.
pub(crate) fn unique_base(
    arena: &TermArena,
    affine: &Affine,
    is_base: impl Fn(&TermArena, TermId) -> bool,
) -> Option<TermId> {
    let mut bases = affine
        .coefficients
        .iter()
        .filter(|(term, k)| **k == 1 && is_base(arena, **term))
        .map(|(term, _)| *term);
    let base = bases.next()?;
    bases.next().is_none().then_some(base)
}

/// Take `address` apart around the one base the arena's certificates name.
///
/// `None` when no atom is a certified pointer, or when two are: both mean the
/// address has no base this can justify, and the caller spells it as the
/// scalar it is rather than guessing.
pub fn address_form(arena: &TermArena, address: TermId) -> Option<AddressForm> {
    let affine = affine_of(arena, address)?;
    let base = unique_base(arena, &affine, |arena, term| arena.is_pointer(term))?;
    let width_bits = affine.width;
    let index = affine
        .coefficients
        .iter()
        .filter(|(term, _)| **term != base)
        .map(|(term, k)| (*term, crate::eval::signed(u128::from(*k), width_bits)))
        .collect();
    Some(AddressForm {
        base,
        index,
        offset: crate::eval::signed(u128::from(affine.constant), width_bits),
        width_bits,
    })
}
