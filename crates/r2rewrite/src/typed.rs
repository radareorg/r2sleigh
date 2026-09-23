//! The C type at every boundary of the base arena.
//!
//! A cast in the rendered C is a statement that one type becomes another.
//! The renderer used to make that statement at each site from the text it
//! had just produced -- a name looked like a pointer, a cast was already
//! there -- and seven sites each spelled their own, so a value declared
//! `uint64_t` was converted to `uint64_t` three thousand times over the
//! corpus. This module states the types once, from the arena and the plan,
//! and the renderer converts exactly where two of them meet and differ.
//!
//! Two questions are answered for every node. What the rendering of the node
//! *has* -- [`TypedBoundaries::produced`] -- follows from the operator and
//! the machine type: an unsigned integer for wrapping arithmetic, the
//! promoted `int` where the operands are narrower than `int`, `_Bool` for a
//! comparison, the signed integer of a sign extension. What the node
//! *requires* of each operand -- [`TypedBoundaries::required`] -- is the
//! operator's operand rule: the signedness a comparison, a shift or a
//! division states, the unsigned width every other integer operator works
//! in, the pointee for an address. A leaf's rendering has the type the plan
//! declared the object with, or, for a value rendered in place, the type of
//! the expression that stands for it.
//!
//! Signedness is never re-derived from the C operator that will be spelled.
//! It comes from the `interpretation` at a `Compare`, the `kind` at a
//! `Shift`, and the node kind at a division, which is where the machine
//! states it.

use std::collections::{BTreeMap, BTreeSet};

use r2ssa::{
    MachineCastKind, MachineExprId, MachineExprKind, MachineProjection, MachineShiftKind,
    MachineSignedness, MachineType, ValueId,
};
use r2types::{CTypeLike, Signedness};

use crate::{TermArena, TermId, TermKind};

/// What the renderer's plan says about a value, as far as typing needs it.
///
/// The binding plan lives in the renderer; this is the two answers of it that
/// decide a C type. A bound value renders as a name with a declaration; an
/// inlined value renders as its canonical term.
pub trait RenderTypes {
    /// The declared type of the object a bound value renders as.
    fn declaration_type(&self, value: ValueId) -> Option<CTypeLike>;

    /// The canonical term an inlined value renders as, at each of its readers.
    fn inline_root(&self, value: ValueId) -> Option<TermId>;

    /// The C type the rendering of this object's address has.
    ///
    /// A pointer to the object, or the array type itself, which decays to one.
    /// Without it an object address was typed `ptr(Unknown)`, which the
    /// conversion emitter filters out, so the address reached its reader
    /// carrying no type and two renderers recovered one from the rendered
    /// text instead.
    fn object_address_type(&self, object: r2ssa::ObjectId) -> Option<CTypeLike>;
}

/// The C type a rendered expression has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CValue {
    /// An integer constant.
    ///
    /// C types a constant by its value and converts it implicitly, and
    /// exactly, to any integer type it fits. So a constant is not converted
    /// to the type that reads it; it is spelled in that type.
    Constant,
    /// An expression of this type.
    Typed(CTypeLike),
}

impl CValue {
    /// The type, where the expression has one rather than being a constant.
    pub const fn as_type(&self) -> Option<&CTypeLike> {
        match self {
            Self::Constant => None,
            Self::Typed(ty) => Some(ty),
        }
    }
}

/// The C spelling of a machine type: the unsigned integer of an address or
/// an unsigned integer, the signed integer of a signed one, `_Bool` for a
/// boolean, and the limb-backed bitvector for a width C has no scalar for.
pub fn c_type_of(ty: &MachineType) -> CTypeLike {
    match ty {
        MachineType::Bool { .. } => CTypeLike::Bool,
        MachineType::Integer {
            width_bits,
            signedness,
        } => integer(*width_bits, *signedness),
        MachineType::Address { width_bits, .. } => {
            integer(*width_bits, MachineSignedness::Unsigned)
        }
        MachineType::Float { width_bits } => CTypeLike::Float(*width_bits),
    }
}

/// The operand type a conversion requires: the signed integer an
/// `IntegerToFloat` reads, or the floating value the other two read.
fn cast_operand(kind: &MachineCastKind, from: u32) -> CTypeLike {
    match kind {
        MachineCastKind::SignExtend | MachineCastKind::IntegerToFloat => signed(from),
        MachineCastKind::ZeroExtend
        | MachineCastKind::BitReinterpret
        | MachineCastKind::IntegerToAddress
        | MachineCastKind::AddressToInteger => unsigned(from),
        MachineCastKind::FloatToInteger | MachineCastKind::FloatToFloat => CTypeLike::Float(from),
    }
}

fn integer(width_bits: u32, signedness: MachineSignedness) -> CTypeLike {
    match width_bits {
        8 | 16 | 32 | 64 | 128 => CTypeLike::Int {
            bits: width_bits,
            signedness: match signedness {
                MachineSignedness::Unsigned => Signedness::Unsigned,
                MachineSignedness::Signed => Signedness::Signed,
            },
        },
        _ => CTypeLike::BitVector(width_bits),
    }
}

fn unsigned(width_bits: u32) -> CTypeLike {
    integer(width_bits, MachineSignedness::Unsigned)
}

fn signed(width_bits: u32) -> CTypeLike {
    integer(width_bits, MachineSignedness::Signed)
}

/// What C computes an integer operand in.
///
/// Anything narrower than `int` is promoted to `int` before any arithmetic,
/// bitwise, shift or comparison operator sees it, and the result of such an
/// operator has the promoted type, not the operand's. This is the one place
/// a width has to be spelled again -- the narrowing back to the operand's
/// width -- and it is spelled by the boundary that reads the result, from
/// this type, rather than by the operator that produced it.
pub fn promoted(ty: &CTypeLike) -> CTypeLike {
    match ty {
        CTypeLike::Int { bits, .. } if *bits < 32 => CTypeLike::int(32),
        CTypeLike::Bool => CTypeLike::int(32),
        other => other.clone(),
    }
}

/// The C type at every boundary of one function's arena.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypedBoundaries {
    /// What a read of each value renders as, before any use projection.
    values: BTreeMap<ValueId, CValue>,
    /// What the expression each node renders as has.
    produced: BTreeMap<MachineExprId, CValue>,
    /// What each node requires of the operand at each position.
    ///
    /// Keyed by the edge rather than by the operand node: the arena interns
    /// one `Source` leaf per value and type, so one leaf is read by every
    /// operator that wants the value at that type, and a signed comparison
    /// and an unsigned addition of the same value share it while requiring
    /// different things of it.
    required: BTreeMap<(MachineExprId, usize), CTypeLike>,
    /// What the expression each canonical term renders as has.
    term_produced: BTreeMap<TermId, CValue>,
    /// What each canonical term requires of the operand at each position.
    term_required: BTreeMap<(TermId, usize), CTypeLike>,
}

impl TypedBoundaries {
    /// What a read of `value` renders as: the declared type of the object it
    /// is bound to, the type of the expression it is inlined as, or the C
    /// spelling of its machine type where the plan says neither.
    pub fn value_type(&self, value: ValueId) -> Option<&CValue> {
        self.values.get(&value)
    }

    /// What the expression `node` renders as has.
    pub fn produced(&self, node: MachineExprId) -> Option<&CValue> {
        self.produced.get(&node)
    }

    /// What `parent` requires of its operand at `operand`, in the order of
    /// [`MachineExprKind::children`].
    pub fn required(&self, parent: MachineExprId, operand: usize) -> Option<&CTypeLike> {
        self.required.get(&(parent, operand))
    }

    /// What the expression `term` renders as has.
    pub fn term_produced(&self, term: TermId) -> Option<&CValue> {
        self.term_produced.get(&term)
    }

    /// What `parent` requires of its canonical-term operand at `operand`, in
    /// the order of [`TermKind::children`].
    pub fn term_required(&self, parent: TermId, operand: usize) -> Option<&CTypeLike> {
        self.term_required.get(&(parent, operand))
    }
}

/// State the C type at every machine and canonical-term boundary under `plan`.
pub fn typed_boundaries(
    projection: &MachineProjection,
    terms: &TermArena,
    plan: &dyn RenderTypes,
) -> TypedBoundaries {
    let mut builder = Builder {
        projection,
        terms,
        plan,
        out: TypedBoundaries::default(),
        machine_in_progress: BTreeSet::new(),
        term_in_progress: BTreeSet::new(),
    };
    for (id, _) in projection.arena().iter() {
        builder.produced(id);
    }
    for entity in projection.entities() {
        let value = entity.output().value();
        let ty = projection
            .expr(entity.root())
            .map(|expr| *expr.ty())
            .unwrap_or(MachineType::Integer {
                width_bits: entity.output().width_bits(),
                signedness: MachineSignedness::Unsigned,
            });
        builder.value_type(value, &ty);
    }
    for index in 0..terms.len() {
        builder.term_produced(TermId::from_index(index));
    }
    builder.out
}

struct Builder<'a> {
    projection: &'a MachineProjection,
    terms: &'a TermArena,
    plan: &'a dyn RenderTypes,
    out: TypedBoundaries,
    /// Nodes whose type is being derived, so a value read inside its own
    /// definition -- a call that reads the location it defines -- takes its
    /// machine type instead of recursing forever.
    machine_in_progress: BTreeSet<MachineExprId>,
    term_in_progress: BTreeSet<TermId>,
}

impl Builder<'_> {
    fn width(&self, id: MachineExprId) -> u32 {
        self.projection
            .expr(id)
            .map(|expr| expr.ty().width_bits())
            .unwrap_or(0)
    }

    fn require(&mut self, parent: MachineExprId, operand: usize, ty: CTypeLike) {
        self.out.required.insert((parent, operand), ty);
    }

    fn require_term(&mut self, parent: TermId, operand: usize, ty: CTypeLike) {
        self.out.term_required.insert((parent, operand), ty);
    }

    fn value_type(&mut self, value: ValueId, fallback: &MachineType) -> CValue {
        if let Some(known) = self.out.values.get(&value) {
            return known.clone();
        }
        let ty = if let Some(declared) = self.plan.declaration_type(value) {
            CValue::Typed(declared)
        } else if let Some(root) = self.plan.inline_root(value) {
            if self.term_in_progress.contains(&root) {
                CValue::Typed(c_type_of(fallback))
            } else {
                self.term_produced(root)
            }
        } else {
            CValue::Typed(c_type_of(fallback))
        };
        self.out.values.insert(value, ty.clone());
        ty
    }

    fn produced(&mut self, id: MachineExprId) -> CValue {
        if let Some(known) = self.out.produced.get(&id) {
            return known.clone();
        }
        let Some(expr) = self.projection.expr(id) else {
            return CValue::Typed(CTypeLike::Unknown);
        };
        if !self.machine_in_progress.insert(id) {
            return CValue::Typed(c_type_of(expr.ty()));
        }
        let ty = *expr.ty();
        let kind = expr.kind().clone();
        let produced = self.boundary(id, &ty, &kind);
        self.machine_in_progress.remove(&id);
        self.out.produced.insert(id, produced.clone());
        produced
    }

    fn term_width(&self, id: TermId) -> u32 {
        self.terms.term(id).width_bits()
    }

    fn term_produced(&mut self, id: TermId) -> CValue {
        if let Some(known) = self.out.term_produced.get(&id) {
            return known.clone();
        }
        let term = self.terms.term(id);
        if !self.term_in_progress.insert(id) {
            return CValue::Typed(c_type_of(&term.ty));
        }
        let produced = self.term_boundary(id, &term.ty, &term.kind);
        self.term_in_progress.remove(&id);
        self.out.term_produced.insert(id, produced.clone());
        produced
    }

    /// The canonical operator's operand rule and produced type.
    fn term_boundary(&mut self, id: TermId, ty: &MachineType, kind: &TermKind) -> CValue {
        let own = c_type_of(ty);
        match kind {
            TermKind::Leaf(read) => self.produced(read.expr),
            TermKind::Opaque(expr) => self.produced(*expr),
            TermKind::Literal(_) => CValue::Constant,
            TermKind::Variable(_) => CValue::Typed(own),
            TermKind::ObjectAddress(object) => CValue::Typed(
                self.plan
                    .object_address_type(*object)
                    .unwrap_or_else(|| CTypeLike::ptr(CTypeLike::Unknown)),
            ),
            TermKind::Load { address, .. } => {
                self.term_produced(*address);
                self.require_term(id, 0, CTypeLike::ptr(own.clone()));
                CValue::Typed(own)
            }
            TermKind::Subscript { base, index } => {
                self.term_produced(*base);
                self.term_produced(*index);
                self.require_term(id, 0, CTypeLike::ptr(own.clone()));
                self.require_term(id, 1, unsigned(self.term_width(*index)));
                CValue::Typed(own)
            }
            TermKind::Arithmetic { left, right, .. } | TermKind::Bitwise { left, right, .. } => {
                self.term_produced(*left);
                self.term_produced(*right);
                self.require_term(id, 0, own.clone());
                self.require_term(id, 1, own.clone());
                CValue::Typed(promoted(&own))
            }
            TermKind::Negate(input) | TermKind::BitwiseNot(input) => {
                self.term_produced(*input);
                self.require_term(id, 0, own.clone());
                CValue::Typed(promoted(&own))
            }
            TermKind::Boolean { left, right, .. } => {
                self.term_produced(*left);
                self.term_produced(*right);
                self.require_term(id, 0, CTypeLike::Bool);
                self.require_term(id, 1, CTypeLike::Bool);
                CValue::Typed(CTypeLike::Bool)
            }
            TermKind::BooleanNot(input) => {
                self.term_produced(*input);
                self.require_term(id, 0, CTypeLike::Bool);
                CValue::Typed(CTypeLike::Bool)
            }
            TermKind::Shift {
                kind, value, count, ..
            } => {
                self.term_produced(*value);
                self.term_produced(*count);
                let shifted = match kind {
                    MachineShiftKind::ArithmeticRight => signed(ty.width_bits()),
                    MachineShiftKind::Left | MachineShiftKind::LogicalRight => own,
                };
                self.require_term(id, 0, shifted.clone());
                self.require_term(id, 1, unsigned(self.term_width(*count)));
                CValue::Typed(promoted(&shifted))
            }
            TermKind::Compare {
                interpretation,
                left,
                right,
                ..
            } => {
                self.term_produced(*left);
                self.term_produced(*right);
                let operand = integer(self.term_width(*left), *interpretation);
                self.require_term(id, 0, operand.clone());
                self.require_term(id, 1, operand);
                CValue::Typed(CTypeLike::Bool)
            }
            TermKind::Flag { left, right, .. } => {
                self.term_produced(*left);
                self.term_produced(*right);
                let operand = unsigned(self.term_width(*left));
                self.require_term(id, 0, operand.clone());
                self.require_term(id, 1, operand);
                CValue::Typed(CTypeLike::u8())
            }
            TermKind::Cast { kind, input } | TermKind::FloatCast { kind, input } => {
                self.term_produced(*input);
                let from = self.term_width(*input);
                self.require_term(id, 0, cast_operand(kind, from));
                CValue::Typed(own)
            }
            // Floating arithmetic is performed in the operands' own format;
            // C promotes nothing narrower than `float`.
            TermKind::FloatArithmetic { left, right, .. } => {
                self.term_produced(*left);
                self.term_produced(*right);
                self.require_term(id, 0, own.clone());
                self.require_term(id, 1, own.clone());
                CValue::Typed(own)
            }
            TermKind::FloatUnary { input, .. } => {
                self.term_produced(*input);
                let from = self.term_width(*input);
                self.require_term(id, 0, CTypeLike::Float(from));
                CValue::Typed(own)
            }
            TermKind::FloatCompare { left, right, .. } => {
                self.term_produced(*left);
                self.term_produced(*right);
                let operand = CTypeLike::Float(self.term_width(*left));
                self.require_term(id, 0, operand.clone());
                self.require_term(id, 1, operand);
                CValue::Typed(CTypeLike::Bool)
            }
            TermKind::Extract { input, .. } => {
                self.term_produced(*input);
                self.require_term(id, 0, unsigned(self.term_width(*input)));
                CValue::Typed(own)
            }
            TermKind::Concat { high, low } => {
                self.term_produced(*high);
                self.term_produced(*low);
                self.require_term(id, 0, unsigned(self.term_width(*high)));
                self.require_term(id, 1, unsigned(self.term_width(*low)));
                CValue::Typed(promoted(&own))
            }
            TermKind::Select {
                condition,
                if_true,
                if_false,
            } => {
                self.term_produced(*condition);
                self.term_produced(*if_true);
                self.term_produced(*if_false);
                self.require_term(id, 0, CTypeLike::Bool);
                self.require_term(id, 1, own.clone());
                self.require_term(id, 2, own.clone());
                CValue::Typed(own)
            }
        }
    }

    /// The operator's operand rule and what it produces, in one place.
    fn boundary(&mut self, id: MachineExprId, ty: &MachineType, kind: &MachineExprKind) -> CValue {
        let own = c_type_of(ty);
        match kind {
            MachineExprKind::Source { binding, .. } => self.value_type(binding.value(), ty),
            MachineExprKind::Constant { .. } => CValue::Constant,
            // A copy converts nothing. Whatever it reads is what it has, and
            // the assignment that writes the copy's object is where the
            // declared type is met.
            MachineExprKind::Copy { input } => {
                let input_type = self.produced(*input);
                let required = input_type.as_type().cloned().unwrap_or(own);
                self.require(id, 0, required);
                input_type
            }
            // Wrapping arithmetic is unsigned arithmetic at the width, and
            // C performs it in the promoted type.
            MachineExprKind::Arithmetic { left, right, .. }
            | MachineExprKind::Bitwise { left, right, .. } => {
                self.produced(*left);
                self.produced(*right);
                self.require(id, 0, own.clone());
                self.require(id, 1, own.clone());
                CValue::Typed(promoted(&own))
            }
            // Division is the arithmetic whose operands have to be read the
            // way the operation says, because the same bits divide to
            // different quotients signed and unsigned.
            MachineExprKind::Divide {
                interpretation,
                dividend,
                divisor,
                ..
            }
            | MachineExprKind::Remainder {
                interpretation,
                dividend,
                divisor,
                ..
            } => {
                self.produced(*dividend);
                self.produced(*divisor);
                let operand = integer(ty.width_bits(), *interpretation);
                self.require(id, 0, operand.clone());
                self.require(id, 1, operand.clone());
                CValue::Typed(promoted(&operand))
            }
            MachineExprKind::Negate { input, .. } | MachineExprKind::BitwiseNot { input } => {
                self.produced(*input);
                self.require(id, 0, own.clone());
                CValue::Typed(promoted(&own))
            }
            // The signedness of a shift is the kind of the shift: an
            // arithmetic right shift is `>>` on a signed operand and nothing
            // else. The count is any integer C accepts, at its own width.
            MachineExprKind::Shift {
                kind, value, count, ..
            } => {
                self.produced(*value);
                self.produced(*count);
                let shifted = match kind {
                    MachineShiftKind::ArithmeticRight => signed(ty.width_bits()),
                    MachineShiftKind::Left | MachineShiftKind::LogicalRight => own,
                };
                self.require(id, 0, shifted.clone());
                let count_width = self.width(*count);
                self.require(id, 1, unsigned(count_width));
                CValue::Typed(promoted(&shifted))
            }
            // The signedness of a comparison is its interpretation, stated
            // at the node; the operands are compared at their own width.
            MachineExprKind::Compare {
                interpretation,
                left,
                right,
                ..
            } => {
                self.produced(*left);
                self.produced(*right);
                let operand = integer(self.width(*left), *interpretation);
                self.require(id, 0, operand.clone());
                self.require(id, 1, operand);
                CValue::Typed(CTypeLike::Bool)
            }
            // A flag is computed by a prelude helper over the unsigned
            // operands, and the helper returns `uint8_t`.
            MachineExprKind::ArithmeticFlag { left, right, .. } => {
                self.produced(*left);
                self.produced(*right);
                let operand = unsigned(self.width(*left));
                self.require(id, 0, operand.clone());
                self.require(id, 1, operand);
                CValue::Typed(CTypeLike::u8())
            }
            // A boolean operator accepts any scalar and yields a truth
            // value.
            MachineExprKind::Boolean { left, right, .. } => {
                self.produced(*left);
                self.produced(*right);
                self.require(id, 0, CTypeLike::Bool);
                self.require(id, 1, CTypeLike::Bool);
                CValue::Typed(CTypeLike::Bool)
            }
            MachineExprKind::BooleanNot { input } => {
                self.produced(*input);
                self.require(id, 0, CTypeLike::Bool);
                CValue::Typed(CTypeLike::Bool)
            }
            // A cast is the conversion. Its operand must have the
            // signedness the conversion extends by -- `(uint64_t)(int32_t)x`
            // sign-extends and `(uint64_t)(uint32_t)x` does not -- and what
            // it produces is its own type.
            MachineExprKind::Cast { kind, input } => {
                self.produced(*input);
                let from = self.width(*input);
                self.require(id, 0, cast_operand(kind, from));
                CValue::Typed(own)
            }
            MachineExprKind::FloatArithmetic { left, right, .. } => {
                self.produced(*left);
                self.produced(*right);
                self.require(id, 0, own.clone());
                self.require(id, 1, own.clone());
                CValue::Typed(own)
            }
            MachineExprKind::FloatUnary { input, .. } => {
                self.produced(*input);
                let from = self.width(*input);
                self.require(id, 0, CTypeLike::Float(from));
                CValue::Typed(own)
            }
            MachineExprKind::FloatCompare { left, right, .. } => {
                self.produced(*left);
                self.produced(*right);
                let operand = CTypeLike::Float(self.width(*left));
                self.require(id, 0, operand.clone());
                self.require(id, 1, operand);
                CValue::Typed(CTypeLike::Bool)
            }
            MachineExprKind::Extract { input, .. } => {
                self.produced(*input);
                let from = self.width(*input);
                self.require(id, 0, unsigned(from));
                CValue::Typed(own)
            }
            // A concatenation is spelled as a shift and an or over both
            // pieces converted to the whole width, so C promotes it like any
            // other integer operator.
            MachineExprKind::Concat { high, low } => {
                self.produced(*high);
                self.produced(*low);
                let high_width = self.width(*high);
                let low_width = self.width(*low);
                self.require(id, 0, unsigned(high_width));
                self.require(id, 1, unsigned(low_width));
                CValue::Typed(promoted(&own))
            }
            // Both arms of a selection are brought to the machine type, so
            // the selection has it whichever arm is taken.
            MachineExprKind::Select {
                condition,
                if_true,
                if_false,
            } => {
                self.produced(*condition);
                self.produced(*if_true);
                self.produced(*if_false);
                self.require(id, 0, CTypeLike::Bool);
                self.require(id, 1, own.clone());
                self.require(id, 2, own.clone());
                CValue::Typed(own)
            }
            // The address of a read is a pointer to what is read, and a
            // guarded read states the condition it happens under beside it.
            MachineExprKind::MemoryRead { address, .. } => {
                self.produced(*address);
                self.require(id, 0, CTypeLike::ptr(own.clone()));
                CValue::Typed(own)
            }
            MachineExprKind::GuardedRead { address, guard, .. } => {
                self.produced(*address);
                self.produced(*guard);
                self.require(id, 0, CTypeLike::ptr(own.clone()));
                self.require(id, 1, CTypeLike::Bool);
                CValue::Typed(own)
            }
            // `__builtin_popcountll` takes an unsigned long long and returns
            // an `int`.
            MachineExprKind::PopulationCount { input } => {
                self.produced(*input);
                self.require(id, 0, CTypeLike::u64());
                CValue::Typed(CTypeLike::int(32))
            }
            // The root and the lane are both brought to their own unsigned
            // widths; the mask and shift the spelling uses promote like any
            // other integer operator, and the assignment narrows back.
            MachineExprKind::InsertLane {
                root,
                lane,
                position,
                ..
            } => {
                self.produced(*root);
                self.produced(*lane);
                self.produced(*position);
                let root_width = self.width(*root);
                let lane_width = self.width(*lane);
                let position_width = self.width(*position);
                self.require(id, 0, unsigned(root_width));
                self.require(id, 1, unsigned(lane_width));
                // The position is read as the shift count of the spelling, so
                // it takes a shift count's rule. Leaving it unstated let the
                // operand reach the page at whatever type it happened to have.
                self.require(id, 2, unsigned(position_width));
                CValue::Typed(promoted(&own))
            }
            // A merge is not an expression; each of its edges is a copy, and
            // takes a copy's rule -- the edge converts nothing and the
            // declared type is met at the assignment that writes it.
            MachineExprKind::Phi { inputs } => {
                for (index, input) in inputs.iter().enumerate() {
                    let input_type = self.produced(*input);
                    let required = input_type.as_type().cloned().unwrap_or_else(|| own.clone());
                    self.require(id, index, required);
                }
                CValue::Typed(own)
            }
            // The address is a pointer and the value is whatever was stored;
            // what comes back is the machine's answer about the monitor, at
            // the width the instruction writes it.
            MachineExprKind::ExclusiveStoreSucceeded { value, .. } => {
                let stored = self.produced(*value);
                if let Some(stored) = stored.as_type().cloned() {
                    self.require(id, 1, stored);
                }
                CValue::Typed(own)
            }
            // The walk casts its addresses to the element it reads and counts in the counter's width.
            MachineExprKind::BlockAnswer {
                destination,
                source,
                count,
                direction,
                ..
            } => {
                for operand in [destination, source, direction] {
                    self.produced(*operand);
                }
                self.produced(*count);
                self.require(id, 2, unsigned(self.width(*count)));
                CValue::Typed(own)
            }
        }
    }
}
