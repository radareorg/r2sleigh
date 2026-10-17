//! The offset cursor that counts up to zero (AAPCS64's `__gr_offs`) and the branches on it that go
//! one way (doc/adr-resolved-bodies.md, "Count-driven tail").

use crate::graph::{BlockId, InstPayload};
use crate::semantic::{BlockAssumption, PredicateFact, PredicateFacts};
use crate::tail_count::{COPIES, Prover};
use crate::tail_cursors::{Cursors, Kind};
use crate::{SSAOp, ValueId};

const MIN: i64 = i32::MIN as i64;
const MAX: i64 = i32::MAX as i64;
const WRAP: i64 = 1 << 32;

/// The signed 32-bit integers a condition holds for, as sorted disjoint closed intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reach(Vec<(i64, i64)>);

impl Reach {
    fn all() -> Self {
        Self::between(MIN, MAX)
    }

    fn none() -> Self {
        Self(Vec::new())
    }

    fn between(low: i64, high: i64) -> Self {
        let (low, high) = (low.max(MIN), high.min(MAX));
        Self(if low <= high {
            vec![(low, high)]
        } else {
            Vec::new()
        })
    }

    fn union(&self, other: &Self) -> Self {
        let mut all = self.0.iter().chain(&other.0).copied().collect::<Vec<_>>();
        all.sort_unstable();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (low, high) in all {
            match merged.last_mut() {
                Some(last) if low <= last.1 + 1 => last.1 = last.1.max(high),
                _ => merged.push((low, high)),
            }
        }
        Self(merged)
    }

    fn complement(&self) -> Self {
        let mut gaps = Vec::new();
        let mut next = MIN;
        for &(low, high) in &self.0 {
            if next < low {
                gaps.push((next, low - 1));
            }
            next = high + 1;
        }
        if next <= MAX {
            gaps.push((next, MAX));
        }
        Self(gaps)
    }

    fn intersect(&self, other: &Self) -> Self {
        self.complement().union(&other.complement()).complement()
    }

    fn xor(&self, other: &Self) -> Self {
        let (a, b) = (
            self.intersect(&other.complement()),
            other.intersect(&self.complement()),
        );
        a.union(&b)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each interval cut to the multiples of `stride` it holds.
    fn snapped(&self, stride: i64) -> Self {
        let cut = |&(low, high): &(i64, i64)| {
            let (low, high) = (
                (low + stride - 1).div_euclid(stride) * stride,
                high.div_euclid(stride) * stride,
            );
            (low <= high).then_some((low, high))
        };
        Self(self.0.iter().filter_map(cut).collect())
    }

    /// The signed values of the unsigned 32-bit run `low..=high`.
    fn unsigned(low: i64, high: i64) -> Self {
        match (high <= MAX, low > MAX) {
            (true, _) => Self::between(low, high),
            (_, true) => Self::between(low - WRAP, high - WRAP),
            _ => Self::between(low, MAX).union(&Self::between(MIN, high - WRAP)),
        }
    }

    /// Every member moved by `by`, round the 32 bits.
    fn rotated(&self, by: i64) -> Self {
        let mut moved = Self::none();
        for &(low, high) in &self.0 {
            let start = (low + by - MIN).rem_euclid(WRAP) + MIN;
            let end = start + (high - low);
            let part = match end > MAX {
                true => Self::between(start, MAX).union(&Self::between(MIN, end - WRAP)),
                false => Self::between(start, end),
            };
            moved = moved.union(&part);
        }
        moved
    }
}

/// How two signed values compare.
#[derive(Debug, Clone, Copy)]
enum Order {
    Equal,
    Less,
    LessEqual,
}

impl Order {
    /// The values `a` for which `a` against the constant `c` holds (`c` against `a` when
    /// `reversed`).
    fn against(self, c: i64, reversed: bool) -> Reach {
        match (self, reversed) {
            (Self::Equal, _) => Reach::between(c, c),
            (Self::Less, false) => Reach::between(MIN, c - 1),
            (Self::LessEqual, false) => Reach::between(MIN, c),
            (Self::Less, true) => Reach::between(c + 1, MAX),
            (Self::LessEqual, true) => Reach::between(c, MAX),
        }
    }
}

/// The edges no run takes, and why a branch on an offset cursor was not decided.
#[derive(Default)]
pub(crate) struct Infeasible {
    pub(crate) edges: Vec<(BlockId, BlockId)>,
    pub(crate) notes: Vec<String>,
}

/// What a 32-bit operand is of the one offset cursor `x` a condition is about; `k` is added to it,
/// round the 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Num {
    Const(i64),
    Of(i64),
    /// The sign bit of `x + k`, as 0 or 1.
    Sign(i64),
}

impl Prover<'_> {
    /// The edges no run takes where the offset counts up to zero: a step runs only below zero, so
    /// it stays at most zero. O(predicates x dominators).
    pub(crate) fn infeasible(&self, cursors: &Cursors, predicates: &PredicateFacts) -> Infeasible {
        let mut found = Infeasible::default();
        let slot = i64::from(self.width);
        let up_to_zero = self.row.offset_width == 4 && self.next() <= 0 && self.next() % slot == 0;
        if !up_to_zero {
            return found;
        }
        if !self.steps_only_below_zero(cursors, predicates) {
            found
                .notes
                .push("an offset step runs where its value may not be negative".into());
            return found;
        }
        for fact in predicates.predicates.values() {
            let Some(block) = self.graph.block_id_for_addr(fact.block_addr) else {
                continue;
            };
            match self.always(cursors, predicates, (fact.condition, block)) {
                Ok(taken) => found.edges.extend(self.never_taken(fact, block, taken)),
                Err(Some(note)) => found.notes.push(note),
                Err(None) => {}
            }
        }
        found
    }

    /// The edge a branch never takes, given the way it always goes.
    fn never_taken(
        &self,
        fact: &PredicateFact,
        block: BlockId,
        taken: bool,
    ) -> Option<(BlockId, BlockId)> {
        let never = if taken {
            fact.false_target
        } else {
            fact.true_target
        };
        (self.graph.block_id_for_addr(never)).map(|to| (block, to))
    }

    /// Every step of the offset runs where the value stepped is negative, by the branches that
    /// dominate it alone.
    fn steps_only_below_zero(&self, cursors: &Cursors, predicates: &PredicateFacts) -> bool {
        cursors.step_insts.iter().all(|inst| {
            let Some(inst) = self.graph.inst(*inst) else {
                return false;
            };
            if inst.output.and_then(|out| cursors.kinds.get(out)) != Some(Kind::Offset) {
                return true;
            }
            let mut inputs = self.graph.inputs(inst.id).iter().copied();
            let cursor = inputs.find_map(|input| self.cursor(cursors, input));
            cursor.is_some_and(|cursor| {
                let known = self.known(cursors, predicates, (inst.block, cursor), Reach::all());
                known.intersect(&Reach::between(0, MAX)).is_empty()
            })
        })
    }

    /// Which way the branch on `condition` goes on every run, from the cursor's values at it. An
    /// error says why a branch on a cursor is undecided; a branch on no cursor says nothing.
    fn always(
        &self,
        cursors: &Cursors,
        predicates: &PredicateFacts,
        (condition, block): (ValueId, BlockId),
    ) -> Result<bool, Option<String>> {
        let mut only = None;
        let holds = self.holds(cursors, condition, &mut only, COPIES * 2);
        let Some(cursor) = only else {
            return Err(Some(format!(
                "TMP not about a cursor: {}",
                self.described(condition, 8)
            )));
        };
        let slot = i64::from(self.width);
        let holds = holds.ok_or_else(|| {
            Some(format!(
                "a branch on {cursor:?} is no set of its values: {}",
                self.described(condition, 6)
            ))
        })?;
        let possible = Reach::between(MIN, 0).snapped(slot);
        let possible = self
            .known(cursors, predicates, (block, cursor), possible)
            .snapped(slot);
        match (
            possible.intersect(&holds).is_empty(),
            possible.intersect(&holds.complement()).is_empty(),
        ) {
            (_, true) => Ok(true),
            (true, _) => Ok(false),
            _ => Err(Some(format!(
                "a branch on {cursor:?} holds for {holds:?}, the cursor is {possible:?}"
            ))),
        }
    }

    /// `possible`, cut to what the branches dominating `block` say of `cursor`.
    fn known(
        &self,
        cursors: &Cursors,
        predicates: &PredicateFacts,
        (block, cursor): (BlockId, ValueId),
        mut possible: Reach,
    ) -> Reach {
        let mut at = self.graph.block(block).map(|block| block.addr);
        while let Some(addr) = at {
            let assumptions = predicates.block_assumptions.get(&addr);
            for assumption in assumptions.into_iter().flatten() {
                let about = self.assumed(cursors, predicates, cursor, (addr, assumption));
                possible = about.map_or(possible.clone(), |reach| possible.intersect(&reach));
            }
            at = self.function.domtree().idom(addr);
        }
        possible
    }

    /// What an assumption that holds on the way into `addr` says of `cursor`.
    fn assumed(
        &self,
        cursors: &Cursors,
        predicates: &PredicateFacts,
        cursor: ValueId,
        (addr, assumption): (u64, &BlockAssumption),
    ) -> Option<Reach> {
        let edge = crate::values::edge_dominates(self.function, assumption.predecessor, addr);
        let fact = predicates
            .predicates
            .get(&assumption.predicate)
            .filter(|_| edge)?;
        let reach = self.holds(cursors, fact.condition, &mut Some(cursor), COPIES * 2)?;
        Some(match assumption.truth {
            true => reach,
            false => reach.complement(),
        })
    }

    /// The offset cursor a value holds in its low 32 bits, named by the value that makes it: the
    /// copies, widenings and low pieces of one cursor are all its.
    fn cursor(&self, cursors: &Cursors, value: ValueId) -> Option<ValueId> {
        let mut value = crate::view::class_value(self.graph, Some(&self.prep.views), value);
        for _ in 0..COPIES {
            cursors
                .kinds
                .get(value)
                .filter(|kind| *kind == Kind::Offset)?;
            let inst = self
                .graph
                .def_inst(value)
                .and_then(|inst| self.graph.inst(inst));
            let wraps = inst.and_then(|inst| match &inst.payload {
                InstPayload::Op(
                    SSAOp::Copy { src, .. }
                    | SSAOp::IntZExt { src, .. }
                    | SSAOp::Subpiece { src, offset: 0, .. },
                ) => Some(*src),
                _ => None,
            });
            match wraps.filter(|src| cursors.kinds.get(*src) == Some(Kind::Offset)) {
                Some(src) => value = src,
                None => return Some(value),
            }
        }
        None
    }

    /// The values of one offset cursor a boolean holds for. `only` names the cursor it is about:
    /// the one it must be about where one is given, else the one found.
    fn holds(
        &self,
        cursors: &Cursors,
        condition: ValueId,
        only: &mut Option<ValueId>,
        depth: usize,
    ) -> Option<Reach> {
        let depth = depth.checked_sub(1)?;
        let inst = self.graph.inst(self.graph.def_inst(condition)?)?;
        let InstPayload::Op(op) = &inst.payload else {
            return None;
        };
        let boolean = |value: ValueId, only: &mut Option<ValueId>| match self.constant(value) {
            Some(0) => Some(Reach::none()),
            Some(_) => Some(Reach::all()),
            None => self.holds(cursors, value, only, depth),
        };
        Some(match op {
            SSAOp::Copy { src, .. } => boolean(*src, only)?,
            SSAOp::BoolNot { src, .. } => boolean(*src, only)?.complement(),
            SSAOp::BoolOr { a, b, .. } => boolean(*a, only)?.union(&boolean(*b, only)?),
            SSAOp::BoolAnd { a, b, .. } => boolean(*a, only)?.intersect(&boolean(*b, only)?),
            SSAOp::BoolXor { a, b, .. } => boolean(*a, only)?.xor(&boolean(*b, only)?),
            SSAOp::IntEqual { a, b, .. } | SSAOp::IntNotEqual { a, b, .. } => {
                let reach = match self.size(*a) == 1 && self.size(*b) == 1 {
                    true => boolean(*a, only)?.xor(&boolean(*b, only)?).complement(),
                    false => self.compare(cursors, (*a, *b), only, Order::Equal)?,
                };
                match op {
                    SSAOp::IntEqual { .. } => reach,
                    _ => reach.complement(),
                }
            }
            SSAOp::IntSLess { a, b, .. } => self.compare(cursors, (*a, *b), only, Order::Less)?,
            SSAOp::IntSLessEqual { a, b, .. } => {
                self.compare(cursors, (*a, *b), only, Order::LessEqual)?
            }
            SSAOp::IntSBorrow { a, b, .. } => self.overflow(cursors, (*a, *b), only, false)?,
            SSAOp::IntSCarry { a, b, .. } => self.overflow(cursors, (*a, *b), only, true)?,
            SSAOp::IntCarry { a, b, .. } => self.carry(cursors, (*a, *b), only)?,
            _ => return None,
        })
    }

    /// `a` against `b`, where one is the cursor moved by a constant and the other a constant, or
    /// the cursor's sign bit against zero or one.
    fn compare(
        &self,
        cursors: &Cursors,
        (a, b): (ValueId, ValueId),
        only: &mut Option<ValueId>,
        order: Order,
    ) -> Option<Reach> {
        let (left, right) = (self.num(cursors, a, only)?, self.num(cursors, b, only)?);
        Some(match (left, right) {
            (Num::Const(a), Num::Const(b)) => {
                let holds = match order {
                    Order::Equal => a == b,
                    Order::Less => a < b,
                    Order::LessEqual => a <= b,
                };
                if holds { Reach::all() } else { Reach::none() }
            }
            (Num::Of(k), Num::Const(c)) => order.against(c, false).rotated(-k),
            (Num::Const(c), Num::Of(k)) => order.against(c, true).rotated(-k),
            (Num::Sign(k), Num::Const(c)) | (Num::Const(c), Num::Sign(k))
                if matches!(order, Order::Equal) =>
            {
                match c {
                    0 => Reach::between(0, MAX).rotated(-k),
                    1 => Reach::between(MIN, -1).rotated(-k),
                    _ => Reach::none(),
                }
            }
            _ => return None,
        })
    }

    /// Where `a + b` carries out of the unsigned 32 bits, for the cursor moved by a constant and a
    /// constant: the flag `cmn` sets.
    fn carry(
        &self,
        cursors: &Cursors,
        (a, b): (ValueId, ValueId),
        only: &mut Option<ValueId>,
    ) -> Option<Reach> {
        if self.size(a) != 4 {
            return None;
        }
        let (left, right) = (self.num(cursors, a, only)?, self.num(cursors, b, only)?);
        let ((Num::Of(k), Num::Const(c)) | (Num::Const(c), Num::Of(k))) = (left, right) else {
            return None;
        };
        let c = c.rem_euclid(WRAP);
        Some(match c {
            0 => Reach::none(),
            _ => Reach::unsigned(WRAP - c, WRAP - 1).rotated(-k),
        })
    }

    /// Where `a - b` (or `a + b`) leaves the signed 32 bits, for the cursor moved by a constant
    /// against a constant.
    fn overflow(
        &self,
        cursors: &Cursors,
        (a, b): (ValueId, ValueId),
        only: &mut Option<ValueId>,
        sum: bool,
    ) -> Option<Reach> {
        let (left, right) = (self.num(cursors, a, only)?, self.num(cursors, b, only)?);
        let (moved, c) = match (left, right) {
            (Num::Of(k), Num::Const(c)) => (Some((k, false)), c),
            (Num::Const(c), Num::Of(k)) => (Some((k, true)), c),
            _ => return None,
        };
        let (k, constant_first) = moved?;
        // The values `v` of the cursor moved by `k` for which the operation on `v` and `c` leaves
        // the range.
        let leaving = match (sum, constant_first) {
            (true, _) => Reach::between(MIN, MIN - c - 1).union(&Reach::between(MAX - c + 1, MAX)),
            (false, false) => {
                Reach::between(MIN, MIN + c - 1).union(&Reach::between(MAX + c + 1, MAX))
            }
            (false, true) => {
                Reach::between(MIN, c - MAX - 1).union(&Reach::between(c - MIN + 1, MAX))
            }
        };
        Some(leaving.rotated(-k))
    }

    /// A 32-bit operand as the cursor moved by a constant, a constant, or its sign bit: through
    /// the copies, widenings and low pieces, to the merge or the load that makes the cursor.
    fn num(&self, cursors: &Cursors, value: ValueId, only: &mut Option<ValueId>) -> Option<Num> {
        if let Some(bits) = self.constant(value) {
            let shift = 64 - 8 * self.size(value).clamp(1, 8);
            return Some(Num::Const(
                i64::from_ne_bytes(bits.to_ne_bytes()) << shift >> shift,
            ));
        }
        let leaf = |only: &mut Option<ValueId>| match cursors.kinds.get(value) {
            Some(Kind::Offset) => (*only.get_or_insert(value) == value).then_some(Num::Of(0)),
            _ => None,
        };
        let inst = self
            .graph
            .def_inst(value)
            .and_then(|inst| self.graph.inst(inst));
        let Some(InstPayload::Op(op)) = inst.map(|inst| &inst.payload) else {
            return leaf(only);
        };
        match op {
            SSAOp::Copy { src, .. }
            | SSAOp::Subpiece { src, offset: 0, .. }
            | SSAOp::IntZExt { src, .. } => self.num(cursors, *src, only),
            SSAOp::IntAdd { a, b, .. } => self.moved(cursors, (*a, *b), only, false),
            SSAOp::IntSub { a, b, .. } => self.moved(cursors, (*a, *b), only, true),
            SSAOp::IntRight { a, b, .. } | SSAOp::IntSRight { a, b, .. } => {
                let top = u64::from(self.size(*a)) * 8 - 1;
                match (self.num(cursors, *a, only)?, self.constant(*b)) {
                    (Num::Of(k), Some(by)) if by == top => Some(Num::Sign(k)),
                    _ => None,
                }
            }
            SSAOp::IntAnd { a, b, .. } => match (self.num(cursors, *a, only)?, self.constant(*b)) {
                (sign @ Num::Sign(_), Some(1)) => Some(sign),
                _ => None,
            },
            _ => leaf(only),
        }
    }

    /// The cursor moved by a constant: `a + b`, or `a - b`.
    fn moved(
        &self,
        cursors: &Cursors,
        (a, b): (ValueId, ValueId),
        only: &mut Option<ValueId>,
        subtract: bool,
    ) -> Option<Num> {
        match (self.num(cursors, a, only)?, self.num(cursors, b, only)?) {
            (Num::Of(k), Num::Const(c)) => Some(Num::Of(if subtract { k - c } else { k + c })),
            (Num::Const(c), Num::Of(k)) if !subtract => Some(Num::Of(k + c)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reach(parts: &[(i64, i64)]) -> Reach {
        Reach(parts.to_vec())
    }

    #[test]
    fn a_complement_and_a_union_agree_on_what_is_left() {
        let below = Reach::between(MIN, -8);
        assert_eq!(below.complement(), Reach::between(-7, MAX));
        assert_eq!(below.union(&below.complement()), Reach::all());
        assert!(below.intersect(&below.complement()).is_empty());
    }

    #[test]
    fn a_sum_below_zero_wraps_to_the_values_past_the_top() {
        // `x + 8 <= 0` in 32 bits: the sum is at most zero for x up to -8 and wrapped past MAX - 7.
        let holds = Order::LessEqual.against(0, false).rotated(-8);
        assert_eq!(holds, reach(&[(MIN, -8), (MAX - 7, MAX)]));
    }

    #[test]
    fn a_stepped_cursor_below_zero_is_at_most_a_slot_below_it() {
        let possible = Reach::between(MIN, -1).snapped(8);
        assert_eq!(possible, Reach::between(MIN, -8));
        let stepped_at_most_zero = Order::LessEqual.against(0, false).rotated(-8);
        assert!(
            possible
                .intersect(&stepped_at_most_zero.complement())
                .is_empty()
        );
    }

    #[test]
    fn an_overflowing_add_is_the_cursors_top_slots() {
        let leaving = Reach::between(MIN, MIN - 8 - 1).union(&Reach::between(MAX - 8 + 1, MAX));
        assert_eq!(leaving, Reach::between(MAX - 7, MAX));
    }

    #[test]
    fn a_sum_with_a_slot_carries_for_the_top_slots_and_not_for_the_negative_cursor_beyond_them() {
        let carries = Reach::unsigned(WRAP - 8, WRAP - 1);
        assert_eq!(carries, Reach::between(-8, -1));
        // `lower or same` after `cmn x, #8` holds for a cursor below zero in whole slots.
        let possible = Reach::between(MIN, -1).snapped(8);
        let holds = carries.complement().union(&Reach::between(-8, -8));
        assert!(possible.intersect(&holds.complement()).is_empty());
        assert_eq!(
            Reach::unsigned(MAX, MAX + 2),
            reach(&[(MIN, MIN + 1), (MAX, MAX)])
        );
    }

    #[test]
    fn rotating_a_set_keeps_its_size_and_wraps_at_the_top() {
        let set = Reach::between(MAX - 3, MAX);
        assert_eq!(set.rotated(2), reach(&[(MIN, MIN + 1), (MAX - 1, MAX)]));
        assert_eq!(set.rotated(WRAP), set);
    }
}
