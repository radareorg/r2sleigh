//! Strided intervals: what a machine integer can be.
//!
//! The abstract domain the value-set analysis is built on. A value is
//! described by a stride and two bounds -- `4[0, 40]` is every fourth number
//! from nought to forty -- which is what an index into an array of four-byte
//! elements actually looks like, and what an interval alone cannot say.
//!
//! Everything here is width-correct: a domain element belongs to a machine
//! integer of a stated width, and an operation that would leave that width
//! wraps or gives up rather than silently widening. `indirect.rs` refuses on
//! wrap today because its hand-rolled interval has no width to wrap in.
//!
//! The lattice is the usual one. Bottom is the empty set, top is every value
//! of the width, and `join` is the least upper bound. `widen` exists because
//! the lattice has unbounded ascending chains through the bounds, and a
//! fixpoint over a loop would otherwise climb one iteration at a time; it is
//! the convergence operator such a lattice requires, not a budget.

/// Every value a machine integer of some width can hold, described by a
/// stride and two bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StridedInterval {
    width_bits: u32,
    /// `None` is the empty set. Otherwise the stride, and the inclusive
    /// bounds, read as unsigned values of the width.
    body: Option<Body>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Body {
    /// Nought for a single value; otherwise the step between neighbours.
    stride: u64,
    low: u64,
    high: u64,
}

impl StridedInterval {
    /// The empty set: a value that cannot happen.
    pub const fn bottom(width_bits: u32) -> Self {
        Self {
            width_bits,
            body: None,
        }
    }

    /// Every value of this width.
    pub fn top(width_bits: u32) -> Self {
        Self::interval(width_bits, 0, Self::mask_for(width_bits))
    }

    /// Exactly one value.
    pub fn constant(width_bits: u32, value: u64) -> Self {
        let value = value & Self::mask_for(width_bits);
        Self {
            width_bits,
            body: Some(Body {
                stride: 0,
                low: value,
                high: value,
            }),
        }
    }

    /// Every value between two bounds, inclusive.
    pub fn interval(width_bits: u32, low: u64, high: u64) -> Self {
        Self::strided(width_bits, 1, low, high)
    }

    /// Every `stride`th value from `low` up to `high`.
    ///
    /// The bounds are canonicalised: `high` is pulled down to the last value
    /// the stride actually reaches, and a range holding one value loses its
    /// stride, so equal sets compare equal.
    pub fn strided(width_bits: u32, stride: u64, low: u64, high: u64) -> Self {
        let mask = Self::mask_for(width_bits);
        let (low, high) = (low & mask, high & mask);
        if low > high {
            return Self::bottom(width_bits);
        }
        if low == high || stride == 0 {
            return Self::constant(width_bits, low);
        }
        // A stride past the span reaches only `low`; masking it would invent a finer one.
        let span = high - low;
        let high = low + span - span % stride;
        match low == high {
            true => Self::constant(width_bits, low),
            false => Self {
                width_bits,
                body: Some(Body { stride, low, high }),
            },
        }
    }

    pub const fn width_bits(&self) -> u32 {
        self.width_bits
    }

    pub const fn is_bottom(&self) -> bool {
        self.body.is_none()
    }

    pub fn is_top(&self) -> bool {
        self.body.is_some_and(|body| {
            body.stride <= 1 && body.low == 0 && body.high == Self::mask_for(self.width_bits)
        })
    }

    /// The one value this describes, where it describes one.
    pub fn as_constant(&self) -> Option<u64> {
        self.body
            .filter(|body| body.low == body.high)
            .map(|body| body.low)
    }

    /// The step between neighbouring values, or `None` for a single value.
    pub fn stride(&self) -> Option<u64> {
        self.body
            .filter(|body| body.low != body.high)
            .map(|body| body.stride)
    }

    /// The inclusive bounds, read unsigned.
    pub fn bounds(&self) -> Option<(u64, u64)> {
        self.body.map(|body| (body.low, body.high))
    }

    /// Every value this describes, in order.
    ///
    /// Useful only where the count is small -- the case labels of a switch --
    /// and the caller is the one who knows that.
    pub fn values(&self) -> impl Iterator<Item = u64> + '_ {
        let body = self.body;
        let step = body.map_or(1, |body| body.stride.max(1));
        std::iter::successors(body.map(|body| body.low), move |at| {
            let next = at.checked_add(step)?;
            body.filter(|body| next <= body.high).map(|_| next)
        })
    }

    /// How many values this describes, where that is worth counting.
    pub fn count(&self) -> Option<u64> {
        let body = self.body?;
        match body.low == body.high {
            true => Some(1),
            false => Some((body.high - body.low) / body.stride + 1),
        }
    }

    pub fn contains(&self, value: u64) -> bool {
        let value = value & Self::mask_for(self.width_bits);
        self.body.is_some_and(|body| {
            value >= body.low
                && value <= body.high
                && (body.stride == 0 || (value - body.low).is_multiple_of(body.stride))
        })
    }

    /// The least element holding everything either holds.
    ///
    /// The stride of a join is the greatest common divisor of both strides and
    /// of the distance between their starts, which is the coarsest step that
    /// still reaches every value in the union.
    pub fn join(&self, other: &Self) -> Self {
        debug_assert_eq!(self.width_bits, other.width_bits);
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return match self.body.is_some() {
                true => *self,
                false => *other,
            };
        };
        let low = left.low.min(right.low);
        let high = left.high.max(right.high);
        let stride = gcd(gcd(left.stride, right.stride), left.low.abs_diff(right.low));
        Self::strided(self.width_bits, stride.max(1), low, high)
    }

    /// The greatest element both hold: two progressions' intersection, solved in `O(log stride)` (doc/ssa.md).
    pub fn meet(&self, other: &Self) -> Self {
        debug_assert_eq!(self.width_bits, other.width_bits);
        let width = self.width_bits;
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return Self::bottom(width);
        };
        let (low, high) = (left.low.max(right.low), left.high.min(right.high));
        if low > high {
            return Self::bottom(width);
        }
        let Some((first, step)) = common_progression(
            (left.low, left.stride.max(1)),
            (right.low, right.stride.max(1)),
            low,
        ) else {
            return Self::bottom(width);
        };
        let high = u128::from(high);
        match (first > high, step > high.saturating_sub(first)) {
            (true, _) => Self::bottom(width),
            // One common value in range: the next is past `high`, perhaps past `u64` itself.
            (false, true) => Self::constant(width, first as u64),
            (false, false) => Self::strided(width, step as u64, first as u64, high as u64),
        }
    }

    /// Jump a moved bound to the width's extreme on the join's stride and residue (doc/ssa.md, "widen").
    pub fn widen(&self, next: &Self) -> Self {
        debug_assert_eq!(self.width_bits, next.width_bits);
        let (Some(old), Some(new)) = (self.body, next.body) else {
            return match next.body.is_some() {
                true => *next,
                false => *self,
            };
        };
        let mask = Self::mask_for(self.width_bits);
        let stride = gcd(gcd(old.stride, new.stride), old.low.abs_diff(new.low)).max(1);
        let low = match new.low < old.low {
            true => new.low % stride,
            false => old.low,
        };
        let high = match new.high > old.high {
            true => mask - (mask - low) % stride,
            false => old.high,
        };
        Self::strided(self.width_bits, stride, low, high)
    }

    /// Addition at this width, wrapping where the machine would.
    ///
    /// A range that wraps past the width's end is not describable by one
    /// interval, so it becomes top rather than a range that excludes values
    /// the program can reach.
    pub fn add(&self, other: &Self) -> Self {
        self.pointwise(other, |a, b| a.checked_add(b))
    }

    pub fn sub(&self, other: &Self) -> Self {
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return Self::bottom(self.width_bits);
        };
        let Some(low) = left.low.checked_sub(right.high) else {
            return Self::top(self.width_bits);
        };
        let Some(high) = left.high.checked_sub(right.low) else {
            return Self::top(self.width_bits);
        };
        let stride = gcd(left.stride, right.stride).max(1);
        self.bounded(stride, low, high)
    }

    /// Multiplication, which scales the stride as well as the bounds.
    pub fn mul(&self, other: &Self) -> Self {
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return Self::bottom(self.width_bits);
        };
        // Scaling by a single value is the case array indexing produces, and
        // the only one where the result is still a clean stride.
        let Some(scale) = other.as_constant() else {
            return match self.as_constant() {
                Some(_) => other.mul(self),
                None => Self::top(self.width_bits),
            };
        };
        let _ = right;
        let (Some(low), Some(high)) = (left.low.checked_mul(scale), left.high.checked_mul(scale))
        else {
            return Self::top(self.width_bits);
        };
        let stride = left.stride.saturating_mul(scale).max(1);
        self.bounded(stride, low, high)
    }

    /// A remainder is smaller than its divisor, and no larger than what it
    /// divides. That is the bound a table indexed by `x % n` needs, and it
    /// holds whatever the dividend was.
    pub fn rem(&self, divisor: &Self) -> Self {
        let width = self.width_bits;
        let (Some((_, dividend)), Some((low, high))) = (self.bounds(), divisor.bounds()) else {
            return Self::bottom(width);
        };
        // A divisor that can be nought says nothing: the division does not
        // happen, and the width is the only honest answer.
        match low >= 1 {
            true => Self::interval(width, 0, dividend.min(high.saturating_sub(1))),
            false => Self::top(width),
        }
    }

    /// A quotient shrinks by at least the smallest its divisor can be.
    pub fn div(&self, divisor: &Self) -> Self {
        let width = self.width_bits;
        let (Some((dividend_low, dividend_high)), Some((low, high))) =
            (self.bounds(), divisor.bounds())
        else {
            return Self::bottom(width);
        };
        match low >= 1 {
            true => Self::interval(width, dividend_low / high, dividend_high / low),
            false => Self::top(width),
        }
    }

    /// A mask keeps the values below it, which is how a modulo by a power of
    /// two is spelled and how an alignment is imposed.
    pub fn and_mask(&self, mask: u64) -> Self {
        let width_mask = Self::mask_for(self.width_bits);
        let mask = mask & width_mask;
        match mask == width_mask {
            true => *self,
            false => Self::interval(self.width_bits, 0, mask),
        }
    }

    /// A left shift is a multiplication by a power of two.
    pub fn shl(&self, places: u32) -> Self {
        if places >= self.width_bits.min(Self::MAX_WIDTH_BITS) {
            return Self::constant(self.width_bits, 0);
        }
        self.mul(&Self::constant(self.width_bits, 1u64 << places))
    }

    /// A logical right shift, whose stride survives only where `2^places` divides it (doc/ssa.md, "shr").
    pub fn shr(&self, places: u32) -> Self {
        if places >= self.width_bits.min(Self::MAX_WIDTH_BITS) {
            return Self::constant(self.width_bits, 0);
        }
        let Some(body) = self.body else {
            return Self::bottom(self.width_bits);
        };
        let stride = match body.stride.trailing_zeros() >= places {
            true => (body.stride >> places).max(1),
            false => 1,
        };
        self.bounded(stride, body.low >> places, body.high >> places)
    }

    /// Everything strictly below a bound, as a comparison proves.
    pub fn below(&self, bound: u64) -> Self {
        match bound.checked_sub(1) {
            Some(high) => self.meet(&Self::interval(self.width_bits, 0, high)),
            None => Self::bottom(self.width_bits),
        }
    }

    /// Everything at or below a bound.
    pub fn at_most(&self, bound: u64) -> Self {
        self.meet(&Self::interval(self.width_bits, 0, bound))
    }

    fn pointwise(&self, other: &Self, op: impl Fn(u64, u64) -> Option<u64>) -> Self {
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return Self::bottom(self.width_bits);
        };
        let (Some(low), Some(high)) = (op(left.low, right.low), op(left.high, right.high)) else {
            return Self::top(self.width_bits);
        };
        let stride = gcd(left.stride, right.stride).max(1);
        self.bounded(stride, low, high)
    }

    /// A result that left the width is not describable here, so it is top.
    fn bounded(&self, stride: u64, low: u64, high: u64) -> Self {
        let mask = Self::mask_for(self.width_bits);
        match low > mask || high > mask {
            true => Self::top(self.width_bits),
            false => Self::strided(self.width_bits, stride, low, high),
        }
    }

    /// The widest value this domain describes.
    ///
    /// A vector register is a hundred and twenty-eight bits and this is built
    /// on `u64`, so anything wider is described at sixty-four and is top there
    /// rather than shifted by a distance `u64` does not have.
    pub const MAX_WIDTH_BITS: u32 = 64;

    fn mask_for(width_bits: u32) -> u64 {
        match width_bits >= Self::MAX_WIDTH_BITS {
            true => u64::MAX,
            false => (1u64 << width_bits) - 1,
        }
    }
}

/// The first common value at or above `from` and the lcm step, or `None` out of phase (CRT; doc/ssa.md, "meet").
fn common_progression(left: (u64, u64), right: (u64, u64), from: u64) -> Option<(u128, u128)> {
    let ((left_start, left_stride), (right_start, right_stride)) = (left, right);
    let divisor = gcd(left_stride, right_stride);
    let difference = i128::from(right_start) - i128::from(left_start);
    if difference % i128::from(divisor) != 0 {
        return None;
    }
    // left_start + left_stride·t hits the right progression when (left_stride/g)·t ≡ difference/g mod (right_stride/g).
    let modulus = right_stride / divisor;
    let residue = (difference / i128::from(divisor)).rem_euclid(i128::from(modulus)) as u128;
    let steps = residue * u128::from(inverse(left_stride / divisor, modulus)) % u128::from(modulus);
    let step = u128::from(left_stride / divisor) * u128::from(right_stride);
    let solution = u128::from(left_start) + u128::from(left_stride) * steps;
    let from = u128::from(from);
    let first = match solution >= from {
        true => from + (solution - from) % step,
        false => from + (step - (from - solution) % step) % step,
    };
    Some((first, step))
}

/// The inverse of `value` modulo `modulus`, which the caller made coprime to it.
fn inverse(value: u64, modulus: u64) -> u64 {
    let (mut remainder, mut next_remainder) = (i128::from(value % modulus), i128::from(modulus));
    let (mut coefficient, mut next_coefficient) = (1i128, 0i128);
    while next_remainder != 0 {
        let quotient = remainder / next_remainder;
        (remainder, next_remainder) = (next_remainder, remainder - quotient * next_remainder);
        (coefficient, next_coefficient) =
            (next_coefficient, coefficient - quotient * next_coefficient);
    }
    coefficient.rem_euclid(i128::from(modulus)) as u64
}

fn gcd(a: u64, b: u64) -> u64 {
    match b {
        0 => a,
        b => gcd(b, a % b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_stride_reaches_only_its_own_values() {
        let four = StridedInterval::strided(32, 4, 0, 40);
        assert!(four.contains(0));
        assert!(four.contains(40));
        assert!(!four.contains(2));
        assert_eq!(four.count(), Some(11));
        assert_eq!(four.stride(), Some(4));
    }

    #[test]
    fn a_high_bound_is_pulled_down_to_what_the_stride_reaches() {
        // 4[0, 42] holds nothing above forty, and says so.
        let pulled = StridedInterval::strided(32, 4, 0, 42);
        assert_eq!(pulled.bounds(), Some((0, 40)));
        assert!(!pulled.contains(42));
    }

    #[test]
    fn a_join_keeps_a_stride_both_sides_reach() {
        let left = StridedInterval::strided(32, 4, 0, 8);
        let right = StridedInterval::strided(32, 4, 16, 24);
        let joined = left.join(&right);
        assert_eq!(joined.stride(), Some(4));
        assert!(joined.contains(12), "the join is allowed to be wider");
        assert!(!joined.contains(13));
    }

    #[test]
    fn a_join_of_misaligned_starts_coarsens_the_stride() {
        let left = StridedInterval::strided(32, 4, 0, 8);
        let right = StridedInterval::strided(32, 4, 1, 9);
        let joined = left.join(&right);
        assert_eq!(joined.stride(), Some(1));
    }

    #[test]
    fn a_meet_never_invents_a_value_neither_side_holds() {
        let evens = StridedInterval::strided(32, 2, 0, 10);
        let odds = StridedInterval::strided(32, 2, 1, 11);
        let met = evens.meet(&odds);
        for value in 0..12 {
            assert!(
                !met.contains(value) || (evens.contains(value) && odds.contains(value)),
                "{value} is in the meet but not in both"
            );
        }
    }

    #[test]
    fn progressions_out_of_phase_share_nothing() {
        let evens = StridedInterval::strided(32, 2, 0, 10);
        let odds = StridedInterval::strided(32, 2, 1, 11);
        assert!(evens.meet(&odds).is_bottom());
    }

    #[test]
    fn a_meet_keeps_every_value_both_sides_hold() {
        let sixes = StridedInterval::strided(32, 6, 0, 60);
        let fours = StridedInterval::strided(32, 4, 0, 60);
        let met = sixes.meet(&fours);
        // Twelve is the first common step, and every multiple of it survives.
        for value in (0..=60).filter(|v| v % 12 == 0) {
            assert!(met.contains(value), "{value} was lost from the meet");
        }
    }

    #[test]
    fn widening_jumps_to_the_width_rather_than_climbing() {
        let first = StridedInterval::constant(32, 0);
        let second = StridedInterval::interval(32, 0, 1);
        let widened = first.widen(&second);
        assert_eq!(widened.bounds(), Some((0, u32::MAX as u64)));
        // A bound that did not grow is kept, so widening is not top.
        let stable = StridedInterval::interval(32, 0, 10);
        assert_eq!(stable.widen(&stable).bounds(), Some((0, 10)));
    }

    #[test]
    fn a_low_that_fell_keeps_the_residue_of_what_both_held() {
        // `4[0, 8]` would drop the ten the old side held.
        let widened =
            StridedInterval::constant(32, 10).widen(&StridedInterval::strided(32, 4, 6, 10));
        assert!(widened.contains(10), "{widened:?}");
        assert!(widened.contains(6), "{widened:?}");
    }

    #[test]
    fn a_shift_that_drops_a_carry_loses_the_stride() {
        // {1, 11, 21} >> 2 is {0, 2, 5}: no stride of two reaches five.
        let shifted = StridedInterval::strided(32, 10, 1, 21).shr(2);
        assert!(shifted.contains(5), "{shifted:?}");
    }

    #[test]
    fn strides_whose_common_multiple_leaves_u64_still_share_a_value() {
        // Coprime strides near 2^32 meet only every 2^65 or so, which u64 cannot hold.
        let odd = (1u64 << 33) + 1;
        let left = StridedInterval::strided(64, odd, 5, 5 + 3 * odd);
        let right = StridedInterval::strided(64, 1 << 32, 5, 5 + (4 << 32));
        assert_eq!(left.meet(&right), StridedInterval::constant(64, 5));
    }

    #[test]
    fn a_meet_solves_for_the_common_value_rather_than_scanning_for_it() {
        let huge = StridedInterval::strided(64, 1 << 32, 0, 1 << 32);
        let met = huge.meet(&StridedInterval::interval(64, 1, 1 << 40));
        assert_eq!(met, StridedInterval::constant(64, 1 << 32));
    }

    /// Every element of a width, beside the set it describes as a bitmask.
    fn every_element(width: u32) -> Vec<(StridedInterval, u32)> {
        let top = (1u64 << width) - 1;
        let reach = |low: u64, stride: u64, steps: u64| {
            (0..=steps).fold(0u32, |set, step| set | 1 << (low + step * stride))
        };
        let progressions = (0..=top)
            .flat_map(|low| (1..=top).map(move |stride| (low, stride)))
            .flat_map(|(low, stride)| {
                (0..=(top - low) / stride).map(move |steps| (low, stride, steps))
            })
            // Nought steps is a constant, listed once rather than once per stride.
            .filter(|(_, stride, steps)| *steps > 0 || *stride == 1)
            .map(|(low, stride, steps)| {
                let high = low + steps * stride;
                (
                    StridedInterval::strided(width, stride, low, high),
                    reach(low, stride, steps),
                )
            });
        std::iter::once((StridedInterval::bottom(width), 0))
            .chain(progressions)
            .collect()
    }

    /// The values a bitmask holds, lowest first.
    fn members(mut set: u32) -> impl Iterator<Item = u64> {
        std::iter::from_fn(move || {
            let value = (set != 0).then(|| u64::from(set.trailing_zeros()))?;
            set &= set - 1;
            Some(value)
        })
    }

    fn described(element: &StridedInterval) -> u32 {
        element.values().fold(0, |set, value| set | 1 << value)
    }

    /// Checks `op(a, b) ∈ γ(abstract(A, B))` for every pair of elements of a width and every pair of their members.
    fn exhaustively(
        width: u32,
        concrete: impl Fn(u64, u64) -> Option<u64>,
        abstracted: impl Fn(&StridedInterval, &StridedInterval) -> StridedInterval,
    ) {
        let all = every_element(width);
        // What each left value makes of each right element, so a pair costs |A| rather than |A|·|B|.
        let reached = (0..1u64 << width)
            .map(|a| {
                all.iter()
                    .map(|(_, right)| {
                        members(*right)
                            .filter_map(|b| concrete(a, b))
                            .fold(0u32, |set, value| set | 1 << value)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for (left, left_set) in &all {
            for (index, (right, _)) in all.iter().enumerate() {
                let results = members(*left_set).fold(0, |set, a| set | reached[a as usize][index]);
                let result = abstracted(left, right);
                let missed = members(results).find(|value| !result.contains(*value));
                assert_eq!(missed, None, "{left:?} {right:?} -> {result:?}");
            }
        }
    }

    /// Checks `op(a) ∈ γ(abstract(A))` for every element of a width and every member of it.
    fn exhaustively_unary(
        width: u32,
        concrete: impl Fn(u64) -> u64,
        abstracted: impl Fn(&StridedInterval) -> StridedInterval,
    ) {
        for (element, set) in every_element(width) {
            let result = abstracted(&element);
            let missed = members(set)
                .map(&concrete)
                .find(|value| !result.contains(*value));
            assert_eq!(missed, None, "{element:?} -> {result:?}");
        }
    }

    /// Every operation at one width, against what the machine computes.
    fn every_operation_at(width: u32) {
        let mask = (1u64 << width) - 1;
        exhaustively(width, |a, b| Some((a + b) & mask), |l, r| l.add(r));
        exhaustively(
            width,
            |a, b| Some(a.wrapping_sub(b) & mask),
            |l, r| l.sub(r),
        );
        exhaustively(width, |a, b| Some((a * b) & mask), |l, r| l.mul(r));
        exhaustively(width, |a, b| a.checked_rem(b), |l, r| l.rem(r));
        exhaustively(width, |a, b| a.checked_div(b), |l, r| l.div(r));
        for places in 0..=width + 1 {
            let kept = |value: u64| if places < width { value & mask } else { 0 };
            exhaustively_unary(width, |a| kept(a << places.min(63)), |l| l.shl(places));
            exhaustively_unary(width, |a| kept(a >> places.min(63)), |l| l.shr(places));
        }
        for bits in 0..=mask {
            exhaustively_unary(width, |a| a & bits, |l| l.and_mask(bits));
        }
    }

    #[test]
    fn every_operation_keeps_every_concrete_result_at_small_widths() {
        (1..=5).for_each(every_operation_at);
    }

    /// Join and widen hold both sides, and meet is exactly what both hold, at one width.
    fn every_lattice_operation_at(width: u32) {
        let all = every_element(width);
        for (element, set) in &all {
            assert_eq!(described(element), *set, "{element:?}");
        }
        let pairs = all
            .iter()
            .flat_map(|left| all.iter().map(move |right| (left, right)));
        for ((left, left_set), (right, right_set)) in pairs {
            let both = left_set | right_set;
            let joined = left.join(right);
            assert_eq!(described(&joined) & both, both, "{left:?} join {right:?}");
            let widened = left.widen(right);
            assert_eq!(described(&widened) & both, both, "{left:?} widen {right:?}");
            // Two progressions meet in a progression, so the meet is exact.
            let met = left.meet(right);
            assert_eq!(
                described(&met),
                left_set & right_set,
                "{left:?} meet {right:?}"
            );
        }
    }

    #[test]
    fn the_lattice_operations_hold_what_they_promise_at_small_widths() {
        (1..=5).for_each(every_lattice_operation_at);
    }

    /// An element of a width and one value it holds, from unconstrained numbers.
    fn element_and_member(
        width: u32,
        (low, stride, span, pick): (u64, u64, u64, u64),
    ) -> (StridedInterval, u64) {
        let mask = StridedInterval::top(width).bounds().expect("top").1;
        let low = low & mask;
        let element =
            StridedInterval::strided(width, stride, low, low.saturating_add(span).min(mask));
        let (low, high) = element.bounds().expect("never bottom");
        let step = u128::from(element.stride().unwrap_or(1));
        let count = u128::from(high - low) / step + 1;
        (
            element,
            (u128::from(low) + u128::from(pick) % count * step) as u64,
        )
    }

    fn any_element() -> impl Strategy<Value = (u64, u64, u64, u64)> {
        let stride = prop_oneof![0u64..17, (0u32..64).prop_map(|p| 1u64 << p), any::<u64>()];
        let span = prop_oneof![0u64..300, any::<u64>()];
        (any::<u64>(), stride, span, any::<u64>())
    }

    proptest! {
        #[test]
        fn every_operation_keeps_its_concrete_results_at_machine_widths(
            wide in any::<bool>(),
            left in any_element(),
            right in any_element(),
            places in 0u32..66,
            bits in any::<u64>(),
        ) {
            let width = if wide { 64 } else { 32 };
            let mask = StridedInterval::top(width).bounds().expect("top").1;
            let (left, a) = element_and_member(width, left);
            let (right, b) = element_and_member(width, right);
            let kept = |value: u64| if places < width { value & mask } else { 0 };
            let checks = [
                (left.add(&right), Some(a.wrapping_add(b) & mask)),
                (left.sub(&right), Some(a.wrapping_sub(b) & mask)),
                (left.mul(&right), Some(a.wrapping_mul(b) & mask)),
                (left.rem(&right), a.checked_rem(b)),
                (left.div(&right), a.checked_div(b)),
                (left.shl(places), Some(kept(a << places.min(63)))),
                (left.shr(places), Some(kept(a >> places.min(63)))),
                (left.and_mask(bits), Some(a & bits & mask)),
                (left.join(&right), Some(a)),
                (left.join(&right), Some(b)),
                (left.widen(&right), Some(a)),
                (left.widen(&right), Some(b)),
                (left.meet(&right), right.contains(a).then_some(a)),
            ];
            for (result, value) in checks {
                if let Some(value) = value {
                    prop_assert!(result.contains(value), "{:?} {:?} -> {:?} misses {}", left, right, result, value);
                }
            }
        }
    }

    #[test]
    fn multiplying_scales_the_stride_which_is_what_an_index_does() {
        let index = StridedInterval::interval(32, 0, 9);
        let offsets = index.mul(&StridedInterval::constant(32, 4));
        assert_eq!(offsets.stride(), Some(4));
        assert_eq!(offsets.bounds(), Some((0, 36)));
    }

    #[test]
    fn leaving_the_width_gives_top_rather_than_a_wrong_range() {
        let high = StridedInterval::constant(8, 0xff);
        let sum = high.add(&StridedInterval::constant(8, 1));
        assert!(sum.is_top(), "{sum:?}");
    }

    #[test]
    fn a_comparison_narrows_to_what_it_proves() {
        let any = StridedInterval::top(32);
        let bounded = any.below(10);
        assert_eq!(bounded.bounds(), Some((0, 9)));
        assert!(!bounded.contains(10));
    }

    #[test]
    fn a_shift_divides_the_stride_with_the_bounds() {
        let scaled = StridedInterval::strided(32, 8, 0, 80);
        let shifted = scaled.shr(1);
        assert_eq!(shifted.bounds(), Some((0, 40)));
        assert_eq!(shifted.stride(), Some(4));
    }

    #[test]
    fn a_value_wider_than_the_domain_is_described_at_its_widest() {
        // A vector register is a hundred and twenty-eight bits; shifting by
        // that much is not something `u64` can do, and a NEON expansion found
        // it.
        let wide = StridedInterval::top(128);
        assert!(wide.shr(80).is_top() || wide.shr(80).as_constant() == Some(0));
        assert!(wide.shl(80).is_top() || wide.shl(80).as_constant() == Some(0));
        assert_eq!(wide.bounds(), Some((0, u64::MAX)));
    }

    #[test]
    fn a_remainder_is_smaller_than_its_divisor_whatever_it_divides() {
        let anything = StridedInterval::top(32);
        let three = StridedInterval::constant(32, 3);
        assert_eq!(anything.rem(&three).bounds(), Some((0, 2)));
        // A dividend smaller than the divisor is its own remainder's bound.
        assert_eq!(
            StridedInterval::interval(32, 0, 1).rem(&three).bounds(),
            Some((0, 1))
        );
        // A divisor that can be nought divides nothing, so nothing is proven.
        assert!(anything.rem(&StridedInterval::interval(32, 0, 4)).is_top());
    }

    #[test]
    fn a_quotient_shrinks_by_what_divides_it() {
        let hundred = StridedInterval::interval(32, 10, 100);
        assert_eq!(
            hundred.div(&StridedInterval::constant(32, 10)).bounds(),
            Some((1, 10))
        );
        // The widest quotient takes the smallest divisor, and the narrowest
        // the largest.
        assert_eq!(
            hundred.div(&StridedInterval::interval(32, 2, 5)).bounds(),
            Some((2, 50))
        );
        assert!(hundred.div(&StridedInterval::top(32)).is_top());
    }

    #[test]
    fn bottom_is_the_identity_of_join_and_absorbs_meet() {
        let bottom = StridedInterval::bottom(32);
        let some = StridedInterval::interval(32, 3, 7);
        assert_eq!(bottom.join(&some), some);
        assert!(bottom.meet(&some).is_bottom());
    }
}

#[cfg(kani)]
mod kani_proofs {
    //! Eight-bit proofs CBMC settles in a gate's time; the rest are exhausted by unit tests (doc/ssa.md, "Kani").
    use super::*;

    /// An eight-bit element and one value it holds.
    fn any_element() -> (StridedInterval, u64) {
        let (low, stride, count, pick): (u8, u8, u8, u8) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(count >= 1 && pick < count);
        let high = u64::from(low) + u64::from(stride) * u64::from(count - 1);
        kani::assume(high <= 0xff);
        let element = StridedInterval::strided(8, u64::from(stride), u64::from(low), high);
        (
            element,
            u64::from(low) + u64::from(stride) * u64::from(pick),
        )
    }

    #[kani::proof]
    fn eight_bit_shr_keeps_every_concrete_result() {
        let (element, value) = any_element();
        let places: u32 = kani::any();
        kani::assume(places < 10);
        let shifted = if places < 8 { value >> places } else { 0 };
        assert!(element.shr(places).contains(shifted));
    }

    #[kani::proof]
    fn eight_bit_quotients_and_masks_keep_every_concrete_result() {
        let ((left, a), (right, b)) = (any_element(), any_element());
        let mask: u8 = kani::any();
        assert!(left.and_mask(u64::from(mask)).contains(a & u64::from(mask)));
        if b != 0 {
            assert!(left.rem(&right).contains(a % b));
            assert!(left.div(&right).contains(a / b));
        }
    }
}
