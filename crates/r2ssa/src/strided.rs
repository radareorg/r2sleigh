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
        if low == high {
            return Self::constant(width_bits, low);
        }
        let stride = match stride {
            0 => return Self::constant(width_bits, low),
            stride => stride & mask,
        };
        if stride == 0 {
            return Self::constant(width_bits, low);
        }
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

    /// The greatest element both hold.
    ///
    /// Two strided intervals are arithmetic progressions, so their
    /// intersection is one too: it exists only where their starts agree
    /// modulo the greatest common divisor of their strides, and then it steps
    /// by their least common multiple. Solving that is what keeps a meet of
    /// the even numbers and the odd ones empty, which a bounds-only meet
    /// cannot say and a switch recovery would believe.
    pub fn meet(&self, other: &Self) -> Self {
        debug_assert_eq!(self.width_bits, other.width_bits);
        let (Some(left), Some(right)) = (self.body, other.body) else {
            return Self::bottom(self.width_bits);
        };
        let low = left.low.max(right.low);
        let high = left.high.min(right.high);
        if low > high {
            return Self::bottom(self.width_bits);
        }
        let (left_stride, right_stride) = (left.stride.max(1), right.stride.max(1));
        let Some((first, stride)) =
            common_progression((left.low, left_stride), (right.low, right_stride), low)
        else {
            return Self::bottom(self.width_bits);
        };
        match first > high {
            true => Self::bottom(self.width_bits),
            false => Self::strided(self.width_bits, stride, first, high),
        }
    }

    /// Jump to a bound rather than climbing to it.
    ///
    /// Used where a fixpoint would otherwise ascend one loop iteration at a
    /// time: a bound that grew goes to the extreme of the width, and one that
    /// did not is kept. This is what makes the fixpoint terminate.
    pub fn widen(&self, next: &Self) -> Self {
        debug_assert_eq!(self.width_bits, next.width_bits);
        let (Some(old), Some(new)) = (self.body, next.body) else {
            return match next.body.is_some() {
                true => *next,
                false => *self,
            };
        };
        let mask = Self::mask_for(self.width_bits);
        let low = match new.low < old.low {
            true => 0,
            false => old.low,
        };
        let high = match new.high > old.high {
            true => mask,
            false => old.high,
        };
        let stride = gcd(old.stride, new.stride).max(1);
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

    /// A mask keeps the values below it, which is how a modulo by a power of
    /// two is spelled and how an alignment is imposed.
    pub fn and_mask(&self, mask: u64) -> Self {
        let width_mask = Self::mask_for(self.width_bits);
        let mask = mask & width_mask;
        if mask == width_mask {
            return *self;
        }
        // A mask of every low bit bounds the result without saying more.
        match mask.checked_add(1).is_some_and(u64::is_power_of_two) {
            true => Self::interval(self.width_bits, 0, mask),
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

    /// A logical right shift divides, and divides the stride with it.
    pub fn shr(&self, places: u32) -> Self {
        if places >= self.width_bits.min(Self::MAX_WIDTH_BITS) {
            return Self::constant(self.width_bits, 0);
        }
        let Some(body) = self.body else {
            return Self::bottom(self.width_bits);
        };
        let stride = match body.stride >> places {
            0 => 1,
            stride => stride,
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

/// The first value at or above `from` that both progressions reach, and the
/// step between such values.
///
/// `None` where they never coincide, which is the whole point: two strides
/// that start out of phase share nothing.
fn common_progression(left: (u64, u64), right: (u64, u64), from: u64) -> Option<(u64, u64)> {
    let (left_start, left_stride) = (i128::from(left.0), i128::from(left.1));
    let (right_start, right_stride) = (i128::from(right.0), i128::from(right.1));
    let step = gcd(left.1, right.1);
    let difference = right_start - left_start;
    if difference % i128::from(step) != 0 {
        return None;
    }
    let combined = lcm(left.1, right.1)?;
    // Step from the later start until both progressions agree. The search is
    // bounded by the combined stride, because the pattern repeats there.
    let bound = i128::from(combined);
    let mut candidate = i128::from(from);
    let limit = candidate + bound;
    while candidate < limit {
        if (candidate - left_start).rem_euclid(left_stride) == 0
            && (candidate - right_start).rem_euclid(right_stride) == 0
        {
            return u64::try_from(candidate).ok().map(|first| (first, combined));
        }
        candidate += 1;
    }
    None
}

fn gcd(a: u64, b: u64) -> u64 {
    match b {
        0 => a,
        b => gcd(b, a % b),
    }
}

fn lcm(a: u64, b: u64) -> Option<u64> {
    (a / gcd(a, b)).checked_mul(b)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn bottom_is_the_identity_of_join_and_absorbs_meet() {
        let bottom = StridedInterval::bottom(32);
        let some = StridedInterval::interval(32, 3, 7);
        assert_eq!(bottom.join(&some), some);
        assert!(bottom.meet(&some).is_bottom());
    }
}
