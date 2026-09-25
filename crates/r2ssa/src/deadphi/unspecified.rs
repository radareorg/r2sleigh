//! Which bytes of each value carry what the convention leaves unspecified.
//!
//! A register the convention names neither as an argument nor as preserved
//! holds, on entry, whatever the caller last left in it; so does a carrier a
//! call left undefined. No source program's meaning depends on those bytes,
//! so a byte of the result that must carry one is a byte the source's result
//! type does not have. These closures say which bytes may, and which must.
//!
//! *May* is the forward image of [`super::dependence::operand_bytes`]: a byte
//! of a value may carry a seed's bytes when some operand byte it depends on
//! may. It over-approximates, so it can never narrow anything on its own: a
//! byte may depend on a seed and still be defined, as `x - x` is.
//!
//! *Must* under-approximates: a byte must carry a seed when, for every
//! assignment of the specified inputs, it is a non-constant function of the
//! seed bytes. It is proven by forms that compose only where composition
//! preserves that:
//!
//! - a byte moved unchanged (a copy, slice, extension's own bytes, a lane
//!   write's window or root) keeps its form;
//! - at the least significant byte a value may carry a seed at, every lower
//!   byte is seed-free, so a sum, difference, negation or multiple there is
//!   `c * g + h (mod 256)` for one seed byte `g` and an `h` that does not
//!   depend on it; `c != 0` is the whole proof, and `x - 4x` gives `c = -3`
//!   where `x - x` gives `c = 0` and proves nothing;
//! - an exclusive or with a seed-free byte is a bijection on the byte;
//! - a merge carries a form only when every input carries the same seed byte
//!   unchanged, so the path taken cannot matter.
//!
//! Anything else proves nothing, and a loop's back edge proves nothing, which
//! is the side a must fact may err on: a byte called defined that is not only
//! keeps a result wider than the source's.
//!
//! Cost: the may closure queues a value again only when it gains a byte, at
//! most once per byte, and each visit asks the relation once per output byte:
//! O(E * w^2) for values of at most `w` bytes. The must forms are one pass in
//! the graph's instruction order, O(E * w).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::ByteMask;
use super::dependence::operand_bytes;
use crate::SSAOp;
use crate::graph::{GraphInst, InstPayload, SsaGraph, ValueId};

/// One seed byte: the seed value and which of its bytes.
type SeedByte = (ValueId, u32);

/// Why a byte must carry a seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// The byte is `coefficient * seed + h (mod 256)`, `coefficient` never
    /// zero and `h` independent of the seed byte; `exact` when `h` is zero,
    /// which is a byte moved unchanged.
    Linear {
        seed: SeedByte,
        coefficient: u8,
        exact: bool,
    },
    /// A non-constant function of seed bytes with no algebra to compose.
    Opaque,
}

impl Form {
    fn linear(seed: SeedByte, coefficient: u8) -> Option<Self> {
        (coefficient != 0).then_some(Self::Linear {
            seed,
            coefficient,
            exact: false,
        })
    }

    /// `-f`, or `~f`: the same byte through a bijection.
    fn negated(self) -> Self {
        match self {
            Self::Linear {
                seed, coefficient, ..
            } => Self::Linear {
                seed,
                coefficient: coefficient.wrapping_neg(),
                exact: false,
            },
            Self::Opaque => Self::Opaque,
        }
    }

    /// `f * m`, where `m` is the multiplier's least significant byte.
    fn scaled(self, m: u8) -> Option<Self> {
        match self {
            Self::Linear {
                seed, coefficient, ..
            } => Self::linear(seed, coefficient.wrapping_mul(m)),
            // A bijection only where the multiplier is odd.
            Self::Opaque => (m % 2 == 1).then_some(Self::Opaque),
        }
    }
}

/// What an operand's byte is at the byte a sum is proven at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    /// No seed reaches it.
    Free,
    /// It must carry a seed, in this form.
    Must(Form),
    /// A seed may reach it, and nothing proves how.
    Unknown,
}

impl Operand {
    fn negated(self) -> Self {
        match self {
            Self::Must(form) => Self::Must(form.negated()),
            other => other,
        }
    }

    fn scaled(self, m: u8) -> Self {
        match self {
            Self::Must(form) => form.scaled(m).map_or(Self::Unknown, Self::Must),
            other => other,
        }
    }
}

/// `a + b` at the least significant byte either may carry a seed at.
fn sum(a: Operand, b: Operand) -> Option<Form> {
    match (a, b) {
        (Operand::Must(form), Operand::Free) | (Operand::Free, Operand::Must(form)) => {
            Some(match form {
                Form::Linear {
                    seed, coefficient, ..
                } => Form::Linear {
                    seed,
                    coefficient,
                    exact: false,
                },
                Form::Opaque => Form::Opaque,
            })
        }
        (
            Operand::Must(Form::Linear {
                seed: left,
                coefficient: c,
                ..
            }),
            Operand::Must(Form::Linear {
                seed: right,
                coefficient: d,
                ..
            }),
        ) if left == right => Form::linear(left, c.wrapping_add(d)),
        _ => None,
    }
}

/// The bytes of each value that may and that must carry an unspecified seed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnspecifiedBytes {
    may: BTreeMap<ValueId, ByteMask>,
    must: BTreeMap<ValueId, Vec<Option<Form>>>,
}

impl UnspecifiedBytes {
    /// Close `seeds` -- values the convention leaves unspecified, every byte
    /// of them -- forward over the graph.
    pub fn find(graph: &SsaGraph, seeds: &BTreeSet<ValueId>) -> Self {
        let mut found = Self {
            may: may_closure(graph, seeds),
            must: BTreeMap::new(),
        };
        for seed in seeds {
            let Some(width) = graph.value(*seed).map(|value| value.var.size.min(64)) else {
                continue;
            };
            let forms = (0..width)
                .map(|byte| {
                    Some(Form::Linear {
                        seed: (*seed, byte),
                        coefficient: 1,
                        exact: true,
                    })
                })
                .collect();
            found.must.insert(*seed, forms);
        }
        for inst in &graph.insts {
            let Some(output) = inst.output else {
                continue;
            };
            if found.must.contains_key(&output) || found.may(output).is_empty() {
                continue;
            }
            let forms = found.forms_of(graph, inst, output);
            if forms.iter().any(Option::is_some) {
                found.must.insert(output, forms);
            }
        }
        found
    }

    /// The bytes of `value` a seed may reach.
    pub fn may(&self, value: ValueId) -> ByteMask {
        self.may.get(&value).copied().unwrap_or(ByteMask::NONE)
    }

    /// The bytes of `value` that must carry a seed.
    pub fn must(&self, value: ValueId) -> ByteMask {
        let Some(forms) = self.must.get(&value) else {
            return ByteMask::NONE;
        };
        forms
            .iter()
            .enumerate()
            .filter(|(_, form)| form.is_some())
            .fold(ByteMask::NONE, |mask, (byte, _)| {
                mask.union(ByteMask::byte(u32::try_from(byte).unwrap_or(u32::MAX)))
            })
    }

    fn form(&self, value: ValueId, byte: u32) -> Option<Form> {
        self.must
            .get(&value)?
            .get(usize::try_from(byte).ok()?)
            .copied()
            .flatten()
    }

    /// What `value`'s byte is, as an operand of a sum proven at that byte.
    fn operand(&self, value: ValueId, byte: u32) -> Operand {
        if !self.may(value).contains_byte(byte) {
            return Operand::Free;
        }
        self.form(value, byte)
            .map_or(Operand::Unknown, Operand::Must)
    }

    /// The must form of each byte of `output`, defined by `inst`.
    fn forms_of(&self, graph: &SsaGraph, inst: &GraphInst, output: ValueId) -> Vec<Option<Form>> {
        let width = graph
            .value(output)
            .map_or(0, |value| value.var.size.min(64));
        let op = match &inst.payload {
            InstPayload::Phi { .. } => {
                return (0..width)
                    .map(|byte| self.merged(&inst.inputs, byte))
                    .collect();
            }
            InstPayload::Op(op) => op,
        };
        let lowest = self.may(output).lowest();
        (0..width)
            .map(|byte| {
                self.moved(op, &inst.inputs, byte)
                    .or_else(|| self.bijective(op, &inst.inputs, byte))
                    .or_else(|| {
                        (lowest == Some(byte))
                            .then(|| self.arithmetic(op, &inst.inputs, byte))
                            .flatten()
                    })
            })
            .collect()
    }

    /// A merge's byte, where every input carries the same seed byte unchanged.
    fn merged(&self, inputs: &[ValueId], byte: u32) -> Option<Form> {
        let first = self.form(*inputs.first()?, byte)?;
        let Form::Linear { exact: true, .. } = first else {
            return None;
        };
        inputs
            .iter()
            .all(|input| self.form(*input, byte) == Some(first))
            .then_some(first)
    }

    /// A byte moved unchanged from one operand byte.
    fn moved(&self, op: &SSAOp, inputs: &[ValueId], byte: u32) -> Option<Form> {
        let (input, from) = moved_from(op, byte)?;
        self.form(*inputs.get(input)?, from)
    }

    /// A byte-wise bijection of one operand byte: a complement, or an
    /// exclusive or with a byte no seed reaches.
    fn bijective(&self, op: &SSAOp, inputs: &[ValueId], byte: u32) -> Option<Form> {
        match op {
            SSAOp::IntNot { .. } => Some(self.form(inputs[0], byte)?.negated()),
            SSAOp::IntXor { .. } => {
                match (self.operand(inputs[0], byte), self.operand(inputs[1], byte)) {
                    (Operand::Must(_), Operand::Free) | (Operand::Free, Operand::Must(_)) => {
                        Some(Form::Opaque)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// A two's complement operation at the least significant byte a seed may
    /// reach, where every lower operand byte is seed-free.
    fn arithmetic(&self, op: &SSAOp, inputs: &[ValueId], byte: u32) -> Option<Form> {
        let at = |index: usize| self.operand(inputs[index], byte);
        match op {
            SSAOp::IntAdd { .. } => sum(at(0), at(1)),
            SSAOp::IntSub { .. } => sum(at(0), at(1).negated()),
            SSAOp::IntNegate { .. } => sum(at(0).negated(), Operand::Free),
            SSAOp::IntMult { a, b, .. } => match (a.constant_bits(), b.constant_bits()) {
                (None, Some(m)) => sum(at(0).scaled(m as u8), Operand::Free),
                (Some(m), None) => sum(Operand::Free, at(1).scaled(m as u8)),
                _ => None,
            },
            SSAOp::PtrAdd { element_size, .. } | SSAOp::PtrSub { element_size, .. } => {
                let index = at(1).scaled(*element_size as u8);
                let index = if matches!(op, SSAOp::PtrSub { .. }) {
                    index.negated()
                } else {
                    index
                };
                sum(at(0), index)
            }
            SSAOp::IntLeft { b, .. } => {
                // A shift by a constant is a multiple by a power of two at the
                // byte the shifted operand's lowest seed byte lands in.
                let bits = b.constant_bits()?;
                let (whole, rest) = (u32::try_from(bits / 8).ok()?, (bits % 8) as u32);
                let from = byte.checked_sub(whole)?;
                if self.may(inputs[0]).lowest() != Some(from) {
                    return None;
                }
                sum(
                    self.operand(inputs[0], from).scaled(1u8 << rest),
                    Operand::Free,
                )
            }
            _ => None,
        }
    }
}

/// For an operation that moves each byte of its value from one operand byte
/// unchanged, which operand and which of its bytes `byte` comes from.
fn moved_from(op: &SSAOp, byte: u32) -> Option<(usize, u32)> {
    match op {
        SSAOp::Copy { .. } => Some((0, byte)),
        SSAOp::Cast { dst, src } | SSAOp::CallRestore { dst, src } if dst.size == src.size => {
            Some((0, byte))
        }
        SSAOp::IntZExt { src, .. } | SSAOp::IntSExt { src, .. } => {
            (byte < src.size).then_some((0, byte))
        }
        SSAOp::Subpiece { src, offset, .. } => {
            let from = byte.checked_add(*offset)?;
            (from < src.size).then_some((0, from))
        }
        SSAOp::Piece { lo, .. } => Some(if byte < lo.size {
            (1, byte)
        } else {
            (0, byte - lo.size)
        }),
        SSAOp::Insert(insert) => {
            let bits = insert.position.constant_bits()?;
            let start = u32::try_from(bits).ok()?;
            let end = start.checked_add(insert.value.size.checked_mul(8)?)?;
            let (low, high) = (byte.checked_mul(8)?, byte.checked_mul(8)?.checked_add(8)?);
            if high <= start || end <= low {
                Some((0, byte))
            } else if start <= low && high <= end && start % 8 == 0 {
                Some((1, byte - start / 8))
            } else {
                None
            }
        }
        SSAOp::Extract { src, position, .. } => {
            let bits = position.constant_bits()?;
            let from = byte.checked_add(u32::try_from(bits / 8).ok()?)?;
            (bits % 8 == 0 && from < src.size).then_some((0, from))
        }
        SSAOp::IntLeft { b, .. } => {
            let bits = b.constant_bits()?;
            let whole = u32::try_from(bits / 8).ok()?;
            (bits % 8 == 0).then_some((0, byte.checked_sub(whole)?))
        }
        SSAOp::IntRight { a, b, .. } | SSAOp::IntSRight { a, b, .. } => {
            let bits = b.constant_bits()?;
            let from = byte.checked_add(u32::try_from(bits / 8).ok()?)?;
            (bits % 8 == 0 && from < a.size).then_some((0, from))
        }
        _ => None,
    }
}

/// The forward image of the dependence relation from `seeds`: each value's
/// bytes some seed byte may reach.
fn may_closure(graph: &SsaGraph, seeds: &BTreeSet<ValueId>) -> BTreeMap<ValueId, ByteMask> {
    let mut may = BTreeMap::new();
    let mut pending = VecDeque::new();
    for seed in seeds {
        let Some(value) = graph.value(*seed) else {
            continue;
        };
        may.insert(*seed, ByteMask::whole(value.var.size));
        pending.push_back(*seed);
    }
    while let Some(value) = pending.pop_front() {
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                continue;
            };
            let Some(output) = inst.output else {
                continue;
            };
            let before = may.get(&output).copied().unwrap_or(ByteMask::NONE);
            let after = before.union(reached_bytes(graph, inst, output, before, &may));
            if after != before {
                may.insert(output, after);
                pending.push_back(output);
            }
        }
    }
    may
}

/// The bytes of `output` some operand byte that may carry a seed reaches,
/// asked only of the bytes not already known to.
fn reached_bytes(
    graph: &SsaGraph,
    inst: &GraphInst,
    output: ValueId,
    known: ByteMask,
    may: &BTreeMap<ValueId, ByteMask>,
) -> ByteMask {
    let Some(width) = graph.value(output).map(|value| value.var.size) else {
        return ByteMask::NONE;
    };
    let tainted = |input: &ValueId| may.get(input).copied().unwrap_or(ByteMask::NONE);
    if width > 64 {
        let any = inst.inputs.iter().any(|input| !tainted(input).is_empty());
        return if any { ByteMask::All } else { ByteMask::NONE };
    }
    let mut reached = ByteMask::NONE;
    for byte in (0..width).filter(|byte| !known.contains_byte(*byte)) {
        let asks = match &inst.payload {
            InstPayload::Phi { .. } => vec![ByteMask::byte(byte); inst.inputs.len()],
            InstPayload::Op(op) => operand_bytes(op, ByteMask::byte(byte)),
        };
        let hit = inst
            .inputs
            .iter()
            .zip(asks)
            .any(|(input, asked)| !tainted(input).intersection(asked).is_empty());
        if hit {
            reached = reached.union(ByteMask::byte(byte));
        }
    }
    reached
}

#[cfg(test)]
mod tests;
