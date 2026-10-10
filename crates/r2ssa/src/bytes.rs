//! Which bytes of its inputs each output byte of an operation depends on
//! (doc/adr-byte-relation.md): one rule per operation, read backward by demand
//! and observation and forward by written lanes.

use std::collections::VecDeque;

use crate::graph::{SsaGraph, ValueId};
use crate::op::SSAOp;

/// A set of a value's bytes, bit `b` for byte `b`; `All` saturates past 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteMask {
    /// Exactly these bytes.
    Bytes(u64),
    /// Every byte of the value, however wide.
    All,
}

impl ByteMask {
    /// No byte.
    pub const NONE: Self = Self::Bytes(0);

    /// Every byte of a value `size_bytes` wide.
    pub const fn whole(size_bytes: u32) -> Self {
        match size_bytes {
            0..64 => Self::Bytes((1u64 << size_bytes) - 1),
            64 => Self::Bytes(u64::MAX),
            _ => Self::All,
        }
    }

    /// Whether the mask names no byte at all.
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Bytes(0))
    }

    /// The bytes in either mask.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bytes(a), Self::Bytes(b)) => Self::Bytes(a | b),
            _ => Self::All,
        }
    }

    /// The bytes in both masks.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bytes(a), Self::Bytes(b)) => Self::Bytes(a & b),
            (Self::All, other) | (other, Self::All) => other,
        }
    }

    /// The bytes not in `other`; `All` less anything stays `All`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bytes(a), Self::Bytes(b)) => Self::Bytes(a & !b),
            (_, Self::All) => Self::NONE,
            (Self::All, Self::Bytes(_)) => Self::All,
        }
    }

    /// The same bytes `bytes` places more significant; a carry past 64 saturates.
    #[must_use]
    pub const fn shifted_up(self, bytes: u32) -> Self {
        match self {
            Self::Bytes(0) => Self::NONE,
            Self::Bytes(mask) if bytes < 64 && mask.leading_zeros() >= bytes => {
                Self::Bytes(mask << bytes)
            }
            _ => Self::All,
        }
    }

    /// The same bytes `bytes` places less significant; bytes below fall off.
    #[must_use]
    pub const fn shifted_down(self, bytes: u32) -> Self {
        match self {
            Self::Bytes(mask) => Self::Bytes(if bytes < 64 { mask >> bytes } else { 0 }),
            Self::All => Self::All,
        }
    }

    /// The least significant bytes covering every byte named; `None` when
    /// there is none or the mask saturated.
    pub const fn extent_bytes(self) -> Option<u32> {
        match self {
            Self::Bytes(0) | Self::All => None,
            Self::Bytes(mask) => Some(64 - mask.leading_zeros()),
        }
    }

    /// Whether byte `byte` is named.
    #[cfg(test)]
    pub const fn contains(self, byte: u32) -> bool {
        match self {
            Self::All => true,
            Self::Bytes(mask) => byte < 64 && mask & (1 << byte) != 0,
        }
    }
}

impl std::fmt::Display for ByteMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(mask) => write!(f, "{mask:#x}"),
            Self::All => f.write_str("all"),
        }
    }
}

/// How an operation's output bytes come from its inputs, in the order
/// `SSAOp::inputs` and the sealed graph list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Byte `i` is input 0's byte `i` (a copy, and every input of a merge).
    Copy,
    /// Input 0's bytes, then a zero or sign fill above them; the sign fill
    /// reads input 0's top byte.
    Extend { sign: bool, from: u32 },
    /// Input 0's bytes from `offset` up.
    Slice { offset: u32 },
    /// Inputs `[hi, lo]`: `lo` below byte `lo_bytes`, `hi` above.
    Concat { lo_bytes: u32 },
    /// Inputs `[base, lane, position]`: the lane's bytes from byte `first`,
    /// the base's elsewhere; the position is read whole.
    Insert { first: u32, lane_bytes: u32 },
    /// Byte `i` reads byte `i` of each input, except the bytes a constant
    /// operand of an `and` clears in the other (`cleared[j]` for input `j`).
    Lanewise { cleared: [u64; 2] },
    /// Every output byte reads every input whole.
    Whole,
}

/// The bytes of a constant at most eight bytes wide that are zero; a wider
/// constant is taken to clear nothing.
fn zero_bytes(size: u32, bits: Option<u64>) -> u64 {
    match bits.filter(|_| size <= 8) {
        Some(bits) => (0..size).fold(0, |mask, byte| match (bits >> (8 * byte)) & 0xff {
            0 => mask | (1 << byte),
            _ => mask,
        }),
        None => 0,
    }
}

/// The rule of `op`, given each operand's width in bytes and constant bits.
pub(crate) fn rule<V>(op: &SSAOp<V>, facts: impl Fn(&V) -> (u32, Option<u64>)) -> Rule {
    match op {
        SSAOp::Copy { .. } => Rule::Copy,
        SSAOp::IntZExt { src, .. } => Rule::Extend {
            sign: false,
            from: facts(src).0,
        },
        SSAOp::IntSExt { src, .. } => Rule::Extend {
            sign: true,
            from: facts(src).0,
        },
        SSAOp::Subpiece { offset, .. } => Rule::Slice { offset: *offset },
        SSAOp::Piece { lo, .. } => Rule::Concat {
            lo_bytes: facts(lo).0,
        },
        SSAOp::Insert(insert) => match facts(&insert.position).1 {
            Some(bits) if bits % 8 == 0 && bits / 8 < 64 => Rule::Insert {
                first: (bits / 8) as u32,
                lane_bytes: facts(&insert.value).0,
            },
            _ => Rule::Whole,
        },
        SSAOp::IntAnd { a, b, .. } => {
            let (a, b) = (facts(a), facts(b));
            Rule::Lanewise {
                cleared: [zero_bytes(b.0, b.1), zero_bytes(a.0, a.1)],
            }
        }
        SSAOp::IntOr { .. } | SSAOp::IntXor { .. } => Rule::Lanewise { cleared: [0; 2] },
        _ => Rule::Whole,
    }
}

impl Rule {
    /// The bytes of input `index` that `out` of the output reads, before
    /// trimming to the input's width; `None` when the rule names no such input.
    pub(crate) fn backward(self, index: usize, out: ByteMask) -> Option<ByteMask> {
        Some(match (self, index) {
            (Self::Copy, 0) | (Self::Concat { .. }, 1) => out,
            (Self::Extend { sign, from }, 0) => {
                let within = ByteMask::whole(from);
                let fill = out.without(within);
                match sign && !fill.is_empty() && from > 0 {
                    true => out
                        .intersection(within)
                        .union(ByteMask::Bytes(1).shifted_up(from - 1)),
                    false => out.intersection(within),
                }
            }
            (Self::Slice { offset }, 0) => out.shifted_up(offset),
            (Self::Concat { lo_bytes }, 0) => out.shifted_down(lo_bytes),
            (Self::Insert { first, lane_bytes }, 0) => {
                out.without(ByteMask::whole(lane_bytes).shifted_up(first))
            }
            (Self::Insert { first, lane_bytes }, 1) => out
                .intersection(ByteMask::whole(lane_bytes).shifted_up(first))
                .shifted_down(first),
            (Self::Insert { .. }, 2) => ByteMask::All,
            (Self::Lanewise { cleared }, 0 | 1) => out.without(ByteMask::Bytes(cleared[index])),
            (Self::Whole, _) => ByteMask::All,
            _ => return None,
        })
    }
}

/// What a closure found: each value some root depends on, the bytes reached,
/// and the value through which each was first reached.
pub(crate) struct Closure {
    pub(crate) values: crate::dense::IdSet<ValueId>,
    pub(crate) bytes: crate::dense::IdMap<ValueId, ByteMask>,
    pub(crate) parents: crate::dense::IdMap<ValueId, ValueId>,
}

/// What an observation of `observed` bytes of a value asks of each input, by
/// the one byte relation (`crate::bytes`); the closure trims each mask to its
/// input's width.
fn observed_input_bytes(
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
    observed: ByteMask,
) -> impl Iterator<Item = (ValueId, ByteMask)> {
    let rule = match &inst.payload {
        crate::graph::InstPayload::Phi { .. } => None,
        crate::graph::InstPayload::Op(op) => Some(crate::bytes::rule(op, |value| {
            let var = graph.var(*value);
            (var.size, var.constant_bits())
        })),
    };
    inst.inputs.iter().enumerate().map(move |(index, input)| {
        let read = match rule {
            None => observed,
            Some(rule) => rule.backward(index, observed).unwrap_or(ByteMask::All),
        };
        (*input, read)
    })
}

/// Every value some root depends on, with the bytes of it that dependence
/// reaches: one closure, which demand and observation run from their roots.
///
/// A mask only grows, by union, and is trimmed to its value's width, so a
/// value is queued again only when it gains a byte or saturates -- at most 65
/// times -- and the walk stays linear in the graph's edges.
pub(crate) fn closure(graph: &SsaGraph, roots: impl IntoIterator<Item = ValueId>) -> Closure {
    closure_of(graph, roots.into_iter().map(|value| (value, ByteMask::All)))
}

/// `closure`, from only the given bytes of each root.
pub(crate) fn closure_of(
    graph: &SsaGraph,
    roots: impl IntoIterator<Item = (ValueId, ByteMask)>,
) -> Closure {
    let width = |value: ValueId| {
        graph
            .value(value)
            .map_or(ByteMask::All, |value| ByteMask::whole(value.var.size))
    };
    let mut bytes: crate::dense::IdMap<ValueId, ByteMask> = crate::dense::IdMap::default();
    let mut parents = crate::dense::IdMap::default();
    let mut pending = VecDeque::new();
    for (value, mask) in roots {
        let mask = mask.intersection(width(value));
        if mask.is_empty() {
            continue;
        }
        let entry = bytes.get_or_insert_with(value, || ByteMask::NONE);
        let before = *entry;
        *entry = before.union(mask);
        if *entry != before {
            pending.push_back(value);
        }
    }
    while let Some(value) = pending.pop_front() {
        let observed = bytes.get(value).copied().unwrap_or(ByteMask::NONE);
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        for (input, mask) in observed_input_bytes(graph, inst, observed) {
            let mask = mask.intersection(width(input));
            if mask.is_empty() {
                continue;
            }
            let entry = bytes.get_or_insert_with(input, || ByteMask::NONE);
            let before = *entry;
            *entry = before.union(mask);
            if before.is_empty() {
                parents.insert(input, value);
            }
            if *entry != before {
                pending.push_back(input);
            }
        }
    }
    Closure {
        values: bytes.keys().collect(),
        bytes,
        parents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::eval::{Operation, Word, apply};

    fn byte(value: u128, at: u32) -> u8 {
        (value >> (8 * at)) as u8
    }

    fn words(values: &[u128], widths: &[u32]) -> Vec<Word> {
        values
            .iter()
            .zip(widths)
            .map(|(value, width)| Word::new(*value, *width).expect("a width"))
            .collect()
    }

    /// Perturbing any input byte outside `reads` leaves every byte of `out` as it was.
    fn unchanged_outside(
        (operation, widths, out_width): (Operation, &[u32], u32),
        out: ByteMask,
        reads: &[ByteMask],
        case: &[u128],
    ) {
        let base = apply(operation, &words(case, widths), out_width).expect("defined");
        let outside = (0..widths.len())
            .flat_map(|index| (0..widths[index]).map(move |at| (index, at)))
            .filter(|(index, at)| !reads[*index].contains(*at));
        for (index, at) in outside {
            let mut moved = case.to_vec();
            moved[index] ^= 0xa5 << (8 * at);
            let value = apply(operation, &words(&moved, widths), out_width).expect("defined");
            let changed = (0..out_width)
                .find(|check| out.contains(*check) && byte(value, *check) != byte(base, *check));
            assert_eq!(
                changed, None,
                "{operation:?}: output byte moved with input {index} byte {at}"
            );
        }
    }

    /// For one operation and rule over the cases: a demanded output byte
    /// depends on no input byte the rule's backward reading leaves out.
    fn holds(
        rule: Rule,
        operation: Operation,
        widths: &[u32],
        out_width: u32,
        cases: &[[u128; 2]],
    ) {
        for demanded in 1..(1u64 << out_width) {
            let out = ByteMask::Bytes(demanded);
            let reads = (0..widths.len())
                .map(|index| rule.backward(index, out).expect("an input the rule names"))
                .collect::<Vec<_>>();
            for case in cases {
                unchanged_outside(
                    (operation, widths, out_width),
                    out,
                    &reads,
                    &case[..widths.len()],
                );
            }
        }
    }

    /// Each rule against the machine (`r2il::eval`): a demanded output byte
    /// depends on no input byte the rule's backward reading leaves out.
    #[test]
    fn every_rule_reads_what_the_machine_computes_from() {
        let pairs = (0u128..=0xffff)
            .step_by(0x3d)
            .map(|v| [v, v.rotate_left(7) & 0xffff])
            .collect::<Vec<_>>();
        holds(Rule::Copy, Operation::Copy, &[2], 2, &pairs);
        holds(
            Rule::Extend {
                sign: false,
                from: 1,
            },
            Operation::ZExt,
            &[1],
            2,
            &pairs,
        );
        holds(
            Rule::Extend {
                sign: true,
                from: 1,
            },
            Operation::SExt,
            &[1],
            2,
            &pairs,
        );
        holds(
            Rule::Slice { offset: 1 },
            Operation::Subpiece { offset: 1 },
            &[2],
            1,
            &pairs,
        );
        holds(
            Rule::Concat { lo_bytes: 1 },
            Operation::Piece,
            &[1, 1],
            2,
            &pairs,
        );
        holds(
            Rule::Lanewise { cleared: [0; 2] },
            Operation::Or,
            &[2, 2],
            2,
            &pairs,
        );
        holds(
            Rule::Lanewise { cleared: [0; 2] },
            Operation::Xor,
            &[2, 2],
            2,
            &pairs,
        );
        holds(
            Rule::Lanewise { cleared: [0; 2] },
            Operation::And,
            &[2, 2],
            2,
            &pairs,
        );
        // `x & 0x00ff`: the constant clears x's high byte.
        let masked = pairs.iter().map(|[v, _]| [*v, 0x00ff]).collect::<Vec<_>>();
        holds(
            Rule::Lanewise { cleared: [0b10, 0] },
            Operation::And,
            &[2, 2],
            2,
            &masked,
        );
    }
}
