//! What a value is, and what it computes to.
//!
//! Two questions are asked of an SSA value all over the engine, and until now
//! every caller answered its own with its own walk. Nine of them existed, and
//! no two agreed: one followed copies, another copies and widenings, another
//! copies and three arithmetic shapes, each with its own depth limit and its
//! own idea of what counts as a literal. A value that one part of the engine
//! could prove constant was opaque to the part beside it, and which of the
//! nine a call site happened to reach decided whether a bound was found.
//!
//! The questions themselves are distinct, and both have exact answers.
//!
//! `value_of` answers what a value *is*: a literal, read through operations
//! that move a value without changing it -- a copy, a zero extension, a
//! reinterpretation. `root_of` is the same walk, returning the value it
//! arrived at rather than that value's bits, which is what a proof about one
//! temporary needs in order to meet a use several temporaries later.
//!
//! `folded_value` answers what a value *computes to*: `value_of` widened with
//! integer and boolean arithmetic over operands that are themselves constant.
//! Every step is evaluated at the width the machine evaluated it at, so what
//! comes back is the value and not an estimate of it.
//!
//! Neither walk is depth-limited. A definition chain in SSA is acyclic and the
//! fold expands no phi, so recording each value once terminates the walk and
//! also keeps a shared subexpression from being evaluated twice.

use std::collections::{BTreeMap, BTreeSet};

use crate::CanonicalStorageSpace;
use crate::function::DecompilePrepFacts;
use crate::graph::{GraphInst, InstPayload, SsaGraph, ValueId};
use crate::indirect::exact_input;
use crate::op::SSAOp;

/// Whether an operation delivers its first operand's unsigned value
/// unchanged: a copy or a zero extension, as the one identity fact states
/// them (`crate::view`). A truncation, a lane at an offset and a sign
/// extension each change the number.
fn is_value_preserving(op: &SSAOp) -> bool {
    crate::view::preserves_integer(op)
}

/// The literal a value states about itself, at its own width.
///
/// A constant varnode carries its bits directly; a value too wide for that
/// accessor states them as the offset of its constant-space storage. When
/// preparation has a root for the value, what the root states counts too:
/// the root relation closes over phis, which no walk over definitions does.
fn literal_of(graph: &SsaGraph, facts: Option<&DecompilePrepFacts>, value: ValueId) -> Option<u64> {
    let value = graph.value(value)?;
    facts
        .map(|facts| facts.canonical_root(&value.var))
        .and_then(|root| root.constant_bits())
        .or_else(|| value.var.constant_bits())
        .or_else(|| {
            value
                .canonical_storage
                .filter(|storage| storage.space == CanonicalStorageSpace::Constant)
                .map(|storage| storage.offset)
        })
}

/// The value this value is, named by where it came from.
///
/// A bound is proven against the value one instruction compared and the index
/// is read several copies later; they are the same value, and the proof only
/// connects them when both are named by their origin rather than by whichever
/// temporary happened to be holding them.
pub(crate) fn root_of(graph: &SsaGraph, value: ValueId) -> ValueId {
    let mut current = value;
    let mut seen = BTreeSet::new();
    while seen.insert(current) {
        let Some(inst) = graph.def_inst(current).and_then(|inst| graph.inst(inst)) else {
            break;
        };
        let InstPayload::Op(op) = &inst.payload else {
            break;
        };
        if !is_value_preserving(op) {
            break;
        }
        let Some(source) = exact_input(graph, inst, 0) else {
            break;
        };
        current = source;
    }
    current
}

/// The constant a value is.
pub(crate) fn value_of(graph: &SsaGraph, value: ValueId) -> Option<u64> {
    literal_of(graph, None, root_of(graph, value))
}

/// The constant a value is, read at its own width as a signed number.
///
/// `[x3, #-3]` lifts to an addition of `0xfffffffffffffffd`, and taking that
/// unsigned makes a three-byte step backwards into an index the size of the
/// address space.
pub(crate) fn signed_value_of(graph: &SsaGraph, value: ValueId) -> Option<i64> {
    let bits = value_of(graph, value)?;
    let size = graph.value(value)?.var.size;
    Some(sign_extend(bits, size))
}

/// Read a folded value as signed at the width it was computed at.
pub(crate) fn sign_extend(value: u64, size: u32) -> i64 {
    let bits = size.saturating_mul(8).min(64);
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    ((value << (64 - bits)) as i64) >> (64 - bits)
}

/// How many operands an operation folds over, when it folds at all.
fn folded_arity(op: &SSAOp) -> Option<usize> {
    if is_value_preserving(op) {
        return Some(1);
    }
    op.operation().map(|_| op.sources().len())
}

/// What an operation computes from its operands' values, in `sources` order, as `r2il::eval` states it.
///
/// `None` where p-code leaves the value undefined or it does not fit a constant.
pub(crate) fn computed(op: &SSAOp, operands: &[u64]) -> Option<u64> {
    let operation = op.operation()?;
    let sources = op.sources();
    if sources.len() != operands.len() {
        return None;
    }
    let words = sources
        .iter()
        .zip(operands)
        .map(|(source, value)| r2il::eval::Word::new(u128::from(*value), source.size).ok())
        .collect::<Option<Vec<_>>>()?;
    let value = r2il::eval::apply(operation, &words, op.dst()?.size).ok()?;
    u64::try_from(value).ok()
}

/// The operands an operation folds over, where it folds at all.
fn folded_inputs(graph: &SsaGraph, inst: &GraphInst, op: &SSAOp) -> Option<Vec<ValueId>> {
    (0..folded_arity(op)?)
        .map(|index| exact_input(graph, inst, index))
        .collect()
}

/// What one operation computes where `known` gives every operand it folds over.
pub(crate) fn fold_inst(
    graph: &SsaGraph,
    inst: &GraphInst,
    known: impl Fn(ValueId) -> Option<u64>,
) -> Option<u64> {
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    let inputs = folded_inputs(graph, inst, op)?;
    let operands = inputs.iter().map(|input| known(*input)).collect::<Vec<_>>();
    fold_op(op, &operands)
}

/// Evaluate one operation over operands already folded to constants.
fn fold_op(op: &SSAOp, operands: &[Option<u64>]) -> Option<u64> {
    if is_value_preserving(op) {
        return *operands.first()?;
    }
    computed(op, &operands.iter().copied().collect::<Option<Vec<_>>>()?)
}

/// The constant a value computes to.
pub(crate) fn folded_value(graph: &SsaGraph, value: ValueId) -> Option<u64> {
    fold(graph, None, value)
}

/// The constant a value computes to, with what preparation proved admitted.
pub(crate) fn prepared_folded_value(
    graph: &SsaGraph,
    facts: Option<&DecompilePrepFacts>,
    value: ValueId,
) -> Option<u64> {
    fold(graph, facts, value)
}

fn fold(graph: &SsaGraph, facts: Option<&DecompilePrepFacts>, value: ValueId) -> Option<u64> {
    let mut known: BTreeMap<ValueId, Option<u64>> = BTreeMap::new();
    let mut pending = vec![(value, false)];
    while let Some((current, operands_ready)) = pending.pop() {
        if known.contains_key(&current) {
            continue;
        }
        if let Some(bits) = literal_of(graph, facts, current) {
            known.insert(current, Some(bits));
            continue;
        }
        let definition = graph
            .def_inst(current)
            .and_then(|inst| graph.inst(inst))
            .filter(|inst| matches!(inst.payload, InstPayload::Op(_)));
        let Some(inst) = definition else {
            known.insert(current, None);
            continue;
        };
        let InstPayload::Op(op) = &inst.payload else {
            unreachable!("filtered to an operation");
        };
        let Some(inputs) = folded_inputs(graph, inst, op) else {
            known.insert(current, None);
            continue;
        };
        if !operands_ready {
            pending.push((current, true));
            pending.extend(inputs.iter().rev().map(|input| (*input, false)));
            continue;
        }
        let operands: Vec<Option<u64>> = inputs
            .iter()
            .map(|input| known.get(input).copied().flatten())
            .collect();
        let folded = fold_op(op, &operands);
        known.insert(current, folded);
    }
    known.get(&value).copied().flatten()
}

#[cfg(test)]
mod tests {
    use super::{folded_value, root_of, signed_value_of, value_of};
    use crate::function::SSAFunction;
    use crate::graph::SsaGraph;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    /// `narrow = 5; wide = zext(narrow); moved = wide; sum = moved * 3 + 1`.
    ///
    /// The shape a counter's initializer takes when the compiler starts it in a
    /// 32-bit register and the loop indexes with the 64-bit one.
    fn widened_counter() -> SSAFunction {
        let mut arch = ArchSpec::new("widened-counter");
        arch.add_register(RegisterDef::new("narrow", 0, 4));
        arch.add_register(RegisterDef::new("wide", 8, 8));
        arch.add_register(RegisterDef::new("moved", 16, 8));
        arch.add_register(RegisterDef::new("scaled", 24, 8));
        arch.add_register(RegisterDef::new("sum", 32, 8));
        arch.add_register(RegisterDef::new("pc", 0x80, 8));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: reg(0, 4),
            src: Varnode::constant(5, 4),
        });
        block.push(R2ILOp::IntZExt {
            dst: reg(8, 8),
            src: reg(0, 4),
        });
        block.push(R2ILOp::Copy {
            dst: reg(16, 8),
            src: reg(8, 8),
        });
        block.push(R2ILOp::IntMult {
            dst: reg(24, 8),
            a: reg(16, 8),
            b: Varnode::constant(3, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: reg(32, 8),
            a: reg(24, 8),
            b: Varnode::constant(1, 8),
        });
        block.push(R2ILOp::Return {
            target: reg(0x80, 8),
        });
        SSAFunction::from_blocks_raw(&[block], Some(&arch)).expect("widened counter SSA")
    }

    /// The value defined by the instruction at `index` in the entry block.
    fn defined(graph: &SsaGraph, index: usize) -> crate::graph::ValueId {
        graph
            .insts
            .iter()
            .filter(|inst| matches!(inst.payload, crate::graph::InstPayload::Op(_)))
            .nth(index)
            .and_then(|inst| inst.output)
            .expect("an operation with an output")
    }

    #[test]
    fn a_widened_constant_is_still_that_constant() {
        let function = widened_counter();
        let graph = SsaGraph::from_function(&function);
        let moved = defined(&graph, 2);
        assert_eq!(
            value_of(&graph, moved),
            Some(5),
            "a copy of a zero extension of a constant is that constant"
        );
    }

    #[test]
    fn a_widened_constant_names_the_value_it_came_from() {
        let function = widened_counter();
        let graph = SsaGraph::from_function(&function);
        assert_eq!(
            root_of(&graph, defined(&graph, 2)),
            root_of(&graph, defined(&graph, 1)),
            "a copy and its source are the same value"
        );
    }

    #[test]
    fn arithmetic_over_widened_constants_folds() {
        let function = widened_counter();
        let graph = SsaGraph::from_function(&function);
        assert_eq!(
            folded_value(&graph, defined(&graph, 4)),
            Some(16),
            "5 * 3 + 1"
        );
        assert_eq!(
            value_of(&graph, defined(&graph, 4)),
            None,
            "a computed value is not a constant it is a copy of"
        );
    }

    #[test]
    fn a_narrow_constant_reads_signed_at_its_own_width() {
        let function = widened_counter();
        let graph = SsaGraph::from_function(&function);
        let narrow = defined(&graph, 0);
        assert_eq!(signed_value_of(&graph, narrow), Some(5));
        assert_eq!(
            signed_value_of(&graph, defined(&graph, 1)),
            Some(5),
            "zero extending keeps a positive constant positive"
        );
    }
}
