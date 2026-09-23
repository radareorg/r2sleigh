//! Whether a value is a step towards another number or a result, for every value at once in `O(V + E)`.

use r2il::ValueUse;

use crate::graph::{GraphInst, SsaGraph};
use crate::{CanonicalStorageSpace, InstPayload, ValueId};

/// What becomes of one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// An operation builds a different number on it, through the copies and merges it flows into.
    Step,
    /// Every path it takes ends before anything builds another number on it.
    Result,
}

/// The fate of every value in one function, each path carrying one bit: whether its number was built on yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fates {
    /// For each value and each bit, whether a step is reachable: index `2 * value + built`.
    step: Vec<bool>,
}

impl Fates {
    /// Every value's fate: the states that reach a step, found by one backward pass from the steps themselves.
    pub fn of(graph: &SsaGraph) -> Self {
        let mut fates = Self {
            step: vec![false; 2 * graph.values.len()],
        };
        let mut pending = Vec::new();
        for inst in &graph.insts {
            for (value, built) in reading(inst, |built| steps_at(graph, inst, built)) {
                fates.mark(value, built, &mut pending);
            }
        }
        // A state reaches a step where the state its use carries the number into does.
        while let Some((value, built)) = pending.pop() {
            let Some(defined) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
                continue;
            };
            for (input, from) in reading(defined, |from| carried(defined, from) == Some(built)) {
                fates.mark(input, from, &mut pending);
            }
        }
        fates
    }

    /// What becomes of a value as it is defined, before anything has built on it.
    pub fn of_value(&self, value: ValueId) -> Fate {
        match self.reaches(value, false) {
            true => Fate::Step,
            false => Fate::Result,
        }
    }

    fn reaches(&self, value: ValueId, built: bool) -> bool {
        self.step
            .get(2 * value.0 as usize + usize::from(built))
            .copied()
            .unwrap_or(false)
    }

    fn mark(&mut self, value: ValueId, built: bool, pending: &mut Vec<(ValueId, bool)>) {
        let Some(slot) = self.step.get_mut(2 * value.0 as usize + usize::from(built)) else {
            return;
        };
        if !*slot {
            *slot = true;
            pending.push((value, built));
        }
    }
}

/// Each state in which an operation reads one of its inputs, where `holds` accepts the bit.
fn reading<'a>(
    inst: &'a GraphInst,
    holds: impl Fn(bool) -> bool + 'a,
) -> impl Iterator<Item = (ValueId, bool)> + 'a {
    [false, true]
        .into_iter()
        .filter(move |built| holds(*built))
        .flat_map(move |built| inst.inputs.iter().map(move |input| (*input, built)))
}

/// The bit an operation leaves on its output: a copy or merge passes it, deriving sets it, a test or a use ends the path.
fn carried(inst: &GraphInst, built: bool) -> Option<bool> {
    match &inst.payload {
        InstPayload::Phi { .. } => Some(built),
        InstPayload::Op(op) => match op.value_use() {
            ValueUse::Carries => Some(built),
            ValueUse::Derives => Some(true),
            ValueUse::Consumes | ValueUse::Tests => None,
        },
    }
}

/// Whether a read is a step: consuming a built number, or building into more than a temporary, which a flag passes through.
fn steps_at(graph: &SsaGraph, inst: &GraphInst, built: bool) -> bool {
    if built && matches!(&inst.payload, InstPayload::Op(op) if op.value_use() == ValueUse::Consumes)
    {
        return true;
    }
    carried(inst, built) == Some(true) && inst.output.is_some_and(|out| !temporary(graph, out))
}

/// Whether a value lives in a temporary one instruction's operations share.
fn temporary(graph: &SsaGraph, value: ValueId) -> bool {
    graph
        .value(value)
        .and_then(|value| value.canonical_storage)
        .is_some_and(|storage| storage.space == CanonicalStorageSpace::Unique)
}

#[cfg(test)]
mod tests {
    use r2il::{R2ILBlock, R2ILOp, Varnode};

    use crate::SSAFunction;

    /// A lifted operation uses a number as its SSA form does, or `pd` and `pdf` settle one line two ways.
    #[test]
    fn a_lifted_operation_and_its_ssa_form_use_a_number_alike() {
        let (dst, a, b) = (
            Varnode::register(0, 8),
            Varnode::register(8, 8),
            Varnode::register(16, 8),
        );
        let flag = Varnode::register(24, 1);
        let ops = [
            R2ILOp::Copy {
                dst: dst.clone(),
                src: a.clone(),
            },
            R2ILOp::IntAdd {
                dst: dst.clone(),
                a: a.clone(),
                b: b.clone(),
            },
            R2ILOp::IntLess {
                dst: flag.clone(),
                a: a.clone(),
                b: b.clone(),
            },
            R2ILOp::Load {
                dst: dst.clone(),
                space: r2il::SpaceId::Ram,
                addr: a.clone(),
            },
            R2ILOp::Cast {
                dst: dst.clone(),
                src: a.clone(),
            },
            R2ILOp::Select {
                dst: dst.clone(),
                cond: flag,
                if_true: a.clone(),
                if_false: b.clone(),
            },
            R2ILOp::Extract {
                dst: dst.clone(),
                src: a.clone(),
                position: b.clone(),
            },
            R2ILOp::Insert {
                dst,
                src: a,
                value: b,
                position: Varnode::constant(0, 8),
            },
        ];
        for op in ops {
            let mut block = R2ILBlock::new(0x1000, 4);
            block.push(op.clone());
            block.push(R2ILOp::Return {
                target: Varnode::constant(0, 8),
            });
            let function = SSAFunction::from_blocks_raw(&[block], None).expect("it builds");
            let converted = function
                .blocks()
                .iter()
                .flat_map(|block| &block.ops)
                .find(|ssa| ssa.dst().is_some())
                .expect("the operation defines a value");
            assert_eq!(converted.value_use(), op.value_use(), "{op:?}");
        }
    }
}
