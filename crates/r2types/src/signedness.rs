use std::collections::{BTreeSet, VecDeque};

use r2ssa::dense::{DenseId, IdMap, IdSet};
use r2ssa::{SSAOp, ValueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScalarSignednessEvidence {
    Signed,
    Unsigned,
}

impl ScalarSignednessEvidence {
    /// The signedness this evidence establishes.
    pub(crate) const fn signedness(self) -> crate::Signedness {
        match self {
            Self::Signed => crate::Signedness::Signed,
            Self::Unsigned => crate::Signedness::Unsigned,
        }
    }
}

/// Recover signedness only from operations whose machine semantics distinguish
/// signed from unsigned values, then flow that evidence backward through exact
/// same-width aliases. Width alone remains deliberately neutral.
///
/// Each operation comes with whether it is a zero extension the architecture
/// performs on a write of a register's lower half (r2ssa's
/// `Written::is_conventional_extension`): that one says nothing about the
/// value's signedness. `facts` gives a value's width in bytes and whether it
/// is a literal. Linear in the operations and the aliases, plus the evidence
/// carried backward, each value moving at most twice.
pub(crate) fn infer_scalar_signedness<'a, V: DenseId + 'a>(
    operations: impl IntoIterator<Item = (&'a SSAOp<V>, bool)>,
    aliases: impl IntoIterator<Item = (V, V)>,
    facts: impl Fn(V) -> (u32, bool),
) -> IdMap<V, BTreeSet<ScalarSignednessEvidence>> {
    let operations = operations.into_iter().collect::<Vec<_>>();
    let condition_values = control_condition_values(&operations, &facts);
    let mut reverse_edges = IdMap::<V, Vec<V>>::default();
    let mut signedness = IdMap::<V, BTreeSet<ScalarSignednessEvidence>>::default();
    let mut link = |source: V, derived: V| {
        if facts(source).0 == facts(derived).0 {
            reverse_edges
                .get_or_insert_with(derived, Vec::new)
                .push(source);
        }
    };
    let mut seed = |value: V, evidence: ScalarSignednessEvidence| {
        if !facts(value).1 {
            signedness
                .get_or_insert_with(value, BTreeSet::new)
                .insert(evidence);
        }
    };

    for (source, derived) in aliases {
        link(source, derived);
    }
    for (op, conventional) in operations {
        match op {
            SSAOp::Copy { dst, src } | SSAOp::Cast { dst, src } | SSAOp::New { dst, src } => {
                link(*src, *dst);
            }
            SSAOp::Phi { dst, sources } => {
                for source in sources {
                    link(*source, *dst);
                }
            }
            SSAOp::IntZExt { src, .. } if !conventional => {
                seed(*src, ScalarSignednessEvidence::Unsigned);
            }
            SSAOp::IntSExt { src, .. } => seed(*src, ScalarSignednessEvidence::Signed),
            SSAOp::IntLess { dst, a, b } | SSAOp::IntLessEqual { dst, a, b }
                if condition_values.contains(*dst) =>
            {
                seed(*a, ScalarSignednessEvidence::Unsigned);
                seed(*b, ScalarSignednessEvidence::Unsigned);
            }
            SSAOp::IntSLess { dst, a, b } | SSAOp::IntSLessEqual { dst, a, b }
                if condition_values.contains(*dst) =>
            {
                seed(*a, ScalarSignednessEvidence::Signed);
                seed(*b, ScalarSignednessEvidence::Signed);
            }
            SSAOp::IntDiv { a, b, .. } | SSAOp::IntRem { a, b, .. } => {
                seed(*a, ScalarSignednessEvidence::Unsigned);
                seed(*b, ScalarSignednessEvidence::Unsigned);
            }
            SSAOp::IntSDiv { a, b, .. } | SSAOp::IntSRem { a, b, .. } => {
                seed(*a, ScalarSignednessEvidence::Signed);
                seed(*b, ScalarSignednessEvidence::Signed);
            }
            SSAOp::IntRight { a, .. } => seed(*a, ScalarSignednessEvidence::Unsigned),
            SSAOp::IntSRight { a, .. } => seed(*a, ScalarSignednessEvidence::Signed),
            _ => {}
        }
    }

    // Each value gains at most both kinds of evidence, so it is queued at
    // most twice and the propagation ends.
    let mut ready = signedness.keys().collect::<VecDeque<_>>();
    while let Some(derived) = ready.pop_front() {
        let Some(observed) = signedness.get(derived).cloned() else {
            continue;
        };
        let Some(sources) = reverse_edges.get(derived) else {
            continue;
        };
        for source in sources {
            let entry = signedness.get_or_insert_with(*source, BTreeSet::new);
            let before = entry.len();
            entry.extend(observed.iter().copied());
            if entry.len() != before {
                ready.push_back(*source);
            }
        }
    }
    signedness
}

/// The values a conditional branch tests, and every value they carry the
/// test from through a copy, a merge or boolean logic: one worklist from
/// the branches back through the definitions, each value queued once.
fn control_condition_values<V: DenseId>(
    operations: &[(&SSAOp<V>, bool)],
    facts: &impl Fn(V) -> (u32, bool),
) -> IdSet<V> {
    let mut definitions = IdMap::<V, usize>::default();
    for (index, (op, _)) in operations.iter().enumerate() {
        if let Some(dst) = op.dst() {
            definitions.get_or_insert_with(*dst, || index);
        }
    }
    let mut values = IdSet::default();
    let mut pending = operations
        .iter()
        .filter_map(|(op, _)| match op {
            SSAOp::CBranch { cond, .. } => Some(*cond),
            _ => None,
        })
        .collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        if !values.insert(value) {
            continue;
        }
        let Some((op, _)) = definitions.get(value).map(|index| operations[*index]) else {
            continue;
        };
        if !condition_carrier_op(op, facts) {
            continue;
        }
        op.for_each_source(|source| {
            if !facts(*source).1 && !values.contains(*source) {
                pending.push(*source);
            }
        });
    }
    values
}

fn condition_carrier_op<V: Copy>(op: &SSAOp<V>, facts: &impl Fn(V) -> (u32, bool)) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::Cast { .. }
            | SSAOp::New { .. }
            | SSAOp::Phi { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
    ) || matches!(
        op,
        SSAOp::IntAnd { dst, .. } | SSAOp::IntOr { dst, .. } | SSAOp::IntXor { dst, .. }
            if facts(*dst).0 == 1
    )
}

/// The scalar signedness of a prepared function's values: its graph
/// operations, with each zero extension the architecture performs set
/// aside, plus the same-width `aliases`, plus its merges where `merges`.
pub(crate) fn scalar_signedness_of(
    source: &r2ssa::SsaArtifact,
    merges: bool,
    aliases: impl IntoIterator<Item = (ValueId, ValueId)>,
) -> IdMap<ValueId, BTreeSet<ScalarSignednessEvidence>> {
    let graph = source.graph();
    let written = source.function().written();
    let operations = graph.insts.iter().filter_map(|inst| match &inst.payload {
        r2ssa::InstPayload::Op(op) => Some((
            op,
            graph
                .op_for_inst(inst.id)
                .is_some_and(|op| written.is_conventional_extension(op)),
        )),
        r2ssa::InstPayload::Phi { .. } => None,
    });
    let merge_links = graph
        .insts
        .iter()
        .filter(|_| merges)
        .filter_map(|inst| match &inst.payload {
            r2ssa::InstPayload::Phi { .. } => inst.output.map(|output| (inst, output)),
            r2ssa::InstPayload::Op(_) => None,
        })
        .flat_map(|(inst, output)| inst.inputs.iter().map(move |input| (*input, output)));
    infer_scalar_signedness(operations, merge_links.chain(aliases), |value| {
        graph.value(value).map_or((0, false), |value| {
            (value.var.size, value.var.constant_bits().is_some())
        })
    })
}

/// Scalar signedness over named blocks, keyed back by name: the same
/// evidence for the readers that still take named blocks (the local struct
/// and stack slot analyses; doc/adr-one-ir.md, transitional until they read
/// graph values). `conventional` says which operations, by id, are zero
/// extensions the architecture performs.
pub(crate) struct NamedSignedness {
    table: r2ssa::ValueTable,
    by_var: IdMap<r2ssa::VarId, BTreeSet<ScalarSignednessEvidence>>,
}

impl NamedSignedness {
    pub(crate) fn of(
        blocks: &[r2ssa::SSABlock],
        merges: bool,
        conventional: &dyn Fn(r2ssa::OpId) -> bool,
    ) -> Self {
        let mut table = r2ssa::ValueTable::default();
        let operations = blocks
            .iter()
            .flat_map(|block| block.sited())
            .map(|(id, op)| (op.map(&mut |var| table.intern(var)), conventional(id)))
            .collect::<Vec<_>>();
        let merge_links = blocks
            .iter()
            .filter(|_| merges)
            .flat_map(|block| block.phis())
            .flat_map(|phi| {
                phi.sources
                    .iter()
                    .map(move |(_, source)| (source, &phi.dst))
            })
            .map(|(source, dst)| (table.intern(source), table.intern(dst)))
            .collect::<Vec<_>>();
        let by_var = infer_scalar_signedness(
            operations
                .iter()
                .map(|(op, conventional)| (op, *conventional)),
            merge_links,
            |id| {
                let var = table.var(id);
                (var.size, var.is_const())
            },
        );
        Self { table, by_var }
    }

    pub(crate) fn get(&self, var: &r2ssa::SSAVar) -> Option<&BTreeSet<ScalarSignednessEvidence>> {
        self.by_var.get(self.table.id_of(var)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2ssa::SSAVar;

    /// The evidence for named operations, interned the way a function's
    /// value table interns them; `conventional` marks every zero extension
    /// as the architecture's.
    fn infer(
        operations: &[SSAOp],
        aliases: &[(&SSAVar, &SSAVar)],
        conventional: bool,
    ) -> impl Fn(&SSAVar) -> Option<BTreeSet<ScalarSignednessEvidence>> + use<> {
        let mut table = r2ssa::ValueTable::default();
        let operations = operations
            .iter()
            .map(|op| (op.map(&mut |var| table.intern(var)), conventional))
            .collect::<Vec<_>>();
        let aliases = aliases
            .iter()
            .map(|(source, derived)| (table.intern(source), table.intern(derived)))
            .collect::<Vec<_>>();
        let inferred = infer_scalar_signedness(
            operations
                .iter()
                .map(|(op, conventional)| (op, *conventional)),
            aliases,
            |id| {
                let var = table.var(id);
                (var.size, var.is_const())
            },
        );
        move |var| inferred.get(table.id_of(var)?).cloned()
    }

    #[test]
    fn exact_alias_propagates_extension_signedness_to_source() {
        let source = SSAVar::new("source", 1, 1);
        let reload = SSAVar::new("reload", 1, 1);
        let operations = [SSAOp::IntZExt {
            dst: SSAVar::new("wide", 1, 4),
            src: reload.clone(),
        }];

        let inferred = infer(&operations, &[(&source, &reload)], false);

        assert_eq!(
            inferred(&source),
            Some(BTreeSet::from([ScalarSignednessEvidence::Unsigned]))
        );
    }

    #[test]
    fn conflicting_machine_semantics_remain_explicit() {
        let value = SSAVar::new("value", 1, 1);
        let operations = [
            SSAOp::IntZExt {
                dst: SSAVar::new("unsigned_wide", 1, 4),
                src: value.clone(),
            },
            SSAOp::IntSExt {
                dst: SSAVar::new("signed_wide", 1, 4),
                src: value.clone(),
            },
        ];

        let inferred = infer(&operations, &[], false);

        assert_eq!(
            inferred(&value),
            Some(BTreeSet::from([
                ScalarSignednessEvidence::Signed,
                ScalarSignednessEvidence::Unsigned,
            ]))
        );
    }

    /// A zero extension r2ssa says the architecture performs -- a write of
    /// a register's lower half zeroing the rest -- is no evidence about the
    /// value written; the same extension written by the program is.
    #[test]
    fn a_conventional_zero_extension_is_not_unsigned_evidence() {
        let value = SSAVar::new("loaded", 1, 4);
        let operations = [SSAOp::IntZExt {
            dst: SSAVar::new("RAX", 1, 8),
            src: value.clone(),
        }];

        assert_eq!(infer(&operations, &[], true)(&value), None);
        assert_eq!(
            infer(&operations, &[], false)(&value),
            Some(BTreeSet::from([ScalarSignednessEvidence::Unsigned]))
        );
    }

    #[test]
    fn unsigned_compare_reaching_branch_types_its_operands() {
        let value = SSAVar::new("value", 1, 8);
        let carry = SSAVar::new("carry", 1, 1);
        let condition = SSAVar::new("condition", 1, 1);
        let operations = [
            SSAOp::IntLessEqual {
                dst: carry.clone(),
                a: value.clone(),
                b: SSAVar::new("bound", 1, 8),
            },
            SSAOp::Copy {
                dst: condition.clone(),
                src: carry,
            },
            SSAOp::CBranch {
                target: SSAVar::constant(0x2000, 8),
                cond: condition,
            },
        ];

        let inferred = infer(&operations, &[], false);

        assert_eq!(
            inferred(&value),
            Some(BTreeSet::from([ScalarSignednessEvidence::Unsigned]))
        );
    }

    #[test]
    fn dead_unsigned_flag_does_not_type_signed_branch_operands() {
        let value = SSAVar::new("value", 1, 8);
        let operations = [
            SSAOp::IntLessEqual {
                dst: SSAVar::new("dead_carry", 1, 1),
                a: value.clone(),
                b: SSAVar::new("bound", 1, 8),
            },
            SSAOp::IntSLess {
                dst: SSAVar::new("negative", 1, 1),
                a: SSAVar::new("difference", 1, 8),
                b: SSAVar::constant(0, 8),
            },
            SSAOp::CBranch {
                target: SSAVar::constant(0x2000, 8),
                cond: SSAVar::new("negative", 1, 1),
            },
        ];

        let inferred = infer(&operations, &[], false);

        assert_eq!(inferred(&value), None);
    }
}
