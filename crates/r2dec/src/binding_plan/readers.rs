//! Who reads a value in the rendered text.
//!
//! Folding a value into its reader is legal when the text reads it exactly
//! once, so the fold rule, the deadness rule and the placement rule all turn
//! on the same relation: the set of instructions that render a read of a
//! value. Until now that set was never named. It was recomputed inside the
//! fold rule's per-value loop, one filter arm at a time, and each arm records
//! a case someone found the hard way -- a call boundary whose read the graph
//! states twice, a merge nothing observes, a lane answered from a binding, a
//! reader whose own output reaches the page nowhere.
//!
//! Stating it once is what lets a new case be one line in one place. It is
//! also what lets the fold rule be read: a value folds when it has one
//! rendered reader, and everything else the rule asks is about whether the
//! value can be spelled there, which is a different question.
//!
//! Two counts, because two rules need different ones. Deadness asks whether
//! the value is read at all, and a read that renders nothing is still a read
//! for that purpose -- an operand of an elided instruction keeps its producer
//! alive even though neither prints. Folding asks how many readers reach the
//! page, because that is how many places the expression would have to be
//! spelled.

use std::collections::{BTreeMap, BTreeSet};

use r2ssa::{InstId, UseSite, ValueId};

/// Every graphless read the boundary certificates state, indexed by value.
///
/// A return, a call argument, a switch selector and a derived-width call
/// result are reads the text performs and the SSA graph has no operand for.
/// Four separate rules need to know them -- deadness, renderability, the
/// escaped-frame walk and the fold rule -- and each used to rebuild this
/// index by walking every instruction itself. It depends on nothing but the
/// certificates, so it is built before any of them and shared.
#[derive(Debug, Default)]
pub(super) struct BoundaryReads {
    by_value: BTreeMap<ValueId, Vec<InstId>>,
}

impl BoundaryReads {
    pub(super) fn compute(source: &r2ssa::SsaArtifact) -> Self {
        let mut by_value = BTreeMap::<ValueId, Vec<InstId>>::new();
        for inst in &source.graph().insts {
            for value in super::certified_boundary_read_values(source, inst.id) {
                by_value.entry(value).or_default().push(inst.id);
            }
        }
        Self { by_value }
    }

    pub(super) fn of(&self, value: ValueId) -> &[InstId] {
        self.by_value.get(&value).map_or(&[], Vec::as_slice)
    }

    /// Whether any certificate states a graphless read of the value.
    pub(super) fn any(&self, value: ValueId) -> bool {
        !self.of(value).is_empty()
    }
}

/// The instructions that read one value.
#[derive(Debug, Default)]
pub(super) struct ValueReaders {
    /// The graph operands that render a read.
    pub(super) sites: Vec<UseSite>,
    /// The certified boundary reads that render: a return, a call argument, a
    /// switch selector, a derived-width call result.
    pub(super) boundary: Vec<InstId>,
    /// How many distinct instructions read the value at all, rendered or not.
    pub(super) all: usize,
}

impl ValueReaders {
    /// How many distinct instructions render a read.
    pub(super) fn rendered(&self) -> usize {
        distinct(&self.sites, &self.boundary)
    }

    /// Why a value's readers disqualify it from folding, for the trace.
    ///
    /// Which operation reads it, not only where: a reader that renders
    /// nothing looks the same as one that does until the operation is named.
    pub(super) fn describe(
        &self,
        graph: &r2ssa::SsaGraph,
        elided_reads: &BTreeSet<InstId>,
        root_kind: &str,
    ) -> String {
        let sites = &self.sites;
        let boundary_readers = &self.boundary;
        let reader_count = self.rendered();
        let all_reader_count = self.all;
        format!(
            "{reader_count} of {all_reader_count} readers rendered ({} of them certified boundary reads), of which {} sit in a \
             certificate-elided instruction; root {root_kind}; sites [{}]; boundary [{}]",
            boundary_readers.len(),
            sites
                .iter()
                .filter(|site| elided_reads.contains(&site.inst))
                .count(),
            sites
                .iter()
                .map(|site| {
                    // Which operation reads it, not only where: a reader
                    // that renders nothing looks the same as one that does
                    // until the operation is named.
                    let out = graph.inst(site.inst).and_then(|inst| inst.output);
                    format!(
                        "i{}#{}={}->{}[{} uses]",
                        site.inst.0,
                        site.input_idx,
                        graph.inst(site.inst).map_or("-".to_string(), |inst| {
                            match &inst.payload {
                                r2ssa::InstPayload::Op(op) => format!("{op:?}")
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("Op")
                                    .to_string(),
                                r2ssa::InstPayload::Phi { .. } => "Phi".to_string(),
                            }
                        }),
                        out.and_then(|out| graph.value(out))
                            .map_or("-".to_string(), |v| v.var.display_name()),
                        out.map_or(0, |out| graph.use_sites(out).len())
                    )
                })
                .collect::<Vec<_>>()
                .join(" "),
            boundary_readers
                .iter()
                .map(|inst| {
                    let out = graph.inst(*inst).and_then(|inst| inst.output);
                    format!(
                        "i{}={}[{} uses]{}",
                        inst.0,
                        out.and_then(|out| graph.value(out))
                            .map_or("-".to_string(), |v| v.var.display_name()),
                        out.map_or(0, |out| graph.use_sites(out).len()),
                        graph.inst(*inst).map_or(String::new(), |inst| format!(
                            " {:?}",
                            inst.payload
                        )
                        .chars()
                        .take(70)
                        .collect::<String>()),
                    )
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    /// The one instruction that renders a read, when there is exactly one.
    pub(super) fn sole(&self) -> Option<InstId> {
        match (self.sites.as_slice(), self.boundary.as_slice()) {
            ([site], []) => Some(site.inst),
            ([], [reader]) => Some(*reader),
            ([site], [reader]) if site.inst == *reader => Some(site.inst),
            _ => None,
        }
    }
}

/// How many distinct instructions two reader sets name between them.
fn distinct(sites: &[UseSite], boundary: &[InstId]) -> usize {
    sites.len()
        + boundary
            .iter()
            .filter(|reader| !sites.iter().any(|site| site.inst == **reader))
            .count()
}

/// Every value's readers, in the rendered text.
#[derive(Debug)]
pub(super) struct RenderedReaders {
    by_value: BTreeMap<ValueId, ValueReaders>,
    none: ValueReaders,
}

impl RenderedReaders {
    pub(super) fn get(&self, value: ValueId) -> &ValueReaders {
        self.by_value.get(&value).unwrap_or(&self.none)
    }

    /// Build the relation once, over every value in the graph.
    ///
    /// `unrendered` and `dead` are the two sets the caller has already proved
    /// about definitions: a value nothing renders, and a value nothing reads.
    /// An instruction whose own output is in either renders nothing, so a read
    /// it performs reaches no page.
    pub(super) fn compute(
        facts: super::rules::PlanFacts<'_>,
        unrendered: &BTreeSet<ValueId>,
        dead: &BTreeSet<ValueId>,
    ) -> Self {
        let source = facts.source();
        let graph = facts.graph();
        let boundary_reads = facts.boundary;
        let unobserved = source.unobserved_values();
        let unobserved_uses = source.unobserved_merges().unobserved_uses();
        // An instruction that owns a memory effect renders for the effect, reading its operands, whatever reads its value.
        let effectful = super::rules::effectful_definition_values(source);
        let renders_nothing = |inst: InstId| {
            graph
                .inst(inst)
                .and_then(|node| node.output)
                .is_some_and(|output| {
                    !effectful.contains(&output)
                        && (dead.contains(&output)
                            || unrendered.contains(&output)
                            || unobserved.contains(&output))
                })
        };
        let mut by_value = BTreeMap::new();
        for value in &graph.values {
            let sites = graph
                .use_sites(value.id)
                .iter()
                .copied()
                // A call boundary's read is counted once, as a certified
                // boundary read. `SSAOp::CallUse` states the same read in the
                // graph so liveness can see it, and counting both would make
                // every inlined call argument look like a two-reader value.
                .filter(|site| {
                    !matches!(
                        graph.inst(site.inst).map(|inst| &inst.payload),
                        Some(r2ssa::InstPayload::Op(r2ssa::SSAOp::CallUse { .. }))
                    )
                })
                // A merge nothing observes renders nothing, so it reads
                // nothing. That is a fact about the merge rather than about
                // where the value is kept, and restricting it to the lifter's
                // own scratch space is what makes a condition code look
                // multi-reader: a flag register merges at every loop header,
                // and the merge was counted as a read of it.
                .filter(|site| {
                    value
                        .canonical_storage
                        .is_none_or(|storage| storage.space != r2ssa::CanonicalStorageSpace::Unique)
                        || !unobserved_uses.contains(site)
                        || !graph.inst(site.inst).is_some_and(|inst| {
                            matches!(inst.payload, r2ssa::InstPayload::Phi { .. })
                        })
                })
                .collect::<Vec<_>>();
            let boundary = boundary_reads.of(value.id).to_vec();
            let all = distinct(&sites, &boundary);
            if all == 0 {
                continue;
            }
            by_value.insert(
                value.id,
                ValueReaders {
                    sites: sites
                        .into_iter()
                        .filter(|site| !renders_nothing(site.inst))
                        .collect(),
                    boundary: boundary
                        .into_iter()
                        .filter(|reader| !renders_nothing(*reader))
                        .collect(),
                    all,
                },
            );
        }
        Self {
            by_value,
            none: ValueReaders::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::distinct;
    use r2ssa::{InstId, UseSite};

    #[test]
    fn a_boundary_read_on_an_instruction_that_already_reads_the_value_counts_once() {
        let call = InstId(7);
        let graph_read = UseSite {
            inst: call,
            input_idx: 0,
        };
        assert_eq!(distinct(&[graph_read], &[call]), 1);
    }

    #[test]
    fn a_boundary_read_elsewhere_is_its_own_reader() {
        let read = UseSite {
            inst: InstId(3),
            input_idx: 0,
        };
        assert_eq!(distinct(&[read], &[InstId(7)]), 2);
    }

    #[test]
    fn two_reads_in_one_instruction_are_two_readers() {
        let inst = InstId(3);
        let sites = [
            UseSite { inst, input_idx: 0 },
            UseSite { inst, input_idx: 1 },
        ];
        assert_eq!(distinct(&sites, &[]), 2);
    }
}
