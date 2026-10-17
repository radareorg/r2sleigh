//! Loops, their carriers and the inductions they run.

use super::*;
use crate::cfg::BlockTerminator;

/// Every carrier of one loop whose motion round the latch is known exactly.
///
/// Derived from the carrier facts rather than from a second walk of the CFG:
/// the carriers already prove which merge carries a value, which edge enters
/// it and which edge updates it, and this only asks what the update does to
/// the merge. A carrier with more than one update edge is skipped, because two
/// latches may step the value differently and one step would not describe
/// both.
fn loop_induction_facts(
    graph: &SsaGraph,
    loop_id: LoopId,
    header: u64,
    carriers: &[LoopCarrierFact],
    reading: Reading,
) -> Vec<InductionFact> {
    carriers
        .iter()
        .flat_map(|carrier| {
            let ([entry], updates) = (carrier.entries.as_slice(), carrier.updates.as_slice())
            else {
                return Vec::new();
            };
            let updates = match (updates, reading.every_latch) {
                ([update], _) => std::slice::from_ref(update),
                (updates, true) => updates,
                _ => return Vec::new(),
            };
            let width_bits = carrier.width.saturating_mul(8).max(1);
            // The carrier whole, then the low pieces a caller asks for: a 32-bit counter kept in a
            // 64-bit register is stepped and tested at 32 bits.
            let narrower = reading
                .views
                .iter()
                .copied()
                .filter(|bits| *bits < width_bits);
            let widths = [width_bits].into_iter().chain(narrower).collect::<Vec<_>>();
            let facts = updates.iter().flat_map(|update| {
                widths.iter().filter_map(|&width_bits| {
                    let step =
                        induction_step_for_update(graph, carrier.phi, update.value, width_bits)?;
                    let fact = InductionFact {
                        loop_id,
                        header,
                        phi: carrier.phi,
                        init: entry.value,
                        update: update.value,
                        latch: update.predecessor,
                        width_bits,
                        step,
                    };
                    // A fact that does not prove itself against the graph it came from
                    // is a fact nobody should read.
                    fact.validate(graph).then_some(fact)
                })
            });
            facts.collect()
        })
        .collect()
}

/// What an induction may be read as: at the widths of its low pieces, and once for each latch that
/// updates it.
#[derive(Clone, Copy)]
pub(crate) struct Reading<'a> {
    pub(crate) views: &'a [u32],
    pub(crate) every_latch: bool,
}

/// The carrier as it stands: one width, one latch.
const WHOLE: Reading<'static> = Reading {
    views: &[],
    every_latch: false,
};

/// What loop recovery reads beside the body: the branch tests and the value ranges.
pub(crate) struct LoopEvidence<'a> {
    pub(crate) predicates: &'a PredicateFacts,
    pub(crate) values: &'a crate::values::ValueRanges,
}

/// Every natural loop with its carriers and trip count, and every induction its carriers prove.
pub(crate) fn collect_structured_loop_facts(
    code: Body<'_>,
    evidence: LoopEvidence<'_>,
    live_out: &crate::liveout::FunctionLiveOut,
    storage_spans: &StorageSpans,
) -> (
    BTreeMap<LoopId, StructuredLoopFact>,
    crate::dense::IdMap<ValueId, InductionFact>,
) {
    let Body {
        function, graph, ..
    } = code;
    let LoopEvidence { predicates, values } = evidence;
    let mut counter = TripCounter::new(function, graph, predicates, values);
    let mut loops = BTreeMap::new();
    let mut inductions = crate::dense::IdMap::default();
    for (idx, natural) in function.natural_loops().iter().enumerate() {
        let id = LoopId(idx as u32);
        let header = natural.header;
        let latches = &natural.latches;
        let body_set = &natural.body;
        let body = body_set.iter().copied().collect::<Vec<_>>();
        let leaving = LoopExits::of(function, body_set);
        let exits = leaving.targets();
        let condition = loop_condition(predicates, header, body_set, &exits);
        let loop_ = NaturalLoop {
            id,
            header,
            latches,
            body: body_set,
            exits: &leaving,
        };
        let carriers = loop_carrier_facts(code, loop_, live_out, storage_spans);
        let loop_inductions = loop_induction_facts(graph, id, header, &carriers, WHOLE);
        let trips = counter.count(&TripLoop {
            loop_,
            condition,
            inductions: &loop_inductions,
        });
        inductions.extend(loop_inductions.into_iter().map(|fact| (fact.phi, fact)));
        loops.insert(
            id,
            StructuredLoopFact {
                id,
                kind: if latches.contains(&header) {
                    StructuredLoopKind::SelfLoop
                } else {
                    StructuredLoopKind::Natural
                },
                header,
                latches: latches.iter().copied().collect(),
                body,
                exits,
                condition,
                carriers,
                trips,
            },
        );
    }
    (loops, inductions)
}

/// How many times the header of the loop headed by `header` runs, from the merges of its header
/// alone: no liveness and no memory model, for a caller that holds neither.
pub(crate) fn header_trips(
    function: &SSAFunction,
    graph: &SsaGraph,
    evidence: LoopEvidence<'_>,
    header: u64,
) -> Result<LoopTrips, TripRefusal> {
    let natural = (function.natural_loops().get(header)).ok_or(TripRefusal::ExitNotInduction)?;
    let leaving = LoopExits::of(function, &natural.body);
    let condition = loop_condition(
        evidence.predicates,
        header,
        &natural.body,
        &leaving.targets(),
    );
    let loop_ = NaturalLoop {
        id: LoopId(0),
        header,
        latches: &natural.latches,
        body: &natural.body,
        exits: &leaving,
    };
    let carriers = header_carriers(graph, loop_, |phi| !graph.use_sites(phi).is_empty());
    let inductions = loop_induction_facts(
        graph,
        loop_.id,
        header,
        &carriers,
        Reading {
            views: &[32, 16, 8],
            every_latch: true,
        },
    );
    let mut counter = TripCounter::new(function, graph, evidence.predicates, evidence.values);
    counter.count(&TripLoop {
        loop_,
        condition,
        inductions: &inductions,
    })
}

/// One natural loop: which it is, where it begins, the edges back to it, the
/// blocks it contains and how control leaves it.
///
/// These are computed together and every rule that reasons about a loop takes
/// them all, so they are one thing rather than parameters each rule takes
/// apart again.
#[derive(Clone, Copy)]
pub(crate) struct NaturalLoop<'a> {
    pub(crate) id: LoopId,
    pub(crate) header: u64,
    pub(crate) latches: &'a BTreeSet<u64>,
    pub(crate) body: &'a BTreeSet<u64>,
    pub(crate) exits: &'a LoopExits,
}

/// How control leaves one loop, from one walk of its blocks' terminators.
pub(crate) struct LoopExits {
    /// Each edge from a block inside to a block outside, as `(from, to)`.
    pub(crate) edges: BTreeSet<(u64, u64)>,
    /// Whether a block returns, branches indirectly, or transfers out of the function.
    pub(crate) leaves_function: bool,
}

impl LoopExits {
    pub(crate) fn of(function: &SSAFunction, body: &BTreeSet<u64>) -> Self {
        let cfg = function.cfg();
        let leaves = |block: u64| {
            cfg.get_block(block).is_none_or(|bb| {
                matches!(
                    bb.terminator,
                    BlockTerminator::Return
                        | BlockTerminator::ConditionalExit { .. }
                        | BlockTerminator::IndirectBranch
                        | BlockTerminator::None
                ) || bb
                    .successors()
                    .into_iter()
                    .any(|succ| cfg.get_block(succ).is_none())
            })
        };
        let mut exits = Self {
            edges: BTreeSet::new(),
            leaves_function: false,
        };
        for &block in body {
            exits.leaves_function |= leaves(block);
            let outside = function.successors(block).into_iter();
            let outside = outside.filter(|succ| !body.contains(succ));
            exits.edges.extend(outside.map(|succ| (block, succ)));
        }
        exits
    }

    /// The blocks control reaches on leaving, in address order.
    pub(crate) fn targets(&self) -> Vec<u64> {
        let targets = self.edges.iter().map(|(_, to)| *to);
        targets.collect::<BTreeSet<_>>().into_iter().collect()
    }
}

/// The merges of a loop's header and the edges that enter and update each: the carriers before any
/// owner is shared between them. `read` says which merges something reads.
pub(crate) fn header_carriers(
    graph: &SsaGraph,
    loop_: NaturalLoop<'_>,
    read: impl Fn(ValueId) -> bool,
) -> Vec<LoopCarrierFact> {
    let NaturalLoop {
        id: loop_id,
        header,
        latches,
        ..
    } = loop_;
    let Some(header_block) = graph.block_id_for_addr(header) else {
        return Vec::new();
    };
    (graph.phi_insts(header_block).iter())
        .filter_map(|&phi_inst| {
            let phi = graph.inst(phi_inst)?;
            let phi_value = phi.output?;
            let crate::InstPayload::Phi { predecessors } = &phi.payload else {
                return None;
            };
            // Pruned SSA is not guaranteed at this seam. A loop-local output
            // can induce a syntactic header phi whose value is never read;
            // such a dead merge carries no live state and must not acquire a
            // preservation obligation. Being read includes being read by the
            // caller, which the use list alone cannot see: a function's result
            // has no reader anywhere inside it.
            if !read(phi_value) {
                return None;
            }
            let mut entries = Vec::new();
            let mut updates = Vec::new();
            let sources = predecessors.iter().zip(graph.inputs(phi_inst));
            for (input_idx, (predecessor, source)) in sources.enumerate() {
                let predecessor = &graph.block(*predecessor)?.addr;
                let edge = LoopCarrierEdgeValue {
                    predecessor: *predecessor,
                    value: *source,
                    site: UseSite {
                        inst: phi_inst,
                        input_idx,
                    },
                };
                if !edge.validate(graph) {
                    return None;
                }
                if latches.contains(predecessor) {
                    updates.push(LoopCarrierUpdateFact {
                        predecessor: edge.predecessor,
                        value: edge.value,
                        site: edge.site,
                        identity_values: exact_copy_identity_values(graph, edge.value),
                    });
                } else {
                    entries.push(edge);
                }
            }
            if entries.is_empty() || updates.is_empty() {
                return None;
            }
            entries.sort_unstable();
            entries.dedup();
            updates.sort_unstable();
            updates.dedup();
            Some(LoopCarrierFact {
                id: SemanticId::loop_carrier(phi_value),
                loop_id,
                header,
                phi: phi_value,
                width: graph.var(phi_value).size,
                identity_values: BTreeSet::from([phi_value]),
                entries,
                updates,
                dominating_initializers: Vec::new(),
                members: Vec::new(),
            })
        })
        .collect::<Vec<_>>()
}

pub(crate) fn loop_carrier_facts(
    body: Body<'_>,
    loop_: NaturalLoop<'_>,
    live_out: &crate::liveout::FunctionLiveOut,
    storage_spans: &StorageSpans,
) -> Vec<LoopCarrierFact> {
    let Body {
        function,
        graph,
        machine_context,
        ..
    } = body;
    let NaturalLoop {
        header,
        latches,
        body: loop_body,
        ..
    } = loop_;
    let mut carriers = header_carriers(graph, loop_, |phi| {
        crate::liveout::is_read(graph, live_out, phi)
    });

    // A post-loop phi such as `result = phi(init, update)` denotes the same
    // mutable carrier after structured control flow. Resolve the transitive
    // relation through a sorted worklist: every phi edge is reconsidered only
    // when a newly certified output can change its answer.
    let mut owners_by_value = crate::dense::IdMap::<ValueId, BTreeSet<usize>>::default();
    let mut continuing_owners_by_value = crate::dense::IdMap::<ValueId, BTreeSet<usize>>::default();
    for (carrier_index, carrier) in carriers.iter().enumerate() {
        for value in carrier
            .identity_values
            .iter()
            .copied()
            .chain(carrier.entries.iter().map(|edge| edge.value))
            .chain(carrier.updates.iter().flat_map(|update| {
                std::iter::once(update.value).chain(update.identity_values.iter().copied())
            }))
        {
            owners_by_value
                .get_or_insert_with(value, Default::default)
                .insert(carrier_index);
        }
        for value in carrier
            .identity_values
            .iter()
            .copied()
            .chain(carrier.updates.iter().flat_map(|update| {
                std::iter::once(update.value).chain(update.identity_values.iter().copied())
            }))
        {
            continuing_owners_by_value
                .get_or_insert_with(value, Default::default)
                .insert(carrier_index);
        }
    }
    // A worklist over the loop's inner phis. A phi is given its one owner at
    // most once -- one already owned is skipped -- and owners only grow, so
    // a phi is re-queued only when an input it reads gains one: each phi is
    // decided once, and the work is the phis plus their uses.
    let mut pending = graph
        .insts
        .iter()
        .filter(|inst| {
            matches!(inst.payload, InstPayload::Phi { .. })
                && graph
                    .block(inst.block)
                    .is_some_and(|block| block.addr != header)
        })
        .map(|inst| inst.id)
        .collect::<crate::dense::IdWorklist<_>>();
    while let Some(phi_inst) = pending.pop_first() {
        let Some(inst) = graph.inst(phi_inst) else {
            continue;
        };
        let InstPayload::Phi { predecessors } = &inst.payload else {
            continue;
        };
        let Some(output) = inst.output else {
            continue;
        };
        if owners_by_value.contains(output)
            || predecessors.len() != graph.inputs(inst.id).len()
            || graph.inputs(inst.id).is_empty()
            || graph
                .inputs(inst.id)
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != graph.inputs(inst.id).len()
        {
            continue;
        }
        let Some(mut candidate_owners) = graph
            .inputs(inst.id)
            .first()
            .and_then(|input| owners_by_value.get(*input))
            .cloned()
        else {
            continue;
        };
        for input in graph.inputs(inst.id).iter().skip(1) {
            let Some(input_owners) = owners_by_value.get(*input) else {
                candidate_owners.clear();
                break;
            };
            candidate_owners.retain(|owner| input_owners.contains(owner));
        }
        candidate_owners.retain(|owner| {
            graph.inputs(inst.id).iter().any(|input| {
                continuing_owners_by_value
                    .get(*input)
                    .is_some_and(|owners| owners.contains(owner))
            })
        });
        if candidate_owners.len() != 1 {
            continue;
        }
        let carrier_index = *candidate_owners
            .first()
            .expect("one exact carrier owner remains");
        let source_edges = predecessors
            .iter()
            .copied()
            .zip(graph.inputs(inst.id).iter().copied())
            .enumerate()
            .filter_map(|(input_idx, (predecessor, value))| {
                let edge = LoopCarrierEdgeValue {
                    predecessor: graph.block(predecessor)?.addr,
                    value,
                    site: UseSite {
                        inst: phi_inst,
                        input_idx,
                    },
                };
                edge.validate(graph).then_some(edge)
            })
            .collect::<Vec<_>>();
        if source_edges.len() != graph.inputs(inst.id).len()
            || !carriers[carrier_index].identity_values.insert(output)
        {
            continue;
        }
        for edge in source_edges {
            if carriers[carrier_index]
                .entries
                .iter()
                .any(|entry| entry.value == edge.value)
                && function.dominates(edge.predecessor, header)
            {
                carriers[carrier_index].dominating_initializers.push(edge);
            }
        }
        owners_by_value
            .get_or_insert_with(output, Default::default)
            .insert(carrier_index);
        continuing_owners_by_value
            .get_or_insert_with(output, Default::default)
            .insert(carrier_index);
        for site in graph.use_sites(output) {
            if graph
                .inst(site.inst)
                .is_some_and(|use_inst| matches!(use_inst.payload, InstPayload::Phi { .. }))
            {
                pending.insert(site.inst);
            }
        }
    }

    for carrier in &mut carriers {
        carrier.dominating_initializers.sort_unstable();
        carrier.dominating_initializers.dedup();
    }
    carriers.retain(|carrier| carrier.validate(graph));
    carriers.sort_by_key(|carrier| carrier.phi);
    let Some(member_rows) = loop_carrier_member_rows(
        graph,
        header,
        latches,
        loop_body,
        storage_spans,
        machine_context,
        &carriers,
    ) else {
        return Vec::new();
    };
    for (carrier, members) in carriers.iter_mut().zip(member_rows) {
        carrier.members = members;
    }
    carriers
}
