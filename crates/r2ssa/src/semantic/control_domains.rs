//! Which region each predicate governs.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlDomainFacts {
    pub domains: BTreeMap<ControlDomainId, ControlDomain>,
    pub by_block: BTreeMap<u64, ControlDomainId>,
}

impl ControlDomainFacts {
    pub fn for_block(&self, block_addr: u64) -> Option<&ControlDomain> {
        self.by_block
            .get(&block_addr)
            .and_then(|id| self.domains.get(id))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ControlDomainState {
    pub(crate) guards: BTreeSet<ControlGuard>,
    pub(crate) complete: bool,
}

pub(crate) fn collect_control_domain_facts(
    function: &SSAFunction,
    predicates: &PredicateFacts,
    structured: &StructuredDataflowFacts,
) -> ControlDomainFacts {
    let mut guard_universe = BTreeSet::new();
    for &predecessor in function.block_addrs() {
        for successor in function.successors(predecessor) {
            if let (Some(guard), _) =
                control_guard_for_edge(function, predicates, predecessor, successor)
            {
                guard_universe.insert(guard);
            }
        }
    }
    // Every way out of each switch, so a merged arm that covers all of them can
    // be recognised as no constraint at all.
    let mut switch_arity = BTreeMap::<u64, (BTreeSet<u64>, bool)>::new();
    for &addr in function.block_addrs() {
        if let Some(block) = function.cfg().get_block(addr)
            && let BlockTerminator::Switch { cases, default } = &block.terminator
        {
            switch_arity.insert(
                addr,
                (
                    cases.iter().map(|(value, _)| *value).collect(),
                    default.is_some(),
                ),
            );
        }
    }
    let mut states = function
        .block_addrs()
        .iter()
        .copied()
        .map(|addr| {
            (
                addr,
                Some(ControlDomainState {
                    guards: guard_universe.clone(),
                    complete: true,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    states.insert(
        function.root(),
        Some(ControlDomainState {
            guards: BTreeSet::new(),
            complete: true,
        }),
    );

    // A worklist over the blocks, reading the states as they stand.
    //
    // This used to sweep every block once per round and copy the whole state
    // map at the top of each round so that a round read the previous round's
    // answers. The map holds one guard set per block, initialised to the whole
    // universe, so a copy is the function's guard count times its block count,
    // and a five-hundred-block function paid it once per round. Reading the
    // current answers instead is the same fixed point -- every state only ever
    // loses guards, the transfer over an edge is monotone in its input, and a
    // monotone decreasing iteration from the top element reaches the same
    // greatest fixed point whatever order the equations are applied in -- and
    // a block is only revisited when a predecessor actually changed.
    //
    // The bound is the same one the round count was derived from: a state can
    // change only by losing a guard or by widening a switch arm, so the number
    // of updates is bounded by the blocks times the height of the lattice.
    let update_limit = function
        .num_blocks()
        .saturating_mul(guard_universe.len().saturating_add(2))
        .max(8);
    let mut worklist =
        std::collections::VecDeque::from_iter(function.block_addrs().iter().copied());
    let mut queued = function
        .block_addrs()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut updates = 0usize;
    while let Some(block_addr) = worklist.pop_front() {
        queued.remove(&block_addr);
        if block_addr == function.root() || updates >= update_limit {
            continue;
        }
        let predecessors = function.predecessors(block_addr);
        let state = if predecessors.is_empty() {
            Some(ControlDomainState {
                guards: BTreeSet::new(),
                complete: false,
            })
        } else {
            let mut incoming = Vec::new();
            for predecessor in predecessors {
                let Some(mut state) = states.get(&predecessor).cloned().flatten() else {
                    continue;
                };
                let (guard, edge_complete) =
                    control_guard_for_edge(function, predicates, predecessor, block_addr);
                if let Some(guard) = guard {
                    insert_control_guard(&mut state.guards, guard, &switch_arity);
                }
                state.complete &= edge_complete;
                incoming.push(state);
            }
            if incoming.is_empty() {
                continue;
            }
            let mut guards = incoming[0].guards.clone();
            for state in &incoming[1..] {
                guards = meet_control_guards(&guards, &state.guards, &switch_arity);
            }
            Some(ControlDomainState {
                guards,
                complete: incoming.iter().all(|state| state.complete),
            })
        };
        if states.get(&block_addr) == Some(&state) {
            continue;
        }
        states.insert(block_addr, state);
        updates += 1;
        for successor in function.successors(block_addr) {
            if queued.insert(successor) {
                worklist.push_back(successor);
            }
        }
    }

    let mut loops_by_block = BTreeMap::<u64, Vec<LoopId>>::new();
    for (loop_id, loop_fact) in &structured.loops {
        for block_addr in &loop_fact.body {
            loops_by_block
                .entry(*block_addr)
                .or_default()
                .push(*loop_id);
        }
    }
    for loops in loops_by_block.values_mut() {
        loops.sort_unstable();
        loops.dedup();
    }

    let mut domain_ids = BTreeMap::<(Vec<ControlGuard>, Vec<LoopId>, bool), ControlDomainId>::new();
    let mut domains = BTreeMap::new();
    let mut by_block = BTreeMap::new();
    for &block_addr in function.block_addrs() {
        let state = states
            .remove(&block_addr)
            .flatten()
            .unwrap_or(ControlDomainState {
                guards: BTreeSet::new(),
                complete: false,
            });
        let guards = state.guards.into_iter().collect::<Vec<_>>();
        let loops = loops_by_block.remove(&block_addr).unwrap_or_default();
        let key = (guards.clone(), loops.clone(), state.complete);
        let id = if let Some(id) = domain_ids.get(&key).copied() {
            id
        } else {
            let id = ControlDomainId(domain_ids.len() as u32);
            domain_ids.insert(key, id);
            domains.insert(
                id,
                ControlDomain {
                    id,
                    guards,
                    loops,
                    complete: state.complete,
                },
            );
            id
        };
        by_block.insert(block_addr, id);
    }
    ControlDomainFacts { domains, by_block }
}

/// Meet two guard sets: what is true on both paths into a block.
///
/// A plain intersection for everything except two arms of the same switch. A
/// case body reached by its own arm and by falling through from the arm above
/// it has no guard common to both paths, and reporting nothing says the block
/// runs unconditionally, which is false. `SwitchArm` carries a vector of case
/// values precisely so it can say "the selector is one of these", so the arms
/// are merged rather than dropped. Growth is bounded by the switch's own case
/// count, so the fixpoint still converges.
/// The arms of one switch that a guard set holds, as one arm per switch block.
///
/// Two arms of the same switch on one state are one guard weakened to the
/// union of their cases: a path takes one arm, so the only thing both can say
/// together is "one of these". Keeping them as two guards let every meet mint
/// a new subset of the cases, and the states grew through the power set of a
/// switch's arms -- which is what took one function of a binary built at -O2
/// past a gigabyte and the harness's memory limit.
pub(crate) fn switch_arms_by_block(
    guards: &BTreeSet<ControlGuard>,
) -> BTreeMap<u64, (Vec<u64>, bool)> {
    let mut arms = BTreeMap::<u64, (Vec<u64>, bool)>::new();
    for guard in guards {
        let ControlGuard::SwitchArm {
            block_addr,
            case_values,
            includes_default,
        } = guard
        else {
            continue;
        };
        let entry = arms.entry(*block_addr).or_default();
        entry.0.extend(case_values.iter().copied());
        entry.1 |= *includes_default;
    }
    for (values, _) in arms.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    arms
}

/// A merged arm that covers every way out of the switch says nothing: the
/// block runs whatever the selector is. That is the block the switch converges
/// on, and giving it a guard would demand one from a rendering that correctly
/// has none.
pub(crate) fn switch_arm_is_vacuous(
    block_addr: u64,
    case_values: &[u64],
    includes_default: bool,
    switch_arity: &BTreeMap<u64, (BTreeSet<u64>, bool)>,
) -> bool {
    switch_arity
        .get(&block_addr)
        .is_some_and(|(all_values, has_default)| {
            all_values.iter().all(|value| case_values.contains(value))
                && (includes_default || !has_default)
        })
}

/// Add one guard to a state, keeping at most one arm per switch block.
pub(crate) fn insert_control_guard(
    guards: &mut BTreeSet<ControlGuard>,
    guard: ControlGuard,
    switch_arity: &BTreeMap<u64, (BTreeSet<u64>, bool)>,
) {
    let ControlGuard::SwitchArm {
        block_addr,
        case_values,
        includes_default,
    } = &guard
    else {
        guards.insert(guard);
        return;
    };
    let mut merged = case_values.clone();
    let mut default = *includes_default;
    let existing = guards
        .iter()
        .filter(|other| {
            matches!(other, ControlGuard::SwitchArm { block_addr: other_block, .. } if other_block == block_addr)
        })
        .cloned()
        .collect::<Vec<_>>();
    for other in existing {
        if let ControlGuard::SwitchArm {
            case_values: other_values,
            includes_default: other_default,
            ..
        } = &other
        {
            merged.extend(other_values.iter().copied());
            default |= *other_default;
        }
        guards.remove(&other);
    }
    merged.sort_unstable();
    merged.dedup();
    if switch_arm_is_vacuous(*block_addr, &merged, default, switch_arity) {
        return;
    }
    guards.insert(ControlGuard::SwitchArm {
        block_addr: *block_addr,
        case_values: merged,
        includes_default: default,
    });
}

/// What holds on every path into a block: the branch guards both sides
/// share, and for each switch both sides passed through, the arm covering
/// the cases either side took.
pub(crate) fn meet_control_guards(
    left: &BTreeSet<ControlGuard>,
    right: &BTreeSet<ControlGuard>,
    switch_arity: &BTreeMap<u64, (BTreeSet<u64>, bool)>,
) -> BTreeSet<ControlGuard> {
    let mut met = left
        .iter()
        .filter(|guard| matches!(guard, ControlGuard::Branch { .. }))
        .filter(|guard| right.contains(guard))
        .cloned()
        .collect::<BTreeSet<_>>();
    let right_arms = switch_arms_by_block(right);
    for (block_addr, (left_values, left_default)) in switch_arms_by_block(left) {
        let Some((right_values, right_default)) = right_arms.get(&block_addr) else {
            continue;
        };
        let mut merged = left_values;
        merged.extend(right_values.iter().copied());
        merged.sort_unstable();
        merged.dedup();
        let includes_default = left_default || *right_default;
        if switch_arm_is_vacuous(block_addr, &merged, includes_default, switch_arity) {
            continue;
        }
        met.insert(ControlGuard::SwitchArm {
            block_addr,
            case_values: merged,
            includes_default,
        });
    }
    met
}

pub(crate) fn control_guard_for_edge(
    function: &SSAFunction,
    predicates: &PredicateFacts,
    predecessor: u64,
    successor: u64,
) -> (Option<ControlGuard>, bool) {
    let Some(block) = function.cfg().get_block(predecessor) else {
        return (None, false);
    };
    match &block.terminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => {
            if true_target == false_target {
                return (None, *true_target == successor);
            }
            let predicate = predicates
                .predicates
                .values()
                .find(|fact| fact.block_addr == predecessor)
                .map(|fact| fact.id);
            let Some(predicate) = predicate else {
                return (None, false);
            };
            if *true_target == successor {
                (
                    Some(ControlGuard::Branch {
                        predicate,
                        truth: true,
                    }),
                    true,
                )
            } else if *false_target == successor {
                (
                    Some(ControlGuard::Branch {
                        predicate,
                        truth: false,
                    }),
                    true,
                )
            } else {
                (None, false)
            }
        }
        BlockTerminator::Switch { cases, default } => {
            let mut case_values = cases
                .iter()
                .filter_map(|(value, target)| (*target == successor).then_some(*value))
                .collect::<Vec<_>>();
            case_values.sort_unstable();
            case_values.dedup();
            let includes_default = *default == Some(successor);
            if case_values.is_empty() && !includes_default {
                return (None, false);
            }
            (
                Some(ControlGuard::SwitchArm {
                    block_addr: predecessor,
                    case_values,
                    includes_default,
                }),
                true,
            )
        }
        BlockTerminator::IndirectBranch if function.successors(predecessor).len() > 1 => {
            (None, false)
        }
        _ => (None, function.successors(predecessor).contains(&successor)),
    }
}
