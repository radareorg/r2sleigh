//! The frame's objects and what the body does to memory.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessSummary {
    pub(crate) uses: Vec<MemoryLocation>,
    pub(crate) defs: Vec<MemoryLocation>,
}

pub(crate) fn collect_object_and_memory_facts(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    addresses: &AddressProvenanceFacts,
    machine_context: Option<&SourceMachineContext>,
    declared_slots: &DeclaredStackSlots,
    values: &crate::values::ValueRanges,
) -> (ObjectModel, MemorySSAFacts) {
    let facts = prep;
    let builder = ObjectModelBuilder::new(facts, addresses, declared_slots, machine_context);
    let mut object_model = builder.build(function, graph, values);
    object_model.frame_reach =
        FrameReach::of(function, prep, graph, &object_model, machine_context);
    let access_summaries =
        collect_access_summaries(function, graph, facts, addresses, &object_model);
    let memory = build_memory_ssa(function, graph, &object_model, access_summaries);
    (object_model, memory)
}

pub(crate) fn collect_access_summaries(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep_facts: Option<&DecompilePrepFacts>,
    addresses: &AddressProvenanceFacts,
    object_model: &ObjectModel,
) -> BTreeMap<InstId, AccessSummary> {
    let mut summaries = BTreeMap::new();

    for block in function.named_blocks() {
        for (op_id, op) in block.sited() {
            let Some(inst_id) = graph.inst_for_op(op_id) else {
                continue;
            };
            let mut uses = Vec::new();
            let mut defs = Vec::new();
            match op {
                SSAOp::Load { dst, addr, space }
                | SSAOp::LoadLinked {
                    dst, addr, space, ..
                }
                | SSAOp::LoadGuarded {
                    dst, addr, space, ..
                } => {
                    uses.push(memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        dst.size,
                    ));
                }
                SSAOp::Store { addr, val, space }
                | SSAOp::StoreGuarded {
                    addr, val, space, ..
                } => {
                    defs.push(memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        val.size,
                    ));
                }
                SSAOp::StoreConditional {
                    addr, val, space, ..
                } => {
                    let location = memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        addr,
                        *space,
                        val.size,
                    );
                    uses.push(location.clone());
                    defs.push(location);
                }
                SSAOp::AtomicCAS(swap) => {
                    let location = memory_location_for_addr(
                        prep_facts,
                        addresses,
                        object_model,
                        graph,
                        &swap.addr,
                        swap.space,
                        swap.expected.size.max(swap.replacement.size),
                    );
                    uses.push(location.clone());
                    defs.push(location);
                }
                // Every call may read and write whatever has escaped, whether or
                // not a call site certifies it: a call the site facts do not
                // know is no less a call. Leaving it out made two reads of an
                // escaped object on either side of it one memory version.
                SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                    let locations = call_locations(object_model, inst_id);
                    uses.extend(locations.iter().cloned());
                    defs.extend(locations);
                }
                _ => {}
            }
            if !uses.is_empty() || !defs.is_empty() {
                summaries.insert(inst_id, AccessSummary { uses, defs });
            }
        }
    }

    summaries
}

/// What a call reads and writes: the escaped memory of every space, and the
/// frame the callee finds above its stack pointer -- this call's argument
/// area, or the whole frame where nothing bounds it -- as whole objects. What
/// has escaped, the escaped memory already covers.
fn call_locations(object_model: &ObjectModel, call: InstId) -> Vec<MemoryLocation> {
    let escaped = object_model.memory_spaces().filter_map(|space| {
        Some(MemoryLocation {
            space,
            object: object_model.escaped_unknown_object(space)?,
            address: RelativeMemoryAddress::Unknown,
            size: 0,
        })
    });
    let reach = object_model.frame_reach.call(call);
    let frame = object_model.objects.iter().filter_map(|(id, fact)| {
        let space = match fact.kind {
            ObjectKind::StackSlot { space, .. } | ObjectKind::FrameObject { space, .. } => space,
            _ => return None,
        };
        let reached = match reach {
            CallFrameReach::Whole => true,
            CallFrameReach::Objects(objects) => objects.contains(id),
        };
        (reached && !object_model.frame_reach.escaped(*id)).then_some(MemoryLocation {
            space,
            object: *id,
            address: RelativeMemoryAddress::Unknown,
            size: 0,
        })
    });
    escaped.chain(frame).collect()
}

/// What a memory location holds at a point, named before versions are
/// numbered: the value the function was entered with, the one a definition
/// wrote, or the merge of different ones at a block's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Held {
    Defined(MemoryVersion),
    /// The merge at this block's entry.
    Merged(u64),
    /// Different values met at a merge whose block is not yet named; the
    /// block's transfer names it [`Held::Merged`] at once.
    Merging,
}

/// The value each memory location holds. A location absent from the map
/// holds what the function was entered with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Holding(BTreeMap<MemoryLocation, Held>);

impl crate::fixpoint::Join for Holding {
    /// Per location, over a flat lattice: the entry value and every named
    /// value are atoms, and two different atoms join to a merge.
    fn join(&mut self, other: &Self) -> bool {
        let mut moved = false;
        let locations = self
            .0
            .keys()
            .chain(other.0.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        for location in locations {
            let mine = self.0.get(&location).copied();
            let theirs = other.0.get(&location).copied();
            if mine == theirs || mine == Some(Held::Merging) {
                continue;
            }
            self.0.insert(location, Held::Merging);
            moved = true;
        }
        moved
    }
}

/// Memory SSA over the function's blocks (doc/adr-fixpoint.md, K1).
///
/// Each location's value at each block entry is solved on the fixpoint
/// driver over a lattice of height three: unreached, one value, a merge. An
/// unreached predecessor adds nothing, so a loop that stores nothing to a
/// location merges nothing for it. Versions stay symbolic while the states
/// settle; the merges are numbered after, in block and location order, and
/// the uses, the definitions and each merge's inputs are read once off the
/// settled states.
pub(crate) fn build_memory_ssa(
    function: &SSAFunction,
    graph: &SsaGraph,
    object_model: &ObjectModel,
    access_summaries: BTreeMap<InstId, AccessSummary>,
) -> MemorySSAFacts {
    let mut next_version_by_object = BTreeMap::<ObjectId, u32>::new();
    for object in object_model.objects.keys() {
        next_version_by_object.insert(*object, 1);
    }
    let mut mint = |object: ObjectId| {
        let next = next_version_by_object.entry(object).or_insert(1);
        let version = MemoryVersion {
            object,
            version: *next,
        };
        *next = next.saturating_add(1);
        version
    };
    let mut def_versions = BTreeMap::<InstId, Vec<MemoryVersion>>::new();
    for (inst_id, summary) in &access_summaries {
        if !summary.defs.is_empty() {
            let versions = summary.defs.iter().map(|location| mint(location.object));
            def_versions.insert(*inst_id, versions.collect());
        }
    }
    let locations = access_summaries
        .values()
        .flat_map(|summary| summary.defs.iter())
        .cloned()
        .collect::<BTreeSet<_>>();

    // One block's accesses, in order, from the state at its entry; each use
    // and definition is handed to `seen` with what it read.
    let walk =
        |block_addr: u64, entry: &Holding, seen: &mut dyn FnMut(InstId, Access<'_>)| -> Holding {
            let mut state = entry.clone();
            for held in state.0.values_mut() {
                if *held == Held::Merging {
                    *held = Held::Merged(block_addr);
                }
            }
            let Some(block) = function.get_block(block_addr) else {
                return state;
            };
            for (op_id, _) in block.sited() {
                let Some(inst_id) = graph.inst_for_op(op_id) else {
                    continue;
                };
                let Some(summary) = access_summaries.get(&inst_id) else {
                    continue;
                };
                let reaching = |state: &Holding, location: &MemoryLocation| {
                    state
                        .0
                        .iter()
                        .filter(|(candidate, _)| {
                            memory_locations_may_alias(object_model, candidate, location)
                        })
                        .map(|(candidate, held)| (candidate.clone(), *held))
                        .collect::<Vec<_>>()
                };
                for location in &summary.uses {
                    seen(inst_id, Access::Use(location, reaching(&state, location)));
                }
                let Some(versions) = def_versions.get(&inst_id) else {
                    continue;
                };
                for (location, next) in summary.defs.iter().zip(versions) {
                    seen(
                        inst_id,
                        Access::Def(location, reaching(&state, location), *next),
                    );
                    state.0.retain(|candidate, _| {
                        !memory_locations_may_alias(object_model, candidate, location)
                    });
                    state.0.insert(location.clone(), Held::Defined(*next));
                }
            }
            state
        };

    // Each location can move from unreached to one value to a merge at each
    // block entry, so the entry states rise at most twice per location.
    let height = locations.len().saturating_mul(2).max(1);
    let solved = match crate::fixpoint::forward(
        function,
        "memory-ssa",
        height,
        Holding::default(),
        |block, entry| walk(block, entry, &mut |_, _| {}),
    ) {
        Ok(solved) => solved,
        Err(exhausted) => {
            r2il::refusal_evidence!("memory-ssa", "{exhausted}");
            return MemorySSAFacts::default();
        }
    };

    // Number the merges after the definitions, in block and location order.
    let mut merges = BTreeMap::<(u64, MemoryLocation), MemoryVersion>::new();
    for &block_addr in function.block_addrs() {
        let Some(entry) = solved.entry.get(&block_addr) else {
            continue;
        };
        for (location, held) in &entry.0 {
            if *held == Held::Merging {
                merges.insert((block_addr, location.clone()), mint(location.object));
            }
        }
    }
    // Every merge named at a block's entry was numbered above, and the walk
    // names a merge only at its own block, so the lookup always finds it.
    let version = |location: &MemoryLocation, held: Option<Held>| match held {
        None => MemoryVersion {
            object: location.object,
            version: 0,
        },
        Some(Held::Defined(version)) => version,
        Some(Held::Merged(block)) => *merges
            .get(&(block, location.clone()))
            .expect("every merge at a block entry is numbered"),
        Some(Held::Merging) => unreachable!("an unnamed merge never leaves its block's entry"),
    };
    let named = |reached: Vec<(MemoryLocation, Held)>, location: &MemoryLocation| {
        let mut versions = reached
            .into_iter()
            .map(|(candidate, held)| version(&candidate, Some(held)))
            .collect::<BTreeSet<_>>();
        if versions.is_empty() {
            versions.insert(version(location, None));
        }
        versions
    };

    let mut uses_by_inst = crate::dense::IdMap::<InstId, Vec<MemoryUseFact>>::default();
    let mut defs_by_inst = crate::dense::IdMap::<InstId, Vec<MemoryDefFact>>::default();
    for &block_addr in function.block_addrs() {
        let Some(entry) = solved.entry.get(&block_addr) else {
            continue;
        };
        walk(block_addr, entry, &mut |inst_id, access| match access {
            Access::Use(location, reached) => {
                for version in named(reached, location) {
                    uses_by_inst
                        .get_or_insert_with(inst_id, Vec::new)
                        .push(MemoryUseFact {
                            location: location.clone(),
                            version,
                        });
                }
            }
            Access::Def(location, reached, next) => {
                for previous_version in named(reached, location) {
                    defs_by_inst
                        .get_or_insert_with(inst_id, Vec::new)
                        .push(MemoryDefFact {
                            location: location.clone(),
                            previous_version,
                            next_version: next,
                        });
                }
            }
        });
    }

    let mut phis_by_block = BTreeMap::<u64, Vec<MemoryPhiFact>>::new();
    for ((block_addr, location), output_version) in &merges {
        let inputs = function
            .predecessors(*block_addr)
            .into_iter()
            .filter_map(|pred| {
                let held = solved.exit.get(&pred)?.0.get(location).copied();
                Some((pred, version(location, held)))
            })
            .collect();
        phis_by_block
            .entry(*block_addr)
            .or_default()
            .push(MemoryPhiFact {
                object: location.object,
                location: location.clone(),
                output_version: *output_version,
                inputs,
            });
    }

    MemorySSAFacts {
        uses_by_inst,
        defs_by_inst,
        phis_by_block,
    }
}

/// One memory access a block's walk meets: a use of a location, or a
/// definition of one with the version it writes; each with what reached it.
enum Access<'a> {
    Use(&'a MemoryLocation, Vec<(MemoryLocation, Held)>),
    Def(
        &'a MemoryLocation,
        Vec<(MemoryLocation, Held)>,
        MemoryVersion,
    ),
}
