//! The rewrites a built function applies to itself.

use super::*;
use crate::dense::{IdMap, IdSet, IdVec};

impl SSAFunction {
    /// Give every lane of a register read as the function was entered with it
    /// one value: a `Subpiece` of the root's entry value, defined at entry.
    ///
    /// A formal declared narrower than its carrier is such a lane whether or
    /// not the body reads it, so it is minted from the interface; every other
    /// entry-lane read the renamer produced -- one `Subpiece` per reading
    /// instruction -- becomes a copy of the one projection. The projection has
    /// no register storage of its own: it is a temporary the boundary facts
    /// know by this table (doc/adr-register-identity.md §6).
    /// Start a scratch register's lane writes from zero rather than from what
    /// the caller left in it.
    ///
    /// A lane written into a register the function never read is not
    /// preserving anything: `pinsrd xmm3, eax, 0` into a register no earlier
    /// instruction defined reads bits the caller happened to leave, and no
    /// compiled program depends on them. The insert still needs a value to
    /// build on, and C has to spell it, so where the root's entry value is
    /// read by nothing but the inserts themselves -- and the convention names
    /// no carrier there, so nobody passed anything in it -- the chain starts
    /// at zero and the rendering has no uninitialised read.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "ordered by variable on purpose: the first match must not depend on interning order (doc/adr-one-ir.md, 5c)"
        )
    )]
    pub(crate) fn zero_scratch_insert_roots(&mut self, abi_carriers: &[CanonicalStorageId]) {
        // A candidate's bits reach nothing but inserts. A merge passes the
        // same undefined bits along, so a use as a phi source is followed to
        // that merge and asked the same question; any other read -- a spill of
        // a callee-saved register, a return of an untouched argument -- is a
        // use of what the caller left, and disqualifies it.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum ScratchUse {
            InsertSource,
            Carried,
            Observed,
        }
        let mut uses =
            IdVec::<VarId, Vec<(ScratchUse, VarId)>>::filled(self.values.len(), Vec::new());
        for block in self.blocks.iter() {
            for phi in block.phis() {
                for (_, src) in &phi.sources {
                    uses[*src].push((ScratchUse::Carried, phi.dst));
                }
            }
            for op in block.ops() {
                if let SSAOp::Insert(insert) = op {
                    uses[insert.src].push((ScratchUse::InsertSource, insert.src));
                    for other in [insert.value, insert.position] {
                        uses[other].push((ScratchUse::Observed, other));
                    }
                } else {
                    for src in op.sources() {
                        uses[*src].push((ScratchUse::Observed, *src));
                    }
                }
            }
        }
        let reaches_inserts_only = |start: VarId| {
            let mut pending = vec![start];
            let mut seen = IdSet::<VarId>::new(uses.len());
            let mut inserted = false;
            while let Some(var) = pending.pop() {
                if !seen.insert(var) {
                    continue;
                }
                for (kind, next) in &uses[var] {
                    match kind {
                        ScratchUse::InsertSource => inserted = true,
                        ScratchUse::Carried => pending.push(*next),
                        ScratchUse::Observed => return false,
                    }
                }
            }
            inserted
        };
        // In variable order, which is the order the zeros are minted in.
        let scratch = uses
            .iter()
            .filter(|(_, reads)| !reads.is_empty())
            .map(|(id, _)| id)
            .filter(|id| self.var(*id).version == 0 && reaches_inserts_only(*id))
            .filter_map(|id| {
                let var = self.var(id);
                let storage = self.storage_of(id)?;
                (storage.space == CanonicalStorageSpace::Register
                    && !abi_carriers.iter().any(|carrier| {
                        carrier.space == storage.space
                            && carrier.offset < storage.offset + u64::from(storage.size)
                            && storage.offset < carrier.offset + u64::from(carrier.size)
                    }))
                .then(|| var.clone())
            })
            .collect::<BTreeSet<_>>();
        if scratch.is_empty() {
            return;
        }
        // A vector register is wider than any C constant, so its zero is the
        // zero-extension of a narrow one -- the same operation the prelude
        // spells for every other wide value.
        let mut minted = Vec::new();
        let mut zeros = IdMap::<VarId, VarId>::new(self.values.len());
        for var in &scratch {
            let zero = if var.size <= 16 {
                SSAVar::constant(0, var.size)
            } else {
                let disambiguator = self
                    .values
                    .storage_by_var()
                    .into_iter()
                    .map(|(other, _)| other)
                    .filter(|other| other.name() == var.name())
                    .map(SSAVar::rename_disambiguator)
                    .max()
                    .map_or(1, |max| max + 1);
                // Version one: it is a definition, and version zero is
                // reserved for the value a block was entered with.
                let zero =
                    SSAVar::new(var.name(), 1, var.size).with_rename_disambiguator(disambiguator);
                minted.push(SSAOp::IntZExt {
                    dst: zero.clone(),
                    src: SSAVar::constant(0, 4),
                });
                if let Some(storage) = self.canonical_storage_for_var(var) {
                    self.values.intern_with_storage(&zero, storage);
                }
                zero
            };
            let held = self
                .values
                .id_of(var)
                .expect("a scratch root is an operand");
            zeros.insert(held, self.values.intern(&zero));
        }
        for block in self.blocks.edit().iter_mut() {
            for phi in block.phis_mut() {
                for (_, src) in &mut phi.sources {
                    if let Some(zero) = zeros.get(*src) {
                        *src = *zero;
                    }
                }
            }
            for op in block.ops_mut() {
                if let SSAOp::Insert(insert) = op
                    && let Some(zero) = zeros.get(insert.src)
                {
                    insert.src = *zero;
                }
            }
        }
        let minted = minted
            .iter()
            .map(|op| (op.map(&mut |var| self.values.intern(var)), None))
            .collect::<Vec<_>>();
        let mut plan = EditPlan::new();
        plan.insert(Anchor::Start(self.root()), Pass::ScratchZero, minted);
        self.apply_edits(plan);
    }

    /// Replace the values a boundary states: the processor specification's
    /// tracked registers on entry, and the direction flag on entry and after
    /// every call, with the zero the convention requires of it.
    ///
    /// A repeated string instruction reads the flag to decide which way it
    /// walks, and no compiled function sets it -- the corpus contains no `cld`
    /// or `std` at all -- so what it holds where the instruction reads it is
    /// whatever the caller or the last callee left. Both x86 ABIs require it
    /// clear on entry and on return, and that is the whole of what makes the
    /// direction knowable. Substituting the constant here rather than reading
    /// the fact at the rendering is what lets the arithmetic beside the
    /// transfer fold: the instruction's own pointer updates are written over
    /// the flag, and with it a constant they collapse to the extent.
    ///
    /// A tracked register states only its entry value: past a call it holds
    /// what the call effect leaves, which is the entry value where the effect
    /// preserves it and a call definition where it does not.
    ///
    /// Nothing is substituted for a convention that states no such thing, or a
    /// machine with no such flag, and a function that writes the flag itself
    /// has a later version neither boundary value reaches.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "ordered by variable on purpose: the first match must not depend on interning order (doc/adr-one-ir.md, 5c)"
        )
    )]
    pub(crate) fn apply_boundary_constants(&mut self, machine_context: &SourceMachineContext) {
        let clears = machine_context
            .convention_slots()
            .is_some_and(|slots| slots.abi_class().clears_direction_flag());
        let cleared_flag = machine_context
            .machine_roles()
            .direction_flag_storage()
            .filter(|_| clears);
        let entry_constants = machine_context
            .tracked_entry_values()
            .iter()
            .copied()
            .chain(cleared_flag.map(|storage| (storage, 0)))
            .collect::<BTreeMap<_, _>>();
        let storage_of = |id: VarId| self.storage_of(id);
        // The entry values, and the value each call's clobber leaves in the flag.
        let boundary_values = self
            .values
            .storage_by_var()
            .into_iter()
            .filter(|(var, _)| var.version == 0)
            .filter_map(|(var, storage)| Some((var.clone(), *entry_constants.get(&storage)?)))
            .chain(
                self.blocks
                    .iter()
                    .flat_map(|block| block.ops())
                    .filter_map(|op| match op {
                        SSAOp::CallDefine { dst }
                            if cleared_flag.is_some() && storage_of(*dst) == cleared_flag =>
                        {
                            Some((self.var(*dst).clone(), 0))
                        }
                        _ => None,
                    }),
            )
            .collect::<BTreeMap<_, _>>();
        if boundary_values.is_empty() {
            return;
        }
        r2il::refusal_evidence!(
            "boundary-constants",
            "{} boundary values become the constants stated for them: entry {entry_constants:?}, after a call {cleared_flag:?}",
            boundary_values.len()
        );
        let mut substitutes = IdMap::<VarId, VarId>::new(self.values.len());
        for (var, value) in &boundary_values {
            if let Some(held) = self.values.id_of(var) {
                substitutes.insert(
                    held,
                    self.values.intern(&SSAVar::constant(*value, var.size)),
                );
            }
        }
        let substitute = |id: &VarId| substitutes.get(*id).copied().unwrap_or(*id);
        for block in self.blocks.edit().iter_mut() {
            for phi in block.phis_mut() {
                for (_, src) in &mut phi.sources {
                    *src = substitute(src);
                }
            }
            for op in block.ops_mut() {
                *op = op.map_sources(substitute);
            }
        }
    }

    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "ordered by variable on purpose: the first match must not depend on interning order (doc/adr-one-ir.md, 5c)"
        )
    )]
    pub(crate) fn mint_entry_lane_projections(&mut self, machine_context: &SourceMachineContext) {
        let is_root_entry = |var: &SSAVar, storage: Option<CanonicalStorageId>| {
            var.version == 0
                && storage.is_some_and(|storage| {
                    storage.space == CanonicalStorageSpace::Register && storage.size == var.size
                })
        };
        // Lane key: (root storage, byte offset in the root, width) -> the root's
        // entry variable and the reads to fold into the projection.
        // Lane key: (root storage, byte offset in the root, width) -> the root's
        // entry variable and the reads inside the lane, each with its offset
        // from the lane's start.
        let mut lanes = BTreeMap::<
            (CanonicalStorageId, u32, u32),
            (Option<SSAVar>, Vec<(u64, usize, u32)>),
        >::new();
        // The entry registers the renamer read whole: a formal inside one of
        // them is a lane of that root, whatever width the convention names
        // it at -- `d1` is a lane of `z1` as much as `edi` is one of `rdi`.
        let entry_roots = self
            .values
            .storage_by_var()
            .into_iter()
            .filter(|(var, storage)| {
                var.version == 0
                    && storage.space == CanonicalStorageSpace::Register
                    && storage.size == var.size
            })
            .map(|(_, storage)| storage)
            .collect::<Vec<_>>();
        for projection in crate::semantic::source_formal_parameter_projections(machine_context) {
            let lane = projection.graph_storage;
            let root = entry_roots
                .iter()
                .copied()
                .find(|root| {
                    *root != lane
                        && root.offset <= lane.offset
                        && lane.offset + u64::from(lane.size) <= root.offset + u64::from(root.size)
                })
                .unwrap_or(projection.abi_storage);
            if root == lane {
                continue;
            }
            let Some(offset) = lane
                .offset
                .checked_sub(root.offset)
                .and_then(|offset| u32::try_from(offset).ok())
            else {
                continue;
            };
            r2il::refusal_evidence!(
                "entry-lane",
                "formal {} lane {:?} of root {:?}",
                projection.index,
                lane,
                root
            );
            lanes.entry((root, offset, lane.size)).or_default();
        }
        if lanes.is_empty() {
            return;
        }
        // Only a lane the interface declares is a formal; any other lane read
        // of an entry root stays the `Subpiece` of the caller's value it is.
        for addr in self.block_order.clone() {
            let Some(block) = self.get_block(addr) else {
                continue;
            };
            for (op_index, op) in block.ops().iter().enumerate() {
                let SSAOp::Subpiece { dst, src, offset } = op else {
                    continue;
                };
                let (dst, src) = (self.var(*dst), self.var(*src));
                let storage = self.canonical_storage_for_var(src);
                if !is_root_entry(src, storage) {
                    continue;
                }
                let Some(root) = storage else {
                    continue;
                };
                // A read inside a declared lane reads the formal, whether it
                // is the whole lane or a byte of it.
                let Some((key, inside)) = lanes.keys().find_map(|key| {
                    (key.0 == root && key.1 <= *offset && *offset + dst.size <= key.1 + key.2)
                        .then_some((*key, *offset - key.1))
                }) else {
                    r2il::refusal_evidence!(
                        "entry-lane",
                        "({addr:#x}, {op_index}) reads {offset}+{} of entry root {:?}, no declared lane",
                        dst.size,
                        root
                    );
                    continue;
                };
                let lane = lanes.get_mut(&key).expect("a key just found");
                lane.0.get_or_insert_with(|| src.clone());
                lane.1.push((addr, op_index, inside));
            }
        }
        let mut minted = Vec::new();
        // Each root's declared lanes, to rebuild the root from them below.
        let mut lanes_by_root = BTreeMap::<SSAVar, (CanonicalStorageId, Vec<(SSAVar, u32)>)>::new();
        for ((root, offset, width), (root_var, reads)) in lanes {
            // The root's entry value is the renamer's, when it named one; a
            // fresh name would enter the family a second time.
            let root_var = root_var
                .or_else(|| {
                    // Live, not a snapshot: a root an earlier lane named is
                    // the one this lane must name too.
                    self.values
                        .storage_by_var()
                        .into_iter()
                        .find(|(var, storage)| var.version == 0 && *storage == root)
                        .map(|(var, _)| var.clone())
                })
                .unwrap_or_else(|| {
                    let name = machine_context
                        .register_name(root)
                        .unwrap_or_else(|| format!("reg:{:x}", root.offset));
                    SSAVar::initial(name, root.size)
                });
            let lane_storage = CanonicalStorageId {
                space: CanonicalStorageSpace::Register,
                offset: root.offset + u64::from(offset),
                size: width,
            };
            // The formal is named as the lane register the caller filled, the
            // way an entry value is named after its register.
            let name = machine_context
                .register_name(lane_storage)
                .map(|name| name.to_ascii_uppercase())
                .unwrap_or_else(|| format!("reg:{:x}:{width}", lane_storage.offset));
            // The caller's value of the lane, live at entry: nothing in the
            // body defines it, so it is version zero with no definition.
            let projection = SSAVar::new(name, 0, width);
            let held = self.values.intern(&root_var);
            if self.values.storage(held).is_none() {
                self.values.set_storage(held, root);
            }
            let projection_id = self.values.intern(&projection);
            self.formal_projections.insert(projection_id, lane_storage);
            if offset == 0 {
                self.entry_lanes.insert(projection_id, held);
            }
            for (addr, op_index, inside) in reads {
                if let Some(block) = block_at_mut(&self.block_index, self.blocks.edit(), addr)
                    && let Some(SSAOp::Subpiece { dst, .. }) = block.ops().get(op_index)
                {
                    let dst = *dst;
                    block.ops_mut()[op_index] = if inside == 0 && self.values.var(dst).size == width
                    {
                        SSAOp::Copy {
                            dst,
                            src: projection_id,
                        }
                    } else {
                        SSAOp::Subpiece {
                            dst,
                            src: projection_id,
                            offset: inside,
                        }
                    };
                }
            }
            lanes_by_root
                .entry(root_var.clone())
                .or_insert((root, Vec::new()))
                .1
                .push((projection, offset));
        }
        // A read of the whole register -- a merge input, a spill -- reads the
        // declared lanes through their formals and every other byte as the
        // caller left it: the root rebuilt by inserting each formal into the
        // caller's own register. No byte is invented. Where nothing reads the
        // bytes above the lanes the demand pass releases the base with its
        // proof; where something does, it reads the caller's entry bytes,
        // which no declaration names and the rendering shows as residuals.
        // Every variable the body reads, and the highest disambiguator each
        // name carries. Both were asked once per root, and each asking walked
        // the whole function, so a body with many entry registers paid for it
        // as many times over.
        let mut read_anywhere = IdSet::<VarId>::new(self.values.len());
        for block in self.blocks.iter() {
            for phi in block.phis() {
                for (_, src) in &phi.sources {
                    read_anywhere.insert(*src);
                }
            }
            for op in block.ops() {
                for src in op.sources() {
                    read_anywhere.insert(*src);
                }
            }
        }
        let mut highest_disambiguator = BTreeMap::<String, u32>::new();
        for (var, _) in self.values.storage_by_var() {
            let entry = highest_disambiguator
                .entry(var.name().to_string())
                .or_insert(0);
            *entry = (*entry).max(var.rename_disambiguator());
        }
        let mut substitutions = IdMap::<VarId, VarId>::new(self.values.len());
        for (root_var, (root, lanes)) in lanes_by_root {
            // Only for a root a C integer can hold; a vector register's
            // lanes are not parameters and have no declaration to rest on.
            if root.size > 8 {
                continue;
            }
            let Some(root_id) = self
                .values
                .id_of(&root_var)
                .filter(|id| read_anywhere.contains(*id))
            else {
                continue;
            };
            let disambiguator = highest_disambiguator
                .get(root_var.name())
                .map_or(1, |max| max + 1);
            // A definition, so not version zero.
            let composed =
                SSAVar::new(root_var.name(), 1, root.size).with_rename_disambiguator(disambiguator);
            let mut carried = root_var.clone();
            for (index, (lane, offset)) in lanes.iter().enumerate() {
                let dst = if index + 1 == lanes.len() {
                    composed.clone()
                } else {
                    SSAVar::new(
                        format!("tmp:root:{}:{index}", root_var.name()),
                        1,
                        root.size,
                    )
                };
                minted.push(SSAOp::Insert(Box::new(crate::op::InsertOp {
                    dst: dst.clone(),
                    src: carried,
                    value: lane.clone(),
                    position: SSAVar::constant(u64::from(*offset) * 8, 4),
                })));
                carried = dst;
            }
            highest_disambiguator.insert(composed.name().to_string(), disambiguator);
            let composed_id = self.values.intern_with_storage(&composed, root);
            self.formal_roots.insert(composed_id, root);
            substitutions.insert(root_id, self.values.intern(&composed));
        }
        // One walk for every root. Each root substitutes one variable, and
        // rewriting the body once per root read every operation R times to do
        // R independent substitutions; no root's replacement is another
        // root's key, because each composed variable is minted here.
        if !substitutions.is_empty() {
            let replace = |var: &VarId| substitutions.get(*var).copied().unwrap_or(*var);
            for block in self.blocks.edit().iter_mut() {
                for phi in block.phis_mut() {
                    for (_, src) in &mut phi.sources {
                        *src = replace(src);
                    }
                }
                for op in block.ops_mut() {
                    *op = op.map_sources(replace);
                }
            }
        }
        let minted = minted
            .iter()
            .map(|op| (op.map(&mut |var| self.values.intern(var)), None))
            .collect::<Vec<_>>();
        let mut plan = EditPlan::new();
        plan.insert(Anchor::Start(self.root()), Pass::EntryLanes, minted);
        self.apply_edits(plan);
    }

    pub(crate) fn collect_decompile_prep_facts_with_control<C: SsaWorkControl + ?Sized>(
        &self,
        graph: &crate::graph::SsaGraph,
        function_interface: Option<&SourceFunctionInterface>,
        control: &C,
    ) -> Result<DecompilePrepFacts, SsaExecutionStopReason> {
        control.poll()?;
        // A call only threatens entry-relative facts if it can leave the stack
        // and frame carriers changed. The convention states which carriers a
        // callee restores, and the source now carries that statement, so a
        // direct or indirect call is no longer a reason to withhold every
        // entry-relative fact from the function that makes one.
        //
        // Operations whose effect the model does not describe are a different
        // matter: nothing says what they leave behind, so they still stop this.
        // The convention's call effect states it, with or without a linked signature.
        let call_carriers_are_restored = self
            .call_preserved_carriers
            .is_some_and(|carriers| carriers.stack_pointer() && carriers.frame_pointer());
        // A user operation writes only its output varnode.
        let frame_carriers = [
            self.stack_pointer_carrier(),
            function_interface.and_then(SourceFunctionInterface::frame_pointer_storage),
        ];
        let writes_no_frame_carrier = |output: &Option<VarId>| {
            output.as_ref().is_none_or(|dst| {
                self.canonical_storage_for_var(self.var(*dst))
                    .is_none_or(|storage| {
                        !frame_carriers.iter().flatten().any(|carrier| {
                            crate::semantic::register_storages_overlap(storage, *carrier)
                        })
                    })
            })
        };
        let entry_stack_roots_are_stable = self.blocks().iter().all(|block| {
            block.ops().iter().all(|op| match op {
                SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. } => call_carriers_are_restored,
                SSAOp::CallOther { output, .. } => writes_no_frame_carrier(output),
                SSAOp::Unimplemented | SSAOp::CpuId { .. } | SSAOp::New { .. } => false,
                _ => true,
            })
        });
        // Identity first: every stack-root question below names a value by its
        // representative, and the representative is the view's answer.
        let values = graph.values.len();
        let mut facts = DecompilePrepFacts {
            views: crate::view::ValueViews::of_graph(graph),
            stack_address_roots: crate::dense::IdMap::new(values),
            entry_stack_address_roots: crate::dense::IdMap::new(values),
            indexed_stack_address_roots: crate::dense::IdMap::new(values),
            formal_parameters: crate::dense::IdMap::new(values),
            formal_parameter_bases: crate::dense::IdMap::new(values),
        };
        control.poll()?;
        let mut declared_stack_bases = BTreeMap::new();
        let mut entry_stack_address_size = None;
        // The stack pointer is a machine fact: the roles name it for every
        // function, and the entry-relative position of anything derived from
        // it does not wait on a linked signature or exact slot roles. Only the
        // declared slots' bases come from the interface, and only where its
        // roles are exact.
        if let Some(storage) = function_interface
            .and_then(SourceFunctionInterface::stack_pointer_storage)
            .or(self.stack_pointer_carrier)
        {
            declared_stack_bases.insert(storage, StackAddressBase::StackPointer);
            if entry_stack_roots_are_stable {
                entry_stack_address_size = Some(storage.size);
            }
        }
        // A slot's base register is a per-slot fact. Requiring every slot's
        // role to be attributed before believing any slot's base installed no
        // stack bases at all when one local went unclassified, which left
        // every stack address in the function without a root -- and with it
        // every frame object a call takes the address of.
        if let Some(interface) = function_interface.filter(|interface| {
            interface.stack_pointer_storage().is_some()
                && interface.return_address_storage().is_some()
        }) {
            for slot in interface.stack_slots() {
                declared_stack_bases.insert(slot.base_storage(), slot.base());
            }
        }
        // The entry values of the declared bases are the seeds: a value of
        // the graph at version zero whose storage is one of them.
        for value in &graph.values {
            if value.var.version != 0 || self.canonical_storage_for_var(&value.var).is_none() {
                continue;
            }
            let Some(storage) = self.canonical_storage_for_var(&value.var) else {
                continue;
            };
            if let Some(base) = declared_stack_bases.get(&storage).copied() {
                facts
                    .stack_address_roots
                    .insert(value.id, StackAddressRoot { base, offset: 0 });
                if entry_stack_roots_are_stable && base == StackAddressBase::StackPointer {
                    facts.entry_stack_address_roots.insert(
                        value.id,
                        StackAddressRoot {
                            base: StackAddressBase::StackPointer,
                            offset: 0,
                        },
                    );
                }
            }
        }
        // Every stack root, solved once from the seeds above
        // (`stack_roots`, doc/adr-fixpoint.md K2).
        control.poll()?;
        let seeds = super::stack_roots::Seeds {
            exact: facts.stack_address_roots.clone(),
            entry: facts.entry_stack_address_roots.clone(),
            entry_size: entry_stack_address_size,
        };
        match super::stack_roots::solve(graph, self.entry, &facts.views, seeds) {
            Ok(roots) => {
                facts.stack_address_roots = roots.exact;
                facts.entry_stack_address_roots = roots.entry;
                facts.indexed_stack_address_roots = roots.indexed;
            }
            // A monotone solve settles within its budget; past it, only the
            // seeds -- what the entry states -- are claimed.
            Err(exhausted) => {
                r2il::refusal_evidence!("stack-roots", "{:#x}: {exhausted}", self.entry);
            }
        }
        control.poll()?;
        Ok(facts)
    }
}
