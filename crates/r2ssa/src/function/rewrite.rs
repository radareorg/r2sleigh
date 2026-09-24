//! The rewrites a built function applies to itself.

use super::*;

impl SSAFunction {
    /// Give every lane of a register read as the function was entered with it
    /// one value: a `Subpiece` of the root's entry value, defined at entry.
    ///
    /// A formal declared narrower than its carrier is such a lane whether or
    /// not the body reads it, so it is minted from the interface; every other
    /// entry-lane read the renamer produced -- one `Subpiece` per reading
    /// instruction -- becomes a copy of the one projection. The projection has
    /// no register storage of its own: it is a temporary the boundary facts
    /// know by this table (doc/adr-register-identity.md §8, 6).
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
        let mut uses = BTreeMap::<SSAVar, Vec<(ScratchUse, SSAVar)>>::new();
        for block in self.blocks.iter() {
            for phi in &block.phis {
                for (_, src) in &phi.sources {
                    uses.entry(src.clone())
                        .or_default()
                        .push((ScratchUse::Carried, phi.dst.clone()));
                }
            }
            for op in &block.ops {
                if let SSAOp::Insert(insert) = op {
                    let (src, value, position) = (&insert.src, &insert.value, &insert.position);
                    uses.entry(src.clone())
                        .or_default()
                        .push((ScratchUse::InsertSource, src.clone()));
                    for other in [value, position] {
                        uses.entry((*other).clone())
                            .or_default()
                            .push((ScratchUse::Observed, (*other).clone()));
                    }
                } else {
                    for src in op.sources() {
                        uses.entry(src.clone())
                            .or_default()
                            .push((ScratchUse::Observed, src.clone()));
                    }
                }
            }
        }
        let reaches_inserts_only = |start: &SSAVar| {
            let mut pending = vec![start.clone()];
            let mut seen = BTreeSet::new();
            let mut inserted = false;
            while let Some(var) = pending.pop() {
                if !seen.insert(var.clone()) {
                    continue;
                }
                for (kind, next) in uses.get(&var).into_iter().flatten() {
                    match kind {
                        ScratchUse::InsertSource => inserted = true,
                        ScratchUse::Carried => pending.push(next.clone()),
                        ScratchUse::Observed => return false,
                    }
                }
            }
            inserted
        };
        let scratch = uses
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|var| var.version == 0 && reaches_inserts_only(var))
            .filter_map(|var| {
                let storage = self.canonical_storage_by_var.get(&var).copied()?;
                (storage.space == CanonicalStorageSpace::Register
                    && !abi_carriers.iter().any(|carrier| {
                        carrier.space == storage.space
                            && carrier.offset < storage.offset + u64::from(storage.size)
                            && storage.offset < carrier.offset + u64::from(carrier.size)
                    }))
                .then_some(var)
            })
            .collect::<BTreeSet<_>>();
        if scratch.is_empty() {
            return;
        }
        // A vector register is wider than any C constant, so its zero is the
        // zero-extension of a narrow one -- the same operation the prelude
        // spells for every other wide value.
        let mut minted = Vec::new();
        let zeros = scratch
            .iter()
            .map(|var| {
                let zero = if var.size <= 16 {
                    SSAVar::constant(0, var.size)
                } else {
                    let disambiguator = self
                        .canonical_storage_by_var
                        .keys()
                        .filter(|other| other.name() == var.name())
                        .map(SSAVar::rename_disambiguator)
                        .max()
                        .map_or(1, |max| max + 1);
                    // Version one: it is a definition, and version zero is
                    // reserved for the value a block was entered with.
                    let zero = SSAVar::new(var.name(), 1, var.size)
                        .with_rename_disambiguator(disambiguator);
                    minted.push(SSAOp::IntZExt {
                        dst: zero.clone(),
                        src: SSAVar::constant(0, 4),
                    });
                    if let Some(storage) = self.canonical_storage_by_var.get(var).copied() {
                        self.canonical_storage_by_var.insert(zero.clone(), storage);
                    }
                    zero
                };
                (var.clone(), zero)
            })
            .collect::<BTreeMap<_, _>>();
        for block in self.blocks.iter_mut() {
            for phi in &mut block.phis {
                for (_, src) in &mut phi.sources {
                    if let Some(zero) = zeros.get(src) {
                        *src = zero.clone();
                    }
                }
            }
            for op in &mut block.ops {
                if let SSAOp::Insert(insert) = op
                    && let Some(zero) = zeros.get(&insert.src)
                {
                    insert.src = zero.clone();
                }
            }
        }
        self.insert_ops(
            self.entry,
            0,
            minted.into_iter().map(|op| (op, None)).collect(),
        );
        self.decompile_prep_facts = None;
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
        let storage_of = |var: &SSAVar| self.canonical_storage_by_var.get(var).copied();
        // The entry values, and the value each call's clobber leaves in the flag.
        let boundary_values = self
            .canonical_storage_by_var
            .iter()
            .filter(|(var, _)| var.version == 0)
            .filter_map(|(var, storage)| Some((var.clone(), *entry_constants.get(storage)?)))
            .chain(
                self.blocks
                    .iter()
                    .flat_map(|block| &block.ops)
                    .filter_map(|op| match op {
                        SSAOp::CallDefine { dst }
                            if cleared_flag.is_some() && storage_of(dst) == cleared_flag =>
                        {
                            Some((dst.clone(), 0))
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
        let substitute = |var: &SSAVar| match boundary_values.get(var) {
            Some(value) => SSAVar::constant(*value, var.size),
            None => var.clone(),
        };
        for block in self.blocks.iter_mut() {
            for phi in &mut block.phis {
                for (_, src) in &mut phi.sources {
                    *src = substitute(src);
                }
            }
            for op in &mut block.ops {
                *op = crate::optimize::map_sources_in_op(op, &substitute);
            }
        }
        self.invalidate_query_index();
    }

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
            .canonical_storage_by_var
            .iter()
            .filter(|(var, storage)| {
                var.version == 0
                    && storage.space == CanonicalStorageSpace::Register
                    && storage.size == var.size
            })
            .map(|(_, storage)| *storage)
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
            for (op_index, op) in block.ops.iter().enumerate() {
                let SSAOp::Subpiece { dst, src, offset } = op else {
                    continue;
                };
                let storage = self.canonical_storage_by_var.get(src).copied();
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
                    self.canonical_storage_by_var
                        .iter()
                        .find(|(var, storage)| var.version == 0 && **storage == root)
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
            let projection = SSAVar::new(name, 0, width);
            self.canonical_storage_by_var
                .entry(root_var.clone())
                .or_insert(root);
            self.formal_projections
                .insert(projection.clone(), lane_storage);
            for (addr, op_index, inside) in reads {
                if let Some(block) = block_at_mut(&self.block_index, &mut self.blocks, addr)
                    && let Some(SSAOp::Subpiece { dst, .. }) = block.ops.get(op_index)
                {
                    let dst = dst.clone();
                    block.ops[op_index] = if inside == 0 && dst.size == width {
                        SSAOp::Copy {
                            dst,
                            src: projection.clone(),
                        }
                    } else {
                        SSAOp::Subpiece {
                            dst,
                            src: projection.clone(),
                            offset: inside,
                        }
                    };
                }
            }
            lanes_by_root
                .entry(root_var.clone())
                .or_insert((root, Vec::new()))
                .1
                .push((projection.clone(), offset));
            minted.push(SSAOp::Subpiece {
                dst: projection,
                src: root_var,
                offset,
            });
        }
        // The caller's root is its formals: a read of the whole register --
        // a merge input, a spill -- takes the declared lanes with zero above
        // them, so no rendering reads a register byte no formal names.
        //
        // The bytes above a declared lane are not the caller's to describe.
        // The declaration is the source's own statement of what it passed, so
        // no source expression names them, and where the interface was
        // recovered rather than declared they are exactly the bytes no
        // observation reached -- which is why the recovery declared the lane
        // narrow in the first place. Either way nothing the program computes
        // depends on them, and zero is as good a value as the register held.
        // Every variable the body reads, and the highest disambiguator each
        // name carries. Both were asked once per root, and each asking walked
        // the whole function, so a body with many entry registers paid for it
        // as many times over.
        let mut read_anywhere = BTreeSet::<SSAVar>::new();
        for block in self.blocks.iter() {
            for phi in &block.phis {
                read_anywhere.extend(phi.sources.iter().map(|(_, src)| src.clone()));
            }
            for op in &block.ops {
                read_anywhere.extend(op.sources().into_iter().cloned());
            }
        }
        let mut highest_disambiguator = BTreeMap::<String, u32>::new();
        for var in self.canonical_storage_by_var.keys() {
            let entry = highest_disambiguator
                .entry(var.name().to_string())
                .or_insert(0);
            *entry = (*entry).max(var.rename_disambiguator());
        }
        let mut substitutions = BTreeMap::<SSAVar, SSAVar>::new();
        for (root_var, (root, lanes)) in lanes_by_root {
            // Only for a root a C integer can hold; a vector register's
            // lanes are not parameters and have no declaration to rest on.
            if root.size > 8 {
                continue;
            }
            if !read_anywhere.contains(&root_var) {
                continue;
            }
            let disambiguator = highest_disambiguator
                .get(root_var.name())
                .map_or(1, |max| max + 1);
            let composed =
                SSAVar::new(root_var.name(), 0, root.size).with_rename_disambiguator(disambiguator);
            match lanes.as_slice() {
                [(lane, 0)] if lane.size < root.size => minted.push(SSAOp::IntZExt {
                    dst: composed.clone(),
                    src: lane.clone(),
                }),
                _ => {
                    let mut carried = SSAVar::constant(0, root.size);
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
                }
            }
            highest_disambiguator.insert(composed.name().to_string(), disambiguator);
            self.canonical_storage_by_var.insert(composed.clone(), root);
            substitutions.insert(root_var, composed);
        }
        // One walk for every root. Each root substitutes one variable, and
        // rewriting the body once per root read every operation R times to do
        // R independent substitutions; no root's replacement is another
        // root's key, because each composed variable is minted here.
        if !substitutions.is_empty() {
            let replace = |var: &SSAVar| {
                substitutions
                    .get(var)
                    .cloned()
                    .unwrap_or_else(|| var.clone())
            };
            for block in self.blocks.iter_mut() {
                for phi in &mut block.phis {
                    for (_, src) in &mut phi.sources {
                        *src = replace(src);
                    }
                }
                for op in &mut block.ops {
                    *op = crate::optimize::map_sources_in_op(op, &replace);
                }
            }
        }
        self.insert_ops(
            self.entry,
            0,
            minted.into_iter().map(|op| (op, None)).collect(),
        );
    }

    pub(crate) fn collect_decompile_prep_facts_with_control<C: SsaWorkControl + ?Sized>(
        &self,
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
        let writes_no_frame_carrier = |output: &Option<SSAVar>| {
            output.as_ref().is_none_or(|dst| {
                self.canonical_storage_for_var(dst).is_none_or(|storage| {
                    !frame_carriers.iter().flatten().any(|carrier| {
                        crate::semantic::register_storages_overlap(storage, *carrier)
                    })
                })
            })
        };
        let entry_stack_roots_are_stable = self.blocks().iter().all(|block| {
            block.ops.iter().all(|op| match op {
                SSAOp::Call { .. }
                | SSAOp::CallInd { .. }
                | SSAOp::CallDefine { .. }
                | SSAOp::CallRestore { .. } => call_carriers_are_restored,
                SSAOp::CallOther { output, .. } => writes_no_frame_carrier(output),
                SSAOp::Unimplemented | SSAOp::CpuId { .. } | SSAOp::New { .. } => false,
                _ => true,
            })
        });
        let mut facts = DecompilePrepFacts::default();
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
        for var in self.canonical_storage_by_var.keys() {
            if var.version != 0 {
                continue;
            }
            let Some(storage) = self.canonical_storage_for_var(var) else {
                continue;
            };
            if let Some(base) = declared_stack_bases.get(&storage).copied() {
                facts
                    .stack_address_roots
                    .insert(var.clone(), StackAddressRoot { base, offset: 0 });
                if entry_stack_roots_are_stable && base == StackAddressBase::StackPointer {
                    facts.entry_stack_address_roots.insert(
                        var.clone(),
                        StackAddressRoot {
                            base: StackAddressBase::StackPointer,
                            offset: 0,
                        },
                    );
                }
            }
        }
        self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
        if self.root_realigned_stack_pointer(&mut facts, entry_stack_address_size) {
            self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
        }
        // A stack pointer carried around a loop cannot be rooted by a meet: the
        // phi wants every source rooted, and the back edge derives from the phi,
        // so neither ever starts. Assume the back edge agrees with the sources
        // that are rooted, propagate, and keep the assumption only if the back
        // edge comes back agreeing. An unbalanced loop body disagrees by its own
        // drift and is rejected, which is the same answer the meet gave -- but
        // only for the loops that really drift.
        let mut rejected = BTreeSet::new();
        loop {
            control.poll()?;
            let proven = facts.clone();
            let speculated = self.speculate_loop_carried_stack_roots(&mut facts, &rejected);
            if speculated.is_empty() {
                break;
            }
            self.propagate_stack_roots(&mut facts, entry_stack_address_size, control)?;
            let failed = self.unverified_stack_root_speculations(&facts, &speculated);
            r2il::refusal_evidence!(
                "stack-root-speculation",
                "{:#x}: speculated {:?} failed {:?}",
                self.entry,
                speculated
                    .iter()
                    .map(|(dst, root, entry)| (dst.display_name(), *root, *entry))
                    .collect::<Vec<_>>(),
                failed.iter().map(SSAVar::display_name).collect::<Vec<_>>()
            );
            // A round that holds may make a later merge speculable: the
            // second loop's stack pointer rests on the first loop's, whose
            // root arrived only now. Stopping here left it unrooted.
            if !failed.is_empty() {
                facts = proven;
                rejected.extend(failed);
            }
        }

        control.poll()?;
        Ok(facts)
    }

    /// Root the phis whose rooted sources agree, assuming the rest will.
    ///
    /// Returns what was assumed, so a second propagation can judge it. Only a
    /// phi with at least one rooted source and no disagreement among the rooted
    /// ones is a candidate: with nothing known there is nothing to assume.
    fn speculate_loop_carried_stack_roots(
        &self,
        facts: &mut DecompilePrepFacts,
        rejected: &BTreeSet<SSAVar>,
    ) -> Vec<(SSAVar, StackAddressRoot, bool)> {
        let mut speculated = Vec::new();
        for &addr in &self.block_order {
            let Some(block) = self.get_block(addr) else {
                continue;
            };
            for phi in &block.phis {
                if rejected.contains(&phi.dst) {
                    continue;
                }
                for entry in [false, true] {
                    let roots = if entry {
                        &facts.entry_stack_address_roots
                    } else {
                        &facts.stack_address_roots
                    };
                    if roots.contains_key(&phi.dst) {
                        continue;
                    }
                    let known = phi
                        .sources
                        .iter()
                        .filter_map(|(_, source)| {
                            resolve_stack_root(source, &facts.canonical_value_roots, roots)
                        })
                        .collect::<BTreeSet<_>>();
                    let [root] = known.into_iter().collect::<Vec<_>>()[..] else {
                        continue;
                    };
                    speculated.push((phi.dst.clone(), root, entry));
                }
            }
        }
        for (dst, root, entry) in &speculated {
            let roots = if *entry {
                &mut facts.entry_stack_address_roots
            } else {
                &mut facts.stack_address_roots
            };
            insert_stack_root(roots, dst.clone(), *root);
        }
        speculated
    }

    /// Propagate stack-address roots to a fixpoint.
    ///
    /// Separated so it can be re-run: a stack pointer carried around a loop
    /// is rooted only after a speculation, and the speculation is judged by
    /// what a second run of this makes of it.
    fn propagate_stack_roots<C: SsaWorkControl + ?Sized>(
        &self,
        facts: &mut DecompilePrepFacts,
        entry_stack_address_size: Option<u32>,
        control: &C,
    ) -> Result<(), SsaExecutionStopReason> {
        let mut changed = true;
        while changed {
            control.poll()?;
            changed = false;
            for &addr in &self.block_order {
                control.poll()?;
                let Some(block) = self.get_block(addr) else {
                    continue;
                };

                for phi in &block.phis {
                    control.poll()?;
                    // Resolve each source's root once. The three questions
                    // below all read it, and asking each of them separately
                    // walked the root map three times per incoming edge and
                    // copied a variable's name on every walk.
                    let source_roots = phi
                        .sources
                        .iter()
                        .map(|(_, src)| canonical_root_in(&facts.canonical_value_roots, src))
                        .collect::<Vec<_>>();
                    let common = common_root_of(&source_roots).cloned();
                    let stack_root = common_stack_root_of(
                        &phi.sources,
                        &source_roots,
                        &facts.stack_address_roots,
                    );
                    let entry_stack_root = entry_stack_address_size
                        .is_some_and(|size| {
                            phi.dst.size == size
                                && phi.sources.iter().all(|(_, source)| source.size == size)
                        })
                        .then(|| {
                            common_stack_root_of(
                                &phi.sources,
                                &source_roots,
                                &facts.entry_stack_address_roots,
                            )
                        })
                        .flatten();
                    drop(source_roots);
                    if let Some(root) = common {
                        changed |= insert_canonical_root(
                            &mut facts.canonical_value_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                    if let Some(root) = stack_root {
                        changed |= insert_stack_root(
                            &mut facts.stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                    if let Some(root) = entry_stack_root {
                        changed |= insert_stack_root(
                            &mut facts.entry_stack_address_roots,
                            phi.dst.clone(),
                            root,
                        );
                    }
                }
                for op in &block.ops {
                    control.poll()?;
                    // Each operand's root is resolved once for the questions
                    // below. Asking the helpers to resolve it themselves cost a
                    // walk of the root map and a copy of a variable's name per
                    // question, and a sum asks six.
                    match op {
                        SSAOp::Copy { dst, src }
                        | SSAOp::Cast { dst, src }
                        | SSAOp::CallRestore { dst, src } => {
                            let src_root = canonical_root_in(&facts.canonical_value_roots, src);
                            let stack = stack_root_of(src, src_root, &facts.stack_address_roots);
                            let entry_stack = entry_stack_address_size
                                .is_some_and(|size| dst.size == size && src.size == size)
                                .then(|| {
                                    stack_root_of(src, src_root, &facts.entry_stack_address_roots)
                                })
                                .flatten();
                            let src_root = src_root.clone();
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                src_root,
                            );
                            if let Some(stack_root) = stack {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                            if let Some(stack_root) = entry_stack {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    stack_root,
                                );
                            }
                        }
                        SSAOp::Subpiece { dst, src, .. } => {
                            let src_root = canonical_root_in(&facts.canonical_value_roots, src);
                            let adapted = adapt_root_width(src_root, dst.size)
                                .unwrap_or_else(|| src_root.clone());
                            changed |= insert_canonical_root(
                                &mut facts.canonical_value_roots,
                                dst.clone(),
                                adapted,
                            );
                        }
                        SSAOp::IntAdd { dst, a, b } => {
                            let a_root = canonical_root_in(&facts.canonical_value_roots, a);
                            let b_root = canonical_root_in(&facts.canonical_value_roots, b);
                            // An exact root is preferred; this records the
                            // object an address is inside when the offset
                            // within it is computed rather than stated.
                            let indexed = (!facts.stack_address_roots.contains_key(dst))
                                .then(|| {
                                    indexed_stack_address_root_from_add(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.stack_address_roots,
                                        &facts.indexed_stack_address_roots,
                                    )
                                })
                                .flatten();
                            let exact = stack_address_root_from_add(
                                a,
                                a_root,
                                b,
                                b_root,
                                &facts.stack_address_roots,
                            );
                            let entry = entry_stack_address_size
                                .is_some_and(|size| {
                                    dst.size == size && a.size == size && b.size == size
                                })
                                .then(|| {
                                    stack_address_root_from_add(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.entry_stack_address_roots,
                                    )
                                })
                                .flatten();
                            if let Some(root) = indexed {
                                changed |= insert_stack_root(
                                    &mut facts.indexed_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = exact {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = entry {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                        }
                        SSAOp::IntSub { dst, a, b } => {
                            let a_root = canonical_root_in(&facts.canonical_value_roots, a);
                            let b_root = canonical_root_in(&facts.canonical_value_roots, b);
                            let exact = stack_address_root_from_sub(
                                a,
                                a_root,
                                b,
                                b_root,
                                &facts.stack_address_roots,
                            );
                            let indexed = (!facts.stack_address_roots.contains_key(dst)
                                && exact.is_none())
                            .then(|| {
                                indexed_stack_address_root_from_sub(
                                    a,
                                    a_root,
                                    b,
                                    b_root,
                                    &facts.indexed_stack_address_roots,
                                )
                            })
                            .flatten();
                            let entry = entry_stack_address_size
                                .is_some_and(|size| {
                                    dst.size == size && a.size == size && b.size == size
                                })
                                .then(|| {
                                    stack_address_root_from_sub(
                                        a,
                                        a_root,
                                        b,
                                        b_root,
                                        &facts.entry_stack_address_roots,
                                    )
                                })
                                .flatten();
                            if let Some(root) = exact {
                                changed |= insert_stack_root(
                                    &mut facts.stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = indexed {
                                changed |= insert_stack_root(
                                    &mut facts.indexed_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                            if let Some(root) = entry {
                                changed |= insert_stack_root(
                                    &mut facts.entry_stack_address_roots,
                                    dst.clone(),
                                    root,
                                );
                            }
                        }
                        SSAOp::IntZExt { .. } | SSAOp::IntSExt { .. } => {}
                        _ => {}
                    }

                    if let Some(dst) = op.dst() {
                        changed |= ensure_value_root_identity(
                            &mut facts.canonical_value_roots,
                            dst.clone(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
