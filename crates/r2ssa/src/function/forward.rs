//! A copy is a value fact: what reads the copy reads its source.
//!
//! The machine moves values between registers and slots constantly, and every
//! move is an SSA `Copy` whose result is the same content under a new name. A
//! reader of the copy is a reader of the source, and saying so in the graph --
//! before spans, certificates or obligations are built from it -- is what lets
//! every later count of readers be exact instead of estimated. The copy itself
//! stays where it was, read by nothing: block positions do not move, so every
//! identity keyed by position is unchanged, and a definition nothing reads is
//! accounted as dead by the layers that already know how.

use super::SSAFunction;
use crate::dense::{IdMap, IdSet};
use crate::op::SSAOp;
use crate::value_table::VarId;

/// What one forwarding pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Forwarding {
    /// Reads moved from a copy to the value it copied.
    pub reads_forwarded: usize,
}

impl SSAFunction {
    /// Forward every copy that is a value fact to the readers of the copy.
    ///
    /// One principle decides which: a copy the program means keeps its
    /// statement, and every other copy is the value it copied. See
    /// [`Self::copy_is_a_program_write`].
    pub(crate) fn forward_copies(&mut self) -> Forwarding {
        let mut merge_sources = IdSet::<VarId>::new(self.values.len());
        for block in &self.blocks {
            for phi in block.phis() {
                for (_, source) in &phi.sources {
                    merge_sources.insert(*source);
                }
            }
        }
        let mut forwarded = Forwarded::new(self.values.len());
        for block in &self.blocks {
            for op in block.ops() {
                if let SSAOp::Copy { dst, src } = op
                    && self.var(*dst).size == self.var(*src).size
                    && dst != src
                    && !self.copy_is_a_program_write(*dst, *src, &merge_sources)
                {
                    forwarded.insert(*dst, *src);
                }
            }
        }
        self.apply_forwarding(forwarded)
    }

    /// Rewrite every read of a forwarded variable to the value it names.
    fn apply_forwarding(&mut self, forwarded: Forwarded) -> Forwarding {
        let mut stats = Forwarding::default();
        if forwarded.is_empty() {
            return stats;
        }
        let resolved = resolve_chains(forwarded);
        let map = |var: &VarId| resolved.get(*var).copied().unwrap_or(*var);
        for block in self.blocks.edit().iter_mut() {
            // A merge reads each source on its edge; the read moves the same
            // way, and the merge's own definition stays its own.
            for phi in block.phis_mut() {
                for (_, source) in &mut phi.sources {
                    let mapped = map(source);
                    if mapped != *source {
                        *source = mapped;
                        stats.reads_forwarded += 1;
                    }
                }
            }
            for op in block.ops_mut() {
                let mapped = op.map_sources(map);
                if mapped != *op {
                    stats.reads_forwarded += moved_reads(op, &mapped);
                    *op = mapped;
                }
            }
        }
        if stats.reads_forwarded > 0 {
            r2il::refusal_evidence!(
                "copies-forwarded",
                "{:#x}: {} reads now name the value a copy carried",
                self.entry,
                stats.reads_forwarded
            );
        }
        stats
    }
}

impl SSAFunction {
    /// A call's result is the address the call pushed, where its callee's body
    /// proves that is what it returns.
    ///
    /// A position-independent thunk hands back the return address, which this
    /// caller wrote as a literal one operation before the transfer. They are
    /// one value, so a reader of the carrier reads the literal -- and the
    /// address arithmetic above it then folds into the address it names
    /// instead of standing as `ESI + 0xe0d`. The `CallDefine` stays where it
    /// was, read by nothing, exactly as a forwarded copy does.
    pub(crate) fn forward_proven_call_return_addresses(
        &mut self,
        callees: &super::CalleeBoundaries,
    ) -> Forwarding {
        if callees.return_addresses().is_empty() {
            return Forwarding::default();
        }
        let storage = |id: VarId| self.canonical_storage_by_var.get(self.var(id)).copied();
        let mut forwarded = Forwarded::new(self.values.len());
        for block in &self.blocks {
            let mut pushed: Option<VarId> = None;
            let mut carrier = None;
            for op in block.ops() {
                match op {
                    SSAOp::Store { addr, val, .. } if self.var(*val).is_const() => {
                        pushed = storage(*addr)
                            .filter(|storage| Some(*storage) == self.stack_pointer_carrier)
                            .map(|_| *val);
                    }
                    SSAOp::Call { target, .. } => {
                        carrier = storage(*target)
                            .filter(|storage| storage.space == crate::CanonicalStorageSpace::Ram)
                            .and_then(|storage| callees.return_addresses().get(&storage.offset))
                            .copied();
                    }
                    SSAOp::CallDefine { dst } if carrier.is_some() => {
                        r2il::refusal_evidence!(
                            "call-return-address",
                            "{:#x}: {} defines {:?} against the proven carrier {carrier:?}, \
                             pushed {:?}",
                            block.addr,
                            self.var(*dst).display_name(),
                            storage(*dst),
                            pushed.map(|pushed| self.var(pushed).display_name())
                        );
                        if storage(*dst) == carrier
                            && let Some(pushed) = pushed
                                .filter(|pushed| self.var(*pushed).size == self.var(*dst).size)
                        {
                            forwarded.insert(*dst, pushed);
                        }
                    }
                    // The boundary's own reads and defines are inside the run.
                    SSAOp::CallDefine { .. }
                    | SSAOp::CallRestore { .. }
                    | SSAOp::CallUse { .. } => {}
                    // Anything else ends it; one call's address is not the next's.
                    _ => {
                        pushed = None;
                        carrier = None;
                    }
                }
            }
        }
        self.apply_forwarding(forwarded)
    }

    /// Whether a copy is one the program means, so its statement stays.
    ///
    /// Three copies mean something: a write of a named object, which is the
    /// source's assignment to a private slot; a merge's edge write, which the
    /// block makes before it branches and which forwarded would land on every
    /// edge the block leaves by; and a literal's spelling, which is the plan's
    /// decision with the partition in hand. Every other copy is a value fact.
    fn copy_is_a_program_write(
        &self,
        dst: VarId,
        src: VarId,
        merge_sources: &IdSet<VarId>,
    ) -> bool {
        self.var(src).is_const() || merge_sources.contains(dst) || self.is_memory_variable(dst)
    }

    /// Whether this variable is a stack slot the function proved private and
    /// treats as a variable.
    fn is_memory_variable(&self, var: VarId) -> bool {
        self.canonical_storage_by_var
            .get(self.var(var))
            .is_some_and(|storage| storage.space == crate::CanonicalStorageSpace::Ram)
    }
}

/// Which copy each variable is forwarded to, by variable.
type Forwarded = IdMap<VarId, VarId>;

/// Follow each copy to the end of its chain, so a copy of a copy names the
/// original. A chain that meets itself is left pointing at its immediate
/// source, which is still correct and cannot happen in valid SSA. Each step
/// is one index, and a chain is walked once per variable that starts it.
fn resolve_chains(forwarded: Forwarded) -> Forwarded {
    let mut resolved = forwarded.clone();
    for key in forwarded.keys() {
        let mut seen = vec![key];
        let mut current = forwarded[key];
        while let Some(next) = forwarded.get(current).copied() {
            if seen.contains(&next) {
                break;
            }
            seen.push(current);
            current = next;
        }
        resolved.insert(key, current);
    }
    resolved
}

/// How many operands changed between an operation and its rewritten form.
fn moved_reads(before: &SSAOp<VarId>, after: &SSAOp<VarId>) -> usize {
    before
        .sources()
        .into_iter()
        .zip(after.sources())
        .filter(|(old, new)| old != new)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SsaGraph;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("EAX", 0, 4));
        arch.add_register(RegisterDef::new("RCX", 8, 8));
        arch.add_register(RegisterDef::new("RDX", 16, 8));
        arch.add_register(RegisterDef::new("RDI", 24, 8));
        arch.add_register(RegisterDef::new("cond", 32, 1));
        arch.add_register(RegisterDef::new("RIP", 0x288, 8));
        arch
    }

    fn straight_line(ops: Vec<R2ILOp>) -> SSAFunction {
        let mut block = R2ILBlock::new(0x1000, 4);
        for op in ops {
            block.push(op);
        }
        SSAFunction::from_blocks_with_arch(&[block], Some(&arch())).expect("ssa")
    }

    fn op_at(func: &SSAFunction, addr: u64, index: usize) -> SSAOp {
        func.named_block(addr).expect("block").ops()[index].clone()
    }

    #[test]
    fn a_chain_of_copies_reads_the_original_at_every_link() {
        // RCX = RDX; RAX = RCX; RDI = RAX; RDX = RDI + 1
        let mut func = straight_line(vec![
            R2ILOp::Copy {
                dst: reg(8, 8),
                src: reg(16, 8),
            },
            R2ILOp::Copy {
                dst: reg(0, 8),
                src: reg(8, 8),
            },
            R2ILOp::Copy {
                dst: reg(24, 8),
                src: reg(0, 8),
            },
            R2ILOp::IntAdd {
                dst: reg(16, 8),
                a: reg(24, 8),
                b: Varnode::constant(1, 8),
            },
            R2ILOp::Return {
                target: reg(0x288, 8),
            },
        ]);
        let original = match op_at(&func, 0x1000, 0) {
            SSAOp::Copy { src, .. } => src,
            other => panic!("{other:?}"),
        };
        let stats = func.forward_copies();
        assert_eq!(stats.reads_forwarded, 3);
        for index in 1..=2 {
            let SSAOp::Copy { src, .. } = op_at(&func, 0x1000, index) else {
                panic!("copy kept in place");
            };
            assert_eq!(src, original, "each copy now copies the original");
        }
        let SSAOp::IntAdd { a, .. } = op_at(&func, 0x1000, 3) else {
            panic!("add kept in place");
        };
        assert_eq!(a, original);
        let graph = SsaGraph::from_function(&func);
        for index in 0..=2 {
            let copy = graph
                .inst_spelled_at(0x1000, index)
                .and_then(|inst| graph.inst(inst))
                .and_then(|inst| inst.output)
                .expect("copy output");
            assert!(
                graph.use_sites(copy).is_empty(),
                "a forwarded copy is read by nothing"
            );
        }
    }

    #[test]
    fn a_copy_a_merge_reads_is_the_edge_write_and_stays() {
        // entry: RAX = RCX; header: RAX = phi(entry RAX, latch RAX); latch: RAX = RDX
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(8, 8),
        });
        let mut header = R2ILBlock::new(0x1004, 4);
        header.push(R2ILOp::IntAdd {
            dst: reg(24, 8),
            a: reg(0, 8),
            b: Varnode::constant(1, 8),
        });
        header.push(R2ILOp::CBranch {
            target: Varnode::constant(0x100c, 8),
            cond: reg(32, 1),
        });
        let mut latch = R2ILBlock::new(0x1008, 4);
        latch.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(16, 8),
        });
        latch.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });
        let mut exit = R2ILBlock::new(0x100c, 4);
        exit.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let mut func =
            SSAFunction::from_blocks_with_arch(&[entry, header, latch, exit], Some(&arch()))
                .expect("ssa");
        let before = func
            .named_block(0x1004)
            .expect("header")
            .phis()
            .iter()
            .find(|phi| phi.dst.name() == "RAX")
            .expect("merge of RAX")
            .clone();
        let stats = func.forward_copies();
        assert_eq!(
            stats.reads_forwarded, 0,
            "both copies are the merge's edge writes"
        );
        let after = func
            .named_block(0x1004)
            .expect("header")
            .phis()
            .iter()
            .find(|phi| phi.dst.name() == "RAX")
            .expect("merge of RAX")
            .clone();
        assert_eq!(before.sources, after.sources);
    }

    #[test]
    fn a_copy_of_a_constant_is_left_to_its_readers() {
        // RAX = 5; RDX = RAX + 1
        let mut func = straight_line(vec![
            R2ILOp::Copy {
                dst: reg(0, 8),
                src: Varnode::constant(5, 8),
            },
            R2ILOp::IntAdd {
                dst: reg(16, 8),
                a: reg(0, 8),
                b: Varnode::constant(1, 8),
            },
            R2ILOp::Return {
                target: reg(0x288, 8),
            },
        ]);
        let before = func.named_block(0x1000).expect("block").ops().to_vec();
        let stats = func.forward_copies();
        assert_eq!(stats.reads_forwarded, 0);
        assert_eq!(func.named_block(0x1000).expect("block").ops(), before);
    }

    #[test]
    fn a_call_argument_reads_the_value_the_argument_register_was_loaded_from() {
        let mut arch = arch();
        arch.add_register(RegisterDef::new("RSP", 0x20, 8));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: reg(24, 8),
            src: reg(8, 8),
        });
        block.push(R2ILOp::Call {
            target: Varnode::constant(0x2000, 8),
        });
        block.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let mut func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        let source = match op_at(&func, 0x1000, 0) {
            SSAOp::Copy { src, .. } => src,
            other => panic!("{other:?}"),
        };
        func.forward_copies();
        let reads_source = func
            .named_block(0x1000)
            .expect("block")
            .ops()
            .iter()
            .any(|op| matches!(op, SSAOp::CallUse { src } if *src == source));
        let reads_copy = func.named_block(0x1000).expect("block").ops().iter().any(
            |op| matches!(op, SSAOp::CallUse { src } if src.name() == "RDI" && src.version > 0),
        );
        assert!(
            reads_source || !reads_copy,
            "a call's use of its argument register names the forwarded value"
        );
    }
}
