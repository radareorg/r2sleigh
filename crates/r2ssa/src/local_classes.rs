//! Which values are one location's successive contents: one storage, joined along read merges,
//! live ranges disjoint (ROADMAP D470; doc/adr-one-ir.md "D470 as built").

use crate::graph::{InstPayload, SsaGraph, ValueId};
use crate::liveness::{ComponentLiveness, ValueLiveness};
use crate::var::CanonicalStorageSpace;

/// The class of each value, by dense `ValueId`: a class is named by its smallest member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalClasses {
    class: Vec<u32>,
}

impl LocalClasses {
    /// One union pass over the operands of every read merge, in `InstId` order. `O(V alpha(V))`
    /// finds plus the segment sweeps of `ComponentLiveness`, small absorbed into large.
    pub(crate) fn compute(graph: &SsaGraph, liveness: &ValueLiveness) -> Self {
        let count = graph.values.len();
        let mut parent = (0..count as u32).collect::<Vec<_>>();
        let mut live = vec![None::<ComponentLiveness>; count];
        for inst in &graph.insts {
            let (InstPayload::Phi { .. }, Some(output)) = (&inst.payload, inst.output) else {
                continue;
            };
            if liveness.phi_is_unread(inst.id) || !member(graph, output) {
                continue;
            }
            let storage = graph
                .value(output)
                .and_then(|value| value.canonical_storage);
            for operand in graph.inputs(inst.id) {
                let same = graph
                    .value(*operand)
                    .and_then(|value| value.canonical_storage);
                if same != storage || !member(graph, *operand) {
                    continue;
                }
                let (a, b) = (find(&mut parent, output.0), find(&mut parent, operand.0));
                if a == b {
                    continue;
                }
                let held = |live: &mut Vec<Option<ComponentLiveness>>, root: u32| {
                    live[root as usize]
                        .take()
                        .unwrap_or_else(|| ComponentLiveness::of(liveness, ValueId(root)))
                };
                let (mut left, right) = (held(&mut live, a), held(&mut live, b));
                if left.interferes(&right, liveness) {
                    (live[a as usize], live[b as usize]) = (Some(left), Some(right));
                    continue;
                }
                let (root, child) = match left.members() >= right.members() {
                    true => (a, b),
                    false => (b, a),
                };
                parent[child as usize] = root;
                left.absorb(right);
                live[root as usize] = Some(left);
            }
        }
        // Each class named by its smallest member, so union order never reaches the fact.
        let roots = (0..count as u32)
            .map(|value| find(&mut parent, value))
            .collect::<Vec<_>>();
        let mut smallest = vec![u32::MAX; count];
        for (value, root) in roots.iter().enumerate() {
            smallest[*root as usize] = smallest[*root as usize].min(value as u32);
        }
        let class = roots.iter().map(|root| smallest[*root as usize]).collect();
        Self { class }
    }

    /// The class `value` belongs to, named by its smallest member; itself where none was joined.
    pub fn class_of(&self, value: ValueId) -> ValueId {
        ValueId(self.class.get(value.0 as usize).copied().unwrap_or(value.0))
    }
}

/// A value a class may hold: an instruction's or a merge's output in a register or temporary.
/// Formals and entry values have no definition; constants and memory versions are no location.
fn member(graph: &SsaGraph, value: ValueId) -> bool {
    let storage = graph.value(value).and_then(|value| value.canonical_storage);
    graph.def_inst(value).is_some()
        && storage.is_some_and(|storage| {
            matches!(
                storage.space,
                CanonicalStorageSpace::Register | CanonicalStorageSpace::Unique
            )
        })
}

/// Find with path halving.
fn find(parent: &mut [u32], mut index: u32) -> u32 {
    while parent[index as usize] != index {
        let grandparent = parent[parent[index as usize] as usize];
        parent[index as usize] = grandparent;
        index = grandparent;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::SSAFunction;
    use crate::liveness::ValueContent;
    use crate::liveout::FunctionLiveOut;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn arch() -> crate::Arch {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("RCX", 8, 8));
        arch.add_register(RegisterDef::new("RDX", 16, 8));
        arch.add_register(RegisterDef::new("cond", 32, 1));
        arch.add_register(RegisterDef::new("RIP", 0x288, 8));
        crate::Arch::new(arch)
    }

    fn defined_at(graph: &SsaGraph, addr: u64, op_idx: usize) -> ValueId {
        graph
            .inst_spelled_at(addr, op_idx)
            .and_then(|inst| graph.inst(inst))
            .and_then(|inst| inst.output)
            .unwrap_or_else(|| panic!("no definition at {addr:#x}:{op_idx}"))
    }

    /// The merge of the register at `offset`.
    fn merge_of(graph: &SsaGraph, offset: u64) -> ValueId {
        let at = |out: ValueId| {
            let storage = graph.value(out).and_then(|value| value.canonical_storage);
            storage.is_some_and(|storage| storage.offset == offset)
        };
        let phi = graph.insts.iter().find(|inst| {
            matches!(inst.payload, InstPayload::Phi { .. }) && inst.output.is_some_and(at)
        });
        phi.and_then(|inst| inst.output).expect("a merge")
    }

    fn store(addr: u64, val: u64) -> R2ILOp {
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: reg(addr, 8),
            val: reg(val, 8),
        }
    }

    /// entry: `RAX = RCX`; header: the merges, a test; body: `body`, back to the header; the exit
    /// stores RAX and RCX.
    fn looped(body_ops: &[R2ILOp]) -> SsaGraph {
        looped_forwarded(body_ops, false)
    }

    /// [`looped`], its copies forwarded where `forward`.
    fn looped_forwarded(body_ops: &[R2ILOp], forward: bool) -> SsaGraph {
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: reg(8, 8),
        });
        let mut header = R2ILBlock::new(0x1004, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1010, 8),
            cond: reg(32, 1),
        });
        let mut body = R2ILBlock::new(0x1008, 4);
        body_ops.iter().for_each(|op| body.push(op.clone()));
        body.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });
        let mut exit = R2ILBlock::new(0x1010, 4);
        exit.push(store(8, 0));
        exit.push(store(0, 8));
        exit.push(R2ILOp::Return {
            target: reg(0x288, 8),
        });
        let mut func =
            SSAFunction::from_blocks_with_arch(&[entry, header, body, exit], Some(&arch()))
                .expect("ssa");
        if forward {
            func.forward_copies();
        }
        SsaGraph::from_function(&func)
    }

    fn classes(graph: &SsaGraph) -> LocalClasses {
        let liveness = ValueLiveness::compute(
            graph,
            &FunctionLiveOut::default(),
            ValueContent::unmapped(graph),
        );
        LocalClasses::compute(graph, &liveness)
    }

    fn increment() -> R2ILOp {
        R2ILOp::IntAdd {
            dst: reg(0, 8),
            a: reg(0, 8),
            b: Varnode::constant(1, 8),
        }
    }

    #[test]
    fn a_loop_carrier_and_its_update_are_one_class_named_by_the_smallest_member() {
        let graph = looped(&[increment()]);
        let classes = classes(&graph);
        let (entry, merged, updated) = (
            defined_at(&graph, 0x1000, 0),
            merge_of(&graph, 0),
            defined_at(&graph, 0x1008, 0),
        );
        let named = entry.min(merged).min(updated);
        for value in [entry, merged, updated] {
            assert_eq!(classes.class_of(value), named, "{value:?}");
        }
    }

    #[test]
    fn a_merge_read_after_its_update_stays_out_of_the_update_s_class() {
        // `RDX = RAX` forwarded: `RDX = RDX + RAX` reads the merge after `RAX = RAX + 1`.
        let graph = looped_forwarded(
            &[
                R2ILOp::Copy {
                    dst: reg(16, 8),
                    src: reg(0, 8),
                },
                increment(),
                R2ILOp::IntAdd {
                    dst: reg(16, 8),
                    a: reg(16, 8),
                    b: reg(0, 8),
                },
                store(16, 8),
            ],
            true,
        );
        let classes = classes(&graph);
        let (merged, updated) = (merge_of(&graph, 0), defined_at(&graph, 0x1008, 1));
        assert_ne!(classes.class_of(merged), classes.class_of(updated));
    }

    #[test]
    fn a_swap_keeps_its_two_locations_two_classes() {
        // `RDX = RAX; RAX = RCX; RCX = RDX`: each merge joins its own location's update only.
        let copy = |dst, src| R2ILOp::Copy {
            dst: reg(dst, 8),
            src: reg(src, 8),
        };
        let graph = looped(&[copy(16, 0), copy(0, 8), copy(8, 16)]);
        let classes = classes(&graph);
        let (rax, rcx) = (merge_of(&graph, 0), merge_of(&graph, 8));
        assert_ne!(classes.class_of(rax), classes.class_of(rcx));
        assert_eq!(
            classes.class_of(defined_at(&graph, 0x1008, 1)),
            classes.class_of(rax)
        );
        assert_eq!(
            classes.class_of(defined_at(&graph, 0x1008, 2)),
            classes.class_of(rcx)
        );
    }

    #[test]
    fn an_operand_of_another_location_or_width_never_joins() {
        for (offset, size) in [(8, 8), (0, 4)] {
            let mut graph = looped(&[increment()]);
            let updated = defined_at(&graph, 0x1008, 0);
            let storage =
                (graph.values[updated.0 as usize].canonical_storage.as_mut()).expect("a register");
            (storage.offset, storage.size) = (offset, size);
            let classes = classes(&graph);
            let merged = merge_of(&graph, 0);
            assert_ne!(classes.class_of(merged), classes.class_of(updated));
            assert_eq!(classes.class_of(updated), updated);
        }
    }
}
