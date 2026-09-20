//! Which entries of a pointer table a call can actually reach.
//!
//! A call through `table[index]` reaches exactly the entries `index` can select,
//! and nothing else. The table's contents are a fact the source carries; the
//! range of the index is not, because it follows from the branches that had to
//! be taken to arrive at the call. Proving that range is what turns an opaque
//! dispatch into a set of real edges.
//!
//! The proof is deliberately narrow. A block that strictly dominates the call
//! and ends in a conditional branch tells us which way that branch went, but
//! only when exactly one of its successors dominates the call: if both do, the
//! condition says nothing about how we got here. Every such branch contributes
//! one bound on one value, the bounds are intersected, and a range that is not
//! fully pinned inside the table yields nothing at all.
//!
//! Failing closed is the point. An unproven target set would be a guess about
//! control flow, and a wrong edge is worse than a missing one.

use crate::SSAOp;
use crate::function::{SSAFunction, SsaArtifact};
use crate::graph::{GraphInst, InstPayload, SsaGraph, UseSite, ValueId};

/// A call site and the table entries it can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIndirectCall {
    pub block_addr: u64,
    pub op_index: usize,
    pub table_address: u64,
    pub targets: Vec<u64>,
}

/// One table of function pointers as the caller sees it.
pub trait PointerTable {
    fn address(&self) -> u64;
    /// Bytes between consecutive entries, as the table was read.
    fn entry_size(&self) -> u32;
    fn targets(&self) -> &[u64];
}

impl PointerTable for r2source::SourceCodePointerTable {
    fn address(&self) -> u64 {
        Self::address(self)
    }

    fn entry_size(&self) -> u32 {
        Self::entry_size(self)
    }

    fn targets(&self) -> &[u64] {
        Self::targets(self)
    }
}

pub(crate) fn exact_input(graph: &SsaGraph, inst: &GraphInst, input_idx: usize) -> Option<ValueId> {
    let value = *inst.inputs.get(input_idx)?;
    graph
        .use_sites(value)
        .binary_search(&UseSite {
            inst: inst.id,
            input_idx,
        })
        .is_ok()
        .then_some(value)
}

/// Resolve every indirect transfer whose reachable target set can be proven.
fn resolve_indirect_calls_in_graph<T: PointerTable>(
    function: &SSAFunction,
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    tables: &[T],
) -> Vec<ResolvedIndirectCall> {
    let mut resolved = Vec::new();
    for block in function.blocks() {
        for (op_index, op) in block.ops.iter().enumerate() {
            // A tail call through a table is a branch, not a call, and it
            // reaches the same set of functions either way.
            let (SSAOp::CallInd { target, .. } | SSAOp::BranchInd { target, .. }) = op else {
                continue;
            };
            let Some(call_inst) = graph
                .inst_id_for_op_site(block.addr, op_index)
                .and_then(|inst| graph.inst(inst))
            else {
                continue;
            };
            let Some(target_value) = exact_input(graph, call_inst, 0) else {
                continue;
            };
            if graph.value_id_for_var(target) != Some(target_value) {
                continue;
            }
            // The callee is whatever the table held, so the target has to be a
            // load rather than a computed address.
            let target_value = crate::constant::root_of(graph, target_value);
            let Some(load_inst) = graph
                .def_inst(target_value)
                .and_then(|inst| graph.inst(inst))
            else {
                continue;
            };
            let InstPayload::Op(SSAOp::Load { .. }) = &load_inst.payload else {
                continue;
            };
            let Some(address) = exact_input(graph, load_inst, 0) else {
                continue;
            };
            // What the address can be is what the table read selects: the
            // low bound is the first entry, the stride is how far apart the
            // entries it steps through are, and the high bound is the last.
            // Decomposing the address syntactically and then proving a bound
            // on the index separately is what this replaces.
            let Some(reach) = values
                .get(address)
                .filter(|reach| !reach.is_top() && !reach.is_bottom())
            else {
                continue;
            };
            let (Some((base, last)), Some(stride)) = (reach.bounds(), reach.stride()) else {
                continue;
            };
            // The base need not be the address the table was read from: a table
            // read as one run may be indexed from an entry inside it. What it
            // must be is an entry boundary, or the index steps between entries.
            let Some(table) = tables.iter().find(|table| {
                let entry = u64::from(table.entry_size());
                entry != 0
                    && base >= table.address()
                    && (base - table.address()).is_multiple_of(entry)
                    && (base - table.address()) / entry < table.targets().len() as u64
            }) else {
                continue;
            };
            // Stepping by anything but one entry selects something the read
            // never described, so where it lands is not a fact about this
            // table.
            if stride != u64::from(table.entry_size()) {
                continue;
            }
            let entry_size = u64::from(table.entry_size());
            let first = (base - table.address()) / entry_size;
            let last = (last - table.address()) / entry_size;
            // A range reaching past the last entry read is not proven: the
            // table may continue where the read stopped.
            if last as usize >= table.targets().len() {
                continue;
            }
            let Some(selected) = table.targets().get(first as usize..=last as usize) else {
                continue;
            };
            if selected.is_empty() {
                continue;
            }
            resolved.push(ResolvedIndirectCall {
                block_addr: block.addr,
                op_index,
                table_address: base,
                targets: selected.to_vec(),
            });
        }
    }
    resolved
}

/// Resolve every indirect transfer against the graph retained by the artifact.
/// The function and graph therefore share one `ValueId`/`InstId` universe.
pub fn resolve_indirect_calls<T: PointerTable>(
    artifact: &SsaArtifact,
    tables: &[T],
) -> Vec<ResolvedIndirectCall> {
    resolve_indirect_calls_in_graph(
        artifact.function(),
        artifact.graph(),
        &artifact.facts().values,
        tables,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SSAVar;
    use crate::cfg::CFG;
    use crate::domtree::DomTree;
    use crate::function::SSABlock;

    struct Table {
        address: u64,
        entry_size: u32,
        targets: Vec<u64>,
    }

    impl PointerTable for Table {
        fn address(&self) -> u64 {
            self.address
        }
        fn entry_size(&self) -> u32 {
            self.entry_size
        }
        fn targets(&self) -> &[u64] {
            &self.targets
        }
    }

    fn resolve_test_indirect_calls<T: PointerTable>(
        blocks: &[SSABlock],
        cfg: &CFG,
        _domtree: &DomTree,
        tables: &[T],
    ) -> Vec<ResolvedIndirectCall> {
        let function = SSAFunction::from_exact_test_blocks(blocks, cfg.clone());
        let graph = SsaGraph::from_function(&function);
        // The dispatch is resolved from what the address can be, so the test
        // solves for that exactly as the analysis phase does.
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let values =
            crate::values::solve_value_ranges(&graph, &function, &predicates, &Default::default());
        resolve_indirect_calls_in_graph(&function, &graph, &values, tables)
    }

    /// The graph for a straight guard: entry dominates both arms.
    fn graph_for(blocks: &[SSABlock], taken: u64, fallthrough: Option<u64>) -> (CFG, DomTree) {
        let entry = blocks[0].addr;
        let mut cfg = crate::cfg::CFG::new(entry);
        for block in blocks {
            let mut basic = crate::cfg::BasicBlock::new(block.addr);
            basic.size = block.size;
            basic.terminator = if block.addr != entry {
                crate::cfg::BlockTerminator::Return
            } else if let Some(next) = fallthrough {
                crate::cfg::BlockTerminator::ConditionalBranch {
                    true_target: taken,
                    false_target: next,
                }
            } else {
                crate::cfg::BlockTerminator::Return
            };
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();
        let domtree = DomTree::compute(&cfg);
        (cfg, domtree)
    }

    fn input(name: &str, size: u32) -> SSAVar {
        SSAVar::new(name, 0, size)
    }

    fn temp(name: &str, size: u32) -> SSAVar {
        SSAVar::new(name, 1, size)
    }

    /// A guarded dispatch: `if (i >= 5) return; call table[i]`.
    ///
    /// Block 0 tests the bound and branches away on failure, so arriving at
    /// block 0x20 proves `i < 5`; the unsigned test proves `i >= 0`.
    fn guarded_dispatch(bound: u64, entries: usize) -> (Vec<SSABlock>, Vec<Table>) {
        let index = input("index", 8);
        let cond = temp("cond", 1);
        let scaled = temp("scaled", 8);
        let addr = temp("addr", 8);
        let callee = temp("callee", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntLess {
                        dst: cond.clone(),
                        a: index.clone(),
                        b: SSAVar::constant(bound, 8),
                    },
                    SSAOp::CBranch {
                        target: SSAVar::constant(0x20, 8),
                        cond,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntMult {
                        dst: scaled.clone(),
                        a: index,
                        b: SSAVar::constant(8, 8),
                    },
                    SSAOp::IntAdd {
                        dst: addr.clone(),
                        a: SSAVar::constant(0xc000, 8),
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr,
                    },
                    SSAOp::CallInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        let targets = (0..entries).map(|i| 0x1000 + i as u64 * 0x20).collect();
        (
            blocks,
            vec![Table {
                address: 0xc000,
                entry_size: 8,
                targets,
            }],
        )
    }

    #[test]
    fn a_guarded_index_resolves_to_exactly_the_entries_it_can_select() {
        let (blocks, tables) = guarded_dispatch(5, 5);
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        let resolved = resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].table_address, 0xc000);
        assert_eq!(resolved[0].targets, tables[0].targets);
    }

    #[test]
    fn a_guard_wider_than_the_table_proves_nothing() {
        // The index may reach past the entries that were read, so the target
        // set is unknown and must stay unknown rather than be truncated.
        let (blocks, tables) = guarded_dispatch(9, 5);
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        assert!(resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables).is_empty());
    }

    #[test]
    fn a_stride_the_table_was_not_read_at_proves_nothing() {
        // Reading 8-byte entries and stepping by 4 lands halfway into each one,
        // so the target set the read describes is not the set the call reaches.
        let (blocks, mut tables) = guarded_dispatch(5, 5);
        tables[0].entry_size = 4;
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        assert!(resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables).is_empty());
    }

    /// The shape hardware actually emits, taken from an arm64 -O1 dispatch.
    ///
    /// `cmp w0, 3` lands in a flag, `b.ls` tests its negation, the table base
    /// is built by `adrp`+`add`, and the transfer is a tail-call branch. None
    /// of it is a literal operand, and all of it is exact.
    fn hardware_dispatch(entries: usize) -> (Vec<SSABlock>, Vec<Table>) {
        let index = input("w0", 4);
        let flag = temp("cy", 1);
        let zero = temp("zr", 1);
        let negated = temp("tmp:b00", 1);
        let lower_or_same = temp("tmp:1000", 1);
        let page = temp("x8_page", 8);
        let base = temp("x8", 8);
        let widened = temp("x9", 8);
        let scaled = temp("tmp:7100", 8);
        let addr = temp("tmp:7580", 8);
        let callee = temp("x3", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    // arm64 `cmp w0, 3` then `b.ls`: the branch tests
                    // `!cy || zr`, where cy is `3 <= w0` and zr is `w0 == 3`.
                    // Together they prove `w0 <= 3` and nothing narrower.
                    SSAOp::IntLessEqual {
                        dst: flag.clone(),
                        a: SSAVar::constant(3, 4),
                        b: index.clone(),
                    },
                    SSAOp::IntEqual {
                        dst: zero.clone(),
                        a: index.clone(),
                        b: SSAVar::constant(3, 4),
                    },
                    SSAOp::BoolNot {
                        dst: negated.clone(),
                        src: flag,
                    },
                    SSAOp::BoolOr {
                        dst: lower_or_same.clone(),
                        a: negated,
                        b: zero,
                    },
                    SSAOp::CBranch {
                        target: SSAVar::new("ram:20", 0, 8),
                        cond: lower_or_same,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    // adrp x8, 0xc000 ; add x8, x8, 0x10
                    SSAOp::Copy {
                        dst: page.clone(),
                        src: SSAVar::constant(0xc000, 8),
                    },
                    SSAOp::IntAdd {
                        dst: base.clone(),
                        a: page,
                        b: SSAVar::constant(0x10, 8),
                    },
                    SSAOp::IntZExt {
                        dst: widened.clone(),
                        src: index,
                    },
                    SSAOp::IntLeft {
                        dst: scaled.clone(),
                        a: widened,
                        b: SSAVar::constant(3, 8),
                    },
                    SSAOp::IntAdd {
                        dst: addr.clone(),
                        a: base,
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr,
                    },
                    SSAOp::BranchInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        // The table was read from 0xc000, but the code indexes from 0xc010.
        let targets = (0..entries).map(|i| 0x1000 + i as u64 * 0x20).collect();
        (
            blocks,
            vec![Table {
                address: 0xc000,
                entry_size: 8,
                targets,
            }],
        )
    }

    #[test]
    fn a_flag_tested_by_its_negation_still_bounds_the_index() {
        // Two entries precede the base the code indexes from, and four follow.
        let (blocks, tables) = hardware_dispatch(6);
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        let resolved = resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].table_address, 0xc010);
        assert_eq!(resolved[0].targets, tables[0].targets[2..6]);
    }

    #[test]
    fn a_base_inside_a_table_still_has_to_fit_the_entries_that_were_read() {
        // Indexing from entry two of a five-entry table can select four, and
        // the read only describes three of them.
        let (blocks, tables) = hardware_dispatch(5);
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        assert!(resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables).is_empty());
    }

    #[test]
    fn an_unguarded_index_resolves_to_nothing() {
        let index = input("index", 8);
        let scaled = temp("scaled", 8);
        let addr = temp("addr", 8);
        let callee = temp("callee", 8);
        let blocks = vec![SSABlock {
            addr: 0,
            phis: Vec::new(),
            size: 0x10,
            ops: vec![
                SSAOp::IntMult {
                    dst: scaled.clone(),
                    a: index,
                    b: SSAVar::constant(8, 8),
                },
                SSAOp::IntAdd {
                    dst: addr.clone(),
                    a: SSAVar::constant(0xc000, 8),
                    b: scaled,
                },
                SSAOp::Load {
                    dst: callee.clone(),
                    space: r2il::SpaceId::Ram,
                    addr,
                },
                SSAOp::CallInd {
                    target: callee,
                    instruction: None,
                },
            ],
        }];
        let (cfg, domtree) = graph_for(&blocks, 0, None);
        let tables = vec![Table {
            address: 0xc000,
            entry_size: 8,
            targets: vec![0x1000, 0x1020],
        }];
        assert!(resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables).is_empty());
    }

    #[test]
    fn colliding_display_spelling_cannot_transfer_a_bound_between_values() {
        let narrow_index = input("index", 4);
        let wide_index = input("index", 8);
        assert_eq!(narrow_index.display_name(), wide_index.display_name());
        let condition = temp("condition", 1);
        let scaled = temp("scaled", 8);
        let address = temp("address", 8);
        let callee = temp("callee", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntLess {
                        dst: condition.clone(),
                        a: narrow_index,
                        b: SSAVar::constant(2, 4),
                    },
                    SSAOp::CBranch {
                        target: SSAVar::constant(0x20, 8),
                        cond: condition,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntMult {
                        dst: scaled.clone(),
                        a: wide_index,
                        b: SSAVar::constant(8, 8),
                    },
                    SSAOp::IntAdd {
                        dst: address.clone(),
                        a: SSAVar::constant(0xc000, 8),
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr: address,
                    },
                    SSAOp::CallInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        let (cfg, domtree) = graph_for(&blocks, 0x20, Some(0x10));
        let tables = [Table {
            address: 0xc000,
            entry_size: 8,
            targets: vec![0x1000, 0x1020],
        }];

        assert!(resolve_test_indirect_calls(&blocks, &cfg, &domtree, &tables).is_empty());
    }
}
