use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::arena::OpId;
use crate::function::SSAFunction;
use crate::op::SSAOp;
use crate::value_table::VarId;
use crate::var::SSAVar;
use crate::{CanonicalStorageId, CanonicalStorageSpace};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InstId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ValueId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UseSite {
    pub inst: InstId,
    pub input_idx: usize,
}

#[cfg(test)]
mod tests {
    use super::{InstId, InstPayload, SsaGraph, UseSite};
    use crate::function::SSAFunction;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    /// Two registers written on both arms of a branch, merged.
    fn two_phi_merge() -> SSAFunction {
        let mut arch = ArchSpec::new("two-phi-merge");
        arch.add_register(RegisterDef::new("first", 0, 8));
        arch.add_register(RegisterDef::new("second", 8, 8));
        arch.add_register(RegisterDef::new("cond", 32, 1));
        arch.add_register(RegisterDef::new("pc", 0x80, 8));
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1008, 8),
            cond: reg(32, 1),
        });
        let arm = |addr: u64, first: u64, second: u64| {
            let mut block = R2ILBlock::new(addr, 4);
            block.push(R2ILOp::Copy {
                dst: reg(0, 8),
                src: Varnode::constant(first, 8),
            });
            block.push(R2ILOp::Copy {
                dst: reg(8, 8),
                src: Varnode::constant(second, 8),
            });
            block.push(R2ILOp::Branch {
                target: Varnode::constant(0x100c, 8),
            });
            block
        };
        let left = arm(0x1004, 0, 1);
        let right = arm(0x1008, 2, 3);
        let mut merge = R2ILBlock::new(0x100c, 4);
        merge.push(R2ILOp::Return {
            target: reg(0x80, 8),
        });
        SSAFunction::from_blocks_raw(
            &[entry, left, right, merge],
            Some(&crate::Arch::from(arch.clone())),
        )
        .expect("two phi merge SSA")
    }

    /// A phi that states no storage writes none, whatever its variable's table says.
    #[test]
    fn a_phi_without_storage_writes_none() {
        let mut func = two_phi_merge();
        let cleared = func.named_block(0x100c).expect("merge").phis()[0]
            .dst
            .clone();
        let mut merge = func.edit_block(0x100c).expect("merge block");
        merge.edit_phi(0, |phi| phi.canonical_storage = None);
        let graph = SsaGraph::from_function(&func);
        for inst in &graph.insts {
            let Some(output) = inst
                .output
                .filter(|_| matches!(inst.payload, InstPayload::Phi { .. }))
            else {
                continue;
            };
            let is_cleared = graph
                .value(output)
                .is_some_and(|value| value.var == cleared);
            assert_eq!(graph.written_storage(inst).is_none(), is_cleared);
        }
    }

    /// The arena's live count is every phi and operation the blocks hold, a removed phi gone.
    #[test]
    fn the_arena_counts_what_the_blocks_hold() {
        let held = |func: &SSAFunction| {
            func.blocks()
                .iter()
                .map(|block| block.phis().len() + block.ops().len())
                .sum::<usize>()
        };
        let mut func = two_phi_merge();
        assert_eq!(func.arena().live(), held(&func));
        let removed = func.named_block(0x100c).expect("merge").phis()[0]
            .dst
            .clone();
        let mut merge = func.edit_block(0x100c).expect("merge block");
        merge.retain_phis(crate::Pass::Fixture, |phi| phi.dst != removed);
        assert_eq!(func.arena().live(), held(&func));
        assert_eq!(SsaGraph::from_function(&func).insts.len(), held(&func));
    }

    /// A merge's storage belongs to the merge, not to its position in the block.
    ///
    /// This arrived with copy propagation, which asserted it by collapsing one
    /// of two phis and checking the survivor. Removing a phi is what exercises
    /// the property and the pass was only one way to do it, so the removal is
    /// done directly here and the pass is gone.
    #[test]
    fn phi_storage_identity_survives_removing_preceding_phi() {
        let mut func = two_phi_merge();
        let merge = func.named_block(0x100c).expect("merge block");
        assert_eq!(
            merge.phis().len(),
            2,
            "the fixture must merge two registers"
        );
        let retained_storage = merge.phis()[1]
            .canonical_storage
            .expect("second merge storage");
        let retained_dst = merge.phis()[1].dst.clone();
        let removed_dst = merge.phis()[0].dst.clone();
        assert_ne!(retained_storage, merge.phis()[0].canonical_storage.unwrap());

        let mut merge = func.edit_block(0x100c).expect("merge block");
        merge.retain_phis(crate::Pass::Fixture, |phi| phi.dst != removed_dst);

        let merge = func.named_block(0x100c).expect("merge block");
        assert_eq!(merge.phis().len(), 1);
        assert_eq!(merge.phis()[0].dst, retained_dst);
        assert_eq!(merge.phis()[0].canonical_storage, Some(retained_storage));

        let graph = SsaGraph::from_function(&func);
        let graph_phi = graph
            .insts
            .iter()
            .find(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
            .expect("retained graph phi");
        assert_eq!(
            graph.written_storage(graph_phi),
            Some(retained_storage),
            "the graph must carry the surviving merge's own storage"
        );
    }

    /// `use_sites` is the inverse of `inputs`, phis and copies included: every input is a use site of
    /// its value, and every use site names an input (D411 rescans R5 reads it as the def-use).
    #[test]
    fn use_sites_invert_inputs() {
        let graph = SsaGraph::from_function(&two_phi_merge());
        assert!(
            (graph.insts.iter()).any(|inst| matches!(inst.payload, InstPayload::Phi { .. })),
            "the fixture merges"
        );
        let mut inputs = 0;
        for inst in graph.insts.iter() {
            for (input_idx, value) in graph.inputs(inst.id).iter().enumerate() {
                inputs += 1;
                let site = UseSite {
                    inst: inst.id,
                    input_idx,
                };
                assert!(
                    graph.use_sites(*value).contains(&site),
                    "{site:?} of {value:?}"
                );
            }
        }
        let sites = (graph.values.iter()).flat_map(|value| {
            (graph.use_sites(value.id).iter()).map(move |site| (value.id, *site))
        });
        let mut counted = 0;
        for (value, site) in sites {
            counted += 1;
            assert_eq!(graph.inputs(site.inst).get(site.input_idx), Some(&value));
        }
        assert_eq!(counted, inputs);
    }

    #[test]
    fn use_sites_have_stable_instruction_then_input_order() {
        let mut sites = [
            UseSite {
                inst: InstId(3),
                input_idx: 1,
            },
            UseSite {
                inst: InstId(2),
                input_idx: 4,
            },
            UseSite {
                inst: InstId(3),
                input_idx: 0,
            },
        ];

        sites.sort();

        assert_eq!(
            sites,
            [
                UseSite {
                    inst: InstId(2),
                    input_idx: 4,
                },
                UseSite {
                    inst: InstId(3),
                    input_idx: 0,
                },
                UseSite {
                    inst: InstId(3),
                    input_idx: 1,
                },
            ]
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphValue {
    pub id: ValueId,
    pub var: SSAVar,
    /// Name-independent storage retained from the lifted varnode.
    #[serde(default)]
    pub canonical_storage: Option<CanonicalStorageId>,
}

/// Graph instructions keep the canonical operation inline, so reading one is
/// not a pointer chase and building one is not an allocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InstPayload {
    Phi {
        predecessors: Vec<BlockId>,
    },
    /// The operation over value ids: an operand is the value it reads or
    /// defines, and its name is `SsaGraph::value(id).var`, kept once.
    Op(SSAOp<ValueId>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphInst {
    pub id: InstId,
    pub block: BlockId,
    pub ordinal: usize,
    pub output: Option<ValueId>,
    pub payload: InstPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphBlock {
    pub id: BlockId,
    pub addr: u64,
    pub size: u32,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
    pub insts: crate::dense::Metered<Vec<InstId>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsaGraph {
    pub entry: BlockId,
    pub block_order: Vec<BlockId>,
    pub blocks: crate::dense::Metered<Vec<GraphBlock>>,
    pub insts: crate::dense::Metered<Vec<GraphInst>>,
    pub values: crate::dense::Metered<Vec<GraphValue>>,
    pub def_of: Vec<Option<InstId>>,
    /// The values each instruction reads, in operand order: one array for the function.
    pub(crate) inputs: crate::dense::Csr<InstId, ValueId>,
    /// Where each value is read, grouped by value.
    ///
    /// Flat, with an offset per value, rather than a vector per value: a
    /// function has one vector header and one allocation per value that way,
    /// and a thirty-thousand-value function had thirty thousand of each.
    /// Nothing adds a use to a value after the graph is built -- a value
    /// interned afterwards is read nowhere -- so the offsets never move.
    pub(crate) use_offsets: Vec<u32>,
    pub(crate) use_sites: Vec<UseSite>,
    /// Each function variable's value, by its [`crate::VarId`]; `None` for a
    /// variable no operation names. How an operand of the function crosses
    /// into the graph.
    pub(crate) value_of_var: Vec<Option<ValueId>>,
    pub block_by_addr: BTreeMap<u64, BlockId>,
    /// Each value addressed by its variable's hash, open-addressed over
    /// `values`: a slot holds a value's identifier plus one, and zero is
    /// empty.
    ///
    /// This was an ordered map from the variable to its value, then the values
    /// in the order their variables sort. Both held the variable twice and
    /// both answered a lookup by comparing variables, which is comparing
    /// names: a thirty-thousand-value function paid fifteen of those, each a
    /// random read into `values`, for every question. A probe reads the
    /// variable back out of `values`, which is where it already is, and asks
    /// once.
    pub(crate) value_index: crate::dense::HashIndex,
    /// The instruction each operation and phi became, indexed by its
    /// [`OpId`]: dense over the function's arena, `None` for an id whose
    /// operation is dead.
    pub(crate) inst_by_op: Vec<Option<InstId>>,
    /// The operation or phi each instruction is, indexed by [`InstId`].
    pub(crate) op_by_inst: Vec<OpId>,
    /// The machine instruction each operation came from, as runs over [`InstId`]; a phi and an
    /// operation the lifter stamped no address on are in none.
    pub(crate) instructions: r2il::InstructionRuns,
    /// Each instruction's runs, by address then run: a block the CFG split holds one in two.
    pub(crate) runs_by_instruction: Vec<(u64, u32)>,
    /// Entry-lane projections by value, valued by the lane's storage
    /// (`SSAFunction::mint_entry_lane_projections`).
    pub(crate) formal_projections: crate::dense::IdMap<ValueId, CanonicalStorageId>,
    /// Entry roots rebuilt from their declared lanes, valued by the root's
    /// storage (`SSAFunction::mint_entry_lane_projections`).
    pub(crate) formal_roots: crate::dense::IdMap<ValueId, CanonicalStorageId>,
    /// Each entry-lane formal at the low end of its root, with the root.
    pub(crate) entry_lanes: Vec<(SSAVar, SSAVar)>,
}

/// Each instruction's runs, by address, so the insts one instruction became are found by search.
pub(crate) fn runs_by_instruction(instructions: &r2il::InstructionRuns) -> Vec<(u64, u32)> {
    let mut runs = instructions
        .iter()
        .enumerate()
        .map(|(index, run)| {
            (
                run.addr,
                u32::try_from(index).expect("fewer than 2^32 runs"),
            )
        })
        .collect::<Vec<_>>();
    runs.sort_unstable();
    runs
}

/// Every value, addressed by its variable's hash.
pub(crate) fn value_index_of(values: &[GraphValue]) -> crate::dense::HashIndex {
    crate::dense::HashIndex::of(values.len(), |at| values[at as usize].var.index_hash())
}

/// The start of each value's run of uses, with a final entry for the total.
/// The graph's values as the function's variables are first named: phis
/// before operations, sources before the destination, block by block in
/// order. Each variable is numbered once, in O(1), through the dense index
/// its id gives.
struct ValueNumbering<'f> {
    function: &'f SSAFunction,
    values: Vec<GraphValue>,
    by_var: Vec<Option<ValueId>>,
    def_of: Vec<Option<InstId>>,
    uses_of: Vec<Vec<UseSite>>,
}

impl<'f> ValueNumbering<'f> {
    fn new(function: &'f SSAFunction) -> Self {
        Self {
            function,
            values: Vec::new(),
            by_var: vec![None; function.values().len()],
            def_of: Vec::new(),
            uses_of: Vec::new(),
        }
    }

    /// The value `operand` names, numbered now if this is its first name.
    fn intern(&mut self, operand: VarId) -> ValueId {
        if let Some(id) = self.by_var[operand.0 as usize] {
            return id;
        }
        let var = self.function.var(operand);
        let id = ValueId(self.values.len() as u32);
        let canonical_storage = self.function.storage_of(operand).or_else(|| {
            var.constant_bits().map(|bits| CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: bits,
                size: var.size,
            })
        });
        self.values.push(GraphValue {
            id,
            var: var.clone(),
            canonical_storage,
        });
        self.by_var[operand.0 as usize] = Some(id);
        self.def_of.push(None);
        self.uses_of.push(Vec::new());
        id
    }

    /// The value an operand already numbered names.
    fn value_of(&self, operand: VarId) -> ValueId {
        self.by_var[operand.0 as usize].expect("every operand is numbered before its payload")
    }

    /// `inst` reads `inputs`, in order, and defines `output`.
    fn record(&mut self, inst: InstId, inputs: &[ValueId], output: Option<ValueId>) {
        for (input_idx, input) in inputs.iter().enumerate() {
            self.uses_of[input.0 as usize].push(UseSite { inst, input_idx });
        }
        if let Some(output) = output {
            self.def_of[output.0 as usize] = Some(inst);
        }
    }
}

pub(crate) fn use_offsets_of(uses: &[Vec<UseSite>]) -> Vec<u32> {
    let mut offsets = Vec::with_capacity(uses.len() + 1);
    let mut total = 0u32;
    for sites in uses {
        offsets.push(total);
        total += sites.len() as u32;
    }
    offsets.push(total);
    offsets
}

impl SsaGraph {
    pub fn from_function(function: &SSAFunction) -> Self {
        Self::try_from_function(function).expect("SSA graph construction requires valid SSA")
    }

    /// Build a graph only after sealing the complete function-level SSA contract.
    #[expect(
        clippy::result_large_err,
        reason = "graph construction preserves the exact typed SSA validation failure at this artifact boundary"
    )]
    pub fn try_from_function(function: &SSAFunction) -> Result<Self, crate::SsaIntegrityError> {
        crate::validate_ssa_function(function)?;
        Ok(Self::from_function_with_storage(function))
    }

    pub(crate) fn from_function_with_storage(function: &SSAFunction) -> Self {
        let mut block_by_addr = BTreeMap::new();
        let mut block_order = Vec::new();
        let mut blocks = Vec::new();

        for (idx, &addr) in function.block_addrs().iter().enumerate() {
            let id = BlockId(idx as u32);
            block_by_addr.insert(addr, id);
            block_order.push(id);
            let size = function
                .get_block(addr)
                .map(|block| block.size)
                .unwrap_or_default();
            blocks.push(GraphBlock {
                id,
                addr,
                size,
                predecessors: Vec::new(),
                successors: Vec::new(),
                insts: Default::default(),
            });
        }

        for block in &mut blocks {
            block.predecessors = function
                .predecessors(block.addr)
                .into_iter()
                .map(|addr| {
                    block_by_addr
                        .get(&addr)
                        .copied()
                        .expect("validated predecessor must name an SSA block")
                })
                .collect();
            block.successors = function
                .successors(block.addr)
                .into_iter()
                .map(|addr| {
                    block_by_addr
                        .get(&addr)
                        .copied()
                        .expect("validated successor must name an SSA block")
                })
                .collect();
        }

        let mut numbering = ValueNumbering::new(function);
        // Sized from the arena's live count: an array grown by doubling holds up to twice its
        // instructions at the peak.
        let count = function.arena().live();
        let mut insts = Vec::with_capacity(count);
        let mut inputs = crate::dense::Csr::with_capacity(count, 2 * count);
        let mut reads = Vec::new();
        let mut inst_by_op = vec![None; function.id_limit()];
        let mut op_by_inst = Vec::with_capacity(count);
        let mut instructions = r2il::InstructionRuns::default();

        for block in function.blocks() {
            let block_id = block_by_addr[&block.addr];

            for (phi_idx, (op_id, phi)) in block.sited_phis().enumerate() {
                reads.clear();
                reads.extend(
                    phi.sources
                        .iter()
                        .map(|(_, value)| numbering.intern(*value)),
                );
                let output = numbering.intern(phi.dst);
                // A merge's storage is the phi's to state, a cleared one included.
                if let Some(value) = numbering.values.get_mut(output.0 as usize) {
                    value.canonical_storage = phi.canonical_storage;
                }
                let inst_id = inputs.push_row(reads.iter().copied());
                numbering.record(inst_id, &reads, Some(output));
                let predecessors = phi
                    .sources
                    .iter()
                    .map(|(addr, _)| {
                        block_by_addr
                            .get(addr)
                            .copied()
                            .expect("validated phi predecessor must name an SSA block")
                    })
                    .collect();
                insts.push(GraphInst {
                    id: inst_id,
                    block: block_id,
                    ordinal: phi_idx,
                    output: Some(output),
                    payload: InstPayload::Phi { predecessors },
                });
                blocks[block_id.0 as usize].insts.push(inst_id);
                inst_by_op[op_id.index()] = Some(inst_id);
                op_by_inst.push(op_id);
            }

            for (op_idx, (op_id, op)) in block.sited().enumerate() {
                reads.clear();
                reads.extend(
                    op.sources()
                        .into_iter()
                        .map(|value| numbering.intern(*value)),
                );
                let output = op.dst().map(|dst| numbering.intern(*dst));
                let payload = InstPayload::Op(op.map(&mut |operand| numbering.value_of(*operand)));
                let inst_id = inputs.push_row(reads.iter().copied());
                numbering.record(inst_id, &reads, output);
                insts.push(GraphInst {
                    id: inst_id,
                    block: block_id,
                    ordinal: block.phis().len() + op_idx,
                    output,
                    payload,
                });
                blocks[block_id.0 as usize].insts.push(inst_id);
                inst_by_op[op_id.index()] = Some(inst_id);
                op_by_inst.push(op_id);
                if let Some(from) = function.instruction_of(op_id) {
                    instructions.stamp(inst_id.0 as usize, from);
                }
            }
        }
        let ValueNumbering {
            values,
            by_var: value_by_var,
            def_of,
            uses_of,
            ..
        } = numbering;

        let entry = block_by_addr
            .get(&function.root())
            .copied()
            .unwrap_or(BlockId(0));

        let formal_projections = function
            .formal_projection_ids()
            .filter_map(|(operand, storage)| {
                value_by_var[operand.0 as usize].map(|value| (value, *storage))
            })
            .collect();
        let formal_roots = function
            .formal_root_ids()
            .filter_map(|(operand, storage)| {
                value_by_var[operand.0 as usize].map(|value| (value, *storage))
            })
            .collect();
        let entry_lanes = function
            .entry_lanes()
            .map(|(lane, root)| (function.var(lane).clone(), function.var(root).clone()))
            .collect();
        let value_index = value_index_of(&values);
        Self {
            entry,
            block_order,
            blocks: blocks.into(),
            insts: insts.into(),
            values: values.into(),
            def_of,
            inputs,
            use_offsets: use_offsets_of(&uses_of),
            use_sites: uses_of.into_iter().flatten().collect(),
            value_of_var: value_by_var,
            block_by_addr,
            value_index,
            inst_by_op,
            op_by_inst,
            runs_by_instruction: runs_by_instruction(&instructions),
            instructions,
            formal_projections,
            formal_roots,
            entry_lanes,
        }
    }

    /// Whether the caller supplied this value: an entry value with no
    /// defining instruction, or a lane the declaration mints from one.
    pub fn caller_supplied(&self, value: ValueId) -> bool {
        self.def_inst(value).is_none() || self.formal_projections.contains(value)
    }

    /// Whether this function's body wrote the value. It wrote no
    /// caller-supplied value, and no root the declaration rebuilt from its
    /// formals: the rebuild has a defining instruction, but that instruction
    /// restates what the caller passed rather than storing anything the body
    /// computed.
    pub fn written_by_body(&self, value: ValueId) -> bool {
        !self.caller_supplied(value) && !self.formal_roots.contains(value)
    }

    /// The lane storage an entry-lane projection stands for.
    pub fn formal_projection_storage(&self, value: ValueId) -> Option<CanonicalStorageId> {
        self.formal_projections.get(value).copied()
    }

    /// Every entry-lane projection with the lane it stands for.
    pub fn formal_projections(&self) -> impl Iterator<Item = (ValueId, &CanonicalStorageId)> {
        self.formal_projections.iter()
    }

    pub fn block_id_for_addr(&self, addr: u64) -> Option<BlockId> {
        self.block_by_addr.get(&addr).copied()
    }

    /// Return storage provenance already retained at the lift/SSA boundary.
    /// This lookup never parses or resolves the variable's display name.
    pub fn canonical_storage_for_var(&self, var: &SSAVar) -> Option<CanonicalStorageId> {
        self.value_id_for_var(var)
            .and_then(|value| self.value(value))
            .and_then(|value| value.canonical_storage)
    }

    pub fn value_id_for_var(&self, var: &SSAVar) -> Option<ValueId> {
        let values = &self.values;
        (self.value_index)
            .find(var.index_hash(), |at| values[at as usize].var == *var)
            .map(ValueId)
    }

    /// The instruction an operation or phi became.
    pub fn inst_for_op(&self, id: OpId) -> Option<InstId> {
        self.inst_by_op.get(id.index()).copied().flatten()
    }

    /// The operation or phi an instruction is.
    pub fn op_for_inst(&self, id: InstId) -> Option<OpId> {
        self.op_by_inst.get(id.0 as usize).copied()
    }

    /// Every block spelled by name, as the sealed function's `named_blocks` was: each operation
    /// and phi under its own `OpId`. For readers still keyed by name (F2.3's transitional
    /// readers, which P9 moves to values).
    pub fn named_blocks(&self) -> Vec<crate::SSABlock> {
        (self.blocks.iter())
            .map(|block| self.spelled_block(block))
            .collect()
    }

    /// One block spelled by name; see [`Self::named_blocks`].
    pub fn named_block(&self, addr: u64) -> Option<crate::SSABlock> {
        Some(self.spelled_block(self.block(self.block_id_for_addr(addr)?)?))
    }

    fn spelled_block(&self, block: &GraphBlock) -> crate::SSABlock {
        let spelled = |id: &ValueId| self.var(*id).clone();
        let insts = self.op_insts(block.id);
        let ops = (insts.iter())
            .filter_map(|inst| Some(self.op(*inst)?.map(&mut |id| spelled(id))))
            .collect();
        let ids = (insts.iter())
            .filter_map(|inst| self.op_for_inst(*inst))
            .collect();
        let phi_insts = self.phi_insts(block.id);
        let phis = (phi_insts.iter())
            .filter_map(|inst| {
                let phi = self.inst(*inst)?;
                let InstPayload::Phi { predecessors } = &phi.payload else {
                    return None;
                };
                let output = phi.output?;
                let sources = (predecessors.iter().zip(self.inputs(*inst)))
                    .filter_map(|(from, value)| Some((self.block(*from)?.addr, spelled(value))))
                    .collect();
                Some(crate::PhiNode {
                    dst: spelled(&output),
                    sources,
                    canonical_storage: self.value(output)?.canonical_storage,
                })
            })
            .collect();
        let phi_ids = (phi_insts.iter())
            .filter_map(|inst| self.op_for_inst(*inst))
            .collect();
        crate::SSABlock::with_ids(block.addr, block.size, (ops, ids), (phis, phi_ids))
    }

    /// The operation an instruction is; `None` for a phi.
    pub fn op(&self, id: InstId) -> Option<&SSAOp<ValueId>> {
        match &self.inst(id)?.payload {
            InstPayload::Op(op) => Some(op),
            InstPayload::Phi { .. } => None,
        }
    }

    /// A block's operations, in order, as its instructions after its phis.
    pub fn op_insts(&self, block: BlockId) -> &[InstId] {
        self.block(block)
            .map_or(&[][..], |held| &held.insts[self.phi_count(held)..])
    }

    /// A block's phis, as its first instructions.
    pub fn phi_insts(&self, block: BlockId) -> &[InstId] {
        self.block(block)
            .map_or(&[][..], |held| &held.insts[..self.phi_count(held)])
    }

    /// How many of a block's instructions are its phis: they stand first.
    fn phi_count(&self, block: &GraphBlock) -> usize {
        block.insts.partition_point(|inst| {
            self.insts
                .get(inst.0 as usize)
                .is_some_and(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
        })
    }

    /// Where an operation's instruction stands among its block's operations,
    /// phis not counted. `None` for a phi.
    ///
    /// A presentation view of a sealed function, for spelling a site as
    /// `0x{block}:op:{n}` and for ordering what is spelled. A fact is keyed
    /// by the [`InstId`] or the [`OpId`], never by this.
    pub fn op_ordinal(&self, id: InstId) -> Option<usize> {
        let inst = self.inst(id)?;
        let block = self.blocks.get(inst.block.0 as usize)?;
        inst.ordinal.checked_sub(self.phi_count(block))
    }

    /// Where a walk over a sealed block from this instruction starts: the
    /// block's address and the instruction's place among the block's
    /// operations.
    ///
    /// A cursor for the walks that read the operations before or after an
    /// instruction, private to the crate. The way back from a place is the
    /// block's own [`SSABlock::op_id`](crate::FunctionSSABlock::op_id) and
    /// [`Self::inst_for_op`]; no fact is keyed by a place.
    pub(crate) fn walk_start(&self, id: InstId) -> Option<(u64, usize)> {
        Some((self.block_addr_of(id)?, self.op_ordinal(id)?))
    }

    /// The instruction a spelled site `0x{block}:{n}` names: the inverse of
    /// [`Self::op_ordinal`], for reading back a site a person wrote.
    /// The instructions of `block` strictly between two ordinals, in order.
    ///
    /// A block's instructions are held in ordinal order -- its phis, then its
    /// operations -- and an instruction's ordinal is its position there, so
    /// the range is a slice: `O(1)` to find rather than a walk of the block.
    pub fn insts_between(&self, block: BlockId, after: usize, before: usize) -> &[InstId] {
        self.block(block)
            .map(|block| &block.insts)
            .and_then(|insts| insts.get(after.saturating_add(1)..before.min(insts.len())))
            .unwrap_or(&[])
    }

    pub(crate) fn inst_spelled_at(&self, block_addr: u64, ordinal: usize) -> Option<InstId> {
        let block = self.block(self.block_id_for_addr(block_addr)?)?;
        block.insts.get(self.phi_count(block) + ordinal).copied()
    }

    /// The address of the block an instruction stands in.
    pub fn block_addr_of(&self, id: InstId) -> Option<u64> {
        Some(self.block(self.inst(id)?.block)?.addr)
    }

    /// Which machine instruction this operation came from.
    ///
    /// The one answer to that question. Looking it up in the lifted operations'
    /// index space instead was wrong from the first operation renaming added
    /// to a block, and wrong in silence.
    pub fn instruction_for_inst(&self, id: InstId) -> Option<u64> {
        self.instructions.of(id.0 as usize)
    }

    /// Every operation one machine instruction became, in order.
    ///
    /// This used to be answered by finding the instruction's span of *lifted*
    /// operations and reading that range out of the graph, which is a range in
    /// the wrong index space and misses a block the CFG split.
    pub fn insts_for_instruction(&self, from: u64) -> impl DoubleEndedIterator<Item = InstId> + '_ {
        let runs = &self.runs_by_instruction;
        let first = runs.partition_point(|(at, _)| *at < from);
        let end = runs.partition_point(|(at, _)| *at <= from);
        runs[first..end]
            .iter()
            .filter_map(|(_, run)| self.instructions.get(*run as usize))
            .flat_map(|run| (run.first..run.first + run.len).map(InstId))
    }

    /// What one instruction leaves in each storage it writes: the last value it defines there, in the order it leaves them.
    pub fn left_by(&self, from: u64) -> Vec<(CanonicalStorageId, ValueId)> {
        let mut seen = BTreeSet::new();
        let mut left = self
            .insts_for_instruction(from)
            .rev()
            .filter_map(|inst| self.inst(inst))
            .filter_map(|inst| Some((self.written_storage(inst)?, inst.output?)))
            .filter(|(storage, _)| seen.insert(*storage))
            .collect::<Vec<_>>();
        left.reverse();
        left
    }

    /// The value one instruction leaves in a storage.
    pub fn left_by_instruction(&self, from: u64, storage: CanonicalStorageId) -> Option<ValueId> {
        self.left_by(from)
            .into_iter()
            .find_map(|(held, value)| (held == storage).then_some(value))
    }

    pub fn block(&self, id: BlockId) -> Option<&GraphBlock> {
        self.blocks.get(id.0 as usize)
    }

    pub fn inst(&self, id: InstId) -> Option<&GraphInst> {
        self.insts.get(id.0 as usize)
    }

    /// The call a `CallUse` at `read` is read by: the first call after it in its block, which
    /// rename emits it for, a compiler-inserted one alike (D392: the one link). O(run).
    pub fn call_reading(&self, read: InstId) -> Option<InstId> {
        let inst = self.inst(read)?;
        let block = self.block(inst.block)?;
        (block.insts.get(inst.ordinal + 1..)?.iter())
            .copied()
            .find(|inst| self.op(*inst).is_some_and(|op| op.call().is_some()))
    }

    /// The values an instruction reads, in operand order; a phi's in its predecessors' order.
    pub fn inputs(&self, id: InstId) -> &[ValueId] {
        self.inputs.get(id)
    }

    /// Give back the room the values grew, once the seal has added the last entry value.
    pub(crate) fn shrink_to_fit(&mut self) {
        self.values.shrink_to_fit();
        self.def_of.shrink_to_fit();
        self.inputs.shrink_to_fit();
    }

    /// The storage an instruction writes: its output value's, which a phi shares with its merge.
    pub fn written_storage(&self, inst: &GraphInst) -> Option<CanonicalStorageId> {
        self.value(inst.output?)?.canonical_storage
    }

    pub fn value(&self, id: ValueId) -> Option<&GraphValue> {
        self.values.get(id.0 as usize)
    }

    /// An operation with each operand spelled as its variable, borrowed from
    /// this graph's one table of values. For a reader that still works in
    /// names (the renderer, until it reads values: doc/adr-renderer-printer.md);
    /// nothing is cloned.
    pub fn named_op(&self, op: &SSAOp<ValueId>) -> SSAOp<&SSAVar> {
        op.map(&mut |id| self.var(*id))
    }

    /// The value a function operand names, where an operation names it.
    pub fn value_of(&self, operand: crate::VarId) -> Option<ValueId> {
        self.value_of_var.get(operand.0 as usize).copied().flatten()
    }

    /// The variable a value is spelled as: its name, version and width.
    /// Every id an operation names is a value of this graph.
    pub fn var(&self, id: ValueId) -> &SSAVar {
        &self.values[id.0 as usize].var
    }

    /// Materialize an exact source-declared value at function entry.
    ///
    /// Calls read their register arguments implicitly. A parameter handed
    /// straight to a call therefore has no operation for graph construction to
    /// discover, even though the source function interface proves that the
    /// value exists. This adds that boundary value without inventing an
    /// instruction or a graph use; the exact call boundary supplies the read.
    pub(crate) fn ensure_entry_value(
        &mut self,
        var: SSAVar,
        storage: CanonicalStorageId,
    ) -> Option<ValueId> {
        if var.version != 0
            || var.size != storage.size
            || storage.space != CanonicalStorageSpace::Register
            || storage.size == 0
        {
            return None;
        }
        if let Some(id) = self.value_id_for_var(&var) {
            let value = self.value(id)?;
            return (self.def_inst(id).is_none() && value.canonical_storage == Some(storage))
                .then_some(id);
        }
        let id = ValueId(u32::try_from(self.values.len()).ok()?);
        let hash = var.index_hash();
        self.values.push(GraphValue {
            id,
            var,
            canonical_storage: Some(storage),
        });
        let values = &self.values;
        (self.value_index).insert(id.0, hash, |at| values[at as usize].var.index_hash());
        self.def_of.push(None);
        self.use_offsets.push(self.use_sites.len() as u32);
        Some(id)
    }

    /// Forget every recorded use. A fixture that empties the graph to make a
    /// malformed one uses this; nothing else may.
    #[cfg(test)]
    pub(crate) fn clear_use_sites(&mut self) {
        self.use_offsets.clear();
        self.use_sites.clear();
    }

    pub fn def_inst(&self, id: ValueId) -> Option<InstId> {
        self.def_of.get(id.0 as usize).copied().flatten()
    }

    /// The operation that defines `var`, when an operation rather than a
    /// phi does.
    pub fn defining_op(&self, var: &SSAVar) -> Option<&SSAOp<ValueId>> {
        let def = self.def_inst(self.value_id_for_var(var)?)?;
        match &self.inst(def)?.payload {
            InstPayload::Op(op) => Some(op),
            InstPayload::Phi { .. } => None,
        }
    }

    /// The `CallUse` reads minted just before the call spelled at `(block_addr, ordinal)`, found from
    /// its position: O(reads), where `call_boundary_reads` searches the block for the call.
    pub(crate) fn boundary_reads_spelled_at(&self, block_addr: u64, ordinal: usize) -> &[InstId] {
        let Some(block) = self
            .block_id_for_addr(block_addr)
            .and_then(|id| self.block(id))
        else {
            return &[];
        };
        let end = (self.phi_count(block) + ordinal).min(block.insts.len());
        let start = (block.insts[..end].iter().rev())
            .take_while(|inst| matches!(self.op(**inst), Some(SSAOp::CallUse { .. })))
            .count();
        &block.insts[end - start..end]
    }

    /// The `CallUse` reads `call` is read by, the inverse of `call_reading` (D392): each one after
    /// the call before it in its block. O(reads), from its ordinal (D389).
    pub fn call_boundary_reads(&self, call: InstId) -> Vec<InstId> {
        let Some((inst, block)) =
            (self.inst(call)).and_then(|inst| Some((inst, self.block(inst.block)?)))
        else {
            return Vec::new();
        };
        let before = inst.ordinal.min(block.insts.len());
        (block.insts[..before].iter().rev())
            .take_while(|inst| self.op(**inst).is_none_or(|op| op.call().is_none()))
            .filter(|inst| matches!(self.op(**inst), Some(SSAOp::CallUse { .. })))
            .copied()
            .collect()
    }

    pub fn use_sites(&self, id: ValueId) -> &[UseSite] {
        let start = self.use_offsets.get(id.0 as usize).copied().unwrap_or(0) as usize;
        let end = self
            .use_offsets
            .get(id.0 as usize + 1)
            .copied()
            .unwrap_or(self.use_sites.len() as u32) as usize;
        self.use_sites.get(start..end).unwrap_or(&[])
    }
}
