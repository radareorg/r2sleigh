//! Where a value points in the frame: an SSA value as a root plus a constant byte offset.
//!
//! One walker for the passes that read stack addresses before preparation (the stack-protector
//! check, slot promotion): through copies, constant adds and subtracts, and merges whose every
//! source points at the same place. `O(definitions)` to build, `O(chain)` per question.

use crate::arena::OpId;
use crate::dense::{Csr, IdMap};
use crate::function::SSAFunction;
use crate::op::SSAOp;
use crate::value_table::VarId;

pub(crate) type Op = SSAOp<VarId>;

/// An address as a root value plus a constant byte offset.
pub(crate) type Affine = (VarId, i64);

/// Each variable's defining operation or merge, and where each operation sits.
pub(crate) struct Definitions {
    defs: IdMap<VarId, (OpId, Op)>,
    phis: IdMap<VarId, Vec<VarId>>,
    /// Where each operation sits: its block and its index there.
    positions: IdMap<OpId, (u64, usize)>,
    /// A bound on any definition chain: every step moves to an operand defined earlier.
    values: usize,
    /// Where each merge points, where its sources agree (`Merge::Place`).
    merges: IdMap<VarId, Merge>,
}

/// What a merge of addresses is, solved once over every merge of the function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merge {
    /// No source resolved yet.
    Undefined,
    Place(Affine),
    Conflict,
}

impl Merge {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Undefined, other) | (other, Self::Undefined) => other,
            (Self::Place(a), Self::Place(b)) if a == b => self,
            _ => Self::Conflict,
        }
    }
}

impl Definitions {
    pub(crate) fn of(func: &SSAFunction) -> Self {
        let values = func.values().len();
        let mut defs = IdMap::new(values);
        let mut phis = IdMap::new(values);
        let mut positions = IdMap::new(func.id_limit());
        for addr in func.block_addrs() {
            let Some(block) = func.get_block(*addr) else {
                continue;
            };
            for (_, phi) in block.sited_phis() {
                phis.insert(
                    phi.dst,
                    phi.sources.iter().map(|(_, source)| *source).collect(),
                );
            }
            for (index, (id, op)) in block.sited().enumerate() {
                positions.insert(id, (*addr, index));
                if let Some(dst) = op.dst() {
                    defs.insert(*dst, (id, op.clone()));
                }
            }
        }
        let mut definitions = Self {
            defs,
            phis,
            positions,
            values,
            merges: IdMap::new(values),
        };
        definitions.solve_merges(func);
        definitions
    }

    /// Every merge's place, on the sparse driver: a cell only falls (`Undefined`, a place,
    /// `Conflict`), so the lattice has height 2.
    fn solve_merges(&mut self, func: &SSAFunction) {
        let order = self.phis.iter().map(|(dst, _)| dst).collect::<Vec<_>>();
        let chains = order
            .iter()
            .map(|dst| {
                let sources = self.phis.get(*dst).map(Vec::as_slice).unwrap_or_default();
                let chains = sources.iter().map(|source| self.chain(func, *source));
                (*dst, chains.collect::<Vec<_>>())
            })
            .collect::<IdMap<VarId, Vec<Affine>>>();
        let readers = Csr::from_pairs(
            self.values,
            chains.iter().flat_map(|(dst, chains)| {
                let phis = &self.phis;
                chains
                    .iter()
                    .filter(move |(root, _)| phis.get(*root).is_some())
                    .map(move |(root, _)| (*root, dst))
            }),
        );
        let solved = crate::fixpoint::sparse(
            "frame-address-merges",
            2,
            &order,
            &readers,
            Merge::Undefined,
            |dst, cells| {
                let sources = chains.get(dst).map(Vec::as_slice).unwrap_or_default();
                sources
                    .iter()
                    .fold(Merge::Undefined, |joined, (root, offset)| {
                        joined.join(match cells.get(*root).copied() {
                            Some(Merge::Place((inner, at))) => {
                                Merge::Place((inner, at.wrapping_add(*offset)))
                            }
                            Some(other) => other,
                            None => Merge::Place((*root, *offset)),
                        })
                    })
            },
        );
        // An exhausted driver is a defect it reports; every merge then stays unresolved.
        self.merges = solved.unwrap_or_else(|_| IdMap::new(self.values));
    }

    /// The constant a value is, through copies, extensions and constant arithmetic.
    pub(crate) fn constant(&self, func: &SSAFunction, var: VarId) -> Option<i64> {
        self.constant_within(func, var, 8)
    }

    fn constant_within(&self, func: &SSAFunction, var: VarId, depth: u32) -> Option<i64> {
        if let Some(bits) = func.var(var).constant_bits() {
            return Some(bits as i64);
        }
        let depth = depth.checked_sub(1)?;
        let of = |var: VarId| self.constant_within(func, var, depth);
        match &self.op(var)?.1 {
            SSAOp::Copy { src, .. } | SSAOp::IntZExt { src, .. } => of(*src),
            SSAOp::IntSExt { src, .. } => {
                let bits = func.var(*src).size * 8;
                let value = of(*src)?;
                Some(match bits {
                    1..=63 => (value << (64 - bits)) >> (64 - bits),
                    _ => value,
                })
            }
            SSAOp::IntAdd { a, b, .. } => Some(of(*a)?.wrapping_add(of(*b)?)),
            SSAOp::IntSub { a, b, .. } => Some(of(*a)?.wrapping_sub(of(*b)?)),
            SSAOp::IntMult { a, b, .. } => Some(of(*a)?.wrapping_mul(of(*b)?)),
            _ => None,
        }
    }

    /// The sources of the merge defining `var`, empty where no merge does.
    pub(crate) fn phi_sources(&self, var: VarId) -> &[VarId] {
        self.phis.get(var).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn op(&self, var: VarId) -> Option<&(OpId, Op)> {
        self.defs.get(var)
    }

    /// Where an operation sits: its block and its index there.
    pub(crate) fn position(&self, op: OpId) -> Option<(u64, usize)> {
        self.positions.get(op).copied()
    }

    /// Whether operation `a` runs before `b` on every path to `b`.
    pub(crate) fn precedes(&self, func: &SSAFunction, a: OpId, b: OpId) -> bool {
        match (self.position(a), self.position(b)) {
            (Some((block_a, at)), Some((block_b, bt))) if block_a == block_b => at < bt,
            (Some((block_a, _)), Some((block_b, _))) => func.dominates(block_a, block_b),
            _ => false,
        }
    }

    /// The value a run of copies forwards.
    pub(crate) fn copied(&self, mut var: VarId) -> VarId {
        for _ in 0..self.values {
            match self.op(var) {
                Some((_, SSAOp::Copy { src, .. } | SSAOp::CallRestore { src, .. })) => var = *src,
                _ => return var,
            }
        }
        var
    }

    /// An address as a root and a constant offset; a merge whose sources all agree is that place.
    pub(crate) fn affine(&self, func: &SSAFunction, var: VarId) -> Affine {
        let (root, offset) = self.chain(func, var);
        match self.merges.get(root).copied() {
            Some(Merge::Place((inner, at))) => (inner, at.wrapping_add(offset)),
            _ => (root, offset),
        }
    }

    /// `var` as a root and offset through copies and constant adds and subtracts, stopping at a merge.
    fn chain(&self, func: &SSAFunction, mut var: VarId) -> Affine {
        let mut offset = 0i64;
        let constant = |var: VarId| self.constant(func, var);
        for _ in 0..self.values {
            if self.phis.get(var).is_some() {
                break;
            }
            match self.op(var) {
                Some((_, SSAOp::Copy { src, .. } | SSAOp::CallRestore { src, .. })) => var = *src,
                Some((_, SSAOp::IntAdd { a, b, .. })) if constant(*b).is_some() => {
                    offset = offset.wrapping_add(constant(*b).unwrap_or(0));
                    var = *a;
                }
                Some((_, SSAOp::IntAdd { a, b, .. })) if constant(*a).is_some() => {
                    offset = offset.wrapping_add(constant(*a).unwrap_or(0));
                    var = *b;
                }
                Some((_, SSAOp::IntSub { a, b, .. })) if constant(*b).is_some() => {
                    offset = offset.wrapping_sub(constant(*b).unwrap_or(0));
                    var = *a;
                }
                _ => break,
            }
        }
        (var, offset)
    }

    /// The load a value is, through copies: its operation, its address and its width.
    pub(crate) fn load(&self, func: &SSAFunction, var: VarId) -> Option<(OpId, Affine, u32)> {
        match self.op(self.copied(var)) {
            Some((id, SSAOp::Load { dst, addr, .. })) => {
                Some((*id, self.affine(func, *addr), func.var(*dst).size))
            }
            _ => None,
        }
    }
}
