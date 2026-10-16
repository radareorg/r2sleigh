//! The edits a lift pass plans for one instruction's operations, and the one applier that keeps
//! every instruction-relative label on the operation it named (doc/adr-verified-layers.md D34).

use r2il::R2ILOp;

/// What a plan does at one operation.
#[derive(Default)]
struct Edit {
    before: Vec<R2ILOp>,
    fate: Fate,
    after: Vec<R2ILOp>,
}

/// What becomes of the operation itself.
#[derive(Default)]
enum Fate {
    #[default]
    Keep,
    /// One operation in its place, which keeps the label the old one named.
    Replace(R2ILOp),
    Remove,
}

/// A pass's edits to one instruction, each against the index of an operation it was given;
/// applying them is `O(n)` in the operations, and free when there are none.
#[derive(Default)]
pub struct Plan {
    /// By operation index, ascending; a pass walks the operations in order, so each lands at the end.
    edits: Vec<(usize, Edit)>,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
    }

    fn edit(&mut self, at: usize) -> &mut Edit {
        let place = match self.edits.binary_search_by_key(&at, |(index, _)| *index) {
            Ok(place) => place,
            Err(place) => {
                self.edits.insert(place, (at, Edit::default()));
                place
            }
        };
        &mut self.edits[place].1
    }

    /// Operations computed just before operation `at`, which a label naming `at` reaches first.
    pub fn insert_before(&mut self, at: usize, ops: impl IntoIterator<Item = R2ILOp>) {
        let ops: Vec<R2ILOp> = ops.into_iter().collect();
        debug_assert!(ops.iter().all(|op| !op.is_local_branch()));
        self.edit(at).before.extend(ops);
    }

    /// Operations that complete operation `at`, which a label naming the next operation skips.
    pub fn insert_after(&mut self, at: usize, ops: impl IntoIterator<Item = R2ILOp>) {
        let ops: Vec<R2ILOp> = ops.into_iter().collect();
        debug_assert!(ops.iter().all(|op| !op.is_local_branch()));
        self.edit(at).after.extend(ops);
    }

    /// `op` in the place of operation `at`; a local branch keeps the label the old one named.
    pub fn replace(&mut self, at: usize, op: R2ILOp) {
        self.edit(at).fate = Fate::Replace(op);
    }

    pub fn remove(&mut self, at: usize) {
        self.edit(at).fate = Fate::Remove;
    }

    /// Operations `ops` in the place of operation `at`.
    pub fn expand(&mut self, at: usize, ops: impl IntoIterator<Item = R2ILOp>) {
        self.remove(at);
        self.insert_before(at, ops);
    }

    /// The operations with the plan applied. A label naming operation `t` names the start of what
    /// `t` became: the operations inserted before it, or what follows if it was removed.
    pub fn apply(self, ops: Vec<R2ILOp>) -> Vec<R2ILOp> {
        let Some(&(last, _)) = self.edits.last() else {
            return ops;
        };
        assert!(
            last < ops.len(),
            "a plan edits an operation the instruction has"
        );
        let count = ops.len();
        let mut out = Vec::with_capacity(count + self.edits.len());
        // Where each operation's expansion begins, the end last; and each local branch's place.
        let mut starts = Vec::with_capacity(count + 1);
        let mut branches: Vec<(usize, usize)> = Vec::new();
        let mut edits = self.edits.into_iter().peekable();
        for (index, op) in ops.into_iter().enumerate() {
            starts.push(out.len());
            let Some((_, edit)) = edits.next_if(|(at, _)| *at == index) else {
                land(&mut out, &mut branches, index, op);
                continue;
            };
            out.extend(edit.before);
            match edit.fate {
                Fate::Keep => land(&mut out, &mut branches, index, op),
                Fate::Replace(replacement) => land(&mut out, &mut branches, index, replacement),
                Fate::Remove => {}
            }
            out.extend(edit.after);
        }
        starts.push(out.len());
        for (old, new) in branches {
            let Some(offset) = out[new].local_offset() else {
                continue;
            };
            let named = isize::try_from(offset)
                .ok()
                .and_then(|offset| old.checked_add_signed(offset));
            if let Some(&start) = named.and_then(|named| starts.get(named)) {
                out[new].set_local_offset(start as i64 - new as i64);
            }
        }
        out
    }
}

/// Place an operation, remembering where a local branch of operation `index` landed.
fn land(out: &mut Vec<R2ILOp>, branches: &mut Vec<(usize, usize)>, index: usize, op: R2ILOp) {
    if op.is_local_branch() {
        branches.push((index, out.len()));
    }
    out.push(op);
}

#[cfg(test)]
mod tests {
    use r2il::Varnode;

    use super::*;

    fn set(at: u64) -> R2ILOp {
        R2ILOp::Copy {
            dst: Varnode::register(at, 1),
            src: Varnode::constant(0, 1),
        }
    }

    fn branch(offset: i64) -> R2ILOp {
        let mut branch = R2ILOp::Branch {
            target: Varnode::constant(0, 4),
        };
        branch.set_local_offset(offset);
        branch
    }

    /// Where each local branch of `ops` goes, as an index.
    fn goes(ops: &[R2ILOp]) -> Vec<(usize, usize)> {
        (0..ops.len())
            .filter_map(|at| Some((at, at.checked_add_signed(ops[at].local_offset()? as isize)?)))
            .collect()
    }

    /// A label names the start of what its operation became, whatever came before or after.
    #[test]
    fn a_label_keeps_naming_the_operation_it_named() {
        // 0: branch to 2, 1: set a, 2: set b, 3: branch to 1, 4: set c
        let ops = vec![branch(2), set(1), set(2), branch(-2), set(3)];
        let mut plan = Plan::new();
        plan.insert_before(0, [set(10), set(11)]);
        plan.insert_before(2, [set(12)]);
        plan.insert_after(2, [set(13), set(14)]);
        plan.expand(3, []);
        plan.insert_after(4, [set(15)]);
        let out = plan.apply(ops);
        // The branch to `set b` reaches the insertion before it, and the removed branch is gone.
        assert_eq!(out.len(), 10);
        assert_eq!(goes(&out), [(2, 4)]);
        assert_eq!(out[4], set(12));
    }

    /// A removed operation's label names what follows it; a label one past the last names the end.
    #[test]
    fn a_label_naming_a_removed_operation_names_the_next_and_one_past_the_end_stays() {
        let ops = vec![branch(1), set(1), branch(1)];
        let mut plan = Plan::new();
        plan.expand(1, [set(7), set(8)]);
        let out = plan.apply(ops);
        assert_eq!(goes(&out), [(0, 1), (3, 4)]);
        // The first branch lands on the expansion's first operation.
        assert_eq!(out[1], set(7));
    }

    /// A replacement that is a branch keeps the label of the one it replaced.
    #[test]
    fn a_replacement_keeps_the_label_of_the_operation_it_replaces() {
        let conditional = R2ILOp::CBranch {
            target: Varnode::constant(2, 4),
            cond: Varnode::register(0, 1),
        };
        let ops = vec![conditional, set(1), set(2)];
        let mut plan = Plan::new();
        plan.insert_before(0, [set(9)]);
        plan.insert_before(1, [set(11)]);
        plan.insert_before(2, [set(10)]);
        plan.replace(
            0,
            R2ILOp::CBranch {
                target: Varnode::constant(2, 4),
                cond: Varnode::register(1, 1),
            },
        );
        let out = plan.apply(ops);
        let R2ILOp::CBranch { target, cond } = &out[1] else {
            panic!("{out:?}");
        };
        assert_eq!((cond.offset, target.offset), (1, 3));
        assert_eq!(out[4], set(10));
    }

    #[test]
    fn an_empty_plan_returns_the_operations_untouched() {
        let ops = vec![branch(1), set(1)];
        assert_eq!(Plan::new().apply(ops.clone()), ops);
    }

    /// A deterministic stream of small numbers.
    struct Draw(u64);

    impl Draw {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    fn register(n: u64) -> Varnode {
        Varnode::register(8 * n, 8)
    }

    /// Register sums and forward branches, each naming an operation up to one past the last.
    fn program(draw: &mut Draw) -> Vec<R2ILOp> {
        let len = 3 + draw.below(10) as i64;
        (0..len)
            .map(|at| {
                let mut skip = R2ILOp::Branch {
                    target: Varnode::constant(0, 4),
                };
                if draw.below(4) == 2 {
                    skip = R2ILOp::CBranch {
                        target: Varnode::constant(0, 4),
                        cond: Varnode::register(0x100 + draw.below(3), 1),
                    };
                }
                match draw.below(4) {
                    0 | 1 => R2ILOp::IntAdd {
                        dst: register(draw.below(4)),
                        a: register(draw.below(4)),
                        b: Varnode::constant(1 + draw.below(250), 8),
                    },
                    _ => {
                        skip.set_local_offset(1 + draw.below((len - at) as u64) as i64);
                        skip
                    }
                }
            })
            .collect()
    }

    /// Insertions of operations that write only a temporary, and replacements by the same operation.
    fn neutral_plan(ops: &[R2ILOp], draw: &mut Draw) -> Plan {
        let neutral = |n: u64| R2ILOp::Copy {
            dst: Varnode::unique(0x1000 + n, 1),
            src: Varnode::constant(n, 1),
        };
        let mut plan = Plan::new();
        for (at, op) in ops.iter().enumerate() {
            if draw.below(3) == 0 {
                plan.insert_before(at, (0..=draw.below(2)).map(neutral));
            }
            if draw.below(3) == 0 {
                plan.insert_after(at, (0..=draw.below(2)).map(neutral));
            }
            match draw.below(4) {
                0 => plan.replace(at, op.clone()),
                1 if !op.is_local_branch() => plan.expand(at, [neutral(7), op.clone(), neutral(8)]),
                _ => {}
            }
        }
        plan
    }

    /// How a run of `ops` from one entry state ends, and the registers it leaves.
    fn leaves(ops: &[R2ILOp], entry: u64) -> (r2il::eval::Flow, Vec<Option<u128>>) {
        use r2il::Endianness;
        use r2il::eval::{State, run};

        let mut state = State::new(Endianness::Little, |_| None::<u8>, 256).expect("a machine");
        for n in 0..4 {
            let value = u128::from(n * 77 + entry);
            state.set_register(8 * n, 8, value).expect("entry");
        }
        for n in 0..3 {
            let flag = u128::from((entry >> n) & 1);
            state.set_register(0x100 + n, 1, flag).expect("flag");
        }
        let exit = run(ops, &mut state);
        (exit, (0..4).map(|n| state.register(8 * n, 8)).collect())
    }

    /// Neutral operations inserted around forward branches leave `r2il::eval`'s run ending where
    /// it did, with the registers it left.
    #[test]
    fn a_plan_of_neutral_edits_leaves_every_run_as_it_was() {
        let mut draw = Draw(0x2545_f491_4f6c_dd1d);
        let mut edited = 0;
        for _ in 0..400 {
            let ops = program(&mut draw);
            let planned = neutral_plan(&ops, &mut draw).apply(ops.clone());
            edited += usize::from(planned.len() != ops.len());
            for entry in 0..8 {
                assert_eq!(
                    leaves(&planned, entry),
                    leaves(&ops, entry),
                    "{ops:?}\n=>\n{planned:?}"
                );
            }
        }
        assert!(edited > 100, "{edited} programs were edited");
    }
}
