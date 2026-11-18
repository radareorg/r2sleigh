//! The control certificate of `doc/adr-structure-dominator-tree.md` §3.
//!
//! The rendered body is read back as a control graph over block occurrences,
//! and that graph must equal the function's CFG: every block occurs, every
//! occurrence leaves exactly the way its block's terminator says, and a
//! rendered test is the block's own test. The reader here is a small
//! interpreter of C control that knows nothing about how the tree was built,
//! which is what makes it a certificate rather than a re-derivation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use r2ssa::cfg::{BlockTerminator, CFG};
use r2ssa::domtree::DomTree;

use crate::ast::RenderObservationId;
use crate::ast::{CExpr, CStmt};

/// What the markers say of the statements the placement wrote.
pub(crate) trait Placed {
    /// The block a marker was written for.
    fn block_of(&self, id: RenderObservationId) -> Option<u64>;
    /// The statement the placement wrote that a marker stands for: itself, or the one it copies.
    fn statement_of(&self, id: RenderObservationId) -> Option<RenderObservationId>;
    /// How many statements the placement wrote: markers `0..written` are the originals.
    fn written(&self) -> usize;
    /// Whether a marker is on a copy an edge carries, which is its block's statement but no place in it.
    fn edge_copy(&self, id: RenderObservationId) -> bool;
}

/// What a terminator says about one of its edges.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EdgeLabel {
    Normal,
    True,
    False,
    Case(BTreeSet<u64>),
    Default,
}

/// Where an edge arrives: a block of this function, or somewhere outside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Target {
    Block(u64),
    External,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(addr) => write!(f, "{addr:#x}"),
            Self::External => write!(f, "external"),
        }
    }
}

/// One clause of the certificate that the rendered body violates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Violation {
    /// The first block the text runs is not the function's root (read through
    /// to the entry where the root is the entry-edge block).
    EntryNotFirst {
        first: Option<u64>,
    },
    /// A block with no occurrence that cannot be read as an empty pass-through.
    MissingBlock(u64),
    /// A `goto` or label names something no block answers for.
    UnknownLabel(String),
    /// A test statement reached by no single occurrence, or by several.
    UnownedControl {
        kind: &'static str,
        open: usize,
    },
    StrayBreak,
    StrayContinue,
    /// A loop whose body enters no block, so its back edge has no target.
    EmptyLoopBody,
    /// A `case` label that is not an integer literal.
    SwitchValue {
        block: u64,
    },
    /// A block the source declared terminal whose text continues.
    TerminalFallthrough {
        block: u64,
        to: Target,
    },
    /// An indirect branch with no declared successor whose text continues.
    UnresolvedIndirect {
        block: u64,
        to: Target,
    },
    /// The text ends while the machine still has somewhere to go.
    FallsOffEnd {
        block: u64,
    },
    /// A `return` where the machine continues inside the function.
    ReturnWhereMachineContinues {
        block: u64,
    },
    /// A selection that is not one assignment of a test's value to a plain variable, each arm
    /// writing nothing and naming at most one block.
    Selection {
        block: u64,
    },
    /// A test written as a chain of blocks that the machine's branches do not make.
    Chain {
        block: u64,
        fault: super::condition::ChainFault,
    },
    /// The statements the placement wrote for a block are not all written as often as each other, or
    /// none is: a block read through as a pass-through that was not one.
    Statement {
        block: u64,
        fewest: usize,
        most: usize,
    },
    /// The occurrence's edges are not the block's edges.
    EdgeMismatch {
        block: u64,
        rendered: Vec<(Target, EdgeLabel)>,
        expected: Vec<(Target, EdgeLabel)>,
    },
}

impl Violation {
    /// The clause name, stable for tallying across a census.
    pub(crate) fn clause(&self) -> &'static str {
        match self {
            Self::EntryNotFirst { .. } => "entry-not-first",
            Self::MissingBlock(_) => "missing-block",
            Self::UnknownLabel(_) => "unknown-label",
            Self::UnownedControl { .. } => "unowned-control",
            Self::StrayBreak => "stray-break",
            Self::StrayContinue => "stray-continue",
            Self::EmptyLoopBody => "empty-loop-body",
            Self::SwitchValue { .. } => "switch-value",
            Self::TerminalFallthrough { .. } => "terminal-fallthrough",
            Self::UnresolvedIndirect { .. } => "unresolved-indirect",
            Self::FallsOffEnd { .. } => "falls-off-end",
            Self::ReturnWhereMachineContinues { .. } => "return-where-machine-continues",
            Self::Selection { .. } => "selection",
            Self::Chain { .. } => "chain",
            Self::Statement { .. } => "statement",
            Self::EdgeMismatch { .. } => "edge-mismatch",
        }
    }
}

fn write_edges(f: &mut fmt::Formatter<'_>, edges: &[(Target, EdgeLabel)]) -> fmt::Result {
    write!(f, "[")?;
    for (index, (target, label)) in edges.iter().enumerate() {
        if index > 0 {
            write!(f, ", ")?;
        }
        match label {
            EdgeLabel::Normal => write!(f, "{target}")?,
            EdgeLabel::True => write!(f, "true->{target}")?,
            EdgeLabel::False => write!(f, "false->{target}")?,
            EdgeLabel::Default => write!(f, "default->{target}")?,
            EdgeLabel::Case(values) => write!(f, "case{values:?}->{target}")?,
        }
    }
    write!(f, "]")
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.clause())?;
        match self {
            Self::EntryNotFirst { first } => write!(f, " first={first:#x?}"),
            Self::MissingBlock(addr) => write!(f, " {addr:#x}"),
            Self::UnknownLabel(name) => write!(f, " {name}"),
            Self::UnownedControl { kind, open } => write!(f, " {kind} open-ends={open}"),
            Self::StrayBreak | Self::StrayContinue | Self::EmptyLoopBody => Ok(()),
            Self::SwitchValue { block } | Self::Selection { block } => write!(f, " at {block:#x}"),
            Self::Chain { block, fault } => write!(f, " at {block:#x}: {fault}"),
            Self::Statement { block, most: 0, .. } => {
                write!(f, " at {block:#x}: no statement of the block is written")
            }
            Self::Statement {
                block,
                fewest,
                most,
            } => write!(
                f,
                " at {block:#x}: a statement written {fewest} times where another is {most}"
            ),
            Self::TerminalFallthrough { block, to } | Self::UnresolvedIndirect { block, to } => {
                write!(f, " {block:#x} -> {to}")
            }
            Self::FallsOffEnd { block } | Self::ReturnWhereMachineContinues { block } => {
                write!(f, " at {block:#x}")
            }
            Self::EdgeMismatch {
                block,
                rendered,
                expected,
            } => {
                write!(f, " at {block:#x} rendered ")?;
                write_edges(f, rendered)?;
                write!(f, " expected ")?;
                write_edges(f, expected)
            }
        }
    }
}

/// The certificate's verdict on one rendered body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlCertificate {
    pub(crate) violations: Vec<Violation>,
    pub(crate) occurrences: usize,
    pub(crate) blocks: usize,
    pub(crate) duplicated: Vec<u64>,
    pub(crate) contracted: usize,
    pub(crate) unreachable_missing: usize,
}

impl ControlCertificate {
    pub(crate) fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for ControlCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ok() {
            write!(f, "ok")?;
        } else {
            write!(f, "FAIL {} ", self.violations.len())?;
            let mut clauses = BTreeMap::<&'static str, usize>::new();
            for violation in &self.violations {
                *clauses.entry(violation.clause()).or_default() += 1;
            }
            let summary = clauses
                .iter()
                .map(|(clause, count)| format!("{clause}={count}"))
                .collect::<Vec<_>>()
                .join(",");
            write!(f, "{summary}")?;
        }
        write!(
            f,
            " occurrences={} blocks={} duplicated={} contracted={} unreachable={}",
            self.occurrences,
            self.blocks,
            self.duplicated.len(),
            self.contracted,
            self.unreachable_missing
        )
    }
}

/// What the caller says a statement is, which the walk then checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatementRole {
    Plain,
    /// A trap or a call that never returns: control ends here.
    Ends,
    /// `x = c ? a : b;` written for its test block's `if` with one assignment in each arm.
    Selects,
}

impl From<bool> for StatementRole {
    /// Whether a statement ends control, where a caller says nothing of selections.
    fn from(ends: bool) -> Self {
        match ends {
            true => Self::Ends,
            false => Self::Plain,
        }
    }
}

/// One rendered copy of one block's text.
struct Occurrence {
    block: u64,
    edges: Vec<(Target, EdgeLabel)>,
    returned: bool,
    fell_off_end: bool,
}

/// Control that has run some occurrence to a point where the next statement
/// decides where it goes, with the label the edge it takes will carry.
type OpenEnd = (usize, EdgeLabel);

enum LoopHead {
    /// `continue` reaches this block's occurrence.
    Block(u64),
    /// `continue` reaches the trailing test of a do-while.
    Test,
    /// `continue` reaches the first block of a `for (;;)` body.
    Entry,
}

enum Frame {
    Loop {
        head: LoopHead,
        breaks: Vec<OpenEnd>,
        continues: Vec<OpenEnd>,
    },
    Switch {
        breaks: Vec<OpenEnd>,
    },
}

struct Walker<'a> {
    cfg: &'a CFG,
    dom: &'a DomTree,
    block_of: &'a dyn Fn(RenderObservationId) -> Option<u64>,
    label_block: &'a dyn Fn(&str) -> Option<u64>,
    role: &'a dyn Fn(&CStmt) -> StatementRole,
    occurrences: Vec<Occurrence>,
    frames: Vec<Frame>,
    violations: Vec<Violation>,
    first_block: Option<u64>,
    /// The next statement starts a position of its own: the function's
    /// first, or a do-while body's entry.
    force_open: bool,
    /// By occurrence: the chain its test is written as, when it is one.
    chains: BTreeMap<usize, super::condition::Written>,
    /// Every marker the text writes a statement under, in the order the walk meets them.
    met: Vec<RenderObservationId>,
    edge_copy: &'a dyn Fn(RenderObservationId) -> bool,
}

impl Walker<'_> {
    fn new_occurrence(&mut self, open: Vec<OpenEnd>, block: u64) -> Vec<OpenEnd> {
        let id = self.occurrences.len();
        self.occurrences.push(Occurrence {
            block,
            edges: Vec::new(),
            returned: false,
            fell_off_end: false,
        });
        self.first_block.get_or_insert(block);
        self.force_open = false;
        for (from, label) in open {
            self.occurrences[from]
                .edges
                .push((Target::Block(block), label));
        }
        vec![(id, EdgeLabel::Normal)]
    }

    /// Control arriving at `block`'s text: the same occurrence when the text
    /// is merely continuing, a fresh one entered by every open end otherwise.
    fn enter_block(&mut self, open: Vec<OpenEnd>, block: u64) -> Vec<OpenEnd> {
        // Any label, not just `Normal`: a predicated instruction puts part of
        // its own block's text under an `if`, so control reaches that text
        // carrying the arm's label. It is the same occurrence continuing --
        // which `edges.is_empty()` still distinguishes from the block's text
        // being rendered a second time.
        if let [(id, _)] = open.as_slice()
            && self.occurrences[*id].block == block
            && self.occurrences[*id].edges.is_empty()
        {
            return open;
        }
        self.new_occurrence(open, block)
    }

    fn close(&mut self, open: Vec<OpenEnd>, target: Target) {
        for (from, label) in open {
            self.occurrences[from].edges.push((target, label));
        }
    }

    fn single_owner(&mut self, open: &[OpenEnd], kind: &'static str) -> Option<usize> {
        match open {
            [(id, _)] => Some(*id),
            _ => {
                self.violations.push(Violation::UnownedControl {
                    kind,
                    open: open.len(),
                });
                None
            }
        }
    }

    /// Take the chain `test` is written as, when its atoms carry blocks' markers.
    fn note_test(&mut self, owner: usize, test: &CExpr) {
        match super::condition::read(test, self.block_of) {
            Ok(Some(written)) => {
                self.chains.insert(owner, written);
            }
            Ok(None) => {}
            Err(fault) => self.violations.push(Violation::Chain {
                block: self.occurrences[owner].block,
                fault,
            }),
        }
    }

    /// Among the blocks a loop statement is observed under -- its header and
    /// its latches -- the header is the one that tests, or the one a latch
    /// falls to when the header's own test was observed elsewhere.
    fn choose_header(&self, candidates: &[u64]) -> Option<u64> {
        let tests = |addr: u64| {
            self.cfg.get_block(addr).is_some_and(|block| {
                matches!(block.terminator, BlockTerminator::ConditionalBranch { .. })
            })
        };
        candidates
            .iter()
            .copied()
            .find(|candidate| tests(*candidate))
            .or_else(|| {
                candidates.iter().copied().find_map(|candidate| {
                    match self.cfg.successors(candidate).as_slice() {
                        [next] if tests(*next) => Some(*next),
                        _ => None,
                    }
                })
            })
            .or_else(|| candidates.first().copied())
    }

    /// The block a control statement is observed under, preferring the one
    /// whose terminator is the statement's kind.
    fn choose_control_block(&self, candidates: &[u64], stmt: &CStmt) -> Option<u64> {
        let fits = |addr: u64| {
            self.cfg.get_block(addr).is_some_and(|block| {
                matches!(
                    (stmt, &block.terminator),
                    (CStmt::If { .. }, BlockTerminator::ConditionalBranch { .. })
                        | (CStmt::Switch { .. }, BlockTerminator::Switch { .. })
                        | (CStmt::Return(_), BlockTerminator::Return)
                )
            })
        };
        candidates
            .iter()
            .copied()
            .find(|candidate| fits(*candidate))
            .or_else(|| candidates.first().copied())
    }

    fn walk_seq(&mut self, stmts: &[CStmt], mut open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        for stmt in stmts {
            open = self.walk(stmt, open);
        }
        open
    }

    fn walk(&mut self, stmt: &CStmt, open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        match stmt {
            CStmt::Observed { .. } => self.walk_observed(stmt, open),
            CStmt::Block(stmts) => self.walk_seq(stmts, open),
            CStmt::Label(name) => match (self.label_block)(name) {
                Some(block) => self.enter_block(open, block),
                None => {
                    self.violations.push(Violation::UnknownLabel(name.clone()));
                    open
                }
            },
            CStmt::Goto(name) => {
                match (self.label_block)(name) {
                    Some(block) => self.close(open, Target::Block(block)),
                    None => self.violations.push(Violation::UnknownLabel(name.clone())),
                }
                Vec::new()
            }
            CStmt::Break => {
                let breaks = self.frames.last_mut().map(|frame| match frame {
                    Frame::Loop { breaks, .. } | Frame::Switch { breaks } => breaks,
                });
                match breaks {
                    Some(breaks) => breaks.extend(open),
                    None => self.violations.push(Violation::StrayBreak),
                }
                Vec::new()
            }
            CStmt::Continue => {
                let target = self.frames.iter().rev().find_map(|frame| match frame {
                    Frame::Loop {
                        head: LoopHead::Block(block),
                        ..
                    } => Some(Some(*block)),
                    Frame::Loop {
                        head: LoopHead::Test | LoopHead::Entry,
                        ..
                    } => Some(None),
                    Frame::Switch { .. } => None,
                });
                match target {
                    Some(Some(header)) => self.close(open, Target::Block(header)),
                    Some(None) => {
                        let continues =
                            self.frames.iter_mut().rev().find_map(|frame| match frame {
                                Frame::Loop { continues, .. } => Some(continues),
                                Frame::Switch { .. } => None,
                            });
                        if let Some(continues) = continues {
                            continues.extend(open);
                        }
                    }
                    None => self.violations.push(Violation::StrayContinue),
                }
                Vec::new()
            }
            CStmt::Return(_) => {
                for (id, _) in open {
                    self.occurrences[id].returned = true;
                }
                Vec::new()
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let Some(owner) = self.single_owner(&open, "if") else {
                    return Vec::new();
                };
                self.note_test(owner, cond);
                let mut ends = self.walk(then_body, vec![(owner, EdgeLabel::True)]);
                match else_body {
                    Some(else_body) => {
                        ends.extend(self.walk(else_body, vec![(owner, EdgeLabel::False)]))
                    }
                    None => ends.push((owner, EdgeLabel::False)),
                }
                ends
            }
            CStmt::For {
                cond: None, body, ..
            } => self.walk_infinite_loop(body, open),
            CStmt::While { body, .. } | CStmt::For { body, .. } => {
                // Its `if` and `break` are the operation's own, not edges between blocks.
                if self.body_owns_no_block(body) {
                    return open;
                }
                self.walk_pre_test_loop(loop_test(stmt), body, open)
            }
            // A do-while nobody observed cannot say which block its test is.
            CStmt::DoWhile { body, .. } => self.walk_do_while(&[], loop_test(stmt), body, open),
            CStmt::Switch {
                expr,
                cases,
                default,
            } => match cases.iter().any(|case| case.test.is_some()) {
                true => self.walk_chained_switch(open, expr, cases, default.as_deref()),
                false => self.walk_switch(open, cases, default.as_deref()),
            },
            // A call the prototype declares `noreturn`, or a transfer the caller says traps, ends the text here.
            CStmt::Expr(_) | CStmt::Gap(_) if (self.role)(stmt) == StatementRole::Ends => {
                for (id, _) in open {
                    self.occurrences[id].returned = true;
                }
                Vec::new()
            }
            CStmt::Expr(_)
            | CStmt::Decl { .. }
            | CStmt::Comment(_)
            | CStmt::Empty
            | CStmt::Gap(_) => open,
        }
    }

    /// Whether a loop statement is one the control flow has, or one a lowering
    /// wrote.
    ///
    /// The certificate is about blocks: where each one is placed and which
    /// edges the text expresses. A construct that places no block and makes no
    /// transfer says nothing it could be wrong about. One machine operation
    /// whose meaning is a loop is rendered as a loop, and its body is a few
    /// statements of one block rather than blocks of its own, so reading it as
    /// a pre-test loop invents a back edge to the block it sits in --
    /// `fill_window` certified `[false->0x577c, true->0x57cd]` against an
    /// expected `[0x577c]` for exactly that.
    fn body_owns_no_block(&self, body: &CStmt) -> bool {
        let mut stack = vec![body];
        while let Some(stmt) = stack.pop() {
            match stmt {
                CStmt::Observed { ids, .. }
                    if ids.iter().any(|id| (self.block_of)(id).is_some()) =>
                {
                    return false;
                }
                CStmt::Observed { stmt, .. } => stack.push(stmt),
                CStmt::Block(statements) => stack.extend(statements.iter()),
                CStmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    stack.push(then_body);
                    if let Some(else_body) = else_body.as_deref() {
                        stack.push(else_body);
                    }
                }
                CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => stack.push(body),
                CStmt::For { init, body, .. } => {
                    if let Some(init) = init.as_deref() {
                        stack.push(init);
                    }
                    stack.push(body);
                }
                CStmt::Switch { cases, default, .. } => {
                    for case in cases {
                        stack.extend(case.body.iter());
                    }
                    if let Some(default) = default.as_deref() {
                        stack.extend(default.iter());
                    }
                }
                // A body that leaves by anything but its own `break` transfers somewhere.
                CStmt::Goto(_) | CStmt::Label(_) | CStmt::Return(_) | CStmt::Continue => {
                    return false;
                }
                _ => {}
            }
        }
        true
    }

    /// A control statement is placed at the block its observations name; a
    /// loop is observed under its header and its latches together. A plain
    /// statement opens nothing: a block that only computes is read as part
    /// of whatever text it sits in, and its edge is read through it.
    fn walk_observed(&mut self, stmt: &CStmt, open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        let mut blocks = Vec::new();
        let ids = stmt.observation_ids();
        self.met.extend(ids.iter());
        for id in ids.iter().filter(|id| !(self.edge_copy)(**id)) {
            if let Some(block) = (self.block_of)(*id)
                && !blocks.contains(&block)
            {
                blocks.push(block);
            }
        }
        let inner = stmt.unobserved();
        match inner {
            CStmt::Expr(selection) if (self.role)(stmt) == StatementRole::Selects => {
                self.walk_selection(&blocks, selection, open)
            }
            CStmt::DoWhile { body, .. } => {
                self.walk_do_while(&blocks, loop_test(inner), body, open)
            }
            CStmt::For {
                cond: None, body, ..
            } => self.walk_infinite_loop(body, open),
            CStmt::While { body, .. } | CStmt::For { body, .. } => {
                if self.body_owns_no_block(body) {
                    let open = match self.choose_header(&blocks) {
                        Some(header) => self.enter_block(open, header),
                        None => open,
                    };
                    return self.walk(body, open);
                }
                let open = match self.choose_header(&blocks) {
                    Some(header) => self.enter_block(open, header),
                    None => open,
                };
                self.walk_pre_test_loop(loop_test(inner), body, open)
            }
            CStmt::If { .. }
            | CStmt::Switch { .. }
            | CStmt::Return(_)
            | CStmt::Goto(_)
            | CStmt::Break
            | CStmt::Continue => {
                let open = match self.choose_control_block(&blocks, inner) {
                    Some(block) => self.enter_block(open, block),
                    None => open,
                };
                self.walk(inner, open)
            }
            _ => {
                let open = match blocks.first() {
                    Some(block) if self.plain_statement_opens(&open, *block) => {
                        self.enter_block(open, *block)
                    }
                    _ => open,
                };
                self.walk(inner, open)
            }
        }
    }

    /// A selection is its test block's `if`: each arm's value is the occurrence of the block its
    /// markers name, entered on the arm's edge, or that edge itself where they name none.
    fn walk_selection(
        &mut self,
        candidates: &[u64],
        selection: &CExpr,
        open: Vec<OpenEnd>,
    ) -> Vec<OpenEnd> {
        let tests = |addr: &u64| {
            self.cfg.get_block(*addr).is_some_and(|block| {
                matches!(block.terminator, BlockTerminator::ConditionalBranch { .. })
            })
        };
        let open = match candidates.iter().copied().find(tests) {
            Some(block) => self.enter_block(open, block),
            None => open,
        };
        let Some(owner) = self.single_owner(&open, "selection") else {
            return Vec::new();
        };
        let block = self.occurrences[owner].block;
        let arms = selected_arms(selection).filter(|_| tests(&block));
        let Some((test, arms)) = arms else {
            self.violations.push(Violation::Selection { block });
            return Vec::new();
        };
        self.note_test(owner, test);
        let mut ends = Vec::new();
        for (arm, label) in arms.into_iter().zip([EdgeLabel::True, EdgeLabel::False]) {
            self.met.extend(arm.observation_ids().iter());
            let mut named = (arm.observation_ids().iter())
                .filter(|id| !(self.edge_copy)(**id))
                .filter_map(|id| (self.block_of)(*id))
                .collect::<Vec<_>>();
            named.sort_unstable();
            named.dedup();
            match named.as_slice() {
                [] => ends.push((owner, label)),
                [at] => ends.extend(self.enter_block(vec![(owner, label)], *at)),
                _ => {
                    self.violations.push(Violation::Selection { block });
                    return Vec::new();
                }
            }
        }
        ends
    }

    /// Whether a plain statement of `block` is the text moving on to that
    /// block. It is at a forced position, where several ends converge, or
    /// when the one open end's block flows into it forward; a statement
    /// observed under a loop header that a latch's text carries -- a merge
    /// write normalisation placed for the header -- is not.
    fn plain_statement_opens(&self, open: &[OpenEnd], block: u64) -> bool {
        if self.force_open || open.is_empty() || open.len() > 1 {
            return true;
        }
        let from = self.occurrences[open[0].0].block;
        from != block
            && self.leaves_to(open[0].0).contains(&block)
            && !self.dom.dominates(block, from)
    }

    /// The blocks control can go to from an occurrence: its block's successors, or, where its test
    /// is a chain, the blocks the chain's tests lead out to.
    fn leaves_to(&self, occurrence: usize) -> Vec<u64> {
        let from = self.occurrences[occurrence].block;
        let Some(written) = self.chains.get(&occurrence) else {
            return self.cfg.successors(from);
        };
        let tested: BTreeSet<u64> = written.blocks.iter().copied().collect();
        let mut out: Vec<u64> = tested
            .iter()
            .flat_map(|block| self.cfg.successors(*block))
            .filter(|next| !tested.contains(next))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn walk_pre_test_loop(
        &mut self,
        test: Option<&CExpr>,
        body: &CStmt,
        open: Vec<OpenEnd>,
    ) -> Vec<OpenEnd> {
        let Some(owner) = self.single_owner(&open, "loop") else {
            return Vec::new();
        };
        if let Some(test) = test {
            self.note_test(owner, test);
        }
        let header = self.occurrences[owner].block;
        self.frames.push(Frame::Loop {
            head: LoopHead::Block(header),
            breaks: Vec::new(),
            continues: Vec::new(),
        });
        let body_ends = self.walk(body, vec![(owner, EdgeLabel::True)]);
        self.close(body_ends, Target::Block(header));
        let Some(Frame::Loop { breaks, .. }) = self.frames.pop() else {
            unreachable!("the loop frame pushed above is still on top");
        };
        let mut ends = vec![(owner, EdgeLabel::False)];
        ends.extend(breaks);
        ends
    }

    /// `for (;;)`: control enters the body's first block, and whatever falls
    /// off the end, and every `continue`, returns there.
    fn walk_infinite_loop(&mut self, body: &CStmt, open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        self.frames.push(Frame::Loop {
            head: LoopHead::Entry,
            breaks: Vec::new(),
            continues: Vec::new(),
        });
        let first = self.occurrences.len();
        self.force_open = true;
        let mut ends = self.walk(body, open);
        self.force_open = false;
        let Some(Frame::Loop {
            breaks, continues, ..
        }) = self.frames.pop()
        else {
            unreachable!("the loop frame pushed above is still on top");
        };
        let Some(entry) = self
            .occurrences
            .get(first)
            .map(|occurrence| occurrence.block)
        else {
            self.violations.push(Violation::EmptyLoopBody);
            return breaks;
        };
        ends.extend(continues);
        self.close(ends, Target::Block(entry));
        breaks
    }

    /// The body runs first; whatever leaves it, and every `continue`, reaches
    /// the test, which is the observed block that branches back to the entry.
    fn walk_do_while(
        &mut self,
        candidates: &[u64],
        test: Option<&CExpr>,
        body: &CStmt,
        open: Vec<OpenEnd>,
    ) -> Vec<OpenEnd> {
        self.frames.push(Frame::Loop {
            head: LoopHead::Test,
            breaks: Vec::new(),
            continues: Vec::new(),
        });
        let first = self.occurrences.len();
        self.force_open = true;
        let body_ends = self.walk(body, open);
        self.force_open = false;
        let Some(Frame::Loop {
            breaks, continues, ..
        }) = self.frames.pop()
        else {
            unreachable!("the loop frame pushed above is still on top");
        };
        let Some(entry) = self
            .occurrences
            .get(first)
            .map(|occurrence| occurrence.block)
        else {
            self.violations.push(Violation::EmptyLoopBody);
            return breaks;
        };
        let mut ends = body_ends;
        ends.extend(continues);
        let branches_to_entry = |block: &u64| self.cfg.successors(*block).contains(&entry);
        let test_block = candidates
            .iter()
            .copied()
            .find(branches_to_entry)
            .or_else(|| {
                ends.iter()
                    .filter(|(_, label)| *label == EdgeLabel::Normal)
                    .map(|(id, _)| self.occurrences[*id].block)
                    .find(branches_to_entry)
            })
            .or_else(|| candidates.first().copied());
        // Ends already inside the test block's own text are the test; the
        // others arrive at it.
        let (own, arriving): (Vec<OpenEnd>, Vec<OpenEnd>) =
            ends.into_iter().partition(|(id, label)| {
                *label == EdgeLabel::Normal
                    && Some(self.occurrences[*id].block) == test_block
                    && self.occurrences[*id].edges.is_empty()
            });
        let mut tests: Vec<usize> = own.into_iter().map(|(id, _)| id).collect();
        if !arriving.is_empty() {
            match test_block {
                Some(test_block) => {
                    let opened = self.new_occurrence(arriving, test_block);
                    tests.push(opened[0].0);
                }
                None => self.violations.push(Violation::UnownedControl {
                    kind: "do-while",
                    open: arriving.len(),
                }),
            }
        }
        for at in &tests {
            if let Some(test) = test {
                self.note_test(*at, test);
            }
            self.occurrences[*at]
                .edges
                .push((Target::Block(entry), EdgeLabel::True));
        }
        let mut exits: Vec<OpenEnd> = tests
            .into_iter()
            .map(|test| (test, EdgeLabel::False))
            .collect();
        exits.extend(breaks);
        exits
    }

    /// Whether `addr` ends in a two-way branch, as a chained case's test block does.
    fn branches(&self, addr: u64) -> bool {
        let block = self.cfg.get_block(addr);
        block.is_some_and(|block| {
            matches!(block.terminator, BlockTerminator::ConditionalBranch { .. })
        })
    }

    /// A switch an equality chain was written as (ROADMAP D474): case i's test block is entered as
    /// its `if` was, the case on the test's equal edge and the next test or the default on the other.
    fn walk_chained_switch(
        &mut self,
        mut open: Vec<OpenEnd>,
        expr: &CExpr,
        cases: &[crate::ast::SwitchCase],
        default: Option<&[CStmt]>,
    ) -> Vec<OpenEnd> {
        self.frames.push(Frame::Switch { breaks: Vec::new() });
        let (mut carry, mut values) = (Vec::new(), BTreeSet::new());
        for case in cases {
            let Some(test) = &case.test else {
                self.violations.push(Violation::SwitchValue {
                    block: open
                        .first()
                        .map_or(0, |(id, _)| self.occurrences[*id].block),
                });
                continue;
            };
            let ids = test.observation_ids();
            self.met.extend(ids.iter());
            let blocks = (ids.iter().filter(|id| !(self.edge_copy)(**id)))
                .filter_map(|id| (self.block_of)(*id))
                .collect::<Vec<_>>();
            let block = blocks.iter().copied().find(|addr| self.branches(*addr));
            let Some(block) = block.or_else(|| blocks.first().copied()) else {
                self.violations.push(Violation::UnownedControl {
                    kind: "switch",
                    open: 0,
                });
                continue;
            };
            let entered = self.enter_block(std::mem::take(&mut open), block);
            let Some(owner) = self.single_owner(&entered, "switch") else {
                continue;
            };
            let Some((equal, other)) = chained_equality(test.unobserved(), expr, &case.value)
                .filter(|(value, _, _)| values.insert(*value))
                .map(|(_, equal, other)| (equal, other))
            else {
                self.violations.push(Violation::SwitchValue { block });
                open = vec![(owner, EdgeLabel::False)];
                continue;
            };
            let mut entering = vec![(owner, equal)];
            entering.append(&mut carry);
            carry = self.walk_seq(&case.body, entering);
            open = vec![(owner, other)];
        }
        match default {
            Some(body) => {
                open.append(&mut carry);
                carry = self.walk_seq(body, open);
            }
            None => carry.append(&mut open),
        }
        let Some(Frame::Switch { breaks }) = self.frames.pop() else {
            unreachable!("the switch frame pushed above is still on top");
        };
        carry.extend(breaks);
        carry
    }

    fn walk_switch(
        &mut self,
        open: Vec<OpenEnd>,
        cases: &[crate::ast::SwitchCase],
        default: Option<&[CStmt]>,
    ) -> Vec<OpenEnd> {
        let Some(owner) = self.single_owner(&open, "switch") else {
            return Vec::new();
        };
        let block = self.occurrences[owner].block;
        self.frames.push(Frame::Switch { breaks: Vec::new() });
        let mut carry: Vec<OpenEnd> = Vec::new();
        let mut values = BTreeSet::new();
        for case in cases {
            match &case.value {
                CExpr::IntLit(value) => {
                    values.insert(*value as u64);
                }
                CExpr::UIntLit(value) => {
                    values.insert(*value);
                }
                _ => self.violations.push(Violation::SwitchValue { block }),
            }
            if case.body.is_empty() {
                continue;
            }
            let mut entering = vec![(owner, EdgeLabel::Case(std::mem::take(&mut values)))];
            entering.append(&mut carry);
            carry = self.walk_seq(&case.body, entering);
        }
        if !values.is_empty() {
            carry.push((owner, EdgeLabel::Case(std::mem::take(&mut values))));
        }
        match default {
            Some(body) => {
                let mut entering = vec![(owner, EdgeLabel::Default)];
                entering.append(&mut carry);
                carry = self.walk_seq(body, entering);
            }
            None => carry.push((owner, EdgeLabel::Default)),
        }
        let Some(Frame::Switch { breaks }) = self.frames.pop() else {
            unreachable!("the switch frame pushed above is still on top");
        };
        carry.extend(breaks);
        carry
    }
}

/// A chained case's test as `scrutinee == value` or `!=`, under the lowering's boolean cast: the
/// literal, the edge label on which the two are equal, and the other label.
fn chained_equality(
    test: &CExpr,
    scrutinee: &CExpr,
    value: &CExpr,
) -> Option<(u64, EdgeLabel, EdgeLabel)> {
    let test = match test.unobserved() {
        CExpr::Cast { expr, .. } => expr.unobserved(),
        other => other,
    };
    let CExpr::Binary { op, left, right } = test else {
        return None;
    };
    let (equal, other) = match op {
        crate::ast::BinaryOp::Eq => (EdgeLabel::True, EdgeLabel::False),
        crate::ast::BinaryOp::Ne => (EdgeLabel::False, EdgeLabel::True),
        _ => return None,
    };
    let same =
        left.clone_without_render_observations() == scrutinee.clone_without_render_observations();
    let (written, bits, _) = super::chain::case_literal(left, right)?;
    (same && written == *value.unobserved()).then_some((bits, equal, other))
}

/// The test of a `while` or `do-while`, which a `for` of the lowering does not state as one.
fn loop_test(stmt: &CStmt) -> Option<&CExpr> {
    match stmt.unobserved() {
        CStmt::While { cond, .. } | CStmt::DoWhile { cond, .. } => Some(cond),
        _ => None,
    }
}

/// A selection's test, and its two values, then and else, when it assigns a plain variable and
/// neither writes.
fn selected_arms(selection: &CExpr) -> Option<(&CExpr, [&CExpr; 2])> {
    let CExpr::Binary {
        op: crate::ast::BinaryOp::Assign,
        left,
        right,
    } = selection.unobserved()
    else {
        return None;
    };
    let CExpr::Ternary {
        cond,
        then_expr,
        else_expr,
    } = right.unobserved()
    else {
        return None;
    };
    let plain = left.observation_ids().is_empty() && matches!(left.unobserved(), CExpr::Var(_));
    (plain && right.observation_ids().is_empty() && !writes(then_expr) && !writes(else_expr))
        .then_some((cond.as_ref(), [then_expr.as_ref(), else_expr.as_ref()]))
}

/// Whether evaluating `expr` writes: one write in a selected value is a second effect the arm made.
pub(crate) fn writes(expr: &CExpr) -> bool {
    let mut writes = false;
    expr.visit(&mut |node| {
        writes |= match node {
            CExpr::Binary { op, .. } => op.writes_left_operand(),
            CExpr::Unary { op, .. } => matches!(
                op,
                crate::ast::UnaryOp::PreInc
                    | crate::ast::UnaryOp::PreDec
                    | crate::ast::UnaryOp::PostInc
                    | crate::ast::UnaryOp::PostDec
            ),
            _ => false,
        };
    });
    writes
}

/// The one block a nothing-rendering region entered here leaves through.
///
/// A single pass-through block is the degenerate case of this, and it was the
/// only case until a conditional could become an expression. When it does, the
/// arms stop rendering and the whole subtree between the branch and the join is
/// control the text no longer performs: the text reads it through exactly as it
/// reads one empty block through. A region qualifies only if every block in it
/// renders nothing, none of them leaves the function, and they all converge on
/// one block -- anything else is code that went missing rather than control that
/// was converted, and the obligation ledger is what catches that.
fn contracted_region(
    cfg: &CFG,
    count: &BTreeMap<u64, usize>,
    entry: u64,
) -> Option<(BTreeSet<u64>, u64)> {
    let mut region = BTreeSet::new();
    let mut exits = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(addr) = pending.pop() {
        if count.get(&addr).copied().unwrap_or(0) != 0 {
            exits.insert(addr);
            continue;
        }
        if !region.insert(addr) {
            continue;
        }
        cfg.get_block(addr)?;
        let successors = cfg.successors(addr);
        if successors.is_empty() {
            return None;
        }
        for next in successors {
            cfg.get_block(next)?;
            pending.push(next);
        }
    }
    let [exit] = exits.iter().copied().collect::<Vec<_>>()[..] else {
        return None;
    };
    Some((region, exit))
}

/// The edges a block's terminator promises, each target read through the
/// blocks that rendered nothing.
fn expected_edges(
    cfg: &CFG,
    addr: u64,
    contract: &dyn Fn(u64) -> Target,
) -> Vec<(Target, EdgeLabel)> {
    let Some(block) = cfg.get_block(addr) else {
        return Vec::new();
    };
    let mut edges = match &block.terminator {
        BlockTerminator::Fallthrough { next: target }
        | BlockTerminator::Branch { target }
        | BlockTerminator::Call {
            fallthrough: Some(target),
            ..
        }
        | BlockTerminator::IndirectCall {
            fallthrough: Some(target),
        } => vec![(contract(*target), EdgeLabel::Normal)],
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } if true_target == false_target => vec![(contract(*true_target), EdgeLabel::Normal)],
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        } => vec![
            (contract(*true_target), EdgeLabel::True),
            (contract(*false_target), EdgeLabel::False),
        ],
        // Leaving the function is not an edge here, as `Return` shows: only
        // the arm that stays has one, and the guard renders it as the `if`'s
        // false arm because its true arm is the transfer.
        BlockTerminator::ConditionalExit { next } => {
            vec![(contract(*next), EdgeLabel::False)]
        }
        BlockTerminator::Switch { cases, default } => {
            let mut by_target = BTreeMap::<u64, BTreeSet<u64>>::new();
            for (value, target) in cases {
                by_target.entry(*target).or_default().insert(*value);
            }
            let mut edges: Vec<_> = by_target
                .into_iter()
                .map(|(target, values)| (contract(target), EdgeLabel::Case(values)))
                .collect();
            if let Some(target) = default {
                edges.push((contract(*target), EdgeLabel::Default));
            }
            edges
        }
        BlockTerminator::IndirectBranch => cfg
            .successors(addr)
            .into_iter()
            .map(|target| (contract(target), EdgeLabel::Normal))
            .collect(),
        BlockTerminator::Call {
            fallthrough: None, ..
        }
        | BlockTerminator::IndirectCall { fallthrough: None }
        | BlockTerminator::Return
        | BlockTerminator::None => Vec::new(),
    };
    edges.sort();
    edges
}

/// A rendered `default` stands for every selector value the arms do not
/// name, so it agrees with the table when those values all reach its target
/// and the table's own default, if any, does too.
/// Whether the text converted a branch that decides no control.
///
/// Both arms of the conditional render nothing and rejoin at once, so every
/// edge leaving the block arrives at the same place and the branch chooses only
/// a value. The text says so with a conditional expression and one edge, which
/// is the same control flow the machine has: whichever way the test goes,
/// execution continues in the same block.
fn converted_conditional_agrees(
    rendered: &[(Target, EdgeLabel)],
    expected: &[(Target, EdgeLabel)],
) -> bool {
    let [(target, EdgeLabel::Normal)] = rendered else {
        return false;
    };
    expected.len() > 1
        && expected.iter().all(|(expected_target, label)| {
            expected_target == target && matches!(label, EdgeLabel::True | EdgeLabel::False)
        })
}

fn switch_edges_agree(rendered: &[(Target, EdgeLabel)], expected: &[(Target, EdgeLabel)]) -> bool {
    let is_switch = |edges: &[(Target, EdgeLabel)]| {
        !edges.is_empty()
            && edges
                .iter()
                .all(|(_, label)| matches!(label, EdgeLabel::Case(_) | EdgeLabel::Default))
    };
    if !is_switch(rendered) || !is_switch(expected) {
        return false;
    }
    let mut named = BTreeSet::new();
    let mut default_target = None;
    for (target, label) in rendered {
        match label {
            EdgeLabel::Case(values) => {
                if !expected.iter().any(|(expected_target, expected_label)| {
                    expected_target == target
                        && matches!(expected_label, EdgeLabel::Case(expected_values) if values.is_subset(expected_values))
                }) {
                    return false;
                }
                named.extend(values.iter().copied());
            }
            EdgeLabel::Default => default_target = Some(*target),
            _ => return false,
        }
    }
    let Some(default_target) = default_target else {
        return rendered == expected;
    };
    expected.iter().all(|(target, label)| match label {
        EdgeLabel::Case(values) => values
            .iter()
            .all(|value| named.contains(value) || *target == default_target),
        EdgeLabel::Default => *target == default_target,
        _ => false,
    })
}

/// The CFG as a written chain's blocks are read from it.
struct CfgMachine<'a> {
    cfg: &'a CFG,
    contract: &'a dyn Fn(u64) -> Target,
}

impl super::condition::Machine for CfgMachine<'_> {
    type Exit = Target;

    fn successors(&self, block: u64) -> Option<(u64, u64)> {
        match self.cfg.get_block(block).map(|block| &block.terminator) {
            Some(BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
            }) if true_target != false_target => Some((*true_target, *false_target)),
            _ => None,
        }
    }

    fn arrives(&self, target: u64) -> Target {
        (self.contract)(target)
    }

    fn entered_from_outside(&self, block: u64, chain: &BTreeSet<u64>) -> bool {
        (self.cfg.predecessors(block).into_iter()).any(|pred| !chain.contains(&pred))
    }
}

/// What a chain test makes of the occurrences it heads: their edges, the occurrences that were
/// refused, and the blocks the tests are written through.
#[derive(Default)]
struct ChainReading {
    edges: BTreeMap<usize, Vec<(Target, EdgeLabel)>>,
    faulted: BTreeSet<usize>,
    members: BTreeSet<u64>,
}

/// A test written as a chain stands for the blocks it tests: its head's edges are the chain's
/// exits, and the blocks past the head are written nowhere else.
fn read_chains(
    occurrences: &[Occurrence],
    chains: &BTreeMap<usize, super::condition::Written>,
    count: &BTreeMap<u64, usize>,
    machine: &CfgMachine<'_>,
    violations: &mut Vec<Violation>,
) -> ChainReading {
    let mut reading = ChainReading::default();
    for (index, written) in chains {
        let head = occurrences[*index].block;
        match super::condition::exits(head, written, machine) {
            Ok(exits) => {
                let mut edges: Vec<_> = (exits.into_iter())
                    .map(|(target, true_side)| match true_side {
                        true => (target, EdgeLabel::True),
                        false => (target, EdgeLabel::False),
                    })
                    .collect();
                edges.sort();
                reading.edges.insert(*index, edges);
            }
            Err(fault) => {
                reading.faulted.insert(*index);
                violations.push(Violation::Chain { block: head, fault });
            }
        }
        for member in written.blocks.iter().skip(1) {
            reading.members.insert(*member);
            if count.contains_key(member) {
                violations.push(Violation::Chain {
                    block: head,
                    fault: super::condition::ChainFault::Rendered { block: *member },
                });
            }
        }
    }
    reading
}

/// Compare an occurrence with `expected`, labels and all: a negation is read from the `!` over a
/// marked atom, never from swapped arms.
fn judge(
    cfg: &CFG,
    occurrence: &Occurrence,
    expected: Vec<(Target, EdgeLabel)>,
) -> Option<Violation> {
    let block = occurrence.block;
    let mut rendered = occurrence.edges.clone();
    rendered.sort();
    if rendered.is_empty() {
        let continues = (expected.iter()).any(|(target, _)| matches!(target, Target::Block(_)));
        return match (continues, occurrence.returned) {
            (false, _) => None,
            (true, true) => Some(Violation::ReturnWhereMachineContinues { block }),
            (true, false) => Some(Violation::FallsOffEnd { block }),
        };
    }
    if rendered == expected {
        return None;
    }
    if switch_edges_agree(&rendered, &expected)
        || converted_conditional_agrees(&rendered, &expected)
    {
        return None;
    }
    let terminator = cfg.get_block(block).map(|block| &block.terminator);
    Some(match terminator {
        Some(
            BlockTerminator::None
            | BlockTerminator::Call {
                fallthrough: None, ..
            }
            | BlockTerminator::IndirectCall { fallthrough: None },
        ) => Violation::TerminalFallthrough {
            block,
            to: rendered[0].0,
        },
        Some(BlockTerminator::IndirectBranch) if expected.is_empty() => {
            Violation::UnresolvedIndirect {
                block,
                to: rendered[0].0,
            }
        }
        _ => Violation::EdgeMismatch {
            block,
            rendered,
            expected,
        },
    })
}

/// A block's text is copied whole: every statement the placement wrote for a block is written, and as
/// often as any other of it. `met` holds each marker a statement is written under; O(statements).
fn statement_violations(placed: &dyn Placed, met: &[RenderObservationId]) -> Vec<Violation> {
    let mut found = vec![0usize; placed.written()];
    for id in met {
        if let Some(slot) =
            (placed.statement_of(*id)).and_then(|at| found.get_mut(at.index() as usize))
        {
            *slot += 1;
        }
    }
    let mut span = BTreeMap::<u64, (usize, usize)>::new();
    for (at, found) in found.into_iter().enumerate() {
        if let Some(block) = placed.block_of(RenderObservationId::from_dense_index(at)) {
            let (fewest, most) = span.entry(block).or_insert((found, found));
            *fewest = (*fewest).min(found);
            *most = (*most).max(found);
        }
    }
    (span.into_iter())
        .filter(|(_, (fewest, most))| fewest != most || *most == 0)
        .map(|(block, (fewest, most))| Violation::Statement {
            block,
            fewest,
            most,
        })
        .collect()
}

/// Read the body back as a control graph and compare it with the CFG.
///
/// `placed` says which block an observed statement was emitted for and which statement the placement
/// wrote it as, and `label_block` which block a label names; neither is derived here.
pub(crate) fn certify<R: Into<StatementRole>>(
    body: &CStmt,
    cfg: &CFG,
    dom: &DomTree,
    entry: u64,
    placed: &dyn Placed,
    label_block: &dyn Fn(&str) -> Option<u64>,
    role: &dyn Fn(&CStmt) -> R,
) -> ControlCertificate {
    let block_of = |id: RenderObservationId| placed.block_of(id);
    let edge_copy = |id: RenderObservationId| placed.edge_copy(id);
    let mut walker = Walker {
        cfg,
        dom,
        block_of: &block_of,
        label_block,
        role: &|stmt| role(stmt).into(),
        occurrences: Vec::new(),
        frames: Vec::new(),
        violations: Vec::new(),
        first_block: None,
        force_open: true,
        chains: BTreeMap::new(),
        met: Vec::new(),
        edge_copy: &edge_copy,
    };
    let ends = walker.walk(body, Vec::new());
    for (id, _) in ends {
        walker.occurrences[id].fell_off_end = true;
    }
    let Walker {
        occurrences,
        mut violations,
        first_block,
        chains,
        mut met,
        ..
    } = walker;
    let mut count = BTreeMap::<u64, usize>::new();
    for occurrence in &occurrences {
        *count.entry(occurrence.block).or_default() += 1;
    }
    // A chain's tests past its head are written as atoms of the head's test, not as statements.
    let members: BTreeSet<_> = (chains.values())
        .flat_map(|written| written.marks.iter().skip(1).flatten().copied())
        .collect();
    met.extend(members);
    violations.extend(statement_violations(placed, &met));
    // A block that rendered nothing and only passes control on is read
    // through, the way the text does; the blocks read through are counted.
    let contracted = std::cell::RefCell::new(BTreeSet::<u64>::new());
    let contract = |mut addr: u64| -> Target {
        if cfg.get_block(addr).is_none() {
            return Target::External;
        }
        let mut seen = BTreeSet::new();
        while count.get(&addr).copied().unwrap_or(0) == 0 {
            if !seen.insert(addr) {
                break;
            }
            let Some((region, exit)) = contracted_region(cfg, &count, addr) else {
                break;
            };
            contracted.borrow_mut().extend(region);
            addr = exit;
            if cfg.get_block(addr).is_none() {
                return Target::External;
            }
        }
        Target::Block(addr)
    };
    // The text starts at the root. The entry-edge block in front of a loop at
    // the function's first instruction is the graph's own and renders nothing
    // where no copy lands on its edge, so there the text starts where it is
    // read through to.
    let starts = if cfg.has_entry_edge() && entry == cfg.entry {
        contract(entry)
    } else {
        Target::Block(entry)
    };
    if first_block.map(Target::Block) != Some(starts) {
        violations.push(Violation::EntryNotFirst { first: first_block });
    }

    let machine = CfgMachine {
        cfg,
        contract: &contract,
    };
    let ChainReading {
        edges: chain_edges,
        faulted: chain_faulted,
        members: chain_members,
    } = read_chains(&occurrences, &chains, &count, &machine, &mut violations);

    for (index, occurrence) in occurrences.iter().enumerate() {
        if chain_faulted.contains(&index) {
            continue;
        }
        let expected = match chain_edges.get(&index) {
            Some(edges) => edges.clone(),
            None => expected_edges(cfg, occurrence.block, &contract),
        };
        violations.extend(judge(cfg, occurrence, expected));
    }

    let mut contracted = contracted.into_inner();
    contracted.extend(chain_members);
    let mut unreachable_missing = 0;
    let mut blocks = 0;
    for addr in cfg.block_addrs() {
        blocks += 1;
        if count.contains_key(&addr) || contracted.contains(&addr) {
            continue;
        }
        if addr != entry && cfg.predecessors(addr).is_empty() {
            unreachable_missing += 1;
        } else {
            violations.push(Violation::MissingBlock(addr));
        }
    }
    let duplicated = count
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(addr, _)| *addr)
        .collect();
    ControlCertificate {
        violations,
        occurrences: occurrences.len(),
        blocks,
        duplicated,
        contracted: contracted.len(),
        unreachable_missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::SwitchCase;
    use crate::ast::test_render_observation_id;
    use crate::structure::support::{ByBlock, at, branch, cfg, cond, cond_branch, expr};

    fn run(body: CStmt, cfg: &CFG, entry: u64, labels: &[(&str, u64)]) -> ControlCertificate {
        run_selecting(body, cfg, entry, labels, &[])
    }

    /// The certificate where the statements observed under `selects` are selections.
    fn run_selecting(
        body: CStmt,
        cfg: &CFG,
        entry: u64,
        labels: &[(&str, u64)],
        selects: &[RenderObservationId],
    ) -> ControlCertificate {
        let label_block = |name: &str| {
            labels
                .iter()
                .find(|(label, _)| *label == name)
                .map(|(_, block)| *block)
        };
        certify(
            &body,
            cfg,
            &DomTree::compute(cfg),
            entry,
            &ByBlock,
            &label_block,
            &|stmt| match stmt.observation_ids().iter().any(|id| selects.contains(id)) {
                true => StatementRole::Selects,
                false => StatementRole::Plain,
            },
        )
    }

    #[test]
    fn diamond_with_both_arms_is_certified() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(0x10, expr()),
            at(
                0x10,
                CStmt::if_stmt(cond(), at(0x20, expr()), Some(at(0x30, expr()))),
            ),
            at(0x40, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.occurrences, 4);
        assert_eq!(certificate.contracted, 0);
    }

    #[test]
    fn an_empty_pass_through_block_is_read_through_and_a_branching_one_is_missing() {
        let pass_through = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(0x10, CStmt::if_stmt(cond(), at(0x20, expr()), None)),
            at(0x40, CStmt::Return(None)),
        ]);
        let certificate = run(body.clone(), &pass_through, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.contracted, 1);

        let branching = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, cond_branch(0x40, 0x20)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let certificate = run(body, &branching, 0x10, &[]);
        assert!(
            certificate
                .violations
                .contains(&Violation::MissingBlock(0x30)),
            "{certificate}"
        );
    }

    #[test]
    fn a_while_loop_certifies_its_body_edge_exit_and_back_edge() {
        let blocks = |true_target, false_target| {
            cfg(
                0x10,
                &[
                    (0x10, branch(0x20)),
                    (0x20, cond_branch(true_target, false_target)),
                    (0x30, branch(0x20)),
                    (0x40, BlockTerminator::Return),
                ],
            )
        };
        let body = CStmt::Block(vec![
            at(0x10, expr()),
            at(0x20, CStmt::while_loop(cond(), at(0x30, expr()))),
            at(0x40, CStmt::Return(None)),
        ]);
        let straight = run(body.clone(), &blocks(0x30, 0x40), 0x10, &[]);
        assert!(straight.ok(), "{straight}");
        // A test the text does not mark cannot say it is negated, so the swapped edges are refused.
        let swapped = run(body, &blocks(0x40, 0x30), 0x10, &[]);
        assert!(
            swapped
                .violations
                .iter()
                .any(|violation| matches!(violation, Violation::EdgeMismatch { block: 0x20, .. })),
            "{swapped}"
        );
    }

    /// The loop whose test block 0x20 is marked on its one atom, which says which edge stays.
    fn marked_while(test: impl Fn(CExpr) -> CExpr) -> CStmt {
        let atom = CExpr::observe_one(test_render_observation_id(0x20), cond());
        CStmt::Block(vec![
            at(0x10, expr()),
            at(0x20, CStmt::while_loop(test(atom), at(0x30, expr()))),
            at(0x40, CStmt::Return(None)),
        ])
    }

    fn loop_blocks(true_target: u64, false_target: u64) -> CFG {
        cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(true_target, false_target)),
                (0x30, branch(0x20)),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    #[test]
    fn a_loop_test_of_one_marked_atom_is_read_with_the_polarity_it_is_written() {
        let not = |expr| CExpr::unary(crate::ast::UnaryOp::Not, expr);
        // The machine stays in the loop when the test holds: the atom is the loop's test.
        let stays = run(
            marked_while(|atom| atom),
            &loop_blocks(0x30, 0x40),
            0x10,
            &[],
        );
        assert!(stays.ok(), "{stays}");
        // It leaves when the test holds: the atom alone would stay when the machine leaves.
        let leaves = loop_blocks(0x40, 0x30);
        let wrong = run(marked_while(|atom| atom), &leaves, 0x10, &[]);
        assert!(
            wrong
                .violations
                .iter()
                .any(|violation| matches!(violation, Violation::EdgeMismatch { block: 0x20, .. })),
            "{wrong}"
        );
        // ... and the negated atom stays when the machine does.
        let right = run(marked_while(not), &leaves, 0x10, &[]);
        assert!(right.ok(), "{right}");
        let again = run(marked_while(not), &loop_blocks(0x30, 0x40), 0x10, &[]);
        assert!(!again.ok(), "{again}");
    }

    /// D474: a switch written for an equality chain is entered as the chain's `if`s were, and a
    /// case whose value is not its test's literal is a violation.
    #[test]
    fn a_chained_switch_case_holds_its_tests_literal() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x40, 0x20)),
                (0x20, cond_branch(0x50, 0x30)),
                (0x30, cond_branch(0x60, 0x70)),
                (0x40, branch(0x80)),
                (0x50, branch(0x80)),
                (0x60, branch(0x80)),
                (0x70, branch(0x80)),
                (0x80, BlockTerminator::Return),
            ],
        );
        let x = crate::symbol::SymbolTable::new().declare_or_reuse("x");
        let word = |expr: CExpr| CExpr::cast(crate::ast::CType::uint(32), expr);
        let chained = |values: [u64; 3]| {
            let case = |(block, test, value): (u64, u64, u64), arm: u64| SwitchCase {
                value: CExpr::UIntLit(value),
                body: vec![at(arm, expr()), CStmt::Break],
                test: Some(CExpr::observe_all(
                    [test_render_observation_id(u32::try_from(block).unwrap())],
                    CExpr::Binary {
                        op: crate::ast::BinaryOp::Eq,
                        left: Box::new(word(CExpr::Var(x))),
                        right: Box::new(word(CExpr::UIntLit(test))),
                    },
                )),
            };
            CStmt::Block(vec![
                CStmt::Switch {
                    expr: word(CExpr::Var(x)),
                    cases: vec![
                        case((0x10, 1, values[0]), 0x40),
                        case((0x20, 2, values[1]), 0x50),
                        case((0x30, 3, values[2]), 0x60),
                    ],
                    default: Some(vec![at(0x70, expr())]),
                },
                at(0x80, CStmt::Return(None)),
            ])
        };
        let certificate = run(chained([1, 2, 3]), &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        let wrong = run(chained([1, 5, 3]), &cfg, 0x10, &[]);
        assert!(
            wrong
                .violations
                .contains(&Violation::SwitchValue { block: 0x20 }),
            "{wrong}"
        );
    }

    #[test]
    fn a_do_while_tests_at_its_last_block_and_branches_back_to_its_entry() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, branch(0x30)),
                (0x30, cond_branch(0x20, 0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(0x10, expr()),
            at(
                0x30,
                CStmt::DoWhile {
                    body: Box::new(CStmt::Block(vec![at(0x20, expr()), at(0x30, expr())])),
                    cond: cond(),
                },
            ),
            at(0x40, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.occurrences, 4);
        assert_eq!(certificate.contracted, 0);
    }

    #[test]
    fn a_terminal_block_whose_text_continues_is_named() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, BlockTerminator::None),
                (0x20, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![at(0x10, expr()), at(0x20, CStmt::Return(None))]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert_eq!(
            certificate.violations,
            vec![Violation::TerminalFallthrough {
                block: 0x10,
                to: Target::Block(0x20)
            }]
        );
    }

    #[test]
    fn a_switch_groups_its_values_and_falls_into_its_default() {
        let cfg = cfg(
            0x10,
            &[
                (
                    0x10,
                    BlockTerminator::Switch {
                        cases: vec![(1, 0x20), (2, 0x20), (3, 0x30)],
                        default: Some(0x40),
                    },
                ),
                (0x20, branch(0x50)),
                (0x30, branch(0x50)),
                (0x40, branch(0x50)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let case = |value: i64, body: Vec<CStmt>| SwitchCase {
            value: CExpr::IntLit(value),
            body,
            test: None,
        };
        let body = CStmt::Block(vec![
            at(
                0x10,
                CStmt::Switch {
                    expr: cond(),
                    cases: vec![
                        case(1, Vec::new()),
                        case(2, vec![at(0x20, expr()), CStmt::Break]),
                        case(3, vec![at(0x30, expr()), CStmt::Break]),
                    ],
                    default: Some(vec![at(0x40, expr())]),
                },
            ),
            at(0x50, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
    }

    #[test]
    fn a_rendered_default_stands_for_the_table_values_the_arms_omit() {
        let cfg = cfg(
            0x10,
            &[
                (
                    0x10,
                    BlockTerminator::Switch {
                        cases: vec![(1, 0x20), (2, 0x30), (3, 0x30)],
                        default: None,
                    },
                ),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(
                0x10,
                CStmt::Switch {
                    expr: cond(),
                    cases: vec![SwitchCase {
                        value: CExpr::IntLit(1),
                        body: vec![at(0x20, expr()), CStmt::Break],
                        test: None,
                    }],
                    default: Some(vec![at(0x30, expr())]),
                },
            ),
            at(0x40, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
    }

    #[test]
    fn a_statement_of_a_pass_through_block_opens_no_occurrence() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, branch(0x30)),
                (0x30, BlockTerminator::Return),
            ],
        );
        // The merge write the latch carries is observed under the block it
        // was normalised for, which is not where the text put it.
        let body = CStmt::Block(vec![
            at(0x10, expr()),
            at(0x30, expr()),
            at(0x20, expr()),
            at(0x30, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.occurrences, 3);
    }

    #[test]
    fn a_merge_rendered_as_plain_statements_after_the_if_is_its_own_position() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(
                0x10,
                CStmt::if_stmt(cond(), at(0x20, expr()), Some(at(0x30, expr()))),
            ),
            at(0x40, expr()),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.occurrences, 4);
    }

    #[test]
    fn a_goto_reaches_the_label_of_its_block() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x30, 0x20)),
                (0x20, branch(0x30)),
                (0x30, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            at(0x10, CStmt::if_stmt(cond(), CStmt::Goto("L1".into()), None)),
            at(0x20, expr()),
            CStmt::Label("L1".into()),
            at(0x30, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[("L1", 0x30)]);
        assert!(certificate.ok(), "{certificate}");
    }

    #[test]
    fn a_return_where_the_machine_continues_is_named() {
        let cfg = cfg(
            0x10,
            &[(0x10, branch(0x20)), (0x20, BlockTerminator::Return)],
        );
        let body = CStmt::Block(vec![
            at(0x10, CStmt::Return(None)),
            at(0x20, CStmt::Return(None)),
        ]);
        let certificate = run(body, &cfg, 0x10, &[]);
        assert_eq!(
            certificate.violations,
            vec![Violation::ReturnWhereMachineContinues { block: 0x10 }]
        );
    }

    /// `x = c ? a : b` for the test at 0x10, each value observed under its arm's block, if any.
    fn selection(
        x: CExpr,
        then_arm: (Option<u64>, CExpr),
        else_arm: (Option<u64>, CExpr),
    ) -> CStmt {
        let arm = |(block, value): (Option<u64>, CExpr)| match block {
            Some(block) => CExpr::observe_one(
                test_render_observation_id(u32::try_from(block).expect("small address")),
                value,
            ),
            None => value,
        };
        let ternary = CExpr::Ternary {
            cond: Box::new(cond()),
            then_expr: Box::new(arm(then_arm)),
            else_expr: Box::new(arm(else_arm)),
        };
        at(0x10, CStmt::Expr(CExpr::assign(x, ternary)))
    }

    fn selects() -> Vec<RenderObservationId> {
        vec![test_render_observation_id(0x10)]
    }

    fn diamond() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    #[test]
    fn a_selection_is_its_test_s_if_with_each_arm_s_block_entered_on_its_edge() {
        // The triangle `test; je join; mov eax, 5; join:`: the taken arm is the edge itself.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x40, 0x20)),
                (0x20, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = symbols.declare_or_reuse("x");
        let assign = |value| CStmt::Expr(CExpr::assign(CExpr::var(x), CExpr::IntLit(value)));
        let arms = CStmt::if_stmt(
            cond(),
            CStmt::Block(vec![assign(0x1000)]),
            Some(CStmt::Block(vec![at(0x20, CStmt::Empty), assign(5)])),
        );
        let mut body = CStmt::Block(vec![at(0x10, arms), at(0x40, CStmt::Return(None))]);
        let mut selections = BTreeSet::new();
        crate::structure::shape::select(
            &mut body,
            &|_, value| value,
            &|id| Some(u64::from(id.index())),
            &mut selections,
        );
        assert_eq!(selections.into_iter().collect::<Vec<_>>(), selects());
        let CStmt::Block(stmts) = &body else {
            panic!("a block");
        };
        assert!(matches!(stmts[0].unobserved(), CStmt::Expr(_)), "{body:?}");
        let certificate = run_selecting(body, &cfg, 0x10, &[], &selects());
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(certificate.occurrences, 3);
        assert_eq!(certificate.contracted, 0);
    }

    #[test]
    fn a_selection_whose_arms_assign_two_variables_or_make_two_statements_is_refused() {
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = CExpr::var(symbols.declare_or_reuse("x"));
        let y = CExpr::var(symbols.declare_or_reuse("y"));
        let join = at(0x40, CStmt::Return(None));
        // The then arm assigns `y`, which the selection could only spell as a write inside its value.
        let two_variables = CStmt::Block(vec![
            selection(
                x.clone(),
                (Some(0x20), CExpr::assign(y.clone(), CExpr::IntLit(1))),
                (Some(0x30), CExpr::IntLit(2)),
            ),
            join.clone(),
        ]);
        let certificate = run_selecting(two_variables, &diamond(), 0x10, &[], &selects());
        assert_eq!(
            certificate.violations.first(),
            Some(&Violation::Selection { block: 0x10 }),
            "{certificate}"
        );
        // The then arm's block has a second statement, so its text occurs twice.
        let two_statements = CStmt::Block(vec![
            selection(
                x.clone(),
                (Some(0x20), CExpr::IntLit(1)),
                (Some(0x30), CExpr::IntLit(2)),
            ),
            at(
                0x20,
                CStmt::Expr(CExpr::assign(y.clone(), CExpr::IntLit(3))),
            ),
            join,
        ]);
        let certificate = run_selecting(two_statements, &diamond(), 0x10, &[], &selects());
        assert!(!certificate.ok(), "{certificate}");
        assert_eq!(certificate.duplicated, vec![0x20]);
        // Neither shape is one the stage writes: it leaves both as `if`s.
        let assign = |target: &CExpr, value| {
            CStmt::Expr(CExpr::assign(target.clone(), CExpr::IntLit(value)))
        };
        for (then_arm, else_arm) in [
            (vec![assign(&y, 1)], vec![assign(&x, 2)]),
            (vec![assign(&x, 1), assign(&y, 3)], vec![assign(&x, 2)]),
            // Empty markers of two blocks: the certificate enters one block per arm.
            (
                vec![assign(&x, 1)],
                vec![
                    at(0x20, CStmt::Empty),
                    at(0x30, CStmt::Empty),
                    assign(&x, 2),
                ],
            ),
        ] {
            let mut stmt = at(
                0x10,
                CStmt::if_stmt(cond(), CStmt::Block(then_arm), Some(CStmt::Block(else_arm))),
            );
            let mut selections = BTreeSet::new();
            crate::structure::shape::select(
                &mut stmt,
                &|_, value| value,
                &|id| Some(u64::from(id.index())),
                &mut selections,
            );
            assert!(selections.is_empty());
            assert!(matches!(stmt.unobserved(), CStmt::If { .. }), "{stmt:?}");
        }
    }

    // -- Condition chains.

    /// `if (a && b) { X } else { Y }` over blocks 0x10 and 0x20, with 0x30 and 0x40 behind it.
    fn chain_cfg() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x40)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, BlockTerminator::Return),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    /// An atom of a chain: the block's marker on its test.
    fn atom(block: u32) -> CExpr {
        CExpr::observe_one(
            test_render_observation_id(block),
            CExpr::IntLit(i64::from(block)),
        )
    }

    fn both(left: CExpr, right: CExpr) -> CExpr {
        CExpr::binary(crate::ast::BinaryOp::And, left, right)
    }

    /// The text of `chain_cfg` with `test` as the head's test, and `x` entered on its true arm.
    fn chain_text(test: CExpr, x: u64) -> CStmt {
        let enter = |block: u64| at(block, CStmt::Return(None));
        let (yes, no) = match x {
            0x30 => (enter(0x30), CStmt::Goto("L".to_owned())),
            _ => (CStmt::Goto("L".to_owned()), enter(0x30)),
        };
        CStmt::Block(vec![
            at(0x10, CStmt::if_stmt(test, yes, Some(no))),
            CStmt::Block(vec![
                CStmt::Label("L".to_owned()),
                at(0x40, CStmt::Return(None)),
            ]),
        ])
    }

    #[test]
    fn a_condition_chain_is_certified_by_its_exit_function() {
        let body = chain_text(both(atom(0x10), atom(0x20)), 0x30);
        let certificate = run(body, &chain_cfg(), 0x10, &[("L", 0x40)]);
        assert!(certificate.ok(), "{certificate}");
        // The second test is read through, as an empty block is, and counted.
        assert_eq!(certificate.occurrences, 3);
        assert_eq!(certificate.contracted, 1);
    }

    #[test]
    fn a_chain_whose_second_test_goes_back_to_its_head_has_the_head_as_an_exit() {
        // Both tests hold and the loop goes round again; either fails to 0x30.
        let looped = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, cond_branch(0x10, 0x30)),
                (0x30, BlockTerminator::Return),
            ],
        );
        let text = |stay: CStmt, leave: CStmt| {
            let test = CStmt::if_stmt(both(atom(0x10), atom(0x20)), stay, Some(leave));
            let body = CStmt::Block(vec![at(0x10, test)]);
            CStmt::Block(vec![
                CStmt::For {
                    init: None,
                    cond: None,
                    update: None,
                    body: Box::new(body),
                },
                at(0x30, CStmt::Return(None)),
            ])
        };
        let right = run(text(CStmt::Continue, CStmt::Break), &looped, 0x10, &[]);
        assert!(right.ok(), "{right}");
        let swapped = run(text(CStmt::Break, CStmt::Continue), &looped, 0x10, &[]);
        assert!(!swapped.ok(), "{swapped}");
    }

    #[test]
    fn a_chain_taking_the_other_exit_is_not_the_machine_s_even_with_the_test_negated() {
        // `a && b` reaching 0x40 on its true arm: the machine reaches it when it is false.
        let wrong = chain_text(both(atom(0x10), atom(0x20)), 0x40);
        let certificate = run(wrong, &chain_cfg(), 0x10, &[("L", 0x40)]);
        assert!(!certificate.ok(), "{certificate}");
        // Negated, the same arms are right.
        let negated = CExpr::unary(crate::ast::UnaryOp::Not, both(atom(0x10), atom(0x20)));
        let right = run(
            chain_text(negated, 0x40),
            &chain_cfg(),
            0x10,
            &[("L", 0x40)],
        );
        assert!(right.ok(), "{right}");
    }

    #[test]
    fn a_chain_whose_test_is_not_the_blocks_function_is_different() {
        // `a || b` over blocks that make a conjunction.
        let or = CExpr::binary(crate::ast::BinaryOp::Or, atom(0x10), atom(0x20));
        let certificate = run(chain_text(or, 0x30), &chain_cfg(), 0x10, &[("L", 0x40)]);
        // The chain is the one fault: its head is not also read as a block with edges of its own.
        assert!(
            matches!(
                certificate.violations.as_slice(),
                [Violation::Chain {
                    fault: super::super::condition::ChainFault::Different,
                    ..
                }]
            ),
            "{certificate} {:?}",
            certificate.violations
        );
    }

    #[test]
    fn a_chain_may_not_test_a_block_the_text_also_writes() {
        let body = CStmt::Block(vec![
            at(0x20, expr()),
            chain_text(both(atom(0x10), atom(0x20)), 0x30),
        ]);
        let certificate = run(body, &chain_cfg(), 0x20, &[("L", 0x40)]);
        assert!(
            certificate.violations.iter().any(|violation| matches!(
                violation,
                Violation::Chain {
                    fault: super::super::condition::ChainFault::Rendered { block: 0x20 },
                    ..
                }
            )),
            "{:?}",
            certificate.violations
        );
    }

    #[test]
    fn a_chain_block_that_is_entered_from_outside_or_does_not_branch_is_refused() {
        use super::super::condition::ChainFault;
        let body = || chain_text(both(atom(0x10), atom(0x20)), 0x30);
        let fault = |certificate: &ControlCertificate| {
            certificate
                .violations
                .iter()
                .find_map(|violation| match violation {
                    Violation::Chain { fault, .. } => Some(*fault),
                    _ => None,
                })
        };
        // 0x50 also reaches 0x20.
        let entered = cfg(
            0x50,
            &[
                (0x50, cond_branch(0x10, 0x20)),
                (0x10, cond_branch(0x20, 0x40)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, BlockTerminator::Return),
                (0x40, BlockTerminator::Return),
            ],
        );
        let text = CStmt::Block(vec![
            at(
                0x50,
                CStmt::if_stmt(CExpr::IntLit(1), CStmt::Empty, Some(CStmt::Empty)),
            ),
            chain_text(both(atom(0x10), atom(0x20)), 0x30),
        ]);
        let outside = run(text, &entered, 0x50, &[("L", 0x40)]);
        assert_eq!(fault(&outside), Some(ChainFault::Outside { block: 0x20 }));
        // A block that does not branch two ways is no test.
        let straight = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x40)),
                (0x20, branch(0x30)),
                (0x30, BlockTerminator::Return),
                (0x40, BlockTerminator::Return),
            ],
        );
        let plain = run(body(), &straight, 0x10, &[("L", 0x40)]);
        assert_eq!(
            fault(&plain),
            Some(ChainFault::NotConditional { block: 0x20 })
        );
    }

    #[test]
    fn a_test_whose_atoms_are_not_all_marked_is_not_read_as_a_chain() {
        use super::super::condition::ChainFault;
        // The head's test is bare: its polarity could not be told from the expression's own.
        let bare = both(CExpr::IntLit(1), atom(0x20));
        let certificate = run(chain_text(bare, 0x30), &chain_cfg(), 0x10, &[("L", 0x40)]);
        assert!(
            certificate.violations.iter().any(|violation| matches!(
                violation,
                Violation::Chain {
                    fault: ChainFault::Shape,
                    ..
                }
            )),
            "{:?}",
            certificate.violations
        );
    }

    #[test]
    fn a_selection_may_test_a_chain() {
        // `x = (a && b) ? 1 : 2` over the chain 0x10, 0x20, with an arm block under each value.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x40)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, branch(0x50)),
                (0x40, branch(0x50)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = symbols.declare_or_reuse("x");
        let value = |block: u32, value: i64| {
            CExpr::observe_one(test_render_observation_id(block), CExpr::IntLit(value))
        };
        let ternary = CExpr::Ternary {
            cond: Box::new(both(atom(0x10), atom(0x20))),
            then_expr: Box::new(value(0x30, 1)),
            else_expr: Box::new(value(0x40, 2)),
        };
        let body = CStmt::Block(vec![
            at(0x10, CStmt::Expr(CExpr::assign(CExpr::var(x), ternary))),
            at(0x50, CStmt::Return(None)),
        ]);
        let certificate = run_selecting(body, &cfg, 0x10, &[], &selects());
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
        assert_eq!(certificate.contracted, 1);
    }

    // -- Statements: a block's text is copied whole.

    use crate::ast::RenderObservationId;
    use crate::structure::shape::Occurrences;

    /// The markers a placement wrote: marker `n` is a statement of `blocks[n]`, and of an instruction
    /// unless `copies` names it (an edge's copy).
    fn written(blocks: &[u64], copies: &[usize]) -> Occurrences {
        let addresses = (blocks.iter().enumerate())
            .map(|(at, block)| (!copies.contains(&at)).then_some(*block))
            .collect();
        Occurrences::new(blocks.to_vec(), addresses)
    }

    fn id(index: usize) -> RenderObservationId {
        RenderObservationId::from_dense_index(index)
    }

    fn mark(index: usize, stmt: CStmt) -> CStmt {
        CStmt::observe_one(id(index), stmt)
    }

    fn certify_written(
        body: &CStmt,
        cfg: &CFG,
        entry: u64,
        placed: &Occurrences,
    ) -> ControlCertificate {
        let labels = |name: &str| (name == "L").then_some(0x40);
        let dom = DomTree::compute(cfg);
        let role = |_: &CStmt| StatementRole::Plain;
        certify(body, cfg, &dom, entry, placed, &labels, &role)
    }

    /// 0x10 tests; 0x20 and 0x30 each go on to the return 0x40.
    fn two_ways_to_a_return() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    /// The text of 0x40 (marker 3 a statement, marker 4 its return) at the end of the true arm, and the
    /// `keep` of it as copies at the end of the false arm.
    fn return_in_both_arms(placed: &mut Occurrences, keep: &[usize]) -> CStmt {
        let text = |at: usize| match at {
            4 => CStmt::Return(None),
            _ => expr(),
        };
        let then_arm = vec![mark(1, expr()), mark(3, text(3)), mark(4, text(4))];
        let mut else_arm = vec![mark(2, expr())];
        for at in keep {
            else_arm.push(CStmt::observe_one(placed.copy_of(id(*at)), text(*at)));
        }
        let test = CStmt::if_stmt(cond(), CStmt::Block(then_arm), Some(CStmt::Block(else_arm)));
        mark(0, test)
    }

    #[test]
    fn a_block_copied_to_a_second_place_is_written_whole_there() {
        let mut placed = written(&[0x10, 0x20, 0x30, 0x40, 0x40], &[]);
        let body = return_in_both_arms(&mut placed, &[3, 4]);
        let certificate = certify_written(&body, &two_ways_to_a_return(), 0x10, &placed);
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
    }

    #[test]
    fn a_copy_that_leaves_out_a_statement_of_its_block_is_refused_though_its_edges_hold() {
        // The second copy of 0x40 is entered and returns as the machine does, but lacks its first
        // statement: every edge is right and only what the text says of the block is wrong.
        let mut placed = written(&[0x10, 0x20, 0x30, 0x40, 0x40], &[]);
        let body = return_in_both_arms(&mut placed, &[4]);
        let certificate = certify_written(&body, &two_ways_to_a_return(), 0x10, &placed);
        assert_eq!(
            certificate.violations,
            [Violation::Statement {
                block: 0x40,
                fewest: 1,
                most: 2
            }],
            "{certificate}"
        );
    }

    /// 0x10 tests and each side returns; each edge carries one copy of 0x10 (markers 1 and 2), written
    /// where `shown` says.
    fn copies_on_the_edges(shown: [bool; 2]) -> (Occurrences, CStmt, CFG) {
        let placed = written(&[0x10, 0x10, 0x10, 0x20, 0x30], &[1, 2]);
        let arm = |copy: usize, shown: bool, ret: usize| {
            let mut stmts = Vec::new();
            if shown {
                stmts.push(mark(copy, expr()));
            }
            stmts.push(mark(ret, CStmt::Return(None)));
            CStmt::Block(stmts)
        };
        let test = CStmt::if_stmt(cond(), arm(1, shown[0], 3), Some(arm(2, shown[1], 4)));
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, BlockTerminator::Return),
                (0x30, BlockTerminator::Return),
            ],
        );
        (placed, mark(0, test), cfg)
    }

    #[test]
    fn an_edge_s_copy_is_a_statement_of_the_block_it_leaves_and_no_place_of_its_own() {
        let (placed, body, cfg) = copies_on_the_edges([true, true]);
        let certificate = certify_written(&body, &cfg, 0x10, &placed);
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
        // One edge's copy gone: every edge is the machine's, and 0x10 has lost a statement.
        let (placed, body, cfg) = copies_on_the_edges([true, false]);
        let certificate = certify_written(&body, &cfg, 0x10, &placed);
        assert_eq!(
            certificate.violations,
            [Violation::Statement {
                block: 0x10,
                fewest: 0,
                most: 1
            }],
            "{certificate}"
        );
    }

    /// `a && b` over 0x10 and 0x20 as the chain writes it: the head's statement carries marker 0 and its
    /// atom a copy of it, and 0x20's marker rides on the second atom.
    fn chain_over_two_blocks(placed: &mut Occurrences) -> CStmt {
        let atom = |marker: RenderObservationId, value: i64| {
            CExpr::observe_one(marker, CExpr::IntLit(value))
        };
        let test = both(atom(placed.copy_of(id(0)), 1), atom(id(1), 2));
        let taken = mark(2, CStmt::Return(None));
        CStmt::Block(vec![
            mark(
                0,
                CStmt::if_stmt(test, taken, Some(CStmt::Goto("L".to_owned()))),
            ),
            CStmt::Block(vec![
                CStmt::Label("L".to_owned()),
                mark(3, CStmt::Return(None)),
            ]),
        ])
    }

    #[test]
    fn a_chain_s_tests_past_its_head_are_statements_of_their_blocks() {
        let mut placed = written(&[0x10, 0x20, 0x30, 0x40], &[]);
        let body = chain_over_two_blocks(&mut placed);
        let certificate = certify_written(&body, &chain_cfg(), 0x10, &placed);
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
        // A second statement of 0x20 (marker 4) that the chain does not carry is a statement lost.
        let mut placed = written(&[0x10, 0x20, 0x30, 0x40, 0x20], &[]);
        let body = chain_over_two_blocks(&mut placed);
        let certificate = certify_written(&body, &chain_cfg(), 0x10, &placed);
        assert_eq!(
            certificate.violations,
            [Violation::Statement {
                block: 0x20,
                fewest: 0,
                most: 1
            }],
            "{certificate}"
        );
    }

    #[test]
    fn the_values_of_a_selection_carry_the_statements_of_their_blocks() {
        // `x = c ? 0x1000 : 5` for a triangle: the values carry the test block's copy (marker 1) and block 0x20
        // with its copy (markers 2, 3). Each block is written whole, though none stands at a statement.
        let placed = written(&[0x10, 0x10, 0x20, 0x20, 0x40], &[1, 3]);
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x40, 0x20)),
                (0x20, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = symbols.declare_or_reuse("x");
        let ternary = CExpr::Ternary {
            cond: Box::new(cond()),
            then_expr: Box::new(CExpr::observe_all([id(1)], CExpr::IntLit(0x1000))),
            else_expr: Box::new(CExpr::observe_all([id(2), id(3)], CExpr::IntLit(5))),
        };
        let selection = mark(0, CStmt::Expr(CExpr::assign(CExpr::var(x), ternary)));
        let body = CStmt::Block(vec![selection, mark(4, CStmt::Return(None))]);
        let role = |stmt: &CStmt| match stmt.observation_ids().contains(&id(0)) {
            true => StatementRole::Selects,
            false => StatementRole::Plain,
        };
        let dom = DomTree::compute(&cfg);
        let certificate = certify(&body, &cfg, &dom, 0x10, &placed, &|_| None, &role);
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
    }

    #[test]
    fn a_block_whose_statements_are_all_missing_is_not_read_through() {
        // 0x20 is the block between: with its text gone, the edge from 0x10 still reaches 0x30 by reading
        // 0x20 as a pass-through, and only the count of what was written says it was not one.
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, branch(0x30)),
                (0x30, BlockTerminator::Return),
            ],
        );
        let placed = written(&[0x10, 0x20, 0x30], &[]);
        let body = CStmt::Block(vec![mark(0, expr()), mark(2, CStmt::Return(None))]);
        let certificate = certify_written(&body, &cfg, 0x10, &placed);
        assert_eq!(
            certificate.violations,
            [Violation::Statement {
                block: 0x20,
                fewest: 0,
                most: 0
            }],
            "{certificate}"
        );
        let body = CStmt::Block(vec![
            mark(0, expr()),
            mark(1, expr()),
            mark(2, CStmt::Return(None)),
        ]);
        let certificate = certify_written(&body, &cfg, 0x10, &placed);
        assert!(
            certificate.ok(),
            "{certificate} {:?}",
            certificate.violations
        );
    }
}
