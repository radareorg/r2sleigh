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
use std::sync::OnceLock;

use r2ssa::cfg::{BlockTerminator, CFG};
use r2ssa::domtree::DomTree;

use crate::ast::{CExpr, CStmt};
use crate::observation_journal::RenderObservationId;
use crate::structured_region::StructuredRegionKind;

/// What a terminator says about one of its edges.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EdgeLabel {
    Normal,
    True,
    False,
    Case(BTreeSet<u64>),
    Default,
}

impl EdgeLabel {
    fn inverted(&self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            other => other.clone(),
        }
    }
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
    /// The first block the text runs is not the function's entry.
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
            Self::SwitchValue { block } => write!(f, " at {block:#x}"),
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
    pub(crate) inversions: usize,
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
            " occurrences={} blocks={} duplicated={} contracted={} inversions={} unreachable={}",
            self.occurrences,
            self.blocks,
            self.duplicated.len(),
            self.contracted,
            self.inversions,
            self.unreachable_missing
        )
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
    terminal_call: &'a dyn Fn(&CStmt) -> bool,
    occurrences: Vec<Occurrence>,
    frames: Vec<Frame>,
    violations: Vec<Violation>,
    first_block: Option<u64>,
    /// The next statement starts a position of its own: the function's
    /// first, or a do-while body's entry.
    force_open: bool,
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
        if let [(id, EdgeLabel::Normal)] = open.as_slice()
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
            // A region's marker names the block its text starts with; a
            // loop's names its header, which the loop's own walk opens.
            CStmt::StructuredRegion { marker, stmt } => {
                let open = match marker.kind() {
                    StructuredRegionKind::Block
                    | StructuredRegionKind::IfThenElse
                    | StructuredRegionKind::Switch => self.enter_block(open, marker.entry()),
                    _ => open,
                };
                self.walk(stmt, open)
            }
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
                then_body,
                else_body,
                ..
            } => {
                let Some(owner) = self.single_owner(&open, "if") else {
                    return Vec::new();
                };
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
                self.walk_pre_test_loop(body, open)
            }
            // A do-while nobody observed cannot say which block its test is.
            CStmt::DoWhile { body, .. } => self.walk_do_while(&[], body, open),
            CStmt::Switch { cases, default, .. } => {
                self.walk_switch(open, cases, default.as_deref())
            }
            // A call the prototype declares `noreturn` ends the text here.
            CStmt::Expr(_) if (self.terminal_call)(stmt) => {
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

    /// A control statement is placed at the block its observations name; a
    /// loop is observed under its header and its latches together. A plain
    /// statement opens nothing: a block that only computes is read as part
    /// of whatever text it sits in, and its edge is read through it.
    fn walk_observed(&mut self, stmt: &CStmt, open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        let mut blocks = Vec::new();
        let mut inner = stmt;
        while let CStmt::Observed { id, stmt } = inner {
            if let Some(block) = (self.block_of)(*id)
                && !blocks.contains(&block)
            {
                blocks.push(block);
            }
            inner = stmt;
        }
        match inner {
            CStmt::DoWhile { body, .. } => self.walk_do_while(&blocks, body, open),
            CStmt::For {
                cond: None, body, ..
            } => self.walk_infinite_loop(body, open),
            CStmt::While { body, .. } | CStmt::For { body, .. } => {
                let open = match self.choose_header(&blocks) {
                    Some(header) => self.enter_block(open, header),
                    None => open,
                };
                self.walk_pre_test_loop(body, open)
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
            && self.cfg.successors(from).contains(&block)
            && !self.dom.dominates(block, from)
    }

    fn walk_pre_test_loop(&mut self, body: &CStmt, open: Vec<OpenEnd>) -> Vec<OpenEnd> {
        let Some(owner) = self.single_owner(&open, "loop") else {
            return Vec::new();
        };
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
        for test in &tests {
            self.occurrences[*test]
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

/// The external callee a statement calls, when the statement is a call or
/// an assignment of one.
pub(crate) fn stmt_callee_name(stmt: &CStmt) -> Option<&str> {
    let expr = match stmt.unobserved() {
        CStmt::Expr(expr) => expr,
        _ => return None,
    };
    let call = match expr.unobserved() {
        CExpr::Binary {
            op: crate::ast::BinaryOp::Assign,
            right,
            ..
        } => right.unobserved(),
        other => other,
    };
    match call {
        CExpr::Call { func, .. } => match func.unobserved() {
            CExpr::External { name, .. } => Some(name.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// A block whose only way out is one unconditional transfer.
fn passes_through(cfg: &CFG, addr: u64) -> bool {
    cfg.get_block(addr).is_some_and(|block| {
        matches!(
            block.terminator,
            BlockTerminator::Fallthrough { .. }
                | BlockTerminator::Branch { .. }
                | BlockTerminator::Call {
                    fallthrough: Some(_),
                    ..
                }
                | BlockTerminator::IndirectCall {
                    fallthrough: Some(_)
                }
        )
    }) && cfg.successors(addr).len() == 1
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

/// Read the body back as a control graph and compare it with the CFG.
///
/// `block_of` says which block an observed statement was emitted for, and
/// `label_block` which block a label names; neither is derived here.
pub(crate) fn certify(
    body: &CStmt,
    cfg: &CFG,
    entry: u64,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
    label_block: &dyn Fn(&str) -> Option<u64>,
    terminal_call: &dyn Fn(&CStmt) -> bool,
) -> ControlCertificate {
    let dom = DomTree::compute(cfg);
    let mut walker = Walker {
        cfg,
        dom: &dom,
        block_of,
        label_block,
        terminal_call,
        occurrences: Vec::new(),
        frames: Vec::new(),
        violations: Vec::new(),
        first_block: None,
        force_open: true,
    };
    let ends = walker.walk(body, Vec::new());
    for (id, _) in ends {
        walker.occurrences[id].fell_off_end = true;
    }
    let Walker {
        occurrences,
        mut violations,
        first_block,
        ..
    } = walker;
    if first_block != Some(entry) {
        violations.push(Violation::EntryNotFirst { first: first_block });
    }

    let mut count = BTreeMap::<u64, usize>::new();
    for occurrence in &occurrences {
        *count.entry(occurrence.block).or_default() += 1;
    }
    // A block that rendered nothing and only passes control on is read
    // through, the way the text does; the blocks read through are counted.
    let contracted = std::cell::RefCell::new(BTreeSet::<u64>::new());
    let contract = |mut addr: u64| -> Target {
        if cfg.get_block(addr).is_none() {
            return Target::External;
        }
        let mut seen = BTreeSet::new();
        while count.get(&addr).copied().unwrap_or(0) == 0 && passes_through(cfg, addr) {
            if !seen.insert(addr) {
                break;
            }
            contracted.borrow_mut().insert(addr);
            addr = cfg.successors(addr)[0];
            if cfg.get_block(addr).is_none() {
                return Target::External;
            }
        }
        Target::Block(addr)
    };

    let mut inversions = 0;
    for occurrence in &occurrences {
        let block = occurrence.block;
        let expected = expected_edges(cfg, block, &contract);
        let inside: Vec<_> = expected
            .iter()
            .filter(|(target, _)| matches!(target, Target::Block(_)))
            .cloned()
            .collect();
        let mut rendered = occurrence.edges.clone();
        rendered.sort();
        if rendered.is_empty() {
            if inside.is_empty() {
                continue;
            }
            violations.push(if occurrence.returned {
                Violation::ReturnWhereMachineContinues { block }
            } else {
                Violation::FallsOffEnd { block }
            });
            continue;
        }
        if rendered == expected {
            continue;
        }
        let mut swapped: Vec<_> = rendered
            .iter()
            .map(|(target, label)| (*target, label.inverted()))
            .collect();
        swapped.sort();
        if swapped == expected {
            inversions += 1;
            continue;
        }
        if switch_edges_agree(&rendered, &expected) {
            continue;
        }
        let terminator = cfg.get_block(block).map(|block| &block.terminator);
        violations.push(match terminator {
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
        });
    }

    let contracted = contracted.into_inner();
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
        inversions,
        unreachable_missing,
    }
}

fn reporting() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("R2DEC_CONTROL_CERTIFICATE").is_some())
}

/// Print one line per function under `R2DEC_CONTROL_CERTIFICATE`, and the
/// same line on the refusal-evidence channel. The register-identity census
/// (`doc/adr-register-identity.md`, S0) rides on the same switch.
pub(crate) fn report(
    function: &str,
    certificate: &ControlCertificate,
    rewrites: &str,
    identity: r2ssa::RegisterIdentityCensus,
) {
    r2il::refusal_evidence!(
        "control-certificate",
        "{function}: {certificate} rewrites={rewrites}"
    );
    if !reporting() {
        return;
    }
    eprintln!("control-certificate {function}: {certificate} rewrites={rewrites}");
    for violation in certificate.violations.iter().take(12) {
        eprintln!("control-certificate {function}:   - {violation}");
    }
    eprintln!(
        "register-identity {function}: split_entries={}",
        identity.split_entry_families
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::SwitchCase;
    use crate::observation_journal::test_render_observation_id;
    use r2ssa::cfg::BasicBlock;

    fn cfg(entry: u64, blocks: &[(u64, BlockTerminator)]) -> CFG {
        let mut cfg = CFG::new(entry);
        for (addr, _) in blocks {
            cfg.add_block(BasicBlock::new(*addr));
        }
        for (addr, terminator) in blocks {
            cfg.set_terminator(*addr, terminator.clone());
        }
        cfg
    }

    /// A statement observed as belonging to `block`.
    fn at(block: u64, stmt: CStmt) -> CStmt {
        CStmt::observed(
            test_render_observation_id(u32::try_from(block).expect("small address")),
            stmt,
        )
    }

    fn expr() -> CStmt {
        CStmt::Expr(CExpr::IntLit(0))
    }

    fn cond() -> CExpr {
        CExpr::IntLit(1)
    }

    fn run(body: CStmt, cfg: &CFG, entry: u64, labels: &[(&str, u64)]) -> ControlCertificate {
        let block_of = |id: RenderObservationId| Some(u64::from(id.index()));
        let label_block = |name: &str| {
            labels
                .iter()
                .find(|(label, _)| *label == name)
                .map(|(_, block)| *block)
        };
        certify(&body, cfg, entry, &block_of, &label_block, &|_| false)
    }

    fn branch(target: u64) -> BlockTerminator {
        BlockTerminator::Branch { target }
    }

    fn cond_branch(true_target: u64, false_target: u64) -> BlockTerminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        }
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
        assert_eq!(certificate.inversions, 0);
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
        assert_eq!(straight.inversions, 0);
        let inverted = run(body, &blocks(0x40, 0x30), 0x10, &[]);
        assert!(inverted.ok(), "{inverted}");
        assert_eq!(inverted.inversions, 1);
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
}
