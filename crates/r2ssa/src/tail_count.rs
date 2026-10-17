//! A variadic body whose `va_arg` loop is bounded by a fixed parameter consumes at most that many
//! tail arguments (doc/adr-resolved-bodies.md, "Count-driven tail").

use r2source::{
    CanonicalStorageId, SourceConventionSlots, SourceRegisterSaveArea, SourceTailCount,
    StackAddressBase,
};

use crate::dense::DenseId;
use crate::graph::{BlockId, GraphInst, InstId, InstPayload};
use crate::save_area::SaveArea;
use crate::semantic::{CompareKind, LoopEvidence, TripCount};
use crate::tail_cursors::{Cursors, Kind, Kinds};
use crate::{SSAFunction, SSAOp, SsaGraph, ValueId};

/// The longest run of register copies a value is followed through.
pub(crate) const COPIES: usize = 8;

/// A stack cell at entry-stack-pointer offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cell {
    pub(crate) at: i64,
    pub(crate) size: u32,
}

impl Cell {
    pub(crate) fn overlaps(self, at: i64, size: u32) -> bool {
        at < self.at + i64::from(self.size) && self.at < at + i64::from(size)
    }

    fn holds(self, at: i64) -> bool {
        self.at <= at && at < self.at + i64::from(self.size)
    }
}

/// What a `va_arg` loop does, in the order a block runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// The counter is set to zero.
    CounterInit,
    /// The counter steps by one.
    CounterStep,
    /// A cursor steps by one slot.
    Advance,
    /// A load through a cursor.
    Fetch,
    /// A load of a cursor's own cell: it must see the value the trip started with.
    Read,
}

/// What a path has done since it entered the loop: the cursors' steps and loads against the
/// counter's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Tally {
    counting: bool,
    advances: i32,
    fetches: i32,
    stepped: bool,
    /// A cursor has stepped since the trip began.
    moved: bool,
}

/// The `va_list` cells the convention names, from the bound `va_start` stored.
pub(crate) struct List {
    pub(crate) base: Cell,
    pub(crate) offset: Cell,
    pub(crate) overflow: Cell,
}

/// The counter and the count the loop's header compares.
struct Bound {
    counter: Cell,
    count: Cell,
    signed: bool,
}

/// What the loop's trips are counted by: a header merge the trip count reads, or a counter cell.
enum Counting {
    Trips { parameter: usize, width: u32 },
    Memory(Bound),
}

/// The stores that keep the count and the counter, where a cell counts.
struct Stores {
    counter_init: Option<InstId>,
    count_store: Option<(InstId, ValueId)>,
}

/// What a store to the cells is.
enum Write {
    /// Another frame object.
    Other,
    /// One of the entry saves in the register save area.
    Save,
    BaseInit,
    OverflowInit,
    OffsetInit,
    /// A cursor kept in its cell: the step was an event where it was computed.
    Keep,
    CounterInit,
    CounterStep,
    CountStore,
}

/// The cells a store is told apart by, and the value `va_start` leaves in the offset field.
struct Cells<'a> {
    list: &'a List,
    bound: Option<&'a Bound>,
    kinds: &'a Kinds,
    saved: Cell,
    overflow_init: i64,
}

/// The stores that set the cells up, as `classify_stores` meets them.
#[derive(Default)]
struct Found {
    counter_inits: Vec<InstId>,
    count_stores: Vec<(InstId, ValueId)>,
    overflow_inits: usize,
    base_inits: usize,
    offset_inits: usize,
}

impl Found {
    fn into_stores(self, counting: bool) -> Result<Stores, String> {
        if self.base_inits != 1 || self.offset_inits != 1 || self.overflow_inits != 1 {
            return Err("the va_list's cells are not set exactly once".into());
        }
        if !counting {
            return Ok(Stores {
                counter_init: None,
                count_store: None,
            });
        }
        let (&[counter_init], &[count_store]) = (&self.counter_inits[..], &self.count_stores[..])
        else {
            return Err("the counter or the count is not set exactly once".into());
        };
        Ok(Stores {
            counter_init: Some(counter_init),
            count_store: Some(count_store),
        })
    }
}

/// The loop's blocks, and its header.
struct Walk {
    in_loop: Vec<bool>,
    header: BlockId,
    /// The trips are the header's runs, so no counter steps.
    trips: bool,
}

impl Walk {
    /// Whether `event` sits where it may: the counter's zeroing before the loop, the rest in its body.
    fn placed(&self, index: usize, event: Event) -> bool {
        let inside = self.in_loop[index];
        match event {
            Event::CounterInit => !inside,
            Event::Read if self.trips => true,
            Event::Advance | Event::Fetch if self.trips => inside,
            _ => inside && index != self.header.index(),
        }
    }

    /// The tally after the edge `from` to `next`: a trip back to the header stepped the counter.
    fn across(&self, tally: Tally, from: BlockId, next: BlockId) -> Result<Tally, String> {
        let mut onward = tally;
        // Leaving a loop that counts by its header's runs, its trips are over.
        if self.trips && self.in_loop[from.index()] && !self.in_loop[next.index()] {
            return Ok(Tally::counting());
        }
        if next != self.header {
            return Ok(onward);
        }
        if self.in_loop[from.index()] && self.trips {
            if tally.advances != tally.fetches {
                return Err("a trip fetches other than it steps".into());
            }
            return Ok(Tally::counting());
        }
        if self.in_loop[from.index()] {
            if !tally.stepped {
                return Err("a trip does not step the counter".into());
            }
            onward.stepped = false;
            onward.moved = false;
        } else if !tally.counting {
            return Err("the loop is entered before its counter is set".into());
        }
        Ok(onward)
    }

    /// The tally after a block's events; a trip that counts by its header runs steps and fetches
    /// at most once.
    fn run(&self, tally: Tally, events: &[(usize, Event)]) -> Result<Tally, String> {
        let tally = tally.run(events)?;
        match self.trips && (tally.advances > 1 || tally.fetches > 1) {
            true => Err("a trip steps or fetches more than once".into()),
            false => Ok(tally),
        }
    }
}

impl Tally {
    fn counting() -> Self {
        Self {
            counting: true,
            ..Self::default()
        }
    }

    /// The tally after a block's events, in the order the block runs them.
    fn run(mut self, events: &[(usize, Event)]) -> Result<Tally, String> {
        let mut events = events.to_vec();
        events.sort_by_key(|(ordinal, _)| *ordinal);
        for (_, event) in events {
            match event {
                Event::CounterInit if !self.counting => self.counting = true,
                Event::CounterStep if self.counting && !self.stepped => {
                    self.advances -= 1;
                    self.fetches -= 1;
                    self.stepped = true;
                }
                Event::Advance if self.counting => {
                    self.advances += 1;
                    self.moved = true;
                }
                Event::Fetch if self.counting => self.fetches += 1,
                Event::Read if self.counting && !self.moved => {}
                _ => return Err(format!("{event:?} runs out of order")),
            }
        }
        Ok(self)
    }
}

/// A block reached for the first time is queued; one reached again must carry the same tally.
fn arrive(
    seen: &mut [Option<Tally>],
    pending: &mut Vec<BlockId>,
    next: BlockId,
    onward: Tally,
) -> Result<(), String> {
    match seen[next.index()] {
        None => {
            seen[next.index()] = Some(onward);
            pending.push(next);
            Ok(())
        }
        Some(before) if before == onward => Ok(()),
        Some(_) => Err("paths reach a block with different tallies".into()),
    }
}

pub(crate) struct Prover<'a> {
    pub(crate) function: &'a SSAFunction,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) prep: &'a crate::DecompilePrepFacts,
    pub(crate) area: &'a SaveArea,
    pub(crate) observations: &'a crate::deadphi::ProvenProgramObservations,
    pub(crate) slots: &'a SourceConventionSlots,
    pub(crate) row: SourceRegisterSaveArea,
    /// The slot width: what a cursor steps by.
    pub(crate) width: u32,
}

/// The fixed parameter the body's `va_arg` loop is bounded by, where its machine code proves one.
/// O(insts + uses): every access to the tail must be a counted `va_arg`, or nothing is stated.
pub(crate) fn tail_count(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep: &crate::DecompilePrepFacts,
    slots: &SourceConventionSlots,
    (area, observations): (&SaveArea, &crate::deadphi::ProvenProgramObservations),
) -> Option<SourceTailCount> {
    let row = slots.register_save_area()?;
    let prover = Prover {
        function,
        graph,
        prep,
        area,
        observations,
        slots,
        row,
        width: slots.argument_slots().first()?.size,
    };
    match prover.prove() {
        Ok(count) => Some(count),
        Err(why) => {
            r2il::refusal_evidence!("tail-count", "no parameter bounds the tail: {why}");
            None
        }
    }
}

impl Prover<'_> {
    pub(crate) fn root(&self, value: ValueId) -> Option<i64> {
        self.prep
            .entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    }

    /// The value `value` copies, through the copies that move it between registers.
    fn source(&self, mut value: ValueId) -> ValueId {
        for _ in 0..COPIES {
            match self
                .graph
                .def_inst(value)
                .and_then(|inst| self.graph.inst(inst))
            {
                Some(inst) => match &inst.payload {
                    InstPayload::Op(SSAOp::Copy { src, .. }) => value = *src,
                    _ => break,
                },
                None => break,
            }
        }
        value
    }

    /// The operation that computes `value`, through its copies.
    pub(crate) fn op(&self, value: ValueId) -> Option<&SSAOp<ValueId>> {
        let inst = self.graph.inst(self.graph.def_inst(self.source(value))?)?;
        match &inst.payload {
            InstPayload::Op(op) => Some(op),
            InstPayload::Phi { .. } => None,
        }
    }

    pub(crate) fn size(&self, value: ValueId) -> u32 {
        self.graph.value(value).map_or(0, |value| value.var.size)
    }

    pub(crate) fn constant(&self, value: ValueId) -> Option<u64> {
        let (bits, _) = self.prep.views.representative_constant(value)?;
        Some(bits)
    }

    /// What `va_start` leaves in the offset field: the first unnamed slot's distance from the bound.
    pub(crate) fn next(&self) -> i64 {
        self.area.base + i64::from(self.width) * i64::try_from(self.area.named).unwrap_or(0)
            - self.area.bound
    }

    /// The cell a value was loaded whole from.
    fn loaded_from(&self, value: ValueId) -> Option<Cell> {
        let SSAOp::Load { dst, addr, .. } = self.op(value)? else {
            return None;
        };
        Some(Cell {
            at: self.root(*addr)?,
            size: self.size(*dst),
        })
    }

    /// `value` is `x + step` for an `x` loaded from `cell`.
    fn steps(&self, value: ValueId, cell: Cell, step: u64) -> bool {
        let Some(SSAOp::IntAdd { a, b, .. }) = self.op(value) else {
            return false;
        };
        [(*a, *b), (*b, *a)].into_iter().any(|(loaded, by)| {
            self.constant(by) == Some(step) && self.loaded_from(loaded) == Some(cell)
        })
    }

    fn prove(&self) -> Result<SourceTailCount, String> {
        let list = self.list()?;
        let overflow_init = self.overflow_init(&list)?;
        let mut cursors = self.cursors(&list, overflow_init)?;
        if cursors.steps.is_empty() {
            return Err("no cursor steps".into());
        }
        let header = self.innermost(&cursors)?;
        let predicates =
            crate::semantic::collect_predicate_facts(self.function, Some(self.prep), self.graph);
        let counting = self.counting(header, &predicates)?;
        let bound = match &counting {
            Counting::Memory(bound) => Some(bound),
            Counting::Trips { .. } => None,
        };
        let mut events = std::mem::take(&mut cursors.events);
        let stores =
            self.classify_stores(&list, (&cursors.kinds, overflow_init), bound, &mut events)?;
        self.contain_cursors(&list, bound, overflow_init, &cursors.kinds)?;
        let infeasible = self.infeasible(&cursors, &predicates);
        self.check_paths(header, &events, (bound.is_none(), &infeasible.edges))
            .map_err(|why| format!("{why} ({})", infeasible.notes.join("; ")))?;
        let header_block = (self.graph.block_id_for_addr(header)).ok_or("no header block")?;
        self.fresh(&cursors, header_block)?;
        match counting {
            Counting::Trips { parameter, width } => Ok(SourceTailCount {
                parameter_index: u32::try_from(parameter).map_err(|_| "a parameter index")?,
                width_bytes: width,
                signed: false,
            }),
            Counting::Memory(bound) => {
                self.dominating(header, &stores)?;
                let (_, stored) = stores.count_store.ok_or("the count is not kept")?;
                let parameter = self.parameter(stored, bound.count)?;
                Ok(SourceTailCount {
                    parameter_index: u32::try_from(parameter).map_err(|_| "a parameter index")?,
                    width_bytes: bound.count.size,
                    signed: bound.signed,
                })
            }
        }
    }

    fn list(&self) -> Result<List, String> {
        let bound = self.area.stored_at;
        let list = List {
            base: Cell {
                at: bound,
                size: self.width,
            },
            offset: Cell {
                at: bound + self.row.offset_field,
                size: self.row.offset_width,
            },
            overflow: Cell {
                at: bound + self.row.stack_field,
                size: self.width,
            },
        };
        let cells = [list.base, list.offset, list.overflow];
        for (index, one) in cells.iter().enumerate() {
            if cells[index + 1..]
                .iter()
                .any(|other| one.overlaps(other.at, other.size))
            {
                return Err("the va_list cells overlap".into());
            }
        }
        Ok(list)
    }

    /// The address `va_start` stores in the overflow pointer, stored once.
    fn overflow_init(&self, list: &List) -> Result<i64, String> {
        let mut firsts = (self.graph.insts.iter())
            .filter_map(|inst| match &inst.payload {
                InstPayload::Op(SSAOp::Store { addr, val, .. }) => {
                    (self.root(*addr) == Some(list.overflow.at)).then_some(self.root(*val)?)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        firsts.dedup();
        match firsts[..] {
            [first] => Ok(first),
            _ => Err("the overflow pointer is not set to one address".into()),
        }
    }

    /// The area `va_start` saved the registers to: the unnamed slots, which a tail reads.
    pub(crate) fn saved(&self) -> Cell {
        let width = i64::from(self.width);
        let named = i64::try_from(self.area.named).unwrap_or(0);
        let slots = u32::try_from(self.slots.argument_slots().len()).unwrap_or(u32::MAX);
        Cell {
            at: self.area.base + width * named,
            size: self.width.saturating_mul(slots) - self.width * u32::try_from(named).unwrap_or(0),
        }
    }

    /// The header of the innermost loop holding every step and every fetch.
    fn innermost(&self, cursors: &Cursors) -> Result<u64, String> {
        let blocks = (cursors.events.iter().enumerate())
            .filter(|(_, events)| {
                (events.iter()).any(|(_, event)| matches!(event, Event::Advance | Event::Fetch))
            })
            .map(|(index, _)| {
                self.graph
                    .block(BlockId::from_index(index))
                    .map(|block| block.addr)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("a step has no block")?;
        let loops = self.function.natural_loops();
        let natural = (loops.iter())
            .filter(|natural| blocks.iter().all(|addr| natural.body.contains(addr)))
            .min_by_key(|natural| natural.body.len())
            .ok_or("no loop holds every step")?;
        // A loop entered again would read a count's worth of slots again.
        let entered_again = loops
            .iter()
            .any(|other| other.header != natural.header && other.body.contains(&natural.header));
        match entered_again {
            true => Err("the loop is inside another".into()),
            false => Ok(natural.header),
        }
    }

    /// What counts the loop's trips: the header's run count where the machine states one, else a
    /// counter cell the header compares with a count.
    fn counting(
        &self,
        header: u64,
        predicates: &crate::semantic::PredicateFacts,
    ) -> Result<Counting, String> {
        let trips = match self.trips(header, predicates) {
            Ok((parameter, width)) => return Ok(Counting::Trips { parameter, width }),
            Err(why) => why,
        };
        self.exits_at_header(header)
            .and_then(|()| self.bound(header, predicates))
            .map(Counting::Memory)
            .map_err(|memory| {
                self.exit_evidence(header, predicates);
                format!("{trips}; {memory}")
            })
    }

    /// The parameter the loop's header runs a number of times equal to, from its induction.
    fn trips(
        &self,
        header: u64,
        predicates: &crate::semantic::PredicateFacts,
    ) -> Result<(usize, u32), String> {
        let evidence = LoopEvidence {
            predicates,
            values: crate::semantic::empty_value_ranges(),
        };
        let trips = crate::semantic::header_trips(self.function, self.graph, evidence, header)
            .map_err(|why| format!("the header's runs are not counted ({why:?})"))?;
        let TripCount::Symbolic { form, .. } = trips.count else {
            return Err("the header runs a constant number of times".into());
        };
        let mut terms = form.terms.iter();
        let (Some((&count, &1)), None, 0) = (terms.next(), terms.next(), form.constant) else {
            return Err("the header runs other than the count of times".into());
        };
        let width = form.width_bits / 8;
        let cell = Cell { at: 0, size: width };
        match self.graph.caller_supplied(count) {
            true => Ok((self.argument_slot(count, cell)?, width)),
            false => Err("the count is not a named parameter's entry value".into()),
        }
    }

    /// The comparisons the loop's exits branch on, as refusal evidence.
    fn exit_evidence(&self, header: u64, predicates: &crate::semantic::PredicateFacts) {
        let Some(natural) = self.function.natural_loops().get(header) else {
            return;
        };
        for fact in predicates.predicates.values() {
            let leaves = natural.body.contains(&fact.block_addr)
                && natural.body.contains(&fact.true_target)
                    != natural.body.contains(&fact.false_target);
            if !leaves {
                continue;
            }
            for compare in [&fact.comparison, &fact.evaluated_comparison]
                .into_iter()
                .flatten()
            {
                r2il::refusal_evidence!(
                    "tail-count",
                    "exit at {:#x}: {:?} of {:?} defined by {:?} and {:?} defined by {:?}",
                    fact.block_addr,
                    compare.kind,
                    compare.lhs,
                    self.graph
                        .def_inst(compare.lhs)
                        .and_then(|inst| self.graph.inst(inst))
                        .map(|inst| &inst.payload),
                    compare.rhs,
                    self.graph
                        .def_inst(compare.rhs)
                        .and_then(|inst| self.graph.inst(inst))
                        .map(|inst| &inst.payload)
                );
            }
        }
    }

    /// The loop's only exit leaves from its header, and no block of it ends the function.
    fn exits_at_header(&self, header: u64) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let cfg = self.function.cfg();
        for block in &natural.body {
            let successors = cfg.successors(*block);
            if successors.is_empty() {
                return Err(format!("block {block:#x} of the loop ends the function"));
            }
            if *block != natural.header && successors.iter().any(|s| !natural.body.contains(s)) {
                return Err(format!(
                    "block {block:#x} leaves the loop beside its header"
                ));
            }
        }
        Ok(())
    }

    /// The counter and the count the header compares: the loop continues while the counter is
    /// below the count, or differs from it, so the counter never passes the count.
    fn bound(
        &self,
        header: u64,
        predicates: &crate::semantic::PredicateFacts,
    ) -> Result<Bound, String> {
        let fact = (predicates.predicates.values())
            .find(|fact| fact.block_addr == header)
            .ok_or("the header branches on nothing")?;
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let continues = match (
            natural.body.contains(&fact.true_target),
            natural.body.contains(&fact.false_target),
        ) {
            (true, false) => true,
            (false, true) => false,
            _ => return Err("the header's branch does not leave the loop".into()),
        };
        let header_block =
            (self.graph.block_id_for_addr(header)).ok_or("the header has no block")?;
        let in_header = |value: ValueId| {
            (self.graph.def_inst(value))
                .and_then(|inst| self.graph.inst(inst))
                .is_some_and(|inst| inst.block == header_block)
        };
        for compare in [&fact.comparison, &fact.evaluated_comparison]
            .into_iter()
            .flatten()
        {
            let (below, above, equality) = match (compare.kind, continues) {
                (CompareKind::Less | CompareKind::SignedLess, true) => {
                    (compare.lhs, compare.rhs, false)
                }
                (CompareKind::LessEqual | CompareKind::SignedLessEqual, false) => {
                    (compare.rhs, compare.lhs, false)
                }
                (CompareKind::NotEqual, true) | (CompareKind::Equal, false) => {
                    (compare.lhs, compare.rhs, true)
                }
                _ => continue,
            };
            if !in_header(below) || !in_header(above) {
                continue;
            }
            let (Some(first), Some(second)) = (self.loaded_from(below), self.loaded_from(above))
            else {
                continue;
            };
            // An equality names no order, so the counter is the cell the body steps by one.
            let swap = equality && !self.stepped(first) && self.stepped(second);
            let (counter, count) = if swap {
                (second, first)
            } else {
                (first, second)
            };
            if counter.size != count.size || counter.overlaps(count.at, count.size) {
                continue;
            }
            return Ok(Bound {
                counter,
                count,
                signed: matches!(
                    compare.kind,
                    CompareKind::SignedLess | CompareKind::SignedLessEqual
                ),
            });
        }
        Err("the header compares no counter below a count".into())
    }

    /// Whether the body stores `cell + 1` back to `cell`.
    fn stepped(&self, cell: Cell) -> bool {
        self.graph.insts.iter().any(|inst| {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                return false;
            };
            self.root(*addr) == Some(cell.at) && self.steps(*val, cell, 1)
        })
    }

    /// Every store to a tracked cell is `va_start`'s, a cursor kept, the counter's, or the one
    /// that keeps the count; anything else refuses.
    fn classify_stores(
        &self,
        list: &List,
        (kinds, overflow_init): (&Kinds, i64),
        bound: Option<&Bound>,
        events: &mut [Vec<(usize, Event)>],
    ) -> Result<Stores, String> {
        let saved = self.saved();
        let tracked = [list.base, list.offset, list.overflow, saved];
        let inside = |cell: &Cell| tracked.iter().any(|t| t.overlaps(cell.at, cell.size));
        if bound.is_some_and(|bound| [bound.counter, bound.count].iter().any(inside)) {
            return Err("the counter or the count sits in the va_list or its area".into());
        }
        let cells = Cells {
            list,
            bound,
            kinds,
            saved,
            overflow_init,
        };
        let mut found = Found::default();
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                continue;
            };
            let Some(at) = self.root(*addr) else {
                continue;
            };
            let mut note = |event| events[inst.block.index()].push((inst.ordinal, event));
            match self.write(&cells, at, *val)? {
                Write::Other | Write::Save | Write::Keep => {}
                Write::BaseInit => found.base_inits += 1,
                Write::OverflowInit => found.overflow_inits += 1,
                Write::OffsetInit => found.offset_inits += 1,
                Write::CounterStep => note(Event::CounterStep),
                Write::CounterInit => {
                    note(Event::CounterInit);
                    found.counter_inits.push(inst.id);
                }
                Write::CountStore => found.count_stores.push((inst.id, *val)),
            }
        }
        found.into_stores(bound.is_some())
    }

    /// What a store of `val` at `at` is to the cells.
    fn write(&self, cells: &Cells, at: i64, val: ValueId) -> Result<Write, String> {
        let list = cells.list;
        let size = self.size(val);
        let whole = |cell: Cell| cell.at == at && cell.size == size;
        if cells.saved.overlaps(at, size) {
            return self.save(val, at);
        }
        if list.base.overlaps(at, size) {
            return self.base_write(val, whole(list.base));
        }
        if list.overflow.overlaps(at, size) {
            return self.overflow_write(cells, val, whole(list.overflow));
        }
        if list.offset.overlaps(at, size) {
            let wide = at == list.offset.at && size > list.offset.size;
            return self.offset_write(cells, val, (whole(list.offset), wide));
        }
        let Some(bound) = cells.bound else {
            return Ok(Write::Other);
        };
        if bound.counter.overlaps(at, size) {
            return self.counter_write(val, whole(bound.counter), bound.counter);
        }
        if bound.count.overlaps(at, size) {
            return match whole(bound.count) {
                true => Ok(Write::CountStore),
                false => Err("the count is written in part".into()),
            };
        }
        Ok(Write::Other)
    }

    fn save(&self, val: ValueId, at: i64) -> Result<Write, String> {
        match self.area.saved.contains(self.prep.views.copy_root(val)) {
            true => Ok(Write::Save),
            false => Err(format!(
                "the area is written at {at:#x} beside the entry saves"
            )),
        }
    }

    fn base_write(&self, val: ValueId, whole: bool) -> Result<Write, String> {
        match whole && self.root(val) == Some(self.area.bound) {
            true => Ok(Write::BaseInit),
            false => Err("the area's bound is written other than by va_start".into()),
        }
    }

    fn overflow_write(&self, cells: &Cells, val: ValueId, whole: bool) -> Result<Write, String> {
        if !whole {
            return Err("the overflow pointer is written in part".into());
        }
        match (cells.kinds.get(val), self.root(val)) {
            (Some(Kind::Overflow | Kind::Rooted), Some(first)) if first == cells.overflow_init => {
                Ok(Write::OverflowInit)
            }
            (Some(Kind::Overflow), _) => Ok(Write::Keep),
            _ => Err("the overflow pointer is set to something else".into()),
        }
    }

    /// `(whole, wide)` is whether the store is the offset field's own, and whether it is a wider
    /// word starting there.
    fn offset_write(
        &self,
        cells: &Cells,
        val: ValueId,
        (whole, wide): (bool, bool),
    ) -> Result<Write, String> {
        if (whole || wide) && self.sets_offset(val, cells.list.offset) {
            return Ok(Write::OffsetInit);
        }
        match whole && cells.kinds.get(val) == Some(Kind::Offset) {
            true => Ok(Write::Keep),
            false => Err("the offset is written other than by va_start or a step".into()),
        }
    }

    fn counter_write(&self, val: ValueId, whole: bool, cell: Cell) -> Result<Write, String> {
        if !whole {
            return Err("the counter is written in part".into());
        }
        if self.constant(val) == Some(0) {
            return Ok(Write::CounterInit);
        }
        match self.steps(val, cell, 1) {
            true => Ok(Write::CounterStep),
            false => Err("the counter is set to something but zero or a step".into()),
        }
    }

    /// Whether a constant store holds `next` in the offset field, alone or as the low bytes of a
    /// wider word.
    fn sets_offset(&self, value: ValueId, offset: Cell) -> bool {
        let Some((bits, size)) = self.prep.views.representative_constant(value) else {
            return false;
        };
        size >= offset.size && self.is_next(bits)
    }

    /// An address into the cells or the area is only loaded or stored through, bar `va_start`'s
    /// stores of an address: nothing else writes a cell or reads the tail without a cursor.
    fn contain_cursors(
        &self,
        list: &List,
        bound: Option<&Bound>,
        overflow_init: i64,
        kinds: &Kinds,
    ) -> Result<(), String> {
        let mut spans = vec![list.base, list.offset, list.overflow, self.saved()];
        spans.extend(
            bound
                .into_iter()
                .flat_map(|bound| [bound.counter, bound.count]),
        );
        for value in &self.graph.values {
            let Some(at) = self.root(value.id) else {
                continue;
            };
            let in_tail = spans.iter().any(|span| span.holds(at)) || at >= overflow_init;
            if in_tail && kinds.get(value.id).is_none() {
                self.confined(value.id, at, list)?;
            }
        }
        self.constant_reads(list, overflow_init)
    }

    /// Every use of the address `value`, rooted at `at`, is contained.
    fn confined(&self, value: ValueId, at: i64, list: &List) -> Result<(), String> {
        for site in self.graph.use_sites(value) {
            let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
            // The flags a subtraction of the stack pointer sets read no slot.
            let flags = inst
                .output
                .is_some_and(|out| !self.observations.contains(out));
            if !flags && !self.contained_use(inst, value, list) {
                return Err(format!(
                    "an address into the va_list or its area at {at:#x} is used by {:?}",
                    inst.payload
                ));
            }
        }
        Ok(())
    }

    fn contained_use(&self, inst: &GraphInst, value: ValueId, list: &List) -> bool {
        match &inst.payload {
            InstPayload::Op(SSAOp::Load { addr, .. }) => *addr == value,
            InstPayload::Op(SSAOp::Store { addr, val, .. }) => {
                *addr == value
                    || (*val == value
                        && (self.root(*addr))
                            .is_some_and(|to| to == list.base.at || to == list.overflow.at))
            }
            InstPayload::Op(SSAOp::Copy { .. } | SSAOp::IntAdd { .. } | SSAOp::IntSub { .. }) => {
                inst.output.is_some_and(|out| self.root(out).is_some())
            }
            _ => false,
        }
    }

    /// The tail is never read at a constant address, and a cursor's own cell is read whole.
    fn constant_reads(&self, list: &List, overflow_init: i64) -> Result<(), String> {
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Load { addr, .. }) = &inst.payload else {
                continue;
            };
            let (Some(at), Some(out)) = (self.root(*addr), inst.output) else {
                continue;
            };
            let size = self.size(out);
            let cell = Cell { at, size };
            let in_area = self.saved().overlaps(at, size);
            if in_area || at >= overflow_init {
                return Err(format!("the tail is read at {at:#x} without a cursor"));
            }
            let whole = [list.base, list.offset, list.overflow].contains(&cell);
            let apart = [list.base, list.offset, list.overflow]
                .iter()
                .any(|part| part.overlaps(at, size));
            if apart && !whole {
                return Err("a cursor is read in part".into());
            }
        }
        Ok(())
    }

    /// Each trip pays for one cursor step and one fetch: a tally per block, checked once per edge,
    /// so the loop reads no more slots than it runs trips.
    fn check_paths(
        &self,
        header: u64,
        events: &[Vec<(usize, Event)>],
        (trips, infeasible): (bool, &[(BlockId, BlockId)]),
    ) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let header = (self.graph.block_id_for_addr(header)).ok_or("no header block")?;
        let blocks = self.graph.blocks.len();
        let in_loop = (0..blocks)
            .map(|index| {
                (self.graph.block(BlockId::from_index(index)))
                    .is_some_and(|block| natural.body.contains(&block.addr))
            })
            .collect::<Vec<_>>();
        let walk = Walk {
            in_loop,
            header,
            trips,
        };
        let misplaced = (events.iter().enumerate())
            .flat_map(|(index, events)| events.iter().map(move |(_, event)| (index, *event)))
            .find(|(index, event)| !walk.placed(*index, *event));
        if let Some((_, event)) = misplaced {
            return Err(format!("{event:?} sits outside its place in the loop"));
        }
        let entry = self.graph.entry;
        let mut seen: Vec<Option<Tally>> = vec![None; blocks];
        seen[entry.index()] = Some(match trips {
            true => Tally::counting(),
            false => Tally::default(),
        });
        // Each block is expanded once, on its first arrival; a later arrival must carry the same tally.
        let mut pending = vec![entry];
        while let Some(block) = pending.pop() {
            let tally = seen[block.index()].ok_or("a block without a tally")?;
            let tally = walk.run(tally, &events[block.index()])?;
            for (next, onward) in self.onward(&walk, (block, tally), infeasible)? {
                arrive(&mut seen, &mut pending, next, onward)?;
            }
        }
        Ok(())
    }

    /// The tally on each edge out of `block` that some run takes; an edge none takes carries none.
    fn onward(
        &self,
        walk: &Walk,
        (block, tally): (BlockId, Tally),
        infeasible: &[(BlockId, BlockId)],
    ) -> Result<Vec<(BlockId, Tally)>, String> {
        let successors = &self.graph.block(block).ok_or("no block")?.successors;
        (successors.iter())
            .filter(|next| !infeasible.contains(&(block, **next)))
            .map(|next| Ok((*next, walk.across(tally, block, *next)?)))
            .collect()
    }

    /// The counter is zeroed and the count kept before the loop runs.
    fn dominating(&self, header: u64, stores: &Stores) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let kept = stores
            .counter_init
            .into_iter()
            .chain(stores.count_store.map(|(store, _)| store));
        for store in kept {
            let addr = (self.graph.inst(store))
                .and_then(|inst| self.graph.block(inst.block))
                .map(|block| block.addr)
                .ok_or("a store has no block")?;
            if natural.body.contains(&addr) || !self.function.dominates(addr, header) {
                return Err("the counter or the count is not set before the loop".into());
            }
        }
        Ok(())
    }

    /// The register slot the count was stored from.
    fn parameter(&self, stored: ValueId, count: Cell) -> Result<usize, String> {
        let mut value = self.source(self.prep.views.copy_root(stored));
        for _ in 0..COPIES {
            if self.graph.caller_supplied(value) {
                return self.argument_slot(value, count);
            }
            match self.op(value) {
                Some(SSAOp::Subpiece { src, offset: 0, .. }) => value = self.source(*src),
                _ => break,
            }
        }
        Err("the count is not a named parameter's entry value".into())
    }

    /// The named argument register a caller-supplied `value` of `count`'s width holds.
    fn argument_slot(&self, value: ValueId, count: Cell) -> Result<usize, String> {
        let storage = self
            .graph
            .formal_projection_storage(value)
            .or_else(|| self.graph.value(value).and_then(|v| v.canonical_storage))
            .ok_or("the count is no register")?;
        let held = |slot: &CanonicalStorageId| {
            slot.space == storage.space && slot.offset == storage.offset
        };
        let slot = (self.slots.argument_slots().iter())
            .position(|slot| held(slot) && storage.size >= count.size)
            .ok_or("the count is no argument register")?;
        match slot < self.area.named {
            true => Ok(slot),
            false => Err("the count is a tail register".into()),
        }
    }
}
