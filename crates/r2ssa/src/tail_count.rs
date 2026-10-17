//! A variadic body whose `va_arg` loop is bounded by a fixed parameter consumes at most that many
//! tail arguments (doc/adr-resolved-bodies.md, "Count-driven tail").

use r2source::{
    CanonicalStorageId, SourceConventionSlots, SourceRegisterSaveArea, SourceTailCount,
    StackAddressBase,
};

use crate::dense::DenseId;
use crate::graph::{BlockId, GraphInst, InstId, InstPayload};
use crate::save_area::SaveArea;
use crate::semantic::CompareKind;
use crate::{SSAFunction, SSAOp, SsaGraph, ValueId};

/// The longest run of register copies a value is followed through.
const COPIES: usize = 8;

/// A stack cell at entry-stack-pointer offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    at: i64,
    size: u32,
}

impl Cell {
    fn overlaps(self, at: i64, size: u32) -> bool {
        at < self.at + i64::from(self.size) && self.at < at + i64::from(size)
    }

    fn holds(self, at: i64) -> bool {
        self.at <= at && at < self.at + i64::from(self.size)
    }
}

/// What a `va_arg` loop does, in the order a block runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
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

/// How a value relates to the `va_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// The loaded `reg_save_area` (or `__gr_top`): an address only once an offset is added.
    Base,
    /// An address in the tail: the loaded overflow pointer, or the base and a register offset.
    Address,
}

/// The `va_list` cells the convention names, from the bound `va_start` stored.
struct List {
    base: Cell,
    offset: Cell,
    overflow: Cell,
}

/// The counter and the count the loop's header compares.
struct Bound {
    counter: Cell,
    count: Cell,
    signed: bool,
}

/// What the stores to the tracked cells are.
struct Stores {
    events: Vec<Vec<(usize, Event)>>,
    counter_init: InstId,
    count_store: (InstId, ValueId),
    overflow_init: i64,
}

/// What a store to the cells is.
enum Write {
    /// Another frame object.
    Other,
    /// One of the entry saves in the register save area.
    Save,
    BaseInit,
    OverflowInit(i64),
    OffsetInit,
    Advance,
    CounterInit,
    CounterStep,
    CountStore,
}

/// The cells a store is told apart by, and the value `va_start` leaves in the offset field.
struct Cells<'a> {
    list: &'a List,
    bound: &'a Bound,
    saved: Cell,
    next: i64,
}

/// The stores that set the cells up, as `classify_stores` meets them.
#[derive(Default)]
struct Found {
    counter_inits: Vec<InstId>,
    count_stores: Vec<(InstId, ValueId)>,
    overflow_inits: Vec<i64>,
    base_inits: usize,
    offset_inits: usize,
}

impl Found {
    fn into_stores(self, events: Vec<Vec<(usize, Event)>>) -> Result<Stores, String> {
        let (&[counter_init], &[count_store], &[overflow_init]) = (
            &self.counter_inits[..],
            &self.count_stores[..],
            &self.overflow_inits[..],
        ) else {
            return Err(
                "the counter, the count or the overflow pointer is not set exactly once".into(),
            );
        };
        if self.base_inits != 1 || self.offset_inits != 1 {
            return Err("the va_list's base or offset is not set exactly once".into());
        }
        Ok(Stores {
            events,
            counter_init,
            count_store,
            overflow_init,
        })
    }
}

/// The values that hold a cursor, and the loads and stores through them, as `fetches` finds them.
struct Fetching<'a> {
    list: &'a List,
    tail: Vec<Option<Tail>>,
    pending: Vec<ValueId>,
    fetched: crate::dense::IdSet<InstId>,
    events: &'a mut [Vec<(usize, Event)>],
}

impl Fetching<'_> {
    fn tag(&mut self, out: ValueId, kind: Tail) {
        if self.tail[out.index()].is_none() {
            self.tail[out.index()] = Some(kind);
            self.pending.push(out);
        }
    }
}

/// The loop's blocks, and its header.
struct Walk {
    in_loop: Vec<bool>,
    header: BlockId,
}

impl Walk {
    /// Whether `event` sits where it may: the counter's zeroing before the loop, the rest in its body.
    fn placed(&self, index: usize, event: Event) -> bool {
        match event {
            Event::CounterInit => !self.in_loop[index],
            _ => self.in_loop[index] && index != self.header.index(),
        }
    }

    /// The tally after the edge `from` to `next`: a trip back to the header stepped the counter.
    fn across(&self, tally: Tally, from: BlockId, next: BlockId) -> Result<Tally, String> {
        let mut onward = tally;
        if next != self.header {
            return Ok(onward);
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
}

impl Tally {
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

struct Prover<'a> {
    function: &'a SSAFunction,
    graph: &'a SsaGraph,
    prep: &'a crate::DecompilePrepFacts,
    area: &'a SaveArea,
    observations: &'a crate::deadphi::ProvenProgramObservations,
    slots: &'a SourceConventionSlots,
    row: SourceRegisterSaveArea,
    /// The slot width: what a cursor steps by.
    width: u32,
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
    fn root(&self, value: ValueId) -> Option<i64> {
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
    fn op(&self, value: ValueId) -> Option<&SSAOp<ValueId>> {
        let inst = self.graph.inst(self.graph.def_inst(self.source(value))?)?;
        match &inst.payload {
            InstPayload::Op(op) => Some(op),
            InstPayload::Phi { .. } => None,
        }
    }

    fn size(&self, value: ValueId) -> u32 {
        self.graph.value(value).map_or(0, |value| value.var.size)
    }

    fn constant(&self, value: ValueId) -> Option<u64> {
        let (bits, _) = self.prep.views.representative_constant(value)?;
        Some(bits)
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

    /// Whether `value` is a load from the offset cell, widened or copied.
    fn offset_index(&self, mut value: ValueId, offset: Cell) -> bool {
        for _ in 0..COPIES {
            if self.loaded_from(value) == Some(offset) {
                return true;
            }
            match self.op(value) {
                Some(SSAOp::IntZExt { src, .. } | SSAOp::IntSExt { src, .. }) => value = *src,
                _ => return false,
            }
        }
        false
    }

    fn prove(&self) -> Result<SourceTailCount, String> {
        let list = self.list()?;
        let advances = self.advances(&list)?;
        let header = self.counted_loop(&advances)?;
        let bound = self.bound(header)?;
        let mut stores = self.classify_stores(&list, &bound)?;
        self.contain_cursors(&list, &bound, stores.overflow_init)?;
        self.fetches(&list, stores.overflow_init, &mut stores.events)?;
        self.check_paths(header, &stores)?;
        self.dominating(header, &stores)?;
        let parameter = self.parameter(stores.count_store.1, bound.count)?;
        Ok(SourceTailCount {
            parameter_index: u32::try_from(parameter).map_err(|_| "a parameter index")?,
            width_bytes: bound.count.size,
            signed: bound.signed,
        })
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

    /// The area `va_start` saved the registers to.
    fn saved(&self) -> Cell {
        let slots = u32::try_from(self.slots.argument_slots().len()).unwrap_or(u32::MAX);
        Cell {
            at: self.area.base,
            size: self.width.saturating_mul(slots),
        }
    }

    /// The blocks that step a cursor by one slot.
    fn advances(&self, list: &List) -> Result<Vec<BlockId>, String> {
        let blocks = (self.graph.insts.iter())
            .filter(|inst| self.steps_a_cursor(inst, list))
            .map(|inst| inst.block)
            .collect::<Vec<_>>();
        match blocks.is_empty() {
            true => Err("no cursor steps".into()),
            false => Ok(blocks),
        }
    }

    /// Whether `inst` stores a cursor's next slot to the cursor's cell.
    fn steps_a_cursor(&self, inst: &GraphInst, list: &List) -> bool {
        let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
            return false;
        };
        let Some(at) = self.root(*addr) else {
            return false;
        };
        let size = self.size(*val);
        [list.offset, list.overflow]
            .into_iter()
            .filter(|cursor| cursor.overlaps(at, size))
            .any(|cursor| self.step_or_note(*val, cursor))
    }

    fn step_or_note(&self, val: ValueId, cursor: Cell) -> bool {
        if self.steps(val, cursor, self.width.into()) {
            return true;
        }
        if self.constant(val).is_none() {
            r2il::refusal_evidence!(
                "tail-count",
                "a store to {cursor:?} is no step: {val:?} defined by {:?}",
                self.op(val)
            );
        }
        false
    }

    /// The header of the innermost loop holding every step, whose only exit leaves from the
    /// header and which no block returns from.
    fn counted_loop(&self, advances: &[BlockId]) -> Result<u64, String> {
        let addrs = advances
            .iter()
            .map(|block| self.graph.block(*block).map(|block| block.addr))
            .collect::<Option<Vec<_>>>()
            .ok_or("a step has no block")?;
        let natural = self
            .function
            .natural_loops()
            .iter()
            .filter(|natural| addrs.iter().all(|addr| natural.body.contains(addr)))
            .min_by_key(|natural| natural.body.len())
            .ok_or("no loop holds every step")?;
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
        Ok(natural.header)
    }

    /// The counter and the count the header compares: the loop continues while the counter is
    /// below the count, or differs from it, so the counter never passes the count.
    fn bound(&self, header: u64) -> Result<Bound, String> {
        let predicates =
            crate::semantic::collect_predicate_facts(self.function, Some(self.prep), self.graph);
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

    /// Every store to a tracked cell is `va_start`'s, a cursor's step, the counter's, or the one
    /// that keeps the count; anything else refuses.
    fn classify_stores(&self, list: &List, bound: &Bound) -> Result<Stores, String> {
        let saved = self.saved();
        let tracked = [list.base, list.offset, list.overflow, saved];
        let inside = |cell: &Cell| tracked.iter().any(|t| t.overlaps(cell.at, cell.size));
        if [bound.counter, bound.count].iter().any(inside) {
            return Err("the counter or the count sits in the va_list or its area".into());
        }
        let next = self.area.base
            + i64::from(self.width) * i64::try_from(self.area.named).unwrap_or(0)
            - self.area.bound;
        let cells = Cells {
            list,
            bound,
            saved,
            next,
        };
        let mut found = Found::default();
        let mut events = vec![Vec::new(); self.graph.blocks.len()];
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                continue;
            };
            let Some(at) = self.root(*addr) else {
                continue;
            };
            let mut note = |event| events[inst.block.index()].push((inst.ordinal, event));
            match self.write(&cells, at, *val)? {
                Write::Other | Write::Save => {}
                Write::BaseInit => found.base_inits += 1,
                Write::OffsetInit => found.offset_inits += 1,
                Write::OverflowInit(first) => found.overflow_inits.push(first),
                Write::Advance => note(Event::Advance),
                Write::CounterStep => note(Event::CounterStep),
                Write::CounterInit => {
                    note(Event::CounterInit);
                    found.counter_inits.push(inst.id);
                }
                Write::CountStore => found.count_stores.push((inst.id, *val)),
            }
        }
        found.into_stores(events)
    }

    /// What a store of `val` at `at` is to the cells.
    fn write(&self, cells: &Cells, at: i64, val: ValueId) -> Result<Write, String> {
        let (list, bound) = (cells.list, cells.bound);
        let size = self.size(val);
        let whole = |cell: Cell| cell.at == at && cell.size == size;
        if cells.saved.overlaps(at, size) {
            return self.save(val, at);
        }
        if list.base.overlaps(at, size) {
            return self.base_write(val, whole(list.base));
        }
        if list.overflow.overlaps(at, size) {
            return self.overflow_write(val, whole(list.overflow), list.overflow);
        }
        if list.offset.overlaps(at, size) {
            let wide = at == list.offset.at && size > list.offset.size;
            let fields = (whole(list.offset), wide);
            return self.offset_write(val, fields, (list.offset, cells.next));
        }
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

    fn overflow_write(&self, val: ValueId, whole: bool, cell: Cell) -> Result<Write, String> {
        if !whole {
            return Err("the overflow pointer is written in part".into());
        }
        if self.steps(val, cell, self.width.into()) {
            return Ok(Write::Advance);
        }
        match self.root(val) {
            Some(first) => Ok(Write::OverflowInit(first)),
            None => Err("the overflow pointer is set to something else".into()),
        }
    }

    /// `fields` is whether the store is the offset field's own, and whether it is a wider word
    /// starting there; `(cell, next)` the field and the value `va_start` leaves in it.
    fn offset_write(
        &self,
        val: ValueId,
        (whole, wide): (bool, bool),
        (cell, next): (Cell, i64),
    ) -> Result<Write, String> {
        if whole && self.steps(val, cell, self.width.into()) {
            return Ok(Write::Advance);
        }
        match (whole || wide) && self.sets_offset(val, cell, next) {
            true => Ok(Write::OffsetInit),
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
    fn sets_offset(&self, value: ValueId, offset: Cell, next: i64) -> bool {
        let Some((bits, size)) = self.prep.views.representative_constant(value) else {
            return false;
        };
        let mask = u64::MAX >> (64 - 8 * offset.size.clamp(1, 8));
        size >= offset.size && bits & mask == next.cast_unsigned() & mask
    }

    /// An address into the cells or the area is only loaded or stored through, bar `va_start`'s
    /// two stores of an address: nothing else writes a cell or reads the tail without a cursor.
    fn contain_cursors(
        &self,
        list: &List,
        bound: &Bound,
        overflow_init: i64,
    ) -> Result<(), String> {
        let spans = [
            list.base,
            list.offset,
            list.overflow,
            bound.counter,
            bound.count,
            self.saved(),
        ];
        for value in &self.graph.values {
            let Some(at) = self.root(value.id) else {
                continue;
            };
            if !spans.iter().any(|span| span.holds(at)) && at < overflow_init {
                continue;
            }
            self.confined(value.id, at, list)?;
        }
        Ok(())
    }

    /// Every use of the address `value`, rooted at `at`, is contained.
    fn confined(&self, value: ValueId, at: i64, list: &List) -> Result<(), String> {
        for site in self.graph.use_sites(value) {
            let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
            if !self.contained_use(inst, value, list) {
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

    /// Every load through a cursor reads the next slot: the base indexed by the register offset, or
    /// the overflow pointer itself, and nothing else holds a cursor's value. The loads are events.
    fn fetches(
        &self,
        list: &List,
        overflow_init: i64,
        events: &mut [Vec<(usize, Event)>],
    ) -> Result<(), String> {
        let mut found = Fetching {
            list,
            tail: vec![None; self.graph.values.len()],
            pending: Vec::new(),
            fetched: crate::dense::IdSet::new(self.graph.insts.len()),
            events,
        };
        for inst in &self.graph.insts {
            self.cursor_load(&mut found, inst, overflow_init)?;
        }
        while let Some(value) = found.pending.pop() {
            let kind = found.tail[value.index()].ok_or("an untagged cursor value")?;
            for site in self.graph.use_sites(value) {
                let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
                self.cursor_use(&mut found, (value, kind), inst)?;
            }
        }
        self.merged_addresses(&found)
    }

    /// A load of a cell: the tail is never read at a constant address, and a cursor's own cell is
    /// read whole.
    fn cursor_load(
        &self,
        found: &mut Fetching,
        inst: &GraphInst,
        overflow_init: i64,
    ) -> Result<(), String> {
        let InstPayload::Op(SSAOp::Load { addr, .. }) = &inst.payload else {
            return Ok(());
        };
        let (Some(at), Some(out)) = (self.root(*addr), inst.output) else {
            return Ok(());
        };
        let size = self.size(out);
        let cell = Cell { at, size };
        let unnamed = i64::from(self.width) * i64::try_from(self.area.named).unwrap_or(0);
        if self.saved().overlaps(at, size) && at >= self.area.base + unnamed || at >= overflow_init
        {
            return Err(format!("the tail is read at {at:#x} without a cursor"));
        }
        let list = found.list;
        let read = (inst.ordinal, Event::Read);
        if cell == list.base {
            found.tag(out, Tail::Base);
        } else if cell == list.overflow {
            found.events[inst.block.index()].push(read);
            found.tag(out, Tail::Address);
        } else if list.offset.overlaps(at, size) {
            if cell != list.offset {
                return Err("the offset is read in part".into());
            }
            found.events[inst.block.index()].push(read);
        } else if list.base.overlaps(at, size) || list.overflow.overlaps(at, size) {
            return Err("a cursor pointer is read in part".into());
        }
        Ok(())
    }

    /// One use of a cursor value `value` of `kind`.
    fn cursor_use(
        &self,
        found: &mut Fetching,
        (value, kind): (ValueId, Tail),
        inst: &GraphInst,
    ) -> Result<(), String> {
        // A use nothing observes (the flags an `add` sets) reads no slot.
        let unobserved = (inst.output).is_some_and(|out| !self.observations.contains(out));
        if unobserved && !matches!(inst.payload, InstPayload::Op(SSAOp::Load { .. })) {
            return Ok(());
        }
        match &inst.payload {
            InstPayload::Op(SSAOp::Load { addr, dst, .. }) if *addr == value => {
                self.fetch(found, inst, kind, *dst)
            }
            InstPayload::Op(SSAOp::Copy { dst, src }) if *src == value => {
                found.tag(*dst, kind);
                Ok(())
            }
            InstPayload::Phi { .. } if kind == Tail::Address => {
                found.tag(inst.output.ok_or("a phi without an output")?, Tail::Address);
                Ok(())
            }
            InstPayload::Op(SSAOp::IntAdd { dst, a, b }) => {
                let other = if *a == value { *b } else { *a };
                self.cursor_add(found, kind, *dst, other)
            }
            other => Err(format!("a cursor value is used by {other:?}")),
        }
    }

    fn fetch(
        &self,
        found: &mut Fetching,
        inst: &GraphInst,
        kind: Tail,
        dst: ValueId,
    ) -> Result<(), String> {
        if kind == Tail::Base || self.size(dst) > self.width {
            return Err("a cursor is loaded through other than a slot".into());
        }
        if found.fetched.insert(inst.id) {
            found.events[inst.block.index()].push((inst.ordinal, Event::Fetch));
        }
        Ok(())
    }

    /// `cursor + other`: the base and the register offset make an address, an address and one slot
    /// make the next stack pointer, which only the pointer's cell takes.
    fn cursor_add(
        &self,
        found: &mut Fetching,
        kind: Tail,
        dst: ValueId,
        other: ValueId,
    ) -> Result<(), String> {
        let list = found.list;
        match kind {
            Tail::Base if self.offset_index(other, list.offset) => found.tag(dst, Tail::Address),
            Tail::Address
                if self.constant(other) == Some(self.width.into())
                    && self.only_stored_to(dst, list.overflow) => {}
            _ => {
                return Err(format!(
                    "a {kind:?} cursor is added {:?} defined by {:?}",
                    other,
                    self.op(other)
                ));
            }
        }
        Ok(())
    }

    /// An address that merges with a value that is no cursor is no cursor.
    fn merged_addresses(&self, found: &Fetching) -> Result<(), String> {
        for inst in &self.graph.insts {
            let (InstPayload::Phi { .. }, Some(out)) = (&inst.payload, inst.output) else {
                continue;
            };
            let merges = |input: &ValueId| found.tail[input.index()] != Some(Tail::Address);
            if found.tail[out.index()] == Some(Tail::Address)
                && self.graph.inputs(inst.id).iter().any(merges)
            {
                return Err("an address merges with a value that is no cursor".into());
            }
        }
        Ok(())
    }

    /// Whether every use of `value`, through copies, stores it whole to `cell`.
    fn only_stored_to(&self, value: ValueId, cell: Cell) -> bool {
        let mut pending = vec![value];
        let mut seen = crate::dense::IdSet::<ValueId>::new(self.graph.values.len());
        while let Some(value) = pending.pop() {
            if seen.insert(value) && !self.sinks_into(value, cell, &mut pending) {
                return false;
            }
        }
        true
    }

    /// Whether every use of `value` is a copy (queued in `copies`) or a whole store to `cell`.
    fn sinks_into(&self, value: ValueId, cell: Cell, copies: &mut Vec<ValueId>) -> bool {
        self.graph.use_sites(value).iter().all(|site| {
            match self.graph.inst(site.inst).map(|inst| &inst.payload) {
                Some(InstPayload::Op(SSAOp::Copy { dst, .. })) => {
                    copies.push(*dst);
                    true
                }
                Some(InstPayload::Op(SSAOp::Store { addr, val, .. })) => {
                    *val == value && self.root(*addr) == Some(cell.at)
                }
                _ => false,
            }
        })
    }

    /// Each trip steps the counter once and pays for one cursor step and one fetch: a tally per
    /// block, checked once per edge, so the loop reads no more slots than the counter passes.
    fn check_paths(&self, header: u64, stores: &Stores) -> Result<(), String> {
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
        let walk = Walk { in_loop, header };
        let misplaced = (stores.events.iter().enumerate())
            .flat_map(|(index, events)| events.iter().map(move |(_, event)| (index, *event)))
            .find(|(index, event)| !walk.placed(*index, *event));
        if let Some((_, event)) = misplaced {
            return Err(format!("{event:?} sits outside its place in the loop"));
        }
        let entry = self.graph.entry;
        let mut seen: Vec<Option<Tally>> = vec![None; blocks];
        seen[entry.index()] = Some(Tally::default());
        // Each block is expanded once, on its first arrival; a later arrival must carry the same tally.
        let mut pending = vec![entry];
        while let Some(block) = pending.pop() {
            let tally = seen[block.index()].ok_or("a block without a tally")?;
            let tally = tally.run(&stores.events[block.index()])?;
            for next in &self.graph.block(block).ok_or("no block")?.successors {
                let onward = walk.across(tally, block, *next)?;
                arrive(&mut seen, &mut pending, *next, onward)?;
            }
        }
        Ok(())
    }

    /// The counter is zeroed and the count kept before the loop runs.
    fn dominating(&self, header: u64, stores: &Stores) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        for store in [stores.counter_init, stores.count_store.0] {
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
