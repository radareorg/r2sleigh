//! The values that hold a variadic body's cursors, wherever they live: in the `va_list`'s cells,
//! in registers, or both (doc/adr-resolved-bodies.md, "Count-driven tail").

use crate::dense::DenseId;
use crate::graph::{GraphInst, InstId, InstPayload};
use crate::tail_count::{COPIES, Cell, Event, List, Prover};
use crate::{SSAOp, ValueId};

/// What a value is to the `va_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The register save area's bound: an address only once an offset is added.
    Base,
    /// An address that is both the bound and the overflow pointer's start (AAPCS64's `__gr_top`
    /// is the first stack argument), whichever its uses make it.
    Rooted,
    /// A position in the register save area, as the offset field states it.
    Offset,
    /// The overflow pointer: it steps, and a load through it is a fetch.
    Overflow,
    /// An address in the tail: the base and an offset, or either path of a merge of them.
    Address,
    /// The overflow pointer plus the rounding the stack's alignment adds, before its mask.
    Rounded,
}

impl Kind {
    /// What a merge of two kinds is, where they can merge.
    fn join(self, other: Self) -> Option<Self> {
        match (self, other) {
            (a, b) if a == b => Some(a),
            (Self::Overflow, Self::Address) | (Self::Address, Self::Overflow) => {
                Some(Self::Address)
            }
            (Self::Rooted, kind @ (Self::Base | Self::Overflow | Self::Address))
            | (kind @ (Self::Base | Self::Overflow | Self::Address), Self::Rooted) => Some(kind),
            _ => None,
        }
    }
}

/// Each value's kind, where it is a cursor.
pub(crate) struct Kinds(Vec<Option<Kind>>);

impl Kinds {
    pub(crate) fn get(&self, value: ValueId) -> Option<Kind> {
        self.0[value.index()]
    }
}

/// What the cursors do: their events by block, the values a step leaves, and the loads that fetch.
pub(crate) struct Cursors {
    pub(crate) kinds: Kinds,
    pub(crate) events: Vec<Vec<(usize, Event)>>,
    pub(crate) steps: Vec<ValueId>,
    pub(crate) step_insts: Vec<InstId>,
    pub(crate) fetches: Vec<(InstId, ValueId)>,
}

impl Prover<'_> {
    /// The cursor values and their events. O(insts + uses): each value is tagged once, a merge of
    /// an overflow pointer with an address once more.
    pub(crate) fn cursors(&self, list: &List, overflow_init: i64) -> Result<Cursors, String> {
        let mut kinds = Kinds(vec![None; self.graph.values.len()]);
        let mut pending = Vec::new();
        self.seeds(&mut kinds, &mut pending, (list, overflow_init))?;
        while let Some(value) = pending.pop() {
            self.spread(&mut kinds, &mut pending, value)?;
        }
        let mut cursors = Cursors {
            kinds,
            events: vec![Vec::new(); self.graph.blocks.len()],
            steps: Vec::new(),
            step_insts: Vec::new(),
            fetches: Vec::new(),
        };
        self.uses(&mut cursors, list)?;
        self.merges(&cursors.kinds)?;
        self.reads(&mut cursors, list);
        if cursors.kinds.0.contains(&Some(Kind::Rounded)) {
            self.aligned(overflow_init)?;
        }
        Ok(cursors)
    }

    /// What the uses of a tagged `value` make of it.
    fn spread(
        &self,
        kinds: &mut Kinds,
        pending: &mut Vec<ValueId>,
        value: ValueId,
    ) -> Result<(), String> {
        let kind = kinds.get(value).ok_or("an untagged cursor value")?;
        for site in self.graph.use_sites(value) {
            let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
            let Some((out, derived)) = self.derived(kinds, value, kind, inst) else {
                continue;
            };
            raise(kinds, pending, out, derived).map_err(|why| {
                format!("{why}, made by {} from a {kind:?}", self.described(out, 3))
            })?;
        }
        Ok(())
    }

    /// A value and what computes it, a few operations deep: refusal evidence.
    pub(crate) fn described(&self, value: ValueId, depth: u8) -> String {
        let def = (self.graph.def_inst(value)).and_then(|inst| self.graph.inst(inst));
        match (def.map(|inst| &inst.payload), depth) {
            (_, 0) | (None, _) => format!("{value:?}"),
            (Some(InstPayload::Phi { .. }), _) => format!("{value:?}=phi"),
            (Some(InstPayload::Op(op)), _) => {
                let inputs = def.map_or(&[][..], |inst| self.graph.inputs(inst.id));
                let inputs = inputs.iter().map(|input| self.described(*input, depth - 1));
                let name = format!("{op:?}");
                let name = name.split([' ', '{']).next().unwrap_or("");
                format!(
                    "{value:?}={name}({})",
                    inputs.collect::<Vec<_>>().join(", ")
                )
            }
        }
    }

    /// The cells' loads, the addresses `va_start` stores, and the offset a merge starts from.
    fn seeds(
        &self,
        kinds: &mut Kinds,
        pending: &mut Vec<ValueId>,
        (list, overflow_init): (&List, i64),
    ) -> Result<(), String> {
        for value in &self.graph.values {
            // The entry stack pointer is no address `va_start` computed.
            if self.graph.def_inst(value.id).is_none() {
                continue;
            }
            let kind = match self.root(value.id) {
                Some(at) if at == self.area.bound && at == overflow_init => Kind::Rooted,
                Some(at) if at == self.area.bound => Kind::Base,
                Some(at) if at == overflow_init => Kind::Overflow,
                _ => continue,
            };
            raise(kinds, pending, value.id, kind)?;
        }
        for inst in &self.graph.insts {
            if let Some((out, kind)) = self.cell_load(inst, list) {
                raise(kinds, pending, out, kind)?;
            }
            for start in self.offset_starts(inst) {
                raise(kinds, pending, start, Kind::Offset)?;
            }
        }
        Ok(())
    }

    /// A load of a whole cell, and what it holds.
    fn cell_load(&self, inst: &GraphInst, list: &List) -> Option<(ValueId, Kind)> {
        let InstPayload::Op(SSAOp::Load { addr, .. }) = &inst.payload else {
            return None;
        };
        let (at, out) = (self.root(*addr)?, inst.output?);
        let cell = Cell {
            at,
            size: self.size(out),
        };
        [
            (list.base, Kind::Base),
            (list.overflow, Kind::Overflow),
            (list.offset, Kind::Offset),
        ]
        .into_iter()
        .find_map(|(whole, kind)| (cell == whole).then_some((out, kind)))
    }

    /// The constants `va_start` leaves in the offset field that a merge takes beside a step of
    /// its own value: where a register-held offset begins.
    fn offset_starts(&self, inst: &GraphInst) -> Vec<ValueId> {
        let inputs = match &inst.payload {
            InstPayload::Phi { .. } => self.graph.inputs(inst.id),
            _ => &[],
        };
        if !inputs.iter().any(|input| self.is_step(*input)) {
            return Vec::new();
        }
        let starts = |input: &ValueId| {
            self.size(*input) >= self.row.offset_width
                && self
                    .constant(*input)
                    .is_some_and(|bits| self.is_next_extended(bits))
        };
        inputs.iter().copied().filter(starts).collect()
    }

    /// Whether the low bytes of `bits` are what `va_start` leaves in the offset field.
    pub(crate) fn is_next(&self, bits: u64) -> bool {
        let mask = u64::MAX >> (64 - 8 * self.row.offset_width.clamp(1, 8));
        bits & mask == self.next().cast_unsigned() & mask
    }

    /// Whether `bits` is that field zero-extended: a register holding the offset.
    fn is_next_extended(&self, bits: u64) -> bool {
        let field = 8 * self.row.offset_width.clamp(1, 8);
        self.is_next(bits) && (field == 64 || bits >> field == 0)
    }

    /// Whether `value` is a constant added to something, in the width of a slot, through the
    /// widenings of a register's low half.
    fn is_step(&self, mut value: ValueId) -> bool {
        for _ in 0..COPIES {
            match self.op(value) {
                Some(SSAOp::IntAdd { a, b, .. }) => {
                    return [*a, *b]
                        .into_iter()
                        .any(|by| self.constant(by) == Some(self.width.into()));
                }
                Some(SSAOp::IntZExt { src, .. } | SSAOp::IntSExt { src, .. }) => value = *src,
                _ => return false,
            }
        }
        false
    }

    /// The value `inst` makes of the cursor `value` of `kind`, where it makes another cursor.
    fn derived(
        &self,
        kinds: &Kinds,
        value: ValueId,
        kind: Kind,
        inst: &GraphInst,
    ) -> Option<(ValueId, Kind)> {
        let out = inst.output?;
        match &inst.payload {
            // A merge nothing observes (a register the paths leave different) holds no cursor.
            InstPayload::Phi { .. } => self.observations.contains(out).then_some((out, kind)),
            InstPayload::Op(SSAOp::Copy { .. }) => Some((out, kind)),
            InstPayload::Op(
                SSAOp::IntZExt { .. }
                | SSAOp::IntSExt { .. }
                | SSAOp::Trunc { .. }
                | SSAOp::Subpiece { offset: 0, .. },
            ) => (kind == Kind::Offset).then_some((out, kind)),
            InstPayload::Op(SSAOp::IntAdd { a, b, .. }) => {
                let other = if *a == value { *b } else { *a };
                self.added(kinds, kind, other).map(|derived| (out, derived))
            }
            InstPayload::Op(SSAOp::IntAnd { a, b, .. }) if kind == Kind::Rounded => {
                let other = if *a == value { *b } else { *a };
                (self.constant(other) == Some(self.mask())).then_some((out, Kind::Overflow))
            }
            _ => None,
        }
    }

    /// `cursor + other`: the base and an offset make an address, a slot makes the next cursor.
    fn added(&self, kinds: &Kinds, kind: Kind, other: ValueId) -> Option<Kind> {
        let slot = self.constant(other) == Some(self.width.into());
        match (kind, kinds.get(other)) {
            (Kind::Base | Kind::Rooted, Some(Kind::Offset))
            | (Kind::Offset, Some(Kind::Base | Kind::Rooted)) => Some(Kind::Address),
            (Kind::Offset | Kind::Overflow, _) if slot => Some(kind),
            (Kind::Rooted, _) if slot => Some(Kind::Overflow),
            (Kind::Overflow | Kind::Rooted, _) if self.constant(other) == Some(self.round()) => {
                Some(Kind::Rounded)
            }
            _ => None,
        }
    }

    /// What the stack's alignment adds to a step and masks off: a slot and the bits below it.
    fn round(&self) -> u64 {
        2 * u64::from(self.width) - 1
    }

    fn mask(&self) -> u64 {
        !(u64::from(self.width) - 1)
    }

    /// Every use of every cursor is one the proof reads, and the events they make.
    fn uses(&self, cursors: &mut Cursors, list: &List) -> Result<(), String> {
        for value in &self.graph.values {
            let Some(kind) = cursors.kinds.get(value.id) else {
                continue;
            };
            for site in self.graph.use_sites(value.id) {
                let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
                self.cursor_use(cursors, list, (value.id, kind), inst)?;
            }
        }
        Ok(())
    }

    fn cursor_use(
        &self,
        cursors: &mut Cursors,
        list: &List,
        (value, kind): (ValueId, Kind),
        inst: &GraphInst,
    ) -> Result<(), String> {
        let unobserved = (inst.output).is_some_and(|out| !self.observations.contains(out));
        // A constant address is the frame's own: the cells and the tail are checked where they sit.
        let constant = self.root(value).is_some();
        let address = match &inst.payload {
            InstPayload::Op(SSAOp::Load { .. }) => true,
            InstPayload::Op(SSAOp::Store { addr, .. }) => *addr == value,
            _ => false,
        };
        let rooted_arithmetic = matches!(
            inst.payload,
            InstPayload::Op(SSAOp::IntAdd { .. } | SSAOp::IntSub { .. })
        ) && inst.output.is_some_and(|out| self.root(out).is_some());
        if constant && (address || rooted_arithmetic) {
            return Ok(());
        }
        match &inst.payload {
            // A call reads the convention's argument registers, not the callee's: no slot.
            InstPayload::Op(SSAOp::CallUse { .. }) => Ok(()),
            InstPayload::Op(SSAOp::Load { dst, .. }) => {
                self.fetch(cursors, inst, (value, kind), *dst)
            }
            InstPayload::Op(SSAOp::Store { addr, val, .. }) => {
                if *addr == value {
                    return Err("a store goes through a cursor".into());
                }
                self.cursor_store(list, (*val, kind), *addr)
            }
            // A use nothing observes (the flags an `add` sets) reads no slot.
            _ if unobserved => Ok(()),
            InstPayload::Op(SSAOp::Copy { .. }) | InstPayload::Phi { .. } => Ok(()),
            InstPayload::Op(
                SSAOp::IntZExt { .. }
                | SSAOp::IntSExt { .. }
                | SSAOp::Trunc { .. }
                | SSAOp::Subpiece { offset: 0, .. },
            ) if kind == Kind::Offset => Ok(()),
            InstPayload::Op(SSAOp::IntAdd { dst, a, b }) => {
                let other = if *a == value { *b } else { *a };
                self.cursor_add(cursors, inst, (kind, *dst), other)
            }
            InstPayload::Op(SSAOp::IntAnd { dst, .. }) if kind == Kind::Rounded => {
                if cursors.kinds.get(*dst) != Some(Kind::Overflow) {
                    return Err("the rounded pointer is masked other than to a slot".into());
                }
                self.step(cursors, inst, *dst);
                Ok(())
            }
            // An offset beside the limit it is tested against reads no slot: only an address does.
            _ if kind == Kind::Offset => Ok(()),
            other => Err(format!("a {kind:?} cursor is used by {other:?}")),
        }
    }

    fn step(&self, cursors: &mut Cursors, inst: &GraphInst, out: ValueId) {
        cursors.events[inst.block.index()].push((inst.ordinal, Event::Advance));
        cursors.steps.push(out);
        cursors.step_insts.push(inst.id);
    }

    /// A cell's load is an event where its value reaches a fetch or a step: it must see what the
    /// trip started with. A value that is only compared reads no slot.
    fn reads(&self, cursors: &mut Cursors, list: &List) {
        let mut feeding = crate::dense::IdSet::<ValueId>::new(self.graph.values.len());
        let mut pending = cursors
            .fetches
            .iter()
            .map(|(_, address)| *address)
            .collect::<Vec<_>>();
        for inst in &cursors.step_insts {
            pending.extend(self.graph.inputs(*inst).iter().copied());
        }
        while let Some(value) = pending.pop() {
            if cursors.kinds.get(value).is_none() || !feeding.insert(value) {
                continue;
            }
            let Some(def) = self
                .graph
                .def_inst(value)
                .and_then(|inst| self.graph.inst(inst))
            else {
                continue;
            };
            pending.extend(self.graph.inputs(def.id).iter().copied());
        }
        for inst in &self.graph.insts {
            let read = self
                .cell_load(inst, list)
                .filter(|(out, kind)| *kind != Kind::Base && feeding.contains(*out));
            if read.is_some() {
                cursors.events[inst.block.index()].push((inst.ordinal, Event::Read));
            }
        }
    }

    /// A rounded step moves one slot only from an address aligned to it: the first stack argument
    /// sits at a multiple of the slot from the entry stack pointer the convention aligns.
    fn aligned(&self, overflow_init: i64) -> Result<(), String> {
        let slot = i64::from(self.width);
        let entry = self
            .slots
            .entry_stack()
            .ok_or("the entry stack is not aligned by the convention")?;
        let stated = i64::from(entry.alignment) % slot == 0;
        match stated && (i64::from(entry.residue) + overflow_init).rem_euclid(slot) == 0 {
            true => Ok(()),
            false => Err("the overflow pointer starts unaligned to a slot".into()),
        }
    }

    fn cursor_add(
        &self,
        cursors: &mut Cursors,
        inst: &GraphInst,
        (kind, dst): (Kind, ValueId),
        other: ValueId,
    ) -> Result<(), String> {
        let derived = cursors.kinds.get(dst);
        let slot = self.constant(other) == Some(self.width.into());
        match kind {
            Kind::Offset if slot && derived == Some(kind) => {
                // A sum only compared (`cmn` beside the `add`) moves no cursor.
                if !self.compared_only(dst) {
                    self.step(cursors, inst, dst);
                }
                Ok(())
            }
            Kind::Overflow | Kind::Rooted if slot && derived == Some(Kind::Overflow) => {
                self.step(cursors, inst, dst);
                Ok(())
            }
            Kind::Overflow | Kind::Rooted if derived == Some(Kind::Rounded) => Ok(()),
            Kind::Offset if derived != Some(Kind::Address) => Ok(()),
            Kind::Base | Kind::Rooted | Kind::Offset if derived == Some(Kind::Address) => Ok(()),
            _ => Err(format!(
                "a {kind:?} cursor is added {other:?} defined by {:?}",
                self.op(other)
            )),
        }
    }

    /// Whether every use of `value`, through the copies and low pieces, is a comparison.
    fn compared_only(&self, value: ValueId) -> bool {
        let mut pending = vec![value];
        for _ in 0..COPIES {
            let Some(value) = pending.pop() else {
                return true;
            };
            if !self.passes_on(value, &mut pending) {
                return false;
            }
        }
        pending.is_empty()
    }

    /// Whether each use of `value` is a comparison or a copy, which `pending` then follows.
    fn passes_on(&self, value: ValueId, pending: &mut Vec<ValueId>) -> bool {
        self.graph.use_sites(value).iter().all(|site| {
            let Some((InstPayload::Op(op), out)) =
                self.graph.inst(site.inst).map(|i| (&i.payload, i.output))
            else {
                return false;
            };
            match (is_comparison(op), out.filter(|_| is_low_copy(op))) {
                (true, _) => true,
                (_, Some(out)) => {
                    pending.push(out);
                    true
                }
                _ => false,
            }
        })
    }

    /// A load through a cursor: the overflow pointer or an address fetches one slot.
    fn fetch(
        &self,
        cursors: &mut Cursors,
        inst: &GraphInst,
        (address, kind): (ValueId, Kind),
        dst: ValueId,
    ) -> Result<(), String> {
        match kind {
            Kind::Overflow | Kind::Address | Kind::Rooted if self.size(dst) <= self.width => {
                if !cursors.fetches.iter().any(|(fetch, _)| *fetch == inst.id) {
                    cursors.events[inst.block.index()].push((inst.ordinal, Event::Fetch));
                    cursors.fetches.push((inst.id, address));
                }
                Ok(())
            }
            Kind::Base if self.root(address).is_some() => Ok(()),
            _ => Err(format!(
                "a {kind:?} cursor is loaded through other than a slot"
            )),
        }
    }

    /// A cursor stored whole to the cell of its kind.
    fn cursor_store(
        &self,
        list: &List,
        (val, kind): (ValueId, Kind),
        addr: ValueId,
    ) -> Result<(), String> {
        let cells: &[Cell] = match kind {
            Kind::Base => &[list.base],
            Kind::Overflow => &[list.overflow],
            Kind::Rooted => &[list.base, list.overflow],
            Kind::Offset => &[list.offset],
            Kind::Address | Kind::Rounded => {
                return Err(format!("a {kind:?} cursor is stored"));
            }
        };
        let to = self.root(addr);
        match cells
            .iter()
            .any(|cell| to == Some(cell.at) && self.size(val) == cell.size)
        {
            true => Ok(()),
            false => Err(format!(
                "a {kind:?} cursor is stored other than to its cell"
            )),
        }
    }

    /// A merge holding a cursor merges cursors only: the paths of a fetch, never a value that is
    /// no cursor.
    fn merges(&self, kinds: &Kinds) -> Result<(), String> {
        for inst in &self.graph.insts {
            let (InstPayload::Phi { .. }, Some(out)) = (&inst.payload, inst.output) else {
                continue;
            };
            let plain =
                (self.graph.inputs(inst.id).iter()).find(|input| kinds.get(**input).is_none());
            // A merge nothing observes (a register the loop leaves behind) holds no cursor.
            if !self.observations.contains(out) {
                continue;
            }
            if let (Some(kind), Some(plain)) = (kinds.get(out), plain) {
                return Err(format!(
                    "a {kind:?} cursor merges with {plain:?} defined by {:?}",
                    self.op(*plain)
                ));
            }
        }
        Ok(())
    }

    /// No fetch reads a slot the trip's own step moved to: a value that follows a step reaches a
    /// load only round the loop's header.
    pub(crate) fn fresh(
        &self,
        cursors: &Cursors,
        header: crate::graph::BlockId,
    ) -> Result<(), String> {
        let mut stepped = crate::dense::IdSet::<ValueId>::new(self.graph.values.len());
        let mut pending = cursors.steps.clone();
        while let Some(value) = pending.pop() {
            if !stepped.insert(value) {
                continue;
            }
            let kind = cursors.kinds.get(value).ok_or("an untagged cursor value")?;
            for site in self.graph.use_sites(value) {
                let inst = (self.graph.inst(site.inst)).ok_or("a use has no instruction")?;
                let leaves =
                    matches!(inst.payload, InstPayload::Phi { .. }) && inst.block == header;
                let flowing = self.derived(&cursors.kinds, value, kind, inst);
                pending.extend(flowing.filter(|_| !leaves).map(|(out, _)| out));
            }
        }
        match cursors
            .fetches
            .iter()
            .find(|(_, address)| stepped.contains(*address))
        {
            Some(_) => Err("a fetch reads the slot its trip's step moved to".into()),
            None => Ok(()),
        }
    }
}

fn is_comparison(op: &SSAOp<ValueId>) -> bool {
    matches!(
        op,
        SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntLessEqual { .. }
    )
}

fn is_low_copy(op: &SSAOp<ValueId>) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. } | SSAOp::Subpiece { offset: 0, .. } | SSAOp::IntZExt { .. }
    )
}

/// Tag `value` as `kind`, or join it with what it was; a change is queued again.
fn raise(
    kinds: &mut Kinds,
    pending: &mut Vec<ValueId>,
    value: ValueId,
    kind: Kind,
) -> Result<(), String> {
    let slot = &mut kinds.0[value.index()];
    let joined = match *slot {
        None => kind,
        Some(old) => old
            .join(kind)
            .ok_or_else(|| format!("a {old:?} cursor merges with a {kind:?} one at {value:?}"))?,
    };
    if *slot != Some(joined) {
        *slot = Some(joined);
        pending.push(value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Kind::{Address, Base, Offset, Overflow, Rooted, Rounded};

    #[test]
    fn the_kinds_that_merge_are_the_paths_of_one_fetch_and_the_one_address_both_roles_share() {
        assert_eq!(Overflow.join(Address), Some(Address));
        assert_eq!(Address.join(Overflow), Some(Address));
        assert_eq!(Rooted.join(Overflow), Some(Overflow));
        assert_eq!(Base.join(Rooted), Some(Base));
        assert_eq!(Offset.join(Offset), Some(Offset));
    }

    #[test]
    fn a_cursor_never_merges_with_a_cursor_of_another_role() {
        assert_eq!(Offset.join(Base), None);
        assert_eq!(Overflow.join(Offset), None);
        assert_eq!(Rounded.join(Overflow), None);
        assert_eq!(Rooted.join(Offset), None);
    }
}
