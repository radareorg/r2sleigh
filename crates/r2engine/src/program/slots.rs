//! Results from declared callback slots (S30, D227; doc/adr-call-boundary.md "S30 as built"): a
//! function whose address every take hands only into cited code-pointer slots.

use r2abi::ResultRead;
use r2abi::statement::SourceLanguage;
use r2il::R2ILOp;
use r2source::{CanonicalStorageId, CanonicalStorageSpace, SourceSlotOrigin};
use r2ssa::site_boundary::{CallReadsAt, RegisterFate, Transfer};

use super::fates::BodyRead;
use super::reads::Escapes;
use super::{ProgramInputs, Source, View};
use crate::query::db::{Db, Query, Retention};

/// The least cited slot a take hands an address into, and what the slots it reaches read of the
/// result: a `void` slot nothing, an `int` one its integer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SlotProof {
    pub(super) origin: SourceSlotOrigin,
    pub(super) reads: ResultRead,
}

impl SlotProof {
    /// Both slots' least origin; a read by either is a read.
    fn join(self, other: Self) -> Self {
        let reads = match (self.reads, other.reads) {
            (ResultRead::Integer { bytes: a }, ResultRead::Integer { bytes: b }) => {
                ResultRead::Integer { bytes: a.max(b) }
            }
            (ResultRead::Nothing, read) | (read, ResultRead::Nothing) => read,
        };
        Self {
            origin: self.origin.min(other.origin),
            reads,
        }
    }
}

/// The cited slots every way in other than a call takes `entry`'s address into; `None` where a
/// take is anything else (doc/adr-call-boundary.md, "S30 as built").
pub(super) struct DeclaredSlot;

impl<S: Source + 'static> Query<ProgramInputs<S>> for DeclaredSlot {
    type Key = u64;
    type Value = Option<SlotProof>;
    const NAME: &'static str = "declared-slot";
    const RETENTION: Retention = Retention::Held;

    /// Work: per take, one walk of one register over its owner's held body, `O(B + E)`, and one
    /// `SlotParameter` per body it is handed to.
    fn compute(db: &Db<ProgramInputs<S>>, &entry: &u64) -> Self::Value {
        let language = db.inputs().source.container().languages.at(entry);
        let c_like = matches!(
            language,
            SourceLanguage::C | SourceLanguage::Cpp | SourceLanguage::Rust
        );
        if !c_like {
            return None;
        }
        let escapes = db.get::<Escapes>(&()).ok()?;
        let ways = escapes.as_ref().as_ref()?;
        if ways.escaped(entry) || ways.takes_of(entry).is_empty() {
            r2il::refusal_evidence!(
                "declared-slot",
                "{entry:#x}: escaped {}, takes {}",
                ways.escaped(entry),
                ways.takes_of(entry).len()
            );
            return None;
        }
        let mut proof = None::<SlotProof>;
        for take in ways.takes_of(entry) {
            let slot = taken_into_slots(db, take.owner, take.from)?;
            proof = Some(proof.map_or(slot, |known| known.join(slot)));
        }
        r2il::refusal_evidence!("declared-slot", "{entry:#x}: every take reaches {proof:?}");
        proof
    }
}

/// The cited slots `register` reaches from `body`'s entry when every path hands it only into
/// them; `None` otherwise. Asked per (body, register) as a take hands one on.
pub(super) struct SlotParameter;

impl<S: Source + 'static> Query<ProgramInputs<S>> for SlotParameter {
    type Key = (u64, bool, CanonicalStorageId);
    type Value = Option<SlotProof>;
    const NAME: &'static str = "slot-parameter";
    const RETENTION: Retention = Retention::Held;

    /// Work: one walk of one register over the held body, `O(B + E)`. A body that reaches itself
    /// again is a cycle the database refuses, which reads as no slot: the least answer.
    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb, register): &Self::Key) -> Self::Value {
        super::fates::read_body(db, (entry, thumb), |read| {
            let reads = SiteReads::of(db, read);
            let fate = read.flow.fate_from_entry(entry, register, &reads);
            r2il::refusal_evidence!("declared-slot", "{entry:#x} entered: {register:?} {fate:?}");
            into_slots(db, fate)
        })
        .flatten()
    }
}

/// The slots the register `from` writes in `owner` reaches; `None` unless the instruction writes
/// exactly one register and every path hands it only into cited slots.
fn taken_into_slots<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    owner: u64,
    from: u64,
) -> Option<SlotProof> {
    let thumb = View::new(db, true).thumb_at(owner);
    super::fates::read_body(db, (owner, thumb), |read| {
        let blocks = &read.body.blocks;
        let held = blocks.partition_point(|block| block.lifted.addr <= from);
        let block = held.checked_sub(1)?;
        let lifted = &blocks[block].lifted;
        let ops = (0..lifted.ops.len()).filter(|op| lifted.instruction_of(*op) == Some(from));
        let ops = ops.collect::<Vec<_>>();
        let last = *ops.last()?;
        let mut written = (ops.iter())
            .filter_map(|op| lifted.ops[*op].output())
            .filter(|output| output.space == r2il::SpaceId::Register)
            .map(CanonicalStorageId::from_varnode)
            .collect::<Vec<_>>();
        // A narrow write the instruction widens (`mov edi, imm` zero-extends into RDI) is one write.
        let widest = written.iter().copied().max_by_key(|written| written.size);
        let within = |inner: &CanonicalStorageId, outer: &CanonicalStorageId| {
            outer.offset <= inner.offset
                && inner.offset + u64::from(inner.size) <= outer.offset + u64::from(outer.size)
        };
        if let Some(widest) = widest {
            written.retain(|written| !within(written, &widest) || *written == widest);
        }
        written.sort_unstable();
        written.dedup();
        let [register] = written.as_slice() else {
            r2il::refusal_evidence!("declared-slot", "{from:#x}: writes {written:?}");
            return None;
        };
        let reads = SiteReads::of(db, read);
        let fate = read.flow.fate_after(block, last, *register, &reads);
        r2il::refusal_evidence!("declared-slot", "{from:#x}: {register:?} {fate:?}");
        into_slots(db, fate)
    })
    .flatten()
}

/// The slots a fate hands its register into, where every handoff is into a cited slot: an
/// import's code-pointer parameter, or a body's `SlotParameter`. `Dead` and `Other` prove nothing.
fn into_slots<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    fate: RegisterFate,
) -> Option<SlotProof> {
    let RegisterFate::Handed(handed) = fate else {
        return None;
    };
    let view = View::new(db, true);
    let mut least = None::<SlotProof>;
    for handoff in handed.iter() {
        let Transfer::Direct(target) = handoff.target else {
            return None;
        };
        let slot = match crate::native::Program::import_at(&view, target) {
            Some(name) => {
                let walker = super::returns::Walking::new(view.clone(), true).ok()?;
                let native = walker.target(view.thumb_at(target));
                let (parameter, reads) = crate::native::code_slot(native, &name, handoff.storage)?;
                let origin = SourceSlotOrigin {
                    import: target,
                    parameter,
                };
                SlotProof { origin, reads }
            }
            None => {
                let key = (target, view.thumb_at(target), handoff.storage);
                (*db.get::<SlotParameter>(&key).ok()?)?
            }
        };
        least = Some(least.map_or(slot, |known| known.join(slot)));
    }
    least
}

/// What each transfer reads and overwrites: an import's placed reads and clobbers; a body or an
/// unknown target reads everything and overwrites nothing beyond its result lanes.
struct SiteReads<'r> {
    /// Each transfer's target as the walk read it, and what it is, by block and operation.
    callees: Vec<Vec<Option<(u64, Callee)>>>,
    clobbering: Option<&'r r2source::ConventionModel>,
}

/// What one transfer's target is.
enum Callee {
    Import(Option<Vec<CanonicalStorageId>>),
    Other,
}

impl<'r> SiteReads<'r> {
    fn of<S: Source + 'static>(db: &Db<ProgramInputs<S>>, read: &BodyRead<'r, S>) -> Self {
        let view = View::new(db, true);
        let callee = |target: u64| match crate::native::Program::import_at(&view, target) {
            Some(_) => (
                target,
                Callee::Import(super::fates::import_reads(db, target)),
            ),
            None => (target, Callee::Other),
        };
        let mut callees = Vec::with_capacity(read.body.blocks.len());
        for block in &read.body.blocks {
            let read = |(at, operation): (usize, &R2ILOp)| {
                let walked = block.transfers.iter().find(|transfer| transfer.op == at);
                let transfer = operation.transfer()?;
                let direct = transfer.direct && transfer.target.space == r2il::SpaceId::Ram;
                let target = walked.map(|transfer| transfer.target);
                target
                    .or(direct.then_some(transfer.target.offset))
                    .map(callee)
            };
            callees.push(block.lifted.ops.iter().enumerate().map(read).collect());
        }
        Self {
            callees,
            clobbering: read.clobbering(),
        }
    }
}

impl CallReadsAt for SiteReads<'_> {
    fn target(&self, block: usize, op: usize) -> Option<u64> {
        self.callees[block][op].as_ref().map(|(target, _)| *target)
    }

    fn reads(&self, block: usize, op: usize, register: CanonicalStorageId) -> bool {
        match &self.callees[block][op] {
            Some((_, Callee::Import(Some(registers)))) => registers.iter().any(|read| {
                read.space == CanonicalStorageSpace::Register
                    && read.offset < register.offset + u64::from(register.size)
                    && register.offset < read.offset + u64::from(read.size)
            }),
            _ => true,
        }
    }

    fn overwrites(&self, block: usize, op: usize, register: CanonicalStorageId) -> bool {
        let import = matches!(self.callees[block][op], Some((_, Callee::Import(_))));
        import
            && self
                .clobbering
                .is_some_and(|model| model.clobbers(register))
    }
}
