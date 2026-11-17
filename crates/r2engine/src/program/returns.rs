//! Whether control comes back from a call to each function, for one state of the bytes.

use std::collections::BTreeMap;

use crate::body::{Body, BodyError, Trace};
use crate::machine::Machine;

use super::{ProgramInputs, Source, View};
use crate::discovery::{Return, Transfers, Walker};
use crate::native::{NativeRefusal, NativeTarget};
use crate::query::db::{Db, Query, Retention};

/// One body being walked, and whether it is walked as Thumb.
pub(super) struct BodyWalk {
    entry: u64,
    trace: Trace,
    pub(super) thumb: bool,
    /// How far the survey has read the body's tables.
    tables: Tabled,
    /// The supervisor calls its seal proves never come back, read once where it reaches no return.
    halts: Halts,
}

/// The supervisor calls of one body a kernel row proves halting, by instruction (D505).
type Halts = BTreeMap<u64, r2source::Citation>;

/// The tables a survey's walk followed: none asked yet, none to ask, or the read it followed.
enum Tabled {
    Unread,
    Untabled,
    Read(super::analysis::Shared<crate::native::Tables>),
}

impl BodyWalk {
    /// The blocks the walk traced, and their bytes.
    pub(super) fn extent(&self) -> crate::body::TraceExtent {
        self.trace.extent()
    }

    /// The instructions the walk reached that enter the supervisor.
    pub(super) fn supervisor_calls(&self) -> &std::collections::BTreeSet<u64> {
        self.trace.supervisor_calls()
    }

    /// The address after each call the walk ended a block at because its callee never comes back.
    pub(super) fn exits_after(&self) -> impl Iterator<Item = u64> + '_ {
        self.trace.exits_after()
    }

    /// Every direct call target the walk reached.
    pub(super) fn calls(&self) -> &std::collections::BTreeSet<u64> {
        self.trace.calls()
    }

    /// Every function entry the walk leaves for by a direct branch.
    pub(super) fn tail_calls(&self) -> impl Iterator<Item = u64> + '_ {
        self.trace.tail_calls().iter().copied()
    }

    /// Whether a call of the body unwinds to a landing pad (D570).
    pub(super) fn unwinds(&self) -> bool {
        self.trace.unwinds()
    }

    /// The bytes the walk decoded as this body's instructions.
    pub(super) fn spans(&self) -> Vec<std::ops::Range<u64>> {
        self.trace.spans()
    }
}

/// Discovery's walker over one open program.
pub(super) struct Walking<'p, S: Source + 'static> {
    program: View<'p, S>,
    primary: NativeTarget<'p>,
    thumb: Option<NativeTarget<'p>>,
    /// Whether a body is walked in the instruction set its callers enter it in, rather than the one the program places there.
    entered: bool,
    /// Whether each walk records its calls' unwinds: the survey walks their pads, a return does not (D599).
    unwinds: bool,
}

/// The program as one walk in one instruction set reads it, told which callees are known to come back.
struct Knowing<'a> {
    program: &'a dyn crate::body::Program,
    thumb: bool,
    returns: &'a dyn Fn(u64, bool) -> bool,
    /// The body's supervisor calls its own seal proves halting (D505).
    halts: &'a BTreeMap<u64, r2source::Citation>,
}

impl crate::body::Program for Knowing<'_> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.program.read(vaddr, max)
    }

    fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
        self.program.region(vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.program.is_entry(vaddr)
    }

    fn returns(&self, callee: u64, foreign: bool) -> bool {
        (self.returns)(callee, self.thumb != foreign)
    }

    fn exit_through(&self, slot: u64) -> Option<crate::discovery::Never> {
        self.program.exit_through(slot)
    }

    fn halts_on_through(&self, slot: u64) -> Option<crate::body::Halting> {
        self.program.halts_on_through(slot)
    }

    fn halts_on(&self, callee: u64) -> Option<crate::body::Halting> {
        self.program.halts_on(callee)
    }

    fn holds_values(&self) -> bool {
        self.program.holds_values()
    }

    fn interrupt_halts(&self, arch: &str, vector: u64) -> Option<r2source::Citation> {
        self.program.interrupt_halts(arch, vector)
    }

    fn supervisor_halts(&self, _entry: u64, instruction: u64) -> Option<r2source::Citation> {
        self.halts.get(&instruction).copied()
    }

    fn yields_through(&self, slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Handle)> {
        self.program.yields_through(slot)
    }

    fn binds_handles(&self) -> bool {
        self.program.binds_handles()
    }

    fn loader_writes(&self) -> &[crate::program::LoaderWrite] {
        self.program.loader_writes()
    }

    fn permanence(&self, range: &std::ops::Range<u64>) -> super::Permanence {
        self.program.permanence(range)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.program.return_address_register()
    }

    fn landing_pad(&self, last: u64) -> Option<u64> {
        self.program.landing_pad(last)
    }
}

impl<'p, S: Source + 'static> Walking<'p, S> {
    /// A walker over both instruction sets, entering each body in the set `entered` chooses.
    pub(super) fn new(program: View<'p, S>, entered: bool) -> Result<Self, String> {
        let decoder = |machine: Option<&'p Machine>| machine.map(|m| program.decoder_of(m));
        let primary = decoder(program.machine_in(false)).ok_or("no machine")??;
        let thumb = decoder(program.machine_in(true)).transpose()?;
        Ok(Self {
            program,
            primary,
            thumb,
            entered,
            unwinds: false,
        })
    }

    /// The same walker, each walk recording its calls' unwinds for `walk_pads` (D570).
    pub(super) const fn recording_unwinds(mut self) -> Self {
        self.unwinds = true;
        self
    }

    /// Walk the landing pads of a body the survey walked, its callees' returns as `returns` says (D570).
    pub(super) fn walk_pads(&self, walk: &mut BodyWalk, returns: &dyn Fn(u64, bool) -> bool) {
        let knowing = Knowing {
            program: &self.program,
            thumb: walk.thumb,
            returns,
            halts: &walk.halts,
        };
        let disasm = self.target(walk.thumb).disasm;
        walk.trace.walk_pads(disasm, &knowing);
    }

    /// The decoder a body is walked with.
    pub(super) fn target(&self, thumb: bool) -> &NativeTarget<'p> {
        match (thumb, &self.thumb) {
            (true, Some(thumb)) => thumb,
            _ => &self.primary,
        }
    }

    pub(super) fn machine(&self, thumb: bool) -> Option<&'p Machine> {
        self.program.machine_in(thumb && self.thumb.is_some())
    }

    /// The whole body of `entry`, lifted, past every call `returns` says comes back.
    pub(super) fn lifted(
        &self,
        entry: u64,
        thumb: bool,
        returns: &dyn Fn(u64, bool) -> bool,
    ) -> Result<Body, BodyError> {
        let none = BTreeMap::new();
        let knowing = Knowing {
            program: &self.program,
            thumb,
            returns,
            halts: &none,
        };
        let disasm = self.target(thumb).disasm;
        crate::body::lift_body(entry, disasm, &knowing, &BTreeMap::new())
    }

    /// What the walk reached since last asked; a target the lift states another context for is in the other set.
    fn step(trace: &mut Trace, thumb: bool) -> Transfers {
        let reached = trace.reached();
        let entered_in = reached
            .calls
            .iter()
            .chain(&reached.tail_calls)
            .filter_map(|target| Some((*target, thumb != *trace.target_contexts().get(target)?)))
            .collect();
        Transfers {
            calls: reached.calls,
            tail_calls: reached.tail_calls,
            gated: reached.gated,
            falls_into: reached.falls_into,
            leaves: reached.leaves,
            entered_in,
        }
    }
}

impl<S: Source + 'static> Walker for Walking<'_, S> {
    type Walk = BodyWalk;
    type Refusal = NativeRefusal;

    fn walk(
        &self,
        address: u64,
        thumb: bool,
        returns: &dyn Fn(u64, bool) -> bool,
    ) -> Result<(BodyWalk, Transfers), NativeRefusal> {
        let thumb = match self.entered {
            true => thumb && self.thumb.is_some(),
            false => self.program.thumb_at(address),
        };
        let halts = Halts::default();
        let knowing = Knowing {
            program: &self.program,
            thumb,
            returns,
            halts: &halts,
        };
        let disasm = self.target(thumb).disasm;
        let trace = Trace::start(address, disasm, &knowing, self.unwinds);
        let mut trace = trace.map_err(NativeRefusal::Body)?;
        let transfers = Self::step(&mut trace, thumb);
        let walk = BodyWalk {
            entry: address,
            trace,
            thumb,
            tables: Tabled::Unread,
            halts,
        };
        Ok((walk, transfers))
    }

    fn open(
        &self,
        walk: &mut BodyWalk,
        callee: u64,
        returns: &dyn Fn(u64, bool) -> bool,
    ) -> Transfers {
        let knowing = Knowing {
            program: &self.program,
            thumb: walk.thumb,
            returns,
            halts: &walk.halts,
        };
        let disasm = self.target(walk.thumb).disasm;
        walk.trace.open(callee, disasm, &knowing);
        Self::step(&mut walk.trace, walk.thumb)
    }

    fn answered(&self, returns: BTreeMap<(u64, bool), Return>) {
        let keyed = (returns.into_iter())
            .map(|((address, thumb), answer)| (self.program.returns_key(address, thumb), answer));
        self.program.db.deposit::<ComesBack>(keyed);
    }

    fn dispatch(
        &self,
        walk: &mut BodyWalk,
        returns: &dyn Fn(u64, bool) -> bool,
    ) -> Option<Transfers> {
        // The first read is the first round; every round is asked only where the trace through the
        // first round's arms stops at a dispatch that round did not see. At most two reads per body.
        let key = (walk.entry, walk.thumb);
        let mut tables = match &walk.tables {
            Tabled::Unread if walk.trace.dispatches().next().is_none() => {
                walk.tables = Tabled::Untabled;
                return None;
            }
            Tabled::Unread => super::analysis::dispatch_tables(self.program.db, key),
            Tabled::Read(first) if first.0.later_reached(walk.trace.dispatches()) => {
                super::analysis::later_tables(self.program.db, key)
            }
            Tabled::Read(_) | Tabled::Untabled => return None,
        };
        let knowing = Knowing {
            program: &self.program,
            thumb: walk.thumb,
            returns,
            halts: &walk.halts,
        };
        let disasm = self.target(walk.thumb).disasm;
        let mut followed = false;
        loop {
            let arms = tables.0.dispatched();
            if !arms.is_empty() {
                walk.trace.dispatch(&arms, disasm, &knowing);
                followed = true;
            }
            let later = tables.0.later_reached(walk.trace.dispatches());
            walk.tables = Tabled::Read(tables);
            if !later {
                break;
            }
            tables = super::analysis::later_tables(self.program.db, key);
        }
        followed.then(|| Self::step(&mut walk.trace, walk.thumb))
    }

    fn may_halt(&self, walk: &BodyWalk) -> bool {
        // A body still reading tables can grow past the seal, so only one with none is read.
        !walk.trace.supervisor_calls().is_empty()
            && walk.halts.is_empty()
            && walk.trace.dispatches().next().is_none()
    }

    fn halt(&self, walk: &mut BodyWalk, returns: &dyn Fn(u64, bool) -> bool) -> Option<Transfers> {
        if !self.may_halt(walk) {
            return None;
        }
        let container = self.program.source().container();
        let kernel = super::kernel(container);
        let target = self.target(walk.thumb);
        let arch = (container.arch.name.as_str(), container.arch.bits);
        // Sealed as the walk reads it: the same returns, so the seal's graph is the walk's.
        let body = self.lifted(walk.entry, walk.thumb, returns).ok()?;
        let halts = crate::native::supervisor_halts(target, &self.program, kernel, arch, body);
        if halts.is_empty() {
            return None;
        }
        // The seal read the body walked to here; the walk again is its subgraph, so each constant holds.
        let knowing = Knowing {
            program: &self.program,
            thumb: walk.thumb,
            returns,
            halts: &halts,
        };
        let mut trace = Trace::start(walk.entry, target.disasm, &knowing, self.unwinds).ok()?;
        let transfers = Self::step(&mut trace, walk.thumb);
        (walk.trace, walk.halts, walk.tables) = (trace, halts, Tabled::Unread);
        Some(transfers)
    }

    fn handed(&self, walk: &BodyWalk, returns: &dyn Fn(u64, bool) -> bool) -> Vec<(u64, bool)> {
        let target = self.target(walk.thumb);
        let callees = walk.trace.calls().iter().chain(walk.trace.tail_calls());
        let loads = walk.trace.loads();
        // Preparing costs far more than walking, so only a body that calls something declared to take a function is lifted and prepared.
        if !crate::native::hands_a_function(target, &self.program, callees.copied(), loads) {
            return Vec::new();
        }
        let Ok(body) = self.lifted(walk.entry, walk.thumb, returns) else {
            return Vec::new();
        };
        crate::native::handed(target, &self.program, body)
            .into_iter()
            .map(|pointer| match self.thumb.is_some() {
                // A handed pointer states its instruction set in its low bit, as `bx` reads it.
                true => (pointer & !1, pointer & 1 == 1),
                false => (pointer, walk.thumb),
            })
            // A handed constant is a function only where it decodes, in the instruction set it is entered in.
            .filter(|(address, thumb)| {
                crate::native::decodes(self.target(*thumb).disasm, &self.program, *address)
            })
            .collect()
    }

    fn declared(&self, address: u64) -> Option<crate::discovery::Return> {
        crate::native::declared_return(&self.primary, &self.program, address)
    }

    fn ends<'a>(&self, walk: &'a BodyWalk) -> (Vec<&'a crate::discovery::Never>, usize) {
        walk.trace.ends()
    }

    fn within(&self, address: u64) -> Option<u64> {
        let extents = self
            .program
            .db
            .get::<super::starts::StatedExtents>(&())
            .ok()?;
        super::starts::within(&extents, address)
    }

    fn begins(&self, walk: &BodyWalk, address: u64) -> bool {
        walk.trace.begins(address)
    }
}

/// Whether control comes back from a call to a function, by its entry and whether it is entered
/// in Thumb; the lazy least fixpoint, sharing answers (doc/adr-query-database.md, Q3).
pub(crate) struct ComesBack;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ComesBack {
    type Key = (u64, bool);
    type Value = Return;
    const NAME: &'static str = "comes-back";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, &(callee, thumb): &(u64, bool)) -> Return {
        // Each body is walked in the set its call enters it in, so no mode is read: the survey
        // reading a dispatch whose arm calls an undiscovered function asks this.
        let view = View::new(db, false);
        let Ok(walker) = Walking::new(view.clone(), true) else {
            return Return::Comes;
        };
        if let Some(declared) = walker.declared(callee) {
            return declared;
        }
        let known = |address, thumb| {
            db.held::<ComesBack>(&view.returns_key(address, thumb))
                .expect("a held lookup never computes")
                .map(|answer| (*answer).clone())
        };
        let found = crate::discovery::returns(callee, thumb, &known, &walker);
        let mut found = (found.into_iter())
            .map(|((address, thumb), answer)| (view.returns_key(address, thumb), answer))
            .collect::<BTreeMap<_, _>>();
        let answer = found.remove(&(callee, thumb)).unwrap_or(Return::Comes);
        db.deposit::<ComesBack>(found);
        answer
    }
}
