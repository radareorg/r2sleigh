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
}

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
}

/// The program as one walk in one instruction set reads it, told which callees are known to come back.
struct Knowing<'a> {
    program: &'a dyn crate::body::Program,
    thumb: bool,
    returns: &'a dyn Fn(u64, bool) -> bool,
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

    fn returns_through(&self, slot: u64) -> bool {
        self.program.returns_through(slot)
    }

    fn halts_on_through(&self, slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Halt)> {
        self.program.halts_on_through(slot)
    }

    fn halts_on(&self, callee: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Halt)> {
        self.program.halts_on(callee)
    }

    fn holds_values(&self) -> bool {
        self.program.holds_values()
    }

    fn interrupt_returns(&self, arch: &str, vector: u64) -> bool {
        self.program.interrupt_returns(arch, vector)
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
        })
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
        let knowing = Knowing {
            program: &self.program,
            thumb,
            returns,
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
        let knowing = Knowing {
            program: &self.program,
            thumb,
            returns,
        };
        let disasm = self.target(thumb).disasm;
        let mut trace = Trace::start(address, disasm, &knowing).map_err(NativeRefusal::Body)?;
        let transfers = Self::step(&mut trace, thumb);
        let walk = BodyWalk {
            entry: address,
            trace,
            thumb,
            tables: Tabled::Unread,
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

    fn ends(&self, walk: &BodyWalk) -> (usize, usize) {
        walk.trace.ends()
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
