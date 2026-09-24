//! Whether control comes back from a call to each function, for one state of the bytes.

use std::collections::BTreeMap;

use r2sleigh_lift::EmbeddedMachine;
use r2ssa::body::{Body, BodyError, Trace};

use super::{OpenProgram, Source};
use crate::discovery::{Transfers, Walker};
use crate::native::{NativeRefusal, NativeTarget};

/// Each function's answer, for the bytes it was derived from.
#[derive(Default)]
pub(super) struct Returns {
    at: Option<(u64, u64)>,
    by_entry: BTreeMap<u64, bool>,
}

/// One body being walked, and whether it is walked as Thumb.
pub(super) struct BodyWalk {
    entry: u64,
    trace: Trace,
    pub(super) thumb: bool,
}

/// Discovery's walker over one open program.
pub(super) struct Walking<'p, S: Source> {
    program: &'p OpenProgram<S>,
    primary: NativeTarget<'p>,
    thumb: Option<NativeTarget<'p>>,
    /// Whether a body is walked in the instruction set its callers enter it in, rather than the one the program places there.
    entered: bool,
}

/// The program as one walk reads it, told which callees are known to come back.
struct Knowing<'a> {
    program: &'a dyn r2ssa::body::Program,
    returns: &'a dyn Fn(u64) -> bool,
}

impl r2ssa::body::Program for Knowing<'_> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.program.read(vaddr, max)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.program.is_entry(vaddr)
    }

    fn returns(&self, callee: u64) -> bool {
        (self.returns)(callee)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.program.return_address_register()
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        self.program.mode_register()
    }
}

impl<'p, S: Source> Walking<'p, S> {
    /// A walker over both instruction sets, entering each body in the set `entered` chooses.
    pub(super) fn new(program: &'p OpenProgram<S>, entered: bool) -> Result<Self, String> {
        let decoder = |machine: Option<&'p EmbeddedMachine>| machine.map(|m| program.target_of(m));
        Ok(Self {
            program,
            primary: decoder(program.machine_in(false)).ok_or("no machine")??,
            thumb: decoder(program.machine_in(true)).transpose()?,
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

    pub(super) fn machine(&self, thumb: bool) -> Option<&'p EmbeddedMachine> {
        self.program.machine_in(thumb && self.thumb.is_some())
    }

    /// The whole body of `entry`, lifted, past every call `returns` says comes back.
    pub(super) fn lifted(
        &self,
        entry: u64,
        thumb: bool,
        returns: &dyn Fn(u64) -> bool,
    ) -> Result<Body, BodyError> {
        let knowing = Knowing {
            program: self.program,
            returns,
        };
        let disasm = self.target(thumb).disasm;
        r2ssa::body::lift_body(entry, disasm, &knowing, &BTreeMap::new())
    }

    fn step(trace: &mut Trace) -> Transfers {
        let reached = trace.reached();
        // Sleigh's `ISAModeSwitch` holds the Thumb bit a call enters with.
        let entered_in = reached
            .calls
            .iter()
            .chain(&reached.tail_calls)
            .filter_map(|target| Some((*target, *trace.entered_with().get(target)? != 0)))
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

impl<S: Source> Walker for Walking<'_, S> {
    type Walk = BodyWalk;
    type Refusal = NativeRefusal;

    fn walk(
        &self,
        address: u64,
        thumb: bool,
        returns: &dyn Fn(u64) -> bool,
    ) -> Result<(BodyWalk, Transfers), NativeRefusal> {
        let thumb = match self.entered {
            true => thumb && self.thumb.is_some(),
            false => self.program.thumb_at(address),
        };
        let knowing = Knowing {
            program: self.program,
            returns,
        };
        let disasm = self.target(thumb).disasm;
        let mut trace = Trace::start(address, disasm, &knowing).map_err(NativeRefusal::Body)?;
        let transfers = Self::step(&mut trace);
        let walk = BodyWalk {
            entry: address,
            trace,
            thumb,
        };
        Ok((walk, transfers))
    }

    fn open(&self, walk: &mut BodyWalk, callee: u64, returns: &dyn Fn(u64) -> bool) -> Transfers {
        let knowing = Knowing {
            program: self.program,
            returns,
        };
        let disasm = self.target(walk.thumb).disasm;
        walk.trace.open(callee, disasm, &knowing);
        Self::step(&mut walk.trace)
    }

    fn handed(&self, walk: &BodyWalk, returns: &dyn Fn(u64) -> bool) -> Vec<(u64, bool)> {
        let target = self.target(walk.thumb);
        let callees = walk.trace.calls().iter().chain(walk.trace.tail_calls());
        let loads = walk.trace.loads();
        // Preparing costs far more than walking, so only a body that calls something declared to take a function is lifted and prepared.
        if !crate::native::hands_a_function(target, self.program, callees.copied(), loads) {
            return Vec::new();
        }
        let Ok(body) = self.lifted(walk.entry, walk.thumb, returns) else {
            return Vec::new();
        };
        crate::native::handed(target, self.program, body)
            .into_iter()
            .map(|pointer| match self.thumb.is_some() {
                // A handed pointer states its instruction set in its low bit, as `bx` reads it.
                true => (pointer & !1, pointer & 1 == 1),
                false => (pointer, walk.thumb),
            })
            // A handed constant is a function only where it decodes, in the instruction set it is entered in.
            .filter(|(address, thumb)| {
                crate::native::decodes(self.target(*thumb).disasm, self.program, *address)
            })
            .collect()
    }

    fn declared(&self, address: u64) -> Option<bool> {
        crate::native::declared_return(&self.primary, self.program, address)
    }
}

impl<S: Source> OpenProgram<S> {
    /// Whether control comes back from a call to `callee`: false only where the program proves it never does.
    pub(super) fn comes_back(&self, callee: u64) -> bool {
        let Ok(walker) = Walking::new(self, false) else {
            return true;
        };
        if let Some(declared) = walker.declared(callee) {
            return declared;
        }
        let at = (self.source.identity(), self.source.byte_revision());
        if let Some(known) = self.returns_held(at, callee) {
            return known;
        }
        let known = |address| self.returns_held(at, address);
        let found = crate::discovery::returns(callee, &known, &walker);
        let answer = found.get(&callee).copied().unwrap_or(true);
        self.hold_returns(at, found);
        answer
    }

    /// The answer held for these bytes, the table dropped where they have moved.
    fn returns_held(&self, at: (u64, u64), address: u64) -> Option<bool> {
        let mut held = self.returns.lock().unwrap_or_else(|held| held.into_inner());
        if held.at != Some(at) {
            *held = Returns {
                at: Some(at),
                by_entry: BTreeMap::new(),
            };
        }
        held.by_entry.get(&address).copied()
    }

    /// Hold answers derived for these bytes; the least fixpoint is one, so no two derivations disagree.
    pub(super) fn hold_returns(&self, at: (u64, u64), found: BTreeMap<u64, bool>) {
        let mut held = self.returns.lock().unwrap_or_else(|held| held.into_inner());
        if held.at != Some(at) {
            *held = Returns {
                at: Some(at),
                by_entry: BTreeMap::new(),
            };
        }
        held.by_entry.extend(found);
    }
}
