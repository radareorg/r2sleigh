//! Which addresses in a program are functions, and why each one is believed to
//! be.
//!
//! A symbol table is not discovery. `r2s` listed what the image named and
//! nothing else, so a stripped binary offered no function at all while its
//! entry points, its initialiser arrays and its procedure-linkage stubs were
//! already computed and thrown away.
//!
//! Discovery is the least set of addresses closed under "walk it and take
//! where it transfers", started from what the image states. It is a fixed
//! point, so it terminates: the set only grows, every member is an address in
//! the image, and the image is finite.
//!
//! Every address carries why it is here. That is the first inferred fact this
//! engine produces, so it is the first one that needs saying how far it can be
//! trusted -- an entry point is the format's own statement and a tail jump's
//! target is this engine's reading of one instruction, and a consumer that
//! cannot tell them apart has to treat both as the weaker.
//!
//! Which functions can return is the least fixpoint over the same walks; a defined function's name is never proof.

use std::collections::{BTreeMap, BTreeSet};

use crate::native::Program;

/// Why an address is believed to begin a function, and what that assumes.
///
/// `r2source`'s, the one type every derived fact states its trust in; the
/// engine's answers carry it, so the shell reads it from here.
pub use r2source::confidence::{Basis, Confidence, Premise};

/// One address discovery believes is a function.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub address: u64,
    pub confidence: Confidence,
    /// Whether its code is Thumb rather than the image's own instruction set.
    pub thumb: bool,
    /// What the program calls it, where anything does. Presentation only.
    pub name: Option<String>,
}

/// What one stretch of a body's walk reached, which is the whole of what discovery reads from a body.
#[derive(Debug, Clone, Default)]
pub struct Transfers {
    pub calls: Vec<u64>,
    pub tail_calls: Vec<u64>,
    /// Callees a call to which holds a fallthrough closed until they are known to return.
    pub gated: Vec<u64>,
    /// Functions control runs on into from the end of this one, which then returns what they return.
    pub falls_into: Vec<u64>,
    /// Whether the walk reached a return, or a stop it cannot see past.
    pub leaves: bool,
    /// Whether each target is entered in Thumb, where the transfer states it.
    pub entered_in: BTreeMap<u64, bool>,
}

/// How discovery reads bodies: walked once, and continued past a call once that call is known to come back.
pub trait Walker {
    type Walk;
    type Refusal;

    /// Walk the body at `address`, in Thumb where `thumb`, past every call `returns` says comes back.
    fn walk(
        &self,
        address: u64,
        thumb: bool,
        returns: &dyn Fn(u64) -> bool,
    ) -> Result<(Self::Walk, Transfers), Self::Refusal>;

    /// Continue a walk past every call to `callee`, which is now known to come back.
    fn open(&self, walk: &mut Self::Walk, callee: u64, returns: &dyn Fn(u64) -> bool) -> Transfers;

    /// Where a finished body hands a function to a parameter declared to take one, and whether each is Thumb.
    fn handed(&self, walk: &Self::Walk, returns: &dyn Fn(u64) -> bool) -> Vec<(u64, bool)>;

    /// Whether control comes back from the import at this address, as its own declaration says; `None` for anything else.
    fn declared(&self, address: u64) -> Option<bool>;
}

/// Every function in the program, whether control can come back from each, and each body as the fixpoint left it.
pub struct Discovery<T, E> {
    pub functions: Vec<Discovered>,
    pub returns: BTreeMap<u64, bool>,
    pub walks: BTreeMap<u64, Result<T, E>>,
}

/// Every function in the program from the seeds the image states, each in its stated instruction set, and what their bodies reach.
pub fn functions<W: Walker>(
    program: &dyn Program,
    seeds: impl IntoIterator<Item = (u64, Confidence, bool)>,
    walker: &W,
) -> Discovery<W::Walk, W::Refusal> {
    let unknown = |_| None;
    let mut fixpoint = Fixpoint::new(walker, &unknown, None);
    for (address, confidence, thumb) in seeds {
        fixpoint.offer(address, confidence, thumb);
    }
    fixpoint.run();
    let returns = fixpoint
        .believed
        .keys()
        .map(|address| (*address, fixpoint.comes_back(*address)))
        .collect();
    Discovery {
        functions: fixpoint
            .believed
            .into_iter()
            .map(|(address, (confidence, thumb))| Discovered {
                address,
                confidence,
                thumb,
                name: program.name_at(address),
            })
            .collect(),
        returns,
        walks: fixpoint.walks,
    }
}

/// Whether control can come back from `seed` and from each function walked to decide it, walking a callee only while an undecided caller waits on it.
pub fn returns<W: Walker>(
    seed: u64,
    known: &dyn Fn(u64) -> Option<bool>,
    walker: &W,
) -> BTreeMap<u64, bool> {
    let mut fixpoint = Fixpoint::new(walker, known, Some(seed));
    fixpoint.pending.push(seed);
    fixpoint.run();
    fixpoint
        .walks
        .keys()
        .map(|address| (*address, fixpoint.returning.contains(address)))
        .collect()
}

/// What a caller waits on a callee for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Wait {
    /// The bytes after a call to it.
    Fallthrough,
    /// Whether the caller returns, which its tail call to it or running on into it decides.
    TailCall,
}

/// The joint least fixpoint of the believed functions and those that can return, one whatever the order because walks are bounded by fixed stated entries.
struct Fixpoint<'w, W: Walker> {
    walker: &'w W,
    /// What an earlier run settled, which this one neither walks nor revises.
    known: &'w dyn Fn(u64) -> Option<bool>,
    /// The one function whose return is asked, where discovery is not walking every believed body.
    seed: Option<u64>,
    believed: BTreeMap<u64, (Confidence, bool)>,
    pending: Vec<u64>,
    walks: BTreeMap<u64, Result<W::Walk, W::Refusal>>,
    /// The functions shown to return so far.
    returning: BTreeSet<u64>,
    /// Functions that joined `returning` whose waiters have not been told.
    joined: Vec<u64>,
    /// Who waits on each callee, and for what.
    waiting: BTreeMap<u64, BTreeSet<(u64, Wait)>>,
    /// Bodies already read for the functions they hand on.
    read: BTreeSet<u64>,
}

impl<'w, W: Walker> Fixpoint<'w, W> {
    fn new(walker: &'w W, known: &'w dyn Fn(u64) -> Option<bool>, seed: Option<u64>) -> Self {
        Self {
            walker,
            known,
            seed,
            believed: BTreeMap::new(),
            pending: Vec::new(),
            walks: BTreeMap::new(),
            returning: BTreeSet::new(),
            joined: Vec::new(),
            waiting: BTreeMap::new(),
            read: BTreeSet::new(),
        }
    }

    fn run(&mut self) {
        loop {
            if let Some(callee) = self.joined.pop() {
                self.tell(callee);
            } else if let Some(address) = self.pending.pop() {
                self.walk(address);
            } else if !self.hand_on() {
                return;
            }
        }
    }

    /// Whether a body still needs walking: every one in discovery, else the seed and what an undecided caller waits on.
    fn demanded(&self, address: u64) -> bool {
        let undecided = |(caller, _): &(u64, Wait)| !self.returning.contains(caller);
        let waited = self.waiting.get(&address);
        self.seed.is_none_or(|seed| seed == address)
            || waited.is_some_and(|waiters| waiters.iter().any(undecided))
    }

    /// A status no walk here decides: an earlier run's, or an import's declaration.
    fn settled(&self, address: u64) -> Option<bool> {
        settled(self.walker, self.known, address)
    }

    fn comes_back(&self, address: u64) -> bool {
        comes_back(self.walker, self.known, &self.returning, address)
    }

    /// Believe an address for a reason, keeping the stronger one; the first reason decides the instruction set.
    fn offer(&mut self, address: u64, confidence: Confidence, thumb: bool) {
        match self.believed.get_mut(&address) {
            Some((held, _)) => {
                if confidence < *held {
                    *held = confidence;
                }
            }
            None => {
                self.believed.insert(address, (confidence, thumb));
                if self.seed.is_none() {
                    self.pending.push(address);
                }
            }
        }
    }

    fn walk(&mut self, address: u64) {
        if self.walks.contains_key(&address) || !self.demanded(address) {
            return;
        }
        let thumb = self.believed.get(&address).is_some_and(|(_, thumb)| *thumb);
        let (walker, known, returning) = (self.walker, self.known, &self.returning);
        let returns = |callee| comes_back(walker, known, returning, callee);
        match walker.walk(address, thumb, &returns) {
            Ok((walk, transfers)) => {
                self.walks.insert(address, Ok(walk));
                self.absorb(address, thumb, transfers);
            }
            // Nothing proves a body that cannot be walked never returns.
            Err(refusal) => {
                self.walks.insert(address, Err(refusal));
                self.join(address);
            }
        }
    }

    fn absorb(&mut self, address: u64, thumb: bool, transfers: Transfers) {
        // A transfer that states no instruction set keeps this body's.
        let entered = |target: u64| transfers.entered_in.get(&target).copied().unwrap_or(thumb);
        for &target in &transfers.calls {
            self.offer(target, Confidence::of(Basis::Called), entered(target));
        }
        for &target in &transfers.tail_calls {
            self.offer(target, Confidence::of(Basis::Reached), entered(target));
            self.wait(address, target, Wait::TailCall);
        }
        for &callee in &transfers.gated {
            self.wait(address, callee, Wait::Fallthrough);
        }
        for &next in &transfers.falls_into {
            self.wait(address, next, Wait::TailCall);
        }
        if transfers.leaves {
            self.join(address);
        }
    }

    /// Make `caller` wait on `callee`, told at once where the callee already returns.
    fn wait(&mut self, caller: u64, callee: u64, wait: Wait) {
        self.waiting
            .entry(callee)
            .or_default()
            .insert((caller, wait));
        let unwalked = !self.walks.contains_key(&callee) && self.settled(callee).is_none();
        if self.comes_back(callee) {
            self.joined.push(callee);
        } else if self.seed.is_some() && unwalked {
            self.pending.push(callee);
        }
    }

    fn join(&mut self, address: u64) {
        if self.settled(address).is_none() && self.returning.insert(address) {
            self.joined.push(address);
        }
    }

    /// Tell everything waiting on `callee` that it returns.
    fn tell(&mut self, callee: u64) {
        for (caller, wait) in self.waiting.remove(&callee).unwrap_or_default() {
            match wait {
                Wait::TailCall => self.join(caller),
                Wait::Fallthrough => self.open(caller, callee),
            }
        }
    }

    fn open(&mut self, caller: u64, callee: u64) {
        let Some(Ok(walk)) = self.walks.get_mut(&caller) else {
            return;
        };
        let (walker, known, returning) = (self.walker, self.known, &self.returning);
        let returns = |callee| comes_back(walker, known, returning, callee);
        let transfers = walker.open(walk, callee, &returns);
        let thumb = self.believed.get(&caller).is_some_and(|(_, thumb)| *thumb);
        self.absorb(caller, thumb, transfers);
    }

    /// Read each body, final once every callee is walked, for the functions it hands on; answer whether any need walking.
    fn hand_on(&mut self) -> bool {
        if self.seed.is_some() {
            return false;
        }
        let (walker, known, returning) = (self.walker, self.known, &self.returning);
        let returns = |callee| comes_back(walker, known, returning, callee);
        let unread = self
            .walks
            .iter()
            .filter(|(address, _)| !self.read.contains(address))
            .filter_map(|(address, walk)| Some((*address, walk.as_ref().ok()?)))
            .map(|(address, walk)| (address, walker.handed(walk, &returns)))
            .collect::<Vec<_>>();
        self.read.extend(self.walks.keys().copied());
        for (_, handed) in unread {
            for (target, thumb) in handed {
                self.offer(target, Confidence::of(Basis::Handed), thumb);
            }
        }
        !self.pending.is_empty()
    }
}

fn settled<W: Walker>(
    walker: &W,
    known: &dyn Fn(u64) -> Option<bool>,
    address: u64,
) -> Option<bool> {
    known(address).or_else(|| walker.declared(address))
}

fn comes_back<W: Walker>(
    walker: &W,
    known: &dyn Fn(u64) -> Option<bool>,
    returning: &BTreeSet<u64>,
    address: u64,
) -> bool {
    settled(walker, known, address).unwrap_or_else(|| returning.contains(&address))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Named;

    impl r2ssa::body::Program for Named {
        fn read(&self, _vaddr: u64, _max: usize) -> Option<Vec<u8>> {
            None
        }

        fn region(&self, _vaddr: u64) -> Option<r2ssa::body::Region> {
            None
        }

        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    impl Program for Named {
        fn name_at(&self, vaddr: u64) -> Option<String> {
            (vaddr == 0x1000).then(|| "entry".to_owned())
        }

        fn import_at(&self, _vaddr: u64) -> Option<String> {
            None
        }

        fn holds_static_data(&self, _vaddr: u64) -> bool {
            false
        }

        fn extents(&self) -> &r2types::ProgramExtents {
            const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
            NONE
        }
    }

    /// One thing a straight-line body does.
    #[derive(Debug, Clone, Copy)]
    enum Step {
        Call(u64),
        Tail(u64),
        Hand(u64),
        Return,
    }

    /// Straight-line bodies by entry; an address with none cannot be walked.
    struct Bodies(BTreeMap<u64, Vec<Step>>);

    /// A body walked up to a step.
    struct At {
        address: u64,
        next: usize,
    }

    impl Bodies {
        fn of(bodies: &[(u64, &[Step])]) -> Self {
            Self(
                bodies
                    .iter()
                    .map(|(address, steps)| (*address, steps.to_vec()))
                    .collect(),
            )
        }

        fn go(&self, at: &mut At, returns: &dyn Fn(u64) -> bool) -> Transfers {
            let mut transfers = Transfers::default();
            let steps = &self.0[&at.address][at.next..];
            let stopped = steps
                .iter()
                .position(|step| !taken(*step, &mut transfers, returns));
            at.next += stopped.unwrap_or(steps.len());
            transfers
        }
    }

    /// Record one step, and answer whether the walk goes on past it.
    fn taken(step: Step, transfers: &mut Transfers, returns: &dyn Fn(u64) -> bool) -> bool {
        match step {
            Step::Call(callee) => {
                transfers.calls.push(callee);
                let back = returns(callee);
                if !back {
                    transfers.gated.push(callee);
                }
                back
            }
            Step::Tail(target) => {
                transfers.tail_calls.push(target);
                false
            }
            Step::Hand(_) => true,
            Step::Return => {
                transfers.leaves = true;
                false
            }
        }
    }

    impl Walker for Bodies {
        type Walk = At;
        type Refusal = ();

        fn walk(
            &self,
            address: u64,
            _thumb: bool,
            returns: &dyn Fn(u64) -> bool,
        ) -> Result<(At, Transfers), ()> {
            self.0.get(&address).ok_or(())?;
            let mut at = At { address, next: 0 };
            let transfers = self.go(&mut at, returns);
            Ok((at, transfers))
        }

        fn open(&self, walk: &mut At, _callee: u64, returns: &dyn Fn(u64) -> bool) -> Transfers {
            walk.next += 1;
            self.go(walk, returns)
        }

        fn handed(&self, walk: &At, _returns: &dyn Fn(u64) -> bool) -> Vec<(u64, bool)> {
            let handed = self.0[&walk.address].iter().filter_map(|step| match step {
                Step::Hand(target) => Some((*target, false)),
                _ => None,
            });
            handed.collect()
        }

        fn declared(&self, _address: u64) -> Option<bool> {
            None
        }
    }

    fn found(bodies: &[(u64, &[Step])], seeds: &[u64]) -> Discovery<At, ()> {
        let seeds = seeds
            .iter()
            .map(|seed| (*seed, Confidence::of(Basis::Stated), false));
        functions(&Named, seeds, &Bodies::of(bodies))
    }

    fn seen(discovery: &Discovery<At, ()>) -> Vec<(u64, Basis)> {
        let functions = discovery.functions.iter();
        functions
            .map(|one| (one.address, one.confidence.basis))
            .collect()
    }

    #[test]
    fn a_call_reaches_a_function_the_image_never_named() {
        let found = found(
            &[(0x1000, &[Step::Call(0x2000), Step::Tail(0x3000)])],
            &[0x1000],
        );
        assert_eq!(
            seen(&found),
            [
                (0x1000, Basis::Stated),
                (0x2000, Basis::Called),
                (0x3000, Basis::Reached),
            ]
        );
        assert_eq!(found.functions[0].name.as_deref(), Some("entry"));
    }

    #[test]
    fn an_address_found_twice_keeps_the_stronger_reason() {
        // Reached first and stated second: the order a walk happens to take
        // must not decide how far a fact can be trusted.
        let found = found(&[(0x1000, &[Step::Tail(0x2000)])], &[0x2000, 0x1000]);
        assert!(seen(&found).contains(&(0x2000, Basis::Stated)));
    }

    #[test]
    fn an_address_handed_to_a_declared_function_parameter_is_believed() {
        // Nothing transfers to it: it was put in an argument register and the
        // callee's declaration says that parameter is a function.
        let found = found(&[(0x1000, &[Step::Hand(0x4000), Step::Return])], &[0x1000]);
        assert_eq!(
            seen(&found),
            [(0x1000, Basis::Stated), (0x4000, Basis::Handed)]
        );
    }

    #[test]
    fn a_call_outranks_a_handoff_for_the_same_address() {
        let body = [Step::Hand(0x4000), Step::Call(0x4000), Step::Return];
        let found = found(&[(0x1000, &body), (0x4000, &[Step::Return])], &[0x1000]);
        assert!(seen(&found).contains(&(0x4000, Basis::Called)));
    }

    #[test]
    fn a_cycle_of_calls_that_never_reaches_a_return_never_returns() {
        // Each call's fallthrough waits on the other, and nothing else opens it.
        let found = found(
            &[
                (0x1000, &[Step::Call(0x2000), Step::Return]),
                (0x2000, &[Step::Call(0x1000), Step::Return]),
            ],
            &[0x1000],
        );
        assert_eq!(seen(&found).len(), 2);
        assert_eq!(
            found.returns,
            BTreeMap::from([(0x1000, false), (0x2000, false)])
        );
    }

    #[test]
    fn a_body_that_cannot_be_walked_is_still_a_function_that_may_return() {
        let found = found(&[(0x1000, &[Step::Call(0x2000), Step::Return])], &[0x1000]);
        assert_eq!(seen(&found).len(), 2);
        assert_eq!(
            found.returns,
            BTreeMap::from([(0x1000, true), (0x2000, true)])
        );
    }

    #[test]
    fn a_tail_call_returns_what_its_target_returns_whatever_the_order() {
        let bodies: [(u64, &[Step]); 3] = [
            (0x1000, &[Step::Tail(0x2000)]),
            (0x2000, &[Step::Call(0x3000), Step::Return]),
            (0x3000, &[Step::Tail(0x3000)]),
        ];
        let forward = found(&bodies, &[0x1000, 0x2000, 0x3000]);
        let backward = found(&bodies, &[0x3000, 0x2000, 0x1000]);
        assert_eq!(forward.returns, backward.returns);
        assert!(forward.returns.values().all(|returns| !returns));
        // The same walks, asked of one function against what an earlier run settled.
        let settled = |address| (address == 0x3000).then_some(true);
        let from = returns(0x1000, &settled, &Bodies::of(&bodies));
        assert_eq!(from, BTreeMap::from([(0x1000, true), (0x2000, true)]));
    }
}
