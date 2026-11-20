//! How far a fact the engine derives about a program can be trusted, and what it assumes.
//!
//! A fact the container states is as good as the file. Everything else is a
//! reading of the bytes, and a reading is only as good as what it rests on:
//! the instruction it decoded, the declaration it believed, and the premises
//! it took for granted about the world the program runs in. A consumer that
//! cannot tell a stated fact from a read one, or a read one from one that
//! assumes nobody outside the image calls in, has to treat all of them as the
//! weakest. So the fact carries both, and this is the one type that says it.

use std::collections::BTreeSet;

/// How strongly a fact is known, strongest first.
///
/// One scale for every fact, so a consumer states the least grade it acts on
/// rather than testing how one producer happened to flag its output. Derived
/// from the [`Basis`], never stored beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Grade {
    /// The file says so, in its tables or its debug information.
    Stated,
    /// Exact: the bytes were read and the reading proves it.
    Proven,
    /// Proven true everywhere and exact nowhere: a bound.
    Bounded,
    /// A declaration says so, found for this program by a name.
    Declared,
    /// A reading of the bytes that nothing proves.
    Read,
    /// A convention's default, with no evidence about this program at all.
    Assumed,
}

impl Grade {
    /// The grade as answers spell it.
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::Stated => "stated",
            Self::Proven => "proven",
            Self::Bounded => "bounded",
            Self::Declared => "declared",
            Self::Read => "read",
            Self::Assumed => "assumed",
        }
    }
}

/// What a derived fact is read from, strongest first.
///
/// Ordered by how much is being claimed, so a consumer may take everything at
/// or above the level it is willing to act on, and a fact found twice keeps
/// the stronger reason: a symbol that is also called is stated, not inferred.
/// The order refines [`Grade`]'s: every basis sorts with its grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Basis {
    /// The image says so. An entry point, an initialiser or finaliser array
    /// slot, a symbol typed as a function, a linkage stub the format declares.
    /// Nothing is inferred and nothing can be wrong here that is not wrong in
    /// the file.
    Stated,
    /// The image's debug information says so: what the compiler wrote down
    /// about the source it compiled.
    DebugInfo,
    /// The instruction alone says so: where it transfers, what it accesses,
    /// or the bound its own operations put on what it writes.
    Decoded,
    /// A walked body calls it. One decoded call instruction with a constant
    /// target, which is a reading of bytes this engine did itself.
    Called,
    /// Evaluated over the run of instructions around it in its block.
    Folded,
    /// Exact over the whole function: its def-use, or a certificate `r2ssa`
    /// issued.
    Certified,
    /// A bound an analysis over the whole function proved.
    Solved,
    /// A walked body hands it to a function whose declaration says that
    /// parameter is a function.
    ///
    /// `entry0` never calls `main`: it passes it to `__libc_start_main`, whose
    /// prototype spells the first parameter `func`. The address is a function
    /// on the declaration's authority plus a constant this engine folded, so
    /// it is weaker than a call the machine makes and stronger than a
    /// transfer that may be a jump inside one function.
    Handed,
    /// A library's prototype, found by the name of an import: true of this
    /// program only if the import is the library's function.
    Declared,
    /// A callee's own body loads or stores through the parameter the value
    /// arrives in.
    Dereferenced,
    /// A walked body leaves for it without returning. The same reading, over
    /// an instruction that is a jump: whether the target is a function of its
    /// own or a continuation of this one is exactly what a tail call makes
    /// ambiguous.
    Reached,
    /// A type that is only the width of the carrier the value travels in:
    /// what the body was read to use, saying nothing of pointer, sign or name.
    CarrierWidth,
    /// What the calling convention does by default, read from no byte.
    Convention,
}

impl Basis {
    /// Every basis, strongest first.
    pub const ALL: [Self; 13] = [
        Self::Stated,
        Self::DebugInfo,
        Self::Decoded,
        Self::Called,
        Self::Folded,
        Self::Certified,
        Self::Solved,
        Self::Handed,
        Self::Declared,
        Self::Dereferenced,
        Self::Reached,
        Self::CarrierWidth,
        Self::Convention,
    ];

    /// Whether a type on this basis states the C type, where every other basis states only a
    /// width: debug information or a library's declaration (D261).
    pub const fn states_type(self) -> bool {
        matches!(self, Self::DebugInfo | Self::Declared)
    }

    /// How strongly a fact on this basis is known.
    pub const fn grade(self) -> Grade {
        match self {
            Self::Stated | Self::DebugInfo => Grade::Stated,
            Self::Decoded | Self::Called | Self::Folded | Self::Certified => Grade::Proven,
            Self::Solved => Grade::Bounded,
            Self::Handed | Self::Declared => Grade::Declared,
            Self::Dereferenced | Self::Reached | Self::CarrierWidth => Grade::Read,
            Self::Convention => Grade::Assumed,
        }
    }

    /// The basis as answers spell it.
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::Stated => "stated",
            Self::DebugInfo => "debug-info",
            Self::Decoded => "decoded",
            Self::Called => "called",
            Self::Folded => "folded",
            Self::Certified => "certified",
            Self::Solved => "solved",
            Self::Handed => "handed",
            Self::Declared => "declared",
            Self::Dereferenced => "dereferenced",
            Self::Reached => "reached",
            Self::CarrierWidth => "carrier-width",
            Self::Convention => "convention",
        }
    }
}

/// Something a derived fact takes for granted that no byte of the image states.
///
/// A premise is not evidence. It is the condition under which the evidence
/// means what the fact says, and a consumer that cannot grant it must not
/// act on the fact.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Premise {
    /// Every transfer into the code is one the image shows: no caller outside
    /// it -- another image, a callback registered at run time, generated
    /// code -- reaches a function other than the ways this image reaches it.
    /// What a function's callers all pass, or that it has no caller, holds
    /// only under this.
    ClosedWorld,
    /// The source the program was compiled from has no undefined behaviour,
    /// so what the compiler was entitled to assume of it holds of the machine
    /// code too: a signed add does not wrap, an access stays in its object.
    UbFreeSource,
    /// The routine the container names `runtime.morestack` keeps the Go runtime's contract: it
    /// grows the stack and resumes the caller after the call, which then re-enters. A name states
    /// the routine; only this premise says it behaves as the runtime does.
    GoRuntime,
    /// The code is compiler output: a callee writes its caller's frame only through an address
    /// the caller exposed, and no caller reads a stack parameter home back (D471, a ruling).
    FrameIsolation,
}

impl Premise {
    /// Every premise, in order.
    pub const ALL: [Self; 4] = [
        Self::ClosedWorld,
        Self::UbFreeSource,
        Self::GoRuntime,
        Self::FrameIsolation,
    ];

    /// The premise as answers spell it.
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::ClosedWorld => "closed-world",
            Self::UbFreeSource => "ub-free",
            Self::GoRuntime => "go-runtime",
            Self::FrameIsolation => "frame-isolation",
        }
    }
}

/// A set of premises: one bit per [`Premise`], so a confidence costs two bytes, ordered as the
/// sorted sequence it holds.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Premises(u8);

impl Premises {
    pub const fn new() -> Self {
        Self(0)
    }

    const fn bit(premise: Premise) -> u8 {
        1 << premise as u8
    }

    /// Whether `premise` was not already held.
    pub fn insert(&mut self, premise: Premise) -> bool {
        let fresh = !self.contains(&premise);
        self.0 |= Self::bit(premise);
        fresh
    }

    pub const fn contains(&self, premise: &Premise) -> bool {
        self.0 & Self::bit(*premise) != 0
    }

    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub const fn len(&self) -> usize {
        self.0.count_ones() as usize
    }

    pub const fn is_subset(&self, other: &Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub const fn is_superset(&self, other: &Self) -> bool {
        other.is_subset(self)
    }

    /// The premises held, in [`Premise`]'s order.
    pub fn iter(&self) -> impl Iterator<Item = Premise> + Clone + '_ {
        Premise::ALL
            .into_iter()
            .filter(|premise| self.contains(premise))
    }
}

impl Ord for Premises {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}

impl PartialOrd for Premises {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Extend<Premise> for Premises {
    fn extend<I: IntoIterator<Item = Premise>>(&mut self, premises: I) {
        for premise in premises {
            self.insert(premise);
        }
    }
}

impl FromIterator<Premise> for Premises {
    fn from_iter<I: IntoIterator<Item = Premise>>(premises: I) -> Self {
        let mut set = Self::new();
        set.extend(premises);
        set
    }
}

impl std::fmt::Debug for Premises {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl serde::Serialize for Premises {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

/// A source that states a fact (D410): a cited row, debug information, a kernel's document or a
/// runtime model, minted only from that owner's statement.
#[doc = "```compile_fail,E0423\nlet forged = r2source::Citation(());\n```"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Citation(Cited);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Cited {
    Row,
    DebugInfo,
    Kernel,
    Runtime,
}

impl Citation {
    /// A row that cites its source; radare2's uncited rows mint none (D395).
    pub fn of(row: &r2abi::LibraryRow) -> Option<Self> {
        row.cited().then_some(Self(Cited::Row))
    }

    /// The debug information's declaration of the function at `entry`, where no other contests it.
    pub fn debug_info(declarations: &r2abi::Declarations, entry: u64) -> Option<Self> {
        let stated = declarations.function_at(entry).is_some();
        (stated && !declarations.is_contested(entry)).then_some(Self(Cited::DebugInfo))
    }

    /// The document stating that interrupt `vector` never comes back under `kernel` (D229).
    pub fn interrupt(kernel: r2abi::Kernel, arch: &str, vector: u64) -> Option<Self> {
        r2abi::syscalls::interrupt_never_returns(kernel, arch, vector).map(|_| Self(Cited::Kernel))
    }

    /// The kernel source stating system call `number` never comes back under `kernel` (D505).
    pub fn syscall(kernel: r2abi::Kernel, arch: &str, bits: u32, number: u64) -> Option<Self> {
        r2abi::syscalls::syscall_never_returns(kernel, arch, bits, number)
            .map(|_| Self(Cited::Kernel))
    }

    /// The Go runtime model naming `name` among the routines its compiler ends a block at; what it
    /// states holds under [`Premise::GoRuntime`].
    pub fn runtime(name: &str) -> Option<Self> {
        r2abi::runtime::exits(name).then_some(Self(Cited::Runtime))
    }
}

/// What a "never comes back" rests on (doc/adr-call-boundary.md, "S30 as built"; RULING 1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeverProof {
    /// A cited row, a runtime model or the binary's debug information states it.
    Declared,
    /// Every end of the body is a transfer a statement or a `Composed` callee proves halts (D229).
    Composed,
    /// No walk of the body reached a return: a lower bound on what it does, never proof.
    NoReturnReached,
}

impl NeverProof {
    /// The proof as answers spell it.
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Composed => "composed",
            Self::NoReturnReached => "no return reached",
        }
    }
}

/// A call that never comes back: what states it, and what it takes for granted. A proving one is
/// minted only from a [`Citation`] or from proving ends (D410).
#[doc = "```compile_fail,E0451\nlet never = r2source::Never { proof: r2source::NeverProof::Declared, premises: Default::default() };\n```"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Never {
    proof: NeverProof,
    premises: BTreeSet<Premise>,
}

impl Never {
    /// What `citation` states, assuming what its source does: the runtime model its contract.
    pub fn cited(citation: Citation) -> Self {
        let premises = match citation.0 {
            Cited::Runtime => BTreeSet::from([Premise::GoRuntime]),
            Cited::Row | Cited::DebugInfo | Cited::Kernel => BTreeSet::new(),
        };
        Self {
            proof: NeverProof::Declared,
            premises,
        }
    }

    /// A body every one of whose `ends` proves it never comes back (D229), assuming what each
    /// does; `None` where there is no end or one is a bound.
    pub fn composed<'a>(ends: impl IntoIterator<Item = &'a Self>) -> Option<Self> {
        let mut premises = BTreeSet::new();
        let mut any = false;
        for end in ends {
            premises.extend(end.proves()?.iter().copied());
            any = true;
        }
        any.then_some(Self {
            proof: NeverProof::Composed,
            premises,
        })
    }

    /// No walk of the body reached a return: a bound, never proof.
    pub const fn unreached() -> Self {
        Self::bound(NeverProof::NoReturnReached)
    }

    const fn bound(proof: NeverProof) -> Self {
        Self {
            proof,
            premises: BTreeSet::new(),
        }
    }

    /// The same claim, also taking `premises` for granted: only ever weaker.
    #[must_use]
    pub fn assuming(mut self, premises: impl IntoIterator<Item = Premise>) -> Self {
        self.premises.extend(premises);
        self
    }

    /// What the proof takes for granted where it proves the call never comes back; `None` for a
    /// bound. The one predicate: a consumer that cannot carry a premise demands none.
    pub const fn proves(&self) -> Option<&BTreeSet<Premise>> {
        match self.proof {
            NeverProof::Declared | NeverProof::Composed => Some(&self.premises),
            NeverProof::NoReturnReached => None,
        }
    }

    pub const fn proof(&self) -> NeverProof {
        self.proof
    }

    pub const fn premises(&self) -> &BTreeSet<Premise> {
        &self.premises
    }
}

/// A fact's standing as a reader sees it: one ASCII cell after a note's `;`, weakest first
/// (doc/adr-display.md, D580). `Refused` and `Unknown` come from a fact's kind, never a confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Mark {
    /// A refusal, whose reason follows.
    Refused,
    /// Asked, and no answer or reason.
    Unknown,
    /// A convention's default.
    Assumed,
    /// A reading nothing proves.
    Read,
    /// A declaration found by a name.
    Declared,
    /// A bound.
    Bound,
    /// Stated or proven under a premise.
    Premise,
    /// Stated or proven, assuming nothing.
    Holds,
}

impl Mark {
    /// Every mark, weakest first.
    pub const ALL: [Self; 8] = [
        Self::Refused,
        Self::Unknown,
        Self::Assumed,
        Self::Read,
        Self::Declared,
        Self::Bound,
        Self::Premise,
        Self::Holds,
    ];

    /// The cell a listing writes after `;`.
    pub const fn cell(self) -> char {
        match self {
            Self::Refused => '!',
            Self::Unknown => '?',
            Self::Assumed => '_',
            Self::Read => '.',
            Self::Declared => '^',
            Self::Bound => '~',
            Self::Premise => '*',
            Self::Holds => ' ',
        }
    }

    /// What a reader takes the cell to say, as the legend, `ao` and the JSON spell it
    /// (doc/adr-display.md, "Visual grammar").
    pub const fn reads_as(self) -> &'static str {
        match self {
            Self::Holds => "holds",
            Self::Premise => "holds if the premise holds",
            Self::Bound => "holds as the bound the text spells",
            Self::Declared => "holds if the declaration is right",
            Self::Read => "a width or a use, no type",
            Self::Assumed => "the ABI default, no evidence",
            Self::Unknown => "asked, no answer, no reason",
            Self::Refused => "refused; the reason follows",
        }
    }

    /// The order a line's notes take, weakest first: by mark, then the weaker confidence first;
    /// `Confidence::cmp` is basis-first, so it cannot order marks (doc/adr-display.md).
    pub fn weakest_first(a: (Self, &Confidence), b: (Self, &Confidence)) -> std::cmp::Ordering {
        a.0.cmp(&b.0).then_with(|| b.1.cmp(a.1))
    }
}

/// Why a fact about a program is believed, and what that belief assumes.
///
/// Ordered strongest first: by basis, then by how many premises it takes for
/// granted, so the same basis with fewer premises is the stronger claim, then
/// by which, so the order is total.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Confidence {
    pub basis: Basis,
    /// What the fact takes for granted. Empty where it assumes nothing beyond its basis.
    pub premises: Premises,
}

impl Confidence {
    /// A belief on this basis that assumes nothing else.
    pub const fn of(basis: Basis) -> Self {
        Self {
            basis,
            premises: Premises::new(),
        }
    }

    /// The same belief, also resting on `premise`.
    pub fn assuming(mut self, premise: Premise) -> Self {
        self.premises.insert(premise);
        self
    }

    /// How strongly the fact is known.
    pub const fn grade(&self) -> Grade {
        self.basis.grade()
    }

    /// The cell a reader sees: a premise marks a stated or proven fact, and a weaker grade
    /// keeps its own mark whatever it assumes.
    pub fn mark(&self) -> Mark {
        match self.grade() {
            Grade::Stated | Grade::Proven if self.premises.is_empty() => Mark::Holds,
            Grade::Stated | Grade::Proven => Mark::Premise,
            Grade::Bounded => Mark::Bound,
            Grade::Declared => Mark::Declared,
            Grade::Read => Mark::Read,
            Grade::Assumed => Mark::Assumed,
        }
    }

    /// What a fact derived from two others is believed on: the weaker basis,
    /// taking for granted everything either does.
    #[must_use]
    pub fn and(mut self, other: &Self) -> Self {
        self.basis = self.basis.max(other.basis);
        self.premises.extend(other.premises.iter());
        self
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.basis
            .cmp(&other.basis)
            .then(self.premises.len().cmp(&other.premises.len()))
            .then_with(|| self.premises.cmp(&other.premises))
    }
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// `called`, or `handed+closed-world+ub-free`: the basis, then each premise.
impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.basis.spelled())?;
        for premise in self.premises.iter() {
            write!(f, "+{}", premise.spelled())?;
        }
        Ok(())
    }
}

/// A value the engine derived, with why it is believed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Fact<T> {
    pub value: T,
    pub confidence: Confidence,
}

impl<T> Fact<T> {
    pub fn new(value: T, confidence: impl Into<Confidence>) -> Self {
        Self {
            value,
            confidence: confidence.into(),
        }
    }

    pub const fn grade(&self) -> Grade {
        self.confidence.grade()
    }

    /// The value, where it is known at least as strongly as `least`.
    pub fn at_least(&self, least: Grade) -> Option<&T> {
        (self.grade() <= least).then_some(&self.value)
    }

    /// The same belief about a value computed from this one.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Fact<U> {
        Fact {
            value: f(self.value),
            confidence: self.confidence,
        }
    }

    /// A value computed from this one and `other`, believed as the weaker.
    pub fn with<U, V>(self, other: Fact<U>, f: impl FnOnce(T, U) -> V) -> Fact<V> {
        Fact {
            confidence: self.confidence.and(&other.confidence),
            value: f(self.value, other.value),
        }
    }
}

impl From<Basis> for Confidence {
    fn from(basis: Basis) -> Self {
        Self::of(basis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every confidence over every basis and set of premises: the domain is
    /// finite, so these laws are checked whole rather than sampled.
    fn every_confidence() -> Vec<Confidence> {
        let sets = [
            vec![],
            vec![Premise::ClosedWorld],
            vec![Premise::UbFreeSource],
            vec![Premise::ClosedWorld, Premise::UbFreeSource],
        ];
        let assuming = |basis: Basis, premises: &[Premise]| {
            premises
                .iter()
                .fold(Confidence::of(basis), |held, premise| {
                    held.assuming(*premise)
                })
        };
        Basis::ALL
            .iter()
            .flat_map(|basis| sets.iter().map(|premises| assuming(*basis, premises)))
            .collect()
    }

    /// Every pair of confidences, each pair once in each order.
    fn pairs(all: &[Confidence]) -> impl Iterator<Item = (&Confidence, &Confidence)> {
        all.iter().flat_map(|a| all.iter().map(move |b| (a, b)))
    }

    #[test]
    fn the_basis_order_refines_the_grade_order() {
        assert!(Basis::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            Basis::ALL
                .windows(2)
                .all(|pair| pair[0].grade() <= pair[1].grade())
        );
    }

    #[test]
    fn fewer_premises_on_one_basis_are_the_stronger_claim() {
        let all = every_confidence();
        let comparable =
            pairs(&all).filter(|(a, b)| a.basis == b.basis && a.premises.is_subset(&b.premises));
        for (a, b) in comparable {
            assert!(a <= b, "{a} should be at least as strong as {b}");
        }
        // A fact found twice keeps the stronger of its two confidences whole.
        let called = Confidence::of(Basis::Called);
        let stated = Confidence::of(Basis::Stated).assuming(Premise::ClosedWorld);
        assert_eq!(called.min(stated.clone()), stated);
    }

    #[test]
    fn a_derived_fact_is_no_stronger_than_what_it_is_derived_from() {
        let all = every_confidence();
        for a in &all {
            assert_eq!(&a.clone().and(a), a, "and is idempotent");
        }
        for (a, b) in pairs(&all) {
            let both = a.clone().and(b);
            assert_eq!(both, b.clone().and(a), "and commutes");
            assert!(
                &both >= a && &both >= b,
                "{both} is stronger than {a} or {b}"
            );
            assert!(both.premises.is_superset(&a.premises));
            let associates = all
                .iter()
                .all(|c| both.clone().and(c) == a.clone().and(&b.clone().and(c)));
            assert!(associates, "and associates over {a} and {b}");
        }
    }

    #[test]
    fn a_fact_answers_only_a_consumer_that_accepts_its_grade() {
        let declared = Fact::new(4u32, Basis::Declared);
        assert_eq!(declared.at_least(Grade::Read), Some(&4));
        assert_eq!(declared.at_least(Grade::Declared), Some(&4));
        assert_eq!(declared.at_least(Grade::Proven), None);
        let sum = declared.with(Fact::new(1u32, Basis::Certified), |a, b| a + b);
        assert_eq!(sum.value, 5);
        assert_eq!(sum.grade(), Grade::Declared);
        assert_eq!(
            Confidence::of(Basis::Handed)
                .assuming(Premise::UbFreeSource)
                .assuming(Premise::ClosedWorld)
                .to_string(),
            "handed+closed-world+ub-free"
        );
    }

    /// Every set of premises: `Premise` has 4 variants, so 16 sets.
    fn every_premise_set() -> Vec<Premises> {
        (0..1u8 << Premise::ALL.len())
            .map(|bits| {
                let held = Premise::ALL.iter().enumerate();
                let held = held.filter(|(index, _)| bits & (1 << index) != 0);
                held.map(|(_, premise)| *premise).collect()
            })
            .collect()
    }

    /// The mark over every basis and premise set (D580): a space only where nothing is assumed
    /// past a stated or proven basis, and a premise never hides behind a space.
    #[test]
    fn the_mark_is_a_space_only_for_a_stated_or_proven_fact_with_no_premise() {
        let sets = every_premise_set();
        assert_eq!(sets.len(), 16);
        let strong = |grade| matches!(grade, Grade::Stated | Grade::Proven);
        for basis in Basis::ALL {
            for premises in &sets {
                let confidence = Confidence {
                    basis,
                    premises: *premises,
                };
                let cell = confidence.mark().cell();
                let exact = strong(basis.grade()) && premises.is_empty();
                let assumed = strong(basis.grade()) && !premises.is_empty();
                assert_eq!(cell == ' ', exact, "{confidence}");
                assert_eq!(cell == '*', assumed, "{confidence}");
                assert!(!matches!(confidence.mark(), Mark::Refused | Mark::Unknown));
            }
        }
        // Without premises the mark falls as the grade does.
        for (a, b) in Basis::ALL
            .iter()
            .flat_map(|a| Basis::ALL.iter().map(move |b| (a, b)))
        {
            if a.grade() <= b.grade() {
                assert!(
                    Confidence::of(*a).mark() >= Confidence::of(*b).mark(),
                    "{a:?} {b:?}"
                );
            }
        }
        let cells = Mark::ALL.map(Mark::cell);
        assert!(cells.iter().all(char::is_ascii));
        assert_eq!(BTreeSet::from(cells).len(), 8);
        assert!(Mark::ALL.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// Notes sort by mark first: `Confidence`'s own order is basis-first, so it puts
    /// `stated+closed-world` above `certified` while its mark is the weaker.
    #[test]
    fn notes_sort_by_mark_before_confidence() {
        let assumed = Confidence::of(Basis::Stated).assuming(Premise::ClosedWorld);
        let certified = Confidence::of(Basis::Certified);
        assert!(assumed < certified);
        assert!(assumed.mark() < certified.mark());
        let mut notes = vec![
            certified.clone(),
            Confidence::of(Basis::Solved),
            assumed.clone(),
        ];
        notes.sort_by(|a, b| Mark::weakest_first((a.mark(), a), (b.mark(), b)));
        assert_eq!(notes, [Confidence::of(Basis::Solved), assumed, certified]);
    }
}

#[cfg(test)]
mod never_tests {
    use super::{Citation, Never, NeverProof, Premise};

    /// A composition proves only from proving ends, at least one, assuming what each does (D410).
    #[test]
    fn a_composition_needs_an_end_and_proves_only_from_proofs() {
        let go = Never::cited(Citation::runtime("runtime.gopanic").expect("the model names it"));
        assert_eq!(go.premises(), &[Premise::GoRuntime].into());
        assert_eq!(Never::composed([]), None);
        assert_eq!(Never::composed([&go, &Never::unreached()]), None);
        assert_eq!(Never::composed([&Never::unreached()]), None);
        let composed = Never::composed([&go, &go]).expect("every end proves");
        assert_eq!(composed.proof(), NeverProof::Composed);
        assert_eq!(composed.proves(), Some(&[Premise::GoRuntime].into()));
        assert_eq!(
            Never::unreached().assuming([Premise::ClosedWorld]).proves(),
            None
        );
    }
}
