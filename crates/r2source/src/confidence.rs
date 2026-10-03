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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
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
}

impl Premise {
    /// The premise as answers spell it.
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::ClosedWorld => "closed-world",
            Self::UbFreeSource => "ub-free",
        }
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
    /// What the fact takes for granted. Empty where it assumes nothing beyond
    /// its basis, which is every fact the engine derives today.
    pub premises: BTreeSet<Premise>,
}

impl Confidence {
    /// A belief on this basis that assumes nothing else.
    pub const fn of(basis: Basis) -> Self {
        Self {
            basis,
            premises: BTreeSet::new(),
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

    /// What a fact derived from two others is believed on: the weaker basis,
    /// taking for granted everything either does.
    #[must_use]
    pub fn and(mut self, other: &Self) -> Self {
        self.basis = self.basis.max(other.basis);
        self.premises.extend(other.premises.iter().copied());
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
        for premise in &self.premises {
            write!(f, "+{}", premise.spelled())?;
        }
        Ok(())
    }
}

/// A value the engine derived, with why it is believed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
}
