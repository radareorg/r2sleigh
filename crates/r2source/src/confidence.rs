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

/// What a derived fact is read from, strongest first.
///
/// Ordered by how much is being claimed, so a consumer may take everything at
/// or above the level it is willing to act on, and a fact found twice keeps
/// the stronger reason: a symbol that is also called is stated, not inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Basis {
    /// The image says so. An entry point, an initialiser or finaliser array
    /// slot, a symbol typed as a function, a linkage stub the format declares.
    /// Nothing is inferred and nothing can be wrong here that is not wrong in
    /// the file.
    Stated,
    /// A walked body calls it. One decoded call instruction with a constant
    /// target, which is a reading of bytes this engine did itself.
    Called,
    /// A walked body hands it to a function whose declaration says that
    /// parameter is a function.
    ///
    /// `entry0` never calls `main`: it passes it to `__libc_start_main`, whose
    /// prototype spells the first parameter `func`. The address is a function
    /// on the declaration's authority plus a constant this engine folded, so
    /// it is weaker than a call the machine makes and stronger than a
    /// transfer that may be a jump inside one function.
    Handed,
    /// A walked body leaves for it without returning. The same reading, over
    /// an instruction that is a jump: whether the target is a function of its
    /// own or a continuation of this one is exactly what a tail call makes
    /// ambiguous.
    Reached,
}

/// Something a derived fact takes for granted that no byte of the image states.
///
/// A premise is not evidence. It is the condition under which the evidence
/// means what the fact says, and a consumer that cannot grant it must not
/// act on the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Why a fact about a program is believed, and what that belief assumes.
///
/// Ordered by basis, then by premises: the same basis with fewer premises is
/// the stronger claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl From<Basis> for Confidence {
    fn from(basis: Basis) -> Self {
        Self::of(basis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stronger_basis_orders_first_and_on_one_basis_fewer_premises_do() {
        // A fact found twice keeps the lesser of its two confidences, which
        // is the stronger claim: each is kept whole, never merged.
        let called = Confidence::of(Basis::Called);
        let stated = Confidence::of(Basis::Stated).assuming(Premise::ClosedWorld);
        assert_eq!(called.clone().min(stated.clone()), stated);
        let assuming = Confidence::of(Basis::Called).assuming(Premise::UbFreeSource);
        assert_eq!(assuming.min(called.clone()), called);
    }
}
