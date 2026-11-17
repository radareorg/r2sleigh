//! What a `ret` line says of the function's result: r2types' sealed `ReturnTypeFact`, the fact
//! `afi` reads, so the listing and `afi` name one standing (D584).

use r2source::confidence::Confidence;
use r2types::{ReturnTypeFact, ReturnTypeRefusal, UnprovenCause};

/// The result's standing as the sealed return fact states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultStanding {
    /// A type is decided, on this confidence.
    Decided(Confidence),
    /// No exit is proven to hand a value back, and why, as `afi` names it.
    Unproven(Option<UnprovenCause>),
    /// No type may be claimed.
    Refused(ReturnTypeRefusal),
}

impl ResultStanding {
    /// The standing of one sealed fact, its confidence the basis `afi` reads (`FunctionInfo`).
    pub fn of(fact: &ReturnTypeFact, artifact: &r2ssa::SsaArtifact) -> Option<Self> {
        Some(match fact {
            ReturnTypeFact::Decided { .. } => Self::Decided(fact.basis(artifact)?.into()),
            ReturnTypeFact::Unproven { cause, .. } => Self::Unproven(*cause),
            ReturnTypeFact::Refused(refusal) => Self::Refused(*refusal),
        })
    }

    /// Why the result is unproven, in `afi`'s words.
    pub fn cause_name(cause: Option<UnprovenCause>) -> &'static str {
        cause.map_or("no return reached", UnprovenCause::name)
    }

    /// Why no type may be claimed.
    pub const fn refusal_name(refusal: ReturnTypeRefusal) -> &'static str {
        match refusal {
            ReturnTypeRefusal::UntypedReturn => "UntypedReturn",
            ReturnTypeRefusal::UnreadTailCall => "UnreadTailCall",
            ReturnTypeRefusal::UntypedTailCall => "UntypedTailCall",
            ReturnTypeRefusal::Disagreement => "Disagreement",
        }
    }
}
