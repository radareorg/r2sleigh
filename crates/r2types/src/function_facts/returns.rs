//! What a function hands back, decided once from the strongest evidence that answers.

use std::collections::BTreeMap;

use crate::{CTypeLike, EvidenceTypes, FunctionFacts, FunctionType};

/// The type a function returns, or why none may be claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnTypeFact {
    Decided {
        ty: CTypeLike,
        by: ReturnTypeEvidence,
    },
    Refused(ReturnTypeRefusal),
}

/// What decided a return type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnTypeEvidence {
    /// The render-authorized signature declares it.
    Signature,
    /// The source declares the type the return carrier holds.
    ExactSource,
    /// Every returned value and every tail-called result has it.
    Exits,
    /// No exit hands back a value, and the function's boundary proves it fills no result carrier.
    VoidBoundary,
}

/// Why no return type may be claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnTypeRefusal {
    /// A return hands back a value the evidence leaves untyped.
    UntypedReturn,
    /// A tail call whose site states no interface.
    UnreadTailCall,
    /// Two exits hand back different types.
    Disagreement,
    /// No exit hands back a value, and the boundary does not prove there is none.
    UnprovenBoundary,
}

impl ReturnTypeFact {
    /// The type, where one is decided.
    pub const fn decided(&self) -> Option<&CTypeLike> {
        match self {
            Self::Decided { ty, .. } => Some(ty),
            Self::Refused(_) => None,
        }
    }

    /// Decide in order: the signature, the exact source type, what every exit agrees on, then the boundary.
    pub(crate) fn decide(
        source: &r2ssa::SsaArtifact,
        report: &FunctionFacts,
        evidence: &EvidenceTypes,
    ) -> Self {
        let fact = Self::decided_from(source, report, evidence);
        r2il::refusal_evidence!("return-type", "{:#x}: {fact:?}", source.function().entry);
        fact
    }

    fn decided_from(
        source: &r2ssa::SsaArtifact,
        report: &FunctionFacts,
        evidence: &EvidenceTypes,
    ) -> Self {
        let signature = report.type_facts().render_authorized_signature();
        if let Some(ty) = signature.and_then(|signature| signature.ret_type.clone()) {
            return Self::decided_by(ty, ReturnTypeEvidence::Signature);
        }
        if let Some(ty) = crate::exact_source_return_type(source) {
            return Self::decided_by(ty, ReturnTypeEvidence::ExactSource);
        }
        let signatures = report.callsite_signatures();
        match agreed(exit_types(source, &signatures, evidence)) {
            Ok(Some(ty)) => Self::decided_by(ty, ReturnTypeEvidence::Exits),
            Ok(None) => Self::without_values(source),
            Err(refusal) => Self::Refused(refusal),
        }
    }

    const fn decided_by(ty: CTypeLike, by: ReturnTypeEvidence) -> Self {
        Self::Decided { ty, by }
    }

    /// No exit hands back a value: void only where the boundary proves no result carrier is filled.
    fn without_values(source: &r2ssa::SsaArtifact) -> Self {
        match crate::signature_infer::boundary_result_type(source) {
            CTypeLike::Void => Self::decided_by(CTypeLike::Void, ReturnTypeEvidence::VoidBoundary),
            _ => Self::Refused(ReturnTypeRefusal::UnprovenBoundary),
        }
    }
}

/// The type each value-carrying return hands back, then each tail call's result.
fn exit_types<'a>(
    source: &'a r2ssa::SsaArtifact,
    signatures: &'a BTreeMap<r2ssa::CallSiteId, FunctionType>,
    evidence: &'a EvidenceTypes,
) -> impl Iterator<Item = Result<CTypeLike, ReturnTypeRefusal>> + 'a {
    let certificates = source.certificates();
    let returned = certificates.returns.iter().map(|certificate| {
        evidence
            .value_type(certificate.value)
            .cloned()
            .ok_or(ReturnTypeRefusal::UntypedReturn)
    });
    let tails = certificates
        .callsites
        .values()
        .filter(|certificate| certificate.transfer == r2ssa::CallSiteTransfer::TailCall)
        .map(|certificate| tail_result(source, signatures, certificate.call_site));
    returned.chain(tails)
}

/// What a tail call hands back on this function's behalf: its callee's declared result, else its carrier.
fn tail_result(
    source: &r2ssa::SsaArtifact,
    signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
    call_site: r2ssa::CallSiteId,
) -> Result<CTypeLike, ReturnTypeRefusal> {
    let interface = source
        .call_site_interface(call_site)
        .ok_or(ReturnTypeRefusal::UnreadTailCall)?;
    Ok(match interface.result() {
        r2ssa::SourceCallResult::Void => CTypeLike::Void,
        r2ssa::SourceCallResult::Register { storage } => signatures
            .get(&call_site)
            .map(|signature| signature.return_type.clone())
            .filter(|ty| *ty != CTypeLike::Unknown)
            .unwrap_or_else(|| CTypeLike::uint(storage.size * 8)),
    })
}

/// The one type every exit has, none where no exit hands back a value.
fn agreed(
    exits: impl Iterator<Item = Result<CTypeLike, ReturnTypeRefusal>>,
) -> Result<Option<CTypeLike>, ReturnTypeRefusal> {
    let mut agreed: Option<CTypeLike> = None;
    for ty in exits {
        let ty = ty?;
        match &agreed {
            Some(existing) if *existing != ty => return Err(ReturnTypeRefusal::Disagreement),
            Some(_) => {}
            None => agreed = Some(ty),
        }
    }
    Ok(agreed)
}
