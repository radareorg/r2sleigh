//! What a function hands back, decided once from the strongest evidence that answers.

use std::collections::BTreeMap;

use crate::{CTypeLike, EvidenceTypes, FunctionType};

/// The type a function returns, or why none may be claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnTypeFact {
    Decided {
        ty: CTypeLike,
        by: ReturnTypeEvidence,
    },
    /// No exit hands back a value, and the boundary does not prove there is
    /// none.
    ///
    /// No type is claimed for what the function returns. A caller still reads
    /// the convention's result carrier after the call, so a definition declares
    /// that carrier at its storage word and hands back a residual of it at
    /// every return: the header states only where the machine leaves a result,
    /// and the value is marked unproven where it is returned. `None` where no
    /// convention names a carrier C can declare.
    Unproven {
        carrier: Option<CTypeLike>,
    },
    Refused(ReturnTypeRefusal),
}

/// What decided a return type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnTypeEvidence {
    /// The declaration's type graph states it, and every return certifies the carrier.
    ExactSource,
    /// The program's own declaration of this function states it.
    Declared,
    /// The recovered interface's storage word for the carrier every return certifies, as its parameters have.
    Carrier,
    /// Every returned value and every tail-called result has it.
    Exits,
    /// No exit hands back a value, and the boundary proves no result carrier is filled.
    VoidBoundary,
}

/// Why no return type may be claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnTypeRefusal {
    /// A return hands back a value the evidence leaves untyped.
    UntypedReturn,
    /// A tail call whose site states no interface.
    UnreadTailCall,
    /// A tail call whose callee declares no result type.
    UntypedTailCall,
    /// Two exits hand back different types.
    Disagreement,
}

/// What one exit says about the returned type.
enum Exit {
    Typed(CTypeLike),
    /// A constant carries no type, only a value any type wide enough can hold.
    Constant(u64),
}

impl ReturnTypeFact {
    /// The type, where one is decided.
    pub const fn decided(&self) -> Option<&CTypeLike> {
        match self {
            Self::Decided { ty, .. } => Some(ty),
            Self::Unproven { .. } | Self::Refused(_) => None,
        }
    }

    /// The type a definition declares it returns: the decided type, or where
    /// the value is unproven, the result carrier a caller reads.
    ///
    /// The one answer every view of the function reads -- the rendered header
    /// and the function's own description -- so they cannot state two types.
    pub const fn declared(&self) -> Option<&CTypeLike> {
        match self {
            Self::Decided { ty, .. } => Some(ty),
            Self::Unproven { carrier } => carrier.as_ref(),
            Self::Refused(_) => None,
        }
    }

    /// Whether the boundary leaves what the function returns unproven.
    pub const fn is_unproven(&self) -> bool {
        matches!(self, Self::Unproven { .. })
    }

    /// An unproven result, declared as the carrier a caller reads after the
    /// call: the convention's result slot where the interface proves nothing,
    /// at its storage word, where C has an integer that wide.
    fn unproven(source: &r2ssa::SsaArtifact) -> Self {
        let carrier = source
            .machine_context()
            .return_value_carrier()
            .map(|storage| storage.size.saturating_mul(8))
            .filter(|bits| CTypeLike::is_integer_width(*bits))
            .map(CTypeLike::uint);
        Self::Unproven { carrier }
    }

    /// Decide in order: the declared graph, the declaration, a void boundary, the recovered carrier, what every exit agrees on.
    pub(crate) fn decide(
        source: &r2ssa::SsaArtifact,
        signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
        evidence: &EvidenceTypes,
    ) -> Self {
        let fact = Self::decided_from(source, signatures, evidence);
        r2il::refusal_evidence!("return-type", "{:#x}: {fact:?}", source.function().entry);
        fact
    }

    fn decided_from(
        source: &r2ssa::SsaArtifact,
        signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
        evidence: &EvidenceTypes,
    ) -> Self {
        let interface = source.machine_context().function_interface();
        // A recovered interface's graph states the carrier the body fills, not a declaration.
        let read =
            interface.is_some_and(r2ssa::SourceFunctionInterface::prototype_from_source_types);
        let graph = crate::exact_source_return_type(source);
        if let Some(ty) = graph.clone().filter(|_| read) {
            return Self::decided_by(ty, ReturnTypeEvidence::ExactSource);
        }
        if let Some(ty) = declared(source) {
            return Self::decided_by(ty, ReturnTypeEvidence::Declared);
        }
        // r2ssa owns the result boundary: one it proved void leaves no type to agree on.
        if interface.map(r2ssa::SourceFunctionInterface::return_kind)
            == Some(r2ssa::SourceFunctionReturn::Void)
        {
            return Self::decided_by(CTypeLike::Void, ReturnTypeEvidence::VoidBoundary);
        }
        // A return whose result r2ssa left unproven hands back something no exit can type.
        if source
            .facts()
            .boundaries
            .returns
            .values()
            .any(|boundary| boundary.result_unproven)
        {
            return Self::unproven(source);
        }
        if let Some(ty) = graph {
            return Self::decided_by(ty, ReturnTypeEvidence::Carrier);
        }
        match agreed(exits(source, signatures, evidence)) {
            Ok(Some(ty)) => Self::decided_by(ty, ReturnTypeEvidence::Exits),
            Ok(None) => Self::unproven(source),
            Err(refusal) => Self::Refused(refusal),
        }
    }

    const fn decided_by(ty: CTypeLike, by: ReturnTypeEvidence) -> Self {
        Self::Decided { ty, by }
    }
}

/// The return type the program's declaration of this function spells, where it spells one.
fn declared(source: &r2ssa::SsaArtifact) -> Option<CTypeLike> {
    let spelling = source.source_signature()?.return_type()?;
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    crate::parse_c_type_like(spelling, ptr_bits).filter(|ty| *ty != CTypeLike::Unknown)
}

/// What each value-carrying return hands back, then each tail call's result.
fn exits<'a>(
    source: &'a r2ssa::SsaArtifact,
    signatures: &'a BTreeMap<r2ssa::CallSiteId, FunctionType>,
    evidence: &'a EvidenceTypes,
) -> impl Iterator<Item = Result<Exit, ReturnTypeRefusal>> + 'a {
    let certificates = source.certificates();
    let returned = certificates.returns.iter().map(|certificate| {
        if let Some(ty) = evidence.value_type(certificate.value) {
            return Ok(Exit::Typed(ty.clone()));
        }
        source
            .value_var(certificate.value)
            .and_then(r2ssa::SSAVar::constant_bits)
            .map(Exit::Constant)
            .ok_or(ReturnTypeRefusal::UntypedReturn)
    });
    let tails = certificates
        .callsites
        .values()
        .filter(|certificate| certificate.transfer == r2ssa::CallSiteTransfer::TailCall)
        .map(|certificate| tail_result(source, signatures, certificate.call_site));
    returned.chain(tails)
}

/// What a tail call hands back on this function's behalf: nothing, or its callee's declared result.
fn tail_result(
    source: &r2ssa::SsaArtifact,
    signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
    call_site: r2ssa::CallSiteId,
) -> Result<Exit, ReturnTypeRefusal> {
    let interface = source
        .call_site_interface(call_site)
        .ok_or(ReturnTypeRefusal::UnreadTailCall)?;
    match interface.result() {
        r2ssa::SourceCallResult::Void => Ok(Exit::Typed(CTypeLike::Void)),
        r2ssa::SourceCallResult::Register { .. } => signatures
            .get(&call_site)
            .map(|signature| signature.return_type.clone())
            .filter(|ty| *ty != CTypeLike::Unknown)
            .map(Exit::Typed)
            .ok_or(ReturnTypeRefusal::UntypedTailCall),
    }
}

/// The one type every exit has, none where no exit hands back a value.
fn agreed(
    exits: impl Iterator<Item = Result<Exit, ReturnTypeRefusal>>,
) -> Result<Option<CTypeLike>, ReturnTypeRefusal> {
    let mut agreed: Option<CTypeLike> = None;
    let mut constants = Vec::new();
    for exit in exits {
        match exit? {
            Exit::Constant(value) => constants.push(value),
            Exit::Typed(ty) => match &agreed {
                Some(existing) if *existing != ty => return Err(ReturnTypeRefusal::Disagreement),
                Some(_) => {}
                None => agreed = Some(ty),
            },
        }
    }
    match agreed {
        None if constants.is_empty() => Ok(None),
        None => Err(ReturnTypeRefusal::UntypedReturn),
        Some(ty) if constants.iter().all(|value| holds(&ty, *value)) => Ok(Some(ty)),
        Some(_) => Err(ReturnTypeRefusal::Disagreement),
    }
}

/// Whether a returned constant is a value of this type: an integer wide enough, or a null pointer.
fn holds(ty: &CTypeLike, value: u64) -> bool {
    match ty {
        CTypeLike::Int { bits, .. } => *bits >= 64 || value >> bits == 0,
        CTypeLike::Bool => value <= 1,
        CTypeLike::Pointer(_) => value == 0,
        CTypeLike::Typedef { ty, .. } | CTypeLike::Const(ty) => holds(ty, value),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(bits: u32) -> CTypeLike {
        CTypeLike::uint(bits)
    }

    fn agree(
        exits: Vec<Result<Exit, ReturnTypeRefusal>>,
    ) -> Result<Option<CTypeLike>, ReturnTypeRefusal> {
        agreed(exits.into_iter())
    }

    #[test]
    fn a_value_return_and_a_tail_to_a_void_callee_disagree() {
        let exits = vec![Ok(Exit::Typed(int(32))), Ok(Exit::Typed(CTypeLike::Void))];
        assert_eq!(agree(exits), Err(ReturnTypeRefusal::Disagreement));
    }

    #[test]
    fn a_constant_agrees_with_any_type_that_holds_it() {
        let fits = vec![Ok(Exit::Constant(0xffff_ffff)), Ok(Exit::Typed(int(32)))];
        assert_eq!(agree(fits), Ok(Some(int(32))));
        let wide = vec![Ok(Exit::Constant(1 << 32)), Ok(Exit::Typed(int(32)))];
        assert_eq!(agree(wide), Err(ReturnTypeRefusal::Disagreement));
        let null = vec![
            Ok(Exit::Constant(0)),
            Ok(Exit::Typed(CTypeLike::ptr(CTypeLike::Void))),
        ];
        assert_eq!(agree(null), Ok(Some(CTypeLike::ptr(CTypeLike::Void))));
    }

    #[test]
    fn untyped_exits_refuse_rather_than_guess() {
        assert_eq!(
            agree(vec![Ok(Exit::Constant(1))]),
            Err(ReturnTypeRefusal::UntypedReturn)
        );
        let untyped_tail = vec![
            Ok(Exit::Typed(int(64))),
            Err(ReturnTypeRefusal::UntypedTailCall),
        ];
        assert_eq!(agree(untyped_tail), Err(ReturnTypeRefusal::UntypedTailCall));
        assert_eq!(agree(Vec::new()), Ok(None));
    }
}
