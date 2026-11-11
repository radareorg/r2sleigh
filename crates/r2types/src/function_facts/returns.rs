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
        cause: Option<UnprovenCause>,
        /// Whether the returns spell their values through the carrier: r2ssa states a register.
        spelled: bool,
    },
    Refused(ReturnTypeRefusal),
}

/// Why a result is unproven, as the proof line and `afi` name it (doc/adr-scratch-result.md,
/// "Rendering of Unproven"); `None` where no return is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnprovenCause {
    /// A defined value reaches a return, and no declaration and no reading caller decide it.
    Written,
    /// A return hands back the entry byte of an input location.
    EntryInput,
    /// No call reads the result, under the closed world.
    Unread,
    /// The result forwards through a cycle of callees that state none.
    ForwardCycle,
    /// The convention states no complete set of result lanes, so none is proven empty.
    LanesUnbounded,
}

impl UnprovenCause {
    /// The cause as the proof line and `afi` spell it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Written => "Written",
            Self::EntryInput => "EntryInput",
            Self::Unread => "Unread",
            Self::ForwardCycle => "ForwardCycle",
            Self::LanesUnbounded => "LanesUnbounded",
        }
    }

    /// The cause r2ssa's evidence names: the closed world's decision outranks the body's evidence,
    /// and a value reaching a return outranks a handed-back input.
    fn of(causes: &[r2ssa::SourceResultCause]) -> Option<Self> {
        use r2ssa::SourceResultCause as Cause;
        if causes.contains(&Cause::ForwardCycle) {
            return Some(Self::ForwardCycle);
        }
        if causes.contains(&Cause::Unread) {
            return Some(Self::Unread);
        }
        let written = causes.iter().any(|cause| {
            !matches!(
                cause,
                Cause::HandedBack | Cause::NoReturn | Cause::LanesUnbounded
            )
        });
        if written {
            return Some(Self::Written);
        }
        if causes.contains(&Cause::HandedBack) {
            return Some(Self::EntryInput);
        }
        (causes.contains(&Cause::LanesUnbounded)).then_some(Self::LanesUnbounded)
    }
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
            Self::Unproven { carrier, .. } => carrier.as_ref(),
            Self::Refused(_) => None,
        }
    }

    /// Whether the boundary leaves what the function returns unproven.
    pub const fn is_unproven(&self) -> bool {
        matches!(self, Self::Unproven { .. })
    }

    /// The result type a caller's declaration states: the decided type, or a spelled unproven
    /// result's carrier, the typedef's target (doc/adr-scratch-result.md, "S1 and S2 as built").
    pub fn signature_type(&self) -> Option<&CTypeLike> {
        match self {
            Self::Decided { ty, .. } => Some(ty),
            Self::Unproven {
                carrier,
                spelled: true,
                ..
            } => carrier.as_ref(),
            Self::Unproven { .. } | Self::Refused(_) => None,
        }
    }

    /// Why the result is unproven, where it is and a cause is named.
    pub const fn unproven_cause(&self) -> Option<UnprovenCause> {
        match self {
            Self::Unproven { cause, .. } => *cause,
            Self::Decided { .. } | Self::Refused(_) => None,
        }
    }

    /// An unproven result, declared at the width the body's own returns write (r2ssa's seed), else
    /// at the convention's result slot's storage word, where C has an integer that wide.
    fn unproven(source: &r2ssa::SsaArtifact) -> Self {
        let context = source.machine_context();
        let unproven = (context.function_interface())
            .and_then(r2ssa::SourceFunctionInterface::unproven_result);
        let seed = unproven
            .and_then(r2ssa::SourceUnprovenResult::seed)
            .map(|seed| seed.bits);
        let cause = unproven.and_then(|result| UnprovenCause::of(result.causes()));
        Self::unproven_at(source, seed, cause, false)
    }

    /// An unproven result at `bits`, else at the convention's storage word.
    fn unproven_at(
        source: &r2ssa::SsaArtifact,
        bits: Option<u32>,
        cause: Option<UnprovenCause>,
        spelled: bool,
    ) -> Self {
        let context = source.machine_context();
        let carrier = bits
            .or_else(|| {
                (context.return_value_carrier()).map(|storage| storage.size.saturating_mul(8))
            })
            .filter(|bits| CTypeLike::is_integer_width(*bits))
            .map(CTypeLike::uint);
        Self::Unproven {
            carrier,
            cause,
            spelled,
        }
    }

    /// What this return type rests on (doc/adr-provenance.md, C2); none where it is refused. A type
    /// the interface's graph states rests on what the interface's types are read from.
    pub fn basis(&self, source: &r2ssa::SsaArtifact) -> Option<r2source::confidence::Basis> {
        use r2source::confidence::Basis;
        Some(match self {
            Self::Decided { by, .. } => match by {
                ReturnTypeEvidence::ExactSource => {
                    source.machine_context().function_interface()?.types().basis
                }
                // The function's own prototype, as its debug information spells it.
                ReturnTypeEvidence::Declared => Basis::DebugInfo,
                // Every exit proven to hand back no value.
                ReturnTypeEvidence::VoidBoundary => Basis::Certified,
                // One type agreed by every exit: true of each, exact of none.
                ReturnTypeEvidence::Exits => Basis::Solved,
                // Only the width of the storage word every return certifies.
                ReturnTypeEvidence::Carrier => Basis::CarrierWidth,
            },
            // The convention's result slot, which no exit is proven to fill.
            Self::Unproven { .. } => Basis::Convention,
            Self::Refused(_) => return None,
        })
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
        let read = interface.is_some_and(r2ssa::SourceFunctionInterface::types_are_declared);
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
        // A body's integer result no declaration and no reading call decides is written, not proven;
        // the closed world names why where it decided (D202, D166).
        if let Some(bits) = interface.and_then(written_bits) {
            let cause = interface.map(r2ssa::SourceFunctionInterface::written_cause);
            let cause = cause.and_then(|cause| UnprovenCause::of(&[cause]));
            return Self::unproven_at(source, Some(bits), cause, true);
        }
        // A return whose result r2ssa left unproven hands back something no exit can type.
        let unproven = interface.map(r2ssa::SourceFunctionInterface::return_kind)
            == Some(r2ssa::SourceFunctionReturn::Unproven);
        if unproven
            || (source.facts().boundaries.returns.values()).any(|boundary| boundary.result_unproven)
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

/// The return type the program's declaration of this function states, from its interface's graph.
fn declared(source: &r2ssa::SsaArtifact) -> Option<CTypeLike> {
    let interface = source.machine_context().function_interface()?;
    if !interface.types_are_declared() {
        return None;
    }
    match interface.return_kind() {
        r2ssa::SourceFunctionReturn::Void => Some(CTypeLike::Void),
        _ => crate::convert::source_type_like(
            interface.type_graph()?,
            interface.return_logical_value()?.type_id(),
        ),
    }
}

/// The width a body's own integer result is written at, where nothing else states it: a float or a
/// pair a reading call decided stays a value (doc/adr-scratch-result.md, "Rendering of Unproven").
fn written_bits(interface: &r2ssa::SourceFunctionInterface) -> Option<u32> {
    let r2ssa::SourceFunctionReturn::Register { storage } = interface.return_kind() else {
        return None;
    };
    if interface.result_read_by_callers() {
        return None;
    }
    let whole = storage.size.saturating_mul(8);
    let logical = (interface.return_logical_value())
        .and_then(|value| u32::try_from(value.carrier().size_bits()).ok());
    Some(logical.map_or(whole, |bits| bits.min(whole)))
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
        r2ssa::SourceCallResult::Register { .. }
        | r2ssa::SourceCallResult::Pair { .. }
        | r2ssa::SourceCallResult::Unproven { .. } => signatures
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
