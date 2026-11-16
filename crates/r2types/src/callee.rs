use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

use r2ssa::dense::IdMap;
use r2ssa::{InstId, SSAVarNameKind};

use crate::{CalleeFact, CalleeLinkage, FunctionType, SignatureCertificateSource};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeIdentityKey {
    DirectAddress(u64),
    IndirectSite(InstId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeClass {
    Internal,
    Imported,
    ExternalSymbol,
    RawAddress,
    Indirect,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeIdentityEvidence {
    DirectTarget,
    RawMemoryName,
    RawConstantName,
    ImportLinkage,
    InternalLinkage,
    CalleeFactName,
    KnownSignature,
    FunctionName,
    SymbolName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeTargetPolicySource {
    ImportLinkage,
    CalleeFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeCallArgPolicy {
    Standard,
    ImportedLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeTargetResolutionSource {
    CallsiteResolution,
    PreparedDirectTarget,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalleeTargetPolicyDecision {
    pub imported: bool,
    pub modeled: bool,
    pub modeled_addr: Option<u64>,
    pub sources: BTreeSet<CalleeTargetPolicySource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCalleeIdentity {
    pub key: CalleeIdentityKey,
    pub identity: CalleeIdentity,
    pub source: CalleeTargetResolutionSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCalleeTarget {
    pub key: CalleeIdentityKey,
    pub identity: CalleeIdentity,
    pub source: CalleeTargetResolutionSource,
    pub policy: CalleeTargetPolicyDecision,
}

#[derive(Debug, Clone, Copy)]
pub struct CalleeTargetIdentityRequest<'a> {
    pub resolution: Option<&'a CalleeResolutionFacts>,
    pub callsite: Option<InstId>,
    pub prepared_direct_target: Option<u64>,
    pub direct_target_context: Option<&'a CalleeIdentityContext<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct CalleeTargetResolutionRequest<'a> {
    pub identity: CalleeTargetIdentityRequest<'a>,
    pub callee_facts: &'a BTreeMap<u64, CalleeFact>,
}

impl CalleeTargetPolicyDecision {
    pub fn imported_or_modeled(&self) -> bool {
        self.imported || self.modeled
    }

    pub fn arg_policy(&self) -> CalleeCallArgPolicy {
        if self.imported_or_modeled() {
            CalleeCallArgPolicy::ImportedLike
        } else {
            CalleeCallArgPolicy::Standard
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CalleeIdentityContext<'a> {
    pub function_names: &'a FxHashMap<u64, String>,
    pub symbols: &'a FxHashMap<u64, String>,
    pub callee_facts: &'a BTreeMap<u64, CalleeFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalleeIdentity {
    pub target_addr: Option<u64>,
    pub raw_name: Option<String>,
    pub display_name: Option<String>,
    pub class: CalleeClass,
    pub is_recursive: bool,
    pub signature: Option<FunctionType>,
    pub signature_source: Option<SignatureCertificateSource>,
    pub evidence: BTreeSet<CalleeIdentityEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalleeResolutionFacts {
    pub by_key: BTreeMap<CalleeIdentityKey, CalleeIdentity>,
    pub by_direct_addr: BTreeMap<u64, CalleeIdentityKey>,
    pub by_callsite: IdMap<InstId, CalleeIdentityKey>,
    /// Where an indirect call through a stated table can go: sorted, and no one callee's identity.
    pub table_targets: IdMap<InstId, Box<[u64]>>,
}

fn import_policy_authorized_from_evidence(class: CalleeClass, has_import_linkage: bool) -> bool {
    class == CalleeClass::Imported && has_import_linkage
}

impl CalleeResolutionFacts {
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
            && self.by_direct_addr.is_empty()
            && self.by_callsite.is_empty()
            && self.table_targets.is_empty()
    }

    /// The functions the indirect call at `callsite` can reach, where a table states them.
    pub fn targets_for_callsite(&self, callsite: InstId) -> Option<&[u64]> {
        self.table_targets.get(callsite).map(|targets| &targets[..])
    }

    pub fn from_direct_call_targets<I>(targets: I, ctx: &CalleeIdentityContext<'_>) -> Self
    where
        I: IntoIterator<Item = (InstId, u64)>,
    {
        let mut facts = Self::default();
        facts.index_context(ctx);
        for (callsite, addr) in targets {
            let _ = facts.insert_direct_callsite(callsite, addr, ctx);
        }
        facts
    }

    pub fn from_context(ctx: &CalleeIdentityContext<'_>) -> Self {
        let mut facts = Self::default();
        facts.index_context(ctx);
        facts
    }

    pub fn index_context(&mut self, ctx: &CalleeIdentityContext<'_>) {
        let mut direct_addrs = BTreeSet::new();
        direct_addrs.extend(ctx.callee_facts.keys().copied());
        direct_addrs.extend(ctx.function_names.keys().copied());
        direct_addrs.extend(ctx.symbols.keys().copied());
        for addr in direct_addrs {
            self.ensure_direct_identity(addr, ctx);
        }
    }

    pub fn insert_direct_callsite(
        &mut self,
        callsite: InstId,
        addr: u64,
        ctx: &CalleeIdentityContext<'_>,
    ) -> Option<&CalleeIdentity> {
        let key = CalleeIdentityKey::DirectAddress(addr);
        if Self::callsite_binding_conflicts(self.by_callsite.get(callsite), &key) {
            return None;
        }
        let key = self.ensure_direct_identity(addr, ctx);
        self.bind_callsite(callsite, key.clone());
        self.by_key.get(&key)
    }

    pub fn identity_for_callsite(&self, callsite: InstId) -> Option<&CalleeIdentity> {
        self.by_callsite
            .get(callsite)
            .and_then(|key| self.by_key.get(key))
    }

    pub fn identity_for_direct_addr(&self, addr: u64) -> Option<&CalleeIdentity> {
        self.by_direct_addr
            .get(&addr)
            .and_then(|key| self.by_key.get(key))
    }

    pub fn target_resolution_source_for_presence(
        has_callsite_identity: bool,
        has_prepared_direct_target_identity: bool,
    ) -> Option<CalleeTargetResolutionSource> {
        if has_callsite_identity {
            Some(CalleeTargetResolutionSource::CallsiteResolution)
        } else if has_prepared_direct_target_identity {
            Some(CalleeTargetResolutionSource::PreparedDirectTarget)
        } else {
            None
        }
    }

    fn direct_target_identity_from_request(
        request: CalleeTargetIdentityRequest<'_>,
    ) -> Option<(CalleeIdentityKey, CalleeIdentity)> {
        let addr = request.prepared_direct_target?;
        if let Some(identity) = request
            .resolution
            .and_then(|facts| facts.identity_for_direct_addr(addr))
        {
            return Some((CalleeIdentityKey::DirectAddress(addr), identity.clone()));
        }
        request.direct_target_context.map(|ctx| {
            (
                CalleeIdentityKey::DirectAddress(addr),
                CalleeIdentity::from_direct_target(addr, ctx),
            )
        })
    }

    pub fn resolve_target_identity(
        request: CalleeTargetIdentityRequest<'_>,
    ) -> Option<ResolvedCalleeIdentity> {
        let callsite_identity = request.callsite.and_then(|callsite| {
            let facts = request.resolution?;
            let key = facts.key_for_callsite(callsite)?.clone();
            let identity = facts.by_key.get(&key)?.clone();
            Some((key, identity))
        });
        let direct_target_identity = Self::direct_target_identity_from_request(request);
        let source = Self::target_resolution_source_for_presence(
            callsite_identity.is_some(),
            direct_target_identity.is_some(),
        )?;
        let (key, identity) = match source {
            CalleeTargetResolutionSource::CallsiteResolution => callsite_identity?,
            CalleeTargetResolutionSource::PreparedDirectTarget => direct_target_identity?,
        };
        Some(ResolvedCalleeIdentity {
            key,
            identity,
            source,
        })
    }

    pub fn resolve_target_policy(
        request: CalleeTargetResolutionRequest<'_>,
    ) -> Option<ResolvedCalleeTarget> {
        let resolved = Self::resolve_target_identity(request.identity)?;
        let policy = resolved
            .identity
            .target_policy_decision(request.identity.resolution, request.callee_facts);
        Some(ResolvedCalleeTarget {
            key: resolved.key,
            identity: resolved.identity,
            source: resolved.source,
            policy,
        })
    }

    pub fn key_for_callsite(&self, callsite: InstId) -> Option<&CalleeIdentityKey> {
        self.by_callsite.get(callsite)
    }

    fn ensure_direct_identity(
        &mut self,
        addr: u64,
        ctx: &CalleeIdentityContext<'_>,
    ) -> CalleeIdentityKey {
        let key = CalleeIdentityKey::DirectAddress(addr);
        if self.by_key.contains_key(&key) {
            return key;
        }

        let identity = CalleeIdentity::from_direct_target(addr, ctx);
        self.by_direct_addr.insert(addr, key.clone());
        self.by_key.insert(key.clone(), identity);
        key
    }

    fn bind_callsite(&mut self, callsite: InstId, key: CalleeIdentityKey) {
        self.by_callsite.get_or_insert_with(callsite, || key);
    }

    fn callsite_binding_conflicts(
        existing: Option<&CalleeIdentityKey>,
        key: &CalleeIdentityKey,
    ) -> bool {
        existing.is_some_and(|existing| existing != key)
    }
}

impl CalleeIdentity {
    pub fn from_name(name: &str) -> Self {
        let lower = name.trim().to_ascii_lowercase();
        let storage_kind = SSAVarNameKind::classify(&lower);
        let target_addr = parse_raw_address_name(name);
        // Linkage is a typed fact on the callee, never read off the spelling.
        let (class, classification_evidence) = classify_callee_name(storage_kind);
        let mut evidence = BTreeSet::new();
        if let Some(classification_evidence) = classification_evidence {
            evidence.insert(classification_evidence);
        }
        let raw_name = name.trim().to_string();

        Self {
            target_addr,
            raw_name: Some(raw_name.clone()),
            display_name: Some(raw_name),
            class,
            is_recursive: false,
            signature: None,
            signature_source: None,
            evidence,
        }
    }

    pub fn from_direct_target(addr: u64, ctx: &CalleeIdentityContext<'_>) -> Self {
        let mut evidence = BTreeSet::from([CalleeIdentityEvidence::DirectTarget]);
        let callee_fact = ctx.callee_facts.get(&addr);
        let fact_name = callee_fact
            .and_then(|fact| fact.name.as_deref())
            .filter(|name| !name.trim().is_empty());
        let function_name = ctx
            .function_names
            .get(&addr)
            .map(String::as_str)
            .filter(|name| !name.trim().is_empty());
        let symbol_name = ctx
            .symbols
            .get(&addr)
            .map(String::as_str)
            .filter(|name| !name.trim().is_empty());

        let (name, name_evidence) = if let Some(name) = fact_name {
            (name, CalleeIdentityEvidence::CalleeFactName)
        } else if let Some(name) = function_name {
            (name, CalleeIdentityEvidence::FunctionName)
        } else if let Some(name) = symbol_name {
            (name, CalleeIdentityEvidence::SymbolName)
        } else {
            ("", CalleeIdentityEvidence::DirectTarget)
        };

        let mut identity = if name.is_empty() {
            let display_name = r2source::unnamed_identifier(addr);
            CalleeIdentity {
                target_addr: Some(addr),
                raw_name: Some(display_name.clone()),
                display_name: Some(display_name),
                class: CalleeClass::RawAddress,
                is_recursive: false,
                signature: None,
                signature_source: None,
                evidence,
            }
        } else {
            evidence.insert(name_evidence);
            let mut identity = Self::from_name(name);
            identity.target_addr = Some(addr);
            identity.evidence.extend(evidence);
            identity
        };

        if symbol_name.is_some() && identity.class == CalleeClass::Unknown {
            identity.class = CalleeClass::ExternalSymbol;
        }
        if callee_fact.is_some_and(|fact| fact.linkage.authorizes_import_policy()) {
            identity = identity.with_import_linkage_evidence();
        } else if callee_fact.is_some_and(|fact| fact.linkage == CalleeLinkage::Internal)
            && identity.class == CalleeClass::Unknown
        {
            identity.class = CalleeClass::Internal;
            identity
                .evidence
                .insert(CalleeIdentityEvidence::InternalLinkage);
        }
        if let Some(signature) = callee_fact.and_then(|fact| fact.signature.as_ref()) {
            identity.signature = Some(signature.clone());
            identity.signature_source = Some(SignatureCertificateSource::ExternalContext);
            identity
                .evidence
                .insert(CalleeIdentityEvidence::KnownSignature);
        }
        identity
    }

    pub fn with_import_linkage_evidence(mut self) -> Self {
        self.class = CalleeClass::Imported;
        self.evidence.insert(CalleeIdentityEvidence::ImportLinkage);
        self
    }

    pub fn raw_name(&self) -> &str {
        self.raw_name.as_deref().unwrap_or("")
    }

    pub fn class(&self) -> CalleeClass {
        self.class
    }

    pub fn is_raw_storage_target(&self) -> bool {
        self.class == CalleeClass::RawAddress
            && self.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    CalleeIdentityEvidence::RawMemoryName | CalleeIdentityEvidence::RawConstantName
                )
            })
    }

    pub fn is_import_policy_authorized(&self) -> bool {
        import_policy_authorized_from_evidence(
            self.class,
            self.evidence
                .contains(&CalleeIdentityEvidence::ImportLinkage),
        )
    }

    pub fn has_known_signature(&self) -> bool {
        self.signature.is_some()
            && self
                .evidence
                .contains(&CalleeIdentityEvidence::KnownSignature)
    }

    pub fn known_signature(&self) -> Option<&FunctionType> {
        self.has_known_signature()
            .then_some(self.signature.as_ref())
            .flatten()
    }

    pub fn non_variadic_known_arity(&self) -> Option<usize> {
        self.known_signature()
            .and_then(|signature| (!signature.variadic).then_some(signature.params.len()))
    }

    pub fn target_policy_decision(
        &self,
        _callee_resolution: Option<&CalleeResolutionFacts>,
        callee_facts: &BTreeMap<u64, CalleeFact>,
    ) -> CalleeTargetPolicyDecision {
        let mut decision = CalleeTargetPolicyDecision::default();
        if self.is_import_policy_authorized() {
            decision.imported = true;
            decision
                .sources
                .insert(CalleeTargetPolicySource::ImportLinkage);
        }

        if let Some(addr) = self.modeled_target_addr(callee_facts) {
            decision.modeled = true;
            decision.modeled_addr = Some(addr);
            decision
                .sources
                .insert(CalleeTargetPolicySource::CalleeFact);
        }

        decision
    }

    pub fn modeled_target_addr(&self, callee_facts: &BTreeMap<u64, CalleeFact>) -> Option<u64> {
        if let Some(addr) = self.target_addr
            && callee_facts
                .get(&addr)
                .is_some_and(CalleeFact::authorizes_model_policy)
        {
            return Some(addr);
        }
        None
    }
}

fn classify_callee_name(
    storage_kind: SSAVarNameKind,
) -> (CalleeClass, Option<CalleeIdentityEvidence>) {
    match storage_kind {
        SSAVarNameKind::Memory => (
            CalleeClass::RawAddress,
            Some(CalleeIdentityEvidence::RawMemoryName),
        ),
        SSAVarNameKind::Constant => (
            CalleeClass::RawAddress,
            Some(CalleeIdentityEvidence::RawConstantName),
        ),
        _ => (CalleeClass::Unknown, None),
    }
}

fn parse_raw_address_name(name: &str) -> Option<u64> {
    let lower = name.trim().to_ascii_lowercase();
    let kind = SSAVarNameKind::classify(&lower);
    let payload = match kind {
        SSAVarNameKind::Memory => lower.strip_prefix("ram:")?,
        SSAVarNameKind::Constant => lower.strip_prefix("const:")?,
        _ => return None,
    };
    parse_address_payload(payload)
}

fn parse_address_payload(payload: &str) -> Option<u64> {
    let value = payload.split('_').next().unwrap_or(payload);
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return u64::from_str_radix(value, 16).ok();
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_identity_context<'a>(
        function_names: &'a FxHashMap<u64, String>,
        symbols: &'a FxHashMap<u64, String>,
        callee_facts: &'a BTreeMap<u64, CalleeFact>,
    ) -> CalleeIdentityContext<'a> {
        CalleeIdentityContext {
            function_names,
            symbols,
            callee_facts,
        }
    }

    fn callee_fact_with_linkage(addr: u64, name: &str, linkage: CalleeLinkage) -> CalleeFact {
        CalleeFact {
            function_id: addr,
            name: Some(name.to_string()),
            linkage,
            signature: None,
            model_policy_evidence: BTreeSet::new(),
            direct_callees: Vec::new(),
            callsite_count: 0,
            has_unknown_calls: false,
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: crate::CalleeReturnRelation::Unknown,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        }
    }

    fn callee_fact(addr: u64, name: &str) -> CalleeFact {
        callee_fact_with_linkage(addr, name, CalleeLinkage::Unknown)
    }

    fn imported_callee_fact(addr: u64, name: &str) -> CalleeFact {
        callee_fact_with_linkage(addr, name, CalleeLinkage::Imported)
    }

    fn modeled_callee_fact(addr: u64, name: &str) -> CalleeFact {
        let mut fact = callee_fact(addr, name);
        fact.model_policy_evidence
            .insert(crate::CalleeModelPolicyEvidence::InterprocSummary);
        fact
    }

    fn test_signature() -> FunctionType {
        FunctionType {
            return_type: crate::CTypeLike::Int {
                bits: 32,
                signedness: crate::Signedness::Signed,
            },
            params: Vec::new(),
            bases: Vec::new(),
            variadic: true,
        }
    }

    fn non_variadic_signature(param_count: usize) -> FunctionType {
        FunctionType {
            return_type: crate::CTypeLike::Void,
            params: vec![
                crate::CTypeLike::Int {
                    bits: 32,
                    signedness: crate::Signedness::Signed,
                };
                param_count
            ],
            bases: vec![r2source::Basis::Declared; param_count],
            variadic: false,
        }
    }

    #[test]
    fn callee_identity_class_is_never_read_off_a_namespace_spelling() {
        let cases = [
            ("ram:401000_0", CalleeClass::RawAddress),
            ("const:0x401000", CalleeClass::RawAddress),
            ("sym.imp.printf", CalleeClass::Unknown),
            ("imp.printf", CalleeClass::Unknown),
            ("reloc.memcpy", CalleeClass::Unknown),
            ("sym.helper", CalleeClass::Unknown),
            ("fcn.401000", CalleeClass::Unknown),
            ("helper", CalleeClass::Unknown),
        ];

        for (name, class) in cases {
            let identity = CalleeIdentity::from_name(name);
            assert_eq!(identity.raw_name(), name);
            assert_eq!(identity.display_name.as_deref(), Some(name));
            assert_eq!(identity.class(), class, "{name}");
            assert_eq!(
                identity.is_raw_storage_target(),
                class == CalleeClass::RawAddress,
                "{name}",
            );
            assert!(!identity.is_import_policy_authorized(), "{name}");
        }
    }

    #[test]
    fn direct_target_identity_uses_callee_fact_before_function_and_symbol_names() {
        let function_names = FxHashMap::from_iter([(0x401000, "sym.function_name".to_string())]);
        let symbols = FxHashMap::from_iter([(0x401000, "sym.symbol_name".to_string())]);
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x401000, &ctx);

        assert_eq!(identity.target_addr, Some(0x401000));
        assert_eq!(identity.display_name.as_deref(), Some("sym.imp.printf"));
        assert_eq!(identity.class(), CalleeClass::Imported);
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::DirectTarget)
        );
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::CalleeFactName)
        );
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::ImportLinkage)
        );
        assert!(identity.is_import_policy_authorized());
    }

    #[test]
    fn import_looking_callee_fact_name_without_linkage_is_not_an_import() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::from([(0x401020, callee_fact(0x401020, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x401020, &ctx);

        assert_eq!(identity.class(), CalleeClass::Unknown);
        assert!(!identity.is_import_policy_authorized());
        assert!(
            !identity
                .evidence
                .contains(&CalleeIdentityEvidence::ImportLinkage),
            "unknown linkage must not mint import-linkage evidence",
        );
    }

    #[test]
    fn explicit_import_linkage_authorizes_policy_without_import_name_shape() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::from([(0x401028, imported_callee_fact(0x401028, "printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x401028, &ctx);

        assert_eq!(identity.display_name.as_deref(), Some("printf"));
        assert!(identity.is_import_policy_authorized());
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::ImportLinkage),
            "explicit linkage must mint import-linkage evidence independent of name shape",
        );
    }

    #[test]
    fn internal_linkage_classifies_plain_callee_fact_as_internal() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::from([(
            0x40102c,
            callee_fact_with_linkage(0x40102c, "helper", CalleeLinkage::Internal),
        )]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x40102c, &ctx);

        assert_eq!(identity.class(), CalleeClass::Internal);
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::InternalLinkage)
        );
        assert!(!identity.is_import_policy_authorized());
    }

    #[test]
    fn unknown_linkage_plain_callee_fact_remains_unknown() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::from([(0x40102d, callee_fact(0x40102d, "helper"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x40102d, &ctx);

        assert_eq!(identity.class(), CalleeClass::Unknown);
        assert!(!identity.is_import_policy_authorized());
    }

    #[test]
    fn symbol_names_promote_only_unknown_callee_identities_to_external() {
        let function_names = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let external_symbols = FxHashMap::from_iter([(0x40102e, "external_helper".to_string())]);
        let external_ctx =
            empty_identity_context(&function_names, &external_symbols, &callee_facts);

        let external = CalleeIdentity::from_direct_target(0x40102e, &external_ctx);

        assert_eq!(external.class(), CalleeClass::ExternalSymbol);
    }

    #[test]
    fn direct_target_identity_prefers_typed_callee_fact_signature() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let mut fact = callee_fact(0x401000, "sym.imp.printf");
        fact.signature = Some(non_variadic_signature(2));
        let callee_facts = BTreeMap::from([(0x401000, fact)]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x401000, &ctx);

        assert_eq!(
            identity
                .known_signature()
                .map(|signature| signature.params.len()),
            Some(2)
        );
        assert_eq!(
            identity.signature_source,
            Some(SignatureCertificateSource::ExternalContext)
        );
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::KnownSignature)
        );
        assert!(
            !identity.is_import_policy_authorized(),
            "typed callee signatures do not imply imported-call policy"
        );
    }

    #[test]
    fn known_signature_predicate_requires_signature_and_evidence() {
        let mut signature_without_evidence = CalleeIdentity::from_name("printf");
        signature_without_evidence.signature = Some(test_signature());
        assert!(!signature_without_evidence.has_known_signature());
        assert!(signature_without_evidence.known_signature().is_none());
        assert_eq!(signature_without_evidence.non_variadic_known_arity(), None);

        let mut evidence_without_signature = CalleeIdentity::from_name("printf");
        evidence_without_signature
            .evidence
            .insert(CalleeIdentityEvidence::KnownSignature);
        assert!(!evidence_without_signature.has_known_signature());
        assert!(evidence_without_signature.known_signature().is_none());

        let mut complete = CalleeIdentity::from_name("printf");
        complete.signature = Some(test_signature());
        complete
            .evidence
            .insert(CalleeIdentityEvidence::KnownSignature);
        assert!(complete.has_known_signature());
        assert!(complete.known_signature().is_some());
        assert_eq!(complete.non_variadic_known_arity(), None);

        let mut non_variadic = CalleeIdentity::from_name("strcmp");
        non_variadic.signature = Some(non_variadic_signature(2));
        non_variadic
            .evidence
            .insert(CalleeIdentityEvidence::KnownSignature);
        assert_eq!(non_variadic.non_variadic_known_arity(), Some(2));
    }

    #[test]
    fn callee_target_policy_does_not_import_from_name_hint_alone() {
        let identity = CalleeIdentity::from_name("sym.imp.printf");
        let callee_facts = BTreeMap::new();

        let decision = identity.target_policy_decision(None, &callee_facts);

        assert!(!decision.imported);
        assert!(!decision.modeled);
        assert!(
            !decision.imported_or_modeled(),
            "import-looking names are hints until typed linkage or modeled evidence exists",
        );
    }

    #[test]
    fn callee_target_policy_authorizes_import_from_typed_linkage() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let identity = CalleeIdentity::from_direct_target(0x401000, &ctx);

        let decision = identity.target_policy_decision(None, &callee_facts);

        assert!(decision.imported);
        assert!(!decision.modeled);
        assert_eq!(decision.modeled_addr, None);
        assert!(decision.imported_or_modeled());
        assert!(
            decision
                .sources
                .contains(&CalleeTargetPolicySource::ImportLinkage)
        );
        assert!(
            !decision
                .sources
                .contains(&CalleeTargetPolicySource::CalleeFact),
            "typed import linkage is import-policy evidence, not model-policy evidence"
        );
    }

    #[test]
    fn callee_target_policy_does_not_model_from_summary_helper_name_without_resolution() {
        let identity = CalleeIdentity::from_name("helper.summary");
        let callee_facts = BTreeMap::new();

        let decision = identity.target_policy_decision(None, &callee_facts);

        assert!(!decision.imported);
        assert!(
            !decision.modeled,
            "summary helper names must not authorize modeled policy without typed resolution"
        );
        assert_eq!(decision.modeled_addr, None);
        assert!(!decision.imported_or_modeled());
        assert!(decision.sources.is_empty());
    }

    #[test]
    fn callee_target_policy_does_not_model_from_callee_fact_presence_without_evidence() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::from([(0x401000, callee_fact(0x401000, "sym.memcpy"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let resolution = CalleeResolutionFacts::from_context(&ctx);
        let identity = CalleeIdentity::from_name("memcpy");

        let decision = identity.target_policy_decision(Some(&resolution), &callee_facts);

        assert!(!decision.imported);
        assert!(!decision.modeled);
        assert_eq!(decision.modeled_addr, None);
        assert!(decision.sources.is_empty());
    }

    #[test]
    fn callee_target_policy_models_from_explicit_callee_fact_evidence_through_resolution() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, modeled_callee_fact(0x401000, "sym.memcpy"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let identity = CalleeIdentity::from_direct_target(0x401000, &ctx);

        let decision = identity.target_policy_decision(None, &callee_facts);

        assert!(!decision.imported);
        assert!(decision.modeled);
        assert_eq!(decision.modeled_addr, Some(0x401000));
        assert_eq!(
            decision.sources,
            BTreeSet::from([CalleeTargetPolicySource::CalleeFact]),
        );
    }

    #[test]
    fn callee_resolution_source_precedence_truth_table_is_exhaustive() {
        for mask in 0u8..4 {
            let has_callsite_identity = mask & 0b01 != 0;
            let has_prepared_direct_target = mask & 0b10 != 0;

            let expected = if has_callsite_identity {
                Some(CalleeTargetResolutionSource::CallsiteResolution)
            } else if has_prepared_direct_target {
                Some(CalleeTargetResolutionSource::PreparedDirectTarget)
            } else {
                None
            };

            assert_eq!(
                CalleeResolutionFacts::target_resolution_source_for_presence(
                    has_callsite_identity,
                    has_prepared_direct_target,
                ),
                expected,
                "wrong source precedence for mask {mask:02b}",
            );
        }
    }

    #[test]
    fn callee_resolution_policy_prefers_callsite_identity_over_other_typed_inputs() {
        let function_names = FxHashMap::from_iter([(0x402000, "sym.local".to_string())]);
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let callsite = r2ssa::InstId(0x10);
        let resolution =
            CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x402000)], &ctx);

        let resolved =
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: Some(&resolution),
                    callsite: Some(callsite),
                    prepared_direct_target: Some(0x401000),
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .expect("callsite identity should resolve");

        assert_eq!(
            resolved.source,
            CalleeTargetResolutionSource::CallsiteResolution,
        );
        assert_eq!(resolved.identity.target_addr, Some(0x402000));
        assert_eq!(resolved.policy.arg_policy(), CalleeCallArgPolicy::Standard);
        assert!(!resolved.policy.imported);
    }

    #[test]
    fn callee_resolution_policy_keeps_imported_callsite_over_prepared_direct_target() {
        let function_names = FxHashMap::from_iter([(0x402000, "sym.local".to_string())]);
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let callsite = r2ssa::InstId(0x10);
        let resolution =
            CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x401000)], &ctx);

        let resolved =
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: Some(&resolution),
                    callsite: Some(callsite),
                    prepared_direct_target: Some(0x402000),
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .expect("callsite identity should resolve");

        assert_eq!(
            resolved.source,
            CalleeTargetResolutionSource::CallsiteResolution,
        );
        assert_eq!(resolved.identity.target_addr, Some(0x401000));
        assert!(resolved.policy.imported);
        assert_eq!(
            resolved.policy.arg_policy(),
            CalleeCallArgPolicy::ImportedLike
        );
    }

    #[test]
    fn callee_resolution_policy_uses_prepared_direct_target_without_display_fallback() {
        let function_names = FxHashMap::from_iter([(0x402000, "sym.local".to_string())]);
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let resolved =
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: None,
                    callsite: None,
                    prepared_direct_target: Some(0x401000),
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .expect("prepared direct target should resolve");

        assert_eq!(
            resolved.source,
            CalleeTargetResolutionSource::PreparedDirectTarget,
        );
        assert_eq!(resolved.identity.target_addr, Some(0x401000));
        assert!(resolved.policy.imported);
    }

    #[test]
    fn callee_resolution_policy_fails_closed_after_typed_sources_fail() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        assert!(
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: None,
                    callsite: None,
                    prepared_direct_target: None,
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .is_none(),
            "rendered/display identities must not be an authoritative fallback",
        );
    }

    #[test]
    fn callee_resolution_policy_does_not_authorize_plain_rendered_names_for_unresolved_sites() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let unresolved_site = r2ssa::InstId(0x10);
        assert!(
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: None,
                    callsite: Some(unresolved_site),
                    prepared_direct_target: None,
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .is_none(),
            "a rendered name must not resolve an unresolved callsite",
        );
    }

    #[test]
    fn callee_resolution_policy_allows_explicit_prepared_direct_targets() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let resolved =
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: None,
                    callsite: None,
                    prepared_direct_target: Some(0x401000),
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .expect("raw rendered target should resolve");

        assert_eq!(
            resolved.source,
            CalleeTargetResolutionSource::PreparedDirectTarget,
        );
        assert!(resolved.policy.imported);
        assert_eq!(
            resolved.policy.arg_policy(),
            CalleeCallArgPolicy::ImportedLike,
        );
    }

    #[test]
    fn callee_resolution_policy_unresolved_callsite_does_not_inherit_other_site_policy() {
        let function_names = FxHashMap::from_iter([(0x402000, "sym.local".to_string())]);
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, imported_callee_fact(0x401000, "sym.imp.printf"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let imported_site = r2ssa::InstId(0x10);
        let unresolved_site = r2ssa::InstId(0x20);
        let resolution =
            CalleeResolutionFacts::from_direct_call_targets([(imported_site, 0x401000)], &ctx);

        assert!(
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: Some(&resolution),
                    callsite: Some(unresolved_site),
                    prepared_direct_target: None,
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .is_none(),
            "unresolved callsites must not inherit policy from unrelated typed or rendered facts",
        );
    }

    #[test]
    fn callee_resolution_policy_preserves_modeled_callee_fact_through_callsite() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts =
            BTreeMap::from([(0x401000, modeled_callee_fact(0x401000, "sym.memcpy"))]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let callsite = r2ssa::InstId(0x10);
        let resolution =
            CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x401000)], &ctx);

        let resolved =
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: Some(&resolution),
                    callsite: Some(callsite),
                    prepared_direct_target: None,
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .expect("callsite identity should resolve");

        assert_eq!(
            resolved.source,
            CalleeTargetResolutionSource::CallsiteResolution,
        );
        assert!(resolved.policy.modeled);
        assert_eq!(resolved.policy.modeled_addr, Some(0x401000));
        assert!(
            resolved
                .policy
                .sources
                .contains(&CalleeTargetPolicySource::CalleeFact)
        );
    }

    #[test]
    fn callee_resolution_policy_returns_none_without_any_identity_source() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        assert!(
            CalleeResolutionFacts::resolve_target_policy(CalleeTargetResolutionRequest {
                identity: CalleeTargetIdentityRequest {
                    resolution: None,
                    callsite: None,
                    prepared_direct_target: None,
                    direct_target_context: Some(&ctx),
                },
                callee_facts: &callee_facts,
            })
            .is_none()
        );
    }

    #[test]
    fn direct_target_identity_without_names_remains_address_keyed() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);

        let identity = CalleeIdentity::from_direct_target(0x401050, &ctx);

        assert_eq!(identity.target_addr, Some(0x401050));
        assert_eq!(identity.display_name.as_deref(), Some("fcn_401050"));
        assert!(
            identity
                .evidence
                .contains(&CalleeIdentityEvidence::DirectTarget)
        );
    }

    #[test]
    fn callee_resolution_facts_index_direct_call_targets_deterministically() {
        let function_names = FxHashMap::from_iter([(0x401000, "sym.function_name".to_string())]);
        let symbols = FxHashMap::from_iter([(0x401000, "sym.symbol_name".to_string())]);
        let mut fact = imported_callee_fact(0x401000, "sym.imp.printf");
        fact.signature = Some(non_variadic_signature(2));
        let callee_facts = BTreeMap::from([(0x401000, fact)]);
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let callsite = r2ssa::InstId(0x402004);

        let facts = CalleeResolutionFacts::from_direct_call_targets([(callsite, 0x401000)], &ctx);

        assert_eq!(
            facts.key_for_callsite(callsite),
            Some(&CalleeIdentityKey::DirectAddress(0x401000))
        );
        let by_site = facts
            .identity_for_callsite(callsite)
            .expect("callsite identity should be indexed");
        assert_eq!(by_site.display_name.as_deref(), Some("sym.imp.printf"));
        assert_eq!(by_site.non_variadic_known_arity(), Some(2));
        assert_eq!(by_site.class(), CalleeClass::Imported);
        assert!(by_site.is_import_policy_authorized());

        let by_addr = facts
            .identity_for_direct_addr(0x401000)
            .expect("direct address identity should be indexed");
        assert_eq!(by_addr, by_site);
    }

    #[test]
    fn callee_resolution_facts_reject_conflicting_callsite_owner() {
        let function_names = FxHashMap::default();
        let symbols = FxHashMap::default();
        let callee_facts = BTreeMap::new();
        let ctx = empty_identity_context(&function_names, &symbols, &callee_facts);
        let callsite = r2ssa::InstId(0x402004);
        let mut facts = CalleeResolutionFacts::default();

        assert!(
            facts
                .insert_direct_callsite(callsite, 0x401000, &ctx)
                .is_some()
        );
        assert!(
            facts
                .insert_direct_callsite(callsite, 0x401000, &ctx)
                .is_some()
        );
        assert!(
            facts
                .insert_direct_callsite(callsite, 0x401010, &ctx)
                .is_none()
        );

        assert_eq!(
            facts.key_for_callsite(callsite),
            Some(&CalleeIdentityKey::DirectAddress(0x401000))
        );
        assert!(facts.identity_for_direct_addr(0x401010).is_none());
        assert_eq!(
            facts
                .identity_for_callsite(callsite)
                .and_then(|identity| identity.target_addr),
            Some(0x401000)
        );
    }

    #[test]
    fn callee_identity_predicates_require_matching_evidence() {
        let base = CalleeIdentity {
            target_addr: None,
            raw_name: None,
            display_name: None,
            class: CalleeClass::RawAddress,
            is_recursive: false,
            signature: None,
            signature_source: None,
            evidence: BTreeSet::new(),
        };

        assert!(!base.is_raw_storage_target());

        let mut imported_without_evidence = base.clone();
        imported_without_evidence.class = CalleeClass::Imported;
        assert!(!imported_without_evidence.is_import_policy_authorized());

        let mut raw_with_evidence = base;
        raw_with_evidence
            .evidence
            .insert(CalleeIdentityEvidence::RawMemoryName);
        assert!(raw_with_evidence.is_raw_storage_target());

        let import_policy_authorized = imported_without_evidence.with_import_linkage_evidence();
        assert!(import_policy_authorized.is_import_policy_authorized());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn pick_name_kind(tag: u8) -> SSAVarNameKind {
        match tag % 11 {
            0 => SSAVarNameKind::RegisterAlias,
            1 => SSAVarNameKind::Temporary,
            2 => SSAVarNameKind::Constant,
            3 => SSAVarNameKind::Memory,
            4 => SSAVarNameKind::AddressSpace,
            5 => SSAVarNameKind::Symbol,
            6 => SSAVarNameKind::Object,
            7 => SSAVarNameKind::Data,
            8 => SSAVarNameKind::Got,
            9 => SSAVarNameKind::Frame,
            _ => SSAVarNameKind::Ordinary,
        }
    }

    fn pick_callee_class(tag: u8) -> CalleeClass {
        match tag % 6 {
            0 => CalleeClass::Internal,
            1 => CalleeClass::Imported,
            2 => CalleeClass::ExternalSymbol,
            3 => CalleeClass::RawAddress,
            4 => CalleeClass::Indirect,
            _ => CalleeClass::Unknown,
        }
    }

    fn pick_callee_linkage(tag: u8) -> CalleeLinkage {
        match tag % 3 {
            0 => CalleeLinkage::Unknown,
            1 => CalleeLinkage::Internal,
            _ => CalleeLinkage::Imported,
        }
    }

    #[kani::proof]
    fn callee_name_classification_reads_only_storage_kind() {
        let storage_kind = pick_name_kind(kani::any());

        let (class, evidence) = classify_callee_name(storage_kind);

        match storage_kind {
            SSAVarNameKind::Memory => {
                assert_eq!(class, CalleeClass::RawAddress);
                assert_eq!(evidence, Some(CalleeIdentityEvidence::RawMemoryName));
            }
            SSAVarNameKind::Constant => {
                assert_eq!(class, CalleeClass::RawAddress);
                assert_eq!(evidence, Some(CalleeIdentityEvidence::RawConstantName));
            }
            _ => {
                assert_eq!(class, CalleeClass::Unknown);
                assert_eq!(evidence, None);
            }
        }
    }

    #[kani::proof]
    fn callee_identity_is_its_target_address_alone() {
        let a = u64::from(kani::any::<u16>());
        let b = u64::from(kani::any::<u16>());
        let bound = CalleeIdentityKey::DirectAddress(a);

        assert_eq!(
            CalleeResolutionFacts::callsite_binding_conflicts(
                Some(&bound),
                &CalleeIdentityKey::DirectAddress(b),
            ),
            a != b,
        );
    }

    #[kani::proof]
    fn callee_resolution_callsite_binding_is_fail_closed() {
        let addr_a = u64::from(kani::any::<u16>());
        let addr_b = u64::from(kani::any::<u16>()) + 0x1_0000;
        let key_a = CalleeIdentityKey::DirectAddress(addr_a);
        let key_a_repeat = CalleeIdentityKey::DirectAddress(addr_a);
        let key_b = CalleeIdentityKey::DirectAddress(addr_b);

        assert!(!CalleeResolutionFacts::callsite_binding_conflicts(
            None, &key_a,
        ));
        assert!(!CalleeResolutionFacts::callsite_binding_conflicts(
            Some(&key_a),
            &key_a_repeat,
        ));
        assert!(CalleeResolutionFacts::callsite_binding_conflicts(
            Some(&key_a),
            &key_b,
        ));
    }

    #[kani::proof]
    fn imported_name_hint_alone_does_not_authorize_import_policy() {
        let class = pick_callee_class(kani::any());
        let has_import_name_hint: bool = kani::any();
        let has_import_linkage: bool = kani::any();

        let authorized = import_policy_authorized_from_evidence(class, has_import_linkage);

        if !has_import_linkage {
            assert!(!authorized);
        }
        if authorized {
            assert_eq!(class, CalleeClass::Imported);
            assert!(has_import_linkage);
        }
        if has_import_name_hint && !has_import_linkage {
            assert!(!authorized);
        }
    }

    #[kani::proof]
    fn callee_linkage_is_exact_import_policy_authority() {
        let linkage = pick_callee_linkage(kani::any());

        assert_eq!(
            linkage.authorizes_import_policy(),
            linkage == CalleeLinkage::Imported,
        );
    }

    #[kani::proof]
    fn call_target_contract_arg_policy_requires_import_or_model_evidence() {
        let decision = CalleeTargetPolicyDecision {
            imported: kani::any(),
            modeled: kani::any(),
            modeled_addr: None,
            sources: BTreeSet::new(),
        };

        assert_eq!(
            decision.arg_policy(),
            if decision.imported || decision.modeled {
                CalleeCallArgPolicy::ImportedLike
            } else {
                CalleeCallArgPolicy::Standard
            },
        );
        if decision.arg_policy() == CalleeCallArgPolicy::ImportedLike {
            assert!(decision.imported || decision.modeled);
        }
    }

    #[kani::proof]
    fn modeled_policy_requires_explicit_callee_fact_evidence() {
        let evidence_count: usize = kani::any();
        let authorized = crate::facts::model_policy_authorized_from_evidence_count(evidence_count);

        assert_eq!(authorized, evidence_count > 0);
        if evidence_count == 0 {
            assert!(!authorized);
        }
    }

    #[kani::proof]
    fn call_target_contract_standard_policy_has_no_target_policy_sources() {
        let decision = CalleeTargetPolicyDecision {
            imported: false,
            modeled: false,
            modeled_addr: None,
            sources: BTreeSet::new(),
        };

        assert_eq!(decision.arg_policy(), CalleeCallArgPolicy::Standard);
        assert!(!decision.imported_or_modeled());
        assert!(decision.sources.is_empty());
    }

    #[kani::proof]
    fn callee_resolution_source_precedence_is_total() {
        let has_callsite_identity: bool = kani::any();
        let has_prepared_direct_target: bool = kani::any();

        let source = CalleeResolutionFacts::target_resolution_source_for_presence(
            has_callsite_identity,
            has_prepared_direct_target,
        );

        if has_callsite_identity {
            assert_eq!(
                source,
                Some(CalleeTargetResolutionSource::CallsiteResolution)
            );
        } else if has_prepared_direct_target {
            assert_eq!(
                source,
                Some(CalleeTargetResolutionSource::PreparedDirectTarget)
            );
        } else {
            assert_eq!(source, None);
        }
    }

    #[kani::proof]
    fn callee_resolution_source_returns_none_only_without_inputs() {
        let has_callsite_identity: bool = kani::any();
        let has_prepared_direct_target: bool = kani::any();

        let source = CalleeResolutionFacts::target_resolution_source_for_presence(
            has_callsite_identity,
            has_prepared_direct_target,
        );

        assert_eq!(
            source.is_none(),
            !has_callsite_identity && !has_prepared_direct_target,
        );
    }

    #[kani::proof]
    fn callee_resolution_source_never_skips_higher_priority_inputs() {
        let has_callsite_identity: bool = kani::any();
        let has_prepared_direct_target: bool = kani::any();

        let source = CalleeResolutionFacts::target_resolution_source_for_presence(
            has_callsite_identity,
            has_prepared_direct_target,
        );

        if source == Some(CalleeTargetResolutionSource::CallsiteResolution) {
            assert!(has_callsite_identity);
        }
        if source == Some(CalleeTargetResolutionSource::PreparedDirectTarget) {
            assert!(!has_callsite_identity);
            assert!(has_prepared_direct_target);
        }
    }

    #[kani::proof]
    fn callee_resolution_has_no_rendered_expression_source() {
        let has_callsite_identity: bool = kani::any();
        let has_prepared_direct_target: bool = kani::any();

        let source = CalleeResolutionFacts::target_resolution_source_for_presence(
            has_callsite_identity,
            has_prepared_direct_target,
        );

        assert!(
            matches!(
                source,
                Some(CalleeTargetResolutionSource::CallsiteResolution)
                    | Some(CalleeTargetResolutionSource::PreparedDirectTarget)
                    | None
            ),
            "authoritative callee resolution must stay limited to typed sources",
        );
    }
}
