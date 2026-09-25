use r2ssa::{CFGRiskSummary, SsaArtifact};
use r2types::FunctionFacts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngineFunctionIdentity {
    pub function_addr: u64,
    pub canonical_name: String,
    pub display_name: String,
    pub aliases: Vec<String>,
}

/// The plain name behind a radare2 flag.
///
/// A flag carries where radare2 learned the name (`sym.`, `dbg.`, `fcn.`,
/// `sub.`) and the compiler carries what it did to the function (`.isra.0`,
/// `.constprop.1`, `.part.3`, `.cold`, `.llvm.4`). Neither is part of the
/// name a signature database or a header knows, so an alias for the plain
/// form is kept beside the flag.
///
/// This lived in the symbolic crate, where it was used to match worker roles
/// by name. It is a string rule about radare2's naming, not a symbolic fact,
/// and it is the only thing that crate's deletion would otherwise have taken.
fn plain_function_name(name: &str) -> Option<String> {
    let name = name
        .trim()
        .trim_start_matches("sym.")
        .trim_start_matches("dbg.")
        .trim_start_matches("fcn.")
        .trim_start_matches("sub.")
        .to_ascii_lowercase();
    let mut current = name.as_str();
    loop {
        if let Some(stripped) = current.strip_suffix(".cold")
            && !stripped.is_empty()
        {
            current = stripped;
            continue;
        }
        let mut stripped_any = false;
        for marker in [".isra.", ".constprop.", ".part.", ".llvm."] {
            let Some((prefix, suffix)) = current.rsplit_once(marker) else {
                continue;
            };
            if !prefix.is_empty()
                && !suffix.is_empty()
                && suffix.bytes().all(|b| b.is_ascii_digit())
            {
                current = prefix;
                stripped_any = true;
                break;
            }
        }
        if !stripped_any {
            break;
        }
    }
    (!current.is_empty()).then(|| current.to_string())
}

impl EngineFunctionIdentity {
    pub fn new(function_addr: u64, canonical_name: &str, display_name: &str) -> Self {
        Self::with_aliases(
            function_addr,
            canonical_name,
            display_name,
            std::iter::empty::<&str>(),
        )
    }

    pub fn with_aliases<'a>(
        function_addr: u64,
        canonical_name: &str,
        display_name: &str,
        aliases: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut identity = Self {
            function_addr,
            canonical_name: canonical_name.to_string(),
            display_name: display_name.to_string(),
            aliases: Vec::new(),
        };
        identity.push_alias(canonical_name);
        identity.push_alias(display_name);
        for alias in aliases {
            identity.push_alias(alias);
        }
        identity
    }

    pub fn from_name(function_addr: u64, name: &str) -> Self {
        Self::new(function_addr, name, name)
    }

    pub fn push_alias(&mut self, alias: &str) {
        let alias = alias.trim();
        if alias.is_empty() {
            return;
        }
        if !self.aliases.iter().any(|existing| existing == alias) {
            self.aliases.push(alias.to_string());
        }
        if let Some(plain) = plain_function_name(alias)
            && !self.aliases.iter().any(|existing| existing == &plain)
        {
            self.aliases.push(plain);
        }
    }

    pub fn name_candidates(&self) -> impl Iterator<Item = &str> {
        self.aliases.iter().map(String::as_str)
    }

    pub fn primary_name(&self) -> &str {
        if !self.display_name.trim().is_empty() {
            &self.display_name
        } else {
            &self.canonical_name
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineRequestKind {
    Decompile,
    SymbolicQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnginePlan {
    FastLocal,
    SemanticSummary,
    SemanticStructured,
    ReplayValidated,
    RefuseWithEvidence,
}

fn provisional_decompile_route(
    kind: r2types::DecompileRouteKind,
    reason: Option<String>,
    fallback_comment: Option<String>,
) -> r2types::DecompileRouteFacts {
    r2types::DecompileRouteFacts {
        kind,
        reason,
        fallback_comment,
        use_prepared_semantic_view: matches!(kind, r2types::DecompileRouteKind::Standard),
    }
}

#[derive(Debug, Clone, Default)]
pub struct EngineDiagnostics {
    pub plan: Option<EnginePlan>,
    pub route_reason: Option<String>,
    pub warnings: Vec<String>,
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRouteDecision {
    pub request: EngineRequestKind,
    pub plan: EnginePlan,
    pub route: r2types::DecompileRouteFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineTypedRouteDecision {
    Decompile(Box<EngineRouteDecision>),
}

impl EngineTypedRouteDecision {
    pub fn request(&self) -> EngineRequestKind {
        match self {
            Self::Decompile(decision) => decision.request,
        }
    }

    pub fn plan(&self) -> EnginePlan {
        match self {
            Self::Decompile(decision) => decision.plan,
        }
    }

    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Decompile(decision) => decision.route.reason.clone(),
        }
    }

    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Decompile(decision) => decision.route.fallback_comment.clone(),
        }
    }

    pub fn diagnostics(&self) -> EngineDiagnostics {
        EngineDiagnostics {
            plan: Some(self.plan()),
            route_reason: self.reason(),
            refusal: self.refusal(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRequestPlan {
    pub decision: EngineTypedRouteDecision,
}

impl EngineRequestPlan {
    pub fn new(decision: EngineTypedRouteDecision) -> Self {
        Self { decision }
    }

    pub fn decompile(decision: EngineRouteDecision) -> Self {
        Self::new(EngineTypedRouteDecision::Decompile(Box::new(decision)))
    }

    pub fn request(&self) -> EngineRequestKind {
        self.decision.request()
    }

    pub fn engine_plan(&self) -> EnginePlan {
        self.decision.plan()
    }

    pub fn diagnostics(&self) -> EngineDiagnostics {
        self.decision.diagnostics()
    }
}

pub fn select_engine_plan(
    request: EngineRequestKind,
    route: Option<&r2types::DecompileRouteFacts>,
    _function_facts: Option<&FunctionFacts>,
) -> EnginePlan {
    match request {
        EngineRequestKind::SymbolicQuery => EnginePlan::SemanticStructured,
        EngineRequestKind::Decompile => match route {
            Some(route) if route.kind == r2types::DecompileRouteKind::FallbackComment => {
                EnginePlan::RefuseWithEvidence
            }
            Some(route)
                if matches!(
                    route.kind,
                    r2types::DecompileRouteKind::VmSummary
                        | r2types::DecompileRouteKind::SummaryIslands
                        | r2types::DecompileRouteKind::LinearWorker
                ) =>
            {
                EnginePlan::SemanticSummary
            }
            Some(route) if route.kind == r2types::DecompileRouteKind::StructuredWorker => {
                EnginePlan::SemanticStructured
            }
            Some(_) | None => EnginePlan::FastLocal,
        },
    }
}

#[cfg(test)]
pub(crate) fn plan_decompile_request(
    func_name: &str,
    function_facts: &FunctionFacts,
    prepared: Option<&SsaArtifact>,
    cfg_summary: &CFGRiskSummary,
) -> EngineRequestPlan {
    EngineRequestPlan::decompile(decompile_route_decision(
        func_name,
        function_facts,
        prepared,
        cfg_summary,
    ))
}

/// Every function takes the standard route.
///
/// The route used to be chosen from a symbolic artifact -- a virtual-machine
/// summary, summary islands, a structured or linear worker -- and each of
/// those choices ended in prose instead of a rendering. There is one route
/// now, and what a function renders is decided by the native certificates.
pub(crate) fn semantic_route_plan(
    _func_name: &str,
    _function_facts: &FunctionFacts,
    _cfg_summary: &CFGRiskSummary,
) -> r2types::DecompileRouteFacts {
    provisional_decompile_route(r2types::DecompileRouteKind::Standard, None, None)
}

pub(crate) fn decompile_route_decision(
    func_name: &str,
    function_facts: &FunctionFacts,
    prepared: Option<&SsaArtifact>,
    cfg_summary: &CFGRiskSummary,
) -> EngineRouteDecision {
    let route = semantic_route_plan(func_name, function_facts, cfg_summary);
    let plan = select_engine_plan(
        EngineRequestKind::Decompile,
        Some(&route),
        Some(function_facts),
    );
    let mut route = route;
    route.use_prepared_semantic_view = should_use_prepared_semantic_view(prepared, function_facts);
    EngineRouteDecision {
        request: EngineRequestKind::Decompile,
        plan,
        route,
    }
}

#[cfg(test)]
pub(crate) fn semantic_route_reason(route: &r2types::DecompileRouteFacts) -> Option<String> {
    route
        .reason
        .clone()
        .or_else(|| route.fallback_comment.clone())
}

pub fn should_use_prepared_semantic_view(
    prepared: Option<&SsaArtifact>,
    function_facts: &FunctionFacts,
) -> bool {
    let _ = function_facts;
    prepared.is_some()
}
