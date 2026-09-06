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
    Types,
    SymbolicQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnginePlan {
    FastLocal,
    PreparedOnly,
    BoundedType,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineTypeRouteKind {
    FullWriteback,
    BoundedCfg,
    SemanticFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineTypeRouteDecision {
    pub request: EngineRequestKind,
    pub plan: EnginePlan,
    pub kind: EngineTypeRouteKind,
    pub prefer_bounded_type_plan: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineTypedRouteDecision {
    Decompile(Box<EngineRouteDecision>),
    Types(EngineTypeRouteDecision),
}

impl EngineTypedRouteDecision {
    pub fn request(&self) -> EngineRequestKind {
        match self {
            Self::Decompile(decision) => decision.request,
            Self::Types(decision) => decision.request,
        }
    }

    pub fn plan(&self) -> EnginePlan {
        match self {
            Self::Decompile(decision) => decision.plan,
            Self::Types(decision) => decision.plan,
        }
    }

    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Decompile(decision) => decision.route.reason.clone(),
            Self::Types(decision) => decision.reason.clone(),
        }
    }

    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Decompile(decision) => decision.route.fallback_comment.clone(),
            Self::Types(_) => None,
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

    pub fn types(decision: EngineTypeRouteDecision) -> Self {
        Self::new(EngineTypedRouteDecision::Types(decision))
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

pub fn should_guard_program_orchestrator_decompile(block_count: usize, op_count: usize) -> bool {
    block_count > 4 || op_count > 96
}

pub fn select_engine_plan(
    request: EngineRequestKind,
    route: Option<&r2types::DecompileRouteFacts>,
    _function_facts: Option<&FunctionFacts>,
) -> EnginePlan {
    match request {
        EngineRequestKind::Types => EnginePlan::PreparedOnly,
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

pub fn plan_type_request(
    function_facts: &FunctionFacts,
    cfg_summary: &CFGRiskSummary,
    caller_prefers_bounded_type_plan: bool,
) -> EngineRequestPlan {
    EngineRequestPlan::types(type_route_decision(
        function_facts,
        cfg_summary,
        caller_prefers_bounded_type_plan,
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

pub fn cfg_guard_reason_from_summary(summary: &CFGRiskSummary) -> Option<String> {
    if summary.loop_count > 8 || summary.back_edge_count > 16 {
        return Some(format!(
            "complex loop graph (loops={}, back_edges={})",
            summary.loop_count, summary.back_edge_count
        ));
    }

    if summary.loop_count > 0 && summary.block_count >= 32 && summary.max_switch_cases >= 32 {
        return Some(format!(
            "dense switch in looped CFG (blocks={}, loops={}, max_switch_cases={})",
            summary.block_count, summary.loop_count, summary.max_switch_cases
        ));
    }

    if summary.loop_count > 4 && summary.block_count >= 96 && summary.max_switch_cases >= 32 {
        return Some(format!(
            "large dense switch in looped CFG (blocks={}, loops={}, max_switch_cases={})",
            summary.block_count, summary.loop_count, summary.max_switch_cases
        ));
    }

    None
}

pub fn type_cfg_prefers_bounded_plan(summary: &CFGRiskSummary) -> bool {
    if cfg_guard_reason_from_summary(summary).is_some() {
        return true;
    }
    summary.block_count >= 200
        || (summary.block_count >= 96
            && (summary.loop_count > 0
                || summary.back_edge_count > 0
                || summary.max_switch_cases >= 32))
}

pub fn type_cfg_forces_bounded_plan(summary: &CFGRiskSummary) -> bool {
    cfg_guard_reason_from_summary(summary).is_some()
}

pub fn type_cfg_allows_semantic_plan(summary: &CFGRiskSummary) -> bool {
    summary.block_count <= 96 && summary.loop_count <= 4 && summary.back_edge_count <= 8
}

pub fn type_cfg_bounded_reason(summary: &CFGRiskSummary) -> String {
    cfg_guard_reason_from_summary(summary).unwrap_or_else(|| {
        format!(
            "bounded type plan for large CFG (blocks={}, loops={}, back_edges={}, max_switch_cases={})",
            summary.block_count, summary.loop_count, summary.back_edge_count, summary.max_switch_cases
        )
    })
}

pub fn type_route_decision(
    function_facts: &FunctionFacts,
    cfg_summary: &CFGRiskSummary,
    caller_prefers_bounded_type_plan: bool,
) -> EngineTypeRouteDecision {
    let prefer_cfg_bounded = (type_cfg_forces_bounded_plan(cfg_summary)
        && !type_cfg_allows_semantic_plan(cfg_summary))
        || (caller_prefers_bounded_type_plan && type_cfg_prefers_bounded_plan(cfg_summary));
    if prefer_cfg_bounded {
        return EngineTypeRouteDecision {
            request: EngineRequestKind::Types,
            plan: EnginePlan::BoundedType,
            kind: EngineTypeRouteKind::BoundedCfg,
            prefer_bounded_type_plan: true,
            reason: Some(type_cfg_bounded_reason(cfg_summary)),
        };
    }

    EngineTypeRouteDecision {
        request: EngineRequestKind::Types,
        plan: select_engine_plan(EngineRequestKind::Types, None, Some(function_facts)),
        kind: EngineTypeRouteKind::FullWriteback,
        prefer_bounded_type_plan: false,
        reason: None,
    }
}

pub fn should_use_prepared_semantic_view(
    prepared: Option<&SsaArtifact>,
    function_facts: &FunctionFacts,
) -> bool {
    let _ = function_facts;
    prepared.is_some()
}
