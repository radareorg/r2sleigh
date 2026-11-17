use r2ssa::{CFGRiskSummary, SsaArtifact};
use r2types::FunctionFacts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineRequestKind {
    Decompile,
    SymbolicQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnginePlan {
    FastLocal,
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

/// The machines an equivalence target grades, by family, width and byte order (ROADMAP D32):
/// `pdd` renders these alone, and every other refuses with that reason.
const GRADED: [(&str, u32, r2abi::statement::Endian); 2] = [
    ("x86", 64, r2abi::statement::Endian::Little),
    ("arm", 64, r2abi::statement::Endian::Little),
];

/// Whether `pdd` renders this architecture, or the record of why it does not. O(1).
pub(crate) fn admitted(arch: &r2abi::statement::Arch) -> Result<(), crate::native::NativeRefusal> {
    let family = r2abi::family(&arch.name);
    let graded = (GRADED.iter()).any(|&(graded, bits, endian)| {
        family == Some(graded) && arch.bits == bits && arch.endian == endian
    });
    match graded {
        true => Ok(()),
        false => Err(crate::native::NativeRefusal::Unadmitted {
            architecture: arch.name.clone(),
            bits: arch.bits,
            big_endian: arch.endian == r2abi::statement::Endian::Big,
        }),
    }
}

#[cfg(test)]
mod admission {
    use r2abi::statement::{Arch, Endian};

    fn admitted(name: &str, bits: u32, endian: Endian) -> Result<(), String> {
        let arch = Arch {
            name: name.to_owned(),
            bits,
            endian,
            instructions: None,
        };
        super::admitted(&arch).map_err(|refusal| {
            assert_eq!(refusal.kind(), "architecture");
            refusal.to_string()
        })
    }

    #[test]
    fn only_the_graded_machines_are_rendered() {
        assert_eq!(admitted("x86-64", 64, Endian::Little), Ok(()));
        assert_eq!(admitted("AArch64", 64, Endian::Little), Ok(()));
        // No equivalence target runs these: i386, x32, ARM32, big-endian AArch64, RISC-V 64.
        for (name, bits, endian) in [
            ("x86", 32, Endian::Little),
            ("x86-64", 32, Endian::Little),
            ("ARM", 32, Endian::Little),
            ("AArch64", 64, Endian::Big),
            ("riscv64", 64, Endian::Little),
        ] {
            assert!(admitted(name, bits, endian).is_err(), "{name} {bits}");
        }
        assert_eq!(
            admitted("riscv64", 64, Endian::Little),
            Err("no equivalence target grades riscv64 64-bit C, so none is rendered".to_owned())
        );
    }
}
