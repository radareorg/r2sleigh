//! JSON payloads the engine hands to its callers.
//!
//! These are a presentation layer: every type here exists to be serialized,
//! and none of them decides anything. They lived in `lib.rs` among the policy
//! and the planning, which is most of why that file reached eleven thousand
//! lines.

use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineInterprocSummaryJson {
    pub callsite_count: usize,
    pub iterations: usize,
    pub max_iterations: usize,
    pub converged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<r2ssa::FunctionSemanticSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EngineInterprocSummaryJsonInput<'a> {
    pub callsite_count: usize,
    pub iterations: usize,
    pub max_iterations: usize,
    pub converged: bool,
    pub summary: Option<&'a r2ssa::FunctionSemanticSummary>,
    pub scope_report: Option<&'a serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginePhaseTimingJson {
    pub phase: EnginePhase,
    pub status: EnginePhaseStatus,
    pub elapsed_us: u64,
}

pub(crate) fn interproc_summary_json(
    input: EngineInterprocSummaryJsonInput<'_>,
) -> EngineInterprocSummaryJson {
    let iterations = input.iterations.max(1);
    EngineInterprocSummaryJson {
        callsite_count: input.callsite_count,
        iterations,
        max_iterations: input.max_iterations.max(iterations),
        converged: input.converged,
        summary: input.summary.cloned(),
        summary_json: input
            .summary
            .and_then(|summary| serde_json::to_string(summary).ok()),
        scope: input.scope_report.cloned(),
    }
}

/// One function rendered for a consumer that reads rather than parses.
///
/// Everything here comes from the one rendering `pdd` prints: the translation
/// unit is its text below the prelude, the lines and the residuals are what the
/// emitter counted writing it, the variables and links are its declarations,
/// and the proof is its obligation ledger. Nothing is rendered twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedFunctionJson {
    /// The program's name for the function.
    pub name: String,
    pub addr: u64,
    /// The C identifier the unit defines the function under.
    pub definition: String,
    /// The definition's header, or empty where nothing is defined.
    pub signature: String,
    /// Why the unit defines nothing, where it does not.
    pub refused: Option<RenderRefusalJson>,
    /// A translation unit that compiles on its own.
    pub code: String,
    pub proof: RenderProofJson,
    pub variables: Vec<RenderedVariableJson>,
    /// One-based lines of `code`, each with the instructions it accounts for.
    pub lines: Vec<RenderedLineJson>,
    /// Every name outside the function `code` refers to.
    pub links: Vec<RenderedLinkJson>,
    /// Every residual in `code`, in site order.
    pub residuals: Vec<RenderedResidualJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderRefusalJson {
    pub reason: String,
}

/// What became of every obligation the function's source imposes.
///
/// The columns partition `total`: every obligation is in exactly one, so they
/// sum to it. `residual` counts the obligations a residual in the text stands
/// in for. `split` counts the obligations rendered through a variable the
/// reaching-values check split out of a shared one, so that every read sees
/// the value it stands for; they are not also counted as `rendered`.
/// `compiler_inserted` and `assumed` are the columns compiler-inserted idioms
/// and assumed arities answer into; nothing answers into them yet, so they
/// are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct RenderProofJson {
    pub total: usize,
    pub rendered: usize,
    pub elided: usize,
    pub refused: usize,
    pub residual: usize,
    pub split: usize,
    pub compiler_inserted: usize,
    pub assumed: usize,
    pub unaccounted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedVariableJson {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// `param`, `local` or `global`.
    pub kind: &'static str,
    /// `arg:<slot>`, `stack:<offset>`, `addr:<address>` or `carrier`.
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedLineJson {
    pub line: usize,
    pub addrs: Vec<u64>,
}

/// One name outside the function the code refers to.
///
/// Where the contract and the rendering part, the link map says what the
/// rendering does rather than what the contract hoped for:
/// - `addr` is `null` for `machine`: an operation the specification names is
///   held at no program address.
/// - A function the code takes the address of rather than calls is spelled as
///   a data object (`extern char main[];`), and linked as the `object` it is
///   spelled as, at the function's address.
/// - A machine operation the code calls without declaring it (the atomic and
///   guarded-access intrinsics) is not linked, and a unit that calls one does
///   not compile with implicit declarations refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedLinkJson {
    pub ident: String,
    /// `function`, `import`, `object`, or `machine` for an operation the
    /// specification names and no address in the program holds.
    pub kind: &'static str,
    pub addr: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedResidualJson {
    pub site: u32,
    /// The residual helper's type tag: `void`, `u64`, `ptr`, ...
    #[serde(rename = "type")]
    pub ty: String,
    /// Why the construct is unproven: `unproven-return`, `held-from-entry`,
    /// `unadmitted-argument`, `never-assigned`, `unrepresentable-float` or
    /// `gap`.
    pub cause: &'static str,
    /// For a gap, the kind its marker names.
    pub gap: Option<String>,
    pub line: usize,
}

impl RenderProofJson {
    fn of(ledger: Option<&r2dec::ledger::ObligationLedger>) -> Self {
        let Some(ledger) = ledger else {
            return Self::default();
        };
        let closure = ledger.close();
        let split = ledger.split_rendered();
        Self {
            total: closure.total,
            rendered: closure.rendered - split,
            split,
            elided: closure.elided,
            refused: closure.refused,
            residual: closure.gapped,
            unaccounted: closure.unattributed,
            ..Self::default()
        }
    }
}

impl RenderedFunctionJson {
    /// The rendering a response carries, under the program's name for it.
    ///
    /// `definition` is the C name the renderer gives the function, which is
    /// what a unit that defines nothing still names.
    pub(crate) fn of(
        response: &EngineDecompileResponse,
        name: &str,
        addr: u64,
        definition: String,
    ) -> Self {
        let proof = RenderProofJson::of(response.obligation_ledger.as_ref());
        let rendered = match &response.output {
            EngineRendering::Function(rendered) => rendered,
            // A listing is what the engine answers with when nothing was
            // rendered: it is the reason, and the unit is only that.
            EngineRendering::Listing(text) => {
                return Self {
                    name: name.to_owned(),
                    addr,
                    definition,
                    signature: String::new(),
                    refused: Some(RenderRefusalJson {
                        reason: Some(comment_body(text))
                            .filter(|reason| !reason.is_empty())
                            .unwrap_or_else(|| {
                                "the engine rendered nothing and stated no reason".to_owned()
                            }),
                    }),
                    code: text.clone(),
                    proof,
                    variables: Vec::new(),
                    lines: Vec::new(),
                    links: Vec::new(),
                    residuals: Vec::new(),
                };
            }
        };
        let emission = rendered.emission();
        let function = rendered.function();
        let refused = match (emission.signature(), &function.declaration_only) {
            (Some(_), _) => None,
            (None, Some(reason)) => Some(reason.clone()),
            (None, None) => Some("no definition was written".to_owned()),
        };
        Self {
            name: name.to_owned(),
            addr,
            definition: function.name.clone(),
            signature: emission.signature().unwrap_or_default().to_owned(),
            refused: refused.map(|reason| RenderRefusalJson { reason }),
            code: emission.unit().to_owned(),
            proof,
            variables: emission.variables().iter().map(variable_json).collect(),
            lines: emission
                .lines()
                .iter()
                .map(|line| RenderedLineJson {
                    line: line.line,
                    addrs: line.addrs.clone(),
                })
                .collect(),
            links: emission.links().iter().map(link_json).collect(),
            residuals: emission
                .residuals()
                .iter()
                .map(|residual| RenderedResidualJson {
                    site: residual.site,
                    ty: residual.ty.tag(),
                    cause: residual.cause.tag(),
                    gap: residual.gap.clone(),
                    line: residual.line,
                })
                .collect(),
        }
    }
}

/// One declared name, as `pddj` spells it.
fn variable_json(variable: &r2dec::report::RenderedVariable) -> RenderedVariableJson {
    use r2dec::report::{VariableKind, VariableLocation};
    RenderedVariableJson {
        name: variable.name.clone(),
        ty: variable.ty.clone(),
        kind: match variable.kind {
            VariableKind::Param => "param",
            VariableKind::Local => "local",
            VariableKind::Global => "global",
        },
        location: match variable.location {
            VariableLocation::Argument { slot } => format!("arg:{slot}"),
            VariableLocation::Frame { offset } if offset < 0 => {
                format!("stack:-{:#x}", offset.unsigned_abs())
            }
            VariableLocation::Frame { offset } => format!("stack:+{offset:#x}"),
            VariableLocation::Address(address) => format!("addr:{address:#x}"),
            VariableLocation::Carrier => "carrier".to_owned(),
        },
    }
}

/// One outside name, as `pddj` spells it.
fn link_json(link: &r2dec::report::RenderedLink) -> RenderedLinkJson {
    use r2dec::report::LinkKind;
    RenderedLinkJson {
        ident: link.ident.clone(),
        kind: match link.kind {
            LinkKind::Function => "function",
            LinkKind::Import => "import",
            LinkKind::Object => "object",
            LinkKind::Machine => "machine",
        },
        addr: link.addr,
        size: link.size,
    }
}

/// The words of a comment-only answer, without the comment's delimiters.
fn comment_body(text: &str) -> String {
    text.lines()
        .map(|line| {
            line.trim()
                .trim_start_matches("/*")
                .trim_end_matches("*/")
                .trim()
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
