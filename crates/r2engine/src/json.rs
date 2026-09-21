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
