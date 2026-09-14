//! The engine's policy budgets.
//!
//! Every number here bounds work rather than describing the program: how many
//! symbolic paths to explore, how large a function may be before the decompile
//! route declines it, how long a post-analysis pass may run. They are collected
//! so that the values a run is governed by can be read in one place instead of
//! found among the planning code.
//!
//! Several are not derived from anything, which is recorded as known debt in
//! the roadmap rather than hidden here.

/// Worklist steps a path listing may take.
///
/// This was 500 wall-clock milliseconds, which made the set of paths a
/// function listed depend on how busy the machine was.
pub const SYMBOLIC_PATHS_LIMIT: usize = 32;
pub const SYMBOLIC_PATHS_CALL_FREE_MAX_STATES: usize = 16;
pub const SYMBOLIC_PATHS_CALL_FREE_MAX_DEPTH: usize = 64;
pub const SYMBOLIC_PATHS_CALL_HEAVY_MAX_STATES: usize = 8;
pub const SYMBOLIC_PATHS_CALL_HEAVY_MAX_DEPTH: usize = 32;
pub const SYMBOLIC_PATHS_MAX_STEPS: u64 = 5_000;
pub const SYMBOLIC_PATHS_SOLUTION_LIMIT: usize = 4;
pub const RADARE2_ANALYSIS_DEPTH_BASIC: u32 = 1;
pub const RADARE2_ANALYSIS_DEPTH_AGGRESSIVE: u32 = 3;
/// Post-analysis time a program is allowed, per function it contains.
///
/// This replaces three whole-program constants -- two, ten and thirty seconds
/// by mode -- that were not derived from anything. Ten seconds is not a fact
/// about a program: on the DecBench bzip2recover build, 38 functions, the sweep
/// finishes in about 1.5 seconds and the budget never binds, while on bzip2,
/// 154 functions, the same ten seconds stopped the sweep after a third of the
/// program. One number cannot be both, because the work scales with the
/// function count and the number did not.
///
/// The allowance is the project's own per-function performance bar, which is
/// already agreed and stated elsewhere: a function is expected to cost under
/// 100 milliseconds net. So the budget is not a new judgement about how long is
/// too long; it is the bar the sweep is already held to, multiplied by the work
/// in front of it. A function that exceeds it is a defect to fix rather than a
/// budget to widen, and the sweep saying so is the point.
///
/// Measured against it, with the per-callback split on bzip2recover: the whole
/// sweep costs about 39ms per function -- an 11.5ms snapshot walk, a 17.6ms
/// proof, and artifact submission for the rest -- so the bar is cleared by
/// roughly a factor of two and a slower machine still finishes.
///
/// The analysis mode is deliberately not a factor. A mode decides how much work
/// each function gets, not how long a wall clock may run, and expressing the
/// same policy twice was what let the two disagree.
pub const POST_ANALYSIS_PER_FUNCTION_BUDGET_USEC: u64 = 100_000;

/// Floor for a program with no functions, so a sweep with nothing to do still
/// has time to establish that rather than refusing on a zero budget.
pub const POST_ANALYSIS_MINIMUM_BUDGET_USEC: u64 = POST_ANALYSIS_PER_FUNCTION_BUDGET_USEC;

/// Per-function budget an operator asked for instead of the derived one.
///
/// A deadline that fires is a measurement of how slow the engine is, and the
/// measurement cannot be taken when the deadline stops the thing being
/// measured. `R2SLEIGH_PER_FUNCTION_BUDGET_USEC` lets a profiling run watch a
/// function run to completion; it is read once, so a sweep cannot change
/// budget underneath itself.
fn per_function_budget_usec() -> u64 {
    static BUDGET: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(|| {
        std::env::var("R2SLEIGH_PER_FUNCTION_BUDGET_USEC")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(POST_ANALYSIS_PER_FUNCTION_BUDGET_USEC)
    })
}

/// Units of counted work a capture of this size may spend.
///
/// A wall clock answered a different question on every machine, and it was
/// scaled by the program's function count, which says nothing about the
/// request in front of it. Counted work answers the same question the clock
/// was standing in for, identically on every run, and the measure it is a
/// function of is the capture: the root and every body taken with it.
///
/// The shape is affine because the cost is: a fixed part that every request
/// pays whatever its size, and a part that grows with the bytes. Over the 1444
/// functions of the whole scratch corpus, the least affine function that
/// dominates every measured point is `346768 + 8.34 * captured_bytes`, computed
/// as the upper convex hull of (captured bytes, work). These constants are that
/// bound doubled and rounded up, so the worst function measured uses 0.48 of its
/// budget and only a run that has stopped making progress can reach it.
///
/// Two things this fit had to get right. A slope alone was wrong in both
/// directions: it gave a tiny capture too little for its fixed cost, which is
/// why it needed a floor, and a large one fifty times more than it can use. And
/// the fit has to be over every binary measured, not one: derived from
/// dpkg-divert alone it refused five functions of the others.
pub const WORK_BUDGET_BASE: u64 = 786_432;

/// Units per captured byte, on top of the base.
pub const WORK_BUDGET_PER_CAPTURED_BYTE: u64 = 17;

/// The work budget for a capture of this size.
///
/// `R2SLEIGH_WORK_BUDGET_SCALE` multiplies it. That is a measurement aid, not a
/// policy knob: re-deriving the constants above needs the work a function spends
/// when nothing stops it, and a bound cannot be fitted from runs the bound
/// truncated. Nothing in production sets it.
pub fn work_budget_for_captured_bytes(captured_bytes: usize) -> u64 {
    let budget = (captured_bytes as u64)
        .saturating_mul(WORK_BUDGET_PER_CAPTURED_BYTE)
        .saturating_add(WORK_BUDGET_BASE);
    budget.saturating_mul(work_budget_scale())
}

fn work_budget_scale() -> u64 {
    static SCALE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SCALE.get_or_init(|| {
        std::env::var("R2SLEIGH_WORK_BUDGET_SCALE")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|scale| *scale > 0)
            .unwrap_or(1)
    })
}

/// The post-analysis budget for a program of this size.
pub fn post_analysis_budget_usec(function_count: usize) -> u64 {
    let per_function = per_function_budget_usec();
    let derived = (function_count as u64).saturating_mul(per_function);
    if derived < per_function {
        per_function
    } else {
        derived
    }
}
pub const TAINT_GLOBAL_MAX_FUNCTIONS: usize = 128;
pub const SIGNATURE_WRITEBACK_GLOBAL_MAX_FUNCTIONS: usize = 128;
pub const TYPE_WRITEBACK_GLOBAL_MAX_FUNCTIONS: usize = 128;
pub const AUTO_CALLBACK_MAX_BLOCKS: u32 = 96;
pub const AUTO_CALLBACK_MAX_COST: u32 = 512;
pub const AUTO_CALLBACK_MAX_LINEAR_SIZE: u64 = 256 * 1024;
pub const TYPE_WRITEBACK_MUTATION_SIGNATURE_ID: u32 = 0;
pub const TYPE_WRITEBACK_MUTATION_CALLCONV_ID: u32 = 1;
pub const TYPE_WRITEBACK_MUTATION_VAR_ID: u32 = 2;
pub const TYPE_WRITEBACK_MUTATION_VAR_RENAME_ID: u32 = 3;
pub const TYPE_WRITEBACK_MUTATION_VAR_TYPE_ID: u32 = 4;
pub const TYPE_WRITEBACK_MUTATION_XREF_ID: u32 = 5;
pub const TYPE_WRITEBACK_MUTATION_COMMENT_ID: u32 = 6;
pub const TYPE_WRITEBACK_MUTATION_FLAG_ID: u32 = 7;
pub const TYPE_WRITEBACK_MUTATION_TYPE_DECL_ID: u32 = 8;
pub const TYPE_WRITEBACK_MUTATION_TYPE_LINK_ID: u32 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_grows_with_the_program_rather_than_with_the_mode() {
        // The case the three constants could not express: the same policy has
        // to give a 154-function binary four times what a 38-function one gets.
        assert_eq!(post_analysis_budget_usec(38), 3_800_000);
        assert_eq!(post_analysis_budget_usec(154), 15_400_000);
        assert!(post_analysis_budget_usec(154) > post_analysis_budget_usec(38));
    }

    #[test]
    fn a_program_with_nothing_to_sweep_still_has_time_to_say_so() {
        assert_eq!(
            post_analysis_budget_usec(0),
            POST_ANALYSIS_MINIMUM_BUDGET_USEC
        );
    }

    #[test]
    fn an_absurd_function_count_does_not_wrap_the_budget() {
        assert_eq!(post_analysis_budget_usec(usize::MAX), u64::MAX);
    }
}
