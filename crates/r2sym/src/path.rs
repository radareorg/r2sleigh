//! Path exploration strategies for symbolic execution.
//!
//! This module provides different strategies for exploring paths
//! during symbolic execution, including DFS, BFS, and coverage-guided.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use r2ssa::SSAFunction;
use z3::Context;

use crate::executor::SymExecutor;
use crate::solver::SymSolver;
use crate::state::{ExitStatus, SymState};

/// Configuration for path exploration.
#[derive(Debug, Clone)]
pub struct ExploreConfig {
    /// Maximum number of states to explore.
    pub max_states: usize,
    /// Maximum execution depth per path.
    pub max_depth: usize,
    /// Timeout for the entire exploration.
    pub timeout: Option<Duration>,
    /// Exploration strategy.
    pub strategy: ExploreStrategy,
    /// Whether to prune infeasible paths early.
    pub prune_infeasible: bool,
    /// Whether to merge states at join points.
    pub merge_states: bool,
}

impl Default for ExploreConfig {
    fn default() -> Self {
        Self {
            max_states: 1000,
            max_depth: 100,
            timeout: Some(Duration::from_secs(60)),
            strategy: ExploreStrategy::Dfs,
            prune_infeasible: true,
            merge_states: false,
        }
    }
}

/// Exploration strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploreStrategy {
    /// Depth-first search.
    Dfs,
    /// Breadth-first search.
    Bfs,
    /// Random path selection.
    Random,
}

/// Result of exploring a single path.
#[derive(Debug)]
pub struct PathResult<'ctx> {
    /// The final state of this path.
    pub state: SymState<'ctx>,
    /// How the path terminated.
    pub exit_status: ExitStatus,
    /// Execution depth.
    pub depth: usize,
    /// Whether the path is feasible (constraints satisfiable).
    pub feasible: bool,
}

impl<'ctx> PathResult<'ctx> {
    /// Create a new path result.
    pub fn new(state: SymState<'ctx>, feasible: bool) -> Self {
        let exit_status = state.exit_status.clone().unwrap_or(ExitStatus::Return);
        let depth = state.depth;
        Self {
            state,
            exit_status,
            depth,
            feasible,
        }
    }
}

/// Path explorer for symbolic execution.
pub struct PathExplorer<'ctx> {
    /// The Z3 context.
    _ctx: &'ctx Context,
    /// The symbolic executor.
    executor: SymExecutor<'ctx>,
    /// The constraint solver.
    solver: SymSolver<'ctx>,
    /// Configuration.
    config: ExploreConfig,
    /// Statistics.
    stats: ExploreStats,
}

/// Statistics from path exploration.
#[derive(Debug, Clone, Default)]
pub struct ExploreStats {
    /// Number of states explored.
    pub states_explored: usize,
    /// Number of paths completed.
    pub paths_completed: usize,
    /// Number of infeasible paths pruned.
    pub paths_pruned: usize,
    /// Number of paths that hit max depth.
    pub paths_max_depth: usize,
    /// Maximum depth reached.
    pub max_depth_reached: usize,
    /// Total execution time.
    pub total_time: Duration,
}

impl<'ctx> PathExplorer<'ctx> {
    /// Create a new path explorer.
    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            _ctx: ctx,
            executor: SymExecutor::new(ctx),
            solver: SymSolver::new(ctx),
            config: ExploreConfig::default(),
            stats: ExploreStats::default(),
        }
    }

    /// Create a path explorer with configuration.
    pub fn with_config(ctx: &'ctx Context, config: ExploreConfig) -> Self {
        let solver = if let Some(timeout) = config.timeout {
            SymSolver::with_timeout(ctx, timeout)
        } else {
            SymSolver::new(ctx)
        };

        Self {
            _ctx: ctx,
            executor: SymExecutor::new(ctx),
            solver,
            config,
            stats: ExploreStats::default(),
        }
    }

    /// Get the exploration statistics.
    pub fn stats(&self) -> &ExploreStats {
        &self.stats
    }

    /// Get the solver for additional queries.
    pub fn solver(&self) -> &SymSolver<'ctx> {
        &self.solver
    }

    /// Explore all paths in a function.
    pub fn explore(&mut self, func: &SSAFunction, initial_state: SymState<'ctx>) -> Vec<PathResult<'ctx>> {
        let start_time = Instant::now();
        let mut results = Vec::new();
        let mut worklist: VecDeque<SymState<'ctx>> = VecDeque::new();
        worklist.push_back(initial_state);

        while let Some(mut state) = self.next_state(&mut worklist) {
            // Check timeout
            if let Some(timeout) = self.config.timeout {
                if start_time.elapsed() > timeout {
                    break;
                }
            }

            // Check state limit
            if self.stats.states_explored >= self.config.max_states {
                break;
            }

            self.stats.states_explored += 1;

            // Check depth limit
            if state.depth >= self.config.max_depth {
                state.terminate(ExitStatus::MaxDepth);
                self.stats.paths_max_depth += 1;
                results.push(PathResult::new(state, true));
                continue;
            }

            // Check feasibility
            if self.config.prune_infeasible && !self.solver.is_sat(&state) {
                self.stats.paths_pruned += 1;
                continue;
            }

            // Get current block
            let block_addr = state.pc;
            let Some(block) = func.get_block(block_addr) else {
                // No block at this address - path ends
                state.terminate(ExitStatus::Return);
                results.push(PathResult::new(state, true));
                self.stats.paths_completed += 1;
                continue;
            };

            // Execute the block
            match self.executor.execute_block(&mut state, block) {
                Ok(forked_states) => {
                    // Add forked states to worklist
                    for forked in forked_states {
                        worklist.push_back(forked);
                    }

                    // Update max depth before potentially moving state
                    if state.depth > self.stats.max_depth_reached {
                        self.stats.max_depth_reached = state.depth;
                    }

                    // Check if state terminated
                    if state.is_terminated() {
                        let feasible = self.solver.is_sat(&state);
                        results.push(PathResult::new(state, feasible));
                        self.stats.paths_completed += 1;
                    } else {
                        // Continue exploring this path
                        // Update PC to next block if not changed by control flow
                        let succs = func.successors(block_addr);
                        if state.pc == block_addr && !succs.is_empty() {
                            state.pc = succs[0];
                        }
                        worklist.push_back(state);
                    }
                }
                Err(e) => {
                    // Update max depth before moving state
                    if state.depth > self.stats.max_depth_reached {
                        self.stats.max_depth_reached = state.depth;
                    }
                    state.terminate(ExitStatus::Error(format!("{}", e)));
                    results.push(PathResult::new(state, false));
                    self.stats.paths_completed += 1;
                }
            }
        }

        self.stats.total_time = start_time.elapsed();
        results
    }

    /// Get the next state from the worklist based on strategy.
    fn next_state(&self, worklist: &mut VecDeque<SymState<'ctx>>) -> Option<SymState<'ctx>> {
        match self.config.strategy {
            ExploreStrategy::Dfs => worklist.pop_back(),
            ExploreStrategy::Bfs => worklist.pop_front(),
            ExploreStrategy::Random => {
                if worklist.is_empty() {
                    None
                } else {
                    // Simple random: alternate between front and back
                    if worklist.len() % 2 == 0 {
                        worklist.pop_front()
                    } else {
                        worklist.pop_back()
                    }
                }
            }
        }
    }

    /// Explore paths to find inputs that reach a target address.
    pub fn find_path_to(
        &mut self,
        func: &SSAFunction,
        initial_state: SymState<'ctx>,
        target_addr: u64,
    ) -> Option<PathResult<'ctx>> {
        let start_time = Instant::now();
        let mut worklist: VecDeque<SymState<'ctx>> = VecDeque::new();
        worklist.push_back(initial_state);

        while let Some(mut state) = self.next_state(&mut worklist) {
            // Check timeout
            if let Some(timeout) = self.config.timeout {
                if start_time.elapsed() > timeout {
                    break;
                }
            }

            // Check if we reached the target
            if state.pc == target_addr {
                let feasible = self.solver.is_sat(&state);
                if feasible {
                    return Some(PathResult::new(state, true));
                }
                continue;
            }

            // Check limits
            if self.stats.states_explored >= self.config.max_states {
                break;
            }
            if state.depth >= self.config.max_depth {
                continue;
            }

            self.stats.states_explored += 1;

            // Check feasibility
            if self.config.prune_infeasible && !self.solver.is_sat(&state) {
                self.stats.paths_pruned += 1;
                continue;
            }

            // Get and execute block
            let block_addr = state.pc;
            let Some(block) = func.get_block(block_addr) else {
                continue;
            };

            if let Ok(forked_states) = self.executor.execute_block(&mut state, block) {
                for forked in forked_states {
                    worklist.push_back(forked);
                }

                if !state.is_terminated() {
                    let succs = func.successors(block_addr);
                    if state.pc == block_addr && !succs.is_empty() {
                        state.pc = succs[0];
                    }
                    worklist.push_back(state);
                }
            }
        }

        None
    }

    /// Explore paths to find inputs that avoid a target address.
    pub fn find_path_avoiding(
        &mut self,
        func: &SSAFunction,
        initial_state: SymState<'ctx>,
        avoid_addrs: &[u64],
    ) -> Option<PathResult<'ctx>> {
        let avoid_set: HashSet<u64> = avoid_addrs.iter().copied().collect();
        let start_time = Instant::now();
        let mut worklist: VecDeque<SymState<'ctx>> = VecDeque::new();
        worklist.push_back(initial_state);

        while let Some(mut state) = self.next_state(&mut worklist) {
            // Check timeout
            if let Some(timeout) = self.config.timeout {
                if start_time.elapsed() > timeout {
                    break;
                }
            }

            // Check if we hit an avoided address
            if avoid_set.contains(&state.pc) {
                continue;
            }

            // Check limits
            if self.stats.states_explored >= self.config.max_states {
                break;
            }
            if state.depth >= self.config.max_depth {
                let feasible = self.solver.is_sat(&state);
                if feasible {
                    return Some(PathResult::new(state, true));
                }
                continue;
            }

            self.stats.states_explored += 1;

            // Check feasibility
            if self.config.prune_infeasible && !self.solver.is_sat(&state) {
                self.stats.paths_pruned += 1;
                continue;
            }

            // Get and execute block
            let block_addr = state.pc;
            let Some(block) = func.get_block(block_addr) else {
                // Reached end without hitting avoided addresses
                let feasible = self.solver.is_sat(&state);
                if feasible {
                    return Some(PathResult::new(state, true));
                }
                continue;
            };

            if let Ok(forked_states) = self.executor.execute_block(&mut state, block) {
                for forked in forked_states {
                    if !avoid_set.contains(&forked.pc) {
                        worklist.push_back(forked);
                    }
                }

                if !state.is_terminated() && !avoid_set.contains(&state.pc) {
                    let succs = func.successors(block_addr);
                    if state.pc == block_addr && !succs.is_empty() {
                        state.pc = succs[0];
                    }
                    worklist.push_back(state);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_explore_config_default() {
        let config = ExploreConfig::default();
        assert_eq!(config.max_states, 1000);
        assert_eq!(config.max_depth, 100);
        assert!(config.prune_infeasible);
    }

    #[test]
    fn test_path_explorer_creation() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let explorer = PathExplorer::new(&ctx);
        assert_eq!(explorer.stats().states_explored, 0);
    }

    #[test]
    fn test_explore_stats() {
        let stats = ExploreStats::default();
        assert_eq!(stats.states_explored, 0);
        assert_eq!(stats.paths_completed, 0);
    }
}
