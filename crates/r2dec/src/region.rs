//! Control flow region identification.
//!
//! This module identifies structured regions in the CFG:
//! - Sequences (linear blocks)
//! - If-then-else (diamond patterns)
//! - Loops (natural loops with back edges)

use std::collections::{HashMap, HashSet};

use r2ssa::SSAFunction;

/// A control flow region.
#[derive(Debug, Clone)]
pub enum Region {
    /// A single basic block.
    Block(u64),
    /// A sequence of regions.
    Sequence(Vec<Region>),
    /// An if-then-else region.
    IfThenElse {
        /// The condition block.
        cond_block: u64,
        /// The then region.
        then_region: Box<Region>,
        /// The else region (optional).
        else_region: Option<Box<Region>>,
        /// The merge block (if any).
        merge_block: Option<u64>,
    },
    /// A while loop.
    WhileLoop {
        /// The header block (condition).
        header: u64,
        /// The loop body.
        body: Box<Region>,
    },
    /// A do-while loop.
    DoWhileLoop {
        /// The loop body.
        body: Box<Region>,
        /// The condition block.
        cond_block: u64,
    },
    /// A switch statement.
    Switch {
        /// The block containing the switch expression.
        switch_block: u64,
        /// Case targets: (case_value, case_region).
        cases: Vec<(Option<u64>, Box<Region>)>,
        /// Default case region (if any).
        default: Option<Box<Region>>,
        /// The merge block after the switch (if any).
        merge_block: Option<u64>,
    },
    /// An irreducible region (contains gotos).
    Irreducible {
        /// Entry block.
        entry: u64,
        /// All blocks in this region.
        blocks: Vec<u64>,
    },
}

impl Region {
    /// Get the entry block of this region.
    pub fn entry(&self) -> u64 {
        match self {
            Self::Block(addr) => *addr,
            Self::Sequence(regions) => regions.first().map(|r| r.entry()).unwrap_or(0),
            Self::IfThenElse { cond_block, .. } => *cond_block,
            Self::WhileLoop { header, .. } => *header,
            Self::DoWhileLoop { body, .. } => body.entry(),
            Self::Switch { switch_block, .. } => *switch_block,
            Self::Irreducible { entry, .. } => *entry,
        }
    }

    /// Get all blocks in this region.
    pub fn blocks(&self) -> Vec<u64> {
        match self {
            Self::Block(addr) => vec![*addr],
            Self::Sequence(regions) => regions.iter().flat_map(|r| r.blocks()).collect(),
            Self::IfThenElse {
                cond_block,
                then_region,
                else_region,
                merge_block,
            } => {
                let mut blocks = vec![*cond_block];
                blocks.extend(then_region.blocks());
                if let Some(else_r) = else_region {
                    blocks.extend(else_r.blocks());
                }
                if let Some(merge) = merge_block {
                    blocks.push(*merge);
                }
                blocks
            }
            Self::WhileLoop { header, body } => {
                let mut blocks = vec![*header];
                blocks.extend(body.blocks());
                blocks
            }
            Self::DoWhileLoop { body, cond_block } => {
                let mut blocks = body.blocks();
                blocks.push(*cond_block);
                blocks
            }
            Self::Switch {
                switch_block,
                cases,
                default,
                merge_block,
            } => {
                let mut blocks = vec![*switch_block];
                for (_, case_region) in cases {
                    blocks.extend(case_region.blocks());
                }
                if let Some(def) = default {
                    blocks.extend(def.blocks());
                }
                if let Some(merge) = merge_block {
                    blocks.push(*merge);
                }
                blocks
            }
            Self::Irreducible { blocks, .. } => blocks.clone(),
        }
    }
}

/// Region analyzer for identifying structured control flow.
pub struct RegionAnalyzer<'a> {
    func: &'a SSAFunction,
    /// Back edges in the CFG (target -> sources).
    back_edges: HashMap<u64, Vec<u64>>,
    /// Natural loops (header -> body blocks).
    loops: HashMap<u64, HashSet<u64>>,
    /// Processed blocks.
    processed: HashSet<u64>,
    /// Blocks that exit a loop (break targets): block_addr -> exit_target.
    loop_exits: HashMap<u64, u64>,
    /// Blocks that continue to loop header: block_addr -> header.
    loop_continues: HashMap<u64, u64>,
}

impl<'a> RegionAnalyzer<'a> {
    /// Create a new region analyzer.
    pub fn new(func: &'a SSAFunction) -> Self {
        let mut analyzer = Self {
            func,
            back_edges: HashMap::new(),
            loops: HashMap::new(),
            processed: HashSet::new(),
            loop_exits: HashMap::new(),
            loop_continues: HashMap::new(),
        };
        analyzer.find_back_edges();
        analyzer.find_loops();
        analyzer.find_loop_exits();
        analyzer
    }

    /// Find back edges using DFS.
    fn find_back_edges(&mut self) {
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();
        self.dfs_back_edges(self.func.entry, &mut visited, &mut in_stack);
    }

    fn dfs_back_edges(
        &mut self,
        block: u64,
        visited: &mut HashSet<u64>,
        in_stack: &mut HashSet<u64>,
    ) {
        if visited.contains(&block) {
            return;
        }
        visited.insert(block);
        in_stack.insert(block);

        for succ in self.func.successors(block) {
            if in_stack.contains(&succ) {
                // Back edge found: block -> succ
                self.back_edges.entry(succ).or_default().push(block);
            } else {
                self.dfs_back_edges(succ, visited, in_stack);
            }
        }

        in_stack.remove(&block);
    }

    /// Find natural loops from back edges.
    fn find_loops(&mut self) {
        for (&header, sources) in &self.back_edges {
            let mut body = HashSet::new();
            body.insert(header);

            for &source in sources {
                self.collect_loop_body(source, header, &mut body);
            }

            self.loops.insert(header, body);
        }
    }

    /// Find loop exit and continue edges.
    fn find_loop_exits(&mut self) {
        for (&header, body) in &self.loops {
            for &block in body {
                // Check successors of each block in the loop
                for succ in self.func.successors(block) {
                    if succ == header && block != header {
                        // This is a continue (jump back to header, not from header itself)
                        self.loop_continues.insert(block, header);
                    } else if !body.contains(&succ) {
                        // This is a break (exit from loop)
                        self.loop_exits.insert(block, succ);
                    }
                }
            }
        }
    }

    /// Check if a block contains a break (loop exit).
    pub fn is_loop_break(&self, block: u64) -> bool {
        self.loop_exits.contains_key(&block)
    }

    /// Check if a block contains a continue (jump to loop header).
    pub fn is_loop_continue(&self, block: u64) -> bool {
        self.loop_continues.contains_key(&block)
    }

    /// Get the loop exit target for a block.
    pub fn get_loop_exit_target(&self, block: u64) -> Option<u64> {
        self.loop_exits.get(&block).copied()
    }

    fn collect_loop_body(&self, block: u64, header: u64, body: &mut HashSet<u64>) {
        if body.contains(&block) {
            return;
        }
        body.insert(block);

        for pred in self.func.predecessors(block) {
            if pred != header {
                self.collect_loop_body(pred, header, body);
            }
        }
    }

    /// Analyze the function and build a region tree.
    pub fn analyze(&mut self) -> Region {
        self.analyze_region(self.func.entry)
    }

    fn analyze_region(&mut self, entry: u64) -> Region {
        if self.processed.contains(&entry) {
            return Region::Block(entry);
        }

        // Check if this is a loop header
        if let Some(body) = self.loops.get(&entry).cloned() {
            return self.analyze_loop(entry, &body);
        }

        // Prefer explicit switch metadata from CFG terminators.
        if let Some((cases, default)) = self.func.switch_info(entry) {
            return self.analyze_switch_with_cases(entry, &cases, default);
        }

        // Get successors
        let succs = self.func.successors(entry);

        match succs.len() {
            0 => {
                // Terminal block
                self.processed.insert(entry);
                Region::Block(entry)
            }
            1 => {
                // Linear flow - try to build a sequence
                self.processed.insert(entry);
                let next = succs[0];
                let preds = self.func.predecessors(next);
                let next_loop_body = self.loops.get(&next);
                let is_loop_preheader = next_loop_body
                    .map(|loop_body| !loop_body.contains(&entry))
                    .unwrap_or(false);

                if (preds.len() == 1 && !self.loops.contains_key(&next)) || is_loop_preheader {
                    // Can extend sequence
                    let next_region = self.analyze_region(next);
                    match next_region {
                        Region::Sequence(mut regions) => {
                            regions.insert(0, Region::Block(entry));
                            Region::Sequence(regions)
                        }
                        _ => Region::Sequence(vec![Region::Block(entry), next_region]),
                    }
                } else {
                    Region::Block(entry)
                }
            }
            2 => {
                // Conditional - check for if-then-else pattern
                self.analyze_conditional(entry, succs[0], succs[1])
            }
            _ => {
                // Multiple successors - likely a switch statement
                // Try to detect switch pattern
                if let Some(switch_region) = self.detect_switch(entry, &succs) {
                    return switch_region;
                }
                // Fallback to irreducible
                self.processed.insert(entry);
                Region::Irreducible {
                    entry,
                    blocks: succs,
                }
            }
        }
    }

    fn analyze_conditional(&mut self, cond: u64, true_target: u64, false_target: u64) -> Region {
        self.processed.insert(cond);

        // Find the merge point (immediate post-dominator)
        let merge = self.find_merge_point(cond, true_target, false_target);

        // Analyze then and else branches
        let then_region = if true_target != merge.unwrap_or(u64::MAX) {
            Some(Box::new(self.analyze_region(true_target)))
        } else {
            None
        };

        let else_region = if false_target != merge.unwrap_or(u64::MAX) {
            Some(Box::new(self.analyze_region(false_target)))
        } else {
            None
        };

        match (then_region, else_region) {
            (Some(then_r), Some(else_r)) => Region::IfThenElse {
                cond_block: cond,
                then_region: then_r,
                else_region: Some(else_r),
                merge_block: merge,
            },
            (Some(then_r), None) => Region::IfThenElse {
                cond_block: cond,
                then_region: then_r,
                else_region: None,
                merge_block: merge,
            },
            (None, Some(else_r)) => {
                // Swap branches (invert condition in codegen)
                Region::IfThenElse {
                    cond_block: cond,
                    then_region: else_r,
                    else_region: None,
                    merge_block: merge,
                }
            }
            (None, None) => Region::Block(cond),
        }
    }

    fn find_merge_point(&self, _cond: u64, true_target: u64, false_target: u64) -> Option<u64> {
        // Simple heuristic: find the first common successor
        let mut true_reachable = HashSet::new();
        self.collect_reachable(true_target, &mut true_reachable, 10);

        let mut false_reachable = HashSet::new();
        self.collect_reachable(false_target, &mut false_reachable, 10);

        // Find intersection
        for &block in &true_reachable {
            if false_reachable.contains(&block) {
                return Some(block);
            }
        }

        None
    }

    fn collect_reachable(&self, start: u64, reachable: &mut HashSet<u64>, depth: usize) {
        if depth == 0 || reachable.contains(&start) {
            return;
        }
        reachable.insert(start);
        for succ in self.func.successors(start) {
            self.collect_reachable(succ, reachable, depth - 1);
        }
    }

    fn analyze_loop(&mut self, header: u64, body: &HashSet<u64>) -> Region {
        self.processed.insert(header);

        // Determine loop type (while vs do-while)
        let succs = self.func.successors(header);
        let is_while = succs.len() == 2 && succs.iter().any(|s| !body.contains(s));

        if is_while {
            // While loop: header is the condition
            let body_entry = succs.iter().find(|s| body.contains(s)).copied();
            let mut body_blocks = body.clone();
            body_blocks.remove(&header);
            let body_region = if let Some(entry) = body_entry {
                self.analyze_loop_body(entry, &body_blocks)
            } else {
                Region::Sequence(Vec::new())
            };

            Region::WhileLoop {
                header,
                body: Box::new(body_region),
            }
        } else {
            // Guarded infinite-loop pattern:
            //   loop_head -> guard
            //   guard: if (break_cond) break; ...
            // Recover this as while(cond) from region analysis instead of cleanup.
            if let Some((guard_block, body_entry)) = self.find_precheck_guard(header, body) {
                let mut body_blocks = body.clone();
                body_blocks.remove(&guard_block);
                if header != guard_block && self.func.successors(header).len() == 1 {
                    body_blocks.remove(&header);
                }
                let body_region = self.analyze_loop_body(body_entry, &body_blocks);
                return Region::WhileLoop {
                    header: guard_block,
                    body: Box::new(body_region),
                };
            }

            // Do-while or infinite loop
            let body_region = self.analyze_loop_body(header, body);
            Region::DoWhileLoop {
                body: Box::new(body_region),
                cond_block: header,
            }
        }
    }

    fn analyze_loop_body(&mut self, entry: u64, body: &HashSet<u64>) -> Region {
        if body.is_empty() {
            return Region::Sequence(Vec::new());
        }

        let mut blocks = Vec::new();
        let mut seen = HashSet::new();
        self.collect_loop_body_order(entry, body, &mut seen, &mut blocks);

        for &b in body {
            if !seen.contains(&b) {
                blocks.push(b);
            }
        }

        let mut regions = Vec::new();
        for b in blocks {
            if self.processed.contains(&b) {
                continue;
            }
            regions.push(self.analyze_region(b));
        }

        if regions.is_empty() {
            Region::Sequence(Vec::new())
        } else if regions.len() == 1 {
            regions.remove(0)
        } else {
            Region::Sequence(regions)
        }
    }

    fn collect_loop_body_order(
        &self,
        block: u64,
        body: &HashSet<u64>,
        seen: &mut HashSet<u64>,
        out: &mut Vec<u64>,
    ) {
        if !body.contains(&block) || !seen.insert(block) {
            return;
        }
        out.push(block);
        for succ in self.func.successors(block) {
            if body.contains(&succ) {
                self.collect_loop_body_order(succ, body, seen, out);
            }
        }
    }

    fn find_precheck_guard(&self, header: u64, body: &HashSet<u64>) -> Option<(u64, u64)> {
        if self.func.successors(header).len() != 1 {
            return None;
        }

        for &block in body {
            if block == header {
                continue;
            }
            let preds = self.func.predecessors(block);
            if !preds.contains(&header) {
                continue;
            }

            let succs = self.func.successors(block);
            if succs.len() != 2 {
                continue;
            }

            let mut inside = None;
            let mut outside = false;
            for succ in succs {
                if body.contains(&succ) {
                    inside = Some(succ);
                } else {
                    outside = true;
                }
            }

            if outside {
                if let Some(next_body) = inside {
                    if next_body != header {
                        return Some((block, next_body));
                    }
                }
            }
        }

        None
    }

    /// Check if a block is a loop header.
    pub fn is_loop_header(&self, block: u64) -> bool {
        self.loops.contains_key(&block)
    }

    /// Get the loop body for a header.
    pub fn get_loop_body(&self, header: u64) -> Option<&HashSet<u64>> {
        self.loops.get(&header)
    }

    /// Detect a switch statement pattern.
    /// Returns a Switch region if the entry block dispatches to multiple targets.
    fn detect_switch(&mut self, entry: u64, targets: &[u64]) -> Option<Region> {
        // A switch is detected when:
        // 1. Multiple successors (already checked by caller)
        // 2. Targets don't all merge back to the same point (that would be if-else chain)

        if targets.len() < 3 {
            // Too few targets for a meaningful switch
            return None;
        }

        self.processed.insert(entry);

        // Find the common merge point for all targets
        let merge = self.find_switch_merge(targets);

        // Try to get real switch info from the CFG
        let switch_info = self.func.switch_info(entry);

        // Build case regions for each target
        let mut cases = Vec::new();
        let mut default_target = None;

        if let Some((switch_cases, def)) = switch_info {
            // Use real case values from switch info
            default_target = def;

            // Group cases by target and deduplicate
            let mut target_to_values: HashMap<u64, Vec<u64>> = HashMap::new();
            for (value, target) in &switch_cases {
                target_to_values.entry(*target).or_default().push(*value);
            }

            for (&target, values) in &target_to_values {
                if Some(target) == merge || Some(target) == default_target {
                    continue;
                }
                // Use the first value for this target
                let case_value = values.first().copied();
                let case_region = Box::new(self.analyze_region(target));
                cases.push((case_value, case_region));
            }
        } else {
            // Fallback: use indices as placeholder values
            for (idx, &target) in targets.iter().enumerate() {
                if Some(target) == merge {
                    default_target = Some(target);
                    continue;
                }

                let case_value = Some(idx as u64);
                let case_region = Box::new(self.analyze_region(target));
                cases.push((case_value, case_region));
            }
        }

        // Build default region if we have one
        let default = default_target.map(|addr| Box::new(self.analyze_region(addr)));

        Some(Region::Switch {
            switch_block: entry,
            cases,
            default,
            merge_block: merge,
        })
    }

    fn analyze_switch_with_cases(
        &mut self,
        entry: u64,
        switch_cases: &[(u64, u64)],
        default: Option<u64>,
    ) -> Region {
        self.processed.insert(entry);

        let mut targets: Vec<u64> = switch_cases.iter().map(|(_, t)| *t).collect();
        if let Some(def) = default {
            targets.push(def);
        }
        targets.sort();
        targets.dedup();

        let merge = self.find_switch_merge(&targets);

        let mut target_to_values: HashMap<u64, Vec<u64>> = HashMap::new();
        for (value, target) in switch_cases {
            target_to_values.entry(*target).or_default().push(*value);
        }

        let mut cases = Vec::new();
        for (&target, values) in &target_to_values {
            if Some(target) == merge || Some(target) == default {
                continue;
            }
            let case_region = Box::new(self.analyze_region(target));
            cases.push((values.first().copied(), case_region));
        }
        cases.sort_by_key(|(v, _)| v.unwrap_or(u64::MAX));

        let default_region = default
            .filter(|t| Some(*t) != merge)
            .map(|addr| Box::new(self.analyze_region(addr)));

        Region::Switch {
            switch_block: entry,
            cases,
            default: default_region,
            merge_block: merge,
        }
    }

    /// Find the merge point for switch targets.
    fn find_switch_merge(&self, targets: &[u64]) -> Option<u64> {
        if targets.is_empty() {
            return None;
        }

        // Collect reachable blocks from each target
        let mut reachable_sets: Vec<HashSet<u64>> = Vec::new();
        for &target in targets {
            let mut reachable = HashSet::new();
            self.collect_reachable(target, &mut reachable, 10);
            reachable_sets.push(reachable);
        }

        // Find intersection of all reachable sets
        if let Some(first) = reachable_sets.first() {
            let common: HashSet<u64> = first
                .iter()
                .copied()
                .filter(|b| reachable_sets.iter().all(|s| s.contains(b)))
                .collect();

            // Return the first common block (closest to targets)
            // In a proper implementation, we'd want the immediate post-dominator
            return common.into_iter().min();
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests would require constructing SSAFunctions
    // which requires r2il blocks. These are placeholder tests.

    #[test]
    fn test_region_entry() {
        let region = Region::Block(0x1000);
        assert_eq!(region.entry(), 0x1000);
    }

    #[test]
    fn test_region_blocks() {
        let region = Region::Sequence(vec![
            Region::Block(0x1000),
            Region::Block(0x1004),
            Region::Block(0x1008),
        ]);
        let blocks = region.blocks();
        assert_eq!(blocks, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn test_if_then_else_blocks() {
        let region = Region::IfThenElse {
            cond_block: 0x1000,
            then_region: Box::new(Region::Block(0x1004)),
            else_region: Some(Box::new(Region::Block(0x1008))),
            merge_block: Some(0x100c),
        };
        let blocks = region.blocks();
        assert!(blocks.contains(&0x1000));
        assert!(blocks.contains(&0x1004));
        assert!(blocks.contains(&0x1008));
        assert!(blocks.contains(&0x100c));
    }
}
