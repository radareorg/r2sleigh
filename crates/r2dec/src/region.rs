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
}

impl<'a> RegionAnalyzer<'a> {
    /// Create a new region analyzer.
    pub fn new(func: &'a SSAFunction) -> Self {
        let mut analyzer = Self {
            func,
            back_edges: HashMap::new(),
            loops: HashMap::new(),
            processed: HashSet::new(),
        };
        analyzer.find_back_edges();
        analyzer.find_loops();
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

                if preds.len() == 1 && !self.loops.contains_key(&next) {
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
                // Multiple successors (switch) - treat as irreducible for now
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

        // Mark all body blocks as processed
        for &block in body {
            self.processed.insert(block);
        }

        // Determine loop type (while vs do-while)
        let succs = self.func.successors(header);
        let is_while = succs.len() == 2 && succs.iter().any(|s| !body.contains(s));

        if is_while {
            // While loop: header is the condition
            let body_entry = succs.iter().find(|s| body.contains(s)).copied();
            let body_region = if let Some(entry) = body_entry {
                self.analyze_loop_body(entry, body)
            } else {
                Region::Block(header)
            };

            Region::WhileLoop {
                header,
                body: Box::new(body_region),
            }
        } else {
            // Do-while or infinite loop
            let body_region = self.analyze_loop_body(header, body);
            Region::DoWhileLoop {
                body: Box::new(body_region),
                cond_block: header,
            }
        }
    }

    fn analyze_loop_body(&mut self, _entry: u64, body: &HashSet<u64>) -> Region {
        // Simplified: just return the blocks as a sequence
        let mut blocks: Vec<u64> = body.iter().copied().collect();
        blocks.sort();

        if blocks.len() == 1 {
            Region::Block(blocks[0])
        } else {
            Region::Sequence(blocks.into_iter().map(Region::Block).collect())
        }
    }

    /// Check if a block is a loop header.
    pub fn is_loop_header(&self, block: u64) -> bool {
        self.loops.contains_key(&block)
    }

    /// Get the loop body for a header.
    pub fn get_loop_body(&self, header: u64) -> Option<&HashSet<u64>> {
        self.loops.get(&header)
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
