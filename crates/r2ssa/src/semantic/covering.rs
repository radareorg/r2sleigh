//! The evidenced spans as one index: the nearest root below a position whose span passes a bound.

use std::collections::{BTreeMap, BTreeSet};

use crate::StackAddressRoot;

/// Spans of evidenced roots in root order, with a max-end tree over them (O(n) to build).
#[derive(Debug, Clone, Default)]
pub(crate) struct CoveringSpans {
    roots: Vec<StackAddressRoot>,
    /// Segment tree over the span ends: leaf `i` is at `leaves + i`, padding is `i64::MIN`.
    tree: Vec<i64>,
    leaves: usize,
}

impl CoveringSpans {
    pub(crate) fn of(
        spans: &BTreeMap<StackAddressRoot, i64>,
        evidenced: &BTreeSet<StackAddressRoot>,
    ) -> Self {
        let held: Vec<(StackAddressRoot, i64)> = (spans.iter())
            .filter(|(root, _)| evidenced.contains(root))
            .map(|(root, end)| (*root, *end))
            .collect();
        let leaves = held.len().next_power_of_two();
        let mut tree = vec![i64::MIN; 2 * leaves];
        for (index, (_, end)) in held.iter().enumerate() {
            tree[leaves + index] = *end;
        }
        for node in (1..leaves).rev() {
            tree[node] = tree[2 * node].max(tree[2 * node + 1]);
        }
        Self {
            roots: held.into_iter().map(|(root, _)| root).collect(),
            tree,
            leaves,
        }
    }

    /// The greatest root on `below`'s base and under it whose span ends past `beyond`: O(log n).
    pub(crate) fn nearest_below(
        &self,
        below: StackAddressRoot,
        beyond: i64,
    ) -> Option<StackAddressRoot> {
        let floor = StackAddressRoot {
            base: below.base,
            offset: i64::MIN,
        };
        let low = self.roots.partition_point(|root| *root < floor);
        let high = self.roots.partition_point(|root| *root < below);
        let index = self.rightmost((1, 0, self.leaves), (low, high), beyond)?;
        Some(self.roots[index])
    }

    /// The greatest leaf of `window` under `node` (index, start, end) holding an end past `beyond`.
    fn rightmost(
        &self,
        node: (usize, usize, usize),
        window: (usize, usize),
        beyond: i64,
    ) -> Option<usize> {
        let (at, start, end) = node;
        if end <= window.0 || window.1 <= start || self.tree.get(at)? <= &beyond {
            return None;
        }
        if end - start == 1 {
            return Some(start);
        }
        let middle = start + (end - start) / 2;
        self.rightmost((2 * at + 1, middle, end), window, beyond)
            .or_else(|| self.rightmost((2 * at, start, middle), window, beyond))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackAddressBase;

    fn root(base: StackAddressBase, offset: i64) -> StackAddressRoot {
        StackAddressRoot { base, offset }
    }

    /// The scan the index replaces, over the same maps.
    fn scanned(
        spans: &BTreeMap<StackAddressRoot, i64>,
        evidenced: &BTreeSet<StackAddressRoot>,
        below: StackAddressRoot,
        beyond: i64,
    ) -> Option<StackAddressRoot> {
        let floor = StackAddressRoot {
            base: below.base,
            offset: i64::MIN,
        };
        (spans.range(floor..below).rev())
            .find(|(base, end)| beyond < **end && evidenced.contains(*base))
            .map(|(base, _)| *base)
    }

    #[test]
    fn the_nearest_covering_span_is_the_scans_whatever_nests() {
        let sp = StackAddressBase::StackPointer;
        let spans: BTreeMap<_, _> = [
            (root(sp, -64), 100),
            (root(sp, -48), -40),
            (root(sp, -32), -20),
            (root(sp, -16), -8),
            (root(sp, -8), -4),
            (root(sp, 8), 40),
        ]
        .into_iter()
        .collect();
        let evidenced: BTreeSet<_> = spans.keys().copied().filter(|r| r.offset != -16).collect();
        let index = CoveringSpans::of(&spans, &evidenced);
        for below in spans
            .keys()
            .copied()
            .chain([root(sp, 0), root(sp, 20), root(sp, -100)])
        {
            for beyond in -70..110 {
                assert_eq!(
                    index.nearest_below(below, beyond),
                    scanned(&spans, &evidenced, below, beyond),
                    "{below:?} past {beyond}"
                );
            }
        }
    }

    #[test]
    fn a_span_ending_at_the_bound_does_not_cover_it() {
        let sp = StackAddressBase::StackPointer;
        let spans: BTreeMap<_, _> = [(root(sp, -32), -16)].into_iter().collect();
        let evidenced: BTreeSet<_> = spans.keys().copied().collect();
        let index = CoveringSpans::of(&spans, &evidenced);
        assert_eq!(index.nearest_below(root(sp, -8), -16), None);
        assert_eq!(index.nearest_below(root(sp, -8), -17), Some(root(sp, -32)));
        assert_eq!(index.nearest_below(root(sp, -32), -17), None);
        assert_eq!(CoveringSpans::default().nearest_below(root(sp, 0), 0), None);
    }
}
