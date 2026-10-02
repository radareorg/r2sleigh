//! A layered (Sugiyama) layout of a control-flow graph on a character grid.
//!
//! 1. **Acyclic.** A depth-first search from the entry, in edge order, finds
//!    the back edges; each is laid out reversed and drawn pointing back up.
//! 2. **Ranks.** Each block's rank is its longest path from a source, so every
//!    edge points down at least one rank.
//! 3. **Dummies.** An edge spanning `k > 1` ranks becomes a chain through
//!    `k - 1` one-column dummy nodes, so every layered edge joins adjacent
//!    ranks and a long edge is routed like a node.
//! 4. **Order.** Barycentre sweeps down and up, then adjacent transpositions,
//!    repeated while the total crossing count strictly falls. The count is a
//!    natural number, so the loop ends; every tie breaks on the current
//!    position, so the order is a function of the graph alone.
//! 5. **Columns.** Each node wants to sit at the median of its neighbours in
//!    the rank before (down passes) or after (up passes). The positions that
//!    are closest to those wishes in weighted least squares while keeping the
//!    rank's order and spacing are an isotonic regression, solved exactly in
//!    `O(rank)` by pooling adjacent violators. Dummies weigh more, which keeps
//!    long edges straight.
//! 6. **Routes.** Each edge leaves its block's bottom at its own port, runs
//!    across on its own track in the gap below the rank -- tracks are dealt
//!    out greedily so that horizontal runs never share a row where they
//!    overlap -- and enters the target's top.
//!
//! Cost: `O((V + E) log E)` per ordering sweep with the crossing count by a
//! Fenwick tree, and `O(V + E)` per column pass.

/// Columns between two neighbours of one rank.
const GAP: i64 = 2;
/// Column passes, each a sweep down then up. Placement is presentation only:
/// four rounds settle every graph in the fixtures to within a column.
const ROUNDS: usize = 4;
/// How much a dummy's wish outweighs a block's.
const DUMMY_WEIGHT: f64 = 4.0;

/// Where one block is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// One edge's path, a run of axis-aligned segments from source to target.
/// The last point is the cell the arrowhead is drawn in, just outside the
/// target's box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub points: Vec<(u32, u32)>,
    /// The edge enters its target from below: a back edge.
    pub upward: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// By node index.
    pub boxes: Vec<Placed>,
    /// By edge index.
    pub routes: Vec<Route>,
    pub width: u32,
    pub height: u32,
}

/// A node of the layered graph: a block, or one rank of a long edge.
struct Layered {
    rank: usize,
    width: i64,
    real: bool,
}

/// Lay out `sizes.len()` boxes of `(width, height)` joined by `edges`.
///
/// Every width is at least three, so a box has an interior column for ports.
pub fn layout(sizes: &[(u32, u32)], edges: &[(usize, usize)], entry: usize) -> Layout {
    let n = sizes.len();
    if n == 0 {
        return Layout {
            boxes: Vec::new(),
            routes: Vec::new(),
            width: 0,
            height: 0,
        };
    }
    let back = back_edges(n, edges, entry.min(n - 1));
    // Each edge as it is laid out: a back edge reversed, a self-loop not at all.
    let dag = edges
        .iter()
        .zip(&back)
        .map(|(&(from, to), &back)| match (from == to, back) {
            (true, _) => None,
            (false, true) => Some((to, from)),
            (false, false) => Some((from, to)),
        })
        .collect::<Vec<_>>();
    let ranks = ranks(n, &dag);

    let (nodes, hops, chains) = layered(sizes, &ranks, &dag);
    let mut preds = vec![Vec::new(); nodes.len()];
    let mut succs = vec![Vec::new(); nodes.len()];
    for &(from, to) in &hops {
        succs[from].push(to);
        preds[to].push(from);
    }

    let layers = ordered(&nodes, &preds, &succs, entry.min(n - 1));
    let left = columns(&nodes, &layers, &preds, &succs);
    let ports = ports(&nodes, &layers, &left, &hops);

    let depth = layers.len();
    let (tracks, gap_tracks) = tracks(&nodes, &hops, &ports, depth);
    let (tops, band) = rows(sizes, &nodes, &gap_tracks);
    let boxes = (0..n)
        .map(|node| Placed {
            x: left[node] as u32,
            y: tops[nodes[node].rank] as u32,
            width: nodes[node].width as u32,
            height: sizes[node].1.max(1),
        })
        .collect::<Vec<_>>();
    let width = (nodes.iter().zip(&left))
        .map(|(layered, left)| left + layered.width + GAP)
        .max()
        .unwrap_or(0);
    let grid = Grid {
        nodes: &nodes,
        boxes: &boxes,
        hops: &hops,
        ports: &ports,
        tracks: &tracks,
        tops: &tops,
        band: &band,
    };
    let routes = edges
        .iter()
        .enumerate()
        .map(|(edge, &(from, _))| match chains[edge].as_slice() {
            [] => self_loop(boxes[from]),
            chain => grid.route(chain, back[edge]),
        })
        .collect();
    let height = grid.bottom(depth - 1) + 1;
    Layout {
        boxes,
        routes,
        width: width as u32,
        height: height as u32,
    }
}

/// Where everything is, once ranks, columns and tracks are settled.
struct Grid<'a> {
    nodes: &'a [Layered],
    boxes: &'a [Placed],
    hops: &'a [(usize, usize)],
    ports: &'a [(i64, i64)],
    tracks: &'a [usize],
    tops: &'a [i64],
    band: &'a [i64],
}

impl Grid<'_> {
    fn bottom(&self, rank: usize) -> i64 {
        self.tops[rank] + self.band[rank]
    }

    /// Where edges leave a node: a block's bottom; a dummy's rank's bottom.
    fn out_row(&self, node: usize) -> i64 {
        if self.nodes[node].real {
            i64::from(self.boxes[node].y + self.boxes[node].height)
        } else {
            self.bottom(self.nodes[node].rank)
        }
    }

    /// One edge's path through its hops: down from each port, across on its
    /// track, down to the arrow row above the next rank.
    fn route(&self, chain: &[usize], back: bool) -> Route {
        let mut points: Vec<(i64, i64)> = Vec::new();
        for &hop in chain {
            let (source, target) = self.hops[hop];
            let (out, into) = self.ports[hop];
            points.push((out, self.out_row(source)));
            if out != into {
                let row = self.bottom(self.nodes[source].rank) + 1 + self.tracks[hop] as i64;
                points.push((out, row));
                points.push((into, row));
            }
            points.push((into, self.tops[self.nodes[target].rank] - 1));
        }
        points.dedup();
        if back {
            points.reverse();
        }
        Route {
            points: points
                .into_iter()
                .map(|(x, y)| (x as u32, y as u32))
                .collect(),
            upward: back,
        }
    }
}

/// The layered graph: the blocks, then one dummy per rank each long edge
/// crosses; every hop between adjacent ranks; and each edge's hops in order
/// (none for a self-loop).
#[allow(clippy::type_complexity)]
fn layered(
    sizes: &[(u32, u32)],
    ranks: &[usize],
    dag: &[Option<(usize, usize)>],
) -> (Vec<Layered>, Vec<(usize, usize)>, Vec<Vec<usize>>) {
    let mut nodes = (0..sizes.len())
        .map(|node| Layered {
            rank: ranks[node],
            width: i64::from(sizes[node].0.max(3)),
            real: true,
        })
        .collect::<Vec<_>>();
    let mut hops = Vec::new();
    let mut chains = Vec::with_capacity(dag.len());
    for edge in dag {
        let Some((from, to)) = *edge else {
            chains.push(Vec::new());
            continue;
        };
        let mut chain = vec![from];
        for rank in ranks[from] + 1..ranks[to] {
            nodes.push(Layered {
                rank,
                width: 1,
                real: false,
            });
            chain.push(nodes.len() - 1);
        }
        chain.push(to);
        let first = hops.len();
        hops.extend(chain.windows(2).map(|pair| (pair[0], pair[1])));
        chains.push((first..hops.len()).collect());
    }
    (nodes, hops, chains)
}

/// Each hop's track in the gap below its source's rank, and how many tracks
/// each gap needs. Runs are dealt out left to right, each to the first track
/// whose last run ends at least a column short of it.
fn tracks(
    nodes: &[Layered],
    hops: &[(usize, usize)],
    ports: &[(i64, i64)],
    depth: usize,
) -> (Vec<usize>, Vec<usize>) {
    let mut tracks = vec![0usize; hops.len()];
    let mut gap_tracks = vec![0usize; depth];
    let mut by_gap = vec![Vec::new(); depth];
    for (hop, &(from, _)) in hops.iter().enumerate() {
        let (out, into) = ports[hop];
        if out != into {
            by_gap[nodes[from].rank].push((out.min(into), out.max(into), hop));
        }
    }
    for (rank, runs) in by_gap.iter_mut().enumerate() {
        runs.sort_unstable();
        let mut ends: Vec<i64> = Vec::new();
        for &(lo, hi, hop) in runs.iter() {
            let track = ends
                .iter()
                .position(|&end| end + 1 < lo)
                .unwrap_or_else(|| {
                    ends.push(i64::MIN);
                    ends.len() - 1
                });
            ends[track] = hi;
            tracks[hop] = track;
        }
        gap_tracks[rank] = ends.len();
    }
    (tracks, gap_tracks)
}

/// Each rank's top row and height: its tallest block, then a gap of its
/// tracks plus a row for the edges' starts and one for their arrows. One row
/// of margin above, for a self-loop's arrow into the first rank.
fn rows(sizes: &[(u32, u32)], nodes: &[Layered], gap_tracks: &[usize]) -> (Vec<i64>, Vec<i64>) {
    let mut band = vec![0i64; gap_tracks.len()];
    for (node, size) in sizes.iter().enumerate() {
        let rank = nodes[node].rank;
        band[rank] = band[rank].max(i64::from(size.1.max(1)));
    }
    let mut tops = Vec::with_capacity(band.len());
    let mut y = 1i64;
    for (height, tracks) in band.iter().zip(gap_tracks) {
        tops.push(y);
        y += height + *tracks as i64 + 2;
    }
    (tops, band)
}

/// A block's edge to itself: out of its bottom, up its right side, into its top.
fn self_loop(placed: Placed) -> Route {
    let inside = placed.x + placed.width - 2;
    let outside = placed.x + placed.width + 1;
    let below = placed.y + placed.height;
    let above = placed.y - 1;
    Route {
        points: vec![
            (inside, below),
            (outside, below),
            (outside, above),
            (inside, above),
        ],
        upward: false,
    }
}

/// The edges a depth-first search from `entry` (then from each unvisited
/// node, in index order) meets while their target is on the stack.
fn back_edges(n: usize, edges: &[(usize, usize)], entry: usize) -> Vec<bool> {
    let mut out = vec![Vec::new(); n];
    for (edge, &(from, _)) in edges.iter().enumerate() {
        out[from].push(edge);
    }
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Unseen,
        Open,
        Done,
    }
    let mut state = vec![State::Unseen; n];
    let mut back = vec![false; edges.len()];
    for root in std::iter::once(entry).chain(0..n) {
        if state[root] != State::Unseen {
            continue;
        }
        state[root] = State::Open;
        let mut stack = vec![(root, 0usize)];
        while let Some(&(node, next)) = stack.last() {
            let Some(&edge) = out[node].get(next) else {
                state[node] = State::Done;
                stack.pop();
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            let to = edges[edge].1;
            match state[to] {
                State::Unseen => {
                    state[to] = State::Open;
                    stack.push((to, 0));
                }
                State::Open => back[edge] = true,
                State::Done => {}
            }
        }
    }
    back
}

/// Each node's longest path from a source, over an acyclic edge set.
fn ranks(n: usize, dag: &[Option<(usize, usize)>]) -> Vec<usize> {
    let mut indegree = vec![0usize; n];
    let mut out = vec![Vec::new(); n];
    for &(from, to) in dag.iter().flatten() {
        indegree[to] += 1;
        out[from].push(to);
    }
    let mut rank = vec![0usize; n];
    let mut ready = (0..n)
        .filter(|&node| indegree[node] == 0)
        .collect::<Vec<_>>();
    while let Some(node) = ready.pop() {
        for &to in &out[node] {
            rank[to] = rank[to].max(rank[node] + 1);
            indegree[to] -= 1;
            if indegree[to] == 0 {
                ready.push(to);
            }
        }
    }
    rank
}

/// Each rank's nodes, left to right.
fn ordered(
    nodes: &[Layered],
    preds: &[Vec<usize>],
    succs: &[Vec<usize>],
    entry: usize,
) -> Vec<Vec<usize>> {
    let depth = nodes.iter().map(|node| node.rank + 1).max().unwrap_or(0);
    // First by a depth-first walk, which keeps a branch's arms beside it.
    let mut layers = vec![Vec::new(); depth];
    let mut seen = vec![false; nodes.len()];
    for root in std::iter::once(entry).chain(0..nodes.len()) {
        if seen[root] {
            continue;
        }
        seen[root] = true;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            layers[nodes[node].rank].push(node);
            let unseen = succs[node].iter().rev().filter(|&&to| !seen[to]).copied();
            let unseen = unseen.collect::<Vec<_>>();
            for to in unseen {
                seen[to] = true;
                stack.push(to);
            }
        }
    }
    let mut pos = vec![0usize; nodes.len()];
    let place = |layers: &[Vec<usize>], pos: &mut [usize]| {
        for layer in layers {
            for (at, &node) in layer.iter().enumerate() {
                pos[node] = at;
            }
        }
    };
    place(&layers, &mut pos);
    let mut best = layers.clone();
    let mut fewest = crossings(&layers, &pos, succs);
    while fewest > 0 {
        for layer in layers.iter_mut().skip(1) {
            reorder(layer, &mut pos, preds);
        }
        for layer in layers.iter_mut().rev().skip(1) {
            reorder(layer, &mut pos, succs);
        }
        transpose(&mut layers, &mut pos, preds, succs);
        let count = crossings(&layers, &pos, succs);
        if count >= fewest {
            break;
        }
        fewest = count;
        best.clone_from(&layers);
    }
    best
}

/// Sort one rank by the mean position of each node's neighbours on one side;
/// a node with none keeps its place.
fn reorder(layer: &mut [usize], pos: &mut [usize], neighbours: &[Vec<usize>]) {
    let key = |node: usize| -> f64 {
        let around = &neighbours[node];
        if around.is_empty() {
            pos[node] as f64
        } else {
            around.iter().map(|&other| pos[other] as f64).sum::<f64>() / around.len() as f64
        }
    };
    let mut keyed = layer
        .iter()
        .map(|&node| (key(node), pos[node], node))
        .collect::<Vec<_>>();
    keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    for (at, (_, _, node)) in keyed.into_iter().enumerate() {
        layer[at] = node;
        pos[node] = at;
    }
}

/// Swap neighbours of a rank while that removes crossings. Each swap strictly
/// lowers the total, so this ends.
fn transpose(
    layers: &mut [Vec<usize>],
    pos: &mut [usize],
    preds: &[Vec<usize>],
    succs: &[Vec<usize>],
) {
    let crossed = |pos: &[usize], left: usize, right: usize| -> usize {
        [preds, succs]
            .iter()
            .map(|side| {
                let rights = &side[right];
                side[left]
                    .iter()
                    .map(|&a| rights.iter().filter(|&&b| pos[a] > pos[b]).count())
                    .sum::<usize>()
            })
            .sum()
    };
    let mut improved = true;
    while improved {
        improved = false;
        for layer in layers.iter_mut() {
            improved |= transpose_layer(layer, pos, &crossed);
        }
    }
}

/// One pass of swaps along one rank; whether any swap was made.
fn transpose_layer(
    layer: &mut [usize],
    pos: &mut [usize],
    crossed: &dyn Fn(&[usize], usize, usize) -> usize,
) -> bool {
    let mut swapped = false;
    for at in 0..layer.len().saturating_sub(1) {
        let (left, right) = (layer[at], layer[at + 1]);
        if crossed(pos, left, right) > crossed(pos, right, left) {
            layer.swap(at, at + 1);
            pos[left] = at + 1;
            pos[right] = at;
            swapped = true;
        }
    }
    swapped
}

/// The edges that cross, counted between each pair of adjacent ranks as the
/// inversions of the lower ends once the upper ends are sorted.
fn crossings(layers: &[Vec<usize>], pos: &[usize], succs: &[Vec<usize>]) -> usize {
    let mut total = 0;
    for pair in layers.windows(2) {
        let mut ends = pair[0]
            .iter()
            .flat_map(|&from| succs[from].iter().map(move |&to| (pos[from], pos[to])))
            .collect::<Vec<_>>();
        ends.sort_unstable();
        // Fenwick tree over the lower rank's positions.
        let size = pair[1].len();
        let mut tree = vec![0usize; size + 1];
        for (seen, &(_, lower)) in ends.iter().enumerate() {
            let mut at_or_below = 0;
            let mut index = lower + 1;
            while index > 0 {
                at_or_below += tree[index];
                index &= index - 1;
            }
            total += seen - at_or_below;
            let mut index = lower + 1;
            while index <= size {
                tree[index] += 1;
                index += index & index.wrapping_neg();
            }
        }
    }
    total
}

/// Each node's left column.
fn columns(
    nodes: &[Layered],
    layers: &[Vec<usize>],
    preds: &[Vec<usize>],
    succs: &[Vec<usize>],
) -> Vec<i64> {
    let mut left = vec![0f64; nodes.len()];
    for layer in layers {
        let mut x = 0f64;
        for &node in layer {
            left[node] = x;
            x += (nodes[node].width + GAP) as f64;
        }
    }
    let depth = layers.len();
    let mut passes = Vec::new();
    for _ in 0..ROUNDS {
        passes.extend((1..depth).map(|rank| (rank, true)));
        passes.extend((0..depth.saturating_sub(1)).rev().map(|rank| (rank, false)));
    }
    passes.extend((1..depth).map(|rank| (rank, true)));
    for (rank, down) in passes {
        let neighbours = if down { preds } else { succs };
        align(nodes, &layers[rank], neighbours, &mut left);
    }
    // To whole columns, keeping the spacing, then from column zero.
    let mut placed = vec![0i64; nodes.len()];
    let mut least = i64::MAX;
    for layer in layers {
        let mut next = i64::MIN;
        for &node in layer {
            let x = (left[node].round() as i64).max(next);
            placed[node] = x;
            next = x + nodes[node].width + GAP;
            least = least.min(x);
        }
    }
    for x in &mut placed {
        *x -= least;
    }
    placed
}

/// Place one rank as near its wishes as its order and spacing allow.
fn align(nodes: &[Layered], layer: &[usize], neighbours: &[Vec<usize>], left: &mut [f64]) {
    let centre = |node: usize, left: &[f64]| left[node] + nodes[node].width as f64 / 2.0;
    // Pools of (weighted sum, weight, count) over y = x - offset, which the
    // spacing constraint makes non-decreasing.
    let mut pools: Vec<(f64, f64, usize)> = Vec::with_capacity(layer.len());
    let mut offsets = Vec::with_capacity(layer.len());
    let mut offset = 0f64;
    for &node in layer {
        let mut around = neighbours[node]
            .iter()
            .map(|&other| centre(other, left))
            .collect::<Vec<_>>();
        around.sort_by(f64::total_cmp);
        let wish = match around.len() {
            0 => centre(node, left),
            len if len % 2 == 1 => around[len / 2],
            len => (around[len / 2 - 1] + around[len / 2]) / 2.0,
        };
        let target = wish - nodes[node].width as f64 / 2.0 - offset;
        let weight = if nodes[node].real { 1.0 } else { DUMMY_WEIGHT };
        pools.push((target * weight, weight, 1));
        while pools.len() > 1 {
            let last = pools[pools.len() - 1];
            let before = pools[pools.len() - 2];
            if before.0 / before.1 <= last.0 / last.1 {
                break;
            }
            pools.pop();
            if let Some(merged) = pools.last_mut() {
                *merged = (before.0 + last.0, before.1 + last.1, before.2 + last.2);
            }
        }
        offsets.push(offset);
        offset += (nodes[node].width + GAP) as f64;
    }
    let mut at = 0;
    for (sum, weight, count) in pools {
        for _ in 0..count {
            left[layer[at]] = sum / weight + offsets[at];
            at += 1;
        }
    }
}

/// Each hop's columns where it leaves its source and enters its target: a
/// block's ports spread across its interior in the order of the far ends, a
/// dummy's is its one column.
fn ports(
    nodes: &[Layered],
    layers: &[Vec<usize>],
    left: &[i64],
    hops: &[(usize, usize)],
) -> Vec<(i64, i64)> {
    let mut pos = vec![0usize; nodes.len()];
    for layer in layers {
        for (at, &node) in layer.iter().enumerate() {
            pos[node] = at;
        }
    }
    let mut outs = vec![Vec::new(); nodes.len()];
    let mut ins = vec![Vec::new(); nodes.len()];
    for (hop, &(from, to)) in hops.iter().enumerate() {
        outs[from].push((pos[to], hop));
        ins[to].push((pos[from], hop));
    }
    let mut ports = vec![(0i64, 0i64); hops.len()];
    let spread = |node: usize, k: usize, m: usize| -> i64 {
        if !nodes[node].real {
            return left[node];
        }
        let interior = nodes[node].width - 2;
        left[node] + 1 + (k as i64 + 1) * interior / (m as i64 + 1)
    };
    for node in 0..nodes.len() {
        outs[node].sort_unstable();
        ins[node].sort_unstable();
        let m = outs[node].len();
        for (k, &(_, hop)) in outs[node].iter().enumerate() {
            ports[hop].0 = spread(node, k, m);
        }
        let m = ins[node].len();
        for (k, &(_, hop)) in ins[node].iter().enumerate() {
            ports[hop].1 = spread(node, k, m);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlap(a: Placed, b: Placed) -> bool {
        a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height
    }

    /// A diamond with a loop back to the head, and a long edge past the arms:
    /// no two boxes overlap, every forward edge points down, the back edge up,
    /// every route is axis-aligned and ends just outside its target.
    #[test]
    fn a_layout_keeps_boxes_apart_and_every_route_ends_at_its_target() {
        let sizes = [(10, 4), (8, 3), (12, 5), (9, 3), (7, 3)];
        let edges = [
            (0, 1),
            (0, 2),
            (1, 3),
            (2, 3),
            (3, 0),
            (0, 4),
            (3, 4),
            (4, 4),
        ];
        let layout = layout(&sizes, &edges, 0);
        for a in 0..sizes.len() {
            for b in a + 1..sizes.len() {
                assert!(!overlap(layout.boxes[a], layout.boxes[b]), "{a} {b}");
            }
        }
        for (edge, &(from, to)) in edges.iter().enumerate() {
            let route = &layout.routes[edge];
            for pair in route.points.windows(2) {
                assert!(
                    pair[0].0 == pair[1].0 || pair[0].1 == pair[1].1,
                    "{route:?}"
                );
            }
            let target = layout.boxes[to];
            let &(x, y) = route.points.last().expect("a route has points");
            assert!(x > target.x && x < target.x + target.width - 1, "{route:?}");
            if route.upward {
                assert_eq!(y, target.y + target.height, "{route:?}");
            } else {
                assert_eq!(y, target.y - 1, "{route:?}");
            }
            if from != to {
                assert_eq!(route.upward, layout.boxes[from].y > target.y, "{edge}");
            }
        }
        assert!(layout.routes[4].upward, "3 -> 0 is the loop's back edge");
        // A function of its input alone.
        assert_eq!(layout, super::layout(&sizes, &edges, 0));
    }

    /// Two arms crossed in the walk's order are uncrossed.
    #[test]
    fn the_order_removes_a_crossing_the_walk_left() {
        // 0 -> {1, 2}; 1 -> 4, 2 -> 3, with 3 found before 4.
        let sizes = [(5, 3); 5];
        let edges = [(0, 2), (0, 1), (1, 4), (2, 3)];
        let layout = layout(&sizes, &edges, 0);
        let left_of = |a: usize, b: usize| layout.boxes[a].x < layout.boxes[b].x;
        assert_eq!(left_of(1, 2), left_of(4, 3));
    }
}
