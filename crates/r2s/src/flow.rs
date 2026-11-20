//! `pdf`'s flow lanes and rail from the engine's edges: cells 0 to `w + 1`, the rail, `w - 2`
//! lanes, the arrow and a separator (doc/adr-display.md, "Round 15 as built: listing", D565).

use r2s_tui::theme::{Role, Roles};

/// One edge between two rows of the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Edge {
    pub from: usize,
    pub to: usize,
    /// A back edge of a loop the engine states, painted `FlowLoop`.
    pub latch: bool,
}

impl Edge {
    const fn low(self) -> usize {
        if self.from < self.to {
            self.from
        } else {
            self.to
        }
    }

    const fn high(self) -> usize {
        if self.from < self.to {
            self.to
        } else {
            self.from
        }
    }

    const fn role(self) -> Role {
        match self.latch {
            true => Role::FlowLoop,
            false => Role::Flow,
        }
    }
}

/// radare2's glyphs: box runes, or its ASCII under `scr.utf8=false` (`libr/anal/reflines.c:486-503`
/// and `:552-555`, `libr/core/disasm.c:26-50` and `:446-460`).
#[derive(Debug, Clone, Copy)]
struct Glyphs {
    down: char,
    up: char,
    /// The corner on the top row of an edge, and on its bottom row.
    top: char,
    bottom: char,
    /// The top corner of an upward edge, whose target is above.
    up_top: char,
    from_run: char,
    to_run: char,
    rail: char,
    rail_end: char,
}

const UTF8: Glyphs = Glyphs {
    down: '│',
    up: '╎',
    top: '┌',
    bottom: '└',
    up_top: '┌',
    from_run: '─',
    to_run: '─',
    rail: '│',
    rail_end: '└',
};

const ASCII: Glyphs = Glyphs {
    down: '|',
    up: ':',
    top: ',',
    bottom: '`',
    up_top: '.',
    from_run: '=',
    to_run: '-',
    rail: '|',
    rail_end: '\\',
};

/// How the gutter is drawn: `asm.lines.width`, `scr.utf8`, and whether lanes are drawn at all.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gutter {
    pub width: usize,
    pub utf8: bool,
    pub lanes: bool,
}

impl Gutter {
    const fn glyphs(self) -> Glyphs {
        match self.utf8 {
            true => UTF8,
            false => ASCII,
        }
    }

    /// The cells lanes may use: `1..=w-2`.
    const fn lanes(self) -> usize {
        self.width.saturating_sub(2)
    }

    /// The rail glyph of the function's own line: `┌`, or radare2's `/` (`libr/core/disasm.c:26-50`).
    pub(crate) const fn head(self) -> char {
        match self.utf8 {
            true => '┌',
            false => '/',
        }
    }

    /// The rail glyph of a row that is not the last.
    pub(crate) const fn rail(self) -> char {
        self.glyphs().rail
    }
}

/// Each edge's lane, none past the budget: admission by a segment tree, `O(E log N)`, then
/// interval colouring by span start, `O(E log E)` (doc/adr-display.md, D565).
pub(crate) fn plan(rows: usize, edges: &[Edge], lanes: usize) -> Vec<Option<usize>> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut order = (0..edges.len()).collect::<Vec<_>>();
    order.sort_by_key(|&at| (edges[at].high() - edges[at].low(), edges[at].from, at));
    let mut tree = MaxTree::new(rows);
    let mut admitted = vec![false; edges.len()];
    for at in order {
        let (low, high) = (edges[at].low(), edges[at].high());
        if lanes > 0 && tree.max(low, high) < lanes {
            tree.add(low, high);
            admitted[at] = true;
        }
    }
    let mut taken = (0..edges.len())
        .filter(|&at| admitted[at])
        .collect::<Vec<_>>();
    taken.sort_by_key(|&at| (edges[at].low(), edges[at].high(), at));
    let mut free = (1..=lanes).map(Reverse).collect::<BinaryHeap<_>>();
    let mut active: BinaryHeap<Reverse<(usize, usize)>> = BinaryHeap::new();
    let mut lane = vec![None; edges.len()];
    for at in taken {
        // An edge sharing a row with another needs its own lane, so only those ended above it free one.
        while let Some(&Reverse((high, lane))) = active.peek()
            && high < edges[at].low()
        {
            active.pop();
            free.push(Reverse(lane));
        }
        let Reverse(given) = free
            .pop()
            .expect("admission bounds the clique by the lanes");
        lane[at] = Some(given);
        active.push(Reverse((edges[at].high(), given)));
    }
    lane
}

/// Each row's gutter with its roles: rail, lanes and arrows, a `+` stub at both ends of an edge
/// past the budget, a `?` stub on each `unknown` row. `O(E log E + R w)`.
pub(crate) fn gutters(
    rows: usize,
    edges: &[Edge],
    unknown: &[usize],
    gutter: Gutter,
) -> Vec<(String, Roles)> {
    let (edges, unknown) = match gutter.lanes {
        true => (edges, unknown),
        false => (&[][..], &[][..]),
    };
    let mut grid = Grid {
        width: gutter.width.max(2),
        glyphs: gutter.glyphs(),
        // Cells 1..=w+1 of each row, as a glyph and the role it is painted in.
        cells: vec![vec![(' ', None::<Role>); gutter.width.max(2) + 1]; rows],
    };
    let lanes = plan(rows, edges, gutter.lanes());
    grid.verticals(edges, &lanes, gutter.lanes());
    let heads = grid.corners(edges, &lanes);
    grid.heads(&heads);
    let mut stub = |row: usize, glyph: char, role: Role| {
        let cell = match heads[row] {
            None => grid.width - 1,
            Some(_) => grid.width,
        };
        grid.cells[row][cell] = (glyph, Some(role));
    };
    for (at, edge) in edges.iter().enumerate() {
        if lanes[at].is_none() {
            stub(edge.from, '+', Role::Flow);
            stub(edge.to, '+', Role::Flow);
        }
    }
    for &row in unknown {
        stub(row, '?', Role::ProofUnknown);
    }
    grid.rendered()
}

/// The gutter's cells while they are drawn, `w + 1` per row.
struct Grid {
    width: usize,
    glyphs: Glyphs,
    cells: Vec<Vec<(char, Option<Role>)>>,
}

impl Grid {
    const fn cell_of(&self, lane: usize) -> usize {
        self.width - 1 - lane
    }

    /// Each lane's vertical on the rows strictly inside its edge, ends sorted by row.
    fn verticals(&mut self, edges: &[Edge], lanes: &[Option<usize>], budget: usize) {
        let mut verticals = vec![Vec::new(); self.cells.len() + 1];
        for (at, edge) in edges.iter().enumerate() {
            let Some(lane) = lanes[at] else { continue };
            if edge.high() > edge.low() + 1 {
                verticals[edge.low() + 1].push((at, lane));
                verticals[edge.high()].push((usize::MAX, lane));
            }
        }
        let mut occupant = vec![None; budget + 1];
        for (row, ends) in verticals.iter().take(self.cells.len()).enumerate() {
            for &(at, lane) in ends {
                occupant[lane] = (at != usize::MAX).then_some(at);
            }
            let occupied = occupant.iter().enumerate();
            for (lane, at) in occupied.filter_map(|(lane, at)| Some((lane, (*at)?))) {
                let edge: Edge = edges[at];
                let glyph = match edge.from < edge.to {
                    true => self.glyphs.down,
                    false => self.glyphs.up,
                };
                let cell = self.cell_of(lane) - 1;
                self.cells[row][cell] = (glyph, Some(edge.role()));
            }
        }
    }

    /// Each edge's two corners and runs; each row's arrow head, `>` where an edge reaches it.
    fn corners(&mut self, edges: &[Edge], lanes: &[Option<usize>]) -> Vec<Option<(char, Role)>> {
        let mut heads = vec![None::<(char, Role)>; self.cells.len()];
        for (at, edge) in edges.iter().enumerate() {
            let Some(lane) = lanes[at] else { continue };
            for (row, source) in [(edge.from, true), (edge.to, false)] {
                self.corner(*edge, lane, row, source);
                // A row an edge reaches takes the `>`; one it only leaves takes the `<`.
                let head = match source {
                    true => '<',
                    false => '>',
                };
                let held = &mut heads[row];
                let replaced = |(held, _): &(char, Role)| held == &'<' && head == '>';
                *held = held
                    .filter(|kept| !replaced(kept))
                    .or(Some((head, edge.role())));
            }
        }
        heads
    }

    /// One end of an edge: its corner in its lane, then a run to the arrow over blank cells.
    fn corner(&mut self, edge: Edge, lane: usize, row: usize, source: bool) {
        let glyphs = self.glyphs;
        let corner = match (row == edge.low(), edge.from < edge.to) {
            _ if edge.from == edge.to => '@',
            (true, true) => glyphs.top,
            (true, false) => glyphs.up_top,
            (false, _) => glyphs.bottom,
        };
        let role = Some(edge.role());
        let (cell, end) = (self.cell_of(lane), self.width - 2);
        let line = &mut self.cells[row];
        line[cell - 1] = (corner, role);
        let run = match source {
            true => glyphs.from_run,
            false => glyphs.to_run,
        };
        let blank = line[cell..end].iter_mut().filter(|cell| cell.0 == ' ');
        blank.for_each(|blank| *blank = (run, role));
    }

    /// Each row's arrow head and the run cell before it.
    fn heads(&mut self, heads: &[Option<(char, Role)>]) {
        for (row, head) in heads.iter().enumerate() {
            let Some((head, role)) = *head else { continue };
            let run = match head {
                '<' => self.glyphs.from_run,
                _ => self.glyphs.to_run,
            };
            self.cells[row][self.width - 2] = (run, Some(role));
            self.cells[row][self.width - 1] = (head, Some(role));
        }
    }

    /// Each row as text after its rail glyph, with one role span per run of cells in one role.
    fn rendered(self) -> Vec<(String, Roles)> {
        let rows = self.cells.len();
        let glyphs = self.glyphs;
        let row_of = |(row, line)| row_text(line, glyphs, row + 1 == rows);
        self.cells.into_iter().enumerate().map(row_of).collect()
    }
}

/// One row's text: the rail glyph, the last row's where `last`, then its cells, one role span
/// per run of cells in one role.
fn row_text(line: Vec<(char, Option<Role>)>, glyphs: Glyphs, last: bool) -> (String, Roles) {
    let mut text = String::new();
    let mut roles = Roles::new();
    let rail = match last {
        true => glyphs.rail_end,
        false => glyphs.rail,
    };
    text.push(rail);
    roles.push((0..text.len(), Role::Rail));
    for (glyph, role) in line {
        let at = text.len();
        text.push(glyph);
        // One escape for a run of cells in one role.
        match (roles.last_mut(), role) {
            (Some((span, last)), Some(role)) if *last == role && span.end == at => {
                span.end = text.len();
            }
            (_, role) => roles.extend(role.map(|role| (at..text.len(), role))),
        }
    }
    (text, roles)
}

/// A maximum over row ranges with range additions, `O(log N)` each.
struct MaxTree {
    size: usize,
    max: Vec<usize>,
    add: Vec<usize>,
}

impl MaxTree {
    fn new(rows: usize) -> Self {
        let size = rows.max(1).next_power_of_two();
        Self {
            size,
            max: vec![0; 2 * size],
            add: vec![0; 2 * size],
        }
    }

    /// One more edge over rows `low..=high`.
    fn add(&mut self, low: usize, high: usize) {
        self.update(self.root(), low, high);
    }

    const fn root(&self) -> Node {
        Node {
            at: 1,
            from: 0,
            to: self.size - 1,
        }
    }

    fn update(&mut self, node: Node, low: usize, high: usize) {
        if high < node.from || node.to < low {
            return;
        }
        if low <= node.from && node.to <= high {
            self.max[node.at] += 1;
            self.add[node.at] += 1;
            return;
        }
        let (left, right) = node.children();
        self.update(left, low, high);
        self.update(right, low, high);
        self.max[node.at] = self.add[node.at] + self.max[left.at].max(self.max[right.at]);
    }

    /// The most edges over any row of `low..=high`.
    fn max(&self, low: usize, high: usize) -> usize {
        self.query(self.root(), low, high)
    }

    fn query(&self, node: Node, low: usize, high: usize) -> usize {
        if high < node.from || node.to < low {
            return 0;
        }
        if low <= node.from && node.to <= high {
            return self.max[node.at];
        }
        let (left, right) = node.children();
        let below = self
            .query(left, low, high)
            .max(self.query(right, low, high));
        self.add[node.at] + below
    }
}

/// A segment tree node: its slot and the rows `from..=to` it covers.
#[derive(Clone, Copy)]
struct Node {
    at: usize,
    from: usize,
    to: usize,
}

impl Node {
    const fn children(self) -> (Self, Self) {
        let middle = self.from + (self.to - self.from) / 2;
        let left = Self {
            at: 2 * self.at,
            from: self.from,
            to: middle,
        };
        let right = Self {
            at: 2 * self.at + 1,
            from: middle + 1,
            to: self.to,
        };
        (left, right)
    }
}

/// What of a line a terminal keeps (doc/adr-display.md, "Column grid").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Kept {
    /// The instruction's cells, or `Some(n)`: `n` cells and `..`.
    pub instruction: Option<usize>,
    /// The spaces before the first `;`.
    pub gap: usize,
    /// Whether `; M` stays.
    pub mark: bool,
    /// The words after the mark, or `Some(n)`: `n` cells and `..`, none at all for 0.
    pub words: Option<usize>,
}

/// A line of `lead`, `instruction`, `gap` and `notes` cells (`notes` from the first `;`, 0 for
/// none) cut to `width`: note text first, ending in `..`; then operand text; then the mark.
pub(crate) fn cut(lead: usize, instruction: usize, gap: usize, notes: usize, width: usize) -> Kept {
    let whole = Kept {
        instruction: None,
        gap,
        mark: notes > 0,
        words: None,
    };
    if lead + instruction + gap + notes <= width {
        return whole;
    }
    let mark = notes.min(3);
    if notes > mark && lead + instruction + gap + mark + 2 < width {
        let words = width - (lead + instruction + gap + mark + 2);
        return Kept {
            words: Some(words),
            ..whole
        };
    }
    if notes > 0 && lead + 1 + mark + 2 < width {
        let kept = width - (lead + 1 + mark + 2);
        return Kept {
            instruction: (kept < instruction).then_some(kept),
            gap: 1,
            mark: true,
            words: Some(0),
        };
    }
    Kept {
        instruction: Some(width.saturating_sub(lead + 2)),
        gap: 0,
        mark: false,
        words: Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic generator: xorshift64.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }
    }

    fn plain() -> Gutter {
        Gutter {
            width: 10,
            utf8: true,
            lanes: true,
        }
    }

    /// The bomb's `jg` over one line: `┌─<`, `│`, `└─>` in lane 1, next to the address.
    #[test]
    fn a_forward_jump_is_drawn_in_lane_one() {
        let edges = [Edge {
            from: 0,
            to: 2,
            latch: false,
        }];
        let drawn = gutters(3, &edges, &[], plain());
        let text = drawn
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(text, ["│       ┌─< ", "│       │   ", "└       └─> "]);
        let ascii = Gutter {
            utf8: false,
            ..plain()
        };
        let drawn = gutters(3, &edges, &[], ascii);
        let text = drawn
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(text, ["|       ,=< ", "|       |   ", "\\       `-> "]);
    }

    /// An upward edge is mirrored: its target above takes `┌─>`, its source below `└─<`.
    #[test]
    fn a_back_edge_is_mirrored_and_painted_as_a_loop() {
        let edges = [Edge {
            from: 3,
            to: 1,
            latch: true,
        }];
        let drawn = gutters(4, &edges, &[], plain());
        let text = drawn
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            text,
            [
                "│           ",
                "│       ┌─> ",
                "│       ╎   ",
                "└       └─< "
            ]
        );
        assert!(drawn[1].1.iter().any(|(_, role)| *role == Role::FlowLoop));
    }

    /// Past the budget an edge ends in `+` stubs, and an unresolved jump in a `?` stub.
    #[test]
    fn an_edge_past_the_budget_is_a_stub_at_both_ends() {
        let narrow = Gutter {
            width: 3,
            ..plain()
        };
        let edges = [
            Edge {
                from: 0,
                to: 3,
                latch: false,
            },
            Edge {
                from: 1,
                to: 2,
                latch: false,
            },
        ];
        let drawn = gutters(5, &edges, &[4], narrow);
        let text = drawn
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(text, ["│  + ", "│┌─< ", "│└─> ", "│  + ", "└  ? "]);
    }

    /// Over random edge sets: no two admitted edges share a lane on a common row, every edge has an
    /// arrow or a `+` at both ends, and no lane leaves the budget.
    #[test]
    fn random_edges_keep_lanes_apart_and_every_end_drawn() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..400 {
            let rows = 2 + rng.next(60);
            let width = 3 + rng.next(9);
            let gutter = Gutter { width, ..plain() };
            let count = rng.next(40);
            let edges = (0..count)
                .map(|_| Edge {
                    from: rng.next(rows),
                    to: rng.next(rows),
                    latch: rng.next(2) == 0,
                })
                .filter(|edge| edge.from != edge.to)
                .collect::<Vec<_>>();
            let lanes = plan(rows, &edges, gutter.lanes());
            apart(&edges, &lanes, gutter.lanes());
            let drawn = gutters(rows, &edges, &[], gutter);
            drawn_ends(&edges, &lanes, &drawn, width);
        }
    }

    /// No two edges sharing a row share a lane, and every lane is within the budget.
    fn apart(edges: &[Edge], lanes: &[Option<usize>], budget: usize) {
        for (a, first) in edges.iter().enumerate() {
            let Some(lane) = lanes[a] else { continue };
            assert!((1..=budget).contains(&lane));
            let sharing =
                edges.iter().enumerate().skip(a + 1).filter(|(_, second)| {
                    first.low() <= second.high() && second.low() <= first.high()
                });
            for (b, second) in sharing {
                assert!(lanes[b] != Some(lane), "{first:?} {second:?}");
            }
        }
    }

    /// Each end of an edge with a lane has its corner and an arrow; one without has a `+` stub.
    fn drawn_ends(
        edges: &[Edge],
        lanes: &[Option<usize>],
        drawn: &[(String, Roles)],
        width: usize,
    ) {
        let ends = (edges.iter().enumerate())
            .flat_map(|(at, edge)| [(at, edge, edge.from), (at, edge, edge.to)]);
        for (at, edge, row) in ends {
            let cells = drawn[row].0.chars().collect::<Vec<_>>();
            let Some(lane) = lanes[at] else {
                assert!(cells[width] == '+' || cells[width + 1] == '+');
                continue;
            };
            let corner = cells[width - 1 - lane];
            assert!("┌└".contains(corner), "{edge:?} row {row}: {cells:?}");
            assert!("<>".contains(cells[width]), "{edge:?}: {cells:?}");
        }
    }

    /// At 80 cells the notes go first and end in `..`, then the operands, then the mark.
    #[test]
    fn a_long_line_loses_note_text_then_operands_then_the_mark() {
        // bomb 0x400f5b at 80 columns: 12 cells of gutter, address, two spaces.
        let lead = "│       ┌─< 0x00400f5b  ".chars().count();
        let instruction = "call sym.imp.__isoc99_sscanf".chars().count();
        let notes = "; ! args: the import has no declaration to state its arguments"
            .chars()
            .count();
        let kept = cut(lead, instruction, 7, notes, 80);
        assert_eq!(kept.instruction, None);
        assert_eq!((kept.gap, kept.mark), (7, true));
        assert_eq!(
            lead + instruction + 7 + 3 + kept.words.expect("cut") + 2,
            80
        );
        // Too narrow for any word: the operands go, the mark stays.
        let kept = cut(lead, instruction, 7, notes, 40);
        assert_eq!(kept.words, Some(0));
        assert_eq!(lead + 1 + 3 + kept.instruction.expect("cut") + 2, 40);
        // Narrower still: the mark goes too.
        let kept = cut(lead, instruction, 7, notes, 26);
        assert!(!kept.mark);
        assert_eq!(cut(lead, instruction, 7, notes, 200).words, None);
    }
}
