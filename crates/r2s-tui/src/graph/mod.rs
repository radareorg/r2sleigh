//! The control-flow graph view, and `agf`'s drawing of it.
//!
//! [`layout`] places the blocks and routes the edges once per graph;
//! [`Canvas`] paints any window of that onto a grid of characters, so a pane
//! only pays for what is on screen and `agf` is the same painting over the
//! whole graph.

pub mod layout;

use crate::host::{EdgeKind, Graph};
pub use layout::{Layout, Placed, Route};

/// The widest a block's text is drawn; longer lines end in `…`.
const TEXT: usize = 56;

/// What a cell was painted as, which the pane colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ink {
    Blank,
    Edge(EdgeKind),
    Border,
    Selected,
    Header,
    Text,
}

/// The header a block's box opens with.
pub fn header(address: u64) -> String {
    format!("[{address:#x}]")
}

/// The boxes' sizes for a graph: the text plus a border and a space each side,
/// and a row for the header. A `mini` graph draws headers only.
pub fn sizes(graph: &Graph, mini: bool) -> Vec<(u32, u32)> {
    graph
        .nodes
        .iter()
        .map(|node| {
            let head = header(node.address).chars().count();
            let (widest, rows) = if mini {
                (head, 0)
            } else {
                let widest = node
                    .lines
                    .iter()
                    .map(|line| line.chars().count().min(TEXT))
                    .max()
                    .unwrap_or(0);
                (widest.max(head), node.lines.len())
            };
            ((widest + 4) as u32, (rows + 3) as u32)
        })
        .collect()
}

/// Lay a graph out.
pub fn lay_out(graph: &Graph, mini: bool) -> Layout {
    let edges = graph
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to))
        .collect::<Vec<_>>();
    let entry = graph.node_at(graph.entry).unwrap_or(0);
    layout::layout(&sizes(graph, mini), &edges, entry)
}

const UP: u8 = 1;
const DOWN: u8 = 2;
const LEFT: u8 = 4;
const RIGHT: u8 = 8;

/// A window onto the laid-out graph.
pub struct Canvas {
    pub x0: i64,
    pub y0: i64,
    pub width: usize,
    pub height: usize,
    lines: Vec<u8>,
    glyphs: Vec<Option<char>>,
    inks: Vec<Ink>,
}

impl Canvas {
    pub fn new(x0: i64, y0: i64, width: usize, height: usize) -> Self {
        let cells = width * height;
        Self {
            x0,
            y0,
            width,
            height,
            lines: vec![0; cells],
            glyphs: vec![None; cells],
            inks: vec![Ink::Blank; cells],
        }
    }

    fn index(&self, x: i64, y: i64) -> Option<usize> {
        let (cx, cy) = (x - self.x0, y - self.y0);
        (cx >= 0 && cy >= 0 && (cx as usize) < self.width && (cy as usize) < self.height)
            .then(|| cy as usize * self.width + cx as usize)
    }

    /// The character and ink at a cell of the window.
    pub fn cell(&self, column: usize, row: usize) -> (char, Ink) {
        let at = row * self.width + column;
        let glyph = self.glyphs[at].unwrap_or_else(|| line_glyph(self.lines[at]));
        (glyph, self.inks[at])
    }

    fn put(&mut self, x: i64, y: i64, glyph: char, ink: Ink) {
        if let Some(at) = self.index(x, y) {
            self.glyphs[at] = Some(glyph);
            self.inks[at] = ink;
        }
    }

    fn join(&mut self, x: i64, y: i64, bits: u8, ink: Ink) {
        if let Some(at) = self.index(x, y) {
            self.lines[at] |= bits;
            self.inks[at] = ink;
        }
    }

    /// Paint one route, only where it crosses the window.
    pub fn route(&mut self, route: &Route, kind: EdgeKind) {
        let ink = Ink::Edge(kind);
        // The first cell is joined to the box it leaves: above it for an edge
        // drawn downward, below it for a back edge.
        if let Some(&(x, y)) = route.points.first() {
            let stub = if route.upward { DOWN } else { UP };
            self.join(i64::from(x), i64::from(y), stub, ink);
        }
        for pair in route.points.windows(2) {
            let (ax, ay) = (i64::from(pair[0].0), i64::from(pair[0].1));
            let (bx, by) = (i64::from(pair[1].0), i64::from(pair[1].1));
            if ax == bx {
                self.vertical(ax, ay.min(by), ay.max(by), ink);
            } else {
                self.horizontal(ay, ax.min(bx), ax.max(bx), ink);
            }
        }
        if let Some(&(x, y)) = route.points.last() {
            let arrow = if route.upward { '^' } else { 'v' };
            self.put(i64::from(x), i64::from(y), arrow, ink);
        }
    }

    /// A vertical run from row `lo` to row `hi`, clipped to the window and
    /// one cell past it, so the cells at its edge are joined as the whole
    /// drawing joins them.
    fn vertical(&mut self, x: i64, lo: i64, hi: i64, ink: Ink) {
        for y in lo.max(self.y0 - 1)..hi.min(self.y0 + self.height as i64) {
            self.join(x, y, DOWN, ink);
            self.join(x, y + 1, UP, ink);
        }
    }

    fn horizontal(&mut self, y: i64, lo: i64, hi: i64, ink: Ink) {
        for x in lo.max(self.x0 - 1)..hi.min(self.x0 + self.width as i64) {
            self.join(x, y, RIGHT, ink);
            self.join(x + 1, y, LEFT, ink);
        }
    }

    /// Paint one block's box: its border, its header, and its lines.
    pub fn block(&mut self, placed: Placed, address: u64, lines: &[String], selected: bool) {
        let (x, y) = (i64::from(placed.x), i64::from(placed.y));
        let (w, h) = (i64::from(placed.width), i64::from(placed.height));
        if x + w <= self.x0
            || y + h <= self.y0
            || x >= self.x0 + self.width as i64
            || y >= self.y0 + self.height as i64
        {
            return;
        }
        let border = if selected { Ink::Selected } else { Ink::Border };
        for (row, column) in (0..h).flat_map(|row| (0..w).map(move |column| (row, column))) {
            let glyph = frame_glyph(row, column, w, h);
            let ink = if glyph == ' ' { Ink::Text } else { border };
            self.put(x + column, y + row, glyph, ink);
        }
        let width = (w - 4).max(0) as usize;
        let header = header(address);
        let rows = std::iter::once((header.as_str(), Ink::Header))
            .chain(lines.iter().map(|line| (line.as_str(), Ink::Text)))
            .take((h - 2).max(0) as usize);
        for (row, (text, ink)) in rows.enumerate() {
            self.write(x + 2, y + 1 + row as i64, &fitted(text, width), ink);
        }
    }

    fn write(&mut self, x: i64, y: i64, text: &str, ink: Ink) {
        for (column, glyph) in text.chars().enumerate() {
            self.put(x + column as i64, y, glyph, ink);
        }
    }

    /// The window as text, each row's trailing blanks dropped.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for row in 0..self.height {
            let line = (0..self.width)
                .map(|column| self.cell(column, row).0)
                .collect::<String>();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

/// A box's border at one cell of a `w` by `h` box; blank inside.
fn frame_glyph(row: i64, column: i64, w: i64, h: i64) -> char {
    let (top, bottom) = (row == 0, row == h - 1);
    let (left, right) = (column == 0, column == w - 1);
    match (top, bottom, left, right) {
        (true, _, true, _) => '┌',
        (true, _, _, true) => '┐',
        (_, true, true, _) => '└',
        (_, true, _, true) => '┘',
        (true, _, _, _) | (_, true, _, _) => '─',
        (_, _, true, _) | (_, _, _, true) => '│',
        _ => ' ',
    }
}

/// `text` cut to `width` characters, ending in `…` when it was longer.
fn fitted(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut cut = text
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    cut.push('…');
    cut
}

fn line_glyph(bits: u8) -> char {
    match bits {
        0 => ' ',
        b if b == UP | DOWN || b == UP || b == DOWN => '│',
        b if b == LEFT | RIGHT || b == LEFT || b == RIGHT => '─',
        b if b == DOWN | RIGHT => '┌',
        b if b == DOWN | LEFT => '┐',
        b if b == UP | RIGHT => '└',
        b if b == UP | LEFT => '┘',
        b if b == UP | DOWN | RIGHT => '├',
        b if b == UP | DOWN | LEFT => '┤',
        b if b == DOWN | LEFT | RIGHT => '┬',
        b if b == UP | LEFT | RIGHT => '┴',
        _ => '┼',
    }
}

/// Paint the window of a laid-out graph: edges first, boxes over them.
pub fn paint(
    graph: &Graph,
    layout: &Layout,
    canvas: &mut Canvas,
    selected: Option<usize>,
    mini: bool,
) {
    for (edge, route) in graph.edges.iter().zip(&layout.routes) {
        canvas.route(route, edge.kind);
    }
    for (index, (node, placed)) in graph.nodes.iter().zip(&layout.boxes).enumerate() {
        let lines: &[String] = if mini { &[] } else { &node.lines };
        canvas.block(*placed, node.address, lines, selected == Some(index));
    }
}

/// The whole graph drawn as text: `agf`.
pub fn text(graph: &Graph) -> String {
    let layout = lay_out(graph, false);
    let mut canvas = Canvas::new(0, 0, layout.width as usize, layout.height as usize);
    paint(graph, &layout, &mut canvas, None, false);
    let mut out = String::new();
    if let Some(note) = &graph.note {
        out.push_str(&format!("; {note}\n"));
    }
    out.push_str(&canvas.text());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{GraphEdge, GraphNode};

    fn branch() -> Graph {
        let node = |address, lines: &[&str]| GraphNode {
            address,
            size: 4,
            lines: lines.iter().map(|line| (*line).to_owned()).collect(),
        };
        Graph {
            entry: 0x10,
            nodes: vec![
                node(0x10, &["test edi, edi", "je 0x1a"]),
                node(0x14, &["mov eax, 2", "ret"]),
                node(0x1a, &["mov eax, 3", "ret"]),
            ],
            edges: vec![
                GraphEdge {
                    from: 0,
                    to: 2,
                    kind: EdgeKind::Taken,
                },
                GraphEdge {
                    from: 0,
                    to: 1,
                    kind: EdgeKind::NotTaken,
                },
            ],
            note: None,
        }
    }

    /// `agf` of a two-way branch: the entry above, both arms below it, joined
    /// by two arrows that end on the arms' tops.
    #[test]
    fn a_branch_is_drawn_as_its_entry_over_its_two_arms() {
        let drawn = text(&branch());
        let rows = drawn.lines().collect::<Vec<_>>();
        let row_of = |needle: &str| rows.iter().position(|row| row.contains(needle));
        let entry = row_of("[0x10]").expect("the entry is drawn");
        let left = row_of("[0x14]").expect("an arm is drawn");
        let right = row_of("[0x1a]").expect("an arm is drawn");
        assert!(entry < left && left == right, "{drawn}");
        assert!(drawn.contains("test edi, edi"), "{drawn}");
        // Both arrows sit on the row just above the arms' boxes, and nowhere else.
        let arrows = |row: &str| row.chars().filter(|glyph| *glyph == 'v').count();
        assert_eq!(arrows(rows[left - 2]), 2, "{drawn}");
        assert!(
            rows[..left - 2].iter().all(|row| arrows(row) == 0),
            "{drawn}"
        );
    }

    /// A window paints exactly the cells the whole drawing has there.
    #[test]
    fn a_window_is_the_whole_drawing_cut_to_it() {
        let graph = branch();
        let layout = lay_out(&graph, false);
        let (w, h) = (layout.width as usize, layout.height as usize);
        let mut whole = Canvas::new(0, 0, w, h);
        paint(&graph, &layout, &mut whole, None, false);
        let mut window = Canvas::new(3, 4, 9, 5);
        paint(&graph, &layout, &mut window, None, false);
        for row in 0..5 {
            for column in 0..9 {
                assert_eq!(
                    window.cell(column, row).0,
                    whole.cell(column + 3, row + 4).0,
                    "{column} {row}"
                );
            }
        }
    }
}
