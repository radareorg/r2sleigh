//! Drawing: the title bar, the pane in front, and the status and prompt lines.

use crate::app::{App, GraphPane, Message, Prompt, View, matches_filter};
use crate::graph::{Canvas, Ink};
use crate::host::{DecompiledLine, EdgeKind, Host, ListKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

const CURSOR: Style = Style::new().add_modifier(Modifier::REVERSED);
const DIM: Style = Style::new().fg(Color::DarkGray);
const ADDRESS: Style = Style::new().fg(Color::Green);
const ERROR: Style = Style::new().fg(Color::Red);
const TITLE: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
const LIT: Style = Style::new().bg(Color::DarkGray);
const VIEWPORT: Style = Style::new().fg(Color::Yellow);

pub(crate) fn draw(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host) {
    let [title, main, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    app.rows = usize::from(main.height.saturating_sub(2)).max(1);

    frame.render_widget(
        Paragraph::new(format!(
            " r2s  {}  [{}]  {:#x}",
            host.title(),
            app.view.title(),
            host.seek()
        ))
        .style(TITLE),
        title,
    );

    match app.view {
        View::Disassembly => disassembly(app, frame, host, main),
        View::Decompiler => decompiler(app, frame, host, main),
        View::Hex => hex(app, frame, host, main),
        View::Graph => graph(app, frame, host, main),
        View::Split => split(app, frame, host, main),
        View::List(kind) => list(app, frame, host, main, kind),
    }

    if let Message::Output(output) = &app.message {
        let area = inset(main, 2, 1);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(output.as_str())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" output (any key) "),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    let bottom = match &app.prompt {
        Prompt::Command(text) => Line::from(format!(":{text}")),
        Prompt::Goto(text) => Line::from(format!("goto: {text}")),
        Prompt::Filter(text) => Line::from(format!("/{text}")),
        Prompt::None => match &app.message {
            Message::Info(text) => Line::from(text.as_str()),
            Message::Error(text) => Line::styled(text.as_str(), ERROR),
            Message::None | Message::Output(_) => Line::styled(help(app.view), DIM),
        },
    };
    frame.render_widget(Paragraph::new(bottom), status);
}

fn help(view: View) -> &'static str {
    match view {
        View::Disassembly => {
            "j/k move  enter follow  u back  g goto  x xrefs  p/P pane  : cmd  q quit"
        }
        View::Decompiler => "j/k move (seeks)  u back  g goto  p/P pane  : cmd  q quit",
        View::Hex => "arrows move  i edit (esc ends)  g goto  p/P pane  : cmd  q quit",
        View::Graph => {
            "hjkl pan  tab block  t/f true/false  . centre  -/+ zoom  m map  enter disasm  q quit"
        }
        View::Split => "j/k move  enter follow  u back  g goto  p/P pane  : cmd  q quit",
        View::List(_) => "j/k move  enter seek  / filter  l next list  p/P pane  : cmd  q quit",
    }
}

fn pane(title: String) -> Block<'static> {
    Block::default().borders(Borders::ALL).title(title)
}

fn disassembly(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
    app.listed = host.disassemble(app.top, app.rows);
    app.cursor = app.cursor.min(app.listed.len().saturating_sub(1));
    let lines = app
        .listed
        .iter()
        .enumerate()
        .map(|(row, line)| {
            let mut spans = vec![Span::styled(format!("{:#010x}  ", line.address), ADDRESS)];
            spans.push(Span::raw(line.text.clone()));
            if let Some(target) = line.target {
                spans.push(Span::styled(format!("  -> {target:#x}"), DIM));
            }
            let text = Line::from(spans);
            if row == app.cursor {
                text.style(CURSOR)
            } else {
                text
            }
        })
        .collect::<Vec<_>>();
    let body = if lines.is_empty() {
        vec![Line::styled("nothing mapped here", ERROR)]
    } else {
        lines
    };
    frame.render_widget(
        Paragraph::new(body).block(pane(" disassembly ".to_owned())),
        area,
    );
}

/// Make the held rendering the function's at the seek; whether it was asked
/// for now.
///
/// The rendering is the function's, so it is kept while the seek stays
/// between the lowest and highest instruction its lines were rendered from --
/// an instruction no line names (a prologue's push) is still the function's --
/// and asked for again only when the seek leaves that span. O(lines) per draw.
fn decompiled(app: &mut App, host: &mut dyn Host) -> bool {
    let seek = host.seek();
    let inside = |lines: &[DecompiledLine]| {
        let addresses = || lines.iter().flat_map(|line| line.addresses.iter().copied());
        match (addresses().min(), addresses().max()) {
            (Some(low), Some(high)) => (low..=high).contains(&seek),
            _ => false,
        }
    };
    let stale = match &app.decompiled {
        Some((_, Ok(lines))) => !inside(lines),
        Some((at, Err(_))) => *at != seek,
        None => true,
    };
    if stale {
        app.decompiled = Some((seek, host.decompile(seek)));
    }
    stale
}

/// The rows of a rendering from `skip`, highlighted as C, with `lit` lines
/// marked and the line at `cursor` reversed.
fn decompiled_rows(
    lines: &[DecompiledLine],
    skip: usize,
    rows: usize,
    cursor: Option<usize>,
    lit: impl Fn(&DecompiledLine) -> bool,
) -> Vec<Line<'static>> {
    // Whether a comment opened above the window is still open at its top.
    let mut in_comment = false;
    for line in &lines[..skip.min(lines.len())] {
        crate::highlight::classify(&line.text, &mut in_comment);
    }
    lines
        .iter()
        .enumerate()
        .skip(skip)
        .take(rows)
        .map(|(row, line)| {
            let text = Line::from(crate::highlight::spans(&line.text, &mut in_comment));
            if cursor == Some(row) {
                text.style(CURSOR)
            } else if lit(line) {
                text.style(LIT)
            } else {
                text
            }
        })
        .collect()
}

/// The pane's title: what the proof comment says, where the rendering has one.
fn decompiler_title(lines: &[DecompiledLine]) -> String {
    match lines
        .iter()
        .find_map(|line| crate::highlight::proof(&line.text))
    {
        Some(proof) => format!(" decompiler -- {proof} "),
        None => " decompiler ".to_owned(),
    }
}

fn decompiler(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
    let seek = host.seek();
    if decompiled(app, host)
        && let Some((_, Ok(lines))) = &app.decompiled
    {
        // Land on the line the seek was rendered into.
        app.cursor = lines
            .iter()
            .position(|line| line.addresses.binary_search(&seek).is_ok())
            .unwrap_or(0);
    }
    let (body, title) = match &app.decompiled {
        Some((_, Ok(lines))) => {
            let skip = app.cursor.saturating_sub(app.rows.saturating_sub(1));
            let body = decompiled_rows(lines, skip, app.rows, Some(app.cursor), |_| false);
            (body, decompiler_title(lines))
        }
        Some((_, Err(error))) => (
            vec![Line::styled(error.clone(), ERROR)],
            " decompiler ".to_owned(),
        ),
        None => (Vec::new(), " decompiler ".to_owned()),
    };
    frame.render_widget(Paragraph::new(body).block(pane(title)), area);
}

/// The disassembly beside the C: the cursor moves in the disassembly, and
/// every line of C rendered from the instruction under it is lit, the first
/// of them kept in view.
fn split(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    disassembly(app, frame, host, left);
    // The disassembly seeks the line under its cursor as it moves; this
    // reads the same line, so the two never disagree by a draw.
    let under = app.listed.get(app.cursor).map(|line| line.address);
    decompiled(app, host);
    let rows = usize::from(right.height.saturating_sub(2)).max(1);
    let (body, title) = match &app.decompiled {
        Some((_, Ok(lines))) => {
            let lit = |line: &DecompiledLine| {
                under.is_some_and(|address| line.addresses.binary_search(&address).is_ok())
            };
            let first = lines.iter().position(lit).unwrap_or(0);
            let skip = first.saturating_sub(rows / 3);
            (
                decompiled_rows(lines, skip, rows, None, lit),
                decompiler_title(lines),
            )
        }
        Some((_, Err(error))) => (
            vec![Line::styled(error.clone(), ERROR)],
            " decompiler ".to_owned(),
        ),
        None => (Vec::new(), " decompiler ".to_owned()),
    };
    frame.render_widget(Paragraph::new(body).block(pane(title)), right);
}

fn hex(app: &App, frame: &mut Frame<'_>, host: &dyn Host, area: Rect) {
    let bytes = host.read(app.top, app.rows * 16);
    let mut lines = Vec::with_capacity(app.rows);
    for row in 0..app.rows {
        let start = row * 16;
        let address = app.top + start as u64;
        let chunk = bytes.get(start..).map(|rest| &rest[..rest.len().min(16)]);
        let Some(chunk) = chunk.filter(|chunk| !chunk.is_empty()) else {
            break;
        };
        let mut spans = vec![Span::styled(format!("{address:#010x}  "), ADDRESS)];
        for (column, byte) in chunk.iter().enumerate() {
            let here = start + column == app.cursor;
            let text = match (here, app.editing) {
                (true, Some(Some(high))) => format!("{high:x}_"),
                _ => format!("{byte:02x}"),
            };
            spans.push(Span::styled(text, if here { CURSOR } else { Style::new() }));
            spans.push(Span::raw(if column == 7 { "  " } else { " " }));
        }
        spans.push(Span::raw(" ".repeat((16 - chunk.len()) * 3 + 1)));
        let ascii: String = chunk
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                }
            })
            .collect();
        spans.push(Span::styled(ascii, DIM));
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::styled("nothing mapped here", ERROR));
    }
    let title = match app.editing {
        Some(_) => " hex [edit] ".to_owned(),
        None => " hex ".to_owned(),
    };
    frame.render_widget(Paragraph::new(lines).block(pane(title)), area);
}

fn list(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect, kind: ListKind) {
    if app.entries.as_ref().is_none_or(|(held, _)| *held != kind) {
        app.entries = Some((kind, host.list(kind)));
    }
    let entries = app.visible_entries();
    let len = entries.len();
    let cursor = app.cursor.min(len.saturating_sub(1));
    let skip = cursor.saturating_sub(app.rows.saturating_sub(1));
    let body = entries
        .iter()
        .enumerate()
        .skip(skip)
        .take(app.rows)
        .map(|(row, entry)| {
            let text = Line::from(vec![
                Span::styled(format!("{:#010x}  ", entry.address), ADDRESS),
                Span::raw(entry.text.clone()),
            ]);
            if row == cursor {
                text.style(CURSOR)
            } else {
                text
            }
        })
        .collect::<Vec<_>>();
    let total = app.entries.as_ref().map_or(0, |(_, all)| all.len());
    let title = if app.filter.is_empty() {
        format!(" {} ({total}) ", kind.title())
    } else {
        debug_assert!(entries.iter().all(|e| matches_filter(&e.text, &app.filter)));
        format!(" {} ({len}/{total}) /{} ", kind.title(), app.filter)
    };
    frame.render_widget(Paragraph::new(body).block(pane(title)), area);
}

fn inset(area: Rect, x: u16, y: u16) -> Rect {
    Rect {
        x: area.x + x.min(area.width / 2),
        y: area.y + y.min(area.height / 2),
        width: area.width.saturating_sub(2 * x),
        height: area.height.saturating_sub(2 * y),
    }
}

/// The graph pane: the function holding the seek, laid out once and painted
/// through the window.
/// Make the held graph the function's at the seek, selecting the block the
/// seek is in; laid out only when the seek leaves the held function.
fn held_graph(app: &mut App, host: &mut dyn Host) {
    let seek = host.seek();
    let held = app.graph.as_ref().map(|pane| match &pane.drawn {
        Ok((graph, _)) => graph.node_at(seek),
        Err(_) if pane.at == seek => Some(0),
        Err(_) => None,
    });
    match held {
        Some(Some(node)) => {
            if let Some(pane) = &mut app.graph
                && pane.selected != node
                && pane.drawn.is_ok()
            {
                pane.selected = node;
                pane.recentre = true;
            }
        }
        _ => {
            let drawn = host.graph(seek).map(|graph| {
                let layout = crate::graph::lay_out(&graph, false);
                (graph, layout)
            });
            let selected = match &drawn {
                Ok((graph, _)) => graph
                    .node_at(seek)
                    .or_else(|| graph.node_at(graph.entry))
                    .unwrap_or(0),
                Err(_) => 0,
            };
            app.graph = Some(GraphPane {
                at: seek,
                drawn,
                selected,
                scroll: (0, 0),
                mini: false,
                recentre: true,
                minimap: true,
            });
        }
    }
}

fn graph(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
    held_graph(app, host);
    let Some(pane) = &mut app.graph else {
        return;
    };
    let block = pane_title(pane);
    let inner = block.inner(area);
    let (graph, layout) = match &pane.drawn {
        Ok(drawn) => drawn,
        Err(error) => {
            frame.render_widget(
                Paragraph::new(Line::styled(error.clone(), ERROR)).block(block),
                area,
            );
            return;
        }
    };
    if pane.recentre && !layout.boxes.is_empty() {
        let placed = layout.boxes[pane.selected.min(layout.boxes.len() - 1)];
        let centre = i64::from(placed.x) + i64::from(placed.width) / 2;
        pane.scroll.0 = (centre - i64::from(inner.width) / 2).max(0);
        pane.scroll.1 = (i64::from(placed.y) - 2).max(0);
        pane.recentre = false;
    }
    frame.render_widget(block, area);
    let mut canvas = Canvas::new(
        pane.scroll.0,
        pane.scroll.1,
        usize::from(inner.width),
        usize::from(inner.height),
    );
    crate::graph::paint(graph, layout, &mut canvas, Some(pane.selected), pane.mini);
    let buffer = frame.buffer_mut();
    for row in 0..canvas.height {
        for column in 0..canvas.width {
            let (glyph, ink) = canvas.cell(column, row);
            if glyph == ' ' {
                continue;
            }
            let cell = &mut buffer[(inner.x + column as u16, inner.y + row as u16)];
            cell.set_char(glyph);
            cell.set_style(ink_style(ink));
        }
    }
    if pane.minimap {
        minimap(frame, inner, layout, pane);
    }
}

/// The whole layout scaled into a corner, with the window drawn on it.
///
/// Drawn only where the layout does not already fit the window; each block
/// is a run of `▪` at its scaled place, the selected one bright.
fn minimap(frame: &mut Frame<'_>, inner: Rect, layout: &crate::graph::Layout, pane: &GraphPane) {
    let (width, height) = (i64::from(layout.width), i64::from(layout.height));
    let fits = width <= i64::from(inner.width) && height <= i64::from(inner.height);
    let map_w = (inner.width / 4).clamp(8, 32);
    let map_h = (inner.height / 3).clamp(4, 12);
    if fits || inner.width < map_w + 4 || inner.height < map_h + 2 {
        return;
    }
    let area = Rect {
        x: inner.x + inner.width - map_w - 2,
        y: inner.y + inner.height - map_h - 2,
        width: map_w + 2,
        height: map_h + 2,
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().borders(Borders::ALL).border_style(DIM),
        area,
    );
    let (map_w, map_h) = (i64::from(map_w), i64::from(map_h));
    // One cell of the map is `scale` cells of the layout, the same on both axes
    // so the shape is kept; rounded up so the whole layout fits.
    let scale = ((width + map_w - 1) / map_w)
        .max((height + map_h - 1) / map_h)
        .max(1);
    let buffer = frame.buffer_mut();
    let mut put = |x: i64, y: i64, glyph: char, style: Style| {
        if (0..map_w).contains(&x) && (0..map_h).contains(&y) {
            let cell = &mut buffer[(area.x + 1 + x as u16, area.y + 1 + y as u16)];
            cell.set_char(glyph);
            cell.set_style(style);
        }
    };
    for (index, placed) in layout.boxes.iter().enumerate() {
        let style = if index == pane.selected {
            VIEWPORT
        } else {
            DIM
        };
        let (x0, y0) = (i64::from(placed.x) / scale, i64::from(placed.y) / scale);
        let x1 = (i64::from(placed.x + placed.width) / scale).max(x0 + 1);
        let y1 = (i64::from(placed.y + placed.height) / scale).max(y0 + 1);
        for y in y0..y1 {
            for x in x0..x1 {
                put(x, y, '▪', style);
            }
        }
    }
    // The window's outline.
    let (wx0, wy0) = (pane.scroll.0 / scale, pane.scroll.1 / scale);
    let wx1 = (pane.scroll.0 + i64::from(inner.width)) / scale;
    let wy1 = (pane.scroll.1 + i64::from(inner.height)) / scale;
    for x in wx0..=wx1 {
        put(x, wy0, '─', VIEWPORT);
        put(x, wy1, '─', VIEWPORT);
    }
    for y in wy0..=wy1 {
        put(wx0, y, '│', VIEWPORT);
        put(wx1, y, '│', VIEWPORT);
    }
}

fn pane_title(held: &GraphPane) -> Block<'static> {
    let title = match &held.drawn {
        Ok((graph, _)) => {
            let note = graph
                .note
                .as_deref()
                .map_or(String::new(), |note| format!(" -- {note}"));
            format!(
                " graph {:#x}  {} blocks  {} edges{} ",
                graph.entry,
                graph.nodes.len(),
                graph.edges.len(),
                note
            )
        }
        Err(_) => " graph ".to_owned(),
    };
    pane(title)
}

/// radare2's edge colours: true green, false red, unconditional blue.
fn ink_style(ink: Ink) -> Style {
    match ink {
        Ink::Edge(EdgeKind::Taken) => Style::new().fg(Color::Green),
        Ink::Edge(EdgeKind::NotTaken) => Style::new().fg(Color::Red),
        Ink::Edge(EdgeKind::Jump | EdgeKind::Fall) => Style::new().fg(Color::Blue),
        Ink::Edge(EdgeKind::Case) => Style::new().fg(Color::Magenta),
        Ink::Edge(EdgeKind::Default) => Style::new().fg(Color::Yellow),
        Ink::Selected => Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        Ink::Header => ADDRESS,
        Ink::Border | Ink::Text | Ink::Blank => Style::new(),
    }
}
