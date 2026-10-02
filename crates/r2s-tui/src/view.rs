//! Drawing: the title bar, the pane in front, and the status and prompt lines.

use crate::app::{App, GraphPane, Message, Prompt, View, matches_filter};
use crate::graph::{Canvas, Ink};
use crate::host::{EdgeKind, Host, ListKind};
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
            "hjkl pan  tab block  t/f true/false  . centre  -/+ zoom  enter disasm  u back  q quit"
        }
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

fn decompiler(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
    let seek = host.seek();
    // The rendering is the function's, so it is kept while the cursor stays
    // in the lines it covers and asked for again only when it leaves them.
    let covers = |lines: &[crate::host::DecompiledLine]| {
        lines
            .iter()
            .any(|line| line.addresses.binary_search(&seek).is_ok())
    };
    let stale = match &app.decompiled {
        Some((_, Ok(lines))) => !covers(lines),
        Some((at, Err(_))) => *at != seek,
        None => true,
    };
    if stale {
        app.decompiled = Some((seek, host.decompile(seek)));
        // Land on the line the seek was rendered into.
        if let Some((_, Ok(lines))) = &app.decompiled {
            app.cursor = lines
                .iter()
                .position(|line| line.addresses.binary_search(&seek).is_ok())
                .unwrap_or(0);
        }
    }
    let body = match &app.decompiled {
        Some((_, Ok(lines))) => {
            let skip = app.cursor.saturating_sub(app.rows.saturating_sub(1));
            lines
                .iter()
                .enumerate()
                .skip(skip)
                .take(app.rows)
                .map(|(row, line)| {
                    let style = if row == app.cursor {
                        CURSOR
                    } else if line.text.contains("r2sleigh_residual") {
                        ERROR
                    } else if line.text.trim_start().starts_with("/*") {
                        DIM
                    } else {
                        Style::new()
                    };
                    Line::styled(line.text.clone(), style)
                })
                .collect::<Vec<_>>()
        }
        Some((_, Err(error))) => vec![Line::styled(error.clone(), ERROR)],
        None => Vec::new(),
    };
    frame.render_widget(
        Paragraph::new(body).block(pane(" decompiler ".to_owned())),
        area,
    );
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
fn graph(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
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
            });
        }
    }
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
