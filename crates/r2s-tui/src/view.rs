//! Drawing: the title bar, the pane in front, and the status and prompt lines.

use crate::app::{App, Message, Prompt, View, matches_filter};
use crate::host::{Host, ListKind};
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

fn hex(app: &mut App, frame: &mut Frame<'_>, host: &mut dyn Host, area: Rect) {
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
