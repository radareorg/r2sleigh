//! The visual mode's state and its keys.
//!
//! One cursor, shared by every pane: moving it in one pane is seeking, and the
//! next pane opens where the last one left it, as in radare2. The keys are
//! radare2's where it has one -- `p`/`P` to cycle panes, `g` to go, `x` for
//! the references to the cursor, `:` for a command, `u` to go back, `q` to
//! leave.

use crate::host::{DecompiledLine, Entry, Host, ListKind, ListedLine};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;

/// The pane in front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Disassembly,
    Decompiler,
    Hex,
    List(ListKind),
}

impl View {
    /// The order `p` steps through, as radare2's print modes cycle.
    const CYCLE: [View; 4] = [
        View::Disassembly,
        View::Decompiler,
        View::Hex,
        View::List(ListKind::Functions),
    ];

    fn next(self, step: isize) -> View {
        let at = View::CYCLE
            .iter()
            .position(|view| match (view, self) {
                (View::List(_), View::List(_)) => true,
                (view, current) => *view == current,
            })
            .unwrap_or(0);
        let len = View::CYCLE.len() as isize;
        View::CYCLE[(at as isize + step).rem_euclid(len) as usize]
    }

    pub fn title(self) -> String {
        match self {
            View::Disassembly => "disassembly".to_owned(),
            View::Decompiler => "decompiler".to_owned(),
            View::Hex => "hex".to_owned(),
            View::List(kind) => kind.title().to_owned(),
        }
    }
}

/// What the bottom line is collecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Prompt {
    None,
    /// `:` -- a shell command.
    Command(String),
    /// `g` -- an address or a name to seek to.
    Goto(String),
    /// `/` in a list -- a filter.
    Filter(String),
}

/// What the last action said, shown until the next key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    None,
    Info(String),
    Error(String),
    /// A command's whole output, shown as a pane over the view.
    Output(String),
}

pub struct App {
    pub(crate) view: View,
    /// The address the disassembly and hex panes start at.
    pub(crate) top: u64,
    /// The cursor's line (disassembly, decompiler, list) or byte (hex),
    /// counted from the top of the pane.
    pub(crate) cursor: usize,
    /// Where `u` goes back to.
    pub(crate) history: Vec<u64>,
    pub(crate) prompt: Prompt,
    pub(crate) message: Message,
    /// The rows the last draw showed, so a key acts on what is on screen.
    pub(crate) listed: Vec<ListedLine>,
    pub(crate) decompiled: Option<(u64, Result<Vec<DecompiledLine>, String>)>,
    pub(crate) entries: Option<(ListKind, Vec<Entry>)>,
    pub(crate) filter: String,
    /// The hex pane's pending high nibble while editing.
    pub(crate) editing: Option<Option<u8>>,
    /// How many rows the main pane had at the last draw.
    pub(crate) rows: usize,
}

impl App {
    pub fn new(host: &dyn Host) -> Self {
        Self {
            view: View::Disassembly,
            top: host.seek(),
            cursor: 0,
            history: Vec::new(),
            prompt: Prompt::None,
            message: Message::None,
            listed: Vec::new(),
            decompiled: None,
            entries: None,
            filter: String::new(),
            editing: None,
            rows: 24,
        }
    }

    pub fn view(&self) -> View {
        self.view
    }

    pub fn draw(&mut self, frame: &mut Frame<'_>, host: &mut dyn Host) {
        crate::view::draw(self, frame, host);
    }

    /// Seek, remembering where the cursor was so `u` can come back.
    fn go(&mut self, host: &mut dyn Host, address: u64) {
        self.history.push(host.seek());
        host.set_seek(address);
        self.top = address;
        self.cursor = 0;
    }

    /// The filtered rows of the list in front.
    pub(crate) fn visible_entries(&self) -> Vec<&Entry> {
        let Some((_, entries)) = &self.entries else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|entry| matches_filter(&entry.text, &self.filter))
            .collect()
    }

    /// Handle one key. `false` when the user leaves.
    pub fn handle_key(&mut self, host: &mut dyn Host, key: KeyEvent) -> bool {
        if !matches!(self.prompt, Prompt::None) {
            self.prompt_key(host, key);
            return true;
        }
        if !matches!(self.message, Message::None) {
            // Any key dismisses what the last action said; it is also acted on
            // unless it only closes an output pane.
            let was_output = matches!(self.message, Message::Output(_));
            self.message = Message::None;
            if was_output {
                return true;
            }
        }
        if self.view == View::Hex && self.editing.is_some() {
            self.edit_key(host, key);
            return true;
        }
        match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
            KeyCode::Char('p') => self.switch(self.view.next(1)),
            KeyCode::Char('P') => self.switch(self.view.next(-1)),
            KeyCode::Char(':') => self.prompt = Prompt::Command(String::new()),
            KeyCode::Char('g') => self.prompt = Prompt::Goto(String::new()),
            KeyCode::Char('u') => {
                if let Some(back) = self.history.pop() {
                    host.set_seek(back);
                    self.top = back;
                    self.cursor = 0;
                    self.decompiled = None;
                }
            }
            KeyCode::Char('x') => {
                self.entries = None;
                self.filter.clear();
                self.cursor = 0;
                self.view = View::List(ListKind::XrefsTo);
            }
            KeyCode::Char('l') if matches!(self.view, View::List(_)) => {
                if let View::List(kind) = self.view {
                    let at = ListKind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
                    self.switch(View::List(ListKind::ALL[(at + 1) % ListKind::ALL.len()]));
                }
            }
            KeyCode::Char('/') if matches!(self.view, View::List(_)) => {
                self.prompt = Prompt::Filter(self.filter.clone());
            }
            KeyCode::Char('i') if self.view == View::Hex => self.editing = Some(None),
            KeyCode::Down | KeyCode::Char('j') => self.step(host, self.row()),
            KeyCode::Up | KeyCode::Char('k') => self.step(host, -self.row()),
            KeyCode::Right if self.view == View::Hex => self.step(host, 1),
            KeyCode::Left if self.view == View::Hex => self.step(host, -1),
            KeyCode::PageDown | KeyCode::Char('J') => {
                self.step(host, self.row() * self.rows as isize)
            }
            KeyCode::PageUp | KeyCode::Char('K') => {
                self.step(host, -self.row() * self.rows as isize)
            }
            KeyCode::Enter => self.follow(host),
            _ => {}
        }
        true
    }

    /// How far one row moves the cursor: a line, or sixteen bytes in hex.
    fn row(&self) -> isize {
        if self.view == View::Hex { 16 } else { 1 }
    }

    fn switch(&mut self, view: View) {
        if view != self.view {
            self.view = view;
            self.cursor = 0;
            self.entries = None;
            self.filter.clear();
            self.editing = None;
        }
    }

    /// Move the cursor `delta` rows (bytes, in hex), scrolling the pane.
    fn step(&mut self, host: &mut dyn Host, delta: isize) {
        match self.view {
            View::Disassembly => {
                let target = self.cursor as isize + delta;
                if target < 0 {
                    for _ in 0..target.unsigned_abs() {
                        self.top = line_before(host, self.top);
                    }
                    self.cursor = 0;
                } else if target as usize >= self.rows.max(1) {
                    let lines = host.disassemble(self.top, target as usize + 1);
                    let shift = target as usize + 1 - self.rows.max(1);
                    if let Some(line) = lines.get(shift) {
                        self.top = line.address;
                    }
                    self.cursor = self.rows.max(1) - 1;
                } else {
                    self.cursor = target as usize;
                }
                if let Some(line) = host.disassemble(self.top, self.cursor + 1).last() {
                    host.set_seek(line.address);
                }
            }
            View::Hex => {
                // The cursor is a byte; the pane scrolls by whole rows.
                let page = self.rows.max(1) as isize * 16;
                let mut target = self.cursor as isize + delta;
                while target < 0 && self.top > 0 {
                    self.top = self.top.saturating_sub(16);
                    target += 16;
                }
                while target >= page {
                    self.top = self.top.saturating_add(16);
                    target -= 16;
                }
                self.cursor = target.max(0) as usize;
                host.set_seek(self.top + self.cursor as u64);
            }
            View::Decompiler => {
                let len = match &self.decompiled {
                    Some((_, Ok(lines))) => lines.len(),
                    _ => 0,
                };
                self.cursor = clamp_add(self.cursor, delta, len);
                if let Some((_, Ok(lines))) = &self.decompiled
                    && let Some(address) = lines
                        .get(self.cursor)
                        .and_then(|line| line.addresses.first())
                {
                    host.set_seek(*address);
                }
            }
            View::List(_) => {
                let len = self.visible_entries().len();
                self.cursor = clamp_add(self.cursor, delta, len);
            }
        }
    }

    /// `Enter`: follow the line's transfer, or open the chosen row.
    fn follow(&mut self, host: &mut dyn Host) {
        match self.view {
            View::Disassembly => {
                let target = self.listed.get(self.cursor).and_then(|line| line.target);
                match target {
                    Some(target) => {
                        self.go(host, target);
                        self.message = Message::Info(format!("seek {target:#x}"));
                    }
                    None => self.message = Message::Info("no transfer on this line".to_owned()),
                }
            }
            View::List(_) => {
                let chosen = self
                    .visible_entries()
                    .get(self.cursor)
                    .map(|entry| entry.address);
                if let Some(address) = chosen {
                    self.go(host, address);
                    self.switch(View::Disassembly);
                }
            }
            View::Decompiler | View::Hex => {}
        }
    }

    fn prompt_key(&mut self, host: &mut dyn Host, key: KeyEvent) {
        let text = match &mut self.prompt {
            Prompt::Command(text) | Prompt::Goto(text) | Prompt::Filter(text) => text,
            Prompt::None => return,
        };
        match key.code {
            KeyCode::Esc => self.prompt = Prompt::None,
            KeyCode::Backspace => {
                text.pop();
                if let Prompt::Filter(filter) = &self.prompt {
                    self.filter = filter.clone();
                    self.cursor = 0;
                }
            }
            KeyCode::Char(c) => {
                text.push(c);
                if let Prompt::Filter(filter) = &self.prompt {
                    self.filter = filter.clone();
                    self.cursor = 0;
                }
            }
            KeyCode::Enter => {
                let prompt = std::mem::replace(&mut self.prompt, Prompt::None);
                match prompt {
                    Prompt::Command(command) if !command.trim().is_empty() => {
                        let before = host.seek();
                        self.message = match host.run(&command) {
                            Ok(output) if output.trim().is_empty() => Message::None,
                            Ok(output) => Message::Output(output),
                            Err(error) => Message::Error(error),
                        };
                        // A command may have written or sought: show what is
                        // there now.
                        self.decompiled = None;
                        self.entries = None;
                        if host.seek() != before {
                            self.history.push(before);
                            self.top = host.seek();
                            self.cursor = 0;
                        }
                    }
                    Prompt::Goto(target) => self.goto(host, &target),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// `g`: seek through the shell's own `s`, so an address expression or a
    /// name means what it means at the prompt.
    fn goto(&mut self, host: &mut dyn Host, target: &str) {
        let target = target.trim();
        if target.is_empty() {
            return;
        }
        let before = host.seek();
        match host.run(&format!("s {target}")) {
            Ok(_) => {
                let after = host.seek();
                host.set_seek(before);
                self.go(host, after);
                self.decompiled = None;
            }
            Err(error) => self.message = Message::Error(error),
        }
    }

    /// The hex pane's edit mode: two hex digits write one byte at the cursor
    /// and move on; `Esc` leaves.
    fn edit_key(&mut self, host: &mut dyn Host, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.editing = None,
            KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                let nibble = c.to_digit(16).unwrap_or(0) as u8;
                match self.editing {
                    Some(None) => self.editing = Some(Some(nibble)),
                    Some(Some(high)) => {
                        let address = self.top + self.cursor as u64;
                        match host.write(address, &[high << 4 | nibble]) {
                            Ok(()) => {
                                self.editing = Some(None);
                                self.step(host, 1);
                            }
                            Err(error) => {
                                self.editing = None;
                                self.message = Message::Error(error);
                            }
                        }
                    }
                    None => {}
                }
            }
            KeyCode::Right => self.step(host, 1),
            KeyCode::Left => self.step(host, -1),
            KeyCode::Down => self.step(host, 16),
            KeyCode::Up => self.step(host, -16),
            _ => {}
        }
    }
}

/// The address of the instruction that ends where `top` starts.
///
/// An instruction stream does not decode backwards, so the line before is found
/// forwards: decode from each of the fifteen bytes before `top`, furthest
/// first, and take the line that ends exactly at `top` in the first stream
/// that lands on it. A stream that lands nowhere leaves one byte as the line.
fn line_before(host: &mut dyn Host, top: u64) -> u64 {
    for back in (1..=15u64).rev() {
        let Some(start) = top.checked_sub(back) else {
            continue;
        };
        let lines = host.disassemble(start, back as usize + 1);
        if let Some(line) = lines
            .iter()
            .find(|line| line.address.checked_add(line.size) == Some(top))
        {
            return line.address;
        }
    }
    top.saturating_sub(1)
}

fn clamp_add(cursor: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (cursor as isize + delta).clamp(0, len as isize - 1) as usize
}

/// A row matches when the filter's characters appear in it in order,
/// ignoring case: `mlc` finds `malloc`.
pub(crate) fn matches_filter(text: &str, filter: &str) -> bool {
    let mut wanted = filter.chars().flat_map(char::to_lowercase).peekable();
    for c in text.chars().flat_map(char::to_lowercase) {
        if wanted.peek() == Some(&c) {
            wanted.next();
        }
    }
    wanted.peek().is_none()
}
