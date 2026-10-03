//! The visual mode's state, and how a message changes it.
//!
//! One cursor, shared by every pane: moving it in one pane is seeking, and the
//! next pane opens where the last one left it, as in radare2. The keys are
//! radare2's where it has one -- `p`/`P` to cycle panes, `g` to go, `x` for
//! the references to the cursor, `:` for a command, `u` to go back, `q` to
//! leave.
//!
//! [`App::update`] is the only thing that changes the state, and it never
//! asks the engine: what a pane needs that the state does not hold is
//! returned as a [`Request`] for the engine's thread, and its answer comes
//! back as a [`Msg`]. [`App::draw`] reads the state and nothing else, so a
//! frame is drawn in the time it takes to lay it out, whatever the engine is
//! doing.

use crate::graph::Layout;
use crate::host::{DecompiledLine, EdgeKind, Entry, Graph, ListKind, ListedLine};
use crate::worker::{Answer, Fetched, Key, Request, Window};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use std::collections::{BTreeMap, VecDeque};

/// The pane in front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Disassembly,
    Decompiler,
    Hex,
    /// `VV`: the function's control-flow graph.
    Graph,
    /// The disassembly beside the decompiled C, each line of C lit while
    /// the instruction under the cursor is one it was rendered from.
    Split,
    List(ListKind),
}

impl View {
    /// The order `p` steps through, as radare2's print modes cycle.
    const CYCLE: [View; 6] = [
        View::Disassembly,
        View::Decompiler,
        View::Hex,
        View::Graph,
        View::Split,
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
            View::Graph => "graph".to_owned(),
            View::Split => "disassembly | decompiler".to_owned(),
            View::List(kind) => kind.title().to_owned(),
        }
    }
}

/// Everything that changes the visual mode, in one stream: the terminal's
/// events, the engine's answers, and the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Key(KeyEvent),
    Mouse(MouseEvent),
    /// The terminal's new size, in columns and rows.
    Resize(u16, u16),
    Answer(Answer),
    /// Time passed with nothing else to say: what animates the spinner.
    Tick,
}

/// What handling a message asks of the world outside the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Send this to the engine's thread.
    Request(Request),
    /// The user left.
    Quit,
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

/// One kind of answer the state holds: the one shown, and the one asked for.
///
/// At most one request per slot is in flight. When the user moves on while it
/// is, its answer is dropped on arrival and the slot asks for what is wanted
/// then; so a slot never queues work the user has already left.
pub(crate) struct Slot<T> {
    pub(crate) held: Option<T>,
    /// The tag and key of the request in flight.
    pub(crate) asked: Option<(u64, Key)>,
    /// The program changed since `held` was answered.
    pub(crate) stale: bool,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self {
            held: None,
            asked: None,
            stale: false,
        }
    }
}

impl<T> Slot<T> {
    pub(crate) fn pending(&self) -> bool {
        self.asked.is_some()
    }
}

/// The disassembly around the address its key names.
pub(crate) struct HeldLines {
    pub(crate) key: Key,
    pub(crate) window: Window,
}

pub(crate) struct HeldBytes {
    pub(crate) at: u64,
    pub(crate) len: usize,
    pub(crate) bytes: Vec<u8>,
}

/// A rendering, and the span of instructions its lines were rendered from.
pub(crate) struct HeldRendering {
    /// The address it was asked for at.
    pub(crate) at: u64,
    pub(crate) result: Result<Vec<DecompiledLine>, String>,
    /// The lowest and highest instruction a line names.
    span: Option<(u64, u64)>,
}

impl HeldRendering {
    fn new(at: u64, result: Result<Vec<DecompiledLine>, String>) -> Self {
        let span = span(&result);
        Self { at, result, span }
    }

    /// Whether this is the rendering of the function holding `seek`.
    ///
    /// The rendering is the function's, so it holds every seek between the
    /// lowest and highest instruction its lines were rendered from -- an
    /// instruction no line names (a prologue's push) is still the
    /// function's -- and the seek it was asked at.
    fn covers(&self, seek: u64) -> bool {
        self.at == seek
            || self
                .span
                .is_some_and(|(low, high)| (low..=high).contains(&seek))
    }
}

/// The lowest and highest instruction a rendering's lines name. O(lines),
/// once per answer.
fn span(result: &Result<Vec<DecompiledLine>, String>) -> Option<(u64, u64)> {
    let lines = result.as_ref().ok()?;
    let addresses = || lines.iter().flat_map(|line| line.addresses.iter().copied());
    Some((addresses().min()?, addresses().max()?))
}

pub(crate) struct HeldList {
    pub(crate) key: Key,
    pub(crate) kind: ListKind,
    pub(crate) entries: Vec<Entry>,
}

/// The graph in front: one function's, laid out once, and the window onto it.
pub(crate) struct GraphPane {
    /// The address it was asked for at, which names a failure.
    pub(crate) at: u64,
    pub(crate) drawn: Result<(Graph, Layout), String>,
    pub(crate) selected: usize,
    /// The window's top-left cell in the layout.
    pub(crate) scroll: (i64, i64),
    /// Headers only: the whole shape of a large function at once.
    pub(crate) mini: bool,
    /// The selected block is brought into the window at the next update.
    pub(crate) recentre: bool,
    /// Whether the overview of the whole layout is drawn in a corner.
    pub(crate) minimap: bool,
}

impl GraphPane {
    fn covers(&self, seek: u64) -> bool {
        match &self.drawn {
            Ok((graph, _)) => self.at == seek || graph.node_at(seek).is_some(),
            Err(_) => self.at == seek,
        }
    }
}

/// How many answers are kept by key before the oldest is forgotten.
const CACHED: usize = 128;

/// How many rows one notch of the wheel moves.
const WHEEL: isize = 3;

pub struct App {
    /// The engine's thread has said what is open and where the cursor is.
    pub(crate) opened: bool,
    pub(crate) title: String,
    /// The shared cursor.
    pub(crate) seek: u64,
    /// The cursor the engine's thread was last told.
    synced: u64,
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
    pub(crate) filter: String,
    /// The hex pane's pending high nibble while editing.
    pub(crate) editing: Option<Option<u8>>,
    /// The terminal's size.
    pub(crate) size: (u16, u16),
    /// How many rows the main pane has inside its border.
    pub(crate) rows: usize,
    pub(crate) lines: Slot<HeldLines>,
    pub(crate) bytes: Slot<HeldBytes>,
    pub(crate) rendering: Slot<HeldRendering>,
    pub(crate) graph: Slot<GraphPane>,
    pub(crate) list: Slot<HeldList>,
    /// Disassembly lines moved over before the lines to move over arrived.
    pending_lines: isize,
    /// The decompiler's cursor is put on the seek's line once a rendering
    /// holding the seek is in hand.
    land: bool,
    /// Answers by key, until the program changes.
    cache: BTreeMap<Key, Fetched>,
    /// The cache's keys, oldest first.
    cached: VecDeque<Key>,
    next_tag: u64,
    /// Commands, seeks by name and writes in flight, the latest named.
    pub(crate) running: usize,
    pub(crate) running_what: String,
    pub(crate) ticks: usize,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            opened: false,
            title: String::new(),
            seek: 0,
            synced: 0,
            view: View::Disassembly,
            top: 0,
            cursor: 0,
            history: Vec::new(),
            prompt: Prompt::None,
            message: Message::None,
            filter: String::new(),
            editing: None,
            size: (80, 24),
            rows: 1,
            lines: Slot::default(),
            bytes: Slot::default(),
            rendering: Slot::default(),
            graph: Slot::default(),
            list: Slot::default(),
            pending_lines: 0,
            land: false,
            cache: BTreeMap::new(),
            cached: VecDeque::new(),
            next_tag: 0,
            running: 0,
            running_what: String::new(),
            ticks: 0,
        };
        app.resize(80, 24);
        app
    }

    pub fn view(&self) -> View {
        self.view
    }

    /// The shared cursor, as the visual mode holds it.
    pub fn seek(&self) -> u64 {
        self.seek
    }

    /// Whether an answer is still to come for something asked.
    pub fn waiting(&self) -> bool {
        !self.opened
            || self.running > 0
            || self.lines.pending()
            || self.bytes.pending()
            || self.rendering.pending()
            || self.graph.pending()
            || self.list.pending()
    }

    /// Draw the state. Reads nothing but the state.
    pub fn draw(&self, frame: &mut Frame<'_>) {
        crate::view::draw(self, frame);
    }

    /// Handle one message, returning what it asks of the outside.
    pub fn update(&mut self, msg: Msg) -> Vec<Effect> {
        let mut effects = Vec::new();
        match msg {
            Msg::Key(key) => {
                if !self.handle_key(key, &mut effects) {
                    effects.push(Effect::Quit);
                    return effects;
                }
            }
            Msg::Mouse(mouse) => self.mouse(mouse),
            Msg::Resize(width, height) => self.resize(width, height),
            Msg::Answer(answer) => self.answer(answer),
            Msg::Tick => self.ticks = self.ticks.wrapping_add(1),
        }
        self.sync(&mut effects);
        effects
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.size = (width, height);
        // Title and status lines, and the pane's border.
        self.rows = usize::from(height.saturating_sub(4)).max(1);
        if let Some(pane) = &mut self.graph.held {
            pane.recentre = true;
        }
    }

    /// Seek, remembering where the cursor was so `u` can come back.
    fn go(&mut self, address: u64) {
        self.history.push(self.seek);
        self.seek = address;
        self.top = address;
        self.cursor = 0;
        self.pending_lines = 0;
    }

    /// The filtered rows of the list in front.
    pub(crate) fn visible_entries(&self) -> Vec<&Entry> {
        let Some(held) = &self.list.held else {
            return Vec::new();
        };
        if !matches!(self.view, View::List(kind) if kind == held.kind) {
            return Vec::new();
        }
        held.entries
            .iter()
            .filter(|entry| matches_filter(&entry.text, &self.filter))
            .collect()
    }

    /// The disassembly lines from the pane's top, as far as they are known:
    /// the held window's, from where the top falls in it. Exact when the
    /// window is the top's own.
    pub(crate) fn shown_lines(&self) -> &[ListedLine] {
        let Some(held) = &self.lines.held else {
            return &[];
        };
        let lines = &held.window.lines;
        match lines.iter().position(|line| line.address == self.top) {
            Some(at) => &lines[at..lines.len().min(at + self.rows)],
            None => &lines[..lines.len().min(self.rows)],
        }
    }

    /// The held window, when it is the one starting at the pane's top and
    /// tall enough for the pane.
    fn window(&self) -> Option<&Window> {
        let held = self.lines.held.as_ref()?;
        (held.key == self.wanted_lines()).then_some(&held.window)
    }

    fn wanted_lines(&self) -> Key {
        Key::Lines {
            at: self.top,
            // A page below the pane, so a page down is answered at once, and
            // a page of starts above it for a page up.
            count: 2 * self.rows + 1,
            back: self.rows,
        }
    }

    fn wanted_bytes(&self) -> Key {
        Key::Bytes {
            at: self.top,
            len: self.rows * 16,
        }
    }

    fn wanted_list(&self) -> Option<Key> {
        match self.view {
            View::List(kind) => {
                let at = if kind == ListKind::XrefsTo {
                    self.seek
                } else {
                    0
                };
                Some(Key::List(kind, at))
            }
            _ => None,
        }
    }

    /// Ask for what the pane in front needs and the state does not hold;
    /// tell the engine's thread where the cursor is. Run after every message.
    fn sync(&mut self, effects: &mut Vec<Effect>) {
        if !self.opened {
            return;
        }
        // The seek goes first, so every request after it sees it.
        self.sync_seek(effects);
        let (lines, bytes, rendering, graph) = match self.view {
            View::Disassembly => (true, false, false, false),
            View::Decompiler => (false, false, true, false),
            View::Hex => (false, true, false, false),
            View::Graph => (false, false, false, true),
            View::Split => (true, false, true, false),
            View::List(_) => (false, false, false, false),
        };
        if lines {
            self.sync_lines(effects);
        }
        if bytes {
            let key = self.wanted_bytes();
            let held = self.bytes.held.as_ref().is_some_and(|held| {
                Key::Bytes {
                    at: held.at,
                    len: held.len,
                } == key
            });
            if !held || self.bytes.stale {
                self.want(key, effects);
            }
        }
        if rendering {
            let seek = self.seek;
            let held = self
                .rendering
                .held
                .as_ref()
                .is_some_and(|held| held.covers(seek));
            if !held || self.rendering.stale {
                self.want(Key::Decompiled(seek), effects);
            } else if self.land {
                self.land_decompiler();
            }
        }
        if graph {
            let seek = self.seek;
            let held = self
                .graph
                .held
                .as_ref()
                .is_some_and(|pane| pane.covers(seek));
            if !held || self.graph.stale {
                self.want(Key::Graph(seek), effects);
            }
            self.follow_seek_in_graph();
        }
        if let Some(key) = self.wanted_list() {
            let held = self.list.held.as_ref().is_some_and(|held| held.key == key);
            if !held || self.list.stale {
                self.want(key, effects);
            }
        }
        self.sync_seek(effects);
    }

    /// Ask for the disassembly window at the top. A window from the cache
    /// may make the moves kept for it, which moves the top to where another
    /// window is wanted; each pass makes at least one kept move or stops.
    fn sync_lines(&mut self, effects: &mut Vec<Effect>) {
        loop {
            let key = self.wanted_lines();
            let held = self.lines.held.as_ref().is_some_and(|held| held.key == key);
            if held && !self.lines.stale {
                return;
            }
            self.want(key, effects);
            if self.lines.pending() || self.wanted_lines() == key {
                return;
            }
        }
    }

    /// Tell the engine's thread where the cursor is, if it has moved since.
    fn sync_seek(&mut self, effects: &mut Vec<Effect>) {
        if self.seek != self.synced {
            self.synced = self.seek;
            effects.push(Effect::Request(Request::Seek(self.seek)));
        }
    }

    /// Install `key`'s answer from the cache, or ask for it unless its slot
    /// already has a request in flight (whose answer will be weighed, and
    /// this asked, when it arrives).
    fn want(&mut self, key: Key, effects: &mut Vec<Effect>) {
        if let Some(value) = self.cache.get(&key).cloned() {
            self.install(key, value);
            return;
        }
        let tag = self.next_tag;
        let slot = match key {
            Key::Lines { .. } => &mut self.lines.asked,
            Key::Bytes { .. } => &mut self.bytes.asked,
            Key::Decompiled(_) => &mut self.rendering.asked,
            Key::Graph(_) => &mut self.graph.asked,
            Key::List(..) => &mut self.list.asked,
        };
        if slot.is_some() {
            return;
        }
        *slot = Some((tag, key));
        self.next_tag += 1;
        effects.push(Effect::Request(Request::Fetch { tag, key }));
    }

    fn answer(&mut self, answer: Answer) {
        match answer {
            Answer::Opened { title, seek } => {
                self.opened = true;
                self.title = title;
                self.seek = seek;
                self.synced = seek;
                self.top = seek;
            }
            Answer::Fetched { tag, key, value } => {
                let asked = match key {
                    Key::Lines { .. } => &mut self.lines.asked,
                    Key::Bytes { .. } => &mut self.bytes.asked,
                    Key::Decompiled(_) => &mut self.rendering.asked,
                    Key::Graph(_) => &mut self.graph.asked,
                    Key::List(..) => &mut self.list.asked,
                };
                if *asked != Some((tag, key)) {
                    return;
                }
                *asked = None;
                // An answer for where the user no longer is is dropped: that
                // is the cancellation, and `sync` asks for what is wanted now.
                if self.wanted(key, &value) {
                    self.remember(key, value.clone());
                    self.install(key, value);
                }
            }
            Answer::Wrote { at, result } => {
                self.running = self.running.saturating_sub(1);
                match result {
                    Ok(()) => self.invalidate(),
                    Err(error) => {
                        self.editing = None;
                        self.message = Message::Error(format!("write at {at:#x}: {error}"));
                    }
                }
            }
            Answer::Ran { result, from, seek } => {
                self.running = self.running.saturating_sub(1);
                self.message = match result {
                    Ok(output) if output.trim().is_empty() => Message::None,
                    Ok(output) => Message::Output(output),
                    Err(error) => Message::Error(error),
                };
                self.invalidate();
                // A command may have sought: show what is there now. One
                // that did not leaves the cursor where the user has since
                // moved it.
                self.synced = seek;
                if seek != from {
                    self.history.push(self.seek);
                    self.seek = seek;
                    self.top = seek;
                    self.cursor = 0;
                    self.pending_lines = 0;
                }
            }
            Answer::Went(went) => {
                self.running = self.running.saturating_sub(1);
                match went {
                    Ok(address) => {
                        self.go(address);
                        self.land = true;
                    }
                    Err(error) => self.message = Message::Error(error),
                }
            }
            // What a scripted caller waits on; nothing to the state.
            Answer::Flushed => {}
        }
    }

    /// The program changed: every answer held, or kept by key, is out of
    /// date, and each pane asks again for what it shows.
    fn invalidate(&mut self) {
        self.cache.clear();
        self.cached.clear();
        self.lines.stale = true;
        self.bytes.stale = true;
        self.rendering.stale = true;
        self.graph.stale = true;
        self.list.stale = true;
    }

    /// Whether an answer is for where the user is now.
    fn wanted(&self, key: Key, value: &Fetched) -> bool {
        match (key, value) {
            (Key::Lines { .. }, _) => key == self.wanted_lines(),
            (Key::Bytes { .. }, _) => key == self.wanted_bytes(),
            (Key::Decompiled(at), Fetched::Decompiled(result)) => {
                at == self.seek
                    || span(result).is_some_and(|(low, high)| (low..=high).contains(&self.seek))
            }
            (Key::Graph(at), Fetched::Graph(result)) => {
                at == self.seek
                    || result
                        .as_ref()
                        .is_ok_and(|graph| graph.node_at(self.seek).is_some())
            }
            (Key::List(..), _) => Some(key) == self.wanted_list(),
            _ => false,
        }
    }

    fn remember(&mut self, key: Key, value: Fetched) {
        if self.cache.insert(key, value).is_none() {
            self.cached.push_back(key);
        }
        while self.cached.len() > CACHED {
            if let Some(oldest) = self.cached.pop_front() {
                self.cache.remove(&oldest);
            }
        }
    }

    fn install(&mut self, key: Key, value: Fetched) {
        match (key, value) {
            (Key::Lines { .. }, Fetched::Lines(window)) => {
                self.lines.held = Some(HeldLines { key, window });
                self.lines.stale = false;
                if let Some(held) = &self.lines.held {
                    self.cursor = self.cursor.min(held.window.lines.len().saturating_sub(1));
                }
                // Moves made while the lines were on their way.
                while self.pending_lines != 0 && self.window().is_some() {
                    let rows = self.rows as isize;
                    let delta = self.pending_lines.clamp(-rows, rows);
                    self.pending_lines -= delta;
                    self.step_lines(delta);
                }
            }
            (Key::Bytes { at, len }, Fetched::Bytes(bytes)) => {
                self.bytes.held = Some(HeldBytes { at, len, bytes });
                self.bytes.stale = false;
            }
            (Key::Decompiled(at), Fetched::Decompiled(result)) => {
                self.rendering.held = Some(HeldRendering::new(at, result));
                self.rendering.stale = false;
                if self.view == View::Decompiler {
                    self.land = true;
                }
                if self.land && self.view == View::Decompiler {
                    self.land_decompiler();
                }
            }
            (Key::Graph(at), Fetched::Graph(result)) => {
                let seek = self.seek;
                let drawn = result.map(|graph| {
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
                self.graph.held = Some(GraphPane {
                    at,
                    drawn,
                    selected,
                    scroll: (0, 0),
                    mini: false,
                    recentre: true,
                    minimap: true,
                });
                self.graph.stale = false;
            }
            (Key::List(kind, _), Fetched::List(entries)) => {
                self.list.held = Some(HeldList { key, kind, entries });
                self.list.stale = false;
            }
            _ => {}
        }
    }

    /// Land the decompiler's cursor on the line the seek was rendered into.
    fn land_decompiler(&mut self) {
        self.land = false;
        if let Some(HeldRendering {
            result: Ok(lines), ..
        }) = &self.rendering.held
        {
            let seek = self.seek;
            self.cursor = lines
                .iter()
                .position(|line| line.addresses.binary_search(&seek).is_ok())
                .unwrap_or(0);
        }
    }

    /// The graph's selection follows the seek, and the window the selection.
    fn follow_seek_in_graph(&mut self) {
        let seek = self.seek;
        let inner = (i64::from(self.size.0.saturating_sub(2)), self.rows as i64);
        let Some(pane) = &mut self.graph.held else {
            return;
        };
        let Ok((graph, layout)) = &pane.drawn else {
            return;
        };
        if let Some(node) = graph.node_at(seek)
            && node != pane.selected
        {
            pane.selected = node;
            pane.recentre = true;
        }
        if pane.recentre && !layout.boxes.is_empty() {
            let placed = layout.boxes[pane.selected.min(layout.boxes.len() - 1)];
            let centre = i64::from(placed.x) + i64::from(placed.width) / 2;
            pane.scroll.0 = (centre - inner.0 / 2).max(0);
            pane.scroll.1 = (i64::from(placed.y) - 2).max(0);
            pane.recentre = false;
        }
    }

    /// Handle one key. `false` when the user leaves.
    fn handle_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) -> bool {
        if !matches!(self.prompt, Prompt::None) {
            self.prompt_key(key, effects);
            return true;
        }
        if !matches!(self.message, Message::None) {
            // Any key dismisses what the last action said; it is also acted on
            // unless it closed a command's output.
            let was_output = matches!(self.message, Message::Output(_));
            self.message = Message::None;
            if was_output {
                return true;
            }
        }
        if !self.opened {
            // Nothing is known yet to act on; only leaving is.
            return !(key.code == KeyCode::Char('q')
                || (key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)));
        }
        if self.view == View::Hex && self.editing.is_some() {
            self.edit_key(key, effects);
            return true;
        }
        if self.view == View::Graph && self.graph_key(key) {
            return true;
        }
        match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
            KeyCode::Char('p') => self.switch(self.view.next(1)),
            KeyCode::Char('P') => self.switch(self.view.next(-1)),
            KeyCode::Char('V') => self.switch(View::Graph),
            KeyCode::Char('\\') => self.switch(View::Split),
            KeyCode::Char(':') => self.prompt = Prompt::Command(String::new()),
            KeyCode::Char('g') => self.prompt = Prompt::Goto(String::new()),
            KeyCode::Char('u') => {
                if let Some(back) = self.history.pop() {
                    self.seek = back;
                    self.top = back;
                    self.cursor = 0;
                    self.pending_lines = 0;
                    self.land = true;
                }
            }
            KeyCode::Char('x') => {
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
            KeyCode::Down | KeyCode::Char('j') => self.step(self.row()),
            KeyCode::Up | KeyCode::Char('k') => self.step(-self.row()),
            KeyCode::Right if self.view == View::Hex => self.step(1),
            KeyCode::Left if self.view == View::Hex => self.step(-1),
            KeyCode::PageDown | KeyCode::Char('J') => self.step(self.row() * self.rows as isize),
            KeyCode::PageUp | KeyCode::Char('K') => self.step(-self.row() * self.rows as isize),
            KeyCode::Enter => self.follow(),
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
            self.filter.clear();
            self.editing = None;
            self.pending_lines = 0;
        }
    }

    /// Move the cursor `delta` rows (bytes, in hex), scrolling the pane.
    fn step(&mut self, delta: isize) {
        match self.view {
            View::Disassembly | View::Split => self.step_lines(delta),
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
                self.seek = self.top + self.cursor as u64;
            }
            View::Decompiler => {
                let lines = match &self.rendering.held {
                    Some(HeldRendering {
                        result: Ok(lines), ..
                    }) => lines.as_slice(),
                    _ => &[],
                };
                let cursor = clamp_add(self.cursor, delta, lines.len());
                let seek = lines
                    .get(cursor)
                    .and_then(|line| line.addresses.first())
                    .copied();
                self.cursor = cursor;
                if let Some(address) = seek {
                    self.seek = address;
                }
            }
            View::List(_) => {
                let len = self.visible_entries().len();
                self.cursor = clamp_add(self.cursor, delta, len);
            }
            View::Graph => {}
        }
    }

    /// Move the disassembly cursor `delta` lines, scrolling by whole lines and
    /// seeking the line it lands on.
    ///
    /// Answered from the window around the top; a move made before that
    /// window arrives is kept and made when it does, so no key is lost and
    /// none waits on the engine.
    fn step_lines(&mut self, delta: isize) {
        let rows = self.rows.max(1);
        let Some(window) = self.window() else {
            self.pending_lines += delta;
            return;
        };
        let target = self.cursor as isize + delta;
        let (top, cursor, seek) = if target < 0 {
            // Scrolling up lands on the starts found before the top.
            let back = target.unsigned_abs();
            let top = window
                .before
                .get(back - 1)
                .or(window.before.last())
                .copied()
                .unwrap_or(self.top);
            (top, 0, Some(top))
        } else if target as usize >= rows {
            let lines = &window.lines;
            let from = target as usize + 1 - rows;
            match lines.get(from) {
                Some(line) => (line.address, rows - 1, last_of(lines, from, rows)),
                None => (self.top, rows - 1, last_of(lines, 0, rows)),
            }
        } else {
            let cursor = target as usize;
            (self.top, cursor, last_of(&window.lines, 0, cursor + 1))
        };
        self.top = top;
        self.cursor = cursor;
        if let Some(seek) = seek {
            self.seek = seek;
        }
    }

    /// `Enter`: follow the line's transfer, or open the chosen row.
    fn follow(&mut self) {
        match self.view {
            View::Disassembly | View::Split => {
                let target = self
                    .shown_lines()
                    .get(self.cursor)
                    .and_then(|line| line.target);
                match target {
                    Some(target) => {
                        self.go(target);
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
                    self.go(address);
                    self.switch(View::Disassembly);
                }
            }
            View::Decompiler | View::Hex | View::Graph => {}
        }
    }

    fn prompt_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) {
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
                    // `:`: run a shell command and show what it printed.
                    Prompt::Command(command) if !command.trim().is_empty() => {
                        self.ask(effects, &command, Request::Run(command.clone()));
                    }
                    // `g`: seek through the shell's own `s`, so an address
                    // expression or a name means what it means at the prompt.
                    Prompt::Goto(target) if !target.trim().is_empty() => {
                        let target = target.trim().to_owned();
                        self.ask(effects, &format!("s {target}"), Request::Goto(target));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Send a request whose answer the status line waits on.
    fn ask(&mut self, effects: &mut Vec<Effect>, what: &str, request: Request) {
        // The engine's thread runs it at the seek on screen.
        self.sync_seek(effects);
        self.running += 1;
        what.clone_into(&mut self.running_what);
        effects.push(Effect::Request(request));
    }

    /// The hex pane's edit mode: two hex digits write one byte at the cursor
    /// and move on; `Esc` leaves.
    fn edit_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) {
        match key.code {
            KeyCode::Esc => self.editing = None,
            KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                self.edit_nibble(c.to_digit(16).unwrap_or(0) as u8, effects);
            }
            KeyCode::Right => self.step(1),
            KeyCode::Left => self.step(-1),
            KeyCode::Down => self.step(16),
            KeyCode::Up => self.step(-16),
            _ => {}
        }
    }

    /// One hex digit typed in edit mode: the first is held, the second writes
    /// the byte and moves on. A write the engine refuses ends the edit and
    /// says why.
    fn edit_nibble(&mut self, nibble: u8, effects: &mut Vec<Effect>) {
        let Some(pending) = self.editing else {
            return;
        };
        let Some(high) = pending else {
            self.editing = Some(Some(nibble));
            return;
        };
        let at = self.top + self.cursor as u64;
        self.ask(
            effects,
            &format!("wx at {at:#x}"),
            Request::Write {
                at,
                bytes: vec![high << 4 | nibble],
            },
        );
        self.editing = Some(None);
        self.step(1);
    }

    /// The graph pane's own keys; `false` for a key the other panes share.
    ///
    /// radare2's: `hjkl` pan (`HJKL` by a page), `Tab` selects the next block,
    /// `t`/`f` follow the true/false edge, `.` brings the selection back,
    /// `-`/`+` zoom out to headers and back. `Enter` opens the block's
    /// disassembly.
    fn graph_key(&mut self, key: KeyEvent) -> bool {
        let page = self.rows.max(2) as i64;
        let Some(pane) = &mut self.graph.held else {
            return false;
        };
        match key.code {
            KeyCode::Char('h') | KeyCode::Left => pan(pane, -4, 0),
            KeyCode::Char('l') | KeyCode::Right => pan(pane, 4, 0),
            KeyCode::Char('k') | KeyCode::Up => pan(pane, 0, -2),
            KeyCode::Char('j') | KeyCode::Down => pan(pane, 0, 2),
            KeyCode::Char('H') => pan(pane, -4 * page, 0),
            KeyCode::Char('L') => pan(pane, 4 * page, 0),
            KeyCode::Char('K') | KeyCode::PageUp => pan(pane, 0, -page),
            KeyCode::Char('J') | KeyCode::PageDown => pan(pane, 0, page),
            KeyCode::Char('.') => pane.recentre = true,
            KeyCode::Char('m') => pane.minimap = !pane.minimap,
            KeyCode::Char('-') | KeyCode::Char('+') => {
                let mini = key.code == KeyCode::Char('-');
                if let Ok((graph, layout)) = &mut pane.drawn
                    && pane.mini != mini
                {
                    *layout = crate::graph::lay_out(graph, mini);
                    pane.mini = mini;
                    pane.recentre = true;
                }
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let Ok((graph, _)) = &pane.drawn else {
                    return true;
                };
                let len = graph.nodes.len();
                let step = if key.code == KeyCode::Tab { 1 } else { len - 1 };
                pane.selected = (pane.selected + step) % len;
                pane.recentre = true;
                self.seek = graph.nodes[pane.selected].address;
            }
            KeyCode::Char('t') | KeyCode::Char('f') => {
                let Ok((graph, _)) = &pane.drawn else {
                    return true;
                };
                let wanted: &[EdgeKind] = if key.code == KeyCode::Char('t') {
                    &[EdgeKind::Taken, EdgeKind::Jump, EdgeKind::Case]
                } else {
                    &[EdgeKind::NotTaken, EdgeKind::Fall, EdgeKind::Default]
                };
                let from = pane.selected;
                let edge = wanted.iter().find_map(|kind| {
                    graph
                        .edges
                        .iter()
                        .find(|edge| edge.from == from && edge.kind == *kind)
                });
                match edge {
                    Some(edge) => {
                        let address = graph.nodes[edge.to].address;
                        pane.selected = edge.to;
                        pane.recentre = true;
                        self.history.push(self.seek);
                        self.seek = address;
                    }
                    None => self.message = Message::Info("no such edge from this block".to_owned()),
                }
            }
            KeyCode::Enter => {
                if let Ok((graph, _)) = &pane.drawn {
                    let address = graph.nodes[pane.selected].address;
                    self.go(address);
                    self.switch(View::Disassembly);
                }
            }
            _ => return false,
        }
        true
    }

    /// The wheel scrolls the pane in front; a left click puts the cursor on
    /// the row (the byte, the block) under the pointer, which seeks there.
    fn mouse(&mut self, mouse: MouseEvent) {
        if !self.opened || !matches!(self.prompt, Prompt::None) {
            return;
        }
        let notch = match mouse.kind {
            MouseEventKind::ScrollDown => 1,
            MouseEventKind::ScrollUp => -1,
            MouseEventKind::Down(MouseButton::Left) => 0,
            _ => return,
        };
        if !matches!(self.message, Message::None) {
            let was_output = matches!(self.message, Message::Output(_));
            self.message = Message::None;
            if was_output {
                return;
            }
        }
        if notch == 0 {
            self.click(mouse.column, mouse.row);
        } else {
            self.wheel(notch);
        }
    }

    /// One notch of the wheel: the rows of three keys, or a pan in the graph.
    fn wheel(&mut self, notch: isize) {
        match (self.view, &mut self.graph.held) {
            (View::Graph, Some(pane)) => pan(pane, 0, 2 * WHEEL as i64 * notch as i64),
            (View::Graph, None) => {}
            _ => self.step(notch * WHEEL * self.row()),
        }
    }

    /// A left click at a cell of the terminal.
    fn click(&mut self, column: u16, row: u16) {
        let main = self.main_area();
        // Inside the pane's border.
        let inner = ratatui::layout::Rect {
            x: main.x + 1,
            y: main.y + 1,
            width: main.width.saturating_sub(2),
            height: main.height.saturating_sub(2),
        };
        if !inner.contains(ratatui::layout::Position { x: column, y: row }) {
            return;
        }
        let (x, y) = (column - inner.x, usize::from(row - inner.y));
        match self.view {
            View::Disassembly => self.click_line(y),
            View::Split => {
                let [left, _] = split_areas(main);
                if column < left.x + left.width.saturating_sub(1) {
                    self.click_line(y);
                }
            }
            View::Decompiler => {
                let len = match &self.rendering.held {
                    Some(HeldRendering {
                        result: Ok(lines), ..
                    }) => lines.len(),
                    _ => 0,
                };
                let skip = self.cursor.saturating_sub(self.rows.saturating_sub(1));
                if skip + y < len {
                    self.step((skip + y) as isize - self.cursor as isize);
                }
            }
            View::List(_) => {
                let len = self.visible_entries().len();
                let cursor = self.cursor.min(len.saturating_sub(1));
                let skip = cursor.saturating_sub(self.rows.saturating_sub(1));
                if skip + y < len {
                    self.cursor = skip + y;
                }
            }
            View::Hex => {
                // `0x00001000  ` then three columns a byte, a gap after the
                // eighth.
                let Some(x) = usize::from(x).checked_sub(12) else {
                    return;
                };
                let column = match x {
                    0..=23 => x / 3,
                    25..=48 => 8 + (x - 25) / 3,
                    _ => return,
                };
                let index = y * 16 + column;
                let shown = self
                    .bytes
                    .held
                    .as_ref()
                    .filter(|held| held.at == self.top)
                    .map_or(0, |held| held.bytes.len());
                if index < shown {
                    self.step(index as isize - self.cursor as isize);
                }
            }
            View::Graph => {
                let Some(pane) = &mut self.graph.held else {
                    return;
                };
                let Ok((graph, layout)) = &pane.drawn else {
                    return;
                };
                let (cx, cy) = (pane.scroll.0 + i64::from(x), pane.scroll.1 + y as i64);
                let hit = layout.boxes.iter().position(|placed| {
                    (i64::from(placed.x)..i64::from(placed.x + placed.width)).contains(&cx)
                        && (i64::from(placed.y)..i64::from(placed.y + placed.height)).contains(&cy)
                });
                if let Some(node) = hit {
                    pane.selected = node;
                    self.seek = graph.nodes[node].address;
                }
            }
        }
    }

    /// A click on a disassembly row: the cursor moves there and seeks it.
    fn click_line(&mut self, y: usize) {
        if y < self.shown_lines().len() && self.window().is_some() {
            self.step_lines(y as isize - self.cursor as isize);
        }
    }

    /// The main pane's area at the current size.
    pub(crate) fn main_area(&self) -> ratatui::layout::Rect {
        let [_, main, _] = screen_areas(ratatui::layout::Rect::new(0, 0, self.size.0, self.size.1));
        main
    }
}

fn pan(pane: &mut GraphPane, dx: i64, dy: i64) {
    pane.scroll.0 = (pane.scroll.0 + dx).max(0);
    pane.scroll.1 = (pane.scroll.1 + dy).max(0);
}

/// The title line, the main pane and the status line.
pub(crate) fn screen_areas(area: ratatui::layout::Rect) -> [ratatui::layout::Rect; 3] {
    use ratatui::layout::{Constraint, Layout};
    Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area)
}

/// The split's two halves.
pub(crate) fn split_areas(area: ratatui::layout::Rect) -> [ratatui::layout::Rect; 2] {
    use ratatui::layout::{Constraint, Layout};
    Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area)
}

/// The start of the last of `count` lines from `from`, as far as there are
/// lines: where the cursor on the `count`th row from `from` seeks.
fn last_of(lines: &[ListedLine], from: usize, count: usize) -> Option<u64> {
    let end = from.saturating_add(count).min(lines.len());
    lines.get(from..end)?.last().map(|line| line.address)
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
