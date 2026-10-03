//! The visual mode, driven by keys over a host that is a little program held
//! in memory, drawn into a test terminal.
//!
//! The host is served on the engine's thread exactly as the terminal's event
//! loop serves it ([`Driver`]); a test settles the state (waits for every
//! answer) between keys where it is about what a key does, and does not
//! where it is about what the screen does while an answer is on its way.
//! The host checks every call is made off the thread that draws.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use r2s_tui::{
    DecompiledLine, Driver, EdgeKind, Entry, Graph, GraphEdge, GraphNode, Host, ListKind,
    ListedLine, Msg, PENDING, View,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

/// What the host has seen, shared with the test.
#[derive(Default)]
struct Seen {
    seek: u64,
    patches: BTreeMap<u64, u8>,
    /// Bytes a write is refused at.
    read_only: std::collections::BTreeSet<u64>,
    commands: Vec<String>,
    /// Every thread that called the host.
    threads: Vec<ThreadId>,
    /// Every address a rendering was asked at, in order.
    decompiled: Vec<u64>,
}

/// Holds each rendering until the test lets it go: the host says it has
/// started one on `started`, then waits on `release`.
struct Gate {
    started: Sender<u64>,
    release: Receiver<()>,
}

/// Four-byte "instructions": `call 0x2000` at 0x1000, then `nop`s, at 0x1000
/// and 0x2000; bytes are the low byte of each address.
struct Program {
    seen: Arc<Mutex<Seen>>,
    /// The thread that draws, which must never call the host.
    ui: ThreadId,
    gate: Option<Gate>,
}

impl Program {
    fn new() -> (Self, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen {
            seek: 0x1000,
            ..Seen::default()
        }));
        let program = Self {
            seen: Arc::clone(&seen),
            ui: std::thread::current().id(),
            gate: None,
        };
        (program, seen)
    }

    /// Every call goes through here: off the drawing thread, or the test fails.
    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        let here = std::thread::current().id();
        assert_ne!(here, self.ui, "the host was called on the drawing thread");
        let mut seen = self.seen.lock().expect("the host's record");
        if !seen.threads.contains(&here) {
            seen.threads.push(here);
        }
        seen
    }
}

impl Host for Program {
    fn title(&self) -> String {
        drop(self.seen());
        "fixture ELF x86-64".to_owned()
    }
    fn seek(&self) -> u64 {
        self.seen().seek
    }
    fn set_seek(&mut self, address: u64) {
        self.seen().seek = address;
    }
    fn disassemble(&mut self, address: u64, count: usize) -> Vec<ListedLine> {
        drop(self.seen());
        (0..count as u64)
            .map(|index| address + index * 4)
            .filter(|at| (0x1000..0x1100).contains(at) || (0x2000..0x2100).contains(at))
            .map(|at| ListedLine {
                address: at,
                size: 4,
                text: if at == 0x1000 {
                    "call fcn.00002000".to_owned()
                } else {
                    "nop".to_owned()
                },
                target: (at == 0x1000).then_some(0x2000),
            })
            .collect()
    }
    fn read(&self, address: u64, len: usize) -> Vec<u8> {
        let seen = self.seen();
        (address..address + len as u64)
            .map(|at| seen.patches.get(&at).copied().unwrap_or(at as u8))
            .collect()
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        let mut seen = self.seen();
        if (address..address + bytes.len() as u64).any(|at| seen.read_only.contains(&at)) {
            return Err("the byte is read-only".to_owned());
        }
        for (offset, byte) in bytes.iter().enumerate() {
            seen.patches.insert(address + offset as u64, *byte);
        }
        Ok(())
    }
    fn decompile(&mut self, address: u64) -> Result<Vec<DecompiledLine>, String> {
        self.seen().decompiled.push(address);
        if let Some(gate) = &self.gate {
            // The test may have stopped listening; the answer is still due.
            let _ = gate.started.send(address);
            gate.release
                .recv()
                .map_err(|_| "the test hung up".to_owned())?;
        }
        if !(0x1000..0x1100).contains(&address) {
            return Err(format!("no function at {address:#x}"));
        }
        Ok(vec![
            DecompiledLine {
                text: "void main(void)".to_owned(),
                addresses: vec![],
            },
            DecompiledLine {
                text: "{".to_owned(),
                addresses: vec![],
            },
            DecompiledLine {
                text: "    fcn_2000();".to_owned(),
                addresses: vec![0x1000],
            },
            DecompiledLine {
                text: "}".to_owned(),
                addresses: vec![0x1004],
            },
        ])
    }
    fn graph(&mut self, address: u64) -> Result<Graph, String> {
        drop(self.seen());
        if !(0x1000..0x1018).contains(&address) {
            return Err(format!("no function at {address:#x}"));
        }
        // A branch at 0x1004 over the block at 0x1008, both reaching 0x1010.
        let node = |address, lines: &[&str]| GraphNode {
            address,
            size: 8,
            lines: lines.iter().map(|line| (*line).to_owned()).collect(),
        };
        let edge = |from, to, kind| GraphEdge { from, to, kind };
        Ok(Graph {
            entry: 0x1000,
            nodes: vec![
                node(0x1000, &["call fcn.00002000", "je 0x1010"]),
                node(0x1008, &["nop", "jmp 0x1010"]),
                node(0x1010, &["nop", "ret"]),
            ],
            edges: vec![
                edge(0, 2, EdgeKind::Taken),
                edge(0, 1, EdgeKind::NotTaken),
                edge(1, 2, EdgeKind::Jump),
            ],
            note: None,
        })
    }
    fn list(&mut self, kind: ListKind) -> Vec<Entry> {
        drop(self.seen());
        match kind {
            ListKind::Functions => vec![
                Entry {
                    address: 0x1000,
                    text: "main".to_owned(),
                },
                Entry {
                    address: 0x2000,
                    text: "malloc_wrapper".to_owned(),
                },
            ],
            _ => Vec::new(),
        }
    }
    fn run(&mut self, command: &str) -> Result<String, String> {
        let mut seen = self.seen();
        seen.commands.push(command.to_owned());
        match command.split_once(' ') {
            Some(("s", target)) => {
                let parsed = u64::from_str_radix(target.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("cannot seek to {target}"))?;
                seen.seek = parsed;
                Ok(String::new())
            }
            _ => Ok(format!("ran {command}")),
        }
    }
}

/// The visual mode in a test terminal, its host on the engine's thread.
struct Ui {
    driver: Driver,
    seen: Arc<Mutex<Seen>>,
    size: (u16, u16),
}

/// Run `test` against the visual mode over `host`; the engine's thread is
/// joined at the end, and must not have panicked.
fn visual(mut host: Program, seen: Arc<Mutex<Seen>>, test: impl FnOnce(&mut Ui)) {
    std::thread::scope(|scope| {
        let (driver, engine) = r2s_tui::connect();
        let worker = scope.spawn(move || engine.serve(&mut host));
        let mut ui = Ui {
            driver,
            seen,
            size: (80, 12),
        };
        ui.resize(80, 12);
        ui.settle();
        test(&mut ui);
        drop(ui);
        worker.join().expect("the engine's thread did not panic");
    });
}

fn code(c: char) -> KeyCode {
    match c {
        '\n' => KeyCode::Enter,
        '\x1b' => KeyCode::Esc,
        '\t' => KeyCode::Tab,
        c => KeyCode::Char(c),
    }
}

impl Ui {
    /// Press each key and let its answers arrive; `false` once one leaves.
    fn press(&mut self, keys: &str) -> bool {
        for c in keys.chars() {
            if !self.key(c) {
                return false;
            }
            self.settle();
        }
        true
    }

    /// Press a key without waiting for anything it asks.
    fn key(&mut self, c: char) -> bool {
        let key = KeyEvent::new(code(c), KeyModifiers::NONE);
        self.driver
            .handle(Msg::Key(key))
            .expect("the engine is there")
    }

    fn mouse(&mut self, kind: MouseEventKind, column: u16, row: u16) {
        let mouse = MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        self.driver
            .handle(Msg::Mouse(mouse))
            .expect("the engine is there");
        self.settle();
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.size = (width, height);
        self.driver
            .handle(Msg::Resize(width, height))
            .expect("the engine is there");
    }

    /// Wait for every answer, then check the shell's cursor is the visual
    /// mode's.
    fn settle(&mut self) {
        self.driver.settle().expect("the engine answers");
        assert_eq!(self.host_seek(), self.seek(), "the shell's seek is in step");
    }

    fn seek(&self) -> u64 {
        self.driver.app().seek()
    }

    fn host_seek(&self) -> u64 {
        self.seen.lock().expect("the host's record").seek
    }

    fn view(&self) -> View {
        self.driver.app().view()
    }

    /// One draw, of the state as it stands.
    fn drawn(&self) -> ratatui::buffer::Buffer {
        let mut terminal =
            Terminal::new(TestBackend::new(self.size.0, self.size.1)).expect("a terminal");
        terminal
            .draw(|frame| self.driver.draw(frame))
            .expect("a draw");
        terminal.backend().buffer().clone()
    }

    fn screen(&self) -> String {
        let buffer = self.drawn();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn run(test: impl FnOnce(&mut Ui)) {
    let (host, seen) = Program::new();
    visual(host, seen, test);
}

#[test]
fn enter_follows_a_call_and_u_comes_back() {
    run(|ui| {
        let first = ui.screen();
        assert!(
            first.contains("0x00001000  call fcn.00002000  -> 0x2000"),
            "{first}"
        );
        ui.press("\n");
        assert_eq!(ui.seek(), 0x2000);
        let followed = ui.screen();
        assert!(followed.contains("0x00002000  nop"), "{followed}");
        ui.press("xu");
        assert_eq!(ui.seek(), 0x1000);
    });
}

#[test]
fn moving_down_in_the_disassembly_seeks_the_line_under_the_cursor() {
    run(|ui| {
        ui.press("jj");
        assert_eq!(ui.seek(), 0x1008);
        ui.press("k");
        assert_eq!(ui.seek(), 0x1004);
        // Past the bottom the pane scrolls by lines; a page up from the
        // bottom row lands on the line before the top, found by decoding
        // forwards from before it.
        ui.press("jjjjjjjj");
        assert_eq!(ui.seek(), 0x1024);
        let scrolled = ui.screen();
        assert!(
            !scrolled.contains("0x00001004") && scrolled.contains("0x00001024"),
            "{scrolled}"
        );
        ui.press("K");
        assert_eq!(ui.seek(), 0x1004);
        assert!(ui.screen().contains("0x00001004  nop"));
    });
}

#[test]
fn hex_edit_writes_two_nibbles_as_one_byte_and_moves_on() {
    run(|ui| {
        ui.press("pp");
        assert_eq!(ui.view(), View::Hex);
        ui.press("iab\x1b");
        assert_eq!(ui.seen.lock().unwrap().patches.get(&0x1000), Some(&0xab));
        assert_eq!(ui.seek(), 0x1001);
        let shown = ui.screen();
        assert!(shown.contains("0x00001000  ab 01"), "{shown}");
    });
}

#[test]
fn a_refused_hex_write_puts_the_cursor_back_on_its_byte_and_says_why() {
    run(|ui| {
        ui.seen.lock().unwrap().read_only.insert(0x1000);
        ui.press("pp");
        assert_eq!(ui.view(), View::Hex);
        ui.press("iab");
        ui.settle();
        assert_eq!(ui.seen.lock().unwrap().patches.get(&0x1000), None);
        assert_eq!(ui.seek(), 0x1000);
        let shown = ui.screen();
        assert!(
            shown.contains("write at 0x1000: the byte is read-only"),
            "{shown}"
        );
    });
}

#[test]
fn a_filtered_list_seeks_the_chosen_row_and_opens_the_disassembly() {
    run(|ui| {
        ui.press("P");
        assert_eq!(ui.view(), View::List(ListKind::Functions));
        let all = ui.screen();
        assert!(all.contains("functions (2)"), "{all}");
        ui.press("/mlc\n");
        let filtered = ui.screen();
        assert!(filtered.contains("functions (1/2) /mlc"), "{filtered}");
        assert!(
            filtered.contains("malloc_wrapper") && !filtered.contains("main"),
            "{filtered}"
        );
        ui.press("\n");
        assert_eq!(ui.seek(), 0x2000);
        assert_eq!(ui.view(), View::Disassembly);
    });
}

#[test]
fn the_command_line_runs_a_shell_command_and_shows_its_output() {
    run(|ui| {
        ui.press(":afl\n");
        assert_eq!(ui.seen.lock().unwrap().commands, ["afl"]);
        let shown = ui.screen();
        assert!(shown.contains("ran afl"), "{shown}");
        ui.press("g2000\n");
        assert_eq!(ui.seek(), 0x2000);
        ui.press("u");
        assert_eq!(ui.seek(), 0x1000);
    });
}

#[test]
fn the_decompiler_lands_on_the_line_the_seek_renders_into_and_moving_seeks() {
    run(|ui| {
        ui.press("p");
        let shown = ui.screen();
        assert!(shown.contains("fcn_2000();"), "{shown}");
        ui.press("j");
        assert_eq!(ui.seek(), 0x1004);
    });
}

#[test]
fn q_leaves() {
    run(|ui| assert!(!ui.press("q")));
}

#[test]
fn the_graph_follows_edges_and_blocks_and_keeps_the_seek_in_step() {
    run(|ui| {
        ui.press("V");
        assert_eq!(ui.view(), View::Graph);
        let shown = ui.screen();
        assert!(shown.contains("graph 0x1000  3 blocks  3 edges"), "{shown}");
        assert!(
            shown.contains("[0x1000]") && shown.contains("call fcn.00002000"),
            "{shown}"
        );
        // `f` follows the false edge, `t` from there the only (unconditional) one.
        ui.press("f");
        assert_eq!(ui.seek(), 0x1008);
        ui.press("t");
        assert_eq!(ui.seek(), 0x1010);
        // The window follows the selection.
        let shown = ui.screen();
        assert!(shown.contains("[0x1010]"), "{shown}");
        // Nothing leaves the exit.
        ui.press("t");
        assert_eq!(ui.seek(), 0x1010);
        assert!(ui.screen().contains("no such edge"));
        // `u` walks back along what was followed, and the selection follows the seek.
        ui.press("uu");
        assert_eq!(ui.seek(), 0x1000);
        ui.press("\t");
        assert_eq!(ui.seek(), 0x1008);
        ui.press("\n");
        assert_eq!(ui.view(), View::Disassembly);
        assert_eq!(ui.seek(), 0x1008);
        // Outside any function the pane says so, and pans nothing.
        ui.press("g2000\nV");
        let shown = ui.screen();
        assert!(shown.contains("no function at 0x2000"), "{shown}");
    });
}

/// Whether the first cell of `needle` on the screen has the lit background.
fn lit(buffer: &ratatui::buffer::Buffer, needle: &str) -> bool {
    let width = buffer.area.width;
    for y in 0..buffer.area.height {
        let row: String = (0..width)
            .map(|x| buffer[(x, y)].symbol().to_owned())
            .collect();
        if let Some(at) = row.find(needle) {
            let x = row[..at].chars().count() as u16;
            return buffer[(x, y)].bg == ratatui::style::Color::DarkGray;
        }
    }
    panic!("{needle} is not on the screen");
}

#[test]
fn the_split_lights_the_c_the_instruction_under_the_cursor_was_rendered_into() {
    run(|ui| {
        ui.press("\\");
        assert_eq!(ui.view(), View::Split);
        let buffer = ui.drawn();
        // The call at 0x1000 is under the cursor, and it is what the call statement was rendered from.
        assert!(lit(&buffer, "fcn_2000();"));
        assert!(!lit(&buffer, "void main(void)"));
        // One line down is 0x1004, which only the closing brace was rendered from.
        ui.press("j");
        assert_eq!(ui.seek(), 0x1004);
        let buffer = ui.drawn();
        assert!(!lit(&buffer, "fcn_2000();"));
        assert!(ui.screen().contains("call fcn.00002000"));
        // Moving inside the function asked for no second rendering.
        assert_eq!(ui.seen.lock().unwrap().decompiled, [0x1000]);
    });
}

#[test]
fn the_graph_shows_a_map_of_a_layout_larger_than_its_window_and_m_hides_it() {
    run(|ui| {
        ui.press("V");
        assert!(ui.screen().contains('▪'));
        ui.press("m");
        assert!(!ui.screen().contains('▪'));
    });
}

/// A host whose renderings wait for the test, and the two ends of its gate.
fn gated() -> (Program, Arc<Mutex<Seen>>, Receiver<u64>, Sender<()>) {
    let (mut host, seen) = Program::new();
    let (started, on_start) = channel();
    let (release, released) = channel();
    host.gate = Some(Gate {
        started,
        release: released,
    });
    (host, seen, on_start, release)
}

/// While a rendering is under way, frames are drawn and keys are handled:
/// the decompiler pane says it is waiting, and every other pane works.
#[test]
fn a_rendering_under_way_blocks_neither_the_frame_nor_the_keys() {
    let (host, seen, started, release) = gated();
    visual(host, seen, |ui| {
        assert!(ui.key('p'));
        assert_eq!(started.recv(), Ok(0x1000), "the rendering is under way");
        let waiting = ui.screen();
        assert!(
            waiting.contains(&format!("decompiler {PENDING}")),
            "{waiting}"
        );
        assert!(ui.driver.app().waiting());
        // Keys go on being handled while the engine is busy: a prompt opens
        // and closes, the panes cycle and come back.
        for c in [':', '\x1b', 'p', 'P'] {
            assert!(ui.key(c));
            ui.screen();
        }
        assert_eq!(ui.view(), View::Decompiler);
        assert!(!ui.screen().contains("fcn_2000();"));
        release.send(()).expect("the host waits");
        ui.settle();
        let rendered = ui.screen();
        assert!(rendered.contains("fcn_2000();"), "{rendered}");
        assert!(!rendered.contains(PENDING), "{rendered}");
    });
}

/// A rendering asked for at a seek the user has left is not shown: the
/// pane asks again for where the user is.
#[test]
fn an_answer_for_a_seek_the_user_left_is_dropped() {
    let (host, seen, started, release) = gated();
    visual(host, Arc::clone(&seen), |ui| {
        assert!(ui.key('p'));
        assert_eq!(started.recv(), Ok(0x1000));
        // Back in the disassembly (already held), follow the call, and look
        // at the C again, all before the rendering of 0x1000 is done.
        assert!(ui.key('P'));
        assert!(ui.key('\n'));
        assert_eq!(ui.seek(), 0x2000);
        assert!(ui.key('p'));
        assert_eq!(ui.view(), View::Decompiler);
        release.send(()).expect("the host waits");
        release.send(()).expect("the host waits");
        ui.settle();
        assert_eq!(started.recv(), Ok(0x2000), "asked again where the user is");
        let shown = ui.screen();
        assert!(!shown.contains("fcn_2000();"), "{shown}");
        assert!(shown.contains("no function at 0x2000"), "{shown}");
    });
    assert_eq!(seen.lock().unwrap().decompiled, [0x1000, 0x2000]);
}

#[test]
fn the_wheel_scrolls_and_a_click_seeks_the_row_under_it() {
    run(|ui| {
        // Rows of the pane start under the title line and the border.
        ui.mouse(MouseEventKind::ScrollDown, 10, 5);
        assert_eq!(ui.seek(), 0x100c);
        ui.mouse(MouseEventKind::Down(MouseButton::Left), 10, 6);
        assert_eq!(ui.seek(), 0x1010);
        ui.mouse(MouseEventKind::ScrollUp, 10, 5);
        assert_eq!(ui.seek(), 0x1004);
        // In hex, a click lands on the byte under it: the second row's
        // tenth byte, past the gap after the eighth.
        ui.press("pp");
        assert_eq!(ui.view(), View::Hex);
        let column = 1 + 12 + 25 + 3;
        ui.mouse(MouseEventKind::Down(MouseButton::Left), column, 3);
        assert_eq!(ui.seek(), 0x1019);
    });
}

#[test]
fn a_resize_lays_the_panes_out_again() {
    run(|ui| {
        let small = ui.screen();
        assert!(small.contains("0x0000101c"), "{small}");
        assert!(!small.contains("0x00001020"), "{small}");
        ui.resize(80, 20);
        ui.settle();
        let tall = ui.screen();
        assert_eq!(tall.lines().count(), 20);
        assert!(tall.contains("0x0000103c"), "{tall}");
        assert!(!tall.contains("0x00001040"), "{tall}");
    });
}

/// Every pane, a command, a seek by name and a write: the host is asked
/// for all of it, and never on the thread that draws.
#[test]
fn the_host_is_only_asked_on_the_engines_thread() {
    let (host, seen) = Program::new();
    let ui_thread = std::thread::current().id();
    visual(host, Arc::clone(&seen), |ui| {
        ui.press("pppppl:afl\n\x1bg1000\n");
        ui.press("ppp");
        ui.press("i12\x1b");
        ui.screen();
    });
    let seen = seen.lock().unwrap();
    assert!(!seen.threads.is_empty());
    assert!(!seen.threads.contains(&ui_thread), "{:?}", seen.threads);
    assert_eq!(seen.commands, ["afl", "s 1000"]);
    assert_eq!(seen.patches.get(&0x1000), Some(&0x12));
}
