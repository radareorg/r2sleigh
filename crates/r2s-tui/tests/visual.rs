//! The visual mode, driven by keys over a host that is a little program held
//! in memory, drawn into a test terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use r2s_tui::{
    App, DecompiledLine, EdgeKind, Entry, Graph, GraphEdge, GraphNode, Host, ListKind, ListedLine,
    View,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::collections::BTreeMap;

/// Four-byte "instructions": `call 0x2000` at 0x1000, then `nop`s, at 0x1000
/// and 0x2000; bytes are the low byte of each address.
struct Program {
    seek: u64,
    patches: BTreeMap<u64, u8>,
    commands: Vec<String>,
}

impl Program {
    fn new() -> Self {
        Self {
            seek: 0x1000,
            patches: BTreeMap::new(),
            commands: Vec::new(),
        }
    }
}

impl Host for Program {
    fn title(&self) -> String {
        "fixture ELF x86-64".to_owned()
    }
    fn seek(&self) -> u64 {
        self.seek
    }
    fn set_seek(&mut self, address: u64) {
        self.seek = address;
    }
    fn disassemble(&mut self, address: u64, count: usize) -> Vec<ListedLine> {
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
        (address..address + len as u64)
            .map(|at| self.patches.get(&at).copied().unwrap_or(at as u8))
            .collect()
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        for (offset, byte) in bytes.iter().enumerate() {
            self.patches.insert(address + offset as u64, *byte);
        }
        Ok(())
    }
    fn decompile(&mut self, address: u64) -> Result<Vec<DecompiledLine>, String> {
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
        self.commands.push(command.to_owned());
        match command.split_once(' ') {
            Some(("s", target)) => {
                let parsed = u64::from_str_radix(target.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("cannot seek to {target}"))?;
                self.seek = parsed;
                Ok(String::new())
            }
            _ => Ok(format!("ran {command}")),
        }
    }
}

fn press(app: &mut App, host: &mut Program, keys: &str) -> bool {
    for c in keys.chars() {
        let code = match c {
            '\n' => KeyCode::Enter,
            '\x1b' => KeyCode::Esc,
            '\t' => KeyCode::Tab,
            c => KeyCode::Char(c),
        };
        if !app.handle_key(host, KeyEvent::new(code, KeyModifiers::NONE)) {
            return false;
        }
    }
    true
}

fn screen(app: &mut App, host: &mut Program) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).expect("a terminal");
    terminal
        .draw(|frame| app.draw(frame, host))
        .expect("a draw");
    let buffer = terminal.backend().buffer().clone();
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

#[test]
fn enter_follows_a_call_and_u_comes_back() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    let first = screen(&mut app, &mut host);
    assert!(
        first.contains("0x00001000  call fcn.00002000  -> 0x2000"),
        "{first}"
    );
    press(&mut app, &mut host, "\n");
    assert_eq!(host.seek, 0x2000);
    let followed = screen(&mut app, &mut host);
    assert!(followed.contains("0x00002000  nop"), "{followed}");
    press(&mut app, &mut host, "xu");
    assert_eq!(host.seek, 0x1000);
}

#[test]
fn moving_down_in_the_disassembly_seeks_the_line_under_the_cursor() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    screen(&mut app, &mut host);
    press(&mut app, &mut host, "jj");
    assert_eq!(host.seek, 0x1008);
    press(&mut app, &mut host, "k");
    assert_eq!(host.seek, 0x1004);
}

#[test]
fn hex_edit_writes_two_nibbles_as_one_byte_and_moves_on() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "pp");
    assert_eq!(app.view(), View::Hex);
    screen(&mut app, &mut host);
    press(&mut app, &mut host, "iab\x1b");
    assert_eq!(host.patches.get(&0x1000), Some(&0xab));
    assert_eq!(host.seek, 0x1001);
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("0x00001000  ab 01"), "{shown}");
}

#[test]
fn a_filtered_list_seeks_the_chosen_row_and_opens_the_disassembly() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "P");
    assert_eq!(app.view(), View::List(ListKind::Functions));
    let all = screen(&mut app, &mut host);
    assert!(all.contains("functions (2)"), "{all}");
    press(&mut app, &mut host, "/mlc\n");
    let filtered = screen(&mut app, &mut host);
    assert!(filtered.contains("functions (1/2) /mlc"), "{filtered}");
    assert!(
        filtered.contains("malloc_wrapper") && !filtered.contains("main"),
        "{filtered}"
    );
    press(&mut app, &mut host, "\n");
    assert_eq!(host.seek, 0x2000);
    assert_eq!(app.view(), View::Disassembly);
}

#[test]
fn the_command_line_runs_a_shell_command_and_shows_its_output() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, ":afl\n");
    assert_eq!(host.commands, ["afl"]);
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("ran afl"), "{shown}");
    press(&mut app, &mut host, "g2000\n");
    assert_eq!(host.seek, 0x2000);
    press(&mut app, &mut host, "u");
    assert_eq!(host.seek, 0x1000);
}

#[test]
fn the_decompiler_lands_on_the_line_the_seek_renders_into_and_moving_seeks() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "p");
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("fcn_2000();"), "{shown}");
    press(&mut app, &mut host, "j");
    assert_eq!(host.seek, 0x1004);
}

#[test]
fn q_leaves() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    assert!(!press(&mut app, &mut host, "q"));
}

#[test]
fn the_graph_follows_edges_and_blocks_and_keeps_the_seek_in_step() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "V");
    assert_eq!(app.view(), View::Graph);
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("graph 0x1000  3 blocks  3 edges"), "{shown}");
    assert!(
        shown.contains("[0x1000]") && shown.contains("call fcn.00002000"),
        "{shown}"
    );
    // `f` follows the false edge, `t` from there the only (unconditional) one.
    press(&mut app, &mut host, "f");
    assert_eq!(host.seek, 0x1008);
    press(&mut app, &mut host, "t");
    assert_eq!(host.seek, 0x1010);
    // The window follows the selection.
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("[0x1010]"), "{shown}");
    // Nothing leaves the exit.
    press(&mut app, &mut host, "t");
    assert_eq!(host.seek, 0x1010);
    assert!(screen(&mut app, &mut host).contains("no such edge"));
    // `u` walks back along what was followed, and the selection follows the seek.
    press(&mut app, &mut host, "uu");
    assert_eq!(host.seek, 0x1000);
    screen(&mut app, &mut host);
    press(&mut app, &mut host, "\t");
    assert_eq!(host.seek, 0x1008);
    press(&mut app, &mut host, "\n");
    assert_eq!(app.view(), View::Disassembly);
    assert_eq!(host.seek, 0x1008);
    // Outside any function the pane says so, and pans nothing.
    press(&mut app, &mut host, "g2000\nV");
    let shown = screen(&mut app, &mut host);
    assert!(shown.contains("no function at 0x2000"), "{shown}");
}

/// The cells of one draw, for the tests that read a style.
fn drawn(app: &mut App, host: &mut Program) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).expect("a terminal");
    terminal
        .draw(|frame| app.draw(frame, host))
        .expect("a draw");
    terminal.backend().buffer().clone()
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
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "\\");
    assert_eq!(app.view(), View::Split);
    let buffer = drawn(&mut app, &mut host);
    // The call at 0x1000 is under the cursor, and it is what the call statement was rendered from.
    assert!(lit(&buffer, "fcn_2000();"));
    assert!(!lit(&buffer, "void main(void)"));
    // One line down is 0x1004, which only the closing brace was rendered from.
    press(&mut app, &mut host, "j");
    assert_eq!(host.seek, 0x1004);
    let buffer = drawn(&mut app, &mut host);
    assert!(!lit(&buffer, "fcn_2000();"));
    // Moving inside the function asked for no second rendering.
    assert!(screen(&mut app, &mut host).contains("call fcn.00002000"));
}

#[test]
fn the_graph_shows_a_map_of_a_layout_larger_than_its_window_and_m_hides_it() {
    let mut host = Program::new();
    let mut app = App::new(&host);
    press(&mut app, &mut host, "V");
    assert!(screen(&mut app, &mut host).contains('▪'));
    press(&mut app, &mut host, "m");
    assert!(!screen(&mut app, &mut host).contains('▪'));
}
