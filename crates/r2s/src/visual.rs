//! The shell as the visual mode's host.
//!
//! Every pane is spelled here by the same code the commands use: a
//! disassembly row is `pd`'s, a decompiled line is `pddj`'s, a list row is the
//! row its command prints. The visual mode only lays them out.

use crate::session::Session;
use r2engine::RenderTier;
use r2engine::program::EdgeKind as Edge;
use r2engine::query::{AnnotationKind, Listing, Stop};
use r2s_tui::{
    DecompiledLine, EdgeKind, Entry, Graph, GraphEdge, GraphNode, Host, ListKind, ListedLine,
};

/// `V`: the visual mode, from the prompt, returning to it on `q`.
pub(crate) fn open(session: &mut Session) -> Result<String, String> {
    r2s_tui::run(&mut Visual { session }).map_err(|error| format!("visual mode: {error}"))?;
    Ok(String::new())
}

/// `agf`: the control-flow graph of the function at the address, drawn as text.
pub(crate) fn agf(session: &mut Session, argument: &str) -> Result<String, String> {
    let entry = crate::commands::parse_number(session, argument)?;
    let graph = graph_of(session, entry)?;
    Ok(r2s_tui::graph::text(&graph).trim_end().to_owned())
}

/// The engine's graph of the function at `entry`, each block's lines spelled as `pd` spells them.
fn graph_of(session: &mut Session, entry: u64) -> Result<Graph, String> {
    let answer = session.program.function_graph(entry)?;
    if answer.blocks.is_empty() {
        return Err(format!("no blocks at {entry:#x}"));
    }
    let index = |address: u64| {
        answer
            .blocks
            .binary_search_by_key(&address, |block| block.address)
            .ok()
    };
    let mut edges = Vec::new();
    for (from, block) in answer.blocks.iter().enumerate() {
        for edge in &block.edges {
            if let Some(to) = index(edge.target) {
                let kind = match edge.kind {
                    Edge::Jump => EdgeKind::Jump,
                    Edge::Fall => EdgeKind::Fall,
                    Edge::Taken => EdgeKind::Taken,
                    Edge::NotTaken => EdgeKind::NotTaken,
                    Edge::Case => EdgeKind::Case,
                    Edge::Default => EdgeKind::Default,
                };
                edges.push(GraphEdge { from, to, kind });
            }
        }
    }
    let nodes = answer
        .blocks
        .iter()
        .map(|block| GraphNode {
            address: block.address,
            size: block.size,
            lines: block
                .lines
                .iter()
                .map(|line| {
                    let text = crate::listing::instruction_text(session, line);
                    format!("{:#x}  {text}", line.address)
                })
                .collect(),
        })
        .collect();
    Ok(Graph {
        entry,
        nodes,
        edges,
        note: answer
            .refused
            .map(|refused| format!("analysis refused: {}", refused.reason)),
    })
}

/// The entry of the function an address is in: an entry is its own; inside
/// bodies discovery walked, the nearest of their entries at or below it, else
/// the first; otherwise the address itself, which the engine then answers for
/// as an entry.
///
/// Discovery's walk follows no dispatch table (ROADMAP P6), so a switch arm
/// is in no walked body; for an address no body holds, the nearest entry
/// below is asked whether its resolved graph holds it. That check goes when
/// every consumer reads one resolved body.
fn containing_entry(session: &mut Session, address: u64) -> Result<u64, String> {
    let holding = session.program.functions_holding(address)?;
    if holding.contains(&address) {
        return Ok(address);
    }
    if let Some(entry) = holding
        .iter()
        .rev()
        .find(|entry| **entry <= address)
        .or(holding.first())
    {
        return Ok(*entry);
    }
    let below = session
        .program
        .functions()?
        .into_iter()
        .map(|function| function.address)
        .filter(|entry| *entry < address)
        .max();
    let Some(below) = below else {
        return Ok(address);
    };
    let holds = session.program.function_graph(below).is_ok_and(|graph| {
        graph
            .blocks
            .iter()
            .any(|block| (block.address..block.address + block.size).contains(&address))
    });
    Ok(if holds { below } else { address })
}

/// The shell and the line reader a command typed in the visual mode runs with.
pub struct Visual<'a> {
    pub session: &'a mut Session,
}

impl Host for Visual<'_> {
    fn title(&self) -> String {
        let image = self.session.image();
        let arch = image.arch();
        format!(
            "{}  {:?} {} {}-bit",
            self.session.path,
            image.format(),
            arch.name,
            arch.bits
        )
    }

    fn seek(&self) -> u64 {
        self.session.addr
    }

    fn set_seek(&mut self, address: u64) {
        self.session.addr = address;
    }

    fn disassemble(&mut self, address: u64, count: usize) -> Vec<ListedLine> {
        let Ok(answer) = self.session.program.listing(Listing {
            start: address,
            stop: Stop::After(count),
        }) else {
            return Vec::new();
        };
        answer
            .value
            .iter()
            .map(|line| {
                let (text, roles) = crate::listing::instruction_painted(self.session, line);
                ListedLine {
                    address: line.address,
                    size: (line.bytes.len() as u64).max(1),
                    text,
                    roles,
                    target: line
                        .annotations
                        .iter()
                        .find_map(|annotation| match annotation.kind {
                            AnnotationKind::Target { address, .. } => Some(address),
                            _ => None,
                        }),
                }
            })
            .collect()
    }

    fn read(&self, address: u64, len: usize) -> Vec<u8> {
        self.session
            .image()
            .read_upto(address, len)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default()
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        self.session
            .image_mut()
            .write(address, bytes)
            .map_err(|error| error.to_string())
    }

    fn decompile(&mut self, address: u64) -> Result<Vec<DecompiledLine>, String> {
        // The function the address is in, so a cursor inside a body renders
        // that body rather than one starting where the cursor is.
        let entry = containing_entry(self.session, address)?;
        let rendering = self.session.program.rendered(entry, RenderTier::C)?;
        let name = self.session.program.names().of(entry).map_or_else(
            || format!("fcn.{entry:08x}"),
            r2engine::names::Name::spelled,
        );
        let answer = rendering.answer(&name, entry);
        // What each part of the unit is, as the renderer wrote it, cut at its
        // lines: the code is the emission's unit.
        let roles = match &rendering.response.output {
            r2engine::EngineRendering::Function(rendered) => {
                let unit = rendered.emission().unit_roles();
                r2s_tui::theme::by_line(&answer.code, &crate::listing::c_roles(&unit))
            }
            r2engine::EngineRendering::Listing(_) => Vec::new(),
        };
        let mut addresses = vec![Vec::new(); answer.code.lines().count()];
        for line in &answer.lines {
            if let Some(slot) = line
                .line
                .checked_sub(1)
                .and_then(|at| addresses.get_mut(at))
            {
                slot.extend(line.addrs.iter().copied());
                slot.sort_unstable();
                slot.dedup();
            }
        }
        Ok(answer
            .code
            .lines()
            .zip(addresses)
            .enumerate()
            .map(|(row, (text, addresses))| DecompiledLine {
                text: text.to_owned(),
                roles: roles.get(row).cloned().unwrap_or_default(),
                addresses,
            })
            .collect())
    }

    fn graph(&mut self, address: u64) -> Result<Graph, String> {
        let entry = containing_entry(self.session, address)?;
        graph_of(self.session, entry)
    }

    fn list(&mut self, kind: ListKind) -> Vec<Entry> {
        use crate::commands as listing;
        let session = &mut *self.session;
        let table = match kind {
            ListKind::Functions => listing::discovered(session),
            ListKind::Strings => listing::strings(session),
            ListKind::Sections => Ok(listing::sections(session)),
            ListKind::Symbols => listing::symbols(session),
            ListKind::Imports => Ok(listing::relocations(session)),
            ListKind::XrefsTo => {
                let at = session.addr;
                listing::references_table(session, at)
            }
        };
        // A row about no address (a section the loader does not map, an
        // import with no stub) is not a place to go.
        table
            .map(|table| {
                table
                    .rows
                    .into_iter()
                    .filter_map(|(address, text)| {
                        Some(Entry {
                            address: address?,
                            text: text.trim_end().to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn run(&mut self, command: &str) -> Result<String, String> {
        let mut reader = crate::line::Reader::default();
        let mut out = String::new();
        for statement in reader.script(command).into_iter().flatten() {
            out.push_str(&crate::commands::run(self.session, &statement?)?);
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "sleigh"))]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use r2s_tui::{Driver, Msg, View};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// `tests/gold/review.c` at -O0 with symbols; `main` at 0x1549 calls `add`
    /// at 0x11a9 first.
    fn fixture() -> Session {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/rv_O0g");
        Session::open(path).expect("the fixture opens")
    }

    fn screen(driver: &Driver) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("a terminal");
        terminal.draw(|frame| driver.draw(frame)).expect("a draw");
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn press(driver: &mut Driver, code: KeyCode) {
        let key = KeyEvent::new(code, KeyModifiers::NONE);
        assert!(driver.handle(Msg::Key(key)).expect("the engine is there"));
        driver.settle().expect("the engine answers");
    }

    /// From `main`, move down to the call to `add`, follow it, and look at
    /// the C.
    fn follow_the_call_and_decompile(mut driver: Driver, call: usize) {
        driver
            .handle(Msg::Resize(120, 30))
            .expect("the engine is there");
        driver.settle().expect("the engine answers");
        let shown = screen(&driver);
        assert!(shown.contains("0x00001549  endbr64"), "{shown}");
        for _ in 0..call {
            press(&mut driver, KeyCode::Char('j'));
        }
        press(&mut driver, KeyCode::Enter);
        assert_eq!(driver.app().seek(), 0x11a9);
        press(&mut driver, KeyCode::Char('p'));
        assert_eq!(driver.app().view(), View::Decompiler);
        let decompiled = screen(&driver);
        assert!(decompiled.contains("return"), "{decompiled}");
    }

    /// The panes show what the commands print: the disassembly row is `pd`'s
    /// spelling, following the first call lands on `add`, the decompiler pane
    /// renders the function the cursor is in, and the function list is
    /// `afl`'s rows with their addresses. The shell is served on this thread,
    /// where it lives, and the visual mode drawn on another, as `V` runs them.
    /// A list goes where its row is about, which the listing records rather
    /// than spells: in a binary whose file offsets differ from its addresses,
    /// the first number on an `iz`, `iS` or `is` row is the offset.
    #[test]
    fn a_list_goes_to_the_address_each_row_is_about() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/coverage/pinned/hashes_gcc_x64_O2"
        );
        let mut session = Session::open(path).expect("the fixture opens");
        let mut visual = Visual {
            session: &mut session,
        };
        let at = |visual: &mut Visual<'_>, kind, text: &str| {
            visual
                .list(kind)
                .into_iter()
                .find(|entry| entry.text.ends_with(text))
                .map(|entry| entry.address)
        };
        assert_eq!(
            at(&mut visual, ListKind::Sections, " .text"),
            Some(0x401050)
        );
        assert_eq!(
            at(&mut visual, ListKind::Symbols, " fnv1a32"),
            Some(0x401330)
        );
        assert_eq!(
            at(&mut visual, ListKind::Strings, "0123456789abcdef"),
            Some(0x402060)
        );
        assert_eq!(
            at(&mut visual, ListKind::Functions, " sym.fnv1a32"),
            Some(0x401330)
        );
    }

    /// `classify` at 0x120a: its entry, an instruction its walked body
    /// holds, and a switch arm only its resolved graph holds all name it;
    /// an address in no function names itself.
    #[test]
    fn an_address_is_answered_for_by_the_function_holding_it() {
        let mut session = fixture();
        assert_eq!(containing_entry(&mut session, 0x120a), Ok(0x120a));
        assert_eq!(containing_entry(&mut session, 0x121b), Ok(0x120a));
        assert_eq!(containing_entry(&mut session, 0x1246), Ok(0x120a));
        assert_eq!(containing_entry(&mut session, 0x1), Ok(0x1));
    }

    #[test]
    fn the_visual_mode_over_the_real_engine_follows_a_call_and_decompiles_it() {
        let mut session = fixture();
        session.addr = 0x1549;
        let mut host = Visual {
            session: &mut session,
        };
        let call = host
            .disassemble(0x1549, 64)
            .into_iter()
            .position(|line| line.target == Some(0x11a9))
            .expect("main calls add");
        let (driver, engine) = r2s_tui::connect();
        std::thread::scope(|scope| {
            let ui = scope.spawn(move || follow_the_call_and_decompile(driver, call));
            engine.serve(&mut host);
            if let Err(panic) = ui.join() {
                std::panic::resume_unwind(panic);
            }
        });
        // The shell's cursor is where the visual mode left it.
        assert_eq!(host.seek(), 0x11a9);
        // The graph of the function holding an address inside its body is
        // that function's: `sum_array`'s loop body is not a function.
        let graph = host.graph(0x11e5).expect("sum_array graphs");
        assert_eq!(graph.entry, 0x11c1);
        assert_eq!(
            graph.node_at(0x11e5).map(|node| graph.nodes[node].address),
            Some(0x11e0)
        );
        assert_eq!(graph.nodes.len(), 4, "{graph:?}");
        // So is the rendering: the cursor inside the loop renders the
        // function the loop is in, not one starting at the cursor.
        let inside = host.decompile(0x11e5).expect("sum_array renders");
        let from_entry = host.decompile(0x11c1).expect("sum_array renders");
        assert_eq!(inside, from_entry);
        assert!(
            inside.iter().any(|line| line.text.contains("sum_array(")),
            "{inside:?}"
        );
        let functions = host.list(r2s_tui::ListKind::Functions);
        assert!(
            functions.iter().any(|entry| entry.address == 0x1549),
            "{functions:?}"
        );
    }
}
