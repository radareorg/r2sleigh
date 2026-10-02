//! The shell as the visual mode's host.
//!
//! Every pane is spelled here by the same code the commands use: a
//! disassembly row is `pd`'s, a decompiled line is `pddj`'s, a list row is the
//! row its command prints. The visual mode only lays them out.

use crate::session::Session;
use r2engine::RenderTier;
use r2engine::query::{AnnotationKind, Listing, Stop};
use r2s_tui::{DecompiledLine, Entry, Host, ListKind, ListedLine};

/// `V`: the visual mode, from the prompt, returning to it on `q`.
pub(crate) fn open(session: &mut Session) -> Result<String, String> {
    r2s_tui::run(&mut Visual { session }).map_err(|error| format!("visual mode: {error}"))?;
    Ok(String::new())
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
            .map(|line| ListedLine {
                address: line.address,
                size: (line.bytes.len() as u64).max(1),
                text: crate::listing::instruction_text(self.session, line),
                target: line
                    .annotations
                    .iter()
                    .find_map(|annotation| match annotation.kind {
                        AnnotationKind::Target { address, .. } => Some(address),
                        _ => None,
                    }),
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
        // As `pdd` asks: the function the engine finds at this address.
        let entry = address;
        let rendering = self.session.program.rendered(entry, RenderTier::C)?;
        let name = self.session.program.names().of(entry).map_or_else(
            || format!("fcn.{entry:08x}"),
            r2engine::names::Name::spelled,
        );
        let answer = rendering.answer(&name, entry);
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
            .map(|(text, addresses)| DecompiledLine {
                text: text.to_owned(),
                addresses,
            })
            .collect())
    }

    fn list(&mut self, kind: ListKind) -> Vec<Entry> {
        let command = match kind {
            ListKind::Functions => "afl".to_owned(),
            ListKind::Strings => "iz".to_owned(),
            ListKind::Sections => "iS".to_owned(),
            ListKind::Symbols => "is".to_owned(),
            ListKind::Imports => "ir".to_owned(),
            ListKind::XrefsTo => format!("axt {:#x}", self.session.addr),
        };
        let Ok(output) = self.run(&command) else {
            return Vec::new();
        };
        // Each row of these commands names its address as the first
        // hexadecimal number on it; a row with none (a header) is not a place.
        output
            .lines()
            .filter_map(|row| {
                let address = row
                    .split(|c: char| c.is_whitespace() || c == ',' || c == '=')
                    .find_map(|token| token.strip_prefix("0x"))
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())?;
                Some(Entry {
                    address,
                    text: row.trim_end().to_owned(),
                })
            })
            .collect()
    }

    fn run(&mut self, command: &str) -> Result<String, String> {
        let mut reader = crate::line::Reader::default();
        let mut out = String::new();
        for line in reader.script(command) {
            for statement in line {
                let statement = statement?;
                let text = crate::commands::run(self.session, &statement)?;
                out.push_str(&text);
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "sleigh"))]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use r2s_tui::{App, View};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// `tests/gold/review.c` at -O0 with symbols; `main` at 0x1549 calls `add`
    /// at 0x11a9 first.
    fn fixture() -> Session {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/rv_O0g");
        Session::open(path).expect("the fixture opens")
    }

    fn screen(app: &mut App, host: &mut Visual<'_>) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("a terminal");
        terminal
            .draw(|frame| app.draw(frame, host))
            .expect("a draw");
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

    fn press(app: &mut App, host: &mut Visual<'_>, code: KeyCode) {
        assert!(app.handle_key(host, KeyEvent::new(code, KeyModifiers::NONE)));
    }

    /// The panes show what the commands print: the disassembly row is `pd`'s
    /// spelling, following the first call lands on `add`, the decompiler pane
    /// renders the function the cursor is in, and the function list is
    /// `afl`'s rows with their addresses.
    #[test]
    fn the_visual_mode_over_the_real_engine_follows_a_call_and_decompiles_it() {
        let mut session = fixture();
        session.addr = 0x1549;
        let mut host = Visual {
            session: &mut session,
        };
        let mut app = App::new(&host);
        let shown = screen(&mut app, &mut host);
        assert!(shown.contains("0x00001549  endbr64"), "{shown}");
        let call = host
            .disassemble(0x1549, 64)
            .into_iter()
            .position(|line| line.target == Some(0x11a9))
            .expect("main calls add");
        for _ in 0..call {
            press(&mut app, &mut host, KeyCode::Char('j'));
        }
        screen(&mut app, &mut host);
        press(&mut app, &mut host, KeyCode::Enter);
        assert_eq!(host.seek(), 0x11a9);
        press(&mut app, &mut host, KeyCode::Char('p'));
        assert_eq!(app.view(), View::Decompiler);
        let decompiled = screen(&mut app, &mut host);
        assert!(decompiled.contains("return"), "{decompiled}");
        let functions = host.list(r2s_tui::ListKind::Functions);
        assert!(
            functions.iter().any(|entry| entry.address == 0x1549),
            "{functions:?}"
        );
    }
}
