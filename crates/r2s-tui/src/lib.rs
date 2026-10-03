//! The visual mode of r2s.
//!
//! radare2's visual mode is a set of panes over one cursor: disassembly,
//! decompiled C, hex, lists of what the binary holds, and a command line that
//! runs anything the shell can. This crate is that, drawn with ratatui.
//!
//! It owns no fact about the program. Everything it shows comes through
//! [`Host`], which the shell implements with the same spellers its commands
//! use, so a line in the disassembly pane is the line `pd` prints and a pane
//! never disagrees with the command line beneath it. That also keeps this
//! crate free of the engine: it depends on nothing but the terminal.
//!
//! The host is asked only on the engine's thread ([`serve`]); the thread that
//! reads the terminal and draws holds the state ([`App`]) and never calls it.
//! Keys, mouse, resizes, the engine's answers and a clock tick arrive as one
//! stream of [`Msg`]s, so a decompilation that takes seconds leaves every
//! other key answered and every frame drawn.

mod app;
pub mod graph;
pub mod highlight;
mod host;
mod view;
mod worker;

pub use app::{App, Effect, Msg, View};
pub use host::{
    DecompiledLine, EdgeKind, Entry, Graph, GraphEdge, GraphNode, Host, ListKind, ListedLine,
};
pub use view::PENDING;
pub use worker::{Answer, Engine, Fetched, Key, Request, Window};

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;

/// How long the event loop waits for the terminal before it ticks.
const TICK: Duration = Duration::from_millis(16);

/// The visual mode's state joined to the engine's thread: messages in,
/// requests out, answers back as messages.
pub struct Driver {
    app: App,
    requests: Sender<Request>,
    answers: Receiver<Answer>,
}

/// The two ends of the visual mode: the [`Driver`] for the thread that
/// draws, the [`Engine`] for the thread the host lives on. The engine serves
/// until the driver is dropped.
pub fn connect() -> (Driver, Engine) {
    let (requests, asked) = mpsc::channel();
    let (answered, answers) = mpsc::channel();
    let driver = Driver {
        app: App::new(),
        requests,
        answers,
    };
    let engine = Engine {
        requests: asked,
        answers: answered,
    };
    (driver, engine)
}

impl Driver {
    pub fn app(&self) -> &App {
        &self.app
    }

    pub fn draw(&self, frame: &mut ratatui::Frame<'_>) {
        self.app.draw(frame);
    }

    /// Handle one message; `false` once the user has left.
    pub fn handle(&mut self, msg: Msg) -> io::Result<bool> {
        for effect in self.app.update(msg) {
            match effect {
                Effect::Request(request) => {
                    if self.requests.send(request).is_err() {
                        return Err(gone());
                    }
                }
                Effect::Quit => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Handle every answer that has arrived, without waiting; whether there
    /// was any.
    pub fn pump(&mut self) -> io::Result<bool> {
        let mut any = false;
        loop {
            match self.answers.try_recv() {
                Ok(answer) => {
                    any = true;
                    self.handle(Msg::Answer(answer))?;
                }
                Err(TryRecvError::Empty) => return Ok(any),
                Err(TryRecvError::Disconnected) => return Err(gone()),
            }
        }
    }

    /// Wait until the engine's thread has served every request sent and the
    /// state has handled every answer, with nothing more asked.
    ///
    /// For a scripted caller (a test) that wants the state settled before it
    /// looks; the event loop never waits. Requests are served in order, so
    /// once a flush sent last is answered, everything before it is.
    pub fn settle(&mut self) -> io::Result<()> {
        loop {
            self.requests.send(Request::Flush).map_err(|_| gone())?;
            loop {
                let answer = self.answers.recv().map_err(|_| gone())?;
                if answer == Answer::Flushed {
                    break;
                }
                self.handle(Msg::Answer(answer))?;
            }
            if !self.app.waiting() {
                return Ok(());
            }
        }
    }
}

fn gone() -> io::Error {
    io::Error::other("the engine's thread stopped")
}

/// The terminal in the visual mode's state; restored when dropped, on every
/// way out, a panic included: a shell that returns to its prompt with raw
/// mode still on is unusable.
struct Screen;

impl Screen {
    fn enter() -> io::Result<Screen> {
        enable_raw_mode()?;
        // From here the guard exists, so a failure below still restores.
        let screen = Screen;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        Ok(screen)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// Run the visual mode on the terminal until the user leaves it.
///
/// The host is served on the calling thread, where it lives; the terminal is
/// read and drawn on a thread of its own that never touches the host. The
/// host is back, at the seek the user left, when this returns. Leaving while
/// the engine is in the middle of an answer restores the terminal at once and
/// returns when that answer is done.
pub fn run(host: &mut dyn Host) -> io::Result<()> {
    let screen = Screen::enter()?;
    let (driver, engine) = connect();
    std::thread::scope(|scope| {
        let ui = scope.spawn(move || {
            let mut driver = driver;
            let result = event_loop(&mut driver);
            // The terminal is the shell's again before the engine is done.
            drop(screen);
            result
        });
        engine.serve(host);
        ui.join()
            .unwrap_or_else(|_| Err(io::Error::other("the visual mode panicked")))
    })
}

fn event_loop(driver: &mut Driver) -> io::Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let size = terminal.size()?;
    driver.handle(Msg::Resize(size.width, size.height))?;
    let mut dirty = true;
    loop {
        if driver.pump()? {
            dirty = true;
        }
        if dirty {
            terminal.draw(|frame| driver.draw(frame))?;
            dirty = false;
        }
        let msg = if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => Msg::Key(key),
                Event::Mouse(mouse) => Msg::Mouse(mouse),
                Event::Resize(width, height) => Msg::Resize(width, height),
                _ => continue,
            }
        } else {
            // Only the spinner moves with time.
            dirty = driver.app().waiting();
            Msg::Tick
        };
        if !matches!(msg, Msg::Tick) {
            dirty = true;
        }
        if !driver.handle(msg)? {
            return Ok(());
        }
    }
}
