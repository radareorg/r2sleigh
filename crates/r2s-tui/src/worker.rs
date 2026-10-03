//! The engine's thread: the only place the [`Host`] is asked anything.
//!
//! The thread that reads keys and draws sends [`Request`]s and receives
//! [`Answer`]s; it never holds the host. Requests are served in the order they
//! were sent, so a seek, a write or a command is seen by every request sent
//! after it and by none sent before, and an answer never arrives ahead of
//! one asked earlier.

use crate::host::{DecompiledLine, Entry, Graph, Host, ListKind, ListedLine};
use std::sync::mpsc::{Receiver, Sender};

/// What a pane shows, named by what it was asked at. One key, one answer:
/// two requests with the same key are answered alike until the program
/// changes, which is what lets the visual mode keep answers by key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// `count` disassembly lines from `at`, and up to `back` lines before it.
    Lines { at: u64, count: usize, back: usize },
    /// `len` bytes from `at`.
    Bytes { at: u64, len: usize },
    /// The rendering of the function holding the address.
    Decompiled(u64),
    /// The graph of the function holding the address.
    Graph(u64),
    /// A list; the address is the seek for the lists that depend on it
    /// (`axt`), zero for the others.
    List(ListKind, u64),
}

/// The disassembly around an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The starts of the lines before the window's first, nearest first: what
    /// scrolling up lands on. Shorter than asked only at address zero.
    pub before: Vec<u64>,
    /// The lines from the window's address; shorter than asked where the
    /// mapping ends.
    pub lines: Vec<ListedLine>,
}

/// An answer's payload, by the kind of its [`Key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    Lines(Window),
    Bytes(Vec<u8>),
    Decompiled(Result<Vec<DecompiledLine>, String>),
    Graph(Result<Graph, String>),
    List(Vec<Entry>),
}

/// What the visual mode asks of the engine's thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Move the shell's cursor; nothing is answered.
    Seek(u64),
    /// Fetch what a pane shows. `tag` is the visual mode's, returned with the
    /// answer so it can tell a current answer from one it no longer wants.
    Fetch { tag: u64, key: Key },
    /// Write bytes into the patch layer.
    Write { at: u64, bytes: Vec<u8> },
    /// Run a shell command, as the prompt would.
    Run(String),
    /// Resolve a seek target (an address expression or a name) through the
    /// shell's `s`, leaving the shell's cursor where it was.
    Goto(String),
    /// Answered with [`Answer::Flushed`] once every request before it is.
    Flush,
}

/// What the engine's thread answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Sent once, first: the title bar's text and the shell's cursor.
    Opened {
        title: String,
        seek: u64,
    },
    Fetched {
        tag: u64,
        key: Key,
        value: Fetched,
    },
    /// A write; one that succeeded changed the program, so every answer
    /// held from before it is out of date.
    Wrote {
        at: u64,
        result: Result<(), String>,
    },
    /// A command's output, and the shell's cursor before and after it. A
    /// command may write, rename or analyse, so every answer held from
    /// before it is out of date.
    Ran {
        result: Result<String, String>,
        from: u64,
        seek: u64,
    },
    Went(Result<u64, String>),
    Flushed,
}

/// The engine's end of the visual mode: requests in, answers out.
pub struct Engine {
    pub(crate) requests: Receiver<Request>,
    pub(crate) answers: Sender<Answer>,
}

impl Engine {
    /// Serve requests with `host`, on the calling thread, until the visual
    /// mode hangs up.
    ///
    /// Returns when the request channel closes (the visual mode left) or the
    /// answer channel does (nobody is left to read an answer).
    pub fn serve(self, host: &mut dyn Host) {
        let opened = Answer::Opened {
            title: host.title(),
            seek: host.seek(),
        };
        if self.answers.send(opened).is_err() {
            return;
        }
        while let Ok(request) = self.requests.recv() {
            if let Some(answer) = answer(host, request)
                && self.answers.send(answer).is_err()
            {
                return;
            }
        }
    }
}

/// Serve one request; a seek is not answered.
fn answer(host: &mut dyn Host, request: Request) -> Option<Answer> {
    Some(match request {
        Request::Seek(address) => {
            host.set_seek(address);
            return None;
        }
        Request::Fetch { tag, key } => {
            let value = fetch(host, key);
            Answer::Fetched { tag, key, value }
        }
        Request::Write { at, bytes } => {
            let result = host.write(at, &bytes);
            Answer::Wrote { at, result }
        }
        Request::Run(command) => {
            let from = host.seek();
            let result = host.run(&command);
            Answer::Ran {
                result,
                from,
                seek: host.seek(),
            }
        }
        Request::Goto(target) => {
            let before = host.seek();
            let went = host.run(&format!("s {target}")).map(|_| host.seek());
            host.set_seek(before);
            Answer::Went(went)
        }
        Request::Flush => Answer::Flushed,
    })
}

fn fetch(host: &mut dyn Host, key: Key) -> Fetched {
    match key {
        Key::Lines { at, count, back } => {
            let lines = host.disassemble(at, count);
            let mut before = Vec::with_capacity(back);
            let mut top = at;
            while before.len() < back && top > 0 {
                top = line_before(host, top);
                before.push(top);
            }
            Fetched::Lines(Window { before, lines })
        }
        Key::Bytes { at, len } => Fetched::Bytes(host.read(at, len)),
        Key::Decompiled(at) => Fetched::Decompiled(host.decompile(at)),
        Key::Graph(at) => Fetched::Graph(host.graph(at)),
        Key::List(kind, _) => Fetched::List(host.list(kind)),
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
