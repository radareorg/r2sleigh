//! What the visual mode asks of the shell.

/// One disassembly line, spelled as the shell's `pd` spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedLine {
    pub address: u64,
    /// How many bytes the line accounts for; at least one, so a cursor always
    /// moves forward.
    pub size: u64,
    pub text: String,
    /// Where the instruction transfers control, where it encodes one: what
    /// following the line jumps to.
    pub target: Option<u64>,
}

/// One line of decompiled C, with the instructions it was rendered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompiledLine {
    pub text: String,
    /// Sorted instruction addresses; empty for a line no instruction produced
    /// (a brace, a declaration).
    pub addresses: Vec<u64>,
}

/// One row of a list pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where choosing the row seeks.
    pub address: u64,
    pub text: String,
}

/// The lists the visual mode shows, each the shell's command of that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// `afl`
    Functions,
    /// `iz`
    Strings,
    /// `iS`
    Sections,
    /// `is`
    Symbols,
    /// `ii`
    Imports,
    /// `axt` at the cursor
    XrefsTo,
}

impl ListKind {
    pub const ALL: [ListKind; 6] = [
        ListKind::Functions,
        ListKind::Strings,
        ListKind::Sections,
        ListKind::Symbols,
        ListKind::Imports,
        ListKind::XrefsTo,
    ];

    pub fn title(self) -> &'static str {
        match self {
            ListKind::Functions => "functions",
            ListKind::Strings => "strings",
            ListKind::Sections => "sections",
            ListKind::Symbols => "symbols",
            ListKind::Imports => "imports",
            ListKind::XrefsTo => "xrefs to",
        }
    }
}

/// The shell, as the visual mode sees it.
///
/// Every answer is already spelled: the shell owns the spelling, and the
/// visual mode only lays it out.
pub trait Host {
    /// What the title bar names: the file, its format and machine.
    fn title(&self) -> String;

    /// The shell's cursor.
    fn seek(&self) -> u64;
    fn set_seek(&mut self, address: u64);

    /// `count` lines of disassembly from `address`. Fewer, or none, where
    /// nothing is mapped.
    fn disassemble(&mut self, address: u64, count: usize) -> Vec<ListedLine>;

    /// Up to `len` bytes from `address`, as the program reads them now
    /// (patches included). Shorter where the mapping ends.
    fn read(&self, address: u64, len: usize) -> Vec<u8>;

    /// Write bytes into the patch layer.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), String>;

    /// The decompiled function that contains `address`.
    fn decompile(&mut self, address: u64) -> Result<Vec<DecompiledLine>, String>;

    /// One of the lists, as its command lists it.
    fn list(&mut self, kind: ListKind) -> Vec<Entry>;

    /// Run any shell command, as the prompt would.
    fn run(&mut self, command: &str) -> Result<String, String>;
}
