//! The `~` grep, read as radare2's documented grammar.
//!
//! radare2 defines the grammar in `libr/cons/grep.c`: `r_cons_grep_expression`
//! parses it and `r_cons_grepbuf` with `r_cons_grep_line` applies it. Here the
//! text after a statement's first unquoted `~` is parsed into a [`Grep`] before
//! the command runs, so a grep r2s cannot honour is refused before any side
//! effect, and a parsed grep selects from the text the shell spelled what
//! radare2 selects from it. Where radare2 contradicts its own documentation r2s
//! follows the documentation, and every such case is listed in [`JUDGED`] and
//! printed by `~??`.
//!
//! No character the grammar gives a meaning is matched as text: it is read as
//! grammar or the grep is refused.
//!
//! Each line is read as radare2 reads it, without its ANSI escapes. The one
//! line radare2 would print broken, where an escape takes the first byte of a
//! longer character with it, is refused when the grep meets it, after the
//! command ran.
//!
//! Cost: parsing reads the expression in a constant number of linear passes:
//! its escapes, its stages, and in each stage its modifiers, the places of its
//! first `[`, `]` and `:`, and its columns and rows. Applying is one pass over
//! the lines for their escapes and the words, one over the kept lines for the
//! columns, a slice for the rows, and a stable `O(k log k)` sort when an order
//! is asked for.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ops::Range;

use crate::line::{SPECIAL, blank};

/// What a statement's `~` asks for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Suffix {
    /// `~??`, or a statement that starts with `~?`: the grammar itself.
    Help,
    /// A grep over the command's output.
    Filter(Grep),
}

impl Suffix {
    /// What the text after a statement's first `~` asks for, where `alone`
    /// says the statement has no command before it.
    pub(crate) fn parse(text: &str, alone: bool) -> Result<Suffix, String> {
        if asks_for_help(text, alone) {
            return Ok(Suffix::Help);
        }
        Grep::parse(text).map(Suffix::Filter)
    }
}

/// radare2 shows the help when the first `~?` starts the statement or is the
/// whole rest of it (cmd.c:5217-5236). The search starts at the grep, so a
/// quoted or escaped `~??` is text.
fn asks_for_help(text: &str, alone: bool) -> bool {
    let grep = format!("~{text}");
    grep.find("~?")
        .is_some_and(|at| (at == 0 && alone) || &grep[at..] == "~??")
}

/// A parsed grep: which lines, which columns, which rows, in what order, and
/// whether they are printed or counted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Grep {
    /// Every stage must match a line. None means every line matches.
    stages: Vec<Stage>,
    /// The columns kept, in line order. None means the whole line.
    columns: Vec<ColumnSpan>,
    /// Row windows, each taken within the one before (grep.c:95-110).
    rows: Vec<RowSpan>,
    /// Which lines the rows count.
    row_base: RowBase,
    /// Blank lines are kept only when a grep is rows and nothing else
    /// (grep.c:872, 897).
    keep_blank: bool,
    order: Order,
    /// Result lines `$:n` keeps in place ahead of the ordered rest.
    header: usize,
    tally: Tally,
}

/// The words between two `~`, and how they must meet a line.
#[derive(Debug, PartialEq, Eq)]
struct Stage {
    /// Lowercased when `fold` is set.
    words: Vec<String>,
    join: Join,
    begin: bool,
    end: bool,
    fold: bool,
}

/// How a stage's words combine (grep.c:1064-1096).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Join {
    /// `,`: any word.
    Any,
    /// `&`: every word.
    All,
    /// `!`: no word. It wins over `&`.
    NoneOf,
}

/// `[n]`, `[n-m]`, `[n-]`: columns counted from 0, negatives from the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnSpan {
    first: i64,
    last: ColumnEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColumnEnd {
    At(i64),
    /// `[n-]`: to the last column.
    Open,
}

/// `:s..e`, half open. A negative start counts from the window's end, and so
/// does an end of zero or less.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RowSpan {
    first: i64,
    last: i64,
}

/// Which lines the rows count, from the order of the stages (grep.c:354-356).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowBase {
    /// Rows come in an earlier stage than columns: they count the lines the
    /// words kept, which are then projected. radare2 does so only for a grep
    /// without words; `w:r~[c]` in [`JUDGED`] records why r2s does not follow.
    Selected,
    /// Otherwise they count the lines left after projection.
    Projected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    Keep,
    Ascending,
    Unique,
    Descending,
    Reversed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tally {
    Lines,
    LineCount,
    ByteCount,
}

/// radare2 stops at nine stages (R_CONS_GREP_COUNT, grep.c:139).
const STAGES: usize = 9;
/// Column numbers lie in -64..64 (R_CONS_GREP_TOKENS, grep.c:517-525).
const COLUMNS: i64 = 64;
/// radare2 keeps at most 64 column spans, and drops them all past that.
const SPANS: usize = 64;
/// What separates columns (grep.c:1048).
const DELIMITERS: &[char] = &[' ', '|', ',', ';', '=', '\t'];
/// Escapes radare2 turns into grammar rather than text (cmd.c:5820 unescapes
/// `\~`, `\$`, `\<` and `\>` before the grammar reads them, and grep.c:336
/// splits words on every `,`).
const ESCAPED_INTO_GRAMMAR: &str = "~$<>,";

/// What a modifier at the head of a stage does.
#[derive(Clone, Copy)]
enum Effect {
    Join(Join),
    Fold,
    Begin,
    Count(Tally),
    Order(Order),
    /// radare2 gives it a meaning r2s does not implement.
    Refused,
}

/// One modifier of radare2's grammar (grep.c:162-292): what the parser
/// matches at the head of a stage, and what `~??` lists.
struct Modifier {
    spelling: &'static str,
    /// Only when it is the whole rest of the stage (`?ea`, grep.c:283).
    whole: bool,
    effect: Effect,
    meaning: &'static str,
}

const fn modifier(spelling: &'static str, effect: Effect, meaning: &'static str) -> Modifier {
    Modifier {
        spelling,
        whole: false,
        effect,
        meaning,
    }
}

const fn refused(spelling: &'static str, meaning: &'static str) -> Modifier {
    modifier(spelling, Effect::Refused, meaning)
}

const MODIFIERS: &[Modifier] = &[
    modifier(
        "&",
        Effect::Join(Join::All),
        "every word of the stage must match",
    ),
    modifier(
        "!",
        Effect::Join(Join::NoneOf),
        "no word of the stage may match; wins over &",
    ),
    modifier("+", Effect::Fold, "match ignoring ASCII case"),
    modifier("^", Effect::Begin, "words must start the line"),
    modifier(
        "?",
        Effect::Count(Tally::LineCount),
        "count the lines instead of printing them",
    ),
    modifier(
        "?.",
        Effect::Count(Tally::ByteCount),
        "count the bytes, one more for each line",
    ),
    modifier(
        "$",
        Effect::Order(Order::Ascending),
        "sort: numbers by value, then the other lines bytewise",
    ),
    modifier(
        "$$",
        Effect::Order(Order::Unique),
        "sort, then drop repeated lines",
    ),
    modifier("$!", Effect::Order(Order::Descending), "sort in reverse"),
    modifier(
        "$!!",
        Effect::Order(Order::Reversed),
        "reverse the lines, like tac",
    ),
    refused("??", "help inside a stage, where radare2 prints nothing"),
    Modifier {
        spelling: "?ea",
        whole: true,
        effect: Effect::Refused,
        meaning: "seven-segment ascii art",
    },
    refused("..", "the interactive pager"),
    refused("...", "the interactive HUD"),
    refused("....", "the one-line HUD"),
    refused("{", "JSON indentation, paths and gron: {} {: {=} {path}"),
    refused(":)", "parse C-like decompiler output"),
    refused(":))", "highlight code syntax"),
    refused(":}", "indent C code by its braces"),
    refused("<>", "xml indentation"),
    refused(
        "<",
        "zoom to a width; radare2 drops a `<` before anything but digits",
    ),
    refused(
        "*",
        "zoom level: documented, but radare2 never parses it (grep.c:42)",
    ),
];

/// The forms outside the modifier table that the parser reads.
const SHAPES: &[(&str, &str)] = &[
    ("word,word", "any of the words matches"),
    ("word$", "the stage's words must end the line"),
    ("a~b", "another stage: every stage must match; at most 9"),
    ("expr?", "a trailing ? counts the lines"),
    (
        "$:n",
        "with $ or $!: keep the first n lines in place, order the rest",
    ),
    (
        "[n]",
        "column n; columns are split at space | , ; = and tab",
    ),
    ("[-n]", "column n from the end"),
    ("[n-m]", "columns n to m"),
    ("[n-]", "columns n to the last"),
    ("[i,j,k]", "columns i, j and k, kept in line order"),
    (
        ":n",
        "row n; a negative n counts from the end. Rows in a stage before the columns \
         count the lines the words kept; otherwise they count the lines the columns leave",
    ),
    (
        ":s..e",
        "rows s up to e; an e of 0 or less counts from the end; clipped to the lines",
    ),
    (":s..", "rows s to the end"),
    (":..e", "rows up to e"),
    (
        "~:a~:b",
        "each later row window is taken within the one before, and clipped to it",
    ),
    (
        "\\X",
        "X as text, for X in @ ; # | ` \" ' ( ) and :, but for a `\\:` refused below; other \
         backslashes are text",
    ),
    (
        "ESC",
        "each line is read without its ANSI escapes, as radare2 reads it (grep.c:907-912): ESC [ \
         to the first J m H or K, ESC # to the first q, otherwise ESC and the byte after it. A \
         line where that byte starts a longer character is refused once the command has run: \
         radare2 prints the rest of the character, which is not text",
    ),
];

/// The forms the parser refuses, with nothing run.
const REFUSED: &[(&str, &str)] = &[
    ("$n", "sort by column n: radare2 discards n (grep.c:244)"),
    (
        "$$:n",
        "radare2 drops the kept lines when it removes repeats",
    ),
    ("$!!:n", "radare2 ignores n when it only reverses"),
    (
        "$$! $$!!",
        "radare2 reads the second `$` of `$$` again, so the `!` is not a negation: `$$!` \
         sorts in reverse and `$$!!` reverses, each then dropping repeats (grep.c:229-243)",
    ),
    (
        "$~:n",
        "an order with rows: radare2 sorts every line the words kept and drops the rows",
    ),
    ("$~$!", "a second order"),
    ("?.~?", "counting both lines and bytes"),
    (
        ":5..2",
        "a window that ends before it starts: radare2 shows from 5 to the end",
    ),
    (
        ":s..[c]",
        "an open row window just before columns: radare2 evaluates `[c]` as the window's end, \
         which reads memory (grep.c:98-101); `[c]:s..` is read the same by both",
    ),
    (
        "[x] :x",
        "a column or row that is not decimal: radare2 evaluates it as an expression",
    ),
    (
        ":010 [010]",
        "a row or column with a leading 0: radare2 reads it as octal, and `08` as 0 \
         (util/unum.c:332-348); `-010` is decimal in both",
    ),
    (
        ":4294967297 $:n",
        "a row, or a count of lines kept in place, wider than 32 bits: radare2 truncates it \
         to an int (grep.c:100-101, 247)",
    ),
    (
        "[64] [-65]",
        "a column outside -64..63 or more than 64 spans: radare2 drops them all",
    ),
    (
        "[n]x",
        "text after `]` or after the rows: radare2 drops it (grep.c:315)",
    ),
    (
        "x:y[c]:r",
        "rows after the columns where the stage's first bare `:` is text: radare2 reads rows \
         only at that first `:` (grep.c:309-314), so it reads none and drops what follows the \
         `]` (grep.c:315-317)",
    ),
    (
        "w]:r[c]",
        "columns after the rows where the stage's first `]` comes before its first `[`: \
         radare2 reads no columns there (grep.c:294-296) and evaluates `[c]` as part of the \
         rows' bound (grep.c:309-313)",
    ),
    (
        "\\~ \\$ \\< \\> \\,",
        "escapes radare2 turns into grammar rather than text",
    ),
    (
        "a:b\\:c a\\:b[n]",
        "a `\\:` after a bare `:`, or in words that end at a column block: radare2 reads `\\:` \
         as `:` only before the stage's first bare `:`, and cuts such words where the `[` stood \
         before it dropped the backslash (grep.c:13-27, 294-317)",
    ),
    (
        "word\\",
        "a trailing backslash escapes nothing: radare2 drops it (cmd.c:3512-3524)",
    ),
    (
        "a~b~...~j",
        "a tenth stage: radare2 prints the text ungrepped",
    ),
];

/// Where r2s follows radare2's documentation and radare2 does not. Each is a
/// radare2 defect of its own.
const JUDGED: &[(&str, &str)] = &[
    (
        "word:-n",
        "rows count back from the lines the words kept; radare2 counts back from every line \
         (grep.c:875-896), so `is~FUNC:-1` prints nothing there",
    ),
    (
        ":s..e?",
        "counts the rows shown, with or without words; radare2 counts at most one (grep.c:918, \
         967-969)",
    ),
    (
        "[c]:r",
        "rows count the projected lines; radare2 projects only the lines inside the window \
         (grep.c:1100-1103), so `is~[4]:2` is `_init` here and `__abi_tag` there",
    ),
    (
        "w:r~[c]",
        "rows in a stage before the columns count every line the words kept, one whose columns \
         are empty too; radare2 keeps that stage order only in a grep without words (grep.c:897, \
         960): with words, a missed word and empty columns both return 0 from r_cons_grep_line \
         (grep.c:928, 1134), so `is~--,FUNC~:0..3~[4]` is `_init main` here and \
         `_init main _start` there",
    ),
    (
        ".word",
        "a `.` among the modifiers is text, and so is what follows it; radare2 skips it and \
         reads on (grep.c:190), so `~.text` matches `text` and `~.!FUNC` negates there",
    ),
    (
        ":-100.. :-2..3",
        "a window is clipped to the lines, and one that ends before it starts is empty; radare2 \
         shows from reaching the exact start line to reaching the exact end line (grep.c:880-895, \
         917-923), so a start before the first line shows nothing and an end before the start \
         shows to the last line",
    ),
    (
        ":5..10~:-7.. a:1~b:2",
        "a later window is clipped to the one before it; radare2 adds their bounds unclipped \
         (grep.c:102-108), so a later window can start before the earlier one, or start past it \
         and then run to the last line",
    ),
    (
        ",  ,:1  $,",
        "words that are only commas select every line, and the rest of the grep applies; \
         radare2 then runs no grep at all unless there is a column block (grep.c:333-356, \
         cons.c:810), keeping blank lines and ANSI escapes and ignoring rows, counts and \
         orders, so `?e b\\na~$,` prints `b` and `a` there; `~,[1]` projects in both",
    ),
    (
        "$",
        "numbers sort before every other line, by exact decimal value; radare2 compares a \
         number with a line that is not one by strcmp, so a number can sort after such a line, \
         and that comparator is not transitive; it also reads a leading 0 as octal and wraps \
         past 64 bits (grep.c:452-464)",
    ),
    (
        "a\\~?? \"~?\"~??",
        "only the grep's own first `~?` asks for the help, where it starts the statement or is \
         the whole rest of it; radare2 finds the statement's first `~?` with strstr (cmd.c:5219), \
         so an escaped `~` asks for it there (`?e a\\~??`), and a quoted `~?` ahead of the grep \
         hides it (`?e \"a~?\" b~??` counts the line)",
    ),
];

/// The grammar, generated from the tables the parser reads.
pub(crate) fn help() -> String {
    let mut out = String::from("Usage: [command]~[modifier][word,word][$][[column]][:rows][?]\n");
    let (done, refusals): (Vec<&Modifier>, Vec<&Modifier>) = MODIFIERS
        .iter()
        .partition(|one| !matches!(one.effect, Effect::Refused));
    let listed = |set: Vec<&Modifier>| {
        set.into_iter()
            .map(|one| (one.spelling, one.meaning))
            .collect::<Vec<_>>()
    };
    section(&mut out, "modifiers, at the head of a stage", &listed(done));
    section(&mut out, "shapes", SHAPES);
    let mut refused = listed(refusals);
    refused.extend_from_slice(REFUSED);
    section(&mut out, "refused, and the command not run", &refused);
    section(&mut out, "where r2s follows the documentation", JUDGED);
    out.trim_end().to_owned()
}

fn section(out: &mut String, title: &str, rows: &[(&str, &str)]) {
    out.push_str(&format!("{title}:\n"));
    for (spelling, meaning) in rows {
        out.push_str(&format!(" {spelling:<16} {meaning}\n"));
    }
}

/// One character of a grep, and whether a backslash made it text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Atom {
    ch: char,
    held: bool,
}

impl Atom {
    fn is(self, ch: char) -> bool {
        !self.held && self.ch == ch
    }
}

/// The grep's characters with its escapes read: `\X` for X in [`SPECIAL`]
/// and `\:` are text (cmd.c:5820, grep.c:13), the escapes radare2 turns into
/// grammar are refused, and any other backslash is text.
fn atoms(text: &str) -> Result<Vec<Atom>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek().is_none() {
            return Err(
                "grep: a trailing `\\` escapes nothing and is refused: radare2 drops it".to_owned(),
            );
        }
        let escaped = chars.peek().copied().filter(|_| ch == '\\');
        match escaped {
            Some(next) if ESCAPED_INTO_GRAMMAR.contains(next) => {
                return Err(format!(
                    "grep: `\\{next}` is refused: radare2 reads it as grammar, not as text"
                ));
            }
            Some(next) if next == ':' || SPECIAL.contains(next) => {
                chars.next();
                out.push(Atom {
                    ch: next,
                    held: true,
                });
            }
            _ => out.push(Atom {
                ch,
                held: ch == '\\',
            }),
        }
    }
    Ok(out)
}

fn text(atoms: &[Atom]) -> String {
    atoms.iter().map(|atom| atom.ch).collect()
}

/// The grep as it is read, stage by stage.
struct Reading {
    grep: Grep,
    /// The last stage with rows and the last with columns (grep.c:354).
    row_stage: Option<usize>,
    column_stage: Option<usize>,
    /// Whether any stage has word text, commas included (grep.c:872).
    word_text: bool,
}

/// The modifiers read at the head of one stage.
#[derive(Clone, Copy)]
struct Flags {
    join: Join,
    begin: bool,
    fold: bool,
}

impl Flags {
    fn join(&mut self, join: Join) {
        if self.join != Join::NoneOf {
            self.join = join;
        }
    }
}

impl Grep {
    fn parse(text: &str) -> Result<Grep, String> {
        let mut atoms = atoms(text)?;
        let mut reading = Reading::new();
        if atoms.last().is_some_and(|atom| atom.is('?')) {
            atoms.pop();
            reading.count(Tally::LineCount)?;
        }
        let stages: Vec<&[Atom]> = atoms.split(|atom| atom.is('~')).collect();
        if stages.len() > STAGES {
            return Err(format!(
                "grep: {} stages is too many; radare2 reads at most {STAGES}",
                stages.len()
            ));
        }
        for (index, stage) in stages.into_iter().enumerate() {
            reading.stage(index, stage)?;
        }
        reading.finish()
    }
}

impl Reading {
    fn new() -> Reading {
        Reading {
            grep: Grep {
                stages: Vec::new(),
                columns: Vec::new(),
                rows: Vec::new(),
                row_base: RowBase::Projected,
                keep_blank: false,
                order: Order::Keep,
                header: 0,
                tally: Tally::Lines,
            },
            row_stage: None,
            column_stage: None,
            word_text: false,
        }
    }

    /// One stage: modifiers, words, then columns and rows in either order.
    fn stage(&mut self, index: usize, atoms: &[Atom]) -> Result<(), String> {
        let mut flags = Flags {
            join: Join::Any,
            begin: false,
            fold: false,
        };
        let rest = self.modifiers(atoms, &mut flags)?;
        let marks = Marks::find(rest);
        let end = marks.words_end(rest.len());
        escaped_colons(rest, end, marks)?;
        self.tail(index, rest, end, marks)?;
        self.words(&rest[..end], flags);
        Ok(())
    }

    /// Read modifiers while the head of the stage is one, longest first.
    fn modifiers<'a>(
        &mut self,
        mut atoms: &'a [Atom],
        flags: &mut Flags,
    ) -> Result<&'a [Atom], String> {
        while let Some(found) = modifier_at(atoms) {
            atoms = &atoms[found.spelling.len()..];
            atoms = self.modify(found, atoms, flags)?;
        }
        Ok(atoms)
    }

    fn modify<'a>(
        &mut self,
        found: &Modifier,
        atoms: &'a [Atom],
        flags: &mut Flags,
    ) -> Result<&'a [Atom], String> {
        match found.effect {
            Effect::Join(join) => flags.join(join),
            Effect::Fold => flags.fold = true,
            Effect::Begin => flags.begin = true,
            Effect::Count(tally) => self.count(tally)?,
            Effect::Order(order) => return self.order(order, atoms),
            Effect::Refused => {
                return Err(format!(
                    "grep: `{}` ({}) is not supported",
                    found.spelling, found.meaning
                ));
            }
        }
        Ok(atoms)
    }

    fn count(&mut self, tally: Tally) -> Result<(), String> {
        if self.grep.tally != Tally::Lines && self.grep.tally != tally {
            return Err("grep: a grep counts lines (`?`) or bytes (`?.`), not both".to_owned());
        }
        self.grep.tally = tally;
        Ok(())
    }

    /// `$`, `$$`, `$!`, `$!!`, and what may follow them (grep.c:229-250).
    fn order<'a>(&mut self, order: Order, atoms: &'a [Atom]) -> Result<&'a [Atom], String> {
        if self.grep.order != Order::Keep {
            return Err("grep: a second `$` order is refused; a grep has one order".to_owned());
        }
        self.grep.order = order;
        match atoms.first() {
            Some(atom) if atom.ch.is_ascii_digit() => Err(
                "grep: `$n` (sort by column n) is not supported: radare2 discards n (grep.c:244)"
                    .to_owned(),
            ),
            // radare2 leaves the second `$` of `$$` unread and reads it again as
            // an order, so the `!` after it inverts that order (grep.c:229-243).
            Some(atom) if order == Order::Unique && atom.is('!') => Err(
                "grep: `$$!` is refused: radare2 reads it as a reverse sort, and `$$!!` as a \
                 reversal, each dropping repeats, not as `$$` and a negation"
                    .to_owned(),
            ),
            Some(atom) if atom.is(':') => self.header(order, &atoms[1..]),
            _ => Ok(atoms),
        }
    }

    /// `$:n`: the first n lines stay in place.
    fn header<'a>(&mut self, order: Order, atoms: &'a [Atom]) -> Result<&'a [Atom], String> {
        let digits = atoms
            .iter()
            .take_while(|atom| atom.ch.is_ascii_digit())
            .count();
        if digits == 0 {
            return Err("grep: `$:` needs the number of lines to keep in place".to_owned());
        }
        if matches!(order, Order::Unique | Order::Reversed) {
            return Err(
                "grep: `$$:n` and `$!!:n` are refused: radare2 drops or ignores the kept lines"
                    .to_owned(),
            );
        }
        // radare2 reads n with atoi, so a wider n is truncated (grep.c:247).
        self.grep.header = text(&atoms[..digits])
            .parse::<i32>()
            .ok()
            .and_then(|header| usize::try_from(header).ok())
            .ok_or_else(|| {
                "grep: `$:n` wider than 32 bits is refused: radare2 truncates it".to_owned()
            })?;
        Ok(&atoms[digits..])
    }

    /// Columns and rows after the words, which end at `at`: `[c]`, `:r`,
    /// `[c]:r` or `:r[c]`, each where radare2 looks for it, and nothing else
    /// (radare2 drops the rest, grep.c:315).
    fn tail(
        &mut self,
        index: usize,
        stage: &[Atom],
        mut at: usize,
        marks: Marks,
    ) -> Result<(), String> {
        let (mut columns, mut rows) = (false, false);
        while let Some(first) = stage.get(at) {
            if first.is('[') && !columns {
                let close = marks.column_block(stage, at)?;
                self.columns(index, &stage[at + 1..close])?;
                at = close + 1;
                columns = true;
            } else if first.is(':') && !rows {
                marks.row_marker(stage, at)?;
                let close = stage[at..]
                    .iter()
                    .position(|atom| atom.is('['))
                    .map_or(stage.len(), |offset| at + offset);
                self.rows(index, &stage[at + 1..close], close < stage.len())?;
                at = close;
                rows = true;
            } else {
                return Err(format!(
                    "grep: `{}` after the columns or rows is refused: radare2 drops it",
                    text(&stage[at..])
                ));
            }
        }
        Ok(())
    }

    fn columns(&mut self, index: usize, atoms: &[Atom]) -> Result<(), String> {
        let spans = text(atoms)
            .split(',')
            .map(|item| item.trim_matches(blank))
            .filter(|item| !item.is_empty())
            .map(ColumnSpan::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if spans.is_empty() {
            // `[]` keeps whole lines, as it does in radare2.
            return Ok(());
        }
        self.grep.columns.extend(spans);
        if self.grep.columns.len() > SPANS {
            return Err(format!(
                "grep: more than {SPANS} column spans; radare2 would drop them all"
            ));
        }
        self.column_stage = Some(index);
        Ok(())
    }

    /// A row window, and whether columns follow it in the same stage.
    fn rows(&mut self, index: usize, atoms: &[Atom], columns: bool) -> Result<(), String> {
        let spelled = text(atoms);
        // radare2 does not cut the rows at the `[`: it evaluates the text
        // after `..` as the end, so `[c]` becomes a memory read (grep.c:98-101,
        // r_num_get).
        if columns && spelled.ends_with("..") {
            return Err(format!(
                "grep: `:{spelled}[` is refused: radare2 reads the columns as the end of the \
                 rows, an expression that reads memory; put the columns first"
            ));
        }
        let span = RowSpan::parse(&spelled).ok_or_else(|| {
            format!(
                "grep: `:{spelled}` is not a row window; rows are 32-bit decimals with no \
                 leading 0, which radare2 reads as octal: :n :s..e :s.. :..e"
            )
        })?;
        if span.inverted() {
            return Err(format!(
                "grep: `:{spelled}` ends before it starts; radare2 would show to the end"
            ));
        }
        self.grep.rows.push(span);
        self.row_stage = Some(index);
        Ok(())
    }

    /// The stage's words: split at `,`, with a trailing `$` anchoring every
    /// one of them to the end (grep.c:319-353).
    fn words(&mut self, atoms: &[Atom], flags: Flags) {
        let end = atoms.len() > 1 && atoms.last().is_some_and(|atom| atom.is('$'));
        let atoms = if end {
            &atoms[..atoms.len() - 1]
        } else {
            atoms
        };
        self.word_text |= !atoms.is_empty();
        let words: Vec<String> = atoms
            .split(|atom| atom.is(','))
            .map(text)
            .filter(|word| !word.is_empty())
            .map(|word| {
                if flags.fold {
                    word.to_ascii_lowercase()
                } else {
                    word
                }
            })
            .collect();
        if !words.is_empty() {
            self.grep.stages.push(Stage {
                words,
                join: flags.join,
                begin: flags.begin,
                end,
                fold: flags.fold,
            });
        }
    }

    fn finish(mut self) -> Result<Grep, String> {
        if !self.grep.rows.is_empty() && self.grep.order != Order::Keep {
            return Err(
                "grep: rows with an order are refused: radare2 sorts every line the words kept \
                 and drops the rows"
                    .to_owned(),
            );
        }
        self.grep.row_base = match (self.row_stage, self.column_stage) {
            (Some(rows), Some(columns)) if rows < columns => RowBase::Selected,
            _ => RowBase::Projected,
        };
        self.grep.keep_blank = !self.grep.rows.is_empty() && !self.word_text;
        Ok(self.grep)
    }
}

/// The longest modifier the stage starts with.
fn modifier_at(atoms: &[Atom]) -> Option<&'static Modifier> {
    MODIFIERS
        .iter()
        .filter(|one| {
            let length = one.spelling.len();
            let prefix = atoms.len() >= length
                && one
                    .spelling
                    .chars()
                    .zip(atoms)
                    .all(|(ch, atom)| atom.is(ch));
            prefix && (!one.whole || atoms.len() == length)
        })
        .max_by_key(|one| one.spelling.len())
}

/// Where radare2 looks for a stage's columns and rows, each in one place
/// (grep.c:294-317).
#[derive(Clone, Copy)]
struct Marks {
    /// The stage's first `[` and first `]`, when the `[` comes first: the one
    /// column block radare2 reads (grep.c:294-296).
    columns: Option<(usize, usize)>,
    /// The stage's first bare `:`, the only place radare2 reads rows
    /// (`strchr_ns`, grep.c:309).
    colon: Option<usize>,
    /// Whether rows start there: a digit, `-` or `.` follows the `:`; after
    /// anything else the `:` is text (grep.c:310).
    rows: bool,
}

impl Marks {
    fn find(stage: &[Atom]) -> Marks {
        let first = |ch: char| stage.iter().position(|atom| atom.is(ch));
        let columns = first('[')
            .zip(first(']'))
            .filter(|(open, close)| open < close);
        let colon = first(':');
        let rows = colon
            .and_then(|at| stage.get(at + 1))
            .is_some_and(|next| next.ch.is_ascii_digit() || next.is('-') || next.is('.'));
        Marks {
            columns,
            colon,
            rows,
        }
    }

    /// Where the words end: at the column block or the rows, whichever is
    /// first.
    fn words_end(self, length: usize) -> usize {
        let columns = self.columns.map(|(open, _)| open);
        let rows = self.colon.filter(|_| self.rows);
        columns.into_iter().chain(rows).min().unwrap_or(length)
    }

    /// The `]` of the column block whose `[` is at `at`. radare2 reads no
    /// other: where the stage's first `]` comes before its first `[`, it
    /// reads no columns and evaluates a later `[c]` as part of the rows'
    /// bound (grep.c:294-296, 309-313).
    fn column_block(self, stage: &[Atom], at: usize) -> Result<usize, String> {
        match self.columns {
            Some((open, close)) if open == at => Ok(close),
            Some(_) => Err(format!(
                "grep: `{}` after the columns or rows is refused: radare2 drops it",
                text(&stage[at..])
            )),
            None => Err(format!(
                "grep: `{}` is refused: the stage's first `]` comes before its first `[`, so \
                 radare2 reads no columns and evaluates this as part of the rows' bound",
                text(&stage[at..])
            )),
        }
    }

    /// Whether the `:` at `at` may start rows: only the stage's first bare
    /// `:` does. Where that one is text, radare2 reads no rows, and drops
    /// what follows the column block (grep.c:309-317).
    fn row_marker(self, stage: &[Atom], at: usize) -> Result<(), String> {
        if self.colon == Some(at) {
            return Ok(());
        }
        Err(format!(
            "grep: `{}` is refused: radare2 reads rows only at the stage's first bare `:`, \
             which is text here, and drops what follows the columns",
            text(&stage[at..])
        ))
    }
}

/// A `\:` where radare2 does not read it as a `:`. radare2 removes the
/// backslash of each `\:` it passes on its way to the stage's first bare `:`,
/// shifting the text left, and stops there (`strchr_ns`, grep.c:13-27): after
/// that `:` the backslash stays. It found the column block before, so words
/// it cuts at the `[` take in one more character of the block for each
/// backslash removed ahead of it (grep.c:294-317).
fn escaped_colons(stage: &[Atom], end: usize, marks: Marks) -> Result<(), String> {
    let escaped = |atom: &Atom| atom.held && atom.ch == ':';
    let bare = marks.colon.unwrap_or(stage.len());
    if stage[bare..].iter().any(escaped) {
        return Err(
            "grep: a `\\:` after a bare `:` is refused: radare2 keeps its backslash as text there"
                .to_owned(),
        );
    }
    let cut_at_columns = marks.columns.is_some_and(|(open, _)| open == end);
    if cut_at_columns && stage[..end].iter().any(escaped) {
        return Err(
            "grep: a `\\:` in words that end at a column block is refused: radare2 cuts the \
             words where the `[` stood before it dropped the backslash, so they take in the `[`"
                .to_owned(),
        );
    }
    Ok(())
}

/// A decimal number, optionally negative, and nothing else. radare2 reads
/// rows and columns with `r_num_get`, which reads an unsigned number that
/// starts with `0` and another digit as octal, `010` as 8 and `08` as an
/// error worth 0 (util/unum.c:332-348), so that spelling is not a decimal
/// here. A negative one is decimal in both (util/unum.c:460).
fn decimal(text: &str) -> Option<i64> {
    let negative = text.strip_prefix('-');
    let digits = negative.unwrap_or(text);
    let octal = negative.is_none() && digits.len() > 1 && digits.starts_with('0');
    if octal || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl ColumnSpan {
    /// `n`, `n-m` or `n-`, where the range's `-` is the first after an
    /// optional sign (grep.c:563-574).
    fn parse(item: &str) -> Result<ColumnSpan, String> {
        let sign = usize::from(item.starts_with('-'));
        let Some(dash) = item[sign..].find('-').map(|at| at + sign) else {
            let only = column(item, item)?;
            return Ok(ColumnSpan {
                first: only,
                last: ColumnEnd::At(only),
            });
        };
        let (first, last) = (
            item[..dash].trim_matches(blank),
            item[dash + 1..].trim_matches(blank),
        );
        Ok(ColumnSpan {
            first: column(first, item)?,
            last: if last.is_empty() {
                ColumnEnd::Open
            } else {
                ColumnEnd::At(column(last, item)?)
            },
        })
    }

    fn holds(self, at: usize, count: usize) -> bool {
        let count = i64::try_from(count).unwrap_or(i64::MAX);
        let from_end = |bound: i64| if bound < 0 { count + bound } else { bound };
        let last = match self.last {
            ColumnEnd::At(last) => from_end(last),
            ColumnEnd::Open => count - 1,
        };
        let at = i64::try_from(at).unwrap_or(i64::MAX);
        from_end(self.first) <= at && at <= last
    }
}

fn column(text: &str, item: &str) -> Result<i64, String> {
    decimal(text)
        .filter(|number| (-COLUMNS..COLUMNS).contains(number))
        .ok_or_else(|| {
            format!(
                "grep: `[{item}]` is not a column: columns are decimal, from -64 to 63, with no \
                 leading 0, which radare2 reads as octal"
            )
        })
}

impl RowSpan {
    /// `n`, `s..e`, `s..` or `..e` (grep.c:95-110). radare2 keeps each bound
    /// in an int, so a wider one is refused rather than truncated.
    fn parse(text: &str) -> Option<RowSpan> {
        let row = |text: &str| decimal(text).filter(|row| i32::try_from(*row).is_ok());
        let bound = |text: &str| if text.is_empty() { Some(0) } else { row(text) };
        match text.split_once("..") {
            Some((first, last)) => Some(RowSpan {
                first: bound(first)?,
                last: bound(last)?,
            }),
            None => {
                let only = row(text)?;
                Some(RowSpan {
                    first: only,
                    last: only.checked_add(1)?,
                })
            }
        }
    }

    /// Whether the window ends before it starts whatever the text it meets:
    /// both bounds count from the same end.
    fn inverted(self) -> bool {
        let from_start = self.first >= 0 && self.last > 0;
        let from_end = self.first < 0 && self.last <= 0;
        (from_start || from_end) && self.first > self.last
    }

    /// This window, taken within `range`.
    fn within(self, range: Range<usize>) -> Range<usize> {
        let length = i64::try_from(range.len()).unwrap_or(i64::MAX);
        let first = resolve(self.first, self.first < 0, length);
        let last = resolve(self.last, self.last <= 0, length).max(first);
        range.start + first..range.start + last
    }
}

/// A row bound as an offset into a window of `length` lines, clipped to it.
/// radare2 does not clip; the window rows of [`JUDGED`] say what it does.
fn resolve(bound: i64, from_end: bool, length: i64) -> usize {
    let at = if from_end {
        length.saturating_add(bound)
    } else {
        bound
    };
    usize::try_from(at.clamp(0, length)).unwrap_or(0)
}

impl Stage {
    fn hit(&self, line: &str) -> bool {
        let folded;
        let line = if self.fold {
            folded = line.to_ascii_lowercase();
            folded.as_str()
        } else {
            line
        };
        let mut hits = self.words.iter().map(|word| self.hit_word(line, word));
        match self.join {
            Join::Any => hits.any(|hit| hit),
            Join::All => hits.all(|hit| hit),
            Join::NoneOf => !hits.any(|hit| hit),
        }
    }

    fn hit_word(&self, line: &str, word: &str) -> bool {
        line.contains(word)
            && (!self.begin || line.starts_with(word))
            && (!self.end || line.ends_with(word))
    }
}

impl Grep {
    /// What this grep keeps of `text`, as radare2 prints it, or a refusal
    /// where radare2 would print a line broken (see [`without_escapes`]).
    ///
    /// `text` is what the command printed, every line ended by a newline, and
    /// so is what the grep prints: an empty line is a line, and no line is
    /// nothing at all.
    pub(crate) fn apply(&self, text: &str) -> Result<String, String> {
        let lines = self.select(text)?;
        let lines = self.window(lines);
        let lines = self.order(lines);
        Ok(self.spell(&lines))
    }

    /// The lines every stage matches, each without its ANSI escapes. A line
    /// left empty by them is blank.
    fn select<'a>(&self, text: &'a str) -> Result<Vec<Cow<'a, str>>, String> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let text = text.strip_suffix('\n').unwrap_or(text);
        let mut kept = Vec::new();
        for line in text.split('\n') {
            let line = without_escapes(line)?;
            let dropped = line.is_empty() && !self.keep_blank;
            if !dropped && self.stages.iter().all(|stage| stage.hit(&line)) {
                kept.push(line);
            }
        }
        Ok(kept)
    }

    /// The columns and rows kept, rows counted as [`RowBase`] says.
    fn window<'a>(&self, lines: Vec<Cow<'a, str>>) -> Vec<Cow<'a, str>> {
        if self.columns.is_empty() {
            return self.rows_of(lines);
        }
        match self.row_base {
            RowBase::Selected => self.project(self.rows_of(lines)),
            RowBase::Projected => self.rows_of(self.project(lines)),
        }
    }

    fn rows_of<T>(&self, mut lines: Vec<T>) -> Vec<T> {
        let window = self
            .rows
            .iter()
            .fold(0..lines.len(), |window, span| span.within(window));
        lines.truncate(window.end);
        lines.drain(..window.start);
        lines
    }

    /// Each line cut to its columns; a line with none of them is dropped
    /// (grep.c:1134).
    fn project<'a>(&self, lines: Vec<Cow<'a, str>>) -> Vec<Cow<'a, str>> {
        lines
            .iter()
            .map(|line| self.columns_of(line))
            .filter(|line| !line.is_empty())
            .map(Cow::Owned)
            .collect()
    }

    fn columns_of(&self, line: &str) -> String {
        let tokens: Vec<&str> = line
            .split(DELIMITERS)
            .filter(|token| !token.is_empty())
            .collect();
        let count = tokens.len();
        let kept: Vec<&str> = tokens
            .iter()
            .enumerate()
            .filter(|(at, _)| self.columns.iter().any(|span| span.holds(*at, count)))
            .map(|(_, token)| *token)
            .collect();
        kept.join(" ")
    }

    fn order<'a>(&self, mut lines: Vec<Cow<'a, str>>) -> Vec<Cow<'a, str>> {
        let head = self.header.min(lines.len());
        let rest = &mut lines[head..];
        match self.order {
            Order::Keep => {}
            Order::Ascending => rest.sort_by(|a, b| compare(a, b)),
            Order::Descending => {
                rest.sort_by(|a, b| compare(a, b));
                rest.reverse();
            }
            Order::Reversed => rest.reverse(),
            Order::Unique => {
                rest.sort_by(|a, b| compare(a, b));
                return unique(lines);
            }
        }
        lines
    }

    /// The result as printed: each line ended by a newline.
    fn spell(&self, lines: &[Cow<'_, str>]) -> String {
        match self.tally {
            Tally::Lines => lines.iter().map(|line| format!("{line}\n")).collect(),
            Tally::LineCount => format!("{}\n", lines.len()),
            Tally::ByteCount => {
                let bytes: usize = lines.iter().map(|line| line.len() + 1).sum();
                format!("{bytes}\n")
            }
        }
    }
}

/// The byte that starts an ANSI escape.
const ESC: u8 = 0x1b;

/// A line as radare2 greps it: without its ANSI escapes (`r_str_ansi_filter`,
/// grep.c:907-912). An escape is ESC `[` through the first `J`, `m`, `H` or
/// `K`, ESC `#` through the first `q`, or ESC and the byte after it, each cut
/// short by the line's end (`__str_ansi_length`, str.c:1911-1934). Where that
/// one byte starts a character of more than one byte, radare2 prints the rest
/// of the character, which is not text, so the line is refused.
fn without_escapes(line: &str) -> Result<Cow<'_, str>, String> {
    let bytes = line.as_bytes();
    if !bytes.contains(&ESC) {
        return Ok(Cow::Borrowed(line));
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == ESC {
            at += escape_length(&bytes[at..]);
        } else {
            out.push(byte);
            at += 1;
        }
    }
    String::from_utf8(out).map(Cow::Owned).map_err(|_| {
        "grep: a line where an ANSI escape ends inside a character is refused: radare2 drops \
         the escape with the character's first byte and prints the rest of it (grep.c:911)"
            .to_owned()
    })
}

/// How long the escape `sequence` starts with is: its ESC is the first byte.
fn escape_length(sequence: &[u8]) -> usize {
    let through = |ends: &[u8]| {
        sequence[2..]
            .iter()
            .position(|byte| ends.contains(byte))
            .map_or(sequence.len(), |at| at + 3)
    };
    match sequence.get(1) {
        Some(b'[') => through(b"JmHK"),
        Some(b'#') => through(b"q"),
        Some(_) => 2,
        None => 1,
    }
}

/// Each line once, where it first appears (radare2 hashes the lines,
/// grep.c:1024).
fn unique(lines: Vec<Cow<'_, str>>) -> Vec<Cow<'_, str>> {
    let mut seen = BTreeSet::new();
    lines
        .into_iter()
        .filter(|line| seen.insert(line.clone()))
        .collect()
}

/// A total order: lines that are decimal integers after leading blanks, as
/// radare2's `r_str_isnumber` reads them, first and by value; the other lines
/// after them, bytewise.
fn compare(a: &str, b: &str) -> Ordering {
    match (Number::read(a), Number::read(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.as_bytes().cmp(b.as_bytes()),
    }
}

/// A decimal integer of any size: its sign and its digits without leading
/// zeros. Zero is never negative, and a lone `-` is zero.
#[derive(Debug, PartialEq, Eq)]
struct Number<'a> {
    negative: bool,
    digits: &'a str,
}

impl<'a> Number<'a> {
    fn read(line: &'a str) -> Option<Number<'a>> {
        let text = line.trim_start_matches(blank);
        let unsigned = text.strip_prefix('-');
        let body = unsigned.unwrap_or(text);
        let numeric = (unsigned.is_some() || !body.is_empty())
            && body.bytes().all(|byte| byte.is_ascii_digit());
        if !numeric {
            return None;
        }
        let digits = body.trim_start_matches('0');
        Some(Number {
            negative: unsigned.is_some() && !digits.is_empty(),
            digits,
        })
    }

    fn magnitude(&self) -> (usize, &'a str) {
        (self.digits.len(), self.digits)
    }
}

impl Ord for Number<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, false) => self.magnitude().cmp(&other.magnitude()),
            (true, true) => other.magnitude().cmp(&self.magnitude()),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        }
    }
}

impl PartialOrd for Number<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Grep {
        Grep::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    #[test]
    fn a_colon_before_anything_but_a_row_is_text() {
        let grep = parsed("sym.radr:__");
        assert_eq!(grep.stages[0].words, ["sym.radr:__"]);
        assert!(grep.rows.is_empty());
        let escaped = parsed("a\\:1");
        assert_eq!(escaped.stages[0].words, ["a:1"]);
        assert!(escaped.rows.is_empty());
        // Rows are read only at the stage's first bare `:`, and here it is
        // text, so the later `:1` is text too, as in radare2.
        let later = parsed("x:y:1");
        assert_eq!(later.stages[0].words, ["x:y:1"]);
        assert!(later.rows.is_empty());
    }

    #[test]
    fn a_column_range_splits_at_the_dash_after_its_sign() {
        let grep = parsed("[-2-]");
        assert_eq!(
            grep.columns,
            [ColumnSpan {
                first: -2,
                last: ColumnEnd::Open
            }]
        );
        let both = parsed("[-2--1]");
        assert_eq!(
            both.columns,
            [ColumnSpan {
                first: -2,
                last: ColumnEnd::At(-1)
            }]
        );
    }

    #[test]
    fn rows_count_the_selected_lines_only_when_they_come_first() {
        assert_eq!(parsed(":0~[1]").row_base, RowBase::Selected);
        assert_eq!(parsed("[1]~:0").row_base, RowBase::Projected);
        assert_eq!(parsed("[1]:0").row_base, RowBase::Projected);
        assert_eq!(parsed(":0[1]").row_base, RowBase::Projected);
    }

    #[test]
    fn row_windows_compose_as_slices_of_the_window_before() {
        let slice = |text: &str, length: usize| {
            parsed(text)
                .rows
                .iter()
                .fold(0..length, |window, span| span.within(window))
        };
        // radare2's own `range` tests over three lines.
        assert_eq!(slice(":0~:1", 3).len(), 0);
        assert_eq!(slice(":1~:0", 3), 1..2);
        assert_eq!(slice(":0..2~:1..3", 3), 1..2);
        assert_eq!(slice(":-2..", 5), 3..5);
        assert_eq!(slice(":0..0", 3), 0..3);
        // Judged (`:-100..` in JUDGED): a start before the first line is
        // clipped to it; radare2 shows nothing.
        assert_eq!(slice(":-100..", 3), 0..3);
        // Judged (`:5..10~:-7..`): a later window stays within the one before;
        // radare2 starts it at row 3.
        assert_eq!(slice(":5..10~:-7..", 20), 5..10);
        // Judged (`:-2..3`): a window that resolves backwards is empty, not
        // "to the end".
        assert_eq!(slice(":-2..3", 10).len(), 0);
    }

    #[test]
    fn the_order_is_total_and_puts_numbers_first_by_value() {
        let mut lines = ["10", "9", "1x", "b", "9", "007", "7", "-", " -3"];
        lines.sort_by(|a, b| compare(a, b));
        assert_eq!(lines, [" -3", "-", "007", "7", "9", "9", "10", "1x", "b"]);
        // Total: sorted, every line is at most every line after it, and the
        // comparison is antisymmetric. radare2's comparator fails this on
        // "9" < "10" < "1x" < "9".
        let mut all = ["10", "9", "1x", "b", "007", "7", "-", "-0", " -3", ""];
        all.sort_by(|a, b| compare(a, b));
        for (at, a) in all.iter().enumerate() {
            for b in &all[at..] {
                assert!(compare(a, b).is_le(), "{a:?} {b:?}");
                assert_eq!(compare(a, b), compare(b, a).reverse(), "{a:?} {b:?}");
            }
        }
    }

    /// Each line as radare2 6.2.3 printed it after `?e` spelled it and a grep
    /// kept it.
    #[test]
    fn a_line_is_read_without_its_ansi_escapes() {
        for (line, read) in [
            ("a\x1b", "a"),
            ("a\x1bb", "a"),
            ("a\x1b\x1b[0mb", "a[0mb"),
            ("a\x1b[31mred\x1b[0m", "ared"),
            ("a\x1b[", "a"),
            ("x\x1b#abcqz", "xz"),
            ("x\x1b#abc", "x"),
            ("a\x1b[1m\u{e9}", "a\u{e9}"),
            ("a\u{e9}", "a\u{e9}"),
        ] {
            assert_eq!(without_escapes(line).as_deref(), Ok(read), "{line:?}");
        }
        // radare2 prints `a\xa9b`: the escape took the first byte of the `é`.
        assert!(without_escapes("a\x1b\u{e9}b").is_err());
    }

    #[test]
    fn every_modifier_the_parser_reads_is_in_the_help() {
        let help = help();
        for one in MODIFIERS {
            assert!(
                help.contains(&format!(" {:<16} {}", one.spelling, one.meaning)),
                "{}",
                one.spelling
            );
        }
        for (spelling, _) in SHAPES.iter().chain(REFUSED).chain(JUDGED) {
            assert!(help.contains(spelling), "{spelling}");
        }
    }

    /// Concrete greps for each row of the help tables written by hand.
    const EXAMPLES: &[(&str, &[&str])] = &[
        ("word,word", &["a,b", "a,,b"]),
        ("word$", &["32$", "a,b$"]),
        ("a~b", &["a~b", "a~b~c~d~e~f~g~h~i"]),
        ("expr?", &["FUNC?", "a~b?"]),
        ("$:n", &["$:2", "$!:2"]),
        ("[n]", &["[0]", "[63]"]),
        ("[-n]", &["[-1]", "[-64]", "[-010]"]),
        ("[n-m]", &["[1-3]", "[-2--1]"]),
        ("[n-]", &["[1-]", "[-2-]"]),
        ("[i,j,k]", &["[0,2,4]", "[]"]),
        (
            ":n",
            &[":0", ":-1", ":2147483647", ":-010", ":0..-010", "a]:1"],
        ),
        (":s..e", &[":0..3", ":-3..-1", ":0..0"]),
        (":s..", &[":2.."]),
        (":..e", &[":..2"]),
        ("~:a~:b", &[":0..5~:1..3"]),
        // Read from each line of the output, whatever the grep.
        ("ESC", &[]),
        (
            "\\X",
            &[
                "\\@",
                "\\;",
                "\\#",
                "a\\:1",
                "a\\b",
                "a\\:b:0[1]",
                "a\\:b~[1]",
            ],
        ),
        ("$n", &["$2", "$$2"]),
        ("$$:n", &["$$:1"]),
        ("$!!:n", &["$!!:1"]),
        ("$$! $$!!", &["$$!", "$$!!", "$$!FUNC"]),
        ("$~:n", &["$imp:0..3", "$~:1", ":1~$!"]),
        ("$~$!", &["$~$!", "$$$", "$!$"]),
        ("?.~?", &["?.~?"]),
        (":5..2", &[":5..2", ":-1..-3"]),
        (":s..[c]", &[":2..[0]", ":..[4]", "FUNC:-2..[1-]"]),
        ("[x] :x", &["[rax]", ":0x", "[+4]"]),
        (
            ":010 [010]",
            &[
                ":010", "[010]", ":1..010", ":010..", ":08", "[1-010]", "[010-]", "[0,010]",
                "FUNC:00",
            ],
        ),
        (
            ":4294967297 $:n",
            &[":4294967297", ":-2147483649", "$:2147483648"],
        ),
        ("[64] [-65]", &["[64]", "[-65]"]),
        ("[n]x", &["[2]x", ":1x", "[2]$"]),
        (
            "x:y[c]:r",
            &["x:y[1]:1", "std::s[1]:0", ":[1]:1", "a:b,c[0]:0..2"],
        ),
        (
            "w]:r[c]",
            &["a]:0[1]", "]:0[0,2]", "]:1..3[1]", "]b,c:0[1]"],
        ),
        ("\\~ \\$ \\< \\> \\,", &["\\~", "\\$", "\\<5", "\\>", "\\,"]),
        (
            "a:b\\:c a\\:b[n]",
            &["x:y\\:z", "a:\\:", "a\\:b[1]", "x,a\\:b[1]", "\\:a[1-]:0"],
        ),
        ("word\\", &["a\\", "a\\\\"]),
        ("a~b~...~j", &["a~b~c~d~e~f~g~h~i~j"]),
        ("word:-n", &["FUNC:-1"]),
        (":s..e?", &["FUNC:0..3?", ":0..3?", ":-3..?"]),
        ("[c]:r", &["[4]:2", "[4]~:2"]),
        ("w:r~[c]", &["--,FUNC~:0..3~[4]", "-,FUNC:0..2~[1]"]),
        (".word", &[".text", ".!FUNC"]),
        (":-100.. :-2..3", &[":-100..", ":-2..3"]),
        (":5..10~:-7.. a:1~b:2", &[":5..10~:-7..", "a:1~b:2"]),
        (",  ,:1  $,", &[",", ",:1", "$,", "$!!,", ",~$"]),
        ("$", &["$"]),
        // Read by the line, not the grep: `?e a\~??` has no grep at all, and
        // the grep of `?e "a~?" b~??` is `??`, the help itself.
        ("a\\~?? \"~?\"~??", &[]),
    ];

    fn examples(spelling: &str) -> &'static [&'static str] {
        EXAMPLES
            .iter()
            .find(|(row, _)| *row == spelling)
            .map(|(_, greps)| *greps)
            .unwrap_or_else(|| panic!("`{spelling}` has no examples"))
    }

    /// The help cannot drift from the parser: every refusal it lists is
    /// refused, and every shape and judged form it lists is read.
    #[test]
    fn every_help_row_is_what_the_parser_does() {
        // A refused modifier heads a stage; `??` alone is the help, not a grep.
        let refused = MODIFIERS
            .iter()
            .filter(|one| matches!(one.effect, Effect::Refused))
            .map(|one| {
                let tail = if one.whole { "" } else { "x" };
                format!("{}{tail}", one.spelling)
            })
            .chain(
                REFUSED
                    .iter()
                    .flat_map(|(row, _)| examples(row).iter().map(|grep| (*grep).to_owned())),
            );
        for grep in refused {
            assert!(Grep::parse(&grep).is_err(), "`{grep}` was not refused");
        }
        for (row, _) in SHAPES.iter().chain(JUDGED) {
            for grep in examples(row) {
                assert!(Grep::parse(grep).is_ok(), "`{grep}` was refused");
            }
        }
    }
}
