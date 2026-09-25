//! The command line: where a line and a statement end, where a statement's
//! grep begins and where its temporary seek begins, and what its command's
//! argument says.
//!
//! This is the one owner of what a quote or a backslash means on a line.
//! radare2 first cuts a script at every LF, whatever the quotes
//! (`r_core_cmd_lines`, cmd.c:6977-7010, and `run_cmd_context`,
//! cmd.c:6778-6801), so each line is read on its own. It reads a line in
//! several passes (`libr/core/cmd.c`); r2s reads it once, the way those passes
//! agree:
//!
//! - `;` ends a statement, `~` starts its grep, and `@` its temporary seek,
//!   in that order (cmd.c:5241-5247);
//! - `"` and `'` protect what they enclose, and `\X` protects X for every X
//!   in [`SPECIAL`], from being read as any of those;
//! - a macro statement, `(name; body)`, ends at the first `;` outside every
//!   parenthesis (cmd.c:3806-3827).
//!
//! Protecting is all the line does with them. radare2 hands a handler its
//! command as written, quotes and backslashes included, and only some
//! handlers read them: `?e` splits its argument into words
//! (cmd_api.c:474-527) and `w` reads its argument as text
//! (cmd_write.inc.c:2627-2640), and r2s reads those two arguments the same
//! way, into a [`Command`]. Every other handler, and an `@` address, takes a
//! quote or a backslash as part of the text. A quote there, or a backslash
//! that escapes a character of [`SPECIAL`], is text radare2 reads its own
//! way, as a bad number or the character constant of `'main'`, so a
//! statement with one outside `?e` and `w` is refused. Any other backslash is
//! text to both, and reaches the handler as written.
//!
//! What radare2 gives a meaning r2s does not implement is refused rather than
//! passed on as text: a pipe, a redirect, a comment, a `&&` chain, a command
//! substitution, a macro, an `@addr@command` prefix, a statement that starts
//! with a quote, and the `?*` recursive help, which radare2 finds anywhere in
//! a statement, quoted or not, unless a `~` comes just before it. So is an
//! unquoted `\~` just before a `~`, a `\` or a quote, which radare2's grep
//! search steps over unread. So is a line radare2 reads whole before it looks
//! for statements (cmd.c:6861-6922): one that starts with `|`, a comment, or
//! with `b64:'`, a call, and a `/*` comment, which runs to a line that starts
//! with `*/` and, in a script, to its end. Every statement of a script is cut
//! and its grep parsed before the first one runs, and a refused statement runs
//! nothing. Where radare2 reads the rest of the line some other way, after a
//! comment, a malformed prefix, a repeat count with no command or a command
//! that starts with a quote, nothing after it on the line runs here. After a line that failed or quit, radare2
//! may run the rest of the script as one command, which ends at a command it
//! does not know, so from then on the first statement that fails ends the
//! script ([`UNSETTLED`]).
//!
//! Cost: a constant number of linear passes over each line. The lexer reads
//! its characters once; a statement's head is read once more to find a
//! prefix or a macro, a macro's body once, and a statement is searched once
//! each for its `;`, its operators, `?*`, its grep's `~` and its seek's `@`,
//! and read once more by its argument's reader.

use crate::grep::Suffix;

/// The characters radare2 gives a meaning on a command line, and so the ones a
/// backslash protects from it (`SPECIAL_CHARS`, cmd.c:22). A grep reads the
/// protected character as text (cmd.c:5820); a command's argument keeps the
/// backslash for its reader.
pub(crate) const SPECIAL: &str = "@;~$#|`\"'()<>";

/// One statement of a line, cut and parsed.
pub(crate) struct Statement {
    /// The command, with its argument read.
    pub(crate) command: Command,
    /// Where it runs, when it names a temporary seek.
    pub(crate) at: Option<String>,
    /// What its `~` asks for.
    pub(crate) grep: Option<Suffix>,
}

/// A command, its argument read the way radare2's handler for it reads one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// `?e`: the line it prints.
    Echo(String),
    /// `w`: the bytes it writes.
    Write(Vec<u8>),
    /// Any other command. Neither its verb nor its argument holds a quote or
    /// an escape: the handler would take one as text.
    Plain { verb: String, argument: String },
}

/// The statements of one line, each parsed or refused on its own.
pub(crate) type Line = Vec<Result<Statement, String>>;

/// Reads scripts one after another, as radare2 reads them. The one fact that
/// outlives a script is whether a `/*` comment is open (cmd.c:6861-6866).
#[derive(Default)]
pub(crate) struct Reader {
    comment: bool,
}

impl Reader {
    /// A script's lines: radare2 cuts it at every LF, whatever the quotes,
    /// and a last line that is empty is none (cmd.c:6977-7018).
    pub(crate) fn script(&mut self, script: &str) -> Vec<Line> {
        let mut lines = Vec::new();
        let mut rest = script;
        while !rest.is_empty() {
            let (line, after) = rest.split_once('\n').unwrap_or((rest, ""));
            rest = after;
            if self.comment {
                // radare2 skips the line, and the `*/` that closes the comment
                // with it (cmd.c:6861-6866).
                self.comment = !line.starts_with("*/");
                lines.push(vec![Err(IN_COMMENT.to_owned())]);
            } else if line.starts_with("/*") {
                // radare2 then runs the rest of the script as one command
                // (cmd.c:6991-6995, 7015-7018), which the open comment skips
                // whole.
                self.comment = !rest.starts_with("*/");
                lines.push(vec![Err(COMMENT_BLOCK.to_owned())]);
                break;
            } else {
                lines.push(read_line(line));
            }
        }
        lines
    }
}

/// One line's statements. radare2 reads a line that starts with `|` as a
/// comment and one that starts with `b64:'` as a call, whole, before it looks
/// for statements (cmd.c:6868, 6916-6919).
fn read_line(line: &str) -> Line {
    if line.starts_with('|') && !line.starts_with("|?") {
        return vec![Err(RAW_COMMENT.to_owned())];
    }
    if line.starts_with("b64:'") {
        return vec![Err(ENCODED_CALL.to_owned())];
    }
    statements(line)
}

/// Every statement of one line, each parsed or refused on its own.
fn statements(line: &str) -> Line {
    Lexer::read(line).statements(line)
}

const SUBSTITUTION: &str = "line: command substitution (`...` or $(...)) is not supported";
const COMMENT: &str = "line: `#` starts a comment in radare2, which r2s does not implement; \
                       nothing after it on the line runs";
const RAW_COMMENT: &str = "line: a line that starts with `|` is a comment in radare2 \
                           (cmd.c:6916), which r2s does not implement";
const ENCODED_CALL: &str = "line: a line that starts with `b64:'` is radare2's base64-encoded \
                            call, read whole (cmd.c:3832), which r2s does not implement";
const COMMENT_BLOCK: &str = "line: `/*` opens a comment in radare2, which r2s does not \
                             implement; radare2 skips every line up to one that starts with \
                             `*/`, and in a script the rest of it, so nothing after it runs";
const IN_COMMENT: &str = "line: this line is inside a `/*` comment, which radare2 skips up to \
                          and including a line that starts with `*/`; r2s does not implement \
                          comments";
/// After a line that failed or quit, radare2 may run the rest of the script
/// as one command, which ends at the first command it does not know
/// (cmd.c:6990-7003, 7015-7018, 6786-6797). Which failures those are is
/// radare2's command table, so after such a line the first statement that
/// fails ends the script here.
pub(crate) const UNSETTLED: &str = "line: after a line that failed or quit, radare2 may run the \
                                    rest of the script as one command, which ends at the first \
                                    command it does not know; r2s cannot tell which failures \
                                    those are, so nothing after this one runs";
const BACKSLASHES: &str = "line: more than one backslash before a special character is \
                           refused: radare2 reads such a run differently at each pass (`\\\\;` \
                           ends the statement, `\\\\~` is a `~`)";
const MACRO: &str = "line: `(` starts a radare2 macro, which r2s does not implement; the macro \
                     runs to the first `;` outside its parentheses";
const PREFIX: &str = "line: a statement that starts with `@` is radare2's `@addr@command` \
                      prefix, which r2s does not implement";
const PREFIX_BROKEN: &str = "line: a statement that starts with `@` is radare2's \
                             `@addr@command` prefix, and this one is malformed; radare2 \
                             abandons the rest of the line, so nothing after it on the line \
                             runs";
const PIPE: &str = "line: `|` pipes to a shell in radare2, which r2s does not implement";
const REDIRECT: &str = "line: `>` redirects to a file in radare2, which r2s does not implement";
const CHAIN: &str = "line: `&&` chains commands in radare2, which r2s does not implement";
const COUNT_ALONE: &str = "line: a repeat count with no command after it is refused: radare2 \
                           abandons the rest of the line there, so nothing after it on the line \
                           runs";
const QUOTED: &str = "line: a quote at the head of a statement is refused: radare2 reads it as \
                      an empty pair or a quoted repeat count, which r2s does not implement";
const QUOTED_REST: &str = "line: a command that starts with a quote is radare2's quoted or raw \
                           command, which reads the rest of the line its own way and which \
                           r2s does not implement; nothing after it on the line runs";
const UNTERMINATED: &str = "line: an unterminated quote or command substitution";
const VERB_QUOTED: &str = "line: a quote or a backslash in a command's name is refused: radare2 \
                           reads it as part of the name";
const SEEK_QUOTED: &str = "line: a quote or an escape in an `@` address is refused: radare2 reads \
                           it as part of the address";
const WRITE_SEPARATOR: &str = "line: `w` takes its text after one space, as radare2's does";
const ESCAPED_TILDE: &str = "line: an unquoted `\\~` followed by `~`, `\\`, `\"` or `'` is \
                             refused: radare2 resumes its grep search one character past an \
                             escaped `~` (grep.c:381-382), so it reads that character as text \
                             where r2s would read a grep, an escape or a quote";
const RECURSIVE_HELP: &str = "line: `?*` is radare2's recursive help, which r2s does not \
                              implement; radare2 finds it anywhere in a statement, quoted or \
                              not, unless a `~` comes just before it (cmd.c:4937-4984)";

/// How one character of a line is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Unquoted and unescaped: it may be an operator.
    Bare,
    /// Quoted or escaped: text, whatever the character.
    Held,
    /// A quote or an escaping backslash: it protects, and is not text.
    Mark,
}

#[derive(Clone, Copy, Debug)]
struct Lexeme {
    offset: usize,
    ch: char,
    role: Role,
}

impl Lexeme {
    fn is(self, ch: char) -> bool {
        self.role == Role::Bare && self.ch == ch
    }

    /// An unquoted, unescaped blank: it separates.
    fn is_blank(&self) -> bool {
        self.role == Role::Bare && blank(self.ch)
    }
}

/// What the lexer is inside.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Within {
    Nothing,
    Quote(char),
    Backticks,
    /// `$(`, with the depth of its parentheses.
    Parens(usize),
}

/// What radare2 reads at the head of a statement, before its command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Head {
    /// A command, perhaps after blanks and a repeat count.
    Plain,
    /// One or more well-formed `@addr@` prefixes before the command.
    Prefixed,
    /// A prefix radare2 rejects, abandoning the rest of the line
    /// (cmd.c:4057-4072).
    Broken,
    /// A repeat count with no command after it, before the statement ends:
    /// radare2 abandons the rest of the line (cmd.c:4122-4124).
    Uncommanded,
    /// A command that starts with a quote: radare2 reads the rest of the
    /// line as a raw command or in its quoted-command mode (cmd.c:4082,
    /// 4110-4122, 4611-4776).
    Quoted,
    /// A macro, whose `(` is at this character.
    Macro(usize),
}

/// radare2's blanks (`IS_WHITECHAR`), which its trims drop.
pub(crate) fn blank(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r')
}

struct Lexer {
    chars: Vec<(usize, char)>,
    next: usize,
    within: Within,
    lexemes: Vec<Lexeme>,
    /// Refusals, each at the index of the lexeme it was found before, in
    /// that order.
    faults: Vec<(usize, &'static str)>,
    /// Where reading stopped: the end of the line, a comment, a malformed
    /// prefix or a command that starts with a quote.
    end: usize,
    /// The last `)` of the line, which a macro needs somewhere after its
    /// `(` (cmd.c:3807).
    last_close: Option<usize>,
}

impl Lexer {
    fn read(line: &str) -> Lexer {
        let chars: Vec<(usize, char)> = line.char_indices().collect();
        let last_close = chars.iter().rposition(|&(_, ch)| ch == ')');
        let mut lexer = Lexer {
            chars,
            next: 0,
            within: Within::Nothing,
            lexemes: Vec::with_capacity(line.len()),
            faults: Vec::new(),
            end: line.len(),
            last_close,
        };
        let mut reading = lexer.opening();
        while reading && lexer.next < lexer.chars.len() {
            reading = lexer.step();
        }
        if lexer.within != Within::Nothing {
            lexer.fault(UNTERMINATED);
        }
        lexer
    }

    /// Read one character, or one escape. False where radare2 reads nothing
    /// after it: a comment, whose `;` are its own, or a statement whose head
    /// hands radare2 the rest of the line.
    fn step(&mut self) -> bool {
        let (offset, ch) = self.chars[self.next];
        if ch == '\\' {
            self.escape();
            return true;
        }
        self.next += 1;
        match self.within {
            Within::Nothing => return self.plain(offset, ch),
            Within::Quote(quote) => self.quoted(offset, ch, quote),
            Within::Backticks => {
                if ch == '`' {
                    self.within = Within::Nothing;
                }
                self.push(offset, ch, Role::Held);
            }
            Within::Parens(depth) => self.parenthesised(offset, ch, depth),
        }
        true
    }

    fn plain(&mut self, offset: usize, ch: char) -> bool {
        match ch {
            '"' | '\'' => {
                self.within = Within::Quote(ch);
                self.push(offset, ch, Role::Mark);
            }
            '`' => {
                self.fault(SUBSTITUTION);
                self.within = Within::Backticks;
                self.push(offset, ch, Role::Held);
            }
            '$' if self.peek() == Some('(') => {
                self.fault(SUBSTITUTION);
                self.within = Within::Parens(0);
                self.push(offset, ch, Role::Held);
            }
            '#' => {
                self.fault(COMMENT);
                self.end = offset;
                return false;
            }
            ';' => {
                self.push(offset, ch, Role::Bare);
                return self.opening();
            }
            _ => self.push(offset, ch, Role::Bare),
        }
        true
    }

    /// A statement starts here. False when radare2 reads nothing after it.
    fn opening(&mut self) -> bool {
        match self.head() {
            Head::Plain => true,
            Head::Prefixed => {
                self.fault(PREFIX);
                true
            }
            Head::Broken => self.stop(PREFIX_BROKEN),
            Head::Uncommanded => self.stop(COUNT_ALONE),
            Head::Quoted => self.stop(QUOTED_REST),
            Head::Macro(open) => self.macro_body(open),
        }
    }

    /// Refuse this statement and read nothing after it.
    fn stop(&mut self, message: &'static str) -> bool {
        self.fault(message);
        self.end = self.offset(self.next);
        false
    }

    /// What radare2 reads before the command: blanks and a repeat count
    /// (`command_start`, cmd.c:3877-3905), then `@addr@` prefixes, each
    /// followed by another repeat count (cmd.c:4057-4081), then the macro
    /// form (`is_macro_command`, cmd.c:3806-3813).
    fn head(&self) -> Head {
        let (mut at, mut counted) = self.command_start(self.next);
        let mut prefixed = false;
        while self.char_at(at) == Some('@') {
            let run = self.run_of(at, |ch| ch == '@');
            if self.char_at(at + run) == Some('?') {
                // `@?`, `@@?`: radare2's help for `@`, not a prefix.
                return Head::Prefixed;
            }
            let end = self.prefix_end(at);
            if run > 1 || self.char_at(end) != Some('@') {
                return Head::Broken;
            }
            prefixed = true;
            let (start, count) = self.command_start(end + 1);
            (at, counted) = (start, counted || count);
        }
        if counted && matches!(self.char_at(at), None | Some(';')) {
            return Head::Uncommanded;
        }
        if matches!(self.char_at(at), Some('"' | '\'')) {
            return Head::Quoted;
        }
        // Blanks, then digits, exactly: a looser skip could call a macro what
        // radare2 cuts as quoted text, and run what radare2 quotes.
        let digits = at + self.run_of(at, blank);
        let open = digits + self.run_of(digits, |ch| ch.is_ascii_digit());
        let closed = self.last_close.is_some_and(|close| close > open);
        match self.char_at(open) {
            Some('(') if closed => Head::Macro(open),
            _ if prefixed => Head::Prefixed,
            _ => Head::Plain,
        }
    }

    /// Past blanks, empty `""` pairs and a repeat count, bare or quoted,
    /// that is at least 1 (cmd.c:3877-3905), and whether there was a count.
    fn command_start(&self, at: usize) -> (usize, bool) {
        let at = self.command_head(at);
        let quoted = self.char_at(at) == Some('"');
        let digits = at + usize::from(quoted);
        let count = self.run_of(digits, |ch| ch.is_ascii_digit());
        let end = digits + count;
        let repeat: String = self.chars[digits..end].iter().map(|&(_, ch)| ch).collect();
        let repeats = repeat.parse::<i64>().is_ok_and(|repeat| repeat >= 1);
        if !repeats || (quoted && self.char_at(end) != Some('"')) {
            return (at, false);
        }
        (self.command_head(end + usize::from(quoted)), true)
    }

    /// Past blanks and empty `""` pairs (`trim_command_head`, cmd.c:3877).
    fn command_head(&self, at: usize) -> usize {
        let mut at = at + self.run_of(at, blank);
        loop {
            let after = at + 1 + self.run_of(at + 1, blank);
            if self.char_at(at) != Some('"') || self.char_at(after) != Some('"') {
                return at;
            }
            at = after + 1 + self.run_of(after + 1, blank);
        }
    }

    /// Where the address of an `@addr@` prefix ends: at a character from
    /// `@'`;"`, or at a `)` it did not open (`find_seek_prefix_end`,
    /// cmd.c:3906-3916).
    fn prefix_end(&self, at: usize) -> usize {
        let mut parens = 0usize;
        let mut end = at + 1;
        while let Some(ch) = self.char_at(end) {
            if "@'`;\"".contains(ch) || (ch == ')' && parens == 0) {
                break;
            }
            match ch {
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            end += 1;
        }
        end
    }

    /// A macro statement, read as radare2 reads it: raw, to the first `;`
    /// outside every parenthesis, whatever quotes and backslashes say
    /// (`find_ch_after_macro`, cmd.c:3815-3827). It is refused whole. radare2
    /// cuts a comment before it looks for a macro (cmd.c:4103), so a `#`
    /// inside one ends the line here.
    fn macro_body(&mut self, open: usize) -> bool {
        self.fault(MACRO);
        let mut depth = 0i64;
        while let Some(&(offset, ch)) = self.chars.get(self.next) {
            if ch == ';' && depth == 0 {
                return true;
            }
            if ch == '#' {
                self.end = offset;
                return false;
            }
            if self.next >= open {
                depth += match ch {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
            }
            self.push(offset, ch, Role::Held);
            self.next += 1;
        }
        true
    }

    fn char_at(&self, at: usize) -> Option<char> {
        self.chars.get(at).map(|&(_, ch)| ch)
    }

    /// How many characters from `at` on satisfy `test`.
    fn run_of(&self, at: usize, test: impl Fn(char) -> bool) -> usize {
        self.chars
            .get(at..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&(_, ch)| test(ch))
            .count()
    }

    /// The line offset of a character, or the line's end past the last.
    fn offset(&self, at: usize) -> usize {
        self.chars.get(at).map_or(self.end, |&(offset, _)| offset)
    }

    fn quoted(&mut self, offset: usize, ch: char, quote: char) {
        if ch == quote {
            self.within = Within::Nothing;
            self.push(offset, ch, Role::Mark);
            return;
        }
        // radare2 substitutes inside double quotes too (cmd.c:3975-3998).
        let substitutes = ch == '`' || (ch == '$' && self.peek() == Some('('));
        if quote == '"' && substitutes {
            self.fault(SUBSTITUTION);
        }
        self.push(offset, ch, Role::Held);
    }

    fn parenthesised(&mut self, offset: usize, ch: char, depth: usize) {
        let depth = match ch {
            '(' => depth + 1,
            ')' => depth.saturating_sub(1),
            _ => depth,
        };
        self.within = if depth == 0 && ch == ')' {
            Within::Nothing
        } else {
            Within::Parens(depth)
        };
        self.push(offset, ch, Role::Held);
    }

    /// A run of backslashes. Before a special character the last one makes
    /// that character text; any other backslash is text itself.
    ///
    /// A longer run before a special character is refused, but where the
    /// statement ends still follows radare2, which reads backslashes in pairs
    /// when it cuts statements (`find_cmd_separator`): after an even run the
    /// character is an operator again, so `\\;` ends the statement and `\\#`
    /// starts a comment, and after an odd run it is text.
    fn escape(&mut self) {
        let run = self.run_of(self.next, |ch| ch == '\\');
        let special = self
            .chars
            .get(self.next + run)
            .copied()
            .filter(|(_, ch)| SPECIAL.contains(*ch));
        if special.is_some() && run > 1 {
            self.fault(BACKSLASHES);
        }
        let protected = special.filter(|_| run % 2 == 1);
        let literal = run - usize::from(protected.is_some());
        for _ in 0..literal {
            let (offset, _) = self.chars[self.next];
            self.push(offset, '\\', Role::Held);
            self.next += 1;
        }
        if let Some((offset, ch)) = protected {
            let (mark, _) = self.chars[self.next];
            self.push(mark, '\\', Role::Mark);
            self.push(offset, ch, Role::Held);
            self.next += 2;
            if ch == '~' && self.within == Within::Nothing && self.skipped_after_tilde() {
                self.fault(ESCAPED_TILDE);
            }
        }
    }

    /// Whether the character after an unquoted `\~` is one radare2 does not
    /// read. Its grep search drops the backslash and resumes one character
    /// past the `~` (`find_next_intgrep`, grep.c:371-385), so a `~` there
    /// starts no grep, a `\` escapes nothing and a quote opens or closes
    /// nothing, where this lexer reads each of them. A quoted `\~` is not
    /// searched, and any other character reads the same either way.
    fn skipped_after_tilde(&self) -> bool {
        matches!(self.peek(), Some('~' | '\\' | '"' | '\''))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.next).map(|&(_, ch)| ch)
    }

    fn push(&mut self, offset: usize, ch: char, role: Role) {
        self.lexemes.push(Lexeme { offset, ch, role });
    }

    fn fault(&mut self, message: &'static str) {
        self.faults.push((self.lexemes.len(), message));
    }

    /// Cut at every bare `;`.
    fn statements(&self, line: &str) -> Line {
        let mut out = Vec::new();
        let mut start = 0;
        for (index, lexeme) in self.lexemes.iter().enumerate() {
            if lexeme.is(';') {
                out.push(self.statement(line, start..index));
                start = index + 1;
            }
        }
        out.push(self.statement(line, start..self.lexemes.len()));
        out
    }

    fn statement(&self, line: &str, range: std::ops::Range<usize>) -> Result<Statement, String> {
        // Faults are in lexeme order, so the statement's first is found by
        // bisection rather than a scan per statement.
        let first = self.faults.partition_point(|(at, _)| *at < range.start);
        if let Some((_, fault)) = self.faults.get(first).filter(|(at, _)| *at <= range.end) {
            return Err((*fault).to_owned());
        }
        let stop = self
            .lexemes
            .get(range.end)
            .map_or(self.end, |lexeme| lexeme.offset);
        let lexemes = trimmed(&self.lexemes[range]);
        refuse_operators(lexemes)?;
        let written = lexemes
            .first()
            .map_or("", |first| &line[first.offset..stop]);
        if recursive_help(written) {
            return Err(RECURSIVE_HELP.to_owned());
        }
        if lexemes
            .first()
            .is_some_and(|first| first.role == Role::Mark && first.ch != '\\')
        {
            return Err(QUOTED.to_owned());
        }
        cut(line, lexemes, stop)
    }
}

/// Without the bare blanks at either end, as radare2 trims a statement.
fn trimmed(lexemes: &[Lexeme]) -> &[Lexeme] {
    let start = lexemes
        .iter()
        .position(|lexeme| !lexeme.is_blank())
        .unwrap_or(lexemes.len());
    let end = lexemes
        .iter()
        .rposition(|lexeme| !lexeme.is_blank())
        .map_or(start, |at| at + 1);
    &lexemes[start..end]
}

/// A pipe, a redirect or a `&&` chain, anywhere in the statement. The `>` of
/// a `~<>` grep is not a redirect (cmd.c:5000).
fn refuse_operators(lexemes: &[Lexeme]) -> Result<(), String> {
    for (at, lexeme) in lexemes.iter().enumerate() {
        let next = lexemes.get(at + 1).copied();
        let xml = at >= 2 && lexemes[at - 1].is('<') && lexemes[at - 2].is('~');
        let refusal = match lexeme.role {
            Role::Bare if lexeme.ch == '|' => Some(PIPE),
            Role::Bare if lexeme.ch == '>' && !xml => Some(REDIRECT),
            Role::Bare if lexeme.ch == '&' && next.is_some_and(|next| next.is('&')) => Some(CHAIN),
            _ => None,
        };
        if let Some(refusal) = refusal {
            return Err(refusal.to_owned());
        }
    }
    Ok(())
}

/// Whether radare2 reads the statement, as written, as its recursive help: at
/// its first `?*`, wherever that is, unless a `~` comes just before it
/// (cmd.c:4937-4938).
fn recursive_help(written: &str) -> bool {
    written
        .find("?*")
        .is_some_and(|at| !written[..at].ends_with('~'))
}

/// The statement's command, seek and grep. The grep is the raw text after the
/// first bare `~`, escapes included, and is parsed now; the seek is cut from
/// what precedes it.
fn cut(line: &str, lexemes: &[Lexeme], stop: usize) -> Result<Statement, String> {
    let tilde = lexemes.iter().position(|lexeme| lexeme.is('~'));
    let command = &lexemes[..tilde.unwrap_or(lexemes.len())];
    let (command, at) = seek(command);
    let command = Command::read(trimmed(command))?;
    let at = at.map(address).transpose()?;
    // The grep is alone when its `~` starts the statement (cmd.c:5222).
    let alone = tilde == Some(0);
    let grep = tilde
        .map(|at| line[lexemes[at].offset + 1..stop].trim_end_matches(blank))
        .filter(|text| !text.is_empty())
        .map(|text| Suffix::parse(text, alone))
        .transpose()?;
    Ok(Statement { command, at, grep })
}

/// Cut at the first bare `@`, except in `?@`, radare2's help for `@`
/// (cmd.c:5247-5250).
fn seek(command: &[Lexeme]) -> (&[Lexeme], Option<&[Lexeme]>) {
    match command.iter().position(|lexeme| lexeme.is('@')) {
        Some(1) if command[0].is('?') => (command, None),
        Some(at) => (&command[..at], Some(&command[at + 1..])),
        None => (command, None),
    }
}

/// An `@` address. radare2 hands the address to its number reader as written,
/// where `"main"` is an invalid address and `'main'` is the character constant
/// 0x6d, and it cuts `ma\@in` at the escaped `@`; so an address that quotes or
/// escapes anything is refused.
fn address(lexemes: &[Lexeme]) -> Result<String, String> {
    if lexemes.iter().any(|lexeme| lexeme.role == Role::Mark) {
        return Err(SEEK_QUOTED.to_owned());
    }
    Ok(text(trimmed(lexemes)))
}

/// The characters the lexemes are, as written: quotes and backslashes
/// included.
fn text(lexemes: &[Lexeme]) -> String {
    lexemes.iter().map(|lexeme| lexeme.ch).collect()
}

impl Command {
    /// A trimmed command: its verb runs to the first bare blank, and its
    /// argument, from that blank on, is read by the verb's reader.
    fn read(lexemes: &[Lexeme]) -> Result<Command, String> {
        let end = lexemes
            .iter()
            .position(Lexeme::is_blank)
            .unwrap_or(lexemes.len());
        let (verb, argument) = lexemes.split_at(end);
        if verb.iter().any(|lexeme| lexeme.role != Role::Bare) {
            return Err(VERB_QUOTED.to_owned());
        }
        let verb = text(verb);
        match verb.as_str() {
            "?e" => echo(&text(argument)).map(Command::Echo),
            "w" => written(&text(argument)).map(Command::Write),
            _ => plain(verb, argument),
        }
    }
}

/// A command whose handler reads no quote and no escape. A backslash before
/// anything but a character of [`SPECIAL`] escapes nothing, and is passed on
/// as text, as radare2 passes it.
fn plain(verb: String, argument: &[Lexeme]) -> Result<Command, String> {
    if argument.iter().any(|lexeme| lexeme.role == Role::Mark) {
        return Err(format!(
            "line: a quote, or a backslash before a special character, in the argument of \
             `{verb}` is refused: radare2 hands it to the handler as text, and only `?e` and \
             `w` read one"
        ));
    }
    Ok(Command::Plain {
        verb,
        argument: text(trimmed(argument)),
    })
}

/// C's `isspace`, which splits `?e`'s words.
fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `?e`'s argument as radare2 reads it: words split at unquoted blanks, a
/// quote pairs with its like and is not text, and a backslash escape is
/// decoded, inside quotes too (`cmd_context_parse_args`, cmd_api.c:474-527).
/// The words print joined by one space, up to the first NUL
/// (`echo_append_args`, echo.inc.c:27-45). A line that is not UTF-8 is
/// refused rather than printed as something else.
fn echo(argument: &str) -> Result<String, String> {
    let mut line = Vec::with_capacity(argument.len());
    for (index, word) in words(argument.as_bytes()).iter().enumerate() {
        if index > 0 {
            line.push(b' ');
        }
        let nul = word.iter().position(|&byte| byte == 0);
        line.extend_from_slice(&word[..nul.unwrap_or(word.len())]);
        if nul.is_some() {
            break;
        }
    }
    String::from_utf8(line).map_err(|_| {
        "line: an escape in `?e` spells a byte that is not UTF-8 text, which r2s does not print"
            .to_owned()
    })
}

fn words(argument: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    let mut at = 0;
    loop {
        at += argument[at..]
            .iter()
            .take_while(|&&byte| space(byte))
            .count();
        if at == argument.len() {
            return words;
        }
        let mut word = Vec::new();
        at = read_word(argument, at, &mut word);
        words.push(word);
    }
}

/// One word from `at`, and where it ends.
fn read_word(argument: &[u8], mut at: usize, word: &mut Vec<u8>) -> usize {
    let mut quote = None;
    while let Some(&byte) = argument.get(at) {
        if quote.is_none() && space(byte) {
            break;
        }
        at += 1;
        match byte {
            b'\\' => at = decode_escape(argument, at, word),
            b'"' | b'\'' if quote.is_none() => quote = Some(byte),
            b'"' | b'\'' if quote == Some(byte) => quote = None,
            _ => word.push(byte),
        }
    }
    at
}

/// The escape whose backslash is just before `at` (`cmd_decode_escape`,
/// cmd_api.c:434-472): the C letter escapes and `\s`, `\xHH`, up to three
/// octal digits, and any other character as itself. A backslash that ends the
/// argument is text, and `\x` without two hex digits is nothing.
fn decode_escape(argument: &[u8], at: usize, word: &mut Vec<u8>) -> usize {
    let Some(&letter) = argument.get(at) else {
        word.push(b'\\');
        return at;
    };
    let byte = match letter {
        b'a' => 0x07,
        b'b' => 0x08,
        b'e' => 0x1b,
        b'f' => 0x0c,
        b'n' => b'\n',
        b'r' => b'\r',
        b's' => b' ',
        b't' => b'\t',
        b'v' => 0x0b,
        b'x' => return hex_escape(argument, at + 1, word),
        b'0'..=b'7' => return octal_escape(argument, at, word),
        other => other,
    };
    word.push(byte);
    at + 1
}

/// Two hex digits from `at` as one byte, or nothing when either is missing.
fn hex_escape(argument: &[u8], at: usize, word: &mut Vec<u8>) -> usize {
    let digit = |offset: usize| {
        argument
            .get(at + offset)
            .and_then(|&byte| char::from(byte).to_digit(16))
    };
    let Some(byte) = digit(0)
        .zip(digit(1))
        .and_then(|(high, low)| u8::try_from(high * 16 + low).ok())
    else {
        return at;
    };
    word.push(byte);
    at + 2
}

/// Up to three octal digits from `at`, as one byte, wrapping as C's does.
fn octal_escape(argument: &[u8], at: usize, word: &mut Vec<u8>) -> usize {
    let count = argument[at..]
        .iter()
        .take(3)
        .take_while(|byte| matches!(byte, b'0'..=b'7'))
        .count();
    let byte = argument[at..at + count].iter().fold(0u8, |value, digit| {
        value.wrapping_mul(8).wrapping_add(digit - b'0')
    });
    word.push(byte);
    at + count
}

/// `w`'s argument as radare2's `w` reads it (cmd_write.inc.c:2627-2640): it
/// starts with the one space after `w`; quotes and backslashes are read by
/// `r_str_trim_args` (str_trim.c:167-218), trailing blanks dropped, the space
/// dropped, and the escapes of `r_str_unescape` decoded (str.c:1169-1257).
/// A quoted blank at the end is dropped too, as radare2 drops it.
fn written(argument: &str) -> Result<Vec<u8>, String> {
    if !argument.starts_with(' ') {
        return Err(WRITE_SEPARATOR.to_owned());
    }
    let mut text = trim_args(argument.as_bytes());
    let kept = text.iter().rposition(|&byte| !blank(char::from(byte)));
    text.truncate(kept.map_or(0, |at| at + 1));
    match text.split_first() {
        Some((_, rest)) => unescape(rest),
        None => Ok(Vec::new()),
    }
}

/// What a backslash makes text in `r_str_trim_args` (`is_escapable`,
/// str_trim.c:144-165).
fn escapable(byte: u8) -> bool {
    b"@\"'!#$&*()<>|;`~".contains(&byte)
}

/// `r_str_trim_args`: a quote pairs with its like and is not text; an odd run
/// of backslashes before an escapable character loses one backslash and makes
/// it text; any other backslash is text. A quote left open is text.
fn trim_args(argument: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(argument.len());
    let mut open: Option<(u8, usize)> = None;
    let mut at = 0;
    while let Some(&byte) = argument.get(at) {
        if byte == b'\\' {
            at = backslashes(argument, at, &mut out);
            continue;
        }
        at += 1;
        match (byte, open) {
            (b'"' | b'\'', None) => open = Some((byte, out.len())),
            (b'"' | b'\'', Some((quote, _))) if quote == byte => open = None,
            _ => out.push(byte),
        }
    }
    if let Some((quote, at)) = open {
        out.insert(at, quote);
    }
    out
}

/// A run of backslashes from `at`, as `r_str_trim_args` reads it, and where
/// it ends.
fn backslashes(argument: &[u8], at: usize, out: &mut Vec<u8>) -> usize {
    let run = argument[at..]
        .iter()
        .take_while(|&&byte| byte == b'\\')
        .count();
    let next = argument.get(at + run).copied();
    let escapes = run % 2 == 1 && next.is_some_and(escapable);
    out.extend(std::iter::repeat_n(b'\\', run - usize::from(escapes)));
    match next.filter(|_| escapes) {
        Some(escaped) => {
            out.push(escaped);
            at + run + 1
        }
        None => at + run,
    }
}

/// `r_str_unescape`: the C letter escapes, `\s` and `\ `, `\\`, the quotes,
/// `` \` ``, `\$`, `\xHH` and up to three octal digits; any other backslash is
/// text. radare2 writes nothing when `\x` lacks two hex digits.
fn unescape(text: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut at = 0;
    while let Some(&byte) = text.get(at) {
        at += 1;
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        at = unescape_one(text, at, &mut out)?;
    }
    Ok(out)
}

/// The escape whose backslash is just before `at`, and where it ends.
fn unescape_one(text: &[u8], at: usize, out: &mut Vec<u8>) -> Result<usize, String> {
    let byte = match text.get(at) {
        Some(b'e') => 0x1b,
        Some(b' ' | b's') => b' ',
        Some(b'r') => b'\r',
        Some(b'n') => b'\n',
        Some(b'a') => 0x07,
        Some(b'b') => 0x08,
        Some(b't') => b'\t',
        Some(b'v') => 0x0b,
        Some(b'f') => 0x0c,
        Some(&same @ (b'\\' | b'"' | b'\'' | b'`' | b'$')) => same,
        Some(b'x') => return written_hex(text, at + 1, out),
        Some(b'0'..=b'7') => return Ok(octal_escape(text, at, out)),
        _ => {
            out.push(b'\\');
            return Ok(at);
        }
    };
    out.push(byte);
    Ok(at + 1)
}

fn written_hex(text: &[u8], at: usize, out: &mut Vec<u8>) -> Result<usize, String> {
    let before = out.len();
    let end = hex_escape(text, at, out);
    if out.len() == before {
        return Err("line: `\\x` in `w` needs two hex digits; radare2 writes nothing".to_owned());
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(script: &str) -> Result<Statement, String> {
        let mut all = statements(script);
        assert_eq!(all.len(), 1, "{script}");
        all.remove(0)
    }

    fn command(script: &str) -> Command {
        one(script)
            .unwrap_or_else(|error| panic!("{script}: {error}"))
            .command
    }

    fn echo(line: &str) -> Command {
        Command::Echo(line.to_owned())
    }

    #[test]
    fn quotes_and_escapes_protect_the_separators() {
        let quoted = one("?e \"a~b;c@d\"").expect("parses");
        assert_eq!(quoted.command, echo("a~b;c@d"));
        assert!(quoted.at.is_none() && quoted.grep.is_none());
        assert_eq!(command("?e a\\;b\\~c\\@d"), echo("a;b~c@d"));
        let seek = one("pd 3 @ main~mov").expect("parses");
        let plain = Command::Plain {
            verb: "pd".to_owned(),
            argument: "3".to_owned(),
        };
        assert_eq!(seek.command, plain);
        assert_eq!(seek.at.as_deref(), Some("main"));
        assert!(seek.grep.is_some());
        assert_eq!(statements("?e a ; ?e b;;").len(), 4);
        // Only radare2's blanks separate: an ideographic space is text.
        assert_eq!(command("?e a\u{3000}"), echo("a\u{3000}"));
    }

    /// `?e` and `w` read their argument as radare2 6.2.3's handlers do: each
    /// line is what radare2 printed, and each byte string what it wrote, for
    /// the same statement.
    #[test]
    fn echo_and_write_read_their_argument_as_radare2_does() {
        for (script, line) in [
            ("?e  a   b ", "a b"),
            ("?e \" a \"", " a "),
            ("?e x \"\" ", "x "),
            ("?e \"\" x", " x"),
            ("?e a\"  \"b", "a  b"),
            ("?e \"a'b\"", "a'b"),
            ("?e 'a\\'b'", "a'b"),
            ("?e a\\nb\\tc\\sd", "a\nb\tc d"),
            ("?e \\x41\\x4g\\xZZ", "A4gZZ"),
            ("?e a\\\\b\\qc\\!", "a\\bqc!"),
            ("?e a\\0b c", "a"),
            ("?e \\303\\251", "\u{e9}"),
            ("?e\ta", "a"),
            ("?e a\\", "a\\"),
        ] {
            assert_eq!(command(script), echo(line), "{script}");
        }
        for (script, bytes) in [
            ("w  hi", &b" hi"[..]),
            ("w \" hi\"", b" hi"),
            ("w \"hi \"", b"hi"),
            ("w \"a\" \"b\"", b"a b"),
            ("w a  b", b"a  b"),
            ("w a\\nb", b"a\nb"),
            ("w a\\;b\\\"c", b"a;b\"c"),
            ("w a\\!b", b"a!b"),
            ("w a\\qb", b"a\\qb"),
            ("w a\\0b", b"a\0b"),
            ("w a\\777", b"a\xff"),
            ("w a\\\\b", b"a\\b"),
            ("w 'a\\'b'", b"a'b"),
            ("w \"\"", b""),
        ] {
            assert_eq!(command(script), Command::Write(bytes.to_vec()), "{script}");
        }
        // radare2 rejects these (`w` without its space, `\x` without two hex
        // digits), or prints a byte that is not text.
        for script in ["w", "w\thi", "w a\\x4", "w a\\xZZ", "?e \\x80"] {
            assert!(one(script).is_err(), "{script}");
        }
    }

    #[test]
    fn what_radare2_reads_as_an_operator_is_refused() {
        for script in [
            "?e a|b",
            "?e a>b",
            "?e a && ?e b",
            "?e `?e a`",
            "?e $(?e a)",
            "?e \"`?e a`\"",
            "\"?e a\"",
            "?e \"a",
            "?e a\\\\\\;b",
            "@0x10@?e a",
            "(m;?e a)",
            // radare2 reads what follows an unquoted `\~` as text: these print
            // `~~a`, `a~"b~b` and `x~\` there.
            "?e \\~~a",
            "?e a\\~\\\"b~b",
            "?e x\\~\\~",
            "?e a\\~'b~c'",
            // radare2's recursive help, found as written, quotes and all.
            "?e a?*b",
            "?e \"a?*b\"",
            "?e a~b?*",
            "?*",
        ] {
            assert!(one(script).is_err(), "{script}");
        }
        // A quoted `\~` is not searched, and a `?*` just after a `~` is not
        // the help, in radare2 either.
        assert_eq!(command("?e \"a\\~~b\""), echo("a~~b"));
        assert_eq!(command("?e a\\~xb"), echo("a~xb"));
        assert_eq!(command("?e \"a~?*\" b?*"), echo("a~?* b?*"));
        // A comment runs nothing after it, and a substitution's `;` is its own.
        assert_eq!(read("?e a;?e b#c;?e d"), [true, false]);
        assert_eq!(statements("?e `a;b`;?e c").len(), 2);
    }

    /// Whether each statement of a line was read or refused.
    fn read(script: &str) -> Vec<bool> {
        statements(script).iter().map(Result::is_ok).collect()
    }

    /// Each line's statements as radare2 6.2.3 cuts them: a refused one is
    /// where radare2 reads what r2s does not implement, and the lines end
    /// where radare2 stops reading.
    #[test]
    fn a_statement_ends_where_radare2_ends_it() {
        for (script, cut) in [
            // A macro runs to the first `;` outside its parentheses, after
            // blanks, a repeat count or an `@addr@` prefix.
            ("(m;?e x)", &[false][..]),
            ("2(m;?e x)", &[false]),
            ("?e a;(m;?e x);?e c", &[true, false, true]),
            ("?e a; 2 (m;?e x) ;?e c", &[true, false, true]),
            ("?e a;\"2\"(m;?e x);?e c", &[true, false, true]),
            ("?e a;\"\"(m;?e x);?e c", &[true, false, true]),
            ("@0x10@(m;?e x;?e y);?e c", &[false, true]),
            // Its parentheses are counted raw, so an extra `)` or a quoted one
            // takes the rest of the line, and a `#` in it ends the line.
            ("?e a;(m;?e x));?e c;?e d", &[true, false]),
            ("?e a;(m;?e \")\");?e c", &[true, false]),
            ("?e a;(m;?e a#x);?e c", &[true, false]),
            // Not a macro: something else comes first, or no `)` follows.
            ("?e a;x(m;?e y);?e c", &[true, true, true, true]),
            ("?e (a);?e b", &[true, true]),
            ("(m ?e x;?e c", &[true, true]),
            // An `@addr@` prefix is refused; a malformed one ends the line.
            ("?e a;@0x10@?e z;?e b", &[true, false, true]),
            ("?e a;@?;?e b", &[true, false, true]),
            ("?e a;@0x10 ;?e b", &[true, false]),
            ("?e a;@@x;?e b", &[true, false]),
            // Backslashes pair: after two, `;` and `#` are operators again.
            ("?e a\\\\;?e b", &[false, true]),
            ("?e a\\\\\\;?e b", &[false]),
            ("?e a\\\\#b;?e c", &[false]),
            // A command that starts with a quote takes the rest of the line;
            // an empty pair or a quoted repeat count does not.
            ("?e z;'?e a';?e b", &[true, false]),
            ("?e z;\"?e a\";?e b", &[true, false]),
            ("?e z;2 \"3\"(m;?e y);?e c", &[true, false]),
            ("?e z;@0x10@'?e a;?e b", &[true, false]),
            ("?e z;\"\";?e b", &[true, false, true]),
            ("?e z;\"2\"?e a;?e b", &[true, false, true]),
            // A repeat count with no command abandons the rest of the line,
            // wherever the count stands; `0` is no count.
            ("?e a;1;?e b", &[true, false]),
            ("?e a; 1 \"\" ;?e b", &[true, false]),
            ("?e a;\"2\";?e b", &[true, false]),
            ("?e a;@0x10@2;?e b", &[true, false]),
            ("2@0x10@;?e b", &[false]),
            ("?e a;@0x10@;?e b", &[true, false, true]),
            ("?e a;0;?e b", &[true, true, true]),
            ("?e a;18446744073709551615;?e b", &[true, true, true]),
        ] {
            assert_eq!(read(script), cut, "{script}");
        }
    }

    /// Whether each statement of each line of a script was read or refused.
    fn lines(reader: &mut Reader, script: &str) -> Vec<Vec<bool>> {
        reader
            .script(script)
            .iter()
            .map(|line| line.iter().map(Result::is_ok).collect())
            .collect()
    }

    /// A script's lines as radare2 6.2.3 reads them: cut at every LF, quotes
    /// and all, before anything else is read, with the lines radare2 reads
    /// whole refused whole.
    #[test]
    fn a_script_is_cut_at_every_line_feed_first() {
        let mut reader = Reader::default();
        for (script, cut) in [
            ("?e a\n?e b", &[&[true][..], &[true]][..]),
            // A last line that is empty is none; one between two is a line.
            ("?e a\n", &[&[true]]),
            ("?e a\n\n?e b", &[&[true], &[true], &[true]]),
            ("?e a\r\n?e b", &[&[true], &[true]]),
            // A quote, a grep or a macro does not reach past its line.
            ("?e \"a\nb\"", &[&[false], &[false]]),
            ("?e a;?e \"b\n;?e c\"", &[&[true, false], &[true, false]]),
            ("?e a~a\n?e b", &[&[true], &[true]]),
            // Without a `)` on its line, `(m` is no macro (cmd.c:3806-3813).
            ("(m;?e x\n?e b)", &[&[true, true], &[true]]),
            // A comment ends its line only.
            ("?e a#b;?e c\n?e d", &[&[false], &[true]]),
            // Read whole: a comment line, and a base64 call; `|?` is not one.
            ("|x;?e a\n?e b", &[&[false], &[true]]),
            ("|?;?e a", &[&[false, true]]),
            ("b64:'x';?e a", &[&[false]]),
            // A `/*` comment takes the rest of the script, `*/` and all.
            ("?e a\n/*;?e b\n?e c\n*/\n?e d", &[&[true], &[false]]),
        ] {
            assert_eq!(lines(&mut reader, script), cut, "{script:?}");
        }
        // Between scripts it runs to a line that starts with `*/`, and takes
        // that line with it.
        let mut reader = Reader::default();
        assert_eq!(lines(&mut reader, "/*\n"), [[false]]);
        assert_eq!(lines(&mut reader, "?e a\n"), [[false]]);
        assert_eq!(lines(&mut reader, "*/ ?e b\n"), [[false]]);
        assert_eq!(lines(&mut reader, "?e c\n"), [[true]]);
    }
}
