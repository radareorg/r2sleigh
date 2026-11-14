use std::fs;
use std::path::Path;

#[test]
fn production_has_no_legacy_name_identity_or_repair_answerers() {
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&source_dir, &mut files);
    files.sort();

    let forbidden = [
        (
            "find_ssa_name_for_rendered_alias",
            "rendered-alias reverse lookup",
        ),
        ("resolve_undeclared_carriers", "undeclared-carrier repair"),
        ("resolve_stack_var", "stack spelling identity lookup"),
        (
            "build_param_register_aliases",
            "positional parameter aliasing",
        ),
        ("NameSource for", "parallel naming owner"),
        (".note_ssa_name(", "SSA-name side-table write"),
        ("fn note_ssa_name(", "SSA-name side-table owner"),
        (".for_ssa_name(", "SSA-name side-table lookup"),
        ("fn for_ssa_name(", "SSA-name side-table owner"),
        (
            "declare_assigned_names_without_a_declaration",
            "declare-after-render repair",
        ),
        ("spell_every_name_as_c", "post-render spelling answerer"),
        ("symbol::var_ref(", "generic spelling-to-symbol mint"),
        ("symbol::declare(", "generic spelling-to-symbol mint"),
        ("declare_or_reuse(", "generic spelling-to-symbol mint"),
    ];
    let mut violations = Vec::new();

    for file in files {
        let rel = file
            .strip_prefix(&source_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).expect("r2dec source file should be UTF-8");
        for (line_idx, line) in production_lines(&text) {
            let trimmed = line.trim();
            for (token, reason) in forbidden {
                if rel == "symbol.rs"
                    && matches!(
                        token,
                        "symbol::var_ref(" | "symbol::declare(" | "declare_or_reuse("
                    )
                {
                    continue;
                }
                if trimmed.contains(token) {
                    violations.push(format!("{rel}:{} [{reason}] {trimmed}", line_idx + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "renderer production must consume sealed identities and presentation, \
         never reverse names or repair the final AST. Violations:\n{}",
        violations.join("\n")
    );
}

/// The production lines of `render/<file>` that contain any of `tokens`, as `file:line text`.
fn render_lines_naming(file: &str, tokens: &[&str]) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/render")
        .join(file);
    let text = fs::read_to_string(&path).expect("a render source file should be UTF-8");
    production_lines(&text)
        .into_iter()
        .filter(|(_, line)| tokens.iter().any(|token| line.contains(token)))
        .map(|(index, line)| format!("{file}:{} {}", index + 1, line.trim()))
        .collect()
}

/// A verdict is a function of the facts and the CFG's reverse postorder (ROADMAP D58): control reads
/// no value and the spelling reads no placement, so no write order reaches a verdict.
#[test]
fn control_writes_only_what_was_spelled_and_the_spelling_reads_no_placement() {
    let control = render_lines_naming("control.rs", &["Values", "values::"]);
    assert!(
        control.is_empty(),
        "render/control.rs reads D2 only through `Spelled`:\n{}",
        control.join("\n")
    );
    let placement = [
        "exits_of(",
        "merges_in(",
        "labelled(",
        "loop_headed_by(",
        ".edge(",
        "Placement",
        "EdgeShape",
    ];
    let spelled = render_lines_naming("spelled.rs", &placement);
    assert!(
        spelled.is_empty(),
        "render/spelled.rs spells before any block is placed:\n{}",
        spelled.join("\n")
    );
}

/// Whether a call never returns is a fact of its site's proven `Never` (ROADMAP D75, D384): a function
/// deciding it names no expression and nothing a call carries; `site_of` binds `func` and `site` alone.
#[test]
fn a_noreturn_decision_reads_the_callee_and_nothing_the_call_passes() {
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&source_dir, &mut files);
    files.sort();
    let (mut deciders, mut violations) = (0, Vec::new());
    for file in files {
        let text = fs::read_to_string(&file).expect("r2dec source file should be UTF-8");
        let production = production_lines(&text)
            .into_iter()
            .map(|(_, line)| line)
            .collect::<Vec<_>>()
            .join("\n");
        let code = code_of(&production);
        let decides = |(name, body): &(&str, &str)| {
            *name == "site_of" || (*name != "never_returns" && body.contains(".never_returns("))
        };
        for (name, body) in functions(&code).into_iter().filter(decides) {
            deciders += 1;
            let read = past_the_callee(name, body);
            violations.extend(read.map(|read| format!("{}: fn {name} {read}", file.display())));
        }
    }
    assert!(
        deciders >= 6,
        "the predicate's readers were not found: {deciders}"
    );
    assert!(
        violations.is_empty(),
        "a noreturn decision reads what the call passes:\n{}",
        violations.join("\n")
    );
}

/// What a noreturn decision's `body` reads past the site: `site_of` binds a call's `func` and `site`
/// alone, and a reader binds no expression, so a statement reaches it only through `site_of`.
fn past_the_callee(name: &str, body: &str) -> Option<String> {
    let extracts = name == "site_of";
    let mut words = vec!["args", "format", "Debug"];
    if !extracts {
        words.extend(["site", "CExpr", "Call"]);
    }
    let read = (words.into_iter())
        .filter(|word| mentions(body, word))
        .collect::<Vec<_>>();
    let binds = !extracts && body.replace("Expr(_)", "").contains("Expr(");
    let func_alone = !extracts || body.contains("Call { func, site, .. }");
    (!read.is_empty() || binds || !func_alone)
        .then(|| format!("reads {read:?}, binds an expression {binds}, func alone {func_alone}"))
}

/// Whether `word` occurs in `code` as a whole identifier.
fn mentions(code: &str, word: &str) -> bool {
    code.match_indices(word).any(|(at, _)| {
        !code[..at].ends_with(identifier) && !code[at + word.len()..].starts_with(identifier)
    })
}

fn identifier(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Each `fn` item of `code` with its body, the text between its braces.
fn functions(code: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("fn ") {
        if code[..at].ends_with(identifier) {
            continue;
        }
        let rest = &code[at + 3..];
        let name_end = rest.find(|c| !identifier(c)).unwrap_or(rest.len());
        if let Some(open) = signature_end(rest).filter(|end| rest[*end..].starts_with('{')) {
            out.push((&rest[..name_end], body_at(&rest[open..])));
        }
    }
    out
}

/// Where a signature ends: its first `{` or `;` outside parentheses and brackets.
fn signature_end(code: &str) -> Option<usize> {
    let mut depth = 0isize;
    code.char_indices().find_map(|(at, c)| {
        depth += match c {
            '(' | '[' => 1,
            ')' | ']' => -1,
            _ => 0,
        };
        (depth == 0 && matches!(c, '{' | ';')).then_some(at)
    })
}

/// The text of the brace group `code` opens with.
fn body_at(code: &str) -> &str {
    let mut depth = 0usize;
    for (at, c) in code.char_indices() {
        depth = match c {
            '{' => depth + 1,
            '}' if depth == 1 => return &code[..=at],
            '}' => depth - 1,
            _ => depth,
        };
    }
    code
}

/// `text` with every comment, string and character literal blanked, so a brace in one is no brace.
fn code_of(text: &str) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let end = literal_end(&chars, at).unwrap_or(at + 1);
        let blank = end > at + 1;
        let kept = chars[at..end].iter();
        out.extend(kept.map(|c| if blank && *c != '\n' { ' ' } else { *c }));
        at = end;
    }
    out
}

/// Where the comment or literal starting at `at` ends, or `None` when none starts there.
fn literal_end(chars: &[char], at: usize) -> Option<usize> {
    let ahead = |n: usize| chars.get(at + n).copied();
    let until = |from: usize, close: &[char]| {
        (from..chars.len())
            .find(|end| chars[*end..].starts_with(close))
            .map_or(chars.len(), |end| end + close.len())
    };
    match (chars[at], ahead(1), ahead(2)) {
        ('/', Some('/'), _) => Some(until(at, &['\n'])),
        ('/', Some('*'), _) => Some(until(at + 2, &['*', '/'])),
        ('"', ..) => Some(escaped_end(chars, at + 1, '"')),
        ('r', Some('"'), _) => Some(until(at + 2, &['"'])),
        ('r', Some('#'), Some('"')) => Some(until(at + 3, &['"', '#'])),
        ('\'', Some('\\'), _) => Some(escaped_end(chars, at + 1, '\'')),
        ('\'', _, Some('\'')) => Some(at + 3),
        _ => None,
    }
}

/// The end of a literal closed by `close` from `from`, a backslash escaping the character after it.
fn escaped_end(chars: &[char], from: usize, close: char) -> usize {
    let mut at = from;
    while at < chars.len() && chars[at] != close {
        at += 1 + usize::from(chars[at] == '\\');
    }
    (at + 1).min(chars.len())
}

/// Lines outside `#[cfg(test)]` items, retaining zero-based source line numbers.
/// Test items are skipped rather than treated as EOF so a production item
/// placed after one cannot hide from an architecture interlock.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines
        .iter()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.trim() == "#![cfg(test)]")
    {
        return Vec::new();
    }
    let mut production = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        if lines[index].trim() == "#[cfg(test)]" {
            let mut depth = 0isize;
            let mut opened = false;
            index += 1;
            let item_head = lines.get(index).map_or("", |line| line.trim_start());
            let expects_brace = item_head.starts_with("mod ")
                || item_head.starts_with("impl ")
                || item_head.starts_with("struct ")
                || item_head.starts_with("enum ")
                || item_head.starts_with("trait ")
                || item_head.starts_with("fn ")
                || item_head.contains(" fn ");
            while index < lines.len() {
                for byte in lines[index].bytes() {
                    match byte {
                        b'{' => {
                            depth += 1;
                            opened = true;
                        }
                        b'}' => depth -= 1,
                        _ => {}
                    }
                }
                let terminal = lines[index].trim_end();
                index += 1;
                if opened && depth == 0 {
                    break;
                }
                if !opened
                    && (terminal.ends_with(';') || (!expects_brace && terminal.ends_with(',')))
                {
                    break;
                }
            }
            continue;
        }
        production.push((index, lines[index]));
        index += 1;
    }
    production
}

fn collect_rust_files(directory: &Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .expect("r2dec source directory should be readable")
        .map(|entry| entry.expect("r2dec source entry should be readable").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}
