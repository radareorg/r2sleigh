//! Reading facts off rendered C whichever pipeline spelled it.

#![allow(dead_code)]

/// `text` split at its commas outside parentheses, each piece trimmed.
pub fn top_level(text: &str) -> Vec<String> {
    let mut pieces = vec![String::new()];
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                pieces.push(String::new());
                continue;
            }
            _ => {}
        }
        pieces.last_mut().expect("one piece").push(c);
    }
    pieces
        .into_iter()
        .map(|piece| piece.trim().to_owned())
        .filter(|piece| !piece.is_empty() && piece != "void")
        .collect()
}

/// The byte offset of the parenthesis closing the one at `open`.
fn closing(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, c) in text[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 1 => return Some(open + at),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// The comma-separated operands inside the parentheses opened at `open`.
pub fn arguments_at(text: &str, open: usize) -> Vec<String> {
    closing(text, open).map_or_else(Vec::new, |close| top_level(&text[open + 1..close]))
}

/// The parameter names on the signature line, the first line of `c`.
pub fn parameter_names(c: &str) -> Vec<String> {
    let signature = c.lines().next().unwrap_or_default();
    let Some(open) = signature.find('(') else {
        return Vec::new();
    };
    let close = closing(signature, open).unwrap_or(signature.len());
    top_level(&signature[open + 1..close])
        .into_iter()
        .map(|parameter| {
            let at = parameter.rfind([' ', '*']).map_or(0, |at| at + 1);
            parameter[at..].to_owned()
        })
        .collect()
}

/// `expression` without its leading casts and enclosing parentheses.
pub fn bare(expression: &str) -> &str {
    let mut expression = expression.trim();
    while expression.starts_with('(') {
        let Some(close) = closing(expression, 0) else {
            break;
        };
        let inner = &expression[1..close];
        let rest = expression[close + 1..].trim_start();
        let cast = inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ' || c == '*');
        if close + 1 == expression.len() {
            expression = inner.trim();
        } else if cast && !rest.is_empty() {
            expression = rest;
        } else {
            break;
        }
    }
    expression
}

/// The first `name = value;` in `c`, a declaration's initializer included.
fn first_assignment<'c>(c: &'c str, name: &str) -> Option<&'c str> {
    c.lines().skip(1).find_map(|line| {
        let (target, value) = line.trim().split_once(" = ")?;
        (target.rsplit(' ').next() == Some(name)).then(|| value.trim_end_matches(';'))
    })
}

/// Whether `value` is `parameter`, or reaches it through each variable's first
/// assignment (the entry value; later ones are loop-carried copies), or through
/// a load from an address `c` stores exactly once.
pub fn starts_from(c: &str, value: &str, parameter: &str) -> bool {
    let mut value = bare(value).to_owned();
    for _ in 0..c.lines().count() {
        if value == parameter {
            return true;
        }
        let next = if let Some(address) = value
            .strip_prefix("r2sleigh_load_u")
            .and_then(|rest| rest.find('(').map(|open| &rest[open..]))
        {
            let address = bare(address);
            let stores = c
                .lines()
                .filter_map(|line| {
                    let open = line.find("r2sleigh_store_u")?;
                    let open = open + line[open..].find('(')?;
                    let close = closing(line, open)?;
                    let operands = top_level(&line[open + 1..close]);
                    (operands.len() == 2 && bare(&operands[0]) == address)
                        .then(|| operands[1].clone())
                })
                .collect::<Vec<_>>();
            match stores.as_slice() {
                [stored] => stored.clone(),
                _ => return false,
            }
        } else if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            match first_assignment(c, &value) {
                Some(assigned) => assigned.to_owned(),
                None => return false,
            }
        } else {
            return false;
        };
        bare(&next).clone_into(&mut value);
    }
    false
}

/// `text` split at each `op` outside parentheses and brackets, each piece trimmed.
fn split_top(text: &str, op: char) -> Vec<&str> {
    let (mut pieces, mut depth, mut from) = (Vec::new(), 0usize, 0);
    for (at, c) in text.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            c if c == op && depth == 0 => {
                pieces.push(text[from..at].trim());
                from = at + c.len_utf8();
            }
            _ => {}
        }
    }
    pieces.push(text[from..].trim());
    pieces
}

/// The number a C integer literal spells, suffix and all.
pub fn literal(text: &str) -> Option<u64> {
    let digits = bare(text).trim_end_matches(['U', 'u', 'L', 'l']);
    match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => digits.parse().ok(),
    }
}

/// The bytes of a scalar C type.
fn size_of(ty: &str) -> Option<i64> {
    Some(match ty.trim().trim_start_matches("const ") {
        "uint8_t" | "int8_t" | "char" => 1,
        "uint16_t" | "int16_t" => 2,
        "uint32_t" | "int32_t" | "float" => 4,
        "uint64_t" | "int64_t" | "double" => 8,
        ty if ty.ends_with('*') => 8,
        _ => return None,
    })
}

/// Each local `afv` lists by name, with its entry-stack offset and declared type.
pub fn afv_locals(afv: &str) -> std::collections::BTreeMap<String, (i64, String)> {
    afv.lines()
        .filter_map(|line| {
            let (declared, at) = line.strip_prefix("var ")?.split_once(" @ entry.sp")?;
            let (ty, name) = declared.rsplit_once(' ')?;
            let offset = match at.split_at(1) {
                ("-", magnitude) => -i64::try_from(literal(magnitude)?).ok()?,
                ("+", magnitude) => i64::try_from(literal(magnitude)?).ok()?,
                _ => return None,
            };
            Some((name.to_owned(), (offset, ty.to_owned())))
        })
        .collect()
}

/// The element type and count of an array `c` declares as `T name[N];`.
fn declared_array<'c>(c: &'c str, name: &str) -> Option<(&'c str, i64)> {
    let pattern = format!(" {name}[");
    c.lines().find_map(|line| {
        let line = line.trim();
        let at = line.find(&pattern)?;
        let count = line[at + pattern.len()..].strip_suffix("];")?;
        let ty = line[..at].rsplit(')').next()?.trim();
        Some((ty, i64::try_from(literal(count)?).ok()?))
    })
}

/// Where `name` begins on the entry stack: an `afv` local, or D4's one `frame` array, which
/// ends at the entry stack pointer (doc/adr-decompiler-rewrite.md, "D4's frame").
fn base_of(c: &str, afv: &str, name: &str) -> Option<i64> {
    if name == "frame" {
        let (ty, count) = declared_array(c, "frame")?;
        return Some(-(size_of(ty)? * count));
    }
    afv_locals(afv).get(name).map(|(offset, _)| *offset)
}

/// The value of an address `expression` computes, and whether a stack object is its base.
fn evaluate(c: &str, afv: &str, expression: &str) -> Option<(i64, bool)> {
    let expression = bare(expression);
    let sum = split_top(expression, '+');
    if sum.len() > 1 {
        let mut total = (0i64, false);
        for term in sum {
            let (value, based) = evaluate(c, afv, term)?;
            if based && total.1 {
                return None;
            }
            total = (total.0 + value, total.1 || based);
        }
        return Some(total);
    }
    let product = split_top(expression, '*');
    if product.len() > 1 {
        let mut total = 1i64;
        for factor in product {
            match evaluate(c, afv, factor)? {
                (value, false) => total *= value,
                (_, true) => return None,
            }
        }
        return Some((total, false));
    }
    if let Some(ty) = expression
        .strip_prefix("sizeof(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some((size_of(ty)?, false));
    }
    if let Some(value) = literal(expression) {
        return Some((i64::try_from(value).ok()?, false));
    }
    let name = expression.strip_prefix('&').unwrap_or(expression);
    Some((base_of(c, afv, name)?, true))
}

/// The entry-stack offset of the address `expression` computes, where a stack object is its base.
pub fn entry_offset(c: &str, afv: &str, expression: &str) -> Option<i64> {
    match evaluate(c, afv, expression)? {
        (offset, true) => Some(offset),
        (_, false) => None,
    }
}

/// The operands of the call `callee(` that `expression` is, through its leading casts.
fn call_of(expression: &str, callee: &str) -> Option<Vec<String>> {
    let expression = bare(expression);
    let open = expression.strip_prefix(callee)?.find('(')? + callee.len();
    (closing(expression, open)? + 1 == expression.len()).then(|| arguments_at(expression, open))
}

/// The entry-stack offset `expression` reads, as a named local or through a load helper, seeing
/// through a reinterpretation of the bits read.
pub fn read_offset(c: &str, afv: &str, expression: &str) -> Option<i64> {
    let expression = bare(expression);
    for through in ["r2sleigh_float_from_bits_64", "r2sleigh_float_from_bits_32"] {
        if let Some([bits]) = call_of(expression, through).as_deref() {
            return read_offset(c, afv, bits);
        }
    }
    for width in [8, 16, 32, 64] {
        if let Some([address]) = call_of(expression, &format!("r2sleigh_load_u{width}")).as_deref()
        {
            return entry_offset(c, afv, address);
        }
    }
    afv_locals(afv).get(expression).map(|(offset, _)| *offset)
}

/// Each write to the stack `c` makes: the entry offset written and the value, whether spelled as
/// an assignment to a local `afv` places, to an element of an array `c` declares, or through a
/// store helper.
pub fn stack_writes(c: &str, afv: &str) -> Vec<(i64, String)> {
    let mut writes = Vec::new();
    for line in c.lines().map(str::trim) {
        let statement = line.strip_suffix(';').unwrap_or(line);
        if let Some(open) = statement.find("r2sleigh_store_u") {
            let Some(open) = statement[open..].find('(').map(|at| open + at) else {
                continue;
            };
            if let [address, value] = arguments_at(statement, open).as_slice()
                && let Some(offset) = entry_offset(c, afv, address)
            {
                writes.push((offset, value.clone()));
            }
            continue;
        }
        let Some((target, value)) = statement.split_once(" = ") else {
            continue;
        };
        let target = target.rsplit(' ').next().unwrap_or(target);
        let offset = if let Some((name, index)) = target
            .strip_suffix(']')
            .and_then(|target| target.split_once('['))
        {
            declared_array(c, name).and_then(|(ty, _)| {
                Some(base_of(c, afv, name)? + size_of(ty)? * i64::try_from(literal(index)?).ok()?)
            })
        } else if let Some(address) = target.strip_prefix('*') {
            entry_offset(c, afv, address)
        } else {
            afv_locals(afv).get(target).map(|(offset, _)| *offset)
        };
        if let Some(offset) = offset {
            writes.push((offset, value.to_owned()));
        }
    }
    writes
}

/// The array `c` declares that holds every byte of `[from, to)` on the entry stack, if one does.
pub fn array_spanning(c: &str, afv: &str, from: i64, to: i64) -> Option<String> {
    c.lines().find_map(|line| {
        let declared = line.trim().strip_suffix("];")?;
        let (head, count) = declared.split_once('[')?;
        let (ty, name) = head.rsplit_once(' ')?;
        let ty = ty.rsplit(')').next()?.trim();
        let base = base_of(c, afv, name)?;
        let end = base + size_of(ty)? * i64::try_from(literal(count)?).ok()?;
        (base <= from && to <= end).then(|| name.to_owned())
    })
}

/// The operands of the first call to `callee` in the body, past the signature and declarations.
pub fn call_arguments(c: &str, callee: &str) -> Option<Vec<String>> {
    let call = format!("{callee}(");
    c.lines().skip(1).find_map(|line| {
        let at = line.find(&call)?;
        let before = line[..at].trim_end();
        let preceded = line[..at].chars().next_back();
        // A declaration names the callee after a type; a call follows an operator, `(` or `return`.
        let declares = !before.is_empty()
            && !before.contains('=')
            && !before.ends_with("return")
            && before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '*');
        let part_of_a_name = preceded.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        (!declares && !part_of_a_name).then(|| arguments_at(line, at + callee.len()))
    })
}

/// The expression the first `return` in the body hands back.
pub fn returned(c: &str) -> Option<&str> {
    c.lines()
        .find_map(|line| line.trim().strip_prefix("return "))
        .map(|value| value.trim_end_matches(';'))
}

/// Whether `c` reads `bits` of memory at the constant `address`, as a dereference or through a
/// load helper.
pub fn reads_at(c: &str, address: u64, bits: u32) -> bool {
    let helper = format!("r2sleigh_load_u{bits}(");
    let deref = format!("*(uint{bits}_t*)");
    c.lines().any(|line| {
        let through_helper = line.match_indices(&helper).any(|(at, _)| {
            let open = at + helper.len() - 1;
            matches!(arguments_at(line, open).as_slice(), [operand] if literal(operand) == Some(address))
        });
        let dereferenced = line.match_indices(&deref).any(|(at, _)| {
            let operand = line[at + deref.len()..]
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or_default();
            literal(operand) == Some(address)
        });
        through_helper || dereferenced
    })
}
