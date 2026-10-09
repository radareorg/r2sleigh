//! Reading facts off rendered C whichever pipeline spelled it.

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
