//! Register naming helpers for alias resolution.

fn is_numbered_reg(name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    let (prefix, rest) = name.split_at(1);
    matches!(prefix, "r" | "x" | "w") && rest.chars().all(|c| c.is_ascii_digit())
}

fn is_special_reg(name: &str) -> bool {
    matches!(
        name,
        "pc" | "sp" | "bp" | "fp" | "lr" | "ip" | "ra" | "zero" | "gp" | "tp"
    )
}

fn register_alias_rank(name: &str) -> (u8, usize, String) {
    let lower = name.to_ascii_lowercase();
    if is_special_reg(&lower) {
        return (0, lower.len(), lower);
    }
    if is_numbered_reg(&lower) {
        return (1, lower.len(), lower);
    }
    (2, lower.len(), lower)
}

/// Pick a canonical register name from a list of aliases.
pub fn select_register_name<'a, I>(names: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut best: Option<((u8, usize, String), &'a str)> = None;

    for name in names {
        let rank = register_alias_rank(name);
        match &best {
            None => best = Some((rank, name)),
            Some((best_rank, best_name)) => {
                if rank < *best_rank || (rank == *best_rank && name < *best_name) {
                    best = Some((rank, name));
                }
            }
        }
    }

    best.map(|(_, name)| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::select_register_name;

    #[test]
    fn prefers_special_registers() {
        let names = ["r13", "sp"];
        let chosen = select_register_name(names.iter().copied());
        assert_eq!(chosen.as_deref(), Some("sp"));
    }
}
