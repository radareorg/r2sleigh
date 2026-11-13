mod convert {
    pub struct CTypeLike;

    pub fn parse_c_type_like(spelling: &str, _: u32) -> Option<CTypeLike> {
        // The definition's own module may recurse.
        spelling.strip_suffix('*').and_then(|inner| parse_c_type_like(inner, 64))
    }

    pub fn a_sibling_in_its_module(spelling: &str) {
        let _ = parse_c_type_like(spelling, 64);
    }
}

fn reparses_a_spelling(spelling: &str) {
    let _ = convert::parse_c_type_like(spelling, 64);
}

#[cfg(test)]
mod tests {
    fn a_fixture_may_parse() {
        let _ = super::convert::parse_c_type_like("int", 64);
    }
}

fn main() {
    reparses_a_spelling("char *");
}
