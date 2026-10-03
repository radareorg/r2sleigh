//! What the rendering's proof line says, for the decompiler pane's title.
//!
//! Colour is not read from the text here: the renderer records what each part
//! of the C is as it writes it (`r2dec::CRole`), and the pane paints from that.

/// What the rendering's proof comment says, where the line is one:
/// `/* r2dec proof: 4 constructs are marked below; ... */` gives
/// `4 constructs are marked below`.
pub fn proof(line: &str) -> Option<&str> {
    let after = line.split_once("r2dec proof:")?.1;
    Some(after.split(';').next().unwrap_or(after).trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_comment_is_read_to_its_first_clause() {
        let line = "    /* r2dec proof: 4 constructs are marked below; 28 source obligations */";
        assert_eq!(proof(line), Some("4 constructs are marked below"));
        assert_eq!(proof("return 0;"), None);
    }
}
