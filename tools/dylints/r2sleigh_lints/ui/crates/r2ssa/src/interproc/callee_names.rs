struct DisplayNames;

impl DisplayNames {
    fn functions(&self) -> Vec<(u64, String)> {
        Vec::new()
    }
}

struct Artifact {
    names: DisplayNames,
}

impl Artifact {
    fn display_names(&self) -> &DisplayNames {
        &self.names
    }
}

// Seeding callee summaries from what radare2 called the callees: semantics
// from a spelling.
fn seed_named_callees(artifact: &Artifact) -> usize {
    artifact.display_names().functions().len()
}

fn main() {
    let _ = seed_named_callees(&Artifact {
        names: DisplayNames,
    });
}
