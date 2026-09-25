// Function preparation fills the display-name carrier from the snapshot: a
// copy, not a reading. The module became a directory (`function/`), and the
// allowance follows it.
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

fn copy_into_snapshot(artifact: &Artifact) -> usize {
    artifact.display_names().functions().len()
}

fn main() {
    let _ = copy_into_snapshot(&Artifact {
        names: DisplayNames,
    });
}
