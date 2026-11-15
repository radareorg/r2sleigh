// A public struct's bool that states a negative fact is denied; a private one, and a witness, pass.

pub struct Reads {
    pub registers: Vec<u64>,
    pub stated: bool,
    pub arguments_proven: bool,
}

pub struct Bound(());

pub struct Witnessed {
    pub bound: Option<Bound>,
}

struct Private {
    kept: bool,
}

fn main() {
    let reads = Reads {
        registers: Vec::new(),
        stated: false,
        arguments_proven: false,
    };
    let _ = (reads.registers, reads.stated, reads.arguments_proven);
    let _ = Witnessed { bound: None }.bound;
    let _ = Private { kept: true }.kept;
}
