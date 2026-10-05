use std::cell::{OnceCell, RefCell};
use std::collections::BTreeMap;
use std::sync::Mutex;

struct Program {
    pointers: Mutex<BTreeMap<u64, u64>>,
    survey: RefCell<Option<u64>>,
    #[cfg_attr(dylint_lib = "r2sleigh_lints", allow(cache_outside_query_database))]
    machine: OnceCell<u64>,
    bytes: Vec<u8>,
}

fn main() {}
