use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ValueId(u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InstId(u32);

struct Facts {
    definitions: BTreeMap<ValueId, InstId>,
    by_address: BTreeMap<u64, InstId>,
}

fn readers(values: &[ValueId]) -> HashMap<InstId, usize> {
    let mut seen = BTreeSet::<ValueId>::new();
    let mut counts = BTreeMap::new();
    for value in values {
        seen.insert(*value);
        counts.insert(*value, InstId(value.0));
    }
    let _ = counts;
    HashMap::new()
}

fn main() {
    let facts = Facts {
        definitions: BTreeMap::new(),
        by_address: BTreeMap::new(),
    };
    let _ = (facts.definitions.len(), facts.by_address.len());
    let _ = readers(&[ValueId(0)]);
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_key_by_entity() {
        let _: std::collections::BTreeMap<super::ValueId, u8> = Default::default();
    }
}
