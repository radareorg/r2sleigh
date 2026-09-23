//! Narrative demo: run `cargo run` to watch the late-bound location model
//! resolve, re-walk, and refuse stale access on a small recorded execution.
//! Every line is also an assertion, so the demo is itself a check.

use late_bound_locations::*;

fn main() {
    println!("== Late-bound typed locations: proof by demonstration ==\n");

    // ---- torsor ---------------------------------------------------------
    let a = Addr(0x1000);
    let field_off = Offset(0x18);
    let elem = a + field_off; // torsor action; `a + a` would not compile
    assert_eq!(elem - a, field_off); // difference is an offset
    println!(
        "[torsor]  0x{:x} + off(0x18) = 0x{:x};  (that - base) = off(0x{:x})",
        a.0,
        elem.0,
        (elem - a).0
    );
    println!("          (there is no `Addr + Addr`: that absence is the torsor axiom)\n");

    // ---- a recorded execution ------------------------------------------
    let mut w = World::new();
    // three heap nodes
    w.alloc(1, Addr(0x1000), 16, 0);
    w.alloc(2, Addr(0x2000), 16, 0);
    w.alloc(3, Addr(0x3000), 16, 0);
    // t=5:  A.next -> B, B.data = 111
    w.store(Addr(0x1000), 5, 0x2000);
    w.store(Addr(0x2008), 5, 111);
    // t=15: A.next -> C, C.data = 222   (the list was mutated)
    w.store(Addr(0x1000), 15, 0x3000);
    w.store(Addr(0x3008), 15, 222);

    // ---- one handle, named by meaning ----------------------------------
    let obj = Location::alloc_rooted(1, node_ty());
    let data = obj
        .field("next")
        .unwrap()
        .deref()
        .unwrap()
        .field("data")
        .unwrap(); // obj->next->data

    let d10 = data.read(&w, 10).unwrap();
    let d20 = data.read(&w, 20).unwrap();
    assert_eq!((d10, d20), (111, 222));
    println!(
        "[project] obj->next->data  @t=10 -> {}   @t=20 -> {}",
        d10, d20
    );
    println!("          same handle, re-walked at eval time (next was repointed)\n");

    // ---- time travel via the same handle -------------------------------
    let past = data.at(10).read(&w, 9999).unwrap();
    assert_eq!(past, 111);
    println!(
        "[.at(t)]  read obj->next->data as-of t=10 while now=9999 -> {}",
        past
    );
    println!("          one abstraction serves live debugging AND replay\n");

    // ---- staleness is a typed error, never garbage ---------------------
    let secret = Location::alloc_rooted(2, Ty::U64); // node B chunk
    w.store(Addr(0x2000), 6, 0xdead);
    let live = secret.read(&w, 7).unwrap();
    assert_eq!(live, 0xdead);
    w.free(2, 100);
    let stale = secret.read(&w, 150);
    let raw_bytes = w.load(Addr(0x2000), 150); // the bytes are STILL there
    assert_eq!(raw_bytes, Some(0xdead));
    assert!(matches!(stale, Err(LocErr::UseAfterFree { .. })));
    println!("[safety]  live read @t=7 -> 0x{:x}", live);
    println!(
        "          after free(t=100): raw bytes at 0x2000 still = 0x{:x}",
        raw_bytes.unwrap()
    );
    println!("          but handle.read(@t=150) = {:?}", stale);
    println!("          -> the model refuses to hand you the stale value\n");

    // ---- explicit opt-out ----------------------------------------------
    let frozen = secret.snapshot(&w, 7).unwrap();
    let after_free = frozen.read_at(&w, 150).unwrap();
    assert_eq!(after_free, 0xdead);
    println!("[.snapshot] you can deliberately freeze the address:");
    println!(
        "          frozen.read_at(@t=150) = 0x{:x}  (safety opted out, on purpose)\n",
        after_free
    );

    println!("All demonstrations held. Run `cargo test` for the full proof suite.");
}
