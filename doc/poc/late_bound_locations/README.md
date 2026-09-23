Late-Bound Locations — POC
==========================

A dependency-free, offline Rust proof-of-concept for the late-bound typed
location model in [`../../scripting.md`](../../scripting.md). It exists to
**prove the design works** by making it executable, and to ground the
higher-dimensional-algebra formalization in [`MATH.md`](MATH.md).

This was built without any network access, reasoning about the model locally and
mathematically. The claim being proven:

> A debugger location is a *section of a bundle over the execution timeline*,
> its address lives in a *torsor*, and resolution is *evaluation of that
> section* — defined exactly on its validity domain, so a stale handle raises
> instead of returning a wrong address.

Run it
------

```sh
cd doc/poc/late_bound_locations
cargo test     # the proof: 10 tests, one per design claim
cargo run      # a narrative demo of the same scenario
cargo clippy   # clean
```

It is its own Cargo workspace (see `Cargo.toml`), so it never touches the main
r2sleigh build, and uses only `std`, so it builds fully offline.

What each test proves
---------------------

| Test | Design claim |
|---|---|
| `addresses_are_a_torsor_over_offsets` | addresses are a `ℤ`-torsor; `Addr + Addr` is not even expressible |
| `alloc_rooted_is_constant_over_its_lifetime` | policy #1: snapshot address + liveness-tracked validity |
| `frame_relative_rebinds_live` | policy #2: live re-bind against `fp(t)`, scoped to an activation |
| `projection_rewalks_at_evaluation_time` | policy #3: `obj->next->data` re-walked at eval time |
| `null_deref_is_an_error` | a broken projection is a typed error, not a wild resolve |
| `stale_handle_raises_never_returns_garbage` | the safety property: stale ⇒ error, never stale bytes |
| `at_evaluates_at_a_chosen_timepoint` | `.at(t)` = stalk evaluation; unifies live + replay |
| `at_cascades_into_projection` | `.at(t)` pins an entire pointer walk coherently |
| `snapshot_opts_out_of_validity` | `.snapshot()` is the explicit, greppable escape hatch |
| `offset_math_is_type_driven_and_stays_inside` | offsets come from the type and never escape as raw ints |

Files
-----

- `src/lib.rs` — the model + the proof suite.
- `src/main.rs` — `cargo run` narrative demo.
- `MATH.md` — the higher-dimensional-algebra formalization (torsor, base space,
  sections, provenance-as-section-shape, the safety theorem, stalks/restriction).

Scope & honest limits
----------------------

This is a *model-level* proof, not an engine. It uses a recorded, time-versioned
`World` in place of a live target and a two-field `Node` type in place of
r2types' interned `TypeArena`. It deliberately does **not** implement: a real
allocator model (custom/arena allocators break simple chunk identity),
per-thread validity domains for multi-threaded execution, or the query/probe
layers. Those are named as open items in `../../scripting.md`. What it *does*
establish is that the central data type and its resolution semantics are small,
total, and correct — implementable as a type plus one evaluation function, with
no new language.
