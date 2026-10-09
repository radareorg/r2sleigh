# The scripting surface

Draft, 2026-10-06, reviewed 2026-10-09, not yet on the roadmap. If adopted it
fills ROADMAP row **A** (agent surface) and bounds row **S2** (`@@`, search,
pipes). Nothing described here exists. It names one seam change to
`AGENTS.md`, in section 7.

The review replaced every reliance on the session memo (`query/memo.rs`, since
deleted) with Q0's query database (`query/db.rs`), and added three things the
draft left open: the threading model at the C ABI (3.2A), one owner for the
evaluator (3.4), and the owner of a script-stated fact (8.3). The roadmap fit
it recommends: 3.1 and section 7 as one small item; 3.4's evaluator with the
`ae`/`ar` verbs under row E; 3.2, 3.3 and 3.5 after both.

## 1. What the language is

radare2's command language holds 64-bit numbers and strings. `$$` is the
seek, `$s` the file size, a backtick substitutes one command's text into
another, `@@` loops a command over a list of addresses, and `(name; body)` is
a macro. Every value is text that was printed and read back, and every value
is one untyped integer or that text. A script that wants to know what writes
a variable greps a listing for a register name. A script that wants eight
bytes of `AAAAAAAA` in a register spells `0x4141414141414141` itself, because
`r_num_math` has no pack and `'A'` is one byte (`libr/util/unum.c:267`).

The engine already holds something stronger. F1 gave every function, block,
instruction and SSA value a stable id. `crates/r2engine/src/query/mod.rs`
answers a typed request with `Answer<T>` and a `Completion` saying why it
stopped, and `Support` names the smallest evidence that established each
claim. `Work` admits cost without touching meaning. The query database
(`query/db.rs`) stamps every answer with the byte revision it was last checked
at, which a binding surfaces as the revision its handle was taken at;
`Answer<T>` does not carry it yet, and 3.1 adds it.

So the surface is a typed language over the query database, and the unit a
script passes around is a typed value or a handle with a revision attached. A
script holding a value id asks for its definition, its uses, its type and its
callsites as typed answers. It never parses a listing. A script holding bytes
knows their length and the program's endianness, so a payload is a value the
language builds and never arithmetic the user does.

This is also what makes the surface hackable in the direction radare2 cannot
offer: a script can **state** a fact as well as read one. Row C's `Fact` and
`Confidence`, and `doc/debugger.md` section 2's scope vocabulary, already have
the slot: a script-stated type or signature enters as **assumed**, with the
script as its provenance, and every answer that reads it says so. A user who
knows the convention at `0x401000` admits it, and `pdd` renders under that
premise with the premise named.

## 2. What it must not become

Non-negotiable 4 rules out the quickest build: an SDK that shells out to
`pddj` and `aflj` and parses the JSON. `crates/r2engine/src/json.rs` is a
render target, and a binding that reads it would be a second owner of every
fact it touches, reconstructing downstream what `records.rs` states upstream.

Non-negotiable 8 rules out the quickest ergonomics. A Python attribute that
returns `None` where the engine refused turns a refusal into a default value
one call later. Every binding returns the refusal and its reason, and a
script that wants a default writes one.

The Performance section rules out a Python loop as the search strategy. A
scripted query over a large function takes the same bounded budget and the
same refusal modes a command takes, so `Work` is a parameter of the binding
and not an afterthought.

## 3. Four layers, tightest constraint first

The order is forced: each layer is the binding target of the next, so an
upper layer built first picks a model the lower one then has to keep.

### 3.1 The handle model (`r2engine`, no new crate)

`OpenProgram<S>` is already the object: `prepared`, `rendered`,
`function_info`, `listing`, `function_graph`, `functions`,
`functions_holding`, `revision`. The work is to state the model a binding
holds. No new facts:

- a handle is an id plus the byte revision it was taken at, so a stale handle
  is detectable instead of silently wrong;
- `Program`, `Function`, `Block`, `Instruction`, `Value`, `Type`,
  `Reference` and `Answer` are the only nouns a script sees;
- a write advances the byte revision, and the database's red-green check keeps
  every answer that read none of the written ranges, which is how a long
  script survives a patch without recomputing everything;
- row A's determinism contract holds: the same handles asked in a shuffled
  order give byte-identical answers, which is the test row A already names.

Cost: every accessor is an index read over dense ids, `O(1)` or `O(log n)`,
per the structural rules. A bulk accessor returns every instruction or value
of a function in one call, because the FFI boundary is where a per-item
accessor becomes the cost of the whole script.

### 3.2 The C ABI (`r2ffi`, a new `cdylib`)

One handle-based C header, because every other language binds to C. Opaque
handles, integer ids, bulk arrays out, an error channel carrying a refusal
reason, with no null return. No Rust types cross. This layer exists so
that Python, Lua, Frida and a future Ghidra bridge bind to one thing.

The budget argument crosses here: a caller passes `Work` and gets
`Completion` back, so a script cannot ask for unbounded work by accident.

### 3.2A Threads

The query database is single-threaded: `Db::get` returns `Rc<Q::Value>`, which
cannot cross a thread. So one session belongs to one thread, and the C ABI
says so. A handle holds ids and a revision, never an `Rc`, and every call
re-enters the session on the thread that owns it; a call from another thread is
an error with a reason, never a race. Python holds the GIL while a call runs,
or releases it only around work that touches no Python object. Whether the
database becomes `Send` (`Arc` answers and a lock per query) for a host that
wants parallel scripts is an open question, decided by measuring what the
locks cost on the census before any binding depends on it.

### 3.3 Python (`r2py`, PyO3 over 3.2)

pwntools' shape over the engine's facts, and fast because the loop is in
Rust. `ELF`, `Function`, `Value`, `Type` as classes; iteration over a
function's values is one FFI call, then a Python view over the result; a per-
value call pays the boundary cost each time.

Scope is analysis: discovery, listings, decompilation, references, types,
signatures, patches. pwntools' tubes, ROP chains and process interaction need
a running target, which is `doc/debugger.md`'s design and waits with it for
row D's switch. A `pwnlib`-compatible shim is a later question and not a goal: matching
an API whose model is text and bytes would cost the typed contract.

### 3.4 In-shell: a typed expression language

The shell gets a language of its own, and radare2's command line is a lexical
subset of it. radare2's grammar bounds what `scripts/diff_r2.py` gates, and it
does not bound what the shell can say.

What radare2 cannot do fixes the requirement. `r_num_math` in
`libr/util/unum.c` evaluates `+ - * / % & ^ |` and `<<`/`>>` over 64-bit
integers, and 79 `$` variables read session and program numbers. A character
constant is one byte: `unum.c:267` returns `str[1]` for `'A'`, and line 289
masks `str[1] & 0xff`. There is no `p64` and no pack in `unum.c`, in
`cmd_help.inc.c` or in `rax2`. So `ar rax=0x4141414141414141` sets the ESIL
register, and the eight bytes of `"AAAAAAAA"` have to be spelled by hand
first. Every width, every endianness and every string becomes the user's
arithmetic.

The successor types the value instead. Section 8 is the design.

The evaluator is a library crate of its own (name open), which `r2s`, `r2ffi`
and `r2py` all bind: `p64`, the width rules and packing have one owner, and a
Python script and a shell line that pack the same value cannot disagree. `r2s`
only parses the line and spells the result, per non-negotiable 2.

### 3.5 Embedding, later

An embedded Rhai or Lua over the 3.1 handle model stays available for control
flow the expression language does not carry: a user's own functions,
recursion, data structures. It waits until 3.1 and 3.2 exist, so the
embedding binds to one target, and it sees the same handles, budgets and
refusals the Python SDK sees.

## 4. Why this is faster than pwntools

pwntools is fast to write and slow to run because every fact is re-derived in
Python from bytes. Three properties move the work below the binding:

- a fact asked twice is computed once: the query database keeps each answer
  with the byte ranges and queries it read, and answers a repeated question by
  checking those reads (`query/db.rs`). A handle adds nothing to that; section
  8.7 states what is left to decide, which is retention;
- a loop over a binary's functions runs in Rust behind one call, and a
  bounded search states its budget and refuses when it is spent;
- stable ids mean a script carries a handle instead of re-finding a function
  by name on every call, which is what makes an interactive session over a
  large binary possible.

The number to beat is on record: the ROADMAP census and the release `pdd`
timing on the large 0pack and pumasim functions. A script that asks for one
function's facts must not cost more than the command that prints them.

## 5. What a script looks like

Illustrative. This fixes the model and commits no API:

```python
p = r2.open("./target")
f = p.function("main")                  # a handle, with its revision
for call in f.calls():                  # one FFI call, typed records
    if call.callee.name == "memcpy":
        n = call.argument(2)            # a value handle
        if n.support < r2.Support.CERTIFIED:
            print(f"{call.at:#x}: size {n.refusal()}")
```

Three properties the equivalent pwntools script cannot have: `n` is an SSA
value where pwntools has a parsed operand, `support` says what proved it, and
`refusal()` exists because the engine refuses where it cannot prove.

## 6. Order of work

1. State the handle model and the staleness rule in `r2engine`, with row A's
   shuffled-order determinism test. No new crate.
2. The typed value system and the expression evaluator, in its own library
   crate that `r2s` binds (3.4): `Int{w}`, `Bytes`, `Str`, `p64`, the width
   rules. It replaces `?v`'s arithmetic and needs nothing below it, so it can
   start first.
3. Register and memory lvalues over a session-owned `r2il::eval::State`, with
   `aes` stepping it. This is `doc/command-gap.md`'s rank 1, at 1152 tested
   calls.
4. `r2ffi`: the C header, handles, bulk accessors, the refusal channel.
5. `r2py`: PyO3, the analysis surface, timed against release `pdd`.
6. S2's radare2 subset, one refusal at a time against `diff_r2.py`.
7. Choose and embed Rhai or Lua over 3.1, after 4 exists.

Steps 2 and 3 are the visible win and depend only on 1 and on `r2il::eval`,
which exists. Step 6 runs in parallel throughout. Step 5 before step 4 would
bind Python to Rust types and strand every other language.

## 7. The seam change this needs

`AGENTS.md` says `r2s` is the only implementor of `Source`. `r2ffi` opens
files, so it needs one too, and `crates/r2s` is a bin-only crate whose
`Opened` (`crates/r2s/src/session.rs`) is about 25 lines over `r2image::Image`.
Two options (`Opened` now starts at line 58):

- move `Opened` into `r2image` as the image's own `Source` impl, and let
  `r2s` and `r2ffi` both use it. One owner, and the rule becomes "the image
  is the only file-backed `Source`";
- give `r2s` a `lib.rs` and let `r2ffi` depend on it. Cheaper, and wrong:
  the FFI layer would then depend on command dispatch.

The first. The rule in `AGENTS.md` is amended to name `r2image`, and the
reason recorded here: the rule's purpose is that nothing below `r2s` knows
what a file is, and `r2image` is the crate whose whole job is what a file
states.

## 8. The language

### 8.1 The example that sets the bar

Putting eight bytes of `AAAAAAAA` into a register, live, is one statement:

```
rax = p64("AAAAAAAA")
rdi = &"flag.txt"            ; the bytes written, rdi holds where
[rsp - 0x20] = p64($rip)
aes 4                        ; four steps of r2il::eval
rax                          ; what it holds now, with its width
```

radare2's nearest form is `ar rax=0x4141414141414141`, which works once the
user has packed the string by hand, in the right endianness, at the right
width. The difference is where the packing lives: in the user's head, or in a
typed evaluator that knows the program's endianness from `Program::endian()`.

### 8.2 Types

The grammar is small because the type system carries the weight.

| Type | Written | Notes |
|---|---|---|
| `Int{w}` | `0x41`, `0b1010`, `65`, `65:u8` | width carried, `w` in bits |
| `Bytes` | `p64(x)`, `p32(x)`, `"AAAA"`, `hex:4141` | a length and the program's endianness |
| `Str` | `"flag.txt"` | encoded on use, not on write |
| `Addr` | `0x401000`, `main`, `$$` | an `Int{64}` the engine can resolve to a name |
| handles | `fn("main")`, `$f.calls()[0].argument(2)` | `Function`, `Block`, `Value`, `Type` from 3.1 |
| `Answer<T>` | any query's result | carries the byte revision (3.1), `Completion`, `Support` |

Gotcha 3 becomes a type rule: a `Bytes` of 8 placed in an `Int{32}` slot is a
refusal, and a widening is written (`u32(b)`, `sx(x, 64)`). No silent
truncation, because a silently truncated payload is the bug the whole exercise
exists to prevent.

Packing is a function of the program, so `p64` reads endianness from the open
program rather than from a setting. On a big-endian target
`p64("AAAA\0\0\0\0")`
is a different number and the same source line.

### 8.3 Lvalues: what a statement can set

This is where the successor claim is cashed. Three kinds of assignment, three
owners, and the owners are already in the tree.

| Lvalue | Example | Owner | Effect |
|---|---|---|---|
| ESIL register | `rax = p64("AAAAAAAA")` | `r2il::eval::State::set_register` (`eval.rs:130`) | session VM state |
| VM or program memory | `[rsp - 0x20] = p64($rip)` | `r2il::eval::State` store, or the `w`/`wx` path | a program write advances the byte revision |
| a stated fact | `fn("main").signature = "int main(int, char **)"` | `r2types`, as an **assumed** fact | enters the fact graph with the script as provenance |
| a script variable | `$payload = p64(0x41) * 8` | the shell | scope-local, never a program fact |

The first two are the ESIL virtual machine, ranked first in
`doc/command-gap.md` at 1152 tested calls, and `r2il::eval` already implements
the semantics with a budget and a `Stop`. A step is `r2il::eval::step` under
its budget, so `aes 4` is four steps and a refusal where the semantics run
out.

The third row is a new kind of program input, and its owner is ROADMAP row C
(provenance): an **assumed** fact with the script as its `Basis`, beside the
user assumptions `doc/debugger.md` section 15 admits. This ADR names the need;
C designs the input, its persistence and its withdrawal, and nothing here
writes a stated fact before C does.

One rule holds non-negotiable 8 in place: **VM state is a session fact and
never a program fact.** A register the user set is not evidence. It cannot
reach an `Answer`'s `Support`, it cannot make a refusal into a proof, and
`pdd` renders the same C before and after it. What it can do is answer "what
would this do", which is what `doc/debugger.md` section 2 calls **assumed**
scope, and the renderer names the premise.

### 8.3A Bulk queries over a live target

The register example is small on purpose. The shape that matters is a bulk
query: a heap spray was written, and the question is where it landed, which
copies survived, and which write put each one there.

```
$spray = p64(0x4141414141414141) * 0x100
$hits  = search($spray, in: heap, align: 8)
```

gdb's nearest form is `find /g 0x0, 0xffff..., 0x4141414141414141` and
radare2's is `/x 4141414141414141`, and both return a list of addresses. A
`Hit` carries the region, the allocation it falls in, how many times the
pattern repeats, and `lastwrite` for the instruction that wrote it, each from
its existing owner. `doc/debugger.md` section 12A is the design, the cost
model and the ownership table; it needs the live target seam (the debugger's G0) and the
trace index, so it lands with the debugger.

What the expression language owes that design is the value: `$spray` is
`Bytes` of a stated length built by `p64` and `*`, so the pattern handed to
`search` is typed, and a width or endianness mistake is a refusal before a
single page is read.

### 8.4 Expressions

`+ - * / % & ^ | << >> ~` over `Int{w}`, with the width stated and a mixed
width refused. `Bytes` adds concatenation (`a .. b`) and repetition
(`p64(0x41) * 8`), which is `cyclic`-shaped work without a library. Comparison
and `if`/`for` come from 3.5's embedded language, so the expression language
stays an expression language and does not grow a second control flow.

Query calls are expressions: `fn("main").calls()`, `$v.uses()`,
`xrefs(0x401000)`.
Each takes a `Work` and returns an `Answer<T>`, so a script that asks for more
than its budget gets a `Completion` saying so.

### 8.5 radare2 compatibility, bounded

radare2's line grammar is a subset the shell keeps, and
`crates/r2s/src/line.rs` already parses it and names every gap in a refusal
(`PIPE`, `REDIRECT`, `CHAIN`, `MACRO`, `SUBSTITUTION`, `PREFIX`, `COMMENT`).
S2 turns those into implementations, and `scripts/diff_r2.py` gates the subset
only: a form radare2 parses and the shell reads differently is a defect inside
the subset and allowed outside it.

| Form | Status | Cost | Rule |
|---|---|---|---|
| `@addr`, `~` grep | implemented | `O(1)`, `O(output)` | unchanged |
| `$$`, `$s`, and the other 79 | S2 | `O(1)` index read | a `$` value is a projection of a fact the engine owns |
| `@@f`, `@@=`, `@@b` | S2 | `O(k)` statements, each under its own `Work` | the list comes from typed `functions()`; ordered, per non-negotiable 7 |
| `@@c:cmd`, `` ` `` | S2, parity only | the inner command | they read text to make addresses, which non-negotiable 5 blocks. The typed forms supersede them |
| `>` file | S2 | `O(output)` | the shell spells an answer, and where it spells it is the shell's |
| `\|` shell | refused | the shell's | a policy question. Non-negotiable 2 makes `r2s` a command surface. A value pipe inside the language (`fn("main").calls() \| filter(...)`) is the typed answer and is a different operator |
| `(name; body)` macro | refused | the body | 3.5's embedded language supersedes it |

The two behaviours already measured against radare2 stay: a refused statement
runs nothing, and after a statement that failed or quit nothing later on the
line runs (`UNSETTLED`, cmd.c:6861-6922).

### 8.6 Behaviour rules across every surface

The shell language, the C ABI, Python and an embedded language differ in
syntax and agree on four rules:

1. every call that can cost takes a `Work`, and a call with no `Work` is a
   pure index read;
2. every answer carries the byte revision it was checked at and the
   `Completion` that says why it stopped;
3. a handle taken at an older revision is an error on use only where the
   database's red-green check says what it reads changed: a patch to one
   function does not stale a handle on another, because the check compares
   the ranges each answer read;
4. a refusal is a value with a reason, never a null or a `None`, per
   non-negotiable 8.

### 8.7 Performance

| Level | Cost | Where it is stated |
|---|---|---|
| Parsing a line | a constant number of linear passes | `line.rs` header, already measured |
| Evaluating an expression | `O(expr)`, no program read | the evaluator holds no facts |
| Reading one fact | `O(1)` or `O(log n)` index read over dense ids | the structural rules, over `doc/adr-one-ir.md` ids |
| One VM step | one `r2il::eval::step` under its budget | `Stop` is the refusal |
| Preparing one function | `prepared(entry)`, the real cost | release `pdd` on the large 0pack and pumasim functions |

A scripted loop over k functions costs k preparations and nothing else, so the
one performance question that matters is whether a second pass over the same k
costs k again. The query database answers that already: a second pass checks
each answer's recorded reads and recomputes nothing that is still good, at one
check per dependency (`query/db.rs`). What remains open is retention: a sweep
of every function of a large binary holds every prepared function at once, and
the 16 GB machine the engine is measured on swaps before the CPU is the limit.
Any eviction rule belongs in the query database, per
`doc/adr-query-database.md` and decision D11, never in a binding's own cache.

The measurement that decides it: sweep a large binary's functions twice, timed,
with `DbStats` and peak RSS printed.

## 9. Open questions

- Whether a script-stated fact is persisted, and where. A project file is a
  second owner of program facts unless it is strictly a list of admissions.
- Whether `Work` is a per-call argument, a context manager, or both.
- Whether the embedded language gets write access to the program, or whether
  patching stays in the command surface and the SDK.
- What a handle does when the binding outlives the program. A revision check
  catches a stale read; a closed program is a different failure.
- Whether the expression language gets comparison and branching, or whether
  every conditional goes to 3.5's embedded language.
- Whether a VM state can be named and restored, which `ar.` does in radare2
  with a command dump.
- Whether `p64` on a program with no stated endianness refuses or defaults.
