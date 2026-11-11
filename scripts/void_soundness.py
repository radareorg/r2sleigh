#!/usr/bin/env python3
"""Fail if r2s renders `void` a function whose result a caller reads.

`void` for a function the source declares with a value is a claim of absence: no caller reads
anything the function leaves, in any register, by any instruction. A caller the engine reads
wrongly makes it false, and a false `void` is the worst error a decompiler makes: the value is
gone from every caller. The programs in tests/gold/void_soundness/ (scripts/gen_void_adversaries.py)
return every value type by every route and read it every way, and manifest.json names which
functions some caller reads. This compiles them with each compiler found at each optimisation
level, with debug information (r2s must read its declarations: a build it does not is not scored)
and stripped (what the engine works from), and compares the return type r2s renders at the same
address with the one the source states.

A caller's extern is graded too: `void f(...)` in the function that calls `f` is the same claim of
absence, made where the read happens, so an extern `void` for a function some caller reads is a false
void wherever the header is not. A call the engine refuses declares nothing and is counted, not failed.

A function no caller reads may be `void` (the closed world's premise, doc/adr-resolved-bodies.md)
and is counted, not failed. A global function of a relocatable object is read by other objects.

What the gate claims is what it can fail: a function a caller reads is void only where
tests/gold/void_soundness/known.json names its build (`program.compiler.opt[.isa]/function`) and a cause,
each void at the base: an x87 result recovery holds no lane for (ROADMAP D200).
Every producer is salted so no compiler folds one into another, every compiler
named must be found (or --allow-missing-compilers), every function of the manifest must have a verdict in
every build scored, and at most a tenth of the judged rows may be functions r2s did not render.

Exit status: 0 sound, 1 a read value rendered `void`, 2 the truth could not be read, 77 no ELF toolchain.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "tests/gold/void_soundness"
sys.path.insert(0, str(ROOT / "tests/equiv"))

RETURN = re.compile(r"^\s*(?:static\s+)?(.*?)\s*\b[A-Za-z_][\w:~<>.]*\s*\(")
# A declaration inside a function body: `    void fcn_1379(uint64_t);`.
EXTERN = re.compile(r"^\s+(?!return\b)(?P<ret>[A-Za-z_][^/=;(){}]*?[\s*]+)(?P<name>[A-Za-z_][\w.]*)\((?P<params>[^()]*)\);\s*$")
# A call the engine refused: `/* r2dec gap: CallNotRendered at ... call to fcn_1218: ...`.
GAP = re.compile(r"r2dec gap: \w+ at [^:]*?.*?call to (?P<name>[A-Za-z_][\w.]*):")


def return_type(signature: str | None) -> str | None:
    """`struct pl p_pl_compute(int64_t arg0)` -> `struct pl`."""
    if not signature:
        return None
    found = RETURN.match(signature)
    return found.group(1).strip() if found else None


@dataclass(frozen=True)
class Build:
    program: str
    compiler: str
    opt: str
    # "" for the baseline x86-64, "avx2" for -mavx2 -mfma (a VEX body writes the whole of ZMM0)
    isa: str = ""

    def __str__(self) -> str:
        return f"{self.program}.{self.compiler}.{self.opt}" + (f".{self.isa}" if self.isa else "")

    def flags(self) -> list[str]:
        return ["-mavx2", "-mfma"] if self.isa == "avx2" else []

    @property
    def key(self) -> str:
        """How known.json names a function of this build: the build, then the function's name."""
        return str(self)


@dataclass(frozen=True)
class Verdict:
    build: Build
    function: str
    truth: str | None
    rendered: str | None
    read: bool

    @property
    def false_void(self) -> bool:
        return self.read and self.truth not in (None, "void") and self.rendered == "void"

    @property
    def premised_void(self) -> bool:
        return (not self.read) and self.truth not in (None, "void") and self.rendered == "void"


@dataclass(frozen=True)
class Extern:
    """What one caller declares of a callee some caller reads: its return type, or none where the call was refused."""
    build: Build
    caller: str
    callee: str
    rendered: str | None

    @property
    def false_void(self) -> bool:
        return self.rendered == "void"


def callee_name(spelled: str, named: dict[int, str]) -> str:
    """The function a stripped build's `fcn_1379` names, by its address in the debug build."""
    if spelled.startswith("fcn_"):
        try:
            return named.get(int(spelled[4:], 16), spelled)
        except ValueError:
            return spelled
    return spelled


def externs_of(build: Build, caller: str, code: str, named: dict[int, str],
               read: set[str]) -> list[Extern]:
    """Each extern and refused call in `code` (one function's C) that names a function of `read`."""
    rows = []
    for line in code.splitlines()[1:]:
        declared = EXTERN.match(line)
        if declared:
            name = callee_name(declared.group("name"), named)
            if name in read and name != caller:
                rows.append(Extern(build, caller, name, re.sub(r"\s+\*", "*", declared.group("ret").strip())))
        for gap in GAP.finditer(line):
            name = callee_name(gap.group("name"), named)
            if name in read and name != caller:
                rows.append(Extern(build, caller, name, None))
    return rows


def judge(build: Build, manifest: dict[str, dict], truth: dict[str, str | None],
          rendered: dict[str, str | None]) -> list[Verdict]:
    """One verdict per function the manifest names that both builds list."""
    return [
        Verdict(build, name, truth[name], rendered.get(name), bool(facts["read"]))
        for name, facts in sorted(manifest.items())
        if name in truth
    ]


def compile_program(compiler: str, opt: str, source: Path, out: Path, relocatable: bool,
                    prebuilt: Path | None = None, flags: list[str] = []) -> tuple[Path, Path] | None:
    """The debug build and its stripped copy, or none if it does not build."""
    if prebuilt is not None:
        pair = (prebuilt / f"{out.name}.dbg", prebuilt / f"{out.name}.str")
        return pair if all(path.exists() for path in pair) else None
    # The build's name holds dots (`d.gcc.O2`), so a suffix is added to it, never put in place of its last part.
    debug = out.parent / f"{out.name}.dbg"
    mode = ["-c"] if relocatable else ["-lm"]
    run = subprocess.run([compiler, "-g", f"-{opt}", *flags, "-o", str(debug), str(source), *mode],
                         capture_output=True, text=True, check=False)
    if run.returncode != 0:
        sys.stderr.write(f"{compiler} {opt} {source.name}: {run.stderr[-600:]}\n")
        return None
    stripped = out.parent / f"{out.name}.str"
    strip = ["strip", "--strip-debug"] if relocatable else ["strip"]
    subprocess.run([*strip, "-o", str(stripped), str(debug)], check=True, capture_output=True)
    return debug, stripped


def functions_of(r2s: str, binary: Path) -> dict[int, str]:
    """Address -> name for every function r2s lists in `binary`."""
    run = subprocess.run([r2s, "-q", "-c", "aa; afl", str(binary)], capture_output=True, text=True,
                         timeout=900, check=False)
    found = {}
    for line in run.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].startswith("0x"):
            found[int(fields[0], 16)] = fields[-1].removeprefix("sym.")
    return found


def render_records(r2s: str, binary: Path, addresses: list[int]) -> dict[int, dict]:
    import r2s_batch  # tests/equiv

    report = r2s_batch.run_batch(r2s, str(binary), addresses, function_timeout=120, startup_timeout=900)
    return {answer.address: answer.record or {} for answer in report.answers}


def render(r2s: str, binary: Path, addresses: list[int]) -> dict[int, str | None]:
    return {address: return_type(record.get("signature"))
            for address, record in render_records(r2s, binary, addresses).items()}


def check_build(r2s: str, build: Build, manifest: dict[str, dict], debug: Path, stripped: Path,
                relocatable: bool = False) -> tuple[list[Verdict], list[Extern]] | str:
    """Verdicts for one build, or why it cannot be scored.

    The truth is the declaration the source states, which the manifest holds: the generator wrote
    both. The debug build is read as well, and a build whose DWARF r2s does not read (most of the
    value functions declare no value there) is not scored, since agreeing with itself proves nothing.
    A relocatable object's DWARF is not read at all (its sections are relocated at link time).
    """
    named = functions_of(r2s, debug)
    wanted = {address: name for address, name in named.items() if name in manifest}
    if not wanted:
        return f"{build}: r2s lists none of the program's functions"
    if not relocatable:
        declared = render(r2s, debug, sorted(wanted))
        values = [(address, name) for address, name in wanted.items() if manifest[name]["returns"] != "void"]
        unread = [name for address, name in values if declared.get(address) == "void"]
        if len(unread) * 2 > len(values):
            return f"{build}: the debug build's declarations did not load ({', '.join(sorted(unread)[:3])} are void there)"
    truth = {name: manifest[name]["returns"] for name in wanted.values()}
    # Every function is rendered, so every caller's externs are read.
    records = render_records(r2s, stripped, sorted(named))
    rendered = {name: return_type(records.get(address, {}).get("signature")) for address, name in wanted.items()}
    read = {name for name, facts in manifest.items() if facts["read"] and facts["returns"] != "void"}
    externs = [row for address, record in sorted(records.items())
               for row in externs_of(build, named.get(address, hex(address)), record.get("code") or "", named, read)]
    return judge(build, manifest, truth, rendered), externs


def scored_builds(jobs: list[Build], problems: list[str]) -> list[Build]:
    """The builds no problem names (`d.gcc.O2:` is not `d.gcc.O2.avx2:`)."""
    return [job for job in jobs if all(not problem.startswith(f"{job}:") for problem in problems)]


def known_false_voids(path: Path) -> set[str]:
    """The `build/function` pairs already rendered void that a caller reads, each with a cause in known.json."""
    if not path.exists():
        return set()
    return set(json.loads(path.read_text())["functions"])


def floors(verdicts: list[Verdict], manifest: dict[str, dict], builds: list[Build]) -> list[str]:
    """The scored builds in which some function the manifest names has no verdict: a function the
    compiler folded into another, or r2s did not list, is a row the gate cannot judge, so it fails."""
    judged: dict[str, set[str]] = {}
    for verdict in verdicts:
        judged.setdefault(str(verdict.build), set()).add(verdict.function)
    short = []
    for build in builds:
        names = {name for name in manifest[f"{build.program}.c"] if not name.startswith("__")}
        missing = sorted(names - judged.get(str(build), set()))
        if missing:
            short.append(f"{build}: no verdict for {len(missing)} of {len(names)} functions ({', '.join(missing[:3])})")
    return short


def extern_floors(externs: list[Extern], manifest: dict[str, dict], builds: list[Build]) -> list[str]:
    """Too few extern rows: more than a tenth of the (build, read function) pairs with no extern and no
    refused call. A caller r2s refuses whole declares nothing; a parse a renderer change blinds fails."""
    seen = {(str(row.build), row.callee) for row in externs}
    pairs = missing = 0
    examples = []
    for build in builds:
        facts = manifest[f"{build.program}.c"]
        if facts.get("__object__"):
            continue  # a global function's caller is another object
        for name, fact in sorted(facts.items()):
            if name.startswith("__") or not fact["read"] or fact["returns"] == "void":
                continue
            pairs += 1
            if (str(build), name) not in seen:
                missing += 1
                examples.append(f"{build}/{name}")
    if missing * 10 > pairs:
        return [f"externs: {missing} of {pairs} read functions have no extern and no refused call ({', '.join(examples[:3])})"]
    return []


def toolchain_exit(named: list[str], found: list[str], toolchain: bool, allow_missing: bool) -> int | None:
    """77 where the host builds no ELF, 2 where a compiler named is not found (unless allowed), else none."""
    if not found or not toolchain:
        print("skipped: this host has no ELF toolchain", file=sys.stderr)
        return 77
    if len(found) < len(named) and not allow_missing:
        print(f"CANNOT SCORE: {', '.join(sorted(set(named) - set(found)))} not found; "
              f"pass --compilers or --allow-missing-compilers to run fewer", file=sys.stderr)
        return 2
    return None


def outcome(verdicts: list[Verdict], problems: list[str], short: list[str], known: set[str],
            min_premised: int, externs: list[Extern] = ()) -> tuple[dict, int]:
    """The report and the exit status: 1 for a new or stale false void, a build with a function unjudged,
    or more than a tenth of the judged rows unrendered; 2 for a build not scored; 1 for too few premised."""
    bad = [verdict for verdict in verdicts if verdict.false_void]
    premised = [verdict for verdict in verdicts if verdict.premised_void]
    read = [verdict for verdict in verdicts if verdict.read]
    keyed = lambda verdict: f"{verdict.build.key}/{verdict.function}"
    new = [verdict for verdict in bad if keyed(verdict) not in known]
    # An entry is stale where its build was judged and renders it otherwise; a build not run says nothing.
    run = {str(verdict.build) for verdict in verdicts}
    stale = sorted(key for key in known - {keyed(verdict) for verdict in bad} if key.split("/")[0] in run)
    unrendered = [v for v in verdicts if v.truth not in (None, "void") and v.rendered is None]
    judged = [v for v in verdicts if v.truth not in (None, "void")]
    too_many = len(unrendered) * 10 > len(judged)
    for verdict in new:
        print(f"FALSE VOID {verdict.build} {verdict.function}: the source returns {verdict.truth}, "
              f"a caller reads it, r2s renders void")
    for name in stale:
        print(f"STALE {name}: known.json lists it but its build renders it otherwise; delete the entry")
    voided = [row for row in externs if row.false_void]
    refused = [row for row in externs if row.rendered is None]
    for row in voided:
        print(f"FALSE VOID EXTERN {row.build} {row.caller} declares void {row.callee}, which a caller reads")
    for line in short:
        print(f"TOO FEW ROWS {line}")
    if too_many:
        print(f"UNRENDERED {len(unrendered)} of {len(judged)} judged rows were not rendered at all")
    for problem in problems:
        print(f"CANNOT SCORE {problem}", file=sys.stderr)
    summary = (f"{len(read)} read results, {len(bad)} rendered void, {len(bad) - len(new)} of them known; "
               f"{len(premised)} unread results rendered void under the closed world; "
               f"{len(unrendered)} of {len(judged)} judged rows not rendered (a refusal, not void); "
               f"{len(problems)} builds not scored; "
               f"{len(externs)} externs of read results, {len(voided)} void, {len(refused)} calls refused")
    report = {
        "summary": summary, "read": len(read), "false_void": [f"{v.build} {v.function}" for v in bad],
        "new": [f"{v.build} {v.function}" for v in new], "stale": stale,
        "premised_void": len(premised), "unrendered": len(unrendered), "judged": len(judged),
        "too_few_rows": short, "not_scored": problems,
        "externs": len(externs), "extern_void": [f"{r.build} {r.caller} {r.callee}" for r in voided],
        "extern_refused": len(refused)}
    if new or stale or short or too_many or voided:
        return report, 1
    if problems:
        return report, 2
    if len(premised) < min_premised:
        print(f"the closed world found {len(premised)} premised voids, fewer than the {min_premised} "
              f"the suite is built to find", file=sys.stderr)
        return report, 1
    return report, 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--r2s", default=str(ROOT / "target/release/r2s"))
    parser.add_argument("--sources", type=Path, default=SOURCES)
    parser.add_argument("--compilers", default="gcc,clang")
    parser.add_argument("--opts", default="O1,O2,O3")
    parser.add_argument("--avx2-opts", default="O2",
                        help="the levels also built with -mavx2 -mfma (none: an empty list)")
    parser.add_argument("--allow-missing-compilers", action="store_true",
                        help="run the compilers found; by default one named and not found is an error")
    parser.add_argument("--only", default="", help="comma-separated program names to run")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--prebuilt", type=Path,
                        help="a directory of <program>.<compiler>.<opt>.dbg and .str builds, for a host that cannot build ELF")
    parser.add_argument("--min-premised", type=int, default=1,
                        help="the premised voids the suite must still find, so that a closed world switched off fails")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    named = [name for name in args.compilers.split(",") if name]
    compilers = named if args.prebuilt is not None else [name for name in named if shutil.which(name)]
    toolchain = args.prebuilt is not None or (shutil.which("strip") is not None and sys.platform != "darwin")
    refused = toolchain_exit(named, compilers, toolchain, args.allow_missing_compilers)
    if refused is not None:
        return refused
    manifest = json.loads((args.sources / "manifest.json").read_text())
    only = set(filter(None, args.only.split(",")))
    programs = [name for name in sorted(manifest) if not only or Path(name).stem in only]

    verdicts: list[Verdict] = []
    externs: list[Extern] = []
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as work:
        jobs = []
        for program in programs:
            stem = Path(program).stem
            for compiler in compilers:
                for opt in filter(None, args.opts.split(",")):
                    jobs.append(Build(stem, compiler, opt))
                if not manifest[program].get("__object__"):
                    for opt in filter(None, args.avx2_opts.split(",")):
                        jobs.append(Build(stem, compiler, opt, "avx2"))

        def run(build: Build) -> tuple[list[Verdict], list[Extern]] | str:
            relocatable = bool(manifest[f"{build.program}.c"].get("__object__"))
            built = compile_program(build.compiler, build.opt, args.sources / f"{build.program}.c",
                                    Path(work) / str(build), relocatable, args.prebuilt, build.flags())
            if built is None:
                return f"{build}: does not compile"
            facts = {name: fact for name, fact in manifest[f"{build.program}.c"].items() if not name.startswith("__")}
            return check_build(args.r2s, build, facts, *built, relocatable=relocatable)

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(run, jobs):
                if isinstance(result, str):
                    problems.append(result)
                else:
                    verdicts.extend(result[0])
                    externs.extend(result[1])

    known = known_false_voids(args.sources / "known.json")
    scored = scored_builds(jobs, problems)
    short = floors(verdicts, manifest, scored) + extern_floors(externs, manifest, scored)
    report, code = outcome(verdicts, problems, short, known, args.min_premised if not only else 0, externs)
    print(report["summary"])
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    return code

if __name__ == "__main__":
    sys.exit(main())
