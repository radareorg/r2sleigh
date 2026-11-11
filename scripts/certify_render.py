#!/usr/bin/env python3
"""Certification gate: render every function analysis finds and read the proof.

radare2 is not run. A rendering that reads a value nothing wrote is a claim
about the program the program does not make, and it is wrong on its own terms
with nothing to compare against -- which is why this gate outlived the two-sided
capture comparison it grew out of. The engine is graded against the source a
binary was compiled from, not against another route into the same renderer.

Usage:
  scripts/certify_render.py BINARY                 # every function `aflj` lists
  scripts/certify_render.py BINARY --at 0x1000     # one function
  scripts/certify_render.py --bins DIR --limit 24 --functions 8
"""

import argparse
import itertools
import json
import pathlib
import re
import subprocess
import sys

NOISE = re.compile(r"^\s*(INFO|WARN|ERROR|DEBUG):")
PROOF = re.compile(r"^\s*/\* r2dec proof:.*\*/\s*$")
# A panic the engine caught at an isolation boundary: the function is refused
# and the defect named where it was raised. Isolation keeps the session alive;
# it does not make the panic acceptable, so the gate fails on every one.
PANICKED = re.compile(r"panicked at ")


def run(argv, timeout):
    """The shell's answer, stdout then stderr, or why there is none.

    Stderr is part of the answer: a refusal the shell reports as an error is
    printed there, and so is a panic. A process a signal ended -- an abort for
    memory, say -- answered nothing at all, and says so.
    """
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except OSError as error:
        return "", str(error)
    if done.returncode < 0:
        return "", f"crashed: signal {-done.returncode}"
    return done.stdout + done.stderr, ""


def clean(text):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line):
            continue
        if not line.strip():
            continue
        lines.append(line.rstrip())
    return lines


def functions(r2s, binary, timeout):
    """Every function analysis finds, named or not, as (address, name); and how many have no body.

    `aflj` after `aa` lists what discovery found, so a stripped binary is graded
    as a symbolised one is. A function of no blocks has nothing to render: it is
    discovery's defect (ROADMAP FS), counted, not graded here.
    """
    text, error = run([str(r2s), "-q", "-c", "aa; aflj", str(binary)], timeout)
    if error:
        return [], 0, error
    start = text.find("[")
    try:
        listed = json.loads(text[start:]) if start >= 0 else []
    except json.JSONDecodeError as problem:
        return [], 0, f"aflj is not JSON: {problem}"
    found = [(entry["addr"], entry["name"]) for entry in listed if entry.get("nbbs", 0) > 0]
    return found, len(listed) - len(found), ""


# A separator no rendering prints, between the renderings of one batch; `@` would be read as a seek.
SEPARATOR = "==r2s-certify=="


def native_render(r2s, binary, address, timeout):
    script = f"aa; s {address:#x}; pdd"
    text, error = run([str(r2s), "-q", "-c", script, str(binary)], timeout)
    return text, error


def batch_render(r2s, binary, addresses, timeout):
    """Each function's rendering from one process, `aa` paid once; none where it died.

    An error does not end a script, and stderr is merged in order, so each
    function's refusal stays beside it.
    """
    script = "aa; " + "; ".join(f"?e {SEPARATOR}; pdd @ {address:#x}" for address in addresses)
    try:
        done = subprocess.run(
            [str(r2s), "-q", "-c", script, str(binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout * max(1, len(addresses)),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if done.returncode < 0:
        return None
    parts = done.stdout.split(SEPARATOR + "\n")[1:]
    return parts if len(parts) == len(addresses) else None


def batch_json(r2s, binary, addresses, timeout):
    """Each function's `pddj` from one process, `aa` paid once, by address; none where it died."""
    if not addresses:
        return {}
    script = "aa; " + "; ".join(f"?e {SEPARATOR}; pddj @ {address:#x}" for address in addresses)
    try:
        done = subprocess.run(
            [str(r2s), "-q", "-c", script, str(binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout * max(1, len(addresses)),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}
    parts = done.stdout.split(SEPARATOR + "\n")[1:]
    found = {}
    for address, part in zip(addresses, parts):
        start = part.find("{")
        try:
            found[address] = json.loads(part[start:]) if start >= 0 else None
        except json.JSONDecodeError:
            found[address] = None
    return found


def defined_arity(rendering):
    """How many parameters a rendering's definition takes; None where it defines none or a variadic one."""
    if not rendering or rendering.get("refused") or not rendering.get("signature"):
        return None
    if "..." in rendering["signature"]:
        return None
    return sum(1 for variable in rendering.get("variables", []) if variable["kind"] == "param")


def arity(args, binary, chosen):
    """Each call a rendering spells against its callee's definition, as the same session renders it.

    A caller and its callee are two halves of one link: a call handing on more
    arguments than the definition takes invents them, fewer drops them. Both are
    wrong C whatever the proof line says. A pointer call is counted, not judged:
    nothing names what it reaches.
    """
    tally = {
        "calls graded": 0,
        "invented": 0,
        "dropped": 0,
        "hole arguments": 0,
        "pointer calls": 0,
        "unjudged": 0,
    }
    rendered = batch_json(args.r2s, binary, [address for address, _ in chosen], args.timeout)
    callees = sorted(
        {
            call["addr"]
            for rendering in rendered.values()
            if rendering
            for call in rendering.get("calls", [])
            if call["kind"] == "function"
            and call["addr"] is not None
            and call["addr"] not in rendered
        }
    )
    definitions = dict(rendered)
    definitions.update(batch_json(args.r2s, binary, callees, args.timeout))
    for address, name in chosen:
        rendering = rendered.get(address)
        if not rendering:
            continue
        for call in rendering.get("calls", []):
            if call["kind"] == "pointer":
                tally["pointer calls"] += 1
                continue
            if call["kind"] == "import" or call["variadic"]:
                continue
            target = address if call["kind"] == "self" else call["addr"]
            takes = defined_arity(definitions.get(target))
            if takes is None:
                tally["unjudged"] += 1
                continue
            tally["calls graded"] += 1
            # A slot the callee ignores is passed as its typed residual: counted apart (D165).
            tally["hole arguments"] += call.get("ignored", 0)
            if call["arguments"] == takes:
                continue
            key = "invented" if call["arguments"] > takes else "dropped"
            tally[key] += 1
            print(
                f"  {name}: calls {call['callee']} with {call['arguments']} arguments,"
                f" defined with {takes} ({key})"
            )
    return tally


def refused(lines):
    # An error the shell printed instead of a rendering is a refusal too: a
    # function nothing rendered must not be counted as rendered.
    return any("r2sleigh refused" in line or line.startswith("r2s:") for line in lines)


# A declaration names its variable last: `const int8_t* name;`. The name is an
# identifier, which is what keeps an array bound from being read as one. A
# statement that opens with a keyword has the same shape -- `return x;`,
# `goto L2;` -- and declares nothing: taking `return x;` for a declaration
# listed `x` once more for every return of it. A block-scope `extern` names an
# object defined elsewhere, which the program assigns. `struct Foo;` declares a tag, no object.
DECLARATION = re.compile(
    r"^\s*(?!(?:return|goto|else|case|do|extern)\b)(?!(?:struct|union)\s+\w+\s*;)(?:const\s+)?"
    r"[A-Za-z_][\w*\s]*?\b([A-Za-z_]\w*)\s*;\s*$"
)
# A rendering defines each struct it reads through, `struct node { ... };`,
# and a line inside that definition names a member, not an object: `n->next`
# reads memory through `n`, and nothing the function declares is called
# `next`.
AGGREGATE_OPENS = re.compile(r"^\s*(?:struct|union)\s+\w+\s*\{\s*$")
AGGREGATE_CLOSES = re.compile(r"^\s*\}\s*;\s*$")
PROOF_REFUSED = re.compile(r"(\d+) refused")
# `==`, `!=`, `<=`, `>=` and `!` are comparisons; an assignment is a lone `=`.
ASSIGNMENT = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")


def assigns(line, name):
    """Whether this line writes `name`, however it spells the destination.

    A write reaches its variable through casts, indices and address-of:
    `((uint32_t*)&slot)[3] = 0` assigns `slot` as surely as `slot = 0` does.
    So the test is whether the name stands left of the assignment, not whether
    it is the whole of it. Taking its address counts too: whoever holds the
    pointer may write through it.
    """
    if re.search(r"&\s*{}\b".format(re.escape(name)), line):
        return True
    found = ASSIGNMENT.search(line)
    if not found:
        return False
    return re.search(r"\b{}\b".format(re.escape(name)), line[: found.start()]) is not None


def undefined_reads(lines):
    """Names a rendering declares, never assigns, and then reads.

    A read of a value nothing wrote is not a quality complaint: it is a claim
    about the program that the program does not make. Reported beside what the
    proof line says was refused, because the pair is the interesting part --
    an undefined read under `0 refused` says the accounting is wrong, not just
    the output.
    """
    found = []
    member = False
    for line in lines:
        if member:
            member = not AGGREGATE_CLOSES.match(line)
            continue
        if AGGREGATE_OPENS.match(line):
            member = True
            continue
        declared = DECLARATION.match(line)
        if not declared:
            continue
        name = declared.group(1)
        if name in ("return", "else", "struct", "union") or name in found:
            continue
        if any(assigns(other, name) for other in lines):
            continue
        # Declared, never written. A read anywhere else is a read of nothing.
        uses = sum(
            len(re.findall(r"\b{}\b".format(re.escape(name)), other)) for other in lines
        )
        if uses > 1:
            found.append(name)
    return found


def proof_refusals(lines):
    for line in lines:
        if "r2dec proof:" in line:
            found = PROOF_REFUSED.search(line)
            return int(found.group(1)) if found else None
    return None


def lint(args, binary, found):
    """Report what the rendering claims it proved and did not."""
    tally = {"rendered": 0, "refused": 0, "undefined reads": 0, "panicked": 0, "crashed": 0}
    chosen = found if args.functions is None else found[: args.functions]
    batch = batch_render(args.r2s, binary, [address for address, _ in chosen], args.timeout)
    for index, (address, name) in enumerate(chosen):
        # A batch that died is run again one function at a time, so the one that died is named.
        if batch is not None:
            native, error = batch[index], ""
        else:
            native, error = native_render(args.r2s, binary, address, args.timeout)
        if error:
            if error.startswith("crashed"):
                tally["crashed"] += 1
            print(f"  {name}: {error}")
            continue
        lines = clean(native)
        panics = [line for line in lines if PANICKED.search(line)]
        if panics:
            tally["panicked"] += 1
            print(f"  {name}: {panics[0].strip()}")
        if refused(lines):
            tally["refused"] += 1
            continue
        tally["rendered"] += 1
        report = uncertified_reads(lines)
        if report:
            tally["undefined reads"] += 1
            print(f"  {name}: {report}")
    return tally


def uncertified_reads(lines):
    """What a rendering reads that nothing assigns.

    Nothing is excused. A value the function entered holding, an argument slot
    no parameter admits, and a result nothing claimed all have no spelling in
    C, and the renderer writes each read of one as a residual that traps rather
    than declaring an object it never assigns. So a name declared, never
    assigned and read is a read of something the program never produced,
    whatever the proof line says.
    """
    undefined = undefined_reads(lines)
    if not undefined:
        return ""
    return "reads {} which nothing assigns, proof says {} refused".format(
        ", ".join(undefined), proof_refusals(lines)
    )



def opens(r2s, path):
    """Whether r2s opens the file: a corpus directory also holds sources and notes, and r2image
    alone says which containers it reads."""
    done = subprocess.run([str(r2s), "-q", "-c", "?e", str(path)], capture_output=True, check=False)
    return done.returncode == 0


def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--bins")
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument("--at", type=lambda value: int(value, 0))
    parser.add_argument("--limit", type=int, default=5, help="binaries")
    parser.add_argument("--functions", type=int, default=None, help="per binary (default all)")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="measure whatever binary is already there",
    )
    args = parser.parse_args()

    # Build before measuring. The default binary is the debug one, which a
    # plain `cargo build --release` does not touch, so a measurement taken
    # after one reported the tree as it was several changes ago -- including a
    # whole class of undefined reads that a fix had already closed.
    if not args.no_build and args.r2s == str(here / "target/debug/r2s"):
        subprocess.run(
            ["cargo", "build", "-p", "r2s", "--features", "sleigh"],
            cwd=here,
            check=True,
        )

    if args.binary:
        binaries = [pathlib.Path(args.binary)]
    elif args.bins:
        files = sorted(p for p in pathlib.Path(args.bins).iterdir() if p.is_file())
        binaries = list(itertools.islice((p for p in files if opens(args.r2s, p)), args.limit))
    else:
        parser.error("pass a binary or --bins")

    totals = {}
    for binary in binaries:
        print(binary.name)
        found, empty, error = functions(args.r2s, binary, args.timeout)
        if error:
            # A binary analysis could not list was not graded: that fails the gate.
            totals["unlisted"] = totals.get("unlisted", 0) + 1
            print(f"  {error}")
            continue
        totals["no body"] = totals.get("no body", 0) + empty
        if args.at is not None:
            found = [(address, name) for address, name in found if address == args.at]
            if not found:
                found = [(args.at, f"fcn.{args.at:x}")]
        for key, value in lint(args, binary, found).items():
            totals[key] = totals.get(key, 0) + value
        chosen = found if args.functions is None else found[: args.functions]
        for key, value in arity(args, binary, chosen).items():
            totals[key] = totals.get(key, 0) + value

    print()
    for key in ("rendered", "refused", "no body", "unlisted", "undefined reads", "panicked", "crashed"):
        print(f"{key:16} {totals.get(key, 0)}")
    # The arity check reports; it gates once its counts are blessed (ROADMAP GT).
    print("arity:")
    for key in ("calls graded", "invented", "dropped", "hole arguments", "pointer calls", "unjudged"):
        print(f"  {key:14} {totals.get(key, 0)}")
    # An uncertified rendering is a defect on its own terms, and so is a
    # panic the engine isolated or a process that never answered.
    failed = ("unlisted", "undefined reads", "panicked", "crashed")
    if not totals.get("rendered"):
        print("nothing rendered: the gate graded nothing")
        return 1
    return 1 if any(totals.get(key, 0) for key in failed) else 0


if __name__ == "__main__":
    sys.exit(main())
