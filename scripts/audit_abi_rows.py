#!/usr/bin/env python3
"""Audit r2abi's `void` rows: each is cited, and no cited value return is spelled `void`.

A row that says `void` where the function returns a value lets a body that tails to it
read as returning nothing: `signal` returns the previous handler, and its old row made
diff's `sigsegv_deinstall_handler` void (ROADMAP D204, doc/adr-scratch-result.md S0).

    audit_abi_rows.py          every `void` row against crates/r2abi/data/void-rows.txt
    audit_abi_rows.py --cc gcc also against the return glibc's headers declare (gcc -aux-info),
                               and each cited row's prototype against its header's declaration
                               (a row citing GCC's builtins.def names no header that declares it)

Exit 1 on a `void` row with no citation, a citation whose return is not `void` on a row
spelled `void`, or a citation naming no row; the header check runs only where gcc reads
glibc's headers and says so when it does not.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "crates/r2abi/data"
CITATIONS = DATA / "void-rows.txt"
# The tables glibc's headers speak for.
GLIBC_TABLES = ("types.sdb.txt", "types-linux.sdb.txt", "types-posix.sdb.txt", "types-glibc.sdb.txt")
# The cited tables whose every prototype glibc's header must declare (ROADMAP D242).
CITED_TABLES = ("types-posix.sdb.txt", "types-glibc.sdb.txt")
HEADERS = """
stdio.h stdlib.h string.h strings.h unistd.h fcntl.h errno.h error.h err.h syslog.h signal.h
pthread.h semaphore.h mqueue.h time.h dirent.h wchar.h wctype.h locale.h math.h ctype.h netdb.h
poll.h dlfcn.h glob.h fnmatch.h regex.h getopt.h libgen.h sched.h setjmp.h termios.h utime.h
ftw.h fts.h grp.h pwd.h spawn.h sys/types.h sys/stat.h sys/mman.h sys/ioctl.h sys/wait.h
sys/socket.h sys/time.h sys/resource.h sys/select.h sys/sem.h sys/shm.h sys/msg.h sys/syscall.h
sys/prctl.h sys/ptrace.h sys/uio.h sys/file.h sys/statvfs.h sys/utsname.h sys/epoll.h sys/xattr.h
netinet/in.h arpa/inet.h iconv.h langinfo.h libintl.h argp.h obstack.h malloc.h mntent.h paths.h
search.h stdarg.h stdint.h inttypes.h fenv.h complex.h assert.h execinfo.h
""".split()

RET = re.compile(r"^func\.(.+)\.ret=(.*)$")


def returns_of(text: str) -> dict[str, str]:
    """`name -> return spelling` for every row of one table."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if found := RET.match(line.strip()):
            out[found.group(1)] = found.group(2).strip()
    return out


def tables(directory: Path) -> dict[str, dict[str, str]]:
    return {path.name: returns_of(path.read_text()) for path in sorted(directory.glob("*.sdb.txt"))}


def citations_of(text: str) -> dict[str, tuple[str, str]]:
    """`name -> (return the source states, source)`; a name cited twice is an error."""
    out: dict[str, tuple[str, str]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|")]
        if len(fields) != 3 or not all(fields):
            raise ValueError(f"void-rows.txt:{number}: not `name | return | source`: {line}")
        name, returns, source = fields
        if name in out:
            raise ValueError(f"void-rows.txt:{number}: {name} is cited twice")
        out[name] = (returns, source)
    return out


def audit(
    rows: dict[str, dict[str, str]], cited: dict[str, tuple[str, str]]
) -> tuple[list[str], list[str]]:
    """One report line per `void` row, and every error."""
    report, errors = [], []
    named = set()
    for table, returns in rows.items():
        for name, spelled in sorted(returns.items()):
            named.add(name)
            citation = cited.get(name)
            if spelled != "void":
                if citation and citation[0] == "void":
                    errors.append(f"{table} {name}: spelled `{spelled}`, cited `void` by {citation[1]}")
                continue
            if citation is None:
                errors.append(f"{table} {name}: `void` with no citation in void-rows.txt")
            elif citation[0] != "void":
                errors.append(f"{table} {name}: `void`, but {citation[1]} states `{citation[0]}`")
            else:
                report.append(f"{table} {name}: void, {citation[1]}")
    for name in sorted(cited.keys() - named):
        errors.append(f"void-rows.txt {name}: cited, but no table has the row")
    return report, errors


TYPE_WORDS = {
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "struct", "union", "enum", "const", "volatile", "restrict", "__restrict", "extern",
    "_Complex", "__int128", "__builtin_va_list",
}
NAME_OPEN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def declared_return(line: str) -> tuple[str, bool] | None:
    """`extern void (*signal (int, ...))(int);` -> ("signal", False): the name and whether it returns void."""
    line = re.sub(r"^/\*.*?\*/\s*", "", line.strip())
    if not line.startswith("extern ") or not line.endswith(";"):
        return None
    body = line[len("extern "):-1]
    for found in NAME_OPEN.finditer(body):
        name = found.group(1)
        if name in TYPE_WORDS or name.startswith("__attribute"):
            continue
        prefix = body[: found.start()].split()
        words = [word for word in prefix if word not in {"extern", "static", "inline", "__inline"}]
        return name, words == ["void"]
    return None


def header_returns(cc: str) -> dict[str, bool] | None:
    """`name -> returns void` for what glibc's headers declare, or None where gcc cannot say."""
    if shutil.which(cc) is None:
        return None
    with tempfile.TemporaryDirectory() as work:
        source = Path(work) / "headers.c"
        source.write_text("".join(f"#include <{header}>\n" for header in HEADERS))
        info = Path(work) / "aux.txt"
        subprocess.run(
            [cc, "-D_GNU_SOURCE", "-D_LARGEFILE64_SOURCE", "-fsyntax-only", "-aux-info", str(info), str(source)],
            capture_output=True, text=True, check=False,
        )
        if not info.exists():
            return None
        out: dict[str, bool] = {}
        for line in info.read_text(errors="replace").splitlines():
            if parsed := declared_return(line):
                out.setdefault(*parsed)
        return out


def against_headers(rows: dict[str, dict[str, str]], declared: dict[str, bool]) -> list[str]:
    """A glibc row spelled `void` where the header declares a value, or the reverse."""
    errors = []
    for table in GLIBC_TABLES:
        for name, spelled in sorted(rows.get(table, {}).items()):
            if name in declared and (spelled == "void") != declared[name]:
                header = "void" if declared[name] else "a value"
                errors.append(f"{table} {name}: spelled `{spelled}`, glibc's header returns {header}")
    return errors


@dataclasses.dataclass
class CitedRow:
    name: str
    comment: str
    returns: str = ""
    header: str = ""
    arguments: dict[int, str] = dataclasses.field(default_factory=dict)

    def prototype(self) -> str:
        """`int (const char *, ...)`: the function type the row spells."""
        types = [self.arguments[index].rpartition(",")[0].strip() for index in sorted(self.arguments)]
        spelled = ", ".join(kind or "..." for kind in types) or "void"
        return f"{self.returns} ({spelled})"

    def modes(self) -> list[str]:
        """The modes the row's comment names, strictest first: a row is declared under one of them.
        glibc declares its fortified entry points only where fortification is on."""
        modes = [
            flags
            for source, flags in (
                ("ISO C17", "-std=c17"),
                ("POSIX.1-2017", "-std=c17 -D_POSIX_C_SOURCE=200809L"),
                ("XSI", "-std=c17 -D_XOPEN_SOURCE=700"),
            )
            if source in self.comment
        ]
        others = any(source in self.comment for source in ("glibc", "4.4BSD", "POSIX.1-2024", "LSB"))
        if others or not modes:
            modes.append("-std=gnu17 -D_GNU_SOURCE -O2 -D_FORTIFY_SOURCE=2")
        return modes


def cited_rows(text: str) -> list[CitedRow]:
    """Every row of one cited table that names a header, with the comment block above it."""
    rows: dict[str, CitedRow] = {}
    comment, after = "", False
    for line in map(str.strip, text.splitlines()):
        if line.startswith("#"):
            comment = (comment if after else "") + line[1:] + " "
            after = True
            continue
        after = False
        if line.endswith("=func"):
            rows[line[: -len("=func")]] = CitedRow(line[: -len("=func")], comment)
        elif found := re.match(r"^func\.(.+?)\.(arg\.(\d+)|ret|include)=(.*)$", line):
            row = rows.get(found.group(1))
            if row is None:
                continue
            if found.group(3) is not None:
                row.arguments[int(found.group(3))] = found.group(4)
            elif found.group(2) == "ret":
                row.returns = found.group(4).strip()
            else:
                row.header = found.group(4).strip()
    # GCC's builtins.def is no header: a row citing it is not compiled.
    return [row for row in rows.values() if row.header and "GCC" not in row.comment]


def assertion(row: CitedRow) -> str:
    """One translation unit that compiles only where the header declares the row's prototype."""
    return (
        f"#include <stddef.h>\n#include <stdarg.h>\n#include <{row.header}>\n"
        f"_Static_assert(__builtin_types_compatible_p(__typeof__({row.name}), {row.prototype()}), \"row\");\n"
    )


def spellings(prototype: str) -> list[str]:
    """The function types one row may stand for: a row leaves out a pointer's own `const`
    (`char *const argv[]` is `char **`) and the `noreturn` a header attaches to the type."""
    pieces = prototype.split("**")
    forms = [pieces[0]]
    for piece in pieces[1:]:
        forms = [form + star + piece for form in forms for star in ("**", "*const *")]
    return forms + [f"__attribute__((noreturn)) {form}" for form in forms]


def declared_as_spelled(cc: str, row: CitedRow) -> str | None:
    """None where the header declares one of the row's spellings, else the compiler's first line."""
    first = None
    for flags in row.modes():
        for spelled in spellings(row.prototype()):
            text = assertion(row).replace("), " + row.prototype(), "), " + spelled)
            result = subprocess.run(
                [cc, *flags.split(), "-fsyntax-only", "-w", "-x", "c", "-"],
                input=text, capture_output=True, text=True, check=False,
            )
            if result.returncode == 0:
                return None
            first = first or (result.stderr.strip().splitlines() or ["no diagnostic"])[0]
    return first


def against_declarations(cc: str, directory: Path, tables: tuple[str, ...] = CITED_TABLES) -> tuple[int, list[str]] | None:
    """How many cited rows glibc's headers declare as spelled, and each that they do not; None without glibc."""
    probe = subprocess.run(
        [cc, "-fsyntax-only", "-x", "c", "-"], input="#include <gnu/libc-version.h>\n",
        capture_output=True, text=True, check=False,
    )
    if probe.returncode != 0:
        return None
    checked, errors = 0, []
    for table in tables:
        for row in cited_rows((directory / table).read_text()):
            checked += 1
            if why := declared_as_spelled(cc, row):
                errors.append(f"{table} {row.name}: <{row.header}> declares no `{row.prototype()}` under {row.modes()}: {why}")
    return checked, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--cc", help="also check the glibc rows against this compiler's headers")
    args = parser.parse_args()
    rows = tables(DATA)
    report, errors = audit(rows, citations_of(CITATIONS.read_text()))
    for line in report:
        print(line)
    if args.cc:
        declared = header_returns(args.cc)
        if declared is None:
            print(f"headers: {args.cc} cannot read glibc's headers here; not checked")
        else:
            errors += against_headers(rows, declared)
            checked = sum(name in declared for table in GLIBC_TABLES for name in rows[table])
            print(f"headers: {checked} glibc rows checked against what {args.cc} reads")
        declarations = against_declarations(args.cc, DATA)
        if declarations is None:
            print(f"prototypes: {args.cc} cannot read glibc's headers here; not checked")
        else:
            errors += declarations[1]
            print(f"prototypes: {declarations[0]} cited rows checked against their headers")
    for line in errors:
        print(f"ERROR: {line}")
    print(f"{len(report)} void rows cited, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
