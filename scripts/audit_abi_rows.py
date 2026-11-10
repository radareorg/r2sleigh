#!/usr/bin/env python3
"""Audit r2abi's `void` rows: each is cited, and no cited value return is spelled `void`.

A row that says `void` where the function returns a value lets a body that tails to it
read as returning nothing: `signal` returns the previous handler, and its old row made
diff's `sigsegv_deinstall_handler` void (ROADMAP D204, doc/adr-scratch-result.md S0).

    audit_abi_rows.py          every `void` row against crates/r2abi/data/void-rows.txt
    audit_abi_rows.py --cc gcc also against the return glibc's headers declare (gcc -aux-info)

Exit 1 on a `void` row with no citation, a citation whose return is not `void` on a row
spelled `void`, or a citation naming no row; the header check runs only where gcc reads
glibc's headers and says so when it does not.
"""

from __future__ import annotations

import argparse
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
GLIBC_TABLES = ("types.sdb.txt", "types-linux.sdb.txt")
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
    for line in errors:
        print(f"ERROR: {line}")
    print(f"{len(report)} void rows cited, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
