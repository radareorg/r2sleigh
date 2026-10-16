#!/usr/bin/env python3
"""Fails once an upstream pin is behind past its budget (ROADMAP D39; doc/adr-verified-layers.md).

Reads the Ghidra pins of vendor/README.md, TESTBINS_REF of ci.yml and the judged radare2 release.
Exit 0 within budget, 1 over budget or contradicted by the vendored files, 2 a pin not measurable.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable

REPO = pathlib.Path(__file__).resolve().parent.parent

# Days the oldest upstream change a pin lacks may wait, by pin family; `vendor/README.md` states
# the same numbers and the tests hold them equal.
BUDGET_DAYS = {"ghidra": 90, "testbins": 180, "judged-release": 90}

GHIDRA_URL = "https://github.com/NationalSecurityAgency/ghidra"
RADARE2_RELEASES_URL = "https://api.github.com/repos/radareorg/radare2/releases?per_page=100"
BASE = "Ghidra base"
# Where the vendored copies of Ghidra live, and which upstream paths each covers.
SLEIGH_CONFIG = pathlib.Path("vendor/sleigh-config/ghidra")
LIBSLA_SYS = pathlib.Path("vendor/libsla-sys/ghidra")
BASE_PATHS = (
    "Ghidra/Features/Decompiler/src/decompile/cpp",
    "Ghidra/Features/Decompiler/src/decompile/zlib",
)


class Unmeasurable(Exception):
    """A pin that cannot be measured: the report never reads it as within budget."""


@dataclasses.dataclass(frozen=True)
class Pin:
    """A commit this tree took, and the upstream paths it covers (none: the whole repository)."""

    name: str
    family: str
    url: str
    pinned: str
    paths: tuple[str, ...] = ()
    vendored: pathlib.Path | None = None


@dataclasses.dataclass(frozen=True)
class Drift:
    name: str
    pinned: str
    latest: str
    behind: int
    oldest: datetime.datetime | None
    age_days: int
    budget_days: int
    evidence: str = ""
    refuted: tuple[str, ...] = ()

    @property
    def verdict(self) -> str:
        if self.refuted:
            return f"REFUTED ({len(self.refuted)} files)"
        over = self.age_days - self.budget_days
        return f"OVER by {over}d" if over > 0 else "ok"

    @property
    def failing(self) -> bool:
        return self.verdict != "ok"


def parse_date(text: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def age_days(oldest: datetime.datetime | None, now: datetime.datetime) -> int:
    return 0 if oldest is None else max(0, (now - oldest).days)


class Git:
    """A bare repository holding every commit and tree of one remote, and none of its file contents."""

    def __init__(self, directory: pathlib.Path):
        self.directory = directory

    @classmethod
    def clone(cls, url: str, directory: pathlib.Path) -> Git:
        """A blobless clone of `url`: the default branch's history, exact and a few seconds."""
        cls.call(None, "clone", "--bare", "--quiet", "--filter=blob:none", "--single-branch", url, str(directory))
        return cls(directory)

    @staticmethod
    def call(directory: pathlib.Path | None, *args: str, stdin: str | None = None, ok: tuple[int, ...] = (0,)):
        command = ["git", *(["-C", str(directory)] if directory else []), *args]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        done = subprocess.run(command, input=stdin, capture_output=True, text=True, env=env)
        if done.returncode not in ok:
            raise Unmeasurable(f"git {args[0]} failed: {done.stderr.strip() or done.stdout.strip()}")
        return done

    def run(self, *args: str, stdin: str | None = None) -> str:
        return self.call(self.directory, *args, stdin=stdin).stdout

    def resolve(self, rev: str) -> str:
        """The full commit `rev` names, or "" when there is none."""
        done = self.call(self.directory, "rev-parse", "--verify", "--quiet", rev + "^{commit}", ok=(0, 1))
        return done.stdout.strip()

    def head(self) -> str:
        return self.resolve("HEAD")

    def on_branch(self, commit: str) -> bool:
        return self.call(self.directory, "merge-base", "--is-ancestor", commit, "HEAD", ok=(0, 1)).returncode == 0

    def lacks(self, commit: str, paths: tuple[str, ...]) -> list[tuple[str, datetime.datetime]]:
        """Commits of the branch after `commit` that change `paths`, newest first."""
        tail = ["--", *paths] if paths else []
        out = self.run("log", "--format=%H %cI", f"{commit}..HEAD", *tail)
        return [(line.split()[0], parse_date(line.split()[1])) for line in out.splitlines()]

    def blobs(self, commit: str, paths: tuple[str, ...]) -> dict[str, str]:
        """The blob id of every file under `paths` at `commit`."""
        out = self.run("ls-tree", "-r", commit, "--", *paths)
        return {line.split("\t", 1)[1]: line.split("\t", 1)[0].split()[2] for line in out.splitlines()}

    def hash_files(self, files: list[pathlib.Path]) -> list[str]:
        """The blob id each file would have, in order."""
        listing = "".join(f"{file}\n" for file in files)
        return self.run("hash-object", "--no-filters", "--stdin-paths", stdin=listing).split()


def contradictions(git: Git, pin: Pin, commit: str, root: pathlib.Path) -> tuple[str, list[str]]:
    """How many vendored files equal the pin's, and the files that equal another upstream version."""
    assert pin.vendored is not None
    top = root / pin.vendored
    files = sorted(file for path in pin.paths for file in (top / path).rglob("*") if file.is_file())
    rels = [file.relative_to(top).as_posix() for file in files]
    at_pin = git.blobs(commit, pin.paths)
    local = dict(zip(rels, git.hash_files(files)))
    differing = [rel for rel in rels if at_pin.get(rel) != local[rel]]
    evidence = f"{len(rels) - len(differing)}/{len(rels)} files at the pin"
    after = set(git.run("rev-list", f"{commit}..HEAD").split()) if differing else set()
    found: list[str] = []
    for rel in differing:
        # The raw log names the blob each commit left the file as, so no blob is fetched.
        log = git.run("log", "--format=%H", "--raw", "--no-abbrev", "--no-renames", "HEAD", "--", rel)
        versions: set[str] = set()
        commit_id = ""
        for line in log.splitlines():
            if line.startswith(":"):
                if line.split()[3] == local[rel]:
                    versions.add(commit_id)
            elif line:
                commit_id = line
        if versions:
            found.append(f"{rel} is {'later' if versions & after else 'earlier'} than the pin")
    return evidence, found


def measure_git(pin: Pin, git: Git, now: datetime.datetime, root: pathlib.Path) -> Drift:
    commit = git.resolve(pin.pinned)
    if not commit:
        raise Unmeasurable(f"{pin.name}: {pin.pinned} is not a commit of {pin.url}")
    if not git.on_branch(commit):
        raise Unmeasurable(f"{pin.name}: {pin.pinned} is not an ancestor of the branch of {pin.url}")
    lacked = git.lacks(commit, pin.paths)
    oldest = lacked[-1][1] if lacked else None
    evidence, found = ("", [])
    if pin.vendored is not None:
        evidence, found = contradictions(git, pin, commit, root)
    return Drift(
        pin.name, commit[:10], git.head()[:10], len(lacked), oldest, age_days(oldest, now),
        BUDGET_DAYS[pin.family], evidence, tuple(found),
    )


def measure_release(judged: str, releases: list[dict], now: datetime.datetime) -> Drift:
    """The judged radare2 release against the releases published since (drafts and prereleases apart)."""
    stable = [r for r in releases if not r.get("draft") and not r.get("prerelease")]
    published = sorted((parse_date(r["published_at"]), r["tag_name"]) for r in stable)
    tags = [tag for _, tag in published]
    if judged not in tags:
        raise Unmeasurable(f"radare2: the judged release {judged} is not among the {len(tags)} latest published")
    newer = published[tags.index(judged) + 1 :]
    oldest = newer[0][0] if newer else None
    return Drift("judged radare2 release", judged, tags[-1], len(newer), oldest, age_days(oldest, now), BUDGET_DAYS["judged-release"])


def read_table(text: str, heading: str) -> list[list[str]]:
    """The rows (cells stripped of backticks) of the first table under the `## heading` section."""
    section = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not section:
        raise Unmeasurable(f"no `## {heading}` section")
    lines = [line for line in section.group(1).splitlines() if line.startswith("|")]
    rows = [[cell.strip().strip("`") for cell in line.strip().strip("|").split("|")] for line in lines]
    return rows[2:]  # past the header and its rule


def ghidra_pins(root: pathlib.Path) -> list[Pin]:
    """The README's pins, which must name the base and every processor the tree vendors."""
    rows = read_table((root / "vendor/README.md").read_text(), "Upstream pins")
    named = {row[0]: row[1] for row in rows}
    processors = root / SLEIGH_CONFIG / "Ghidra/Processors"
    vendored = sorted(path.name for path in processors.iterdir() if path.is_dir())
    expected = sorted([BASE, *vendored])
    if sorted(named) != expected:
        raise Unmeasurable(f"vendor/README.md pins {sorted(named)}, but the tree vendors {expected}")
    for name, commit in named.items():
        if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
            raise Unmeasurable(f"vendor/README.md pins {name} at `{commit}`, not a commit")
    pins = [Pin(BASE, "ghidra", GHIDRA_URL, named[BASE], BASE_PATHS, LIBSLA_SYS)]
    for name in vendored:
        paths = (f"Ghidra/Processors/{name}/data/languages",)
        pins.append(Pin(name, "ghidra", GHIDRA_URL, named[name], paths, SLEIGH_CONFIG))
    return pins


def testbins_pin(root: pathlib.Path) -> Pin:
    text = (root / ".github/workflows/ci.yml").read_text()
    ref = re.search(r"^\s*TESTBINS_REF:\s*([0-9a-f]{40})\s*$", text, re.M)
    url = re.search(r"^\s*TESTBINS_URL:\s*(https://\S+)\s*$", text, re.M)
    if not ref or not url:
        raise Unmeasurable(".github/workflows/ci.yml states no TESTBINS_URL and TESTBINS_REF")
    return Pin("radare2-testbins", "testbins", url.group(1), ref.group(1))


def judged_release(root: pathlib.Path) -> str:
    text = (root / "scripts/diff_r2_judged.toml").read_text()
    release = re.search(r'^radare2\s*=\s*"([^"]+)"', text, re.M)
    if not release:
        raise Unmeasurable("scripts/diff_r2_judged.toml names no radare2 release")
    return release.group(1)


def fetch_releases(url: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "r2sleigh-upstream-drift"}
    request = urllib.request.Request(url, headers=headers)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except OSError as error:
        raise Unmeasurable(f"radare2: {url}: {error}") from error


def table(drifts: list[Drift]) -> str:
    header = ("pin", "pinned", "latest", "behind", "oldest lacked", "age", "budget", "verdict")
    rows = [header] + [
        (d.name, d.pinned, d.latest, str(d.behind), d.oldest.strftime("%Y-%m-%d") if d.oldest else "-",
         f"{d.age_days}d", f"{d.budget_days}d", d.verdict)
        for d in drifts
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]
    notes = [f"  {d.name}: {d.evidence}" for d in drifts if d.evidence]
    notes += [f"  {d.name}: {line}" for d in drifts for line in d.refuted]
    return "\n".join(lines + notes)


Clone = Callable[[str, pathlib.Path], Git]


def collect(
    root: pathlib.Path, now: datetime.datetime, releases: Callable[[str], list[dict]], clone: Clone
) -> tuple[list[Drift], list[str]]:
    """Every pin measured, in a fixed order, and the reason of each that could not be."""
    drifts: list[Drift] = []
    errors: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        clones: dict[str, Git] = {}

        def measure(pin: Pin) -> None:
            try:
                if pin.url not in clones:
                    clones[pin.url] = clone(pin.url, pathlib.Path(scratch) / f"clone{len(clones)}")
                drifts.append(measure_git(pin, clones[pin.url], now, root))
            except Unmeasurable as error:
                errors.append(str(error))

        pins: list[Pin] = []
        for read in (lambda: ghidra_pins(root), lambda: [testbins_pin(root)]):
            try:
                pins += read()
            except Unmeasurable as error:
                errors.append(str(error))
        for pin in pins:
            measure(pin)
        try:
            drifts.append(measure_release(judged_release(root), releases(RADARE2_RELEASES_URL), now))
        except Unmeasurable as error:
            errors.append(str(error))
    return drifts, errors


def main(
    argv: list[str] | None = None,
    *,
    now: datetime.datetime | None = None,
    releases: Callable[[str], list[dict]] = fetch_releases,
    clone: Clone = Git.clone,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=pathlib.Path, default=REPO, help="the repository to read the pins from")
    args = parser.parse_args(argv)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    drifts, errors = collect(args.root, now, releases, clone)
    text = table(drifts)
    print(text, flush=True)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as handle:
            handle.write(f"```\n{text}\n```\n")
    for error in errors:
        print(f"upstream drift: cannot measure: {error}", file=sys.stderr)
    failing = [d for d in drifts if d.failing]
    for d in failing:
        print(f"upstream drift: {d.name}: {d.verdict}", file=sys.stderr)
    return 2 if errors else 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
