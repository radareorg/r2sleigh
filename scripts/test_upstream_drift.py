#!/usr/bin/env python3
"""Unit tests for the upstream drift alarm (ROADMAP D39).

Offline: each upstream is a scratch git repository, and the radare2 release list is a literal.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import upstream_drift as drift  # noqa: E402

TESTBINS_URL = "https://example.invalid/testbins"
IA = "Ghidra/Processors/x86/data/languages/ia.sinc"
MIPS = "Ghidra/Processors/MIPS/data/languages/mips.sinc"
CPP = "Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc"
JAVA = "Ghidra/Framework/Gui.java"


def utc(month: int, day: int) -> datetime.datetime:
    return datetime.datetime(2026, month, day, 12, 0, tzinfo=datetime.timezone.utc)


def write(root: pathlib.Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def commit(repo: pathlib.Path, when: datetime.datetime, files: dict[str, str]) -> str:
    """A commit of `files` at `when`; returns its full id."""
    for rel, text in files.items():
        write(repo, rel, text)
    env = {**os.environ, "GIT_AUTHOR_DATE": when.isoformat(), "GIT_COMMITTER_DATE": when.isoformat()}
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "add", "-A"], check=True, env=env, capture_output=True)
    subprocess.run([*git, "commit", "-q", "-m", "c"], check=True, env=env, capture_output=True)
    return subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def init(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "master", str(path)], check=True, capture_output=True)
    return path


def readme(pins: dict[str, str]) -> str:
    rows = "".join(f"| {name} | `{sha}` |\n" for name, sha in pins.items())
    days = "".join(f"| {family} | {days} |\n" for family, days in drift.BUDGET_DAYS.items())
    return f"## Upstream pins\n\n| Pin | Commit |\n|---|---|\n{rows}\n## Drift budget\n\n| Family | Days |\n|---|---|\n{days}"


class Upstreams:
    """A Ghidra history, a testbins history and a commit on a side branch, built once.

    Ghidra: A (2026-01-01) holds x86, MIPS and the C++; B (02-01) and D (03-15) change x86; C (03-01)
    changes only Java; S, on a side branch off A, is no ancestor of the head. Testbins: T1 (01-01), T2 (04-01).
    """

    def __init__(self, scratch: pathlib.Path):
        self.ghidra_dir = init(scratch / "ghidra")
        self.a = commit(self.ghidra_dir, utc(1, 1), {IA: "ia v1", MIPS: "mips v1", CPP: "cpp v1", JAVA: "gui v1"})
        self.b = commit(self.ghidra_dir, utc(2, 1), {IA: "ia v2"})
        self.c = commit(self.ghidra_dir, utc(3, 1), {JAVA: "gui v2"})
        self.d = commit(self.ghidra_dir, utc(3, 15), {IA: "ia v3"})
        subprocess.run(["git", "-C", str(self.ghidra_dir), "checkout", "-q", "-b", "side", self.a], check=True)
        self.side = commit(self.ghidra_dir, utc(2, 2), {IA: "ia side"})
        subprocess.run(["git", "-C", str(self.ghidra_dir), "checkout", "-q", "master"], check=True)
        self.bins_dir = init(scratch / "testbins")
        self.t1 = commit(self.bins_dir, utc(1, 1), {"elf/a": "a"})
        self.t2 = commit(self.bins_dir, utc(4, 1), {"elf/b": "b"})


UPSTREAMS: Upstreams
SCRATCH = tempfile.TemporaryDirectory()


def setUpModule() -> None:
    global UPSTREAMS
    UPSTREAMS = Upstreams(pathlib.Path(SCRATCH.name) / "upstream")


def tearDownModule() -> None:
    SCRATCH.cleanup()


class World(unittest.TestCase):
    """A tree pinned into the upstreams."""

    def setUp(self) -> None:
        up = UPSTREAMS
        self.ghidra_dir, self.bins_dir = up.ghidra_dir, up.bins_dir
        self.a, self.b, self.c, self.d, self.side, self.t1, self.t2 = up.a, up.b, up.c, up.d, up.side, up.t1, up.t2
        self._tree = tempfile.TemporaryDirectory()
        self.addCleanup(self._tree.cleanup)
        self.root = pathlib.Path(self._tree.name)
        self.release_list = [
            {"tag_name": "6.2.4", "published_at": "2026-01-05T00:00:00Z", "draft": False, "prerelease": False}
        ]
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": self.a}, ia="ia v1", testbins=self.t1)

    def tree(self, pins: dict[str, str], ia: str, testbins: str, judged: str = "6.2.4") -> None:
        """The repository the alarm reads: its README, vendored files, CI file and judgments."""
        sleigh = "vendor/sleigh-config/ghidra/"
        write(self.root, "vendor/README.md", readme(pins))
        write(self.root, sleigh + IA, ia)
        write(self.root, sleigh + MIPS, "mips v1")
        write(self.root, "vendor/libsla-sys/ghidra/" + CPP, "cpp v1")
        write(self.root, ".github/workflows/ci.yml", f"env:\n  TESTBINS_URL: {TESTBINS_URL}\n  TESTBINS_REF: {testbins}\n")
        write(self.root, "scripts/diff_r2_judged.toml", f'# judged\nradare2 = "{judged}"\n')

    def clone(self, url: str, directory: pathlib.Path) -> drift.Git:
        repos = {drift.GHIDRA_URL: self.ghidra_dir, TESTBINS_URL: self.bins_dir}
        if url not in repos:
            raise drift.Unmeasurable(f"no remote {url}")
        return drift.Git(repos[url])

    def run_main(self, now: datetime.datetime, *, clone=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = drift.main(
                ["--root", str(self.root)],
                now=now,
                releases=lambda url: self.release_list,
                clone=clone or self.clone,
            )
        return status, out.getvalue(), err.getvalue()

    def by_name(self, now: datetime.datetime) -> dict[str, drift.Drift]:
        drifts, errors = drift.collect(self.root, now, lambda url: self.release_list, self.clone)
        self.assertEqual(errors, [])
        return {d.name: d for d in drifts}


class Measure(World):
    def test_a_pin_is_as_old_as_the_oldest_change_to_its_paths_that_it_lacks(self) -> None:
        got = self.by_name(utc(5, 1))
        # x86 lacks B and D; Java's C is nothing the tree vendors; MIPS and the C++ lack nothing.
        self.assertEqual((got["x86"].behind, got["x86"].oldest), (2, utc(2, 1)))
        self.assertEqual(got["x86"].age_days, 89)
        for name in ("MIPS", "Ghidra base"):
            self.assertEqual((got[name].behind, got[name].oldest, got[name].age_days), (0, None, 0))

    def test_the_budget_is_the_last_day_a_pin_may_wait(self) -> None:
        day = utc(2, 1) + datetime.timedelta(days=drift.BUDGET_DAYS["ghidra"])
        self.assertFalse(self.by_name(day)["x86"].failing)
        over = self.by_name(day + datetime.timedelta(days=1))["x86"]
        self.assertTrue(over.failing)
        self.assertEqual(over.verdict, "OVER by 1d")

    def test_a_testbins_pin_counts_every_commit(self) -> None:
        got = self.by_name(utc(4, 2))["radare2-testbins"]
        self.assertEqual((got.behind, got.oldest, got.pinned), (1, utc(4, 1), self.t1[:10]))
        self.assertEqual(got.budget_days, drift.BUDGET_DAYS["testbins"])

    def test_a_pin_at_the_head_lacks_nothing(self) -> None:
        self.tree(pins={"Ghidra base": self.d, "MIPS": self.d, "x86": self.d}, ia="ia v3", testbins=self.t2)
        for got in self.by_name(utc(12, 31)).values():
            self.assertEqual((got.behind, got.age_days, got.failing), (0, 0, False), got.name)


class Contradiction(World):
    def test_a_file_of_an_earlier_version_refutes_a_pin_that_lacks_nothing(self) -> None:
        self.tree(pins={"Ghidra base": self.d, "MIPS": self.d, "x86": self.d}, ia="ia v1", testbins=self.t2)
        got = self.by_name(utc(3, 16))["x86"]
        self.assertEqual(got.behind, 0)
        self.assertEqual(got.refuted, (f"{IA} is earlier than the pin",))
        self.assertTrue(got.failing)

    def test_a_file_of_a_later_version_refutes_a_pin_that_is_too_old(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": self.a}, ia="ia v3", testbins=self.t1)
        self.assertEqual(self.by_name(utc(3, 16))["x86"].refuted, (f"{IA} is later than the pin",))

    def test_a_file_the_fork_changed_is_carried_not_contradicted(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": self.a}, ia="ia carried", testbins=self.t1)
        got = self.by_name(utc(3, 16))["x86"]
        self.assertEqual((got.refuted, got.evidence), ((), "0/1 files at the pin"))

    def test_the_files_at_the_pin_are_counted(self) -> None:
        self.assertEqual(self.by_name(utc(3, 16))["x86"].evidence, "1/1 files at the pin")


class Alarm(World):
    def test_within_budget_exits_zero_and_lists_every_pin(self) -> None:
        status, out, err = self.run_main(utc(2, 20))
        self.assertEqual((status, err), (0, ""))
        for name in ("Ghidra base", "MIPS", "x86", "radare2-testbins", "judged radare2 release"):
            self.assertIn(name, out)

    def test_one_pin_over_budget_exits_one_and_names_it_beside_the_green_ones(self) -> None:
        status, out, err = self.run_main(utc(5, 20))
        self.assertEqual(status, 1)
        self.assertIn("upstream drift: x86: OVER by", err)
        self.assertNotIn("MIPS", err)
        self.assertIn("MIPS", out)

    def test_a_pin_the_remote_lacks_is_unmeasurable_not_green(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": "deadbeef"}, ia="ia v1", testbins=self.t1)
        status, out, err = self.run_main(utc(2, 20))
        self.assertEqual(status, 2)
        self.assertIn("deadbeef is not a commit", err)
        self.assertIn("MIPS", out)

    def test_a_pin_off_the_branch_is_unmeasurable(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": self.side}, ia="ia side", testbins=self.t1)
        status, _, err = self.run_main(utc(2, 20))
        self.assertEqual(status, 2)
        self.assertIn("not an ancestor", err)

    def test_a_vendored_processor_without_a_pin_is_unmeasurable(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "x86": self.a}, ia="ia v1", testbins=self.t1)
        status, out, err = self.run_main(utc(2, 20))
        self.assertEqual(status, 2)
        self.assertIn("vendor/README.md pins", err)
        self.assertIn("radare2-testbins", out)

    def test_a_pin_that_is_not_a_commit_name_is_unmeasurable(self) -> None:
        self.tree(pins={"Ghidra base": self.a, "MIPS": self.a, "x86": "11.4"}, ia="ia v1", testbins=self.t1)
        self.assertEqual(self.run_main(utc(2, 20))[0], 2)

    def test_an_unreachable_remote_leaves_the_other_pins_measured(self) -> None:
        def clone(url: str, directory: pathlib.Path) -> drift.Git:
            if url == TESTBINS_URL:
                raise drift.Unmeasurable("git clone failed: offline")
            return self.clone(url, directory)

        status, out, err = self.run_main(utc(2, 20), clone=clone)
        self.assertEqual(status, 2)
        self.assertIn("offline", err)
        self.assertIn("x86", out)
        self.assertIn("judged radare2 release", out)

    def test_a_refuted_pin_exits_one(self) -> None:
        self.tree(pins={"Ghidra base": self.d, "MIPS": self.d, "x86": self.d}, ia="ia v1", testbins=self.t2)
        status, out, err = self.run_main(utc(3, 16))
        self.assertEqual(status, 1)
        self.assertIn("REFUTED (1 files)", out)
        self.assertIn(f"x86: {IA} is earlier than the pin", out)


class Releases(unittest.TestCase):
    @staticmethod
    def release(tag: str, day: int, **flags: bool) -> dict:
        return {"tag_name": tag, "published_at": f"2026-05-{day:02d}T00:00:00Z", "draft": False, "prerelease": False, **flags}

    def test_releases_since_the_judged_one_are_behind_by_the_oldest(self) -> None:
        listed = [self.release("6.2.6", 20), self.release("6.2.4", 1), self.release("6.2.5", 10)]
        got = drift.measure_release("6.2.4", listed, utc(5, 30))
        self.assertEqual((got.behind, got.latest, got.oldest.day, got.age_days), (2, "6.2.6", 10, 20))

    def test_the_judged_release_being_the_latest_lacks_nothing(self) -> None:
        got = drift.measure_release("6.2.4", [self.release("6.2.4", 1)], utc(12, 1))
        self.assertEqual((got.behind, got.oldest, got.age_days, got.failing), (0, None, 0, False))

    def test_drafts_and_prereleases_are_not_releases(self) -> None:
        listed = [self.release("6.2.4", 1), self.release("6.3.0", 5, prerelease=True), self.release("6.3.1", 6, draft=True)]
        self.assertEqual(drift.measure_release("6.2.4", listed, utc(12, 1)).behind, 0)

    def test_an_old_judgment_is_over_its_budget(self) -> None:
        listed = [self.release("6.2.4", 1), self.release("6.2.6", 2)]
        got = drift.measure_release("6.2.4", listed, utc(5, 2) + datetime.timedelta(days=drift.BUDGET_DAYS["judged-release"] + 1))
        self.assertTrue(got.failing)

    def test_a_judged_release_the_list_lacks_is_unmeasurable(self) -> None:
        with self.assertRaises(drift.Unmeasurable):
            drift.measure_release("6.2.4", [self.release("6.2.6", 20)], utc(6, 1))


class Repository(unittest.TestCase):
    """The pins as this tree states them."""

    def test_every_vendored_processor_and_the_base_has_a_pin(self) -> None:
        pins = drift.ghidra_pins(drift.REPO)
        self.assertEqual(pins[0].name, drift.BASE)
        processors = (drift.REPO / drift.SLEIGH_CONFIG / "Ghidra/Processors").iterdir()
        self.assertEqual([p.name for p in pins[1:]], sorted(p.name for p in processors))

    def test_the_other_pins_are_read_where_they_are_used(self) -> None:
        self.assertRegex(drift.testbins_pin(drift.REPO).pinned, r"^[0-9a-f]{40}$")
        self.assertTrue(drift.testbins_pin(drift.REPO).url.startswith("https://github.com/radareorg/"))
        self.assertRegex(drift.judged_release(drift.REPO), r"^\d+\.\d+\.\d+$")

    def test_the_budget_the_readme_states_is_the_budget_the_script_holds(self) -> None:
        rows = drift.read_table((drift.REPO / "vendor/README.md").read_text(), "Drift budget")
        self.assertEqual({family: int(days) for family, days in rows}, drift.BUDGET_DAYS)


class Clone(World):
    def test_a_blobless_clone_reads_a_remote_exactly(self) -> None:
        clone = drift.Git.clone(self.ghidra_dir.as_uri(), self.root / "clone")
        self.assertEqual(clone.head(), self.d)
        self.assertEqual([sha for sha, _ in clone.lacks(self.a, (IA,))], [self.d, self.b])
        self.assertTrue(clone.on_branch(self.a))


if __name__ == "__main__":
    unittest.main()
