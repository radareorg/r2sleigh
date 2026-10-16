#!/usr/bin/env python3
"""Unit tests for the gate that a change adds or lengthens no run of more than two `//` lines.

Pure Python and a scratch git repository; no binary runs.
"""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import comment_runs  # noqa: E402

SOURCE = "crates/r2ssa/src/lib.rs"
OTHER = "crates/r2engine/src/lib.rs"


def lines(text: str) -> list[bytes]:
    return comment_runs.lines_of(text.encode())


class Runs(unittest.TestCase):
    """What the ratchet and the gate both call a run."""

    def count(self, text: str) -> int:
        return comment_runs.long_runs(lines(text))

    def test_three_lines_are_a_run_and_two_are_not(self) -> None:
        self.assertEqual(self.count("// a\n// b\nfn f() {}\n"), 0)
        self.assertEqual(self.count("// a\n// b\n// c\nfn f() {}\n"), 1)

    def test_doc_comments_count_beside_plain_ones(self) -> None:
        self.assertEqual(self.count("/// a\n/// b\n/// c\nfn f() {}\n"), 1)
        self.assertEqual(self.count("//! a\n//! b\n//! c\n"), 1)
        self.assertEqual(self.count("// a\n/// b\n//! c\nfn f() {}\n"), 1)

    def test_indentation_does_not_end_a_run_and_a_blank_line_does(self) -> None:
        self.assertEqual(self.count("    // a\n\t// b\n        // c\n"), 1)
        self.assertEqual(self.count("// a\n// b\n\n// c\n// d\n"), 0)

    def test_a_trailing_comment_and_a_block_comment_are_no_run(self) -> None:
        self.assertEqual(self.count("let a = 1; // a\nlet b = 2; // b\nlet c = 3; // c\n"), 0)
        self.assertEqual(self.count("/* a */\n/* b */\n/* c */\n"), 0)

    def test_a_run_at_the_end_of_a_file_without_a_newline_counts(self) -> None:
        self.assertEqual(self.count("fn f() {}\n// a\n// b\n// c"), 1)

    def test_a_form_feed_inside_a_comment_does_not_split_it(self) -> None:
        self.assertEqual(self.count("// a\x0c// still a\n// b\n// c\n"), 1)

    def test_each_run_counts_once_however_long(self) -> None:
        self.assertEqual(self.count("// a\n" * 9 + "x\n" + "// b\n" * 3), 2)


class Scope(unittest.TestCase):
    def test_rust_under_crates_and_tools_outside_a_build_directory(self) -> None:
        for path in [SOURCE, "crates/r2s/tests/golden.rs", "tools/dylints/r2sleigh_lints/src/lib.rs"]:
            self.assertTrue(comment_runs.in_scope(path), path)
        for path in [
            "crates/r2ssa/README.md",
            "scripts/census.py",
            "vendor/libsla/src/lib.rs",
            "tools/dylints/r2sleigh_lints/target/debug/build/x.rs",
            "crates/r2ssa/target/x.rs",
            "build.rs",
        ]:
            self.assertFalse(comment_runs.in_scope(path), path)


class Count(unittest.TestCase):
    def test_the_count_walks_the_tree_and_skips_build_directories(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            run = "// a\n// b\n// c\n"
            for path, text in {
                "crates/a/src/lib.rs": run + "\n" + run,
                "crates/a/target/debug/gen.rs": run,
                "crates/a/README.md": run,
                "tools/b/src/main.rs": run,
            }.items():
                file = pathlib.Path(scratch, path)
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(text)
            self.assertEqual(comment_runs.count([f"{scratch}/crates", f"{scratch}/tools"]), 3)


class AgainstGit(unittest.TestCase):
    """The gate reads `git diff base...HEAD`, so only the branch's own commits count."""

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", self.root, *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def write(self, path: str, text: str) -> None:
        file = pathlib.Path(self.root, path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        self.git("add", path)

    def commit(self, message: str) -> None:
        self.git("commit", "-q", "-m", message)

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = self.scratch.name
        self.git("init", "-q", "-b", "base")
        self.git("config", "user.email", "gate@example.invalid")
        self.git("config", "user.name", "gate")
        self.write(SOURCE, "// one\n// two\nfn a() {}\n\nfn b() {}\n")
        self.write(OTHER, "fn c() {}\n")
        self.commit("base")
        self.git("checkout", "-q", "-b", "change")

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def fork_here(self) -> None:
        """Make what is committed so far the base, and start the change on top of it."""
        self.git("checkout", "-q", "-B", "base")
        self.git("checkout", "-q", "-b", "change2")

    def grown(self) -> dict[str, list[comment_runs.Run]]:
        cwd = pathlib.Path.cwd()
        try:
            os.chdir(self.root)
            return comment_runs.grown_runs("base", "HEAD")
        finally:
            os.chdir(cwd)

    def gate(self) -> int:
        cwd = pathlib.Path.cwd()
        try:
            os.chdir(self.root)
            with contextlib.redirect_stdout(io.StringIO()):
                return comment_runs.main(["--base", "base"])
        finally:
            os.chdir(cwd)

    def test_a_new_run_in_an_existing_file_fails(self) -> None:
        self.write(SOURCE, "// one\n// two\nfn a() {}\n\n// x\n// y\n// z\nfn b() {}\n")
        self.commit("a run")
        self.assertEqual(self.gate(), 1)
        self.assertEqual(self.grown(), {SOURCE: [comment_runs.Run(5, 7, 3, 0)]})

    def test_a_new_file_holding_a_run_fails_and_one_holding_two_lines_passes(self) -> None:
        self.write("crates/r2il/src/new.rs", "// a\n// b\n")
        self.commit("short")
        self.assertEqual(self.gate(), 0)
        self.write("crates/r2il/src/long.rs", "//! a\n//! b\n//! c\n")
        self.commit("long")
        self.assertEqual(self.gate(), 1)
        self.assertEqual(list(self.grown()), ["crates/r2il/src/long.rs"])

    def test_two_lines_made_three_fail(self) -> None:
        self.write(SOURCE, "// one\n// two\n// three\nfn a() {}\n\nfn b() {}\n")
        self.commit("lengthened")
        self.assertEqual(self.grown(), {SOURCE: [comment_runs.Run(1, 3, 3, 2)]})

    def test_a_long_run_made_longer_fails_and_the_report_names_both_lengths(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\n// 4\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.write(SOURCE, "// 1\n// 2\n// 3\n// 4\n// 5\nfn a() {}\n")
        self.commit("longer")
        self.assertEqual(self.grown(), {SOURCE: [comment_runs.Run(1, 5, 5, 4)]})

    def test_an_edit_inside_a_long_run_and_a_shortening_pass(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\n// 4\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.write(SOURCE, "// 1\n// two\n// 3\n// 4\nfn a() {}\n")
        self.commit("one line reworded")
        self.assertEqual(self.gate(), 0)
        self.write(SOURCE, "// 1\n// two\n// 3\nfn a() {}\n")
        self.commit("one line gone")
        self.assertEqual(self.gate(), 0)
        self.write(SOURCE, "// 1\n// 3\nfn a() {}\n")
        self.commit("down to two")
        self.assertEqual(self.gate(), 0)

    def test_a_rewritten_run_is_a_new_run(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.write(SOURCE, "// a\n// b\n// c\nfn a() {}\n")
        self.commit("every line reworded")
        self.assertEqual(self.gate(), 1)

    def test_a_run_untouched_beside_an_unrelated_edit_passes(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n\nfn b() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n\nfn b() { 1; }\n")
        self.commit("code")
        self.assertEqual(self.gate(), 0)

    def test_two_runs_joined_by_deleting_the_line_between_fail(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n// 4\n// 5\n// 6\n")
        self.commit("two long runs on the base")
        self.fork_here()
        self.write(SOURCE, "// 1\n// 2\n// 3\n// 4\n// 5\n// 6\n")
        self.commit("the code between them gone")
        self.assertEqual(self.grown(), {SOURCE: [comment_runs.Run(1, 6, 6, 3)]})

    def test_a_run_gaining_lines_above_an_unchanged_one_is_measured_against_it(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.write(SOURCE, "// 0\n// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("a line above")
        self.assertEqual(self.grown(), {SOURCE: [comment_runs.Run(1, 4, 4, 3)]})

    def test_a_renamed_file_keeps_its_runs(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.git("mv", SOURCE, "crates/r2ssa/src/moved.rs")
        self.commit("moved")
        self.assertEqual(self.gate(), 0)
        self.write("crates/r2ssa/src/moved.rs", "// 1\n// 2\n// 3\n// 4\nfn a() {}\n")
        self.commit("and one line longer")
        self.assertEqual(self.gate(), 1)

    def test_files_outside_the_ratchets_scope_are_not_read(self) -> None:
        long = "// a\n// b\n// c\n"
        self.write("vendor/libsla/src/lib.rs", long)
        self.write("crates/r2ssa/README.md", long)
        self.write("crates/r2ssa/target/gen.rs", long)
        self.commit("elsewhere")
        self.assertEqual(self.gate(), 0)

    def test_a_deleted_file_and_a_deleted_run_pass(self) -> None:
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("long run on the base")
        self.fork_here()
        self.git("rm", "-q", OTHER)
        self.write(SOURCE, "fn a() {}\n")
        self.commit("gone")
        self.assertEqual(self.gate(), 0)

    def test_a_run_that_landed_on_the_base_after_the_fork_is_not_the_branchs(self) -> None:
        self.write(OTHER, "fn c() { 1; }\n")
        self.commit("the branch's own edit")
        self.git("checkout", "-q", "base")
        self.write(SOURCE, "// 1\n// 2\n// 3\nfn a() {}\n")
        self.commit("a long run landed on the base")
        self.git("checkout", "-q", "change")
        self.assertEqual(self.gate(), 0)


if __name__ == "__main__":
    unittest.main()
