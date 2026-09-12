"""Regression checks for elapsed phase accounting."""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import phase_timing


class PhaseTimingTests(unittest.TestCase):
    def test_concurrent_intervals_are_unioned_per_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phases.tsv"
            spans = [
                ("decompile", 5, 12),
                ("reference", 2, 20),
                ("decompile", 1, 8),
                ("decompile", 6, 7),
                ("decompile", 15, 19),
                ("reference", 10, 16),
                ("evaluate", 21, 31),
            ]
            path.write_text("".join(
                f"{phase}\t{start * 10**9}\t{end * 10**9}\n"
                for phase, start, end in spans
            ))
            self.assertEqual(
                phase_timing.phase_seconds(path),
                {"decompile": 15, "reference": 18, "evaluate": 10},
            )

    def test_pipeline_records_results_failures_and_skipped_reference(self):
        pipeline = types.ModuleType("decbench.pipeline")
        pipeline.decompile = types.ModuleType("decbench.pipeline.decompile")
        pipeline.executor = types.ModuleType("decbench.pipeline.executor")
        worker = Mock(return_value={"result": "unchanged"})
        evaluator = Mock(return_value={"scores": "unchanged"})
        pipeline.decompile.decompile_binary = worker
        pipeline.executor.evaluate_projects = evaluator
        modules = {
            "decbench": types.ModuleType("decbench"),
            "decbench.pipeline": pipeline,
            "decbench.pipeline.decompile": pipeline.decompile,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phases.tsv"
            with (
                patch.dict(sys.modules, modules),
                patch.dict(os.environ, {"R2SLEIGH_DECBENCH_PHASE_LOG": str(path)}),
                patch.object(phase_timing.time, "monotonic_ns", side_effect=[
                    value * 10**9 for value in (1, 6, 7, 10, 11, 19)
                ]),
            ):
                phase_timing.install_phase_timing()
                phase_timing.install_phase_timing()
                result = pipeline.decompile.decompile_binary("binary", "r2sleigh")
                self.assertEqual(result, {"result": "unchanged"})
                result = pipeline.executor.evaluate_projects("projects")
                self.assertEqual(result, {"scores": "unchanged"})
                self.assertEqual(phase_timing.phase_seconds(path), {
                    "decompile": 5, "reference": 0, "evaluate": 3,
                })
                worker.side_effect = RuntimeError("decompiler failed")
                with self.assertRaisesRegex(RuntimeError, "decompiler failed"):
                    pipeline.decompile.decompile_binary("binary", "angr")
                self.assertEqual(phase_timing.phase_seconds(path), {
                    "decompile": 5, "reference": 8, "evaluate": 3,
                })
                self.assertEqual(worker.call_count, 2)
                evaluator.assert_called_once_with("projects")


if __name__ == "__main__":
    unittest.main()
