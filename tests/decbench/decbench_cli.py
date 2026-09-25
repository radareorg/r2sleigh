#!/usr/bin/env python3
"""Launch DecBench with a compatibility registration for its VJ-GED helper.

    decbench_cli.py <decbench arguments>                  # the `decbench` CLI
    decbench_cli.py run-benchmark <run_benchmark args>    # the official driver

The r2sleigh backend is not registered here: ``install_backend.py`` puts it
inside the DecBench checkout, which is the only way the per-binary
``decompile_one.py`` subprocess of the official driver can see it, and one
place to register it keeps the measured backend the installed one.

The benchmark host and DecBench upstream currently ship
``decbench.metrics.vj_ged.vj_ged`` but do not expose it through the metric
registry. If a future DecBench does register ``vj_ged`` natively, this launcher
leaves it untouched. Otherwise it registers the existing algorithm directly;
it never aliases the separately budgeted/approximated ``ged`` metric.
"""

from __future__ import annotations

import math
import runpy
import sys
from pathlib import Path
from typing import Any

import decbench.metrics  # noqa: F401
from decbench.metrics.base import Metric
from decbench.metrics.registry import MetricRegistry, register_metric
from decbench.models.metrics import AggregationType, MetricValue
from phase_timing import install_phase_timing


def register_vj_ged_if_needed() -> None:
    if "vj_ged" in MetricRegistry.list_registered():
        return

    @register_metric("vj_ged")
    class VJGEDMetric(Metric):
        """Unapproximated VJ graph-edit distance from DecBench's own helper."""

        name = "vj_ged"
        display_name = "VJ Graph Edit Distance"
        description = "VJ assignment cost between source and decompiled CFGs"
        weight = 1.0
        lower_is_better = True
        perfect_value = 0.0
        default_aggregation = AggregationType.PERCENT
        requires_source_cfg = True
        requires_decompiled_cfg = True
        cache_version = "compat-1"

        def compute_for_function(
            self,
            decompiled,
            source_cfg=None,
            decompiled_cfg=None,
            **kwargs: Any,
        ) -> MetricValue:
            if source_cfg is None or decompiled_cfg is None:
                return MetricValue(
                    value=float("inf"), metadata={"error": "Missing CFG"}
                )
            from decbench.metrics.vj_ged import vj_ged
            from decbench.utils.cfg import is_degenerate_source_cfg

            if is_degenerate_source_cfg(source_cfg):
                return MetricValue(
                    value=float("inf"),
                    metadata={"error": "degenerate source CFG"},
                )
            try:
                value = float(vj_ged(source_cfg, decompiled_cfg))
            except Exception as exc:  # noqa: BLE001
                return MetricValue(value=float("inf"), metadata={"error": str(exc)})
            if not math.isfinite(value):
                return MetricValue(
                    value=float("inf"), metadata={"error": "non-finite VJ-GED"}
                )
            return MetricValue(
                value=value,
                raw_value=value,
                metadata={
                    "source_nodes": source_cfg.number_of_nodes(),
                    "source_edges": source_cfg.number_of_edges(),
                    "decompiled_nodes": decompiled_cfg.number_of_nodes(),
                    "decompiled_edges": decompiled_cfg.number_of_edges(),
                    "method": "decbench.metrics.vj_ged.vj_ged",
                },
            )


def run_benchmark(arguments: list[str]) -> None:
    """Run DecBench's own ``scripts/run_benchmark.py`` in this process."""
    import decbench

    script = Path(decbench.__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    if not script.exists():
        raise SystemExit(f"no {script}: DecBench must be installed from a checkout (pip -e)")
    sys.argv = [str(script), *arguments]
    sys.path.insert(0, str(script.parent))
    runpy.run_path(str(script), run_name="__main__")


register_vj_ged_if_needed()
install_phase_timing()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run-benchmark":
        run_benchmark(sys.argv[2:])
    else:
        from decbench.cli import main

        main()
