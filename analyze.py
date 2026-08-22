"""Plot benchmark timings against the largest valid partition gap.

By default this script reads ``/home/cw3723/data/riscv/v4-*.yml`` and writes
one PNG per program and statistic below ``/home/cw3723/data/plots``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
from typing import Final, Iterable

import numpy as np
import pc_gap
import yaml


class TestCase(Enum):
    Aberr = ("Aberration", Path("/home/cw3723/bpf-prime/tests/aberr/"))
    Aes = ("AES", Path("/home/cw3723/bpf-prime/tests/aes/"))
    Matmul = ("Matmul", Path("/home/cw3723/bpf-prime/tests/matmul/"))
    ncc = ("NCC Score", Path("/home/cw3723/bpf-prime/tests/nccscore/"))

    def __init__(self, title: str, directory: Path) -> None:
        self.title = title
        self.dir = directory

    @property
    def directory(self) -> Path:
        """Descriptive alias for the draft's ``dir`` attribute."""
        return self.dir


PROG_NAME: Final = "a.o"
TRACE_NAME: Final = "trace.yml"
DATA_DIRECTORY: Final = Path("/home/cw3723/data/riscv")
PLOT_DIRECTORY: Final = Path("/home/cw3723/data/plots")
LABELED_DATA: Final = "v4-*.yml"
# Backwards-compatible names from the original draft.
ProgName = PROG_NAME
TraceName = TRACE_NAME
LabeledData = LABELED_DATA


@dataclass(frozen=True)
class CaseData:
    times: np.ndarray
    boundaries: set[int]


@dataclass(frozen=True)
class ProcCaseData:
    times: np.ndarray
    maxGap: int

    @property
    def max_gap(self) -> int:
        """PEP-8 alias for the draft's ``maxGap`` attribute."""
        return self.maxGap


def _read_case(path: Path, test_case: TestCase) -> CaseData:
    """Read and validate one program's measurements from a dataset file."""
    try:
        with path.open(encoding="utf-8") as file:
            document = yaml.safe_load(file)
        case = document[test_case.title]
        samples = case["samples"]
        times = np.asarray([float(sample[0]) for sample in samples], dtype=np.float64)
        boundaries = {int(pc) for pc in case["partition_pcs"]}
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise ValueError(
            f"{path}: invalid data for {test_case.title!r}; expected samples and partition_pcs"
        ) from error

    if times.size == 0:
        raise ValueError(f"{path}: {test_case.title!r} has no timing samples")
    if not np.all(np.isfinite(times)):
        raise ValueError(f"{path}: {test_case.title!r} has a non-finite timing sample")
    return CaseData(times=times, boundaries=boundaries)


def load_all(files: Iterable[Path]) -> dict[TestCase, list[ProcCaseData]]:
    """Load timings and attach the largest reachable gap to every partitioning.

    A timing point is retained only when both endpoints of at least one valid
    gap are partition boundaries for that point's ``split_into`` value.
    """
    raw: dict[TestCase, dict[int, CaseData]] = {test_case: {} for test_case in TestCase}

    for path in files:
        try:
            with path.open(encoding="utf-8") as file:
                document = yaml.safe_load(file)
            split_into = int(document["split_into"])
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{path}: missing or invalid split_into") from error

        for test_case in TestCase:
            if split_into in raw[test_case]:
                raise ValueError(
                    f"duplicate data for {test_case.title!r} with split_into={split_into}"
                )
            raw[test_case][split_into] = _read_case(path, test_case)

    if not any(raw.values()):
        raise ValueError("no input data files were supplied")

    processed: dict[TestCase, list[ProcCaseData]] = {}
    for test_case, cases in raw.items():
        all_boundaries = set().union(*(case.boundaries for case in cases.values()))
        max_gaps: dict[int, int] = {}
        for start_pc, end_pc, gap in pc_gap.gapsInSet(
            all_boundaries,
            test_case.directory / PROG_NAME,
            test_case.directory / TRACE_NAME,
        ):
            for split_into, case in cases.items():
                if start_pc in case.boundaries and end_pc in case.boundaries:
                    max_gaps[split_into] = max(max_gaps.get(split_into, -1), gap)

        points = [
            ProcCaseData(times=cases[split_into].times, maxGap=max_gap)
            for split_into, max_gap in max_gaps.items()
        ]
        processed[test_case] = sorted(points, key=lambda point: point.max_gap)
    return processed


# Preserve the draft's public spelling for callers that already use it.
loadAll = load_all


def _mean_with_ci(times: np.ndarray) -> tuple[float, float]:
    """Return the sample mean and its two-sided 95% Student-t half-width."""
    mean = float(np.mean(times))
    if times.size < 2:
        return mean, 0.0

    # scipy supplies the exact Student-t quantile for the sample's degrees of
    # freedom, rather than using a normal approximation for small samples.
    from scipy.stats import t as student_t

    standard_error = float(np.std(times, ddof=1) / np.sqrt(times.size))
    half_width = float(student_t.ppf(0.975, df=times.size - 1) * standard_error)
    return mean, half_width


def _configure_axes(axis, title: str, statistic: str, max_gap: np.ndarray, upper: np.ndarray) -> None:
    axis.set_title(f"{title} — {statistic}")
    axis.set_xlabel("Maximum gap (cycles)")
    axis.set_ylabel("Time (ms)")
    axis.set_xticks(max_gap)
    axis.grid(True, which="major", alpha=0.35)

    if max_gap.size > 1:
        axis.set_xlim(int(max_gap.min()), int(max_gap.max()))
    max_y = float(upper.max())
    if max_y > 0:
        axis.set_ylim(0, max_y)


def _draw_mean(axis, test_case: TestCase, points: list[ProcCaseData]) -> None:
    x = np.asarray([point.max_gap for point in points])
    means, intervals = zip(*(_mean_with_ci(point.times) for point in points))
    y = np.asarray(means)
    ci = np.asarray(intervals)
    axis.errorbar(x, y, yerr=ci, fmt="o", capsize=4, linestyle="none")
    _configure_axes(axis, test_case.title, "Mean (95% t CI)", x, y + ci)


def _draw_median(axis, test_case: TestCase, points: list[ProcCaseData]) -> None:
    x = np.asarray([point.max_gap for point in points])
    quartiles = np.asarray([np.percentile(point.times, [25, 50, 75]) for point in points])
    lower, median, upper = quartiles.T
    axis.errorbar(
        x,
        median,
        yerr=np.vstack((median - lower, upper - median)),
        fmt="o",
        capsize=4,
        linestyle="none",
    )
    _configure_axes(axis, test_case.title, "Median (IQR)", x, upper)


def draw(
    data: dict[TestCase, list[ProcCaseData]],
    plot_directory: Path = PLOT_DIRECTORY,
    *,
    show: bool = True,
) -> None:
    """Display grouped mean/median figures and export one PNG for each graph."""
    import matplotlib.pyplot as plt

    plotters = (("mean", _draw_mean), ("median", _draw_median))
    for statistic, plotter in plotters:
        output_directory = plot_directory / statistic
        output_directory.mkdir(parents=True, exist_ok=True)

        grouped_figure, grouped_axes = plt.subplots(2, 2, figsize=(12, 8), layout="constrained")
        for axis, test_case in zip(grouped_axes.flat, TestCase):
            points = data.get(test_case, [])
            if not points:
                axis.set_visible(False)
                continue
            plotter(axis, test_case, points)

            individual_figure, individual_axis = plt.subplots(figsize=(6, 4), layout="constrained")
            plotter(individual_axis, test_case, points)
            individual_figure.savefig(output_directory / f"{test_case.title}.png", dpi=150)
            plt.close(individual_figure)
        grouped_figure.suptitle(f"Timing by maximum gap — {statistic.title()}")

    if show:
        plt.show()
    else:
        plt.close("all")


def _default_files() -> list[Path]:
    numbered_files = []
    for path in DATA_DIRECTORY.glob(LABELED_DATA):
        match = re.fullmatch(r"v4-(\d+)\.yml", path.name)
        if match:
            numbered_files.append((int(match.group(1)), path))
    return [path for _number, path in sorted(numbered_files)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files", nargs="*", type=Path,
        help=f"YAML inputs (defaults to {DATA_DIRECTORY / LABELED_DATA})",
    )
    parser.add_argument("--no-show", action="store_true", help="Export plots without opening windows")
    args = parser.parse_args()

    files = args.files or _default_files()
    draw(load_all(files), show=not args.no_show)


if __name__ == "__main__":
    main()
