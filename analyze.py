from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from enum import Enum
import os
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
LABELED_DATA: Final = "BENCHMARK_RESULT-*.yml"
ProgName = PROG_NAME
TraceName = TRACE_NAME
LabeledData = LABELED_DATA


@dataclass(frozen=True)
class CaseData:
    times: np.ndarray
    boundaries: set[int]
    entry: int
    exit: int


@dataclass(frozen=True)
class ProcCaseData:
    times: np.ndarray
    maxGap: int
    splitInto: int
    maxGapPair: tuple[int, int]
    maxCycleCount: int

    @property
    def cycleRatio(self) -> float:
        return self.maxGap / self.maxCycleCount


def _case_from_document(document, path: Path, test_case: TestCase) -> CaseData:
    try:
        case = document[test_case.title]
        samples = case["samples"]
        times = np.asarray([float(sample[0]) for sample in samples], dtype=np.float64)
        boundaries = {int(pc) for pc in case["partition_pcs"]}
        entry, exit = (int(pc) for pc in case["partition_pcs"][:2])
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise ValueError(
            f"{path}: invalid data for {test_case.title!r}; expected samples and partition_pcs"
        ) from error

    if times.size == 0:
        raise ValueError(f"{path}: {test_case.title!r} has no timing samples")
    if not np.all(np.isfinite(times)):
        raise ValueError(f"{path}: {test_case.title!r} has a non-finite timing sample")
    if np.any(times <= 0):
        raise ValueError(
            f"{path}: {test_case.title!r} has a non-positive timing sample; "
            "log-scale plots require positive times"
        )
    return CaseData(times=times, boundaries=boundaries, entry=entry, exit=exit)


def _read_case(path: Path, test_case: TestCase) -> CaseData:
    """Read and validate one program's measurements from a dataset file."""
    with path.open(encoding="utf-8") as file:
        document = yaml.safe_load(file)
    return _case_from_document(document, path, test_case)


def _gaps(
    test_case: TestCase, boundaries: set[int], entry: int
) -> tuple[list[tuple[int, int, int]], int]:
    cache_path = test_case.directory / ".gaps.yml"
    cached_boundaries = sorted(boundaries)
    try:
        with cache_path.open(encoding="utf-8") as file:
            cache = yaml.safe_load(file)
        cached_pcs = {int(pc) for pc in cache["boundaries"]}
        cached_gaps = [tuple(map(int, gap)) for gap in cache["gaps"]]
        cached_entry = int(cache["whole_program_entry"])
        cached_max_cycle_count = int(cache["max_cycle_count"])

        if boundaries <= cached_pcs and entry == cached_entry:
            # Keep all cached entry spans so the whole-program denominator is
            # independent of which split files were selected.  Per-split
            # candidates are filtered below.
            return cached_gaps, cached_max_cycle_count
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
        pass

    gaps, max_cycle_count = pc_gap.gapAnalysisInSet(
        boundaries,
        test_case.directory / PROG_NAME,
        test_case.directory / TRACE_NAME,
        whole_program_entry=entry,
    )
    if max_cycle_count is None:
        raise ValueError(f"{test_case.title!r}: no cycle counts from entry PC {entry}")
    with cache_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            {
                "boundaries": cached_boundaries,
                "gaps": gaps,
                "whole_program_entry": entry,
                "max_cycle_count": max_cycle_count,
            },
            file,
        )
    return gaps, max_cycle_count


def _process_test_case(
    test_case: TestCase, cases: dict[int, CaseData]
) -> tuple[TestCase, list[ProcCaseData]]:
    all_boundaries = set().union(*(case.boundaries for case in cases.values()))
    points: list[ProcCaseData] = []

    entries = {case.entry for case in cases.values()}
    if len(entries) != 1:
        raise ValueError(f"{test_case.title!r}: inconsistent program entry PCs: {entries}")
    entry = entries.pop()
    gaps, max_cycle_count = _gaps(test_case, all_boundaries, entry)
    # A program can have multiple exits, and the PC numerically closest to an
    # exit need not be the last one executed.  The longest reachable span from
    # entry is therefore the whole-program maximum used by every split. Unlike
    # boundary gaps, this span is allowed to cross every internal boundary.
    if max_cycle_count <= 0:
        raise ValueError(f"{test_case.title!r}: program cycle count must be positive")

    for split_into, case in cases.items():
        candidates = [
            (gap, start_pc, end_pc)
            for start_pc, end_pc, gap in gaps
            if start_pc in case.boundaries
            and end_pc in case.boundaries
            and (start_pc, end_pc) != (case.entry, case.exit)
        ]
        # With no internal boundary, entry -> exit is the only meaningful gap.
        if not candidates:
            # Some datasets represent exit as a sentinel just beyond the last
            # executable PC, so there may be no literal gap ending at it.
            candidates = [(max_cycle_count, case.entry, case.exit)]

        max_gap, start_pc, end_pc = max(candidates)
        if max_gap > max_cycle_count:
            raise ValueError(
                f"{test_case.title!r}: boundary gap {start_pc}->{end_pc} "
                f"({max_gap}) exceeds entry-to-exit count ({max_cycle_count})"
            )
        points.append(
            ProcCaseData(
                times=case.times,
                maxGap=max_gap,
                splitInto=split_into,
                maxGapPair=(start_pc, end_pc),
                maxCycleCount=max_cycle_count,
            )
        )

    return test_case, sorted(points, key=lambda point: point.cycleRatio)


def load_all(files: Iterable[Path]) -> dict[TestCase, list[ProcCaseData]]:
    raw: dict[TestCase, dict[int, CaseData]] = {test_case: {} for test_case in TestCase}

    for path in files:
        try:
            with path.open(encoding="utf-8") as file:
                document = yaml.safe_load(file)
            split_into = int(document["split_into"])
        except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as error:
            raise ValueError(f"{path}: missing or invalid split_into") from error

        for test_case in TestCase:
            if split_into in raw[test_case]:
                raise ValueError(
                    f"duplicate data for {test_case.title!r} with split_into={split_into}"
                )
            raw[test_case][split_into] = _case_from_document(document, path, test_case)

    if not any(raw.values()):
        raise ValueError("no input data files were supplied")

    worker_count = min(len(raw), os.cpu_count() or 1)
    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        results = executor.map(
            _process_test_case,
            raw.keys(),
            raw.values(),
        )
        return dict(results)


loadAll = load_all


def _mean_with_ci(times: np.ndarray) -> tuple[float, float]:
    """Return the sample mean and its two-sided 95% Student-t half-width."""
    mean = float(np.mean(times))
    if times.size < 2:
        return mean, 0.0
    from scipy.stats import t as student_t

    standard_error = float(np.std(times, ddof=1) / np.sqrt(times.size))
    half_width = float(student_t.ppf(0.975, df=times.size - 1) * standard_error)
    return mean, half_width


def _baseline(points: list[ProcCaseData]) -> ProcCaseData:
    try:
        return next(point for point in points if point.splitInto == 1)
    except StopIteration as error:
        raise ValueError("normalizing plots requires data for split_into=1") from error


def _configure_axes(
    axis, title: str, statistic: str, ratios: np.ndarray, lower: np.ndarray, upper: np.ndarray
) -> None:
    axis.set_title(f"{title} — {statistic}")
    axis.set_xlabel("Maximum gap / entry-to-exit cycles")
    axis.set_ylabel("Time / splitInto=1 time")
    axis.set_xscale("linear")
    axis.set_yscale("log")
    axis.set_xticks(ratios)
    axis.tick_params(axis="x", labelrotation=90)
    axis.grid(True, which="both", alpha=0.35)

    min_x = float(ratios.min())
    max_x = float(ratios.max())
    if min_x == max_x:
        # A non-zero span is required by Matplotlib. Keep it inside [0, 1].
        padding = 0.05
        axis.set_xlim(max(0.0, min_x - padding), min(1.0, max_x + padding))
    else:
        axis.set_xlim(min_x, max_x)

    positive_lower = lower[lower > 0]
    if positive_lower.size:
        min_y = float(positive_lower.min())
        max_y = float(upper.max())
        if min_y < max_y:
            axis.set_ylim(min_y, max_y)


def _draw_mean(axis, test_case: TestCase, points: list[ProcCaseData]) -> None:
    x = np.asarray([point.cycleRatio for point in points])
    means, intervals = zip(*(_mean_with_ci(point.times) for point in points))
    baseline_mean, _baseline_interval = _mean_with_ci(_baseline(points).times)
    if baseline_mean <= 0:
        raise ValueError(f"{test_case.title!r}: split_into=1 mean must be positive")
    y = np.asarray(means) / baseline_mean
    ci = np.asarray(intervals) / baseline_mean
    axis.errorbar(x, y, yerr=ci, fmt="o", capsize=4, linestyle="none")
    _configure_axes(axis, test_case.title, "Normalized mean (95% t CI)", x, y - ci, y + ci)


def _draw_median(axis, test_case: TestCase, points: list[ProcCaseData]) -> None:
    x = np.asarray([point.cycleRatio for point in points])
    quartiles = np.asarray([np.percentile(point.times, [25, 50, 75]) for point in points])
    baseline_median = float(np.median(_baseline(points).times))
    if baseline_median <= 0:
        raise ValueError(f"{test_case.title!r}: split_into=1 median must be positive")
    quartiles /= baseline_median
    lower, median, upper = quartiles.T
    axis.errorbar(
        x,
        median,
        yerr=np.vstack((median - lower, upper - median)),
        fmt="o",
        capsize=4,
        linestyle="none",
    )
    _configure_axes(axis, test_case.title, "Normalized median (IQR)", x, lower, upper)


def print_summary(data: dict[TestCase, list[ProcCaseData]]) -> None:
    """Print the maximum-gap boundary pair for every program and split."""
    print("Boundary maximum-gap summary")
    for test_case in TestCase:
        for point in sorted(data.get(test_case, []), key=lambda item: item.splitInto):
            start_pc, end_pc = point.maxGapPair
            print(
                f"{test_case.title}: splitInto={point.splitInto}, "
                f"pair={start_pc}->{end_pc}, max_gap={point.maxGap} cycles, "
                f"program_cycles={point.maxCycleCount}, ratio={point.cycleRatio:.6g}"
            )


def draw(
    data: dict[TestCase, list[ProcCaseData]],
    plot_directory: Path = PLOT_DIRECTORY,
    *,
    show: bool = True,
) -> None:
    import matplotlib.pyplot as plt
    plotters = (("mean", _draw_mean), ("median", _draw_median))
    for statistic, plotter in plotters:
        grouped_figure, grouped_axes = plt.subplots(2, 2, figsize=(12, 8), layout="constrained")
        for axis, test_case in zip(grouped_axes.flat, TestCase):
            points = data.get(test_case, [])
            if not points:
                axis.set_visible(False)
                continue
            plotter(axis, test_case, points)

            if show:
                output_directory = plot_directory / statistic
                output_directory.mkdir(parents=True, exist_ok=True)
                individual_figure, individual_axis = plt.subplots(
                    figsize=(6, 4), layout="constrained"
                )
                plotter(individual_axis, test_case, points)
                individual_figure.savefig(output_directory / f"{test_case.title}.png", dpi=150)
                plt.close(individual_figure)
        grouped_figure.suptitle(f"Normalized timing by relative maximum gap — {statistic.title()}")

        if not show:
            plot_directory.mkdir(parents=True, exist_ok=True)
            grouped_figure.savefig(plot_directory / f"{statistic}.png", dpi=150)

    if show:
        plt.show()
    else:
        plt.close("all")


def _default_files() -> list[Path]:
    numbered_files = []
    for path in DATA_DIRECTORY.glob(LABELED_DATA):
        match = re.fullmatch(r"BENCHMARK_RESULT-(\d+)\.yml", path.name)
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
    data = load_all(files)
    print_summary(data)
    draw(
        data,
        plot_directory=Path.cwd() if args.no_show else PLOT_DIRECTORY,
        show=not args.no_show,
    )


if __name__ == "__main__":
    main()
