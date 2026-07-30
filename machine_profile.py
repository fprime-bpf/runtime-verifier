from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class MachineProfile:
    """Doubles as two granularities of the same shape: a per-instruction profile
    (as built by dfs.build_op_info_by_name, one per BPF instruction name) and a
    per-target profile (one instance per hardware target, e.g. profiles/polarfire.py).
    The cache model is flat/uniform across instructions on every target today, so
    these are the same fields either way; cpu_freq_hz/cache_size/
    default_helper_call_cost/latency_overrides are only meaningful on the
    per-target instance and are simply unused (but harmlessly present, via
    dataclasses.replace()) on per-instruction copies."""
    name: str
    latency: Optional[int]                  # None means unknown/unmeasured
    line_size_bytes: Optional[int] = None   # cache line size in bytes; None for non-memory instructions
    l1_associativity: Optional[int] = None  # L1 N-way associativity threshold
    l2_associativity: Optional[int] = None  # L2 N-way associativity threshold (inclusive: cumulative from L1)
    l3_associativity: Optional[int] = None  # L3 N-way associativity threshold (inclusive: cumulative from L1)
    l1_hit_cycles: Optional[int] = None
    l2_hit_cycles: Optional[int] = None
    l3_hit_cycles: Optional[int] = None
    miss_cycles: Optional[int] = None
    cpu_freq_hz: Optional[float] = None
    cache_size: Optional[int] = None        # bounds State.recent_window's length
    default_helper_call_cost: Optional[int] = None
    latency_overrides: dict[str, int] = field(default_factory=dict)  # instr name -> latency
    cache_mode: str = "realistic"           # "realistic" | "always_hit" | "always_miss" -- see
                                             # dfs.mem_events_to_cycles; bounding variants for WCET
                                             # sensitivity analysis, built via dataclasses.replace()
                                             # on a target's realistic profile (e.g. profiles/polarfire.py)
