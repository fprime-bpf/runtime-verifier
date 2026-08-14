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
    # CALL_1/2/3 (bpf_map_lookup/update/delete_elem) cost: each acquires a real
    # shared_mutex (Components/BpfSequencer/maps/shared_mutex.hpp), not a plain
    # memory access, so they get their own fields instead of reusing miss_cycles.
    # None means "no measurement yet, fall back to miss_cycles" -- see dfs.py.
    map_lookup_cycles: Optional[int] = None   # CALL_1: bpf_map_lookup_elem (shared_lock)
    map_update_cycles: Optional[int] = None   # CALL_2: bpf_map_update_elem (unique_lock)
    map_delete_cycles: Optional[int] = None   # CALL_3: bpf_map_delete_elem (unique_lock)
    # CALL_5/6/7 (bpf_iter_num_new/_next/_destroy) cost: unlike the map helpers
    # above, these are genuinely trivial (Components/BpfSequencer/iter_bpf_helpers.cpp
    # -- a few field reads/writes and a comparison, no mutex, no container), and
    # measured real cost is far below the generic default_helper_call_cost guess.
    # None means "no measurement yet, fall back to default_helper_call_cost".
    iter_new_cycles: Optional[int] = None     # CALL_5: bpf_iter_num_new
    iter_next_cycles: Optional[int] = None    # CALL_6: bpf_iter_num_next
    iter_destroy_cycles: Optional[int] = None # CALL_7: bpf_iter_num_destroy
    # CALL_9/10/11/12 (bpf_math_sqrt/sin/cos/atan2), real libm calls; None falls back to default_helper_call_cost.
    math_sqrt_cycles: Optional[int] = None    # CALL_9: bpf_math_sqrt
    math_sin_cycles: Optional[int] = None     # CALL_10: bpf_math_sin
    math_cos_cycles: Optional[int] = None     # CALL_11: bpf_math_cos
    math_atan2_cycles: Optional[int] = None   # CALL_12: bpf_math_atan2
    latency_overrides: dict[str, int] = field(default_factory=dict)  # instr name -> latency
    cache_mode: str = "realistic"           # "realistic" | "always_hit" | "always_miss" -- see
                                             # dfs.mem_events_to_cycles; bounding variants for WCET
                                             # sensitivity analysis, built via dataclasses.replace()
                                             # on a target's realistic profile (e.g. profiles/polarfire.py)
