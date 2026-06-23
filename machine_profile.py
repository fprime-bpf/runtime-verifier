from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MachineProfile:
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
