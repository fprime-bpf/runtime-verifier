from dataclasses import replace
from machine_profile import MachineProfile

# PolarFire SoC / SiFive U54. Reproduces main's pre-profile-system constants exactly,
# including l2_associativity=None/l3_associativity=None -- those tiers were (and
# remain) dead code: nothing ever activated them, so mem_events_to_cycles falls
# straight from L1 to a miss. Not "fixed" here to keep this profile's output
# byte-identical to the prior hardcoded-constant behavior.
POLARFIRE_PROFILE = MachineProfile(
    name="polarfire",
    latency=None,
    line_size_bytes=4,
    l1_associativity=8,
    l1_hit_cycles=8,
    l2_associativity=None,
    l2_hit_cycles=20,
    l3_associativity=None,
    l3_hit_cycles=40,
    miss_cycles=281,
    cpu_freq_hz=6.67e8,
    cache_size=64,
    default_helper_call_cost=100,
)

# Bounding variants for WCET sensitivity analysis: same target (same clock, same
# instruction latencies), but every load is charged as a guaranteed L1 hit or a
# guaranteed miss instead of being classified by recency/associativity -- gives a
# best-case/worst-case bracket around POLARFIRE_PROFILE's realistic estimate.
POLARFIRE_ALL_HIT_PROFILE = replace(POLARFIRE_PROFILE, name="polarfire_all_hit", cache_mode="always_hit")
POLARFIRE_ALL_MISS_PROFILE = replace(POLARFIRE_PROFILE, name="polarfire_all_miss", cache_mode="always_miss")
