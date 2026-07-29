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
