from dataclasses import replace
from machine_profile import MachineProfile

# PolarFire SoC / SiFive U54. Reproduces main's pre-profile-system constants exactly,
# including l2_associativity=None/l3_associativity=None -- those tiers were (and
# remain) dead code: nothing ever activated them, so mem_events_to_cycles falls
# straight from L1 to a miss. Not "fixed" here to keep this profile's output
# byte-identical to the prior hardcoded-constant behavior.
#
# latency_overrides is a full, self-contained 278-entry table (every instruction
# bpf.py's BPF_INFO/BPF_INFO_FPU has a latency for), not a partial patch on top of
# bpf.py's base table -- previously this profile had latency_overrides={} and
# every instruction silently fell through to bpf.py's base InstrInfo latency via
# dfs.py's build_op_info_by_name(); noelv.py had its own separate partial-override
# dict on the same shared base. That made it easy to miss that most instructions
# were never independently measured per-target -- they were (and, for anything
# not re-verified since, still are) the exact same number reused for both boards.
# This table's values are unchanged from that base table; only where they live
# has changed, so each profile is now the single source of truth for its own
# instruction timings instead of an implicit shared fallback.
#
# DIV/DIV64/MOD/MOD64, FADD/FADD64/FSUB/FSUB64, and the helper-call fields below
# are the exception: bpf-prime/tests/latency_test.cpp was run directly on real
# PolarFire hardware (not just NOEL-V), giving independent measurements instead
# of carried-over guesses:
#   - CALL_1/2/3 (map lookup/update/delete) previously reused miss_cycles=281
#     as a stand-in, same bug as NOEL-V had -- measured shared_lock/unique_lock
#     (Os::Mutex-backed, see Components/BpfSequencer/maps/shared_mutex.hpp)
#     directly, ceil'd for WCET-conservatism: 540/530 cycles (two independent
#     runs measured 514-515/528 and 539/530; the higher run is used as the
#     bound), not 281.
#   - CALL_5/6/7 (bpf_iter_num_new/_next/_destroy) previously fell through to
#     the flat default_helper_call_cost=100 guess like every other unmeasured
#     helper. Directly measured cost is genuinely tiny (18/19/8 cycles --
#     Components/BpfSequencer/iter_bpf_helpers.cpp shows no mutex, no
#     container), but that number comes from a tight 2000-iteration
#     back-to-back loop that keeps the whole bpf_iter_num struct resident in
#     L1 the entire time. A real BPF program interleaves other memory-
#     touching helper calls (e.g. bpf_map_update_elem, which touches
#     unrelated shared_mutex/Os::Mutex memory) between successive
#     bpf_iter_num_next() calls, so nothing guarantees the struct's cache
#     lines are still warm next time -- the measured number isn't a sound
#     WCET bound on its own. A theoretical fully-cold-every-call bound
#     (distinct 8-byte cache lines touched per call x miss_cycles) came out
#     to ~1142/862/289 -- large, but that's dominated by conservatively
#     assuming every touched line misses independently each call, which is
#     itself uncertain without deeper cache-behavior modeling. Pending a
#     tighter analysis, these fields are set back to the same flat 100 the
#     unmeasured helpers already use -- a round, already-established number
#     safely above the measured floor without leaning on the untested
#     fully-cold assumption. Other still-unmeasured helper IDs (bpf_rand_int,
#     bpf_math_sqrt/sin/cos/atan2) also use default_helper_call_cost=100.
#   - DIV/DIV64/MOD/MOD64 previously gave 32-bit and 64-bit the identical
#     38/34, but measured worst-case (max dividend, divisor=1) is ~36 (32-bit)
#     vs ~67 (64-bit) -- close for 32-bit, ~1.76x low for 64-bit.
#   - FADD/FSUB (32-bit) vs FADD64/FSUB64 (64-bit) already had different base
#     values here (unlike NOEL-V's override, which collapsed them to one
#     number) -- measured data confirms single genuinely costs less than
#     double (~8.3-9.3 cyc vs ~9.6-10.2 cyc), validating that shape, though
#     the prior magnitudes were both somewhat low.
# Everything else in this table is still the original, never-independently-
# verified-on-real-hardware PolarFire numbers.
#
# l1_hit_cycles=4, l2_associativity=16/l2_hit_cycles=16, miss_cycles=210:
# replace the never-measured legacy guesses (8/None+20/281, and the later
# what-if miss_cycles=200 experiment, all superseded now) with a real
# working-set-size latency sweep run on PolarFire hardware -- see
# bpf-prime/tests/latency_test.cpp's run_cache_sweep_tests() (Section 7):
# a pointer-chase over a randomized cyclic permutation confined to a buffer
# of size S, for S from 1KB to 16MB, walked through a volatile-typed
# dereference so -O3 can't delete the timed loop (an earlier run without
# that qualifier silently measured ~0.00 cycles/access at every size).
#
# The resulting curve isn't a simple two-step L1/miss staircase -- it shows
# four distinct transitions that line up with independently-documented
# hardware geometry (PolarFire SoC MSS Technical Reference Manual /
# SiFive U54-MC Core Complex Manual), not just cache capacity:
#   - 1KB-32KB: flat ~3.0-3.3 cyc/access. Matches the documented 32KB U54
#     L1 D-cache exactly, and the manual's stated "2 cycles for word/
#     doubleword" access latency plus ~1 cycle of loop overhead.
#   - 32KB-64KB: jumps to ~14-15 cyc/access and plateaus there briefly --
#     this is the cleanest L2-hit signal available: past L1 capacity, but
#     still well inside the 32-entry fully-associative DTLB's 128KB reach
#     (32 x 4KB pages), so no TLB-miss overhead is mixed in yet.
#   - 128KB-512KB: gradual climb, 15 -> 28 cyc/access. Starts almost
#     exactly at the documented DTLB's 128KB reach boundary -- L1-DTLB
#     misses now blend in, served by the 128-entry unified L2 TLB.
#   - 512KB-1MB: sharp jump to 44 cyc/access, right at the documented
#     L2 TLB's 512KB reach boundary (128 x 4KB) -- real hardware
#     page-table walks start being required.
#   - 2MB-16MB: climbs further to a ~183-199 cyc/access plateau, crossing
#     the documented 2MB L2 cache capacity into genuine DRAM-miss
#     territory (plus persistent page-walk overhead). This lines up with
#     the independent datasheet-derived DRAM floor for this board's actual
#     DRAM chip (Micron MT40A512M16TB-062E:R: tRP+tRCD+CL=41.25ns with no
#     refresh collision -> ~28 cycles @ 667MHz; +tRFC(~350ns) if colliding
#     with an in-progress refresh -> ~261 cycles @ 667MHz) -- the measured
#     ~199-cycle asymptote sits comfortably inside that independently-
#     computed envelope.
# One value (16384 bytes -> 11.16 cyc/access, sandwiched between two
# 3.00 readings at 8192/24576) was excluded as a single SMI-interrupt-
# corrupted sample, the same noise source documented elsewhere in this
# project as requiring SMI-band filtering on hardware runs.
#
# Values taken: l1_hit_cycles=4 (measured ~3.0-3.3, rounded up for margin).
# miss_cycles=210 (measured ~199-cycle asymptote, rounded up for margin;
# supersedes both the original unverified 281 and the miss_cycles=200
# what-if experiment). The 128KB-1MB region's TLB-walk overhead isn't
# cleanly separable from true L2/DRAM cost with this test as designed
# (buffer footprint in distinct pages scales with size regardless of cache
# tier) -- these numbers are the best real-hardware evidence available, not
# claimed to be TLB-effect-free.
#
# l1_associativity=1, l2_associativity=1 (NOT the L2's real 16-way geometry
# -- see below): the U54-MC Core Complex Manual states, independently for
# each of the L1 icache, L1 dcache, AND the L2 cache, that all three use a
# genuinely random replacement policy, not LRU/pseudo-LRU (contrast: the L1
# and L2 unified TLBs are explicitly pseudo-LRU -- this only applies to the
# data/instruction caches). mem_events_to_cycles's classification --
# "recency < associativity implies a safe hit" -- is only sound for
# LRU-family policies, where recency directly bounds eviction (an LRU cache
# guarantees a line survives at least `associativity` accesses to its set).
# Random replacement gives no such window: once any intervening access
# misses into the same set, the victim is chosen uniformly at random among
# all ways, including the line in question. The only access recency this
# model can prove safe under random replacement is recency==0 -- the
# literal immediately-preceding access, with nothing yet having had a
# chance to trigger an eviction draw. `recency < associativity` degenerates
# to exactly `recency == 0` when associativity=1, which is what both fields
# are set to here.
# This is more conservative than real hardware's average-case behavor
# (Section 7's sweep clearly shows genuine, frequent L2 hits in the
# 49KB-64KB range, ~14-15 cyc/access) -- but that's an artifact of
# mem_events_to_cycles tracking one flat recency count across all touched
# addresses with no real set-index modeling, not just associativity vs. 1.
# It can't distinguish "3 other accesses happened, none conflicting with
# this line's set" (real hardware: still safe) from "3 other accesses
# happened, one conflicting" (real hardware: may have evicted it) --
# tightening associativity to 1 is the soundest fix achievable without
# adding real per-set conflict tracking to dfs.py. Setting
# l2_associativity=1 makes the L2 branch in mem_events_to_cycles
# permanently unreachable (recency==0 is already consumed by the L1 check
# first) -- i.e. this reverts to a 2-tier L1/miss model, same structural
# shape as when l2_associativity was None, just for a different reason
# (proven-unsound-to-model, not unmeasured).
POLARFIRE_PROFILE = MachineProfile(
    name="polarfire",
    latency=None,
    line_size_bytes=4,
    l1_associativity=1,
    l1_hit_cycles=4,
    l2_associativity=1,
    l2_hit_cycles=16,
    l3_associativity=None,
    l3_hit_cycles=40,
    miss_cycles=210,
    cpu_freq_hz=6.67e8,
    cache_size=64,
    default_helper_call_cost=100,
    map_lookup_cycles=540,
    map_update_cycles=530,
    map_delete_cycles=530,
    iter_new_cycles=100,
    iter_next_cycles=100,
    iter_destroy_cycles=100,
    latency_overrides={
        "ADD64_K": 5,
        "ADD64_X": 1,
        "ADD_K": 5,
        "ADD_X": 1,
        "AND64_K": 5,
        "AND64_X": 1,
        "AND_K": 5,
        "AND_X": 1,
        "ARSH64_K": 1,
        "ARSH64_X": 1,
        "ARSH_K": 1,
        "ARSH_X": 1,
        "ATOMIC_ADD_DW": 8,
        "ATOMIC_ADD_FETCH_DW": 8,
        "ATOMIC_ADD_FETCH_W": 8,
        "ATOMIC_ADD_W": 8,
        "ATOMIC_AND_DW": 8,
        "ATOMIC_AND_FETCH_DW": 8,
        "ATOMIC_AND_FETCH_W": 8,
        "ATOMIC_AND_W": 8,
        "ATOMIC_CMPXCHG_DW": 8,
        "ATOMIC_CMPXCHG_W": 8,
        "ATOMIC_OR_DW": 8,
        "ATOMIC_OR_FETCH_DW": 8,
        "ATOMIC_OR_FETCH_W": 8,
        "ATOMIC_OR_W": 8,
        "ATOMIC_XCHG_DW": 8,
        "ATOMIC_XCHG_W": 8,
        "ATOMIC_XOR_DW": 8,
        "ATOMIC_XOR_FETCH_DW": 8,
        "ATOMIC_XOR_FETCH_W": 8,
        "ATOMIC_XOR_W": 8,
        "DIV64_K": 71,
        "DIV64_X": 67,
        "DIV_K": 41,
        "DIV_X": 37,
        "EXIT": 2,
        "FADD64_K": 18,
        "FADD64_X": 11,
        "FADD_K": 16,
        "FADD_X": 9,
        "FDIV64_K": 27,
        "FDIV64_X": 20,
        "FDIV_K": 27,
        "FDIV_X": 20,
        "FLDX_B": 11,
        "FLDX_DW": 11,
        "FLDX_H": 11,
        "FLDX_W": 11,
        "FLD_B": 11,
        "FLD_DW": 11,
        "FLD_H": 11,
        "FLD_W": 11,
        "FMOV64_K": 7,
        "FMOV64_X": 7,
        "FMOV_K": 7,
        "FMOV_X": 7,
        "FMUL64_K": 14,
        "FMUL64_X": 7,
        "FMUL_K": 12,
        "FMUL_X": 5,
        "FNEG64_K": 3,
        "FNEG64_X": 3,
        "FNEG_K": 3,
        "FNEG_X": 3,
        "FSTX_B": 11,
        "FSTX_DW": 11,
        "FSTX_H": 11,
        "FSTX_W": 11,
        "FST_B": 11,
        "FST_DW": 11,
        "FST_H": 11,
        "FST_W": 11,
        "FSUB64_K": 18,
        "FSUB64_X": 11,
        "FSUB_K": 17,
        "FSUB_X": 10,
        "JA": 2,
        "JEQ32_K": 7,
        "JEQ32_X": 3,
        "JEQ_K": 7,
        "JEQ_X": 3,
        "JFEQ32_K": 10,
        "JFEQ32_X": 3,
        "JFEQ_K": 10,
        "JFEQ_X": 3,
        "JFNE32_K": 10,
        "JFNE32_X": 3,
        "JFNE_K": 10,
        "JFNE_X": 3,
        "JFOGE32_K": 10,
        "JFOGE32_X": 3,
        "JFOGE_K": 10,
        "JFOGE_X": 3,
        "JFOGT32_K": 10,
        "JFOGT32_X": 3,
        "JFOGT_K": 10,
        "JFOGT_X": 3,
        "JFOLE32_K": 10,
        "JFOLE32_X": 3,
        "JFOLE_K": 10,
        "JFOLE_X": 3,
        "JFOLT32_K": 10,
        "JFOLT32_X": 3,
        "JFOLT_K": 10,
        "JFOLT_X": 3,
        "JFUGE32_K": 15,
        "JFUGE32_X": 8,
        "JFUGE_K": 15,
        "JFUGE_X": 8,
        "JFUGT32_K": 15,
        "JFUGT32_X": 8,
        "JFUGT_K": 15,
        "JFUGT_X": 8,
        "JFULE32_K": 15,
        "JFULE_32X": 8,
        "JFULE_K": 15,
        "JFULE_X": 8,
        "JFULT32_K": 15,
        "JFULT32_X": 8,
        "JFULT_K": 15,
        "JFULT_X": 8,
        "JGE32_K": 7,
        "JGE32_X": 3,
        "JGE_K": 7,
        "JGE_X": 3,
        "JGT32_K": 7,
        "JGT32_X": 3,
        "JGT_K": 7,
        "JGT_X": 3,
        "JLE32_K": 7,
        "JLE32_X": 3,
        "JLE_K": 7,
        "JLE_X": 3,
        "JLT32_K": 7,
        "JLT32_X": 3,
        "JLT_K": 7,
        "JLT_X": 3,
        "JNE32_K": 7,
        "JNE32_X": 3,
        "JNE_K": 7,
        "JNE_X": 3,
        "JSET32_K": 8,
        "JSET32_X": 4,
        "JSET_K": 8,
        "JSET_X": 4,
        "JSGE32_K": 7,
        "JSGE32_X": 3,
        "JSGE_K": 7,
        "JSGE_X": 3,
        "JSGT32_K": 7,
        "JSGT32_X": 3,
        "JSGT_K": 7,
        "JSGT_X": 3,
        "JSLE32_K": 7,
        "JSLE32_X": 3,
        "JSLE_K": 7,
        "JSLE_X": 3,
        "JSLT32_K": 7,
        "JSLT32_X": 3,
        "JSLT_K": 7,
        "JSLT_X": 3,
        "LDDW": 11,
        "LDX_ABS_B": 11,
        "LDX_ABS_DW": 11,
        "LDX_ABS_H": 11,
        "LDX_ABS_W": 11,
        "LDX_B": 11,
        "LDX_DW": 11,
        "LDX_H": 11,
        "LDX_IMM_B": 11,
        "LDX_IMM_DW": 11,
        "LDX_IMM_H": 11,
        "LDX_IMM_W": 11,
        "LDX_IND_B": 11,
        "LDX_IND_DW": 11,
        "LDX_IND_H": 11,
        "LDX_IND_W": 11,
        "LDX_MEMSX_B": 11,
        "LDX_MEMSX_DW": 11,
        "LDX_MEMSX_H": 11,
        "LDX_MEMSX_W": 11,
        "LDX_W": 11,
        "LD_ABS_B": 11,
        "LD_ABS_DW": 11,
        "LD_ABS_H": 11,
        "LD_ABS_W": 11,
        "LD_IMM_B": 11,
        "LD_IMM_H": 11,
        "LD_IMM_W": 11,
        "LD_IND_B": 11,
        "LD_IND_DW": 11,
        "LD_IND_H": 11,
        "LD_IND_W": 11,
        "LD_MEMSX_B": 11,
        "LD_MEMSX_DW": 11,
        "LD_MEMSX_H": 11,
        "LD_MEMSX_W": 11,
        "LD_MEM_B": 11,
        "LD_MEM_DW": 11,
        "LD_MEM_H": 11,
        "LD_MEM_W": 11,
        "LSH64_K": 1,
        "LSH64_X": 1,
        "LSH_K": 1,
        "LSH_X": 1,
        "MOD64_K": 71,
        "MOD64_X": 67,
        "MOD_K": 41,
        "MOD_X": 37,
        "MOV64_K": 4,
        "MOV64_X": 4,
        "MOV_K": 4,
        "MOV_X": 4,
        "MUL64_K": 14,
        "MUL64_X": 10,
        "MUL_K": 14,
        "MUL_X": 10,
        "NEG64_K": 0,
        "NEG64_X": 0,
        "NEG_K": 0,
        "NEG_X": 0,
        "OR64_K": 5,
        "OR64_X": 1,
        "OR_K": 5,
        "OR_X": 1,
        "RSH64_K": 1,
        "RSH64_X": 1,
        "RSH_K": 1,
        "RSH_X": 1,
        "STX_ABS_B": 11,
        "STX_ABS_DW": 11,
        "STX_ABS_H": 11,
        "STX_ABS_W": 11,
        "STX_B": 11,
        "STX_DW": 11,
        "STX_H": 11,
        "STX_IMM_B": 11,
        "STX_IMM_DW": 11,
        "STX_IMM_H": 11,
        "STX_IMM_W": 11,
        "STX_IND_B": 11,
        "STX_IND_DW": 11,
        "STX_IND_H": 11,
        "STX_IND_W": 11,
        "STX_MEMSX_B": 11,
        "STX_MEMSX_DW": 11,
        "STX_MEMSX_H": 11,
        "STX_MEMSX_W": 11,
        "STX_W": 11,
        "ST_ABS_B": 11,
        "ST_ABS_DW": 11,
        "ST_ABS_H": 11,
        "ST_ABS_W": 11,
        "ST_B": 11,
        "ST_DW": 11,
        "ST_H": 11,
        "ST_IMM_B": 11,
        "ST_IMM_DW": 11,
        "ST_IMM_H": 11,
        "ST_IMM_W": 11,
        "ST_IND_B": 11,
        "ST_IND_DW": 11,
        "ST_IND_H": 11,
        "ST_IND_W": 11,
        "ST_MEMSX_B": 11,
        "ST_MEMSX_DW": 11,
        "ST_MEMSX_H": 11,
        "ST_MEMSX_W": 11,
        "ST_W": 11,
        "SUB64_K": 5,
        "SUB64_X": 1,
        "SUB_K": 5,
        "SUB_X": 1,
        "XOR64_K": 5,
        "XOR64_X": 1,
        "XOR_K": 5,
        "XOR_X": 1,
    },
)

# Bounding variants for WCET sensitivity analysis: same target (same clock, same
# instruction latencies), but every load is charged as a guaranteed L1 hit or a
# guaranteed miss instead of being classified by recency/associativity -- gives a
# best-case/worst-case bracket around POLARFIRE_PROFILE's realistic estimate.
POLARFIRE_ALL_HIT_PROFILE = replace(POLARFIRE_PROFILE, name="polarfire_all_hit", cache_mode="always_hit")
POLARFIRE_ALL_MISS_PROFILE = replace(POLARFIRE_PROFILE, name="polarfire_all_miss", cache_mode="always_miss")
