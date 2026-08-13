from dataclasses import replace
from machine_profile import MachineProfile

# NOEL-V FPGA soft-core. latency_overrides is a full, self-contained 278-entry
# table (every instruction bpf.py's BPF_INFO/BPF_INFO_FPU has a latency for), not
# a partial patch on top of a shared base table -- previously this profile only
# listed the ~131 entries independently measured/retuned for NOEL-V, and every
# other instruction silently fell through to bpf.py's base (PolarFire-derived)
# latency via dfs.py's build_op_info_by_name(). That made it easy to miss that
# most instructions were never independently verified per-target. This table's
# values are unchanged from before (the ~131 previously-overridden entries keep
# their NOEL-V-specific values; everything else is still the same PolarFire-
# derived number it always was) -- only where they live has changed, so this
# profile is now the single source of truth for its own instruction timings.
# See project memory (project_noelv_wcet_calibration) for the provenance of the
# entries that ARE independently measured for NOEL-V (DIV/MOD, map helper calls,
# stores, LDDW) vs. the majority that are still an unverified carryover.
#
# MUL_X=8 (was 2), MUL64_X=9 (was 2), MUL_K=12 (was 6), MUL64_K=13 (was 6):
# the old value of 2 was never independently measured -- traced it through
# grlib-gpl-2026.2-b4300's RTL and it's real but incomplete. mul64.vhd's
# multiply datapath (designs/noelv-xilinx-zcu102/cfg/config_local.vhd sets
# CFG_LOCAL_MULCONF=0, selecting mul64.vhd's split=0 path, which routes
# through techmult with generic num_stages=2 -- "number of pipeline
# stages", an explicit RTL constant) genuinely is a 2-cycle pipeline, which
# is exactly where the old value of 2 came from. But that's only the bare
# functional-unit latency, not the full instruction cost software
# experiences -- iunv.vhd (the main pipeline datapath) has a dedicated
# hazard interlock for this, `INFO_HOLD_RAW_MULDIV` / `ex_hold_pc_muldiv`
# ("Hold PC due to Mul/Div Unit"), confirming the core does insert a real
# stall around MUL/DIV register dependencies beyond the bare 2-cycle
# datapath -- but pinning the exact stall-cycle count would mean tracing
# much more of iunv.vhd's combined hold network (16000+ lines, hold
# reasons from many sources merged together) than was practical here.
# Given the interlock is confirmed to exist but not fully quantified from
# RTL alone, used the real hardware measurement instead (bpf-prime/tests/
# latency_test.cpp Section 2's "MUL/MUL64" block, register-register `mul`
# for the 64-bit BPF ops and `mulw` for the 32-bit ops): mul worst=8.42
# cyc (ceil 9) -> MUL64_X; mulw worst=7.04 cyc (ceil 8) -> MUL_X. K-shape
# (immediate) values keep the existing +4 K-vs-X delta convention used
# throughout this table (no native RISC-V multiply-immediate exists, so a
# BPF MUL_K/MUL64_K has to materialize the immediate first). `mulh large`
# (6.51 cyc) was also measured but isn't used -- eBPF has no high-multiply
# opcode, so nothing in latency_overrides maps to it.
#
# DIV/DIV64/MOD/MOD64 were re-measured in the same run (worst-case: divu
# ~40.41, remu ~41.49, divuw ~24.32, remuw ~24.42) and left UNCHANGED --
# consistent with the existing values (DIV64_X=42/DIV_X=26, from the
# original ~41/~25 measurement documented in project memory), well within
# normal run-to-run noise. One row from this same run, "divuw typical
# (1e6/7)" at 236.81 cyc, was excluded as a corrupted sample -- a
# "typical" case can't legitimately cost 10x more than the deliberately
# adversarial worst-case operands (max dividend, divisor=1) on this
# leading-zero-skip SRT divider, matching the SMI/interrupt noise pattern
# documented elsewhere in this project.
#
# FADD_X=FSUB_X=22 (was 16), FADD64_X=FSUB64_X=23 (was 16), FADD_K=FSUB_K=26
# (was 20), FADD64_K=FSUB64_K=27 (was 20): CFG_LOCAL_FPUCONF=0 in this
# board's config_local.vhd selects nanofpunv over pipefpunv -- its own file
# header calls it "a small non-pipelined IEEE754-2008 compliant
# implementation", a completely different design from mul64.vhd's pipelined
# datapath. Its ADD/SUB path is a literal FSM walk (nf_flopr -> nf_flop0 ->
# nf_flop1 -> nf_addsub2 -> nf_addsub25 -> nf_addsub3 -> [nf_addsub4] ->
# nf_addsub5 -> nf_addsub6 -> nf_addsub7 -> nf_round -> nf_repack ->
# nf_opdone -> nf_rdwrite -> nf_rdwrite2), one state per cycle, which is why
# the cost is so much higher than integer ALU ops -- no further hazard-
# interlock tracing was needed here since the FSM already fully accounts
# for the latency (unlike MUL, there's no separate functional-unit-vs-
# pipeline-hold gap to explain). nf_addsub4 only fires when r.rddp='1'
# (double precision); single precision jumps addsub3 -> addsub5 directly --
# a real, RTL-confirmed 1-state/1-cycle single-vs-double gap, which is why
# this profile now distinguishes FADD_X from FADD64_X (previously identical
# at 16, since the double-vs-single split had never been measured/verified).
# Values are the worst measured cost from bpf-prime/tests/latency_test.cpp
# Section 2's "FADD/FSUB (single)"/"(double)" blocks (normal/subnormal/
# maximal-cancellation operand shapes all measured, since the FSM has no
# leading-zero-skip shortcut the way the divider does, so no case should
# create a wide best/worst gap -- confirmed by the tight ~20.3-21.0 single /
# 21.2-22.8 double clustering) rounded up to the nearest whole cycle for
# soundness: single worst = fsub.s cancel 21.02 cyc -> ceil 22; double worst
# = fadd.d normal 22.78 cyc -> ceil 23. K-shape (immediate) values keep the
# same +4 K-vs-X delta convention as MUL (no float-add-immediate exists in
# RISC-V either).
#
# FADD/FSUB_X=23 (was 22, single now matches double), FMUL64_X=100/K=104, FMUL_X=75/K=79, FDIV64_X=128/K=132, FDIV_X=45/K=49, FMOV/FNEG(64)_X/K=15 (was 22-26/40-44/4/16): re-measured Section 2 -- FMUL/FDIV were badly underestimated (fmul.d=99.76, fmul.s=74.50, fdiv.d=127.36, fdiv.s=44.88 cyc, ceiled), excluding fsub.d normal(163.58 cyc)/mul small(78.15 cyc) as SMI-corrupted (inconsistent with their own tight same-category clusters, same pattern as the earlier-excluded divuw typical). FMOV/FNEG unified across precision at 15 (fmv.d=13.49, fneg.s=14.81, fmv.s=14.06 cyc) since nanofpunv.vhd's nf_sgn2 state (handles FSGNJ/FSGNJN/FSGNJX, i.e. fneg/fmv) is a single-state FSM step straight to nf_opdone regardless of rddp, unlike FADD/FSUB/FMUL/FDIV's long chains -- RTL-confirms no precision-dependent cost, so fneg.d's 77.04 cyc sample is excluded as corrupted too.
#
# line_size_bytes=32, l1_associativity=1 (was 4), l2_associativity=4 (was 12):
# traced directly through this board's GRLIB source (grlib-gpl-2026.2-b4300,
# designs/noelv-xilinx-zcu102), not measured -- config.vhd's CFG_CFG=768
# selects the "GP" entry (index 1) of noelv_cpu_cfg.vhd's cfg_a table, which
# gives L1 icache/dcache (shared cctrl5nv controller): iways=dways=4,
# ilinesize=dlinesize=8 words = 32 bytes/line (GRIP manual: "cache line size
# in number of words", 32-bit words). L2 (l2c) comes straight from
# config.vhd: CFG_L2_WAYS=4, CFG_L2_LSZ=32 (GRIP manual states this generic
# directly in bytes, no word conversion needed) -- both hierarchy levels
# land on the same 32-byte line size, confirmed via two independent unit
# conventions.
#
# Associativity is NOT set to the real way-counts, though -- same reasoning
# as PolarFire's random-replacement fix (see profiles/polarfire.py), but
# split differently here since L1 and L2 use different replacement
# policies on this specific hardware:
#   - L1: cpucorenvbc.vhd line ~693 hardcodes `rnd_repl => 1` on the
#     cctrl5nv instantiation -- not even a per-design config option, this
#     is baked into the RTL. Random replacement gives no N-access-survival
#     guarantee, so mem_events_to_cycles's `recency < associativity` check
#     is only sound at recency==0 (l1_associativity=1), exactly like
#     PolarFire's L1/L2.
#   - L2: config.vhd's CFG_L2_RAN=0, and l2c.in.help is explicit --
#     "Say Y here to enable random replacement policy rather than the
#     default LRU" -- so 0 means this L2 genuinely runs LRU. LRU actually
#     does guarantee a line survives `associativity`-many accesses to its
#     set, and mem_events_to_cycles's flat (not per-set) recency count can
#     only ever OVER-count real conflict pressure (every real same-set
#     access is a subset of "everything touched"), which pushes
#     classification toward "miss" more readily than reality -- the safe
#     direction for a WCET bound. So l2_associativity=4 (the real,
#     RTL-confirmed way-count) is sound here, unlike PolarFire where L2 also
#     had to collapse to 1. (The GRIP manual describes this L2C as
#     non-inclusive -- "data may exist in the Level-1 and Level-2 cache, or
#     only in the Level-1 or Level-2 cache" -- but since it fills both
#     levels together on the shared AHB-bridge miss path and only diverges
#     via each level's later independent eviction, the over-counting
#     argument above still holds.)
# l1_hit_cycles=3/l2_hit_cycles=16 unchanged; miss_cycles=60 (was 100, before that 300) -- a 2MB-hugepage re-run of the working-set sweep (bpf-prime/tests/latency_test.cpp Section 7) fixed a TLB confound in the original 4KB-page run: real DRAM cost is ~53.69 cyc/16MB (not ~92), and L2's real 256KB capacity now shows a clean jump right at that boundary instead of a smeared climb.
#
# iter_new/next_cycles=120, iter_destroy_cycles=60 (was 200/200/100): re-derived cost=lines_touched(2,2,1)*miss_cycles now that miss_cycles=60 (these were never updated after that fix, still used the old 100). Re-measured Section 5 (steady non-NULL: new=26.15/next=14.85/destroy=6.70 cyc) still far below this cold bound, so the model stays sound but not tight -- no per-call warm/cold split exists since traces are order-losing per-path histograms.
#
# map_lookup/update/delete_cycles=240/360/120 (was 650/800/200): re-measured actuals from the new lock-free-map hardware run (BENCHMARK_RESULTS_wamr_noelv.yml, SMI-filtered/50-sample-warmup-cut worst-case) are 4-76x below each benchmark's non-map instruction cost alone, so kalman no longer binds and the original lines-touched*miss_cycles structural estimate (from array_map's real field layout under kMapsAllowRaces=true) is sound with wide margin -- no need for the padded 650/800/200.
#
# ADD_K=ADD64_K=AND_K=AND64_K=OR_K=OR64_K=SUB_K=SUB64_K=XOR_K=XOR64_K=20
# (was 5): these were still using the old flat "+4 over X" delta
# convention, never independently measured. bpf-prime/tests/
# latency_test.cpp's "Immediate-operand ALU (_K shape)" block measures the
# real RISC-V codegen for a BPF `_K` op: an eBPF K-field immediate is a
# full 32-bit value, and 32 bits doesn't fit RISC-V's 12-bit `addi`
# immediate field, so the JIT has to materialize it via a multi-
# instruction `li` sequence (lui+addi) before the actual add -- measured
# "li (32-bit const) + add" at 16.77-19.84 cyc across two runs (ceil'd
# worst: 20). This applies uniformly to the ADD/AND/OR/SUB/XOR K-shape
# family (32- and 64-bit alike, since eBPF's K field is the same 32-bit
# immediate regardless of ALU width) -- the materialization cost dominates
# and doesn't depend on which op follows it. Small-immediate `addi` alone
# (fits 12 bits, no `li` needed) measured only 6.61-6.80 cyc, but can't be
# assumed as the general case since arbitrary 32-bit BPF constants aren't
# guaranteed to fit 12 bits -- using the worst case (large immediate) for
# soundness. Deliberately NOT touched here: LSH_K/RSH_K/ARSH_K (shift-by-
# immediate uses slli/srli/srai, whose 6-bit shift-amount field always
# fits an eBPF shift count 0-63 in one instruction -- no `li` needed, so
# this family doesn't apply), MOV_K/MOV64_K (a `li` alone with no trailing
# op -- no direct isolated measurement of just `li`, left as a follow-up),
# and the ADD_X/AND_X/etc. *register-shape* base costs (still 1, per the
# unresolved compressed-vs-uncompressed-JIT-codegen question flagged
# separately -- measured Simple ALU ops cluster 5.78-6.90 cyc here too,
# but it's not yet known how much of that is real execute cost vs. an
# artifact of this benchmark's uncompressed 4-byte-instruction fetch
# pattern, which may not represent real RVC-compressed JIT output).
#
# ADD_X=ADD64_X=5, AND_X=AND64_X=OR_X=OR64_X=XOR_X=XOR64_X=SUB_X=SUB64_X=
# LSH_X=LSH64_X=RSH_X=RSH64_X=ARSH_X=ARSH64_X=8 (all were 1): the
# compressed-vs-uncompressed question above is RESOLVED for `add`, still
# open for the rest. Added a "Simple ALU (compressed, BPF dst-op=-src
# shape)" block to latency_test.cpp using the real eBPF ALU_X shape
# (`dst op= src`, 2-operand accumulate -- confirmed via objdump this
# compiles to the 2-byte RVC form for add/and/or/xor/sub, never for
# sll/srl/sra since RVC has no register-register shift at all), plus an
# `.option norvc`-forced control for `add` (identical instruction,
# identical dependency chain, only the encoding width differs) to
# isolate the effect cleanly: "add (forced uncompressed, dependent)"
# measured 6.31 cyc vs. "add (compressed, dependent)" measured 4.14 cyc --
# same op, same chain, ~2.2 cyc saved purely from the 2-byte encoding.
# This confirms the fetch-width theory for `add` specifically.
# ADD_X/ADD64_X=5 uses that compressed measurement (ceil'd) directly,
# since `C.ADD` (CR-format) has no register-class restriction beyond
# rd/rs2 != x0 -- essentially guaranteed for any real BPF register op, so
# assuming compression here is safe. AND/OR/XOR/SUB, though, use `C.AND`/
# `C.OR`/`C.XOR`/`C.SUB` (CA-format), which additionally require BOTH
# registers to land in the restricted x8-x15 range (s0/s1/a0-a5) --
# whether `llvmbpf`'s register allocator reliably lands there for
# arbitrary eBPF register pairs is unverified, so these (and SUB, and the
# shifts, which never compress at all) stay at the conservative
# uncompressed worst-case instead: ceil(7.11), the highest uncompressed
# reading across all 3 measurement runs of both the original independent-
# operand block and this one's forced-uncompressed variants (which track
# each other closely, confirming the dependency-chain shape itself
# doesn't matter -- only encoding width does).
NOELV_PROFILE = MachineProfile(
    name="noelv",
    latency=None,
    line_size_bytes=32,
    l1_associativity=1,
    l1_hit_cycles=3,
    l2_associativity=4,
    l2_hit_cycles=16,
    l3_associativity=None,
    l3_hit_cycles=None,
    miss_cycles=60,
    cpu_freq_hz=1e8,
    cache_size=12,
    default_helper_call_cost=150,
    iter_new_cycles=120,
    iter_next_cycles=120,
    iter_destroy_cycles=60,
    map_lookup_cycles=240,
    map_update_cycles=360,
    map_delete_cycles=120,
    latency_overrides={
        "ADD64_K": 20,
        "ADD64_X": 5,
        "ADD_K": 20,
        "ADD_X": 5,
        "AND64_K": 20,
        "AND64_X": 8,
        "AND_K": 20,
        "AND_X": 8,
        "ARSH64_K": 1,
        "ARSH64_X": 8,
        "ARSH_K": 1,
        "ARSH_X": 8,
        "ATOMIC_ADD_DW": 8,
        "ATOMIC_ADD_FETCH_DW": 8,
        "ATOMIC_ADD_FETCH_W": 8,
        "ATOMIC_ADD_W": 8,
        "ATOMIC_AND_DW": 8,
        "ATOMIC_AND_FETCH_DW": 8,
        "ATOMIC_AND_FETCH_W": 8,
        "ATOMIC_AND_W": 8,
        "ATOMIC_CMPXCHG_DW": 17,
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
        "DIV64_K": 46,
        "DIV64_X": 42,
        "DIV_K": 30,
        "DIV_X": 26,
        "EXIT": 2,
        "FADD64_K": 27,
        "FADD64_X": 23,
        "FADD_K": 27,
        "FADD_X": 23,
        "FDIV64_K": 132,
        "FDIV64_X": 128,
        "FDIV_K": 49,
        "FDIV_X": 45,
        "FLDX_B": 11,
        "FLDX_DW": 11,
        "FLDX_H": 11,
        "FLDX_W": 11,
        "FLD_B": 11,
        "FLD_DW": 11,
        "FLD_H": 11,
        "FLD_W": 11,
        "FMOV64_K": 15,
        "FMOV64_X": 15,
        "FMOV_K": 15,
        "FMOV_X": 15,
        "FMUL64_K": 104,
        "FMUL64_X": 100,
        "FMUL_K": 79,
        "FMUL_X": 75,
        "FNEG64_K": 15,
        "FNEG64_X": 15,
        "FNEG_K": 15,
        "FNEG_X": 15,
        "FSTX_B": 11,
        "FSTX_DW": 11,
        "FSTX_H": 11,
        "FSTX_W": 30,
        "FST_B": 11,
        "FST_DW": 11,
        "FST_H": 11,
        "FST_W": 11,
        "FSUB64_K": 27,
        "FSUB64_X": 23,
        "FSUB_K": 27,
        "FSUB_X": 23,
        "JA": 2,
        "JEQ32_K": 8,
        "JEQ32_X": 4,
        "JEQ_K": 8,
        "JEQ_X": 4,
        "JFEQ32_K": 22,
        "JFEQ32_X": 18,
        "JFEQ_K": 22,
        "JFEQ_X": 18,
        "JFNE32_K": 22,
        "JFNE32_X": 18,
        "JFNE_K": 22,
        "JFNE_X": 18,
        "JFOGE32_K": 22,
        "JFOGE32_X": 18,
        "JFOGE_K": 22,
        "JFOGE_X": 18,
        "JFOGT32_K": 22,
        "JFOGT32_X": 18,
        "JFOGT_K": 22,
        "JFOGT_X": 18,
        "JFOLE32_K": 22,
        "JFOLE32_X": 18,
        "JFOLE_K": 22,
        "JFOLE_X": 18,
        "JFOLT32_K": 22,
        "JFOLT32_X": 18,
        "JFOLT_K": 22,
        "JFOLT_X": 18,
        "JFUGE32_K": 22,
        "JFUGE32_X": 18,
        "JFUGE_K": 22,
        "JFUGE_X": 18,
        "JFUGT32_K": 22,
        "JFUGT32_X": 18,
        "JFUGT_K": 22,
        "JFUGT_X": 18,
        "JFULE32_K": 22,
        "JFULE_32X": 18,
        "JFULE_K": 22,
        "JFULE_X": 18,
        "JFULT32_K": 22,
        "JFULT32_X": 18,
        "JFULT_K": 22,
        "JFULT_X": 18,
        "JGE32_K": 8,
        "JGE32_X": 4,
        "JGE_K": 8,
        "JGE_X": 4,
        "JGT32_K": 8,
        "JGT32_X": 4,
        "JGT_K": 8,
        "JGT_X": 4,
        "JLE32_K": 8,
        "JLE32_X": 4,
        "JLE_K": 8,
        "JLE_X": 4,
        "JLT32_K": 8,
        "JLT32_X": 4,
        "JLT_K": 8,
        "JLT_X": 4,
        "JNE32_K": 8,
        "JNE32_X": 4,
        "JNE_K": 8,
        "JNE_X": 4,
        "JSET32_K": 10,
        "JSET32_X": 6,
        "JSET_K": 10,
        "JSET_X": 6,
        "JSGE32_K": 8,
        "JSGE32_X": 4,
        "JSGE_K": 8,
        "JSGE_X": 4,
        "JSGT32_K": 8,
        "JSGT32_X": 4,
        "JSGT_K": 8,
        "JSGT_X": 4,
        "JSLE32_K": 8,
        "JSLE32_X": 4,
        "JSLE_K": 8,
        "JSLE_X": 4,
        "JSLT32_K": 8,
        "JSLT32_X": 4,
        "JSLT_K": 8,
        "JSLT_X": 4,
        "LDDW": 27,
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
        "LSH64_X": 8,
        "LSH_K": 1,
        "LSH_X": 8,
        "MOD64_K": 46,
        "MOD64_X": 42,
        "MOD_K": 30,
        "MOD_X": 26,
        "MOV64_K": 4,
        "MOV64_X": 2,
        "MOV_K": 4,
        "MOV_X": 2,
        "MUL64_K": 13,
        "MUL64_X": 9,
        "MUL_K": 12,
        "MUL_X": 8,
        "NEG64_K": 1,
        "NEG64_X": 1,
        "NEG_K": 1,
        "NEG_X": 1,
        "OR64_K": 20,
        "OR64_X": 8,
        "OR_K": 20,
        "OR_X": 8,
        "RSH64_K": 1,
        "RSH64_X": 8,
        "RSH_K": 1,
        "RSH_X": 8,
        "STX_ABS_B": 11,
        "STX_ABS_DW": 11,
        "STX_ABS_H": 11,
        "STX_ABS_W": 11,
        "STX_B": 11,
        "STX_DW": 30,
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
        "STX_W": 30,
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
        "SUB64_K": 20,
        "SUB64_X": 8,
        "SUB_K": 20,
        "SUB_X": 8,
        "XOR64_K": 20,
        "XOR64_X": 8,
        "XOR_K": 20,
        "XOR_X": 8,
    },
)

# Bounding variants for WCET sensitivity analysis: same target (same clock, same
# instruction/latency_overrides), but every load is charged as a guaranteed L1 hit
# or a guaranteed miss instead of being classified by recency/associativity -- gives
# a best-case/worst-case bracket around NOELV_PROFILE's realistic estimate.
NOELV_ALL_HIT_PROFILE = replace(NOELV_PROFILE, name="noelv_all_hit", cache_mode="always_hit")
NOELV_ALL_MISS_PROFILE = replace(NOELV_PROFILE, name="noelv_all_miss", cache_mode="always_miss")
