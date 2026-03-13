from __future__ import annotations
from dataclasses import dataclass
from block import Block
from bpf import BpfClass, BpfCode, BpfS, BpfSize, BpfMode, BpfInstruction, Mask, Shift
from collections import deque

from typing import Set, Optional, Dict

@dataclass(frozen=True)
class OpInfo:
    name: str
    latency: Optional[int]  # None as default


BPF_ATOMIC_OP_MASK = 0x0F
BPF_FETCH          = 0x10

ATOMIC_ADD     = 0x0
ATOMIC_AND     = 0x1
ATOMIC_OR      = 0x2
ATOMIC_XOR     = 0x3
ATOMIC_XCHG    = 0xE
ATOMIC_CMPXCHG = 0xF


BPF_INFO: Dict[int, OpInfo] = {
    # ===== ALU (32-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   OpInfo("ADD_K",   5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   OpInfo("ADD_X",   1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   OpInfo("SUB_K",   5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   OpInfo("SUB_X",   1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   OpInfo("MUL_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   OpInfo("MUL_X",   10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   OpInfo("DIV_K",   38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   OpInfo("DIV_X",   34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU:   OpInfo("MOD_K",   38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU:   OpInfo("MOD_X",   34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU:   OpInfo("OR_K",    5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU:   OpInfo("OR_X",    1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU:   OpInfo("AND_K",   5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU:   OpInfo("AND_X",   1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU:   OpInfo("LSH_K",   1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU:   OpInfo("LSH_X",   1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU:   OpInfo("RSH_K",   1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU:   OpInfo("RSH_X",   1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   OpInfo("NEG_K",   0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   OpInfo("NEG_X",   0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU:   OpInfo("XOR_K",   5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU:   OpInfo("XOR_X",   1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   OpInfo("MOV_K",   4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   OpInfo("MOV_X",   4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU:   OpInfo("ARSH_K",  1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU:   OpInfo("ARSH_X",  1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU:   OpInfo("END",     None),

    # ===== ALU64 (64-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64: OpInfo("ADD64_K", 5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64: OpInfo("ADD64_X", 1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64: OpInfo("SUB64_K", 5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64: OpInfo("SUB64_X", 1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64: OpInfo("MUL64_K", 14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64: OpInfo("MUL64_X", 10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64: OpInfo("DIV64_K", 38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64: OpInfo("DIV64_X", 34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU64: OpInfo("MOD64_K", 38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU64: OpInfo("MOD64_X", 34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU64: OpInfo("OR64_K",  5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU64: OpInfo("OR64_X",  1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU64: OpInfo("AND64_K", 5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU64: OpInfo("AND64_X", 1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU64: OpInfo("LSH64_K", 1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU64: OpInfo("LSH64_X", 1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU64: OpInfo("RSH64_K", 1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU64: OpInfo("RSH64_X", 1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64: OpInfo("NEG64_K", 0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64: OpInfo("NEG64_X", 0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU64: OpInfo("XOR64_K", 5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU64: OpInfo("XOR64_X", 1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64: OpInfo("MOV64_K", 4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64: OpInfo("MOV64_X", 4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU64: OpInfo("ARSH64_K",1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU64: OpInfo("ARSH64_X",1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU64: OpInfo("END64",   None),

    # ===== JMP (64-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP:   OpInfo("JA",      2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   OpInfo("JEQ_K",   7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   OpInfo("JEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   OpInfo("JGT_K",   7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   OpInfo("JGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   OpInfo("JGE_K",   7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   OpInfo("JGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   OpInfo("JNE_K",   7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   OpInfo("JNE_X",   3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP:   OpInfo("JSET_K",  8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP:   OpInfo("JSET_X",  4),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   OpInfo("JSGT_K",  7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   OpInfo("JSGT_X",  3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   OpInfo("JSGE_K",  7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   OpInfo("JSGE_X",  3),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   OpInfo("JLT_K",   7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   OpInfo("JLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   OpInfo("JLE_K",   7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   OpInfo("JLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   OpInfo("JSLT_K",  7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   OpInfo("JSLT_X",  3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   OpInfo("JSLE_K",  7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   OpInfo("JSLE_X",  3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:   OpInfo("CALL",    281),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP:   OpInfo("CALL",    281),
    BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:   OpInfo("EXIT",    2),

    # ===== JMP32 (32-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP32: OpInfo("JA", 2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32: OpInfo("JEQ32_K", 7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32: OpInfo("JEQ32_X", 3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32: OpInfo("JNE32_K", 7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32: OpInfo("JNE32_X", 3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32: OpInfo("JGT32_K", 7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32: OpInfo("JGT32_X", 3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32: OpInfo("JGE32_K", 7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32: OpInfo("JGE32_X", 3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP32: OpInfo("JSET32_K", 8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP32: OpInfo("JSET32_X", 4),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32: OpInfo("JLT32_K", 7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32: OpInfo("JLT32_X", 3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32: OpInfo("JLE32_K", 7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32: OpInfo("JLE32_X", 3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32: OpInfo("JSGT32_K", 7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32: OpInfo("JSGT32_X", 3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32: OpInfo("JSGE32_K", 7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32: OpInfo("JSGE32_X", 3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32: OpInfo("JSLT32_K", 7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32: OpInfo("JSLT32_X", 3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32: OpInfo("JSLE32_K", 7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32: OpInfo("JSLE32_X", 3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP32: OpInfo("CALL",     281),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP32: OpInfo("CALL",     281),
    
    # ===== LD =====
    BpfMode.IMM | BpfSize.W  | BpfClass.LD:  OpInfo("LD_IMM_W",  281),
    BpfMode.IMM | BpfSize.H  | BpfClass.LD:  OpInfo("LD_IMM_H",  281),
    BpfMode.IMM | BpfSize.B  | BpfClass.LD:  OpInfo("LD_IMM_B",  281),
    BpfMode.IMM | BpfSize.DW | BpfClass.LD:  OpInfo("LDDW",  281),   # 

    BpfMode.ABS | BpfSize.W  | BpfClass.LD:  OpInfo("LD_ABS_W",  None),
    BpfMode.ABS | BpfSize.H  | BpfClass.LD:  OpInfo("LD_ABS_H",  None),
    BpfMode.ABS | BpfSize.B  | BpfClass.LD:  OpInfo("LD_ABS_B",  None),
    BpfMode.ABS | BpfSize.DW | BpfClass.LD:  OpInfo("LD_ABS_DW", None),

    BpfMode.IND | BpfSize.W  | BpfClass.LD:  OpInfo("LD_IND_W",  None),
    BpfMode.IND | BpfSize.H  | BpfClass.LD:  OpInfo("LD_IND_H",  None),
    BpfMode.IND | BpfSize.B  | BpfClass.LD:  OpInfo("LD_IND_B",  None),
    BpfMode.IND | BpfSize.DW | BpfClass.LD:  OpInfo("LD_IND_DW", None),

    BpfMode.MEM   | BpfSize.W  | BpfClass.LD: OpInfo("LD_MEM_W",  None),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LD: OpInfo("LD_MEM_H",  None),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LD: OpInfo("LD_MEM_B",  None),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LD: OpInfo("LD_MEM_DW", None),

    BpfMode.FMEM  | BpfSize.W  | BpfClass.LD: OpInfo("FLD_W",  281),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LD: OpInfo("FLD_H",  281),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LD: OpInfo("FLD_B",  281),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LD: OpInfo("FLD_DW",  281),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LD: OpInfo("LD_MEMSX_W",  None),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LD: OpInfo("LD_MEMSX_H",  None),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LD: OpInfo("LD_MEMSX_B",  None),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LD: OpInfo("LD_MEMSX_DW", None),
    
    # ===== LDX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_ABS_W",  None),
    BpfMode.ABS   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_ABS_H",  None),
    BpfMode.ABS   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_ABS_B",  None),
    BpfMode.ABS   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_ABS_DW", None),

    BpfMode.IND   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_IND_W",  None),
    BpfMode.IND   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_IND_H",  None),
    BpfMode.IND   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_IND_B",  None),
    BpfMode.IND   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_IND_DW", None),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_W",  281),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_H",  281),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_B",  281),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_DW", 281),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.LDX: OpInfo("FLDX_W",  281),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LDX: OpInfo("FLDX_H",  281),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LDX: OpInfo("FLDX_B",  281),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LDX: OpInfo("FLDX_DW",  281),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_MEMSX_W", 281),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_MEMSX_H", 281),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_MEMSX_B", 281),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_MEMSX_DW", 281),
    
    # ===== ST =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_ABS_W",  0),
    BpfMode.ABS   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_ABS_H",  0),
    BpfMode.ABS   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_ABS_B",  0),
    BpfMode.ABS   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_ABS_DW", 0),

    BpfMode.IND   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_IND_W",  0),
    BpfMode.IND   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_IND_H",  0),
    BpfMode.IND   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_IND_B",  0),
    BpfMode.IND   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_IND_DW", 0),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_W",  281),
    BpfMode.MEM   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_H",  281),
    BpfMode.MEM   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_B",  281),
    BpfMode.MEM   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_DW", 281),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.ST: OpInfo("FST_W",  281),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.ST: OpInfo("FST_H",  281),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.ST: OpInfo("FST_B",  281),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.ST: OpInfo("FST_DW",  281),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.ST:  OpInfo("ST_MEMSX_W",  281),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.ST:  OpInfo("ST_MEMSX_H",  281),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.ST:  OpInfo("ST_MEMSX_B",  281),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.ST:  OpInfo("ST_MEMSX_DW", 281),
    
    # ===== STX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.STX: OpInfo("STX_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.STX: OpInfo("STX_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.STX: OpInfo("STX_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.STX: OpInfo("STX_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.STX: OpInfo("STX_ABS_W",  None),
    BpfMode.ABS   | BpfSize.H  | BpfClass.STX: OpInfo("STX_ABS_H",  None),
    BpfMode.ABS   | BpfSize.B  | BpfClass.STX: OpInfo("STX_ABS_B",  None),
    BpfMode.ABS   | BpfSize.DW | BpfClass.STX: OpInfo("STX_ABS_DW", None),

    BpfMode.IND   | BpfSize.W  | BpfClass.STX: OpInfo("STX_IND_W",  None),
    BpfMode.IND   | BpfSize.H  | BpfClass.STX: OpInfo("STX_IND_H",  None),
    BpfMode.IND   | BpfSize.B  | BpfClass.STX: OpInfo("STX_IND_B",  None),
    BpfMode.IND   | BpfSize.DW | BpfClass.STX: OpInfo("STX_IND_DW", None),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.STX: OpInfo("STX_W",  281),
    BpfMode.MEM   | BpfSize.H  | BpfClass.STX: OpInfo("STX_H",  281),
    BpfMode.MEM   | BpfSize.B  | BpfClass.STX: OpInfo("STX_B",  281),
    BpfMode.MEM   | BpfSize.DW | BpfClass.STX: OpInfo("STX_DW", 281),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.STX: OpInfo("FSTX_W",  281),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.STX: OpInfo("FSTX_H",  281),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.STX: OpInfo("FSTX_B",  281),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.STX: OpInfo("FSTX_DW",  281),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.STX: OpInfo("STX_MEMSX_W",  281),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.STX: OpInfo("STX_MEMSX_H",  281),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.STX: OpInfo("STX_MEMSX_B",  281),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.STX: OpInfo("STX_MEMSX_DW", 281),
    
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD) << 8): OpInfo("ATOMIC_ADD_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): OpInfo("ATOMIC_ADD_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND) << 8): OpInfo("ATOMIC_AND_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): OpInfo("ATOMIC_AND_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR) << 8): OpInfo("ATOMIC_OR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): OpInfo("ATOMIC_OR_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR) << 8): OpInfo("ATOMIC_XOR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): OpInfo("ATOMIC_XOR_FETCH_W", 8),

    # XCHG / CMPXCHG
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XCHG) << 8): OpInfo("ATOMIC_XCHG_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_CMPXCHG) << 8): OpInfo("ATOMIC_CMPXCHG_W", 8),

    # === STX | ATOMIC | DW（64-bit）===
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD          ) << 8): OpInfo("ATOMIC_ADD_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): OpInfo("ATOMIC_ADD_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND          ) << 8): OpInfo("ATOMIC_AND_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): OpInfo("ATOMIC_AND_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR           ) << 8): OpInfo("ATOMIC_OR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): OpInfo("ATOMIC_OR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR          ) << 8): OpInfo("ATOMIC_XOR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): OpInfo("ATOMIC_XOR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XCHG         ) << 8): OpInfo("ATOMIC_XCHG_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_CMPXCHG      ) << 8): OpInfo("ATOMIC_CMPXCHG_DW", 8),
}


BPF_INFO_FPU: Dict[int, OpInfo] = {
    # ===== FPU32 (Single Precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   OpInfo("FADD_K",   12),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   OpInfo("FADD_X",   5),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   OpInfo("FSUB_K",   12),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   OpInfo("FSUB_X",   5),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   OpInfo("FMUL_K",   12),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   OpInfo("FMUL_X",   5),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   OpInfo("FDIV_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   OpInfo("FDIV_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   OpInfo("FNEG_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   OpInfo("FNEG_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   OpInfo("FMOV_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   OpInfo("FMOV_X",   7),
    
    # ===== FPU64 (Double precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64:   OpInfo("FADD64_K",   14),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64:   OpInfo("FADD64_X",   7),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64:   OpInfo("FSUB64_K",   14),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64:   OpInfo("FSUB64_X",   7),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64:   OpInfo("FMUL64_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64:   OpInfo("FMUL64_X",   7),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64:   OpInfo("FDIV64_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64:   OpInfo("FDIV64_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64:   OpInfo("FNEG64_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64:   OpInfo("FNEG64_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64:   OpInfo("FMOV64_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64:   OpInfo("FMOV64_X",   7),
    
    ## Only register-register comparisons are supported!
    # ===== FJMP (64-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   OpInfo("JFEQ_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   OpInfo("JFEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   OpInfo("JFOGT_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   OpInfo("JFOGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   OpInfo("JFOGE_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   OpInfo("JFOGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   OpInfo("JFNE_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   OpInfo("JFNE_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   OpInfo("JFUGT_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   OpInfo("JFUGT_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   OpInfo("JFUGE_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   OpInfo("JFUGE_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   OpInfo("JFOLT_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   OpInfo("JFOLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   OpInfo("JFOLE_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   OpInfo("JFOLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   OpInfo("JFULT_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   OpInfo("JFULT_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   OpInfo("JFULE_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   OpInfo("JFULE_X",  8),

    # ===== FJMP32 (32-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32:   OpInfo("JFEQ32_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32:   OpInfo("JFEQ32_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOGT32_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOGT32_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOGE32_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOGE32_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFNE32_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFNE32_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32:   OpInfo("JFUGT32_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32:   OpInfo("JFUGT32_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32:   OpInfo("JFUGE32_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32:   OpInfo("JFUGE32_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOLT32_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOLT32_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOLE32_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOLE32_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32:   OpInfo("JFULT32_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32:   OpInfo("JFULT32_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32:   OpInfo("JFULE32_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32:   OpInfo("JFULE_32X",  8)
}


def is_fpu_instr(instr: BpfInstruction) -> bool:
    cls_ = instr.get_class()

    raw = instr._to_int(instr.instruction)
    offset_u = (raw & Mask.OFFSET) >> Shift.OFFSET
    imm_u = (raw & Mask.IMM) >> Shift.IMM

    # FPU Arithmetic: ALU / ALU64 + offset bit1=1
    if cls_ in (BpfClass.ALU, BpfClass.ALU64):
        f_flag = (offset_u >> 1) & 0x1
        return f_flag == 1

    # FPU Branch: JMP / JMP32 + Not CALL/EXIT + imm bit1=1
    if cls_ in (BpfClass.JMP, BpfClass.JMP32):
        code = instr.opcode & Mask.CODE

        # Exclude CALL and EXIT
        if code in (BpfCode.JMP.CALL, BpfCode.JMP.EXIT):
            return False

        imm_bit1 = (imm_u >> 1) & 0x1
        return imm_bit1 == 1

    return False


def instr_to_runtime(instructions: dict, start: int, end: int) -> int:
    """
    Calculate runtime of the given instructions from `start` to `end` (inclusive).

    Parameters
    ----------
    instructions : dict[int, BpfInstruction]
        A dict mapping PC to decoded eBPF instruction.
    start : int
        Start PC (inclusive).
    end : int
        End PC (inclusive).

    Returns
    -------
    int
        CPU cycles. Returns 0 if the input is invalid.
    """
    runtime = 0
    for idx in sorted(pc for pc in instructions if start <= pc <= end):
        instr = instructions[idx]
        if is_fpu_instr(instr):
            op_info = BPF_INFO_FPU.get(instr.opcode)  # FADD / FNEG / JFEQ / JFOGT ...
        else:
            op_info = BPF_INFO.get(instr.opcode)      # ALU/MEM ... + FLDX & FSTX

        print(f"idx={idx}: name={op_info.name}, latency={op_info.latency}")
        if op_info:
            if op_info.latency:
                runtime += op_info.latency

    return runtime


def dfs_blocks(first_block: Block | None, instructions: dict) -> int:
    """
    Perform a depth-first search over the Block graph using an explicit stack
    to avoid RecursionError on large/deeply unrolled CFGs.
    Returns an integer value (CPU cycles) representing an estimated runtime upper bound.

    Parameters
    ----------
    first_block : Block (The starting basic block of the CFG)

    Returns
    -------
    int: CPU cycles. 0 if the input is invalid.
    """

    print("\n======DFS Start======")

    if first_block is None:
        return 0

    onpath: Set[Block] = set()
    path_runtime_ub = 0
    path_runtime = 0

    # Stack entries are either:
    #   ('VISIT', block)       — process a block and push its successors
    #   ('BACKTRACK', block, cost) — undo the cost added when we entered block
    stack = [('VISIT', first_block)]

    while stack:
        item = stack.pop()

        if item[0] == 'BACKTRACK':
            _, block, cost = item
            path_runtime -= cost
            onpath.remove(block)

        else:  # 'VISIT'
            _, block = item

            # Cycle detection (back-edge) — should not occur after unrolling
            if block in onpath:
                print(f"Back-edge hit at BB({block.start}, {block.end}); ignoring extra iteration for now.")
                continue

            onpath.add(block)

            instr_count = block.end - block.start + 1
            print(f"\n======Visiting BB({block.start}, {block.end}){block.suffix}, instructions={instr_count}======")

            cost = instr_to_runtime(instructions, block.start, block.end)
            path_runtime += cost

            # Push backtrack action first (runs after all successors are done)
            stack.append(('BACKTRACK', block, cost))

            if not block.next:
                print(f"Reaching an exit point {block.end}, path runtime is {path_runtime}")
                path_runtime_ub = max(path_runtime_ub, path_runtime)
            else:
                for nxt in block.next:
                    stack.append(('VISIT', nxt))

    return path_runtime_ub


class Loop:
    """
    Metadata for a natural loop in the CFG.
    """
    def __init__(self, header: Block, tail: Block, members: set[Block]):
        self.header = header
        self.tail = tail
        self.members = members
        # (Source, Target)
        self.entry_edges: set[tuple[Block, Block]] = set()
        self.exit_edges: set[tuple[Block, Block]] = set()
        # Loop iteration metadata
        self.max_iterations: int | None = None
        # Track the exact instruction PCs for loop initialization
        self.call_5_pc: int | None = None
        self.w2_pc: int | None = None
        self.w3_pc: int | None = None

    def find_boundaries(self):
        """
        Populate entry and exit edges based on membership.
        """
        for member in self.members:
            # Exit: source is inside, target is outside
            for succ in member.next:
                if succ not in self.members:
                    self.exit_edges.add((member, succ))
            # Entry: source is outside, target is inside
            for pred in member.prev:
                if pred not in self.members:
                    self.entry_edges.add((pred, member))

    def analyze_max_iterations(self, instructions: dict):
        """
        Use a standard Breadth-First Search (BFS) with a queue to scan backwards
        through the CFG. Looks for `bpf_iter_num_new` (call 0x5) and the
        initialization of its boundary arguments (w2 and w3).
        """
        for pred_block, _ in self.entry_edges:

            # Initialize the BFS queue.
            # Queue element structure:
            # (current_block, found_call_5, val_w2, val_w3, pc_call, pc_w2, pc_w3)
            bfs_queue = deque()
            bfs_queue.append((pred_block, False, None, None, None, None, None))

            # Keep track of visited blocks to prevent infinite loops in cyclic CFGs
            visited = set()

            # Start BFS traversal
            while len(bfs_queue) > 0:
                # Pop a node from the front of the queue
                (curr_block, found_call_5, val_w2, val_w3,
                 pc_call, pc_w2, pc_w3) = bfs_queue.popleft()

                # Skip if we have already evaluated this block in the current path
                if curr_block in visited:
                    continue
                visited.add(curr_block)

                # Extract the instruction PCs for the current block and sort them
                # in descending order (bottom-up scan because we are moving backwards)
                pcs = sorted([pc for pc in instructions.keys()
                              if curr_block.start <= pc <= curr_block.end], reverse=True)

                for pc in pcs:
                    instr = instructions[pc]

                    # Step 1: Look for the iterator initialization (call 0x5)
                    # Opcode 0x85 is CALL, immediate value 5 is bpf_iter_num_new
                    if getattr(instr, 'opcode', -1) == 0x85 and getattr(instr, 'imm', -1) == 5:
                        found_call_5 = True
                        pc_call = pc
                        continue

                    # Step 2: Once call 0x5 is found, look upwards for w2 and w3 assignments
                    if found_call_5:
                        # Opcode 0xb4 is ALU32 | MOV | K (Assign immediate value to 32-bit register)
                        if getattr(instr, 'opcode', -1) == 0xb4:
                            if getattr(instr, 'dst', -1) == 2 and val_w2 is None:
                                val_w2 = instr.imm
                                pc_w2 = pc
                            elif getattr(instr, 'dst', -1) == 3 and val_w3 is None:
                                val_w3 = instr.imm
                                pc_w3 = pc

                        # Step 3: If both w2 and w3 are successfully found, calculate and save
                        if val_w2 is not None and val_w3 is not None:
                            self.max_iterations = val_w3 - val_w2

                            self.call_5_pc = pc_call
                            self.w2_pc = pc_w2
                            self.w3_pc = pc_w3

                            print(
                                f"Loop Header {self.header.start}: Identified {self.max_iterations} max iterations.\n"
                                f"  -> w2={val_w2} at PC {self.w2_pc}, "
                                f"w3={val_w3} at PC {self.w3_pc}, call 0x5 at PC {self.call_5_pc}"
                            )
                            # Target found, exit the analysis for this entry edge
                            return

                # Step 4: If values are not fully resolved in this block,
                # enqueue all unvisited predecessor blocks to continue the BFS
                if curr_block.prev:
                    print(f"Traversing previous blocks")
                else:
                    print(f"Error, no prev found!")
                for prev_block in curr_block.prev:
                    if prev_block not in visited:
                        bfs_queue.append((
                            prev_block, found_call_5, val_w2, val_w3,
                            pc_call, pc_w2, pc_w3
                        ))


def find_loops(root_block: Block, instructions: dict) -> list[Loop]:
    """
    Identifies loops using Three-Color DFS and collects members via reverse traversal.
    """
    visited = set()
    visiting = set()

    loop_list = []
    back_edges = []    # (tail, header) pairs

    def dfs(current_block: Block):
        visiting.add(current_block)

        for next_block in current_block.next:
            if next_block in visiting:  # Loop detected
                back_edges.append((current_block, next_block))
            elif next_block not in visited:
                dfs(next_block)

        visiting.remove(current_block)
        visited.add(current_block)
    dfs(root_block)

    # Create loop_list: list[loop]
    for tail, header in back_edges:
        members = {header, tail}
        stack = [tail]

        while stack:
            curr = stack.pop()
            for pred in curr.prev:
                if pred not in members:
                    members.add(pred)
                    stack.append(pred)

        new_loop = Loop(header, tail, members)
        new_loop.find_boundaries()
        new_loop.analyze_max_iterations(instructions)
        loop_list.append(new_loop)

    # If nested loops found, error out
    for l1 in loop_list:
        for l2 in loop_list:
            if l1 == l2:
                continue

            # Check if any entry-edge source is in l2 AND any exit-edge target is in l2
            entry_from_l2 = any(src in l2.members for src, _ in l1.entry_edges)
            exit_to_l2 = any(target in l2.members for _, target in l1.exit_edges)

            if entry_from_l2 and exit_to_l2:
                raise Exception(
                    f"Nested Loop Error: Loop (Header {l1.header.start}) is nested "
                    f"inside Loop (Header {l2.header.start})."
                )

    return loop_list


def unroll_loops_in_cfg(root_block: Block, loop_list: list[Loop]) -> Block:
    """
    Unrolls loops in the CFG based on the identified max_iterations.
    """
    sorted_loops = sorted(loop_list, key=lambda l: l.header.start, reverse=True)

    for loop in sorted_loops:
        if loop.max_iterations is None or loop.max_iterations <= 0:
            print(f"Warning: Loop at {loop.header.start} has no bound. Skipping unroll.")
            continue

        print(f"Unrolling loop at header {loop.header.start} for {loop.max_iterations} iterations.")

        entry_sources = [entry_source for entry_source, _ in loop.entry_edges]

        prev_header = None

        # Clone the loop body N times
        for i in range(loop.max_iterations):
            block_map: dict[Block, Block] = {}

            # 1. Create clones with new suffix
            for member in loop.members:
                block_map[member] = member.copy_with_suffix(f".{i}")

            # 2. Re-establish connections within this iteration slice and exit edges
            is_last_iteration = (i == loop.max_iterations - 1)
            for member in loop.members:
                new_member = block_map[member]
                for succ in member.next:
                    if succ in loop.members:
                        if succ == loop.header:
                            continue
                        # Internal link to new blocks, disconnect back edges
                        new_member.add(block_map[succ])

                    # Exit link to blocks outside the loop
                    elif succ not in loop.members:
                        # Only the last iteration is allowed to exit the loop.
                        if is_last_iteration:
                            new_member.add(succ)

            # Link the previous iteration's tail to this iteration's header
            if i == 0:
                for entry_source in entry_sources:
                    entry_source.next.remove(loop.header)
                    loop.header.prev.remove(entry_source)
                    entry_source.add(block_map[loop.header])
                prev_header = block_map[loop.tail]
            else:
                prev_header.add(block_map[loop.header])
                prev_header = block_map[loop.tail]

    return root_block
