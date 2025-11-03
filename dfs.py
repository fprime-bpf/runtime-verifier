from __future__ import annotations
from dataclasses import dataclass
from block import Block
from bpf import BpfClass, BpfCode, BpfS, BpfSize, BpfMode

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
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   OpInfo("NEG",     0),
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
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64: OpInfo("NEG64",   0),
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
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:   OpInfo("CALL",    None),
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
    
    # ===== LD =====
    BpfMode.IMM | BpfSize.W  | BpfClass.LD:  OpInfo("LD_IMM_W",  4),
    BpfMode.IMM | BpfSize.H  | BpfClass.LD:  OpInfo("LD_IMM_H",  4),
    BpfMode.IMM | BpfSize.B  | BpfClass.LD:  OpInfo("LD_IMM_B",  4),
    BpfMode.IMM | BpfSize.DW | BpfClass.LD:  OpInfo("LDDW",  4),   # 

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
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_DW", 11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_MEMSX_W", 11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_MEMSX_H", 11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_MEMSX_B", 11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_MEMSX_DW", 11),
    
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
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_DW", 11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.ST:  OpInfo("ST_MEMSX_W",  11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.ST:  OpInfo("ST_MEMSX_H",  11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.ST:  OpInfo("ST_MEMSX_B",  11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.ST:  OpInfo("ST_MEMSX_DW", 11),
    
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
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.STX: OpInfo("STX_W",  7),
    BpfMode.MEM   | BpfSize.H  | BpfClass.STX: OpInfo("STX_H",  7),
    BpfMode.MEM   | BpfSize.B  | BpfClass.STX: OpInfo("STX_B",  7),
    BpfMode.MEM   | BpfSize.DW | BpfClass.STX: OpInfo("STX_DW", 7),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.STX: OpInfo("STX_MEMSX_W",  7),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.STX: OpInfo("STX_MEMSX_H",  7),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.STX: OpInfo("STX_MEMSX_B",  7),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.STX: OpInfo("STX_MEMSX_DW", 7),
    
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




def instr_to_runtime(instructions:list, start:int, end:int) -> int:
    """
    Calculate runtime of the given instructions from `start` to `end` (inclusive).

    Parameters
    ----------
    instructions : list
        A list of decoded eBPF instructions.
    start : int
        Start index (inclusive).
    end : int
        End index (inclusive).

    Returns
    -------
    int
        CPU cycles. Returns 0 if the input is invalid.
    """
    runtime = 0
    for idx in range(start, end+1):
        instr = instructions[idx]
        op_info = BPF_INFO.get(instr.opcode)
        print(f"idx={idx}: {op_info}")
        if op_info:
            if op_info.latency:
                runtime += op_info.latency

    return runtime

def dfs_blocks(first_block: Block | None, instructions: list) -> int:
    """
    Perform a depth-first search over the Block graph. （No loops currently)
    Returns a integer value (CPU cycles) representing an estimated runtime upper bound
    
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

    onpath: Set[Block] = set()      # nodes on the current recursion path
    path_runtime_ub = 0
    path_runtime = 0

    def dfs(block: Block):
        nonlocal path_runtime_ub, path_runtime

        # cycle detection (back-edge)
        if block in onpath:
            # TODO: plug a loop bound policy here.
            print(f"Back-edge hit at BB({block.start}, {block.end}); ignoring extra iteration for now.")
            return

        onpath.add(block)

        instr_count = block.end - block.start + 1
        print(f"Visiting BB({block.start}, {block.end}), instructions={instr_count}")

        instr_runtime = instr_to_runtime(instructions, block.start, block.end)
        path_runtime += instr_runtime

        if not block.next:
            print(f"Reaching an exit point {block.end}, path runtime is {path_runtime}")
            path_runtime_ub = max(path_runtime_ub, path_runtime)
        else:
            for nxt in block.next:
                dfs(nxt)

        path_runtime -= instr_runtime
        onpath.remove(block)

    dfs(first_block)
    return path_runtime_ub

    
