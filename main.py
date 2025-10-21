import sys
import struct
from enum import Enum


class BPFClass(Enum):
    LD = 0x0
    LDX = 0x1
    ST = 0x2
    STX = 0x3
    ALU = 0x4
    JMP = 0x5
    JMP32 = 0x6
    ALU64 = 0x7


class Instruction:
    IMM_SHIFT = 0
    OFFSET_SHIFT = 32
    DST_SHIFT = 48
    SRC_SHIFT = 52
    OPCODE_SHIFT = CLASS_SHIFT = 56
    S_SHIFT = SZ_SHIFT = 59
    CODE_SHIFT = 60
    MODE_SHIFT = 61

    IMM_MASK = 0xFFFFFFFF << IMM_SHIFT
    OFFSET_MASK = 0xFFFF << OFFSET_SHIFT
    DST_MASK = 0b1111 << DST_SHIFT
    SRC_MASK = 0b1111 << SRC_SHIFT
    OPCODE_MASK = 0xFF << OPCODE_SHIFT

    # OPCODE:
    CLASS_MASK = 0b111 << CLASS_SHIFT
    # - ALU and JMP
    S_MASK = 0b1 << S_SHIFT
    CODE_MASK = 0b1111 << CODE_SHIFT
    # - LD and ST
    SZ_MASK = 0b11 << SZ_SHIFT
    MODE_MASK = 0b111 << MODE_SHIFT

    def __init__(self, instruction: bytes) -> None:
        self.instruction = instruction

        self.imm = self._get_imm()
        self.off = self._get_off()
        self.src = self._get_src()
        self.dst = self._get_dst()
        self.opcode = self._get_opcode()

    def _to_int(self, instruction: bytes) -> int:
        (val,) = struct.unpack(
            # big endian = ">"
            # not signed = "Q"
            (">") + ("Q"),
            instruction,
        )

        return val

    def _get_imm(self) -> int:
        return (
            self._to_int(self.instruction) & Instruction.IMM_MASK
        ) >> Instruction.IMM_SHIFT

    def _get_off(self) -> int:
        return (
            self._to_int(self.instruction) & Instruction.OFFSET_MASK
        ) >> Instruction.OFFSET_SHIFT

    def _get_src(self) -> int:
        return (
            self._to_int(self.instruction) & Instruction.SRC_MASK
        ) >> Instruction.SRC_SHIFT

    def _get_dst(self) -> int:
        return (
            self._to_int(self.instruction) & Instruction.DST_MASK
        ) >> Instruction.DST_SHIFT

    def _get_opcode(self) -> int:
        return (
            self._to_int(self.instruction) & Instruction.OPCODE_MASK
        ) >> Instruction.OPCODE_SHIFT

    def get_class(self) -> BPFClass:
        return BPFClass(
            self.opcode & (Instruction.CLASS_MASK >> Instruction.CLASS_SHIFT)
        )


def read_file(filename: str):
    inst_size = 8
    with open(filename, "rb") as file:
        while True:
            instruction = file.read(inst_size)
            if instruction == b"":
                break

            print(f"instruction: {str(instruction)}")
            ins = Instruction(instruction)
            print(f"class: {ins.get_class().name}")
            print(f"src: {ins.src}, dst: {ins.dst}")

    pass


def main():
    args = sys.argv
    if len(args) != 2:
        raise Exception(f"usage: {args[0]} <filename>")

    filename = args[1]

    read_file(filename)


if __name__ == "__main__":
    main()
