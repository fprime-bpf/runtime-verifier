from __future__ import annotations


class Block:
    """Basic Block"""

    def __init__(self, start_idx: int, end_idx: int, suffix="") -> None:
        self.start = start_idx
        self.end = end_idx
        self.suffix = suffix
        self.next: list[Block] = []
        self.prev: list[Block] = []

    def add(self, block: Block):
        if block not in self.next:
            self.next.append(block)
        if self not in block.prev:
            block.prev.append(self)

    def copy_with_suffix(self, new_suffix: str) -> Block:
        """
        Creates a new Block instance with the same boundaries but a new suffix.
        Edges (next/prev) are NOT copied to ensure a clean slate for CFG unrolling.
        """
        return Block(self.start, self.end, suffix=new_suffix)

    def __repr__(self) -> str:
        return f"Block[{self.start:3} - {self.end:3}]{self.suffix}"

    def __eq__(self, other):
        if not isinstance(other, Block):
            return False
        return (self.start == other.start and
                self.end == other.end and
                self.suffix == other.suffix)

    def __hash__(self):
        return hash((self.start, self.end, self.suffix))

    def __str__(self) -> str:
        succs = ", ".join(repr(n) for n in self.next)
        return f"BB({self.start}, {self.end}){self.suffix} -> [{succs}]"
