from __future__ import annotations


class Block:
    """Basic Block"""

    def __init__(self, start_idx: int, end_idx: int) -> None:
        self.start = start_idx
        self.end = end_idx
        self.next: list[Block] = []
        self.prev: list[Block] = []

    def add(self, block: Block):
        if block not in self.next:
            self.next.append(block)
        if self not in block.prev:
            block.prev.append(self)

    def __repr__(self) -> str:
        return f"Block[{self.start:3} - {self.end:3}]"