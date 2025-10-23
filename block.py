from __future__ import annotations


class Block:
    """Basic Block"""

    def __init__(self, start_idx: int, end_idx: int) -> None:
        self.start = start_idx
        self.end = end_idx
        self.next: list[Block] = []

    def add(self, block: Block):
        self.next.append(block)

    def __str__(self) -> str:
        curr = f"BB({self.start}, {self.end})"

        if len(self.next) == 1:
            return f"{curr} -> {str(self.next[0])}"
        if len(self.next) > 1:
            return f"{curr} -> [{'; '.join([f'{str(n)}' for n in self.next])}]"

        return curr
