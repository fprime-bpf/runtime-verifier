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

    def remove_edge(self, block: Block):
        # Drops the edge from both self.next and block.prev.
        if block in self.next:
            self.next.remove(block)
        if self in block.prev:
            block.prev.remove(self)

    def detach(self):
        # Removes every edge this block holds, in either direction.
        for succ in list(self.next):
            self.remove_edge(succ)
        for pred in list(self.prev):
            pred.remove_edge(self)

    def copy_with_suffix(self, new_suffix: str) -> Block:
        # Same start/end, new_suffix prepended to the existing suffix.
        # No edges copied. Prepend order keeps nested-loop suffixes
        # outermost-to-innermost and unique per iteration combination.
        return Block(self.start, self.end, suffix=new_suffix + self.suffix)

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