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
        """Symmetric inverse of add(): drops the edge from both endpoints' lists,
        so `block.prev` stays truthful. add()'s asymmetric cousin -- a bare
        `self.next.remove(block)` -- leaves block.prev pointing back at self even
        after self is orphaned, which is exactly the kind of stale edge that made
        nested-loop unrolling's later find_boundaries() passes see dead blocks as
        live predecessors."""
        if block in self.next:
            self.next.remove(block)
        if self in block.prev:
            block.prev.remove(self)

    def detach(self):
        """Fully removes this block from the graph: clears every edge it holds in
        either direction. Used once a block has been fully replaced by unrolled
        clones, so it stops showing up as a stale predecessor/successor when a
        later (outer) unroll pass recomputes an enclosing loop's boundaries."""
        for succ in list(self.next):
            self.remove_edge(succ)
        for pred in list(self.prev):
            pred.remove_edge(self)
            
    def copy_with_suffix(self, new_suffix: str) -> Block:
        """
        Creates a new Block instance with the same boundaries, prefixing its suffix
        with new_suffix. Edges (next/prev) are NOT copied to ensure a clean slate for
        CFG unrolling.

        Prepending (not replacing) is what makes nested loops work: unrolling runs
        innermost-first, so a block already carrying an inner ".4" becomes ".2.4"
        when its enclosing loop clones it for outer iteration 2 -- suffixes read
        outermost-to-innermost, and (start, end, suffix) stays unique per iteration
        combination. Replacing would collapse every outer iteration into one block.
        """
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