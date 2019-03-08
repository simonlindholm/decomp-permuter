from typing import List, Iterable, Set
import math
import random

from perm.perm import Perm

def get_all_seeds(total_count: int) -> Iterable[int]:
    """Generate all numbers 0..total_count-1 in random order, in expected time
    O(1) per number."""
    seen: Set[int] = set()
    while len(seen) < total_count // 2:
        seed = random.randrange(total_count)
        if seed not in seen:
            seen.add(seed)
            yield seed

    remaining: List[int] = []
    for seed in range(total_count):
        if seed not in seen:
            remaining.append(seed)
    random.shuffle(remaining)
    for seed in remaining:
        yield seed

def perm_evaluate_all(perm: Perm) -> Iterable[str]:
    while True:
        for seed in get_all_seeds(perm.perm_count):
            yield perm.evaluate(seed)
        if not perm.is_random():
            break
