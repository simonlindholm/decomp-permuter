from typing import List, Iterable
import math
import random

from perm.perm import Perm

def get_all_seeds(total_count: int) -> Iterable[int]:
    if total_count > 10**5:
        while True:
            yield random.randrange(total_count)
    else:
        # General list of possible combinations
        all_seeds = list(range(total_count))
        random.shuffle(all_seeds)
        for seed in all_seeds:
            yield seed

def perm_evaluate_all(perm: Perm) -> Iterable[str]:
    while True:
        for seed in get_all_seeds(perm.perm_count):
            yield perm.evaluate(seed)
        if not perm.is_random():
            break
