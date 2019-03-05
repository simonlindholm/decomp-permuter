from typing import List, Iterable
import math
import operator
import random

from perm.perm import Perm

def get_seed_from_num(n: int, counts: List[int]) -> List[int]:
    result = []
    for c in counts:
        n, d = divmod(n, c)
        result.append(d)
    return result

def get_rand_seed(counts: List[int]) -> List[int]:
    result = []
    for c in counts:
        result.append(random.randrange(c))
    return result

def get_all_seeds(counts: List[int]) -> Iterable[List[int]]:
    INF = 10**5
    total_count = 1
    for c in counts:
        total_count *= c

    if total_count > INF:
        while True:
            yield get_rand_seed(counts)
    else:
        # General list of possible combinations
        seed_nums = list(range(total_count))
        random.shuffle(seed_nums)
        for seed_num in seed_nums:
            yield get_seed_from_num(seed_num, counts)

def perm_evaluate_all(perm: Perm) -> Iterable[str]:
    while True:
        for seed in get_all_seeds(perm.get_counts()):
            permutaton = perm.evaluate(seed)
            yield permutaton
        if not perm.is_random():
            break
