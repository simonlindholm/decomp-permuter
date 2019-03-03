import perm
from operator import mul
import random
import itertools
import math
from functools import reduce
import random

def get_seed_from_num(n, counts):
    result = []
    for i in range(len(counts)):
        n, d = divmod(n, counts[i])
        result.append(int(d))

    return result

def random_int_upto_inf(start, end):
    if end == math.inf:
        return math.inf
    else:
        return random.randint(start, end)

def get_all_seeds(counts):
    total_count = reduce(mul, counts, 1)

    if total_count > 10000000:
        while True:
            yield [random_int_upto_inf(0, c) for c in counts]
    else:
        # General list of possible combinations
        seed_nums = list(range(total_count))
        random.shuffle(seed_nums)
        for seed_num in seed_nums:
            yield get_seed_from_num(seed_num, counts)

def perm_evaluate_all(perm):
    for seed in get_all_seeds(perm.get_counts()):
        permutaton = perm.evaluate(seed)
        yield permutaton