from dataclasses import dataclass
import difflib
import itertools
import random
import re
import time
import traceback
from typing import (
    Any,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)

import attr
import pycparser

from .candidate import Candidate, CandidateResult
from .compiler import Compiler
from .perm import perm_eval, perm_gen
from .perm.perm import EvalState
from .profiler import Profiler
from .scorer import Scorer


@attr.s
class EvalError:
    exc_str: str = attr.ib()
    seed: Optional[Tuple[int, int]] = attr.ib()


EvalResult = Union[CandidateResult, EvalError]


class NeedMoreWork:
    pass


@dataclass
class Finished:
    reason: Optional[str] = None


Task = Union[Finished, Tuple[int, int]]
Feedback = Union[NeedMoreWork, Finished, Tuple[int, EvalResult]]


class Permuter:
    """
    Represents a single source from which permutation candidates can be generated,
    and which keeps track of good scores achieved so far.
    """

    def __init__(
        self,
        dir: str,
        fn_name: Optional[str],
        compiler: Compiler,
        scorer: Scorer,
        source_file: str,
        source: str,
        *,
        force_seed: Optional[int],
        force_rng_seed: Optional[int],
        keep_prob: float,
        need_all_sources: bool,
    ) -> None:
        self.dir = dir
        self.compiler = compiler
        self.scorer = scorer
        self.source_file = source_file
        self.source = source

        if fn_name is None:
            fns = _find_fns(source)
            if len(fns) == 0:
                raise Exception(f"{self.source_file} does not contain any function!")
            if len(fns) > 1:
                raise Exception(
                    f"{self.source_file} must contain only one function, "
                    "or have a function.txt next to it with a function name."
                )
            self.fn_name = fns[0]
        else:
            self.fn_name = fn_name
        self.unique_name = self.fn_name

        self._parser = pycparser.CParser()
        self._permutations = perm_gen.perm_gen(source)

        self._force_seed = force_seed
        self._force_rng_seed = force_rng_seed
        self._cur_seed: Optional[Tuple[int, int]] = None

        self.keep_prob = keep_prob
        self._need_all_sources = need_all_sources

        (
            self.base_score,
            self.base_hash,
            self.base_source,
        ) = self._create_and_score_base()
        self.best_score = self.base_score
        self.hashes = {self.base_hash}
        self._cur_cand: Optional[Candidate] = None
        self._last_score: Optional[int] = None

    def _create_and_score_base(self) -> Tuple[int, str, str]:
        base_source = perm_eval.perm_evaluate_one(self._permutations)
        base_cand = Candidate.from_source(
            base_source, self.fn_name, self._parser, rng_seed=0
        )
        o_file = base_cand.compile(self.compiler, show_errors=True)
        if not o_file:
            raise Exception(f"Unable to compile {self.source_file}")
        base_result = base_cand.score(self.scorer, o_file)
        return base_result.score, base_result.hash, base_cand.get_source()

    def _need_to_send_source(self, result: CandidateResult) -> bool:
        if self._need_all_sources:
            return True
        if result.score < self.base_score:
            return True
        if result.score == self.base_score:
            return result.hash != self.base_hash
        return False

    def _eval_candidate(self, seed: int) -> CandidateResult:
        t0 = time.time()

        # Determine if we should keep the last candidate.
        # Don't keep 0-score candidates; we'll only create new, worse, zeroes.
        keep = (
            self._permutations.is_random()
            and random.uniform(0, 1) < self.keep_prob
            and self._last_score != 0
        ) or self._force_rng_seed

        self._last_score = None

        # Create a new candidate if we didn't keep the last one (or if the last one didn't exist)
        # N.B. if we decide to keep the previous candidate, we will skip over the provided seed.
        # This means we're not guaranteed to test all seeds, but it doesn't really matter since
        # we're randomizing anyway.
        if not self._cur_cand or not keep:
            cand_c = self._permutations.evaluate(seed, EvalState())
            rng_seed = self._force_rng_seed or random.randrange(1, 10 ** 20)
            self._cur_seed = (seed, rng_seed)
            self._cur_cand = Candidate.from_source(
                cand_c, self.fn_name, self._parser, rng_seed=rng_seed
            )

        # Randomize the candidate
        if self._permutations.is_random():
            self._cur_cand.randomize_ast()

        t1 = time.time()

        self._cur_cand.get_source()

        t2 = time.time()

        o_file = self._cur_cand.compile(self.compiler)

        t3 = time.time()

        result = self._cur_cand.score(self.scorer, o_file)

        t4 = time.time()

        profiler: Profiler = result.profiler
        profiler.add_stat(Profiler.StatType.perm, t1 - t0)
        profiler.add_stat(Profiler.StatType.stringify, t2 - t1)
        profiler.add_stat(Profiler.StatType.compile, t3 - t2)
        profiler.add_stat(Profiler.StatType.score, t4 - t3)

        self._last_score = result.score

        if not self._need_to_send_source(result):
            result.source = None

        return result

    def seed_generator(self) -> Iterable[int]:
        if self._force_seed is None:
            return perm_eval.perm_gen_all_seeds(self._permutations, random.Random())
        if self._permutations.is_random():
            return itertools.repeat(self._force_seed)
        return [self._force_seed]

    def try_eval_candidate(self, seed: int) -> EvalResult:
        try:
            return self._eval_candidate(seed)
        except Exception:
            return EvalError(exc_str=traceback.format_exc(), seed=self._cur_seed)

    def diff(self, other_source: str) -> str:
        # Return a unified white-space-ignoring diff
        class Line(str):
            def __eq__(self, other: Any) -> bool:
                return isinstance(other, str) and self.strip() == other.strip()

            def __hash__(self) -> int:
                return hash(self.strip())

        a = list(map(Line, self.base_source.split("\n")))
        b = list(map(Line, other_source.split("\n")))
        return "\n".join(
            difflib.unified_diff(a, b, fromfile="before", tofile="after", lineterm="")
        )


def _find_fns(source: str) -> List[str]:
    fns = re.findall(r"(\w+)\([^()\n]*\)\s*?{", source)
    return [
        fn
        for fn in fns
        if not fn.startswith("PERM") and fn not in ["if", "for", "switch", "while"]
    ]
