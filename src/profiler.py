from enum import Enum
import time


class Profiler:
    class StatType(Enum):
        perm = 1
        stringify = 2
        compile = 3
        score = 4

    def __init__(self) -> None:
        self.time_stats = {x: 0.0 for x in Profiler.StatType}

    def add_stat(self, stat: StatType, time_taken: float) -> None:
        self.time_stats[stat] += time_taken

    def get_str_stats(self) -> str:
        total_time = sum(self.time_stats[e] for e in self.time_stats)
        timings = ", ".join(
            f"{round(100 * self.time_stats[e] / total_time)}% {e.name}"
            for e in self.time_stats
        )
        return timings


class Timer:
    def __init__(self) -> None:
        self._time = time.monotonic()

    def tick(self) -> float:
        """Return time elapsed since construction or last call to `tick`."""
        last = self._time
        self._time = time.monotonic()
        return self._time - last
