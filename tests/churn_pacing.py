"""Test workload pacing; never changes production admission or OS TCP limits."""
import math
import threading
import time


class StartPacer:
    def __init__(self, per_second: float, clock=time.monotonic):
        if not math.isfinite(per_second) or per_second < 0:
            raise ValueError('Rate must be finite and nonnegative')
        self.rate = per_second
        self.clock = clock
        self.next_start = clock()
        self.lock = threading.Lock()

    def delay(self) -> float:
        """Reserve one start slot; caller waits cancellably before connecting.

        Rate zero means unpaced. This limits starts, not concurrent capacity;
        the independent baseline phase still holds all 128 actual channels.
        """
        if self.rate == 0:
            return 0.0
        with self.lock:
            now = self.clock()
            scheduled = max(now, self.next_start)
            self.next_start = scheduled + 1.0 / self.rate
            return max(0.0, scheduled - now)
