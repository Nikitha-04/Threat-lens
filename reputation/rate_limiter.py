import logging
import threading
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token-bucket rate limiter.
    Default: 4 requests per 60 seconds (VirusTotal free tier).
    """

    def __init__(self, max_calls: int = 4, period_seconds: float = 60.0):
        self.max_calls = max_calls
        self.period = period_seconds
        self._lock = threading.Lock()
        self._calls: list[float] = []  # timestamps of recent calls

    def acquire(self) -> None:
        """Block until a request slot is available."""
        with self._lock:
            now = time.monotonic()
            # Drop timestamps older than the window
            self._calls = [t for t in self._calls if now - t < self.period]

            if len(self._calls) >= self.max_calls:
                oldest = self._calls[0]
                wait = self.period - (now - oldest)
                if wait > 0:
                    logger.info("Rate limiter holding: waiting %.1fs for next request slot...", wait)
                    time.sleep(wait)
                # Refresh after sleeping
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.period]

            self._calls.append(time.monotonic())

    def pending_count(self) -> int:
        """Return how many calls are in the current window."""
        with self._lock:
            now = time.monotonic()
            return len([t for t in self._calls if now - t < self.period])
