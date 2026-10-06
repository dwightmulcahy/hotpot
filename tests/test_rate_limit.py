import unittest

from hotpot.rate_limit import EventRateLimiter


class EventRateLimiterTests(unittest.TestCase):
    def test_burst_then_suppress_then_report_pending(self):
        limiter = EventRateLimiter(60, 2, ttl_seconds=60)
        self.assertEqual(limiter.admit("203.0.113.1", now=0), (True, 0))
        self.assertEqual(limiter.admit("203.0.113.1", now=0), (True, 0))
        self.assertEqual(limiter.admit("203.0.113.1", now=0), (False, 0))
        self.assertEqual(limiter.admit("203.0.113.1", now=0), (False, 0))
        self.assertEqual(limiter.pending("203.0.113.1"), 2)

        # 60/minute refills one token per second. The first durable event after
        # recovery carries the number of events suppressed since the prior one.
        self.assertEqual(limiter.admit("203.0.113.1", now=1), (True, 2))
        self.assertEqual(limiter.pending("203.0.113.1"), 0)
        self.assertEqual(limiter.suppressed_total("203.0.113.1"), 2)

    def test_zero_rate_disables_suppression(self):
        limiter = EventRateLimiter(0, 1)
        for _ in range(100):
            self.assertEqual(limiter.admit("203.0.113.2", now=0), (True, 0))

    def test_stale_sources_are_pruned(self):
        limiter = EventRateLimiter(60, 1, ttl_seconds=60)
        limiter.admit("203.0.113.3", now=0)
        self.assertEqual(limiter.prune(now=61), 1)


if __name__ == "__main__":
    unittest.main()
