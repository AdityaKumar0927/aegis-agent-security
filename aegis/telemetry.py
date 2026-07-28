"""Lightweight, thread-safe telemetry.

Bounded ring buffers for latency samples (so memory stays flat under sustained
load) plus simple counters.  ``snapshot`` returns a plain dict suitable for
logging or a metrics report.

All shared state is guarded so the concurrent ``aprocess`` path is race-free:
counters and the latency-histogram map are mutated only under a lock, and each
histogram computes its stats under its own lock.
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque

import numpy as np


class LatencyHistogram:
    def __init__(self, maxlen: int = 50_000):
        self._buf: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, ms: float) -> None:
        with self._lock:
            self._buf.append(ms)

    def stats(self) -> dict:
        with self._lock:
            data = np.fromiter(self._buf, dtype=np.float64) if self._buf else np.array([0.0])
            count = len(self._buf)
        return {
            "count": int(count),
            "mean": float(data.mean()),
            "p50": float(np.percentile(data, 50)),
            "p95": float(np.percentile(data, 95)),
            "p99": float(np.percentile(data, 99)),
            "max": float(data.max()),
        }


class Telemetry:
    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)
        self._latency: dict[str, LatencyHistogram] = {}
        self._lock = threading.Lock()

    def incr(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counters[key] += n

    def observe_latency(self, stage: str, ms: float) -> None:
        # Take the map lock only to get-or-create the per-stage histogram; the
        # append itself is guarded by the histogram's own lock.  A plain
        # defaultdict here would let two threads race on __missing__ and lose
        # samples into the discarded histogram.
        with self._lock:
            hist = self._latency.get(stage)
            if hist is None:
                hist = self._latency[stage] = LatencyHistogram()
        hist.record(ms)

    def snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
            hists = list(self._latency.items())   # copy refs under the lock
        latency = {k: h.stats() for k, h in hists}
        return {"counters": counters, "latency": latency}
