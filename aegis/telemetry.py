"""Lightweight, thread-safe telemetry.

Bounded ring buffers for latency samples (so memory stays flat under sustained
load) plus simple counters.  ``snapshot`` returns a plain dict suitable for
logging or a metrics report.

All shared state is guarded so the concurrent ``aprocess`` path is race-free:
counters and the latency-histogram map are mutated only under a lock, and each
histogram computes its stats under its own lock.
"""
from __future__ import annotations

import re
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

    # ------------------------------------------------------------------ #
    def prometheus(self, prefix: str = "aegis") -> str:
        """Render the current snapshot in Prometheus text exposition format.

        Intended to be served from the host application's ``/metrics`` endpoint::

            return Response(gateway.telemetry.prometheus(),
                            mimetype="text/plain; version=0.0.4")
        """
        snap = self.snapshot()
        lines: list[str] = []

        def _name(raw: str) -> str:
            return re.sub(r"[^a-zA-Z0-9_]", "_", raw)

        emitted: set[str] = set()
        for key, value in sorted(snap["counters"].items()):
            # 'verdict.block' -> aegis_verdict_total{verdict="block"}
            if "." in key:
                family, label = key.split(".", 1)
                metric = f"{prefix}_{_name(family)}_total"
                if metric not in emitted:
                    lines.append(f"# TYPE {metric} counter")
                    emitted.add(metric)
                lines.append(f'{metric}{{{_name(family)}="{label}"}} {value}')
            else:
                metric = f"{prefix}_{_name(key)}_total"
                if metric not in emitted:
                    lines.append(f"# TYPE {metric} counter")
                    emitted.add(metric)
                lines.append(f"{metric} {value}")

        for stage, stats in sorted(snap["latency"].items()):
            metric = f"{prefix}_stage_latency_ms"
            if metric not in emitted:
                lines.append(f"# TYPE {metric} gauge")
                emitted.add(metric)
            for q in ("p50", "p95", "p99"):
                lines.append(f'{metric}{{stage="{_name(stage)}",quantile="{q}"}} {stats[q]:.4f}')
            lines.append(f'{prefix}_stage_observations_total{{stage="{_name(stage)}"}} {stats["count"]}')

        return "\n".join(lines) + "\n"

    def health(self) -> dict:
        """A liveness/readiness summary suitable for a health endpoint.

        ``ok`` is False when the gateway has recorded internal errors, so an
        orchestrator can surface a degraded guard rather than silently trusting
        it.  ``error_rate`` is errors per processed request.
        """
        snap = self.snapshot()
        counters = snap["counters"]
        requests = counters.get("requests", 0)
        errors = counters.get("errors", 0)
        total = requests + errors
        return {
            "ok": errors == 0,
            "status": "ok" if errors == 0 else "degraded",
            "requests": requests,
            "errors": errors,
            "error_rate": (errors / total) if total else 0.0,
            "blocks": counters.get("verdict.block", 0),
            "exfiltration_attempts": counters.get("exfil_attempts", 0),
            "exfiltration_successes": counters.get("exfil_success", 0),
        }
