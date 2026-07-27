"""Shared helpers for the benchmark harness."""
from __future__ import annotations

import os
import sys

import numpy as np

# make the package importable when run as `python harness/xyz.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


def percentiles(values) -> dict:
    a = np.asarray(values, dtype=np.float64)
    if a.size == 0:
        a = np.array([0.0])
    return {
        "mean": float(a.mean()),
        "p50": float(np.percentile(a, 50)),
        "p95": float(np.percentile(a, 95)),
        "p99": float(np.percentile(a, 99)),
        "max": float(a.max()),
    }


def bar(frac: float, width: int = 28) -> str:
    n = int(round(frac * width))
    return "█" * n + "·" * (width - n)


def hr(title: str = "") -> str:
    line = "─" * 66
    return f"\n{line}\n{title}\n{line}" if title else line
