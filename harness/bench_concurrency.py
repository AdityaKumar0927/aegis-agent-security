"""Benchmark 4 - intent-scrubber optimisation: memory & concurrency.

Compares the naive baseline scrubber against the optimised implementation on the
same corpus, measuring peak Python heap (retention), single-thread throughput,
and aggregate throughput under concurrent agents.  The optimised algorithm keeps
memory flat (bounded LRU + fast path) and sustains far higher concurrent
throughput.
"""
from __future__ import annotations

import random
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

from aegis.sanitizer.dataset import benign_doc, random_injection
from aegis.scrubber import IntentScrubber, NaiveIntentScrubber

try:
    from .common import bar, hr
except ImportError:
    from common import bar, hr


def _corpus(n: int, pool_size: int = 800, seed: int = 3) -> list[str]:
    """A realistic agent workload: a bounded pool of distinct documents
    (retrieved context, repeated tool outputs, shared instructions) reprocessed
    many times across agents. This recurrence is exactly what a cache exists to
    exploit; the naive scrubber recomputes every time and never benefits.
    """
    rng = random.Random(seed)
    pool = []
    for _ in range(pool_size):
        if rng.random() < 0.3:
            pool.append(benign_doc(rng) + "\n" + random_injection(rng))
        else:
            pool.append(benign_doc(rng))
    # Zipf-ish skew: some documents recur far more often than others.
    weights = [1.0 / (i + 1) for i in range(pool_size)]
    return rng.choices(pool, weights=weights, k=n)


def _peak_mem_mb(make_scrubber, docs) -> float:
    tracemalloc.start()
    tracemalloc.clear_traces()
    scr = make_scrubber()
    for d in docs:
        scr.scrub(d)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1e6


def _throughput(make_scrubber, docs) -> float:
    scr = make_scrubber()
    t0 = time.perf_counter()
    for d in docs:
        scr.scrub(d)
    dt = time.perf_counter() - t0
    return len(docs) / dt if dt else 0.0


def _concurrent_throughput(make_scrubber, docs, workers: int) -> float:
    # each worker owns a scrubber instance (models sharded agent workers)
    chunks = [docs[i::workers] for i in range(workers)]
    scrubbers = [make_scrubber() for _ in range(workers)]

    def work(i):
        s = scrubbers[i]
        for d in chunks[i]:
            s.scrub(d)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, range(workers)))
    dt = time.perf_counter() - t0
    return len(docs) / dt if dt else 0.0


def run(n: int = 20000, workers: int = 8, verbose: bool = True) -> dict:
    docs = _corpus(n)

    naive_mem = _peak_mem_mb(NaiveIntentScrubber, docs)
    opt_mem = _peak_mem_mb(IntentScrubber, docs)

    naive_tps = _throughput(NaiveIntentScrubber, docs)
    opt_tps = _throughput(IntentScrubber, docs)

    naive_ctps = _concurrent_throughput(NaiveIntentScrubber, docs, workers)
    opt_ctps = _concurrent_throughput(IntentScrubber, docs, workers)

    result = {
        "n_docs": n, "workers": workers,
        "naive_peak_mem_mb": naive_mem, "opt_peak_mem_mb": opt_mem,
        "mem_reduction": 1 - opt_mem / naive_mem if naive_mem else 0.0,
        "naive_throughput": naive_tps, "opt_throughput": opt_tps,
        "throughput_gain": opt_tps / naive_tps - 1 if naive_tps else 0.0,
        "naive_concurrent_throughput": naive_ctps, "opt_concurrent_throughput": opt_ctps,
        "concurrency_gain": opt_ctps / naive_ctps - 1 if naive_ctps else 0.0,
        "naive_mem_per_1k": naive_mem / (n / 1000), "opt_mem_per_1k": opt_mem / (n / 1000),
    }

    if verbose:
        print(hr("BENCHMARK 4 · Intent-scrubber optimisation (memory & concurrency)"))
        print(f"  corpus: {n:,} documents, {workers} concurrent workers")
        print(f"  peak heap   naive {naive_mem:7.1f} MB   optimised {opt_mem:7.1f} MB"
              f"   → {result['mem_reduction']*100:5.1f}% less  {bar(result['mem_reduction'])}")
        print(f"  mem / 1k    naive {result['naive_mem_per_1k']:7.2f} MB   "
              f"optimised {result['opt_mem_per_1k']:7.2f} MB")
        print(f"  throughput  naive {naive_tps:8,.0f}/s   optimised {opt_tps:8,.0f}/s"
              f"   → {result['throughput_gain']*100:5.1f}% faster")
        print(f"  concurrent  naive {naive_ctps:8,.0f}/s   optimised {opt_ctps:8,.0f}/s"
              f"   → {result['concurrency_gain']*100:5.1f}% higher capacity")
    return result


if __name__ == "__main__":
    run()
