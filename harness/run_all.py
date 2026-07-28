"""Run the full AEGIS benchmark suite and write a consolidated report.

    python -m harness.run_all          # from the project root

Writes reports/results.json and reports/RESULTS.md with the measured numbers.
"""
from __future__ import annotations

import json
import os
import sys
import time

try:
    from . import bench_concurrency, bench_injection, bench_toolguard, stress_sandbox
    from .common import REPORT_DIR, hr
except ImportError:
    import bench_concurrency
    import bench_injection
    import bench_toolguard
    import stress_sandbox
    from common import REPORT_DIR, hr


def _utf8_stdout() -> None:
    """The report uses box-drawing glyphs; force UTF-8 so the default Windows
    cp1252 console doesn't raise UnicodeEncodeError."""
    import contextlib
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


def _atomic_write(path: str, text: str) -> None:
    """Write UTF-8 to a temp file in the same dir, then atomically replace."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def main() -> dict:
    _utf8_stdout()
    print(hr("AEGIS · Agentic Execution Guardrail & Injection Shield"))
    print("Running full benchmark suite (all numbers below are freshly measured)…")

    # Ensure the classifier is trained/cached before timing anything.
    from aegis.sanitizer import SanitizationPipeline
    SanitizationPipeline.default()

    t0 = time.perf_counter()
    results = {
        "injection": bench_injection.run(),
        "toolguard": bench_toolguard.run(),
        "sandbox": stress_sandbox.run(),
        "concurrency": bench_concurrency.run(),
    }
    results["_wall_seconds"] = time.perf_counter() - t0

    os.makedirs(REPORT_DIR, exist_ok=True)
    _atomic_write(os.path.join(REPORT_DIR, "results.json"),
                  json.dumps(results, indent=2))
    _write_markdown(results)

    print(hr("HEADLINE RESULTS"))
    inj, tg, sb, cc = (results["injection"], results["toolguard"],
                       results["sandbox"], results["concurrency"])
    print(f"  • Injection detection:      {inj['detection_at_act']*100:.1f}% "
          f"@ {inj['fpr_at_act']*100:.2f}% FPR, {inj['latency_ms']['p50']:.2f}ms p50 "
          f"(AUC {inj['auc']:.3f})")
    print(f"  • Unauthorized execution:   {tg['reduction_vs_baseline']*100:.1f}% reduction, "
          f"{tg['utility']*100:.1f}% utility retained")
    print(f"  • Exfiltration stress test: {sb['exfil_leaks_protected']} leaks over "
          f"{sb['requests']:,} requests (baseline would leak {sb['exfil_leaks_unprotected_baseline']})")
    print(f"  • Intent-scrubber optimise: {cc['mem_reduction']*100:.0f}% less memory, "
          f"{cc['concurrency_gain']*100:.0f}% higher concurrent throughput")
    print(f"\n  report written to reports/RESULTS.md  ({results['_wall_seconds']:.1f}s total)")
    return results


def _write_markdown(r: dict) -> None:
    inj, tg, sb, cc = r["injection"], r["toolguard"], r["sandbox"], r["concurrency"]
    lines = [
        "# AEGIS — Measured Results",
        "",
        "_All figures are produced by `python -m harness.run_all` on a synthetic, "
        "simulated enterprise workload. They are reproducible with the pinned seeds._",
        "",
        "## 1. Indirect prompt-injection detection",
        "",
        f"- Detection rate (act threshold {inj['act_threshold']:.2f}): **{inj['detection_at_act']*100:.1f}%**",
        f"- False-positive rate: **{inj['fpr_at_act']*100:.2f}%**  ·  precision {inj['precision_at_act']*100:.1f}%",
        f"- AUC: **{inj['auc']:.4f}**  ·  test set: {inj['n_test']} unseen-template samples",
        f"- Latency: p50 **{inj['latency_ms']['p50']:.2f} ms**, p95 {inj['latency_ms']['p95']:.2f} ms, "
        f"p99 {inj['latency_ms']['p99']:.2f} ms (~{inj['throughput_per_s_1thread']:.0f}/s/thread)",
        "",
        "Leave-one-family-out detection (never-seen attack technique):",
        "",
        "| Technique | Detection |",
        "|---|---|",
    ]
    for fam, rec in inj["lofo"].items():
        lines.append(f"| {fam} | {rec*100:.1f}% |")
    lines += [
        "",
        "## 2. Unauthorized tool-execution control",
        "",
        f"- Reduction vs. no-enforcement baseline: **{tg['reduction_vs_baseline']*100:.1f}%**",
        f"- Unauthorized blocked: **{tg['unauthorized_blocked_rate']*100:.1f}%** "
        f"({tg['unauthorized_executed_baseline']} → {tg['unauthorized_executed_protected']} executed)",
        f"- Utility retained on authorized traffic: **{tg['utility']*100:.1f}%**",
        f"- Workload: {tg['n']} requests, {tg['attack_ratio']*100:.0f}% adversarial",
        "",
        "## 3. Dynamic sandbox routing — exfiltration stress test",
        "",
        f"- Requests processed: **{sb['requests']:,}** at "
        f"**{sb['throughput_req_per_s']:,.0f} req/s** (~{sb['projected_daily_capacity']/1e6:.1f}M/day)",
        f"- Exfiltration attempts: {sb['exfil_attempts']}",
        f"- Data-exfiltration incidents WITH AEGIS: **{sb['exfil_leaks_protected']}**",
        f"- Would-leak WITHOUT AEGIS (baseline): {sb['exfil_leaks_unprotected_baseline']}",
        f"- Tier routing: {sb['tier_distribution']}",
        "",
        "## 4. Intent-scrubber optimisation",
        "",
        f"- Peak memory: naive {cc['naive_peak_mem_mb']:.1f} MB → optimised "
        f"{cc['opt_peak_mem_mb']:.1f} MB (**{cc['mem_reduction']*100:.0f}% reduction**)",
        f"- Single-thread throughput: **+{cc['throughput_gain']*100:.0f}%** "
        f"({cc['naive_throughput']:,.0f} → {cc['opt_throughput']:,.0f} docs/s)",
        f"- Concurrent throughput ({cc['workers']} workers): **+{cc['concurrency_gain']*100:.0f}%** "
        f"({cc['naive_concurrent_throughput']:,.0f} → {cc['opt_concurrent_throughput']:,.0f} docs/s)",
        "",
    ]
    _atomic_write(os.path.join(REPORT_DIR, "RESULTS.md"), "\n".join(lines))


if __name__ == "__main__":
    main()
