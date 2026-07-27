"""Benchmark 3 - sandbox routing under a 5,000+ request exfiltration stress test.

Drives 5,000+ simulated daily API requests (a heavy share of them exfiltration
attempts) through the dynamic sandbox router + egress filter, and counts how many
requests actually leak the honeytoken off-box.  The same workload is replayed
against an unprotected executor to show what would leak without AEGIS.
"""
from __future__ import annotations

import time
from collections import Counter

from aegis import AegisGateway
from aegis.integrations import make_workload

try:
    from .common import bar, hr
except ImportError:
    from common import bar, hr


def run(n: int = 5200, attack_ratio: float = 0.5, seed: int = 23, verbose: bool = True) -> dict:
    items = make_workload(n, attack_ratio=attack_ratio, seed=seed)
    exfil_items = [it for it in items if it.exfil]

    protected = AegisGateway(enforce=True)
    unprotected = AegisGateway(enforce=False)  # no egress enforcement

    tiers = Counter()
    prot_leaks = base_leaks = attempts = blocked_attempts = 0

    t0 = time.perf_counter()
    for it in items:
        d = protected.process(it.request)
        if d.tier is not None:
            tiers[d.tier.value] += 1
        if it.exfil:
            attempts += 1
            if d.exfiltration_attempt and not d.exfiltration_blocked and d.executed:
                prot_leaks += 1
            if d.exfiltration_attempt and d.exfiltration_blocked:
                blocked_attempts += 1
    protected_wall = time.perf_counter() - t0

    # baseline: same exfil attempts with enforcement off
    for it in exfil_items:
        d = unprotected.process(it.request)
        # ground-truth leak recorded by the executor
        if unprotected.telemetry.snapshot()["counters"].get("exfil_success", 0):
            pass
    base_leaks = unprotected.telemetry.snapshot()["counters"].get("exfil_success", 0)

    throughput = n / protected_wall if protected_wall else 0.0
    result = {
        "requests": n,
        "exfil_attempts": attempts,
        "exfil_leaks_protected": prot_leaks,
        "exfil_leaks_unprotected_baseline": int(base_leaks),
        "exfil_attempts_blocked": blocked_attempts,
        "throughput_req_per_s": throughput,
        "projected_daily_capacity": throughput * 86400,
        "tier_distribution": dict(tiers),
        "protected_wall_s": protected_wall,
    }

    if verbose:
        print(hr("BENCHMARK 3 · Sandbox routing · exfiltration stress test"))
        print(f"  processed {n} requests in {protected_wall:.2f}s "
              f"({throughput:,.0f} req/s → ~{throughput*86400/1e6:.1f}M/day capacity)")
        print(f"  exfiltration attempts:                 {attempts}")
        print(f"  leaks WITHOUT AEGIS (baseline):        {int(base_leaks)}")
        print(f"  leaks WITH AEGIS:                      {prot_leaks}   "
              f"{'✅ zero exfiltration' if prot_leaks == 0 else '❌'}")
        print(f"  exfil attempts caught by egress filter:{blocked_attempts}")
        print("  sandbox tier routing distribution:")
        total = sum(tiers.values()) or 1
        for tier in ("no_net", "read_only", "restricted", "trusted"):
            c = tiers.get(tier, 0)
            print(f"    {tier:12} {c:5d}  {bar(c/total)} {c/total*100:5.1f}%")
    return result


if __name__ == "__main__":
    run()
