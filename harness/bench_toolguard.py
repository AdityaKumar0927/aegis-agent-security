"""Benchmark 2 - reduction in unauthorized API tool execution.

Runs a mixed multi-agent workload (authorized work + RBAC violations,
trust-floor breaches, injected tool-hijacks, exfiltration) through the gateway
twice: once in monitor-only mode (a stand-in for "no enforcement") and once with
AEGIS enforcing.  Reports how many unauthorized tool calls execute in each case,
the resulting reduction, and the utility retained on authorized traffic.
"""
from __future__ import annotations

from collections import defaultdict

from aegis import AegisGateway
from aegis.integrations import make_workload

try:
    from .common import bar, hr
except ImportError:
    from common import bar, hr


def run(n: int = 6000, attack_ratio: float = 0.4, seed: int = 11, verbose: bool = True) -> dict:
    items = make_workload(n, attack_ratio=attack_ratio, seed=seed)

    protected = AegisGateway(enforce=True)
    baseline = AegisGateway(enforce=False)   # monitor-only: logs, never blocks

    by_kind = defaultdict(lambda: [0, 0])    # [executed_protected, total]
    auth_exec = auth_tot = 0
    unauth_exec_prot = unauth_exec_base = unauth_tot = 0

    for it in items:
        dp = protected.process(it.request)
        db = baseline.process(it.request)
        by_kind[it.kind][1] += 1
        by_kind[it.kind][0] += dp.executed
        if it.authorized:
            auth_tot += 1
            auth_exec += dp.executed
        else:
            unauth_tot += 1
            unauth_exec_prot += dp.executed
            unauth_exec_base += db.executed

    reduction = 1.0 - (unauth_exec_prot / unauth_exec_base) if unauth_exec_base else 0.0
    result = {
        "n": n, "attack_ratio": attack_ratio,
        "authorized_total": auth_tot, "authorized_executed": auth_exec,
        "utility": auth_exec / auth_tot if auth_tot else 0.0,
        "unauthorized_total": unauth_tot,
        "unauthorized_executed_baseline": unauth_exec_base,
        "unauthorized_executed_protected": unauth_exec_prot,
        "unauthorized_blocked_rate": 1 - unauth_exec_prot / unauth_tot if unauth_tot else 0.0,
        "reduction_vs_baseline": reduction,
        "by_kind": {k: {"executed": v[0], "total": v[1]} for k, v in by_kind.items()},
    }

    if verbose:
        print(hr("BENCHMARK 2 · Unauthorized tool-execution control"))
        print(f"  workload: {n} requests ({attack_ratio*100:.0f}% adversarial), "
              f"{auth_tot} authorized / {unauth_tot} unauthorized")
        print(f"  unauthorized executed WITHOUT enforcement: {unauth_exec_base}/{unauth_tot}")
        print(f"  unauthorized executed WITH AEGIS:          {unauth_exec_prot}/{unauth_tot}")
        print(f"  reduction in unauthorized execution:       {reduction*100:6.2f}%  {bar(reduction)}")
        print(f"  unauthorized blocked:                      {result['unauthorized_blocked_rate']*100:6.2f}%")
        print(f"  utility retained (authorized executed):    {result['utility']*100:6.2f}%  {bar(result['utility'])}")
        print("  by attack kind (executed / total, lower is better except benign):")
        for k, v in sorted(by_kind.items()):
            print(f"    {k:16} {v[0]:4d}/{v[1]:<4d}")
    return result


if __name__ == "__main__":
    run()
