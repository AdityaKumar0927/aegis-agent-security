# AEGIS — Measured Results

_All figures are produced by `python -m harness.run_all` on a synthetic, simulated enterprise workload. They are reproducible with the pinned seeds._

## 1. Indirect prompt-injection detection

- Detection rate (act threshold 0.30): **99.8%**
- False-positive rate: **0.00%**  ·  precision 100.0%
- AUC: **1.0000**  ·  test set: 2666 unseen-template samples
- Latency: p50 **2.12 ms**, p95 3.92 ms, p99 7.46 ms (~422/s/thread)

Leave-one-family-out detection (never-seen attack technique):

| Technique | Detection |
|---|---|
| direct_override | 100.0% |
| fake_system | 100.0% |
| fake_new_policy | 100.0% |
| exfil | 73.2% |
| tool_hijack | 79.0% |
| jailbreak | 100.0% |
| delimiter | 100.0% |
| obfuscated | 81.5% |
| embedded_note | 100.0% |
| multilingual | 100.0% |

## 2. Unauthorized tool-execution control

- Reduction vs. no-enforcement baseline: **100.0%**
- Unauthorized blocked: **100.0%** (2384 → 0 executed)
- Utility retained on authorized traffic: **99.5%**
- Workload: 6000 requests, 40% adversarial

## 3. Dynamic sandbox routing — exfiltration stress test

- Requests processed: **5,200** at **205 req/s** (~17.7M/day)
- Exfiltration attempts: 1011
- Data-exfiltration incidents WITH AEGIS: **0**
- Would-leak WITHOUT AEGIS (baseline): 1011
- Tier routing: {'restricted': 892, 'read_only': 1709, 'trusted': 560, 'no_net': 2}

## 4. Intent-scrubber optimisation

- Peak memory: naive 2.8 MB → optimised 0.3 MB (**90% reduction**)
- Single-thread throughput: **+1946%** (4,272 → 87,434 docs/s)
- Concurrent throughput (8 workers): **+214%** (4,384 → 13,755 docs/s)
