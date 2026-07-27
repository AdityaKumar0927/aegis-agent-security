# AEGIS — Measured Results

_All figures are produced by `python -m harness.run_all` on a synthetic, simulated enterprise workload. They are reproducible with the pinned seeds._

## 1. Indirect prompt-injection detection

- Detection rate (act threshold 0.30): **99.8%**
- False-positive rate: **0.00%**  ·  precision 100.0%
- AUC: **1.0000**  ·  test set: 2666 unseen-template samples
- Latency: p50 **1.40 ms**, p95 2.33 ms, p99 3.66 ms (~654/s/thread)

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
- Utility retained on authorized traffic: **99.4%**
- Workload: 6000 requests, 40% adversarial

## 3. Dynamic sandbox routing — exfiltration stress test

- Requests processed: **5,200** at **696 req/s** (~60.1M/day)
- Exfiltration attempts: 1011
- Data-exfiltration incidents WITH AEGIS: **0**
- Would-leak WITHOUT AEGIS (baseline): 1011
- Tier routing: {'restricted': 751, 'read_only': 1793, 'trusted': 583, 'no_net': 36}

## 4. Intent-scrubber optimisation

- Peak memory: naive 2.9 MB → optimised 0.3 MB (**91% reduction**)
- Single-thread throughput: **+1977%** (23,224 → 482,400 docs/s)
- Concurrent throughput (8 workers): **+442%** (19,298 → 104,522 docs/s)
