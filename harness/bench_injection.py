"""Benchmark 1 - indirect prompt-injection detection.

Reports, at the thresholds the live gateway actually uses:
* detection rate (recall), false-positive rate, precision, AUC on a test set of
  *unseen injection templates*;
* per-sample inference latency (p50/p95/p99) on CPU;
* a leave-one-family-out robustness check - train with a whole attack technique
  removed, then measure detection on that never-seen technique.
"""
from __future__ import annotations

import random
import time

import numpy as np

from aegis.config import DEFAULT_CONFIG
from aegis.sanitizer import SanitizationPipeline
from aegis.sanitizer.classifier import InjectionClassifier
from aegis.sanitizer.dataset import (
    INJECTION_TEMPLATES,
    benign_doc,
    make_dataset,
    random_injection,
)
from aegis.sanitizer.detectors import rule_evaluate
from aegis.types import Source

try:
    from .common import bar, hr, percentiles
except ImportError:
    from common import bar, hr, percentiles


def _metrics(y, s, t):
    pred = (s >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    return rec, fpr, prec


def run(verbose: bool = True) -> dict:
    th = DEFAULT_CONFIG.thresholds
    pipe = SanitizationPipeline.default()

    # Disjoint-template test set (same protocol as training).
    _, test = make_dataset(n_per_class=4000, seed=7)
    y = np.array([s.label for s in test])
    scores = np.array([pipe.inspect(s.text, Source.TOOL_OUTPUT).score for s in test])

    from sklearn.metrics import roc_auc_score
    auc = float(roc_auc_score(y, scores))
    det_act, fpr_act, prec_act = _metrics(y, scores, th.injection_sanitize)
    det_blk, fpr_blk, prec_blk = _metrics(y, scores, th.injection_block)

    # Latency (single-thread, warm)
    sample = [s.text for s in test[:3000]]
    for s in sample[:100]:
        pipe.inspect(s, Source.TOOL_OUTPUT)
    lat = []
    for s in sample:
        t0 = time.perf_counter()
        pipe.inspect(s, Source.TOOL_OUTPUT)
        lat.append((time.perf_counter() - t0) * 1000.0)
    lat_stats = percentiles(lat)

    # Leave-one-family-out robustness (unseen attack technique)
    lofo = _leave_one_family_out(th.injection_sanitize)

    result = {
        "n_test": len(test),
        "auc": auc,
        "act_threshold": th.injection_sanitize,
        "block_threshold": th.injection_block,
        "detection_at_act": det_act, "fpr_at_act": fpr_act, "precision_at_act": prec_act,
        "detection_at_block": det_blk, "fpr_at_block": fpr_blk, "precision_at_block": prec_blk,
        "latency_ms": lat_stats,
        "throughput_per_s_1thread": 1000.0 / lat_stats["mean"] if lat_stats["mean"] else 0,
        "lofo": lofo,
    }

    if verbose:
        print(hr("BENCHMARK 1 · Indirect prompt-injection detection"))
        print(f"  test set: {len(test)} samples (unseen injection templates)")
        print(f"  AUC                      {auc:.4f}")
        print(f"  detection @ act ({th.injection_sanitize:.2f})   {det_act*100:6.2f}%  {bar(det_act)}")
        print(f"  false-positive rate      {fpr_act*100:6.2f}%")
        print(f"  precision                {prec_act*100:6.2f}%")
        print(f"  detection @ block ({th.injection_block:.2f}) {det_blk*100:6.2f}%   (high-confidence blocks)")
        print(f"  latency  p50={lat_stats['p50']:.3f}ms  p95={lat_stats['p95']:.3f}ms  "
              f"p99={lat_stats['p99']:.3f}ms  ({result['throughput_per_s_1thread']:.0f}/s/thread)")
        print("  leave-one-family-out detection (never-seen technique):")
        for fam, rec in lofo.items():
            print(f"    {fam:16} {rec*100:6.2f}%  {bar(rec)}")
    return result


def _leave_one_family_out(act_threshold: float, n: int = 1500, seed: int = 5) -> dict:
    families = list(INJECTION_TEMPLATES)
    out = {}
    for held in families:
        rng = random.Random(seed)
        train_fams = [f for f in families if f != held]
        texts, labels = [], []
        for _ in range(n):
            texts.append(random_injection(rng, rng.choice(train_fams)))
            labels.append(1)
            texts.append(benign_doc(rng))
            labels.append(0)
        clf = InjectionClassifier().fit(texts, labels)
        # test on the unseen technique
        hits = tot = 0
        for _ in range(400):
            inj = random_injection(rng, held)
            score = max(clf.predict_one(inj), rule_evaluate(inj)[0])
            hits += int(score >= act_threshold)
            tot += 1
        out[held] = hits / tot
    return out


if __name__ == "__main__":
    run()
