"""Regenerate the shipped injection-detection model artifact.

Run deliberately (never at import time)::

    python -m aegis.sanitizer.train              # -> aegis/data/injection_model.npz
    python -m aegis.sanitizer.train --out /tmp/m.npz

Training is deterministic (fixed seed), so the artifact is reproducible.  A
sibling ``<out>.sha256`` integrity manifest is written alongside it, which the
loader verifies before unpickling.
"""
from __future__ import annotations

import argparse
import os

from .classifier import InjectionClassifier, train_default


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the AEGIS injection model.")
    ap.add_argument("--out", default=InjectionClassifier._model_path(),
                    help="output .npz path (default: packaged artifact)")
    ap.add_argument("--n-per-class", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    clf, metrics = train_default(n_per_class=args.n_per_class, seed=args.seed, verbose=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    clf.save(args.out)
    print(f"[train] wrote {args.out} (+ .sha256)")
    print(f"[train] recall={metrics['recall']:.3f} precision={metrics['precision']:.3f} "
          f"fpr={metrics['fpr']:.4f} auc={metrics['auc']:.3f} "
          f"threshold={metrics['operating_threshold']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
