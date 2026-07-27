"""The lightweight semantic injection classifier.

A linear model (logistic regression) over the combined hashed-ngram + semantic
feature space from :mod:`features`.  Linear + sparse keeps inference in the
tens-of-microseconds range on CPU with no GPU, no transformer and a small memory
footprint - the "lightweight semantic classifier" the spec calls for.
"""
from __future__ import annotations

import os

import numpy as np
from sklearn.linear_model import LogisticRegression

from .dataset import make_dataset
from .features import FeatureExtractor


class InjectionClassifier:
    def __init__(self, C: float = 4.0):
        self.extractor = FeatureExtractor()
        self.model = LogisticRegression(
            solver="liblinear", C=C, max_iter=3000
        )
        self._fitted = False

    def fit(self, texts: list[str], labels: list[int]) -> "InjectionClassifier":
        X = self.extractor.transform(texts)
        self.model.fit(X, np.asarray(labels))
        self._fitted = True
        return self

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        X = self.extractor.transform(texts)
        return self.model.predict_proba(X)[:, 1]

    def predict_one(self, text: str) -> float:
        return float(self.predict_proba([text])[0])

    # ------------------------------------------------------------------ #
    def save(self, path: str) -> None:
        import joblib
        joblib.dump(self.model, path)

    @classmethod
    def _model_path(cls) -> str:
        here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(here, "data", "injection_model.joblib")

    def load_model(self, path: str) -> "InjectionClassifier":
        import joblib
        self.model = joblib.load(path)
        self._fitted = True
        return self


def _fused_scores(clf: "InjectionClassifier", texts: list[str]) -> np.ndarray:
    """The score the live system uses: max(model proba, deterministic rule)."""
    from .detectors import rule_evaluate
    p = clf.predict_proba(texts)
    r = np.array([rule_evaluate(t)[0] for t in texts])
    return np.maximum(p, r)


def train_default(
    n_per_class: int = 4000,
    seed: int = 7,
    target_val_fpr: float = 0.005,
    verbose: bool = False,
) -> tuple[InjectionClassifier, dict]:
    """Train on the synthetic corpus and evaluate honestly.

    Protocol: fit on 80% of train, select the operating threshold on the held-out
    20% validation split (lowest threshold whose validation FPR <= target), then
    report *fused* (model+rules) detection/FPR/precision on the disjoint test set
    (which uses injection templates never seen in training).
    """
    train, test = make_dataset(n_per_class=n_per_class, seed=seed)
    k = int(len(train) * 0.8)
    fit, val = train[:k], train[k:]

    clf = InjectionClassifier()
    clf.fit([s.text for s in fit], [s.label for s in fit])

    yv = np.array([s.label for s in val])
    sv = _fused_scores(clf, [s.text for s in val])
    # choose the lowest threshold whose validation FPR meets the target
    thresh = 0.5
    for t in np.linspace(0.20, 0.95, 151):
        _, fpr, _ = _binary_metrics(yv, sv, t)
        if fpr <= target_val_fpr:
            thresh = round(float(t), 3)
            break

    yt = np.array([s.label for s in test])
    st = _fused_scores(clf, [s.text for s in test])
    metrics = _evaluate(yt, st, thresh)
    metrics.update(n_train=len(fit), n_val=len(val), n_test=len(test),
                   operating_threshold=thresh)

    if verbose:
        print(f"[sanitizer] fit={len(fit)} val={len(val)} test={len(test)} "
              f"(disjoint injection templates)")
        print(f"[sanitizer] operating threshold={thresh:.3f}")
        print(f"[sanitizer] detection(recall)={metrics['recall']:.3f} "
              f"precision={metrics['precision']:.3f} f1={metrics['f1']:.3f} "
              f"fpr={metrics['fpr']:.4f} auc={metrics['auc']:.3f}")
    return clf, metrics


def _binary_metrics(y: np.ndarray, s: np.ndarray, t: float):
    pred = (s >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return recall, fpr, precision


def _evaluate(y_true: np.ndarray, proba: np.ndarray, threshold: float = 0.5) -> dict:
    from sklearn.metrics import roc_auc_score

    y_pred = (proba >= threshold).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    try:
        auc = float(roc_auc_score(y_true, proba))
    except ValueError:
        auc = float("nan")
    return {
        "recall": recall, "precision": precision, "f1": f1, "fpr": fpr,
        "auc": auc, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "threshold": threshold,
    }
