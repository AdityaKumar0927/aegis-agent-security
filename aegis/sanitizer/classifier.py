"""The lightweight semantic injection classifier.

A linear model (logistic regression) over the combined hashed-ngram + semantic
feature space from :mod:`features`.  Linear + sparse keeps inference in the
tens-of-microseconds range on CPU with no GPU, no transformer and a small memory
footprint - the "lightweight semantic classifier" the spec calls for.
"""
from __future__ import annotations

import hashlib
import os
import warnings

import numpy as np
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.linear_model import LogisticRegression

from ..errors import ModelIntegrityError
from .dataset import make_dataset
from .features import FeatureExtractor


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class InjectionClassifier:
    def __init__(self, C: float = 4.0):
        self.extractor = FeatureExtractor()
        self.model = LogisticRegression(
            solver="liblinear", C=C, max_iter=3000
        )
        self._fitted = False

    def fit(self, texts: list[str], labels: list[int]) -> InjectionClassifier:
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
        """Persist the model and write a sibling ``.sha256`` integrity manifest."""
        import joblib
        joblib.dump(self.model, path)
        digest = _sha256(path)
        with open(path + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(digest + "\n")

    @classmethod
    def _model_path(cls) -> str:
        # The artifact ships inside the package (aegis/data/) so it is importable
        # from an installed wheel; fall back to the repo-root data/ dir for an
        # editable checkout that predates the move.
        here = os.path.dirname(os.path.abspath(__file__))
        pkg = os.path.join(os.path.dirname(here), "data", "injection_model.joblib")
        if os.path.exists(pkg):
            return pkg
        repo = os.path.join(
            os.path.dirname(os.path.dirname(here)), "data", "injection_model.joblib")
        return repo if os.path.exists(repo) else pkg

    def load_model(self, path: str, verify: bool = True) -> InjectionClassifier:
        """Load a pickled model.

        ``joblib.load`` unpickles arbitrary objects, so a tampered/untrusted model
        file is a code-execution sink.  When a sibling ``<path>.sha256`` manifest
        exists it is verified first and a mismatch raises
        :class:`ModelIntegrityError` (fail-closed - the caller retrains rather
        than executing an unknown pickle).  A scikit-learn version mismatch or a
        feature-dimension mismatch also raises, so a silently-invalid model can't
        be used for live security decisions.
        """
        import joblib

        manifest = path + ".sha256"
        if verify and os.path.exists(manifest):
            with open(manifest, encoding="utf-8") as fh:
                expected = fh.read().strip()
            actual = _sha256(path)
            if expected and actual != expected:
                raise ModelIntegrityError(
                    f"model integrity check failed for {path}: "
                    f"expected {expected[:12]}..., got {actual[:12]}...")

        with warnings.catch_warnings():
            # A cross-version pickle is not trustworthy for security decisions.
            warnings.simplefilter("error", InconsistentVersionWarning)
            try:
                model = joblib.load(path)
            except InconsistentVersionWarning as exc:
                raise ModelIntegrityError(
                    f"model at {path} was pickled by an incompatible "
                    f"scikit-learn version: {exc}") from exc

        expected_dim = self.extractor.n_features
        n_in = getattr(model, "n_features_in_", None)
        if n_in is not None and n_in != expected_dim:
            raise ModelIntegrityError(
                f"model feature dimension {n_in} != extractor dimension "
                f"{expected_dim}; the feature pipeline has changed - retrain")

        self.model = model
        self._fitted = True
        return self


def _fused_scores(clf: InjectionClassifier, texts: list[str]) -> np.ndarray:
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
