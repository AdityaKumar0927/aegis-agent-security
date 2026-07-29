"""The lightweight semantic injection classifier.

A linear model (logistic regression) over the combined hashed-ngram + semantic
feature space from :mod:`features`.  Linear + sparse keeps inference in the
tens-of-microseconds range on CPU with no GPU, no transformer and a small memory
footprint - the "lightweight semantic classifier" the spec calls for.
"""
from __future__ import annotations

import hashlib
import os

import numpy as np
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


# Bumped whenever the on-disk artifact layout changes.
MODEL_FORMAT = 1


class InjectionClassifier:
    """Logistic regression over the sparse feature space.

    The trained model is nothing more than a weight vector and an intercept, so
    it is persisted as **plain arrays** (``.npz``) rather than a pickled
    estimator.  That matters twice over:

    * **Safety** - ``joblib``/``pickle`` executes arbitrary objects on load, which
      is an unacceptable sink for a security component that may be pointed at a
      third-party artifact.  ``np.load(..., allow_pickle=False)`` cannot execute
      anything.
    * **Portability** - a pickled estimator is bound to the scikit-learn version
      that produced it, so the shipped model was rejected on any environment that
      resolved a different version (exactly what happened on Python 3.10, where
      pip installs scikit-learn 1.7.x). Plain arrays load anywhere.

    scikit-learn is used for *training* only; inference is a dot product plus a
    sigmoid, so a loaded model needs no estimator object at all.
    """

    def __init__(self, C: float = 4.0):
        self.extractor = FeatureExtractor()
        self.model = LogisticRegression(
            solver="liblinear", C=C, max_iter=3000
        )
        self._fitted = False
        # Populated when loaded from disk; inference then uses these directly.
        self._coef: np.ndarray | None = None
        self._intercept: float = 0.0

    def fit(self, texts: list[str], labels: list[int]) -> InjectionClassifier:
        X = self.extractor.transform(texts)
        self.model.fit(X, np.asarray(labels))
        self._coef = np.asarray(self.model.coef_, dtype=np.float64).ravel()
        self._intercept = float(np.asarray(self.model.intercept_).ravel()[0])
        self._fitted = True
        return self

    @property
    def n_features(self) -> int:
        return int(self._coef.shape[0]) if self._coef is not None else self.extractor.n_features

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        X = self.extractor.transform(texts)
        if self._coef is None:
            raise ModelIntegrityError("classifier has no weights; fit or load a model first")
        # sigmoid(X @ w + b) - identical to LogisticRegression.predict_proba[:, 1]
        z = np.asarray(X @ self._coef).ravel() + self._intercept
        return 1.0 / (1.0 + np.exp(-z))

    def predict_one(self, text: str) -> float:
        return float(self.predict_proba([text])[0])

    # ------------------------------------------------------------------ #
    def save(self, path: str) -> None:
        """Persist the weights as plain arrays + a sibling ``.sha256`` manifest."""
        if self._coef is None:
            raise ModelIntegrityError("nothing to save: the classifier is not fitted")
        np.savez(
            path,
            format=np.array([MODEL_FORMAT]),
            coef=self._coef.astype(np.float64),
            intercept=np.array([self._intercept], dtype=np.float64),
            n_features=np.array([self._coef.shape[0]]),
        )
        digest = _sha256(path)
        with open(path + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(digest + "\n")

    @classmethod
    def _model_path(cls) -> str:
        # The artifact ships inside the package (aegis/data/) so it is importable
        # from an installed wheel.
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(here), "data", "injection_model.npz")

    def load_model(self, path: str, verify: bool = True) -> InjectionClassifier:
        """Load model weights, fail-closed on any integrity problem.

        The artifact is a plain ``.npz`` loaded with ``allow_pickle=False``, so it
        cannot execute code even if an attacker replaces the file - unlike the
        pickled estimator this used to be.  A sibling ``<path>.sha256`` manifest
        is verified first when present, and the weight vector must match the
        feature extractor's dimension, so a silently-invalid model can never be
        used for a live security decision.
        """
        manifest = path + ".sha256"
        if verify and os.path.exists(manifest):
            with open(manifest, encoding="utf-8") as fh:
                expected = fh.read().strip()
            if not expected:
                # A present-but-empty manifest (e.g. a truncated write) must not
                # silently skip verification.
                raise ModelIntegrityError(
                    f"integrity manifest {manifest} is empty; refusing to load")
            actual = _sha256(path)
            if actual != expected:
                raise ModelIntegrityError(
                    f"model integrity check failed for {path}: "
                    f"expected {expected[:12]}..., got {actual[:12]}...")

        try:
            with np.load(path, allow_pickle=False) as data:
                fmt = int(data["format"][0])
                coef = np.asarray(data["coef"], dtype=np.float64).ravel()
                intercept = float(np.asarray(data["intercept"]).ravel()[0])
        except ModelIntegrityError:
            raise
        except Exception as exc:  # noqa: BLE001 - any malformed artifact fails closed
            raise ModelIntegrityError(f"could not read model at {path}: {exc}") from exc

        if fmt != MODEL_FORMAT:
            raise ModelIntegrityError(
                f"model format {fmt} != supported format {MODEL_FORMAT}; retrain")

        expected_dim = self.extractor.n_features
        if coef.shape[0] != expected_dim:
            raise ModelIntegrityError(
                f"model feature dimension {coef.shape[0]} != extractor dimension "
                f"{expected_dim}; the feature pipeline has changed - retrain")

        self._coef = coef
        self._intercept = intercept
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
