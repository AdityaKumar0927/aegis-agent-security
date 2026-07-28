"""The input-sanitization pipeline: classifier + rules, with latency capture.

``inspect`` is the single entry point the gateway calls.  It fuses the learned
model score with the deterministic rule score (noisy-OR -> take the stronger
signal) so that (a) novel phrasings are caught by the model and (b) blatant
attacks are always caught by the rules, then records wall-clock latency.
"""
from __future__ import annotations

import logging
import os
import threading
import time

from ..errors import ModelIntegrityError
from ..types import SanitizeResult, Source
from .classifier import InjectionClassifier, train_default
from .detectors import rule_evaluate
from .features import top_signals

_log = logging.getLogger("aegis.sanitizer")
_DEFAULT_LOCK = threading.Lock()
_DEFAULT_PIPELINE = None


class SanitizationPipeline:
    def __init__(self, classifier: InjectionClassifier, model_weight: float = 1.0,
                 detection_threshold: float = 0.30):
        self.classifier = classifier
        self.model_weight = model_weight
        self.detection_threshold = detection_threshold

    # ------------------------------------------------------------------ #
    def inspect(self, text: str, source: Source = Source.USER) -> SanitizeResult:
        t0 = time.perf_counter()
        if not text or not text.strip():
            return SanitizeResult(0.0, False, (time.perf_counter() - t0) * 1000.0)

        model_score = self.classifier.predict_one(text) * self.model_weight
        rule_score, hits = rule_evaluate(text)

        # Fuse: take the stronger of the two high-precision views.
        score = max(model_score, rule_score)

        # Content arriving from non-user channels is the indirect-injection
        # surface; nudge borderline scores up slightly for untrusted sources.
        if source.is_untrusted and 0.3 <= score < 0.85:
            score = min(1.0, score + 0.05)

        signals = [h.description for h in sorted(hits, key=lambda h: -h.weight)]
        if not signals:
            signals = top_signals(text)

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return SanitizeResult(
            score=float(score),
            is_injection=score >= self.detection_threshold,
            latency_ms=latency_ms,
            top_signals=signals[:4],
            method="ensemble(model+rules)",
        )

    # ------------------------------------------------------------------ #
    @classmethod
    def default(cls, retrain: bool = False) -> SanitizationPipeline:
        """Process-wide singleton.  Loads the shipped model (integrity-checked)
        or deterministically retrains one in memory.

        On any load problem - a failed integrity check, an incompatible
        scikit-learn version, or a feature-dimension mismatch - this logs a
        warning and retrains **in memory** with a fixed seed (same model every
        time).  It does *not* silently write a model into the source tree; run
        ``python -m aegis.sanitizer.train`` to deliberately regenerate the
        shipped artifact.
        """
        global _DEFAULT_PIPELINE
        with _DEFAULT_LOCK:
            if _DEFAULT_PIPELINE is not None and not retrain:
                return _DEFAULT_PIPELINE
            clf = InjectionClassifier()
            path = InjectionClassifier._model_path()
            loaded = False
            if os.path.exists(path) and not retrain:
                try:
                    clf.load_model(path)
                    loaded = True
                except ModelIntegrityError as exc:
                    _log.warning("model load rejected (%s); retraining in memory. "
                                 "Run 'python -m aegis.sanitizer.train' to refresh "
                                 "the shipped artifact.", exc)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("model load failed (%s); retraining in memory.", exc)
            if not loaded:
                clf, _ = train_default()
            _DEFAULT_PIPELINE = cls(clf)
            return _DEFAULT_PIPELINE
