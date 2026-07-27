"""Input sanitization pipeline: lightweight semantic detection of indirect
prompt injection."""
from .classifier import InjectionClassifier, train_default
from .detectors import rule_evaluate
from .pipeline import SanitizationPipeline

__all__ = [
    "SanitizationPipeline",
    "InjectionClassifier",
    "train_default",
    "rule_evaluate",
]
