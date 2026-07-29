"""Shared fixtures.

Tests get a *fresh* gateway per test so behavioural state (per-agent profiles,
telemetry counters) can't leak between tests and make results order-dependent.
The sanitization pipeline is process-wide and read-only after load, so it is
shared deliberately - building it per test would dominate the suite runtime.
"""
import pytest

from aegis import AegisGateway


@pytest.fixture
def gateway():
    """A fresh, isolated AegisGateway."""
    return AegisGateway()


@pytest.fixture(scope="session", autouse=True)
def _warm_pipeline():
    """Load/train the classifier once before timing-sensitive tests run."""
    from aegis.sanitizer import SanitizationPipeline
    SanitizationPipeline.default().inspect("warmup")
