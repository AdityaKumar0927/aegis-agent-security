"""Behavioral baselines and anomaly scoring.

Maintains a small, thread-safe per-agent profile and scores each attempted tool
call for how far it deviates from that agent's normal behaviour.  The signals are
intentionally cheap (O(1) per call) so the monitor adds negligible latency even
under thousands of concurrent agents:

* **rate** - token-bucket; a burst of calls above the sustained rate is
  suspicious.
* **novelty** - a tool this agent has never used before.
* **dangerous sequence** - reading a secret/file and then reaching for an egress
  tool (the canonical read-then-exfiltrate pattern).
* **recent blocks** - an agent that just tripped policy is more likely mid-attack.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from ..config import EGRESS_TOOLS, SENSITIVITY_CRITICAL, AegisConfig
from ..sandbox.egress import (
    _carries_secret,
    _extract_destination,
    _is_internal,
    _payload_text,
)
from ..types import ToolCall

_SENSITIVE_READ = {"read_secret", "read_file", "db_query"}


def _risky_egress(tool_call: ToolCall) -> bool:
    """An egress call is 'risky' only if it targets an external destination or
    carries a secret payload; benign internal egress is not."""
    if tool_call.name not in EGRESS_TOOLS:
        return False
    dest = _extract_destination(tool_call)
    external = bool(dest) and not _is_internal(dest)
    return external or _carries_secret(_payload_text(tool_call))


@dataclass
class AgentProfile:
    seen_tools: set[str] = field(default_factory=set)
    recent_calls: deque = field(default_factory=lambda: deque(maxlen=16))
    call_times: deque = field(default_factory=lambda: deque(maxlen=64))
    recent_blocks: int = 0
    accessed_sensitive: bool = False
    total_calls: int = 0


@dataclass
class AnomalyResult:
    score: float
    reasons: list[str] = field(default_factory=list)


class BehaviorMonitor:
    def __init__(self, config: AegisConfig, rate_window_s: float = 1.0,
                 rate_limit: int = 20):
        self.config = config
        self.rate_window_s = rate_window_s
        self.rate_limit = rate_limit
        self._profiles: dict[str, AgentProfile] = {}
        self._lock = threading.Lock()

    def _profile(self, agent_id: str) -> AgentProfile:
        p = self._profiles.get(agent_id)
        if p is None:
            p = AgentProfile()
            self._profiles[agent_id] = p
        return p

    def observe(self, agent_id: str, tool_call: ToolCall, now: float | None = None) -> AnomalyResult:
        now = now if now is not None else time.time()
        reasons: list[str] = []
        signals: list[float] = []

        with self._lock:
            p = self._profile(agent_id)
            tool = tool_call.name

            # --- rate ---
            p.call_times.append(now)
            recent = sum(1 for t in p.call_times if now - t <= self.rate_window_s)
            if recent > self.rate_limit:
                over = (recent - self.rate_limit) / self.rate_limit
                signals.append(min(0.6, 0.3 + over * 0.3))
                reasons.append(f"rate spike ({recent}/{self.rate_window_s:g}s)")

            # --- novelty ---
            if tool not in p.seen_tools and p.total_calls >= 3:
                signals.append(0.25)
                reasons.append(f"novel tool for this agent ('{tool}')")

            # --- dangerous sequence: read-then-exfiltrate ---
            # Only a *risky* egress (external destination or secret payload) after
            # a sensitive read is anomalous; benign internal egress is not, so
            # legitimate agents that read data then post internally aren't punished.
            if tool in EGRESS_TOOLS and p.accessed_sensitive and _risky_egress(tool_call):
                signals.append(0.7)
                reasons.append("read-then-exfiltrate sequence (sensitive read -> risky egress)")
            # An agent whose very first action is a critical tool has no
            # baseline - mildly suspicious, but not enough on its own to cap the
            # sandbox tier for a legitimately-privileged agent.
            if self.config.sensitivity(tool) == SENSITIVITY_CRITICAL and p.total_calls == 0:
                signals.append(0.25)
                reasons.append("first action is a critical tool (no baseline)")

            # --- recent blocks ---
            if p.recent_blocks > 0:
                signals.append(min(0.5, 0.2 * p.recent_blocks))
                reasons.append(f"agent has {p.recent_blocks} recent policy blocks")

            # update profile
            p.recent_calls.append(tool)
            p.seen_tools.add(tool)
            p.total_calls += 1
            if tool in _SENSITIVE_READ:
                p.accessed_sensitive = True

        # noisy-OR combination -> [0,1]
        keep = 1.0
        for s in signals:
            keep *= (1.0 - s)
        return AnomalyResult(1.0 - keep, reasons)

    def record_block(self, agent_id: str) -> None:
        with self._lock:
            self._profile(agent_id).recent_blocks += 1

    def record_allow(self, agent_id: str) -> None:
        with self._lock:
            p = self._profile(agent_id)
            if p.recent_blocks > 0:
                p.recent_blocks -= 1
