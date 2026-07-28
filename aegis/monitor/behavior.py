"""Behavioral baselines and anomaly scoring.

Maintains a small, thread-safe per-agent profile and scores each attempted tool
call for how far it deviates from that agent's normal behaviour.  The signals are
intentionally cheap (O(1) per call) so the monitor adds negligible latency even
under thousands of concurrent agents:

* **rate** - sliding window over *all* attempts (blocked ones count too); a burst
  above the sustained rate is suspicious.
* **novelty** - a tool this agent has never *successfully* used before.
* **dangerous sequence** - a sensitive read followed within a window by a risky
  egress (the canonical read-then-exfiltrate pattern).
* **recent blocks** - blocks within a recent time window (not a lifetime net
  counter, so a few benign calls can't wash out an attack burst).

Two design decisions harden this against abuse:

* the rate window uses a **monotonic** server clock, not the caller-supplied
  ``AgentRequest.ts`` (which an attacker could forge to suppress rate signals);
* the *learned baseline* (seen tools, sensitive-read state, call count) is
  committed only when a call is **allowed** - a blocked attack can never train
  the baseline to look normal.  ``record_allow``/``record_block`` perform the
  commit; ``observe`` only scores and records the attempt time.

The per-agent store is bounded (LRU by ``config.max_agents``) and idle profiles
are evicted after ``config.profile_ttl_s``, so unique-agent-id spam cannot
exhaust memory.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from ..config import SENSITIVITY_CRITICAL, AegisConfig
from ..sandbox.egress import EgressFilter
from ..types import ToolCall

_SENSITIVE_READ = {"read_secret", "read_file", "db_query"}


@dataclass
class AgentProfile:
    seen_tools: set[str] = field(default_factory=set)
    call_times: deque = field(default_factory=lambda: deque(maxlen=256))
    block_times: deque = field(default_factory=lambda: deque(maxlen=64))
    last_sensitive_read_at: float | None = None
    total_calls: int = 0
    last_seen: float = 0.0


@dataclass
class AnomalyResult:
    score: float
    reasons: list[str] = field(default_factory=list)


class BehaviorMonitor:
    def __init__(self, config: AegisConfig, rate_window_s: float | None = None,
                 rate_limit: int | None = None, clock=time.monotonic):
        self.config = config
        # explicit args win over config for backwards compatibility
        self.rate_window_s = rate_window_s if rate_window_s is not None else config.rate_window_s
        self.rate_limit = rate_limit if rate_limit is not None else config.rate_limit
        self._clock = clock
        self._egress = EgressFilter(config)
        self._profiles: OrderedDict[str, AgentProfile] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _risky_egress(self, tool_call: ToolCall) -> bool:
        """An egress call is 'risky' only if it targets an external destination or
        carries a secret payload; benign internal egress is not."""
        if not self.config.is_egress_tool(tool_call.name):
            return False
        return self._egress.is_risky(tool_call)

    def _profile(self, agent_id: str, now: float) -> AgentProfile:
        """Fetch-or-create under the lock; also evicts stale/overflowing entries.
        Caller must hold self._lock."""
        p = self._profiles.get(agent_id)
        if p is not None:
            # TTL: a long-idle profile is stale; start fresh.
            if now - p.last_seen > self.config.profile_ttl_s:
                p = AgentProfile()
                self._profiles[agent_id] = p
            self._profiles.move_to_end(agent_id)
        else:
            p = AgentProfile()
            self._profiles[agent_id] = p
        p.last_seen = now
        self._evict_if_needed(now)
        return p

    def _evict_if_needed(self, now: float) -> None:
        """Bound the store: drop the least-recently-used entries past the cap.
        Caller must hold self._lock."""
        cap = self.config.max_agents
        while len(self._profiles) > cap:
            self._profiles.popitem(last=False)   # evict LRU

    # ------------------------------------------------------------------ #
    def observe(self, agent_id: str, tool_call: ToolCall, now: float | None = None) -> AnomalyResult:
        """Score this attempt.  Records the attempt time (for rate) but does NOT
        commit the learned baseline - call ``record_allow`` for that.

        ``now`` is accepted for API compatibility but is only used as a tie-break
        for audit; the security-relevant rate window always uses the monotonic
        server clock so a forged ``AgentRequest.ts`` cannot suppress it.
        """
        mono = self._clock()
        reasons: list[str] = []
        signals: list[float] = []

        with self._lock:
            p = self._profile(agent_id, mono)
            tool = tool_call.name

            # --- rate (counts every attempt, blocked included) ---
            p.call_times.append(mono)
            recent = sum(1 for t in p.call_times if mono - t <= self.rate_window_s)
            if recent > self.rate_limit:
                over = (recent - self.rate_limit) / self.rate_limit
                signals.append(min(0.6, 0.3 + over * 0.3))
                reasons.append(f"rate spike ({recent}/{self.rate_window_s:g}s)")

            # --- novelty (against the *allowed* baseline) ---
            if tool not in p.seen_tools and p.total_calls >= 3:
                signals.append(0.25)
                reasons.append(f"novel tool for this agent ('{tool}')")

            # --- dangerous sequence: recent sensitive read -> risky egress ---
            recent_read = (
                p.last_sensitive_read_at is not None
                and mono - p.last_sensitive_read_at <= self.config.sensitive_read_window_s
            )
            if self.config.is_egress_tool(tool) and recent_read and self._risky_egress(tool_call):
                signals.append(0.7)
                reasons.append("read-then-exfiltrate sequence (sensitive read -> risky egress)")

            # --- first action is a critical tool (no baseline) ---
            if self.config.sensitivity(tool) == SENSITIVITY_CRITICAL and p.total_calls == 0:
                signals.append(0.25)
                reasons.append("first action is a critical tool (no baseline)")

            # --- recent blocks (time-windowed, not a washable net counter) ---
            recent_blocks = sum(1 for t in p.block_times
                                if mono - t <= self.config.block_window_s)
            if recent_blocks > 0:
                signals.append(min(0.5, 0.2 * recent_blocks))
                reasons.append(f"agent has {recent_blocks} recent policy blocks")

        # noisy-OR combination -> [0,1]
        keep = 1.0
        for s in signals:
            keep *= (1.0 - s)
        return AnomalyResult(1.0 - keep, reasons)

    def record_allow(self, agent_id: str, tool_call: ToolCall | None = None) -> None:
        """Commit an allowed call into the learned baseline."""
        mono = self._clock()
        with self._lock:
            p = self._profile(agent_id, mono)
            p.total_calls += 1
            if tool_call is not None:
                p.seen_tools.add(tool_call.name)
                if tool_call.name in _SENSITIVE_READ:
                    p.last_sensitive_read_at = mono

    def record_block(self, agent_id: str) -> None:
        mono = self._clock()
        with self._lock:
            p = self._profile(agent_id, mono)
            p.block_times.append(mono)

    def agent_count(self) -> int:
        with self._lock:
            return len(self._profiles)
