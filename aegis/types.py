"""Core data types shared across all AEGIS components.

AEGIS = Agentic Execution Guardrail & Injection Shield.

Every request an agent makes flows through the gateway as an ``AgentRequest`` and
comes back out as a ``Decision``.  Keeping these contracts in one place lets the
four subsystems (sanitizer, scrubber, monitor, sandbox) stay decoupled.
"""
from __future__ import annotations

import enum
import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Optional

_id_counter = itertools.count(1)


def _next_id(prefix: str) -> str:
    return f"{prefix}-{next(_id_counter):08d}"


class Verdict(str, enum.Enum):
    """Terminal decision for a request.

    ALLOW      -> execute normally in the routed sandbox.
    SANITIZE   -> content was scrubbed of injected instructions, then allowed.
    QUARANTINE -> execute, but forced into the most restrictive sandbox tier.
    BLOCK      -> refuse execution entirely.
    """

    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class Source(str, enum.Enum):
    """Where the content originated.

    Indirect prompt injection arrives through non-user channels: a retrieved
    document, the output of a previous tool, a fetched web page, or long-term
    memory.  The sanitizer treats these as lower-trust than direct USER input.
    """

    USER = "user"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"
    WEB = "web"
    MEMORY = "memory"

    @property
    def is_untrusted(self) -> bool:
        return self is not Source.USER


class SandboxTier(str, enum.Enum):
    """Isolation tiers, ordered from most to least restrictive."""

    NO_NET = "no_net"          # no network, ephemeral fs, no secrets
    READ_ONLY = "read_only"    # read-only fs, no egress, scoped read secrets
    RESTRICTED = "restricted"  # allowlisted egress only, scratch fs
    TRUSTED = "trusted"        # broad egress (privileged tools, high trust only)

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK = {
    SandboxTier.NO_NET: 0,
    SandboxTier.READ_ONLY: 1,
    SandboxTier.RESTRICTED: 2,
    SandboxTier.TRUSTED: 3,
}


@dataclass
class ToolCall:
    """A single tool/API invocation an agent wants to perform."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)

    def flat_args(self) -> str:
        """Flatten args to a single string for content inspection."""
        parts = []
        for k, v in self.args.items():
            parts.append(f"{k}={v}")
        return " ".join(parts)


@dataclass
class AgentRequest:
    """One unit of work presented to the gateway.

    ``content`` is the free text associated with the step (a retrieved document,
    a tool result being fed back, or a user instruction).  ``tool_call`` is the
    action the agent proposes to take, if any.
    """

    agent_id: str
    role: str
    content: str = ""
    tool_call: Optional[ToolCall] = None
    source: Source = Source.USER
    request_id: str = field(default_factory=lambda: _next_id("req"))
    ts: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SanitizeResult:
    """Output of the input-sanitization pipeline."""

    score: float                       # P(injection) in [0, 1]
    is_injection: bool
    latency_ms: float
    top_signals: list[str] = field(default_factory=list)
    method: str = "ensemble"


@dataclass
class Decision:
    """The gateway's full, auditable answer for a request."""

    request_id: str
    verdict: Verdict
    allowed: bool
    executed: bool = False
    tier: Optional[SandboxTier] = None
    injection_score: float = 0.0
    anomaly_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    result: Any = None
    latency_ms: float = 0.0
    stage_latencies: dict[str, float] = field(default_factory=dict)

    # populated by the sandbox layer when an exfiltration attempt is caught
    exfiltration_attempt: bool = False
    exfiltration_blocked: bool = False

    def summary(self) -> str:
        tier = self.tier.value if self.tier else "-"
        return (
            f"[{self.verdict.value.upper():10}] tier={tier:10} "
            f"inj={self.injection_score:.2f} anom={self.anomaly_score:.2f} "
            f"{self.latency_ms:5.2f}ms :: {'; '.join(self.reasons) or 'ok'}"
        )
