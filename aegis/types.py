"""Core data types shared across all AEGIS components.

AEGIS = Agentic Execution Guardrail & Injection Shield.

Every request an agent makes flows through the gateway as an ``AgentRequest`` and
comes back out as a ``Decision``.  Keeping these contracts in one place lets the
four subsystems (sanitizer, scrubber, monitor, sandbox) stay decoupled.
"""
from __future__ import annotations

import enum
import itertools
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .errors import AegisValidationError

_id_counter = itertools.count(1)
_id_lock = threading.Lock()
# A short token unique to this process/run, so request IDs do not collide across
# workers or restarts (the counter alone repeats from 1 in every process).
_RUN_TOKEN = f"{os.getpid():x}{uuid.uuid4().hex[:6]}"


def _next_id(prefix: str) -> str:
    with _id_lock:
        n = next(_id_counter)
    return f"{prefix}-{_RUN_TOKEN}-{n:08d}"


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

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise AegisValidationError("ToolCall.name must be a non-empty string")
        if self.args is None:
            self.args = {}
        elif not isinstance(self.args, dict):
            raise AegisValidationError(
                f"ToolCall.args must be a dict, got {type(self.args).__name__}")

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

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise AegisValidationError("AgentRequest.agent_id must be a non-empty string")
        if not isinstance(self.role, str) or not self.role.strip():
            raise AegisValidationError("AgentRequest.role must be a non-empty string")

        # content: coerce None -> "" but reject non-string types (a list/dict
        # here would silently skip sanitization or crash deep in the pipeline).
        if self.content is None:
            self.content = ""
        elif not isinstance(self.content, str):
            raise AegisValidationError(
                f"AgentRequest.content must be a string, got {type(self.content).__name__}")

        # source: accept a Source or its string value (a natural mistake since
        # Source is a str-enum), but reject anything else.
        if not isinstance(self.source, Source):
            try:
                self.source = Source(self.source)
            except ValueError as exc:
                valid = ", ".join(s.value for s in Source)
                raise AegisValidationError(
                    f"AgentRequest.source must be a Source (one of: {valid}), "
                    f"got {self.source!r}") from exc

        if self.tool_call is not None and not isinstance(self.tool_call, ToolCall):
            raise AegisValidationError(
                "AgentRequest.tool_call must be a ToolCall or None, got "
                f"{type(self.tool_call).__name__}")


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

    # In monitor-only mode (gateway ``enforce=False``) the verdict is not applied
    # to execution; ``would_block`` records whether enforcement *would* have
    # blocked, so operators can measure impact before switching enforcement on.
    would_block: bool = False

    # Set to a short error tag when the gateway failed internally and returned a
    # fail-closed BLOCK; None on the normal path.
    error: Optional[str] = None

    def summary(self) -> str:
        tier = self.tier.value if self.tier else "-"
        return (
            f"[{self.verdict.value.upper():10}] tier={tier:10} "
            f"inj={self.injection_score:.2f} anom={self.anomaly_score:.2f} "
            f"{self.latency_ms:5.2f}ms :: {'; '.join(self.reasons) or 'ok'}"
        )
