"""Dynamic sandbox routing.

Given a tool call plus its risk signals, pick the sandbox tier to run it in.  The
principle is *least privilege under risk*: start from the most privileged tier the
agent's trust justifies, then let injection/anomaly risk push the choice down
toward isolation.  Egress-capable tools can only reach an allowlisted tier when
risk is low and trust is high; otherwise they land in a no-egress tier where the
egress filter will deny any outbound data.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..config import (
    EGRESS_TOOLS,
    SENSITIVITY_CRITICAL,
    SENSITIVITY_HIGH,
    AegisConfig,
)
from ..types import AgentRequest, SandboxTier


@dataclass
class RouteResult:
    tier: SandboxTier
    risk: float
    reason: str


def _min_tier(a: SandboxTier, b: SandboxTier) -> SandboxTier:
    """Return the more restrictive (lower-rank) of two tiers."""
    return a if a.rank <= b.rank else b


class SandboxRouter:
    def __init__(self, config: AegisConfig):
        self.config = config

    def route(
        self,
        request: AgentRequest,
        injection_score: float,
        anomaly_score: float,
        force_min_isolation: bool = False,
    ) -> RouteResult:
        tool = request.tool_call.name if request.tool_call else "web_search"
        sensitivity = self.config.sensitivity(tool)
        trust = self.config.trust(request.role)
        needs_egress = tool in EGRESS_TOOLS

        # noisy-OR of the two risk signals
        risk = 1.0 - (1.0 - injection_score) * (1.0 - anomaly_score)

        # 1) Base tier from trust.
        if trust >= 0.90:
            base = SandboxTier.TRUSTED
        elif trust >= 0.60:
            base = SandboxTier.RESTRICTED
        elif trust >= 0.30:
            base = SandboxTier.READ_ONLY
        else:
            base = SandboxTier.NO_NET

        # 2) Highly sensitive non-egress tools never need broad egress; cap them
        #    at READ_ONLY so a compromised step can't reach the network.
        if sensitivity in (SENSITIVITY_HIGH, SENSITIVITY_CRITICAL) and not needs_egress:
            base = _min_tier(base, SandboxTier.READ_ONLY)

        tier = base
        reason = f"base={base.value} (trust {trust:.2f})"

        # 3) Risk pushes toward isolation.
        if force_min_isolation or risk >= 0.60:
            tier = SandboxTier.NO_NET
            reason = f"risk {risk:.2f} -> isolate (NO_NET)"
        elif risk >= 0.35:
            tier = _min_tier(tier, SandboxTier.READ_ONLY)
            reason = f"risk {risk:.2f} -> cap at READ_ONLY"

        # 4) An egress tool that has been forced below RESTRICTED will simply be
        #    denied egress by the filter - which is the desired fail-closed
        #    behaviour for risky outbound calls.
        return RouteResult(tier=tier, risk=risk, reason=reason)
