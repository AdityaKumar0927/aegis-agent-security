"""The Policy Enforcement Point (PEP).

Combines the hard policy (RBAC + trust) with the injection score and the
behavioral anomaly score into a single verdict for an attempted tool call.  This
is the component that "reduces unauthorized API tool execution": every tool call
must pass through ``evaluate`` before it can run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import EGRESS_TOOLS, SENSITIVITY_CRITICAL, SENSITIVITY_HIGH, AegisConfig
from ..types import AgentRequest, Verdict
from .behavior import AnomalyResult, BehaviorMonitor
from .policy import PolicyEngine


@dataclass
class EnforcementOutcome:
    verdict: Verdict
    anomaly_score: float
    reasons: list[str] = field(default_factory=list)
    force_min_isolation: bool = False   # hint to the sandbox router


class PolicyEnforcementPoint:
    def __init__(self, config: AegisConfig, behavior: BehaviorMonitor | None = None):
        self.config = config
        self.policy = PolicyEngine(config)
        self.behavior = behavior or BehaviorMonitor(config)

    def evaluate(self, request: AgentRequest, injection_score: float) -> EnforcementOutcome:
        th = self.config.thresholds
        reasons: list[str] = []

        # --- content-only requests (no tool call) ---------------------- #
        if request.tool_call is None:
            if injection_score >= th.injection_block:
                return EnforcementOutcome(Verdict.BLOCK, 0.0,
                                          [f"injection score {injection_score:.2f} >= block"])
            if injection_score >= th.injection_sanitize:
                return EnforcementOutcome(Verdict.SANITIZE, 0.0,
                                          [f"injection score {injection_score:.2f} -> scrub"])
            return EnforcementOutcome(Verdict.ALLOW, 0.0, ["content ok"])

        tool = request.tool_call.name
        sensitivity = self.config.sensitivity(tool)

        # --- hard policy (RBAC + trust floor) -------------------------- #
        check = self.policy.check(request.role, tool)
        if not check.ok:
            self.behavior.record_block(request.agent_id)
            return EnforcementOutcome(Verdict.BLOCK, 0.0, [check.reason])

        # --- behavioral anomaly ---------------------------------------- #
        anomaly: AnomalyResult = self.behavior.observe(request.agent_id, request.tool_call, now=request.ts)
        reasons.extend(anomaly.reasons)
        score = anomaly.score

        # --- injection-driven decisions -------------------------------- #
        if injection_score >= th.injection_block:
            self.behavior.record_block(request.agent_id)
            return EnforcementOutcome(
                Verdict.BLOCK, score,
                [f"injection score {injection_score:.2f} >= block"] + reasons)

        # High-sensitivity tools with *any* meaningful injection signal are
        # blocked - we never let a possibly-poisoned step touch a dangerous tool.
        if sensitivity in (SENSITIVITY_HIGH, SENSITIVITY_CRITICAL) and \
                injection_score >= th.injection_sanitize:
            self.behavior.record_block(request.agent_id)
            return EnforcementOutcome(
                Verdict.BLOCK, score,
                [f"{sensitivity} tool '{tool}' with injection {injection_score:.2f}"] + reasons)

        # Anomaly-driven decisions.
        if score >= th.anomaly_block and sensitivity in (SENSITIVITY_HIGH, SENSITIVITY_CRITICAL):
            self.behavior.record_block(request.agent_id)
            return EnforcementOutcome(
                Verdict.BLOCK, score,
                [f"anomaly {score:.2f} on {sensitivity} tool '{tool}'"] + reasons)

        if score >= th.anomaly_quarantine:
            return EnforcementOutcome(
                Verdict.QUARANTINE, score,
                [f"anomaly {score:.2f} -> quarantine"] + reasons,
                force_min_isolation=True)

        # Egress tools always run under at least mild scrutiny.
        if tool in EGRESS_TOOLS and injection_score >= th.injection_sanitize:
            return EnforcementOutcome(
                Verdict.SANITIZE, score,
                [f"egress tool '{tool}' - scrub content first"] + reasons)

        self.behavior.record_allow(request.agent_id)
        return EnforcementOutcome(Verdict.ALLOW, score, reasons or ["ok"])
