"""The AEGIS gateway - the real-time behavioral monitoring middleware.

Every agent request flows through one pipeline:

    sanitize  ->  enforce (RBAC + trust + behavior)  ->  [scrub]  ->  route  ->  execute

The gateway is framework-agnostic: it takes an ``AgentRequest`` and returns a
fully-populated ``Decision``.  The LangGraph adapter (see ``integrations``) is a
thin wrapper that turns tool-node execution into calls to ``process``.
"""
from __future__ import annotations

import asyncio
import time

from .config import DEFAULT_CONFIG, AegisConfig
from .monitor import BehaviorMonitor, PolicyEnforcementPoint
from .sandbox import SandboxExecutor, SandboxRouter
from .sanitizer import SanitizationPipeline
from .scrubber import IntentScrubber
from .telemetry import Telemetry
from .types import AgentRequest, Decision, SandboxTier, Source, Verdict


class AegisGateway:
    def __init__(
        self,
        config: AegisConfig | None = None,
        sanitizer: SanitizationPipeline | None = None,
        scrubber: IntentScrubber | None = None,
        pep: PolicyEnforcementPoint | None = None,
        router: SandboxRouter | None = None,
        executor: SandboxExecutor | None = None,
        enforce: bool = True,
    ):
        self.config = config or DEFAULT_CONFIG
        self.sanitizer = sanitizer or SanitizationPipeline.default()
        self.scrubber = scrubber or IntentScrubber()
        self.pep = pep or PolicyEnforcementPoint(self.config, BehaviorMonitor(self.config))
        self.router = router or SandboxRouter(self.config)
        self.executor = executor or SandboxExecutor(enforce_egress=enforce)
        self.enforce = enforce
        self.telemetry = Telemetry()

    # ------------------------------------------------------------------ #
    def process(self, request: AgentRequest) -> Decision:
        t_start = time.perf_counter()
        stage_ms: dict[str, float] = {}
        reasons: list[str] = []

        # --- Stage 1: sanitize content -------------------------------- #
        t = time.perf_counter()
        san = self.sanitizer.inspect(request.content, request.source)
        stage_ms["sanitize"] = (time.perf_counter() - t) * 1000.0
        injection_score = san.score
        if san.top_signals and san.score >= self.config.thresholds.injection_sanitize:
            reasons.append("signals: " + ", ".join(san.top_signals))

        # --- Stage 2: enforce ----------------------------------------- #
        t = time.perf_counter()
        outcome = self.pep.evaluate(request, injection_score)
        stage_ms["enforce"] = (time.perf_counter() - t) * 1000.0
        reasons.extend(outcome.reasons)
        verdict = outcome.verdict
        anomaly = outcome.anomaly_score

        # When AEGIS is in "monitor-only" mode we log but never block/deny.
        if not self.enforce:
            verdict = Verdict.ALLOW if verdict != Verdict.SANITIZE else Verdict.SANITIZE

        # --- Stage 3: scrub (only on SANITIZE) ------------------------ #
        sanitized_content = None
        if verdict == Verdict.SANITIZE:
            t = time.perf_counter()
            scrub = self.scrubber.scrub(request.content)
            stage_ms["scrub"] = (time.perf_counter() - t) * 1000.0
            sanitized_content = scrub.text
            if scrub.modified:
                reasons.append(f"scrubbed {scrub.removed_count} injected line(s)")
            # re-inspect the cleaned content; if still hot, block.
            recheck = self.sanitizer.inspect(sanitized_content, request.source)
            if self.enforce and recheck.score >= self.config.thresholds.injection_block:
                verdict = Verdict.BLOCK
                reasons.append("still injected after scrub -> block")
            else:
                verdict = Verdict.ALLOW

        # --- terminal: blocked ---------------------------------------- #
        if verdict == Verdict.BLOCK:
            return self._finalize(
                request, Verdict.BLOCK, allowed=False, executed=False, tier=None,
                injection_score=injection_score, anomaly=anomaly, reasons=reasons,
                sanitized=sanitized_content, result=None, t_start=t_start, stage_ms=stage_ms,
            )

        # No tool call: content was allowed/sanitized, nothing to execute.
        if request.tool_call is None:
            return self._finalize(
                request, verdict, allowed=True, executed=False, tier=None,
                injection_score=injection_score, anomaly=anomaly, reasons=reasons,
                sanitized=sanitized_content, result=None, t_start=t_start, stage_ms=stage_ms,
            )

        # --- Stage 4: route ------------------------------------------- #
        t = time.perf_counter()
        route = self.router.route(
            request, injection_score, anomaly,
            force_min_isolation=outcome.force_min_isolation or verdict == Verdict.QUARANTINE,
        )
        stage_ms["route"] = (time.perf_counter() - t) * 1000.0
        reasons.append(f"routed -> {route.tier.value} ({route.reason})")

        # --- Stage 5: execute (with egress inspection) ---------------- #
        t = time.perf_counter()
        exec_out = self.executor.execute(route.tier, request.tool_call)
        stage_ms["execute"] = (time.perf_counter() - t) * 1000.0

        executed = exec_out.ok and not exec_out.blocked
        allowed = executed
        if exec_out.blocked:
            reasons.append(exec_out.reason)
            if verdict not in (Verdict.QUARANTINE,):
                verdict = Verdict.BLOCK

        dec = self._finalize(
            request, verdict, allowed=allowed, executed=executed, tier=route.tier,
            injection_score=injection_score, anomaly=anomaly, reasons=reasons,
            sanitized=sanitized_content, result=exec_out.result, t_start=t_start,
            stage_ms=stage_ms,
        )
        dec.exfiltration_attempt = exec_out.exfil_attempt
        dec.exfiltration_blocked = exec_out.exfil_attempt and not exec_out.exfiltrated
        if exec_out.exfil_attempt:
            self.telemetry.incr("exfil_attempts")
            if exec_out.exfiltrated:
                self.telemetry.incr("exfil_success")
        return dec

    async def aprocess(self, request: AgentRequest) -> Decision:
        """Async entry point - offloads the CPU work to a worker thread so many
        agents can be serviced concurrently by one event loop."""
        return await asyncio.to_thread(self.process, request)

    # ------------------------------------------------------------------ #
    def _finalize(self, request, verdict, *, allowed, executed, tier, injection_score,
                  anomaly, reasons, sanitized, result, t_start, stage_ms) -> Decision:
        latency = (time.perf_counter() - t_start) * 1000.0
        self.telemetry.incr("requests")
        self.telemetry.incr(f"verdict.{verdict.value}")
        if request.tool_call is not None:
            self.telemetry.incr("tool_calls")
            self.telemetry.incr("tool_executed" if executed else "tool_denied")
        self.telemetry.observe_latency("total", latency)
        for k, v in stage_ms.items():
            self.telemetry.observe_latency(k, v)
        return Decision(
            request_id=request.request_id,
            verdict=verdict,
            allowed=allowed,
            executed=executed,
            tier=tier,
            injection_score=injection_score,
            anomaly_score=anomaly,
            reasons=reasons,
            sanitized_content=sanitized,
            result=result,
            latency_ms=latency,
            stage_latencies=stage_ms,
        )
