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

from . import audit
from .audit import AuditSink
from .config import DEFAULT_CONFIG, AegisConfig
from .monitor import BehaviorMonitor, PolicyEnforcementPoint
from .sandbox import SandboxExecutor, SandboxRouter
from .sanitizer import SanitizationPipeline
from .scrubber import IntentScrubber
from .telemetry import Telemetry
from .types import AgentRequest, Decision, SandboxTier, Source, Verdict


class AegisGateway:
    """The AEGIS middleware entry point.

    ``process`` is guaranteed to be **fail-closed**: any internal error is
    converted into a ``BLOCK`` decision (never a silent pass-through), recorded
    in telemetry, and audit-logged.

    Set ``enforce=False`` for *monitor-only* mode: the gateway computes and logs
    the verdict (surfaced as ``Decision.would_block``) but never denies a tool.
    In this mode the built-in simulated executor also does not apply the egress
    filter, so it models "no AEGIS" for baseline measurement - do not run
    monitor-only against real side-effecting tools if you need exfiltration
    prevented.
    """

    def __init__(
        self,
        config: AegisConfig | None = None,
        sanitizer: SanitizationPipeline | None = None,
        scrubber: IntentScrubber | None = None,
        pep: PolicyEnforcementPoint | None = None,
        router: SandboxRouter | None = None,
        executor: SandboxExecutor | None = None,
        enforce: bool = True,
        audit_sink: AuditSink | None = None,
    ):
        # Own a private copy so tuning this gateway's config never mutates a
        # shared default or another gateway's policy.
        self.config = (config if config is not None else DEFAULT_CONFIG).copy()
        self.sanitizer = sanitizer or SanitizationPipeline.default()
        self.scrubber = scrubber or IntentScrubber()
        self.pep = pep or PolicyEnforcementPoint(self.config, BehaviorMonitor(self.config))
        self.router = router or SandboxRouter(self.config)
        self.executor = executor or SandboxExecutor(config=self.config, enforce_egress=enforce)
        self.enforce = enforce
        self.audit_sink = audit_sink
        self.telemetry = Telemetry()

    # ------------------------------------------------------------------ #
    def process(self, request: AgentRequest) -> Decision:
        """Run the pipeline for one request; always returns a Decision.

        Fail-closed: on any internal exception this returns a ``BLOCK`` with
        ``error`` set rather than propagating, so an integrator can never
        accidentally build a fail-open guard by forgetting a try/except.
        """
        try:
            return self._process(request)
        except Exception as exc:  # noqa: BLE001 - deliberate fail-closed boundary
            return self._fail_closed(request, exc)

    def _process(self, request: AgentRequest) -> Decision:
        t_start = time.perf_counter()
        stage_ms: dict[str, float] = {}
        reasons: list[str] = []

        # Bound untrusted content length before any regex/normalisation work so a
        # pathologically large input can't burn unbounded CPU (DoS guard).
        content = request.content
        max_len = self.config.max_content_length
        if len(content) > max_len:
            content = content[:max_len]
            reasons.append(f"content truncated to {max_len} chars")

        # --- Stage 1: sanitize content -------------------------------- #
        t = time.perf_counter()
        san = self.sanitizer.inspect(content, request.source)
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

        # Track what enforcement *would* do, independent of enforce mode, so
        # monitor-only deployments can measure impact (Decision.would_block).
        would_block = verdict == Verdict.BLOCK

        # In monitor-only mode we never deny: downgrade a policy BLOCK to ALLOW
        # for the execution path (the verdict recorded reflects reality: it ran).
        if not self.enforce and verdict == Verdict.BLOCK:
            verdict = Verdict.ALLOW
            reasons.append("monitor-only: would BLOCK, allowed")

        # --- Stage 3: scrub (only on SANITIZE) ------------------------ #
        sanitized_content = None
        if verdict == Verdict.SANITIZE:
            t = time.perf_counter()
            scrub = self.scrubber.scrub(content)
            stage_ms["scrub"] = (time.perf_counter() - t) * 1000.0
            sanitized_content = scrub.text
            if scrub.modified:
                reasons.append(f"scrubbed {scrub.removed_count} injected line(s)")
            # re-inspect the cleaned content; if still hot, block.
            recheck = self.sanitizer.inspect(sanitized_content, request.source)
            if recheck.score >= self.config.thresholds.injection_block:
                would_block = True
                if self.enforce:
                    verdict = Verdict.BLOCK
                    reasons.append("still injected after scrub -> block")
                else:
                    verdict = Verdict.ALLOW
                    reasons.append("monitor-only: still injected after scrub, allowed")
            else:
                verdict = Verdict.ALLOW

        # --- terminal: blocked ---------------------------------------- #
        if verdict == Verdict.BLOCK:
            return self._finalize(
                request, Verdict.BLOCK, allowed=False, executed=False, tier=None,
                injection_score=injection_score, anomaly=anomaly, reasons=reasons,
                sanitized=sanitized_content, result=None, t_start=t_start, stage_ms=stage_ms,
                would_block=would_block,
            )

        # No tool call: content was allowed/sanitized, nothing to execute.
        if request.tool_call is None:
            return self._finalize(
                request, verdict, allowed=True, executed=False, tier=None,
                injection_score=injection_score, anomaly=anomaly, reasons=reasons,
                sanitized=sanitized_content, result=None, t_start=t_start, stage_ms=stage_ms,
                would_block=would_block,
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
        # An exfiltration attempt is something enforcement would have stopped,
        # even if monitor-only mode let it through.
        would_block = would_block or exec_out.exfil_attempt

        dec = self._finalize(
            request, verdict, allowed=allowed, executed=executed, tier=route.tier,
            injection_score=injection_score, anomaly=anomaly, reasons=reasons,
            sanitized=sanitized_content, result=exec_out.result, t_start=t_start,
            stage_ms=stage_ms, would_block=would_block,
            exfil_attempt=exec_out.exfil_attempt,
            exfil_blocked=exec_out.exfil_attempt and not exec_out.exfiltrated,
        )
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
    def _fail_closed(self, request: AgentRequest, exc: Exception) -> Decision:
        """Return a fail-closed BLOCK for an internal error, recording it."""
        self.telemetry.incr("errors")
        err = type(exc).__name__
        dec = Decision(
            request_id=getattr(request, "request_id", "unknown"),
            verdict=Verdict.BLOCK,
            allowed=False,
            executed=False,
            injection_score=0.0,
            anomaly_score=0.0,
            reasons=[f"internal error: {err}", "fail-closed -> BLOCK"],
            would_block=True,
            error=err,
        )
        try:
            audit.audit_logger.exception("aegis internal error -> fail-closed BLOCK")
            audit.emit(audit.decision_record(request, dec), self.audit_sink)
        except Exception:  # noqa: BLE001 - never let auditing mask the block
            pass
        return dec

    def _finalize(self, request, verdict, *, allowed, executed, tier, injection_score,
                  anomaly, reasons, sanitized, result, t_start, stage_ms,
                  would_block=False, exfil_attempt=False, exfil_blocked=False) -> Decision:
        latency = (time.perf_counter() - t_start) * 1000.0
        self.telemetry.incr("requests")
        self.telemetry.incr(f"verdict.{verdict.value}")
        if would_block:
            self.telemetry.incr("would_block")
        if request.tool_call is not None:
            self.telemetry.incr("tool_calls")
            self.telemetry.incr("tool_executed" if executed else "tool_denied")
        self.telemetry.observe_latency("total", latency)
        for k, v in stage_ms.items():
            self.telemetry.observe_latency(k, v)
        dec = Decision(
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
            would_block=would_block,
            exfiltration_attempt=exfil_attempt,
            exfiltration_blocked=exfil_blocked,
        )
        audit.emit(audit.decision_record(request, dec), self.audit_sink)
        return dec
