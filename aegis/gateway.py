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
from .types import AgentRequest, Decision, Source, Verdict


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

        content = request.content
        max_len = self.config.max_content_length

        # Oversized untrusted content is a DoS/coverage hazard: we will NOT
        # truncate-and-inspect (that would leave an unscanned tail through which
        # an injection could pass), and we will NOT scan an unbounded input.
        # Fail closed - block and let the operator raise max_content_length for
        # legitimately large content.  Direct USER input (higher trust) is scanned
        # in full up to the limit.
        if len(content) > max_len:
            reasons.append(
                f"content length {len(content)} exceeds max_content_length "
                f"{max_len} -> block (fail-closed)")
            return self._finalize(
                request, Verdict.BLOCK, allowed=False, executed=False, tier=None,
                injection_score=0.0, anomaly=0.0, reasons=reasons,
                sanitized=None, result=None, t_start=t_start, stage_ms=stage_ms,
                would_block=True,
            )

        # --- Stage 1: sanitize content AND tool arguments -------------- #
        # Tool arguments are a first-class injection channel: they are produced
        # by the (possibly compromised) agent, and an attack placed there used to
        # bypass detection entirely because only `content` was inspected.  Args
        # are never treated as USER-trust - the LLM authored them.
        th_sanitize = self.config.thresholds.injection_sanitize
        t = time.perf_counter()
        san = self.sanitizer.inspect(content, request.source)
        injection_score = san.score
        signals = list(san.top_signals)

        if request.tool_call is not None:
            arg_text = request.tool_call.flat_args()
            if arg_text:
                if len(arg_text) > max_len:
                    arg_text = arg_text[:max_len]
                    reasons.append(f"tool args truncated to {max_len} chars for inspection")
                arg_src = request.source if request.source.is_untrusted else Source.TOOL_OUTPUT
                arg_san = self.sanitizer.inspect(arg_text, arg_src)
                if arg_san.score > injection_score:
                    injection_score = arg_san.score
                    signals = list(arg_san.top_signals)
                    reasons.append(f"injection signal in tool arguments ({arg_san.score:.2f})")
                elif arg_san.score >= th_sanitize:
                    reasons.append(f"injection signal in tool arguments ({arg_san.score:.2f})")
        stage_ms["sanitize"] = (time.perf_counter() - t) * 1000.0

        if signals and injection_score >= th_sanitize:
            reasons.append("signals: " + ", ".join(signals))

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

            # Re-inspect the cleaned content.
            recheck = self.sanitizer.inspect(sanitized_content, request.source)

            # A scrub that removed nothing has NOT sanitized anything: the
            # content the caller will hand to the planner still carries whatever
            # the detector flagged.  The recheck below cannot catch this on its
            # own - anything reaching this stage already scored under the block
            # threshold, so an identity scrub trivially passes it.  Treat an
            # ineffective scrub as a failure to neutralise and fail closed.
            ineffective = not scrub.modified and recheck.score >= th_sanitize

            if recheck.score >= self.config.thresholds.injection_block or ineffective:
                would_block = True
                why = ("still injected after scrub -> block" if scrub.modified
                       else f"scrub removed nothing at injection {recheck.score:.2f} "
                            "-> cannot sanitize, block")
                if self.enforce:
                    verdict = Verdict.BLOCK
                    reasons.append(why)
                else:
                    verdict = Verdict.ALLOW
                    reasons.append("monitor-only: " + why + ", allowed")
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

    def _commit_behaviour(self, request: AgentRequest, verdict: Verdict, executed: bool) -> None:
        """Commit the behavioural outcome once the FINAL decision is known.

        Doing this here (rather than in the enforcer) means an ALLOW verdict that
        the egress filter later blocks trains nothing and is recorded as a block;
        a blocked attack can never teach the baseline to look normal.
        """
        if request.tool_call is None:
            return
        behaviour = getattr(self.pep, "behavior", None)
        if behaviour is None:
            return
        if verdict == Verdict.BLOCK:
            behaviour.record_block(request.agent_id)
        elif verdict in (Verdict.ALLOW, Verdict.SANITIZE) and executed:
            behaviour.record_allow(request.agent_id, request.tool_call)
        elif verdict == Verdict.QUARANTINE and executed:
            # suspicious-but-ran: note a sensitive read for later, don't train
            behaviour.record_quarantined(request.agent_id, request.tool_call)

    def _finalize(self, request, verdict, *, allowed, executed, tier, injection_score,
                  anomaly, reasons, sanitized, result, t_start, stage_ms,
                  would_block=False, exfil_attempt=False, exfil_blocked=False) -> Decision:
        self._commit_behaviour(request, verdict, executed)
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
