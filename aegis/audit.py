"""Structured audit logging for AEGIS decisions.

Every decision the gateway reaches is emitted as a structured record on the
``aegis.audit`` logger so a real deployment can ship it to a SIEM / log pipeline:

* ``BLOCK`` / ``QUARANTINE`` and any exfiltration attempt log at ``WARNING``;
* everything else logs at ``INFO``.

The record is attached to the log entry as ``record.aegis`` (a plain dict) and
also rendered into the message, so it is useful with or without a JSON formatter.
By default Python's logging is silent unless the host app configures a handler;
:func:`configure_audit_logging` is a convenience for quick JSON-to-stderr setup.

An optional per-gateway ``audit_sink`` callback (see :class:`AegisGateway`)
receives the same dict, for callers who prefer to route events themselves.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .types import AgentRequest, Decision

AUDIT_LOGGER_NAME = "aegis.audit"
audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
# Library convention: stay silent unless the host application configures a
# handler (or calls configure_audit_logging).  Without this, Python's
# "last resort" handler would print WARNING+ records to stderr uninvited.
audit_logger.addHandler(logging.NullHandler())

AuditSink = Callable[[dict[str, Any]], None]


def decision_record(request: "AgentRequest", decision: "Decision") -> dict[str, Any]:
    """Build the JSON-serialisable audit record for a decision."""
    return {
        "request_id": decision.request_id,
        "agent_id": request.agent_id,
        "role": request.role,
        "source": request.source.value,
        "tool": request.tool_call.name if request.tool_call else None,
        "verdict": decision.verdict.value,
        "allowed": decision.allowed,
        "executed": decision.executed,
        "tier": decision.tier.value if decision.tier else None,
        "injection_score": round(decision.injection_score, 4),
        "anomaly_score": round(decision.anomaly_score, 4),
        "exfiltration_attempt": decision.exfiltration_attempt,
        "exfiltration_blocked": decision.exfiltration_blocked,
        "error": decision.error,
        "latency_ms": round(decision.latency_ms, 3),
        "reasons": list(decision.reasons),
    }


def emit(record: dict[str, Any], sink: Optional[AuditSink] = None) -> None:
    """Log ``record`` at a severity derived from the verdict, then fan out to an
    optional caller-supplied sink.  Never raises: audit failures must not break
    the request path."""
    verdict = record.get("verdict")
    level = logging.INFO
    if verdict in ("block", "quarantine") or record.get("exfiltration_attempt"):
        level = logging.WARNING
    if record.get("error"):
        level = logging.ERROR

    if audit_logger.isEnabledFor(level):
        msg = (f"{verdict} tool={record.get('tool')} agent={record.get('agent_id')} "
               f"inj={record.get('injection_score')} anom={record.get('anomaly_score')} "
               f":: {'; '.join(record.get('reasons') or []) or 'ok'}")
        audit_logger.log(level, msg, extra={"aegis": record})

    if sink is not None:
        try:
            sink(record)
        except Exception:  # noqa: BLE001 - a broken sink must not break the guard
            audit_logger.exception("aegis audit sink raised")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "aegis", None)
        if payload is None:
            payload = {"message": record.getMessage(), "level": record.levelname}
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_audit_logging(level: int = logging.INFO,
                            stream: Any = None) -> logging.Logger:
    """Attach a JSON-lines handler to the ``aegis.audit`` logger (idempotent).

    Convenience for scripts/demos; production apps typically configure logging
    themselves and can ignore this.
    """
    for h in audit_logger.handlers:
        if getattr(h, "_aegis_json", False):
            audit_logger.setLevel(level)
            return audit_logger
    handler = logging.StreamHandler(stream)
    handler.setFormatter(_JsonFormatter())
    handler._aegis_json = True  # type: ignore[attr-defined]
    audit_logger.addHandler(handler)
    audit_logger.setLevel(level)
    return audit_logger


__all__ = [
    "AUDIT_LOGGER_NAME",
    "audit_logger",
    "AuditSink",
    "decision_record",
    "emit",
    "configure_audit_logging",
]
