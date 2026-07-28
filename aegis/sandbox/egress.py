"""Egress / data-exfiltration filter.

Inspects every egress-capable tool call against the routed sandbox tier:

* the destination must be permitted by that tier's allowlist (and never a known
  bad host), and
* the outbound payload must not carry a secret / PII pattern.

Any egress call that fails either test is denied and flagged as an exfiltration
*attempt*.  Because risky or injected requests are routed to no-egress tiers,
and secret-bearing payloads are blocked even on allowlisted tiers, the honeytoken
cannot leave the box.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import EGRESS_TOOLS, KNOWN_BAD_DESTINATIONS, SECRET_PATTERNS
from ..types import SandboxTier, ToolCall
from .tiers import capability

_SECRET_RES = [re.compile(p) for p in SECRET_PATTERNS]
_HOST_RE = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)
_EMAIL_HOST_RE = re.compile(r"@([\w.-]+)")

# arg keys that carry a destination
_DEST_KEYS = ("url", "endpoint", "dest", "destination", "to", "recipient",
              "host", "account", "address", "webhook")
# arg keys that carry the payload/body
_BODY_KEYS = ("body", "data", "payload", "content", "message", "text", "amount", "note")


@dataclass
class EgressDecision:
    allowed: bool
    reason: str
    is_exfil_attempt: bool = False
    destination: str = ""


def _extract_destination(tool_call: ToolCall) -> str:
    for k in _DEST_KEYS:
        if k in tool_call.args:
            v = str(tool_call.args[k])
            m = _HOST_RE.search(v)
            if m:
                return m.group(1).lower()
            m = _EMAIL_HOST_RE.search(v)
            if m:
                return m.group(1).lower()
            return v.lower()
    return ""


def _payload_text(tool_call: ToolCall) -> str:
    parts = []
    for k in _BODY_KEYS:
        if k in tool_call.args:
            parts.append(str(tool_call.args[k]))
    if not parts:                       # fall back to scanning all args
        parts = [tool_call.flat_args()]
    return " ".join(parts)


def _carries_secret(text: str) -> bool:
    return any(r.search(text) for r in _SECRET_RES)


def _is_internal(host: str) -> bool:
    return host.endswith(".internal.corp") or host == "localhost"


class EgressFilter:
    def __init__(self, config=None):
        from ..config import DEFAULT_CONFIG
        self.config = config if config is not None else DEFAULT_CONFIG

    def inspect(self, tier: SandboxTier, tool_call: ToolCall) -> EgressDecision:
        # Non-egress tools have no exfiltration surface here.
        if tool_call.name not in self.config.egress_tools:
            return EgressDecision(True, "not an egress tool")

        cap = self.config.tier_caps.get(tier) or capability(tier)
        dest = _extract_destination(tool_call)
        payload = _payload_text(tool_call)
        secret = _carries_secret(payload)

        # 1) No-egress tiers: any outbound attempt is denied.  If it also carried
        #    a secret or targeted an external host, flag it as exfiltration.
        if cap.egress == "none":
            exfil = secret or (bool(dest) and not _is_internal(dest))
            return EgressDecision(
                False,
                f"tier '{tier.value}' forbids egress (dest='{dest or '?'}')",
                is_exfil_attempt=exfil,
                destination=dest,
            )

        # 2) Known-bad destination -> always exfiltration.
        if dest in self.config.known_bad_destinations:
            return EgressDecision(False, f"known-bad destination '{dest}'",
                                  is_exfil_attempt=True, destination=dest)

        # 3) Secret-bearing payload leaving the box -> exfiltration, even on an
        #    otherwise-allowlisted tier.
        if secret and not _is_internal(dest):
            return EgressDecision(False, f"secret-bearing payload to '{dest}'",
                                  is_exfil_attempt=True, destination=dest)

        # 4) Destination must be on the tier allowlist.
        if cap.egress == "allowlist" and dest not in cap.allow_destinations:
            exfil = bool(dest) and not _is_internal(dest)
            return EgressDecision(False, f"destination '{dest}' not on allowlist",
                                  is_exfil_attempt=exfil, destination=dest)

        if cap.egress == "broad" and dest not in cap.allow_destinations and not _is_internal(dest):
            return EgressDecision(False, f"destination '{dest}' not permitted",
                                  is_exfil_attempt=True, destination=dest)

        return EgressDecision(True, f"egress to '{dest}' permitted", destination=dest)
