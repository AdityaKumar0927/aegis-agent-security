"""Egress / data-exfiltration filter.

Inspects every egress-capable tool call against the routed sandbox tier:

* **every** destination the call names (multiple recipients, CC, nested URLs)
  must be permitted by that tier's allowlist and never a known-bad host, and
* the outbound payload - scanned across **all** arguments, after normalisation
  and best-effort decoding - must not carry a secret / PII pattern.

Any egress call that fails either test is denied and flagged as an exfiltration
*attempt*.  Because risky or injected requests are routed to no-egress tiers, and
secret-bearing payloads are blocked even on allowlisted tiers, the honeytoken
cannot leave the box.

Hardening notes (why this is more than a substring check):

* destinations are extracted from *all* address-bearing arg keys and *all*
  hosts within each value, so a second recipient after a benign first one
  ("to": "ok@internal.corp, attacker@evil.com") cannot slip through;
* the payload is NFKC-normalised, zero-width/soft-hyphen stripped, and long
  base64/hex blobs are decoded and appended before matching, so split or encoded
  secrets are still caught;
* the secret patterns, known-bad hosts, internal domains, egress tool set and
  tier capabilities all come from :class:`~aegis.config.AegisConfig`, so an
  operator can extend them without editing the library.
"""
from __future__ import annotations

import base64
import contextlib
import re
import unicodedata
from dataclasses import dataclass

from ..config import (
    DEFAULT_CONFIG,
    INTERNAL_DOMAINS,
    SECRET_PATTERNS,
)
from ..types import SandboxTier, ToolCall
from .tiers import capability

# Module-level compiled defaults (used by the backwards-compatible helper
# functions below).  The EgressFilter class compiles from its own config.
_SECRET_RES = [re.compile(p) for p in SECRET_PATTERNS]
_HOST_RE = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)
_EMAIL_HOST_RE = re.compile(r"@([\w.-]+)")
_ZERO_WIDTH_RE = re.compile(r"[​‌‍⁠﻿­]")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")

# arg keys that carry a destination
_DEST_KEYS = ("url", "endpoint", "dest", "destination", "to", "cc", "bcc",
              "recipient", "recipients", "host", "account", "address", "webhook")
# arg keys that carry the payload/body (scanned first, but ALL args are scanned)
_BODY_KEYS = ("body", "data", "payload", "content", "message", "text", "amount", "note")


@dataclass
class EgressDecision:
    allowed: bool
    reason: str
    is_exfil_attempt: bool = False
    destination: str = ""


def _normalize(text: str) -> str:
    """NFKC + strip zero-width/soft-hyphen so split/obfuscated secrets collapse."""
    return _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text))


def _with_decoded(text: str) -> str:
    """Return the text plus best-effort base64/hex decodings of embedded blobs,
    so a secret hidden inside an encoded payload is still matched."""
    extra: list[str] = []
    for m in _B64_RE.findall(text):
        with contextlib.suppress(Exception):
            dec = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
            extra.append(dec.decode("utf-8", "ignore"))
    for m in _HEX_RE.findall(text):
        with contextlib.suppress(Exception):
            extra.append(bytes.fromhex(m).decode("utf-8", "ignore"))
    return text if not extra else text + " " + " ".join(extra)


def _hosts_in(value: str) -> list[str]:
    """Every host mentioned in a value: URL hosts, e-mail domains, else the bare
    token(s).  Splits on comma/semicolon/whitespace so multi-recipient fields are
    fully covered."""
    hosts: list[str] = []
    for m in _HOST_RE.findall(value):
        hosts.append(m.lower())
    for m in _EMAIL_HOST_RE.findall(value):
        hosts.append(m.lower())
    if not hosts:
        for tok in re.split(r"[\s,;]+", value.strip()):
            if tok:
                hosts.append(tok.lower())
    return hosts


def _extract_destinations(tool_call: ToolCall) -> list[str]:
    """All destination hosts named across every address-bearing arg."""
    dests: list[str] = []
    for k in _DEST_KEYS:
        if k in tool_call.args:
            dests.extend(_hosts_in(str(tool_call.args[k])))
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for d in dests:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _extract_destination(tool_call: ToolCall) -> str:
    """Backwards-compatible single-destination accessor (first host)."""
    d = _extract_destinations(tool_call)
    return d[0] if d else ""


def _payload_text(tool_call: ToolCall) -> str:
    """All argument values, normalised, with decoded blobs appended.

    Unlike the old body-key-only scan, this always covers *every* argument so a
    secret placed in a non-body field (or alongside a benign body) is still
    inspected.
    """
    parts = [f"{k}={v}" for k, v in tool_call.args.items()]
    text = " ".join(parts) if parts else ""
    return _with_decoded(_normalize(text))


def _carries_secret(text: str, secret_res=None) -> bool:
    res = secret_res if secret_res is not None else _SECRET_RES
    scanned = _with_decoded(_normalize(text))
    return any(r.search(scanned) for r in res)


def _is_internal(host: str, internal_domains=INTERNAL_DOMAINS) -> bool:
    host = host.lower()
    return any(host == d or host.endswith(d) for d in internal_domains)


class EgressFilter:
    def __init__(self, config=None):
        self.config = config if config is not None else DEFAULT_CONFIG
        self._secret_res = [re.compile(p) for p in self.config.secret_patterns]

    # -- helpers (config-aware) ---------------------------------------- #
    def carries_secret(self, text: str) -> bool:
        return _carries_secret(text, self._secret_res)

    def payload_secret(self, tool_call: ToolCall) -> bool:
        return any(r.search(_payload_text(tool_call)) for r in self._secret_res)

    def destinations(self, tool_call: ToolCall) -> list[str]:
        return _extract_destinations(tool_call)

    def is_internal(self, host: str) -> bool:
        return self.config.is_internal_host(host)

    def is_risky(self, tool_call: ToolCall) -> bool:
        """External destination or secret-bearing payload (used by the monitor)."""
        if not self.config.is_egress_tool(tool_call.name):
            return False
        dests = self.destinations(tool_call)
        external = any(not self.is_internal(d) for d in dests)
        return external or self.payload_secret(tool_call)

    # -- main inspection ----------------------------------------------- #
    def inspect(self, tier: SandboxTier, tool_call: ToolCall) -> EgressDecision:
        # Non-egress tools have no exfiltration surface here.
        if not self.config.is_egress_tool(tool_call.name):
            return EgressDecision(True, "not an egress tool")

        cap = self.config.tier_caps.get(tier) or capability(tier)
        dests = self.destinations(tool_call)
        primary = dests[0] if dests else ""
        secret = self.payload_secret(tool_call)
        external = [d for d in dests if not self.is_internal(d)]

        # 1) No-egress tiers: any outbound attempt is denied.  If it also carried
        #    a secret or targeted an external host, flag it as exfiltration.
        if cap.egress == "none":
            exfil = secret or bool(external)
            return EgressDecision(
                False,
                f"tier '{tier.value}' forbids egress (dest='{primary or '?'}')",
                is_exfil_attempt=exfil,
                destination=primary,
            )

        # 2) Any known-bad destination -> always exfiltration.
        bad = [d for d in dests if d in self.config.known_bad_destinations]
        if bad:
            return EgressDecision(False, f"known-bad destination '{bad[0]}'",
                                  is_exfil_attempt=True, destination=bad[0])

        # 3) Secret-bearing payload leaving to any external host -> exfiltration,
        #    even on an otherwise-allowlisted tier.
        if secret and external:
            return EgressDecision(False, f"secret-bearing payload to '{external[0]}'",
                                  is_exfil_attempt=True, destination=external[0])

        # 4) Every destination must satisfy the tier's egress rule.
        if cap.egress == "allowlist":
            for d in dests:
                if d not in cap.allow_destinations and not self.is_internal(d):
                    return EgressDecision(
                        False, f"destination '{d}' not on allowlist",
                        is_exfil_attempt=not self.is_internal(d), destination=d)
        elif cap.egress == "broad":
            for d in dests:
                if d not in cap.allow_destinations and not self.is_internal(d):
                    return EgressDecision(
                        False, f"destination '{d}' not permitted",
                        is_exfil_attempt=True, destination=d)

        # 5) A secret going only to internal hosts is still denied outbound to be
        #    safe, but is not counted as exfiltration.
        if secret:
            return EgressDecision(False, "secret-bearing payload blocked",
                                  is_exfil_attempt=False, destination=primary)

        return EgressDecision(True, f"egress to '{primary}' permitted", destination=primary)
