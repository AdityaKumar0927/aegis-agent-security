"""Deterministic rule detectors.

These run *alongside* the learned classifier as a high-precision safety net: a
handful of patterns that are almost never benign in agent-facing content (an
explicit "ignore previous instructions", a fake system token, an exfiltration
instruction pointing at a URL).  The ensemble takes the max of the rule score
and the model score, so an obvious attack is caught even if the model is unsure.
"""
from __future__ import annotations

from dataclasses import dataclass

from .features import (
    _COERCION,
    _CREDENTIAL,
    _EMAIL,
    _EXFIL_VERB,
    _JAILBREAK,
    _MAL_PAYLOAD,
    _MULTILINGUAL_OVERRIDE,
    _NEW_POLICY,
    _OVERRIDE,
    _ROLE_TOKENS,
    _SECRECY,
    _STRONG_EXFIL_VERB,
    _TOOL_TRIGGER,
    _URL,
    _ZERO_WIDTH,
    normalize_text,
)

_INTERNAL_HOSTS = ("internal.corp", "localhost")


def _has_external_destination(text: str) -> bool:
    """True if the text references a URL or e-mail pointing off the org."""
    for u in _URL.findall(text):
        host = u.split("//", 1)[-1].split("/", 1)[0].lower()
        if not any(h in host for h in _INTERNAL_HOSTS):
            return True
    for e in _EMAIL.findall(text):
        dom = e.split("@", 1)[-1].lower()
        if not any(h in dom for h in _INTERNAL_HOSTS):
            return True
    return False


def _clause(text: str, start: int) -> str:
    """The clause beginning at ``start`` - truncated at the next sentence
    boundary so the rule does not span two unrelated sentences."""
    w = text[start:start + 200]
    cut = len(w)
    for sep in ("\n", ". ", "; ", "! ", "? "):
        i = w.find(sep, 6)
        if i != -1:
            cut = min(cut, i)
    return w[:min(cut, 120)]


def _exfil_score(text: str) -> float:
    """Precise exfiltration signal: an exfil verb moving a secret to an external
    destination *within one clause*.  The clause windowing stops benign
    multi-sentence docs (which may separately mention an e-mail and, in a later
    sentence, an 'API key') from coincidentally firing the rule."""
    for m in _EXFIL_VERB.finditer(text):
        clause = _clause(text, m.start())
        if _CREDENTIAL.search(clause) and _has_external_destination(clause):
            return 0.88
    for m in _STRONG_EXFIL_VERB.finditer(text):
        clause = _clause(text, m.start())
        if _CREDENTIAL.search(clause) or _has_external_destination(clause):
            return 0.82
    return 0.0


@dataclass
class RuleHit:
    name: str
    weight: float
    description: str


# Each rule contributes a weight; the score is 1 - prod(1 - w) over fired rules
# (noisy-OR), so multiple weak signals still combine into a strong one.
_RULES = [
    ("instruction_override", 0.80, _OVERRIDE, "overrides prior instructions"),
    ("multilingual_override", 0.78, _MULTILINGUAL_OVERRIDE,
     "overrides instructions (non-English)"),
    ("role_injection", 0.75, _ROLE_TOKENS, "injects a system/role token"),
    ("fake_new_policy", 0.65, _NEW_POLICY, "claims new/updated instructions"),
    ("jailbreak", 0.70, _JAILBREAK, "jailbreak / developer-mode phrasing"),
    ("malicious_payload", 0.72, _MAL_PAYLOAD, "known harmful action payload"),
    ("hidden_chars", 0.55, _ZERO_WIDTH, "hidden zero-width characters"),
]


def rule_evaluate(text: str) -> tuple[float, list[RuleHit]]:
    """Return (score in [0,1], list of fired rules)."""
    # Detect hidden zero-width characters on the RAW text first - normalisation
    # strips them, so checking after would make the hidden-char rule dead code.
    raw_has_zero_width = bool(_ZERO_WIDTH.search(text))
    text = normalize_text(text)
    hits: list[RuleHit] = []

    if raw_has_zero_width:
        hits.append(RuleHit("hidden_chars_raw", 0.55, "hidden zero-width characters"))

    for name, weight, pattern, desc in _RULES:
        if name == "hidden_chars":
            continue  # handled above on the raw text
        if pattern.search(text):
            hits.append(RuleHit(name, weight, desc))

    # Compound rule: an exfiltration verb moving a secret to an *external*
    # destination is a classic data-exfiltration injection.
    exfil = _exfil_score(text)
    if exfil > 0:
        hits.append(RuleHit("exfil_instruction", exfil,
                            "instructs sending a secret to an external destination"))

    # Compound rule: telling the agent to invoke a tool from inside untrusted
    # content, especially with coercion ("pre-approved", "skip confirmation").
    if _TOOL_TRIGGER.search(text) and (
        _OVERRIDE.search(text) or _CREDENTIAL.search(text) or _COERCION.search(text)
    ):
        hits.append(RuleHit("tool_hijack", 0.80,
                            "directs the agent to invoke a tool"))

    # Compound rule: an instruction to conceal actions from the user, paired with
    # an action verb, is a hallmark of a stealthy injection.
    if _SECRECY.search(text) and (_EXFIL_VERB.search(text) or _TOOL_TRIGGER.search(text)
                                  or _OVERRIDE.search(text)):
        hits.append(RuleHit("stealth_instruction", 0.78,
                            "instructs the agent to act covertly"))

    # noisy-OR combination
    keep = 1.0
    for h in hits:
        keep *= (1.0 - h.weight)
    score = 1.0 - keep
    return score, hits
