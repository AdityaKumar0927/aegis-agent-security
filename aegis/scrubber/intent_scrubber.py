"""Intent scrubbing: neutralise injected instructions before they reach the
agent's planner, while preserving legitimate data.

Two implementations are provided so the optimisation is *measurable*:

* ``NaiveIntentScrubber`` - a straightforward but wasteful baseline: recompiles
  patterns on every call, allocates many throwaway intermediates, and retains
  unbounded per-call history/cache (memory grows O(requests)).

* ``IntentScrubber`` - the optimised algorithm: module-level precompiled
  automata, a single-pass line scan, a cheap pre-filter "fast path" for the
  common benign case, and a bounded LRU cache (flat memory under load).

Both produce identical cleaning output, so the benchmark isolates the
implementation cost.  See ``harness/bench_concurrency.py`` for the numbers.
"""
from __future__ import annotations

import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field

from ..sanitizer.features import (
    _COERCION,
    _INVISIBLE,
    _JAILBREAK,
    _MAL_PAYLOAD,
    _MULTILINGUAL_OVERRIDE,
    _NEW_POLICY,
    _OVERRIDE,
    _ROLE_TOKENS,
    _SECRECY,
    normalize_text,
)

# --------------------------------------------------------------------------- #
# Raw pattern sources (shared spec).  The naive scrubber recompiles these every
# call; the optimised one compiles them once at import.
#
# The scrubber's vocabulary is deliberately *sourced from the detector's own
# lexicon* (aegis.sanitizer.features).  When the two drifted apart, content the
# detector flagged (e.g. a Spanish "ignora las instrucciones anteriores", a
# secrecy instruction, a fake "operating directive") reached the scrubber, was
# not redacted, and the gateway then downgraded the verdict to ALLOW - handing
# the caller an untouched injection labelled as sanitized.  Reusing the compiled
# detector patterns makes that class of gap structurally impossible.
# --------------------------------------------------------------------------- #
_SCRUBBER_OWN_PATTERNS = [
    r"\b(ignore|disregard|forget|override|bypass|discard)\b.{0,40}?\b"
    r"(previous|prior|earlier|above|all|the)\b.{0,20}?"
    r"(instruction|instructions|prompt|rule|rules|policy|policies|context|"
    r"guidance|direction|directions|guardrail|guardrails)\b",
    r"(<\|?\s*(im_start|im_end|system|assistant)\s*\|?>|^\s*(system|assistant|developer)\s*:)",
    r"\b(new|updated|revised|real|actual)\b\s+(instructions?|rules?|policy|system\s+prompt)",
    r"\b(developer\s+mode|do\s+anything\s+now|\bDAN\b|jailbreak|no\s+longer\s+bound)\b",
    r"\b(send|post|upload|exfiltrate|email|forward|leak|transmit)\b.{0,40}?"
    r"(api[\s_-]?key|secret|password|token|credential|\.env|http)",
    r"\b(call|invoke|execute|run|trigger)\b.{0,20}?\b(tool|function|api|command)\b",
]

# Detector signals that must also be *removable*, not merely detectable.
_DETECTOR_PATTERNS = [
    p.pattern for p in (
        _OVERRIDE,                 # English instruction override (full lexicon)
        _ROLE_TOKENS,              # injected system/role delimiters
        _NEW_POLICY,               # fake "new instructions" / operating directive
        _JAILBREAK,                # developer-mode / DAN phrasing
        _MULTILINGUAL_OVERRIDE,    # ES/FR/DE/IT/PT/NL overrides
        _SECRECY,                  # "do not tell the user" concealment
        _COERCION,                 # "pre-approved", "skip confirmation"
        _MAL_PAYLOAD,              # reveal-prompt / delete-files / disable-safety
    )
]

_RAW_PATTERNS = _SCRUBBER_OWN_PATTERNS + _DETECTOR_PATTERNS

REDACTION = "[aegis:redacted-injected-instruction]"


@dataclass
class ScrubResult:
    text: str
    removed_count: int = 0
    chars_removed: int = 0
    redactions: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return self.removed_count > 0


def _canonicalize(text: str) -> str:
    """The text handed back to the caller.

    Only invisible characters (zero-width, soft hyphen, bidi controls) are
    stripped: they are an attack vector in their own right and carry no meaning.
    Homoglyph folding and diacritic stripping are deliberately NOT applied here -
    those are matching-only transforms, and applying them to the output would
    corrupt legitimate non-Latin text.
    """
    return _INVISIBLE.sub("", text)


def _match_view(line: str) -> str:
    """The normalised view a line is *matched* against (obfuscation-resistant)."""
    return normalize_text(line)


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #
class NaiveIntentScrubber:
    """Correct but deliberately un-optimised (for benchmark comparison)."""

    def __init__(self) -> None:
        self.cache: dict[str, str] = {}      # unbounded - grows forever
        self.history: list[tuple[str, str]] = []  # retains every input seen

    def scrub(self, text: str) -> ScrubResult:
        # (1) recompile all patterns on every single call
        patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _RAW_PATTERNS]
        norm = _canonicalize(text)

        # (2) allocate many throwaway intermediates
        lines = norm.split("\n")
        lowered = [ln.lower() for ln in lines]          # unused-ish waste
        stripped = [ln.strip() for ln in lines]         # more waste
        _ = lowered, stripped

        cleaned_lines: list[str] = []
        redactions: list[str] = []
        chars_removed = 0
        for ln in lines:
            probe = _match_view(ln)                     # obfuscation-resistant view
            flagged = False
            for p in patterns:                          # full re-scan per pattern
                if p.search(probe):
                    flagged = True
                    break
            if flagged and ln.strip():
                redactions.append(ln)
                chars_removed += len(ln)
                cleaned_lines.append(REDACTION)
            else:
                cleaned_lines.append(ln)                # original line preserved

        result = "\n".join(cleaned_lines)
        # (3) unbounded retention
        self.cache[text] = result
        self.history.append((text, result))
        return ScrubResult(result, len(redactions), chars_removed, redactions)


# --------------------------------------------------------------------------- #
# Optimised
# --------------------------------------------------------------------------- #
# The per-line patterns are compiled with the SAME flags the naive scrubber uses
# (IGNORECASE | MULTILINE), so the optimised per-line scan is byte-for-byte
# equivalent to the baseline.
_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _RAW_PATTERNS]
# Sound pre-filter: the union of the patterns.  If the master pattern does not
# match anywhere in the (normalised) text, then no individual pattern can match
# any line either - so skipping the per-line scan is provably safe.  This
# replaces the old hand-written substring hint, which could (and did) miss lines
# the full patterns would have redacted.
_MASTER = re.compile("|".join(f"(?:{p})" for p in _RAW_PATTERNS),
                     re.IGNORECASE | re.MULTILINE)


class IntentScrubber:
    """Optimised single-pass scrubber with a bounded LRU cache.

    Produces output identical to :class:`NaiveIntentScrubber` (the fast path is a
    sound superset pre-filter, not a heuristic), but precompiles patterns once and
    caches by content so recurrent inputs are free.
    """

    def __init__(self, cache_size: int = 1024) -> None:
        if cache_size < 1:
            raise ValueError("cache_size must be >= 1")
        # Keyed on the text itself (not hash(text)) so a hash collision can never
        # return a different document's scrub result.
        self._cache: OrderedDict[str, ScrubResult] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()   # bounded cache is safe to share across agents

    def _lru_get(self, key: str):
        with self._lock:
            res = self._cache.get(key)
            if res is not None:
                self._cache.move_to_end(key)
            return res

    def _lru_put(self, key: str, res: ScrubResult) -> None:
        with self._lock:
            self._cache[key] = res
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)   # evict oldest -> flat memory

    def scrub(self, text: str) -> ScrubResult:
        cached = self._lru_get(text)
        if cached is not None:
            return cached

        norm = _canonicalize(text)

        # fast path: the overwhelming majority of benign content hits this and
        # avoids all per-line regex work.  Sound because _MASTER is the union of
        # the per-line patterns, evaluated over the same normalised view the
        # per-line scan uses.
        if not _MASTER.search(_match_view(norm)):
            res = ScrubResult(norm, 0, 0, [])
            self._lru_put(text, res)
            return res

        removed = 0
        chars_removed = 0
        redactions: list[str] = []
        out: list[str] = []
        for ln in norm.split("\n"):
            if ln.strip() and any(p.search(_match_view(ln)) for p in _COMPILED):
                out.append(REDACTION)
                redactions.append(ln)
                removed += 1
                chars_removed += len(ln)
            else:
                out.append(ln)

        res = ScrubResult("\n".join(out), removed, chars_removed, redactions)
        self._lru_put(text, res)
        return res
