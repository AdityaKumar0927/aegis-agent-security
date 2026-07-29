"""Feature extraction for the injection classifier.

Two complementary views are concatenated:

1. **Character n-gram hashing** (``HashingVectorizer``, char_wb 3-5) - cheap,
   stateless, and robust to spacing / homoglyph obfuscation. This is the
   "surface" view.

2. **Semantic / linguistic heuristics** - a small, hand-designed dense vector
   that captures *what the text is trying to do* (override instructions, switch
   roles, exfiltrate secrets, inject delimiters). This is the "intent" view and
   is deliberately template-agnostic so the model generalises to phrasings it
   never saw in training.

Keeping both cheap is what lets the whole pipeline stay sub-millisecond on CPU.
"""
from __future__ import annotations

import re
import unicodedata

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

# --------------------------------------------------------------------------- #
# Lexicons used by the semantic heuristics
# --------------------------------------------------------------------------- #
_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|discard|skip)\b[\w\s,]{0,40}?"
    r"\b(previous|prior|earlier|above|preceding|all|any|the)\b[\w\s]{0,20}?"
    r"\b(instruction|instructions|prompt|prompts|rule|rules|policy|policies|"
    r"direction|directions|guardrail|guardrails|context)\b",
    re.IGNORECASE,
)
_ROLE_TOKENS = re.compile(
    r"(<\|?\s*(im_start|im_end|system|assistant|user)\s*\|?>|"
    r"^\s*(system|assistant|developer)\s*:|"
    r"\[/?INST\]|###\s*(system|instruction))",
    re.IGNORECASE | re.MULTILINE,
)
# Deliberately does NOT match a bare "new policy" (common in benign business
# text); it targets claims about the *assistant's* instructions/system prompt.
_NEW_POLICY = re.compile(
    r"\b(new|updated|revised|real|actual|true)\b\s+"
    r"(system\s+prompt|instructions?|directive|operating\s+directive)"
    r"|\bpolicy\s+change\b[\w\s:,]{0,20}?\b(immediately|effective)\b",
    re.IGNORECASE,
)
_JAILBREAK = re.compile(
    r"\b(developer\s+mode|do\s+anything\s+now|\bDAN\b|jailbreak|"
    r"unfiltered|without\s+restrictions?|no\s+longer\s+bound|no\s+guardrails?|"
    r"roleplay\s+as|pretend\s+(the\s+)?(content\s+)?polic|ignore\s+your\s+(safety|guard))\b",
    re.IGNORECASE,
)
# Focused on unambiguous exfiltration verbs.  Benign-heavy words (report, share,
# copy, export, deliver) are deliberately excluded to avoid false positives on
# ordinary business text.
_EXFIL_VERB = re.compile(
    r"\b(send|post|upload|exfiltrate|email|e-mail|transmit|leak|forward)\b",
    re.IGNORECASE,
)
_STRONG_EXFIL_VERB = re.compile(r"\b(exfiltrate|upload|leak|post)\b", re.IGNORECASE)
_TOOL_TRIGGER = re.compile(
    r"\b(call|invoke|execute|run|trigger|use)\b[\w\s]{0,20}?"
    r"\b(tool|function|api|command|endpoint|action|"
    r"transfer_funds|exec_shell|http_post|send_email|delete_file|read_secret)\b",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(
    r"\b(api[\s_-]?key|secret|password|passwd|credential|token|"
    r"private\s+key|ssn|social\s+security|credit\s+card|"
    r"env(ironment)?\s+variable|\.env)\b",
    re.IGNORECASE,
)
_IMPERATIVE = re.compile(
    r"\b(you\s+must|you\s+should|you\s+will|do\s+not\s+tell|never\s+mention|"
    r"immediately|right\s+now|first|before\s+(you\s+)?(answer|respond|continue))\b",
    re.IGNORECASE,
)
_MULTILINGUAL_OVERRIDE = re.compile(
    r"\b(ignora|ignore|ignorez|ignoriere|oubliez|olvida|dimentica|vergiss|"
    r"negeer|nao\s+considere)\b[\w\s,']{0,30}?"
    r"\b(instruzioni|instrucciones|anweisungen|instructions?|reglas|regole|"
    r"regeln|regles|precedenti|anteriores|vorherigen|precedentes|precedentes|"
    r"previous|prior)\b",
    re.IGNORECASE,
)
_SECRECY = re.compile(
    r"\b(do\s+not|don't|never)\b\s+(tell|reveal|mention|inform|notify|show)\b"
    r"|\b(stay\s+silent|hide\s+this|keep\s+this\s+(secret|hidden)|"
    r"without\s+(telling|informing|notifying)|do\s+not\s+reveal\s+this|"
    r"between\s+us|for\s+(the\s+)?(assistant|ai)\s+only)\b",
    re.IGNORECASE,
)
# The malicious *action* itself - the payload an injection is trying to trigger.
# This generalises across framing (delimiter, jailbreak, embedded note, ...),
# since most attacks share a small set of harmful objectives.
_MAL_PAYLOAD = re.compile(
    r"\b(reveal|print|show|expose|dump|leak)\b[\w\s]{0,20}?"
    r"\b(system\s+prompt|prompt|instructions|environment\s+variables?|env|secrets?|"
    r"api\s*key|credentials?|password)\b"
    r"|\bdelete\s+(all\s+)?(the\s+)?files?\b"
    r"|\btransfer\s+\$?\d"
    # Disabling *AI guardrails* specifically.  A bare "disable the safety check"
    # is ordinary engineering/industrial language, so the object must name an
    # actual guardrail concept - otherwise this fires on benign maintenance text.
    r"|\b(disable|bypass|turn\s+off|switch\s+off)\b[\w\s]{0,25}?"
    r"\b(guardrails?|moderation|content\s+polic\w*|safety\s+(guidelines?|filters?|"
    r"systems?|protocols?|rules?|layers?)|security\s+(controls?|policies|policy)|"
    r"safety\s+training|alignment)\b"
    r"|\bgrant\b[\w\s]{0,20}?\badmin(istrator)?\b"
    r"|\bapprove\b[\w\s]{0,20}?\b(wire|transfer|payment)\b"
    # Forwarding the *conversation* to a third party (the injection pattern),
    # not ordinary business forwarding of invoices/documents.
    r"|\bforward\s+(every|all)\b[\w\s]{0,25}?"
    r"\b(message|messages|email|emails|conversation|conversations|chat|chats|"
    r"reply|replies|response|responses|prompt|prompts)\b"
    r"|\bcurl\b[^\n]*\|\s*sh\b",
    re.IGNORECASE,
)
_COERCION = re.compile(
    r"\b(pre[-\s]?approved|already\s+authoris|already\s+authoriz|"
    r"skip\s+(the\s+)?confirmation|without\s+confirmation|no\s+confirmation|"
    r"do\s+not\s+ask|don't\s+ask|the\s+user\s+has\s+(already\s+)?authoris|"
    r"you\s+are\s+authoris|this\s+is\s+authoris)\w*",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){16,}\b")
_DELIMITER = re.compile(r"(```|-----+|=====+|~~~~+|<!--|-->|\*\*\*+|___+)")
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")
# Every invisible/format character an attacker can sprinkle inside a keyword to
# break a pattern without changing what a human (or the LLM) reads: zero-width
# chars, the soft hyphen, bidirectional controls and directional isolates.
# Used for NORMALISATION (all of these are stripped before matching).
_INVISIBLE = re.compile(
    r"[­؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)
# The subset whose mere *presence* is suspicious enough to score as obfuscation.
# The soft hyphen (U+00AD) is deliberately excluded: it appears legitimately in
# typeset/hyphenated text (notably German), so treating it as an attack marker
# would flag ordinary documents.  It is still stripped during normalisation, so
# using it to break a keyword gains an attacker nothing.
_HIDDEN_SUSPICIOUS = re.compile(
    r"[؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)
# Letter-spacing obfuscation, e.g. "i g n o r e   p r e v i o u s".
# Deliberately uses [ \t] rather than \s so it cannot span a newline: that keeps
# normalize_text *line-independent*, i.e. normalising a whole document equals
# normalising each line separately.  The scrubber relies on this - its whole-text
# _MASTER prefilter is only a sound superset of the per-line scan if the two see
# the same normalisation.  (Letter-spacing attacks live within a line anyway.)
_SPACED = re.compile(r"(?:\b\w[ \t]){3,}\w\b")
_WS = re.compile(r"[ \t]{2,}")

# Homoglyph folding: Cyrillic/Greek/Armenian letters that render identically to
# Latin ones are mapped back, so "іgnоrе" (Cyrillic i/o/e) collapses onto
# "ignore" and the semantic rules fire as they would on the plain text.
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ӏ": "l", "ј": "j", "ҽ": "e", "н": "h",
    "м": "m", "т": "t", "в": "b", "к": "k",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek lowercase
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v",
    "τ": "t", "ι": "i", "κ": "k", "υ": "u", "χ": "x",
    "η": "n", "σ": "o", "μ": "u",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian / other lookalikes
    "օ": "o", "ո": "n", "ռ": "n", "ⲟ": "o", "ⅼ": "l",
    "ⅰ": "i", "ⅹ": "l",
})

HEURISTIC_FEATURE_NAMES = [
    "log_len",
    "nonascii_ratio",
    "zero_width",
    "override_instructions",
    "role_tokens",
    "new_policy",
    "jailbreak",
    "exfil_verb",
    "exfil_verb_near_secret",
    "tool_trigger",
    "credential_ref",
    "imperative_density",
    "url_count",
    "email_count",
    "base64_blob",
    "hex_blob",
    "delimiter_injection",
    "uppercase_ratio",
    "multilingual_override",
    "secrecy",
    "coercion",
    "malicious_payload",
]
N_HEURISTIC = len(HEURISTIC_FEATURE_NAMES)

# Human-readable names for the strongest signals (used for audit trails).
_SIGNAL_LABELS = {
    "override_instructions": "instruction-override phrase",
    "role_tokens": "role/system-token injection",
    "new_policy": "fake 'new instructions' claim",
    "jailbreak": "jailbreak / developer-mode phrasing",
    "exfil_verb_near_secret": "exfiltration verb near a secret reference",
    "tool_trigger": "explicit tool-invocation instruction",
    "credential_ref": "reference to credentials/secrets",
    "zero_width": "hidden zero-width characters",
    "base64_blob": "encoded (base64) payload",
    "delimiter_injection": "delimiter/markup injection",
    "multilingual_override": "non-English instruction-override phrase",
    "secrecy": "instruction to conceal actions from the user",
    "coercion": "false authorisation / skip-confirmation phrasing",
    "malicious_payload": "known harmful action (exfiltrate/delete/disable-safety/...)",
}


def _count(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text))


def heuristic_vector(text: str) -> np.ndarray:
    """Compute the dense semantic-heuristic feature vector for ``text``.

    Obfuscation markers (zero-width chars, non-ASCII ratio, uppercase ratio) are
    measured on the **raw** text, before normalisation would strip them, so
    hidden-character attacks are actually detected.  The semantic patterns are
    measured on the **normalised** text so letter-spacing / homoglyph obfuscation
    collapses onto the canonical phrasing they generalise over.
    """
    if not text:
        return np.zeros(N_HEURISTIC, dtype=np.float32)

    raw = text
    norm = normalize_text(text)

    n = len(raw)
    nonascii = sum(1 for c in raw if ord(c) > 127)
    upper = sum(1 for c in raw if c.isupper())
    # Hidden-character count is measured pre-normalisation, over the
    # *suspicious* invisible subset only (zero-width + bidi controls, not the
    # legitimately-used soft hyphen): their presence inside prose is itself an
    # obfuscation signal.
    zero_width = _count(_HIDDEN_SUSPICIOUS, raw)
    words = max(norm.count(" ") + 1, 1)

    exfil = _count(_EXFIL_VERB, norm)
    cred = 1.0 if _CREDENTIAL.search(norm) else 0.0
    # co-occurrence: an exfiltration verb *and* a secret/URL in the same text is
    # far more suspicious than either alone.
    exfil_near_secret = 1.0 if (exfil and (cred or _URL.search(norm))) else 0.0

    vec = np.array(
        [
            np.log1p(n),
            nonascii / n,
            float(min(zero_width, 5)),
            float(min(_count(_OVERRIDE, norm), 3)),
            float(min(_count(_ROLE_TOKENS, norm), 3)),
            1.0 if _NEW_POLICY.search(norm) else 0.0,
            1.0 if _JAILBREAK.search(norm) else 0.0,
            float(min(exfil, 4)),
            exfil_near_secret,
            1.0 if _TOOL_TRIGGER.search(norm) else 0.0,
            cred,
            min(_count(_IMPERATIVE, norm) / words * 10.0, 3.0),
            float(min(_count(_URL, norm), 5)),
            float(min(_count(_EMAIL, norm), 5)),
            1.0 if _BASE64_BLOB.search(norm) else 0.0,
            1.0 if _HEX_BLOB.search(norm) else 0.0,
            float(min(_count(_DELIMITER, norm), 5)),
            upper / n,
            1.0 if _MULTILINGUAL_OVERRIDE.search(norm) else 0.0,
            1.0 if _SECRECY.search(norm) else 0.0,
            1.0 if _COERCION.search(norm) else 0.0,
            1.0 if _MAL_PAYLOAD.search(norm) else 0.0,
        ],
        dtype=np.float32,
    )
    return vec


def top_signals(text: str, k: int = 4) -> list[str]:
    """Return the human-readable names of the strongest fired heuristics."""
    vec = heuristic_vector(text)
    fired = []
    for name, val in zip(HEURISTIC_FEATURE_NAMES, vec, strict=False):
        if name in _SIGNAL_LABELS and val > 0:
            fired.append((val, _SIGNAL_LABELS[name]))
    fired.sort(reverse=True)
    return [label for _, label in fired[:k]]


def _collapse_spaced(match: re.Match) -> str:
    return match.group(0).replace(" ", "")


def _strip_combining(text: str) -> str:
    """Drop combining marks so "i̇g̈nöre" folds onto "ignore".

    Applied only on the detection copy of the text, never on what is returned to
    the caller, so legitimate accented content is unaffected downstream.
    """
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def normalize_text(text: str) -> str:
    """Light normalisation so obfuscation collapses onto canonical forms.

    Layered so each trick an attacker can use to break a keyword is undone
    before the semantic rules run:

    1. strip invisibles (zero-width, soft hyphen, bidi/isolate controls) - done
       *first*, since NFKC preserves them;
    2. NFKC (fullwidth/compatibility forms);
    3. homoglyph folding (Cyrillic/Greek/Armenian lookalikes -> Latin);
    4. combining-mark removal (stacked diacritics);
    5. de-space letter-spacing attacks ("i g n o r e");
    6. squeeze runs of whitespace.

    This is the *detection* view of the text only.
    """
    # Steps 1-4 are provably identity transforms on pure-ASCII input (every
    # invisible, compatibility form, homoglyph and combining mark is non-ASCII),
    # so skipping them for ASCII text is equivalent - and ASCII is the common
    # case, which keeps the per-line scrubber scan cheap.
    if not text.isascii():
        text = _INVISIBLE.sub("", text)
        text = unicodedata.normalize("NFKC", text)
        text = _INVISIBLE.sub("", text)   # NFKC can re-expand compatibility forms
        # Order matters: strip combining marks FIRST, then fold homoglyphs.
        # A precomposed accented homoglyph (Greek ό, Cyrillic ё/ӑ) is not itself
        # a table key, so folding first would no-op on it and only afterwards
        # decompose to a bare Cyrillic/Greek letter that never gets folded -
        # letting "Ignόrё ӑll prёviόus instructiόns" slip through at 0.011.
        text = _strip_combining(text)
        text = text.translate(_CONFUSABLES)
        # Decomposition can expose further compatibility forms; fold once more.
        text = _strip_combining(text.translate(_CONFUSABLES))
    text = _SPACED.sub(_collapse_spaced, text)
    text = _WS.sub(" ", text)
    return text


class FeatureExtractor:
    """Combine hashed word + char n-grams with the dense semantic heuristics.

    * word (1,2)-grams capture phrase-level intent ("the tool", "previous
      instructions") and generalise across benign vocabulary;
    * a small char (3,4)-gram block adds robustness to typos / obfuscation;
    * the dense semantic heuristics carry the template-agnostic attack intent.

    All blocks are l2-normed and cheap; a single short string transforms in tens
    of microseconds.
    """

    def __init__(self, word_features: int = 2 ** 16, char_features: int = 2 ** 14):
        self.word_hasher = HashingVectorizer(
            analyzer="word", ngram_range=(1, 2), n_features=word_features,
            alternate_sign=False, norm="l2",
        )
        self.char_hasher = HashingVectorizer(
            analyzer="char_wb", ngram_range=(3, 4), n_features=char_features,
            alternate_sign=False, norm="l2",
        )
        # scale heuristics so they are comparable in magnitude to the l2-normed
        # hashing blocks without needing a separate fitted scaler.
        self._heur_scale = np.array(
            [0.15, 2.0, 0.5, 0.6, 0.6, 0.8, 0.8, 0.3, 1.0,
             0.7, 0.6, 0.4, 0.25, 0.25, 0.7, 0.5, 0.3, 1.2,
             0.9, 0.9, 0.8, 1.0],
            dtype=np.float32,
        )

    def transform(self, texts: list[str]) -> sparse.csr_matrix:
        norm = [normalize_text(t) for t in texts]
        word = self.word_hasher.transform(norm)
        char = self.char_hasher.transform(norm)
        # heuristic_vector normalises internally for its semantic features but
        # measures obfuscation (zero-width / non-ASCII) on the RAW text, so it
        # must receive the originals, not the pre-normalised strings.
        heur = np.vstack([heuristic_vector(t) for t in texts]) * self._heur_scale
        return sparse.hstack([word, char, sparse.csr_matrix(heur)], format="csr")

    @property
    def n_features(self) -> int:
        return self.word_hasher.n_features + self.char_hasher.n_features + N_HEURISTIC
