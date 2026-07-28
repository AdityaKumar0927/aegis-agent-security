# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
