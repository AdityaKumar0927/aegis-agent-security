# Security Policy

AEGIS is defensive security software. We take the correctness of its guard
behaviour seriously and welcome reports of ways to get an unauthorized action or
a data-exfiltration past it.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository, or email the maintainer
listed on the GitHub profile.

Include, where possible:

- a minimal `AgentRequest` / `ToolCall` (or config) that reproduces the bypass,
- the expected vs. actual `Decision` (verdict, tier, exfiltration flags),
- the AEGIS version (`python -c "import aegis; print(aegis.__version__)"`) and
  Python/scikit-learn versions.

We aim to acknowledge reports within 5 business days and to ship a fix or a
documented mitigation for confirmed issues.

## Scope

In scope (these are the guarantees AEGIS aims to uphold):

- an indirect prompt injection that reaches a `BLOCK`/`SANITIZE`-worthy score but
  is allowed through;
- a tool call that violates the RBAC matrix or a trust floor but executes;
- a payload carrying a secret/PII pattern that leaves the box to an external
  destination in **protected** mode;
- a way to make `AegisGateway.process` raise instead of returning a fail-closed
  `BLOCK` (the process boundary must never propagate).

Out of scope (documented limitations, not vulnerabilities):

- the bundled `SandboxExecutor` is a **simulation** — it models tier decisions
  and does not provide real OS/container isolation. Wiring tiers to real
  isolation is the integrator's responsibility.
- monitor-only mode (`enforce=False`) intentionally does not prevent egress; it
  only reports what enforcement *would* do.
- detection of a genuinely novel injection *technique* with no lexical/semantic
  overlap with known families may degrade gracefully rather than catch
  everything (see the threat model in the README).

## Handling of the model artifact

The shipped classifier (`aegis/data/injection_model.joblib`) is a pickled
scikit-learn model. `joblib.load` executes arbitrary objects, so:

- the loader verifies a `sha256` manifest before unpickling and refuses a
  tampered or cross-version artifact (`ModelIntegrityError`);
- never point AEGIS at an untrusted model file. Regenerate the artifact yourself
  with `python -m aegis.sanitizer.train` if you don't trust the shipped one.
