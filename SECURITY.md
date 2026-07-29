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
- **argument-value validation is the tool's job, not AEGIS's.** AEGIS scores
  tool arguments for *injection and exfiltration* intent; it is not a path
  traversal, SQL-injection, or command-injection validator. A `read_file` call
  with `path="../../etc/shadow"` carries no injection signal and will be
  allowed — your tool implementation must validate its own inputs.
- **behavioural signals are keyed on the caller-supplied `agent_id`.** An
  attacker who can mint a fresh `agent_id` per call resets the per-agent
  baseline and evades rate/novelty/read-then-exfiltrate detection. Assign
  `agent_id` from a trusted source (your orchestrator), never from model output.
  The non-behavioural guards (RBAC, trust floors, injection scoring, egress
  filtering) are unaffected by this.
- **detection is lexicon-anchored.** A harmful instruction paraphrased entirely
  in benign vocabulary can score below the sanitize threshold; RBAC, trust
  floors and the egress filter remain the backstop for those.

## Handling of the model artifact

The shipped classifier (`aegis/data/injection_model.npz`) is a **plain array
file**, not a pickled estimator. This is deliberate:

- `np.load(..., allow_pickle=False)` **cannot execute code**, so a replaced or
  tampered model file is not a remote-code-execution sink the way a
  `joblib`/`pickle` artifact would be;
- the loader still verifies a `sha256` manifest before reading, and rejects any
  artifact whose weight vector does not match the feature extractor's dimension
  (`ModelIntegrityError`, fail-closed — the caller retrains rather than scoring
  with an unknown model);
- because it stores only weights, the artifact is portable across
  scikit-learn/numpy versions. scikit-learn is used for *training* only;
  inference is a dot product plus a sigmoid.

Regenerate the artifact yourself with `python -m aegis.sanitizer.train` if you
prefer not to trust the shipped one — training is deterministic (fixed seed).
