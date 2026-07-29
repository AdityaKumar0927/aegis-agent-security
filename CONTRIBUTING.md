# Contributing to AEGIS

Thanks for your interest in improving AEGIS. This is a defensive-security
project, so correctness and clear reasoning matter more than feature volume.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                          # tests, ruff, mypy, langgraph
```

## Before you open a PR

Run the same checks CI runs:

```bash
ruff check aegis harness tests
mypy aegis
pytest -q
```

All three must pass. If you changed anything in the detection pipeline or the
benchmark harness, also run `python -m harness.run_all` and update
`reports/RESULTS.md` (it is regenerated, not hand-edited).

## Guidelines

- **Fail closed.** Any new decision path must default to the safe outcome
  (`BLOCK` / most-restrictive tier) on error or ambiguity. `AegisGateway.process`
  must never raise.
- **Config over constants.** New policy knobs (tools, patterns, thresholds,
  limits) belong on `AegisConfig` with a validated default, not as a module
  global read directly at runtime.
- **Add a regression test for every bug you fix.** Security fixes especially:
  include the exact input that used to slip through.
- **Keep the dependency surface small.** The core depends only on
  numpy/scipy/scikit-learn; heavier or framework-specific deps go behind
  an optional extra.
- **Retraining the model** changes `aegis/data/injection_model.npz` and its
  `.sha256`. Regenerate deterministically with `python -m aegis.sanitizer.train`
  and commit both files together.

## Reporting security issues

Do not file public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

By contributing you agree your contributions are licensed under the project's
MIT license.
