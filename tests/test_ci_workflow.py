"""Guard the CI workflow itself.

The workflow has broken twice for reasons unrelated to the code: once from a
stale inline command, once from a `": "` inside an unquoted YAML scalar which
invalidated the entire file (every job vanished, so nothing even ran). Both are
cheap to catch here.
"""
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _load():
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.skipif(not WORKFLOW.exists(), reason="workflow not present")
def test_workflow_is_valid_yaml_with_jobs():
    data = _load()
    assert data.get("jobs"), "workflow parsed but declares no jobs"
    for job_name, job in data["jobs"].items():
        assert job.get("steps"), f"{job_name} has no steps"
        for step in job["steps"]:
            assert "run" in step or "uses" in step, f"{job_name}: step missing run/uses"


@pytest.mark.skipif(not WORKFLOW.exists(), reason="workflow not present")
def test_referenced_scripts_exist():
    """A workflow step calling a missing script fails only on the runner."""
    data = _load()
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            run = str(step.get("run", ""))
            for token in run.split():
                if token.startswith("scripts/") and token.endswith(".py"):
                    assert (ROOT / token).exists(), f"workflow references missing {token}"


def test_verify_model_script_passes():
    """Run the same script CI runs, so a broken artifact fails here first."""
    script = ROOT / "scripts" / "verify_model.py"
    if not script.exists():
        pytest.skip("verify_model.py not present")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, f"verify_model.py failed:\n{proc.stdout}\n{proc.stderr}"
