"""Config loading, validation, and per-gateway isolation."""
import json

import pytest

from aegis import AegisConfig, default_config
from aegis.config import Thresholds
from aegis.errors import AegisConfigError


def test_default_config_is_valid():
    default_config().validate()


def test_bad_thresholds_rejected():
    with pytest.raises(AegisConfigError):
        AegisConfig(thresholds=Thresholds(injection_block=1.5))
    with pytest.raises(AegisConfigError):
        # sanitize must be <= block
        AegisConfig(thresholds=Thresholds(injection_sanitize=0.9, injection_block=0.3))


def test_bad_trust_rejected():
    with pytest.raises(AegisConfigError):
        AegisConfig(role_trust={"ops": 2.0})


def test_bad_limits_rejected():
    with pytest.raises(AegisConfigError):
        AegisConfig(rate_limit=0)
    with pytest.raises(AegisConfigError):
        AegisConfig(max_content_length=0)


def test_from_dict_rejects_unknown_keys():
    with pytest.raises(AegisConfigError):
        AegisConfig.from_dict({"not_a_real_key": 1})


def test_from_dict_roundtrip():
    cfg = AegisConfig.from_dict({
        "egress_tools": ["send_email"],
        "known_bad_destinations": ["bad.example"],
        "thresholds": {"injection_block": 0.7, "injection_sanitize": 0.2,
                       "anomaly_quarantine": 0.5, "anomaly_block": 0.8},
    })
    assert cfg.egress_tools == {"send_email"}
    assert "bad.example" in cfg.known_bad_destinations
    assert cfg.thresholds.injection_block == 0.7


def test_from_file_json(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"rate_limit": 5}), encoding="utf-8")
    cfg = AegisConfig.from_file(str(p))
    assert cfg.rate_limit == 5


def test_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_INJECTION_BLOCK", "0.66")
    monkeypatch.setenv("AEGIS_RATE_LIMIT", "9")
    cfg = AegisConfig.from_env()
    assert cfg.thresholds.injection_block == 0.66
    assert cfg.rate_limit == 9


def test_copy_is_independent():
    a = AegisConfig()
    b = a.copy()
    b.thresholds.injection_block = 0.99
    b.role_tool_matrix["untrusted"].add("exec_shell")
    assert a.thresholds.injection_block == 0.80
    assert "exec_shell" not in a.role_tool_matrix["untrusted"]
