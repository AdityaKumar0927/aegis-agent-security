"""Policy and tuning configuration for AEGIS.

Everything an operator would realistically want to change for a given enterprise
deployment lives on :class:`AegisConfig`: the RBAC matrix, tool sensitivity,
sandbox capabilities, egress allowlists, secret patterns, behavioural limits and
the decision thresholds.  The module-level constants below are only the
*defaults* used to populate a fresh ``AegisConfig``; nothing in the runtime reads
them directly, so an operator can override any of them per deployment without
monkeypatching globals.

Load a config from a JSON/TOML file with :meth:`AegisConfig.from_file`, layer in
environment overrides with :meth:`AegisConfig.from_env`, and validate it with
:meth:`AegisConfig.validate` (also run automatically on construction).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from typing import Any

from .errors import AegisConfigError
from .types import SandboxTier

# --------------------------------------------------------------------------- #
# Roles, trust and RBAC
# --------------------------------------------------------------------------- #
# Trust score in [0, 1]; drives how permissive a sandbox tier an agent may reach.
ROLE_TRUST: dict[str, float] = {
    "untrusted": 0.10,   # e.g. an agent handling arbitrary web content
    "researcher": 0.40,
    "analyst": 0.55,
    "ops": 0.75,
    "admin": 0.95,
}

# Which tools each role is permitted to call at all (hard RBAC boundary).
ROLE_TOOL_MATRIX: dict[str, set[str]] = {
    "untrusted": {"web_search", "read_public_doc"},
    "researcher": {"web_search", "read_public_doc", "read_file", "db_query"},
    "analyst": {"web_search", "read_public_doc", "read_file", "db_query", "send_email"},
    "ops": {
        "web_search", "read_public_doc", "read_file", "db_query",
        "send_email", "http_post", "delete_file",
    },
    "admin": {
        "web_search", "read_public_doc", "read_file", "db_query",
        "send_email", "http_post", "delete_file", "read_secret",
        "transfer_funds", "exec_shell",
    },
}

# --------------------------------------------------------------------------- #
# Tool sensitivity
# --------------------------------------------------------------------------- #
# level -> the minimum sandbox tier that is *allowed* to be granted, and the
# trust floor required to run the tool outside of quarantine.
SENSITIVITY_LOW = "low"
SENSITIVITY_MEDIUM = "medium"
SENSITIVITY_HIGH = "high"
SENSITIVITY_CRITICAL = "critical"

_SENSITIVITY_LEVELS = (
    SENSITIVITY_LOW, SENSITIVITY_MEDIUM, SENSITIVITY_HIGH, SENSITIVITY_CRITICAL,
)

TOOL_SENSITIVITY: dict[str, str] = {
    "web_search": SENSITIVITY_LOW,
    "read_public_doc": SENSITIVITY_LOW,
    "read_file": SENSITIVITY_MEDIUM,
    "db_query": SENSITIVITY_MEDIUM,
    "send_email": SENSITIVITY_HIGH,
    "http_post": SENSITIVITY_HIGH,
    "delete_file": SENSITIVITY_HIGH,
    "read_secret": SENSITIVITY_CRITICAL,
    "transfer_funds": SENSITIVITY_CRITICAL,
    "exec_shell": SENSITIVITY_CRITICAL,
}

# Trust floor required per sensitivity level.  Below the floor a call is blocked
# (or quarantined for medium) regardless of RBAC.
SENSITIVITY_TRUST_FLOOR: dict[str, float] = {
    SENSITIVITY_LOW: 0.0,
    SENSITIVITY_MEDIUM: 0.30,
    SENSITIVITY_HIGH: 0.60,
    SENSITIVITY_CRITICAL: 0.90,
}

# Tools that may transmit data off-box.  These are the exfiltration surface and
# are subject to egress inspection.
EGRESS_TOOLS: set[str] = {"http_post", "send_email", "transfer_funds"}

# Tools that mutate the filesystem / execute code.  They require a writable
# (scratch) tier, so the router must not cap them into a read-only tier.
WRITE_TOOLS: set[str] = {"delete_file", "exec_shell"}

# Non-egress tools that read secrets; require a tier that grants secret access.
SECRET_TOOLS: set[str] = {"read_secret"}

# Domain suffixes / hosts considered internal (not an exfiltration destination).
INTERNAL_DOMAINS: tuple[str, ...] = (".internal.corp", "localhost")

# --------------------------------------------------------------------------- #
# Sandbox tier capabilities
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TierCapability:
    egress: str                 # "none" | "allowlist" | "broad"
    filesystem: str             # "none" | "ro" | "scratch"
    secret_access: str          # "none" | "scoped" | "full"
    allow_destinations: frozenset[str] = frozenset()


TIER_CAPS: dict[SandboxTier, TierCapability] = {
    SandboxTier.NO_NET: TierCapability("none", "none", "none"),
    SandboxTier.READ_ONLY: TierCapability("none", "ro", "scoped"),
    SandboxTier.RESTRICTED: TierCapability(
        "allowlist", "scratch", "scoped",
        allow_destinations=frozenset({
            "api.internal.corp", "mail.internal.corp", "erp.internal.corp",
        }),
    ),
    SandboxTier.TRUSTED: TierCapability(
        "broad", "scratch", "full",
        allow_destinations=frozenset({
            "api.internal.corp", "mail.internal.corp", "erp.internal.corp",
            "partners.trusted-vendor.com",
        }),
    ),
}

# --------------------------------------------------------------------------- #
# Exfiltration / egress inspection
# --------------------------------------------------------------------------- #
# A honeytoken seeded into the simulated secret store.  If this string ever
# reaches a non-allowlisted destination, that counts as a data-exfiltration
# incident in the stress test.
CANARY_SECRET = "AEGIS-CANARY-9f3c1b7e42a8d6"

# Regexes that identify secret-bearing / sensitive payloads on egress.
SECRET_PATTERNS: list[str] = [
    r"AEGIS-CANARY-[0-9a-f]+",
    r"sk-[A-Za-z0-9]{16,}",                  # API keys
    r"AKIA[0-9A-Z]{16}",                     # AWS access key id
    r"gh[pousr]_[A-Za-z0-9]{20,}",           # GitHub tokens
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",   # private keys
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}",  # JWT
    r"\b\d{3}-\d{2}-\d{4}\b",                # US SSN
    r"\b(?:\d[ -]*?){13,16}\b",             # card-like number
    r"password\s*[:=]\s*\S+",
]

# Destinations that are always hostile regardless of tier.
KNOWN_BAD_DESTINATIONS: set[str] = {
    "evil.com", "attacker.net", "exfil.io", "pastebin.com",
    "webhook.site", "requestbin.net", "ngrok.io",
}


# --------------------------------------------------------------------------- #
# Decision thresholds
# --------------------------------------------------------------------------- #
@dataclass
class Thresholds:
    # Operating points selected on a held-out validation split (see
    # classifier.train_default): sanitize ~= 98% detection @ ~0.1% FPR; block is
    # the high-confidence point (~100% precision).
    injection_block: float = 0.80     # >= -> BLOCK outright
    injection_sanitize: float = 0.30  # >= -> scrub content / guard sensitive tools
    anomaly_quarantine: float = 0.55  # >= -> force most restrictive sandbox
    anomaly_block: float = 0.85       # >= -> BLOCK for high/critical tools

    def validate(self) -> None:
        for name in ("injection_block", "injection_sanitize",
                     "anomaly_quarantine", "anomaly_block"):
            v = getattr(self, name)
            if not isinstance(v, (int, float)) or not 0.0 <= float(v) <= 1.0:
                raise AegisConfigError(f"threshold '{name}' must be in [0, 1], got {v!r}")
        if self.injection_sanitize > self.injection_block:
            raise AegisConfigError(
                "injection_sanitize must be <= injection_block "
                f"({self.injection_sanitize} > {self.injection_block})")
        if self.anomaly_quarantine > self.anomaly_block:
            raise AegisConfigError(
                "anomaly_quarantine must be <= anomaly_block "
                f"({self.anomaly_quarantine} > {self.anomaly_block})")


@dataclass
class AegisConfig:
    # --- policy ---
    role_trust: dict[str, float] = field(default_factory=lambda: dict(ROLE_TRUST))
    role_tool_matrix: dict[str, set[str]] = field(
        default_factory=lambda: {k: set(v) for k, v in ROLE_TOOL_MATRIX.items()}
    )
    tool_sensitivity: dict[str, str] = field(
        default_factory=lambda: dict(TOOL_SENSITIVITY)
    )
    sensitivity_trust_floor: dict[str, float] = field(
        default_factory=lambda: dict(SENSITIVITY_TRUST_FLOOR)
    )
    thresholds: Thresholds = field(default_factory=Thresholds)

    # --- egress / sandbox ---
    egress_tools: set[str] = field(default_factory=lambda: set(EGRESS_TOOLS))
    write_tools: set[str] = field(default_factory=lambda: set(WRITE_TOOLS))
    secret_tools: set[str] = field(default_factory=lambda: set(SECRET_TOOLS))
    tier_caps: dict[SandboxTier, TierCapability] = field(
        default_factory=lambda: dict(TIER_CAPS)
    )
    known_bad_destinations: set[str] = field(
        default_factory=lambda: set(KNOWN_BAD_DESTINATIONS)
    )
    secret_patterns: list[str] = field(default_factory=lambda: list(SECRET_PATTERNS))
    internal_domains: tuple[str, ...] = INTERNAL_DOMAINS

    # --- behavioural monitor ---
    rate_window_s: float = 1.0
    rate_limit: int = 20
    max_agents: int = 100_000        # cap on tracked per-agent profiles (DoS bound)
    profile_ttl_s: float = 3600.0    # idle profiles evicted after this many seconds
    sensitive_read_window_s: float = 300.0  # read-then-exfiltrate window
    block_window_s: float = 60.0     # window over which recent blocks count

    # --- resource bounds ---
    max_content_length: int = 100_000   # untrusted content longer than this is truncated

    # ------------------------------------------------------------------ #
    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> AegisConfig:
        """Raise :class:`AegisConfigError` if the config is inconsistent."""
        for role, t in self.role_trust.items():
            if not 0.0 <= float(t) <= 1.0:
                raise AegisConfigError(f"role_trust['{role}'] must be in [0, 1], got {t!r}")
        for level, floor in self.sensitivity_trust_floor.items():
            if level not in _SENSITIVITY_LEVELS:
                raise AegisConfigError(f"unknown sensitivity level '{level}' in trust floor")
            if not 0.0 <= float(floor) <= 1.0:
                raise AegisConfigError(f"trust floor for '{level}' must be in [0, 1], got {floor!r}")
        # Every level must have an explicit floor: a partial override must not
        # silently leave a sensitivity level relying on the fail-closed fallback.
        missing = [lvl for lvl in _SENSITIVITY_LEVELS if lvl not in self.sensitivity_trust_floor]
        if missing:
            raise AegisConfigError(
                f"sensitivity_trust_floor is missing levels {missing}; "
                "provide a floor for every sensitivity level")
        for tool, level in self.tool_sensitivity.items():
            if level not in _SENSITIVITY_LEVELS:
                raise AegisConfigError(f"tool_sensitivity['{tool}'] has unknown level '{level}'")
        if self.rate_limit < 1:
            raise AegisConfigError(f"rate_limit must be >= 1, got {self.rate_limit}")
        if self.rate_window_s <= 0:
            raise AegisConfigError(f"rate_window_s must be > 0, got {self.rate_window_s}")
        if self.max_agents < 1:
            raise AegisConfigError(f"max_agents must be >= 1, got {self.max_agents}")
        if self.max_content_length < 1:
            raise AegisConfigError(f"max_content_length must be >= 1, got {self.max_content_length}")
        self.thresholds.validate()
        return self

    # ------------------------------------------------------------------ #
    def trust(self, role: str) -> float:
        return self.role_trust.get(role, 0.0)

    def sensitivity(self, tool: str) -> str:
        # Unknown tools are treated as high sensitivity (fail closed).
        return self.tool_sensitivity.get(tool, SENSITIVITY_HIGH)

    def trust_floor(self, sensitivity: str) -> float:
        # Fail closed: an unknown/missing level requires maximal trust (1.0)
        # rather than the old permissive 0.6, so a partial override can never
        # silently *lower* a floor (e.g. drop CRITICAL from 0.90).
        return self.sensitivity_trust_floor.get(sensitivity, 1.0)

    def is_permitted(self, role: str, tool: str) -> bool:
        return tool in self.role_tool_matrix.get(role, set())

    def is_egress_tool(self, tool: str) -> bool:
        return tool in self.egress_tools

    def is_write_tool(self, tool: str) -> bool:
        return tool in self.write_tools

    def is_secret_tool(self, tool: str) -> bool:
        return tool in self.secret_tools

    def is_internal_host(self, host: str) -> bool:
        """Internal iff the host matches an entry on a *label boundary*.

        An entry beginning with '.' (e.g. '.internal.corp') matches that domain
        and any subdomain of it; a bare entry (e.g. 'localhost', 'corp.example')
        matches only by exact equality.  This avoids the endswith() footgun where
        'notlocalhost' or 'data.evilcorp.example' would count as internal.
        """
        host = host.lower()
        for d in self.internal_domains:
            d = d.lower()
            if d.startswith("."):
                if host == d[1:] or host.endswith(d):
                    return True
            elif host == d:
                return True
        return False

    def copy(self) -> AegisConfig:
        """Return an independent deep-ish copy (own mutable containers)."""
        return replace(
            self,
            role_trust=dict(self.role_trust),
            role_tool_matrix={k: set(v) for k, v in self.role_tool_matrix.items()},
            tool_sensitivity=dict(self.tool_sensitivity),
            sensitivity_trust_floor=dict(self.sensitivity_trust_floor),
            thresholds=replace(self.thresholds),
            egress_tools=set(self.egress_tools),
            write_tools=set(self.write_tools),
            secret_tools=set(self.secret_tools),
            tier_caps=dict(self.tier_caps),
            known_bad_destinations=set(self.known_bad_destinations),
            secret_patterns=list(self.secret_patterns),
        )

    # ------------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AegisConfig:
        """Build a config from a plain dict (e.g. parsed JSON/TOML).

        Unknown keys are rejected so a typo can't silently leave a security
        setting at its default.
        """
        cfg = cls()
        known = set(vars(cfg))
        thresholds = data.get("thresholds")
        for key, value in data.items():
            if key == "thresholds":
                continue
            if key not in known:
                raise AegisConfigError(f"unknown config key '{key}'")
            if key == "role_tool_matrix":
                value = {k: set(v) for k, v in value.items()}
            elif key in ("egress_tools", "write_tools", "secret_tools",
                         "known_bad_destinations"):
                value = set(value)
            elif key == "internal_domains":
                value = tuple(value)
            setattr(cfg, key, value)
        if thresholds is not None:
            if not isinstance(thresholds, dict):
                raise AegisConfigError(
                    f"'thresholds' must be a mapping, got {type(thresholds).__name__}")
            cfg.thresholds = Thresholds(**thresholds)
        return cfg.validate()

    @classmethod
    def from_file(cls, path: str) -> AegisConfig:
        """Load a config from a ``.json`` or ``.toml`` file."""
        with open(path, "rb") as fh:
            raw = fh.read()
        if path.endswith(".toml"):
            try:
                import tomllib  # Python 3.11+
            except ModuleNotFoundError:  # 3.10 fallback
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ModuleNotFoundError as exc:
                    raise AegisConfigError(
                        "TOML config requires Python 3.11+ or the 'tomli' package "
                        "(pip install aegis-agent-security[toml])") from exc
            data = tomllib.loads(raw.decode("utf-8"))
        else:
            data = json.loads(raw.decode("utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_env(cls, base: AegisConfig | None = None, prefix: str = "AEGIS_") -> AegisConfig:
        """Overlay a small set of scalar overrides from environment variables.

        Recognised: ``AEGIS_INJECTION_BLOCK``, ``AEGIS_INJECTION_SANITIZE``,
        ``AEGIS_ANOMALY_QUARANTINE``, ``AEGIS_ANOMALY_BLOCK`` (floats),
        ``AEGIS_RATE_LIMIT``, ``AEGIS_MAX_AGENTS``, ``AEGIS_MAX_CONTENT_LENGTH``
        (ints), ``AEGIS_RATE_WINDOW_S`` (float).
        """
        cfg = (base or cls()).copy()
        th = cfg.thresholds

        def _f(name: str, cur: float) -> float:
            v = os.environ.get(prefix + name)
            return float(v) if v is not None else cur

        def _i(name: str, cur: int) -> int:
            v = os.environ.get(prefix + name)
            return int(v) if v is not None else cur

        th.injection_block = _f("INJECTION_BLOCK", th.injection_block)
        th.injection_sanitize = _f("INJECTION_SANITIZE", th.injection_sanitize)
        th.anomaly_quarantine = _f("ANOMALY_QUARANTINE", th.anomaly_quarantine)
        th.anomaly_block = _f("ANOMALY_BLOCK", th.anomaly_block)
        cfg.rate_limit = _i("RATE_LIMIT", cfg.rate_limit)
        cfg.rate_window_s = _f("RATE_WINDOW_S", cfg.rate_window_s)
        cfg.max_agents = _i("MAX_AGENTS", cfg.max_agents)
        cfg.max_content_length = _i("MAX_CONTENT_LENGTH", cfg.max_content_length)
        return cfg.validate()


def default_config() -> AegisConfig:
    """A fresh, independent default config.  Prefer this over the module-level
    ``DEFAULT_CONFIG`` when you intend to mutate the result."""
    return AegisConfig()


# Backwards-compatible shared default.  Do NOT mutate this instance; call
# ``default_config()`` (or ``AegisConfig()``) for a private copy you can tune.
# The gateway always takes a private copy, so mutating a gateway's config never
# leaks into this one.
DEFAULT_CONFIG = AegisConfig()
