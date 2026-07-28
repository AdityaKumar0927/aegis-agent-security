"""Static policy: RBAC and per-sensitivity trust floors.

This is the hard boundary - independent of any ML score.  If a role may not call
a tool, or an agent's trust is below the floor for that tool's sensitivity, the
call is refused no matter what the classifier thinks.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..config import (
    SENSITIVITY_CRITICAL,
    SENSITIVITY_HIGH,
    AegisConfig,
)


@dataclass
class PolicyCheck:
    ok: bool
    reason: str = ""
    hard_block: bool = False   # True -> never allow (RBAC/critical trust breach)


class PolicyEngine:
    def __init__(self, config: AegisConfig):
        self.config = config

    def check(self, role: str, tool: str) -> PolicyCheck:
        # 1) RBAC: is the tool in the role's allowlist at all?
        if not self.config.is_permitted(role, tool):
            return PolicyCheck(
                ok=False,
                reason=f"RBAC: role '{role}' is not permitted to call '{tool}'",
                hard_block=True,
            )

        # 2) Trust floor by sensitivity.
        sensitivity = self.config.sensitivity(tool)
        floor = self.config.trust_floor(sensitivity)
        trust = self.config.trust(role)
        if trust < floor:
            hard = sensitivity in (SENSITIVITY_HIGH, SENSITIVITY_CRITICAL)
            return PolicyCheck(
                ok=False,
                reason=(f"trust floor: '{tool}' ({sensitivity}) needs trust>={floor:.2f}, "
                        f"role '{role}' has {trust:.2f}"),
                hard_block=hard,
            )

        return PolicyCheck(ok=True, reason="rbac+trust ok")
