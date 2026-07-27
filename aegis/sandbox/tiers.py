"""Sandbox tier helpers.

Tiers form a lattice from ``NO_NET`` (nothing leaves, nothing persists) to
``TRUSTED`` (broad but still allowlisted egress).  The router picks the
least-privileged tier that still lets a legitimate call function; risk pushes the
choice *down* toward isolation.
"""
from __future__ import annotations

from ..config import TIER_CAPS, TierCapability
from ..types import SandboxTier


def capability(tier: SandboxTier) -> TierCapability:
    return TIER_CAPS[tier]


def most_restrictive() -> SandboxTier:
    return SandboxTier.NO_NET


def describe(tier: SandboxTier) -> str:
    cap = capability(tier)
    return (f"{tier.value}: egress={cap.egress}, fs={cap.filesystem}, "
            f"secrets={cap.secret_access}")
