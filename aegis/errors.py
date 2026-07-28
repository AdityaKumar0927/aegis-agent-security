"""Typed exception hierarchy for AEGIS.

Callers can catch :class:`AegisError` to handle any AEGIS-originated failure, or
a specific subclass.  The gateway itself never lets these (or any other
exception) escape ``process`` - it converts internal failures into a
fail-closed ``BLOCK`` decision - but the config/validation helpers raise them so
that *deployment-time* mistakes surface loudly and early rather than silently
weakening the guard at runtime.
"""
from __future__ import annotations


class AegisError(Exception):
    """Base class for every exception AEGIS raises."""


class AegisValidationError(AegisError, ValueError):
    """A request or value failed validation at a trust boundary.

    Subclasses :class:`ValueError` as well so existing ``except ValueError``
    handlers keep working.
    """


class AegisConfigError(AegisError, ValueError):
    """The configuration is malformed or internally inconsistent."""


class ModelIntegrityError(AegisError):
    """A model artifact failed an integrity or compatibility check."""


__all__ = [
    "AegisError",
    "AegisValidationError",
    "AegisConfigError",
    "ModelIntegrityError",
]
