"""A local playground for exercising AEGIS through a browser.

Every verdict shown in the UI comes from a real :class:`~aegis.AegisGateway`
running in this process - nothing is precomputed or reimplemented in JavaScript,
so what you see is exactly what the library would decide in production.

Start it with::

    aegis-demo                  # or: python -m aegis.demo
"""
from .server import build_app, main, serve

__all__ = ["build_app", "main", "serve"]
