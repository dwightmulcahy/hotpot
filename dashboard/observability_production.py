"""Compatibility import for deployments/tests that referenced the former observability layer."""

from pathlib import Path

from .server import DashboardApplication as ObservabilityDashboard
from .server import build_app, main

_STATIC = Path(__file__).with_name("static")
EXTRA_CSS = (_STATIC / "observability.css").read_text(encoding="utf-8")
EXTRA_JS = (_STATIC / "observability.js").read_text(encoding="utf-8")

__all__ = ["ObservabilityDashboard", "EXTRA_CSS", "EXTRA_JS", "build_app", "main"]
