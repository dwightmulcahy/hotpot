"""Compatibility import for deployments that referenced the former observability layer."""

from .app import DashboardApplication as ObservabilityDashboard
from .app import build_app, main

__all__ = ["ObservabilityDashboard", "build_app", "main"]
