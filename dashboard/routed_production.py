"""Compatibility import for the short-lived routed dashboard entrypoint."""

from .app import DashboardApplication as RoutedObservabilityDashboard
from .app import build_app, main

__all__ = ["RoutedObservabilityDashboard", "build_app", "main"]
