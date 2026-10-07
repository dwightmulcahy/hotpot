"""Compatibility import for the short-lived routed dashboard entrypoint."""

from .server import DashboardApplication as RoutedObservabilityDashboard
from .server import build_app, main

__all__ = ["RoutedObservabilityDashboard", "build_app", "main"]
