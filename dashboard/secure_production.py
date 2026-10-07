"""Compatibility import for deployments that referenced the former security layer."""

from .app import DashboardApplication as SecureProductionDashboard
from .app import build_app, main

__all__ = ["SecureProductionDashboard", "build_app", "main"]
