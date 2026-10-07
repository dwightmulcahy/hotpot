"""Compatibility import for deployments that referenced the former security layer."""

from .server import DashboardApplication as SecureProductionDashboard
from .server import build_app, main

__all__ = ["SecureProductionDashboard", "build_app", "main"]
