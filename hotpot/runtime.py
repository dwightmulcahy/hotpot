"""Compatibility entry point for the pre-refactor runtime module."""

from .runtime_components import ResilientEventLogger, ResilientSourceStore
from .server import HotpotServer, build_app, main

HardenedHotpot = HotpotServer
ResilientStore = ResilientSourceStore

__all__ = [
    "HardenedHotpot",
    "ResilientEventLogger",
    "ResilientStore",
    "build_app",
    "main",
]

if __name__ == "__main__":
    main()
