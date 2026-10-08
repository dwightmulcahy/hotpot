"""Compatibility entry point for the pre-refactor gateway runtime."""

from .server import HotpotServer, build_app, main

GatewayHotpot = HotpotServer

__all__ = ["GatewayHotpot", "build_app", "main"]

if __name__ == "__main__":
    main()
