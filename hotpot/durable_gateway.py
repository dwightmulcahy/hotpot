"""Compatibility entry point for the pre-refactor durable gateway runtime."""

from .server import HotpotServer, build_app, main

DurableGatewayHotpot = HotpotServer

__all__ = ["DurableGatewayHotpot", "build_app", "main"]

if __name__ == "__main__":
    main()
