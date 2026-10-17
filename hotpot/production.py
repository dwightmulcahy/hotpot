"""Compatibility entry point for the pre-refactor production runtime."""

import hmac

from .server import HotpotServer, build_app, main

ProductionHotpot = HotpotServer

__all__ = ["ProductionHotpot", "build_app", "hmac", "main"]

if __name__ == "__main__":
    main()
