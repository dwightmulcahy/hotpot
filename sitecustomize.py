"""Process-wide HTTP server fingerprint hardening for Hotpot.

Python imports ``sitecustomize`` automatically during interpreter startup when
this module is available on ``sys.path``.  aiohttp otherwise advertises a
``Server`` header such as ``Python/3.12 aiohttp/3.x`` whenever a response does
not already provide one.

Hotpot's proxied responses preserve an upstream ``Server`` header when one is
present.  This setting therefore mainly affects Hotpot-generated responses and
proxied responses whose upstream intentionally omitted a server fingerprint.
"""

from __future__ import annotations

import os

import aiohttp.web_response as _web_response


server_header = os.getenv("HOTPOT_SERVER_HEADER", "nginx").strip() or "nginx"
_web_response.SERVER_SOFTWARE = server_header
