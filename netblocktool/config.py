"""Runtime configuration for NetblockTool.

Values may be supplied on the command line or through the environment.
Command-line arguments always win over environment variables, which in turn
win over the built-in defaults.

Recognised environment variables:

    NETBLOCKTOOL_TIMEOUT      Per-request timeout in seconds (float)
    NETBLOCKTOOL_USER_AGENT   User-Agent / SEC identification string
    NETBLOCKTOOL_MAX_WORKERS  Maximum concurrent passive lookups (int)
    NETBLOCKTOOL_MAX_RETRIES  Retry attempts per request (int)
    NETBLOCKTOOL_RATE_LIMIT   Default requests per second, per host (float)
    NETBLOCKTOOL_CACHE_DIR    Directory for the on-disk HTTP cache
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__

#: Default identification string. The SEC requires a descriptive User-Agent
#: containing real contact details; users should override this via ``-u`` or
#: ``NETBLOCKTOOL_USER_AGENT`` before querying EDGAR.
DEFAULT_USER_AGENT = f"NetblockTool/{__version__} (passive recon; set NETBLOCKTOOL_USER_AGENT)"

#: SEC explicitly documents a 10 requests/second ceiling. We stay well under it.
SEC_RATE_LIMIT = 5.0

#: ARIN throttles aggressive Whois-RWS clients; be conservative.
REGISTRY_RATE_LIMIT = 8.0


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(slots=True)
class Config:
    """Everything the network and processing layers need to know."""

    user_agent: str = field(
        default_factory=lambda: os.environ.get("NETBLOCKTOOL_USER_AGENT") or DEFAULT_USER_AGENT
    )
    timeout: float = field(default_factory=lambda: _env_float("NETBLOCKTOOL_TIMEOUT", 15.0))
    max_workers: int = field(default_factory=lambda: _env_int("NETBLOCKTOOL_MAX_WORKERS", 8))
    max_retries: int = field(default_factory=lambda: _env_int("NETBLOCKTOOL_MAX_RETRIES", 3))
    rate_limit: float = field(
        default_factory=lambda: _env_float("NETBLOCKTOOL_RATE_LIMIT", REGISTRY_RATE_LIMIT)
    )
    cache_dir: Path | None = field(
        default_factory=lambda: (
            Path(os.environ["NETBLOCKTOOL_CACHE_DIR"])
            if os.environ.get("NETBLOCKTOOL_CACHE_DIR")
            else None
        )
    )

    #: Registries to consult, in order.
    registries: tuple[str, ...] = ("arin", "ripe", "apnic", "afrinic", "lacnic")
    #: Passive search provider name, or ``None`` to disable search entirely.
    search_provider: str | None = "google"
    #: Restrict results to a single IP version (4, 6 or ``None`` for both).
    ip_version: int | None = None
    #: Maximum registry objects to expand. Guards against runaway wildcards.
    max_objects: int = 500

    def __post_init__(self) -> None:
        # Defensive clamping: a zero or negative value here would either hang
        # the tool forever or spin a busy loop.
        self.timeout = max(1.0, float(self.timeout))
        self.max_workers = max(1, min(int(self.max_workers), 32))
        self.max_retries = max(0, min(int(self.max_retries), 10))
        self.rate_limit = max(0.1, float(self.rate_limit))
        self.max_objects = max(1, int(self.max_objects))

    def is_default_user_agent(self) -> bool:
        """True when the user never supplied real contact information."""
        return self.user_agent == DEFAULT_USER_AGENT
