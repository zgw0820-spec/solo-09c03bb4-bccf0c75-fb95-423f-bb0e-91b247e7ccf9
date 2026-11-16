"""Runtime configuration loaded from environment variables.

The same image runs both roles; behaviour is selected with ``DNS_ROLE``
(``primary`` or ``backup``). Each container gets its own SQLite file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(key: str, default: str) -> str:
    value = os.environ.get(key)
    return value if value not in (None, "") else default


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(_env(key, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    role: str = _env("DNS_ROLE", "primary")
    # Fixed intranet zone served by this deployment.
    dns_zone: str = _env("DNS_ZONE", "internal.local")
    dns_host: str = _env("DNS_HOST", "0.0.0.0")
    dns_port: int = _env_int("DNS_PORT", 5053)
    api_host: str = _env("API_HOST", "0.0.0.0")
    api_port: int = _env_int("API_PORT", 8000)
    db_path: str = _env("DB_PATH", "/data/dns.db")
    # Backup only: base URL of the primary HTTP API.
    primary_api_url: str = _env("PRIMARY_API_URL", "http://primary:8000")
    # Backup background synchronisation interval (seconds).
    sync_interval: float = float(_env_int("SYNC_INTERVAL", 5))
    http_timeout: float = float(_env_int("HTTP_TIMEOUT", 10))
    max_records: int = _env_int("MAX_RECORDS", 8)

    # -- zone diagnosis -------------------------------------------------
    # This node's own REST API, used to read its own current snapshot over
    # HTTP. If unreachable, the diagnoser falls back to the local store
    # and marks the snapshot source as "local".
    # Empty -> http://127.0.0.1:<API_PORT>.
    self_api_url: str = _env("SELF_API_URL", "")
    # The primary's way to reach the backup API. The backup reuses
    # PRIMARY_API_URL, so only the primary needs this set.
    backup_api_url: str = _env("BACKUP_API_URL", "")
    # UDP endpoints of both nodes.
    primary_dns_addr: str = _env("PRIMARY_DNS_ADDR", "primary:5053")
    backup_dns_addr: str = _env("BACKUP_DNS_ADDR", "backup:5053")
    # One UDP attempt may not exceed this many seconds; the whole
    # diagnosis is bounded so it can never hold up publish/sync.
    diagnose_udp_timeout: float = _env_float("DIAGNOSE_UDP_TIMEOUT", 2.0)
    diagnose_udp_attempts: int = _env_int("DIAGNOSE_UDP_ATTEMPTS", 1)
    diagnose_deadline: float = _env_float("DIAGNOSE_DEADLINE", 6.0)

    @property
    def is_primary(self) -> bool:
        return self.role == "primary"

    @property
    def effective_self_api_url(self) -> str:
        if self.self_api_url:
            return self.self_api_url.rstrip("/")
        return f"http://127.0.0.1:{self.api_port}"

    def peer_api_url(self) -> str:
        """API base URL of the other node, or "" when not configured."""
        if self.is_primary:
            return self.backup_api_url.rstrip("/")
        # The backup already knows the primary API URL.
        return self.primary_api_url.rstrip("/")


settings = Settings()
