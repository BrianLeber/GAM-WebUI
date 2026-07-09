"""
Per-client user and OU cache.

Each client gets its own cache entry keyed by client_id. Caches are populated
on first access and refreshed on a timer. This avoids hammering the Google
Admin API on every keystroke in the autocomplete fields.

Refresh intervals:
  users — 30 minutes (large list, changes infrequently mid-session)
  OUs   — 60 minutes (changes rarely)

The cache is in-process memory only. On container restart it rebuilds on
first access. This is acceptable — the rebuild takes 5-15 seconds for a
typical Workspace tenant and happens in the background.
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .gam import GamClient


@dataclass
class ClientCache:
    users:       list[str] = field(default_factory=list)
    ous:         list[str] = field(default_factory=list)
    users_ready: bool = False
    ous_ready:   bool = False
    users_ts:    float = 0.0   # epoch seconds of last successful refresh
    ous_ts:      float = 0.0


_caches: dict[str, ClientCache] = {}
_lock = asyncio.Lock()

USER_TTL = 1800   # 30 min
OU_TTL   = 3600   # 60 min


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


async def _get_or_create(client_id: str) -> ClientCache:
    async with _lock:
        if client_id not in _caches:
            _caches[client_id] = ClientCache()
        return _caches[client_id]


async def get_users(client_id: str, gam: GamClient) -> tuple[bool, list[str]]:
    cache = await _get_or_create(client_id)
    if cache.users_ready and (_now() - cache.users_ts) < USER_TTL:
        return True, list(cache.users)
    ok, emails = await asyncio.to_thread(gam.list_users)
    if ok and emails:
        async with _lock:
            cache.users      = emails
            cache.users_ready = True
            cache.users_ts   = _now()
    return ok, list(cache.users)


async def get_ous(client_id: str, gam: GamClient) -> tuple[bool, list[str]]:
    cache = await _get_or_create(client_id)
    if cache.ous_ready and (_now() - cache.ous_ts) < OU_TTL:
        return True, list(cache.ous)
    ok, ous = await asyncio.to_thread(gam.list_ous)
    if ok and ous:
        async with _lock:
            cache.ous      = ous
            cache.ous_ready = True
            cache.ous_ts   = _now()
    return ok, list(cache.ous)


async def is_users_ready(client_id: str) -> bool:
    cache = await _get_or_create(client_id)
    return cache.users_ready


async def invalidate(client_id: str) -> None:
    """Force a cache refresh on next access (e.g. after a terminate action)."""
    async with _lock:
        if client_id in _caches:
            _caches[client_id].users_ts = 0.0
            _caches[client_id].ous_ts   = 0.0
