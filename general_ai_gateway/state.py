"""Shared admission counters and compare-and-swap configuration. Author: Rajarshi."""
import asyncio
import time
from pathlib import Path

from redis.asyncio import Redis

from .config import GatewayConfig, parse_config

# Both counters are checked before either increments. Redis time avoids clock skew.
ADMIT = """
local t = redis.call('TIME')
local now = tonumber(t[1])
local minute = math.floor(now / 60)
local day = math.floor(now / 86400)
local m = redis.call('HMGET', KEYS[1], 'minute', 'mcount', 'day', 'dcount')
local mc = 0
local dc = 0
if tonumber(m[1]) == minute then mc = tonumber(m[2]) or 0 end
if tonumber(m[3]) == day then dc = tonumber(m[4]) or 0 end
if mc >= tonumber(ARGV[1]) or dc >= tonumber(ARGV[2]) then return 0 end
redis.call('HSET', KEYS[1], 'minute', minute, 'mcount', mc+1, 'day', day, 'dcount', dc+1)
redis.call('EXPIRE', KEYS[1], 172800)
return 1
"""
CAS = """
local old = redis.call('GET', KEYS[1])
if not old then return 0 end
if tonumber(cjson.decode(old).revision) ~= tonumber(ARGV[1]) then return 0 end
redis.call('SET', KEYS[1], ARGV[2])
return 1
"""


class State:
    def __init__(self, path: str, redis_url: str | None):
        self.path = Path(path)
        self.redis = Redis.from_url(redis_url, decode_responses=True, socket_timeout=2,
                                     socket_connect_timeout=2, max_connections=200) if redis_url else None
        self.config: GatewayConfig | None = None
        self.last_sync = 0.0
        self.lock = asyncio.Lock()
        self.counters: dict[str, tuple[int, int, int, int]] = {}

    async def start(self):
        raw = self.path.read_text(encoding="utf-8-sig")
        parse_config(raw)
        if self.redis:
            await self.redis.set("general_ai_gateway:config", raw, nx=True)
            raw = await self.redis.get("general_ai_gateway:config")
        self.config = parse_config(raw)
        self.last_sync = time.monotonic()

    async def sync(self):
        if self.redis:
            raw = await self.redis.get("general_ai_gateway:config")
            candidate = parse_config(raw)
            async with self.lock:
                if candidate.revision >= self.config.revision:
                    self.config = candidate
        self.last_sync = time.monotonic()

    async def replace(self, expected: int, candidate: GatewayConfig) -> bool:
        async with self.lock:
            if candidate.revision != expected + 1:
                return False
            if self.redis:
                ok = await self.redis.eval(
                    CAS, 1, "general_ai_gateway:config", expected, candidate.model_dump_json()
                )
                if not ok:
                    return False
            elif self.config.revision != expected:
                return False
            self.config = candidate
            self.last_sync = time.monotonic()
            return True

    async def admit(self, tenant: str, rpm: int, daily: int) -> bool:
        if self.redis:
            return bool(await self.redis.eval(ADMIT, 1, "general_ai_gateway:quota:" + tenant, rpm, daily))
        async with self.lock:
            now = int(time.time())
            minute, day = now // 60, now // 86400
            old_m, mc, old_d, dc = self.counters.get(tenant, (minute, 0, day, 0))
            mc = mc if minute == old_m else 0
            dc = dc if day == old_d else 0
            if mc >= rpm or dc >= daily:
                return False
            self.counters[tenant] = minute, mc + 1, day, dc + 1
            return True

    def fresh(self) -> bool:
        return not self.redis or time.monotonic() - self.last_sync < 10

    async def close(self):
        if self.redis:
            await self.redis.aclose()
