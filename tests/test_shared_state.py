"""Shared-state Lua behavior and failure modes. Author: Rajarshi.

Uses an in-process Redis emulator with real Lua execution. This does not replace
production Redis failover, persistence or network integration testing.
"""
import asyncio
import hashlib
import json
import time

import fakeredis
import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError

from general_ai_gateway.config import GatewayConfig
from general_ai_gateway.state import State


@pytest.fixture
def shared(tmp_path, monkeypatch):
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ALLOWED_HOSTS", "upstream.example")
    config = {
        "revision": 1,
        "tenants": {"tenant": {"key_sha256": hashlib.sha256(b"key").hexdigest(),
                               "artifacts": ["chat"]}},
        "artifacts": {"chat": {"kind": "chat", "url": "https://upstream.example/chat"}}
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    server = fakeredis.FakeServer()
    replicas = [State(str(path), None), State(str(path), None)]
    for replica in replicas:
        replica.redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    return server, replicas, config


async def test_shared_quota_under_concurrency(shared):
    _, replicas, _ = shared
    for replica in replicas:
        await replica.start()
    try:
        results = await asyncio.gather(*[
            replicas[i % 2].admit("tenant", 7, 100) for i in range(40)
        ])
        assert sum(results) == 7
        # Other tenants have independent allowances.
        assert await replicas[1].admit("other", 7, 100)
    finally:
        for replica in replicas:
            await replica.close()


async def test_shared_cas_one_writer_wins_and_other_replica_syncs(shared):
    _, replicas, raw = shared
    for replica in replicas:
        await replica.start()
    try:
        a = GatewayConfig.model_validate(raw | {"revision": 2})
        b = a.model_copy(deep=True)
        b.artifacts["chat"].enabled = False
        results = await asyncio.gather(replicas[0].replace(1, a), replicas[1].replace(1, b))
        assert sum(results) == 1
        for replica in replicas:
            await replica.sync()
        assert replicas[0].config.model_dump() == replicas[1].config.model_dump()
        assert replicas[0].config.revision == 2
    finally:
        for replica in replicas:
            await replica.close()


async def test_redis_loss_and_invalid_config_fail_closed(shared):
    server, replicas, _ = shared
    state = replicas[0]
    await state.start()
    try:
        await state.redis.set("general_ai_gateway:config", '{"invalid":true}')
        state.last_sync = time.monotonic() - 11
        with pytest.raises(ValueError):
            await state.sync()
        assert not state.fresh()
        assert state.config.revision == 1
        server.connected = False
        with pytest.raises(ConnectionError):
            await state.admit("tenant", 7, 100)
    finally:
        server.connected = True
        await state.close()
        await replicas[1].close()
