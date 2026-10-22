"""Execution boundaries and snapshot consistency. Author: Rajarshi."""
import asyncio
import hashlib
import json

import httpx
import pytest

from general_ai_gateway.app import create_app


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ADMIN_KEY", "a" * 40)
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ALLOWED_HOSTS", "upstream.example")
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REDIS_URL", raising=False)
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REQUIRE_REDIS", raising=False)
    config = {
        "revision": 1,
        "tenants": {"tenant": {"key_sha256": hashlib.sha256(b"key").hexdigest(),
                               "artifacts": ["chat"]}},
        "artifacts": {"chat": {"kind": "chat", "url": "https://upstream.example/chat",
                                "max_concurrency": 1, "timeout_seconds": 0.1}},
        "policy": {"max_response_bytes": 1024}
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return str(path)


BODY = {"model": "chat", "messages": [{"role": "user", "content": "hi"}]}
AUTH = {"Authorization": "Bearer key"}


async def test_total_timeout(config_path):
    async def upstream(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    app = create_app(config_path, httpx.MockTransport(upstream))
    async with app.router.lifespan_context(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", headers=AUTH, json=BODY)
        assert response.status_code == 502


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"Location": "https://evil.example"}),
    httpx.Response(200, text="not JSON"),
    httpx.Response(200, content=b"{bad", headers={"Content-Type": "application/json"}),
    httpx.Response(200, json={"text": "x" * 2048}),
])
async def test_upstream_response_boundaries(config_path, response):
    app = create_app(config_path, httpx.MockTransport(lambda request: response))
    async with app.router.lifespan_context(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as client:
        result = await client.post("/v1/chat/completions", headers=AUTH, json=BODY)
        assert result.status_code == 502


async def test_concurrency_and_inflight_snapshot(config_path):
    entered, release = asyncio.Event(), asyncio.Event()

    async def upstream(request):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"text": "old snapshot completes"})

    app = create_app(config_path, httpx.MockTransport(upstream))
    async with app.router.lifespan_context(app):
        app.state.control.config.artifacts["chat"].timeout_seconds = 5
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://test") as client:
            pending = asyncio.create_task(client.post("/v1/chat/completions", headers=AUTH, json=BODY))
            await entered.wait()
            second = await client.post("/v1/chat/completions", headers=AUTH, json=BODY)
            assert second.status_code == 503
            candidate = app.state.control.config.model_copy(deep=True)
            candidate.revision = 2
            candidate.artifacts["chat"].enabled = False
            assert await app.state.control.replace(1, candidate)
            revoked = await client.post("/v1/chat/completions", headers=AUTH, json=BODY)
            assert revoked.status_code == 403
            release.set()
            original = await pending
            assert original.status_code == 200
            assert original.headers["x-general-ai-gateway-revision"] == "1"
