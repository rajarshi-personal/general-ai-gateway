"""Behavioral security and control-plane regressions. Author: Rajarshi."""
import asyncio
import copy
import hashlib
import json

import httpx
import pytest

from general_ai_gateway.app import create_app

KEY = "tenant-test-key"
ADMIN = "a" * 40


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ADMIN_KEY", ADMIN)
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ALLOWED_HOSTS", "upstream.example")
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REDIS_URL", raising=False)
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REQUIRE_REDIS", raising=False)
    config = {
        "revision": 1,
        "tenants": {"alpha": {"key_sha256": hashlib.sha256(KEY.encode()).hexdigest(),
                              "artifacts": ["chat", "tool"], "requests_per_minute": 50}},
        "artifacts": {
            "chat": {"kind": "chat", "url": "https://upstream.example/chat"},
            "tool": {"kind": "mcp", "url": "https://upstream.example/mcp", "allowed_tools": ["echo"]}
        },
        "policy": {"block_email": True, "block_patterns": ["forbidden"]}
    }
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(config))
    calls = []

    def upstream(request):
        calls.append(request)
        if request.url.path == "/mcp":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})

    return create_app(str(path), httpx.MockTransport(upstream)), config, calls


def auth(key=KEY):
    return {"Authorization": "Bearer " + key}


async def call(app, method, path, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        return await c.request(method, path, **kwargs)


PAYLOAD = {"model": "chat", "messages": [{"role": "user", "content": "hi"}]}


async def test_auth_routing_and_secret_isolation(setup):
    app, _, calls = setup
    async with app.router.lifespan_context(app):
        assert (await call(app, "POST", "/v1/chat/completions", json=PAYLOAD)).status_code == 401
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), json=PAYLOAD)
        assert r.status_code == 200
        assert r.headers["x-general-ai-gateway-revision"] == "1"
        assert "authorization" not in calls[0].headers
        assert json.loads(calls[0].content)["max_tokens"] == 2048


@pytest.mark.parametrize("change,status", [
    ({"model": "secret"}, 403), ({"stream": True}, 422), ({"n": 2}, 422),
    ({"max_tokens": 999999}, 422), ({"max_tokens": True}, 422),
    ({"messages": [{"content": "person@example.com"}]}, 403),
    ({"messages": [{"content": "FORBIDDEN"}]}, 403),
])
async def test_policy_denials_never_reach_upstream(setup, change, status):
    app, _, calls = setup
    async with app.router.lifespan_context(app):
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), json=PAYLOAD | change)
        assert r.status_code == status
        assert not calls


async def test_hot_reload_cas_and_revocation(setup):
    app, config, calls = setup
    async with app.router.lifespan_context(app):
        candidate = copy.deepcopy(config)
        candidate["revision"] = 2
        candidate["artifacts"]["chat"]["enabled"] = False
        headers = auth(ADMIN) | {"If-Match": "1"}
        r = await call(app, "PUT", "/admin/config", headers=headers, json=candidate)
        assert r.status_code == 200
        assert (await call(app, "PUT", "/admin/config", headers=headers, json=candidate)).status_code == 409
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), json=PAYLOAD)
        assert r.status_code == 403
        assert not calls


async def test_invalid_egress_does_not_replace_config(setup):
    app, config, _ = setup
    async with app.router.lifespan_context(app):
        config["revision"] = 2
        config["artifacts"]["chat"]["url"] = "https://169.254.169.254/metadata"
        r = await call(app, "PUT", "/admin/config",
                       headers=auth(ADMIN) | {"If-Match": "1"}, json=config)
        assert r.status_code == 422
        assert app.state.control.config.revision == 1


async def test_atomic_admission(setup):
    app, _, _ = setup
    async with app.router.lifespan_context(app):
        results = await asyncio.gather(*[
            app.state.control.admit("alpha", 5, 100) for _ in range(30)
        ])
        assert sum(results) == 5


async def test_mcp_tool_allowlist(setup):
    app, _, calls = setup
    async with app.router.lifespan_context(app):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "shell"}}
        r = await call(app, "POST", "/v1/mcp/tool", headers=auth(), json=body)
        assert r.status_code == 403
        assert not calls
        body["params"]["name"] = "echo"
        assert (await call(app, "POST", "/v1/mcp/tool", headers=auth(), json=body)).status_code == 200


async def test_protected_metrics_and_bounded_labels(setup):
    app, _, _ = setup
    async with app.router.lifespan_context(app):
        assert (await call(app, "GET", "/metrics")).status_code == 401
        await call(app, "GET", "/secret-user-controlled-path")
        r = await call(app, "GET", "/metrics", headers=auth(ADMIN))
        assert r.status_code == 200
        assert "general_ai_gateway_requests_total" in r.text
        assert "secret-user-controlled-path" not in r.text


async def test_body_limit_and_invalid_json(setup):
    app, _, calls = setup
    async with app.router.lifespan_context(app):
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), content=b"x" * 1048577)
        assert r.status_code == 413
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), content=b'{"x": NaN}')
        assert r.status_code == 400
        assert not calls


async def test_output_dlp_and_circuit_breaker(setup, monkeypatch, tmp_path):
    _, config, _ = setup
    path = tmp_path / "second.json"
    path.write_text(json.dumps(config))
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"text": "secret@example.com"})

    app = create_app(str(path), httpx.MockTransport(upstream))
    async with app.router.lifespan_context(app):
        r = await call(app, "POST", "/v1/chat/completions", headers=auth(), json=PAYLOAD)
        assert r.status_code == 403
        assert "secret@example.com" not in r.text

    calls.clear()

    def failed(request):
        calls.append(request)
        return httpx.Response(503)

    app = create_app(str(path), httpx.MockTransport(failed))
    async with app.router.lifespan_context(app):
        for _ in range(3):
            assert (await call(app, "POST", "/v1/chat/completions",
                               headers=auth(), json=PAYLOAD)).status_code == 502
        assert (await call(app, "POST", "/v1/chat/completions",
                           headers=auth(), json=PAYLOAD)).status_code == 503
        assert len(calls) == 3
