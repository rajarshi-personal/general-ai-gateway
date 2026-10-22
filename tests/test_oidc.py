"""Signed-token and mocked identity-provider regressions. Author: Rajarshi."""
import asyncio
import copy
import hashlib
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from general_ai_gateway.app import create_app
from general_ai_gateway.client_credentials import ClientCredentialsTokenProvider
from general_ai_gateway.config import GatewayConfig, validate_egress

ISSUER = "https://identity.example/realms/gateway"
AUDIENCE = "general-ai-gateway"
ADMIN = "a" * 40
BODY = {"model": "chat", "messages": [{"role": "user", "content": "hello"}]}


@pytest.fixture(scope="module")
def keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]


def jwk(key, kid="key-1"):
    result = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return result | {"kid": kid, "alg": "RS256", "use": "sig"}


def token(key, changes=None, headers=None, remove=()):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "service-account",
              "client_id": "workload", "iat": now, "exp": now + 300,
              "scope": "gateway:invoke models:read", "jti": "request-token"}
    claims.update(changes or {})
    for name in remove:
        claims.pop(name, None)
    return jwt.encode(claims, key, algorithm="RS256",
                      headers={"kid": "key-1", "typ": "at+jwt"} | (headers or {}))


@pytest.fixture
def setup_oidc(tmp_path, monkeypatch, keys):
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ADMIN_KEY", ADMIN)
    monkeypatch.setenv("GENERAL_AI_GATEWAY_ALLOWED_HOSTS", "upstream.example")
    monkeypatch.setenv("GENERAL_AI_GATEWAY_OIDC_ALLOWED_HOSTS", "identity.example")
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REDIS_URL", raising=False)
    monkeypatch.delenv("GENERAL_AI_GATEWAY_REQUIRE_REDIS", raising=False)
    config = {
        "revision": 1, "oidc": {"issuer": ISSUER, "audience": AUDIENCE},
        "tenants": {
            "alpha": {"oauth_client_ids": ["workload"], "artifacts": ["chat", "embedding", "agent", "mcp"],
                      "required_scopes": ["models:read"]},
            "beta": {"oauth_client_ids": ["other-workload"], "artifacts": []}
        },
        "artifacts": {
            "chat": {"kind": "chat", "url": "https://upstream.example/chat"},
            "embedding": {"kind": "embedding", "url": "https://upstream.example/embedding"},
            "agent": {"kind": "agent", "url": "https://upstream.example/agent"},
            "mcp": {"kind": "mcp", "url": "https://upstream.example/mcp", "allowed_tools": ["echo"]}
        }
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    provider = {
        "keys": [jwk(keys[0])], "issuer": ISSUER, "jwks_uri": ISSUER + "/keys",
        "outage": False, "calls": [], "upstreams": []
    }

    def transport(request):
        if request.url.host == "identity.example":
            provider["calls"].append(request)
            if provider["outage"]:
                return httpx.Response(503)
            if request.url.path.endswith("openid-configuration"):
                return httpx.Response(200, json={"issuer": provider["issuer"],
                                                "jwks_uri": provider["jwks_uri"]})
            if request.url.path.endswith("/token"):
                # Fixture authorization server verifies credentials and grant.
                if (request.headers.get("authorization") != "Basic d29ya2xvYWQ6c2VjcmV0"
                        or b"grant_type=client_credentials" not in request.content):
                    return httpx.Response(401, json={"error": "invalid_client"})
                return httpx.Response(200, json={"access_token": token(keys[0]),
                                                "token_type": "Bearer", "expires_in": 300})
            return httpx.Response(200, json={"keys": provider["keys"]})
        provider["upstreams"].append(request)
        return httpx.Response(200, json={"result": "ok"})

    wire = httpx.MockTransport(transport)
    return create_app(str(path), wire), config, provider, wire


async def request(app, access_token, path="/v1/models", method="GET", **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
        return await client.request(method, path,
                                    headers={"Authorization": "Bearer " + access_token}, **kwargs)


async def test_client_credentials_exchange_and_all_adapters(setup_oidc, keys):
    app, _, provider, wire = setup_oidc
    async with app.router.lifespan_context(app):
        async with ClientCredentialsTokenProvider(
            ISSUER + "/token", "workload", "secret", transport=wire
        ) as tokens:
            access_token = await tokens.get_token()
        routes = [
            ("/v1/chat/completions", BODY),
            ("/v1/embeddings", {"model": "embedding", "input": "hello"}),
            ("/v1/agents/agent/invoke", {"task": "hello"}),
            ("/v1/mcp/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "echo"}}),
        ]
        for path, body in routes:
            assert (await request(app, access_token, path, "POST", json=body)).status_code == 200
        assert (await request(app, access_token, "/v1/artifacts")).status_code == 200
        assert (await request(app, access_token)).status_code == 200
        assert len(provider["calls"]) == 3  # token endpoint plus one discovery/JWKS fetch
        assert all("authorization" not in call.headers for call in provider["upstreams"])
        assert (await request(app, access_token, "/admin/config")).status_code == 401
        assert (await request(app, access_token, "/metrics")).status_code == 401


@pytest.mark.parametrize("changes,remove,headers,status", [
    ({"exp": 1}, (), {}, 401),
    ({"nbf": 9999999999}, (), {}, 401),
    ({"iat": 9999999999}, (), {}, 401),
    ({"aud": "another-api"}, (), {}, 401),
    ({"iss": "https://attacker.example"}, (), {}, 401),
    ({}, ("exp",), {}, 401),
    ({}, ("client_id",), {}, 401),
    ({"client_id": ["workload"]}, (), {}, 401),
    ({"scope": {}}, (), {}, 401),
    ({"client_id": "unregistered"}, (), {}, 403),
    ({"scope": "gateway:invoke"}, (), {}, 403),
    ({"scope": "models:read"}, (), {}, 403),
    ({}, (), {"typ": "JWT"}, 401),
    ({}, (), {"jku": "https://attacker.example/jwks"}, 401),
    ({}, (), {"kid": "unknown"}, 401),
    ({"exp": True}, (), {}, 401),
])
async def test_bad_tokens_never_reach_provider(setup_oidc, keys, changes, remove, headers, status):
    app, _, provider, _ = setup_oidc
    async with app.router.lifespan_context(app):
        response = await request(app, token(keys[0], changes, headers, remove),
                                 "/v1/chat/completions", "POST", json=BODY)
        assert response.status_code == status
        if status == 401:
            assert "invalid_token" in response.headers["www-authenticate"]
        assert not provider["upstreams"]


async def test_signature_algorithms_and_header_limits(setup_oidc, keys):
    app, _, provider, _ = setup_oidc
    async with app.router.lifespan_context(app):
        forged = token(keys[1])
        unsigned = jwt.encode({"sub": "workload"}, key=None, algorithm="none",
                              headers={"kid": "key-1", "typ": "at+jwt"})
        symmetric = jwt.encode({"sub": "workload"}, key="x" * 32, algorithm="HS256",
                               headers={"kid": "key-1", "typ": "at+jwt"})
        for value in (forged, unsigned, symmetric, "bad-token", "x" * 16385):
            assert (await request(app, value)).status_code == 401
        assert len(provider["calls"]) == 2


async def test_client_mapping_and_live_revocation(setup_oidc, keys):
    app, raw, _, _ = setup_oidc
    async with app.router.lifespan_context(app):
        assert (await request(app, token(keys[0]))).status_code == 200
        other = await request(app, token(keys[0], {"client_id": "other-workload"}),
                              "/v1/chat/completions", "POST", json=BODY)
        assert other.status_code == 403
        candidate = copy.deepcopy(raw)
        candidate["revision"] = 2
        candidate["tenants"]["alpha"]["oauth_client_ids"] = ["replacement-workload"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
            updated = await client.put("/admin/config", json=candidate,
                                       headers={"Authorization": "Bearer " + ADMIN, "If-Match": "1"})
        assert updated.status_code == 200
        assert (await request(app, token(keys[0]))).status_code == 403


async def test_static_key_migration_is_explicit(setup_oidc):
    app, _, _, _ = setup_oidc
    async with app.router.lifespan_context(app):
        config = app.state.control.config.model_copy(deep=True)
        config.tenants["alpha"].key_sha256 = hashlib.sha256(b"legacy-key").hexdigest()
        config.revision += 1
        assert await app.state.control.replace(1, config)
        assert (await request(app, "legacy-key")).status_code == 401
        enabled = config.model_copy(deep=True)
        enabled.revision += 1
        enabled.oidc.allow_api_keys = True
        assert await app.state.control.replace(2, enabled)
        assert (await request(app, "legacy-key")).status_code == 200


async def test_concurrent_jwks_fetch_and_rotation_cooldown(setup_oidc, keys):
    app, _, provider, _ = setup_oidc
    async with app.router.lifespan_context(app):
        responses = await asyncio.gather(*[request(app, token(keys[0])) for _ in range(12)])
        assert all(response.status_code == 200 for response in responses)
        assert len(provider["calls"]) == 2
        provider["keys"] = [jwk(keys[1], "key-2")]
        rotated = token(keys[1], headers={"kid": "key-2"})
        assert (await request(app, rotated)).status_code == 401
        cache = app.state.authenticator.caches[ISSUER]
        cache.attempted_at -= 31
        assert (await request(app, rotated)).status_code == 200
        assert (await request(app, token(keys[0]))).status_code == 401
        assert len(provider["calls"]) == 4


async def test_outage_uses_fresh_cache_but_never_expired_keys(setup_oidc, keys):
    app, _, provider, _ = setup_oidc
    async with app.router.lifespan_context(app):
        assert (await request(app, token(keys[0]))).status_code == 200
        provider["outage"] = True
        assert (await request(app, token(keys[0]))).status_code == 200
        cache = app.state.authenticator.caches[ISSUER]
        cache.loaded_at -= 301
        cache.attempted_at -= 31
        assert (await request(app, token(keys[0]))).status_code == 503
        assert (await request(app, token(keys[0]))).status_code == 503
        assert len(provider["calls"]) == 3


@pytest.mark.parametrize("field,value", [
    ("issuer", "https://attacker.example"),
    ("jwks_uri", "https://169.254.169.254/keys"),
    ("jwks_uri", "http://identity.example/keys"),
    ("keys", []),
])
async def test_untrusted_discovery_fails_closed(setup_oidc, keys, field, value):
    app, _, provider, _ = setup_oidc
    provider[field] = value
    async with app.router.lifespan_context(app):
        assert (await request(app, token(keys[0]))).status_code == 503
        assert not provider["upstreams"]


async def test_generic_jwt_requires_provider_access_token_guard(setup_oidc, keys):
    app, _, _, _ = setup_oidc
    async with app.router.lifespan_context(app):
        config = app.state.control.config.model_copy(deep=True)
        config.revision += 1
        config.oidc.accepted_token_types = ["JWT"]
        config.oidc.client_id_claim = "azp"
        config.oidc.required_claims = {"typ": "Bearer"}
        assert await app.state.control.replace(1, config)
        access = token(keys[0], {"azp": "workload", "typ": "Bearer"}, {"typ": "JWT"})
        identity = token(keys[0], {"azp": "workload", "typ": "ID"}, {"typ": "JWT"})
        assert (await request(app, access)).status_code == 200
        assert (await request(app, identity)).status_code == 401


def test_config_validation(setup_oidc):
    _, raw, _, _ = setup_oidc
    invalid = copy.deepcopy(raw)
    invalid["tenants"]["beta"]["oauth_client_ids"] = ["workload"]
    with pytest.raises(ValidationError):
        GatewayConfig.model_validate(invalid)
    invalid = copy.deepcopy(raw)
    invalid["oidc"]["accepted_token_types"] = ["JWT"]
    with pytest.raises(ValidationError):
        GatewayConfig.model_validate(invalid)
    invalid = copy.deepcopy(raw)
    invalid["oidc"]["issuer"] = "http://identity.example"
    with pytest.raises(ValueError):
        validate_egress(GatewayConfig.model_validate(invalid))
