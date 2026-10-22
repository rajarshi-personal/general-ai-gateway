"""OAuth token renewal and secret-safe errors. Author: Rajarshi."""
import asyncio
import base64
import json
from urllib.parse import parse_qs, quote_plus

import httpx
import pytest

from general_ai_gateway.client_credentials import ClientCredentialsTokenProvider, OAuthTokenError


async def test_concurrent_cache_and_renewal():
    calls = []

    def identity(request):
        calls.append(request)
        return httpx.Response(200, json={
            "access_token": f"token-{len(calls)}", "token_type": "Bearer", "expires_in": 60
        })

    async with ClientCredentialsTokenProvider(
        "https://identity.example/token", "client:id", "secret+value",
        audience="gateway", resource="urn:gateway", transport=httpx.MockTransport(identity),
    ) as provider:
        tokens = await asyncio.gather(*[provider.get_token() for _ in range(10)])
        assert tokens == ["token-1"] * 10
        assert len(calls) == 1
        # Simulate reaching the renewal point without slowing the test suite.
        provider._renew_at = 0
        assert await provider.get_token() == "token-2"
        assert len(calls) == 2
        credentials = base64.b64decode(calls[0].headers["authorization"].split()[1]).decode()
        assert credentials == quote_plus("client:id") + ":" + quote_plus("secret+value")
        body = parse_qs(calls[0].content.decode())
        assert body["grant_type"] == ["client_credentials"]
        assert body["audience"] == ["gateway"]
        assert body["resource"] == ["urn:gateway"]


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"error_description": "sensitive credential detail"}),
    httpx.Response(302, headers={"Location": "https://attacker.example"}),
    httpx.Response(200, json={"access_token": "sensitive token", "token_type": "Bearer", "expires_in": 60}),
    httpx.Response(200, json={"access_token": "token", "token_type": "MAC", "expires_in": 60}),
    httpx.Response(200, json={"access_token": "token", "token_type": "Bearer", "expires_in": 0}),
    httpx.Response(200, json={"access_token": "token", "token_type": "Bearer", "expires_in": True}),
    httpx.Response(200, content=json.dumps({"expires_in": float("inf")}).encode()),
    httpx.Response(200, content=b"x" * 65537),
])
async def test_bad_token_responses_are_sanitized(response):
    async with ClientCredentialsTokenProvider(
        "https://identity.example/token", "client", "secret",
        transport=httpx.MockTransport(lambda request: response),
    ) as provider:
        with pytest.raises(OAuthTokenError) as failure:
            await provider.get_token()
        assert "sensitive" not in str(failure.value)


def test_token_endpoint_requires_https():
    with pytest.raises(ValueError):
        ClientCredentialsTokenProvider("http://identity.example/token", "client", "secret")
