"""Application-side OAuth client-credentials token acquisition. Author: Rajarshi.

Use this helper in a calling application, not inside the gateway data plane.
Credentials and access tokens stay in memory and are never logged.
"""
import asyncio
import base64
import json
import math
import time
from urllib.parse import quote_plus, urlsplit

import httpx


class OAuthTokenError(RuntimeError):
    """Sanitized token acquisition failure; never includes an IdP response body."""


class ClientCredentialsTokenProvider:
    """Cache access tokens and acquire a new one shortly before expiry.

    No refresh token is used. Concurrent callers share one token request.
    This helper never retries a gateway/model/tool request.
    """
    def __init__(self, token_endpoint: str, client_id: str, client_secret: str,
                 scope: str = "gateway:invoke", audience: str | None = None,
                 resource: str | None = None, *, transport=None):
        parts = urlsplit(token_endpoint)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.fragment or parts.query or any(ord(char) <= 32 for char in token_endpoint)):
            raise ValueError("Token endpoint must be an HTTPS URL without credentials or query")
        _ = parts.port
        if not client_id or not client_secret:
            raise ValueError("Client ID and secret are required")
        self._endpoint = token_endpoint
        credentials = quote_plus(client_id) + ":" + quote_plus(client_secret)
        self._authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        self._body = {"grant_type": "client_credentials", "scope": scope}
        if audience:
            self._body["audience"] = audience
        if resource:
            self._body["resource"] = resource
        self._client = httpx.AsyncClient(transport=transport, trust_env=False,
                                        follow_redirects=False, timeout=10)
        self._lock = asyncio.Lock()
        self._access_token = ""
        self._renew_at = 0.0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    async def aclose(self):
        await self._client.aclose()
        self._access_token = ""
        self._authorization = ""

    async def get_token(self) -> str:
        if self._access_token and time.monotonic() < self._renew_at:
            return self._access_token
        async with self._lock:
            if self._access_token and time.monotonic() < self._renew_at:
                return self._access_token
            started = time.monotonic()
            try:
                async with asyncio.timeout(10):
                    async with self._client.stream(
                        "POST", self._endpoint, data=self._body,
                        headers={"Authorization": self._authorization, "Accept": "application/json"},
                    ) as response:
                        if response.status_code != 200:
                            raise OAuthTokenError("Identity provider rejected token request")
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > 65536:
                                raise OAuthTokenError("Identity provider token response too large")
                        document = json.loads(content)
                if not isinstance(document, dict):
                    raise OAuthTokenError("Invalid token response")
                access_token = document.get("access_token")
                lifetime = document.get("expires_in")
                if (not isinstance(access_token, str) or not 1 <= len(access_token) <= 16384
                        or not access_token.isascii() or any(char.isspace() for char in access_token)
                        or str(document.get("token_type", "")).lower() != "bearer"
                        or type(lifetime) not in (int, float) or not math.isfinite(lifetime)
                        or lifetime <= 0):
                    raise OAuthTokenError("Invalid token response")
                renew_at = started + lifetime - min(30, lifetime * 0.1)
                if time.monotonic() >= renew_at:
                    raise OAuthTokenError("Token lifetime too short for acquisition latency")
                self._access_token, self._renew_at = access_token, renew_at
                return access_token
            except (httpx.HTTPError, TimeoutError, ValueError, TypeError, OverflowError, RecursionError):
                raise OAuthTokenError("Unable to obtain access token") from None
