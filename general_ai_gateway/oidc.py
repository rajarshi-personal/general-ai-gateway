"""OIDC discovery and JWT access-token validation. Author: Rajarshi.

This is a resource-server verifier, not a token issuer. Client secrets stay at the
identity provider and application. No caller-supplied URL is ever fetched.
"""
import asyncio
import hmac
import json
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import httpx
import jwt
from fastapi import HTTPException

from .config import OIDC, GatewayConfig, validate_oidc_url
from .security import fingerprint

MAX_TOKEN_BYTES = 16384
MAX_METADATA_BYTES = 262144
REFRESH_COOLDOWN = 30


def invalid_token():
    return HTTPException(401, "Valid access token required",
                         headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})


def unavailable():
    return HTTPException(503, "Identity provider keys unavailable",
                         headers={"Retry-After": str(REFRESH_COOLDOWN)})


@dataclass
class KeyCache:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    keys: dict = field(default_factory=dict)
    loaded_at: float = 0
    attempted_at: float = float("-inf")


class Authenticator:
    """Bounded per-process key cache with single-flight refresh per trusted issuer."""
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.caches: OrderedDict[str, KeyCache] = OrderedDict()

    async def document(self, url: str) -> dict:
        validate_oidc_url(url)
        async with asyncio.timeout(5):
            async with self.client.stream("GET", url, timeout=5,
                                          headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise ValueError("Identity provider HTTP failure")
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_METADATA_BYTES:
                        raise ValueError("Identity provider document too large")
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise TypeError("Identity provider object required")
                return data

    @staticmethod
    def parse_keys(document: dict) -> dict:
        values = document.get("keys")
        if not isinstance(values, list) or not 1 <= len(values) <= 100:
            raise ValueError("Invalid JWKS")
        keys = {}
        seen = set()
        for item in values:
            if not isinstance(item, dict):
                continue
            kid = item.get("kid")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
                continue
            if kid in seen:
                raise ValueError("Ambiguous JWKS key ID")
            seen.add(kid)
            if (item.get("use", "sig") != "sig" or "d" in item
                    or ("key_ops" in item and (not isinstance(item["key_ops"], list)
                                               or "verify" not in item["key_ops"]))):
                continue
            for algorithm, key_type in (("RS256", "RSA"), ("PS256", "RSA"), ("ES256", "EC")):
                if item.get("kty") != key_type or item.get("alg", algorithm) != algorithm:
                    continue
                if algorithm == "ES256" and item.get("crv") != "P-256":
                    continue
                try:
                    key = jwt.PyJWK.from_dict(item, algorithm=algorithm).key
                    if key_type == "RSA" and key.key_size < 2048:
                        continue
                    keys[(kid, algorithm)] = key
                except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                    continue
        if not keys:
            raise ValueError("No supported signing keys")
        return keys

    async def signing_key(self, settings: OIDC, kid: str, algorithm: str):
        # Include issuer, not arbitrary token headers, in the cache key. Algorithm
        # policy and audience are rechecked on every request, including cache hits.
        cache = self.caches.get(settings.issuer)
        if cache is None:
            cache = KeyCache()
            self.caches[settings.issuer] = cache
            if len(self.caches) > 8:
                self.caches.popitem(last=False)
        else:
            self.caches.move_to_end(settings.issuer)
        selected = (kid, algorithm)
        if time.monotonic() - cache.loaded_at < settings.jwks_cache_seconds and selected in cache.keys:
            return cache.keys[selected]
        async with cache.lock:
            now = time.monotonic()
            fresh = bool(cache.keys) and now - cache.loaded_at < settings.jwks_cache_seconds
            if fresh and selected in cache.keys:
                return cache.keys[selected]
            if now - cache.attempted_at < REFRESH_COOLDOWN:
                if fresh:
                    raise invalid_token()
                raise unavailable()
            cache.attempted_at = now
            try:
                discovery = await self.document(
                    settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
                )
                if discovery.get("issuer") != settings.issuer:
                    raise ValueError("Discovery issuer mismatch")
                uri = discovery.get("jwks_uri")
                if not isinstance(uri, str):
                    raise TypeError("Missing JWKS URI")
                keys = self.parse_keys(await self.document(uri))
            except (httpx.HTTPError, TimeoutError, ValueError, TypeError, RecursionError):
                # Keep still-fresh keys for other callers; expired keys are never served.
                raise unavailable() from None
            cache.keys = keys
            cache.loaded_at = time.monotonic()
            if selected not in keys:
                raise invalid_token()
            return keys[selected]

    async def claims(self, token: str, settings: OIDC) -> dict:
        try:
            header = jwt.get_unverified_header(token)
            algorithm, kid = header.get("alg"), header.get("kid")
            if (not isinstance(algorithm, str) or algorithm not in settings.algorithms
                    or not isinstance(kid, str) or not 1 <= len(kid) <= 128
                    or header.get("typ") not in settings.accepted_token_types
                    or any(field in header for field in ("jku", "x5u", "jwk", "crit"))):
                raise invalid_token()
        except (jwt.PyJWTError, ValueError, TypeError, RecursionError):
            raise invalid_token() from None
        key = await self.signing_key(settings, kid, algorithm)
        try:
            # Use a raw cryptographic key and an explicit algorithm allowlist.
            claims = jwt.decode(
                token, key=key, algorithms=settings.algorithms,
                audience=settings.audience, issuer=settings.issuer,
                leeway=settings.clock_skew_seconds,
                options={"require": ["iss", "aud", "exp", "iat", "sub", settings.client_id_claim]},
            )
            for field in ("exp", "iat", "nbf"):
                if field in claims and (type(claims[field]) not in (int, float)
                                        or not math.isfinite(claims[field])):
                    raise invalid_token()
            if claims["exp"] <= claims["iat"] or not claims["sub"]:
                raise invalid_token()
            client_id = claims[settings.client_id_claim]
            if not isinstance(client_id, str) or not 1 <= len(client_id) <= 256:
                raise invalid_token()
            if any(claims.get(name) != value for name, value in settings.required_claims.items()):
                raise invalid_token()
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, OverflowError, RecursionError):
            raise invalid_token() from None

    async def authenticate(self, header: str, config: GatewayConfig):
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "Bearer authentication required",
                                headers={"WWW-Authenticate": "Bearer"})
        if len(token) > MAX_TOKEN_BYTES or not token.isascii() or any(char.isspace() for char in token):
            raise invalid_token()
        settings = config.oidc
        if (not settings or settings.allow_api_keys) and len(token) <= 512:
            digest = fingerprint(token)
            for name, tenant in config.tenants.items():
                if tenant.key_sha256 and hmac.compare_digest(digest, tenant.key_sha256):
                    return name, tenant, "api_key"
        if not settings:
            raise invalid_token()
        claims = await self.claims(token, settings)
        client_id = claims[settings.client_id_claim]
        for name, tenant in config.tenants.items():
            if client_id not in tenant.oauth_client_ids:
                continue
            value = claims.get(settings.scope_claim, "")
            if isinstance(value, str):
                scopes = set(value.split())
            elif isinstance(value, list) and all(isinstance(scope, str) for scope in value):
                scopes = set(value)
            else:
                raise invalid_token()
            if not (set(settings.required_scopes) | set(tenant.required_scopes)) <= scopes:
                raise HTTPException(403, "Required OAuth scope missing",
                                    headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'})
            return name, tenant, "oauth2"
        raise HTTPException(403, "OAuth client is not assigned to a tenant")
