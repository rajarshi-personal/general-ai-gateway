"""Strict, versioned control-plane documents. Author: Rajarshi."""
import hashlib
import ipaddress
import json
import os
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

NAME = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$"
ClientID = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[^\s]+$")]
Scope = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9:._/-]+$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Tenant(Strict):
    key_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    oauth_client_ids: list[ClientID] = Field(default_factory=list, max_length=100)
    required_scopes: list[Scope] = Field(default_factory=list, max_length=100)
    artifacts: list[str] = Field(max_length=1000)
    requests_per_minute: int = Field(default=60, ge=1, le=1000000)
    daily_requests: int = Field(default=10000, ge=1, le=100000000)
    max_output_tokens: int = Field(default=2048, ge=1, le=131072)


class Artifact(Strict):
    kind: str = Field(pattern=r"^(chat|embedding|agent|mcp)$")
    url: str = Field(max_length=2048)
    credential_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]*$")
    upstream_model: str | None = Field(default=None, max_length=200)
    enabled: bool = True
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_prompts: list[str] = Field(default_factory=list)
    mcp_version: str = Field(default="2025-06-18", pattern=r"^2025-06-18$")
    timeout_seconds: float = Field(default=30, ge=0.1, le=120)
    max_concurrency: int = Field(default=32, ge=1, le=1000)
    data_region: str = Field(default="unspecified", max_length=80)
    owner: str = Field(default="unassigned", max_length=120)


class Policy(Strict):
    block_email: bool = False
    block_patterns: list[str] = Field(default_factory=list, max_length=100)
    max_body_bytes: int = Field(default=262144, ge=1024, le=1048576)
    max_response_bytes: int = Field(default=2097152, ge=1024, le=16777216)

    @model_validator(mode="after")
    def patterns(self):
        # Literal matching deliberately avoids administrator-supplied regex ReDoS.
        if any(not value or len(value) > 256 for value in self.block_patterns):
            raise ValueError("Blocked phrases must contain 1..256 characters")
        return self



class OIDC(Strict):
    """One trusted issuer; machine identities are explicitly mapped to tenants."""
    issuer: str = Field(min_length=1, max_length=2048)
    audience: str = Field(min_length=1, max_length=256)
    algorithms: list[Literal["RS256", "PS256", "ES256"]] = Field(default_factory=lambda: ["RS256"],
                                                              min_length=1, max_length=3)
    client_id_claim: Literal["client_id", "azp"] = "client_id"
    scope_claim: Literal["scope", "scp"] = "scope"
    required_scopes: list[Scope] = Field(default_factory=lambda: ["gateway:invoke"], max_length=100)
    accepted_token_types: list[Literal["at+jwt", "application/at+jwt", "JWT"]] = Field(
        default_factory=lambda: ["at+jwt", "application/at+jwt"], min_length=1, max_length=3)
    required_claims: dict[str, str] = Field(default_factory=dict, max_length=20)
    allow_api_keys: bool = False
    jwks_cache_seconds: int = Field(default=300, ge=30, le=3600)
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)

    @model_validator(mode="after")
    def access_token_guard(self):
        if "JWT" in self.accepted_token_types and not self.required_claims:
            raise ValueError("Generic JWT types require an access-token-only claim guard")
        if any(not key or len(key) > 128 or not value or len(value) > 256
               for key, value in self.required_claims.items()):
            raise ValueError("Invalid required claim")
        return self


def validate_oidc_url(url: str) -> None:
    """OIDC endpoints have a separate operator allowlist and always require HTTPS."""
    parts = urlsplit(url)
    hosts = {host.strip().lower() for host in
             os.getenv("GENERAL_AI_GATEWAY_OIDC_ALLOWED_HOSTS", "").split(",") if host.strip()}
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.hostname.lower() not in hosts
            or any(ord(char) <= 32 for char in url)):
        raise ValueError("OIDC endpoint must be HTTPS on an explicitly allowed host")
    _ = parts.port  # Reject malformed or out-of-range ports before the first request.
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        address = None
    if address and (address.is_link_local or address.is_unspecified or address.is_multicast):
        raise ValueError("Prohibited OIDC endpoint address")


class GatewayConfig(Strict):
    revision: int = Field(default=1, ge=1)
    oidc: OIDC | None = None
    tenants: dict[str, Tenant]
    artifacts: dict[str, Artifact]
    policy: Policy = Field(default_factory=Policy)

    @model_validator(mode="after")
    def references(self):
        if len(self.tenants) > 10000 or len(self.artifacts) > 1000:
            raise ValueError("Registry too large")
        for name in [*self.tenants, *self.artifacts]:
            if not re.fullmatch(NAME, name):
                raise ValueError("Invalid registry identifier")
        hashes = [tenant.key_sha256 for tenant in self.tenants.values() if tenant.key_sha256]
        if len(hashes) != len(set(hashes)):
            raise ValueError("Tenant keys must be unique")
        clients = [client for tenant in self.tenants.values() for client in tenant.oauth_client_ids]
        if len(clients) != len(set(clients)):
            raise ValueError("OAuth client IDs must map to exactly one tenant")
        for tenant in self.tenants.values():
            if not tenant.key_sha256 and not tenant.oauth_client_ids:
                raise ValueError("Tenant needs an API key or OAuth client mapping")
            if tenant.oauth_client_ids and not self.oidc:
                raise ValueError("OAuth client mappings require OIDC configuration")
            if set(tenant.artifacts) - self.artifacts.keys():
                raise ValueError("Unknown artifact permission")
        return self

    def digest(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def validate_egress(config: GatewayConfig) -> None:
    """Check operator-owned egress trust, separate from hot-reload configuration.

    DNS/IP enforcement must also exist at the network layer to prevent rebinding.
    """
    if config.oidc:
        validate_oidc_url(config.oidc.issuer)
    allowed = set(filter(None, os.getenv("GENERAL_AI_GATEWAY_ALLOWED_HOSTS", "").lower().split(",")))
    insecure = os.getenv("GENERAL_AI_GATEWAY_ALLOW_HTTP", "false").lower() == "true"
    for artifact in config.artifacts.values():
        parts = urlsplit(artifact.url)
        if (parts.scheme not in ({"http", "https"} if insecure else {"https"})
                or not parts.hostname or parts.username or parts.password
                or parts.fragment or parts.query):
            raise ValueError("Invalid upstream URL")
        if parts.hostname.lower() not in allowed:
            raise ValueError("Upstream host is not in GENERAL_AI_GATEWAY_ALLOWED_HOSTS")
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            address = None
        if address and (address.is_link_local or address.is_unspecified or address.is_multicast):
            raise ValueError("Prohibited upstream address")
        if artifact.credential_env and not os.getenv(artifact.credential_env):
            raise ValueError("Upstream credential environment variable is missing")


def parse_config(raw: str) -> GatewayConfig:
    config = GatewayConfig.model_validate(json.loads(raw))
    validate_egress(config)
    return config
