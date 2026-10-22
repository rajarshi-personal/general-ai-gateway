# OAuth 2.0 client credentials with OIDC discovery
Author: Rajarshi

General AI Gateway now accepts signed JWT access tokens from one configured OIDC
issuer. Applications authenticate to that identity provider with a client ID and
client secret. The gateway discovers the provider's public signing keys, validates
the bearer token, and maps the verified client ID to a configured tenant.

The gateway is a resource server. It does not issue tokens, store OAuth client
secrets, or expose a /token endpoint. Client credentials is a machine-to-machine
OAuth grant; browser login and OIDC ID tokens are not used.

## 1. Register the application at your identity provider
Create a confidential application/service account and enable the client_credentials
grant. Disable interactive grants for mapped machine clients. Obtain its client ID,
secret, issuer URL and HTTPS token endpoint through your provider's administrator.

Configure a dedicated API audience such as general-ai-gateway and issue signed JWT
access tokens with that audience. Grant the application the gateway:invoke scope.
Keep secrets in the calling application's secret manager. The gateway needs only
public discovery/JWKS endpoints.

The default accepted token profile requires:
- Header: alg=RS256, a kid, and typ=at+jwt or application/at+jwt.
- Claims: exact iss, gateway aud (string or audience array), exp, iat, nonempty sub,
  and a string client_id.
- scope includes gateway:invoke, plus any configured tenant required_scopes.

PS256 and ES256 can be explicitly enabled in algorithms. RSA keys must be at least
2048 bits; ES256 keys must use P-256. Symmetric, unsigned, encrypted and opaque
tokens are unsupported.

Client-credentials issuance is an identity-provider policy. There is no universal
JWT claim proving which grant created a token. Configure required_claims if your
provider supplies a reliable grant/service-account indicator, and do not enable
user grants for client IDs mapped here.

## 2. Configure gateway trust and tenant mapping
Install the new dependency:
```powershell
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

Set the exact discovery/JWKS host allowlist on every gateway replica:
```powershell
$env:GENERAL_AI_GATEWAY_OIDC_ALLOWED_HOSTS = "identity.example"
```

If JWKS uses a different host, include it too, comma-separated. OIDC requests always
require HTTPS, even when GENERAL_AI_GATEWAY_ALLOW_HTTP is true for demo upstreams.
Redirects, URL credentials and token-supplied key URLs are rejected. Enforce egress
network policy as well; host validation alone cannot prevent DNS rebinding.

Add this top-level field to your existing gateway configuration:
```json
{
  "oidc": {
    "issuer": "https://identity.example/realms/gateway",
    "audience": "general-ai-gateway",
    "algorithms": ["RS256"],
    "client_id_claim": "client_id",
    "scope_claim": "scope",
    "required_scopes": ["gateway:invoke"],
    "accepted_token_types": ["at+jwt", "application/at+jwt"],
    "required_claims": {},
    "allow_api_keys": false,
    "jwks_cache_seconds": 300,
    "clock_skew_seconds": 30
  }
}
```

The issuer is an exact match including any trailing slash. Discovery is fetched
from issuer-without-trailing-slash + /.well-known/openid-configuration.
Discovery's issuer must match; jwks_uri must be an allowed HTTPS endpoint.

For each tenant, add its application client IDs:
```json
{
  "oauth_client_ids": ["my-service-client"],
  "artifacts": ["production-chat"],
  "requests_per_minute": 120,
  "daily_requests": 10000,
  "required_scopes": []
}
```
This is a tenant object fragment: retain your existing tenant ID and permitted
artifact IDs. key_sha256 is optional for OAuth-only tenants. A client ID can map
to only one tenant; multiple client IDs can share a tenant and its quotas.
The token cannot select a tenant using a caller-supplied tenant claim.

Publish through PUT /admin/config with If-Match and revision+1, as documented in
[configuration](CONFIGURATION.md). Environment allowlist changes require a rolling
restart; issuer, audience, algorithms, scopes and tenant mappings are live.
Existing configurations without oidc keep API-key authentication. When oidc is
present, API keys are disabled unless allow_api_keys is explicitly true.
Remove the key fingerprint after migration if it is no longer needed.

A complete illustrative document is [oidc.gateway.json](../examples/oidc.gateway.json).
Replace its placeholder hosts/client IDs and supply the upstream credential before use.

## 3. Obtain an access token
This example uses client_secret_basic. Load OAUTH_CLIENT_SECRET from your secret
manager into the process environment; do not commit it or put it in gateway config.
The endpoint, client ID and scope are application-side settings.

```powershell
$env:OAUTH_TOKEN_ENDPOINT = "https://identity.example/realms/gateway/protocol/openid-connect/token"
$env:OAUTH_CLIENT_ID = "my-service-client"
$env:OAUTH_SCOPE = "gateway:invoke"
$env:GATEWAY_URL = "https://gateway.example"
# OAUTH_CLIENT_SECRET must already be supplied securely.
.\.venv\Scripts\python examples/oauth_client.py
```

The example sends a form-encoded grant_type=client_credentials request to the
configured token endpoint, authenticates with HTTP Basic, then calls /v1/models
with Authorization: Bearer <access_token>. It prints model results, never the token.
Optional OAUTH_AUDIENCE or OAUTH_RESOURCE variables add the provider's supported
audience/resource token-request parameter. Set these only when your provider requires
them; requesting a scope alone does not necessarily configure the token audience.

## 4. Automatically renew before expiry
Reuse ClientCredentialsTokenProvider in your application's lifetime:
```python
from general_ai_gateway.client_credentials import ClientCredentialsTokenProvider

async with ClientCredentialsTokenProvider(
    token_endpoint, client_id, client_secret, scope="gateway:invoke"
) as tokens:
    bearer = await tokens.get_token()
    # Later calls reuse the cached token, then obtain a new one before expiry.
```

The helper uses expires_in and a monotonic clock. It renews at 90% of the lifetime,
or 30 seconds before expiry, whichever is later. Concurrent callers share one
acquisition request. Client-credentials renewal repeats the original grant using
the client secret; it does not use a refresh token. The helper does not retry
model/agent/tool invocations because those may have side effects.

## Provider-specific JWT profiles
Some providers use typ=JWT rather than an access-token-specific header, and azp
rather than client_id. To support these, explicitly configure:
```json
{
  "client_id_claim": "azp",
  "accepted_token_types": ["JWT"],
  "required_claims": {"typ": "Bearer"}
}
```
This example requires a *payload* typ claim equal to Bearer; use it only if your
provider actually emits that claim exclusively on access tokens. Another provider
might expose a different access-token-only discriminator. Generic JWT acceptance
without a required claim guard is rejected by config validation. Use a dedicated
API audience and verify provider behavior. The configuration is not a promise of
out-of-the-box compatibility with every provider.

Set scope_claim=scp if your provider puts scopes there. Both space-separated
strings and arrays of strings are supported. Global and tenant scopes are combined;
artifact permissions still apply separately.

## Failures, rotation and revocation
| Status | Meaning |
|---|---|
| 401 + WWW-Authenticate | Missing, malformed, expired, incorrectly signed or otherwise invalid token |
| 403 | Valid identity without a tenant mapping, required scope or artifact permission |
| 503 | Discovery/JWKS unavailable and no usable fresh cached key |

Claims are validated on every call. Expiration and not-before checks allow the
configured skew (30 seconds by default). Cached public keys are reused for up to
jwks_cache_seconds, never beyond that TTL during an outage. Discovery/key fetches
have deadlines and bounded response sizes. OIDC is initialized lazily; /health/ready
reports configuration readiness, not identity-provider availability.

Unknown key IDs can trigger at most one refresh per issuer per process every 30
seconds. A key published immediately after a cache load may therefore take up to
30 seconds to become usable. Publish new public keys before issuing tokens signed
with them, and retain old keys until their tokens expire. Key sets replace
atomically; concurrent callers share one refresh. Same-kid key replacement waits
for cache expiry: rotate with a new kid.

Removing a client mapping revokes its gateway access after configuration propagation.
Already admitted requests retain their original configuration snapshot. Disabling
a client or rotating its secret at the identity provider prevents new issuance;
already issued JWTs remain valid until expiration unless the gateway mapping is
removed. No per-token introspection, denylist or immediate IdP revocation push is
implemented. Keep access-token lifetimes short.

Admin/config and metrics retain the separate administrator secret; an OAuth tenant
token cannot access them. Incoming JWTs, client secrets and token endpoint bodies
are not logged or forwarded upstream. Audit logs record auth_method=oauth2 or api_key.

## References
The renewal flow follows [OAuth 2.0 client credentials, RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4).
The strict access-token type and audience checks follow the security guidance in
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html); this implementation is not a
complete RFC 9068 conformance claim.
