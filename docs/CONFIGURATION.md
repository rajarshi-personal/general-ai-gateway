# Configuration
Author: Rajarshi

JSON schema is enforced by Pydantic in `general_ai_gateway/config.py`; unknown fields are
rejected. Export a machine-readable schema with
`python -c "import json; from general_ai_gateway.config import GatewayConfig; print(json.dumps(GatewayConfig.model_json_schema(), indent=2))"`.

## Real model registration
Add a tenant permission and an artifact, for example:
```json
{
  "kind": "chat",
  "url": "https://models.example.com/v1/chat/completions",
  "credential_env": "MODEL_SERVICE_KEY",
  "upstream_model": "your-deployed-model",
  "max_concurrency": 32,
  "timeout_seconds": 30,
  "owner": "AI platform",
  "data_region": "your-provider-region"
}
```
Set `GENERAL_AI_GATEWAY_ALLOWED_HOSTS=models.example.com` and `MODEL_SERVICE_KEY` on every
replica. Use the registry artifact ID in the client's `model` field.
URLs are exact endpoints, not base URLs. No caller-supplied destinations are used.
Region/owner are inventory metadata, not automatic residency enforcement.

## Live changes without a restart
1. GET `/admin/config` using the administrator bearer key; retain its revision.
2. Edit the JSON and increment `revision` by exactly one.
3. PUT the full document to `/admin/config` with `If-Match: <old revision>`.
4. A 409 means another administrator won the race; read again and merge.

PowerShell:
```powershell
$secrets = Get-Content config/demo.env | ConvertFrom-StringData
$admin = @{Authorization="Bearer " + $secrets.GENERAL_AI_GATEWAY_ADMIN_KEY}
$cfg = Invoke-RestMethod http://localhost:8080/admin/config -Headers $admin
$old = $cfg.revision
$cfg.revision++
$cfg.tenants.demo.requests_per_minute = 120
$admin["If-Match"] = "$old"
Invoke-RestMethod http://localhost:8080/admin/config -Method Put -Headers $admin -ContentType application/json -Body ($cfg | ConvertTo-Json -Depth 30)
```

Redis is authoritative once initialized; subsequent edits to the seed file do not
replace Redis. The updater applies immediately; other replicas poll every second.
In-flight calls complete under their admission revision. Revocation is eventually
consistent, not an instantaneous global cancellation. Roll back by submitting
old content with a new revision. If Redis synchronization fails for ten seconds,
new data-plane requests and readiness fail closed; quota admission fails immediately
when Redis is unavailable.

Changes to API keys, permissions, content policy, routing, concurrency and timeouts
are live. Process environment (egress trust, Redis endpoint, admin/upstream secrets)
requires a rolling restart. Each replica must have the required upstream secret
before a configuration using it is published. Key rotation currently permits one
fingerprint per tenant; use a coordinated cutover.

## Environment
| Variable | Meaning |
|---|---|
| GENERAL_AI_GATEWAY_CONFIG | Seed JSON path (default config/gateway.json) |
| GENERAL_AI_GATEWAY_ADMIN_KEY | Required random admin secret, at least 32 characters |
| GENERAL_AI_GATEWAY_ALLOWED_HOSTS | Exact comma-separated lowercase upstream hosts |
| GENERAL_AI_GATEWAY_ALLOW_HTTP | Development-only HTTP permission; default false |
| GENERAL_AI_GATEWAY_REDIS_URL | Shared Redis endpoint; use rediss:// with TLS in production |
| GENERAL_AI_GATEWAY_REQUIRE_REDIS | Reject process startup without Redis when true |

Use separate Redis instances/databases per deployment. Prefix is `general_ai_gateway:`.
The configuration GET includes key fingerprints; restrict control-plane access.
Tenant keys are random bearer credentials; SHA-256 is appropriate for their high
entropy, not for human passwords.

## OAuth 2.0 / OIDC
See [OAuth setup and token renewal](OAUTH2.md). The optional top-level oidc
configuration enables JWT bearer validation. Tenants map oauth_client_ids to their
existing permissions and quotas; key_sha256 becomes optional. Client IDs must be
unique across tenants. An OIDC configuration disables API keys by default;
allow_api_keys=true is an explicit migration option. API keys do not carry scopes.

GENERAL_AI_GATEWAY_OIDC_ALLOWED_HOSTS is a separate, exact host allowlist for HTTPS
discovery/JWKS fetching. Set it on every replica before publishing an OIDC config.
Client secrets belong in calling applications and the identity provider, never
in gateway configuration. OAuth tokens do not grant administrator access.
