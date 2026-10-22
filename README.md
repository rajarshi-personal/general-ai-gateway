# General AI Gateway
**Author: Rajarshi**

[Original source repository](https://github.com/rajarshi-personal/general-ai-gateway)

An asynchronous Python gateway that puts governed access in front of AI models,
HTTP agents, and a restricted set of MCP operations. This is a runnable initial
implementation, not a claim of universal AI governance or regulatory certification.

## Start the offline demonstration
Requires Python 3.12+ and Docker Compose. No model credentials or external AI calls needed.

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\general_ai_gateway init
docker compose up --build -d
```

On Linux/macOS substitute `python3` for `py` and `.venv/bin/` for
`.venv\Scripts\`. Initialization generates unique keys in
`config/demo.env`; never commit that file. Protect it with filesystem ACLs on Windows.

```powershell
$demo = Get-Content config/demo.env | ConvertFrom-StringData
$headers = @{ Authorization = "Bearer " + $demo.GENERAL_AI_GATEWAY_DEMO_KEY }
$body = @{ model = "demo-chat"; messages = @(@{role="user";content="Hello"}) } | ConvertTo-Json -Depth 8
Invoke-RestMethod http://localhost:8080/v1/chat/completions -Method Post -Headers $headers -ContentType application/json -Body $body
```

The demo response is a deterministic fixture, not a real AI model. Gateway listens
only on localhost in Compose. `docker compose down` stops the stack; the Redis
volume retains configuration and quota counters.

## What is implemented
- Chat completions and embeddings routed to OpenAI-compatible JSON HTTP services.
- JSON agent invocation and explicit MCP tool, resource and prompt allowlists.
- OAuth 2.0 client-credentials JWT authentication with OIDC discovery, cached signing keys and scopes.
- Tenant client-ID mapping, optional API-key migration, and per-artifact permissions.
- Application-side access-token acquisition and automatic renewal before expiry.
- Separate administrator secret, validated registry, disabled-artifact kill switch.
- Input and output email/phrase blocking; body and response limits; output-token ceilings.
- Atomic per-tenant minute/day request allowances, shared across replicas with Redis.
- Async HTTP pooling, bounded concurrency per process, deadlines and circuit breakers.
- Compare-and-swap configuration updates; replicas poll Redis every second.
- Structured metadata audit logs, request IDs, Prometheus counters/histograms and health probes.
- Non-root container, offline demo, regression tests and operational documentation.

Streaming is deliberately rejected because complete output inspection occurs before
delivery. Native Anthropic/Gemini formats, full MCP lifecycle, A2A, interactive OIDC login,
approval workflows, semantic jailbreak detection, cost billing and tracing exporters
are not implemented. See [security boundaries](docs/SECURITY.md).

## OAuth application authentication
Follow the [OAuth 2.0 / OIDC guide](docs/OAUTH2.md) to register a confidential
application, configure issuer/audience and tenant client IDs, and obtain access
tokens. The gateway validates JWTs; your identity provider issues them.
[examples/oauth_client.py](examples/oauth_client.py) obtains a client-credentials
token and calls the gateway. Its reusable token provider renews before expiry.
Existing API-key-only configurations remain supported.

## API surface
| Method | Path | Purpose |
|---|---|---|
| POST | /v1/chat/completions | Governed chat |
| POST | /v1/embeddings | Governed embeddings |
| POST | /v1/agents/{id}/invoke | JSON HTTP agent |
| POST | /v1/mcp/{id} | Restricted JSON-RPC bridge |
| GET | /v1/models | Authorized enabled models |
| GET | /v1/artifacts | Authorized enabled registry |
| GET/PUT | /admin/config | Versioned control plane (admin only) |
| GET | /metrics | Prometheus metrics (admin only) |
| GET | /health/live, /health/ready | Container probes |

See [configuration](docs/CONFIGURATION.md), [architecture](docs/ARCHITECTURE.md),
[operations](docs/OPERATIONS.md), [security](docs/SECURITY.md),
and [contributing](CONTRIBUTING.md).

## Run without Docker
Generate the config with `general_ai_gateway init`. Set `GENERAL_AI_GATEWAY_ADMIN_KEY` from the generated env
file and `GENERAL_AI_GATEWAY_ALLOWED_HOSTS` to your upstream DNS names. Edit artifact URLs to
actual HTTPS endpoints and optionally set upstream credential environment variables.
Then run `general_ai_gateway serve`. Configuration defaults to `config/gateway.json`.

Without Redis this is single-process development mode: counters and live updates
are in memory and updates do not survive restarts. For production set
`GENERAL_AI_GATEWAY_REQUIRE_REDIS=true`, `GENERAL_AI_GATEWAY_REDIS_URL` and use the deployment controls
in the operations guide.

## Verify
```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check general_ai_gateway tests examples
```

A Docker-free real HTTP smoke check is available as `python scripts/smoke.py`.
It starts temporary loopback services, verifies all four adapters and live
configuration revocation, and stops the services. Redis Lua tests use an emulator;
production Redis persistence/failover requires deployment integration testing.

No throughput claims are made until measured with your policies, payloads,
upstream latency and deployment environment.

## License and attribution

Copyright (c) 2026, Rajarshi (General AI Gateway). Licensed under
[BSD-3-Clause](LICENSE). Source redistributions must preserve the original
copyright notice, conditions and disclaimer; binary redistributions must
reproduce them in accompanying documentation or distribution materials.
See [NOTICE](NOTICE) for original project attribution.
