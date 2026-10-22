# Security and governance boundaries
Author: Rajarshi

## Threat controls
| Threat | Implemented control | Residual boundary |
|---|---|---|
| Unauthenticated use | OIDC JWT signature/issuer/audience/expiry checks; optional random API keys | TLS and secret distribution are deployment responsibilities |
| Cross-tenant access | Verified OAuth client-ID mapping, scopes, artifact permissions, filtered discovery | No end-user identity federation or tenant-specific upstream credentials |
| Unapproved tool execution | Explicit MCP method/target allowlists | Tool argument semantics and downstream side effects need service controls |
| Data leakage | Input/output email and literal phrase checks | Not comprehensive PII, secrets, malware or semantic DLP |
| Resource abuse | Body/response bounds, request quotas, token ceilings, concurrency | No actual spend accounting; ingress must bound connections/slow bodies |
| SSRF | Exact operator host allowlist, HTTPS default, no redirects, no caller URLs | DNS rebinding needs enforced egress proxy/firewall |
| Config races | Schema validation and atomic revision comparison | Administrators remain trusted; no four-eyes approval |
| Sensitive logging | Metadata only; no prompts, outputs or credentials | Upstream/server infrastructure may log independently |
| Dependency risk | Bounded dependency ranges | Resolve, scan and lock dependencies for production releases |

Content controls inspect JSON string keys and values. They do not decode base64,
inspect images/audio, recognize every Unicode evasion or prove jailbreak safety.
Do not treat literal phrase blocking as a prompt injection detector. Caller-supplied
tool definitions on chat requests are model input, not execution permission. Disable
or mediate tools at the execution service as well.

Upstream HTTP error payloads are not returned. Successful responses must be JSON,
fit configured bounds and pass output policy. Provider-specific successful envelopes
are otherwise trusted; the gateway does not certify their semantic correctness.
No user authentication headers, cookies or MCP session identifiers are forwarded.

Deploy behind TLS ingress with request-body deadlines, connection limits, trusted
proxy settings, and separate network access for /admin and /metrics. Disable public
egress except approved providers. Block metadata/private network ranges except
explicitly required internal services. DNS allowlisting alone cannot prevent
rebinding. TLS termination and firewall controls are not installed by this project.

Redis stores tenant fingerprints, configuration and usage counters; protect with
TLS, ACLs, network isolation, persistence, backups and a tested failover strategy.
The included unauthenticated Redis is local-demo infrastructure only. Production
must use a managed or separately hardened Redis deployment.

Audit logs go to standard output through Python logging. They are not durable,
cryptographically signed or tamper-evident. Forward them to access-controlled,
retention-managed storage. No compliance certification, legal guarantee, complete
model risk framework, fairness evaluator or human-approval system is supplied.

Report vulnerabilities privately to the deployment owner; do not include live
keys or customer prompts in issue reports.

## OAuth token boundaries
[OIDC authentication](OAUTH2.md) supports confidential machine clients using signed
JWT access tokens. Default access-token type checks reject OIDC ID tokens. Generic
JWT profiles require an explicit access-token-only claim guard. The identity
provider must restrict mapped clients to machine grants. The gateway does not
infer the grant type from the client ID alone.

Signing-key fetches use configured HTTPS trust, bounded documents/deadlines and
per-issuer refresh throttling. Cached keys expire; JWT claims are revalidated on
every call. No opaque-token introspection or per-token revocation list is provided.
Removing a tenant client mapping revokes access after config propagation. Client
secret rotation at the IdP does not invalidate existing JWTs. Readiness does not
probe the IdP; monitor authentication 401/403 and availability 503 responses.

Use TLS to the gateway, short access-token lifetimes, dedicated API audiences,
synchronized clocks, application secret management and ingress rate limits.
No bearer token or OAuth client secret is forwarded to model/agent/MCP upstreams.
