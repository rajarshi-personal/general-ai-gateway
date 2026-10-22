# Operations and scaling
Author: Rajarshi

## Production rollout
1. Build an immutable container; resolve and lock Python dependencies, scan the
   resulting image and pin image digests for your release process.
2. Provision authenticated TLS Redis with AOF/backups and restricted network access.
3. Supply administrator and upstream credentials through your secret manager.
4. Supply a validated seed configuration and exact egress host allowlist.
5. Run one gateway process per container behind TLS ingress. Set
   GENERAL_AI_GATEWAY_REQUIRE_REDIS=true and a rediss:// Redis URL.
6. Expose /health/live for liveness and /health/ready for readiness. Protect
   /admin/* and /metrics with network controls in addition to the administrator key.
7. Scale replicas using CPU, latency and admission rejection metrics; cap maximum
   replicas to respect upstream concurrency budgets.
8. Use rolling deployments with zero unavailable replicas, readiness gates and
   termination grace longer than the largest 120-second request deadline.
9. Enforce ingress body deadlines and connection limits. Apply egress network
   policy using a trusted egress proxy or CNI that enforces destination restrictions.

The Compose stack is a local demonstration, not an HA production installation.
The application supports multiple replicas through Redis, but an orchestrator and
autoscaling policies must be provisioned by the operator. Standard Redis/Sentinel/
cluster deployment integration must be tested for your selected endpoint; the
application uses a single Redis endpoint, not Redis Cluster discovery.

## Monitoring
Scrape /metrics with an administrator bearer secret from a protected Prometheus
instance. Metrics: general_ai_gateway_requests_total{route,status} and
general_ai_gateway_request_seconds. Labels contain route templates rather than user paths,
keys or prompts. Single-process metrics are per replica: scrape each replica
separately, then aggregate. Do not run multiple Uvicorn workers expecting one
process's /metrics to include every worker.

Suggested alerts: elevated 5xx, elevated 429, readiness failures, p95/p99 latency,
config_sync_failed audit events, Redis latency and upstream saturation.
429 is fixed-window admission rejection; Retry-After is advisory and may require
waiting until UTC day rollover for daily allowance exhaustion.

Audit events include request ID, matched route, tenant/artifact identifiers,
revision, duration and status. Configuration changes add a document digest.
A malformed/oversized body rejected by the outer hard limit may not reach audit
middleware; collect ingress access logs too. Telemetry export itself is synchronous
logging; use an external stdout collector and benchmark logging overhead.

## Failure and recovery
- Redis unavailable: admission fails closed. Readiness becomes unhealthy after
  the ten-second freshness bound; recovery resumes polling automatically.
- Invalid shared configuration: retain last valid snapshot, emit sync failure,
  and fail closed after the freshness bound.
- Upstream failures: return sanitized 502; after three counted failures, local
  circuit rejects for 15 seconds. No side-effecting request is retried.
- Deployment rollback: use the previous image and a compatible versioned config.
- Configuration rollback: GET current revision and PUT previous content at +1.
- Emergency revocation: disable artifact or remove tenant permission, allowing
  the polling convergence interval and already admitted calls to finish.

Back up Redis and export /admin/config to encrypted storage. Seed files only
initialize an empty Redis key. A restart does not reset persisted configuration.
Single-process memory mode loses pushed changes on restart.

## Performance validation
Run load generation from another host against deterministic local HTTP fixtures,
then real providers. Measure p50/p95/p99, gateway-added latency, CPU, RSS, errors,
Redis latency and connection counts at representative body/output sizes. Include
quota saturation, Redis loss, config churn and upstream timeouts. Select concurrency
and replica limits from the measurements; this release has no published throughput
benchmark. Buffered JSON is intentionally a latency/memory tradeoff for output DLP.

## Identity provider operations
Configure GENERAL_AI_GATEWAY_OIDC_ALLOWED_HOSTS on all replicas before enabling
OIDC. See [OAuth operations and renewal](OAUTH2.md). Discovery/JWKS are cached per
replica for the configured TTL (300 seconds by default). Unknown-key refreshes
have a 30-second cooldown; publish new keys in advance and rotate with new kids.
After TTL expiry, an unavailable IdP causes OAuth calls to fail closed with 503.
Still-fresh keys continue validating tokens during an outage. Identity-provider
availability is independent of the configuration readiness probe.

Alert on increased authentication 401/403 and identity-key 503 responses. Audit
records include auth_method without tokens or client secrets. Authenticate
Prometheus and administrators with their existing administrator credential.
