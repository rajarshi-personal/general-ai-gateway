"""General AI Gateway data and control planes. Author: Rajarshi.

Requests retain one validated configuration snapshot. Updates swap the snapshot
atomically; in-flight calls finish under the revision at admission.
"""
import asyncio
import contextlib
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from pydantic import ValidationError
from redis.exceptions import RedisError

from .config import GatewayConfig, validate_egress
from .oidc import Authenticator
from .security import decode_json, inspect
from .state import State

log = logging.getLogger("general_ai_gateway.audit")


@dataclass
class Breaker:
    failures: int = 0
    until: float = 0


class BodyLimit:
    """Bound chunked as well as Content-Length bodies before JSON allocation."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        # Hard ceiling also bounds control-plane document size.
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > 1048576:
                return await JSONResponse({"detail": "Body too large"}, status_code=413)(scope, receive, send)
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(config_path: str | None = None, transport=None) -> FastAPI:
    state = State(config_path or os.getenv("GENERAL_AI_GATEWAY_CONFIG", "config/gateway.json"),
                  os.getenv("GENERAL_AI_GATEWAY_REDIS_URL"))
    registry = CollectorRegistry()
    requests = Counter("general_ai_gateway_requests_total", "Completed HTTP requests",
                       ["route", "status"], registry=registry)
    latency = Histogram("general_ai_gateway_request_seconds", "HTTP latency",
                        ["route"], registry=registry)
    breakers: dict[str, Breaker] = {}
    active: dict[str, int] = {}
    client = None
    authenticator = None
    admin_key = os.getenv("GENERAL_AI_GATEWAY_ADMIN_KEY", "")
    if len(admin_key) < 32:
        raise RuntimeError("Set GENERAL_AI_GATEWAY_ADMIN_KEY to a random secret of at least 32 characters")
    if os.getenv("GENERAL_AI_GATEWAY_REQUIRE_REDIS", "false").lower() == "true" and not state.redis:
        raise RuntimeError("Production mode requires Redis")

    async def watcher():
        while True:
            await asyncio.sleep(1)
            try:
                await state.sync()
            except (RedisError, ValueError, TypeError, OSError):
                log.error('{"event":"config_sync_failed"}')

    @asynccontextmanager
    async def lifespan(app):
        nonlocal client, authenticator
        await state.start()
        client = httpx.AsyncClient(
            transport=transport, follow_redirects=False, trust_env=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
        authenticator = Authenticator(client)
        app.state.authenticator = authenticator
        task = asyncio.create_task(watcher())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await client.aclose()
            await state.close()

    app = FastAPI(title="General AI Gateway", version="0.1.0",
                  description="Author: Rajarshi. Governed AI service access.",
                  lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.control = state
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def observe(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = request.state.request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Cache-Control"] = "no-store"
            if hasattr(request.state, "revision"):
                response.headers["X-General-AI-Gateway-Revision"] = str(request.state.revision)
            return response
        finally:
            route = getattr(request.scope.get("route"), "path", "unmatched")
            elapsed = time.perf_counter() - start
            requests.labels(route, str(status)).inc()
            latency.labels(route).observe(elapsed)
            log.info(json.dumps({
                "event": "request", "request_id": request.state.request_id,
                "route": route, "status": status, "duration_ms": round(elapsed * 1000, 2),
                "tenant": getattr(request.state, "tenant", None),
                "auth_method": getattr(request.state, "auth_method", None),
                "artifact": getattr(request.state, "artifact", None),
                "revision": getattr(request.state, "revision", None),
            }))

    def admin(request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), ("Bearer " + admin_key).encode()):
            raise HTTPException(401, "Administrator authentication required")

    def snapshot():
        if not state.config or not state.fresh():
            raise HTTPException(503, "Configuration unavailable or stale")
        return state.config

    @app.get("/health/live")
    async def live():
        return {"status": "alive"}

    @app.get("/health/ready")
    async def ready():
        config = snapshot()
        return {"status": "ready", "revision": config.revision}

    @app.get("/metrics")
    async def metrics(request: Request):
        admin(request)
        return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")

    @app.get("/admin/config")
    async def get_config(request: Request):
        admin(request)
        config = snapshot()
        return JSONResponse(config.model_dump(), headers={"ETag": str(config.revision)})

    @app.put("/admin/config")
    async def put_config(request: Request):
        admin(request)
        try:
            expected = int(request.headers.get("if-match", ""))
        except ValueError:
            raise HTTPException(428, "If-Match revision required") from None
        try:
            candidate = GatewayConfig.model_validate(decode_json(await request.body()))
            validate_egress(candidate)
        except (ValidationError, ValueError):
            raise HTTPException(422, "Invalid configuration; verify schema, references and egress") from None
        try:
            replaced = await state.replace(expected, candidate)
        except RedisError:
            raise HTTPException(503, "Control store unavailable") from None
        if not replaced:
            raise HTTPException(409, "Revision conflict; read current configuration and retry")
        log.info(json.dumps({"event": "config_updated", "revision": candidate.revision,
                             "digest": candidate.digest(), "request_id": request.state.request_id}))
        return {"revision": candidate.revision, "digest": candidate.digest()}

    async def identity(request):
        config = snapshot()
        name, tenant, method = await authenticator.authenticate(request.headers.get("authorization", ""), config)
        request.state.auth_method = method
        request.state.tenant, request.state.revision = name, config.revision
        return config, name, tenant

    @app.get("/v1/artifacts")
    async def artifacts(request: Request):
        config, _, tenant = await identity(request)
        return {"data": [
            {"id": name, "kind": item.kind, "owner": item.owner, "data_region": item.data_region}
            for name, item in config.artifacts.items() if name in tenant.artifacts and item.enabled
        ]}

    @app.get("/v1/models")
    async def models(request: Request):
        config, _, tenant = await identity(request)
        return {"object": "list", "data": [
            {"id": name, "object": "model", "owned_by": item.owner}
            for name, item in config.artifacts.items()
            if name in tenant.artifacts and item.enabled and item.kind in {"chat", "embedding"}
        ]}

    async def forward(request: Request, kind: str, artifact_id: str | None = None):
        config, tenant_id, tenant = await identity(request)
        raw = await request.body()
        if len(raw) > config.policy.max_body_bytes:
            raise HTTPException(413, "Body too large")
        body = decode_json(raw)
        if not isinstance(body, dict):
            raise HTTPException(422, "JSON object required")
        if artifact_id is None:
            artifact_id = body.get("model")
        if not isinstance(artifact_id, str) or artifact_id not in tenant.artifacts:
            raise HTTPException(403, "Artifact access denied")
        artifact = config.artifacts[artifact_id]
        request.state.artifact = artifact_id
        if not artifact.enabled or artifact.kind != kind:
            raise HTTPException(403, "Artifact disabled or incompatible")
        inspect(body, config.policy)
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "X-Request-ID": request.state.request_id}
        if artifact.credential_env:
            secret = os.getenv(artifact.credential_env)
            if not secret:
                raise HTTPException(503, "Upstream credential unavailable")
            headers["Authorization"] = "Bearer " + secret
        if kind in {"chat", "embedding"}:
            body["model"] = artifact.upstream_model or artifact_id
            if body.get("stream"):
                raise HTTPException(422, "Streaming is disabled to enforce output inspection")
            if kind == "chat":
                # One choice prevents n-way token-budget multiplication.
                if body.get("n", 1) != 1:
                    raise HTTPException(422, "Only one completion is allowed")
                if not isinstance(body.get("messages"), list) or not body["messages"]:
                    raise HTTPException(422, "Nonempty messages required")
                for field in ("max_tokens", "max_completion_tokens"):
                    if field in body and (type(body[field]) is not int or
                                          not 1 <= body[field] <= tenant.max_output_tokens):
                        raise HTTPException(422, "Output token allowance exceeded")
                if "max_tokens" not in body and "max_completion_tokens" not in body:
                    body["max_tokens"] = tenant.max_output_tokens
            elif "input" not in body:
                raise HTTPException(422, "Embedding input required")
        if kind == "mcp":
            method = body.get("method")
            params = body.get("params", {})
            if body.get("jsonrpc") != "2.0" or not isinstance(params, dict):
                raise HTTPException(422, "JSON-RPC 2.0 object required")
            # Restricted JSON bridge: no opaque sessions, SSE, batches or discovery bypass.
            target = None
            if method == "tools/call":
                target = params.get("name")
                permitted = artifact.allowed_tools
            elif method == "resources/read":
                target = params.get("uri")
                permitted = artifact.allowed_resources
            elif method == "prompts/get":
                target = params.get("name")
                permitted = artifact.allowed_prompts
            else:
                raise HTTPException(403, "MCP method not enabled by this bridge")
            if not isinstance(target, str) or target not in permitted:
                raise HTTPException(403, "MCP target access denied")
            if "id" not in body or type(body["id"]) not in (str, int):
                raise HTTPException(422, "MCP request id required")
            headers["MCP-Protocol-Version"] = artifact.mcp_version
        try:
            allowed = await state.admit(tenant_id, tenant.requests_per_minute, tenant.daily_requests)
        except RedisError:
            raise HTTPException(503, "Admission store unavailable") from None
        if not allowed:
            raise HTTPException(429, "Request allowance exceeded", headers={"Retry-After": "60"})
        # Stable bounded keys survive live reloads without leaking semaphores.
        key = artifact_id
        breaker = breakers.setdefault(key, Breaker())
        if breaker.until > time.monotonic():
            raise HTTPException(503, "Upstream circuit is open", headers={"Retry-After": "15"})
        if active.get(key, 0) >= artifact.max_concurrency:
            raise HTTPException(503, "Upstream concurrency limit reached", headers={"Retry-After": "1"})
        active[key] = active.get(key, 0) + 1
        try:
            # Total timeout bounds slow trickle responses, beyond httpx per-read timeout.
            async with asyncio.timeout(artifact.timeout_seconds):
                async with client.stream("POST", artifact.url, json=body, headers=headers,
                                         timeout=artifact.timeout_seconds) as upstream:
                    if upstream.status_code >= 500 or upstream.status_code == 429:
                        raise httpx.TransportError("Upstream unavailable")
                    if not 200 <= upstream.status_code < 300:
                        raise HTTPException(502, "Upstream rejected request")
                    if "application/json" not in upstream.headers.get("content-type", ""):
                        raise HTTPException(502, "JSON upstream response required")
                    content = bytearray()
                    async for chunk in upstream.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > config.policy.max_response_bytes:
                            raise HTTPException(502, "Upstream response too large")
                    try:
                        result = decode_json(bytes(content))
                    except HTTPException:
                        raise HTTPException(502, "Invalid upstream JSON") from None
                    inspect(result, config.policy)
                    breaker.failures, breaker.until = 0, 0
                    return JSONResponse(result)
        except (httpx.HTTPError, TimeoutError):
            breaker.failures += 1
            if breaker.failures >= 3:
                breaker.until = time.monotonic() + 15
            raise HTTPException(502, "Upstream unavailable") from None
        finally:
            active[key] -= 1
            # Remove retired idle artifacts from local bookkeeping.
            if key not in state.config.artifacts and active[key] == 0:
                active.pop(key, None)
                breakers.pop(key, None)

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        return await forward(request, "chat")

    @app.post("/v1/embeddings")
    async def embedding(request: Request):
        return await forward(request, "embedding")

    @app.post("/v1/agents/{artifact_id}/invoke")
    async def agent(artifact_id: str, request: Request):
        return await forward(request, "agent", artifact_id)

    @app.post("/v1/mcp/{artifact_id}")
    async def mcp(artifact_id: str, request: Request):
        return await forward(request, "mcp", artifact_id)

    return app
