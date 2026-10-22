"""Real HTTP smoke test using local fixtures. Author: Rajarshi.

Run: python scripts/smoke.py
Creates only temporary configuration and starts two loopback subprocesses.
No model provider credentials or Docker are needed.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    root = Path(__file__).resolve().parents[1]
    scratch = root / ".verification"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as temp:
        folder = Path(temp)
        assert folder.resolve().is_relative_to(scratch.resolve())
        subprocess.run([sys.executable, "-m", "general_ai_gateway.cli", "init",
                        "--directory", str(folder)], check=True, cwd=root)
        env = os.environ.copy()
        for line in (folder / "demo.env").read_text().splitlines():
            key, value = line.split("=", 1)
            env[key] = value
        mock_port, gateway_port = free_port(), free_port()
        config = json.loads((folder / "gateway.json").read_text())
        for artifact in config["artifacts"].values():
            artifact["url"] = artifact["url"].replace("mock:9000", f"127.0.0.1:{mock_port}")
        (folder / "gateway.json").write_text(json.dumps(config))
        env.update({
            "GENERAL_AI_GATEWAY_CONFIG": str(folder / "gateway.json"),
            "GENERAL_AI_GATEWAY_ALLOWED_HOSTS": "127.0.0.1",
            "GENERAL_AI_GATEWAY_ALLOW_HTTP": "true",
            "GENERAL_AI_GATEWAY_REQUIRE_REDIS": "false",
        })
        env.pop("GENERAL_AI_GATEWAY_REDIS_URL", None)
        children = []
        with open(os.devnull, "w") as output:
            try:
                for args in [
                    ["-m", "uvicorn", "examples.mock:app", "--host", "127.0.0.1", "--port", str(mock_port)],
                    ["-m", "general_ai_gateway.cli", "serve", "--port", str(gateway_port)],
                ]:
                    children.append(subprocess.Popen(
                        [sys.executable, *args], env=env, cwd=root, stdout=output, stderr=output,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    ))
                with httpx.Client(base_url=f"http://127.0.0.1:{gateway_port}", timeout=5,
                                  trust_env=False) as client:
                    for _ in range(100):
                        try:
                            if client.get("/health/ready").status_code == 200:
                                upstream = httpx.get(f"http://127.0.0.1:{mock_port}/openapi.json",
                                                     timeout=1, trust_env=False)
                                if upstream.status_code == 200:
                                    break
                        except httpx.HTTPError:
                            pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("Local servers did not become ready")
                    auth = {"Authorization": "Bearer " + env["GENERAL_AI_GATEWAY_DEMO_KEY"]}
                    checks = [
                        ("/v1/chat/completions", {"model": "demo-chat",
                          "messages": [{"role": "user", "content": "hello"}]}),
                        ("/v1/embeddings", {"model": "demo-embedding", "input": "hello"}),
                        ("/v1/agents/demo-agent/invoke", {"task": "hello"}),
                        ("/v1/mcp/demo-mcp", {"jsonrpc": "2.0", "id": 1,
                          "method": "tools/call", "params": {"name": "echo", "arguments": {}}}),
                    ]
                    for endpoint, body in checks:
                        response = client.post(endpoint, headers=auth, json=body)
                        response.raise_for_status()
                        assert response.headers["x-general-ai-gateway-revision"] == "1"
                    assert len(client.get("/v1/artifacts", headers=auth).json()["data"]) == 4
                    admin = {"Authorization": "Bearer " + env["GENERAL_AI_GATEWAY_ADMIN_KEY"]}
                    config = client.get("/admin/config", headers=admin).json()
                    config["revision"] = 2
                    config["artifacts"]["demo-chat"]["enabled"] = False
                    updated = client.put("/admin/config", headers=admin | {"If-Match": "1"}, json=config)
                    updated.raise_for_status()
                    assert client.post(checks[0][0], headers=auth, json=checks[0][1]).status_code == 403
                    assert client.get("/metrics", headers=admin).status_code == 200
                    print("PASS: real HTTP chat, embeddings, agent, MCP bridge, discovery, live revocation, metrics")
            finally:
                for child in children:
                    child.terminate()
                for child in children:
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()


if __name__ == "__main__":
    main()
