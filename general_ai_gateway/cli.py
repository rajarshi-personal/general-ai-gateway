"""Installation-friendly command line. Author: Rajarshi."""
import argparse
import getpass
import hashlib
import json
import logging
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="General AI Gateway — Rajarshi")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="Print a cryptographically random API key and SHA-256 fingerprint")
    sub.add_parser("hash-key", help="Hash an existing key read from a hidden prompt")
    init = sub.add_parser("init", help="Create an offline demo configuration and secret env file")
    init.add_argument("--directory", default="config")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "keygen":
        key = secrets.token_urlsafe(32)
        print(json.dumps({"key": key, "sha256": hashlib.sha256(key.encode()).hexdigest()}, indent=2))
    elif args.command == "hash-key":
        print(hashlib.sha256(getpass.getpass("API key: ").encode()).hexdigest())
    elif args.command == "init":
        directory = Path(args.directory)
        directory.mkdir(parents=True, exist_ok=True)
        config_file, env_file = directory / "gateway.json", directory / "demo.env"
        if config_file.exists() or env_file.exists():
            parser.error("Configuration already exists; refusing to overwrite")
        tenant_key, admin_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        config = {
            "revision": 1,
            "tenants": {"demo": {
                "key_sha256": hashlib.sha256(tenant_key.encode()).hexdigest(),
                "artifacts": ["demo-chat", "demo-embedding", "demo-agent", "demo-mcp"]
            }},
            "artifacts": {
                "demo-chat": {"kind": "chat", "url": "http://mock:9000/chat", "owner": "Rajarshi"},
                "demo-embedding": {"kind": "embedding", "url": "http://mock:9000/embedding"},
                "demo-agent": {"kind": "agent", "url": "http://mock:9000/agent"},
                "demo-mcp": {"kind": "mcp", "url": "http://mock:9000/mcp", "allowed_tools": ["echo"]}
            },
            "policy": {"block_email": True, "block_patterns": ["general_ai_gateway-test-block"]}
        }
        with config_file.open("x", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
        with env_file.open("x", encoding="utf-8") as handle:
            handle.write(f"GENERAL_AI_GATEWAY_ADMIN_KEY={admin_key}\nGENERAL_AI_GATEWAY_DEMO_KEY={tenant_key}\n")
        env_file.chmod(0o600)
        print(f"Created {config_file} and {env_file}. Treat demo.env as a secret.")
    else:
        import uvicorn
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        uvicorn.run("general_ai_gateway.app:create_app", factory=True, host=args.host, port=args.port,
                    access_log=False, limit_concurrency=500, timeout_keep_alive=5)


if __name__ == "__main__":
    main()
