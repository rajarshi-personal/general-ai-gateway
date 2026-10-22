"""Offline protocol fixtures, never a production AI provider. Author: Rajarshi."""
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    return {"id": "demo", "object": "chat.completion", "model": body["model"],
            "choices": [{"index": 0, "message": {"role": "assistant",
                        "content": "General AI Gateway demo: your request passed gateway policies."},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


@app.post("/embedding")
async def embedding():
    return {"object": "list", "data": [{"object": "embedding", "index": 0,
                                       "embedding": [0.1, 0.2, 0.3]}]}


@app.post("/agent")
async def agent(request: Request):
    return {"status": "completed", "output": await request.json()}


@app.post("/mcp")
async def mcp(request: Request):
    body = await request.json()
    return {"jsonrpc": "2.0", "id": body["id"],
            "result": {"content": [{"type": "text", "text": "Governed tool execution."}]}}
