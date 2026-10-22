"""Authentication and deterministic content controls. Author: Rajarshi."""
import hashlib
import json
import re

from fastapi import HTTPException

from .config import Policy

EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def inspect(value, policy: Policy):
    """Walk string values so JSON escaping cannot evade phrase and email checks."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            lowered = item.casefold()
            if any(phrase.casefold() in lowered for phrase in policy.block_patterns):
                raise HTTPException(403, "Content policy denied request or response")
            if policy.block_email and EMAIL.search(item):
                raise HTTPException(403, "Content policy denied request or response")


def decode_json(raw: bytes):
    try:
        def reject_constant(value):
            raise ValueError(value)
        return json.loads(raw, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(400, "Invalid JSON") from None
