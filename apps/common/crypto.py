"""
Canonical JSON hashing and cryptographic helper utilities (DES-04, TECH-01).
Uses standard library hashlib and unicodedata only (no custom crypto algorithms).
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any


def normalize_value(val: Any) -> Any:
    if isinstance(val, str):
        return unicodedata.normalize("NFC", val)
    if isinstance(val, dict):
        return {normalize_value(str(k)): normalize_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [normalize_value(x) for x in val]
    return val


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    normalized = normalize_value(payload)
    serialized = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return serialized.encode("utf-8")


def canonical_json_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def sha256_hex(raw: str) -> str:
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

