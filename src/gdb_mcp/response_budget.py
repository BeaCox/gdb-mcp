"""Deterministic response serialization and conservative token estimates."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

CONSERVATIVE_BYTES_PER_TOKEN = 3


def serialize_response(payload: Any) -> bytes:
    """Serialize a response deterministically as compact UTF-8 JSON."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def estimate_tokens(serialized_size_bytes: int) -> int:
    """Estimate tokens conservatively without depending on a model tokenizer."""

    if serialized_size_bytes < 0:
        raise ValueError("serialized_size_bytes must be non-negative")
    return (
        serialized_size_bytes + CONSERVATIVE_BYTES_PER_TOKEN - 1
    ) // CONSERVATIVE_BYTES_PER_TOKEN


@dataclass(frozen=True)
class ResponseSize:
    bytes: int
    estimated_tokens: int


def measure_response(payload: Any) -> ResponseSize:
    """Measure one serialized response."""

    size = len(serialize_response(payload))
    return ResponseSize(bytes=size, estimated_tokens=estimate_tokens(size))
