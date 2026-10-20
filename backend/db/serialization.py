"""Model -> JSON-safe dict conversion for the API (on-wire shape). Database rows are
mapped explicitly in `case_rows.py` / `custody_log.py`, column by column."""

from __future__ import annotations

import base64
import dataclasses
from datetime import datetime
from enum import Enum
from typing import Any



def to_jsonable(value: Any) -> Any:
    """Recursively convert models to plain JSON types. Enums -> value, datetimes ->
    ISO-8601, bytes -> base64 (the RFC 3161 token), dataclasses -> dicts."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value
