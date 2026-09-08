from __future__ import annotations

import json
from typing import Any


def decode_rows(rows: list[dict[str, Any]], *json_fields: str) -> list[dict[str, Any]]:
    """Decode repository JSON columns at the API boundary without leaking storage details."""

    for row in rows:
        for field in json_fields:
            if field in row and isinstance(row[field], str):
                row[field.removesuffix("_json")] = json.loads(row.pop(field))
        for field in ("auto_correct", "blocked", "auto_applied"):
            if field in row:
                row[field] = bool(row[field])
    return rows

