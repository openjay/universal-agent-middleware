from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..openapi import schema


def with_actions_extensions(doc: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return an optional ChatGPT Actions compatibility overlay.

    This adapter is deliberately outside the UAM core. It only annotates
    operations with client metadata and does not grant capabilities or authority.
    """
    out = deepcopy(doc or schema())
    consequential = {"createExecutionContract", "recordExecutorResult"}
    for path_item in out["paths"].values():
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation["x-openai-isConsequential"] = (
                operation["operationId"] in consequential
            )
    return out
