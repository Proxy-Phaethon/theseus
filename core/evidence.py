from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.identifier import Entity

@dataclass
class Evidence:
    source: str
    entity: Entity
    type: str
    data: Any
    raw: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)