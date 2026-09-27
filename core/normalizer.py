from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from core.evidence import Evidence
from core.identifier import Entity

class Normalizer(ABC):
    source: str

    @abstractmethod
    def normalize(
        self,
        entity: Entity,
        data: Any,
    ) -> list[Evidence]:
        raise NotImplementedError