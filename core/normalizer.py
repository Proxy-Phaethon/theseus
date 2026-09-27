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


class NormalizerRegistry:
    def __init__(self) -> None:
        self._normalizers: dict[str, Normalizer] = {}

    def register(self, normalizer: Normalizer) -> None:
        self._normalizers[normalizer.source] = normalizer

    def get(self, source: str) -> Normalizer | None:
        return self._normalizers.get(source)

    def normalize(
        self,
        source: str,
        entity: Entity,
        data: Any,
    ) -> list[Evidence]:
        normalizer = self.get(source)

        if normalizer is None:
            return [
                Evidence(
                    source=source,
                    entity=entity,
                    type="raw",
                    data=data,
                    raw=data,
                )
            ]

        return normalizer.normalize(entity, data)