from __future__ import annotations

from .base import Collector
from core.identifier import Entity

class CollectorRegistry:
    """
    Registry of available OSINT collectors.
    """

    def __init__(self) -> None:
        self._collectors: list[Collector] = []

    def register(self, collector: Collector) -> None:
        """Add a collector to the registry."""

        if collector not in self._collectors:
            self._collectors.append(collector)

    def unregister(self, collector: Collector) -> None:
        """Remove a collector from the registry."""

        if collector in self._collectors:
            self._collectors.remove(collector)

    def get(self, entity: Entity) -> list[Collector]:
        """
        Return all collectors capable of investigating an entity.
        """

        return [
            collector
            for collector in self._collectors
            if collector.supports(entity)
        ]

    def all(self) -> list[Collector]:
        """Return all registered collectors."""

        return list(self._collectors)