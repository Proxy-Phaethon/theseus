from __future__ import annotations

from abc import ABC, abstractmethod

from core.identifier import Entity, EntityType

class Collector(ABC):
    """
    Base interface for all OSINT collectors.
    """

    name: str
    supported_types: set[EntityType]

    @abstractmethod
    def supports(self, entity: Entity) -> bool:
        """
        Return True if this collector can investigate the entity.
        """
        return entity.type in self.supported_types

    @abstractmethod
    def collect(self, entity: Entity):
        """
        Investigate an entity and return collected evidence.
        """
        raise NotImplementedError