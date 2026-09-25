## currently doesnt work, fixing the bug

from __future__ import annotations

from core.identifier import Entity, EntityType
from internet import Internet

from .base import Collector

class CRTShCollector(Collector):
    name = "crtsh"

    supported_types = {
        EntityType.DOMAIN,
    }

    def __init__(self, internet: Internet) -> None:
        self.internet = internet

    def collect(self, entity: Entity):
        if not self.supports(entity):
            raise ValueError(
                f"{self.name} does not support {entity.type.value}"
            )

        response = self.internet.client.get(
            "https://crt.sh/",
            params={
                "q": entity.value,
                "output": "json",
            },
        )

        return response.json()