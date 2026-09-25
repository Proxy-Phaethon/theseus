from __future__ import annotations

from core.identifier import Entity, EntityType
from internet import Internet

from .base import Collector

class SearXNGCollector(Collector):

    name = "searxng"

    supported_types = {
        EntityType.EMAIL,
        EntityType.USERNAME,
        EntityType.DOMAIN,
        EntityType.PERSON,
        EntityType.ORGANIZATION,
        EntityType.PHONE,
    }

    def __init__(
        self,
        internet: Internet,
        base_url: str = "http://localhost:8080",
    ) -> None:
        self.internet = internet
        self.base_url = base_url.rstrip("/")

    def collect(self, entity: Entity):
        response = self.internet.client.get(
            f"{self.base_url}/search",
            params={
                "q": entity.value,
                "format": "json",
            },
        )

        return response.json()