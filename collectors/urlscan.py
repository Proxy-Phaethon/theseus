from __future__ import annotations

import os

from core.identifier import Entity, EntityType
from internet import Internet

from .base import Collector

class URLScanCollector(Collector):
    name = "urlscan"

    supported_types = {
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.IP_ADDRESS,
    }

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(
        self,
        internet: Internet,
        api_key: str | None = None,
    ) -> None:
        self.internet = internet
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")

        if not self.api_key:
            raise ValueError("URLSCAN_API_KEY is required")

    def collect(self, entity: Entity):
        if not self.supports(entity):
            raise ValueError(
                f"{self.name} does not support {entity.type.value}"
            )

        if entity.type == EntityType.DOMAIN:
            query = f"domain:{entity.value}"
        elif entity.type == EntityType.URL:
            query = f'page.url:"{entity.value}"'
        else:
            query = f"page.ip:{entity.value}"

        response = self.internet.client.get(
            f"{self.BASE_URL}/search/",
            params={
                "q": query,
                "size": 10,
            },
            headers={
                "api-key": self.api_key,
            },
        )

        return response.json()