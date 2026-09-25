## free plan only

from __future__ import annotations

import os
from urllib.parse import quote

from core.identifier import Entity, EntityType
from internet import Internet

from .base import Collector

class ShodanCollector(Collector):
    name = "shodan"

    supported_types = {
        EntityType.IP_ADDRESS,
        EntityType.DOMAIN,
    }

    BASE_URL = "https://api.shodan.io"

    def __init__(
        self,
        internet: Internet,
        api_key: str | None = None,
    ) -> None:
        self.internet = internet
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")

        if not self.api_key:
            raise ValueError("SHODAN_API_KEY is required")

    def collect(self, entity: Entity):
        if not self.supports(entity):
            raise ValueError(
                f"{self.name} does not support {entity.type.value}"
            )

        if entity.type == EntityType.IP_ADDRESS:
            url = (
                f"{self.BASE_URL}/shodan/host/"
                f"{quote(entity.value, safe='')}"
            )

        elif entity.type == EntityType.DOMAIN:
            url = (
                f"{self.BASE_URL}/dns/domain/"
                f"{quote(entity.value, safe='')}"
            )

        else:
            raise ValueError(
                f"Unsupported entity type: {entity.type.value}"
            )

        response = self.internet.client.get(
            url,
            params={
                "key": self.api_key,
            },
        )

        return response.json()