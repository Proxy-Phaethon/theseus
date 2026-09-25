from __future__ import annotations

import os
from urllib.parse import quote

from core.identifier import Entity, EntityType
from internet import Internet

from .base import Collector

class HIBPCollector(Collector):
    """
    Have I Been Pwned breach collector.
    """

    name = "have_i_been_pwned"

    supported_types = {
        EntityType.EMAIL,
    }

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(
        self,
        internet: Internet,
        api_key: str | None = None,
    ) -> None:
        self.internet = internet
        self.api_key = api_key or os.getenv("HIBP_API_KEY")

        if not self.api_key:
            raise ValueError(
                "HIBP_API_KEY is required for HIBP account searches"
            )

    def collect(self, entity: Entity):
        if not self.supports(entity):
            raise ValueError(
                f"{self.name} does not support {entity.type.value}"
            )

        account = quote(entity.value, safe="")
        url = f"{self.BASE_URL}/breachedaccount/{account}"

        response = self.internet.client.get(
            url,
            headers={
                "hibp-api-key": self.api_key,
                "User-Agent": "Theseus/0.1",
            },
        )

        if response.status_code == 404:
            return []

        return response.json()