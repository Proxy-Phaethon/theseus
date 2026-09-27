from __future__ import annotations

from typing import Any

from core.evidence import Evidence
from core.identifier import Entity
from core.normalizer import Normalizer

class ShodanNormalizer(Normalizer):
    source = "shodan"

    def normalize(
        self,
        entity: Entity,
        data: dict[str, Any],
    ) -> list[Evidence]:
        evidence: list[Evidence] = []

        if "ip_str" in data:
            evidence.append(
                Evidence(
                    source=self.source,
                    entity=entity,
                    type="host",
                    data={
                        "ip": data.get("ip_str"),
                        "hostnames": data.get("hostnames", []),
                        "domains": data.get("domains", []),
                        "organization": data.get("org"),
                        "isp": data.get("isp"),
                        "country": data.get("country_name"),
                        "city": data.get("city"),
                        "ports": data.get("ports", []),
                    },
                    raw=data,
                )
            )

        return evidence