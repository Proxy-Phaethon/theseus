from __future__ import annotations

from typing import Any

from core.identifier import Entity, EntityType

class Responder:
    def respond(self, entity: Entity, result: Any) -> str:
        formatters = {
            EntityType.IP_ADDRESS: self._format_ip,
        }

        formatter = formatters.get(
            entity.type,
            self._format_unknown,
        )

        return formatter(entity, result)

    def _format_ip(
        self,
        entity: Entity,
        result: dict[str, Any],
    ) -> str:
        lines = []

        lines.append(f"IP Address: {result.get('ip_str', entity.value)}")

        organization = result.get("org")
        if organization:
            lines.append(f"Organization: {organization}")

        isp = result.get("isp")
        if isp:
            lines.append(f"ISP: {isp}")

        asn = result.get("asn")
        if asn:
            lines.append(f"ASN: {asn}")

        country = result.get("country_name")
        region = result.get("region_code")
        city = result.get("city")

        if country or region or city:
            lines.append("\nLocation:")

            if country:
                lines.append(f"  Country: {country}")

            if region:
                lines.append(f"  Region: {region}")

            if city:
                lines.append(f"  City: {city}")

        hostnames = result.get("hostnames", [])
        if hostnames:
            lines.append("\nHostnames:")
            for hostname in hostnames:
                lines.append(f"  - {hostname}")

        domains = result.get("domains", [])
        if domains:
            lines.append("\nDomains:")
            for domain in domains:
                lines.append(f"  - {domain}")

        ports = result.get("ports", [])
        if ports:
            lines.append("\nOpen Ports:")
            for port in sorted(ports):
                lines.append(f"  - {port}")

        return "\n".join(lines)

    def _format_unknown(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        return "No formatter available for this entity type."