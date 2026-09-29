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
        sections = []

        identity = self._format_ip_identity(entity, result)
        if identity:
            sections.append(identity)

        network = self._format_ip_network(result)
        if network:
            sections.append(network)

        location = self._format_ip_location(result)
        if location:
            sections.append(location)

        exposure = self._format_ip_exposure(result)
        if exposure:
            sections.append(exposure)

        services = self._format_ip_services(result)
        if services:
            sections.append(services)

        return "\n\n".join(sections)

    def _format_ip_identity(
        self,
        entity: Entity,
        result: dict[str, Any],
    ) -> str:
        lines = ["Identity"]

        ip_address = result.get("ip_str", entity.value)
        lines.append(f"  IP Address: {ip_address}")

        organization = result.get("org")
        if organization:
            lines.append(f"  Organization: {organization}")

        isp = result.get("isp")
        if isp:
            lines.append(f"  ISP: {isp}")

        hostnames = result.get("hostnames", [])
        if hostnames:
            lines.append("  Hostnames:")
            for hostname in hostnames:
                lines.append(f"    - {hostname}")

        domains = result.get("domains", [])
        if domains:
            lines.append("  Domains:")
            for domain in domains:
                lines.append(f"    - {domain}")

        return "\n".join(lines)

    def _format_ip_network(
        self,
        result: dict[str, Any],
    ) -> str:
        lines = ["Network"]

        network = result.get("net")
        if network:
            lines.append(f"  Network: {network}")

        asn = result.get("asn")
        if asn:
            lines.append(f"  ASN: {asn}")

        return "\n".join(lines)

    def _format_ip_location(
        self,
        result: dict[str, Any],
    ) -> str:
        lines = ["Location"]

        country = result.get("country_name")
        if country:
            lines.append(f"  Country: {country}")

        region = result.get("region_code")
        if region:
            lines.append(f"  Region: {region}")

        city = result.get("city")
        if city:
            lines.append(f"  City: {city}")

        latitude = result.get("latitude")
        longitude = result.get("longitude")

        if latitude is not None and longitude is not None:
            lines.append(
                f"  Coordinates: {latitude}, {longitude}"
            )

        return "\n".join(lines)

    def _format_ip_exposure(
        self,
        result: dict[str, Any],
    ) -> str:
        ports = result.get("ports", [])

        if not ports:
            return ""

        lines = ["Exposure"]

        lines.append("  Open Ports:")
        for port in sorted(ports):
            lines.append(f"    - {port}")

        return "\n".join(lines)

    def _format_ip_services(
        self,
        result: dict[str, Any],
    ) -> str:
        services = result.get("data", [])

        if not services:
            return ""

        lines = ["Services"]

        for service in services:
            port = service.get("port")
            transport = service.get("transport")

            if port is None:
                continue

            label = str(port)

            if transport:
                label += f"/{transport}"

            lines.append(f"  {label}")

            product = service.get("product")
            if product:
                lines.append(f"    Product: {product}")

            version = service.get("version")
            if version:
                lines.append(f"    Version: {version}")

        return "\n".join(lines)

    def _format_unknown(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        return "No formatter available for this entity type."