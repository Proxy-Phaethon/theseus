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

        asn = result.get("asn")
        if asn:
            lines.append(f"  ASN: {asn}")

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

    def _format_unknown(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        return "No formatter available for this entity type."