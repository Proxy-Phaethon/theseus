from __future__ import annotations

import ipaddress

from core.packets import Packet, PacketStatus

def ipextract(packet: Packet) -> Packet:
    """Extract structured information from an IPv4 or IPv6 address."""

    result = packet.child(
        stage="extraction",
        artefact_type="ip",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("IP input must be a string.")

        address = ipaddress.ip_address(packet.input.strip())

        result.data = {
            "address": str(address),
            "version": address.version,
            "compressed": address.compressed,
            "exploded": address.exploded,
            "is_private": address.is_private,
            "is_global": address.is_global,
            "is_reserved": address.is_reserved,
            "is_loopback": address.is_loopback,
            "is_link_local": address.is_link_local,
            "is_multicast": address.is_multicast,
            "is_unspecified": address.is_unspecified,
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ip_extraction_failed",
            message=str(exc),
            component="extractors.ip",
        )

    return result