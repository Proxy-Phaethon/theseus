from __future__ import annotations

import ipaddress

from core.packets import Packet, PacketStatus

def cidrextract(packet: Packet) -> Packet:
    """Extract structured information from an IPv4 or IPv6 CIDR network."""

    result = packet.child(
        stage="extraction",
        artefact_type="cidr",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("CIDR input must be a string.")

        network = ipaddress.ip_network(
            packet.input.strip(),
            strict=False,
        )

        result.data = {
            "input": packet.input,
            "network": str(network),
            "version": network.version,
            "address": str(network.network_address),
            "broadcast_address": (
                str(network.broadcast_address)
                if network.version == 4
                else None
            ),
            "netmask": str(network.netmask),
            "hostmask": str(network.hostmask),
            "prefix_length": network.prefixlen,
            "num_addresses": network.num_addresses,
            "first_address": str(network[0]),
            "last_address": str(network[-1]),
            "is_private": network.is_private,
            "is_global": network.is_global,
            "is_reserved": network.is_reserved,
            "is_loopback": network.is_loopback,
            "is_link_local": network.is_link_local,
            "is_multicast": network.is_multicast,
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="cidr_extraction_failed",
            message=str(exc),
            component="extractors.cidr",
        )

    return result