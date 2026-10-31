from __future__ import annotations

import socket

from core.packets import Packet, PacketStatus

def portextract(packet: Packet) -> Packet:
    """Extract structured information from a network port."""

    result = packet.child(
        stage="extraction",
        artefact_type="port",
        status=PacketStatus.RUNNING,
    )

    try:
        if isinstance(packet.input, bool):
            raise ValueError("Port number must be an integer.")

        if isinstance(packet.input, int):
            port = packet.input
            protocol = "tcp"
        elif isinstance(packet.input, str):
            value = packet.input.strip().lower()

            if not value:
                raise ValueError("Port input cannot be empty.")

            if "/" in value:
                parts = value.split("/")

                if len(parts) != 2 or parts[1] not in {"tcp", "udp"}:
                    raise ValueError("Protocol must be tcp or udp.")

                port_text, protocol = parts
            else:
                port_text = value
                protocol = "tcp"

            if not port_text.isdigit():
                raise ValueError("Port number must be numeric.")

            port = int(port_text)

        else:
            raise ValueError("Port input must be an integer or string.")

        if not 0 <= port <= 65535:
            raise ValueError("Port number must be between 0 and 65535.")

        try:
            service = socket.getservbyport(port, protocol)
        except OSError:
            service = None

        if port == 0:
            classification = "reserved"
        elif port <= 1023:
            classification = "well-known"
        elif port <= 49151:
            classification = "registered"
        else:
            classification = "dynamic/private"

        result.data = {
            "port": port,
            "protocol": protocol.upper(),
            "service": service,
            "classification": classification,
            "is_system_port": 1 <= port <= 1023,
            "is_registered_port": 1024 <= port <= 49151,
            "is_dynamic_port": 49152 <= port <= 65535,
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="port_extraction_failed",
            message=str(exc),
            component="extractors.port",
        )

    return result