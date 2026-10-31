from __future__ import annotations

import re

from core.packets import Packet, PacketStatus

BSSID_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
)

def bssidextract(packet: Packet) -> Packet:
    """Extract structural information from a BSSID."""

    result = packet.child(
        stage="extraction",
        artefact_type="bssid",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("BSSID input must be a string.")

        address = packet.input.strip().lower()

        if not BSSID_PATTERN.fullmatch(address):
            raise ValueError("Invalid BSSID format.")

        normalised = address.replace("-", ":")
        octets = normalised.split(":")
        address_bytes = bytes(int(octet, 16) for octet in octets)

        first_octet = address_bytes[0]

        is_multicast = bool(first_octet & 0b00000001)
        is_locally_administered = bool(first_octet & 0b00000010)

        result.data = {
            "bssid": normalised.upper(),
            "address_compact": "".join(octets).upper(),
            "octets": [octet.upper() for octet in octets],
            "oui": ":".join(octets[:3]).upper(),
            "nic": ":".join(octets[3:]).upper(),
            "is_unicast": not is_multicast,
            "is_multicast": is_multicast,
            "is_locally_administered": is_locally_administered,
            "is_universally_administered": not is_locally_administered,
            "is_broadcast": address_bytes == b"\xff" * 6,
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="bssid_extraction_failed",
            message=str(exc),
            component="extractors.bssid",
        )

    return result