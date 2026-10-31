from __future__ import annotations

import re

import requests

from core.packets import Packet, PacketStatus

RIPESTAT_URL = "https://stat.ripe.net/data/as-overview/data.json"
TIMEOUT = 10

def asnextract(packet: Packet) -> Packet:
    """Retrieve structured information about an Autonomous System."""

    result = packet.child(
        stage="extraction",
        artefact_type="asn",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("ASN input must be a string.")

        value = packet.input.strip().upper()

        if value.startswith("AS"):
            value = value[2:]

        if not re.fullmatch(r"\d+", value):
            raise ValueError("Invalid ASN format.")

        asn = int(value)

        if not 1 <= asn <= 4294967295:
            raise ValueError("ASN must be between 1 and 4294967295.")

        response = requests.get(
            RIPESTAT_URL,
            params={"resource": f"AS{asn}"},
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        payload = response.json()

        if payload.get("status") != "ok":
            raise ValueError(
                payload.get("messages") or "RIPEstat returned an unsuccessful response."
            )

        data = payload.get("data", {})

        result.data = {
            "asn": asn,
            "identifier": f"AS{asn}",
            "holder": data.get("holder"),
            "announced": data.get("announced"),
            "announced_prefixes": data.get("announced_prefixes"),
            "announced_space": data.get("announced_space"),
            "query_time": payload.get("time"),
            "source": "RIPEstat",
        }

        result.status = PacketStatus.SUCCESS

    except requests.RequestException as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="asn_request_failed",
            message=str(exc),
            component="extractors.asn",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="asn_extraction_failed",
            message=str(exc),
            component="extractors.asn",
        )

    return result