from __future__ import annotations

import ipaddress
import re

import tldextract

from core.packets import Packet, PacketStatus

def hostnameextract(packet: Packet) -> Packet:
    """Extract structured information from a hostname."""

    result = packet.child(
        stage="extraction",
        artefact_type="hostname",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("Hostname input must be a string.")

        hostname = packet.input.strip().rstrip(".").lower()

        if not hostname:
            raise ValueError("Hostname input cannot be empty.")

        if any(char in hostname for char in "/:@?#"):
            raise ValueError("Input must be a hostname, not a URL or address.")

        hostname = hostname.encode("idna").decode("ascii")

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not supported by the hostname extractor.")

        if len(hostname) > 253:
            raise ValueError("Hostname exceeds the maximum length of 253 characters.")

        labels = hostname.split(".")

        if any(
            not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                label,
            )
            for label in labels
        ):
            raise ValueError("Invalid hostname format.")

        extracted = tldextract.extract(hostname)

        result.data = {
            "hostname": hostname,
            "labels": labels,
            "label_count": len(labels),
            "subdomain": extracted.subdomain or None,
            "domain": extracted.domain or None,
            "public_suffix": extracted.suffix or None,
            "registered_domain": (
                f"{extracted.domain}.{extracted.suffix}"
                if extracted.domain and extracted.suffix
                else None
            ),
            "is_fully_qualified": bool(extracted.domain and extracted.suffix),
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="hostname_extraction_failed",
            message=str(exc),
            component="extractors.hostname",
        )

    return result