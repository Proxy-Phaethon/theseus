from __future__ import annotations

import ipaddress
import re

import tldextract

from core.packets import Packet, PacketStatus

def domainextract(packet: Packet) -> Packet:
    """Extract the constituent parts of a domain name."""

    result = packet.child(
        stage="extraction",
        artefact_type="domain",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("Domain input must be a string.")

        hostname = packet.input.strip().rstrip(".").lower()

        if not hostname:
            raise ValueError("Domain input cannot be empty.")

        if "://" in hostname or "/" in hostname or "@" in hostname:
            raise ValueError("Input must be a domain name, not a URL.")

        try:
            ipaddress.ip_address(hostname)
            raise ValueError("IP addresses are not supported by the domain extractor.")
        except ValueError as exc:
            if "not supported" in str(exc):
                raise

        # Convert internationalised domain names to ASCII.
        hostname = hostname.encode("idna").decode("ascii")

        # Validate individual DNS labels.
        labels = hostname.split(".")

        if len(labels) < 2:
            raise ValueError("A fully qualified domain name is required.")

        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Invalid domain name format.")

        extracted = tldextract.extract(hostname)

        if not extracted.domain or not extracted.suffix:
            raise ValueError("Unable to identify a registered domain and public suffix.")

        registered_domain = (
            f"{extracted.domain}.{extracted.suffix}"
        )

        result.data = {
            "input": packet.input,
            "hostname": hostname,
            "subdomain": extracted.subdomain or None,
            "domain": extracted.domain,
            "public_suffix": extracted.suffix,
            "registered_domain": registered_domain,
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="domain_extraction_failed",
            message=str(exc),
            component="extractors.domain",
        )

    return result