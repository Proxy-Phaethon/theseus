"""URL component extractor for Theseus."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import tldextract

from core.packets import Packet, PacketStatus

def urlextract(packet: Packet) -> Packet:
    """Extract structured components from a URL."""

    if not isinstance(packet, Packet):
        raise TypeError("URL extractor requires a Packet.")

    result = packet.child(
        stage="extraction",
        artefact_type="url",
        input=packet.input,
        status=PacketStatus.RUNNING,
    )

    try:
        raw_url = packet.input

        if not isinstance(raw_url, str) or not raw_url.strip():
            raise ValueError("Input must be a non-empty URL string.")

        raw_url = raw_url.strip()
        parsed = urlsplit(raw_url)

        if not parsed.scheme or not parsed.hostname:
            raise ValueError("URL must contain a scheme and hostname.")

        # Accessing .port also validates the port syntax and range.
        port = parsed.port

        hostname = parsed.hostname

        # Extract registrable domain using the public suffix list.
        extracted = tldextract.extract(hostname)

        domain = (
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain and extracted.suffix
            else None
        )

        result.data = {
            "url": raw_url,
            "components": {
                "scheme": parsed.scheme,
                "hostname": hostname,
                "domain": domain,
                "port": port,
                "path": parsed.path,
                "query_parameters": parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                ),
                "fragment": parsed.fragment,
            },
        }

        result.status = PacketStatus.SUCCESS

    except ValueError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="invalid_url",
            message=str(exc),
            component="extractors.url",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="url_extraction_failed",
            message=str(exc),
            component="extractors.url",
        )

    return result