from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

from core.packets import Packet, PacketStatus

def httpextract(packet: Packet) -> Packet:
    """Extract structured information from an HTTP request or response."""

    result = packet.child(
        stage="extraction",
        artefact_type="http",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, Mapping):
            raise ValueError("HTTP input must be a structured mapping.")

        source = packet.input

        url = source.get("url")
        method = source.get("method")
        status_code = source.get("status_code")
        http_version = source.get("http_version")
        headers = source.get("headers", {})
        body = source.get("body")

        if url is not None:
            if not isinstance(url, str):
                raise ValueError("HTTP URL must be a string.")

            parsed_url = urlsplit(url)

            if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.hostname:
                raise ValueError("Invalid HTTP URL.")

            url_data = {
                "url": url,
                "scheme": parsed_url.scheme.lower(),
                "hostname": parsed_url.hostname,
                "port": parsed_url.port,
                "path": parsed_url.path or "/",
                "query": parsed_url.query or None,
            }
        else:
            url_data = None

        if method is not None:
            if not isinstance(method, str) or not method.strip():
                raise ValueError("HTTP method must be a non-empty string.")

            method = method.strip().upper()

        if status_code is not None:
            if (
                isinstance(status_code, bool)
                or not isinstance(status_code, int)
                or not 100 <= status_code <= 599
            ):
                raise ValueError("HTTP status code must be an integer between 100 and 599.")

        if http_version is not None:
            if not isinstance(http_version, str):
                raise ValueError("HTTP version must be a string.")

        if not isinstance(headers, Mapping):
            raise ValueError("HTTP headers must be a mapping.")

        extracted_headers = {}

        for name, value in headers.items():
            if not isinstance(name, str):
                raise ValueError("HTTP header names must be strings.")

            extracted_headers[name.lower()] = value

        cookies = extracted_headers.get("set-cookie")

        result.data = {
            "request": {
                "method": method,
                "url": url_data,
            },
            "response": {
                "status_code": status_code,
                "http_version": http_version,
            },
            "headers": extracted_headers,
            "cookies": cookies,
            "body": {
                "present": body is not None,
                "type": type(body).__name__ if body is not None else None,
                "length": len(body) if isinstance(body, (str, bytes)) else None,
            },
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="http_extraction_failed",
            message=str(exc),
            component="extractors.http",
        )

    return result