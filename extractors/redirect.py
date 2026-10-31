from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests

from core.packets import Packet, PacketStatus

MAX_REDIRECTS = 10
TIMEOUT = 10

def redirectextract(packet: Packet) -> Packet:
    """Follow HTTP redirects and record the redirect chain."""

    result = packet.child(
        stage="extraction",
        artefact_type="redirect",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("Redirect input must be a string.")

        original_url = packet.input.strip()

        if not original_url:
            raise ValueError("URL input cannot be empty.")

        parsed = urlsplit(original_url)

        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required.")

        current_url = original_url
        redirects = []
        visited = set()
        final_response = None

        session = requests.Session()

        try:
            for _ in range(MAX_REDIRECTS + 1):
                if current_url in visited:
                    raise ValueError("Redirect loop detected.")

                visited.add(current_url)

                response = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=TIMEOUT,
                    stream=True,
                )

                final_response = response

                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")

                    if not location:
                        raise ValueError(
                            "Redirect response did not provide a Location header."
                        )

                    next_url = urljoin(current_url, location)

                    redirects.append({
                        "url": current_url,
                        "status_code": response.status_code,
                        "location": location,
                        "destination": next_url,
                    })

                    response.close()
                    current_url = next_url
                    continue

                break

            else:
                raise ValueError(
                    f"Maximum redirect limit of {MAX_REDIRECTS} exceeded."
                )

        finally:
            session.close()

        if final_response is None:
            raise ValueError("No HTTP response was received.")

        result.data = {
            "original_url": original_url,
            "final_url": current_url,
            "redirect_count": len(redirects),
            "redirects": redirects,
            "final_status_code": final_response.status_code,
            "final_content_type": final_response.headers.get("Content-Type"),
        }

        final_response.close()
        result.status = PacketStatus.SUCCESS

    except requests.RequestException as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="redirect_request_failed",
            message=str(exc),
            component="extractors.redirect",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="redirect_extraction_failed",
            message=str(exc),
            component="extractors.redirect",
        )

    return result