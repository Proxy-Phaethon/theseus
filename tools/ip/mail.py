"""Mail infrastructure intelligence for public IPv4 and IPv6 addresses.

Performs limited SMTP protocol probes to identify mail-service behaviour,
server greetings, advertised SMTP extensions, and STARTTLS support.

No email is sent and no authentication or relay testing is performed.
TLS certificate identity and full certificate analysis belong in tls.py.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone

MODULE_NAME = "mail"
TIMEOUT = 4.0
MAX_RESPONSE_LINES = 50
MAX_LINE_BYTES = 4096

SMTP_PORTS = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP submission",
    2525: "Alternative SMTP",
}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _error(message: str, target: str | None = None) -> dict:
    result = {
        "module": MODULE_NAME,
        "status": "error",
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def _read_response(sock) -> dict:
    """Read one SMTP response, including bounded multiline responses."""

    lines = []
    total_bytes = 0
    response_code = None
    complete = False

    stream = sock.makefile("rb")

    try:
        for _ in range(MAX_RESPONSE_LINES):
            line = stream.readline(MAX_LINE_BYTES + 1)

            if not line:
                break

            total_bytes += len(line)

            if len(line) > MAX_LINE_BYTES:
                return {
                    "code": response_code,
                    "lines": lines,
                    "complete": False,
                    "error": "SMTP response line exceeded size limit.",
                }

            decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(decoded)

            if len(decoded) >= 3 and decoded[:3].isdigit():
                code = int(decoded[:3])

                if response_code is None:
                    response_code = code

                # SMTP multiline responses use "code-" for continuation
                # and "code " for the final line.
                if len(decoded) == 3 or decoded[3:4] == " ":
                    complete = True
                    break

        return {
            "code": response_code,
            "lines": lines,
            "complete": complete,
            "bytes_received": total_bytes,
            "truncated": not complete,
        }
    finally:
        stream.close()

def _send_command(sock, command: str) -> dict:
    """Send a bounded SMTP command and read its response."""

    sock.sendall(command.encode("ascii") + b"\r\n")
    return _read_response(sock)

def _extract_extensions(response: dict) -> list[str]:
    """Extract extension names from a successful EHLO response."""

    if response.get("code") != 250:
        return []

    extensions = []

    for line in response.get("lines", []):
        # Strip the SMTP status code and continuation separator.
        if len(line) < 4 or not line[:3].isdigit():
            continue

        value = line[4:].strip()

        if not value:
            continue

        extension = value.split()[0].upper()

        if extension not in extensions:
            extensions.append(extension)

    return extensions

def _probe_smtp(target: str, port: int) -> dict:
    """Probe one SMTP endpoint without sending mail."""

    result = {
        "port": port,
        "service": SMTP_PORTS[port],
        "status": "error",
        "banner": None,
        "banner_code": None,
        "ehlo_code": None,
        "extensions": [],
        "starttls_advertised": False,
        "starttls_attempted": False,
        "starttls_code": None,
        "tls": {
            "mode": "implicit" if port == 465 else "opportunistic",
            "negotiated": False,
            "version": None,
            "cipher": None,
            "certificate_verification": "not_performed",
        },
        "error": None,
    }

    connection = None

    try:
        raw_socket = socket.create_connection(
            (target, port),
            timeout=TIMEOUT,
        )
        raw_socket.settimeout(TIMEOUT)
        connection = raw_socket

        if port == 465:
            # SMTP over implicit TLS begins with a TLS handshake.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                connection = context.wrap_socket(
                    raw_socket,
                    server_hostname=None,
                )
            except (ssl.SSLError, OSError) as exc:
                result["error"] = f"Implicit TLS negotiation failed: {exc}"
                return result

            result["tls"]["negotiated"] = True
            result["tls"]["version"] = connection.version()

            cipher = connection.cipher()
            if cipher:
                result["tls"]["cipher"] = cipher[0]

        banner = _read_response(connection)
        result["banner_code"] = banner.get("code")
        result["banner"] = banner.get("lines", [])

        if not banner.get("complete"):
            result["error"] = "Incomplete SMTP greeting."
            return result

        if banner.get("code") != 220:
            result["status"] = "unexpected_greeting"
            return result

        # EHLO is a capability-discovery command. No mail is sent.
        ehlo = _send_command(connection, "EHLO theseus.local")
        result["ehlo_code"] = ehlo.get("code")
        result["extensions"] = _extract_extensions(ehlo)

        if ehlo.get("code") != 250:
            result["status"] = "smtp_greeting_only"
            return result

        result["starttls_advertised"] = (
            "STARTTLS" in result["extensions"]
        )

        if port != 465 and result["starttls_advertised"]:
            result["starttls_attempted"] = True
            starttls = _send_command(connection, "STARTTLS")
            result["starttls_code"] = starttls.get("code")

            if starttls.get("code") == 220:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    connection = context.wrap_socket(
                        connection,
                        server_hostname=None,
                    )

                    result["tls"]["negotiated"] = True
                    result["tls"]["version"] = connection.version()

                    cipher = connection.cipher()
                    if cipher:
                        result["tls"]["cipher"] = cipher[0]

                    # RFC 3207 requires both sides to discard SMTP
                    # knowledge learned before the TLS handshake.
                    ehlo_after_tls = _send_command(
                        connection,
                        "EHLO theseus.local",
                    )

                    result["ehlo_after_tls_code"] = (
                        ehlo_after_tls.get("code")
                    )
                    result["extensions_after_tls"] = _extract_extensions(
                        ehlo_after_tls
                    )

                except (ssl.SSLError, OSError) as exc:
                    result["tls"]["error"] = (
                        f"STARTTLS negotiation failed: {exc}"
                    )

        result["status"] = "success"

    except (socket.timeout, TimeoutError):
        result["error"] = "Connection timed out."
    except ConnectionRefusedError:
        result["status"] = "closed_or_refused"
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected probe error: {exc}"
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass

    return result

def run(target: str) -> dict:
    """Collect SMTP and mail-service observations for a public IP."""

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": MODULE_NAME,
            "status": "not_checked",
            "target": normalized_ip,
            "reason": "Non-global IP addresses are not probed.",
            "observed_at": _now(),
            "services": [],
        }

    services = [
        _probe_smtp(normalized_ip, port)
        for port in SMTP_PORTS
    ]

    successful = [
        service for service in services
        if service["status"] == "success"
    ]

    open_or_responding = [
        service for service in services
        if service["status"] in {
            "success",
            "smtp_greeting_only",
            "unexpected_greeting",
        }
    ]

    return {
        "module": MODULE_NAME,
        "status": "success",
        "target": normalized_ip,
        "observed_at": _now(),
        "summary": {
            "ports_checked": len(services),
            "smtp_services_identified": len(successful),
            "ports_with_responses": len(open_or_responding),
            "starttls_advertised_count": sum(
                service["starttls_advertised"]
                for service in services
            ),
            "tls_negotiated_count": sum(
                service["tls"]["negotiated"]
                for service in services
            ),
        },
        "services": services,
        "limitations": [
            "Only the configured SMTP ports are checked.",
            "Filtered ports and timeouts do not establish that a service is absent.",
            "SMTP capabilities can vary by client, network, and server policy.",
            "TLS negotiation is tested without certificate identity validation.",
            "No authentication, mail delivery, or relay testing is performed.",
            "An SMTP service does not identify all domains it serves.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Collect SMTP and mail-service intelligence for an IP."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)