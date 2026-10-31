from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from core.packets import Packet, PacketStatus

TIMEOUT = 10
DEFAULT_PORT = 443

def tlsextract(packet: Packet) -> Packet:
    """Extract information from a live TLS connection."""

    result = packet.child(
        stage="extraction",
        artefact_type="tls",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("TLS input must be a hostname or URL string.")

        value = packet.input.strip()

        if not value:
            raise ValueError("TLS input cannot be empty.")

        if "://" in value:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in {"https"}:
                raise ValueError("TLS extraction requires an HTTPS URL.")

            if not parsed.hostname:
                raise ValueError("Invalid HTTPS URL.")

            hostname = parsed.hostname
            port = parsed.port or DEFAULT_PORT

        else:
            if "/" in value or "@" in value:
                raise ValueError("Provide a hostname or HTTPS URL.")

            parsed = urlsplit(f"//{value}")

            if not parsed.hostname:
                raise ValueError("Invalid hostname.")

            hostname = parsed.hostname
            port = parsed.port or DEFAULT_PORT

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=TIMEOUT,
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=hostname,
            ) as tls_connection:

                certificate_der = tls_connection.getpeercert(
                    binary_form=True
                )

                if not certificate_der:
                    raise ValueError("Server did not provide a certificate.")

                certificate = x509.load_der_x509_certificate(
                    certificate_der
                )

                cipher = tls_connection.cipher()

                certificate_info = {
                    "subject": [
                        {
                            "oid": attribute.oid.dotted_string,
                            "name": attribute.oid._name,
                            "value": attribute.value,
                        }
                        for attribute in certificate.subject
                    ],
                    "issuer": [
                        {
                            "oid": attribute.oid.dotted_string,
                            "name": attribute.oid._name,
                            "value": attribute.value,
                        }
                        for attribute in certificate.issuer
                    ],
                    "serial_number": str(certificate.serial_number),
                    "not_before": certificate.not_valid_before_utc.isoformat(),
                    "not_after": certificate.not_valid_after_utc.isoformat(),
                    "sha256_fingerprint": certificate.fingerprint(
                        hashes.SHA256()
                    ).hex(),
                }

                try:
                    san = certificate.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    ).value

                    certificate_info["subject_alternative_names"] = [
                        str(name) for name in san
                    ]

                except x509.ExtensionNotFound:
                    certificate_info["subject_alternative_names"] = None

                result.data = {
                    "hostname": hostname,
                    "port": port,
                    "tls_version": tls_connection.version(),
                    "cipher_suite": {
                        "name": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "secret_bits": cipher[2] if cipher else None,
                    },
                    "server_hostname": tls_connection.server_hostname,
                    "certificate": certificate_info,
                }

        result.status = PacketStatus.SUCCESS

    except (socket.timeout, TimeoutError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="tls_connection_timeout",
            message=str(exc),
            component="extractors.tls",
        )

    except ssl.SSLError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="tls_handshake_failed",
            message=str(exc),
            component="extractors.tls",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="tls_extraction_failed",
            message=str(exc),
            component="extractors.tls",
        )

    return result