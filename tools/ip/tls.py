"""TLS certificate and configuration intelligence for IP targets.

Uses Python's ssl/socket modules and cryptography for X.509 parsing.
Only performs TLS handshakes against predefined TCP ports.
No API keys or external scanning services are required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)

TIMEOUT = 4.0

TLS_PORTS = {
    443: "HTTPS",
    465: "SMTPS",
    636: "LDAPS",
    853: "DNS over TLS",
    993: "IMAPS",
    995: "POP3S",
    8443: "HTTPS Alternate",
    9443: "HTTPS Alternate",
}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _name_to_list(name: x509.Name) -> list[dict[str, str]]:
    """Represent an X.509 distinguished name without losing repeated fields."""
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": attribute.oid._name or attribute.oid.dotted_string,
            "value": str(attribute.value),
        }
        for attribute in name
    ]

def _get_extension(
    cert: x509.Certificate,
    extension_type: type,
) -> Any | None:
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None

def _public_key_info(cert: x509.Certificate) -> dict[str, Any]:
    key = cert.public_key()
    info: dict[str, Any] = {
        "algorithm": type(key).__name__,
        "key_size_bits": getattr(key, "key_size", None),
    }

    if isinstance(key, rsa.RSAPublicKey):
        info["algorithm"] = "RSA"
        info["exponent"] = key.public_numbers().e
    elif isinstance(key, ec.EllipticCurvePublicKey):
        info["algorithm"] = "EC"
        info["curve"] = key.curve.name
    elif isinstance(key, dsa.DSAPublicKey):
        info["algorithm"] = "DSA"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        info["algorithm"] = "Ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        info["algorithm"] = "Ed448"

    return info

def _certificate_details(der: bytes) -> dict[str, Any]:
    """Parse the exact DER certificate presented by the remote endpoint."""
    cert = x509.load_der_x509_certificate(der)

    try:
        san_extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san = san_extension.value
        san_dns = san.get_values_for_type(x509.DNSName)
        san_ips = [
            str(value)
            for value in san.get_values_for_type(x509.IPAddress)
        ]
        san_emails = san.get_values_for_type(x509.RFC822Name)
        san_uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        san_present = True
    except x509.ExtensionNotFound:
        san_dns = []
        san_ips = []
        san_emails = []
        san_uris = []
        san_present = False

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        is_ca = basic_constraints.ca
        path_length = basic_constraints.path_length
    except x509.ExtensionNotFound:
        is_ca = None
        path_length = None

    try:
        key_usage = cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
        key_usage_values = {
            "digital_signature": key_usage.digital_signature,
            "content_commitment": key_usage.content_commitment,
            "key_encipherment": key_usage.key_encipherment,
            "data_encipherment": key_usage.data_encipherment,
            "key_agreement": key_usage.key_agreement,
            "key_cert_sign": key_usage.key_cert_sign,
            "crl_sign": key_usage.crl_sign,
        }
    except x509.ExtensionNotFound:
        key_usage_values = None

    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        extended_key_usage = [oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        extended_key_usage = None

    try:
        ski = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest.hex()
    except x509.ExtensionNotFound:
        ski = None

    try:
        aki = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
        aki = aki.hex() if aki else None
    except x509.ExtensionNotFound:
        aki = None

    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
        authority_information_access = [
            {
                "method": item.access_method.dotted_string,
                "location": (
                    item.access_location.value
                    if isinstance(
                        item.access_location,
                        x509.UniformResourceIdentifier,
                    )
                    else str(item.access_location),
                ),
            }
            for item in aia
        ]
    except x509.ExtensionNotFound:
        authority_information_access = []

    now = datetime.now(timezone.utc)

    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if now < not_before:
        validity_status = "not_yet_valid"
    elif now > not_after:
        validity_status = "expired"
    else:
        validity_status = "within_validity_period"

    signature_hash = None
    try:
        signature_hash = cert.signature_hash_algorithm.name
    except (ValueError, TypeError, AttributeError):
        pass

    return {
        "serial_number_hex": format(cert.serial_number, "X"),
        "version": cert.version.name,
        "subject": _name_to_list(cert.subject),
        "issuer": _name_to_list(cert.issuer),
        "subject_common_names": [
            attribute.value
            for attribute in cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )
        ],
        "subject_alt_names": {
            "extension_present": san_present,
            "dns_names": san_dns,
            "ip_addresses": san_ips,
            "email_addresses": san_emails,
            "uris": san_uris,
        },
        "validity": {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "status": validity_status,
            "days_until_expiry": (not_after - now).days,
        },
        "signature": {
            "algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "algorithm_name": cert.signature_algorithm_oid._name,
            "hash_algorithm": signature_hash,
        },
        "public_key": _public_key_info(cert),
        "extensions": {
            "is_ca": is_ca,
            "ca_path_length": path_length,
            "key_usage": key_usage_values,
            "extended_key_usage_oids": extended_key_usage,
            "subject_key_identifier": ski,
            "authority_key_identifier": aki,
            "authority_information_access": authority_information_access,
        },
        "fingerprints": {
            "sha256": hashlib.sha256(der).hexdigest(),
            "sha1": hashlib.sha1(der).hexdigest(),
        },
        "der_size_bytes": len(der),
    }

def _connect_tls(
    address: str,
    port: int,
    verify: bool,
) -> dict[str, Any]:
    """Attempt TLS and return the observed certificate and handshake data."""
    context = ssl.create_default_context() if verify else ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    result: dict[str, Any] = {
        "port": port,
        "service_guess": TLS_PORTS[port],
        "status": "error",
        "verification_attempted": verify,
        "certificate": None,
        "tls": None,
        "error": None,
    }

    raw_sock = None
    tls_sock = None

    try:
        raw_sock = socket.create_connection(
            (address, port),
            timeout=TIMEOUT,
        )
        raw_sock.settimeout(TIMEOUT)

        tls_sock = context.wrap_socket(
            raw_sock,
            server_hostname=address,
        )
        raw_sock = None

        cert_der = tls_sock.getpeercert(binary_form=True)
        cipher = tls_sock.cipher()

        result["status"] = "success"
        result["tls"] = {
            "version": tls_sock.version(),
            "cipher_suite": cipher[0] if cipher else None,
            "cipher_protocol": cipher[1] if cipher else None,
            "secret_bits": cipher[2] if cipher else None,
            "alpn_protocol": tls_sock.selected_alpn_protocol(),
            "compression": tls_sock.compression(),
            "session_reused": getattr(tls_sock, "session_reused", None),
        }

        if cert_der:
            result["certificate"] = _certificate_details(cert_der)
        else:
            result["status"] = "no_certificate_returned"

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "certificate_verification_failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "verify_code": getattr(exc, "verify_code", None),
            "verify_message": getattr(exc, "verify_message", None),
        }
    except ssl.SSLError as exc:
        result["status"] = "tls_handshake_failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    except socket.timeout:
        result["status"] = "timeout"
        result["error"] = {
            "type": "Timeout",
            "message": f"Connection or TLS handshake exceeded {TIMEOUT} seconds",
        }
    except OSError as exc:
        result["status"] = "connection_error"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    except (ValueError, TypeError) as exc:
        result["status"] = "certificate_parse_error"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass

    return result

def _inspect_port(address: str, port: int) -> dict[str, Any]:
    """Verify first; if verification fails, retry to collect the certificate."""
    verified = _connect_tls(address, port, verify=True)

    if verified["status"] == "success":
        verified["certificate_verification"] = {
            "status": "passed",
            "meaning": (
                "The TLS library accepted the certificate chain and IP "
                "identity using the local trust configuration."
            ),
        }
        return verified

    if verified["status"] == "certificate_verification_failed":
        unverified = _connect_tls(address, port, verify=False)
        unverified["verification_attempted"] = True
        unverified["certificate_verification"] = {
            "status": "failed",
            "verification_error": verified["error"],
            "meaning": (
                "The certificate could not be validated against the local "
                "trust configuration and requested IP identity."
            ),
        }
        unverified["verified_connection_status"] = verified["status"]
        return unverified

    verified["certificate_verification"] = {
        "status": "not_completed",
        "meaning": "No successful certificate verification result was obtained.",
    }
    return verified


def run(target: str) -> dict[str, Any]:
    """Inspect common TLS endpoints on a globally routable IP address."""
    timestamp = _now()

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "module": "tls",
            "target": str(target),
            "status": "error",
            "error": "Invalid IP address",
            "timestamp": timestamp,
        }

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if not address.is_global:
        return {
            "module": "tls",
            "target": str(address),
            "status": "not_checked",
            "reason": "TLS inspection is limited to globally routable IP addresses",
            "timestamp": timestamp,
        }

    canonical_target = str(address)
    results = [
        _inspect_port(canonical_target, port)
        for port in sorted(TLS_PORTS)
    ]

    summary: dict[str, int] = {}
    for result in results:
        status = result["status"]
        summary[status] = summary.get(status, 0) + 1

    certificates = [
        {
            "port": result["port"],
            "service_guess": result["service_guess"],
            "certificate": result["certificate"],
            "certificate_verification": result.get("certificate_verification"),
            "tls": result["tls"],
        }
        for result in results
        if result.get("certificate") is not None
    ]

    return {
        "module": "tls",
        "target": canonical_target,
        "status": "success",
        "timestamp": timestamp,
        "source": "Direct TLS handshakes",
        "scan": {
            "ports_tested": len(results),
            "timeout_seconds": TIMEOUT,
            "verification_uses_system_trust": True,
            "unverified_retry_on_certificate_failure": True,
        },
        "summary": summary,
        "certificates_observed": len(certificates),
        "certificates": certificates,
        "results": results,
        "limitations": [
            "Only the predefined TCP ports are checked.",
            "Certificate validity dates do not establish trust or legitimacy.",
            "Verification depends on the local system trust store and IP identity.",
            "The presented leaf certificate is inspected; a complete certificate "
            "chain is not collected by this module.",
            "TLS configuration is observed only for successful handshakes.",
            "A failed handshake does not prove that the port has no TLS service.",
            "Certificate fingerprints identify the exact DER certificate observed.",
        ],
    }

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Inspect TLS certificates on an authorized IP target."
    )
    parser.add_argument("target", help="Target IP address")
    args = parser.parse_args()

    print(json.dumps(run(args.target), indent=2, ensure_ascii=False))