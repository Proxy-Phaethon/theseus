"""Protocol-aware service fingerprinting for IP targets.

Uses the Python standard library only.

Probes a predefined set of common TCP services. These probes are intended
for identification, not exploitation. Only run against systems you own or
are authorized to assess.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import struct
from datetime import datetime, timezone
from typing import Any

TIMEOUT = 2.0
MAX_BANNER_BYTES = 4096
USER_AGENT = "Theseus-OSINT/0.7"

TCP_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch / HTTP",
}

TLS_PORTS = {443, 465, 993, 995, 8443}
HTTP_PORTS = {80, 443, 8080, 8443, 9200}

PROBE_PORTS = set(TCP_SERVICES)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _clean_text(data: bytes) -> str:
    """Decode protocol evidence without assuming a particular encoding."""
    return data.decode("utf-8", errors="replace").replace("\x00", "\\x00").strip()

def _recv(sock: socket.socket, size: int = MAX_BANNER_BYTES) -> bytes:
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""

def _send(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(payload)

def _connect(address: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((address, port))
    return sock

def _http_probe(sock: socket.socket, address: str) -> dict[str, Any]:
    """Send a minimal HTTP HEAD request and capture the response headers."""
    request = (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {address}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="replace")

    _send(sock, request)
    response = _recv(sock)

    if not response:
        return {
            "protocol": "HTTP",
            "identified": False,
            "evidence": None,
            "reason": "No HTTP response received",
        }

    text = _clean_text(response)
    first_line = text.splitlines()[0] if text.splitlines() else ""

    if first_line.startswith(("HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2 ")):
        headers: dict[str, str] = {}
        for line in text.splitlines()[1:]:
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        return {
            "protocol": "HTTP",
            "identified": True,
            "evidence": first_line,
            "headers": {
                key: headers[key]
                for key in ("server", "date", "content-type", "via")
                if key in headers
            },
            "reason": "Valid HTTP status line received",
        }

    return {
        "protocol": "HTTP",
        "identified": False,
        "evidence": text[:1000],
        "reason": "Response did not contain a recognizable HTTP status line",
    }

def _tls_probe(
    sock: socket.socket,
    address: str,
    port: int,
) -> tuple[socket.socket, dict[str, Any]]:
    """Upgrade a TCP connection to TLS and collect certificate metadata."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    server_name = None if ":" in address else address
    tls_sock = context.wrap_socket(sock, server_hostname=server_name)
    tls_sock.settimeout(TIMEOUT)

    cert = tls_sock.getpeercert()
    cipher = tls_sock.cipher()
    cert_der = tls_sock.getpeercert(binary_form=True)

    subject = [
        {"key": key, "value": value}
        for rdn in cert.get("subject", ())
        for key, value in rdn
    ]
    issuer = [
        {"key": key, "value": value}
        for rdn in cert.get("issuer", ())
        for key, value in rdn
    ]

    tls_info: dict[str, Any] = {
        "negotiated_version": tls_sock.version(),
        "cipher": cipher[0] if cipher else None,
        "certificate_present": bool(cert_der),
        "certificate_der_sha256": (
            __import__("hashlib").sha256(cert_der).hexdigest()
            if cert_der
            else None
        ),
        "subject": subject,
        "issuer": issuer,
        "subject_alt_names": [
            {"type": kind, "value": value}
            for kind, value in cert.get("subjectAltName", ())
        ],
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "certificate_validation": "Not performed",
    }

    return tls_sock, tls_info

def _protocol_probe(
    sock: socket.socket,
    address: str,
    port: int,
) -> dict[str, Any]:
    """Perform a small, service-appropriate identification exchange."""
    service = TCP_SERVICES.get(port, "Unknown")

    if port in HTTP_PORTS:
        result = _http_probe(sock, address)
        result["service_guess"] = service
        return result

    if port == 22:
        banner = _recv(sock, 1024)
        text = _clean_text(banner)
        identified = text.startswith("SSH-")
        return {
            "protocol": "SSH" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "SSH identification string received" if identified
                      else "No recognizable SSH identification string",
        }

    if port == 21:
        banner = _recv(sock, 2048)
        text = _clean_text(banner)
        identified = text.startswith(("220 ", "220-"))
        return {
            "protocol": "FTP" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "FTP greeting received" if identified
                      else "No recognizable FTP greeting",
        }

    if port in {25, 587, 465}:
        banner = _recv(sock, 2048)
        text = _clean_text(banner)
        identified = text.startswith(("220 ", "220-"))

        if identified:
            try:
                _send(sock, b"EHLO theseus.invalid\r\n")
                reply = _clean_text(_recv(sock, 2048))
                if reply:
                    text = (text + "\n" + reply)[:3000]
            except (OSError, socket.timeout):
                pass

        return {
            "protocol": "SMTP" if identified else None,
            "identified": identified,
            "evidence": text[:3000] or None,
            "reason": "SMTP greeting received" if identified
                      else "No recognizable SMTP greeting",
        }

    if port in {110, 995}:
        banner = _recv(sock, 2048)
        text = _clean_text(banner)
        identified = text.startswith("+OK")
        return {
            "protocol": "POP3" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "POP3 greeting received" if identified
                      else "No recognizable POP3 greeting",
        }

    if port in {143, 993}:
        banner = _recv(sock, 2048)
        text = _clean_text(banner)
        upper = text.upper()
        identified = upper.startswith("* OK") or upper.startswith("* PREAUTH")
        return {
            "protocol": "IMAP" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "IMAP greeting received" if identified
                      else "No recognizable IMAP greeting",
        }

    if port == 3306:
        # MySQL servers normally send a handshake packet immediately.
        packet = _recv(sock, 2048)
        if len(packet) >= 5:
            packet_length = packet[0] | (packet[1] << 8) | (packet[2] << 16)
            protocol_version = packet[4]
            identified = protocol_version == 10 and packet_length >= 1
            return {
                "protocol": "MySQL" if identified else None,
                "identified": identified,
                "evidence": packet[:128].hex(),
                "protocol_version": protocol_version,
                "reason": "MySQL handshake structure detected" if identified
                          else "Received data did not match a MySQL handshake",
            }
        return {
            "protocol": None,
            "identified": False,
            "evidence": packet.hex() or None,
            "reason": "No complete MySQL handshake received",
        }

    if port == 5432:
        # PostgreSQL SSLRequest: length 8, request code 80877103.
        _send(sock, struct.pack("!II", 8, 80877103))
        response = _recv(sock, 8)
        identified = response in (b"S", b"N")
        return {
            "protocol": "PostgreSQL" if identified else None,
            "identified": identified,
            "evidence": response.hex() or None,
            "reason": "PostgreSQL SSLRequest response received" if identified
                      else "No recognizable PostgreSQL SSLRequest response",
        }

    if port == 6379:
        _send(sock, b"PING\r\n")
        response = _recv(sock, 1024)
        text = _clean_text(response)
        identified = text.startswith(("+PONG", "-NOAUTH", "-ERR"))
        return {
            "protocol": "Redis" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "Redis-compatible PING response received" if identified
                      else "No recognizable Redis response",
        }

    if port == 5900:
        banner = _recv(sock, 1024)
        text = _clean_text(banner)
        identified = text.startswith("RFB ")
        return {
            "protocol": "RFB/VNC" if identified else None,
            "identified": identified,
            "evidence": text[:1000] or None,
            "reason": "RFB protocol version received" if identified
                      else "No recognizable RFB/VNC greeting",
        }

    if port == 53:
        query_id = 0x5448
        dns_query = struct.pack(
            "!HHHHHH",
            query_id, 0x0100, 1, 0, 0, 0,
        ) + b"\x00" + struct.pack("!HH", 2, 1)
        framed_query = struct.pack("!H", len(dns_query)) + dns_query
        _send(sock, framed_query)
        response = _recv(sock, 2048)

        if len(response) >= 14:
            length = struct.unpack("!H", response[:2])[0]
            response_id = struct.unpack("!H", response[2:4])[0]
            flags = struct.unpack("!H", response[4:6])[0]
            identified = response_id == query_id and bool(flags & 0x8000)
            return {
                "protocol": "DNS over TCP" if identified else None,
                "identified": identified,
                "evidence": response[:128].hex(),
                "response_length": length,
                "reason": "Matching DNS response received" if identified
                          else "Response did not match the DNS query",
            }

        return {
            "protocol": None,
            "identified": False,
            "evidence": response.hex() or None,
            "reason": "No complete DNS response received",
        }

    if port == 23:
        banner = _recv(sock, 1024)
        text = _clean_text(banner)
        return {
            "protocol": None,
            "identified": False,
            "evidence": text[:1000] or None,
            "reason": "Telnet is not reliably identifiable from a silent connection",
        }

    if port == 445:
        # SMB2 NEGOTIATE request for dialect 2.02, 2.10, 3.0, 3.02 and 3.11.
        smb_body = (
            b"\x00" * 2 +                 # StructureSize
            b"\x00" * 2 +                 # CreditCharge
            b"\x00" * 4 +                 # ChannelSequence / Reserved
            b"\x00" * 2 +                 # Command: NEGOTIATE
            b"\x00" * 2 +                 # CreditsRequested
            b"\x00" * 4 +                 # Flags
            b"\x00" * 4 +                 # NextCommand
            b"\x01\x00\x00\x00\x00\x00\x00\x00" +  # MessageId
            b"\x00" * 4 +                 # Reserved / TreeId
            b"\x00" * 8 +                 # SessionId
            b"\x00" * 16 +                # Signature
            b"\x24\x00" +                 # StructureSize 36
            b"\x05\x00" +                 # DialectCount
            b"\x01\x00" +                 # SecurityMode
            b"\x00" * 2 +                 # Reserved
            b"\x00" * 4 +                 # Capabilities
            b"\x00" * 16 +                # ClientGuid
            b"\x00" * 4 +                 # NegotiateContextOffset
            b"\x00" * 2 +                 # NegotiateContextCount
            b"\x00" * 2 +                 # Reserved2
            b"\x02\x02" + b"\x02\x10" + b"\x03\x00" +
            b"\x03\x02" + b"\x11\x03"
        )
        smb_header = (
            b"\xfeSMB" + b"\x40\x00" + b"\x00" * 2 +
            b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4 +
            b"\x01\x00\x00\x00\x00\x00\x00\x00" +
            b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16
        )
        smb_packet = smb_header + smb_body
        _send(sock, struct.pack("!I", len(smb_packet)) + smb_packet)
        response = _recv(sock, 2048)
        identified = response[4:8] == b"\xfeSMB" if len(response) >= 8 else False
        return {
            "protocol": "SMB2" if identified else None,
            "identified": identified,
            "evidence": response[:128].hex() or None,
            "reason": "SMB2 response signature received" if identified
                      else "No recognizable SMB2 response",
        }

    banner = _recv(sock, 1024)
    text = _clean_text(banner)
    return {
        "protocol": None,
        "identified": False,
        "evidence": text[:1000] or None,
        "reason": "No dedicated protocol probe implemented for this port",
    }

def _probe_port(address: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "port": port,
        "service_guess": TCP_SERVICES[port],
        "status": "unknown",
        "identified": False,
        "protocol": None,
        "evidence": None,
        "tls": None,
        "error": None,
    }

    sock: socket.socket | None = None
    tls_active = False

    try:
        sock = _connect(address, port)
        result["status"] = "connected"

        if port in TLS_PORTS:
            try:
                sock, tls_info = _tls_probe(sock, address, port)
                tls_active = True
                result["tls"] = tls_info
            except (ssl.SSLError, OSError, socket.timeout) as exc:
                result["tls"] = {
                    "handshake": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
                result["status"] = "connected_tls_failed"
                result["error"] = None
                return result

        probe = _protocol_probe(sock, address, port)
        result.update(probe)
        result["status"] = "identified" if result["identified"] else "connected_unidentified"

        if tls_active and result.get("protocol") in {"HTTP", None}:
            result["transport"] = "TLS"
        else:
            result["transport"] = "TLS" if tls_active else "TCP"

    except socket.timeout:
        result["status"] = "timeout"
        result["error"] = "Connection or protocol probe timed out"
    except ConnectionRefusedError:
        result["status"] = "connection_refused"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return result

def run(target: str) -> dict[str, Any]:
    """Fingerprint common TCP services on a globally routable IP address."""
    timestamp = _now()

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "module": "services",
            "target": str(target),
            "status": "error",
            "error": "Invalid IP address",
            "timestamp": timestamp,
        }

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if not address.is_global:
        return {
            "module": "services",
            "target": str(address),
            "status": "not_checked",
            "reason": "Service fingerprinting is limited to globally routable IP addresses",
            "timestamp": timestamp,
        }

    canonical_target = str(address)
    results = [_probe_port(canonical_target, port) for port in sorted(PROBE_PORTS)]

    counts: dict[str, int] = {}
    for item in results:
        status = item["status"]
        counts[status] = counts.get(status, 0) + 1

    identified = [
        {
            "port": item["port"],
            "protocol": item.get("protocol"),
            "service_guess": item["service_guess"],
            "evidence": item.get("evidence"),
        }
        for item in results
        if item.get("identified")
    ]

    return {
        "module": "services",
        "target": canonical_target,
        "status": "success",
        "timestamp": timestamp,
        "source": "Direct TCP protocol probes",
        "scan": {
            "ports_tested": len(results),
            "timeout_seconds": TIMEOUT,
            "tls_ports": sorted(TLS_PORTS),
            "active_probing": True,
            "authorized_targets_only": True,
        },
        "summary": counts,
        "identified_services": identified,
        "results": results,
        "limitations": [
            "Port labels are guesses until protocol evidence supports identification.",
            "A failed or silent probe does not prove a service is absent.",
            "TLS certificates are collected without validating trust or hostname.",
            "Service versions and vulnerabilities are not inferred from port numbers.",
            "Only the predefined TCP ports are checked; UDP services are not covered.",
        ],
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Fingerprint common TCP services on an authorized IP target."
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output",
    )
    args = parser.parse_args()

    output = run(args.target)
    print(json.dumps(output, indent=2, ensure_ascii=False))