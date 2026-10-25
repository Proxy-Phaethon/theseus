"""
ASN lookup for Theseus.

Uses Team Cymru's public DNS-based IP-to-ASN service.
No API key or third-party Python package is required.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from typing import Any

CYMRU_HOST = "origin.asn.cymru.com"
TIMEOUT = 10

def _reverse_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return the reversed address representation used by Team Cymru."""
    if address.version == 4:
        return ".".join(reversed(str(address).split(".")))

    return ".".join(reversed(address.exploded.replace(":", "")))

def _query_txt(name: str) -> str:
    """Retrieve a TXT record using the system DNS resolver."""
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(TIMEOUT)

    try:
        answers = socket.getaddrinfo(
            name,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    finally:
        socket.setdefaulttimeout(previous_timeout)

    raise RuntimeError("TXT lookup requires the DNS query implementation")

def _dns_txt_query(name: str) -> list[str]:
    """Query DNS TXT records using a small standard-library DNS client."""
    import random
    import struct

    labels = name.rstrip(".").split(".")
    qname = b"".join(
        bytes([len(label.encode("ascii"))]) + label.encode("ascii")
        for label in labels
    ) + b"\x00"

    query_id = random.randrange(0, 65536)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 16, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.sendto(packet, ("8.8.8.8", 53))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(response) < 12:
        raise ValueError("DNS response was too short")

    response_id, flags, questions, answers, _, _ = struct.unpack(
        "!HHHHHH", response[:12]
    )

    if response_id != query_id:
        raise ValueError("DNS response ID mismatch")

    if flags & 0x000F:
        raise ValueError(f"DNS server returned response code {flags & 0x000F}")

    offset = 12

    def skip_name(data: bytes, position: int) -> int:
        while position < len(data):
            length = data[position]

            if length == 0:
                return position + 1

            if length & 0xC0 == 0xC0:
                return position + 2

            position += length + 1

        raise ValueError("Malformed DNS name")

    for _ in range(questions):
        offset = skip_name(response, offset)
        offset += 4

    results = []

    for _ in range(answers):
        offset = skip_name(response, offset)

        if offset + 10 > len(response):
            raise ValueError("Malformed DNS answer")

        record_type, record_class, ttl, length = struct.unpack(
            "!HHIH", response[offset:offset + 10]
        )
        offset += 10
        data = response[offset:offset + length]
        offset += length

        if record_type == 16 and record_class == 1:
            position = 0
            chunks = []

            while position < len(data):
                chunk_length = data[position]
                position += 1
                chunks.append(data[position:position + chunk_length].decode(
                    "utf-8", errors="replace"
                ))
                position += chunk_length

            results.append("".join(chunks))

    return results

def run(target: str) -> dict[str, Any]:
    """Return ASN and announced-prefix information for an IP address."""
    observed_at = time.time()

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return {
            "module": "asn",
            "target": target,
            "status": "error",
            "observed_at": observed_at,
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    if not address.is_global:
        return {
            "module": "asn",
            "target": str(address),
            "status": "not_checked",
            "observed_at": observed_at,
            "error": "ASN lookup skipped for a non-global address",
        }

    try:
        reversed_ip = _reverse_address(address)
        query = f"{reversed_ip}.origin.asn.cymru.com"
        records = _dns_txt_query(query)

        if not records:
            return {
                "module": "asn",
                "target": str(address),
                "status": "not_found",
                "source": "Team Cymru",
                "observed_at": time.time(),
                "error": "No ASN record returned",
            }

        # Team Cymru format:
        # ASN | announced prefix | country code | registry | allocation date
        parsed_records = []

        for record in records:
            fields = [field.strip() for field in record.split("|")]

            if len(fields) < 5:
                continue

            asn, prefix, country, registry, allocation_date = fields[:5]

            parsed_records.append({
                "asn": f"AS{asn}" if asn.isdigit() else asn,
                "prefix": prefix,
                "country": country or None,
                "registry": registry or None,
                "allocation_date": allocation_date or None,
            })

        if not parsed_records:
            return {
                "module": "asn",
                "target": str(address),
                "status": "error",
                "source": "Team Cymru",
                "observed_at": time.time(),
                "error": "Unexpected ASN response format",
                "raw_records": records,
            }

        return {
            "module": "asn",
            "target": str(address),
            "status": "success",
            "source": "Team Cymru DNS",
            "observed_at": time.time(),
            "records": [
                {
                    **record,
                    "as_name": None,
                }
                for record in parsed_records
            ],
        }

    except (OSError, ValueError, socket.timeout) as exc:
        return {
            "module": "asn",
            "target": str(address),
            "status": "error",
            "source": "Team Cymru DNS",
            "observed_at": time.time(),
            "error": f"{type(exc).__name__}: {exc}",
        }

if __name__ == "__main__":
    while True:
        try:
            target = input("ip> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.casefold() in {"q", "quit", "exit", "bye"}:
            break

        if not target:
            continue

        print(json.dumps(run(target), indent=2, ensure_ascii=False))