"""
IP address classification for Theseus.

Performs local classification of IPv4 and IPv6 addresses.
No network requests or external API keys are required.
"""

from __future__ import annotations

import ipaddress
from typing import Any

def run(target: str) -> dict[str, Any]:
    """
    Parse and classify an IPv4 or IPv6 address.

    Returns structured observations suitable for the IP responder.
    Invalid input returns an error result rather than raising an exception.
    """
    original = target
    value = target.strip()

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return {
            "module": "classification",
            "target": original,
            "status": "error",
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    classification = _classify(address)

    result: dict[str, Any] = {
        "module": "classification",
        "target": original,
        "status": "success",
        "input": value,
        "canonical_address": str(address),
        "version": f"IPv{address.version}",
        "address_family": "AF_INET" if address.version == 4 else "AF_INET6",
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_unspecified": address.is_unspecified,
        "is_reserved": address.is_reserved,
        "classification": classification,
        "is_ipv4_mapped_ipv6": False,
        "ipv4_mapped_address": None,
    }

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        result["is_ipv4_mapped_ipv6"] = True
        result["ipv4_mapped_address"] = str(address.ipv4_mapped)

    return result

def _classify(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return a primary classification for the address."""

    if address.is_unspecified:
        return "unspecified"

    if address.is_loopback:
        return "loopback"

    if address.is_multicast:
        return "multicast"

    if address.is_link_local:
        return "link_local"

    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "shared"

    if address.is_reserved:
        return "reserved"

    if address.is_private:
        return "private"

    if address.is_global:
        return "public"

    return "special_purpose_or_unclassified"

if __name__ == "__main__":
    import json

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

        print(json.dumps(run(target), indent=2))