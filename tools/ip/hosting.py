"""Hosting and network-type intelligence for IPv4 and IPv6 addresses.

Uses the public ipconfig.is API to collect hosting, mobile-network,
VPN, Tor, organization, ASN, network-range, and reverse-DNS signals.

This module reports source-provided classifications, not definitive
proof of the physical device or service behind an IP address.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SOURCE_NAME = "ipconfig.is"
API_BASE = "https://ipconfig.is/json/"
TIMEOUT = 10

def _now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()

def _error(message: str, target: str | None = None) -> dict:
    """Return a consistent error result."""
    result = {
        "module": "hosting",
        "status": "error",
        "source": SOURCE_NAME,
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def _classify(data: dict) -> dict:
    """Summarize network-type signals without overclaiming."""

    hosting = data.get("is_hosting")
    mobile = data.get("is_mobile")
    vpn = data.get("is_vpn")
    tor = data.get("is_tor")

    signals = []
    if hosting is True:
        signals.append("hosting_or_datacenter")
    if mobile is True:
        signals.append("mobile_network")
    if vpn is True:
        signals.append("vpn_or_anonymization")
    if tor is True:
        signals.append("tor_exit")
    if tor is True:
        category = "tor_exit"
        confidence = "source_flag"
    elif vpn is True:
        category = "vpn_or_anonymization"
        confidence = "source_flag"
    elif hosting is True:
        category = "hosting_or_datacenter"
        confidence = "source_flag"
    elif mobile is True:
        category = "mobile_network"
        confidence = "source_flag"
    elif all(value is False for value in (hosting, mobile, vpn, tor)):
        category = "no_listed_hosting_or_anonymization_flag"
        confidence = "source_flags_negative"
    else:
        category = "undetermined"
        confidence = "insufficient_data"

    return {
        "category": category,
        "classification_basis": "ipconfig.is flags",
        "confidence": confidence,
        "signals": signals,
    }

def run(target: str) -> dict:
    """Collect hosting and network-type intelligence for an IP address."""

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": "hosting",
            "status": "not_checked",
            "target": normalized_ip,
            "reason": "Non-global IP addresses are not queried.",
            "source": SOURCE_NAME,
            "observed_at": _now(),
        }

    url = API_BASE + quote(normalized_ip, safe=":")

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Theseus-OSINT/0.7",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            status_code = response.status
            payload = json.loads(response.read().decode("utf-8"))

    except HTTPError as exc:
        return _error(
            f"Source returned HTTP {exc.code}.",
            normalized_ip,
        )
    except (URLError, TimeoutError, OSError) as exc:
        return _error(
            f"Source connection failed: {exc}",
            normalized_ip,
        )
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(
            "Source returned invalid JSON.",
            normalized_ip,
        )

    if not isinstance(payload, dict):
        return _error(
            "Source returned an unexpected response format.",
            normalized_ip,
        )

    returned_ip = payload.get("ip")

    if returned_ip:
        try:
            if ipaddress.ip_address(returned_ip) != address:
                return _error(
                    "Source response IP did not match the requested address.",
                    normalized_ip,
                )
        except ValueError:
            return _error(
                "Source returned an invalid IP address.",
                normalized_ip,
            )

    classification = _classify(payload)

    return {
        "module": "hosting",
        "status": "success",
        "target": normalized_ip,
        "source": SOURCE_NAME,
        "source_url": url,
        "http_status": status_code,
        "observed_at": _now(),
        "network_type": classification,
        "organization": payload.get("org"),
        "asn": payload.get("asn"),
        "asn_number": payload.get("asn_number"),
        "network_range": payload.get("network"),
        "reverse_dns": payload.get("ptr_record"),
        "flags": {
            "is_hosting": payload.get("is_hosting"),
            "is_mobile": payload.get("is_mobile"),
            "is_vpn": payload.get("is_vpn"),
            "is_tor": payload.get("is_tor"),
        },
        "limitations": [
            "Network classifications are source-provided indicators.",
            "A negative hosting flag does not establish residential use.",
            "VPN and hosting indicators can overlap.",
            "Network ownership does not establish who operates a service "
            "at the address.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Collect hosting and network-type intelligence."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)