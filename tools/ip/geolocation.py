"""
IP geolocation for Theseus.

Retrieves estimated geographic information for a public IP address.
Geolocation is approximate and should not be treated as device-level
or person-level location evidence.

Uses Python's standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

BASE_URL = "https://ipwho.is/"
TIMEOUT = 12
USER_AGENT = "Theseus-OSINT/0.1"

def run(target: str) -> dict[str, Any]:
    """Return estimated geolocation for an IP address."""
    observed_at = time.time()
    original = target

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return {
            "module": "geolocation",
            "target": original,
            "status": "error",
            "observed_at": observed_at,
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    if not address.is_global:
        return {
            "module": "geolocation",
            "target": str(address),
            "status": "not_checked",
            "observed_at": observed_at,
            "error": "Geolocation lookup skipped for a non-global address",
        }

    url = f"{BASE_URL}{quote(str(address), safe=':')}"

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if not isinstance(payload, dict):
            raise ValueError("Unexpected response format")

        if payload.get("success") is False:
            return {
                "module": "geolocation",
                "target": str(address),
                "status": "not_found",
                "source": "ipwho.is",
                "observed_at": time.time(),
                "error": payload.get("message", "Geolocation unavailable"),
            }

        connection = payload.get("connection") or {}
        timezone = payload.get("timezone") or {}

        return {
            "module": "geolocation",
            "target": str(address),
            "status": "success",
            "source": "ipwho.is",
            "observed_at": time.time(),
            "location": {
                "country": payload.get("country"),
                "country_code": payload.get("country_code"),
                "region": payload.get("region"),
                "region_code": payload.get("region_code"),
                "city": payload.get("city"),
                "postal_code": payload.get("postal"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "capital": payload.get("capital"),
                "continent": payload.get("continent"),
                "continent_code": payload.get("continent_code"),
                "timezone": timezone.get("id"),
                "utc_offset": timezone.get("utc"),
            },
            "network": {
                "isp": connection.get("isp"),
                "organization": connection.get("org"),
                "asn": connection.get("asn"),
                "domain": connection.get("domain"),
            },
        }

    except HTTPError as exc:
        return {
            "module": "geolocation",
            "target": str(address),
            "status": "error",
            "source": "ipwho.is",
            "observed_at": time.time(),
            "error": f"HTTP {exc.code}: {exc.reason}",
        }

    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "module": "geolocation",
            "target": str(address),
            "status": "error",
            "source": "ipwho.is",
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