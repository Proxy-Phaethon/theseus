"""
BGP routing intelligence for Theseus.

Uses RIPEstat's public data endpoints to retrieve network information
and observed BGP routing state.

No API key or third-party Python package is required.
"""

from __future__ import annotations

import ipaddress
import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE_URL = "https://stat.ripe.net/data"
TIMEOUT = 15
USER_AGENT = "Theseus-OSINT/0.1"
MAX_OBSERVATIONS = 5

def _fetch(endpoint: str, resource: str) -> dict[str, Any]:
    """Fetch one RIPEstat JSON response."""
    query = urlencode({"resource": resource})
    url = f"{BASE_URL}/{endpoint}/data.json?{query}"

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )

    with urlopen(request, timeout=TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not isinstance(payload, dict):
        raise ValueError("Unexpected response format")

    status = payload.get("status")

    if status not in (None, "ok"):
        raise ValueError(f"RIPEstat returned status: {status}")

    return payload

def _error_message(exc: Exception) -> str:
    """Return a concise error message for a failed request."""
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}: {exc.reason}"

    if isinstance(exc, URLError):
        return f"Connection failed: {exc.reason}"

    return f"{type(exc).__name__}: {exc}"

def run(target: str) -> dict[str, Any]:
    """Collect BGP routing observations for an IP address."""
    observed_at = time.time()
    original = target

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        return {
            "module": "bgp",
            "target": original,
            "status": "error",
            "observed_at": observed_at,
            "error": "Target is not a valid IPv4 or IPv6 address",
        }

    result: dict[str, Any] = {
        "module": "bgp",
        "target": str(address),
        "status": "unknown",
        "source": "RIPEstat",
        "observed_at": observed_at,
        "network": None,
        "routing": {
            "visible": None,
            "observation_count": 0,
            "observations": [],
        },
        "errors": [],
    }

    if not address.is_global:
        result["status"] = "not_checked"
        result["errors"].append(
            "BGP lookup skipped for a non-global address"
        )
        return result

    try:
        network_payload = _fetch("network-info", str(address))
        network_data = network_payload.get("data", {})

        if not isinstance(network_data, dict):
            raise ValueError("Missing network information")

        asns = network_data.get("asns", [])

        result["network"] = {
            "resource": network_data.get("resource"),
            "prefix": network_data.get("prefix"),
            "asns": [
                f"AS{asn}" if str(asn).isdigit() else str(asn)
                for asn in asns
            ] if isinstance(asns, list) else [],
            "query_time": network_data.get("query_time"),
        }

    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        result["errors"].append({
            "query": "network-info",
            "error": _error_message(exc),
        })

    try:
        bgp_payload = _fetch("bgp-state", str(address))
        bgp_data = bgp_payload.get("data", {})

        if not isinstance(bgp_data, dict):
            raise ValueError("Missing BGP state data")

        raw_states = bgp_data.get("bgp_state", [])

        if not isinstance(raw_states, list):
            raw_states = []

        observations = []

        for item in raw_states:
            if not isinstance(item, dict):
                continue

            path = item.get("path", [])
            if not isinstance(path, list):
                path = []

            observations.append({
                "source_id": item.get("source_id"),
                "target_prefix": item.get("target_prefix"),
                "path": path,
                "community": item.get("community", []),
                "last_updated": item.get("last_updated"),
            })

        result["routing"] = {
            "visible": bool(observations),
            "observation_count": len(observations),
            "observations": observations[:MAX_OBSERVATIONS],
            "observations_truncated": len(observations) > MAX_OBSERVATIONS,
            "latest_time": bgp_data.get("latest_time"),
            "query_time": bgp_data.get("query_time"),
        }

    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        result["errors"].append({
            "query": "bgp-state",
            "error": _error_message(exc),
        })

    if result["routing"]["visible"] is True:
        result["status"] = "success"
    elif result["routing"]["visible"] is False and not result["errors"]:
        result["status"] = "not_found"
    elif result["network"] is not None or result["routing"]["visible"] is not None:
        result["status"] = "partial"
    else:
        result["status"] = "error"

    return result

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