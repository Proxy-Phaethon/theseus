"""Historical IP observations using the Shodan host history API.

Retrieves historical service banners and observed ports for an IP address.
Requires SHODAN_API_KEY in the environment.

Historical observations describe what Shodan saw at a particular time.
They do not prove that a service is still present or that an IP had the
same operator throughout the observation period.
"""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MODULE_NAME = "history"
SOURCE_NAME = "Shodan"
API_BASE = "https://api.shodan.io/shodan/host"

TIMEOUT = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 100

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _error(
    message: str,
    target: str | None = None,
    status: str = "error",
) -> dict:
    result = {
        "module": MODULE_NAME,
        "status": status,
        "source": SOURCE_NAME,
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def _timestamp(value) -> str | None:
    """Validate and normalize a Shodan observation timestamp."""
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None

def _normalize_banner(record: dict) -> dict:
    """Keep useful historical service evidence without huge raw payloads."""

    data = record.get("data")
    if isinstance(data, str):
        data = data[:2000]
    else:
        data = None

    http_data = record.get("http")
    http_summary = None

    if isinstance(http_data, dict):
        http_summary = {
            "status": http_data.get("status"),
            "title": http_data.get("title"),
            "server": http_data.get("server"),
            "host": http_data.get("host"),
        }

    ssl_data = record.get("ssl")
    ssl_summary = None

    if isinstance(ssl_data, dict):
        cert = ssl_data.get("cert")

        ssl_summary = {
            "version": ssl_data.get("version"),
            "cipher": ssl_data.get("cipher"),
            "certificate": None,
        }

        if isinstance(cert, dict):
            ssl_summary["certificate"] = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "issued": cert.get("issued"),
                "expires": cert.get("expires"),
                "fingerprint": cert.get("fingerprint"),
            }

    return {
        "observed_at": _timestamp(record.get("timestamp")),
        "timestamp_raw": record.get("timestamp"),
        "port": record.get("port"),
        "transport": record.get("transport"),
        "product": record.get("product"),
        "version": record.get("version"),
        "module": record.get("module"),
        "cpe": record.get("cpe"),
        "banner": data,
        "http": http_summary,
        "ssl": ssl_summary,
    }

def run(target: str) -> dict:
    """Retrieve historical Shodan observations for a public IP."""

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
            "source": SOURCE_NAME,
            "reason": "Non-global IP addresses are not queried.",
            "observed_at": _now(),
            "observations": [],
        }

    api_key = os.environ.get("SHODAN_API_KEY", "").strip()

    if not api_key:
        return {
            "module": MODULE_NAME,
            "status": "not_checked",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "reason": (
                "SHODAN_API_KEY is not configured in the environment."
            ),
            "observed_at": _now(),
            "observations": [],
        }

    query = urlencode({
        "key": api_key,
        "history": "true",
        "minify": "false",
    })
    url = f"{API_BASE}/{normalized_ip}?{query}"

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
            body = response.read(MAX_RESPONSE_BYTES + 1)

            if len(body) > MAX_RESPONSE_BYTES:
                return _error(
                    "Response exceeded the configured size limit.",
                    normalized_ip,
                )

            payload = json.loads(body.decode("utf-8"))
            http_status = response.status

    except HTTPError as exc:
        if exc.code == 401:
            message = "Shodan rejected the API key."
        elif exc.code == 403:
            message = (
                "Shodan denied access. The account may not have "
                "permission to retrieve this data."
            )
        elif exc.code == 429:
            message = "Shodan rate limit or query allowance reached."
        else:
            message = f"Shodan returned HTTP {exc.code}."

        return _error(message, normalized_ip)

    except (URLError, TimeoutError, OSError) as exc:
        return _error(
            f"Shodan connection failed: {exc}",
            normalized_ip,
        )

    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(
            "Shodan returned invalid JSON.",
            normalized_ip,
        )

    if not isinstance(payload, dict):
        return _error(
            "Shodan returned an unexpected response format.",
            normalized_ip,
        )

    if payload.get("error"):
        return _error(
            f"Shodan reported an error: {payload['error']}",
            normalized_ip,
        )

    returned_ip = payload.get("ip_str")

    if returned_ip:
        try:
            if ipaddress.ip_address(returned_ip) != address:
                return _error(
                    "Shodan response IP did not match the requested IP.",
                    normalized_ip,
                )
        except ValueError:
            return _error(
                "Shodan returned an invalid IP address.",
                normalized_ip,
            )

    raw_data = payload.get("data", [])

    if not isinstance(raw_data, list):
        return _error(
            "Shodan returned an unexpected history format.",
            normalized_ip,
        )

    observations = [
        _normalize_banner(record)
        for record in raw_data[:MAX_RECORDS]
        if isinstance(record, dict)
    ]

    observed_ports = sorted({
        item["port"]
        for item in observations
        if isinstance(item.get("port"), int)
    })

    timestamps = [
        item["observed_at"]
        for item in observations
        if item.get("observed_at")
    ]

    return {
        "module": MODULE_NAME,
        "status": "success",
        "target": normalized_ip,
        "source": SOURCE_NAME,
        "source_url": (
            f"https://www.shodan.io/host/{normalized_ip}"
        ),
        "http_status": http_status,
        "observed_at": _now(),
        "organization": payload.get("org"),
        "asn": payload.get("asn"),
        "operating_system": payload.get("os"),
        "country": payload.get("country_name"),
        "total_observations_returned": len(raw_data),
        "observations_included": len(observations),
        "truncated": len(raw_data) > MAX_RECORDS,
        "observed_ports": observed_ports,
        "earliest_observation_in_sample": min(timestamps) if timestamps else None,
        "latest_observation_in_sample": max(timestamps) if timestamps else None,
        "observations": observations,
        "limitations": [
            "History reflects Shodan's own scanning and observation coverage.",
            "Absence of a historical banner does not prove a service was absent.",
            "An observation does not establish current service availability.",
            "IP ownership and assignments may change over time.",
            "Only a bounded sample of returned banners is retained.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Retrieve historical IP observations from Shodan."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)