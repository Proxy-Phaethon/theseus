"""Historical IP intelligence using public, unauthenticated sources.

Sources:
- RIPEstat routing-history: historical BGP announcement timelines.
- crt.sh: publicly logged TLS certificates matching the IP address.

No API keys or third-party Python packages are required.

Important:
- BGP history describes routing observations, not service availability.
- Certificate records do not prove a certificate was actively deployed.
- Empty results do not prove that no historical records exist.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

RIPESTAT_URL = (
    "https://stat.ripe.net/data/routing-history/data.json"
)
CRT_SH_URL = "https://crt.sh/"

TIMEOUT = 15
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ROUTING_RECORDS = 100
MAX_CERTIFICATES = 100

USER_AGENT = "Theseus-OSINT/1.0"

def _request_json(url: str) -> Any:
    """Fetch JSON from a public endpoint with bounded response size."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)

    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("Response exceeded the configured size limit")

    return json.loads(body.decode("utf-8"))

def _error_message(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}: {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"Connection failed: {exc.reason}"
    if isinstance(exc, TimeoutError):
        return "Request timed out"
    if isinstance(exc, json.JSONDecodeError):
        return "Source returned invalid JSON"
    return str(exc)

def _get_routing_history(ip: str) -> dict[str, Any]:
    """Retrieve historical BGP announcements for an IP address."""
    url = (
        f"{RIPESTAT_URL}?"
        + urllib.parse.urlencode(
            {
                "resource": ip,
                "max_rows": MAX_ROUTING_RECORDS,
            }
        )
    )

    try:
        payload = _request_json(url)

        if payload.get("status") != "ok":
            return {
                "status": "error",
                "source": "RIPEstat",
                "source_url": url,
                "error": payload.get("message", "Source query failed"),
                "records": [],
            }

        data = payload.get("data") or {}
        records = []
        truncated = False

        for origin_entry in data.get("by_origin", []) or []:
            origin = origin_entry.get("origin")
            prefixes = origin_entry.get("prefixes", []) or []

            for prefix_entry in prefixes:
                prefix = prefix_entry.get("prefix")

                for timeline in prefix_entry.get("timelines", []) or []:
                    if len(records) >= MAX_ROUTING_RECORDS:
                        truncated = True
                        break

                    records.append(
                        {
                            "origin": origin,
                            "prefix": prefix,
                            "start_time": timeline.get("starttime"),
                            "end_time": timeline.get("endtime"),
                            "full_peers_seeing": timeline.get(
                                "full_peers_seeing"
                            ),
                            "visibility": timeline.get("visibility"),
                        }
                    )

                if truncated:
                    break

            if truncated:
                break

        return {
            "status": "success",
            "source": "RIPEstat",
            "source_url": url,
            "record_count": len(records),
            "records_truncated": truncated,
            "records": records,
        }

    except Exception as exc:
        return {
            "status": "error",
            "source": "RIPEstat",
            "source_url": url,
            "error": _error_message(exc),
            "records": [],
        }

def _get_certificate_history(ip: str) -> dict[str, Any]:
    """Search public Certificate Transparency records for an IP."""
    url = CRT_SH_URL + "?" + urllib.parse.urlencode(
        {
            "q": ip,
            "output": "json",
            "limit": MAX_CERTIFICATES,
        }
    )

    try:
        payload = _request_json(url)

        if not isinstance(payload, list):
            raise ValueError("Unexpected certificate search response")

        records = []
        seen = set()

        for certificate in payload:
            if not isinstance(certificate, dict):
                continue

            # crt.sh may return multiple rows associated with the same
            # certificate. Deduplicate by certificate ID where possible.
            certificate_id = certificate.get("id")
            identity = (
                str(certificate_id)
                if certificate_id is not None
                else json.dumps(certificate, sort_keys=True)
            )

            if identity in seen:
                continue
            seen.add(identity)

            records.append(
                {
                    "certificate_id": certificate_id,
                    "common_name": certificate.get("common_name"),
                    "names": certificate.get("name_value"),
                    "issuer": certificate.get("issuer_name"),
                    "not_before": certificate.get("not_before"),
                    "not_after": certificate.get("not_after"),
                    "serial_number": certificate.get("serial_number"),
                    "logged_at": certificate.get("entry_timestamp"),
                }
            )

            if len(records) >= MAX_CERTIFICATES:
                break

        return {
            "status": "success",
            "source": "crt.sh",
            "source_url": url,
            "record_count": len(records),
            "records_truncated": len(payload) >= MAX_CERTIFICATES,
            "records": records,
        }

    except Exception as exc:
        return {
            "status": "error",
            "source": "crt.sh",
            "source_url": url,
            "error": _error_message(exc),
            "records": [],
        }

def run(target: str) -> dict[str, Any]:
    """Collect historical public observations for an IP address."""
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "status": "error",
            "target": str(target),
            "error": "Invalid IP address",
        }

    ip = str(address)

    if not address.is_global:
        return {
            "status": "not_checked",
            "target": ip,
            "reason": "Historical lookups are skipped for non-global IPs",
            "sources": {},
        }

    routing = _get_routing_history(ip)
    certificates = _get_certificate_history(ip)

    sources = {
        "routing_history": routing,
        "certificate_transparency": certificates,
    }

    successful = sum(
        source["status"] == "success"
        for source in sources.values()
    )

    if successful == len(sources):
        status = "success"
    elif successful:
        status = "partial"
    else:
        status = "error"

    return {
        "status": status,
        "target": ip,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source_count": len(sources),
        "successful_sources": successful,
        "summary": {
            "routing_observations": routing.get("record_count", 0),
            "certificate_records": certificates.get("record_count", 0),
        },
        "sources": sources,
        "limitations": [
            "BGP history describes routing observations, not service availability.",
            "Historical routing does not establish who controlled an IP at a given time.",
            "Certificate records do not prove a certificate was deployed on this IP.",
            "Public-source coverage is incomplete; no results do not mean no history exists.",
        ],
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Collect public historical IP observations"
    )
    parser.add_argument("target", help="IPv4 or IPv6 address")
    args = parser.parse_args()

    print(json.dumps(run(args.target), indent=2))