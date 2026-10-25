"""Passive DNS intelligence for IPv4 and IPv6 addresses.

Uses mnemonic's public PassiveDNS API to retrieve historical DNS records.

No API key or third-party Python package is required. Public queries are
subject to source rate limits and only return publicly accessible records.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

SOURCE_NAME = "mnemonic PassiveDNS"
API_BASE = "https://api.mnemonic.no/pdns/v3"
TIMEOUT = 15
RESULT_LIMIT = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _timestamp(value) -> str | None:
    """Convert a source Unix timestamp in milliseconds to UTC ISO format."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None

    try:
        return datetime.fromtimestamp(
            value / 1000,
            tz=timezone.utc,
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return None

def _error(message: str, target: str | None = None) -> dict:
    result = {
        "module": "passive_dns",
        "status": "error",
        "source": SOURCE_NAME,
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def _fetch(target: str) -> tuple[dict | None, dict]:
    """Query the public PassiveDNS API for an IP address."""

    encoded_target = quote(target, safe=":")
    query = urlencode({"limit": RESULT_LIMIT})
    url = f"{API_BASE}/{encoded_target}?{query}"

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
                return None, {
                    "status": "error",
                    "url": url,
                    "error": "Response exceeded the configured size limit.",
                }

            payload = json.loads(body.decode("utf-8"))

            return payload, {
                "status": "success",
                "url": url,
                "http_status": response.status,
                "retrieved_at": _now(),
                "bytes_received": len(body),
            }

    except HTTPError as exc:
        message = f"Source returned HTTP {exc.code}."

        if exc.code == 402:
            message = "Source resource limit reached."
        elif exc.code == 429:
            message = "Source rate limit reached."

        return None, {
            "status": "error",
            "url": url,
            "error": message,
        }

    except (URLError, TimeoutError, OSError) as exc:
        return None, {
            "status": "error",
            "url": url,
            "error": f"Connection failed: {exc}",
        }

    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, {
            "status": "error",
            "url": url,
            "error": "Source returned invalid JSON.",
        }

def _normalize_record(record: dict) -> dict:
    """Normalize a PassiveDNS record while retaining source observations."""

    return {
        "record_type": record.get("rrtype"),
        "record_class": record.get("rrclass"),
        "query": record.get("query"),
        "answer": record.get("answer"),
        "first_seen": _timestamp(record.get("firstSeenTimestamp")),
        "last_seen": _timestamp(record.get("lastSeenTimestamp")),
        "first_seen_timestamp": record.get("firstSeenTimestamp"),
        "last_seen_timestamp": record.get("lastSeenTimestamp"),
        "min_ttl": record.get("minTtl"),
        "max_ttl": record.get("maxTtl"),
        "observation_count": record.get("times"),
        "tlp": record.get("tlp"),
    }

def run(target: str) -> dict:
    """Retrieve historical DNS observations associated with an IP address."""

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": "passive_dns",
            "status": "not_checked",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "reason": "Non-global IP addresses are not queried.",
            "observed_at": _now(),
            "records": [],
        }

    payload, metadata = _fetch(normalized_ip)

    if payload is None:
        return {
            "module": "passive_dns",
            "status": "error",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "observed_at": _now(),
            "records": [],
            **metadata,
        }

    if not isinstance(payload, dict):
        return _error(
            "Source returned an unexpected response format.",
            normalized_ip,
        )

    response_code = payload.get("responseCode")

    if response_code != 200:
        messages = payload.get("messages", [])
        return {
            "module": "passive_dns",
            "status": "error",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "source_response_code": response_code,
            "source_messages": messages,
            "observed_at": _now(),
            "records": [],
            **metadata,
        }

    raw_records = payload.get("data")

    if not isinstance(raw_records, list):
        return _error(
            "Source returned an unexpected record format.",
            normalized_ip,
        )

    records = [
        _normalize_record(record)
        for record in raw_records
        if isinstance(record, dict)
    ]

    hostnames = set()

    for record in records:
        record_type = str(record.get("record_type") or "").upper()
        query_name = record.get("query")
        answer = record.get("answer")

        if record_type in {"A", "AAAA"} and isinstance(query_name, str):
            name = query_name.rstrip(".").lower()

            if name and name != normalized_ip:
                hostnames.add(name)

        # Some data sources can express a reverse-DNS relationship as PTR.
        if record_type == "PTR" and isinstance(answer, str):
            name = answer.rstrip(".").lower()

            if name and name != normalized_ip:
                hostnames.add(name)

    total_count = payload.get("count")
    result_limit = payload.get("limit", RESULT_LIMIT)

    return {
        "module": "passive_dns",
        "status": "success",
        "target": normalized_ip,
        "source": SOURCE_NAME,
        "source_url": metadata.get("url"),
        "http_status": metadata.get("http_status"),
        "observed_at": _now(),
        "result_count": len(records),
        "source_count": total_count,
        "result_limit": result_limit,
        "truncated": (
            isinstance(total_count, int)
            and isinstance(result_limit, int)
            and total_count >= result_limit
        ),
        "hostnames": sorted(hostnames),
        "records": records,
        "limitations": [
            "Records reflect the source's passive DNS visibility.",
            "Historical associations do not prove current DNS resolution.",
            "A domain sharing an IP does not establish common ownership.",
            "A lack of records does not mean an IP has no associated domains.",
            "Public queries may omit records unavailable to unauthenticated users.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Retrieve passive DNS records for an IP address."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)