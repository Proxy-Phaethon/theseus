"""IP threat-intelligence lookups against public abuse.ch feeds.

Sources:
- Feodo Tracker recommended botnet C2 IP list.
- SSL Blacklist (SSLBL) IP blacklist.

Uses only the Python standard library. No API key is required.

A match means that a source has listed the IP. It is not, by itself,
proof that the address is currently malicious.
"""

from __future__ import annotations

import csv
import ipaddress
import io
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SOURCE_NAME = "abuse.ch"

FEODO_URL = (
    "https://feodotracker.abuse.ch/downloads/"
    "ipblocklist_recommended.json"
)
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

TIMEOUT = 15
MAX_FEED_BYTES = 5 * 1024 * 1024

IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(\d{1,5}))?"
    r"(?![\d.])"
)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _error(message: str, target: str | None = None) -> dict:
    result = {
        "module": "threat_intel",
        "status": "error",
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def _fetch(url: str) -> tuple[bytes | None, dict]:
    """Fetch a feed and return its bytes plus source metadata."""

    request = Request(
        url,
        headers={
            "Accept": "application/json, text/csv, text/plain, */*",
            "User-Agent": "Theseus-OSINT/0.7",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            content_length = response.headers.get("Content-Length")

            if content_length:
                try:
                    if int(content_length) > MAX_FEED_BYTES:
                        return None, {
                            "status": "error",
                            "error": "Feed exceeds the configured size limit.",
                            "url": url,
                        }
                except ValueError:
                    pass

            body = response.read(MAX_FEED_BYTES + 1)

            if len(body) > MAX_FEED_BYTES:
                return None, {
                    "status": "error",
                    "error": "Feed exceeds the configured size limit.",
                    "url": url,
                }

            return body, {
                "status": "success",
                "url": url,
                "http_status": response.status,
                "retrieved_at": _now(),
                "bytes_received": len(body),
            }

    except HTTPError as exc:
        return None, {
            "status": "error",
            "url": url,
            "error": f"HTTP {exc.code}",
        }

    except (URLError, TimeoutError, OSError) as exc:
        return None, {
            "status": "error",
            "url": url,
            "error": f"Connection failed: {exc}",
        }

def _lookup_feodo(target: str) -> dict:
    """Match an IPv4 address against the recommended Feodo feed."""

    body, metadata = _fetch(FEODO_URL)

    if body is None:
        return {
            "source": "Feodo Tracker",
            **metadata,
            "matches": [],
        }

    try:
        records = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "source": "Feodo Tracker",
            "status": "error",
            "url": FEODO_URL,
            "error": "Feed returned invalid JSON.",
            "matches": [],
        }

    if not isinstance(records, list):
        return {
            "source": "Feodo Tracker",
            "status": "error",
            "url": FEODO_URL,
            "error": "Feed returned an unexpected format.",
            "matches": [],
        }

    matches = []

    for record in records:
        if not isinstance(record, dict):
            continue

        candidate = record.get("ip_address")

        try:
            normalized_candidate = str(ipaddress.ip_address(candidate))
        except (ValueError, TypeError):
            continue

        if normalized_candidate == target:
            matches.append({
                "indicator": normalized_candidate,
                "indicator_type": "ipv4",
                "threat_category": "botnet_command_and_control",
                "malware": record.get("malware"),
                "port": record.get("port"),
                "reported_status": record.get("status"),
                "hostname": record.get("hostname"),
                "asn": record.get("as_number"),
                "asn_name": record.get("as_name"),
                "country": record.get("country"),
                "first_seen": record.get("first_seen"),
                "last_online": record.get("last_online"),
            })

    return {
        "source": "Feodo Tracker",
        **metadata,
        "match_count": len(matches),
        "matches": matches,
    }

def _lookup_sslbl(target: str) -> dict:
    """Match an IPv4 address against the SSLBL IP blacklist."""

    body, metadata = _fetch(SSLBL_URL)

    if body is None:
        return {
            "source": "SSL Blacklist (SSLBL)",
            **metadata,
            "matches": [],
        }

    try:
        text = body.decode("utf-8", errors="replace")
        rows = csv.reader(io.StringIO(text))
        matches = []

        for row in rows:
            if not row:
                continue

            line = ",".join(row).strip()

            if not line or line.startswith("#"):
                continue

            for candidate, port in IPV4_PATTERN.findall(line):
                try:
                    normalized_candidate = str(
                        ipaddress.ip_address(candidate)
                    )
                except ValueError:
                    continue

                if normalized_candidate != target:
                    continue

                matches.append({
                    "indicator": normalized_candidate,
                    "indicator_type": "ipv4",
                    "port": int(port) if port else None,
                    "record": row,
                })
                break

        return {
            "source": "SSL Blacklist (SSLBL)",
            **metadata,
            "match_count": len(matches),
            "matches": matches,
        }

    except (csv.Error, ValueError) as exc:
        return {
            "source": "SSL Blacklist (SSLBL)",
            "status": "error",
            "url": SSLBL_URL,
            "error": f"Could not parse feed: {exc}",
            "matches": [],
        }

def run(target: str) -> dict:
    """Check a public IP address against supported threat-intel feeds."""

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": "threat_intel",
            "status": "not_checked",
            "target": normalized_ip,
            "reason": "Non-global IP addresses are not queried.",
            "observed_at": _now(),
            "sources": [],
        }

    if address.version != 4:
        return {
            "module": "threat_intel",
            "status": "not_checked",
            "target": normalized_ip,
            "reason": (
                "The configured Feodo Tracker and SSLBL IP feeds "
                "are being queried for IPv4 indicators only."
            ),
            "observed_at": _now(),
            "sources": [],
        }

    source_results = [
        _lookup_feodo(normalized_ip),
        _lookup_sslbl(normalized_ip),
    ]

    successful_sources = [
        source for source in source_results
        if source.get("status") == "success"
    ]

    failed_sources = [
        source for source in source_results
        if source.get("status") != "success"
    ]

    matches = []

    for source in successful_sources:
        for match in source.get("matches", []):
            matches.append({
                "source": source["source"],
                **match,
            })

    if not successful_sources:
        status = "error"
        assessment = "feeds_unavailable"
    elif matches:
        status = "success"
        assessment = "threat_indicators_found"
    elif failed_sources:
        status = "partial"
        assessment = "no_match_in_successful_feeds"
    else:
        status = "success"
        assessment = "no_match_in_feeds_checked"

    return {
        "module": "threat_intel",
        "status": status,
        "target": normalized_ip,
        "observed_at": _now(),
        "assessment": assessment,
        "match_count": len(matches),
        "matches": matches,
        "sources": source_results,
        "failed_source_count": len(failed_sources),
        "limitations": [
            "A feed match is an indicator, not proof of current malicious activity.",
            "Feed coverage is incomplete and changes over time.",
            "No match does not establish that an IP is benign.",
            "Historical or stale indicators may refer to a previous IP user.",
            "This module checks IPv4 indicators from two specific feeds only.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Check IP addresses against public threat-intelligence feeds."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)