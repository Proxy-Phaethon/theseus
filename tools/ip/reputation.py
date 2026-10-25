"""IP reputation intelligence using the public Outpost API.

Collects source-reported reputation indicators for public IPv4 addresses.
No API key or third-party Python package is required.

Reputation indicators are third-party assessments, not proof of malicious
activity. This module does not automatically block or report any address.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SOURCE_NAME = "Outpost IP Reputation"
API_BASE = "https://reputation.noc.org/api/"
TIMEOUT = 10

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _error(message: str, target: str | None = None) -> dict:
    result = {
        "module": "reputation",
        "status": "error",
        "source": SOURCE_NAME,
        "error": message,
        "observed_at": _now(),
    }

    if target is not None:
        result["target"] = target

    return result

def run(target: str) -> dict:
    """Collect reputation indicators for a public IPv4 address."""

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": "reputation",
            "status": "not_checked",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "reason": "Non-global IP addresses are not queried.",
            "observed_at": _now(),
        }

    if address.version != 4:
        return {
            "module": "reputation",
            "status": "not_checked",
            "target": normalized_ip,
            "source": SOURCE_NAME,
            "reason": "The selected reputation source supports IPv4 only.",
            "observed_at": _now(),
        }

    url = API_BASE + "?" + urlencode({"ip": normalized_ip})

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
            http_status = response.status
            payload = json.loads(response.read().decode("utf-8"))

    except HTTPError as exc:
        if exc.code == 429:
            message = "Source rate limit reached."
        else:
            message = f"Source returned HTTP {exc.code}."

        return _error(message, normalized_ip)

    except (URLError, TimeoutError, OSError) as exc:
        return _error(f"Source connection failed: {exc}", normalized_ip)

    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error("Source returned invalid JSON.", normalized_ip)

    if not isinstance(payload, dict):
        return _error("Source returned an unexpected response format.", normalized_ip)

    if payload.get("status") == "error":
        return _error(
            f"Source reported an error: {payload.get('reason', 'unknown error')}",
            normalized_ip,
        )

    returned_ip = payload.get("ip")

    if returned_ip != normalized_ip:
        return _error(
            "Source response IP did not match the requested address.",
            normalized_ip,
        )

    usage = payload.get("usage")
    reputation = payload.get("reputation")
    recommendations = payload.get("recommendations")

    if not isinstance(usage, dict):
        usage = {}

    if not isinstance(reputation, dict):
        reputation = {}

    if not isinstance(recommendations, dict):
        recommendations = {}

    flagged_indicators = [
        name for name, value in reputation.items() if value is True
    ]

    if flagged_indicators:
        assessment = "source_reports_positive_indicators"
    elif reputation and all(
        value is False for value in reputation.values()
    ):
        assessment = "no_positive_indicators_returned"
    else:
        assessment = "incomplete_or_unavailable_indicators"

    return {
        "module": "reputation",
        "status": "success",
        "target": normalized_ip,
        "source": SOURCE_NAME,
        "source_url": url,
        "http_status": http_status,
        "observed_at": _now(),
        "assessment": {
            "summary": assessment,
            "positive_indicators": flagged_indicators,
            "indicator_count": len(flagged_indicators),
        },
        "network": {
            "reverse_dns": payload.get("reverse"),
            "asn": payload.get("as_number"),
            "asn_name": payload.get("as_name"),
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
        },
        "usage": usage,
        "reputation": reputation,
        "source_recommendations": recommendations,
        "limitations": [
            "Indicators reflect this source's data and classification.",
            "A positive indicator is not proof of malicious activity.",
            "A negative result does not establish that an IP is safe.",
            "Shared addresses and reassigned IPs can complicate attribution.",
            "Source recommendations are recorded, not automatically applied.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Collect IP reputation intelligence."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    args = parser.parse_args()

    pprint(run(args.ip), sort_dicts=False)