"""
IP registration lookup for Theseus.

Discovers the authoritative RDAP service through IANA bootstrap data,
queries the network registration record, and returns structured results.

Uses Python's standard library. No API keys or third-party enrichment
services are required.
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}

TIMEOUT = 15
USER_AGENT = "Theseus-OSINT/1.0"

def _get_json(url: str) -> Any:
    """Fetch a JSON document over HTTPS."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": USER_AGENT,
        },
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))

def _find_rdap_base(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    bootstrap: dict[str, Any],
) -> str | None:
    """Find the most-specific matching RDAP service in bootstrap data."""
    matches: list[tuple[int, str]] = []

    for entry in bootstrap.get("services", []):
        if not isinstance(entry, list) or len(entry) != 2:
            continue

        prefixes, urls = entry

        if not isinstance(prefixes, list) or not isinstance(urls, list):
            continue

        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except (TypeError, ValueError):
                continue

            if network.version != address.version:
                continue

            if address in network:
                for base_url in urls:
                    if isinstance(base_url, str) and base_url.startswith("https://"):
                        matches.append((network.prefixlen, base_url))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]

def _extract_vcard_value(vcard: Any, field_name: str) -> str | None:
    """Extract a value from an RDAP vCard array."""
    if not isinstance(vcard, list):
        return None

    for field in vcard:
        if (
            isinstance(field, list)
            and len(field) >= 4
            and str(field[0]).casefold() == field_name.casefold()
        ):
            value = field[3]

            if isinstance(value, str) and value.strip():
                return value.strip()

            if isinstance(value, list):
                parts = [str(part) for part in value if part]
                if parts:
                    return " ".join(parts)

    return None

def _extract_contacts(entities: Any) -> list[dict[str, Any]]:
    """Extract publicly published contact information from RDAP entities."""
    contacts: list[dict[str, Any]] = []

    if not isinstance(entities, list):
        return contacts

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray")
        if not isinstance(roles, list):
            roles = []

        contact: dict[str, Any] = {
            "roles": roles,
            "handle": entity.get("handle"),
            "name": _extract_vcard_value(vcard[1], "fn")
            if isinstance(vcard, list) and len(vcard) > 1
            else None,
            "organization": _extract_vcard_value(vcard[1], "org")
            if isinstance(vcard, list) and len(vcard) > 1
            else None,
            "emails": [],
            "phones": [],
        }

        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1] if isinstance(vcard[1], list) else []:
                if not isinstance(field, list) or len(field) < 4:
                    continue

                field_name = str(field[0]).casefold()
                field_value = field[3]

                if field_name == "email" and isinstance(field_value, str):
                    contact["emails"].append(field_value)

                elif field_name == "tel":
                    if isinstance(field_value, str):
                        contact["phones"].append(field_value)
                    elif isinstance(field_value, dict):
                        contact["phones"].append(field_value.get("value"))

        nested = _extract_contacts(entity.get("entities"))
        contacts.extend(nested)

        if any(
            (
                contact["name"],
                contact["organization"],
                contact["emails"],
                contact["phones"],
                contact["handle"],
            )
        ):
            contacts.append(contact)

    return contacts

def _parse_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize commonly available RDAP network fields."""
    cidrs = []

    for item in record.get("cidr0_cidrs", []):
        if not isinstance(item, dict):
            continue

        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")

        if prefix is not None and length is not None:
            cidrs.append(f"{prefix}/{length}")

    events = []

    for event in record.get("events", []):
        if isinstance(event, dict):
            events.append(
                {
                    "action": event.get("eventAction"),
                    "date": event.get("eventDate"),
                }
            )

    return {
        "handle": record.get("handle"),
        "name": record.get("name"),
        "type": record.get("type"),
        "country": record.get("country"),
        "start_address": record.get("startAddress"),
        "end_address": record.get("endAddress"),
        "cidr_prefixes": cidrs,
        "parent_handle": record.get("parentHandle"),
        "status": record.get("status", []),
        "events": events,
        "remarks": record.get("remarks", []),
        "notices": record.get("notices", []),
        "links": [
            {
                "rel": link.get("rel"),
                "href": link.get("href"),
                "type": link.get("type"),
            }
            for link in record.get("links", [])
            if isinstance(link, dict)
        ],
        "contacts": _extract_contacts(record.get("entities")),
    }

def run(target: str) -> dict[str, Any]:
    """
    Retrieve the RDAP registration record for an IPv4 or IPv6 address.

    Returns structured data for Theseus. A missing record or failed request
    is not interpreted as proof that an address is unallocated.
    """
    observed_at = time.time()
    value = target.strip()

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return {
            "module": "rdap",
            "target": target,
            "status": "error",
            "error": "Target is not a valid IPv4 or IPv6 address",
            "observed_at": observed_at,
        }

    lookup_address = address
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        lookup_address = address.ipv4_mapped

    try:
        bootstrap = _get_json(BOOTSTRAP_URLS[lookup_address.version])

        if not isinstance(bootstrap, dict):
            raise ValueError("Unexpected IANA bootstrap response format")

        rdap_base = _find_rdap_base(lookup_address, bootstrap)

        if not rdap_base:
            return {
                "module": "rdap",
                "target": value,
                "lookup_address": str(lookup_address),
                "status": "unknown",
                "source": BOOTSTRAP_URLS[lookup_address.version],
                "observed_at": observed_at,
                "error": "No matching RDAP service found in IANA bootstrap data",
            }

        query_url = (
            rdap_base.rstrip("/")
            + "/ip/"
            + urllib.parse.quote(str(lookup_address), safe=":")
        )

        record = _get_json(query_url)

        if not isinstance(record, dict):
            raise ValueError("Unexpected RDAP response format")

        return {
            "module": "rdap",
            "target": value,
            "lookup_address": str(lookup_address),
            "status": "success",
            "source": query_url,
            "observed_at": time.time(),
            "registration": _parse_record(record),
        }

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            message = "RDAP service returned no record for this address"
            status = "not_found"
        elif exc.code == 429:
            message = "RDAP service rate limit reached"
            status = "error"
        else:
            message = f"RDAP service returned HTTP {exc.code}"
            status = "error"

        return {
            "module": "rdap",
            "target": value,
            "lookup_address": str(lookup_address),
            "status": status,
            "observed_at": time.time(),
            "error": message,
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        return {
            "module": "rdap",
            "target": value,
            "lookup_address": str(lookup_address),
            "status": "error",
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