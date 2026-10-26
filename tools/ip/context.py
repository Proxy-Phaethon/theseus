"""Aggregate contextual information from existing IP collectors.

This module combines existing collector observations into a concise,
structured context profile for the Theseus IP responder.

No network requests, API keys, or third-party packages are required.

Context is descriptive, not attribution. Geolocation, registration,
hosting classification, and organization labels have different meanings
and should not be treated as interchangeable.
"""

from __future__ import annotations

import ipaddress
from typing import Any

SUPPORTED_MODULES = (
    "classification",
    "rdap",
    "asn",
    "bgp",
    "geolocation",
    "reverse_dns",
    "hosting",
    "reputation",
    "reachability",
    "passive_dns",
    "tls",
    "http",
    "history",
)

SUCCESS_STATUSES = {"success", "partial"}

def _clean(value: Any) -> Any:
    """Convert empty or placeholder strings to None."""
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value or value.lower() in {
            "none",
            "null",
            "unknown",
            "n/a",
            "not available",
        }:
            return None

    return value

def _first(data: dict[str, Any], *keys: str) -> Any:
    """Return the first available non-empty value."""
    for key in keys:
        value = _clean(data.get(key))
        if value is not None:
            return value

    return None

def _module_data(
    observations: dict[str, Any],
    module_name: str,
) -> dict[str, Any]:
    """Return a usable result from a collector."""
    result = observations.get(module_name)

    if not isinstance(result, dict):
        return {}

    if result.get("status") not in SUCCESS_STATUSES:
        return {}

    return result

def _collect_fields(
    observations: dict[str, Any],
    module_name: str,
    fields: dict[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Extract a small set of normalized fields from a module."""
    result = _module_data(observations, module_name)
    extracted = {}

    for output_key, input_keys in fields.items():
        value = _first(result, *input_keys)

        if value is not None:
            extracted[output_key] = value

    return extracted

def _nested_fields(
    data: dict[str, Any],
    fields: dict[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Extract concise fields from one already-validated nested mapping."""
    extracted = {}

    for output_key, input_keys in fields.items():
        value = _first(data, *input_keys)
        if value is not None:
            extracted[output_key] = value

    return extracted

def _true_keys(value: Any) -> list[str]:
    """Return only source-reported positive boolean indicators."""
    if not isinstance(value, dict):
        return []

    return sorted(str(key) for key, item in value.items() if item is True)

def _source_outcomes(observations: dict[str, Any]) -> list[dict[str, str]]:
    """Keep lightweight provenance for supplied collector results."""
    outcomes = []

    for module_name in SUPPORTED_MODULES:
        result = observations.get(module_name)
        if isinstance(result, dict) and isinstance(result.get("status"), str):
            outcomes.append({
                "module": module_name,
                "raw_status": result["status"],
            })

    return outcomes

def _is_reverse_query_name(hostname: Any) -> bool:
    """Identify reverse-DNS query names, not resolved hostnames."""
    if not isinstance(hostname, str):
        return False

    normalized = hostname.strip().rstrip(".").lower()

    return (
        normalized.endswith(".in-addr.arpa")
        or normalized.endswith(".ip6.arpa")
    )

def _clean_hostnames(hostnames: Any) -> list[str]:
    """Filter reverse-query names and deduplicate hostnames."""
    if isinstance(hostnames, str):
        hostnames = [hostnames]

    if not isinstance(hostnames, list):
        return []

    cleaned = []
    seen = set()

    for item in hostnames:
        if isinstance(item, str):
            hostname = item
        elif isinstance(item, dict):
            hostname = _first(item, "hostname", "name", "value")
        else:
            continue

        if not isinstance(hostname, str):
            continue

        hostname = hostname.strip().rstrip(".")

        if not hostname or _is_reverse_query_name(hostname):
            continue

        key = hostname.lower()

        if key in seen:
            continue

        seen.add(key)
        cleaned.append(hostname)

    return cleaned

def run(
    target: str,
    observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a contextual profile for an IPv4 or IPv6 address.

    Args:
        target: The IP address under investigation.
        observations: Mapping of collector names to their results.

    Returns:
        A structured context profile for use by the IP responder.
    """
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "status": "error",
            "target": str(target),
            "error": "Invalid IP address",
        }

    ip = str(address)
    observations = observations or {}

    classification = _module_data(observations, "classification")
    rdap = _module_data(observations, "rdap")
    asn = _module_data(observations, "asn")
    bgp = _module_data(observations, "bgp")
    geo = _module_data(observations, "geolocation")
    reverse_dns = _module_data(observations, "reverse_dns")
    hosting = _module_data(observations, "hosting")
    reputation = _module_data(observations, "reputation")
    reachability = _module_data(observations, "reachability")
    passive_dns = _module_data(observations, "passive_dns")
    tls = _module_data(observations, "tls")
    http = _module_data(observations, "http")
    history = _module_data(observations, "history")

    address_context = {
        "ip_address": ip,
        "version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_unspecified": address.is_unspecified,
    }

    if classification:
        address_context["collector_classification"] = _first(
            classification,
            "classification",
            "primary_classification",
        )

    registration_context = _nested_fields(
        rdap.get("registration", {}) if isinstance(rdap, dict) else {},
        {
            "network_name": ("name", "network_name"),
            "network_handle": ("handle", "network_handle"),
            "network_type": ("type", "network_type"),
            "registration_country": ("country", "country_code"),
            "network_start": ("start_address", "start"),
            "network_end": ("end_address", "end"),
            "parent_network": ("parent_handle", "parent"),
            "cidr_prefixes": ("cidr_prefixes",),
        },
    )

    asn_context = _collect_fields(
        observations,
        "asn",
        {
            "asn": ("asn", "origin_asn"),
            "announced_prefix": ("prefix", "announced_prefix"),
            "country_code": ("country_code", "country"),
            "registry": ("registry",),
            "allocation_date": ("allocation_date", "date"),
            "asn_name": ("as_name", "name"),
        },
    )

    bgp_context = _collect_fields(
        observations,
        "bgp",
        {
            "announced_prefix": ("prefix",),
            "origin_asn": ("origin_asn", "asn"),
            "observation_count": ("observation_count", "total_observations"),
            "observations_truncated": ("observations_truncated",),
        },
    )

    geolocation_context = _collect_fields(
        observations,
        "geolocation",
        {
            "country": ("country",),
            "country_code": ("country_code",),
            "region": ("region",),
            "city": ("city",),
            "latitude": ("latitude", "lat"),
            "longitude": ("longitude", "lon"),
            "timezone": ("timezone",),
            "isp": ("isp",),
            "organization": ("org", "organization"),
            "geolocation_asn": ("asn",),
        },
    )

    hostnames = (
        reverse_dns.get("hostnames")
        or reverse_dns.get("hostnames_found")
        or reverse_dns.get("ptr_records")
        or []
    )

    hostname_context = {
        "hostnames": _clean_hostnames(hostnames),
    }

    hosting_context = _collect_fields(
        observations,
        "hosting",
        {
            "is_hosting": ("is_hosting",),
            "is_mobile": ("is_mobile",),
            "is_vpn": ("is_vpn",),
            "is_tor": ("is_tor",),
            "organization": ("organization", "org"),
            "network_range": ("network_range", "range"),
            "hosting_asn": ("asn",),
        },
    )

    reputation_context = {
        **_nested_fields(
            reputation.get("assessment", {}) if isinstance(reputation, dict) else {},
            {
                "source_assessment": ("summary",),
                "positive_indicators": ("positive_indicators",),
                "positive_indicator_count": ("indicator_count",),
            },
        ),
        **{
            f"network_{key}": value
            for key, value in _nested_fields(
                reputation.get("network", {}) if isinstance(reputation, dict) else {},
                {
                    "reverse_dns": ("reverse_dns",),
                    "asn": ("asn",),
                    "asn_name": ("asn_name",),
                    "country": ("country",),
                    "country_code": ("country_code",),
                },
            ).items()
        },
    }

    usage_indicators = _true_keys(reputation.get("usage"))
    source_indicators = _true_keys(reputation.get("reputation"))

    if usage_indicators:
        reputation_context["source_reported_usage_indicators"] = usage_indicators

    if source_indicators:
        reputation_context["source_reported_reputation_indicators"] = source_indicators

    passive_dns_context = _nested_fields(
        passive_dns,
        {
            "returned_record_count": ("result_count",),
            "source_record_count": ("source_count",),
            "output_truncated": ("truncated",),
        },
    )

    if passive_dns.get("hostnames"):
        passive_dns_context["historical_hostname_count"] = len(
            passive_dns["hostnames"]
        )

    tls_context = _nested_fields(
        tls,
        {"certificates_observed": ("certificates_observed",)},
    )

    if isinstance(tls.get("summary"), dict):
        tls_context["probe_outcomes"] = {
            str(key): value
            for key, value in tls["summary"].items()
            if isinstance(value, int)
        }

    http_context = _nested_fields(
        http,
        {},
    )

    responding_endpoints = http.get("responding_endpoints", [])

    if isinstance(responding_endpoints, list):
        http_context["responding_endpoint_count"] = len(responding_endpoints)
        http_context["response_statuses"] = [
            {
                "port": item.get("port"),
                "scheme": item.get("scheme"),
                "http_status": item.get("http_status"),
            }
            for item in responding_endpoints[:10]
            if isinstance(item, dict)
        ]

    historical_context = _nested_fields(
        history,
        {
            "successful_sources": ("successful_sources",),
            "source_count": ("source_count",),
        },
    )

    historical_context.update(_nested_fields(
        history.get("summary", {}) if isinstance(history, dict) else {},
        {
            "routing_observations": ("routing_observations",),
            "certificate_records": ("certificate_records",),
        },
    ))

    reachability_context = _collect_fields(
        observations,
        "reachability",
        {
            "assessment": ("assessment",),
            "icmp_responsive": ("icmp_responsive",),
            "tcp_responsive": ("tcp_responsive",),
        },
    )

    sections = {
        "address": address_context,
        "registration": registration_context,
        "routing": {
            "origin_asn": (
                bgp_context.get("origin_asn")
                or asn_context.get("asn")
            ),
            "announced_prefix": (
                bgp_context.get("announced_prefix")
                or asn_context.get("announced_prefix")
            ),
            "bgp_observation_count": bgp_context.get(
                "observation_count"
            ),
            "bgp_observations_truncated": bgp_context.get(
                "observations_truncated"
            ),
        },
        "geolocation": geolocation_context,
        "reverse_dns": hostname_context,
        "hosting": hosting_context,
        "reputation": reputation_context,
        "reachability": reachability_context,
        "passive_dns": passive_dns_context,
        "tls": tls_context,
        "http": http_context,
        "historical": historical_context,
    }

    section_sources = {
        "address": ["stdlib.ipaddress (derived)"],
        "registration": ["rdap"],
        "routing": ["bgp", "asn"],
        "geolocation": ["geolocation"],
        "reverse_dns": ["reverse_dns"],
        "hosting": ["hosting"],
        "reputation": ["reputation"],
        "reachability": ["reachability"],
        "passive_dns": ["passive_dns"],
        "tls": ["tls"],
        "http": ["http"],
        "historical": ["history"],
    }

    for section_name, section in sections.items():
        sections[section_name] = {
            key: value
            for key, value in section.items()
            if value is not None and value != "" and value != []
        }

    sections = {
        name: values
        for name, values in sections.items()
        if values
    }

    successful_modules = sorted(
        name
        for name in SUPPORTED_MODULES
        if _module_data(observations, name)
    )

    if _module_data(observations, "reachability"):
        successful_modules.append("reachability")

    return {
        "status": "success",
        "target": ip,
        "summary": {
            "context_sections": list(sections.keys()),
            "successful_modules": sorted(set(successful_modules)),
            "sections_populated": len(sections),
            "derived_sections": ["address"],
            "section_sources": {
                name: section_sources[name]
                for name in sections
            },
            "source_outcomes": _source_outcomes(observations),
        },
        "context": sections,
        "limitations": [
            "Registration country describes the allocation record, not necessarily the server's physical location.",
            "Geolocation is an estimate supplied by an external source.",
            "ASN and prefix observations describe routing context, not individual ownership.",
            "Hosting, VPN, mobile, and Tor classifications depend on their source's coverage and definitions.",
            "Reachability results reflect the tested ports and time of observation.",
            "Missing fields mean no usable observation was supplied, not that the property is absent.",
        ],
    }

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Aggregate contextual IP intelligence from collector results"
    )
    parser.add_argument("target", help="IPv4 or IPv6 address")
    parser.add_argument(
        "--input",
        help="Path to JSON mapping collector names to their results",
    )
    args = parser.parse_args()

    supplied_observations = {}

    if args.input:
        with open(args.input, "r", encoding="utf-8") as handle:
            supplied_observations = json.load(handle)

    print(
        json.dumps(
            run(args.target, supplied_observations),
            indent=2,
        )
    )