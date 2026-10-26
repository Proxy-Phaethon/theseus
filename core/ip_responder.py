"""
IP investigation responder for Theseus.

Responsibilities:
- Format executor results into a readable terminal report.
- Surface useful registration, routing, exposure, and threat findings.
- Hide routine empty results while preserving meaningful warnings.
- Preserve the original investigation data without modification.

This module does not execute collectors.
"""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ui.panels import (
    print_message_panel,
    print_panel,
    print_summary_panel,
)

SLOW_COLLECTOR_SECONDS = 2.0
SLOWEST_COLLECTOR_LIMIT = 3

def _get(value: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)

def _collector_results(investigation: Any) -> dict[str, Any]:
    """Index collector results by their registered display names."""
    results: dict[str, Any] = {}

    for collector in _get(investigation, "collectors", []) or []:
        name = _get(collector, "name", "")
        if name:
            results[str(name)] = _get(collector, "result")

    return results

def _value(
    data: Any,
    *keys: str,
    default: Any = None,
) -> Any:
    """Return the first non-empty value found under candidate keys."""
    for key in keys:
        result = _get(data, key)
        if result is not None and result != "":
            return result
    return default

def _text(value: Any, default: str = "Not available") -> str:
    if value is None:
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, dict):
        return "Structured data available" if value else default

    if isinstance(value, (list, tuple, set)):
        if not value:
            return default
        if all(not isinstance(item, (dict, list, tuple, set)) for item in value):
            return ", ".join(_text(item) for item in value)
        return "Multiple observations available"

    rendered = " ".join(str(value).split())
    return rendered or default

def _compact(value: Any, limit: int = 110) -> str:
    rendered = _text(value)

    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"

    return rendered

def _join_scalars(value: Any, *, limit: int | None = None) -> str | None:
    """Render a scalar or scalar collection without exposing Python reprs."""
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value if item is not None and item != ""]
        if not values:
            return None
        rendered = ", ".join(values)
    elif isinstance(value, dict):
        return None
    else:
        rendered = str(value)
    return _compact(rendered, limit) if limit else rendered

def _distinguished_name(value: Any) -> str | None:
    """Render the TLS collector's structured X.509 name fields."""
    if not isinstance(value, list):
        return None
    values = [
        str(item.get("value"))
        for item in value
        if isinstance(item, dict) and item.get("value")
    ]
    return ", ".join(values) if values else None

def _field_pairs(value: Any) -> str | None:
    """Render source-reported boolean/scalar indicators readably."""
    if not isinstance(value, dict):
        return _join_scalars(value)
    pairs = []
    for key, item in value.items():
        if isinstance(item, (str, int, float, bool)):
            pairs.append(f"{key}: {_text(item)}")
    return ", ".join(pairs) if pairs else None

def _status_label(value: Any) -> str:
    if not value:
        return "Unknown"

    return str(value).replace("_", " ").capitalize()

def _is_success(data: Any) -> bool:
    return _get(data, "status") in {"success", "partial", "found"}

def _has_content(data: Any) -> bool:
    """Check whether a result contains substantive data."""
    if not isinstance(data, dict):
        return data is not None

    ignored = {
        "module",
        "target",
        "input",
        "status",
        "error",
        "message",
        "source",
        "duration_seconds",
    }

    for key, value in data.items():
        if key in ignored or value is None:
            continue

        if value == "" or value == [] or value == {}:
            continue

        return True

    return False

def _print_table(
    console: Console,
    title: str,
    columns: list[str],
    rows: list[list[str]],
    *,
    border_style: str = "border",
) -> None:
    """Print a consistently styled table inside a Theseus panel."""
    if not rows:
        return

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="heading",
        border_style=border_style,
        expand=True,
        padding=(0, 1),
    )

    for column in columns:
        table.add_column(column, overflow="fold")

    for row in rows:
        table.add_row(*row)

    print_panel(
        console,
        table,
        title=title,
        border_style=border_style,
        padding=(0, 1),
    )

def _print_observations(
    console: Console,
    title: str,
    data: Any,
    fields: list[tuple[str, tuple[str, ...]]],
    *,
    border_style: str = "border",
) -> None:
    """Display selected fields from a collector result."""
    if not isinstance(data, dict):
        if data is None:
            return

    rows = []

    for label, candidates in fields:
        value = _value(data, *candidates)

        if value is None:
            continue

        if isinstance(value, (dict, list, tuple, set)) and not value:
            continue

        rows.append([label, _compact(value)])

    if rows:
        _print_table(
            console,
            title,
            ["Field", "Observation"],
            rows,
            border_style=border_style,
        )

def _print_overview(
    console: Console,
    investigation: Any,
    results: dict[str, Any],
) -> None:
    normalizer = _get(_get(investigation, "normalizer"), "result")
    classification = results.get("IP classification") or normalizer

    target = (
        _get(investigation, "normalized_target")
        or _get(investigation, "original_target", "Unknown")
    )

    fields = [
        ("IP address", str(target)),
        (
            "Address family",
            _text(_value(classification, "version", "address_family")),
        ),
        (
            "Classification",
            _text(_value(classification, "classification")),
        ),
        (
            "Globally routable",
            _text(_value(classification, "is_global")),
        ),
        (
            "Private",
            _text(_value(classification, "is_private")),
        ),
        (
            "Loopback",
            _text(_value(classification, "is_loopback")),
        ),
        (
            "Link-local",
            _text(_value(classification, "is_link_local")),
        ),
        (
            "Reserved",
            _text(_value(classification, "is_reserved")),
        ),
    ]

    print_summary_panel(
        console,
        "IP Overview",
        fields,
        status=(
            "success"
            if _get(classification, "status") == "success"
            else "warning"
        ),
    )

def _print_registration_and_routing(
    console: Console,
    results: dict[str, Any],
) -> None:
    rdap = results.get("RDAP lookup")
    asn = results.get("ASN lookup")
    bgp = results.get("BGP intelligence")

    registration = _get(rdap, "registration", {})
    if isinstance(registration, dict):
        rows = []
        for label, value in [
            ("Network name", registration.get("name")),
            ("Network handle", registration.get("handle")),
            ("Network type", registration.get("type")),
            ("Country", registration.get("country")),
            ("Start address", registration.get("start_address")),
            ("End address", registration.get("end_address")),
            ("CIDR prefixes", _join_scalars(registration.get("cidr_prefixes"))),
            ("Parent handle", registration.get("parent_handle")),
            ("Registration status", _join_scalars(registration.get("status"))),
        ]:
            rendered = _join_scalars(value)
            if rendered:
                rows.append([label, rendered])
        _print_table(console, "IP Registration / RDAP", ["Field", "Observation"], rows)

        events = registration.get("events", [])
        if isinstance(events, list) and events:
            _print_table(
                console,
                "RDAP Registration Events",
                ["Action", "Date"],
                [[_text(_get(event, "action")), _text(_get(event, "date"))]
                 for event in events if isinstance(event, dict)],
            )

        contacts = registration.get("contacts", [])
        if isinstance(contacts, list) and contacts:
            _print_table(
                console,
                "RDAP Contacts",
                ["Role", "Name", "Organization"],
                [[
                    _join_scalars(_get(contact, "roles")) or "Not available",
                    _text(_get(contact, "name")),
                    _text(_get(contact, "organization")),
                ] for contact in contacts if isinstance(contact, dict)],
            )

    _print_observations(
        console,
        "ASN / Origin Network",
        asn,
        [
            ("ASN", ("asn", "origin_asn")),
            ("Announced prefix", ("prefix", "announced_prefix")),
            ("Country code", ("country_code", "country")),
            ("Registry", ("registry",)),
            ("Allocation date", ("allocation_date",)),
            ("ASN name", ("as_name", "name")),
        ],
    )

    _print_observations(
        console,
        "BGP Routing",
        bgp,
        [
            ("Prefix", ("prefix",)),
            ("Origin ASN", ("origin_asn", "asn")),
            ("Observations", ("observation_count", "total_observations")),
            ("Returned observations", ("returned_observations",)),
            ("Sample paths", ("paths", "observations")),
            ("Truncated", ("observations_truncated",)),
        ],
    )

def _print_geolocation_and_hosting(
    console: Console,
    results: dict[str, Any],
) -> None:
    geo = results.get("Geolocation")
    hosting = results.get("Hosting classification")
    rdns = results.get("Reverse DNS")

    _print_observations(
        console,
        "Estimated Geolocation",
        geo,
        [
            ("Country", ("country",)),
            ("Country code", ("country_code",)),
            ("Region", ("region",)),
            ("City", ("city",)),
            ("Postal code", ("postal", "postal_code")),
            ("Coordinates", ("latitude", "lat")),
            ("Longitude", ("longitude", "lon")),
            ("ISP", ("isp",)),
            ("Organization", ("org", "organization")),
            ("ASN", ("asn",)),
            ("Domain", ("domain",)),
        ],
    )

    _print_observations(
        console,
        "Hosting Classification",
        hosting,
        [
            ("Organization", ("organization", "org")),
            ("ASN", ("asn",)),
            ("Network range", ("network_range", "range")),
            ("Reverse DNS", ("reverse_dns", "hostname")),
            ("Hosting", ("is_hosting",)),
            ("Mobile", ("is_mobile",)),
            ("VPN", ("is_vpn",)),
            ("Tor", ("is_tor",)),
            ("Classification", ("classification", "category")),
        ],
    )

    if isinstance(rdns, dict):
        hostnames = _value(rdns, "hostnames", "hostnames_found", default=[])
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        hostnames = [
            hostname for hostname in hostnames
            if isinstance(hostname, str)
            and not hostname.rstrip(".").lower().endswith((".in-addr.arpa", ".ip6.arpa"))
        ]

        if hostnames:
            rows = [[_compact(hostname, 180)] for hostname in hostnames]
            _print_table(
                console,
                "Reverse DNS Names",
                ["Hostname"],
                rows,
            )
        elif rdns.get("status") == "not_found":
            print_message_panel(
                console,
                "The resolver returned no PTR record. This is an absence of a reverse-DNS observation, not a safety assessment.",
                title="Reverse DNS",
                status="info",
            )

def _print_network_exposure(
    console: Console,
    results: dict[str, Any],
) -> None:
    ports = results.get("Port scanner")
    services = results.get("Service detection")
    http = results.get("HTTP intelligence")
    tls = results.get("TLS intelligence")
    mail = results.get("Mail infrastructure")
    reachability = results.get("Reachability")

    if isinstance(ports, dict):
        summary = _value(ports, "summary", default={}) or {}
        open_ports = _value(ports, "open_ports", default=[]) or []

        _print_observations(
            console,
            "Port Scan Summary",
            summary if summary else ports,
            [
                ("Open ports", ("open", "open_ports", "open_count")),
                ("Closed ports", ("closed", "closed_count")),
                ("No response", ("no_response", "no_response_count")),
                ("Errors", ("errors", "error_count")),
            ],
        )

        if open_ports:
            rows = []

            for item in open_ports:
                if isinstance(item, dict):
                    rows.append([
                        _text(_value(item, "port")),
                        _text(_value(item, "service", "name")),
                        _text(_value(item, "status"), "Open"),
                    ])
                else:
                    rows.append([_text(item), "Unknown", "Open"])

            _print_table(
                console,
                "Open TCP Ports",
                ["Port", "Service", "Status"],
                rows,
                border_style="success",
            )

        if not open_ports and _is_success(ports):
            print_message_panel(
                console,
                "No open ports were identified in the scanned port set. "
                "This is not a complete assessment of all ports.",
                title="Port Scan",
                status="info",
            )

    if isinstance(services, dict):
        service_items = services.get("identified_services", []) or []

        if isinstance(service_items, list) and service_items:
            rows = []

            for item in service_items:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(_value(item, "port")),
                    _text(_value(item, "protocol", "service_guess")),
                    _text(_value(item, "service_guess")),
                    _compact(_value(item, "evidence")),
                ])

            _print_table(
                console,
                "Service Detection",
                ["Port", "Protocol", "Service guess", "Evidence"],
                rows,
            )

        probe_failures = [
            item for item in services.get("results", []) or []
            if isinstance(item, dict) and item.get("status") not in {
                "identified", "connected_unidentified"
            }
        ]
        if probe_failures:
            _print_table(
                console,
                "Service Probe Outcomes",
                ["Port", "Service guess", "Probe status", "Detail"],
                [[
                    _text(item.get("port")),
                    _text(item.get("service_guess")),
                    _status_label(item.get("status")),
                    _compact(_value(item, "error", "reason")),
                ] for item in probe_failures],
                border_style="warning",
            )

    if isinstance(tls, dict):
        certificates = tls.get("certificates", []) or []

        if isinstance(certificates, list) and certificates:
            rows = []

            for item in certificates:
                if not isinstance(item, dict):
                    continue
                cert = item.get("certificate", {})
                if not isinstance(cert, dict):
                    continue
                validity = cert.get("validity", {})
                verification = item.get("certificate_verification", {})
                fingerprints = cert.get("fingerprints", {})

                rows.append([
                    _text(item.get("port")),
                    _compact(_join_scalars(cert.get("subject_common_names")) or _distinguished_name(cert.get("subject"))),
                    _compact(_distinguished_name(cert.get("issuer"))),
                    _text(_get(validity, "not_after")),
                    _text(_get(validity, "days_until_expiry")),
                    _compact(_get(fingerprints, "sha256"), 22),
                    _status_label(_get(verification, "status")),
                ])

            _print_table(
                console,
                "TLS Certificates",
                ["Port", "Subject", "Issuer", "Expires", "Days", "SHA-256", "Verification"],
                rows,
            )
        tls_failures = [
            item for item in tls.get("results", []) or []
            if isinstance(item, dict) and item.get("status") != "success"
        ]
        if tls_failures:
            _print_table(
                console,
                "TLS Probe Outcomes",
                ["Port", "Service guess", "Probe status", "Detail"],
                [[
                    _text(item.get("port")),
                    _text(item.get("service_guess")),
                    _status_label(item.get("status")),
                    _compact(_get(item.get("error"), "message") or item.get("error")),
                ] for item in tls_failures],
                border_style="warning",
            )

    if isinstance(http, dict):
        http_items = http.get("responding_endpoints", []) or []

        if isinstance(http_items, list) and http_items:
            rows = []

            for item in http_items:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(item.get("port")),
                    _text(item.get("scheme")),
                    _text(item.get("http_status")),
                    _compact(_get(item.get("headers"), "server")),
                    _compact(_get(item.get("redirect"), "location")),
                ])

            _print_table(
                console,
                "HTTP Responses",
                ["Port", "Scheme", "HTTP status", "Server", "Redirect"],
                rows,
            )
        for item in http.get("results", []) or []:
            if not isinstance(item, dict) or item.get("status") != "success":
                continue
            security = item.get("security_headers", {})
            present = _get(security, "present", {})
            technology = item.get("technology_indicators", [])
            detail_rows = []
            if isinstance(present, dict) and present:
                detail_rows.append(["Security headers observed", _join_scalars(list(present)) or "Not available"])
            if isinstance(technology, list) and technology:
                detail_rows.append(["Technology indicators", _join_scalars([
                    _get(indicator, "value") for indicator in technology if isinstance(indicator, dict)
                ]) or "Not available"])
            if detail_rows:
                _print_table(console, f"HTTP Details: port {item.get('port')}", ["Observation", "Value"], detail_rows)
        http_failures = [
            item for item in http.get("results", []) or []
            if isinstance(item, dict) and item.get("status") != "success"
        ]
        if http_failures:
            _print_table(
                console,
                "HTTP Probe Outcomes",
                ["Port", "Scheme", "Probe status", "Detail"],
                [[
                    _text(item.get("port")), _text(item.get("scheme")),
                    _status_label(item.get("status")),
                    _compact(_get(item.get("error"), "message") or item.get("error")),
                ] for item in http_failures], border_style="warning",
            )

    if isinstance(mail, dict):
        mail_items = _value(
            mail,
            "servers",
            "results",
            "observations",
            default=[],
        ) or []

        if isinstance(mail_items, list) and mail_items:
            rows = []

            for item in mail_items:
                if not isinstance(item, dict):
                    continue

                extensions = _value(
                    item,
                    "extensions",
                    "capabilities",
                    default=[],
                ) or []

                rows.append([
                    _text(_value(item, "port")),
                    _text(_value(item, "status")),
                    _text(_value(item, "starttls", "starttls_available")),
                    _compact(", ".join(map(str, extensions)) if extensions else None),
                ])

            _print_table(
                console,
                "Mail Infrastructure",
                ["Port", "Status", "STARTTLS", "Advertised capabilities"],
                rows,
            )
        elif _has_content(mail):
            _print_observations(
                console,
                "Mail Infrastructure",
                mail,
                [
                    ("Ports checked", ("ports_checked",)),
                    ("SMTP responses", ("response_count",)),
                    ("STARTTLS available", ("starttls_available",)),
                ],
            )

    if isinstance(reachability, dict):
        _print_observations(
            console,
            "Reachability",
            reachability,
            [
                ("Assessment", ("assessment",)),
                ("ICMP status", ("icmp_status",)),
                ("ICMP latency", ("latency_ms", "icmp_latency_ms")),
                ("Responsive TCP ports", ("responsive_ports",)),
            ],
        )

def _print_reputation_and_threats(
    console: Console,
    results: dict[str, Any],
) -> None:
    reputation = results.get("IP reputation")
    threat = results.get("Threat intelligence")

    if isinstance(reputation, dict):
        assessment = reputation.get("assessment", {})
        network = reputation.get("network", {})
        rows = []
        for label, value in [
            ("Assessment", _get(assessment, "summary")),
            ("Positive indicators", _join_scalars(_get(assessment, "positive_indicators"))),
            ("Indicator count", _get(assessment, "indicator_count")),
            ("Reverse DNS", _get(network, "reverse_dns")),
            ("ASN", _get(network, "asn")),
            ("ASN name", _get(network, "asn_name")),
            ("Country", _get(network, "country")),
            ("Usage", _field_pairs(reputation.get("usage"))),
            ("Source indicators", _field_pairs(reputation.get("reputation"))),
            ("Source recommendations", _field_pairs(reputation.get("source_recommendations"))),
        ]:
            rendered = _join_scalars(value)
            if rendered:
                rows.append([label, rendered])
        _print_table(console, "IP Reputation", ["Field", "Source observation"], rows, border_style="warning")

    if isinstance(threat, dict):
        _print_observations(
            console,
            "Threat Intelligence Summary",
            threat,
            [
                ("Assessment", ("assessment",)),
                ("Matches", ("match_count",)),
                ("Source status", ("status",)),
            ],
            border_style="warning",
        )

        sources = _value(threat, "sources", "results", default=[])
        if isinstance(sources, dict):
            rows = [
                [
                    str(name),
                    _status_label(_get(item, "status")),
                    _compact(_value(item, "match", "matches", "message")),
                ]
                for name, item in sources.items()
            ]
            _print_table(
                console,
                "Threat Feed Results",
                ["Source", "Status", "Finding"],
                rows,
                border_style="warning",
            )
        elif isinstance(sources, list) and sources:
            rows = []

            for item in sources:
                if isinstance(item, dict):
                    rows.append([
                        _text(_value(item, "source", "name")),
                        _status_label(_get(item, "status")),
                        _compact(_value(item, "match", "matches", "message")),
                    ])

            _print_table(
                console,
                "Threat Feed Results",
                ["Source", "Status", "Finding"],
                rows,
                border_style="warning",
            )

        matches = _value(threat, "matches", "records", default=[])
        if isinstance(matches, list) and matches:
            rows = []

            for item in matches:
                if isinstance(item, dict):
                    rows.append([
                        _text(_value(item, "source")),
                        _compact(_value(item, "threat", "family", "name", "type")),
                        _compact(_value(item, "date", "first_seen", "last_seen")),
                    ])
                else:
                    rows.append(["Unknown", _compact(item), "Unknown"])

            _print_table(
                console,
                "Threat Intelligence Matches",
                ["Source", "Threat / Record", "Date"],
                rows,
                border_style="warning",
            )

    if reputation is None and threat is None:
        return

    print_message_panel(
        console,
        "Reputation and threat-feed results describe the sources queried "
        "and their coverage. No match does not establish that an IP is safe.",
        title="Threat Intelligence Note",
        status="info",
    )

def _print_dns_and_history(
    console: Console,
    results: dict[str, Any],
) -> None:
    passive_dns = results.get("Passive DNS")
    history = results.get("Historical intelligence")

    if isinstance(passive_dns, dict):
        records = _value(
            passive_dns,
            "records",
            "observations",
            default=[],
        ) or []

        if isinstance(records, list) and records:
            rows = []

            for item in records[:10]:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(_value(item, "query", "hostname", "name")),
                    _text(_value(item, "type", "record_type")),
                    _compact(_value(item, "answer", "value", "rdata")),
                    _text(_value(item, "first_seen", "timestamp", "time")),
                    _text(_value(item, "last_seen")),
                ])

            _print_table(
                console,
                "Passive DNS Records",
                ["Query / Hostname", "Type", "Answer", "First seen", "Last seen"],
                rows,
            )

        if _has_content(passive_dns):
            _print_observations(
                console,
                "Passive DNS",
                passive_dns,
                [
                    ("Returned records", ("result_count",)),
                    ("Source record count", ("source_count",)),
                    ("Output truncated", ("truncated",)),
                ],
            )

        if records:
            print_message_panel(
                console,
                "Passive DNS entries are historical source observations. They do not establish current resolution, ownership, or maliciousness.",
                title="Passive DNS Note",
                status="info",
            )

    if isinstance(history, dict):
        sources = _value(history, "sources", "results", default={})

        if isinstance(sources, dict):
            rows = []

            for name, item in sources.items():
                if isinstance(item, dict):
                    count = _value(
                        item,
                        "record_count",
                        "count",
                        default="Unknown",
                    )
                    rows.append([
                        str(name),
                        _status_label(_get(item, "status")),
                        str(count),
                        _compact(_value(item, "error", "message")),
                    ])

            _print_table(
                console,
                "Historical Intelligence Sources",
                ["Source", "Status", "Records", "Notes"],
                rows,
            )

            for name, item in sources.items():
                if not isinstance(item, dict) or item.get("status") != "success":
                    continue
                source_records = item.get("records", [])
                if not isinstance(source_records, list) or not source_records:
                    continue
                if name == "routing_history":
                    rows = [[
                        _text(record.get("origin")), _text(record.get("prefix")),
                        _text(record.get("start_time")), _text(record.get("end_time")),
                    ] for record in source_records[:10] if isinstance(record, dict)]
                    _print_table(console, "Historical Routing Observations", ["Origin", "Prefix", "Start", "End"], rows)
                elif name == "certificate_transparency":
                    rows = [[
                        _text(record.get("common_name")), _compact(record.get("issuer")),
                        _text(record.get("not_after")),
                    ] for record in source_records[:10] if isinstance(record, dict)]
                    _print_table(console, "Historical Certificate Transparency", ["Common name", "Issuer", "Expires"], rows)

        records = _value(history, "records", "observations", default=[])
        if isinstance(records, list) and records:
            rows = []

            for item in records:
                if isinstance(item, dict):
                    rows.append([
                        _text(_value(item, "source")),
                        _compact(_value(item, "type", "event", "name")),
                        _compact(_value(item, "value", "prefix", "hostname")),
                        _text(_value(item, "timestamp", "date", "first_seen")),
                    ])

            _print_table(
                console,
                "Historical Observations",
                ["Source", "Type", "Observation", "Date"],
                rows,
            )

def _print_analysis(
    console: Console,
    results: dict[str, Any],
) -> None:
    vulnerabilities = results.get("Vulnerability intelligence")
    relationships = results.get("Relationship analysis")
    context = results.get("Context aggregation")

    if isinstance(vulnerabilities, dict):
        candidates = vulnerabilities.get("software_candidates", []) or []
        if candidates:
            _print_table(console, "Observed Software Candidates", ["Product", "Version", "Evidence source", "Evidence"], [
                [_text(item.get("product")), _text(item.get("version")), _text(item.get("evidence_source")), _compact(item.get("evidence_value"))]
                for item in candidates if isinstance(item, dict)
            ])

        kev_matches = vulnerabilities.get("kev_matches", []) or []
        if kev_matches:
            _print_table(console, "Potential KEV Product-Level Correlations", ["CVE", "Product", "Name", "Added"], [
                [_text(item.get("cve_id")), _text(item.get("product")), _compact(item.get("name")), _text(item.get("date_added"))]
                for item in kev_matches if isinstance(item, dict)
            ], border_style="warning")

        nvd = _get(vulnerabilities.get("sources", {}), "nvd", []) or []
        if isinstance(nvd, list):
            _print_table(console, "Potential NVD Keyword Matches", ["Query", "Source status", "Candidates", "Note"], [
                [_text(item.get("query")), _status_label(item.get("status")), _text(len(item.get("vulnerabilities", []) or [])), _compact(item.get("error"))]
                for item in nvd if isinstance(item, dict)
            ], border_style="warning")

        evidence = vulnerabilities.get("evidence", []) or []
        if evidence:
            _print_table(console, "Vulnerability Correlation Evidence", ["Source", "Field", "Observed value"], [
                [_text(item.get("source")), _text(item.get("field")), _compact(item.get("value"))]
                for item in evidence if isinstance(item, dict)
            ])

        limitations = _join_scalars(vulnerabilities.get("limitations"))
        if limitations:
            print_message_panel(
                console,
                limitations,
                title="Vulnerability Correlation Limitations",
                status="info",
            )

        print_message_panel(
            console,
            "These are software candidates and source correlations, not confirmed vulnerabilities on this IP. Vendor affected-version analysis is required.",
            title="Vulnerability Correlation Note",
            status="info",
        )

    if isinstance(relationships, dict):
        nodes = _value(relationships, "nodes", default=[]) or []
        edges = _value(relationships, "edges", default=[]) or []

        if nodes or edges:
            _print_observations(
                console,
                "Relationship Analysis",
                {
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                },
                [
                    ("Nodes", ("node_count",)),
                    ("Relationships", ("edge_count",)),
                ],
            )

            rows = []

            for edge in edges:
                if not isinstance(edge, dict):
                    continue

                rows.append([
                    _compact(_value(edge, "source", "from")),
                    _text(_value(edge, "relationship", "type", "label")),
                    _compact(_value(edge, "target", "to")),
                    _compact(_value(edge, "evidence", "source_module")),
                ])

            _print_table(
                console,
                "Observed Relationships",
                ["From", "Relationship", "To", "Evidence"],
                rows,
            )

    if isinstance(context, dict):
        sections = context.get("context", {})
        if isinstance(sections, dict):
            for name, section in sections.items():
                if not isinstance(section, dict):
                    continue
                rows = []
                for key, value in section.items():
                    rendered = _field_pairs(value)
                    if rendered:
                        rows.append([key.replace("_", " ").capitalize(), _compact(rendered)])
                _print_table(console, f"Context: {name.replace('_', ' ').title()}", ["Field", "Observation"], rows)

def _print_collector_warnings(
    console: Console,
    investigation: Any,
) -> None:
    """Show collectors that failed or returned their own error status."""
    collectors = _get(investigation, "collectors", []) or []
    rows = []

    for collector in collectors:
        name = _get(collector, "name", "Unknown collector")
        execution_status = _get(collector, "status", "unknown")
        result = _get(collector, "result")
        result_status = _get(result, "status")

        if execution_status == "error":
            detail = _get(collector, "error") or _get(result, "error")
            rows.append([
                str(name),
                "Execution error",
                _compact(detail),
            ])
        elif result_status == "error":
            rows.append([
                str(name),
                "Source error",
                _compact(_get(result, "error", "Source returned an error")),
            ])
        elif result_status in {"partial", "not_checked", "skipped"}:
            rows.append([
                str(name),
                _status_label(result_status),
                _compact(_value(result, "reason", "message", "error")),
            ])

    if rows:
        _print_table(
            console,
            "Collector Warnings",
            ["Collector", "Status", "Details"],
            rows,
            border_style="warning",
        )


def _print_investigation_metadata(
    console: Console,
    investigation: Any,
) -> None:
    status = _get(investigation, "status", "unknown")
    duration = _get(investigation, "duration_seconds", 0)
    completed = _get(investigation, "completed_count", 0)
    failed = _get(investigation, "failed_count", 0)
    errors = _get(investigation, "errors", []) or []

    print_summary_panel(
        console,
        "Investigation Summary",
        [
            ("Execution status", _status_label(status)),
            ("Collectors completed", str(completed)),
            ("Collector errors", str(failed)),
            (
                "Elapsed",
                f"{duration:.2f} seconds"
                if isinstance(duration, (int, float))
                else str(duration),
            ),
        ],
        status=(
            "success" if status == "success"
            else "warning" if status == "partial"
            else "error" if status == "error"
            else "info"
        ),
    )

    # Read timing metadata without modifying the original results.
    collectors = _get(investigation, "collectors", []) or []
    timed_components = []

    for component in collectors:
        component_duration = _get(
            component, "duration_seconds", None
        )

        if (
            isinstance(component_duration, (int, float))
            and not isinstance(component_duration, bool)
            and component_duration >= 0
        ):
            timed_components.append(
                (
                    float(component_duration),
                    str(_get(component, "name", "Unknown component")),
                    str(_get(component, "status", "unknown")),
                )
            )

    timed_components.sort(key=lambda item: item[0], reverse=True)

    if timed_components:
        performance_text = Table(
            box=None,
            show_header=True,
            header_style="heading",
            expand=True,
        )
        performance_text.add_column("Component", ratio=3)
        performance_text.add_column(
            "Duration", justify="right", ratio=1
        )
        performance_text.add_column("Status", ratio=1)

        for component_duration, name, component_status in (
            timed_components[:5]
        ):
            performance_text.add_row(
                name,
                f"{component_duration:.2f} s",
                _status_label(component_status),
            )

        print_panel(
            console,
            performance_text,
            title=(
                "Slowest Components "
                f"({len(timed_components)} timed)"
            ),
            border_style="info",
            padding=(0, 1),
        )

    if errors:
        error_text = Text()

        for index, error in enumerate(errors):
            if index:
                error_text.append("\n")

            error_text.append("• ", style="warning")
            error_text.append(str(error), style="text")

        print_panel(
            console,
            error_text,
            title="Execution Notes",
            border_style="warning",
            padding=(0, 1),
        )

def _print_collector_timing(
    console: Console,
    investigation: Any,
) -> None:
    """Show the slowest measured collector invocations when available."""
    timings = []

    for collector in _get(investigation, "collectors", []) or []:
        duration = _get(collector, "duration_seconds")
        if not isinstance(duration, (int, float)) or duration < 0:
            continue

        timings.append((
            float(duration),
            str(_get(collector, "name", "Unknown collector")),
            _status_label(_get(collector, "status", "unknown")),
        ))

    if not timings:
        return

    timings.sort(key=lambda item: item[0], reverse=True)
    slowest = timings[:SLOWEST_COLLECTOR_LIMIT]
    _print_table(
        console,
        "Slowest Collector Operations",
        ["Collector", "Status", "Elapsed"],
        [[name, status, f"{duration:.2f} seconds"]
         for duration, name, status in slowest],
        border_style=(
            "warning"
            if any(duration >= SLOW_COLLECTOR_SECONDS for duration, _, _ in slowest)
            else "border"
        ),
    )

    unusually_slow = [
        f"{name} ({duration:.2f}s)"
        for duration, name, _ in timings
        if duration >= SLOW_COLLECTOR_SECONDS
    ]
    if unusually_slow:
        print_message_panel(
            console,
            "Measured collector duration exceeded "
            f"{SLOW_COLLECTOR_SECONDS:.0f} seconds: "
            + ", ".join(unusually_slow),
            title="Slow Operations",
            status="warning",
        )

class IPResponder:
    """Format an IP InvestigationResult for terminal display."""

    @staticmethod
    def respond(investigation: Any, console: Console) -> None:
        """Print the readable IP investigation report."""
        entity_type = _get(investigation, "entity_type")

        if entity_type != "ip_address":
            print_message_panel(
                console,
                f"IPResponder received entity type: {entity_type!r}",
                title="Responder Error",
                status="error",
            )
            return

        results = _collector_results(investigation)

        target = (
            _get(investigation, "normalized_target")
            or _get(investigation, "original_target", "Unknown")
        )

        console.print()
        console.print(
            Panel(
                Text(
                    str(target),
                    style="bold text",
                    justify="center",
                ),
                title="[heading]IP INVESTIGATION[/heading]",
                subtitle="[muted]THESEUS[/muted]",
                border_style="border",
                padding=(1, 2),
                expand=False,
            )
        )
        console.print()

        _print_overview(console, investigation, results)
        _print_registration_and_routing(console, results)
        _print_geolocation_and_hosting(console, results)
        _print_network_exposure(console, results)
        _print_reputation_and_threats(console, results)
        _print_dns_and_history(console, results)
        _print_analysis(console, results)
        _print_collector_warnings(console, investigation)
        _print_collector_timing(console, investigation)
        _print_investigation_metadata(console, investigation)

        console.print()
