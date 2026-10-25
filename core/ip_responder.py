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

    if isinstance(value, (dict, list, tuple, set)):
        return str(value) if value else default

    rendered = " ".join(str(value).split())
    return rendered or default

def _compact(value: Any, limit: int = 110) -> str:
    rendered = _text(value)

    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"

    return rendered

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

    _print_observations(
        console,
        "IP Registration / RDAP",
        rdap,
        [
            ("Network name", ("name", "network_name")),
            ("Network handle", ("handle", "network_handle")),
            ("Network type", ("type", "network_type")),
            ("Country", ("country",)),
            ("Start address", ("start_address", "start")),
            ("End address", ("end_address", "end")),
            ("CIDR", ("cidr", "cidrs")),
            ("Parent network", ("parent",)),
            ("Status", ("status",)),
        ],
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

        if hostnames:
            rows = [[_compact(hostname, 180)] for hostname in hostnames]
            _print_table(
                console,
                "Reverse DNS Names",
                ["Hostname"],
                rows,
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
        service_items = _value(
            services,
            "services",
            "identified_services",
            "results",
            default=[],
        ) or []

        if isinstance(service_items, list) and service_items:
            rows = []

            for item in service_items:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(_value(item, "port")),
                    _text(_value(item, "service", "protocol", "name")),
                    _text(_value(item, "status")),
                    _compact(_value(item, "banner", "evidence", "product")),
                ])

            _print_table(
                console,
                "Service Detection",
                ["Port", "Service", "Status", "Evidence"],
                rows,
            )
        elif _has_content(services):
            _print_observations(
                console,
                "Service Detection",
                services,
                [
                    ("Identified services", ("identified_services", "services")),
                    ("Ports checked", ("ports_checked",)),
                    ("Summary", ("summary",)),
                ],
            )

    if isinstance(tls, dict):
        certificates = _value(
            tls,
            "certificates",
            "results",
            "observations",
            default=[],
        ) or []

        if isinstance(certificates, list) and certificates:
            rows = []

            for cert in certificates:
                if not isinstance(cert, dict):
                    continue

                rows.append([
                    _text(_value(cert, "port")),
                    _compact(_value(cert, "subject", "common_name")),
                    _compact(_value(cert, "issuer")),
                    _text(_value(cert, "not_after", "valid_to", "expires")),
                    _text(_value(cert, "verification", "verified")),
                ])

            _print_table(
                console,
                "TLS Certificates",
                ["Port", "Subject", "Issuer", "Expires", "Verification"],
                rows,
            )
        elif _has_content(tls):
            _print_observations(
                console,
                "TLS Intelligence",
                tls,
                [
                    ("Ports checked", ("ports_checked",)),
                    ("Certificates found", ("certificate_count",)),
                    ("TLS version", ("tls_version", "version")),
                    ("Cipher", ("cipher",)),
                ],
            )

    if isinstance(http, dict):
        http_items = _value(
            http,
            "responses",
            "results",
            "observations",
            default=[],
        ) or []

        if isinstance(http_items, list) and http_items:
            rows = []

            for item in http_items:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(_value(item, "port")),
                    _text(_value(item, "status_code", "status")),
                    _compact(_value(item, "server", "technology")),
                    _compact(_value(item, "title", "location", "url")),
                ])

            _print_table(
                console,
                "HTTP Responses",
                ["Port", "HTTP status", "Server / Technology", "Details"],
                rows,
            )
        elif _has_content(http):
            _print_observations(
                console,
                "HTTP Intelligence",
                http,
                [
                    ("Ports checked", ("ports_checked",)),
                    ("Responses", ("response_count",)),
                    ("Technologies", ("technologies",)),
                    ("Security headers", ("security_headers",)),
                ],
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

    _print_observations(
        console,
        "IP Reputation",
        reputation,
        [
            ("Assessment", ("assessment", "reputation")),
            ("Score", ("score", "reputation_score")),
            ("Usage", ("usage",)),
            ("Recommendation", ("recommendation", "recommendations")),
            ("Network", ("network", "network_range")),
            ("Organization", ("organization",)),
        ],
        border_style="warning",
    )

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

            for item in records:
                if not isinstance(item, dict):
                    continue

                rows.append([
                    _text(_value(item, "query", "hostname", "name")),
                    _text(_value(item, "type", "record_type")),
                    _compact(_value(item, "answer", "value", "rdata")),
                    _text(_value(item, "timestamp", "last_seen", "time")),
                ])

            _print_table(
                console,
                "Passive DNS Records",
                ["Query / Hostname", "Type", "Answer", "Observed"],
                rows,
            )

        if not records and _has_content(passive_dns):
            _print_observations(
                console,
                "Passive DNS",
                passive_dns,
                [
                    ("Record count", ("record_count", "total")),
                    ("Hostnames", ("hostnames", "candidate_hostnames")),
                ],
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
        findings = _value(
            vulnerabilities,
            "findings",
            "vulnerabilities",
            "matches",
            default=[],
        ) or []

        if isinstance(findings, list) and findings:
            rows = []

            for item in findings:
                if isinstance(item, dict):
                    rows.append([
                        _text(_value(item, "cve", "cve_id", "id", "name")),
                        _compact(_value(item, "product", "package")),
                        _text(_value(item, "version", "affected_version")),
                        _compact(_value(item, "severity", "kev_status", "status")),
                    ])
                else:
                    rows.append([_compact(item), "Unknown", "Unknown", "Unknown"])

            _print_table(
                console,
                "Vulnerability Intelligence",
                ["Identifier", "Product", "Version", "Assessment"],
                rows,
                border_style="warning",
            )
        else:
            _print_observations(
                console,
                "Vulnerability Intelligence",
                vulnerabilities,
                [
                    ("Status", ("status",)),
                    ("Products examined", ("products_checked", "candidate_count")),
                    ("Findings", ("finding_count", "match_count")),
                    ("Limitations", ("limitations",)),
                ],
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
        fields = [
            ("Assessment", ("assessment",)),
            ("Summary", ("summary",)),
            ("Organization", ("organization",)),
            ("Network", ("network", "network_range")),
            ("ASN", ("asn",)),
            ("Hostnames", ("hostnames",)),
            ("Geolocation", ("geolocation",)),
            ("Limitations", ("limitations",)),
        ]

        _print_observations(
            console,
            "Context Aggregation",
            context,
            fields,
        )

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
        _print_investigation_metadata(console, investigation)

        console.print()