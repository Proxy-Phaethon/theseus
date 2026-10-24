"""
Email investigation responder for Theseus.

Responsibilities:
- Format executor results into a readable terminal report.
- Surface useful findings and meaningful warnings.
- Hide routine negative and unimplemented service checks.
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

from ui.panels import print_message_panel, print_panel, print_summary_panel
from ui.status import format_status
from ui.theme import status_style

def _get(value: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)

def _collector_results(investigation: Any) -> dict[str, Any]:
    """Index collector results by their registered display names."""
    results = {}

    for collector in _get(investigation, "collectors", []) or []:
        name = _get(collector, "name", "")
        result = _get(collector, "result")
        results[name] = result

    return results

def _finding(
    results: dict[str, Any],
    collector_name: str,
) -> Any:
    """Get the returned data from a named collector."""
    return results.get(collector_name)

def _yes_no(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"

def _status_label(value: Any) -> str:
    """Make internal status strings readable."""
    if not value:
        return "Unknown"
    return str(value).replace("_", " ").capitalize()

def _compact(value: Any, limit: int = 100) -> str:
    """Make a potentially long value suitable for a compact report."""
    if value is None:
        return "Not available"

    text = " ".join(str(value).split())

    if len(text) > limit:
        return text[: limit - 1] + "…"

    return text

def _print_table(
    console: Console,
    title: str,
    columns: list[str],
    rows: list[list[str]],
    *,
    border_style: str = "border",
) -> None:
    """Print a consistently styled table inside a panel."""
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

def _print_overview(
    console: Console,
    investigation: Any,
    normalized: Any,
    syntax: Any,
    domain: Any,
) -> None:
    target = _get(investigation, "normalized_target")
    if not target:
        target = _get(investigation, "original_target", "Unknown")

    lines = [
        ("Email", str(target)),
        (
            "Syntax",
            "Valid" if _get(syntax, "valid") is True
            else "Invalid" if _get(syntax, "valid") is False
            else "Not verified",
        ),
    ]

    domain_name = _get(domain, "registrable_domain")
    if domain_name:
        lines.append(("Registered domain", str(domain_name)))

    role_based = _get(normalized, "role_based")
    disposable = _get(normalized, "disposable_looking")
    special_use = _get(normalized, "special_use_domain")

    if role_based:
        lines.append(("Address type", "Role-based mailbox"))

    if disposable:
        lines.append(("Address warning", "Disposable-looking domain"))

    if special_use:
        lines.append(("Domain warning", "Special-use domain"))

    transformations = _get(normalized, "transformations", []) or []
    if transformations:
        lines.append(
            ("Normalization", "; ".join(str(x) for x in transformations))
        )

    normalization_errors = _get(normalized, "errors", []) or []
    if normalization_errors:
        lines.append(
            ("Normalization notes", "; ".join(str(x) for x in normalization_errors))
        )

    print_summary_panel(
        console,
        "Email Overview",
        lines,
        status="success" if _get(syntax, "valid") is True else "info",
    )

def _print_infrastructure(console: Console, mx: Any) -> None:
    if not mx:
        print_message_panel(
            console,
            "MX lookup returned no result.",
            title="Mail Infrastructure",
            status="warning",
        )
        return

    mx_status = _get(mx, "status", "unknown")
    servers = _get(mx, "mail_servers", []) or []
    accepts_email = _get(mx, "accepts_email")

    summary = [
        ("MX lookup", _status_label(mx_status)),
        ("Accepts email", _yes_no(accepts_email)),
        ("Mail servers", str(len(servers))),
    ]

    print_summary_panel(
        console,
        "Mail Infrastructure",
        summary,
        status="success" if mx_status == "found" else "warning",
    )

    if not servers:
        return

    rows = []
    for server in sorted(
        servers,
        key=lambda item: _get(item, "priority", 9999),
    ):
        hostname = str(_get(server, "hostname", "Unknown"))
        priority = str(_get(server, "priority", "—"))

        ipv4 = _get(server, "ipv4", []) or []
        ipv6 = _get(server, "ipv6", []) or []

        addresses = [str(address) for address in ipv4 + ipv6]
        address_summary = ", ".join(addresses) if addresses else "No addresses returned"

        rows.append([priority, hostname, address_summary])

    _print_table(
        console,
        "Mail Exchange Records",
        ["Priority", "Hostname", "Resolved addresses"],
        rows,
    )

def _print_email_security(console: Console, security: Any) -> None:
    if not security:
        print_message_panel(
            console,
            "Email security checks returned no result.",
            title="Email Security",
            status="warning",
        )
        return

    rows = []

    for key, label in (
        ("spf", "SPF"),
        ("dmarc", "DMARC"),
        ("mta_sts", "MTA-STS"),
        ("tls_rpt", "TLS reporting"),
    ):
        item = _get(security, key, {}) or {}
        status = _get(item, "status", "unknown")
        record = _get(item, "record")

        if record:
            detail = _compact(record, 110)
        else:
            detail = _status_label(status)

        rows.append([label, _status_label(status), detail])

    _print_table(
        console,
        "Email Security",
        ["Control", "Status", "Finding"],
        rows,
    )

    dmarc = _get(security, "dmarc", {}) or {}
    policy = _get(dmarc, "policy")

    if policy:
        policy_note = (
            f"DMARC policy: {policy}. "
            "This describes the domain's published policy, "
            "not whether a particular message passed authentication."
        )
        print_message_panel(
            console,
            policy_note,
            title="DMARC Policy",
            status="info",
        )

    dnssec = _get(security, "dnssec", {}) or {}
    dnssec_rows = []

    for key, label in (("dnskey", "DNSKEY"), ("ds", "DS")):
        item = _get(dnssec, key, {}) or {}
        status = _get(item, "status", "unknown")
        records = _get(item, "records", []) or []

        dnssec_rows.append(
            [label, _status_label(status), str(len(records))]
        )

    if dnssec_rows:
        _print_table(
            console,
            "DNSSEC Record Observations",
            ["Record type", "Lookup status", "Records returned"],
            dnssec_rows,
        )

def _print_breach_results(console: Console, breach: Any) -> None:
    if not breach:
        print_message_panel(
            console,
            "Breach lookup returned no result.",
            title="Breach Exposure",
            status="warning",
        )
        return

    status = _get(breach, "status", "unknown")
    source = _get(breach, "source", "Unknown source")
    count = _get(breach, "breach_count")
    breaches = _get(breach, "breaches", []) or []

    if status == "not_found":
        message = (
            f"No breach was returned by {source}. "
            "This does not prove that the address has never been exposed."
        )
        print_message_panel(
            console,
            message,
            title="Breach Exposure",
            status="info",
        )
        return

    if status in {"found", "breaches_found"} or breaches:
        lines = [
            ("Source", str(source)),
            ("Breaches reported", str(count if count is not None else len(breaches))),
        ]

        print_summary_panel(
            console,
            "Breach Exposure",
            lines,
            status="warning",
        )

        if breaches:
            rows = []
            for item in breaches:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("title") or item.get("breach") or str(item)
                    date_value = item.get("date") or item.get("breach_date") or "Unknown"
                else:
                    name = str(item)
                    date_value = "Unknown"

                rows.append([str(name), str(date_value)])

            _print_table(
                console,
                "Reported Breaches",
                ["Breach", "Date"],
                rows,
            )
        return

    if status == "error":
        message = _get(breach, "error") or "The source reported an error."
        print_message_panel(
            console,
            f"{source}: {message}",
            title="Breach Exposure",
            status="error",
        )
        return

    print_summary_panel(
        console,
        "Breach Exposure",
        [
            ("Source", str(source)),
            ("Result", _status_label(status)),
        ],
        status="info",
    )

def _print_associated_services(console: Console, services: Any) -> None:
    """Display confirmed service associations and profile URLs when available."""
    services = services or []

    # Only confirmed associations belong in the normal report. Other results
    # remain available in the original investigation data.
    visible = [
        service
        for service in services
        if _get(service, "status") == "associated"
    ]

    if not visible:
        print_message_panel(
            console,
            "No associated service profiles were identified by the implemented checks.",
            title="Associated Services",
            status="info",
        )
        return

    rows = []
    for service in visible:
        name = str(_get(service, "service", "Unknown service"))
        url = _get(service, "url")
        rows.append([name, str(url) if url else "URL couldn't be retrieved"])

    _print_table(
        console,
        "Associated Services",
        ["Service", "Profile URL"],
        rows,
        border_style="success",
    )

def _print_investigation_metadata(console: Console, investigation: Any) -> None:
    status = _get(investigation, "status", "unknown")
    duration = _get(investigation, "duration_seconds", 0)
    completed = _get(investigation, "completed_count", 0)
    failed = _get(investigation, "failed_count", 0)
    errors = _get(investigation, "errors", []) or []

    lines = [
        ("Execution status", _status_label(status)),
        ("Collectors completed", str(completed)),
        ("Collector errors", str(failed)),
        ("Elapsed", f"{duration:.2f} seconds" if isinstance(duration, (int, float)) else str(duration)),
    ]

    print_summary_panel(
        console,
        "Investigation Summary",
        lines,
        status=(
            "success" if status == "success"
            else "warning" if status == "partial"
            else "error" if status == "error"
            else "info"
        ),
    )

    if errors:
        # Errors remain visible because they may affect interpretation.
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

class EmailResponder:
    """Format an email InvestigationResult for terminal display."""

    @staticmethod
    def respond(investigation: Any, console: Console) -> None:
        """Print the readable email investigation report."""
        entity_type = _get(investigation, "entity_type")

        if entity_type != "email":
            print_message_panel(
                console,
                f"EmailResponder received entity type: {entity_type!r}",
                title="Responder Error",
                status="error",
            )
            return

        results = _collector_results(investigation)

        normalizer_component = _get(investigation, "normalizer")
        normalized = _get(normalizer_component, "result")

        syntax = _finding(results, "Email syntax")
        domain = _finding(results, "Email domain analysis")
        mx = _finding(results, "MX lookup")
        security = _finding(results, "Email security")
        breach = _finding(results, "Breach lookup")
        services = _finding(results, "Service discovery")

        target = _get(investigation, "normalized_target") or _get(
            investigation, "original_target", "Unknown"
        )

        console.print()
        console.print(
            Panel(
                Text(str(target), style="bold text", justify="center"),
                title="[heading]EMAIL INVESTIGATION[/heading]",
                subtitle="[muted]THESEUS[/muted]",
                border_style="border",
                padding=(1, 2),
                expand=False,
            )
        )
        console.print()

        _print_overview(console, investigation, normalized, syntax, domain)
        _print_infrastructure(console, mx)
        _print_email_security(console, security)
        _print_breach_results(console, breach)
        _print_associated_services(console, services)
        _print_investigation_metadata(console, investigation)

        console.print()