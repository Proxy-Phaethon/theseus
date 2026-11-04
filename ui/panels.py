from datetime import datetime
from collections.abc import Mapping

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group

from ui.terminal import console

DISPLAY_LIMIT = 5

def format_value(value, limit: int = DISPLAY_LIMIT) -> tuple[str, bool]:
    if value is None:
        return "", False

    if isinstance(value, Mapping):
        parts = []

        for key, item in value.items():
            if item is None or item == "":
                continue

            parts.append(f"{key}: {item}")

        value = "; ".join(parts)

    elif isinstance(value, (list, tuple, set)):
        parts = [
            str(item)
            for item in value
            if item is not None and item != ""
        ]
        value = ", ".join(parts)

    else:
        value = str(value)

    value = value.strip()

    if not value:
        return "", False

    max_length = limit * 100

    if len(value) > max_length:
        return value[:max_length].rstrip() + "...", True

    return value, False

def _has_content(value) -> bool:
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, Mapping):
        return any(_has_content(item) for item in value.values())

    if isinstance(value, (list, tuple, set)):
        return any(_has_content(item) for item in value)

    return True

def _section_title(number: str, title: str) -> Text:
    text = Text()
    text.append(f"{number}  ", style="bold cyan")
    text.append(title.upper(), style="bold white")
    return text

def build_case_header(domain: str, case_reference=None) -> Panel:
    timestamp = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right")

    header.add_row(
        Text("TARGET", style="bold cyan"),
        Text("INVESTIGATION RECORD", style="bold cyan"),
    )

    header.add_row(
        Text(str(domain), style="bold white"),
        Text(timestamp, style="dim"),
    )

    if case_reference:
        header.add_row(
            Text("CASE REFERENCE", style="dim"),
            Text(str(case_reference), style="dim"),
        )

    return Panel(
        header,
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    )

def build_identification(
    identification: Mapping,
) -> tuple[Panel | None, bool]:
    if not isinstance(identification, Mapping) or not identification:
        return None, False

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(ratio=1, style="white")

    truncated = False

    for label, value in identification.items():
        if not _has_content(value):
            continue

        formatted, was_truncated = format_value(value)

        if formatted:
            table.add_row(str(label), formatted)
            truncated = truncated or was_truncated

    if not table.row_count:
        return None, False

    panel = Panel(
        table,
        title=_section_title("01", "Identification"),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    return panel, truncated

def build_findings_section(
    number: str,
    title: str,
    findings: list,
) -> tuple[Panel | None, bool]:
    if not findings:
        return None, False

    table = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("Finding", style="cyan", no_wrap=True)
    table.add_column("Value", style="white", ratio=1)

    displayed = 0
    total = 0
    truncated = False

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue

        label = finding.get("label", "Finding")
        value = finding.get("value")

        if not _has_content(value):
            continue

        total += 1

        if displayed >= DISPLAY_LIMIT:
            continue

        formatted, was_truncated = format_value(value)

        if not formatted:
            continue

        table.add_row(str(label), formatted)
        displayed += 1
        truncated = truncated or was_truncated

    if not displayed:
        return None, False

    omitted = total - displayed

    if omitted > 0:
        truncated = True
        table.add_row(
            Text(""),
            Text(
                f"{omitted} additional entries available in the full report.",
                style="dim",
            ),
        )

    panel = Panel(
        table,
        title=_section_title(number, title),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    return panel, truncated

def build_investigation_leads(
    leads: list,
) -> tuple[Panel | None, bool]:
    if not leads:
        return None, False

    table = Table(
        box=box.SIMPLE,
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )

    table.add_column("TYPE", style="cyan", no_wrap=True)
    table.add_column("VALUE", style="white", ratio=2)
    table.add_column("BASIS", style="dim", ratio=1)

    displayed = 0
    total = 0

    for lead in leads:
        if not isinstance(lead, Mapping):
            continue

        value = lead.get("value")

        if not _has_content(value):
            continue

        total += 1

        if displayed >= DISPLAY_LIMIT:
            continue

        basis = lead.get("basis", [])

        if isinstance(basis, str):
            basis = [basis]

        if "explicit_relationship" in basis:
            basis_label = "Explicit relationship"
        elif "extracted_value" in basis:
            basis_label = "Extracted value"
        else:
            basis_label = "Extracted entity"

        table.add_row(
            str(lead.get("type", "entity")).upper(),
            str(value),
            basis_label,
        )

        displayed += 1

    if not displayed:
        return None, False

    omitted = total - displayed
    truncated = omitted > 0

    if truncated:
        table.caption = (
            f"{omitted} additional leads available in the full report."
        )

    panel = Panel(
        table,
        title=_section_title("08", "Investigation Leads"),
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    return panel, truncated

def build_supporting_data(
    supporting_data: Mapping,
) -> tuple[Panel | None, bool]:
    if not isinstance(supporting_data, Mapping) or not supporting_data:
        return None, False

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(ratio=1, style="white")

    truncated = False

    for label, value in supporting_data.items():
        if not _has_content(value):
            continue

        formatted, was_truncated = format_value(value)

        if formatted:
            table.add_row(
                str(label).replace("_", " ").title(),
                formatted,
            )
            truncated = truncated or was_truncated

    if not table.row_count:
        return None, False

    panel = Panel(
        table,
        title=_section_title("09", "Supporting Data"),
        border_style="dim",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    return panel, truncated

def render_investigation(response: Mapping) -> bool:

    if not isinstance(response, Mapping):
        console.print("[red]Invalid investigation response.[/red]")
        return False

    report = response.get("report")

    if not isinstance(report, Mapping):
        console.print("[red]No investigation report available.[/red]")
        return False

    domain = response.get("domain", "Unknown target")
    case_reference = response.get("case_reference")

    panels = [build_case_header(domain, case_reference)]
    truncated = False

    identification, was_truncated = build_identification(
        report.get("identification", {})
    )

    if identification:
        panels.append(identification)

    truncated = truncated or was_truncated

    findings = report.get("findings", {})

    section_order = [
        ("02", "Geography", "geography"),
        ("03", "Network", "network"),
        ("04", "Digital Identities", "digital_identities"),
        ("05", "Infrastructure", "infrastructure"),
        ("06", "Historical Records", "historical"),
        ("07", "Technical Indicators", "technical"),
    ]

    for number, title, key in section_order:
        panel, was_truncated = build_findings_section(
            number,
            title,
            findings.get(key, []),
        )

        if panel:
            panels.append(panel)

        truncated = truncated or was_truncated

    leads, was_truncated = build_investigation_leads(
        report.get("investigation_leads", [])
    )

    if leads:
        panels.append(leads)

    truncated = truncated or was_truncated

    supporting, was_truncated = build_supporting_data(
        report.get("supporting_data", {})
    )

    if supporting:
        panels.append(supporting)

    truncated = truncated or was_truncated

    console.print(Group(*panels))

    return truncated

def render_provenance(response: Mapping):
    """Provenance is retained in module envelopes, not shown in the main report."""
    return None

def render_related_entities(response: Mapping):
    """Related entities are incorporated into investigation leads."""
    return None