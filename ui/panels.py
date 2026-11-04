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

    if len(value) > limit * 100:
        return value[:limit * 100].rstrip() + "...", True

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

def _flatten_values(value):
    if not _has_content(value):
        return

    if isinstance(value, Mapping):
        for item in value.values():
            yield from _flatten_values(item)

    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _flatten_values(item)

    else:
        yield value

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

def build_identification(identification: Mapping) -> Panel | None:
    if not isinstance(identification, Mapping) or not identification:
        return None

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(ratio=1, style="white")

    for label, value in identification.items():
        if not _has_content(value):
            continue

        formatted, _ = format_value(value)

        if formatted:
            table.add_row(str(label), formatted)

    if not table.row_count:
        return None

    return Panel(
        table,
        title=_section_title("01", "Identification"),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def build_findings_section(
    number: str,
    title: str,
    findings: list,
) -> Panel | None:
    if not findings:
        return None

    table = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("Finding", style="cyan", no_wrap=True)
    table.add_column("Value", style="white", ratio=1)

    displayed = 0
    truncated = False

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue

        label = finding.get("label", "Finding")
        value = finding.get("value")

        if not _has_content(value):
            continue

        formatted, was_truncated = format_value(value)

        if not formatted:
            continue

        if displayed >= DISPLAY_LIMIT:
            truncated = True
            break

        table.add_row(str(label), formatted)
        displayed += 1
        truncated = truncated or was_truncated

    if not displayed:
        return None

    if len(findings) > displayed:
        truncated = True

    if truncated:
        table.add_row(
            Text(""),
            Text("Additional values available in the full extraction data.", style="dim"),
        )

    return Panel(
        table,
        title=_section_title(number, title),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def build_investigation_leads(leads: list) -> Panel | None:
    if not leads:
        return None

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

    for lead in leads:
        if not isinstance(lead, Mapping):
            continue

        value = lead.get("value")

        if not _has_content(value):
            continue

        if displayed >= DISPLAY_LIMIT:
            break

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
        return None

    if len(leads) > displayed:
        table.caption = (
            f"{len(leads) - displayed} additional leads available in the full report."
        )

    return Panel(
        table,
        title=_section_title("08", "Investigation Leads"),
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def build_supporting_data(supporting_data: Mapping) -> Panel | None:
    if not isinstance(supporting_data, Mapping) or not supporting_data:
        return None

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(ratio=1, style="white")

    for label, value in supporting_data.items():
        if not _has_content(value):
            continue

        formatted, _ = format_value(value)

        if formatted:
            table.add_row(str(label).replace("_", " ").title(), formatted)

    if not table.row_count:
        return None

    return Panel(
        table,
        title=_section_title("09", "Supporting Data"),
        border_style="dim",
        box=box.ROUNDED,
        padding=(1, 2),
    )

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

    panels = []

    header = build_case_header(domain, case_reference)
    panels.append(header)

    identification = build_identification(
        report.get("identification", {})
    )

    if identification:
        panels.append(identification)

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
        panel = build_findings_section(
            number,
            title,
            findings.get(key, []),
        )

        if panel:
            panels.append(panel)

    leads = build_investigation_leads(
        report.get("investigation_leads", [])
    )

    if leads:
        panels.append(leads)

    supporting = build_supporting_data(
        report.get("supporting_data", {})
    )

    if supporting:
        panels.append(supporting)

    console.print(Group(*panels))

    return False

def render_provenance(response: Mapping):
    return None

def render_related_entities(response: Mapping):
    return None