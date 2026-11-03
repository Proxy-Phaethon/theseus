from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group

from ui.terminal import console

def format_value(value) -> str:

    if value is None:
        return "N/A"

    if isinstance(value, bool):
        return "YES" if value else "NO"

    if isinstance(value, (list, tuple, set)):
        if not value:
            return "N/A"

        return "\n".join(
            f"• {format_value(item)}"
            for item in value
        )

    if isinstance(value, dict):
        if not value:
            return "N/A"

        return "\n".join(
            f"{key.replace('_', ' ').title()}: {format_value(item)}"
            for key, item in value.items()
        )

    return str(value)

def build_case_header(
    domain: str,
    case_reference: str | None = None,
    status: str = "COMPLETE",
) -> Panel:

    table = Table.grid(padding=(0, 2))
    table.add_column(style="label", width=20)
    table.add_column(style="value")

    table.add_row("TARGET", domain)
    table.add_row(
        "DATE",
        datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    )

    if case_reference:
        table.add_row("CASE REFERENCE", case_reference)

    status_style = (
        "success" if status.upper() == "COMPLETE"
        else "error" if status.upper() == "FAILED"
        else "warning"
    )

    table.add_row(
        "STATUS",
        Text(status.upper(), style=status_style),
    )

    return Panel(
        table,
        title="[heading]INVESTIGATION RECORD[/heading]",
        border_style="accent",
        box=box.DOUBLE,
        padding=(1, 2),
    )

def build_section(
    number: int,
    module_name: str,
    data: dict,
    status: str = "SUCCESS",
    error: str | None = None,
) -> Panel:

    title = module_name.replace("_", " ").upper()

    table = Table(
        show_header=False,
        show_edge=False,
        show_lines=False,
        box=None,
        padding=(0, 1),
        expand=True,
    )

    table.add_column(
        "Field",
        style="label",
        width=28,
        no_wrap=False,
    )

    table.add_column(
        "Value",
        style="value",
        overflow="fold",
    )

    for field, value in data.items():
        table.add_row(
            field.replace("_", " ").upper(),
            format_value(value),
        )

    if error:
        table.add_row(
            "ERROR",
            Text(error, style="error"),
        )

    status_style = (
        "success" if status.upper() in {"SUCCESS", "COMPLETE"}
        else "error" if status.upper() == "FAILED"
        else "warning"
    )

    content = Group(
        Text(f"STATUS: {status.upper()}", style=status_style),
        Text(""),
        table,
    )

    return Panel(
        content,
        title=f"[section][{number:02d}] {title}[/section]",
        border_style="border",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def build_provenance(provenance: list) -> Panel | None:

    if not provenance:
        return None

    content = "\n".join(
        f"• {format_value(source)}"
        for source in provenance
    )

    return Panel(
        content,
        title="[section]DATA PROVENANCE[/section]",
        border_style="border",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def build_related_entities(entities: list) -> Panel | None:

    if not entities:
        return None

    table = Table(
        show_header=True,
        box=None,
        expand=True,
    )

    table.add_column("TYPE", style="label")
    table.add_column("ENTITY", style="value")
    table.add_column("RELATIONSHIP", style="muted")

    for entity in entities:
        if isinstance(entity, dict):
            entity_type = entity.get("type", "UNKNOWN")
            value = entity.get(
                "value",
                entity.get("name", "N/A"),
            )
            relationship = entity.get("relationship", "N/A")

            table.add_row(
                str(entity_type).upper(),
                format_value(value),
                format_value(relationship),
            )
        else:
            table.add_row("UNKNOWN", format_value(entity), "N/A")

    return Panel(
        table,
        title="[section]RELATED ENTITIES[/section]",
        border_style="border",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def render_investigation(response: dict) -> None:

    domain = response.get("domain", "UNKNOWN")
    modules = response.get("modules", [])

    console.print()
    console.print(build_case_header(domain))

    for index, result in enumerate(modules, start=1):
        if not isinstance(result, dict):
            continue

        module_name = result.get("module", f"MODULE {index}")
        data = result.get("data", {})
        status = result.get("status", "UNKNOWN")
        error = result.get("error")

        if not isinstance(data, dict):
            data = {"result": data}

        console.print()
        console.print(
            build_section(
                number=index,
                module_name=module_name,
                data=data,
                status=status,
                error=error,
            )
        )

        provenance = build_provenance(
            result.get("provenance", [])
        )

        if provenance:
            console.print(provenance)

        related_entities = build_related_entities(
            result.get("related_entities", [])
        )

        if related_entities:
            console.print(related_entities)

    console.print()
    console.rule(
        "[muted]END OF INVESTIGATION RECORD[/muted]",
        style="case.separator",
    )
    console.print()