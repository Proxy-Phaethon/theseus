from datetime import datetime
from collections.abc import Mapping

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group

from ui.terminal import console

DISPLAY_LIMIT = 8

def format_value(value, limit: int = DISPLAY_LIMIT) -> tuple[str, bool]:

    if value is None:
        return "N/A", False

    if isinstance(value, bool):
        return ("YES" if value else "NO"), False

    if isinstance(value, Mapping):
        if not value:
            return "N/A", False

        items = list(value.items())
        truncated = len(items) > limit
        visible_items = items[:limit]

        formatted = []

        for key, item in visible_items:
            item_text, item_truncated = format_value(item, limit)

            formatted.append(
                f"{str(key).replace('_', ' ').title()}: {item_text}"
            )

            truncated = truncated or item_truncated

        if truncated and len(items) > limit:
            formatted.append(
                f"... {len(items) - limit} additional entries omitted."
            )

        return "\n".join(formatted), truncated

    if isinstance(value, (list, tuple, set)):
        if not value:
            return "N/A", False

        items = list(value)
        truncated = len(items) > limit
        visible_items = items[:limit]

        formatted = []

        for item in visible_items:
            item_text, item_truncated = format_value(item, limit)

            formatted.append(f"• {item_text}")
            truncated = truncated or item_truncated

        if len(items) > limit:
            formatted.append(
                f"... {len(items) - limit} additional entries omitted."
            )

        return "\n".join(formatted), truncated

    return str(value), False

def build_case_header(
    domain: str,
    case_reference: str | None = None,
    status: str = "success",
) -> Panel:

    table = Table.grid(padding=(0, 2))
    table.add_column(style="label", width=20)
    table.add_column(style="value")

    table.add_row("TARGET", domain)

    table.add_row(
        "DATE",
        datetime.now().astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
    )

    if case_reference:
        table.add_row("CASE REFERENCE", case_reference)

    status = status.lower()

    status_styles = {
        "success": "success",
        "no_results": "muted",
        "partial": "warning",
        "error": "error",
    }

    table.add_row(
        "STATUS",
        Text(
            status.replace("_", " ").upper(),
            style=status_styles.get(status, "warning"),
        ),
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
    status: str = "success",
    errors: list | None = None,
) -> tuple[Panel, bool]:

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

    has_truncated_data = False

    for field, value in data.items():
        formatted, truncated = format_value(value)

        table.add_row(
            field.replace("_", " ").upper(),
            formatted,
        )

        has_truncated_data = has_truncated_data or truncated

    if errors:
        error_text = "\n".join(
            f"• {format_value(error)[0]}"
            for error in errors
        )

        table.add_row(
            "ERRORS",
            Text(error_text, style="error"),
        )

    status = status.lower()

    status_styles = {
        "success": "success",
        "no_results": "muted",
        "partial": "warning",
        "error": "error",
    }

    content = Group(
        Text(
            f"STATUS: {status.replace('_', ' ').upper()}",
            style=status_styles.get(status, "warning"),
        ),
        Text(""),
        table,
    )

    panel = Panel(
        content,
        title=f"[section][{number:02d}] {title}[/section]",
        border_style="border",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    return panel, has_truncated_data

def build_provenance(provenance: list) -> Panel | None:

    if not provenance:
        return None

    content = "\n".join(
        f"• {format_value(source)[0]}"
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
                format_value(value)[0],
                format_value(relationship)[0],
            )
        else:
            table.add_row(
                "UNKNOWN",
                format_value(entity)[0],
                "N/A",
            )

    return Panel(
        table,
        title="[section]RELATED ENTITIES[/section]",
        border_style="border",
        box=box.ROUNDED,
        padding=(1, 2),
    )

def render_investigation(response: dict) -> bool:
    domain = response.get("domain", "UNKNOWN")
    modules = response.get("modules", [])

    console.print()
    console.print(
        build_case_header(
            domain=domain,
            status=response.get("status", "success"),
        )
    )

    has_truncated_data = False

    for index, result in enumerate(modules, start=1):
        if not isinstance(result, dict):
            continue

        module_name = result.get(
            "module",
            f"MODULE {index}",
        )

        data = result.get("data", {})
        status = result.get("status", "error")
        errors = result.get("errors", [])

        if not isinstance(data, dict):
            data = {"result": data}

        if not isinstance(errors, list):
            errors = [errors]

        panel, truncated = build_section(
            number=index,
            module_name=module_name,
            data=data,
            status=status,
            errors=errors,
        )

        console.print()
        console.print(panel)

        has_truncated_data = (
            has_truncated_data or truncated
        )

    console.print()
    console.rule(
        "[muted]END OF INVESTIGATION RECORD[/muted]",
        style="case.separator",
    )
    console.print()

    return has_truncated_data

def render_provenance(response: dict) -> None:
    for result in response.get("modules", []):
        if not isinstance(result, dict):
            continue

        provenance = build_provenance(
            result.get("provenance", [])
        )

        if provenance:
            console.print()
            console.print(
                f"[heading]{result.get('module', 'UNKNOWN').upper()}[/heading]"
            )
            console.print(provenance)

def render_related_entities(response: dict) -> None:
    for result in response.get("modules", []):
        if not isinstance(result, dict):
            continue

        entities = build_related_entities(
            result.get("related_entities", [])
        )

        if entities:
            console.print()
            console.print(
                f"[heading]{result.get('module', 'UNKNOWN').upper()}[/heading]"
            )
            console.print(entities)