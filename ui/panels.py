from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ui.theme import status_style

def print_panel(
    console: Console,
    content: RenderableType,
    *,
    title: str | None = None,
    border_style: str = "border",
    padding: tuple[int, int] = (1, 2),
    expand: bool = True,
) -> None:
    """Render a standard Theseus panel."""
    console.print(
        Panel(
            content,
            title=title,
            title_align="left",
            border_style=border_style,
            padding=padding,
            expand=expand,
        )
    )

def print_message_panel(
    console: Console,
    message: str,
    *,
    title: str | None = None,
    status: str = "info",
) -> None:
    """Render a short informational, warning, or error message."""
    style = status_style(status)
    content = Text(message, style="text")

    print_panel(
        console,
        content,
        title=title,
        border_style=style,
        expand=False,
    )

def print_summary_panel(
    console: Console,
    title: str,
    lines: list[tuple[str, str]],
    *,
    status: str = "info",
) -> None:
    """Render a compact label/value summary.

    Args:
        console: Console used for output.
        title: Panel heading.
        lines: Sequence of (label, value) pairs.
        status: Semantic status controlling the border color.
    """
    content = Table.grid(padding=(0, 2))
    content.add_column(style="muted", no_wrap=True)
    content.add_column(style="text", overflow="fold")

    for label, value in lines:
        content.add_row(label, value)

    print_panel(
        console,
        content,
        title=title,
        border_style=status_style(status),
    )

def print_centered_panel(
    console: Console,
    content: RenderableType,
    *,
    title: str | None = None,
) -> None:
    """Render centered content inside a standard panel."""
    print_panel(
        console,
        Align.center(Group(content)),
        title=title,
        expand=False,
    )