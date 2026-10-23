from __future__ import annotations

from rich.console import Console
from rich.text import Text

from ui.theme import status_style, status_symbol

STATUS_LABELS = {
    "success": "SUCCESS",
    "completed": "COMPLETED",
    "warning": "WARNING",
    "partial": "PARTIAL",
    "error": "ERROR",
    "failed": "FAILED",
    "timeout": "TIMEOUT",
    "info": "INFO",
    "running": "RUNNING",
    "pending": "PENDING",
    "skipped": "SKIPPED",
}

def format_status(status: str, *, label: str | None = None) -> Text:
    """Build a consistently styled status indicator."""
    normalized = status.strip().lower()
    style = status_style(normalized)
    symbol = status_symbol(normalized)
    display_label = label or STATUS_LABELS.get(
        normalized, normalized.upper() or "UNKNOWN"
    )

    result = Text()
    result.append(f"{symbol} ", style=style)
    result.append(display_label, style=style)
    return result


def print_status(
    console: Console,
    status: str,
    message: str,
    *,
    label: str | None = None,
) -> None:
    """Print a status indicator followed by a message."""
    line = Text()
    line.append_text(format_status(status, label=label))
    line.append("  ")
    line.append(message, style="text")
    console.print(line)

def print_collector_status(
    console: Console,
    collector: str,
    status: str,
    message: str = "",
) -> None:
    """Print a status line associated with a collector."""
    line = Text()
    line.append_text(format_status(status))
    line.append("  ")
    line.append(collector, style="target")

    if message:
        line.append("  ")
        line.append(message, style="muted")

    console.print(line)