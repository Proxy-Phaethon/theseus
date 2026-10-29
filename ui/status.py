"""Standalone status formatting for Theseus."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from ui.theme import status_style, status_symbol

STATUS_LABELS = {
    "success": "SUCCESS",
    "completed": "COMPLETED",
    "partial_success": "PARTIAL SUCCESS",
    "partial": "PARTIAL",
    "failed": "FAILED",
    "failure": "FAILURE",
    "error": "ERROR",
    "timeout": "TIMEOUT",
    "not_supported": "NOT SUPPORTED",
    "not_implemented": "NOT IMPLEMENTED",
    "running": "RUNNING",
    "pending": "PENDING",
    "skipped": "SKIPPED",
    "info": "INFO",
}

# Map equivalent statuses to the shared theme's existing styles.
STYLE_ALIASES = {
    "completed": "success",
    "partial_success": "partial",
    "failure": "error",
    "failed": "error",
    "timeout": "error",
    "not_supported": "skipped",
    "not_implemented": "skipped",
}

SYMBOL_ALIASES = {
    "completed": "success",
    "partial_success": "partial",
    "failure": "error",
    "failed": "error",
    "timeout": "error",
    "not_supported": "skipped",
    "not_implemented": "skipped",
}

def normalize_status(status: str) -> str:
    """Normalize a status value without assuming its source."""
    if not isinstance(status, str):
        return "unknown"

    normalized = status.strip().lower().replace("-", "_").replace(" ", "_")

    aliases = {
        "complete": "completed",
        "partial_successful": "partial_success",
        "unsupported": "not_supported",
        "unimplemented": "not_implemented",
        "fail": "failed",
    }

    return aliases.get(normalized, normalized or "unknown")

def format_status(
    status: str,
    *,
    label: str | None = None,
) -> Text:
    """Return a styled status indicator."""
    normalized = normalize_status(status)
    style_status = STYLE_ALIASES.get(normalized, normalized)
    symbol_status = SYMBOL_ALIASES.get(normalized, normalized)

    style = status_style(style_status)
    symbol = status_symbol(symbol_status)
    display_label = label or STATUS_LABELS.get(
        normalized,
        normalized.replace("_", " ").upper(),
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
    """Print a standalone status line."""
    line = Text()
    line.append_text(format_status(status, label=label))
    line.append("  ")
    line.append(str(message), style="text")
    console.print(line)

def print_task_status(
    console: Console,
    task: str,
    status: str,
    message: str = "",
) -> None:
    """Print a status line for an extractor or pipeline task."""
    line = Text()
    line.append_text(format_status(status))
    line.append("  ")
    line.append(str(task), style="target")

    if message:
        line.append("  ")
        line.append(str(message), style="muted")

    console.print(line)

def print_collector_status(
    console: Console,
    collector: str,
    status: str,
    message: str = "",
) -> None:
    """Backward-compatible wrapper for existing collector callers."""
    print_task_status(console, collector, status, message)