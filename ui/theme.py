from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

TEAL = "#39D6C0"
CYAN = "#50CFE8"
AMBER = "#E8BD5A"
RED = "#FF6474"
MUTED = "#91A5AE"
TEXT = "#D1DEE1"
DIM = "#71858D"
BORDER = "#26383D"

THEME = Theme(
    {
        "primary": TEAL,
        "accent": CYAN,
        "success": f"bold {TEAL}",
        "warning": f"bold {AMBER}",
        "error": f"bold {RED}",
        "info": MUTED,
        "muted": MUTED,
        "dim": DIM,
        "text": TEXT,
        "border": BORDER,
        "heading": f"bold {TEAL}",
        "target": f"bold {TEXT}",
        "running": CYAN,
    }
)

STATUS_SYMBOLS = {
    "success": "✓",
    "warning": "!",
    "error": "✗",
    "info": "·",
    "running": "›",
    "pending": "○",
    "skipped": "–",
}

def create_console(*, plain: bool = False, stderr: bool = False) -> Console:
    """Create a consistently configured Rich console.

    Args:
        plain: Disable colors, styling, and terminal control sequences.
        stderr: Write to stderr instead of stdout.
    """
    return Console(
        theme=THEME,
        no_color=plain,
        highlight=False,
        soft_wrap=False,
        stderr=stderr,
    )

def status_style(status: str) -> str:
    """Return the Rich style associated with a status."""
    styles = {
        "success": "success",
        "completed": "success",
        "warning": "warning",
        "partial": "warning",
        "error": "error",
        "failed": "error",
        "timeout": "error",
        "info": "info",
        "running": "running",
        "pending": "muted",
        "skipped": "dim",
    }
    return styles.get(status.lower(), "text")

def status_symbol(status: str) -> str:
    """Return the symbol associated with a status."""
    symbols = {
        **STATUS_SYMBOLS,
        "completed": STATUS_SYMBOLS["success"],
        "partial": STATUS_SYMBOLS["warning"],
        "failed": STATUS_SYMBOLS["error"],
        "timeout": STATUS_SYMBOLS["error"],
    }
    return symbols.get(status.lower(), STATUS_SYMBOLS["info"])