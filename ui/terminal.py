import os
import sys

from rich.console import Console

from ui.theme import THESEUS_THEME

def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}

PLAIN_MODE = env_flag("THESEUS_PLAIN")
COLOR_ENABLED = not PLAIN_MODE and "NO_COLOR" not in os.environ
INTERACTIVE = (
    sys.stdout.isatty()
    and not PLAIN_MODE
)

ANIMATION_ENABLED = (
    INTERACTIVE
    and COLOR_ENABLED
    and not env_flag("THESEUS_NO_ANIMATION")
)

console = Console(
    theme=THESEUS_THEME,
    no_color=not COLOR_ENABLED,
    force_terminal=INTERACTIVE,
    highlight=False,
)

def clear() -> None:
    if INTERACTIVE:
        console.clear()

def print_text(message: str = "", style: str | None = None) -> None:
    console.print(message, style=style)

def print_separator(
    character: str = "─",
    style: str = "case.separator",
) -> None:
    """Print a terminal-width separator."""
    console.rule(style=style, characters=character)

def is_interactive() -> bool:
    return INTERACTIVE

def animations_enabled() -> bool:
    return ANIMATION_ENABLED