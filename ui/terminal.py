from __future__ import annotations

import sys
from dataclasses import dataclass

from rich.console import Console

from ui.theme import create_console

@dataclass(frozen=True)
class TerminalConfig:
    """Resolved terminal settings for a Theseus CLI session."""

    plain: bool
    interactive: bool
    animate: bool
    color: bool

def detect_terminal(
    *,
    force_plain: bool = False,
    force_color: bool = False,
    stdin=None,
    stdout=None,
    stderr=None,
) -> TerminalConfig:
    """Determine whether styling and animation are appropriate.

    Plain mode takes precedence over forced color. Animation is enabled
    only when both stdin and stdout are interactive terminals.
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    stdin_tty = _is_tty(stdin)
    stdout_tty = _is_tty(stdout)
    stderr_tty = _is_tty(stderr)

    plain = force_plain or (
        not force_color
        and (
            _env_enabled("NO_COLOR")
            or _env_enabled("THESEUS_PLAIN")
            or not stdout_tty
        )
    )

    interactive = stdin_tty and stdout_tty
    color = not plain and (force_color or stdout_tty)
    animate = interactive and not plain

    return TerminalConfig(
        plain=plain,
        interactive=interactive,
        animate=animate,
        color=color,
    )

def create_terminal_console(
    config: TerminalConfig,
    *,
    stderr: bool = False,
) -> Console:
    """Create a Rich console using the resolved terminal settings."""
    console = create_console(
        plain=config.plain or not config.color,
        stderr=stderr,
    )

    if not config.interactive:
        console = Console(
            theme=console._theme,
            no_color=config.plain or not config.color,
            highlight=False,
            soft_wrap=False,
            stderr=stderr,
            force_terminal=False,
        )

    return console

def _is_tty(stream) -> bool:
    """Safely check whether a stream is attached to a terminal."""
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False

def _env_enabled(name: str) -> bool:
    """Return whether an environment variable is set to a truthy value."""
    value = __import__("os").environ.get(name, "").strip().lower()
    return value not in ("", "0", "false", "no", "off")