from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import TextIO

from rich.console import Console

from ui.theme import THEME

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
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> TerminalConfig:
    """Determine whether styling and animation are appropriate.

    Plain mode takes precedence over forced color. Animation requires
    both stdin and stdout to be attached to terminals.
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    stdin_tty = _is_tty(stdin)
    stdout_tty = _is_tty(stdout)

    no_color = _env_enabled("NO_COLOR")
    plain_env = _env_enabled("THESEUS_PLAIN")

    plain = force_plain or plain_env or (
        no_color and not force_color
    )

    interactive = stdin_tty and stdout_tty

    color = not plain and (stdout_tty or force_color)

    return TerminalConfig(
        plain=plain,
        interactive=interactive,
        animate=interactive and not plain,
        color=color,
    )

def create_terminal_console(
    config: TerminalConfig,
    *,
    stderr: bool = False,
) -> Console:
    """Create a Rich console using the shared Theseus theme."""
    return Console(
        theme=THEME,
        no_color=config.plain or not config.color,
        highlight=False,
        soft_wrap=False,
        stderr=stderr,
        force_terminal=config.interactive and config.color,
    )

def _is_tty(stream: TextIO) -> bool:
    """Safely check whether a stream is attached to a terminal."""
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False

def _env_enabled(name: str) -> bool:
    """Return whether an environment variable is set to a truthy value."""
    value = os.environ.get(name, "").strip().lower()
    return value not in {"", "0", "false", "no", "off"}