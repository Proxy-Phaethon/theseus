from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

MINOTAUR = r"""
           ███                      ███
         ████████                ████████
        ██████████   ██    ██  ███████████
       ███     ████████    ████████     ███
       █▒█        ████      ████        █▒█
       █▓█     ███ █          █ ███     █▓█
       ███        █            █        ███
       ███         ██        ██         ███
        ███         ██      ██         ███
           ██       ██      ██       ██
                    ███    ███
                      █    █
                      █    █

                       █  █
""".strip("\n")

def render_banner(
    console: Console,
    version: str = "0.7.0",
    *,
    subtitle: str = "INTERNET EXPLORER  /  OSINT INVESTIGATION",
) -> None:
    """Render the Theseus startup banner."""

    emblem = Text(MINOTAUR, style="primary", justify="center")
    identity = Text()
    identity.append("THESEUS", style="bold text")
    identity.append(f"  v{version}", style="muted")

    tagline = Text(subtitle, style="dim")

    content = Group(
        Align.center(emblem),
        Align.center(identity),
        Align.center(tagline),
    )

    console.print()
    console.print(
        Panel(
            content,
            border_style="border",
            padding=(1, 2),
            expand=False,
        ),
        justify="center",
    )
    console.print()