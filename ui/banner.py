from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

ASSET_DIR = Path(__file__).parent / "assets"
MINOTAUR_PATH = ASSET_DIR / "minotaur.txt"

def load_minotaur() -> str:
    """Load the Minotaur emblem while preserving its artwork spacing."""
    return MINOTAUR_PATH.read_text(encoding="utf-8").rstrip("\n")

def render_banner(
    console: Console,
    version: str = "0.7.0",
    *,
    subtitle: str = "INTERNET EXPLORER  /  OSINT INVESTIGATION TOOL",
) -> None:
    """Render the Theseus startup banner."""

    emblem = Text(load_minotaur(), style="primary", no_wrap=True)

    identity = Text()
    identity.append("THESEUS", style="bold text")
    identity.append(f"  v{version}", style="muted")

    tagline = Text(subtitle, style="dim")

    content = Group(
        emblem,
        Text(),
        identity,
        tagline,
    )

    console.print()
    console.print(
        Panel(
            content,
            border_style="border",
            padding=(1, 2),
            expand=False,
        )
    )
    console.print()