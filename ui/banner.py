import time
from pathlib import Path

from rich.console import Group
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from ui.terminal import (
    ANIMATION_ENABLED,
    INTERACTIVE,
    console,
    clear,
)

VERSION = "1.0.0"
DESCRIPTION = "DIGITAL ARTEFACT EXTRACTION SYSTEM"
MINIMUM_DURATION = 3.0

ASSET_PATH = Path(__file__).parent / "assets" / "minotaur.txt"

def load_logo() -> str:
    try:
        return ASSET_PATH.read_text(encoding="utf-8").rstrip()
    except OSError:
        return "THESEUS"

def build_banner() -> Group:
    logo = Text(
        load_logo(),
        style="accent",
        justify="center",
    )

    title = Text("THESEUS", style="bold white", justify="center")
    version = Text(f"VERSION {VERSION}", style="muted", justify="center")
    description = Text(DESCRIPTION, style="muted", justify="center")

    return Group(
        logo,
        Text(""),
        title,
        version,
        Text(""),
        description,
        Text(""),
    )

def initialize() -> None:
    start_time = time.monotonic()

    banner = build_banner()

    if ANIMATION_ENABLED:
        loading = Spinner(
            "dots",
            text=Text(" INITIALISING SYSTEM...", style="accent"),
            style="accent",
        )

        display = Group(banner, loading)

        with Live(
            display,
            console=console,
            refresh_per_second=12,
            transient=True,
        ):
            elapsed = time.monotonic() - start_time
            remaining = max(0, MINIMUM_DURATION - elapsed)
            time.sleep(remaining)

    else:
        console.print(banner)
        console.print(
            "INITIALISING SYSTEM...",
            style="accent",
        )

        elapsed = time.monotonic() - start_time
        remaining = max(0, MINIMUM_DURATION - elapsed)
        time.sleep(remaining)

    if INTERACTIVE:
        clear()

if __name__ == "__main__":
    initialize()