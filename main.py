from __future__ import annotations

from rich.console import Console
from rich.text import Text

from core.identifier import identify
from ui.banner import print_banner
from ui.commands import CommandHandler
from ui.theme import configure_theme

VERSION = "1.0.0"
APP_NAME = "THESEUS"
DESCRIPTION = "A digital artefact extraction and intelligence platform"

def main() -> None:
    """Initialise the terminal and run the interactive input loop."""
    configure_theme()

    console = Console()

    commands = CommandHandler(
        console=console,
        app_name=APP_NAME,
        version=VERSION,
        description=DESCRIPTION,
    )

    print_banner(console)

    while not commands.should_quit:
        try:
            user_input = console.input(
                Text("theseus › ", style="primary")
            ).strip()

        except (KeyboardInterrupt, EOFError):
            console.print()
            break

        if not user_input:
            continue

        # Helper commands are handled by the terminal UI.
        if commands.execute(user_input):
            continue

        # Everything else is passed to the identifier.
        try:
            result = identify(user_input)

            if result is not None:
                console.print(result)

        except Exception as exc:
            console.print(
                Text(
                    f"Unable to process input: {exc}",
                    style="error",
                )
            )

    console.print(Text("Session ended.", style="muted"))

if __name__ == "__main__":
    main()