from collections.abc import Callable
from typing import Any

from rich.prompt import Prompt

from ui.terminal import console, clear
from ui.status import error, system
from ui.banner import initialize
from ui.progress import extraction_progress
from ui.panels import render_investigation
from ui.commands import CommandHandler

class TheseusShell:
    def __init__(
        self,
        processor: Callable[[Any], dict],
        version: str = "1.0.0",
    ):
        self.processor = processor
        self.version = version
        self.running = True
        self.commands = CommandHandler()

    def display_welcome(self) -> None:
        console.print()
        console.rule(
            "[heading]THESEUS[/heading]",
            style="accent",
        )

        console.print(
            "[muted]DIGITAL ARTEFACT EXTRACTION SYSTEM[/muted]"
        )

        console.print()

        console.print(
            "[label]SYSTEM STATUS[/label]    "
            "[success]OPERATIONAL[/success]"
        )

        console.print(
            f"[label]VERSION[/label]           [value]{self.version}[/value]"
        )

        console.print()

        console.print(
            "[label]Enter a domain or URL to begin extraction.[/label]"
        )
        console.print(
            "[label]Type 'help' to view available commands.[/label]"
        )

        console.print()
        console.rule(style="case.separator")
        console.print()

    def handle_command(self, value: str) -> bool:
        command = value.strip().lower()

        if command in {"exit", "quit"}:
            self.commands.execute(command)
            self.running = False
            return True

        if command == "clear":
            self.commands.execute(command)
            clear()
            self.display_welcome()
            return True

        if command in {"help", "input"}:
            self.commands.execute(command)
            return True

        return False

    def process_input(self, value: str) -> None:
        try:
            with extraction_progress():
                response = self.processor(value)

            if not isinstance(response, dict):
                error(
                    "The processing pipeline returned an invalid response."
                )
                return

            console.print()
            render_investigation(response)

        except KeyboardInterrupt:
            console.print()
            error("Operation interrupted by user.")

        except Exception as exc:
            console.print()
            error(f"Operation failed: {exc}")

    def run(self) -> None:
        initialize()
        self.display_welcome()

        while self.running:
            try:
                value = Prompt.ask(
                    "[prompt]>",
                    console=console,
                    default="",
                ).strip()

                if not value:
                    continue

                if self.handle_command(value):
                    continue

                self.process_input(value)

            except KeyboardInterrupt:
                console.print()
                system("INTERRUPTED. TYPE 'exit' TO TERMINATE.")
                console.print()

            except EOFError:
                self.running = False

        console.print()
        console.rule(
            "[muted]SESSION TERMINATED[/muted]",
            style="case.separator",
        )
        console.print()