import json
import re

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.prompt import Prompt

from ui.terminal import console, clear
from ui.status import error, system
from ui.banner import initialize
from ui.progress import extraction_progress
from ui.panels import (
    render_investigation,
    render_provenance,
    render_related_entities,
)
from ui.commands import CommandHandler

class TheseusShell:

    EXPORT_DIRECTORY = Path("exports")

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

    @staticmethod
    def ask_yes_no(question: str) -> bool:
        answer = Prompt.ask(
            question,
            choices=["y", "n"],
            default="n",
            show_choices=True,
            console=console,
        )

        return answer.lower() == "y"

    def export_response(self, response: dict) -> None:
        try:
            self.EXPORT_DIRECTORY.mkdir(
                parents=True,
                exist_ok=True,
            )

            domain = response.get("domain", "unknown")

            safe_domain = re.sub(
                r"[^a-zA-Z0-9._-]",
                "_",
                str(domain),
            )

            timestamp = datetime.now().astimezone().strftime(
                "%Y%m%d_%H%M%S"
            )

            filename = (
                f"{safe_domain}_{timestamp}.json"
            )

            filepath = self.EXPORT_DIRECTORY / filename

            with filepath.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    response,
                    file,
                    indent=4,
                    ensure_ascii=False,
                    default=str,
                )

            system(
                f"Full response exported to: {filepath}"
            )

        except (OSError, TypeError, ValueError) as exc:
            error(f"Could not export response: {exc}")

    def handle_supplementary_information(
        self,
        response: dict,
    ) -> None:

        modules = response.get("modules", [])

        has_provenance = any(
            isinstance(module, dict) and module.get("provenance")
            for module in modules
        )

        has_related_entities = any(
            isinstance(module, dict) and module.get("related_entities")
            for module in modules
        )

        if has_provenance:
            if self.ask_yes_no("Print provenance?"):
                render_provenance(response)

        if has_related_entities:
            if self.ask_yes_no("Print related entities?"):
                render_related_entities(response)

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

            truncated = render_investigation(response)

            self.handle_supplementary_information(response)

            if truncated:
                console.print()

                if self.ask_yes_no(
                    "Display full response through a JSON export?"
                ):
                    self.export_response(response)

            console.print()

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
                system(
                    "INTERRUPTED. TYPE 'exit' TO TERMINATE."
                )
                console.print()

            except EOFError:
                self.running = False

        console.print()

        console.rule(
            "[muted]SESSION TERMINATED[/muted]",
            style="case.separator",
        )

        console.print()