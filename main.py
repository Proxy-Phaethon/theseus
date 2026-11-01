"""Theseus interactive terminal application."""

from __future__ import annotations

import shlex
import sys
import json

from rich.text import Text

from core.packets import Packet, PacketStatus
from core.identifier import Identifier
from core.executor import Executor
from core.responder import Responder

from ui.banner import render_banner
from ui.commands import CommandHandler
from ui.progress import ProgressDisplay
from ui.terminal import detect_terminal, create_terminal_console

VERSION = "1.0.0"
DESCRIPTION = "Digital artefact extraction tool."

class Theseus:
    """Coordinate the interactive Theseus terminal session."""

    def __init__(self) -> None:
        self.config = detect_terminal()
        self.console = create_terminal_console(self.config)

        self.identifier = Identifier()
        self.executor = Executor()
        self.responder = Responder()

        self.commands = CommandHandler(
            console=self.console,
            app_name="Theseus",
            version=VERSION,
            description=DESCRIPTION,
        )

    def start(self) -> None:
        """Launch the application and maintain the input loop."""

        render_banner(
            self.console,
            version=VERSION,
            subtitle="DIGITAL ARTEFACT EXTRACTION TOOL",
        )

        self.console.print(
            Text(
                "Enter an extraction flag followed by its input.",
                style="muted",
            )
        )
        self.console.print(
            Text(
                "Type 'help' to see available commands.",
                style="muted",
            )
        )
        self.console.print()

        while not self.commands.should_quit:
            try:
                user_input = self.console.input(
                    "[primary]theseus[/primary] [muted]>[/muted] "
                ).strip()

                if not user_input:
                    continue

                self.handle_input(user_input)

            except KeyboardInterrupt:
                self.console.print()
                self.console.print(
                    Text(
                        "Use 'q' or 'quit' to exit Theseus.",
                        style="muted",
                    )
                )

            except EOFError:
                self.console.print()
                self.commands.should_quit = True

        self.console.print(
            Text("Session terminated.", style="muted")
        )

    def handle_input(self, user_input: str) -> None:
        """Determine whether input is a command or extraction request."""

        if self.commands.execute(user_input):
            return

        try:
            parts = shlex.split(user_input)
        except ValueError as exc:
            self.console.print(
                Text(
                    f"Invalid input syntax: {exc}",
                    style="error",
                )
            )
            return

        if not parts:
            return

        flag = parts[0].lower()

        if not flag.startswith("--"):
            self.console.print(
                Text(
                    "Unrecognised command or input. Type 'help' for assistance.",
                    style="warning",
                )
            )
            return

        value = " ".join(parts[1:]) if len(parts) > 1 else None

        if flag == "--http-message" and value is not None:
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                self.console.print(
                    Text(
                        f"Invalid JSON input: {exc}",
                        style="error",
                    )
                )
                return

        self.process_request(flag, value)

    def process_request(
        self,
        flag: str,
        value: str | None,
    ) -> None:
        """Run the identification and extraction pipeline."""

        packet = Packet(
            stage="input",
            artefact_type="unknown",
            input=value,
            metadata={
                "flag": flag,
            },
        )

        progress = ProgressDisplay(
            console=self.console,
            animate=self.config.animate,
        )

        progress.register(
            "Identification",
            "Checking input type and structure.",
        )
        progress.register(
            "Extraction",
            "Waiting for identification.",
        )

        progress.start()

        try:

            progress.start_task(
                "Identification",
                "Validating supplied input.",
            )

            report = self.identifier.identify(packet)

            if report.status != PacketStatus.SUCCESS:
                progress.fail(
                    "Identification",
                    "Input was not recognised or supported.",
                )
                progress.skip(
                    "Extraction",
                    "Identification unsuccessful.",
                )

                progress.finish()
                self.display_result(report)
                return

            progress.complete(
                "Identification",
                f"Recognised {report.artefact_type} input.",
            )

            progress.start_task(
                "Extraction",
                "Running compatible extractors.",
            )

            results = self.executor.execute(report)

            if not isinstance(results, list) or not results:
                progress.fail(
                    "Extraction",
                    "No extraction responses were returned.",
                )
                progress.finish()

                self.console.print(
                    Text(
                        "Executor returned no valid extraction responses.",
                        style="error",
                    )
                )
                return

            successful = sum(
                result.status in {
                    PacketStatus.SUCCESS,
                    PacketStatus.PARTIAL_SUCCESS,
                }
                for result in results
                if isinstance(result, Packet)
            )

            failed = sum(
                result.status in {
                    PacketStatus.FAILED,
                    PacketStatus.NOT_SUPPORTED,
                    PacketStatus.NOT_IMPLEMENTED,
                }
                for result in results
                if isinstance(result, Packet)
            )

            pending = sum(
                result.status in {
                    PacketStatus.PENDING,
                    PacketStatus.RUNNING,
                }
                for result in results
                if isinstance(result, Packet)
            )

            if successful == len(results) and pending == 0:
                progress.complete(
                    "Extraction",
                    f"All {len(results)} extractor(s) completed successfully.",
                )

            elif successful > 0:
                progress.partial(
                    "Extraction",
                    f"{successful} successful, {failed} failed.",
                )

            elif pending > 0:
                progress.partial(
                    "Extraction",
                    "Some extractors are still running.",
                )

            else:
                progress.fail(
                    "Extraction",
                    f"All {failed} extractor(s) failed.",
                )

            progress.finish()

            self.display_result(results)

            if successful > 0:
                self.commands.record_history(
                    str(value)
                )

        except Exception as exc:
            progress.finish()

            self.console.print(
                Text(
                    f"An unexpected error occurred: {exc}",
                    style="error",
                )
            )

    def display_result(
        self,
        packets: Packet | list[Packet],
    ) -> None:
        """Format and display extraction responses."""

        if isinstance(packets, Packet):
            packets = [packets]

        response = self.responder.respond(packets)

        self.console.print()
        self.console.print(response)
        self.console.print()

def main() -> None:
    """Application entry point."""

    try:
        application = Theseus()
        application.start()

    except KeyboardInterrupt:
        print("\nTheseus interrupted.")
        sys.exit(130)

    except Exception as exc:
        print(
            f"Theseus encountered an unexpected error: {exc}"
        )
        sys.exit(1)

if __name__ == "__main__":
    main()