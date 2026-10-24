from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.identifier import Command, CommandType, EntityType
from registry.collectors import (
    CollectorStatus,
    get_collectors,
    get_normalizer,
    get_status,
)
from ui.panels import print_message_panel, print_panel
from ui.status import print_status

class CommandHandler:
    """Execute CLI helper commands and render their output."""

    def __init__(
        self,
        console: Console,
        responders: dict[EntityType, object],
        *,
        version: str = "0.7.0",
    ) -> None:
        self.console = console
        self.responders = responders
        self.version = version
        self.history: list[str] = []
        self.should_quit = False

    def execute(self, command: Command) -> None:
        """Execute a recognized command."""
        handlers = {
            CommandType.HELP: self._help,
            CommandType.ABOUT: self._about,
            CommandType.CLEAR: self._clear,
            CommandType.HISTORY: self._history,
            CommandType.STATUS: self._status,
            CommandType.QUIT: self._quit,
        }

        handler = handlers.get(command.type)

        if handler is None:
            print_status(
                self.console,
                "warning",
                f"Unsupported command: {command.type.value}",
            )
            return

        handler(command.argument)

    def record_investigation(self, target: str) -> None:
        """Record a target after its investigation completes."""
        target = target.strip()

        if target:
            self.history.append(target)

    def _help(self, argument: str | None = None) -> None:
        """Display general help or details for a specific command."""
        if argument:
            self._help_command(argument)
            return

        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("Command", style="primary", no_wrap=True)
        table.add_column("Description", style="text")

        commands = [
            ("help", "Show available commands."),
            ("help <command>", "Show details for a specific command."),
            ("about", "Show information about Theseus."),
            ("clear", "Clear the terminal screen."),
            ("history", "Show completed investigation targets."),
            ("status", "Show implemented investigation workflows."),
            ("q / quit / bye / exit", "Exit Theseus."),
        ]

        for name, description in commands:
            table.add_row(name, description)

        print_panel(
            self.console,
            table,
            title="Helper commands",
            expand=False,
        )

        self.console.print(
            Text(
                "\nEnter an email address to start an investigation. "
                "Additional entity types will become available as their "
                "new investigation workflows are implemented.",
                style="muted",
            )
        )

    def _help_command(self, argument: str) -> None:
        """Display information about one supported command."""
        name = argument.strip().lower().lstrip("/")

        aliases = {
            "q": "quit",
            "q.": "quit",
            "quit.": "quit",
            "bye": "quit",
            "bye.": "quit",
            "exit": "quit",
            "exit.": "quit",
        }
        name = aliases.get(name, name)

        details = {
            "help": (
                "help [command]",
                "Display the command list or explain a specific command.",
                "Examples: help, help history",
            ),
            "about": (
                "about",
                "Display the version and purpose of Theseus.",
                "Does not start an investigation.",
            ),
            "clear": (
                "clear",
                "Clear the visible terminal screen.",
                "Does not delete investigation history.",
            ),
            "history": (
                "history",
                "Display targets investigated during this session.",
                "History is kept in memory and is not written to disk.",
            ),
            "status": (
                "status",
                "Display which entity types have implemented collector workflows.",
                "Reports registry configuration, not live collector availability.",
            ),
            "quit": (
                "q / quit / bye / exit",
                "Exit the Theseus interactive session.",
                "All listed aliases are accepted.",
            ),
        }

        detail = details.get(name)

        if detail is None:
            print_status(
                self.console,
                "warning",
                f"Unknown helper command: {argument}",
            )
            self.console.print(
                "[muted]Use 'help' to see available commands.[/muted]"
            )
            return

        syntax, description, note = detail

        content = Table.grid(padding=(0, 1))
        content.add_column(style="muted", no_wrap=True)
        content.add_column(style="text", overflow="fold")
        content.add_row("Usage", syntax)
        content.add_row("Description", description)
        content.add_row("Note", note)

        print_panel(
            self.console,
            content,
            title=f"Command: {name}",
            expand=False,
        )

    def _about(self, _argument: str | None = None) -> None:
        """Display project information."""
        content = Table.grid(padding=(0, 1))
        content.add_column(style="muted", no_wrap=True)
        content.add_column(style="text", overflow="fold")
        content.add_row("Project", "Theseus")
        content.add_row("Version", f"v{self.version}")
        content.add_row("Purpose", "Internet exploration and OSINT investigation")
        content.add_row(
            "Approach",
            "Investigates digital targets using its own tools and integrations.",
        )

        print_panel(
            self.console,
            content,
            title="About Theseus",
            expand=False,
        )

    def _clear(self, _argument: str | None = None) -> None:
        """Clear the terminal without changing session state."""
        self.console.clear()
        self.console.print()

    def _history(self, _argument: str | None = None) -> None:
        """Display targets recorded during the current session."""
        if not self.history:
            print_message_panel(
                self.console,
                "No completed investigations have been recorded this session.",
                title="Investigation history",
                status="info",
            )
            return

        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("#", style="muted", justify="right", no_wrap=True)
        table.add_column("Target", style="text", overflow="fold")

        for index, target in enumerate(self.history, start=1):
            table.add_row(str(index), target)

        print_panel(
            self.console,
            table,
            title=f"Investigation history ({len(self.history)})",
            expand=False,
        )

        self.console.print(
            "[muted]Session-only history. Targets are not saved to disk.[/muted]"
        )

    def _status(self, _argument: str | None = None) -> None:
        """Show which entity types have implemented collector workflows."""
        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("Entity type", style="text")
        table.add_column("Collectors", style="text", justify="right")
        table.add_column("Workflow status", style="text")

        for entity_type in EntityType:
            if entity_type == EntityType.UNKNOWN:
                continue

            status = get_status(entity_type)
            collectors = get_collectors(entity_type)
            normalizer = get_normalizer(entity_type)

            component_count = len(collectors)
            if normalizer is not None:
                component_count += 1

            if status == CollectorStatus.IMPLEMENTED:
                status_text = "[success]IMPLEMENTED[/success]"
            else:
                status_text = "[warning]NOT IMPLEMENTED[/warning]"

            table.add_row(
                entity_type.value,
                str(component_count),
                status_text,
            )

        print_panel(
            self.console,
            table,
            title="Investigation workflows",
            expand=False,
        )

        self.console.print(
            "[muted]Status reflects registry configuration, not live service "
            "availability or investigation results.[/muted]"
        )

    def _quit(self, _argument: str | None = None) -> None:
        """Signal the main input loop to exit."""
        self.should_quit = True
        self.console.print("[muted]Exiting Theseus.[/muted]")