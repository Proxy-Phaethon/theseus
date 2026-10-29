from __future__ import annotations

import shlex
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

CommandCallback = Callable[[str | None], None]

@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Definition of a terminal command."""

    name: str
    description: str
    callback: CommandCallback
    usage: str | None = None
    aliases: tuple[str, ...] = ()

@dataclass(slots=True)
class CommandHandler:
    """Reusable command registration, execution, and terminal rendering."""

    console: Console
    app_name: str = "Application"
    version: str = "1.0.0"
    description: str = "Interactive terminal application"
    history_limit: int | None = None

    history: list[str] = field(default_factory=list, init=False)
    should_quit: bool = field(default=False, init=False)
    _commands: dict[str, CommandSpec] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _aliases: dict[str, str] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Register the standard terminal commands."""
        self.register(
            "help",
            "Show available commands or details about one command.",
            self._help,
            usage="help [command]",
            aliases=("?",),
        )
        self.register(
            "about",
            "Show application information.",
            self._about,
            usage="about",
        )
        self.register(
            "clear",
            "Clear the visible terminal screen.",
            self._clear,
            usage="clear",
        )
        self.register(
            "history",
            "Show completed targets recorded during this session.",
            self._history,
            usage="history",
        )
        self.register(
            "quit",
            "Exit the interactive session.",
            self._quit,
            usage="quit",
            aliases=("q", "bye", "exit"),
        )

    def register(
        self,
        name: str,
        description: str,
        callback: CommandCallback,
        *,
        usage: str | None = None,
        aliases: Iterable[str] = (),
    ) -> None:
        """Register a command or replace an existing command definition."""
        name = name.strip().lower().lstrip("/")

        if not name or any(char.isspace() for char in name):
            raise ValueError("Command names must be non-empty single words.")

        alias_names = tuple(
            alias.strip().lower().lstrip("/")
            for alias in aliases
        )

        if any(
            not alias or any(char.isspace() for char in alias)
            for alias in alias_names
        ):
            raise ValueError("Command aliases must be non-empty single words.")

        if len(set(alias_names)) != len(alias_names):
            raise ValueError(f"Duplicate aliases for command: {name}")

        if name in alias_names:
            raise ValueError("A command cannot alias itself.")

        reserved_names = set(alias_names) | {name}

        for registered_name in reserved_names:
            existing_command = self._aliases.get(registered_name)

            if (
                existing_command is not None
                and existing_command != name
            ):
                raise ValueError(
                    f"'{registered_name}' is already an alias for "
                    f"'{existing_command}'."
                )

            if (
                registered_name in self._commands
                and registered_name != name
            ):
                raise ValueError(
                    f"'{registered_name}' is already a registered command."
                )

        # Remove the previous aliases when replacing a command.
        previous = self._commands.get(name)
        if previous is not None:
            for alias in previous.aliases:
                self._aliases.pop(alias, None)

        spec = CommandSpec(
            name=name,
            description=description,
            callback=callback,
            usage=usage or name,
            aliases=alias_names,
        )

        self._commands[name] = spec

        for alias in alias_names:
            self._aliases[alias] = name

    def unregister(self, name: str) -> bool:
        """Remove a command and its aliases. Return whether it existed."""
        name = name.strip().lower().lstrip("/")
        name = self._aliases.get(name, name)

        spec = self._commands.pop(name, None)
        if spec is None:
            return False

        for alias in spec.aliases:
            self._aliases.pop(alias, None)

        return True

    def execute(
        self,
        command: str,
        argument: str | None = None,
    ) -> bool:
        """Execute a command. Return False if it is not recognised.

        Accepts either a complete command line or a command and argument
        supplied separately.
        """
        if argument is None:
            try:
                parts = shlex.split(command.strip())
            except ValueError as exc:
                self._message(
                    f"Invalid command syntax: {exc}",
                    status="warning",
                )
                return True

            if not parts:
                return True

            name = parts[0].lower().lstrip("/")
            argument = " ".join(parts[1:]) or None
        else:
            name = command.strip().lower().lstrip("/")
            argument = argument.strip() or None

        name = self._aliases.get(name, name)
        spec = self._commands.get(name)

        if spec is None:
            return False

        try:
            spec.callback(argument)
        except Exception as exc:
            self._message(
                f"Command '{name}' failed: {exc}",
                status="error",
            )

        return True

    def record_history(self, target: str) -> None:
        """Record a completed target in session history."""
        target = target.strip()

        if not target:
            return

        self.history.append(target)

        if self.history_limit is not None:
            if self.history_limit < 0:
                raise ValueError("history_limit cannot be negative.")

            if self.history_limit == 0:
                self.history.clear()
            else:
                del self.history[:-self.history_limit]

    def _help(self, argument: str | None = None) -> None:
        """Display the command list or details about one command."""
        if argument:
            name = argument.strip().lower().lstrip("/")
            name = self._aliases.get(name, name)
            spec = self._commands.get(name)

            if spec is None:
                self._message(
                    f"Unknown command: {argument}",
                    status="warning",
                )
                return

            details = Table.grid(padding=(0, 1))
            details.add_column(style="muted", no_wrap=True)
            details.add_column(style="text", overflow="fold")

            details.add_row("Usage", spec.usage or spec.name)
            details.add_row("Description", spec.description)

            if spec.aliases:
                details.add_row("Aliases", ", ".join(spec.aliases))

            self._panel(details, title=f"Command: {spec.name}")
            return

        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("Command", style="primary", no_wrap=True)
        table.add_column("Description", style="text", overflow="fold")

        for spec in sorted(self._commands.values(), key=lambda item: item.name):
            names = spec.name

            if spec.aliases:
                names += " (" + ", ".join(spec.aliases) + ")"

            table.add_row(names, spec.description)

        self._panel(table, title="Available commands")
        self.console.print(
            Text(
                "Use 'help <command>' for more information.",
                style="muted",
            )
        )

    def _about(self, _argument: str | None = None) -> None:
        """Display application information."""
        content = Table.grid(padding=(0, 1))
        content.add_column(style="muted", no_wrap=True)
        content.add_column(style="text", overflow="fold")

        content.add_row("Application", self.app_name)
        content.add_row("Version", f"v{self.version}")
        content.add_row("Description", self.description)

        self._panel(content, title=f"About {self.app_name}")

    def _clear(self, _argument: str | None = None) -> None:
        """Clear the visible terminal without changing session state."""
        self.console.clear()

    def _history(self, _argument: str | None = None) -> None:
        """Display completed targets recorded during this session."""
        if not self.history:
            self._message(
                "No completed targets have been recorded this session.",
                title="Session history",
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

        self._panel(
            table,
            title=f"Session history ({len(self.history)})",
        )
        self.console.print(
            Text(
                "History is held in memory and is not written to disk.",
                style="muted",
            )
        )

    def _quit(self, _argument: str | None = None) -> None:
        """Signal the application's input loop to exit."""
        self.should_quit = True
        self.console.print(Text("Exiting.", style="muted"))

    def _panel(
        self,
        renderable: object,
        *,
        title: str,
    ) -> None:
        """Render a consistently styled terminal panel."""
        self.console.print(
            Panel(
                renderable,
                title=title,
                border_style="border",
                expand=False,
            )
        )

    def _message(
        self,
        message: str,
        *,
        title: str = "Notice",
        status: str = "info",
    ) -> None:
        """Render a standard terminal message."""
        styles = {
            "info": "primary",
            "success": "success",
            "warning": "warning",
            "error": "error",
        }

        self.console.print(
            Panel(
                Text(message, style="text"),
                title=title,
                border_style=styles.get(status, "border"),
                expand=False,
            )
        )