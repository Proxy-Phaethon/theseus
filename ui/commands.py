"""Command handling and help system for Theseus."""

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

@dataclass(frozen=True, slots=True)
class FlagSpec:
    """Definition of a Theseus extraction flag."""

    name: str
    category: str
    expected_input: str
    description: str
    implemented: bool = False

# Extraction flag reference.
# Only mark an extractor implemented when it actually exists and works.

FLAG_CATALOG: tuple[FlagSpec, ...] = (
    # Web and internet infrastructure
    FlagSpec("url", "Web", "URL", "Extract URL components.", True),
    FlagSpec("domain", "Web", "Domain name", "Extract domain information."),
    FlagSpec("dns", "Web", "Domain name", "Extract DNS records."),
    FlagSpec("ip", "Network", "IP address", "Extract IP address information."),
    FlagSpec("cidr", "Network", "CIDR range", "Extract network range information."),
    FlagSpec("hostname", "Network", "Hostname", "Extract hostname information."),
    FlagSpec("redirect", "Web", "URL", "Extract redirect information."),
    FlagSpec("http", "Web", "HTTP response or headers", "Extract HTTP metadata."),
    FlagSpec("webpage", "Web", "HTML source or webpage", "Extract webpage information."),
    FlagSpec("javascript", "Web", "JavaScript source", "Extract JavaScript artefacts."),
    FlagSpec("css", "Web", "CSS source", "Extract CSS information."),
    FlagSpec("asn", "Network", "ASN", "Extract autonomous system information."),
    FlagSpec("mac", "Network", "MAC address", "Extract MAC address information."),
    FlagSpec("bssid", "Network", "BSSID", "Extract wireless network identifiers."),
    FlagSpec("port", "Network", "Port or scan result", "Extract port information."),
    FlagSpec("certificate", "Network", "Certificate data", "Extract certificate fields."),
    FlagSpec("tls", "Network", "TLS data", "Extract TLS information."),
    FlagSpec("pcap", "Network", "PCAP file", "Extract packet capture data."),
    FlagSpec("flow", "Network", "Network flow data", "Extract network flow information."),

    # Files and digital media
    FlagSpec("file", "Files", "File path or file data", "Extract general file metadata."),
    FlagSpec("hash", "Files", "File hash", "Extract hash information."),
    FlagSpec("pdf", "Files", "PDF file", "Extract PDF metadata and contents."),
    FlagSpec("office", "Files", "Office document", "Extract Office document metadata."),
    FlagSpec("image", "Media", "Image file", "Extract image metadata."),
    FlagSpec("audio", "Media", "Audio file", "Extract audio metadata."),
    FlagSpec("video", "Media", "Video file", "Extract video metadata."),
    FlagSpec("archive", "Files", "Archive file", "Extract archive contents and metadata."),
    FlagSpec("binary", "Files", "Binary file", "Extract binary file information."),
    FlagSpec("font", "Files", "Font file", "Extract font metadata."),
    FlagSpec("shortcut", "Files", "Shortcut file", "Extract shortcut information."),
    FlagSpec("directory", "Files", "Directory path", "Extract directory information."),

    # Email and communications
    FlagSpec("email", "Communications", "Email message", "Extract email information."),
    FlagSpec("email_headers", "Communications", "Email headers", "Extract email header fields."),
    FlagSpec("message_id", "Communications", "Message-ID", "Extract message identifier information."),
    FlagSpec("contact", "Communications", "Contact data", "Extract contact information."),
    FlagSpec("calendar", "Communications", "Calendar data", "Extract calendar information."),
    FlagSpec("vcf", "Communications", "VCF file", "Extract vCard contact records."),
    FlagSpec("ics", "Communications", "ICS file", "Extract calendar records."),

    # Development and software
    FlagSpec("git_repository", "Software", "Git repository", "Extract repository metadata."),
    FlagSpec("git_commit", "Software", "Git commit", "Extract commit information."),
    FlagSpec("package", "Software", "Package metadata", "Extract software package information."),
    FlagSpec("sbom", "Software", "SBOM document", "Extract software bill of materials."),
    FlagSpec("container", "Software", "Container image or metadata", "Extract container information."),
    FlagSpec("api_spec", "Software", "API specification", "Extract API specification details."),
    FlagSpec("cve", "Software", "CVE identifier or record", "Extract vulnerability record fields."),

    # Structured data and system artefacts
    FlagSpec("json", "Structured Data", "JSON data", "Extract JSON structure and values."),
    FlagSpec("xml", "Structured Data", "XML data", "Extract XML structure and values."),
    FlagSpec("csv", "Structured Data", "CSV file or data", "Extract CSV records."),
    FlagSpec("sqlite", "Structured Data", "SQLite database", "Extract database structure and records."),
    FlagSpec("config", "System", "Configuration file", "Extract configuration data."),
    FlagSpec("env", "System", "Environment file", "Extract environment variables."),
    FlagSpec("registry", "System", "Registry data", "Extract registry information."),
    FlagSpec("log", "System", "Log file or data", "Extract log entries."),
    FlagSpec("browser", "System", "Browser artefacts", "Extract browser information."),
    FlagSpec("har", "Web", "HAR file", "Extract HTTP archive information."),
)

@dataclass(slots=True)
class CommandHandler:
    """Register, execute, and display terminal commands."""

    console: Console
    app_name: str = "Theseus"
    version: str = "1.0.0"
    description: str = "Digital artefact extraction tool."
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
        """Register built-in terminal commands."""

        self.register(
            "help",
            "Show available commands and extraction flags.",
            self._help,
            usage="help [command | --flag]",
            aliases=("?",),
        )
        self.register(
            "flags",
            "List available extraction flags.",
            self._flags,
            usage="flags [category]",
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
            "Show completed extraction inputs.",
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
        """Register or replace a terminal command."""

        name = name.strip().lower().lstrip("/")
        alias_names = tuple(
            alias.strip().lower().lstrip("/")
            for alias in aliases
        )

        if not name or any(char.isspace() for char in name):
            raise ValueError("Command names must be single words.")

        if any(
            not alias or any(char.isspace() for char in alias)
            for alias in alias_names
        ):
            raise ValueError("Command aliases must be single words.")

        if len(set(alias_names)) != len(alias_names):
            raise ValueError(f"Duplicate aliases for command: {name}")

        if name in alias_names:
            raise ValueError("A command cannot alias itself.")

        for registered_name in {name, *alias_names}:
            existing = self._aliases.get(registered_name)

            if existing is not None and existing != name:
                raise ValueError(
                    f"'{registered_name}' is already an alias for '{existing}'."
                )

            if (
                registered_name in self._commands
                and registered_name != name
            ):
                raise ValueError(
                    f"'{registered_name}' is already a registered command."
                )

        previous = self._commands.get(name)

        if previous:
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
        """Remove a command and its aliases."""

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
        """Execute a command. Return False if it is unrecognised."""

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
        """Record a completed extraction input."""

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
        """Display command help or extraction flag details."""

        if argument:
            name = argument.strip().lower()

            if name.startswith("--"):
                self._flag_details(name[2:])
                return

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

        # Terminal commands
        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("Command", style="primary", no_wrap=True)
        table.add_column("Description", style="text", overflow="fold")

        for spec in sorted(
            self._commands.values(),
            key=lambda item: item.name,
        ):
            names = spec.name

            if spec.aliases:
                names += " (" + ", ".join(spec.aliases) + ")"

            table.add_row(names, spec.description)

        self._panel(table, title="Terminal commands")

        # Extraction flags
        self._display_flags()

        self.console.print(
            Text(
                "Use 'help <command>' or 'help --<flag>' for details.",
                style="muted",
            )
        )

    def _flags(self, argument: str | None = None) -> None:
        """List extraction flags, optionally filtered by category."""

        self._display_flags(category=argument)

    def _display_flags(self, category: str | None = None) -> None:
        """Render the extraction flag catalogue."""

        category_filter = category.strip().lower() if category else None

        flags = [
            flag
            for flag in FLAG_CATALOG
            if category_filter is None
            or flag.category.lower() == category_filter
        ]

        if not flags:
            self._message(
                f"No extraction flags found for category '{category}'.",
                status="warning",
            )
            return

        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )

        table.add_column("Flag", style="primary", no_wrap=True)
        table.add_column("Category", style="muted")
        table.add_column("Expected input", style="text", overflow="fold")
        table.add_column("Status", no_wrap=True)

        for flag in flags:
            status = (
                Text("IMPLEMENTED", style="success")
                if flag.implemented
                else Text("PENDING", style="warning")
            )

            table.add_row(
                f"--{flag.name}",
                flag.category,
                flag.expected_input,
                status,
            )

        title = "Extraction flags"

        if category_filter:
            title += f" / {category_filter}"

        self._panel(table, title=title)

        implemented = sum(flag.implemented for flag in flags)

        self.console.print(
            Text(
                f"{len(flags)} recognised flags | "
                f"{implemented} implemented | "
                f"{len(flags) - implemented} pending",
                style="muted",
            )
        )

    def _flag_details(self, name: str) -> None:
        """Display information about one extraction flag."""

        flag = next(
            (
                item
                for item in FLAG_CATALOG
                if item.name == name
            ),
            None,
        )

        if flag is None:
            self._message(
                f"Unknown extraction flag: --{name}",
                status="warning",
            )
            return

        details = Table.grid(padding=(0, 1))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text", overflow="fold")

        details.add_row("Flag", f"--{flag.name}")
        details.add_row("Category", flag.category)
        details.add_row("Expected input", flag.expected_input)
        details.add_row("Description", flag.description)
        details.add_row(
            "Status",
            "Implemented" if flag.implemented else "Not yet implemented",
        )
        details.add_row("Usage", f"--{flag.name} <input>")

        self._panel(details, title=f"Extractor: {flag.name}")

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
        """Clear the terminal screen."""

        self.console.clear()

    def _history(self, _argument: str | None = None) -> None:
        """Display completed extraction inputs."""

        if not self.history:
            self._message(
                "No completed extractions have been recorded this session.",
                title="Session history",
            )
            return

        table = Table(
            show_header=True,
            header_style="heading",
            border_style="border",
            expand=False,
        )
        table.add_column("#", style="muted", justify="right", no_wrap=True)
        table.add_column("Input", style="text", overflow="fold")

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
        """Signal the interactive session to exit."""

        self.should_quit = True
        self.console.print(Text("Exiting.", style="muted"))

    def _panel(
        self,
        renderable: object,
        *,
        title: str,
    ) -> None:
        """Display a standard Theseus panel."""

        self.console.print(
            Panel(
                renderable,
                title=title,
                title_align="left",
                border_style="border",
                padding=(1, 2),
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
        """Display a standard terminal message."""

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