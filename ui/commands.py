from rich.table import Table
from rich.panel import Panel
from rich import box

from ui.terminal import console, clear
from ui.status import system

class CommandHandler:
    COMMANDS = {
        "help": "Display available commands",
        "input": "Display supported input types and formats",
        "clear": "Clear the terminal screen",
        "exit": "Terminate the Theseus session",
        "quit": "Terminate the Theseus session",
    }

    INPUT_TYPES = {
        "DOMAIN": {
            "description": "Domain name or URL",
            "formats": [
                "example.com",
                "sub.example.com",
                "https://example.com",
                "https://example.com/about",
            ],
            "restrictions": [
                "Standalone IP addresses are not supported.",
                "URLs containing literal IP addresses are not supported.",
                "Malformed domains and arbitrary text are rejected.",
            ],
        }
    }

    def __init__(self):
        self.running = True

    def display_help(self) -> None:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="section",
            expand=False,
            padding=(0, 2),
        )

        table.add_column("COMMAND", style="accent")
        table.add_column("DESCRIPTION", style="text")

        for command, description in self.COMMANDS.items():
            if command == "quit":
                continue

            table.add_row(command, description)

        console.print()
        console.print(
            Panel(
                table,
                title="[section]AVAILABLE COMMANDS[/section]",
                title_align="left",
                border_style="border",
                box=box.SIMPLE,
                padding=(0, 1),
            )
        )
        console.print()

    def display_input_types(self) -> None:
        console.print()
        console.print(
            "[section]SUPPORTED INPUT TYPES[/section]"
        )
        console.rule(style="case.separator")

        for name, details in self.INPUT_TYPES.items():
            console.print(
                f"\n[accent][{name}][/accent]"
            )
            console.print(details["description"])

            console.print("\n[label]ACCEPTED FORMATS[/label]")

            for example in details["formats"]:
                console.print(f"  [success]>[/success] {example}")

            console.print("\n[label]RESTRICTIONS[/label]")

            for restriction in details["restrictions"]:
                console.print(
                    f"  [warning]![/warning] {restriction}"
                )

        console.print()
        console.rule(style="case.separator")
        console.print()

    def execute(self, value: str) -> bool:
        command = value.strip().lower()

        if command == "help":
            self.display_help()
            return True

        if command == "input":
            self.display_input_types()
            return True

        if command == "clear":
            clear()
            return True

        if command in {"exit", "quit"}:
            self.running = False
            system("TERMINATING THESEUS SESSION...")
            return True

        return False