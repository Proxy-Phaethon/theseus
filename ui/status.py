from rich.text import Text

from ui.terminal import console

def info(message: str) -> None:
    console.print(
        Text.assemble(
            ("[i] ", "accent"),
            (message, "text"),
        )
    )

def success(message: str) -> None:
    console.print(
        Text.assemble(
            ("[+] ", "success"),
            (message, "text"),
        )
    )

def warning(message: str) -> None:
    console.print(
        Text.assemble(
            ("[!] ", "warning"),
            (message, "text"),
        )
    )

def error(message: str) -> None:
    console.print(
        Text.assemble(
            ("[X] ", "error"),
            (message, "text"),
        )
    )

def system(message: str) -> None:
    console.print(
        Text.assemble(
            ("[*] ", "accent"),
            (message, "muted"),
        )
    )

def divider() -> None:
    console.rule(style="case.separator")