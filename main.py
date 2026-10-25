from __future__ import annotations

import random
import threading
import time

from dotenv import load_dotenv
from rich.console import Console, Group
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from core.identifier import Identifier, EntityType
from core.email_responder import EmailResponder
from core.ip_responder import IPResponder
from registry.executor import execute_entity

from ui.banner import render_banner
from ui.commands import CommandHandler
from ui.panels import print_message_panel
from ui.status import print_status
from ui.terminal import detect_terminal, create_terminal_console

load_dotenv()

VERSION = "0.7.0"

INVESTIGATION_MESSAGES = [
    "Identifying target...",
    "Asking the internet nicely...",
    "Consulting the suspiciously large notebook...",
    "Following the digital breadcrumbs...",
    "Checking whether the DNS knows something...",
    "Untangling the web...",
    "Looking under the digital doormat...",
    "Cross-referencing the evidence...",
    "Interrogating the metadata...",
    "Connecting dots that may or may not connect...",
    "Checking the back of the filing cabinet...",
    "Politely bothering public APIs...",
    "Sorting signal from noise...",
    "Making the internet explain itself...",
    "Consulting the archives...",
    "Counting the breadcrumbs...",
    "Having a word with the registry...",
    "Checking the other side of the rabbit hole...",
    "Compiling the findings...",
    "Drinking tea while the packets do their thing...",
    "Petting the metaphorical cat...",
    "Wondering who configured this DNS...",
    "Almost certainly not summoning anything...",
]

def build_identifier() -> Identifier:
    return Identifier()

def investigate(
    identifier: Identifier,
    target: str,
    console: Console,
    *,
    animate: bool = True,
):
    """Execute an investigation with an optional spinner."""

    def run_investigation():
        entity = identifier.identify(target)

        if entity.type not in {
            EntityType.EMAIL,
            EntityType.IP_ADDRESS,
        }:
            raise ValueError(
                f"Investigation for {entity.type.value} is not implemented yet. "
                "The current collector pipeline supports email and IP targets only."
            )

        return entity, execute_entity(entity)

    if not animate:
        return run_investigation()

    started = time.monotonic()
    stop_event = threading.Event()
    result = []
    errors = []

    def worker() -> None:
        try:
            result.append(run_investigation())
        except Exception as exc:
            errors.append(exc)
        finally:
            stop_event.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    message = random.choice(INVESTIGATION_MESSAGES)
    spinner = Spinner("dots", text=Text(message, style="text"), style="primary")

    try:
        with Live(
            console=console,
            refresh_per_second=10,
            transient=True,
            redirect_stdout=False,
            redirect_stderr=False,
        ) as live:
            while not stop_event.is_set():
                elapsed = time.monotonic() - started

                live.update(
                    Group(
                        spinner,
                        Text(f"  └─ {message}", style="muted"),
                        Text(f"     Elapsed: {elapsed:.1f}s", style="dim"),
                    ),
                    refresh=True,
                )

                if stop_event.wait(2.5):
                    break

                message = random.choice(INVESTIGATION_MESSAGES)
                spinner = Spinner(
                    "dots",
                    text=Text("Investigating target...", style="text"),
                    style="primary",
                )
    except KeyboardInterrupt:
        stop_event.set()
        raise

    thread.join()

    if errors:
        raise errors[0]

    if not result:
        raise RuntimeError("Investigation finished without returning results.")

    return result[0]

def main() -> None:
    terminal = detect_terminal()
    console = create_terminal_console(terminal)

    render_banner(console, version=VERSION)

    identifier = build_identifier()
    responders = {
        EntityType.EMAIL: EmailResponder(),
        EntityType.IP_ADDRESS: IPResponder(),
    }

    commands = CommandHandler(
        console,
        responders,
        version=VERSION,
    )

    while not commands.should_quit:
        try:
            target = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[muted]Exiting.[/muted]")
            break

        if not target:
            continue

        command = identifier.identify_command(target)

        if command is not None:
            commands.execute(command)
            continue

        try:
            entity, investigation = investigate(
                identifier,
                target,
                console,
                animate=terminal.animate,
            )
        except KeyboardInterrupt:
            console.print()
            print_status(console, "warning", "Investigation interrupted.")
            continue
        except Exception as exc:
            print_status(console, "error", f"Investigation failed: {exc}")
            continue

        commands.record_investigation(target)

        console.print()
        console.print(
            f"[muted]Type:[/muted] [target]{entity.type.value}[/target]"
        )

        responder = responders.get(entity.type)

        if responder is None:
            print_status(
                console,
                "warning",
                f"No responder available for {entity.type.value}.",
            )
            continue

        try:
            responder.respond(investigation, console)
        except KeyboardInterrupt:
            console.print()
            print_status(console, "warning", "Report generation interrupted.")
        except Exception as exc:
            print_status(console, "error", f"Responder failed: {exc}")

if __name__ == "__main__":
    main()