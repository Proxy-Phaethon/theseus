from dotenv import load_dotenv

import random
import threading
import time

from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from rich.console import Group

from core.identifier import Identifier, EntityType
from core.ip_responder import IPResponder
from core.domain_responder import DomainResponder
from core.email_responder import EmailResponder
from core.url_responder import URLResponder
from core.username_responder import UsernameResponder

from registry.collectors import build_collectors

from ui.banner import render_banner
from ui.terminal import detect_terminal, create_terminal_console
from ui.status import print_status
from ui.panels import print_message_panel

load_dotenv()

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
    "Trying not to get distracted by unrelated domains...",
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
    return Identifier(tools=build_collectors())

def build_responders():
    return {
        EntityType.IP_ADDRESS: IPResponder(),
        EntityType.DOMAIN: DomainResponder(),
        EntityType.EMAIL: EmailResponder(),
        EntityType.URL: URLResponder(),
        EntityType.USERNAME: UsernameResponder(),
    }

def investigate(identifier, target, console, *, animate=True):
    """Run an investigation with a spinner and rotating commentary."""

    if not animate:
        return identifier.process(target)

    started = time.monotonic()
    stop_event = threading.Event()
    result = []
    errors = []

    def worker():
        try:
            result.append(identifier.process(target))
        except BaseException as exc:
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

                display = Group(
                    spinner,
                    Text(
                        f"  └─ {message}",
                        style="muted",
                    ),
                    Text(
                        f"     Elapsed: {elapsed:.1f}s",
                        style="dim",
                    ),
                )
                live.update(display, refresh=True)

                # Change the commentary every few seconds.
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

def print_all_subdomains(responder, console) -> None:
    subdomains = getattr(responder, "subdomains", [])
    if not subdomains:
        return

    try:
        answer = input(
            f"\nPrint all {len(subdomains)} discovered subdomains? [y/n]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return

    if answer not in {"y", "yes"}:
        return

    console.print("\n[heading]All discovered subdomains[/heading]")

    for item in subdomains:
        if isinstance(item, dict):
            hostname = item.get("hostname")
            sources = item.get("sources", [])

            if not hostname:
                continue

            source_text = ", ".join(
                str(source) for source in sources if source
            )
            suffix = f" [muted][{source_text}][/muted]" if source_text else ""
            console.print(f"  {hostname}{suffix}")
        else:
            console.print(f"  {item}")

def main() -> None:
    terminal = detect_terminal()
    console = create_terminal_console(terminal)

    render_banner(console, version="0.7.0")

    identifier = build_identifier()
    responders = build_responders()

    while True:
        try:
            target = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[muted]Exiting.[/muted]")
            break

        if target.lower() in {
            "q", "q.", "quit", "quit.", "bye", "bye.",
            "exit", "exit.",
        }:
            console.print("[muted]Exiting.[/muted]")
            break

        if not target:
            continue

        try:
            entity, results = investigate(
                identifier,
                target,
                console,
                animate=terminal.animate,
            )
        except KeyboardInterrupt:
            console.print()
            print_status(
                console,
                "warning",
                "Investigation interrupted.",
            )
            continue
        except Exception as exc:
            print_status(
                console,
                "error",
                f"Investigation failed: {exc}",
            )
            continue

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
            response = responder.respond(entity, results)
        except KeyboardInterrupt:
            console.print()
            print_status(
                console,
                "warning",
                "Report generation interrupted.",
            )
            continue
        except Exception as exc:
            print_status(
                console,
                "error",
                f"Responder failed: {exc}",
            )
            continue

        if response:
            console.print()
            console.print(response, soft_wrap=True)
        else:
            print_message_panel(
                console,
                "No reportable findings returned by the available collectors.",
                title="No findings",
                status="info",
            )

        if entity.type == EntityType.DOMAIN:
            print_all_subdomains(responder, console)

if __name__ == "__main__":
    main()