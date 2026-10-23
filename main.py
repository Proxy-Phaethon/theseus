from dotenv import load_dotenv

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

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
    """Run an investigation with optional live progress animation."""
    if not animate:
        return identifier.process(target)

    with Progress(
        SpinnerColumn(spinner_name="dots", style="primary"),
        TextColumn("[text]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
        transient=True,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        progress.add_task("Investigating Target Entity...", total=None)
        return identifier.process(target)

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