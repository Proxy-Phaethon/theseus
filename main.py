from __future__ import annotations

from rich.console import Console

from core.identifier import identify
from core.registry import ExtractorRegistry
from core.executor import Executor
from core.responder import Responder

from ui.banner import render_banner
from ui.terminal import detect_terminal, create_terminal_console


EXIT_COMMANDS = {"exit", "quit", ":q"}

def build_pipeline() -> tuple[ExtractorRegistry, Executor, Responder]:
    """Discover extractors and assemble the Theseus processing pipeline."""
    registry = ExtractorRegistry()
    registry.discover()

    executor = Executor(registry)
    responder = Responder()

    return registry, executor, responder

def process_input(
    user_input: str,
    executor: Executor,
    responder: Responder,
) -> object:
    """Run input through identification, extraction, and response formatting."""

    # 1. Identify the artefacts present in the input.
    identification_packet = identify(user_input)

    # 2. Dispatch the identified artefacts to compatible extractors.
    extraction_packets = executor.execute(identification_packet)

    # 3. Aggregate and format the extractor responses.
    report = responder.respond(extraction_packets)

    # 4. Return the formatted report to the terminal interface.
    return report.renderable

def main() -> None:
    """Run the Theseus interactive terminal interface."""

    terminal_config = detect_terminal()
    console: Console = create_terminal_console(terminal_config)

    render_banner(console)

    registry, executor, responder = build_pipeline()

    console.print(
        f"[dim]Loaded {len(registry)} extractors.[/dim]"
    )
    console.print(
        "[dim]Enter an artefact to investigate, or type 'exit' to quit.[/dim]\n"
    )

    while True:
        try:
            user_input = console.input("[bold cyan]theseus > [/bold cyan]").strip()

            if not user_input:
                continue

            if user_input.lower() in EXIT_COMMANDS:
                console.print("[dim]Theseus shutting down.[/dim]")
                break

            response = process_input(
                user_input=user_input,
                executor=executor,
                responder=responder,
            )

            console.print()
            console.print(response)
            console.print()

        except KeyboardInterrupt:
            console.print("\n[dim]Theseus shutting down.[/dim]")
            break

        except EOFError:
            console.print("\n[dim]Input stream closed.[/dim]")
            break

        except Exception as exc:
            console.print(
                f"[bold red]Pipeline error:[/bold red] {exc}"
            )

if __name__ == "__main__":
    main()