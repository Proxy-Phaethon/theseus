"""Theseus entry point.

Receives command-line input and coordinates the
identification, extraction, and response pipeline.
"""

from __future__ import annotations

import argparse
import sys

from core.packets import Packet, PacketStatus
from core.identifier import Identifier
from core.executor import Executor
from core.responder import Responder

FLAGS = (
    "url", "domain", "dns", "ip", "cidr", "hostname", "redirect",
    "http", "webpage", "javascript", "css", "asn", "mac", "bssid",
    "port", "certificate", "tls", "pcap", "flow", "file", "hash",
    "pdf", "office", "image", "audio", "video", "archive", "binary",
    "font", "shortcut", "directory", "email", "email_headers",
    "message_id", "contact", "calendar", "vcf", "ics",
    "git_repository", "git_commit", "package", "sbom", "container",
    "api_spec", "cve", "json", "xml", "csv", "sqlite", "config",
    "env", "registry", "log", "browser", "har",
)

def parse_arguments() -> tuple[str | None, str | None]:
    """Parse the command-line arguments."""

    parser = argparse.ArgumentParser(
        prog="theseus",
        description="Digital artefact extraction tool.",
    )

    group = parser.add_mutually_exclusive_group()

    for flag in FLAGS:
        group.add_argument(
            f"--{flag}",
            dest=flag,
            nargs="?",
            const=None,
            default=argparse.SUPPRESS,
            metavar="INPUT",
            help=f"Input for the {flag} extractor.",
        )

    arguments, unknown = parser.parse_known_args()
    supplied = vars(arguments)

    for flag in FLAGS:
        if flag in supplied:
            return f"--{flag}", supplied[flag]

    # Pass unknown flags to the identifier so it can reject them.
    if unknown and unknown[0].startswith("-"):
        flag = unknown[0]
        value = unknown[1] if len(unknown) > 1 else None
        return flag, value

    return None, None

def main() -> None:
    """Run the Theseus pipeline."""

    flag, value = parse_arguments()

    packet = Packet(
        stage="input",
        artefact_type="unknown",
        input=value,
        metadata={
            "flag": flag,
        },
    )

    identifier = Identifier()
    executor = Executor()
    responder = Responder()

    # Identification
    report = identifier.identify(packet)

    if report.status != PacketStatus.SUCCESS:
        print(responder.respond(report))
        return

    # Extraction
    result = executor.execute(report)

    # Response
    # Supports the current Executor returning a Packet.
    if isinstance(result, Packet):
        response = responder.respond(result)
    else:
        response = result

    print(response)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted.")
        sys.exit(130)
    except Exception as exc:
        print(f"Theseus encountered an unexpected error: {exc}")
        sys.exit(1)