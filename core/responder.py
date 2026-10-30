"""Response formatter for Theseus.

Receives extraction packets and formats their contents
into a readable response.
"""

from __future__ import annotations

from typing import Any

from core.packets import Packet, PacketStatus

class Responder:
    """Formats extraction results for presentation."""

    def respond(self, packet: Packet) -> str:
        """Convert an extraction Packet into a readable response."""

        if not isinstance(packet, Packet):
            raise TypeError("Responder requires a Packet.")

        packet.validate()

        if packet.status == PacketStatus.FAILED:
            return self._format_errors(packet)

        if packet.status == PacketStatus.NOT_SUPPORTED:
            return "This input type is not supported."

        if packet.status == PacketStatus.NOT_IMPLEMENTED:
            return "This extractor has not been implemented yet."

        if packet.status == PacketStatus.PENDING:
            return "Extraction has not started."

        if packet.status == PacketStatus.RUNNING:
            return "Extraction is still in progress."

        return self._format_results(packet)

    def _format_results(self, packet: Packet) -> str:
        """Format successful extraction results."""

        lines: list[str] = []

        lines.append(f"Artefact: {packet.artefact_type}")
        lines.append(f"Status: {packet.status.value}")
        lines.append("")

        if packet.data:
            lines.append("Results")
            self._format_value(packet.data, lines, indent=0)

        if packet.entities:
            lines.append("")
            lines.append("Entities")
            self._format_value(packet.entities, lines, indent=0)

        if packet.related_entities:
            lines.append("")
            lines.append("Related entities")
            self._format_value(packet.related_entities, lines, indent=0)

        if packet.provenance:
            lines.append("")
            lines.append("Provenance")
            self._format_value(packet.provenance, lines, indent=0)

        if packet.errors:
            lines.append("")
            lines.append("Warnings")
            self._format_value(packet.errors, lines, indent=0)

        if not any((
            packet.data,
            packet.entities,
            packet.related_entities,
            packet.provenance,
            packet.errors,
        )):
            lines.append("No results found.")

        return "\n".join(lines)

    def _format_errors(self, packet: Packet) -> str:
        """Format extraction errors."""

        lines = [
            f"Extraction failed: {packet.artefact_type}",
            "",
        ]

        if packet.errors:
            for error in packet.errors:
                code = error.get("code", "unknown_error")
                message = error.get("message", "No details available.")

                lines.append(f"[{code}] {message}")
        else:
            lines.append("No error details available.")

        return "\n".join(lines)

    def _format_value(
        self,
        value: Any,
        lines: list[str],
        indent: int,
    ) -> None:
        """Recursively format dictionaries and lists."""

        prefix = " " * indent

        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}{key.replace('_', ' ').title()}:")
                    self._format_value(item, lines, indent + 4)
                else:
                    lines.append(
                        f"{prefix}{key.replace('_', ' ').title()}: {item}"
                    )

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}-")
                    self._format_value(item, lines, indent + 4)
                else:
                    lines.append(f"{prefix}- {item}")

        else:
            lines.append(f"{prefix}{value}")