"""Response formatter for Theseus."""

from __future__ import annotations

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.packets import Packet, PacketStatus
from ui.status import format_status
from ui.theme import status_style

class Responder:
    """Format extraction Packets into terminal-ready Rich renderables."""

    def respond(self, packet: Packet) -> RenderableType:
        """Convert an extraction Packet into a formatted response."""

        if not isinstance(packet, Packet):
            raise TypeError("Responder requires a Packet.")

        packet.validate()

        sections: list[RenderableType] = [
            self._header(packet),
        ]

        if packet.status in {
            PacketStatus.FAILED,
            PacketStatus.NOT_SUPPORTED,
            PacketStatus.NOT_IMPLEMENTED,
        }:
            sections.append(self._failure(packet))

        else:
            if packet.data:
                sections.append(
                    self._data_section(packet.data)
                )

            if packet.entities:
                sections.append(
                    self._structured_section(
                        "Entities",
                        packet.entities,
                    )
                )

            if packet.related_entities:
                sections.append(
                    self._structured_section(
                        "Related entities",
                        packet.related_entities,
                    )
                )

            if packet.provenance:
                sections.append(
                    self._structured_section(
                        "Provenance",
                        packet.provenance,
                    )
                )

            if packet.errors:
                sections.append(
                    self._errors_section(packet.errors)
                )

            if not any((
                packet.data,
                packet.entities,
                packet.related_entities,
                packet.provenance,
                packet.errors,
            )):
                sections.append(
                    Text(
                        "No results found.",
                        style="muted",
                    )
                )

        return Group(*sections)

    def _header(self, packet: Packet) -> RenderableType:
        """Build the extraction result heading."""

        status = format_status(packet.status.value)

        details = Table.grid(padding=(0, 2))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text")

        details.add_row("Artefact", packet.artefact_type)
        details.add_row("Status", status)

        if packet.request_id:
            details.add_row("Request ID", packet.request_id)

        return Panel(
            details,
            title="THESEUS / EXTRACTION RESULT",
            title_align="left",
            border_style=status_style(packet.status.value),
            padding=(1, 2),
            expand=False,
        )

    def _data_section(self, data: dict[str, Any]) -> RenderableType:
        """Format extractor-specific data."""

        return self._structured_section("Results", data)

    def _structured_section(
        self,
        title: str,
        value: Any,
    ) -> RenderableType:
        """Format dictionaries and lists into readable tables."""

        table = Table.grid(padding=(0, 2))
        table.add_column(style="muted", no_wrap=True)
        table.add_column(style="text", overflow="fold")

        self._add_values(table, value)

        return Panel(
            table,
            title=title,
            title_align="left",
            border_style="border",
            padding=(1, 2),
            expand=False,
        )

    def _add_values(
        self,
        table: Table,
        value: Any,
        *,
        label: str | None = None,
    ) -> None:
        """Recursively add structured values to a table."""

        if isinstance(value, dict):
            if not value:
                table.add_row(label or "Value", Text("No data", style="muted"))
                return

            for key, item in value.items():
                self._add_values(
                    table,
                    item,
                    label=self._format_label(str(key)),
                )

        elif isinstance(value, list):
            if not value:
                table.add_row(label or "Value", Text("None", style="muted"))
                return

            for index, item in enumerate(value, start=1):
                if isinstance(item, (dict, list)):
                    table.add_row(
                        label or f"Entry {index}",
                        self._nested_table(item),
                    )
                else:
                    table.add_row(
                        label or f"Entry {index}",
                        self._format_scalar(item),
                    )

        else:
            table.add_row(
                label or "Value",
                self._format_scalar(value),
            )

    def _nested_table(self, value: Any) -> RenderableType:
        """Create a nested table for structured list entries."""

        table = Table.grid(padding=(0, 2))
        table.add_column(style="muted", no_wrap=True)
        table.add_column(style="text", overflow="fold")

        self._add_values(table, value)

        return table

    def _errors_section(
        self,
        errors: list[dict[str, Any]],
    ) -> RenderableType:
        """Display extraction errors and warnings."""

        table = Table.grid(padding=(0, 2))
        table.add_column(style="error", no_wrap=True)
        table.add_column(style="text", overflow="fold")

        for error in errors:
            code = str(error.get("code", "unknown_error"))
            message = str(error.get("message", "No details available."))

            table.add_row(code, message)

        return Panel(
            table,
            title="Errors / Warnings",
            title_align="left",
            border_style="warning",
            padding=(1, 2),
            expand=False,
        )

    def _failure(self, packet: Packet) -> RenderableType:
        """Display unsuccessful extraction states."""

        messages = {
            PacketStatus.FAILED: "Extraction failed.",
            PacketStatus.NOT_SUPPORTED: "This input type is not supported.",
            PacketStatus.NOT_IMPLEMENTED: "This extractor has not been implemented.",
            PacketStatus.PENDING: "Extraction has not started.",
            PacketStatus.RUNNING: "Extraction is still in progress.",
        }

        message = messages.get(
            packet.status,
            "Extraction did not complete successfully.",
        )

        if packet.errors:
            details = self._errors_section(packet.errors)

            return Group(
                Panel(
                    Text(message, style="text"),
                    border_style=status_style(packet.status.value),
                    expand=False,
                ),
                details,
            )

        return Panel(
            Text(message, style="text"),
            border_style=status_style(packet.status.value),
            expand=False,
        )

    @staticmethod
    def _format_label(value: str) -> str:
        """Convert field names into readable labels."""

        return value.replace("_", " ").strip().title()

    @staticmethod
    def _format_scalar(value: Any) -> Text:
        """Convert scalar values into readable Rich text."""

        if value is None:
            return Text("None", style="muted")

        if isinstance(value, bool):
            return Text(str(value), style="success" if value else "muted")

        return Text(str(value), style="text")