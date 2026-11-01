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

    FAILURE_STATUSES = {
        PacketStatus.FAILED,
        PacketStatus.NOT_SUPPORTED,
        PacketStatus.NOT_IMPLEMENTED,
    }

    SUCCESS_STATUSES = {
        PacketStatus.SUCCESS,
        PacketStatus.PARTIAL_SUCCESS,
    }

    def respond(self, packets: list[Packet]) -> RenderableType:
        """Convert multiple extraction Packets into one response."""

        if not isinstance(packets, list):
            raise TypeError("Responder requires a list of Packets.")

        if not packets:
            return self._empty_response()

        valid_packets: list[Packet] = []
        invalid_count = 0

        for packet in packets:
            if not isinstance(packet, Packet):
                invalid_count += 1
                continue

            try:
                packet.validate()
            except Exception:
                invalid_count += 1
                continue

            valid_packets.append(packet)

        if not valid_packets:
            return self._invalid_response(invalid_count)

        sections: list[RenderableType] = [
            self._summary(valid_packets, invalid_count),
        ]

        for packet in valid_packets:
            sections.append(self._result(packet))

        if invalid_count:
            sections.append(
                Panel(
                    Text(
                        f"{invalid_count} invalid extraction response(s) "
                        "were omitted.",
                        style="warning",
                    ),
                    title="Response warnings",
                    border_style="warning",
                    expand=False,
                )
            )

        return Group(*sections)

    def _summary(
        self,
        packets: list[Packet],
        invalid_count: int,
    ) -> RenderableType:
        """Display the combined extraction outcome."""

        successful = sum(
            packet.status in self.SUCCESS_STATUSES
            for packet in packets
        )

        failed = sum(
            packet.status in self.FAILURE_STATUSES
            for packet in packets
        )

        pending = sum(
            packet.status in {
                PacketStatus.PENDING,
                PacketStatus.RUNNING,
            }
            for packet in packets
        )

        if failed == 0 and pending == 0 and invalid_count == 0:
            overall_status = PacketStatus.SUCCESS

        elif successful > 0:
            overall_status = PacketStatus.PARTIAL_SUCCESS

        elif pending > 0:
            overall_status = PacketStatus.RUNNING

        else:
            overall_status = PacketStatus.FAILED

        details = Table.grid(padding=(0, 2))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text")

        details.add_row("Status", format_status(overall_status.value))
        details.add_row("Extractors executed", str(len(packets)))
        details.add_row("Successful", str(successful))
        details.add_row("Failed", str(failed))

        if pending:
            details.add_row("Pending / running", str(pending))

        if invalid_count:
            details.add_row("Invalid responses", str(invalid_count))

        request_ids = {
            packet.request_id
            for packet in packets
            if packet.request_id
        }

        if len(request_ids) == 1:
            details.add_row("Request ID", next(iter(request_ids)))

        return Panel(
            details,
            title="THESEUS / EXTRACTION SUMMARY",
            title_align="left",
            border_style=status_style(overall_status.value),
            padding=(1, 2),
            expand=False,
        )

    def _result(self, packet: Packet) -> RenderableType:
        """Format one extractor's response."""

        sections: list[RenderableType] = [
            self._header(packet),
        ]

        if packet.status in self.FAILURE_STATUSES:
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
        """Build an individual extraction heading."""

        status = format_status(packet.status.value)

        details = Table.grid(padding=(0, 2))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text")

        details.add_row("Artefact", packet.artefact_type)
        details.add_row("Status", status)

        if packet.task_id:
            details.add_row("Task ID", packet.task_id)

        return Panel(
            details,
            title="EXTRACTION RESULT",
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
                table.add_row(
                    label or "Value",
                    Text("None", style="muted"),
                )
                return

            for key, item in value.items():
                self._add_values(
                    table,
                    item,
                    label=self._format_label(str(key)),
                )

        elif isinstance(value, list):
            if not value:
                table.add_row(
                    label or "Value",
                    Text("None", style="muted"),
                )
                return

            for index, item in enumerate(value, start=1):
                entry_label = (
                    f"{label} [{index}]"
                    if label
                    else f"Entry {index}"
                )

                if isinstance(item, (dict, list)):
                    table.add_row(
                        entry_label,
                        self._nested_table(item),
                    )
                else:
                    table.add_row(
                        entry_label,
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
            if not isinstance(error, dict):
                continue

            code = str(error.get("code", "unknown_error"))
            message = str(
                error.get("message", "No details available.")
            )

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
            PacketStatus.NOT_IMPLEMENTED: "No extractor is configured for this input type.",
            PacketStatus.PENDING: "Extraction has not started.",
            PacketStatus.RUNNING: "Extraction is still in progress.",
        }

        message = messages.get(
            packet.status,
            "Extraction did not complete successfully.",
        )

        sections: list[RenderableType] = [
            Panel(
                Text(message, style="text"),
                border_style=status_style(packet.status.value),
                expand=False,
            )
        ]

        if packet.errors:
            sections.append(
                self._errors_section(packet.errors)
            )

        return Group(*sections)

    @staticmethod
    def _empty_response() -> RenderableType:
        return Panel(
            Text(
                "No extraction responses were received.",
                style="muted",
            ),
            title="THESEUS / EXTRACTION RESULT",
            border_style="warning",
            expand=False,
        )

    @staticmethod
    def _invalid_response(count: int) -> RenderableType:
        return Panel(
            Text(
                f"No valid extraction responses were received. "
                f"{count} invalid response(s) were rejected.",
                style="error",
            ),
            title="THESEUS / EXTRACTION FAILURE",
            border_style="error",
            expand=False,
        )

    @staticmethod
    def _format_label(value: str) -> str:
        return value.replace("_", " ").strip().title()

    @staticmethod
    def _format_scalar(value: Any) -> Text:
        if value is None:
            return Text("None", style="muted")

        if isinstance(value, bool):
            return Text(
                str(value),
                style="success" if value else "muted",
            )

        return Text(str(value), style="text")