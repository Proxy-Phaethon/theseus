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
    """Format extraction Packets into one consolidated Rich response."""

    FAILURE_STATUSES = {
        PacketStatus.FAILED,
        PacketStatus.NOT_SUPPORTED,
        PacketStatus.NOT_IMPLEMENTED,
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

        overall_status = self._overall_status(valid_packets)

        sections: list[RenderableType] = [
            self._header(valid_packets, overall_status),
            self._results(valid_packets, invalid_count),
        ]

        return Group(*sections)

    def _overall_status(
        self,
        packets: list[Packet],
    ) -> PacketStatus:
        """Determine the combined extraction status."""

        statuses = [packet.status for packet in packets]

        if all(status == PacketStatus.SUCCESS for status in statuses):
            return PacketStatus.SUCCESS

        if all(status in self.FAILURE_STATUSES for status in statuses):
            return PacketStatus.FAILED

        return PacketStatus.PARTIAL_SUCCESS

    def _header(
        self,
        packets: list[Packet],
        overall_status: PacketStatus,
    ) -> RenderableType:
        """Build the consolidated extraction heading."""

        artefacts = sorted({
            packet.artefact_type
            for packet in packets
            if packet.artefact_type
        })

        details = Table.grid(padding=(0, 2))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text", overflow="fold")

        details.add_row(
            "Artefact(s)",
            ", ".join(artefacts) if artefacts else "None",
        )
        details.add_row(
            "Status",
            format_status(overall_status.value),
        )

        task_id = self._task_id(packets)

        if task_id:
            details.add_row("Task ID", task_id)

        return Panel(
            details,
            title="EXTRACTION RESULT",
            title_align="left",
            border_style=status_style(overall_status.value),
            padding=(1, 2),
            expand=False,
        )

    @staticmethod
    def _task_id(packets: list[Packet]) -> str | None:
        """Resolve the common parent task ID where possible."""

        parent_ids = {
            packet.parent_task_id
            for packet in packets
            if packet.parent_task_id
        }

        if len(parent_ids) == 1:
            return next(iter(parent_ids))

        task_ids = {
            packet.task_id
            for packet in packets
            if packet.task_id
        }

        if len(task_ids) == 1:
            return next(iter(task_ids))

        if len(task_ids) > 1:
            return "Multiple"

        return None

    def _results(
        self,
        packets: list[Packet],
        invalid_count: int,
    ) -> RenderableType:
        """Merge and display the results from all extractors."""

        merged: dict[str, Any] = {}

        for packet in packets:
            self._merge_section(merged, packet.data)

            self._merge_section(
                merged,
                {"Entities": packet.entities},
            )
            self._merge_section(
                merged,
                {"Related Entities": packet.related_entities},
            )
            self._merge_section(
                merged,
                {"Provenance": packet.provenance},
            )
            self._merge_section(
                merged,
                {"Errors / Warnings": packet.errors},
            )

            if packet.status in self.FAILURE_STATUSES:
                self._merge_section(
                    merged,
                    {
                        "Extraction Status": packet.status.value,
                    },
                )

        if invalid_count:
            self._merge_section(
                merged,
                {
                    "Response Warnings": [
                        f"{invalid_count} invalid extraction "
                        "response(s) were omitted."
                    ],
                },
            )

        merged = self._clean(merged)

        table = Table.grid(padding=(0, 2))
        table.add_column(style="muted", overflow="fold")
        table.add_column(style="text", overflow="fold")

        if merged:
            self._add_values(table, merged)
        else:
            table.add_row(
                "Results",
                Text("No results found.", style="muted"),
            )

        return Panel(
            table,
            title="RESULTS",
            title_align="left",
            border_style="border",
            padding=(1, 2),
            expand=False,
        )

    def _merge_section(
        self,
        target: dict[str, Any],
        section: Any,
    ) -> None:
        """Merge a section into the consolidated result."""

        section = self._clean(section)

        if not section:
            return

        if not isinstance(section, dict):
            return

        for key, value in section.items():
            if key not in target:
                target[key] = value
            else:
                target[key] = self._merge_values(
                    target[key],
                    value,
                )

    def _merge_values(self, existing: Any, incoming: Any) -> Any:
        """Recursively merge values without discarding conflicts."""

        if isinstance(existing, dict) and isinstance(incoming, dict):
            merged = dict(existing)

            for key, value in incoming.items():
                if key in merged:
                    merged[key] = self._merge_values(
                        merged[key],
                        value,
                    )
                else:
                    merged[key] = value

            return merged

        if isinstance(existing, list) and isinstance(incoming, list):
            merged = list(existing)

            for value in incoming:
                self._append_unique(merged, value)

            return merged

        if existing == incoming:
            return existing

        if isinstance(existing, list):
            merged = list(existing)
        else:
            merged = [existing]

        if isinstance(incoming, list):
            for value in incoming:
                self._append_unique(merged, value)
        else:
            self._append_unique(merged, incoming)

        return merged

    @staticmethod
    def _append_unique(target: list[Any], value: Any) -> None:
        """Append a value only when it is not already present."""

        if not any(existing == value for existing in target):
            target.append(value)

    def _clean(self, value: Any) -> Any:
        """Remove empty values while preserving meaningful falsey values."""

        if value is None:
            return None

        if isinstance(value, str):
            return value if value.strip() else None

        if isinstance(value, dict):
            cleaned = {}

            for key, item in value.items():
                cleaned_item = self._clean(item)

                if cleaned_item is not None:
                    cleaned[key] = cleaned_item

            return cleaned or None

        if isinstance(value, list):
            cleaned = []

            for item in value:
                cleaned_item = self._clean(item)

                if cleaned_item is not None:
                    self._append_unique(cleaned, cleaned_item)

            return cleaned or None

        return value

    def _add_values(
        self,
        table: Table,
        value: Any,
        *,
        label: str | None = None,
    ) -> None:
        """Recursively render merged values."""

        if isinstance(value, dict):
            for key, item in value.items():
                formatted_key = self._format_label(str(key))

                item_label = (
                    f"{label} / {formatted_key}"
                    if label
                    else formatted_key
                )

                self._add_values(
                    table,
                    item,
                    label=item_label,
                )

        elif isinstance(value, list):
            for index, item in enumerate(value, start=1):
                if isinstance(item, (dict, list)):
                    table.add_row(
                        f"{label or 'Entry'} [{index}]",
                        self._nested_table(item),
                    )
                else:
                    table.add_row(
                        f"{label or 'Entry'} [{index}]",
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
        table.add_column(style="muted", overflow="fold")
        table.add_column(style="text", overflow="fold")

        self._add_values(table, value)

        return table

    @staticmethod
    def _format_label(value: str) -> str:
        return value.replace("_", " ").strip().title()

    @staticmethod
    def _format_scalar(value: Any) -> Text:
        if isinstance(value, bool):
            return Text(
                str(value),
                style="success" if value else "muted",
            )

        return Text(str(value), style="text")

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