"""Aggregate extractor envelopes into a consistently formatted response.

The responder preserves each extractor's envelope and raw data. It builds
Rich renderables for main.py to display, but never prints to the console.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.packets import Packet, PacketStatus
from ui.status import format_status
from ui.theme import status_style

@dataclass(frozen=True)
class ResponseReport:
    """Complete response returned by the responder to main.py."""

    request_id: str
    status: str
    responses: tuple[Packet, ...]
    status_counts: dict[str, int]
    renderable: RenderableType

    @property
    def response_count(self) -> int:
        return len(self.responses)

    @property
    def successful_count(self) -> int:
        return sum(
            packet.status == PacketStatus.SUCCESS
            for packet in self.responses
        )

    @property
    def failed_count(self) -> int:
        return sum(
            packet.status == PacketStatus.FAILED
            for packet in self.responses
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the report as structured data, excluding UI renderables."""
        return {
            "request_id": self.request_id,
            "status": self.status,
            "response_count": self.response_count,
            "successful_count": self.successful_count,
            "failed_count": self.failed_count,
            "status_counts": dict(self.status_counts),
            "responses": [
                packet.to_dict() for packet in self.responses
            ],
        }

class ResponderError(ValueError):
    """Raised when extractor responses cannot form a valid report."""

class Responder:
    """Format one or more extractor envelopes into a single report."""

    def respond(
        self,
        responses: Iterable[Packet | dict[str, Any]],
    ) -> ResponseReport:
        """Build and return a formatted report without printing it.

        Accepts Packet instances or dictionaries matching the agreed
        universal packet envelope.
        """
        packets = tuple(self._normalise(response) for response in responses)

        request_ids = {packet.request_id for packet in packets}

        if len(request_ids) > 1:
            raise ResponderError(
                "All extractor responses must belong to the same request."
            )

        request_id = next(iter(request_ids), "")
        status_counts = dict(
            Counter(packet.status.value for packet in packets)
        )
        overall_status = self._overall_status(packets)

        renderable = self._build_report(
            request_id=request_id,
            status=overall_status,
            packets=packets,
            status_counts=status_counts,
        )

        return ResponseReport(
            request_id=request_id,
            status=overall_status,
            responses=packets,
            status_counts=status_counts,
            renderable=renderable,
        )

    @staticmethod
    def _normalise(response: Packet | dict[str, Any]) -> Packet:
        """Validate an envelope without interpreting its data payload."""
        if isinstance(response, Packet):
            response.validate()
            return response

        if isinstance(response, dict):
            try:
                return Packet.from_dict(response)
            except (TypeError, ValueError) as exc:
                raise ResponderError(
                    f"Invalid extractor envelope: {exc}"
                ) from exc

        raise ResponderError(
            "Each extractor response must be a Packet or envelope dictionary."
        )

    @staticmethod
    def _overall_status(packets: tuple[Packet, ...]) -> str:
        if not packets:
            return PacketStatus.PENDING.value

        statuses = {packet.status for packet in packets}

        if len(statuses) == 1:
            return next(iter(statuses)).value

        # Do not declare a final outcome while work remains active.
        if statuses & {PacketStatus.PENDING, PacketStatus.RUNNING}:
            return PacketStatus.RUNNING.value

        # Some extractors returned results, while others did not.
        if PacketStatus.SUCCESS in statuses:
            return PacketStatus.PARTIAL_SUCCESS.value

        # No successful extraction: distinguish actual failures from
        # extractors that simply cannot handle the artefact.
        if PacketStatus.FAILED in statuses:
            return PacketStatus.FAILED.value

        if PacketStatus.NOT_SUPPORTED in statuses:
            return PacketStatus.NOT_SUPPORTED.value

        if PacketStatus.NOT_IMPLEMENTED in statuses:
            return PacketStatus.NOT_IMPLEMENTED.value

        if PacketStatus.PARTIAL_SUCCESS in statuses:
            return PacketStatus.PARTIAL_SUCCESS.value

        return PacketStatus.PENDING.value

    def _build_report(
        self,
        *,
        request_id: str,
        status: str,
        packets: tuple[Packet, ...],
        status_counts: dict[str, int],
    ) -> RenderableType:
        """Build the request summary and consistently formatted result panels."""
        sections: list[RenderableType] = []

        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="muted", no_wrap=True)
        summary.add_column(style="text", overflow="fold")

        summary.add_row("Request ID", request_id or "No responses received")
        summary.add_row("Extractor responses", str(len(packets)))
        summary.add_row("Overall status", self._status_renderable(status))

        for status_name, count in sorted(status_counts.items()):
            summary.add_row(
                f"{status_name.replace('_', ' ').title()}",
                str(count),
            )

        sections.append(
            Panel(
                summary,
                title="THESEUS / RESPONSE SUMMARY",
                title_align="left",
                border_style=status_style(status),
                padding=(1, 2),
                expand=True,
            )
        )

        if not packets:
            sections.append(
                Panel(
                    Text(
                        "No extractor responses were received.",
                        style="muted",
                    ),
                    title="RESULTS",
                    border_style="border",
                    expand=True,
                )
            )
        else:
            for index, packet in enumerate(packets, start=1):
                sections.append(
                    self._build_response_panel(packet, index)
                )

        return Group(*sections)

    def _build_response_panel(
        self,
        packet: Packet,
        index: int,
    ) -> RenderableType:
        """Render every shared envelope field in a fixed layout."""
        extractor = self._extractor_name(packet)
        status = packet.status.value

        details = Table.grid(padding=(0, 2))
        details.add_column(style="muted", no_wrap=True)
        details.add_column(style="text", overflow="fold")

        details.add_row("Status", self._status_renderable(status))
        details.add_row("Request ID", packet.request_id)
        details.add_row("Task ID", packet.task_id)
        details.add_row(
            "Parent task ID",
            packet.parent_task_id or "None",
        )
        details.add_row("Stage", packet.stage)
        details.add_row("Artefact type", packet.artefact_type)
        details.add_row("Input", self._render_value(packet.input))
        details.add_row("Source", self._render_value(packet.source))
        details.add_row("Entities", self._render_value(packet.entities))
        details.add_row(
            "Related entities",
            self._render_value(packet.related_entities),
        )
        details.add_row(
            "Provenance",
            self._render_value(packet.provenance),
        )
        details.add_row("Errors", self._render_value(packet.errors))
        details.add_row("Metadata", self._render_value(packet.metadata))

        # Keep the extractor's data payload intact in the returned Packet.
        # This is only its generic visual representation for now.
        data_panel = Panel(
            Text(self._json_text(packet.data), style="text"),
            title="DATA",
            title_align="left",
            border_style="border",
            padding=(1, 2),
            expand=True,
        )

        content = Group(details, Text(), data_panel)

        return Panel(
            content,
            title=f"RESULT {index:02d} / {extractor}",
            title_align="left",
            border_style=status_style(self._ui_status(status)),
            padding=(1, 2),
            expand=True,
        )

    @staticmethod
    def _extractor_name(packet: Packet) -> str:
        """Resolve the extractor label from envelope metadata or source."""
        metadata_name = packet.metadata.get("extractor")
        if isinstance(metadata_name, str) and metadata_name.strip():
            return metadata_name.strip()

        source_name = packet.source.get("extractor")
        if isinstance(source_name, str) and source_name.strip():
            return source_name.strip()

        return "Unknown extractor"

    @staticmethod
    def _ui_status(status: str) -> str:
        """Translate packet statuses to existing UI status vocabulary."""
        return {
            "partial_success": "partial",
            "not_supported": "skipped",
            "not_implemented": "skipped",
        }.get(status, status)

    @classmethod
    def _status_renderable(cls, status: str) -> Text:
        """Use the existing status formatter and theme conventions."""
        labels = {
            "partial_success": "PARTIAL SUCCESS",
            "not_supported": "NOT SUPPORTED",
            "not_implemented": "NOT IMPLEMENTED",
        }

        return format_status(
            cls._ui_status(status),
            label=labels.get(status),
        )

    @classmethod
    def _render_value(cls, value: Any) -> Text:
        """Render a field value without changing its stored representation."""
        if value is None:
            return Text("None", style="dim")

        if isinstance(value, str):
            return Text(value if value else "(empty)", style="text")

        return Text(cls._json_text(value), style="text")

    @staticmethod
    def _json_text(value: Any) -> str:
        """Serialize values for display, including non-JSON-native objects."""
        def default(item: Any) -> Any:
            if isinstance(item, bytes):
                import base64

                return {
                    "encoding": "base64",
                    "value": base64.b64encode(item).decode("ascii"),
                }

            if hasattr(item, "value"):
                return item.value

            return repr(item)

        try:
            return json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                default=default,
            )
        except (TypeError, ValueError):
            return repr(value)


def respond(
    responses: Iterable[Packet | dict[str, Any]],
) -> ResponseReport:
    """Convenience entry point for main.py."""
    return Responder().respond(responses)