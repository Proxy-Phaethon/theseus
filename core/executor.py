"""Execute extraction tasks selected from an identification report."""

from __future__ import annotations

from typing import Any

from core.packets import Packet, PacketStatus

# These artefact types require the original content to be parsed,
# rather than an individual string extracted from that content.
WHOLE_INPUT_TYPES = {
    "json",
    "json_document",
    "jsonl",
    "jsonl_document",
    "xml",
    "xml_document",
    "html",
    "html_document",
    "http_request",
    "http_response",
    "email_message",
    "robots_txt",
    "dns_zone",
    "network_configuration",
    "pem_key_material",
    "csv",
    "csv_document",
    "file_signature",
}

class ExecutorError(RuntimeError):
    """Raised when the executor cannot perform its own operations."""

class Executor:
    """Dispatch compatible extractors and collect their result packets."""

    def __init__(self, registry: Any) -> None:
        if registry is None:
            raise ValueError("Executor requires a registry.")

        self.registry = registry

    def execute(self, identification_packet: Packet) -> list[Packet]:
        """Execute applicable extractors for an identification packet.

        Each extractor must implement:
            execute(packet: Packet) -> Packet

        The registry must implement:
            get_compatible(artefact_type: str) -> list
        """
        if not isinstance(identification_packet, Packet):
            raise TypeError(
                "execute() requires an identification Packet."
            )

        matches = identification_packet.data.get("matches", [])

        if not isinstance(matches, list):
            raise ExecutorError(
                "Identification packet data['matches'] must be a list."
            )

        candidates = self._build_candidates(matches)
        results: list[Packet] = []

        for candidate in candidates:
            artefact_type = candidate["artefact_type"]

            extractors = self.registry.get_compatible(artefact_type)

            if not extractors:
                results.append(
                    self._unsupported_packet(
                        identification_packet,
                        candidate,
                    )
                )
                continue

            for extractor in extractors:
                task_packet = self._create_task_packet(
                    identification_packet,
                    candidate,
                    extractor,
                )

                results.append(
                    self._run_extractor(extractor, task_packet)
                )

        return results

    @staticmethod
    def _build_candidates(
        matches: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Validate matches and remove duplicate type/value pairs."""
        candidates: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for match in matches:
            if not isinstance(match, dict):
                continue

            artefact_type = match.get("artefact_type")
            evidence = match.get("evidence")

            if not isinstance(artefact_type, str) or not artefact_type:
                continue

            if evidence is None:
                continue

            key = (artefact_type, str(evidence))

            if key in seen:
                continue

            seen.add(key)

            candidates.append(
                {
                    "artefact_type": artefact_type,
                    "evidence": evidence,
                    "match": match,
                }
            )

        return candidates

    @staticmethod
    def _create_task_packet(
        parent: Packet,
        candidate: dict[str, Any],
        extractor: Any,
    ) -> Packet:
        """Create a uniquely identified task for one extractor."""
        artefact_type = candidate["artefact_type"]
        match = candidate["match"]

        if artefact_type in WHOLE_INPUT_TYPES:
            task_input = parent.input
        else:
            task_input = candidate["evidence"]

        extractor_name = getattr(
            extractor,
            "name",
            extractor.__class__.__name__,
        )

        task = parent.child(
            stage="extraction",
            artefact_type=artefact_type,
            input=task_input,
            source={
                **parent.source,
                "identified_by": "core.identifier",
                "identification_task_id": parent.task_id,
            },
            status=PacketStatus.RUNNING,
        )

        task.metadata.update(
            {
                "extractor": extractor_name,
                "identification_match": match,
            }
        )

        return task

    def _run_extractor(
        self,
        extractor: Any,
        task: Packet,
    ) -> Packet:
        """Run one extractor and validate its returned packet."""
        extractor_name = getattr(
            extractor,
            "name",
            extractor.__class__.__name__,
        )

        try:
            execute_method = getattr(extractor, "execute", None)

            if not callable(execute_method):
                raise TypeError(
                    f"{extractor_name} has no callable execute() method."
                )

            result = execute_method(task)

            if not isinstance(result, Packet):
                raise TypeError(
                    f"{extractor_name}.execute() must return a Packet."
                )

            if (
                result.request_id != task.request_id
                or result.task_id != task.task_id
            ):
                raise ValueError(
                    f"{extractor_name} returned a packet with "
                    "mismatched request_id or task_id."
                )

            if result.status == PacketStatus.RUNNING:
                result.status = PacketStatus.FAILED
                result.add_error(
                    code="incomplete_extraction",
                    message=(
                        f"{extractor_name} returned a packet "
                        "without setting a final status."
                    ),
                    component=extractor_name,
                )

            return result

        except Exception as exc:
            task.status = PacketStatus.FAILED
            task.add_error(
                code="extractor_execution_failed",
                message=f"{type(exc).__name__}: {exc}",
                component=extractor_name,
            )
            return task

    @staticmethod
    def _unsupported_packet(
        parent: Packet,
        candidate: dict[str, Any],
    ) -> Packet:
        """Report that no registered extractor supports this artefact."""
        task = parent.child(
            stage="extraction",
            artefact_type=candidate["artefact_type"],
            input=candidate["evidence"],
            status=PacketStatus.NOT_SUPPORTED,
        )

        task.metadata["identification_match"] = candidate["match"]

        task.add_error(
            code="no_compatible_extractor",
            message=(
                "No registered extractor supports this artefact type."
            ),
            component="core.executor",
        )

        return task