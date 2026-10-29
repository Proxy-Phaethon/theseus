"""Universal packet contract for Theseus.

All pipeline stages use the same Packet envelope.
Stage-specific findings belong in `data`; shared fields retain
the same meaning throughout the pipeline.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from typing import Any
from uuid import uuid4

class PacketStatus(StrEnum):
    """Standard statuses shared by every pipeline component."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    NOT_SUPPORTED = "not_supported"
    NOT_IMPLEMENTED = "not_implemented"

class PacketValidationError(ValueError):
    """Raised when a packet violates the universal contract."""

def _new_id() -> str:
    return str(uuid4())

def _json_safe(value: Any) -> Any:
    """Convert supported Python values into JSON-compatible values."""

    if isinstance(value, bytes):
        return {
            "__theseus_type__": "bytes",
            "encoding": "base64",
            "value": base64.b64encode(value).decode("ascii"),
        }

    if isinstance(value, StrEnum):
        return value.value

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(
        f"Cannot serialise value of type {type(value).__name__}. "
        "Convert it to a supported primitive or structured value first."
    )

def _json_restore(value: Any) -> Any:
    """Restore values encoded by `_json_safe`."""

    if isinstance(value, dict):
        if (
            value.get("__theseus_type__") == "bytes"
            and value.get("encoding") == "base64"
            and isinstance(value.get("value"), str)
        ):
            try:
                return base64.b64decode(
                    value["value"], validate=True
                )
            except ValueError as exc:
                raise PacketValidationError(
                    "Invalid base64-encoded bytes in packet."
                ) from exc

        return {
            key: _json_restore(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_json_restore(item) for item in value]

    return value

@dataclass
class Packet:
    """The universal data envelope used throughout Theseus."""

    # Investigation and task identity
    request_id: str = field(default_factory=_new_id)
    task_id: str = field(default_factory=_new_id)
    parent_task_id: str | None = None

    # Processing context
    stage: str = "input"
    artefact_type: str = "unknown"
    input: Any = None
    source: dict[str, Any] = field(default_factory=dict)
    status: PacketStatus | str = PacketStatus.PENDING

    # Results
    data: dict[str, Any] = field(default_factory=dict)
    entities: list[dict[str, Any]] = field(default_factory=list)
    related_entities: list[dict[str, Any]] = field(default_factory=list)

    # Evidence tracking and diagnostics
    provenance: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate every newly constructed packet."""
        self.validate()

    def validate(self) -> None:
        """Check the packet against the universal envelope contract."""

        for name in ("request_id", "task_id", "stage", "artefact_type"):
            value = getattr(self, name)

            if not isinstance(value, str) or not value.strip():
                raise PacketValidationError(
                    f"'{name}' must be a non-empty string."
                )

        if self.parent_task_id is not None:
            if (
                not isinstance(self.parent_task_id, str)
                or not self.parent_task_id.strip()
            ):
                raise PacketValidationError(
                    "'parent_task_id' must be a non-empty string or None."
                )

        try:
            self.status = PacketStatus(self.status)
        except (ValueError, TypeError) as exc:
            allowed = ", ".join(status.value for status in PacketStatus)
            raise PacketValidationError(
                f"Invalid packet status. Allowed statuses: {allowed}"
            ) from exc

        for name in (
            "source",
            "data",
            "provenance",
            "metadata",
        ):
            if not isinstance(getattr(self, name), dict):
                raise PacketValidationError(
                    f"'{name}' must be a dictionary."
                )

        for name in ("entities", "related_entities", "errors"):
            value = getattr(self, name)

            if not isinstance(value, list):
                raise PacketValidationError(
                    f"'{name}' must be a list."
                )

            if not all(isinstance(item, dict) for item in value):
                raise PacketValidationError(
                    f"Every item in '{name}' must be a dictionary."
                )

    def to_dict(self) -> dict[str, Any]:
        """Return the complete envelope as a Python dictionary."""
        self.validate()
        return asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialise the complete packet to JSON."""
        return json.dumps(
            _json_safe(self.to_dict()),
            indent=indent,
            ensure_ascii=False,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Packet:
        """Construct and validate a packet from a dictionary."""

        if not isinstance(payload, dict):
            raise PacketValidationError(
                "Packet input must be a dictionary."
            )

        allowed_fields = {item.name for item in fields(cls)}
        unknown_fields = set(payload) - allowed_fields

        if unknown_fields:
            raise PacketValidationError(
                "Unknown packet fields: "
                + ", ".join(sorted(unknown_fields))
            )

        return cls(**payload)

    @classmethod
    def from_json(cls, raw: str) -> Packet:
        """Deserialise and validate a JSON packet."""

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PacketValidationError(
                "Packet contains invalid JSON."
            ) from exc

        payload = _json_restore(payload)
        return cls.from_dict(payload)

    def child(
        self,
        *,
        stage: str,
        artefact_type: str,
        input: Any = None,
        source: dict[str, Any] | None = None,
        status: PacketStatus | str = PacketStatus.PENDING,
    ) -> Packet:
        """Create a child task while preserving investigation identity."""

        return Packet(
            request_id=self.request_id,
            parent_task_id=self.task_id,
            stage=stage,
            artefact_type=artefact_type,
            input=input,
            source=dict(source or self.source),
            status=status,
            provenance=dict(self.provenance),
            metadata={},
        )

    def add_error(
        self,
        *,
        code: str,
        message: str,
        component: str | None = None,
    ) -> None:
        """Append a structured error without discarding existing errors."""

        error: dict[str, Any] = {
            "code": code,
            "message": message,
        }

        if component is not None:
            error["component"] = component

        self.errors.append(error)