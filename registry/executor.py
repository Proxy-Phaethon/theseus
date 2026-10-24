"""
Registry-driven execution engine for Theseus.

Responsibilities:
- Resolve registered components dynamically.
- Normalize targets before running collectors.
- Execute each collector independently.
- Preserve raw results, statuses, timing, and errors.
- Return structured results for entity responders.

This module does not format terminal output.
"""

from __future__ import annotations

import importlib
import inspect
import time
import traceback
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from core.identifier import Entity, EntityType
from registry.collectors import (
    ComponentSpec,
    EntityCollectorSpec,
    get_entity_spec,
)

@dataclass
class ComponentResult:
    """Result from one normalizer or collector."""

    name: str
    module: str
    function: str
    status: str
    duration_seconds: float
    result: Any = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "module": self.module,
            "function": self.function,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "result": serialise(self.result),
            "error": self.error,
        }

@dataclass
class InvestigationResult:
    """Complete execution result for one entity."""

    original_target: str
    entity_type: str
    normalized_target: str | None
    status: str
    normalizer: ComponentResult | None
    collectors: list[ComponentResult]
    started_at: str
    finished_at: str
    duration_seconds: float
    errors: list[str]

    @property
    def completed_count(self) -> int:
        return sum(item.status == "success" for item in self.collectors)

    @property
    def failed_count(self) -> int:
        return sum(item.status == "error" for item in self.collectors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_target": self.original_target,
            "entity_type": self.entity_type,
            "normalized_target": self.normalized_target,
            "status": self.status,
            "normalizer": (
                self.normalizer.to_dict() if self.normalizer else None
            ),
            "collectors": [item.to_dict() for item in self.collectors],
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "errors": list(self.errors),
        }

def serialise(value: Any) -> Any:
    """Convert component results into JSON-friendly data."""
    if is_dataclass(value) and not isinstance(value, type):
        return serialise(asdict(value))

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, dict):
        return {str(key): serialise(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [serialise(item) for item in value]

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if hasattr(value, "to_dict") and callable(value.to_dict):
        return serialise(value.to_dict())

    if hasattr(value, "__dict__"):
        return serialise(vars(value))

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return repr(value)

def _invoke(
    component: ComponentSpec,
    target: str,
) -> ComponentResult:
    """Import and invoke one registered component."""
    started = time.perf_counter()

    try:
        module = importlib.import_module(component.module)
        function = getattr(module, component.function)

        if not callable(function):
            raise TypeError(
                f"{component.module}.{component.function} is not callable"
            )

        result = function(target)

        return ComponentResult(
            name=component.name,
            module=component.module,
            function=component.function,
            status="success",
            duration_seconds=round(time.perf_counter() - started, 4),
            result=result,
        )

    except Exception as exc:
        return ComponentResult(
            name=component.name,
            module=component.module,
            function=component.function,
            status="error",
            duration_seconds=round(time.perf_counter() - started, 4),
            error=f"{type(exc).__name__}: {exc}",
        )

def _resolve_normalized_target(result: Any) -> str | None:
    """Extract the normalized address from a normalizer result."""
    if result is None:
        return None

    if isinstance(result, dict):
        value = result.get("address")
    else:
        value = getattr(result, "address", None)

    if not isinstance(value, str):
        return None

    value = value.strip()
    return value or None

def _make_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

def execute_entity(entity: Entity) -> InvestigationResult:
    """
    Execute the registered normalizer and collectors for an entity.

    Each collector receives the normalized target as a string.
    Collector failures are recorded without preventing other collectors
    from running.
    """
    started_clock = time.perf_counter()
    started_at = _make_timestamp()
    errors: list[str] = []

    spec: EntityCollectorSpec | None = get_entity_spec(entity.type)

    if spec is None:
        return InvestigationResult(
            original_target=entity.value,
            entity_type=entity.type.value,
            normalized_target=None,
            status="not_implemented",
            normalizer=None,
            collectors=[],
            started_at=started_at,
            finished_at=_make_timestamp(),
            duration_seconds=round(
                time.perf_counter() - started_clock, 4
            ),
            errors=[f"No registry entry for {entity.type.value}"],
        )

    if spec.normalizer is None or not spec.collectors:
        return InvestigationResult(
            original_target=entity.value,
            entity_type=entity.type.value,
            normalized_target=None,
            status="not_implemented",
            normalizer=None,
            collectors=[],
            started_at=started_at,
            finished_at=_make_timestamp(),
            duration_seconds=round(
                time.perf_counter() - started_clock, 4
            ),
            errors=[
                f"Collectors not implemented for {entity.type.value}"
            ],
        )

    normalizer_result = _invoke(spec.normalizer, entity.value)
    normalized_target = _resolve_normalized_target(
        normalizer_result.result
    )

    if normalizer_result.status != "success":
        errors.append(
            f"Normalizer failed: {normalizer_result.error}"
        )

    if normalized_target is None:
        if normalizer_result.status == "success":
            errors.append(
                "Normalizer did not produce a usable target address"
            )

        return InvestigationResult(
            original_target=entity.value,
            entity_type=entity.type.value,
            normalized_target=None,
            status="error",
            normalizer=normalizer_result,
            collectors=[],
            started_at=started_at,
            finished_at=_make_timestamp(),
            duration_seconds=round(
                time.perf_counter() - started_clock, 4
            ),
            errors=errors,
        )

    collector_results: list[ComponentResult] = []

    for component in spec.collectors:
        result = _invoke(component, normalized_target)
        collector_results.append(result)

        if result.status == "error":
            errors.append(f"{component.name}: {result.error}")

    successful = sum(
        result.status == "success" for result in collector_results
    )
    failed = len(collector_results) - successful

    if successful == len(collector_results):
        status = "success"
    elif successful > 0:
        status = "partial"
    else:
        status = "error"

    return InvestigationResult(
        original_target=entity.value,
        entity_type=entity.type.value,
        normalized_target=normalized_target,
        status=status,
        normalizer=normalizer_result,
        collectors=collector_results,
        started_at=started_at,
        finished_at=_make_timestamp(),
        duration_seconds=round(
            time.perf_counter() - started_clock, 4
        ),
        errors=errors,
    )

if __name__ == "__main__":
    import json

    print("Theseus Registry Executor")
    print("Enter a target, or type 'q' to quit.\n")

    while True:
        try:
            target = input("target> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.lower() in {
            "q", "q.", "quit", "quit.", "bye", "bye.", "exit"
        }:
            break

        if not target:
            continue

        # This test entry point deliberately tests the email pipeline only.
        from core.identifier import Identifier

        entity = Identifier().identify(target)

        if entity.type != EntityType.EMAIL:
            print(
                f"This test entry point expects an email address. "
                f"Detected: {entity.type.value}\n"
            )
            continue

        result = execute_entity(entity)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        print()