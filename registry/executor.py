"""
Registry-driven execution engine for Theseus.

Responsibilities:
- Resolve registered components dynamically.
- Normalize targets before running collectors.
- Run ordinary collectors before analysis components.
- Pass raw collector observations to analysis components.
- Preserve raw results, statuses, timing, and errors.
- Return structured results for entity responders.

This module does not format terminal output.
"""

from __future__ import annotations

import importlib
import time
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from core.identifier import Entity
from registry.collectors import (
    ComponentSpec,
    EntityCollectorSpec,
    get_entity_spec,
)

SUCCESS_STATUSES = {"success", "ok"}
PARTIAL_STATUSES = {"partial"}
NO_RESULT_STATUSES = {"not_found", "unknown", "no_result"}
SKIPPED_STATUSES = {"skipped", "skip"}
NOT_CHECKED_STATUSES = {"not_checked", "not checked"}
TIMEOUT_STATUSES = {"timeout"}
ERROR_STATUSES = {"error", "failed", "failure"}

COLLECTOR_STAGE = "collector"
ANALYSIS_STAGE = "analysis"

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
        """Count collectors that completed, including no-result lookups."""
        return sum(
            item.status in {"success", "partial", "no_result"}
            for item in self.collectors
        )

    @property
    def failed_count(self) -> int:
        """Count collectors that failed, including timed-out collection."""
        return sum(
            item.status in {"error", "timeout"}
            for item in self.collectors
        )

    @property
    def skipped_count(self) -> int:
        """Count collectors deliberately skipped."""
        return sum(item.status == "skipped" for item in self.collectors)

    @property
    def not_checked_count(self) -> int:
        """Count collectors that could not make an assessment."""
        return sum(
            item.status == "not_checked"
            for item in self.collectors
        )

    @property
    def partial_count(self) -> int:
        """Count collectors that returned incomplete results."""
        return sum(item.status == "partial" for item in self.collectors)

    @property
    def no_result_count(self) -> int:
        """Count completed lookups that returned no source result."""
        return sum(item.status == "no_result" for item in self.collectors)

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
            "partial_count": self.partial_count,
            "no_result_count": self.no_result_count,
            "skipped_count": self.skipped_count,
            "not_checked_count": self.not_checked_count,
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

def _normalise_status(value: Any) -> str | None:
    """Map known collector statuses without changing their raw payload values.

    ``success`` means collection completed with usable observations;
    ``partial`` means some requested collection completed; ``no_result``
    means a source was queried but returned no matching observation;
    ``not_checked`` and ``skipped`` are intentional non-collection;
    ``timeout`` is a distinct collection timeout; ``error`` is another
    collection failure. Unknown status
    strings remain unclassified rather than being silently recast as errors.
    """
    if isinstance(value, Enum):
        value = value.value

    if not isinstance(value, str):
        return None

    value = value.strip().lower().replace("-", "_")

    if value in SUCCESS_STATUSES:
        return "success"

    if value in PARTIAL_STATUSES:
        return "partial"

    if value in NO_RESULT_STATUSES:
        return "no_result"

    if value in SKIPPED_STATUSES:
        return "skipped"

    if value in NOT_CHECKED_STATUSES:
        return "not_checked"

    if value in TIMEOUT_STATUSES:
        return "timeout"

    if value in ERROR_STATUSES:
        return "error"

    return None

def _result_status(result: Any) -> str:
    """Determine component status while retaining the raw result unchanged.

    A payload that declares an unrecognized status is marked ``partial``:
    the component returned a payload, but the executor cannot safely claim
    a successful or failed collection. Payloads with no declared status
    retain the historical ``success`` default. Raw statuses are never
    rewritten, and known no-result statuses are explicitly ``no_result``.
    """
    if isinstance(result, dict):
        status = _normalise_status(result.get("status"))
        if status is not None:
            return status

        raw_status = result.get("status")
        if isinstance(raw_status, str) and raw_status.strip():
            return "partial"

    return "success"

def _result_error(result: Any) -> str | None:
    """Extract a useful error message from a returned error payload."""
    if not isinstance(result, dict):
        return None

    for key in ("error", "message", "detail", "reason"):
        value = result.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return None

def _invoke(
    component: ComponentSpec,
    target: str,
    observations: dict[str, Any] | None = None,
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

        if component.stage == ANALYSIS_STAGE:
            if component.observation_mode == "list":
                component_observations = _observations_as_list(
                    observations or {}
                )
            else:
                component_observations = observations or {}

            result = function(
                target,
                observations=component_observations,
            )
        else:
            result = function(target)

        status = _result_status(result)
        error = None

        if status in {"error", "timeout"}:
            error = _result_error(result) or (
                f"Component returned a {status} status"
            )

        return ComponentResult(
            name=component.name,
            module=component.module,
            function=component.function,
            status=status,
            duration_seconds=round(
                time.perf_counter() - started, 4
            ),
            result=result,
            error=error,
        )

    except Exception as exc:
        return ComponentResult(
            name=component.name,
            module=component.module,
            function=component.function,
            status="error",
            duration_seconds=round(
                time.perf_counter() - started, 4
            ),
            error=f"{type(exc).__name__}: {exc}",
        )

def _observations_as_mapping(
    results: list[ComponentResult],
) -> dict[str, Any]:
    """
    Build a mapping from stable module identifiers to raw results.

    For example, tools.ip.reverse_dns becomes the key "reverse_dns".
    Results are not filtered by status: analysis modules need to be able
    to distinguish failed, skipped, and not-checked observations.
    """
    observations: dict[str, Any] = {}

    for item in results:
        if item.result is None:
            continue

        module_name = item.module.rsplit(".", 1)[-1]
        observations[module_name] = item.result

    return observations

def _observations_as_list(
    observations: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert raw observations into a list for analyzers that expect one.

    A module identifier is added to a shallow copy of dictionary results
    so evidence can retain its originating collector. Original results
    stored in ComponentResult are left unchanged.
    """
    items: list[dict[str, Any]] = []

    for module_name, result in observations.items():
        if not isinstance(result, dict):
            continue

        item = dict(result)
        item.setdefault("module", module_name)
        items.append(item)

    return items

def _resolve_normalized_target(result: Any) -> str | None:
    """Extract the canonical target from a normalizer result."""
    if not isinstance(result, dict):
        return None

    if result.get("status") != "success":
        return None

    value = result.get("canonical_address")

    if not isinstance(value, str):
        return None

    value = value.strip()
    return value or None

def _make_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

def _overall_status(results: list[ComponentResult]) -> str:
    """Determine investigation status from collector outcomes."""
    if not results:
        return "error"

    statuses = [item.status for item in results]

    completed_statuses = {"success", "no_result"}

    if all(status in completed_statuses for status in statuses):
        return "success"

    if all(status in {"error", "timeout"} for status in statuses):
        return "error"

    if any(status in {"success", "partial", "no_result"} for status in statuses):
        return "partial"

    if any(status in {"skipped", "not_checked"} for status in statuses):
        return "partial"

    return "error"

def execute_entity(entity: Entity) -> InvestigationResult:
    """
    Execute the registered normalizer, collectors, and analysis components.

    Ordinary collectors run first. Their raw results are then passed to
    analysis components through each component's declared observation mode.
    Component failures are recorded without preventing subsequent execution.
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

    if normalizer_result.status == "error":
        errors.append(
            f"Normalizer failed: {normalizer_result.error}"
        )
    elif normalizer_result.status != "success":
        errors.append(
            f"Normalizer returned status: {normalizer_result.status}"
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

    ordinary_components = [
        component
        for component in spec.collectors
        if component.stage == COLLECTOR_STAGE
    ]
    analysis_components = [
        component
        for component in spec.collectors
        if component.stage == ANALYSIS_STAGE
    ]

    for component in ordinary_components:
        result = _invoke(component, normalized_target)
        collector_results.append(result)

        if result.status in {"error", "timeout"}:
            errors.append(f"{component.name}: {result.error}")

    observations = _observations_as_mapping(collector_results)

    for component in analysis_components:
        result = _invoke(
            component,
            normalized_target,
            observations=observations,
        )
        collector_results.append(result)

        if result.status in {"error", "timeout"}:
            errors.append(f"{component.name}: {result.error}")

    status = _overall_status(collector_results)

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

        from core.identifier import Identifier, EntityType

        entity = Identifier().identify(target)

        if entity.type != EntityType.EMAIL:
            print(
                "This test entry point expects an email address. "
                f"Detected: {entity.type.value}\n"
            )
            continue

        result = execute_entity(entity)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        print()
