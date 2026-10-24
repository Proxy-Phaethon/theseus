"""
Registered-service discovery for Theseus.

Provides a modular framework for collecting service-association signals.
Each service adapter should use an authorized API or a public source.

A result is a lead, not proof of current account ownership.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

@dataclass
class ServiceResult:
    service: str
    category: str
    status: str
    url: str | None
    evidence: dict[str, Any]
    source: str
    observed_at: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

STATUS_VALUES = {
    "associated",
    "possible",
    "not_found",
    "unknown",
    "error",
    "not_checked",
}

@dataclass
class ServiceAdapter:
    name: str
    category: str
    check: Callable[[str], ServiceResult]

class ServiceRegistry:
    """Registry for independently implemented service adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, ServiceAdapter] = {}

    def register(self, adapter: ServiceAdapter) -> None:
        key = adapter.name.casefold()

        if key in self._adapters:
            raise ValueError(f"Service already registered: {adapter.name}")

        self._adapters[key] = adapter

    def names(self) -> list[str]:
        return sorted(adapter.name for adapter in self._adapters.values())

    def run(
        self,
        email: str,
        selected: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Run registered adapters.

        If selected is omitted, all registered adapters run.
        Unknown service names are returned as explicit errors.
        """
        requested = (
            [name.casefold() for name in selected]
            if selected is not None
            else list(self._adapters)
        )

        results = []

        for name in requested:
            adapter = self._adapters.get(name)

            if adapter is None:
                results.append(
                    asdict(
                        ServiceResult(
                            service=name,
                            category="unknown",
                            status="error",
                            url=None,
                            evidence={},
                            source="Theseus",
                            observed_at=time.time(),
                            error="No adapter registered for this service",
                        )
                    )
                )
                continue

            try:
                result = adapter.check(email)

                if result.status not in STATUS_VALUES:
                    result.status = "error"
                    result.error = "Adapter returned an unsupported status"

                results.append(result.to_dict())

            except Exception as exc:
                results.append(
                    asdict(
                        ServiceResult(
                            service=adapter.name,
                            category=adapter.category,
                            status="error",
                            url=None,
                            evidence={},
                            source=adapter.name,
                            observed_at=time.time(),
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )
                )

        return results

def _not_implemented(
    service: str,
    category: str,
) -> Callable[[str], ServiceResult]:
    """Create a placeholder adapter without making network requests."""

    def check(email: str) -> ServiceResult:
        return ServiceResult(
            service=service,
            category=category,
            status="not_checked",
            url=None,
            evidence={},
            source="Theseus",
            observed_at=time.time(),
            error="Adapter has not been implemented",
        )

    return check

def build_service_registry() -> ServiceRegistry:
    """
    Build the initial service registry.

    These entries are placeholders, not live account checks. Each will
    be replaced with a separately tested adapter.
    """
    registry = ServiceRegistry()

    services = [
        ("GitHub", "developer"),
        ("GitLab", "developer"),
        ("Reddit", "social"),
        ("Instagram", "social"),
        ("Facebook", "social"),
        ("X", "social"),
        ("LinkedIn", "professional"),
        ("Pinterest", "social"),
        ("TikTok", "social"),
        ("Gravatar", "public_profile"),
    ]

    for name, category in services:
        registry.register(
            ServiceAdapter(
                name=name,
                category=category,
                check=_not_implemented(name, category),
            )
        )

    return registry

def discover_services(
    email: str,
    selected: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Entry point for Theseus and isolated tests."""
    registry = build_service_registry()
    return registry.run(email, selected)

if __name__ == "__main__":
    print("Theseus Registered-Service Discovery")
    print("Currently registered adapters are placeholders.")
    print("Enter an email address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("email> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.casefold() in {"q", "quit", "exit", "bye"}:
            break

        if not target:
            print("Please enter an email address.")
            continue

        print(
            json.dumps(
                discover_services(target),
                indent=2,
                ensure_ascii=False,
            )
        )