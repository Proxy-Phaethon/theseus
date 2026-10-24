"""
Registered-service discovery for Theseus.

Coordinates email-to-service lookups through independently implemented
adapters in tools/email/apps/.

A result is a lead, not proof of current account ownership.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable

from .apps.base import STATUS_VALUES, ServiceResult
from .apps.gravatar import check_gravatar

@dataclass
class ServiceAdapter:
    """Connect a service name and category to its lookup function."""

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
        """Return registered service names in alphabetical order."""
        return sorted(adapter.name for adapter in self._adapters.values())

    def run(
        self,
        email: str,
        selected: list[str] | None = None,
    ) -> list[dict]:
        """
        Run all registered adapters or only the selected services.

        Unknown service names are returned as explicit errors.
        Individual adapter failures do not interrupt other lookups.
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
                    ServiceResult(
                        service=name,
                        category="unknown",
                        status="error",
                        url=None,
                        evidence={},
                        source="Theseus",
                        observed_at=time.time(),
                        error="No adapter registered for this service",
                    ).to_dict()
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
                    ServiceResult(
                        service=adapter.name,
                        category=adapter.category,
                        status="error",
                        url=None,
                        evidence={},
                        source=adapter.name,
                        observed_at=time.time(),
                        error=f"{type(exc).__name__}: {exc}",
                    ).to_dict()
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
    """Build the service registry with implemented and placeholder adapters."""

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
    ]

    for name, category in services:
        registry.register(
            ServiceAdapter(
                name=name,
                category=category,
                check=_not_implemented(name, category),
            )
        )

    registry.register(
        ServiceAdapter(
            name="Gravatar",
            category="public_profile",
            check=check_gravatar,
        )
    )

    return registry

def discover_services(
    email: str,
    selected: list[str] | None = None,
) -> list[dict]:
    """Entry point for Theseus and isolated tests."""
    registry = build_service_registry()
    return registry.run(email, selected)

if __name__ == "__main__":
    print("Theseus Registered-Service Discovery")
    print("Gravatar is implemented; other adapters are placeholders.")
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