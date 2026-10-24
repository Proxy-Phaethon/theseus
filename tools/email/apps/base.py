"""
Shared models for Theseus email service adapters.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

STATUS_VALUES = {
    "associated",
    "possible",
    "not_found",
    "unknown",
    "error",
    "not_checked",
}

@dataclass
class ServiceResult:
    """Standardized result returned by an email service adapter."""

    service: str
    category: str
    status: str
    url: str | None
    evidence: dict[str, Any]
    source: str
    observed_at: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dictionary."""
        return asdict(self)

def make_result(
    service: str,
    category: str,
    status: str,
    *,
    url: str | None = None,
    evidence: dict[str, Any] | None = None,
    source: str = "Theseus",
    error: str | None = None,
) -> ServiceResult:
    """Create a result with consistent defaults and an observation time."""

    if status not in STATUS_VALUES:
        raise ValueError(f"Unsupported service status: {status}")

    return ServiceResult(
        service=service,
        category=category,
        status=status,
        url=url,
        evidence=evidence or {},
        source=source,
        observed_at=time.time(),
        error=error,
    )